//! Complete pool lifecycle against owned keys, real node state and controlled metadata.
use super::*;
use crate::pool_fixture::{self, Metadata};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::DirBuilderExt,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
};

fn round_ratio(n: u128, d: u128) -> Result<u128> {
    ensure!(d != 0, "zero stake denominator");
    let q = n / d;
    let r = n % d;
    Ok(q + u128::from(r > d - r || (r == d - r && q % 2 == 1)))
}
/// Correctly round the exact controlled stake ratio once to IEEE754 binary64.
fn rational_double(n: u128, d: u128) -> Result<f64> {
    ensure!(d > 0, "zero saturation denominator");
    if n == 0 {
        return Ok(0.0);
    }
    let mut exponent = (128 - n.leading_zeros()) as i32 - (128 - d.leading_zeros()) as i32;
    if exponent >= 0 {
        ensure!(
            exponent < 128 && d <= (u128::MAX >> exponent),
            "saturation normalization overflow"
        );
        if n < d << exponent {
            exponent -= 1;
        }
    } else {
        ensure!(
            -exponent < 128 && n <= (u128::MAX >> -exponent),
            "saturation normalization overflow"
        );
        if n << -exponent < d {
            exponent -= 1;
        }
    }
    let shift = 52 - exponent;
    ensure!(
        (0..128).contains(&shift) && n <= (u128::MAX >> shift),
        "saturation scaling overflow"
    );
    let mut significand = round_ratio(n << shift, d)?;
    if significand == 1u128 << 53 {
        significand >>= 1;
        exponent += 1;
    }
    ensure!(
        (-1022..=1023).contains(&exponent) && ((1u128 << 52)..(1u128 << 53)).contains(&significand),
        "unsupported saturation representation"
    );
    Ok(f64::from_bits(
        ((exponent + 1023) as u64) << 52 | (significand as u64 - (1u64 << 52)),
    ))
}
fn query_timestamp(value: &str) -> Result<String> {
    let nanoseconds = validity::utc_ns(value)?;
    ensure!(
        nanoseconds.is_multiple_of(1_000_000_000),
        "native timestamp must be an exact whole second"
    );
    let canonical = match value.split_once('.') {
        Some((prefix, _)) => format!("{prefix}Z"),
        None => value.to_owned(),
    };
    ensure!(
        validity::utc_ns(&canonical)? == nanoseconds,
        "native timestamp formatting changes the instant"
    );
    Ok(canonical)
}
fn ids(pools: &Value) -> Result<Vec<String>> {
    pools
        .as_array()
        .context("pool list is not an array")?
        .iter()
        .map(|p| text(p, "/id"))
        .collect()
}
fn snapshot(
    pools: &Value,
    expected: &BTreeSet<String>,
    distribution: &Value,
    state: &Value,
    target: u64,
    zero_stake: bool,
) -> Result<()> {
    let actual = ids(pools)?;
    ensure!(
        actual.len() == expected.len()
            && actual.iter().cloned().collect::<BTreeSet<_>>() == *expected,
        "pool identities/count differ"
    );
    let mut previous = u64::MAX;
    for pool in pools.as_array().unwrap() {
        let id = text(pool, "/id")?;
        let reward = number(pool, "/metrics/non_myopic_member_rewards/quantity")?;
        ensure!(
            reward <= previous && (!zero_stake || reward == 0),
            "pool rewards/order differ"
        );
        previous = reward;
        let fraction = distribution.get(&id).context("node pool stake missing")?;
        let n = u128::from(number(fraction, "/numerator")?);
        let d = u128::from(number(fraction, "/denominator")?);
        ensure!(n <= d && d != 0, "invalid node stake fraction");
        let percent = round_ratio(n * 10000, d)? as f64 / 100.0;
        ensure!(
            pool.pointer("/metrics/relative_stake/quantity")
                .and_then(Value::as_f64)
                .map(f64::to_bits)
                == Some(percent.to_bits()),
            "pool percentage differs from exact node rounding"
        );
        let saturation = rational_double(n * u128::from(target), d)?;
        ensure!(
            pool.pointer("/metrics/saturation")
                .and_then(Value::as_f64)
                .map(f64::to_bits)
                == Some(saturation.to_bits()),
            "pool saturation differs from exact node ratio"
        );
        let (hrp, raw) = crate::encoding::bech32(&id)?;
        ensure!(hrp == "pool" && raw.len() == 28, "invalid pool id encoding");
        let entry = state
            .get(hex::encode(raw))
            .context("node pool parameters missing")?;
        let parameters = if entry["futurePoolParams"].is_object() {
            &entry["futurePoolParams"]
        } else {
            &entry["poolParams"]
        };
        ensure!(
            pool["pledge"]["quantity"] == parameters["spsPledge"]
                && pool["cost"]["quantity"] == parameters["spsCost"]
                && parameters["spsMargin"].as_f64() == Some(0.1)
                && pool["margin"]["quantity"].as_f64() == Some(10.0),
            "pool registration parameters differ from node"
        );
    }
    Ok(())
}
struct MetadataServer {
    port: u16,
    stop: Arc<AtomicBool>,
    good: Arc<AtomicU64>,
    bad: Arc<AtomicU64>,
    bad_body: Arc<Mutex<Vec<u8>>>,
    failed: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl MetadataServer {
    fn start(good: Vec<u8>, bad: Vec<u8>) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let good_count = Arc::new(AtomicU64::new(0));
        let bad_count = Arc::new(AtomicU64::new(0));
        let failed = Arc::new(AtomicBool::new(false));
        let bad_body = Arc::new(Mutex::new(bad));
        let served_bad = bad_body.clone();
        let (done, gc, bc, errors) = (
            stop.clone(),
            good_count.clone(),
            bad_count.clone(),
            failed.clone(),
        );
        let worker = thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let body = served_bad.lock().expect("metadata phase mutex poisoned");
                        if serve(&mut stream, &good, &body, &gc, &bc).is_err() {
                            errors.store(true, Ordering::SeqCst);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        sleep(Duration::from_millis(10))
                    }
                    Err(_) => {
                        errors.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
        });
        Ok(Self {
            port,
            stop,
            good: good_count,
            bad: bad_count,
            bad_body,
            failed,
            worker: Some(worker),
        })
    }
    fn url(&self, name: &str) -> String {
        format!("http://127.0.0.1:{}/{name}.json", self.port)
    }
    fn observed(&self) -> bool {
        self.good.load(Ordering::SeqCst) > 0 && self.bad.load(Ordering::SeqCst) > 0
    }
    fn wallet_phase(&self, mismatched: Vec<u8>) -> Result<()> {
        let mut body = self
            .bad_body
            .lock()
            .map_err(|_| anyhow!("metadata phase mutex poisoned"))?;
        ensure!(*body != mismatched, "negative metadata body did not change");
        *body = mismatched;
        self.good.store(0, Ordering::SeqCst);
        self.bad.store(0, Ordering::SeqCst);
        Ok(())
    }
    fn check(&self) -> Result<()> {
        ensure!(
            !self.failed.load(Ordering::SeqCst),
            "metadata fixture server failed"
        );
        Ok(())
    }
}
impl Drop for MetadataServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn serve(
    stream: &mut TcpStream,
    good: &[u8],
    bad: &[u8],
    good_count: &AtomicU64,
    bad_count: &AtomicU64,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let mut bytes = Vec::new();
    let mut buffer = [0; 512];
    while !bytes.windows(4).any(|s| s == b"\r\n\r\n") {
        let n = stream.read(&mut buffer)?;
        ensure!(
            n > 0 && bytes.len() + n <= 8192,
            "invalid metadata request headers"
        );
        bytes.extend(&buffer[..n]);
    }
    let first = std::str::from_utf8(&bytes)?
        .lines()
        .next()
        .context("metadata request missing")?;
    let parts: Vec<_> = first.split_whitespace().collect();
    ensure!(
        parts.len() == 3 && parts[0] == "GET",
        "invalid metadata request method"
    );
    let (body, count) = match parts[1] {
        "/good.json" => (good, good_count),
        "/bad.json" => (bad, bad_count),
        _ => anyhow::bail!("unexpected metadata request path"),
    };
    write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len())?;
    stream.write_all(body)?;
    stream.flush()?;
    count.fetch_add(1, Ordering::SeqCst);
    Ok(())
}
impl Session<'_> {
    fn pool_list(&mut self, stake: u64) -> Result<Value> {
        self.call(
            "listStakePools",
            "GET",
            &format!("/stake-pools?stake={stake}"),
            None,
            200,
        )
    }
    fn pool_settings(&mut self, source: Value) -> Result<()> {
        self.call(
            "putSettings",
            "PUT",
            "/settings",
            Some(json!({"settings":{"pool_metadata_source":source}})),
            204,
        )?;
        Ok(())
    }
    fn pool_proof(&mut self, case: &str, proof: Value) {
        self.report
            .record(case, &["wallet.stake-pools".into()], Ok(()));
        self.report.evidence.last_mut().unwrap().detail = proof.to_string();
    }
    pub(super) fn exercise_pools(&mut self, options: &LiveOptions) -> Result<()> {
        ensure!(
            options.node.network_magic == 42,
            "pools require controlled magic42 cluster"
        );
        let directory = options
            .pool_directory
            .as_ref()
            .context("owned pool directory missing")?;
        let workspace = options
            .pool_workspace
            .as_ref()
            .context("fresh pool workspace missing")?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(workspace)
            .context("pool workspace must be fresh")?;
        let original = self.call("getSettings", "GET", "/settings", None, 200)?;
        let good = json!({"ticker":"CFM","name":"Conformance valid","description":"Owned pool metadata fixture","homepage":"https://example.com/valid"});
        let expected_bad = json!({"ticker":"BAD","name":"Conformance expected","description":"Owned expected metadata","homepage":"https://example.com/expected"});
        let served_bad = json!({"ticker":"BAD","name":"Conformance wrong","description":"Different valid JSON bytes","homepage":"https://example.com/wrong"});
        let good_bytes = serde_json::to_vec(&good)?;
        let bad_bytes = serde_json::to_vec(&expected_bad)?;
        ensure!(
            crate::transaction::blake2b(&good_bytes, 32)?
                != crate::transaction::blake2b(&bad_bytes, 32)?
                && bad_bytes != serde_json::to_vec(&served_bad)?,
            "metadata controls are not distinct"
        );
        let server = MetadataServer::start(good_bytes.clone(), bad_bytes.clone())?;
        let result = (|| -> Result<()> {
            self.pool_settings(json!("none"))?;
            let mut registrations = Vec::new();
            for (index, (name, bytes, pledge)) in [
                ("good", good_bytes, 150_000_000_000_000u64),
                ("bad", bad_bytes, 100_000_000_000_000u64),
            ]
            .into_iter()
            .enumerate()
            {
                let metadata = Metadata {
                    url: server.url(name),
                    bytes,
                };
                let receipt = pool_fixture::prepare_with_metadata(
                    &pool_fixture::Options {
                        node: crate::node::NodeOracle {
                            executable: options.node.executable.clone(),
                            socket: options.node.socket.clone(),
                            network_magic: 42,
                        },
                        owned_pool: directory.join(format!("pool-{}", [1, 3][index])),
                        target: self.api.label.clone(),
                        faucet: options.faucet.clone().context("pools require faucet")?,
                        output: workspace.join(format!("registration-{}", index + 1)),
                        timeout: self.timeout,
                        pledge,
                    },
                    Some(&metadata),
                )?;
                registrations.push(serde_json::from_slice::<Value>(&fs::read(receipt)?)?);
            }
            let expected = registrations
                .iter()
                .map(|r| text(r, "/pool_id"))
                .collect::<Result<BTreeSet<_>>>()?;
            ensure!(expected.len() == 2, "fixture pool identities collide");
            let deadline = Instant::now() + self.timeout;
            loop {
                let before = options.node.query(&["tip"], self.timeout)?;
                let distribution = options
                    .node
                    .query(&["stake-distribution", "--output-json"], self.timeout)?;
                let state = options.node.query(
                    &["pool-state", "--all-stake-pools", "--output-json"],
                    self.timeout,
                )?;
                let parameters = options.node.protocol_parameters(self.timeout)?;
                let target = number(&parameters, "/stakePoolTargetNum")?;
                ensure!(target > 0, "node pool target is zero");
                let mut observations = BTreeMap::new();
                for stake in [0u64, 100_000_000, 1_000_000_000] {
                    observations.insert(stake, (self.pool_list(stake)?, self.pool_list(stake)?));
                }
                let after_distribution = options
                    .node
                    .query(&["stake-distribution", "--output-json"], self.timeout)?;
                let after = options.node.query(&["tip"], self.timeout)?;
                ensure!(
                    Instant::now() < deadline,
                    "pool ranking alignment timed out"
                );
                if before["epoch"] != after["epoch"] || distribution != after_distribution {
                    continue;
                }
                let mut nonzero = false;
                for (stake, (first, second)) in &observations {
                    snapshot(first, &expected, &distribution, &state, target, *stake == 0)?;
                    snapshot(
                        second,
                        &expected,
                        &distribution,
                        &state,
                        target,
                        *stake == 0,
                    )?;
                    ensure!(
                        ids(first)? == ids(second)?,
                        "pool reward tie order changed within one service"
                    );
                    for (a, b) in first
                        .as_array()
                        .unwrap()
                        .iter()
                        .zip(second.as_array().unwrap())
                    {
                        ensure!(
                            a["metrics"]["non_myopic_member_rewards"]
                                == b["metrics"]["non_myopic_member_rewards"],
                            "pool rewards changed in aligned observations"
                        );
                        nonzero |= *stake > 0
                            && number(a, "/metrics/non_myopic_member_rewards/quantity")? > 0;
                    }
                }
                if !nonzero {
                    sleep(Duration::from_millis(200));
                    continue;
                }
                let public: Vec<_> = observations
                    .iter()
                    .map(|(stake, (a, b))| json!({"stake":stake,"first":a,"second":b}))
                    .collect();
                self.pool_proof("pools:ranking",json!({"node_tip_before":before,"node_tip_after":after,"distribution":distribution,"pool_state":state,"parameters":parameters,"queries":public}));
                break;
            }
            server.wallet_phase(serde_json::to_vec(&served_bad)?)?;
            self.pool_settings(json!("direct"))?;
            let good_id = text(&registrations[0], "/pool_id")?;
            let bad_id = text(&registrations[1], "/pool_id")?;
            let deadline = Instant::now() + self.timeout;
            let fetched = loop {
                server.check()?;
                let pools = self.pool_list(100_000_000)?;
                let rows = pools.as_array().context("metadata pools missing")?;
                let valid = rows
                    .iter()
                    .find(|p| p["id"] == good_id)
                    .context("valid metadata pool missing")?;
                let invalid = rows
                    .iter()
                    .find(|p| p["id"] == bad_id)
                    .context("invalid metadata pool missing")?;
                ensure!(
                    invalid.get("metadata").is_none(),
                    "mismatched metadata hash was accepted"
                );
                if let Some(actual) = valid.get("metadata") {
                    ensure!(actual == &good, "valid pool metadata differs");
                    if server.observed() {
                        break pools;
                    }
                }
                ensure!(
                    Instant::now() < deadline,
                    "metadata requests/fetch timed out"
                );
                sleep(Duration::from_millis(200));
            };
            let mut negative_observations = Vec::new();
            for _ in 0..3 {
                let height = options.node.height(self.timeout)?;
                options.node.advancing(height, self.timeout)?;
                let pools = self.pool_list(100_000_000)?;
                ensure!(
                    pools
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|p| p["id"] == good_id)
                        .context("good metadata disappeared")?["metadata"]
                        == good
                        && pools
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|p| p["id"] == bad_id)
                            .context("bad metadata pool disappeared")?
                            .get("metadata")
                            .is_none(),
                    "metadata hash controls changed after node advancement"
                );
                negative_observations.push(pools);
            }
            let mut maintenance = Vec::new();
            for source in ["direct", "none"] {
                let node_before = registrations
                    .iter()
                    .map(|r| {
                        options.node.utxos(
                            r["payment_address"]
                                .as_str()
                                .context("fixture address missing")?,
                            self.timeout,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?;
                self.pool_settings(json!(source))?;
                ensure!(
                    self.call("getSettings", "GET", "/settings", None, 200)?
                        == json!({"pool_metadata_source":source}),
                    "metadata source setting differs"
                );
                self.call(
                    "postMaintenanceAction",
                    "POST",
                    "/stake-pools/maintenance-actions",
                    Some(json!({"maintenance_action":"gc_stake_pools"})),
                    204,
                )?;
                let status = self.poll(
                    "getMaintenanceActions",
                    "/stake-pools/maintenance-actions",
                    |v| v == &json!({"gc_stake_pools":{"status":"not_applicable"}}),
                )?;
                let pools = self.pool_list(100_000_000)?;
                ensure!(
                    ids(&pools)?.into_iter().collect::<BTreeSet<_>>() == expected,
                    "maintenance changed pool identities"
                );
                if source == "none" {
                    ensure!(
                        pools
                            .as_array()
                            .unwrap()
                            .iter()
                            .all(|p| p.get("metadata").is_none()),
                        "none metadata mode retained metadata"
                    );
                }
                let node_after = registrations
                    .iter()
                    .map(|r| {
                        options.node.utxos(
                            r["payment_address"]
                                .as_str()
                                .context("fixture address missing")?,
                            self.timeout,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?;
                ensure!(
                    node_before == node_after,
                    "metadata maintenance spent fixture funds"
                );
                maintenance.push(
                    json!({"source":source,"status":status,"pools":pools,"node_utxos":node_after}),
                );
            }
            server.check()?;
            self.pool_proof("pools:metadata",json!({"registrations":registrations,"fetched":fetched,"hash_mismatch_after_advancement":negative_observations,"good_requests":server.good.load(Ordering::SeqCst),"bad_requests":server.bad.load(Ordering::SeqCst),"none":maintenance[1]["pools"]}));
            self.pool_proof("pools:maintenance", json!({"observations":maintenance}));
            let tip = options.node.query(&["tip"], self.timeout)?;
            let epoch = number(&tip, "/epoch")?
                .checked_add(3)
                .context("retirement epoch overflow")?;
            let retirement_path = pool_fixture::retire(
                &options.node,
                &directory.join("pool-3"),
                &workspace.join("registration-2"),
                epoch,
                &workspace.join("retirement-2"),
                self.timeout,
            )?;
            let retirement: Value = serde_json::from_slice(&fs::read(retirement_path)?)?;
            let deadline = Instant::now() + self.timeout;
            let retiring = loop {
                let pools = self.pool_list(100_000_000)?;
                let pool = pools
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|p| p["id"] == bad_id)
                    .context("pool disappeared before scheduled retirement was observed")?;
                if let Some(value) = pool.get("retirement") {
                    ensure!(
                        value["epoch_number"] == epoch,
                        "wallet retirement epoch differs"
                    );
                    break pools;
                }
                ensure!(
                    Instant::now() < deadline,
                    "wallet retirement never scheduled"
                );
                sleep(Duration::from_millis(200));
            };
            let scheduled = retiring
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["id"] == bad_id)
                .unwrap();
            let timestamp = text(scheduled, "/retirement/epoch_start_time")?;
            let native_timestamp = query_timestamp(&timestamp)?;
            let genesis: Value = serde_json::from_slice(&fs::read(
                options
                    .shelley_genesis
                    .as_ref()
                    .context("public Shelley genesis missing")?,
            )?)?;
            ensure!(
                genesis["networkMagic"] == 42,
                "pool genesis network differs"
            );
            let expected_slot = epoch
                .checked_mul(number(&genesis, "/epochLength")?)
                .context("retirement slot overflow")?;
            let byron: Value = serde_json::from_slice(&fs::read(
                options
                    .byron_genesis
                    .as_ref()
                    .context("public Byron genesis missing")?,
            )?)?;
            ensure!(
                byron["protocolConsts"]["protocolMagic"] == 42,
                "pool Byron genesis network differs"
            );
            let start = u128::from(number(&byron, "/startTime")?);
            ensure!(
                validity::rounded_posix_seconds(validity::utc_ns(&text(
                    &genesis,
                    "/systemStart"
                )?)?)
                    == start,
                "pool genesis starts disagree"
            );
            let slot_ps = validity::decimal_ps(&genesis["slotLength"])?;
            ensure!(
                slot_ps > 0 && slot_ps % 1000 == 0,
                "unsupported pool slot precision"
            );
            let expected_time = start
                .checked_mul(1_000_000_000)
                .and_then(|base| {
                    u128::from(expected_slot)
                        .checked_mul(slot_ps / 1000)
                        .and_then(|offset| base.checked_add(offset))
                })
                .context("retirement clock overflow")?;
            ensure!(
                validity::utc_ns(&timestamp)? == expected_time,
                "wallet retirement timestamp differs from public genesis clock"
            );
            let (_, hash) = crate::encoding::bech32(&bad_id)?;
            let node_scheduled = options.node.query(
                &["pool-state", "--all-stake-pools", "--output-json"],
                self.timeout,
            )?;
            ensure!(
                node_scheduled[hex::encode(hash)]["retiring"] == epoch,
                "node retirement certificate state differs"
            );
            let deadline = Instant::now() + self.timeout;
            let activated = loop {
                let tip = options.node.query(&["tip"], self.timeout)?;
                if number(&tip, "/epoch")? >= epoch {
                    break tip;
                }
                ensure!(
                    Instant::now() < deadline,
                    "actual retirement epoch not reached"
                );
                sleep(Duration::from_millis(200));
            };
            let slot = options
                .node
                .query(&["slot-number", &native_timestamp], self.timeout)?;
            ensure!(
                slot.as_u64() == Some(expected_slot),
                "wallet retirement timestamp differs from actual node epoch clock"
            );
            let active = options.node.stake_pools(self.timeout)?;
            ensure!(
                active
                    .as_array()
                    .context("node active pools missing")?
                    .contains(&json!(good_id))
                    && !active.as_array().unwrap().contains(&json!(bad_id)),
                "node retirement not activated"
            );
            let removed = self.poll("listStakePools", "/stake-pools?stake=100000000", |v| {
                v.as_array()
                    .is_some_and(|rows| rows.iter().all(|p| p["id"] != bad_id))
            })?;
            ensure!(
                ids(&removed)? == [good_id],
                "wallet survivor set differs after retirement"
            );
            self.pool_proof("pools:retirement",json!({"retirement":retirement,"scheduled_wallet":retiring,"scheduled_node":node_scheduled,"timestamp_node_slot":slot,"expected_slot":expected_slot,"activated_tip":activated,"node_active_pools":active,"wallet_after":removed}));
            Ok(())
        })();
        let restored = self.call(
            "putSettings",
            "PUT",
            "/settings",
            Some(json!({"settings":original})),
            204,
        );
        result?;
        restored?;
        ensure!(
            self.call("getSettings", "GET", "/settings", None, 200)? == original,
            "original pool settings not restored"
        );
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_timestamp_formatting_preserves_exact_instant_and_rejects_rounding() {
        let canonical = "2026-11-04T18:38:07Z";
        assert_eq!(query_timestamp(canonical).unwrap(), canonical);
        assert_eq!(
            query_timestamp("2026-11-04T18:38:07.000000Z").unwrap(),
            canonical
        );
        assert_eq!(
            query_timestamp("2026-11-04T18:38:07.000000000Z").unwrap(),
            canonical
        );
        assert!(query_timestamp("2026-11-04T18:38:07.000001Z").is_err());
        assert!(query_timestamp("2026-11-04T18:38:07.999999Z").is_err());
        assert!(query_timestamp("invalid").is_err());
    }
    #[test]
    fn stake_rounding_is_nearest_even_and_binary_rounding_is_exact() {
        assert_eq!(round_ratio(5, 2).unwrap(), 2);
        assert_eq!(round_ratio(7, 2).unwrap(), 4);
        assert!(round_ratio(1, 0).is_err());
        for (n, d, value) in [
            (0, 1, 0.0f64),
            (1, 1, 1.0),
            (1, 2, 0.5),
            (1, 3, 1.0 / 3.0),
            (3, 2, 1.5),
            (1, 10, 0.1),
        ] {
            assert_eq!(rational_double(n, d).unwrap().to_bits(), value.to_bits());
        }
        assert_eq!(
            rational_double(9_007_199_254_740_993, 9_007_199_254_740_992).unwrap(),
            1.0
        );
        assert_eq!(
            rational_double(9_007_199_254_740_995, 9_007_199_254_740_992)
                .unwrap()
                .to_bits(),
            1.0f64.to_bits() + 2
        );
        assert!(rational_double(1, 0).is_err());
    }
    #[test]
    fn pool_snapshot_rejects_fabricated_values_order_and_node_parameters() {
        let mut distribution = serde_json::Map::new();
        let mut state = serde_json::Map::new();
        let mut pools = Vec::new();
        for (key, reward, n) in [(1u8, 200, 1u64), (2, 100, 2)] {
            let bytes = vec![key; 28];
            let id = crate::encoding::bech32_encode("pool", &bytes).unwrap();
            distribution.insert(id.clone(), json!({"numerator":n,"denominator":100}));
            state.insert(hex::encode(bytes),json!({"poolParams":{"spsPledge":150,"spsCost":0,"spsMargin":0.1},"futurePoolParams":null}));
            pools.push(json!({"id":id,"pledge":{"quantity":150},"cost":{"quantity":0},"margin":{"quantity":10},"metrics":{"non_myopic_member_rewards":{"quantity":reward},"relative_stake":{"quantity":n},"saturation":rational_double(u128::from(n)*3,100).unwrap()}}));
        }
        let pools = Value::Array(pools);
        let distribution = Value::Object(distribution);
        let state = Value::Object(state);
        let expected = ids(&pools).unwrap().into_iter().collect();
        snapshot(&pools, &expected, &distribution, &state, 3, false).unwrap();
        let mut wrong = pools.clone();
        wrong.as_array_mut().unwrap().swap(0, 1);
        assert!(snapshot(&wrong, &expected, &distribution, &state, 3, false).is_err());
        for pointer in [
            "/0/pledge/quantity",
            "/0/metrics/saturation",
            "/0/metrics/relative_stake/quantity",
        ] {
            let mut wrong = pools.clone();
            *wrong.pointer_mut(pointer).unwrap() = json!(99);
            assert!(snapshot(&wrong, &expected, &distribution, &state, 3, false).is_err());
        }
        assert!(snapshot(&pools, &expected, &distribution, &state, 3, true).is_err());
    }
    #[test]
    fn metadata_server_really_serves_distinct_bodies_and_stops() {
        let server = MetadataServer::start(b"good".to_vec(), b"expected".to_vec()).unwrap();
        for (name, expected) in [("good", "good"), ("bad", "expected")] {
            assert_eq!(
                reqwest::blocking::get(server.url(name))
                    .unwrap()
                    .text()
                    .unwrap(),
                expected
            );
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        while !server.observed() {
            assert!(
                Instant::now() < deadline,
                "metadata server did not finish its response accounting"
            );
            sleep(Duration::from_millis(5));
        }
        server.check().unwrap();
        server.wallet_phase(b"different".to_vec()).unwrap();
        assert!(!server.observed());
        assert_eq!(server.good.load(Ordering::SeqCst), 0);
        assert_eq!(server.bad.load(Ordering::SeqCst), 0);
        for (name, expected) in [("good", "good"), ("bad", "different")] {
            assert_eq!(
                reqwest::blocking::get(server.url(name))
                    .unwrap()
                    .text()
                    .unwrap(),
                expected
            );
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        while !server.observed() {
            assert!(Instant::now() < deadline);
            sleep(Duration::from_millis(5));
        }
        let port = server.port;
        drop(server);
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    }
}
