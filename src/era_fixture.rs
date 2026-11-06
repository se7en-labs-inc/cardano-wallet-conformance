//! Directly owned node fixture for a genuinely scheduled Babbage→Conway boundary.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) fn read(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "fixture input is not a regular file"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(4_194_305)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4_194_304, "era fixture file exceeds4MiB");
    Ok(bytes)
}
pub(crate) fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}
pub(crate) fn save(path: &Path, value: &Value) -> Result<()> {
    write(path, &serde_json::to_vec_pretty(value)?)
}
pub(crate) fn directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
pub(crate) fn utc(seconds: u64) -> Result<String> {
    let seconds: libc::time_t = seconds.try_into()?;
    let mut time: libc::tm = unsafe { std::mem::zeroed() };
    ensure!(
        !unsafe { libc::gmtime_r(&seconds, &mut time) }.is_null(),
        "UTC timestamp outside supported range"
    );
    ensure!(
        (70..=200).contains(&time.tm_year),
        "fixture timestamp outside1970..2100"
    );
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        time.tm_year + 1900,
        time.tm_mon + 1,
        time.tm_mday,
        time.tm_hour,
        time.tm_min,
        time.tm_sec
    ))
}

const GENESIS: [(&str, &str); 5] = [
    ("ByronGenesisFile", "byron-genesis.json"),
    ("ShelleyGenesisFile", "shelley-genesis.json"),
    ("AlonzoGenesisFile", "alonzo-genesis.json"),
    ("ConwayGenesisFile", "conway-genesis.json"),
    ("DijkstraGenesisFile", "dijkstra-genesis.json"),
];
fn config(mut source: Value, root: &Path, fork_epoch: u64) -> Result<Value> {
    ensure!(
        (2..=10).contains(&fork_epoch),
        "controlled Conway epoch must be2..10"
    );
    ensure!(source.is_object(), "node configuration is not an object");
    for name in ["Shelley", "Allegra", "Mary", "Alonzo", "Babbage", "Conway"] {
        let field = format!("Test{name}HardForkAtEpoch");
        ensure!(
            source[&field] == 0,
            "source must be the native all-at-genesis fixture"
        );
    }
    ensure!(
        source.get("TestDijkstraHardForkAtEpoch").is_none()
            && source.get("TestDijkstraHardForkAtVersion").is_none(),
        "unexpected scheduled Dijkstra fork"
    );
    for (field, file) in GENESIS {
        ensure!(source[field].is_string(), "source genesis path missing");
        source[field] = json!(root.join(file));
        source
            .as_object_mut()
            .unwrap()
            .remove(&field.replace("File", "Hash"));
    }
    source["TestConwayHardForkAtEpoch"] = json!(fork_epoch);
    Ok(source)
}

struct OwnedNode {
    child: Option<Child>,
    pid: u32,
}
impl OwnedNode {
    fn live(&mut self) -> Result<()> {
        ensure!(
            self.child
                .as_mut()
                .context("node handle is closed")?
                .try_wait()?
                .is_none(),
            "owned era fixture node exited unexpectedly"
        );
        Ok(())
    }
    fn stop(&mut self) -> Result<Value> {
        if let Some(child) = self.child.as_mut() {
            if child.try_wait()?.is_none() {
                // Still an unreaped, directly owned Child: the PID cannot be reused here.
                ensure!(
                    unsafe { libc::kill(self.pid as i32, libc::SIGTERM) } == 0,
                    "cannot terminate owned era node"
                );
                let deadline = Instant::now() + Duration::from_secs(3);
                while child.try_wait()?.is_none() && Instant::now() < deadline {
                    sleep(Duration::from_millis(20));
                }
                if child.try_wait()?.is_none() {
                    child.kill()?;
                }
            }
            let status = child.wait()?;
            self.child.take();
            return Ok(json!({"pid":self.pid,"stopped_and_reaped":true,"exit_code":status.code()}));
        }
        anyhow::bail!("owned era node already closed")
    }
}
impl Drop for OwnedNode {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub struct Options<'a> {
    pub base_cluster: &'a Path,
    pub workspace: &'a Path,
    pub node_executable: &'a Path,
    pub cli_executable: &'a Path,
    pub conway_epoch: u64,
    pub timeout: Duration,
}

/// Fixture audit only; no wallet obligation is closed by observing a node fork.
pub fn audit(options: Options<'_>) -> Result<PathBuf> {
    struct NoWallet;
    impl Observer for NoWallet {}
    drive(options, &mut NoWallet)
}

pub(crate) trait Observer {
    fn funding(&mut self, _cli: &Path, _root: &Path) -> Result<Option<(String, u64)>> {
        Ok(None)
    }
    fn before(
        &mut self,
        _node: &crate::node::NodeOracle,
        _root: &Path,
        _tip: &Value,
    ) -> Result<Value> {
        Ok(Value::Null)
    }
    fn after(
        &mut self,
        _node: &crate::node::NodeOracle,
        _root: &Path,
        _tip: &Value,
    ) -> Result<Value> {
        Ok(Value::Null)
    }
}

pub(crate) fn drive(options: Options<'_>, observer: &mut impl Observer) -> Result<PathBuf> {
    let Options {
        base_cluster,
        workspace,
        node_executable,
        cli_executable,
        conway_epoch,
        timeout,
    } = options;
    ensure!(
        base_cluster.is_absolute() && workspace.is_absolute() && !workspace.exists(),
        "era fixture needs an explicit base and fresh absolute workspace"
    );
    let base = base_cluster.canonicalize()?;
    ensure!(
        !fs::symlink_metadata(base_cluster)?.file_type().is_symlink(),
        "era fixture base must not be a symlink"
    );
    ensure!(
        !base.starts_with("/nix/store"),
        "refusing source-store traversal"
    );
    ensure!(
        node_executable.is_absolute() && cli_executable.is_absolute(),
        "fixture executable paths must be absolute"
    );
    directory(workspace)?;
    let root = workspace.canonicalize()?;
    let public = root.join("public");
    directory(&public)?;
    let extra_funding = observer.funding(cli_executable, &root)?;
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .checked_add(20)
        .context("genesis time overflow")?;
    let mut genesis = json!({});
    for (_, file) in GENESIS {
        let mut value: Value = serde_json::from_slice(&read(&base.join(file))?)?;
        if file == "byron-genesis.json" {
            ensure!(
                value["protocolConsts"]["protocolMagic"] == 42,
                "Byron fixture is not magic42"
            );
            value["startTime"] = json!(start);
        }
        if file == "shelley-genesis.json" {
            ensure!(
                value["networkMagic"] == 42
                    && value["epochLength"] == 120
                    && value["slotLength"] == json!(0.2)
                    && value["staking"]["pools"]
                        .as_object()
                        .is_some_and(|v| v.len() == 4)
                    && value["staking"]["stake"]
                        .as_object()
                        .is_some_and(|v| v.len() == 4)
                    && value["protocolParams"]["protocolVersion"] == json!({"major":12,"minor":0}),
                "source cluster slotting/stake/protocol fixture differs"
            );
            value["systemStart"] = json!(utc(start)?);
            if let Some((address, amount)) = &extra_funding {
                let bytes = hex::decode(address)?;
                ensure!(
                    bytes.len() == 29 && bytes[0] == 0x60 && *amount >= 1_000_000,
                    "extra genesis funding must be a valid testnet enterprise allocation"
                );
                let funds = value["initialFunds"]
                    .as_object_mut()
                    .context("genesis initial funds missing")?;
                ensure!(
                    !funds.contains_key(address),
                    "extra genesis allocation is not fresh"
                );
                funds.insert(address.clone(), json!(amount));
                let total = funds.values().try_fold(0u128, |sum, v| {
                    Ok::<_, anyhow::Error>(
                        sum + u128::from(v.as_u64().context("invalid genesis coin")?),
                    )
                })?;
                ensure!(
                    total
                        <= u128::from(
                            value["maxLovelaceSupply"]
                                .as_u64()
                                .context("genesis supply missing")?
                        ),
                    "extra genesis allocation exceeds total supply"
                );
            }
        }
        save(&root.join(file), &value)?;
        genesis[file] = json!({"sha256":hex::encode(Sha256::digest(read(&root.join(file))?)),"source_sha256":hex::encode(Sha256::digest(read(&base.join(file))?))});
    }
    let mut reservations = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..5 {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        ports.push(listener.local_addr()?.port());
        reservations.push(listener);
    }
    let names = ["pool-1", "pool-2", "pool-3", "pool-4", "relay"];
    let mut launches = Vec::new();
    let mut configurations = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let source_directory = fs::symlink_metadata(base.join(name))?;
        ensure!(
            source_directory.is_dir() && !source_directory.file_type().is_symlink(),
            "era fixture node directory must not be a symlink"
        );
        let dir = root.join(name);
        directory(&dir)?;
        let original = if *name == "relay" {
            "node-relay-config.yaml".to_owned()
        } else {
            "node-config.yaml".to_owned()
        };
        let source: Value = serde_yaml::from_slice(&read(&base.join(name).join(original))?)?;
        let configuration = config(source, &root, conway_epoch)?;
        save(&dir.join("config.json"), &configuration)?;
        let peers: Vec<_> = ports
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != index)
            .map(|(_, p)| json!({"address":"127.0.0.1","port":p}))
            .collect();
        save(
            &dir.join("topology.json"),
            &json!({"localRoots":[{"accessPoints":peers,"advertise":false,"valency":4}],"publicRoots":[],"useLedgerAfterSlot":-1}),
        )?;
        let mut args: Vec<String> = vec![
            "run".into(),
            "--config".into(),
            dir.join("config.json").display().to_string(),
            "--topology".into(),
            dir.join("topology.json").display().to_string(),
            "--database-path".into(),
            dir.join("database").display().to_string(),
            "--port".into(),
            ports[index].to_string(),
        ];
        if *name == "relay" {
            args.extend([
                "--socket-path".into(),
                root.join("node.socket").display().to_string(),
            ]);
        } else {
            for (file, flag) in [
                ("op.cert", "--shelley-operational-certificate"),
                ("kes.prv", "--shelley-kes-key"),
                ("vrf.prv", "--shelley-vrf-key"),
            ] {
                write(&dir.join(file), &read(&base.join(name).join(file))?)?;
                args.extend([flag.into(), dir.join(file).display().to_string()]);
            }
        }
        args.extend(["+RTS".into(), "-N2".into(), "-RTS".into()]);
        configurations.push(json!({"name":name,"port":ports[index],"configuration":configuration}));
        launches.push((dir, args));
    }
    save(
        &public.join("configuration.json"),
        &json!({"source_cluster":base,"genesis":genesis,"start_time":start,
        "scheduled_conway_epoch":conway_epoch,"nodes":configurations,"counts_as_conformance_evidence":false}),
    )?;
    drop(reservations);
    let mut children = Vec::new();
    for (dir, args) in launches {
        let log = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(dir.join("private-node.log"))?;
        let child = Command::new(node_executable)
            .args(&args)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        let pid = child.id();
        children.push(OwnedNode {
            child: Some(child),
            pid,
        });
        save(
            &public.join(format!("launch-{pid}.json")),
            &json!({"pid":pid,"executable":node_executable,"arguments":args}),
        )?;
    }
    let node = crate::node::NodeOracle {
        executable: cli_executable.to_owned(),
        socket: root.join("node.socket"),
        network_magic: 42,
    };
    let deadline = Instant::now() + timeout;
    let before = loop {
        for child in &mut children {
            child.live()?;
        }
        ensure!(
            Instant::now() < deadline,
            "Babbage fixture startup timed out"
        );
        if node.socket.exists() {
            match node.query(&["tip"], Duration::from_secs(5)) {
                Ok(tip) => {
                    ensure!(tip.is_object(), "node tip is not an object");
                    if tip["block"].as_u64().is_some() {
                        ensure!(
                            tip["era"] == "Babbage"
                                && tip["epoch"].as_u64().is_some_and(|e| e < conway_epoch),
                            "first advancing node tip is not before scheduled Conway"
                        );
                        break tip;
                    }
                    ensure!(
                        tip["block"].is_null() && tip["slot"].is_null(),
                        "malformed initial node tip"
                    );
                }
                Err(error) if error.to_string() == "trusted node query failed" => {}
                Err(error) => return Err(error),
            }
        }
        sleep(Duration::from_millis(200));
    };
    let parameters_before = node.protocol_parameters(Duration::from_secs(10))?;
    save(
        &public.join("before.json"),
        &json!({"tip":before,"parameters":parameters_before}),
    )?;
    let wallet_before = observer.before(&node, &root, &before)?;
    let after = loop {
        for child in &mut children {
            child.live()?;
        }
        ensure!(
            Instant::now() < deadline,
            "scheduled Conway transition timed out"
        );
        let tip = node.query(&["tip"], Duration::from_secs(5))?;
        let epoch = tip["epoch"]
            .as_u64()
            .context("node transition epoch missing")?;
        ensure!(
            tip["era"] == "Babbage" || tip["era"] == "Conway",
            "unexpected fixture era"
        );
        if tip["era"] == "Conway" {
            ensure!(
                epoch >= conway_epoch
                    && tip["block"].as_u64() > before["block"].as_u64()
                    && tip["slot"].as_u64() > before["slot"].as_u64(),
                "hard fork did not advance on the same chain"
            );
            break tip;
        }
        ensure!(
            epoch < conway_epoch,
            "node remained Babbage beyond scheduled fork"
        );
        sleep(Duration::from_millis(200));
    };
    let parameters_after = node.protocol_parameters(Duration::from_secs(10))?;
    let wallet_after = observer.after(&node, &root, &after)?;
    let mut stopped = Vec::new();
    for child in &mut children {
        stopped.push(child.stop()?);
    }
    let receipt = json!({"format_version":1,"kind":"scheduled-era-fixture-audit","suite_sha256":crate::report::suite_sha256(),
        "counts_as_conformance_evidence":false,"conway_epoch":conway_epoch,"before":before,"after":after,
        "parameters_before":parameters_before,"parameters_after":parameters_after,"stopped_children":stopped,
        "wallet_before":wallet_before,"wallet_after":wallet_after});
    let path = public.join("receipt.json");
    save(&path, &receipt)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utc_preserves_integer_seconds_and_leap_day() {
        assert_eq!(utc(0).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(utc(1_709_164_800).unwrap(), "2024-02-29T00:00:00Z");
        assert!(utc(u64::MAX).is_err());
    }
    #[test]
    fn scheduled_config_preserves_unrelated_fields_and_rejects_other_forks() {
        let mut source = json!({"unrelated":{"preserve":true},"Protocol":"Cardano"});
        for name in ["Shelley", "Allegra", "Mary", "Alonzo", "Babbage", "Conway"] {
            source[format!("Test{name}HardForkAtEpoch")] = json!(0);
        }
        for (field, _) in GENESIS {
            source[field] = json!("old");
            source[field.replace("File", "Hash")] = json!("oldhash");
        }
        let after = config(source.clone(), Path::new("/fixture"), 3).unwrap();
        assert_eq!(after["unrelated"], source["unrelated"]);
        assert_eq!(after["TestConwayHardForkAtEpoch"], 3);
        assert!(after.get("ByronGenesisHash").is_none());
        assert!(config(source.clone(), Path::new("/fixture"), 0).is_err());
        source["TestDijkstraHardForkAtEpoch"] = json!(0);
        assert!(config(source, Path::new("/fixture"), 3).is_err());
    }
}
