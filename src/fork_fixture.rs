//! Directly owned native branches from a closed common relay database.
//! Fixture preparation alone never earns wallet conformance credit.
use crate::{
    era_fixture::{directory, read, save, write},
    node::{NodeOracle, Tip},
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    net::TcpListener,
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const GENESIS: [(&str, &str); 5] = [
    ("ByronGenesisFile", "byron-genesis.json"),
    ("ShelleyGenesisFile", "shelley-genesis.json"),
    ("AlonzoGenesisFile", "alonzo-genesis.json"),
    ("ConwayGenesisFile", "conway-genesis.json"),
    ("DijkstraGenesisFile", "dijkstra-genesis.json"),
];
const COPY_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
const FILE_LIMIT: u64 = 100_000;

fn control(child: &Child, signal: i32) -> Result<()> {
    // A directly owned unreaped Child keeps this PID from being reused.
    ensure!(
        unsafe { libc::kill(child.id() as i32, signal) } == 0,
        "cannot signal owned native child: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
fn state(child: &Child) -> Result<char> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", child.id()))?;
    let (_, fields) = stat
        .rsplit_once(") ")
        .context("invalid native child process state")?;
    fields
        .chars()
        .next()
        .context("missing native child process state")
}
struct NativeNode {
    child: Option<Child>,
    producer: bool,
}
impl NativeNode {
    fn stop(&mut self, graceful: bool) -> Result<Value> {
        let Some(child) = self.child.as_mut() else {
            return Ok(json!({"already_stopped":true}));
        };
        let pid = child.id();
        let mut forced = false;
        if child.try_wait()?.is_none() {
            if let Err(error) = control(child, libc::SIGTERM) {
                if child.try_wait()?.is_none() {
                    return Err(error);
                }
            }
            if let Err(error) = control(child, libc::SIGCONT) {
                if child.try_wait()?.is_none() {
                    return Err(error);
                }
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            while child.try_wait()?.is_none() && Instant::now() < deadline {
                sleep(Duration::from_millis(20));
            }
            if child.try_wait()?.is_none() {
                forced = true;
                child.kill()?;
            }
        }
        let status = child.wait()?;
        self.child.take();
        ensure!(
            !graceful || (!forced && status.success()),
            "native child did not shut down cleanly; refusing database snapshot"
        );
        Ok(json!({"pid":pid,"forced":forced,"exit_code":status.code(),"stopped_and_reaped":true}))
    }
}
impl Drop for NativeNode {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub struct Branch {
    root: PathBuf,
    nodes: Vec<NativeNode>,
    pub node: NodeOracle,
    stopped: bool,
}
pub struct Pause<'a> {
    nodes: Vec<&'a Child>,
}
impl Pause<'_> {
    pub fn resume(mut self) -> Result<()> {
        for child in &self.nodes {
            control(child, libc::SIGCONT)?;
        }
        self.nodes.clear();
        Ok(())
    }
}
impl Drop for Pause<'_> {
    fn drop(&mut self) {
        for child in &self.nodes {
            let _ = control(child, libc::SIGCONT);
        }
    }
}
/// Constructible only after successful graceful shutdown of all owned seed nodes.
pub struct ClosedSnapshot {
    database: PathBuf,
    pub tip: Tip,
    pub stopped_nodes: Vec<Value>,
}
impl Branch {
    pub fn ensure_running(&mut self) -> Result<()> {
        ensure!(!self.stopped, "native branch is stopped");
        for node in &mut self.nodes {
            ensure!(
                node.child
                    .as_mut()
                    .context("native node closed")?
                    .try_wait()?
                    .is_none(),
                "native branch child exited"
            );
        }
        Ok(())
    }
    pub fn pause(&self, timeout: Duration) -> Result<Pause<'_>> {
        ensure!(!self.stopped, "native branch is stopped");
        let mut guard = Pause { nodes: Vec::new() };
        for node in self.nodes.iter().filter(|node| node.producer) {
            let child = node.child.as_ref().context("native producer closed")?;
            ensure!(
                !matches!(state(child)?, 'Z' | 'X'),
                "native producer already dead"
            );
            control(child, libc::SIGSTOP)?;
            guard.nodes.push(child);
        }
        let deadline = Instant::now() + timeout;
        loop {
            if guard
                .nodes
                .iter()
                .map(|child| state(child))
                .collect::<Result<Vec<_>>>()?
                .iter()
                .all(|state| *state == 'T')
            {
                return Ok(guard);
            }
            ensure!(Instant::now() < deadline, "native producers did not pause");
            sleep(Duration::from_millis(10));
        }
    }
    pub fn ready(&mut self, timeout: Duration) -> Result<Tip> {
        let deadline = Instant::now() + timeout;
        loop {
            self.ensure_running()?;
            if self.node.socket.exists() {
                match self.node.query(&["tip"], Duration::from_secs(5)) {
                    Ok(value) if value["block"].as_u64().is_some_and(|height| height > 0) => {
                        return self.node.tip(Duration::from_secs(5))
                    }
                    Ok(value) => {
                        ensure!(
                            value.is_object()
                                && ((value["block"].is_null() && value["slot"].is_null())
                                    || value["block"].as_u64() == Some(0)),
                            "malformed initial native branch tip"
                        );
                    }
                    Err(error) if error.to_string() == "trusted node query failed" => {}
                    Err(error) => return Err(error),
                }
            }
            ensure!(Instant::now() < deadline, "native branch readiness timeout");
            sleep(Duration::from_millis(100));
        }
    }
    /// Freeze production and close the relay first; no live database is copied.
    pub fn close_for_snapshot(&mut self, timeout: Duration) -> Result<ClosedSnapshot> {
        self.ensure_running()?;
        let result = (|| -> Result<ClosedSnapshot> {
            for node in self.nodes.iter().filter(|node| node.producer) {
                control(node.child.as_ref().unwrap(), libc::SIGSTOP)?;
            }
            let deadline = Instant::now() + timeout;
            loop {
                if self
                    .nodes
                    .iter()
                    .filter(|node| node.producer)
                    .map(|node| state(node.child.as_ref().unwrap()))
                    .collect::<Result<Vec<_>>>()?
                    .iter()
                    .all(|state| *state == 'T')
                {
                    break;
                }
                ensure!(
                    Instant::now() < deadline,
                    "common native producers did not freeze"
                );
                sleep(Duration::from_millis(10));
            }
            let mut tip = self.node.tip(timeout)?;
            let mut stable = 0;
            while stable < 3 {
                sleep(Duration::from_millis(200));
                let next = self.node.tip(timeout)?;
                if next.hash == tip.hash && next.slot == tip.slot && next.height == tip.height {
                    stable += 1;
                } else {
                    stable = 0;
                    tip = next;
                }
                ensure!(Instant::now() < deadline, "common relay did not stabilize");
            }
            // Relay first, then producers. Every DB has closed before a snapshot token exists.
            let mut stopped_nodes = Vec::new();
            for node in self.nodes.iter_mut().filter(|node| !node.producer) {
                stopped_nodes.push(node.stop(true)?);
            }
            for node in self.nodes.iter_mut().filter(|node| node.producer) {
                stopped_nodes.push(node.stop(true)?);
            }
            self.stopped = true;
            Ok(ClosedSnapshot {
                database: self.root.join("relay/database"),
                tip,
                stopped_nodes,
            })
        })();
        if result.is_err() {
            for node in &self.nodes {
                if let Some(child) = &node.child {
                    let _ = control(child, libc::SIGCONT);
                }
            }
        }
        result
    }
    pub fn stop(&mut self) -> Result<Value> {
        let mut receipts = Vec::new();
        let mut error = None;
        for node in &mut self.nodes {
            match node.stop(false) {
                Ok(value) => receipts.push(value),
                Err(failure) => error = Some(failure),
            }
        }
        if let Some(error) = error {
            return Err(error);
        }
        self.stopped = true;
        Ok(json!({"nodes":receipts,"stopped_and_reaped":true}))
    }
}
impl Drop for Branch {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn copy_closed_tree(source: &Path, destination: &Path) -> Result<()> {
    fn copy(
        source: &Path,
        destination: &Path,
        bytes: &mut u64,
        files: &mut u64,
        depth: usize,
    ) -> Result<()> {
        ensure!(depth <= 16, "native snapshot depth exceeded");
        let metadata = fs::symlink_metadata(source)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "native snapshot symlink refused"
        );
        if metadata.is_dir() {
            directory(destination)?;
            for entry in fs::read_dir(source)? {
                let entry = entry?;
                copy(
                    &entry.path(),
                    &destination.join(entry.file_name()),
                    bytes,
                    files,
                    depth + 1,
                )?;
            }
        } else {
            ensure!(
                metadata.is_file(),
                "native snapshot is not a regular file/directory"
            );
            *bytes = bytes
                .checked_add(metadata.len())
                .context("snapshot byte count overflow")?;
            *files = files
                .checked_add(1)
                .context("snapshot file count overflow")?;
            ensure!(
                *bytes <= COPY_LIMIT && *files <= FILE_LIMIT,
                "native snapshot copy limit exceeded"
            );
            let mut input = fs::File::open(source)?;
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(destination)?;
            ensure!(
                std::io::copy(&mut input, &mut output)? == metadata.len(),
                "native snapshot file changed while copying"
            );
            output.flush()?;
        }
        Ok(())
    }
    ensure!(
        source.is_absolute()
            && destination.is_absolute()
            && !source.starts_with("/nix/store")
            && !destination.starts_with("/nix/store"),
        "native snapshot requires explicit non-store paths"
    );
    ensure!(
        !fs::symlink_metadata(source)?.file_type().is_symlink(),
        "native snapshot root symlink refused"
    );
    let resolved = source.canonicalize()?;
    let parent = destination
        .parent()
        .context("snapshot destination parent missing")?
        .canonicalize()?;
    ensure!(
        !resolved.starts_with("/nix/store") && !parent.starts_with("/nix/store"),
        "snapshot resolves into source store"
    );
    let destination = parent.join(
        destination
            .file_name()
            .context("snapshot destination name missing")?,
    );
    ensure!(
        !destination.starts_with(&resolved) && !resolved.starts_with(&destination),
        "snapshot source/destination overlap"
    );
    copy(&resolved, &destination, &mut 0, &mut 0, 0)
}
fn node_config(mut source: Value, genesis: &Path) -> Result<Value> {
    ensure!(
        source["Protocol"] == "Cardano",
        "native source protocol differs"
    );
    for era in ["Shelley", "Allegra", "Mary", "Alonzo", "Babbage", "Conway"] {
        ensure!(
            source[format!("Test{era}HardForkAtEpoch")] == 0,
            "native fork source must start in Conway"
        );
    }
    ensure!(
        source.get("TestDijkstraHardForkAtEpoch").is_none()
            && source.get("TestDijkstraHardForkAtVersion").is_none(),
        "unexpected native Dijkstra boundary"
    );
    for (field, file) in GENESIS {
        ensure!(source[field].is_string(), "native genesis path missing");
        source[field] = json!(genesis.join(file));
        source
            .as_object_mut()
            .unwrap()
            .remove(&field.replace("File", "Hash"));
    }
    Ok(source)
}
fn topology(ports: &[u16], index: usize) -> Value {
    let peers: Vec<_> = ports
        .iter()
        .enumerate()
        .filter(|(other, _)| *other != index)
        .map(|(_, port)| json!({"address":"127.0.0.1","port":port}))
        .collect();
    json!({"localRoots":[{"accessPoints":peers,"advertise":false,"valency":peers.len()}],"publicRoots":[],"useLedgerAfterSlot":-1})
}
pub struct Fixture {
    root: PathBuf,
    base: PathBuf,
    genesis: PathBuf,
}
impl Fixture {
    /// The caller supplies a public enterprise address for its private isolated funder.
    pub fn prepare(base: &Path, workspace: &Path, funder_hex: &str, coin: u64) -> Result<Self> {
        ensure!(
            base.is_absolute()
                && workspace.is_absolute()
                && !base.starts_with("/nix/store")
                && !workspace.starts_with("/nix/store"),
            "fork fixture needs explicit non-store paths"
        );
        ensure!(
            !fs::symlink_metadata(base)?.file_type().is_symlink(),
            "fork base symlink refused"
        );
        let base = base.canonicalize()?;
        ensure!(
            !base.starts_with("/nix/store"),
            "fork base resolves into source store"
        );
        let address = hex::decode(funder_hex)?;
        ensure!(
            address.len() == 29 && address[0] == 0x60 && coin >= 1_000_000,
            "fork funder allocation differs"
        );
        directory(workspace)?;
        let root = workspace.canonicalize()?;
        let genesis = root.join("genesis");
        directory(&genesis)?;
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .checked_add(20)
            .context("fork genesis time overflow")?;
        let mut receipts = Vec::new();
        for (_, file) in GENESIS {
            let bytes = read(&base.join(file))?;
            let mut value: Value = serde_json::from_slice(&bytes)?;
            if file == "byron-genesis.json" {
                ensure!(
                    value["protocolConsts"]["protocolMagic"] == 42,
                    "fork Byron network differs"
                );
                value["startTime"] = json!(start);
            }
            if file == "shelley-genesis.json" {
                ensure!(
                    value["networkMagic"] == 42
                        && value["protocolParams"]["protocolVersion"]
                            == json!({"major":12,"minor":0}),
                    "native fork genesis network/era differs"
                );
                let maximum = value["maxLovelaceSupply"]
                    .as_u64()
                    .context("native genesis supply missing")?;
                let funds = value["initialFunds"]
                    .as_object_mut()
                    .context("native genesis funds missing")?;
                ensure!(
                    !funds.contains_key(funder_hex),
                    "native fork funder not fresh"
                );
                funds.insert(funder_hex.into(), json!(coin));
                let total = funds.values().try_fold(0u128, |total, value| {
                    Ok::<_, anyhow::Error>(
                        total + u128::from(value.as_u64().context("invalid genesis allocation")?),
                    )
                })?;
                ensure!(
                    total <= u128::from(maximum),
                    "fork genesis allocations exceed supply"
                );
                value["systemStart"] = json!(crate::era_fixture::utc(start)?);
            }
            // One declared future start for all branches; other protocol fields remain pinned.
            save(&genesis.join(file), &value)?;
            receipts.push(json!({"file":file,"source_sha256":hex::encode(Sha256::digest(bytes)),"sha256":hex::encode(Sha256::digest(read(&genesis.join(file))?))}));
        }
        save(
            &root.join("genesis-provenance.json"),
            &json!({"kind":"native-fork-fixture","genesis":receipts,"funder_address_hex":funder_hex,"allocation":coin,"counts_as_conformance_evidence":false}),
        )?;
        Ok(Self {
            root,
            base,
            genesis,
        })
    }
    pub fn genesis(&self) -> &Path {
        &self.genesis
    }
    pub fn seed(&self, node: &Path, cli: &Path) -> Result<Branch> {
        self.start("seed", &[1, 2, 3, 4], node, cli, None)
    }
    pub fn branches(
        &self,
        snapshot: &ClosedSnapshot,
        node: &Path,
        cli: &Path,
    ) -> Result<(Branch, Branch)> {
        ensure!(
            snapshot.database == self.root.join("seed/relay/database"),
            "snapshot does not belong to this owned fixture"
        );
        let a = self.start("branch-a", &[1], node, cli, Some(snapshot))?;
        let b = self.start("branch-b", &[2, 3, 4], node, cli, Some(snapshot))?;
        Ok((a, b))
    }
    fn start(
        &self,
        name: &str,
        producers: &[usize],
        executable: &Path,
        cli: &Path,
        snapshot: Option<&ClosedSnapshot>,
    ) -> Result<Branch> {
        ensure!(
            executable.is_absolute() && executable.is_file() && cli.is_absolute() && cli.is_file(),
            "native fixture executables must be absolute files"
        );
        let root = self.root.join(name);
        directory(&root)?;
        let mut reservations = Vec::new();
        let mut ports = Vec::new();
        for _ in 0..producers.len() + 1 {
            let listener = TcpListener::bind(("127.0.0.1", 0))?;
            ports.push(listener.local_addr()?.port());
            reservations.push(listener);
        }
        let mut names: Vec<_> = producers
            .iter()
            .map(|index| format!("pool-{index}"))
            .collect();
        names.push("relay".into());
        let mut launches = Vec::new();
        let mut configurations = Vec::new();
        for (index, name) in names.iter().enumerate() {
            let dir = root.join(name);
            directory(&dir)?;
            let producer = name != "relay";
            let config_path = self.base.join(name).join(if producer {
                "node-config.yaml"
            } else {
                "node-relay-config.yaml"
            });
            let config = node_config(serde_yaml::from_slice(&read(&config_path)?)?, &self.genesis)?;
            let peers = topology(&ports, index);
            save(&dir.join("config.json"), &config)?;
            save(&dir.join("topology.json"), &peers)?;
            if let Some(snapshot) = snapshot {
                copy_closed_tree(&snapshot.database, &dir.join("database"))?;
            }
            let mut args = vec![
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
            if producer {
                for (file, flag) in [
                    ("op.cert", "--shelley-operational-certificate"),
                    ("kes.prv", "--shelley-kes-key"),
                    ("vrf.prv", "--shelley-vrf-key"),
                ] {
                    write(&dir.join(file), &read(&self.base.join(name).join(file))?)?;
                    args.extend([flag.into(), dir.join(file).display().to_string()]);
                }
            } else {
                args.extend([
                    "--socket-path".into(),
                    root.join("node.socket").display().to_string(),
                ]);
            }
            args.extend(["+RTS".into(), "-N2".into(), "-RTS".into()]);
            configurations.push(json!({"node":name,"producer":producer,"port":ports[index],"topology":peers,"configuration":config}));
            launches.push((dir, producer, args));
        }
        save(
            &root.join("public-configuration.json"),
            &json!({"branch":name,"genesis":self.genesis,"nodes":configurations,"common_tip":snapshot.map(|snapshot|json!({"hash":snapshot.tip.hash,"slot":snapshot.tip.slot,"height":snapshot.tip.height})),"counts_as_conformance_evidence":false}),
        )?;
        drop(reservations);
        let mut nodes = Vec::new();
        for (dir, producer, args) in launches {
            let log = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dir.join("private-node.log"))?;
            let child = Command::new(executable)
                .args(args)
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn()?;
            nodes.push(NativeNode {
                child: Some(child),
                producer,
            });
        }
        Ok(Branch {
            root: root.clone(),
            nodes,
            node: NodeOracle {
                executable: cli.into(),
                socket: root.join("node.socket"),
                network_magic: 42,
            },
            stopped: false,
        })
    }
}

/// Control audit only: no wallet is involved and no644 obligation is credited.
pub fn audit(
    base: &Path,
    workspace: &Path,
    node: &Path,
    cli: &Path,
    timeout: Duration,
) -> Result<PathBuf> {
    ensure!(
        workspace.is_absolute() && !workspace.exists(),
        "native fork audit workspace must be fresh/absolute"
    );
    directory(workspace)?;
    let key = workspace.join("private-funder.skey");
    let public = workspace.join("funder.vkey");
    crate::pool_fixture::run(
        Command::new(cli)
            .args(["conway", "address", "key-gen", "--verification-key-file"])
            .arg(&public)
            .arg("--signing-key-file")
            .arg(&key),
        timeout,
    )?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
    let raw = crate::protocol_update::public_key(&public)?.1;
    let mut address = vec![0x60];
    address.extend(crate::transaction::blake2b(&raw, 28)?);
    let encoded = crate::encoding::bech32_encode("addr_test", &address)?;
    let fixture = Fixture::prepare(
        base,
        &workspace.join("native"),
        &hex::encode(&address),
        3_000_000_000,
    )?;
    let mut seed = fixture.seed(node, cli)?;
    let initial = seed.ready(timeout)?;
    seed.node.advancing(initial.height, timeout)?;
    let seed_funding = seed.node.utxos(&encoded, timeout)?;
    ensure!(
        seed_funding
            .as_object()
            .is_some_and(|entries| entries.len() == 1)
            && seed_funding
                .as_object()
                .unwrap()
                .values()
                .all(|output| output["address"] == encoded
                    && output["value"] == json!({"lovelace":3_000_000_000u64})),
        "native seed genesis allocation differs"
    );
    let snapshot = seed.close_for_snapshot(timeout)?;
    let (mut a, mut b) = fixture.branches(&snapshot, node, cli)?;
    a.ready(timeout)?;
    b.ready(timeout)?;
    let deadline = Instant::now() + timeout;
    let (tip_a, tip_b) = loop {
        a.ensure_running()?;
        b.ensure_running()?;
        let tip_a = a.node.tip(timeout)?;
        let tip_b = b.node.tip(timeout)?;
        if tip_a.height > snapshot.tip.height + 1
            && tip_b.height > tip_a.height
            && tip_b.hash != tip_a.hash
        {
            break (tip_a, tip_b);
        }
        ensure!(
            Instant::now() < deadline,
            "isolated native branches did not diverge/advance"
        );
        sleep(Duration::from_millis(200));
    };
    let funds_a = a.node.utxos(&encoded, timeout)?;
    let funds_b = b.node.utxos(&encoded, timeout)?;
    ensure!(
        funds_a == seed_funding && funds_b == seed_funding,
        "native fork changed common genesis inputs"
    );
    let stopped_a = a.stop()?;
    let stopped_b = b.stop()?;
    let receipt = workspace.join("receipt.json");
    save(
        &receipt,
        &json!({"format_version":1,"kind":"native-fork-control-audit","suite_sha256":crate::report::suite_sha256(),"counts_as_conformance_evidence":false,"harness_self_test":true,"common_tip":{"height":snapshot.tip.height,"slot":snapshot.tip.slot,"hash":snapshot.tip.hash},"branch_a":{"height":tip_a.height,"slot":tip_a.slot,"hash":tip_a.hash,"producers":[1]},"branch_b":{"height":tip_b.height,"slot":tip_b.slot,"hash":tip_b.hash,"producers":[2,3,4]},"public_funder":encoded,"common_inputs":seed_funding,"branch_a_inputs":funds_a,"branch_b_inputs":funds_b,"cleanup_a":stopped_a,"cleanup_b":stopped_b}),
    )?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn closed_snapshot_copy_is_independent_private_and_refuses_symlinks_or_overlap() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("closed");
        directory(&source).unwrap();
        directory(&source.join("ledger")).unwrap();
        write(&source.join("ledger/state"), b"closed-common-ledger").unwrap();
        let destination = root.path().join("copy");
        copy_closed_tree(&source, &destination).unwrap();
        assert_eq!(
            fs::read(destination.join("ledger/state")).unwrap(),
            b"closed-common-ledger"
        );
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(destination.join("ledger/state"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::write(destination.join("ledger/state"), b"branch-specific").unwrap();
        assert_eq!(
            fs::read(source.join("ledger/state")).unwrap(),
            b"closed-common-ledger"
        );
        assert!(copy_closed_tree(&source, &destination).is_err());
        assert!(copy_closed_tree(&source, &source.join("nested")).is_err());
        std::os::unix::fs::symlink(source.join("ledger/state"), source.join("external-link"))
            .unwrap();
        assert!(copy_closed_tree(&source, &root.path().join("bad-copy")).is_err());
        let link = root.path().join("root-link");
        std::os::unix::fs::symlink(&source, &link).unwrap();
        assert!(copy_closed_tree(&link, &root.path().join("bad-root")).is_err());
    }
    #[test]
    fn native_fork_config_keeps_protocol_fields_and_rejects_scheduled_other_eras() {
        let mut source = json!({"Protocol":"Cardano","preserve":{"untouched":true}});
        for era in ["Shelley", "Allegra", "Mary", "Alonzo", "Babbage", "Conway"] {
            source[format!("Test{era}HardForkAtEpoch")] = json!(0);
        }
        for (field, _) in GENESIS {
            source[field] = json!("source");
            source[field.replace("File", "Hash")] = json!("stale-hash");
        }
        let config = node_config(source.clone(), Path::new("/private/common-genesis")).unwrap();
        assert_eq!(config["preserve"], source["preserve"]);
        for (field, file) in GENESIS {
            assert_eq!(
                config[field],
                json!(format!("/private/common-genesis/{file}"))
            );
            assert!(config.get(field.replace("File", "Hash")).is_none());
        }
        source["TestConwayHardForkAtEpoch"] = json!(3);
        assert!(node_config(source.clone(), Path::new("/private/genesis")).is_err());
        source["TestConwayHardForkAtEpoch"] = json!(0);
        source["TestDijkstraHardForkAtVersion"] = json!(13);
        assert!(node_config(source, Path::new("/private/genesis")).is_err());
    }
    #[test]
    fn topology_is_closed_and_contains_only_other_ports_in_the_same_branch() {
        let a = topology(&[10001, 10002], 0);
        let b = topology(&[20001, 20002, 20003, 20004], 1);
        assert_eq!(
            a["localRoots"][0]["accessPoints"],
            json!([{"address":"127.0.0.1","port":10002}])
        );
        let peers = b["localRoots"][0]["accessPoints"].as_array().unwrap();
        assert_eq!(peers.len(), 3);
        assert!(peers
            .iter()
            .all(|value| value["port"] != 20002 && value["port"].as_u64().unwrap() >= 20001));
        assert_eq!(b["publicRoots"], json!([]));
        assert_eq!(b["useLedgerAfterSlot"], -1);
    }
}
