//! Owned Linux cluster producer controls; control audits never count as conformance.
#[cfg(target_os = "linux")]
mod linux {
    use crate::{node::NodeOracle, owned_process::Launch};
    use anyhow::{ensure, Context, Result};
    use serde::Serialize;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeSet,
        fs,
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{
                fs::{DirBuilderExt, OpenOptionsExt},
                process::CommandExt,
            },
        },
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread::sleep,
        time::{Duration, Instant},
    };

    fn digest(path: &Path) -> Result<String> {
        let mut file = fs::File::open(path)?;
        let mut hash = Sha256::new();
        let mut buffer = [0; 65536];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        Ok(hex::encode(hash.finalize()))
    }
    #[derive(Debug, PartialEq, Eq)]
    struct Stat {
        state: char,
        parent: u32,
        group: u32,
        start: u64,
    }
    fn stat_text(text: &str) -> Result<Stat> {
        let (_, fields) = text.rsplit_once(") ").context("invalid process stat")?;
        let f: Vec<_> = fields.split_whitespace().collect();
        ensure!(f.len() >= 20, "short process stat");
        Ok(Stat {
            state: f[0].parse()?,
            parent: f[1].parse()?,
            group: f[2].parse()?,
            start: f[19].parse()?,
        })
    }
    fn stat(pid: u32) -> Result<Stat> {
        stat_text(&fs::read_to_string(format!("/proc/{pid}/stat"))?)
    }
    fn task_children(root: &Path) -> Result<BTreeSet<u32>> {
        let mut children = BTreeSet::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let _: u32 = entry
                .file_name()
                .to_str()
                .context("invalid task id")?
                .parse()?;
            let text = match fs::read_to_string(entry.path().join("children")) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            for child in text.split_whitespace() {
                children.insert(child.parse()?);
            }
        }
        Ok(children)
    }
    fn pidfd(pid: u32) -> Result<OwnedFd> {
        // SAFETY: pidfd_open accepts an integer PID and zero flags; ownership transfers once.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        ensure!(
            fd >= 0,
            "pidfd_open failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }
    fn signal(fd: &OwnedFd, value: i32) -> Result<()> {
        // SAFETY: a live owned descriptor, valid signal, null siginfo and zero flags.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                value,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        ensure!(
            result == 0,
            "pidfd signal failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    fn option<'a>(args: &'a [String], key: &str) -> Result<Option<&'a str>> {
        let indices: Vec<_> = args
            .iter()
            .enumerate()
            .filter(|(_, v)| *v == key)
            .map(|(i, _)| i)
            .collect();
        ensure!(indices.len() <= 1, "duplicate node argument {key}");
        indices
            .first()
            .map(|i| {
                args.get(i + 1)
                    .map(String::as_str)
                    .context("missing node argument value")
            })
            .transpose()
    }
    fn owned_path(value: &str, workspace: &Path) -> Result<PathBuf> {
        let path = Path::new(value);
        ensure!(path.is_absolute(), "node path is relative");
        let path = fs::canonicalize(path)
            .with_context(|| format!("cannot resolve owned node path {}", path.display()))?;
        ensure!(
            path.starts_with(workspace),
            "node path leaves owned workspace"
        );
        Ok(path)
    }
    fn database_ready(value: &str, workspace: &Path) -> Result<bool> {
        match owned_path(value, workspace) {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                let path = Path::new(value);
                let parent = path.parent().context("missing node database parent")?;
                owned_path(
                    parent.to_str().context("non-UTF8 database parent")?,
                    workspace,
                )?;
                match fs::symlink_metadata(path) {
                    Ok(metadata) => ensure!(
                        !metadata.file_type().is_symlink(),
                        "dangling node database symlink"
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
    fn producer(args: &[String], workspace: &Path) -> Result<Option<bool>> {
        ensure!(
            args.get(1).is_some_and(|a| a == "run"),
            "unexpected node subcommand"
        );
        for key in ["--config", "--topology"] {
            owned_path(
                option(args, key)?.context("missing node identity path")?,
                workspace,
            )?;
        }
        let keys = [
            "--shelley-operational-certificate",
            "--shelley-kes-key",
            "--shelley-vrf-key",
        ];
        let mut count = 0;
        for key in keys {
            if let Some(path) = option(args, key)? {
                owned_path(path, workspace)?;
                count += 1;
            }
        }
        ensure!(count == 0 || count == 3, "incomplete producer key identity");
        if !database_ready(
            option(args, "--database-path")?.context("missing node database path")?,
            workspace,
        )? {
            return Ok(None);
        }
        Ok(Some(count == 3))
    }
    #[derive(Serialize)]
    struct Identity {
        pid: u32,
        parent: u32,
        group: u32,
        start: u64,
        producer: bool,
        executable_sha256: String,
    }
    pub struct Node {
        identity: Identity,
        fd: OwnedFd,
    }
    impl Node {
        fn verify(&self) -> Result<()> {
            let now = stat(self.identity.pid)?;
            ensure!(
                now.parent == self.identity.parent
                    && now.group == self.identity.group
                    && now.start == self.identity.start,
                "node process identity changed"
            );
            Ok(())
        }
    }
    pub struct Pause<'a> {
        nodes: Vec<&'a Node>,
    }
    impl Drop for Pause<'_> {
        fn drop(&mut self) {
            for node in &self.nodes {
                let _ = signal(&node.fd, libc::SIGCONT);
            }
        }
    }
    impl Pause<'_> {
        pub fn resume_one(mut self, timeout: Duration) -> Result<(Self, serde_json::Value)> {
            ensure!(
                self.nodes.len() > 1,
                "selective resume needs multiple paused producers"
            );
            for node in &self.nodes {
                node.verify()?;
                ensure!(
                    node.identity.producer && stat(node.identity.pid)?.state == 'T',
                    "producer is not independently stopped"
                );
            }
            let (selected_index, selected) = self
                .nodes
                .iter()
                .enumerate()
                .min_by_key(|(_, node)| (node.identity.start, node.identity.pid))
                .context("no paused producer")?;
            let selected = *selected;
            signal(&selected.fd, libc::SIGCONT)?;
            let deadline = Instant::now() + timeout;
            loop {
                selected.verify()?;
                for (index, node) in self.nodes.iter().enumerate() {
                    if index == selected_index {
                        continue;
                    }
                    node.verify()?;
                    ensure!(
                        stat(node.identity.pid)?.state == 'T',
                        "another producer resumed unexpectedly"
                    );
                }
                let state = stat(selected.identity.pid)?.state;
                ensure!(state != 'Z', "selected producer died");
                if state != 'T' && state != 't' {
                    break;
                }
                ensure!(
                    Instant::now() < deadline,
                    "selected producer did not resume"
                );
                sleep(Duration::from_millis(10));
            }
            let proof = json!({"selection":"earliest-started-owned-producer","running_producer":selected.identity,"paused_producers":self.nodes.iter().enumerate().filter(|(index,_)|*index!=selected_index).map(|(_,node)|&node.identity).collect::<Vec<_>>()});
            self.nodes.remove(selected_index);
            Ok((self, proof))
        }
        pub fn resume(mut self) -> Result<()> {
            for node in &self.nodes {
                signal(&node.fd, libc::SIGCONT)?;
            }
            self.nodes.clear();
            Ok(())
        }
    }
    pub struct Cluster {
        child: Child,
        nodes: Vec<Node>,
        stopped: bool,
    }
    fn pause_nodes(nodes: &[Node], timeout: Duration) -> Result<Pause<'_>> {
        let mut guard = Pause { nodes: Vec::new() };
        for node in nodes.iter().filter(|node| node.identity.producer) {
            node.verify()?;
            // An existing pause belongs to its original guard, which must keep
            // responsibility for resuming it. Nested guards own only changes.
            if stat(node.identity.pid)?.state == 'T' {
                continue;
            }
            guard.nodes.push(node);
            signal(&node.fd, libc::SIGSTOP)?;
        }
        let deadline = Instant::now() + timeout;
        loop {
            for node in nodes {
                node.verify()?;
            }
            let states = nodes
                .iter()
                .map(|node| Ok((node.identity.producer, stat(node.identity.pid)?.state)))
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                states
                    .iter()
                    .filter(|(producer, _)| !*producer)
                    .all(|(_, state)| !matches!(state, 'T' | 't' | 'Z')),
                "relay is stopped or dead"
            );
            if states
                .iter()
                .filter(|(producer, _)| *producer)
                .all(|(_, state)| *state == 'T')
            {
                return Ok(guard);
            }
            ensure!(Instant::now() < deadline, "producer stop timed out");
            sleep(Duration::from_millis(10));
        }
    }
    #[derive(Debug, Serialize)]
    pub struct NodeDiscoveryTimeout {
        pub observed_nodes: usize,
        pub observed_producers: usize,
    }
    impl std::fmt::Display for NodeDiscoveryTimeout {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "node discovery timed out: {} owned nodes, {} producers; expected five nodes and four producers", self.observed_nodes, self.observed_producers)
        }
    }
    impl std::error::Error for NodeDiscoveryTimeout {}

    fn port_shortage_proof(
        topology: &serde_json::Value,
        genesis: &serde_json::Value,
        observed: &NodeDiscoveryTimeout,
    ) -> Result<Option<serde_json::Value>> {
        ensure!(
            genesis
                .pointer("/staking/pools")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|pools| pools.len() == 4),
            "port shortage recovery requires exactly four genesis pools"
        );
        let roots = topology["localRoots"]
            .as_array()
            .context("invalid local roots")?;
        ensure!(
            roots.len() == 1
                && topology["publicRoots"] == json!([])
                && topology["useLedgerAfterSlot"] == json!(-1),
            "unexpected owned relay topology"
        );
        let peers = roots[0]["accessPoints"]
            .as_array()
            .context("invalid relay peers")?;
        ensure!(
            !peers.is_empty() && peers.len() <= 4 && roots[0]["valency"] == json!(peers.len()),
            "invalid producer peer cardinality"
        );
        let mut ports = BTreeSet::new();
        for peer in peers {
            let port = peer["port"].as_u64().context("invalid producer port")?;
            ensure!(
                peer["address"] == "127.0.0.1"
                    && (1024..=49151).contains(&port)
                    && ports.insert(port),
                "nonlocal, duplicate or invalid producer port"
            );
        }
        if peers.len() == 4 {
            return Ok(None);
        }
        ensure!(
            observed.observed_nodes == peers.len() + 1
                && observed.observed_producers == peers.len(),
            "discovered process counts do not prove the port shortage"
        );
        Ok(Some(
            json!({"requested_ports":5,"allocated_ports":peers.len()+1,"producer_peer_ports":ports,"genesis_pools":4,"verified_owned_nodes":observed.observed_nodes,"verified_owned_producers":observed.observed_producers}),
        ))
    }
    pub fn port_shortage_after_timeout(
        workspace: &Path,
        observed: &NodeDiscoveryTimeout,
    ) -> Result<Option<serde_json::Value>> {
        let topology = fs::read(workspace.join("cluster/relay/config.json"))?;
        let genesis = fs::read(workspace.join("cluster/shelley-genesis.json"))?;
        let mut proof = port_shortage_proof(
            &serde_json::from_slice(&topology)?,
            &serde_json::from_slice(&genesis)?,
            observed,
        )?;
        if let Some(proof) = proof.as_mut() {
            proof["topology_sha256"] = json!(hex::encode(Sha256::digest(&topology)));
            proof["genesis_sha256"] = json!(hex::encode(Sha256::digest(&genesis)));
        }
        Ok(proof)
    }
    impl Cluster {
        pub fn start(launch: Launch, workspace: &Path) -> Result<Self> {
            ensure!(
                workspace.is_absolute(),
                "cluster workspace must be absolute"
            );
            ensure!(
                launch.executable.is_absolute() && launch.executable.is_file(),
                "cluster executable must be an absolute file"
            );
            ensure!(
                launch.arguments.iter().any(|a| a == "{cluster}")
                    && launch.arguments.iter().any(|a| a == "{socket}")
                    && launch.arguments.iter().any(|a| a == "{funds}"),
                "cluster launch lacks required whole-value placeholders"
            );
            fs::DirBuilder::new()
                .mode(0o700)
                .create(workspace)
                .context("cluster workspace must be fresh")?;
            let workspace = fs::canonicalize(workspace)?;
            let replacements = [
                ("{workspace}", workspace.clone()),
                ("{cluster}", workspace.join("cluster")),
                ("{socket}", workspace.join("node.socket")),
                ("{logs}", workspace.join("cluster.log")),
                ("{funds}", workspace.join("funds.json")),
            ];
            let expand = |value: &String| -> Result<String> {
                if let Some((_, path)) = replacements.iter().find(|(name, _)| value == name) {
                    return Ok(path.to_str().context("non UTF8 workspace")?.to_owned());
                }
                ensure!(
                    !value.contains('{') && !value.contains('}'),
                    "unrecognized or embedded cluster placeholder"
                );
                Ok(value.clone())
            };
            let args: Vec<_> = launch.arguments.iter().map(expand).collect::<Result<_>>()?;
            let env: Vec<_> = launch
                .environment
                .iter()
                .map(|(k, v)| Ok((k.clone(), expand(v)?)))
                .collect::<Result<_>>()?;
            fs::write(
                workspace.join("funds.json"),
                b"{\"pureAdaFunds\":[],\"maryAllegraFunds\":[],\"massiveWalletFunds\":[]}",
            )?;
            let log = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(workspace.join("cluster-console.log"))?;
            let child = Command::new(launch.executable)
                .args(args)
                .envs(env)
                .stdin(Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log)
                .process_group(0)
                .spawn()?;
            Ok(Self {
                child,
                nodes: Vec::new(),
                stopped: false,
            })
        }
        pub fn discover(
            &mut self,
            executable: &Path,
            workspace: &Path,
            timeout: Duration,
        ) -> Result<()> {
            let executable = fs::canonicalize(executable)?;
            let expected_hash = digest(&executable)?;
            let workspace = fs::canonicalize(workspace)?;
            let parent = self.child.id();
            let deadline = Instant::now() + timeout;
            loop {
                ensure!(
                    self.child.try_wait()?.is_none(),
                    "cluster exited before node discovery"
                );
                let mut nodes = Vec::new();
                for pid in task_children(Path::new(&format!("/proc/{parent}/task")))
                    .context("cannot enumerate exclusively owned cluster children")?
                {
                    let proc = PathBuf::from(format!("/proc/{pid}"));
                    let Ok(actual) = fs::read_link(proc.join("exe")) else {
                        continue;
                    };
                    if actual != executable {
                        continue;
                    }
                    let fd = pidfd(pid)
                        .with_context(|| format!("cannot open owned node pidfd {pid}"))?;
                    let before = stat(pid)
                        .with_context(|| format!("cannot inspect owned node identity {pid}"))?;
                    ensure!(
                        before.parent == parent && before.group == parent,
                        "node is not an owned cluster child"
                    );
                    ensure!(
                        digest(&proc.join("exe"))? == expected_hash,
                        "node executable changed"
                    );
                    let args = fs::read(proc.join("cmdline"))?
                        .split(|b| *b == 0)
                        .filter(|b| !b.is_empty())
                        .map(|s| Ok(std::str::from_utf8(s)?.to_owned()))
                        .collect::<Result<Vec<_>>>()?;
                    let Some(is_producer) = producer(&args, &workspace)? else {
                        continue;
                    };
                    let node = Node {
                        identity: Identity {
                            pid,
                            parent,
                            group: before.group,
                            start: before.start,
                            producer: is_producer,
                            executable_sha256: expected_hash.clone(),
                        },
                        fd,
                    };
                    node.verify()?;
                    nodes.push(node);
                }
                if nodes.len() == 5 {
                    ensure!(
                        nodes.iter().filter(|n| n.identity.producer).count() == 4,
                        "expected four producers and one relay"
                    );
                    self.nodes = nodes;
                    return Ok(());
                }
                ensure!(nodes.len() < 5, "unexpected extra owned node");
                if Instant::now() >= deadline {
                    let error = NodeDiscoveryTimeout {
                        observed_nodes: nodes.len(),
                        observed_producers: nodes
                            .iter()
                            .filter(|node| node.identity.producer)
                            .count(),
                    };
                    self.nodes = nodes;
                    return Err(error.into());
                }
                sleep(Duration::from_millis(100));
            }
        }
        pub fn wait_stopped_nodes(&self, timeout: Duration) -> Result<()> {
            ensure!(self.stopped, "owned cluster has not stopped");
            let deadline = Instant::now() + timeout;
            loop {
                let mut remaining = false;
                for node in &self.nodes {
                    match fs::read_to_string(format!("/proc/{}/stat", node.identity.pid)) {
                        Ok(text) => remaining |= stat_text(&text)?.start == node.identity.start,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                if !remaining {
                    return Ok(());
                }
                ensure!(
                    Instant::now() < deadline,
                    "owned native children remain after cluster stop"
                );
                sleep(Duration::from_millis(20));
            }
        }
        pub fn pause(&self, timeout: Duration) -> Result<Pause<'_>> {
            ensure!(self.nodes.len() == 5, "cluster nodes not discovered");
            pause_nodes(&self.nodes, timeout)
        }
        pub fn stop(&mut self) -> Result<()> {
            if self.stopped {
                return Ok(());
            }
            for node in &self.nodes {
                let _ = signal(&node.fd, libc::SIGCONT);
            }
            // SAFETY: this process group was created by our directly spawned child.
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGTERM);
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if self.child.try_wait()?.is_some() {
                    self.stopped = true;
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    unsafe {
                        libc::kill(-(self.child.id() as i32), libc::SIGKILL);
                    }
                    self.child.wait()?;
                    self.stopped = true;
                    return Ok(());
                }
                sleep(Duration::from_millis(50));
            }
        }
    }
    impl Drop for Cluster {
        fn drop(&mut self) {
            let _ = self.stop();
        }
    }

    pub fn audit(
        launch_path: &Path,
        workspace: &Path,
        executable: &Path,
        cli: &Path,
        magic: u32,
        timeout: Duration,
        output: &Path,
    ) -> Result<()> {
        ensure!(!output.exists(), "audit output already exists");
        let launch: Launch = serde_json::from_slice(&fs::read(launch_path)?)?;
        let mut cluster = Cluster::start(launch, workspace)?;
        cluster.discover(executable, workspace, timeout)?;
        let oracle = NodeOracle {
            executable: cli.into(),
            socket: workspace.join("node.socket"),
            network_magic: magic,
        };
        let deadline = Instant::now() + timeout;
        let initial = loop {
            match oracle.height(Duration::from_secs(5)) {
                Ok(height) => break height,
                Err(_) => {
                    ensure!(Instant::now() < deadline, "relay startup timed out");
                    sleep(Duration::from_millis(100));
                }
            }
        };
        oracle.advancing(initial, timeout)?;
        let pause = cluster.pause(timeout)?;
        let mut stable = oracle.tip(timeout)?;
        let mut equal_samples = 0;
        let deadline = Instant::now() + timeout;
        while equal_samples < 3 {
            sleep(Duration::from_millis(200));
            let tip = oracle.tip(timeout)?;
            if tip.hash == stable.hash && tip.slot == stable.slot && tip.height == stable.height {
                equal_samples += 1;
            } else {
                equal_samples = 0;
                stable = tip;
            }
            ensure!(
                Instant::now() < deadline,
                "relay did not settle after producer stop"
            );
        }
        let hold_start = Instant::now();
        let mut samples = 0;
        while hold_start.elapsed() < Duration::from_secs(3) {
            let tip = oracle.tip(timeout)?;
            ensure!(
                tip.hash == stable.hash && tip.slot == stable.slot && tip.height == stable.height,
                "chain advanced while producers stopped"
            );
            samples += 1;
            sleep(Duration::from_millis(200));
        }
        let held_ms = hold_start.elapsed().as_millis();
        pause.resume()?;
        oracle.advancing(stable.height, timeout)?;
        let after = oracle.tip(timeout)?;
        let identities = serde_json::to_value(
            cluster
                .nodes
                .iter()
                .map(|n| &n.identity)
                .collect::<Vec<_>>(),
        )?;
        cluster.stop()?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while cluster
            .nodes
            .iter()
            .any(|n| Path::new(&format!("/proc/{}", n.identity.pid)).exists())
        {
            ensure!(
                Instant::now() < deadline,
                "owned nodes remain after cluster cleanup"
            );
            sleep(Duration::from_millis(50));
        }
        let receipt = json!({"format_version":1,"count_as_conformance_evidence":false,"node_executable_sha256":digest(executable)?,"nodes":identities,"initial_height":initial,"frozen_tip":{"height":stable.height,"slot":stable.slot,"hash":stable.hash},"hold_milliseconds":held_ms,"successful_queries_while_paused":samples,"resumed_tip":{"height":after.height,"slot":after.slot,"hash":after.hash},"cluster_reaped":true,"all_observed_nodes_absent":true});
        fs::write(output, serde_json::to_vec_pretty(&receipt)?)?;
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn task_union_deduplicates_and_tolerates_only_disappeared_tasks() {
            let root = tempfile::tempdir().unwrap();
            for id in ["1", "2", "3"] {
                fs::create_dir(root.path().join(id)).unwrap();
            }
            fs::write(root.path().join("1/children"), "100 101 ").unwrap();
            fs::write(root.path().join("2/children"), "101 102 ").unwrap();
            assert_eq!(
                task_children(root.path()).unwrap(),
                BTreeSet::from([100, 101, 102])
            );
            fs::write(root.path().join("2/children"), "bad").unwrap();
            assert!(task_children(root.path()).is_err());
        }
        #[test]
        fn worker_thread_child_is_absent_from_main_list_but_in_owned_union() {
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (stop_tx, stop_rx) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "cluster_control::linux::tests::child_fixture"])
                    .env("WC_CLUSTER_CONTROL_CHILD", "1")
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap();
                ready_tx.send(child.id()).unwrap();
                let _ = stop_rx.recv();
                let _ = child.kill();
                child.wait().unwrap();
            });
            let pid = ready_rx.recv().unwrap();
            let parent = std::process::id();
            let main =
                fs::read_to_string(format!("/proc/{parent}/task/{parent}/children")).unwrap();
            let main_has_child = main.split_whitespace().any(|s| s == pid.to_string());
            let union_has_child = task_children(Path::new(&format!("/proc/{parent}/task")))
                .unwrap()
                .contains(&pid);
            stop_tx.send(()).unwrap();
            worker.join().unwrap();
            assert!(!main_has_child);
            assert!(union_has_child);
            assert!(!Path::new(&format!("/proc/{pid}")).exists());
        }
        #[test]
        fn stat_parser_handles_spaces_and_parentheses_in_command() {
            let fields = format!(
                "11 (name with ) spaces) S 12 13 {} 777",
                vec!["0"; 16].join(" ")
            );
            assert_eq!(
                stat_text(&fields).unwrap(),
                Stat {
                    state: 'S',
                    parent: 12,
                    group: 13,
                    start: 777
                }
            );
            assert!(stat_text("11 (bad) S 1").is_err());
        }
        #[test]
        fn classification_requires_owned_paths_and_complete_keys() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().to_str().unwrap().to_owned();
            let mut args = vec![
                "node".into(),
                "run".into(),
                "--config".into(),
                path.clone(),
                "--database-path".into(),
                path.clone(),
                "--topology".into(),
                path.clone(),
            ];
            assert_eq!(producer(&args, root.path()).unwrap(), Some(false));
            args.extend(["--shelley-kes-key".into(), path.clone()]);
            assert!(producer(&args, root.path()).is_err());
            args.extend([
                "--shelley-operational-certificate".into(),
                path.clone(),
                "--shelley-vrf-key".into(),
                path,
            ]);
            assert_eq!(producer(&args, root.path()).unwrap(), Some(true));
            args[3] = "/tmp".into();
            assert!(producer(&args, root.path()).is_err());
        }
        #[test]
        fn child_fixture() {
            if std::env::var_os("WC_CLUSTER_CONTROL_CHILD").is_some() {
                loop {
                    sleep(Duration::from_millis(10));
                }
            }
        }
        #[test]
        fn only_missing_database_child_defers_owned_node_identity() {
            let root = tempfile::tempdir().unwrap();
            let config = root.path().join("config");
            fs::write(&config, b"fixture").unwrap();
            let database = root.path().join("db");
            let mut args = vec![
                "node".into(),
                "run".into(),
                "--config".into(),
                config.display().to_string(),
                "--topology".into(),
                config.display().to_string(),
                "--database-path".into(),
                database.display().to_string(),
            ];
            assert_eq!(producer(&args, root.path()).unwrap(), None);
            fs::create_dir(&database).unwrap();
            assert_eq!(producer(&args, root.path()).unwrap(), Some(false));
            fs::remove_dir(&database).unwrap();
            std::os::unix::fs::symlink(root.path().join("missing-target"), &database).unwrap();
            assert!(producer(&args, root.path()).is_err());
            fs::remove_file(&database).unwrap();
            let outside = tempfile::tempdir().unwrap();
            args[7] = outside.path().join("not-created").display().to_string();
            assert!(producer(&args, root.path()).is_err());
            args[7] = database.display().to_string();
            args[3] = root.path().join("missing-config").display().to_string();
            assert!(producer(&args, root.path()).is_err());
            args[3] = config.display().to_string();
            args.extend(["--shelley-kes-key".into(), config.display().to_string()]);
            assert!(producer(&args, root.path()).is_err());
        }
        #[test]
        fn port_shortage_requires_matching_closed_topology_and_owned_process_counts() {
            let genesis = json!({"staking":{"pools":{"a":{},"b":{},"c":{},"d":{}}}});
            let topology = json!({"localRoots":[{"accessPoints":[{"address":"127.0.0.1","port":33482},{"address":"127.0.0.1","port":43889},{"address":"127.0.0.1","port":47939}],"advertise":false,"valency":3}],"publicRoots":[],"useLedgerAfterSlot":-1});
            let observed = NodeDiscoveryTimeout {
                observed_nodes: 4,
                observed_producers: 3,
            };
            let proof = port_shortage_proof(&topology, &genesis, &observed)
                .unwrap()
                .unwrap();
            assert_eq!(proof["allocated_ports"], 4);
            assert_eq!(proof["requested_ports"], 5);
            let mut full = topology.clone();
            full["localRoots"][0]["accessPoints"]
                .as_array_mut()
                .unwrap()
                .push(json!({"address":"127.0.0.1","port":40001}));
            full["localRoots"][0]["valency"] = json!(4);
            assert!(port_shortage_proof(&full, &genesis, &observed)
                .unwrap()
                .is_none());
            let wrong_count = NodeDiscoveryTimeout {
                observed_nodes: 3,
                observed_producers: 2,
            };
            assert!(port_shortage_proof(&topology, &genesis, &wrong_count).is_err());
            let mut changed = topology.clone();
            changed["localRoots"][0]["accessPoints"][1]["port"] = json!(33482);
            assert!(port_shortage_proof(&changed, &genesis, &observed).is_err());
            changed = topology.clone();
            changed["localRoots"][0]["accessPoints"][0]["address"] = json!("192.0.2.1");
            assert!(port_shortage_proof(&changed, &genesis, &observed).is_err());
            changed = topology.clone();
            changed["localRoots"][0]["valency"] = json!(4);
            assert!(port_shortage_proof(&changed, &genesis, &observed).is_err());
            changed = topology.clone();
            changed["localRoots"][0]["accessPoints"][0]["port"] = json!(70000);
            assert!(port_shortage_proof(&changed, &genesis, &observed).is_err());
            let mut wrong_genesis = genesis.clone();
            wrong_genesis["staking"]["pools"]
                .as_object_mut()
                .unwrap()
                .remove("d");
            assert!(port_shortage_proof(&topology, &wrong_genesis, &observed).is_err());
            assert!(port_shortage_proof(&json!({}), &genesis, &observed).is_err());
        }
        #[test]
        fn selective_resume_keeps_other_owned_children_stopped_until_drop() {
            struct Children(Vec<Child>);
            impl Drop for Children {
                fn drop(&mut self) {
                    for child in &mut self.0 {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                }
            }
            let mut children = Children(Vec::new());
            let mut nodes = Vec::new();
            for _ in 0..3 {
                let child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "cluster_control::linux::tests::child_fixture",
                        "--nocapture",
                    ])
                    .env("WC_CLUSTER_CONTROL_CHILD", "1")
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap();
                let pid = child.id();
                children.0.push(child);
                let before = stat(pid).unwrap();
                nodes.push(Node {
                    identity: Identity {
                        pid,
                        parent: before.parent,
                        group: before.group,
                        start: before.start,
                        producer: true,
                        executable_sha256: String::new(),
                    },
                    fd: pidfd(pid).unwrap(),
                });
                sleep(Duration::from_millis(20));
            }
            for node in &nodes {
                signal(&node.fd, libc::SIGSTOP).unwrap();
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while nodes
                .iter()
                .any(|node| stat(node.identity.pid).unwrap().state != 'T')
            {
                assert!(Instant::now() < deadline);
                sleep(Duration::from_millis(10));
            }
            let guard = Pause {
                nodes: vec![&nodes[2], &nodes[0], &nodes[1]],
            };
            let (remaining, proof) = guard.resume_one(Duration::from_secs(5)).unwrap();
            assert_eq!(proof["paused_producers"].as_array().unwrap().len(), 2);
            assert_eq!(proof["running_producer"]["pid"], nodes[0].identity.pid);
            assert_eq!(stat(nodes[1].identity.pid).unwrap().state, 'T');
            assert_eq!(stat(nodes[2].identity.pid).unwrap().state, 'T');
            assert!(!matches!(
                stat(nodes[0].identity.pid).unwrap().state,
                'T' | 't' | 'Z'
            ));
            let nested = pause_nodes(&nodes, Duration::from_secs(5)).unwrap();
            assert_eq!(nested.nodes.len(), 1);
            assert!(nodes
                .iter()
                .all(|node| stat(node.identity.pid).unwrap().state == 'T'));
            nested.resume().unwrap();
            assert_eq!(stat(nodes[1].identity.pid).unwrap().state, 'T');
            assert_eq!(stat(nodes[2].identity.pid).unwrap().state, 'T');
            assert!(!matches!(
                stat(nodes[0].identity.pid).unwrap().state,
                'T' | 't' | 'Z'
            ));
            drop(remaining);
            while nodes
                .iter()
                .any(|node| stat(node.identity.pid).unwrap().state == 'T')
            {
                assert!(Instant::now() < deadline);
                sleep(Duration::from_millis(10));
            }
            for node in &nodes {
                signal(&node.fd, libc::SIGSTOP).unwrap();
            }
            while nodes
                .iter()
                .any(|node| stat(node.identity.pid).unwrap().state != 'T')
            {
                assert!(Instant::now() < deadline);
                sleep(Duration::from_millis(10));
            }
            let invalid = Node {
                identity: Identity {
                    pid: nodes[0].identity.pid,
                    parent: nodes[0].identity.parent,
                    group: nodes[0].identity.group,
                    start: nodes[0].identity.start + 1,
                    producer: true,
                    executable_sha256: String::new(),
                },
                fd: pidfd(nodes[0].identity.pid).unwrap(),
            };
            let invalid_guard = Pause {
                nodes: vec![&nodes[1], &nodes[2], &invalid],
            };
            assert!(invalid_guard.resume_one(Duration::from_secs(5)).is_err());
            while nodes
                .iter()
                .any(|node| stat(node.identity.pid).unwrap().state == 'T')
            {
                assert!(Instant::now() < deadline);
                sleep(Duration::from_millis(10));
            }
            assert!(Pause { nodes: vec![] }
                .resume_one(Duration::from_secs(1))
                .is_err());
        }
        #[test]
        fn pidfd_guard_resumes_real_child_and_refuses_wrong_identity() {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cluster_control::linux::tests::child_fixture",
                    "--nocapture",
                ])
                .env("WC_CLUSTER_CONTROL_CHILD", "1")
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            let pid = child.id();
            let before = stat(pid).unwrap();
            let node = Node {
                identity: Identity {
                    pid,
                    parent: before.parent,
                    group: before.group,
                    start: before.start,
                    producer: true,
                    executable_sha256: String::new(),
                },
                fd: pidfd(pid).unwrap(),
            };
            let mut wrong = node.identity.start;
            wrong += 1;
            let invalid = Node {
                identity: Identity {
                    pid,
                    parent: before.parent,
                    group: before.group,
                    start: wrong,
                    producer: true,
                    executable_sha256: String::new(),
                },
                fd: pidfd(pid).unwrap(),
            };
            assert!(invalid.verify().is_err());
            signal(&node.fd, libc::SIGSTOP).unwrap();
            let guard = Pause { nodes: vec![&node] };
            let deadline = Instant::now() + Duration::from_secs(5);
            while stat(pid).unwrap().state != 'T' {
                assert!(Instant::now() < deadline);
                sleep(Duration::from_millis(10));
            }
            drop(guard);
            while stat(pid).unwrap().state == 'T' {
                assert!(Instant::now() < deadline);
                sleep(Duration::from_millis(10));
            }
            child.kill().unwrap();
            child.wait().unwrap();
            assert!(signal(&node.fd, libc::SIGCONT).is_err());
        }
    }
}
#[cfg(target_os = "linux")]
pub use linux::{audit, port_shortage_after_timeout, Cluster, NodeDiscoveryTimeout};
#[cfg(not(target_os = "linux"))]
pub fn audit(
    _: &std::path::Path,
    _: &std::path::Path,
    _: &std::path::Path,
    _: &std::path::Path,
    _: u32,
    _: std::time::Duration,
    _: &std::path::Path,
) -> anyhow::Result<()> {
    anyhow::bail!("owned producer controls require Linux pidfds")
}
