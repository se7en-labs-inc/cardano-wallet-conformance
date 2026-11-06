//! Executable specification: one fresh, owned cohort, never historical report import.
use crate::{
    api::{request, Api, Contract},
    cluster_control::{port_shortage_after_timeout, Cluster, NodeDiscoveryTimeout},
    node::NodeOracle,
    owned_process::{require_unused_listener, Launch, WalletProcess},
    report::{self, Report, Requirement},
    specification,
};
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    thread::sleep,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adapter {
    pub executable: PathBuf,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub sha256: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub format_version: u32,
    pub environment: String,
    pub target: String,
    pub reference_target: String,
    pub faucet: String,
    pub base_configs: PathBuf,
    pub cluster_launch: Launch,
    pub candidate_launch: Launch,
    pub reference_launch: Launch,
    pub cardano_node: PathBuf,
    pub cardano_cli: PathBuf,
    pub key_oracle: PathBuf,
    pub openssl: PathBuf,
    /// Required SHA256 values: factory, reference-wallet, node, cli, key-oracle, openssl.
    pub trusted_sha256: BTreeMap<String, String>,
    #[serde(default)]
    pub adapter: Option<Adapter>,
    /// Qualification only: one independently pinned reference adapter per profile.
    #[serde(default)]
    pub reference_adapters: BTreeMap<String, Adapter>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}
fn default_timeout() -> u64 {
    180
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profiles {
    format_version: u32,
    http: Vec<String>,
    internals: Vec<Internal>,
    live: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Internal {
    name: String,
    corpora: Vec<String>,
    operations: Vec<String>,
}
fn profiles() -> Result<Profiles> {
    Ok(serde_json::from_str(include_str!(
        "../fixtures/execution-profiles.json"
    ))?)
}
fn digest(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut b = [0; 65536];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
fn text(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("non-UTF8 executable specification path")?
        .to_owned())
}
fn save(path: &Path, value: &Value) -> Result<()> {
    crate::era_fixture::save(path, value)
}
fn rewrite(path: &Path, value: &Value) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
fn expand(launch: &Launch, replacements: &[(&str, String)]) -> Result<Launch> {
    let replace = |v: &String| -> Result<String> {
        if let Some((_, value)) = replacements.iter().find(|(name, _)| v == name) {
            return Ok(value.clone());
        }
        ensure!(
            v == "{database}" || (!v.contains('{') && !v.contains('}')),
            "unknown or embedded launch placeholder"
        );
        Ok(v.clone())
    };
    Ok(Launch {
        executable: launch.executable.clone(),
        arguments: launch
            .arguments
            .iter()
            .map(replace)
            .collect::<Result<_>>()?,
        environment: launch
            .environment
            .iter()
            .map(|(k, v)| Ok((k.clone(), replace(v)?)))
            .collect::<Result<_>>()?,
    })
}
fn write_launch(root: &Path, name: &str, launch: &Launch) -> Result<PathBuf> {
    let path = root.join(format!("{name}.json"));
    save(
        &path,
        &json!({"executable":launch.executable,"arguments":launch.arguments,"environment":launch.environment}),
    )?;
    Ok(path)
}
fn materialize(root: &Path, bundle: &Value) -> Result<()> {
    for (name, entry) in bundle["corpora"]
        .as_object()
        .context("specification corpora missing")?
    {
        let path = Path::new(name);
        ensure!(
            path.components().all(|c| matches!(c, Component::Normal(_)))
                && name.starts_with("fixtures/"),
            "invalid embedded corpus path"
        );
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap())?;
        let source = entry["source_text"]
            .as_str()
            .context("embedded corpus source missing")?;
        ensure!(
            hex::encode(Sha256::digest(source.as_bytes())) == entry["sha256"],
            "embedded corpus source digest mismatch"
        );
        ensure!(
            serde_json::from_str::<Value>(source)? == entry["contract"],
            "embedded corpus source/contract mismatch"
        );
        crate::era_fixture::write(&path, source.as_bytes())?;
    }
    Ok(())
}
fn identify(c: &Config) -> Result<BTreeMap<String, Value>> {
    let mut identities = BTreeMap::new();
    let runner = std::env::current_exe()?;
    identities.insert(
        "runner".into(),
        json!({"path":runner,"sha256":digest(&runner)?}),
    );
    for (name, path, trusted) in [
        ("factory", &c.cluster_launch.executable, true),
        ("reference-wallet", &c.reference_launch.executable, true),
        ("candidate-wallet", &c.candidate_launch.executable, false),
        ("node", &c.cardano_node, true),
        ("cli", &c.cardano_cli, true),
        ("key-oracle", &c.key_oracle, true),
        ("openssl", &c.openssl, true),
    ] {
        ensure!(
            path.is_absolute() && path.is_file(),
            "{name} executable must be an existing absolute file"
        );
        let hash = digest(path)?;
        if trusted {
            ensure!(
                c.trusted_sha256.get(name) == Some(&hash),
                "{name} trusted executable hash mismatch or missing pin"
            );
        }
        identities.insert(name.to_owned(), json!({"path":path,"sha256":hash}));
    }
    for (name, adapter) in c
        .adapter
        .iter()
        .map(|a| ("candidate".to_owned(), a))
        .chain(c.reference_adapters.iter().map(|(n, a)| (n.clone(), a)))
    {
        ensure!(
            adapter.executable.is_absolute() && adapter.executable.is_file(),
            "adapter executable must be an existing absolute file"
        );
        let hash = digest(&adapter.executable)?;
        if c.adapter.is_none() {
            ensure!(
                adapter.sha256.as_ref() == Some(&hash),
                "reference adapter hash mismatch or missing pin"
            );
        }
        if let Some(expected) = &adapter.sha256 {
            ensure!(expected == &hash, "adapter executable hash mismatch");
        }
        identities.insert(
            format!("adapter:{name}"),
            json!({"path":adapter.executable,"sha256":hash}),
        );
        if c.adapter.is_none() {
            for (index, argument) in adapter.arguments.iter().enumerate() {
                let path = Path::new(argument);
                if path.is_absolute() && path.is_file() {
                    let role = format!("adapter-argument:{name}:{index}");
                    let hash = digest(path)?;
                    ensure!(
                        c.trusted_sha256.get(&role) == Some(&hash),
                        "reference adapter argument hash mismatch or missing pin"
                    );
                    identities.insert(role, json!({"path":path,"sha256":hash}));
                }
            }
        }
    }
    Ok(identities)
}
fn validate(c: &Config, p: &Profiles) -> Result<()> {
    ensure!(
        c.format_version == 1 && p.format_version == 1,
        "unsupported execution format"
    );
    ensure!(
        !c.environment.trim().is_empty() && !c.environment.contains("harness-self-test"),
        "explicit non-harness cohort environment required"
    );
    ensure!(
        (1..=3600).contains(&c.timeout_seconds),
        "invalid component timeout"
    );
    ensure!(
        c.base_configs.is_absolute() && c.base_configs.is_dir(),
        "absolute existing base configs required"
    );
    require_unused_listener(&c.target)?;
    require_unused_listener(&c.reference_target)?;
    let target = reqwest::Url::parse(&c.target)?;
    let reference = reqwest::Url::parse(&c.reference_target)?;
    let faucet = reqwest::Url::parse(&c.faucet)?;
    ensure!(
        target.port() != reference.port(),
        "candidate and reference ports must differ"
    );
    let host: std::net::IpAddr = faucet.host_str().context("faucet host missing")?.parse()?;
    ensure!(
        host.is_loopback()
            && faucet.scheme() == "http"
            && faucet.port().is_some()
            && faucet.username().is_empty()
            && faucet.password().is_none()
            && faucet.query().is_none()
            && faucet.fragment().is_none()
            && faucet.path() == "/",
        "faucet must be an explicit loopback HTTP root"
    );
    ensure!(
        faucet.port() != target.port() && faucet.port() != reference.port(),
        "faucet and wallet ports must differ"
    );
    let listener = std::net::SocketAddr::new(host, faucet.port().unwrap());
    ensure!(
        matches!(std::net::TcpStream::connect_timeout(&listener,Duration::from_millis(100)),Err(e) if e.kind()==std::io::ErrorKind::ConnectionRefused),
        "faucet listener must be unused"
    );
    ensure!(
        c.cluster_launch
            .arguments
            .iter()
            .any(|a| a == "{cluster_configs}"),
        "cluster launch requires whole-value cluster_configs placeholder"
    );
    for launch in [&c.candidate_launch, &c.reference_launch] {
        for placeholder in ["{node_socket}", "{byron_genesis}", "{database}"] {
            ensure!(
                launch
                    .arguments
                    .iter()
                    .filter(|a| a.as_str() == placeholder)
                    .count()
                    == 1,
                "wallet launch requires one whole-value {placeholder} argument"
            );
        }
        ensure!(
            launch
                .environment
                .values()
                .all(|v| !v.contains('{') && !v.contains('}')),
            "wallet environment placeholders unsupported by owned live profiles"
        );
    }
    let names: BTreeSet<_> = p.internals.iter().map(|g| g.name.clone()).collect();
    ensure!(
        p.http.len() == 9 && p.internals.len() == 16 && p.live.len() == 12 && names.len() == 16,
        "invalid compiled full profile inventory"
    );
    ensure!(
        c.adapter.is_some() != !c.reference_adapters.is_empty(),
        "provide either one candidate adapter or all explicit reference adapters"
    );
    if c.adapter.is_none() {
        ensure!(
            c.reference_adapters
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                == names,
            "reference adapters must cover exactly every internal profile"
        );
    }
    Ok(())
}
struct Execution<'a, F> {
    c: &'a Config,
    root: PathBuf,
    dispatch: F,
    attempts: Vec<Value>,
    reports: Vec<PathBuf>,
}
impl<F: FnMut(Vec<String>) -> Result<bool>> Execution<'_, F> {
    fn invoke(&mut self, name: &str, args: Vec<String>, report: bool) -> Result<bool> {
        println!("conform: {name}");
        let result = (self.dispatch)(args);
        let error = result.as_ref().err().map(|e| format!("{e:#}"));
        let passed = result.as_ref().copied().unwrap_or(false);
        self.attempts
            .push(json!({"profile":name,"passed":passed,"error":error,"counts_as_report":report}));
        rewrite(&self.root.join("attempts.json"), &json!(self.attempts))?;
        if report {
            let path = self.root.join("reports").join(format!("{name}.json"));
            if path.is_file() {
                self.reports.push(path);
            }
        }
        result
    }
    fn common(&self, name: &str, command: &str) -> Vec<String> {
        vec![
            "wallet-conformance".into(),
            command.into(),
            "--target".into(),
            self.c.target.clone(),
            "--environment".into(),
            self.c.environment.clone(),
            "--report".into(),
            self.root
                .join("reports")
                .join(format!("{name}.json"))
                .display()
                .to_string(),
            "--timeout-seconds".into(),
            self.c.timeout_seconds.to_string(),
        ]
    }
    fn fixture(&mut self, name: &str, args: Vec<String>) -> Result<()> {
        ensure!(self.invoke(name, args, false)?, "fixture {name} failed");
        Ok(())
    }
    fn node(&self, runtime: &Path) -> NodeOracle {
        NodeOracle {
            executable: self.c.cardano_cli.clone(),
            socket: runtime.join("node.socket"),
            network_magic: 42,
        }
    }
    fn wallet(&self, launch: &Launch, runtime: &Path) -> Result<Launch> {
        expand(
            launch,
            &[
                ("{node_socket}", text(&runtime.join("node.socket"))?),
                (
                    "{byron_genesis}",
                    text(&runtime.join("cluster/byron-genesis.json"))?,
                ),
            ],
        )
    }
    fn cluster_launch(&self, configs: &Path) -> Result<Launch> {
        expand_cluster(&self.c.cluster_launch, configs)
    }
    fn cluster(&mut self, phase: &str, configs: &Path) -> Result<(Cluster, PathBuf)> {
        for attempt in 1..=2 {
            let runtime = self.root.join(format!("{phase}-runtime-{attempt}"));
            let mut cluster = Cluster::start(self.cluster_launch(configs)?, &runtime)?;
            if let Err(error) = cluster.discover(
                &self.c.cardano_node,
                &runtime,
                Duration::from_secs(self.c.timeout_seconds),
            ) {
                cluster.stop()?;
                cluster.wait_stopped_nodes(Duration::from_secs(10))?;
                let shortage = error
                    .downcast_ref::<NodeDiscoveryTimeout>()
                    .map(|e| port_shortage_after_timeout(&runtime, e))
                    .transpose()?
                    .flatten();
                save(
                    &self.root.join(format!("{phase}-setup-{attempt}.json")),
                    &json!({"error":format!("{error:#}"),"port_shortage":shortage,"owned_nodes_absent":true}),
                )?;
                if attempt == 1 && shortage.is_some() {
                    continue;
                }
                return Err(error);
            }
            let node = self.node(&runtime);
            let timeout = Duration::from_secs(self.c.timeout_seconds);
            let api = Api::new(&self.c.faucet, Duration::from_secs(2))?;
            let deadline = Instant::now() + timeout;
            loop {
                if let Ok(response) = api.request(&request("GET", "/ready", None)) {
                    if response.status == 200 && response.json == Some(json!(true)) {
                        break;
                    }
                }
                ensure!(
                    Instant::now() < deadline,
                    "owned faucet readiness timed out"
                );
                sleep(Duration::from_millis(100));
            }
            node.advancing(node.height(timeout)?, timeout)?;
            let hashes = [
                "byron-genesis.json",
                "shelley-genesis.json",
                "alonzo-genesis.json",
                "conway-genesis.json",
                "dijkstra-genesis.json",
            ]
            .into_iter()
            .map(|name| {
                Ok((
                    name.to_owned(),
                    digest(&runtime.join("cluster").join(name))?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
            save(
                &self.root.join(format!("{phase}-genesis.json")),
                &json!(hashes),
            )?;
            return Ok((cluster, runtime));
        }
        unreachable!()
    }
    fn native_probe(&mut self, name: &str, runtime: &Path) -> Result<()> {
        let result = crate::executable::native_probe(
            &self.node(runtime),
            &self.c.faucet,
            Duration::from_secs(self.c.timeout_seconds),
        );
        self.attempts.push(json!({"profile":name,"passed":result.is_ok(),"error":result.as_ref().err().map(|e|format!("{e:#}")),"counts_as_report":false}));
        rewrite(&self.root.join("attempts.json"), &json!(self.attempts))?;
        result
    }
    fn standard(&mut self, p: &Profiles, bundle: &Path) -> Result<PathBuf> {
        let (mut cluster, runtime) = self.cluster("standard", &self.c.base_configs.clone())?;
        let (lease, proof) = cluster
            .pause(Duration::from_secs(10))?
            .resume_one(Duration::from_secs(10))?;
        save(&self.root.join("standard-producer-lease.json"), &proof)?;
        let candidate = self.wallet(&self.c.candidate_launch, &runtime)?;
        let reference = self.wallet(&self.c.reference_launch, &runtime)?;
        let candidate_manifest = write_launch(&self.root, "standard-wallet", &candidate)?;
        let mut target = WalletProcess::start(candidate, &self.root.join("http-candidate"))?;
        target.wait_listener(&self.c.target, Duration::from_secs(self.c.timeout_seconds))?;
        let mut reference = WalletProcess::start(reference, &self.root.join("http-reference"))?;
        reference.wait_listener(
            &self.c.reference_target,
            Duration::from_secs(self.c.timeout_seconds),
        )?;
        for name in &p.http {
            let mut args = self.common(name, "http");
            args.extend([
                "--suite".into(),
                text(&bundle.join(format!("fixtures/{name}.json")))?,
                "--reference".into(),
                self.c.reference_target.clone(),
            ]);
            self.invoke(name, args, true)?;
        }
        let pool = self.root.join("reward-pool");
        self.fixture(
            "prepare-reward-pool",
            vec![
                "wallet-conformance".into(),
                "prepare-pool-fixture".into(),
                "--owned-cluster-pool".into(),
                text(&runtime.join("cluster/pool-1"))?,
                "--node-socket".into(),
                text(&runtime.join("node.socket"))?,
                "--cardano-cli".into(),
                text(&self.c.cardano_cli)?,
                "--target".into(),
                self.c.target.clone(),
                "--faucet".into(),
                self.c.faucet.clone(),
                "--output-directory".into(),
                text(&pool)?,
                "--pledge".into(),
                "0".into(),
                "--timeout-seconds".into(),
                self.c.timeout_seconds.to_string(),
            ],
        )?;
        let drep = self.root.join("drep-fixture");
        self.fixture(
            "prepare-drep",
            vec![
                "wallet-conformance".into(),
                "prepare-drep-fixture".into(),
                "--node-socket".into(),
                text(&runtime.join("node.socket"))?,
                "--faucet".into(),
                self.c.faucet.clone(),
                "--cardano-cli".into(),
                text(&self.c.cardano_cli)?,
                "--workspace".into(),
                text(&drep)?,
                "--timeout-seconds".into(),
                self.c.timeout_seconds.to_string(),
            ],
        )?;
        target.stop()?;
        let pool: Value = serde_json::from_slice(&fs::read(pool.join("public/receipt.json"))?)?;
        let mut args = self.live("live-main", &runtime, &candidate_manifest, "owned-main")?;
        args.extend([
            "--external-signer".into(),
            self.c.reference_target.clone(),
            "--stake-pool".into(),
            pool["pool_id"]
                .as_str()
                .context("pool receipt ID missing")?
                .into(),
            "--openssl".into(),
            text(&self.c.openssl)?,
        ]);
        for flag in [
            "families",
            "shared",
            "assets",
            "payments",
            "concurrency",
            "metadata",
            "precedence",
            "validity",
            "balance",
            "collateral",
            "voting",
            "delegation-fees",
            "input-limits",
            "history",
            "discovery",
        ] {
            args.push(format!("--{flag}"));
        }
        self.invoke("live-main", args, true)?;
        let socket = self.root.join("disconnect.socket");
        let disconnected = expand(
            &self.c.candidate_launch,
            &[
                ("{node_socket}", text(&socket)?),
                (
                    "{byron_genesis}",
                    text(&runtime.join("cluster/byron-genesis.json"))?,
                ),
            ],
        )?;
        let disconnected = write_launch(&self.root, "disconnect-wallet", &disconnected)?;
        let mut args = self.live("disconnect", &runtime, &disconnected, "owned-disconnect")?;
        args.extend(["--node-disconnect-socket".into(), text(&socket)?]);
        self.invoke("disconnect", args, true)?;
        let mut args = self.common("drep", "verify-drep-lookup");
        args.extend([
            "--node-socket".into(),
            text(&runtime.join("node.socket"))?,
            "--cardano-cli".into(),
            text(&self.c.cardano_cli)?,
            "--fixture-receipt".into(),
            text(&drep.join("public/receipt.json"))?,
            "--wallet-launch".into(),
            text(&candidate_manifest)?,
            "--wallet-workspace".into(),
            text(&self.root.join("drep-owned"))?,
        ]);
        self.invoke("drep", args, true)?;
        self.native_probe("standard-final-native-integration", &runtime)?;
        reference.stop()?;
        drop(lease);
        cluster.stop()?;
        cluster.wait_stopped_nodes(Duration::from_secs(10))?;
        save(
            &self.root.join("standard-cleanup.json"),
            &json!({"owned_wallets_stopped_and_reaped":true,"owned_nodes_absent":true}),
        )?;
        Ok(runtime.join("cluster"))
    }
    fn live(
        &self,
        name: &str,
        runtime: &Path,
        launch: &Path,
        workspace: &str,
    ) -> Result<Vec<String>> {
        let mut args = self.common(name, "live");
        args.extend([
            "--node-socket".into(),
            text(&runtime.join("node.socket"))?,
            "--network-magic".into(),
            "42".into(),
            "--cardano-cli".into(),
            text(&self.c.cardano_cli)?,
            "--faucet".into(),
            self.c.faucet.clone(),
            "--wallet-launch".into(),
            text(launch)?,
            "--wallet-workspace".into(),
            text(&self.root.join(workspace))?,
            "--shelley-genesis".into(),
            text(&runtime.join("cluster/shelley-genesis.json"))?,
            "--byron-genesis".into(),
            text(&runtime.join("cluster/byron-genesis.json"))?,
        ]);
        Ok(args)
    }
    fn committee(&mut self) -> Result<()> {
        let fixture = self.root.join("committee-fixture");
        self.fixture(
            "prepare-committee",
            vec![
                "wallet-conformance".into(),
                "prepare-parameter-cluster".into(),
                "--base-configs".into(),
                text(&self.c.base_configs)?,
                "--workspace".into(),
                text(&fixture)?,
                "--cardano-cli".into(),
                text(&self.c.cardano_cli)?,
            ],
        )?;
        let (mut cluster, runtime) = self.cluster("committee", &fixture.join("config"))?;
        let manifest = write_launch(
            &self.root,
            "committee-wallet",
            &self.wallet(&self.c.candidate_launch, &runtime)?,
        )?;
        let mut args = self.live("pools", &runtime, &manifest, "owned-pools")?;
        args.extend([
            "--pool-directory".into(),
            text(&runtime.join("cluster"))?,
            "--pool-workspace".into(),
            text(&self.root.join("pool-proofs"))?,
        ]);
        self.invoke("pools", args, true)?;
        let mut args = self.live("parameters", &runtime, &manifest, "owned-parameters")?;
        args.extend([
            "--pool-join-guard".into(),
            "--parameter-fixture".into(),
            text(&fixture)?,
            "--parameter-workspace".into(),
            text(&self.root.join("parameter-update"))?,
        ]);
        self.invoke("parameters", args, true)?;
        self.native_probe("committee-final-native-integration", &runtime)?;
        cluster.stop()?;
        cluster.wait_stopped_nodes(Duration::from_secs(10))?;
        save(
            &self.root.join("committee-cleanup.json"),
            &json!({"owned_nodes_absent":true}),
        )?;
        Ok(())
    }
    fn owned(&mut self, base: &Path) -> Result<()> {
        let cluster = write_launch(
            &self.root,
            "owned-cluster",
            &self.cluster_launch(&self.c.base_configs)?,
        )?;
        let candidate = write_launch(&self.root, "owned-wallet", &self.c.candidate_launch)?;
        let reference = write_launch(&self.root, "owned-adversary", &self.c.reference_launch)?;
        for (name, flag) in [
            ("pending-normal", None),
            ("pending-expiry", Some("--expiry")),
            ("pending-byron", Some("--byron")),
            ("pending-retry", Some("--retry")),
            ("checkpoint", Some("--checkpoint")),
        ] {
            let mut args = self.common(name, "verify-pending-state");
            args.extend([
                "--cluster-launch".into(),
                text(&cluster)?,
                "--wallet-launch".into(),
                text(&candidate)?,
                "--workspace".into(),
                text(&self.root.join(name))?,
                "--cardano-node".into(),
                text(&self.c.cardano_node)?,
                "--cardano-cli".into(),
                text(&self.c.cardano_cli)?,
                "--faucet".into(),
                self.c.faucet.clone(),
            ]);
            if let Some(flag) = flag {
                args.push(flag.into());
            }
            if name == "pending-retry" {
                args.extend([
                    "--adversary-wallet-launch".into(),
                    text(&reference)?,
                    "--adversary-target".into(),
                    self.c.reference_target.clone(),
                ]);
            }
            self.invoke(name, args, true)?;
        }
        for (name, command) in [
            ("rollback", "verify-rollback"),
            ("era", "verify-era-boundary"),
        ] {
            let mut args = self.common(name, command);
            args.extend([
                "--base-cluster".into(),
                text(base)?,
                "--workspace".into(),
                text(&self.root.join(name))?,
                "--cardano-node".into(),
                text(&self.c.cardano_node)?,
                "--cardano-cli".into(),
                text(&self.c.cardano_cli)?,
                "--wallet-launch".into(),
                text(&candidate)?,
            ]);
            if name == "rollback" {
                args.extend(["--key-oracle".into(), text(&self.c.key_oracle)?]);
            } else {
                args.extend(["--conway-epoch".into(), "3".into()]);
            }
            self.invoke(name, args, true)?;
        }
        Ok(())
    }
}
fn expand_cluster(launch: &Launch, configs: &Path) -> Result<Launch> {
    let mut result = launch.clone();
    let value = text(configs)?;
    for arg in &mut result.arguments {
        if arg == "{cluster_configs}" {
            *arg = value.clone();
        }
    }
    Ok(result)
}
/// The same independent faucet/UTxO control used after manual reference phases.
fn native_probe(node: &NodeOracle, faucet: &str, timeout: Duration) -> Result<()> {
    let vectors: Value =
        serde_json::from_str(include_str!("../fixtures/vectors/haskell-keys.json"))?;
    let address = vectors
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "haskell-Shelley-0-0-0-enterprise-0")
        .context("public native control missing")?["expected"]["result"]["address"]
        .as_str()
        .context("native address missing")?;
    node.advancing(node.height(timeout)?, timeout)?;
    let before = node.utxos(address, timeout)?;
    let before = before.as_object().context("invalid initial native UTxOs")?;
    let response=Api::new(faucet,timeout)?.request(&request("POST","/send/faucet-assets",Some(json!({"batch-size":1,"assets":[{"address":address,"bundle":{"coin":100_000_000,"assets":[]},"metadata":[]}]}))))?;
    ensure!(response.status == 204, "independent native faucet rejected");
    let deadline = Instant::now() + timeout;
    loop {
        let after = node.utxos(address, timeout)?;
        let fresh = after
            .as_object()
            .context("invalid native UTxOs")?
            .keys()
            .filter(|key| before.get(*key).is_none())
            .collect::<Vec<_>>();
        ensure!(
            fresh.len() <= 1,
            "independent native faucet produced extra outputs"
        );
        if let Some(reference) = fresh.first() {
            node.payment(
                reference.split('#').next().unwrap(),
                address,
                100_000_000,
                timeout,
            )?;
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "independent native payment not confirmed"
        );
        sleep(Duration::from_millis(200));
    }
}
pub fn run<F: FnMut(Vec<String>) -> Result<bool>>(
    config: &Path,
    workspace: &Path,
    contract: &Contract,
    requirements: &[Requirement],
    dispatch: F,
) -> Result<bool> {
    let input = fs::read(config)?;
    let c: Config = serde_json::from_slice(&input)?;
    let p = profiles()?;
    validate(&c, &p)?;
    let identities = identify(&c)?;
    ensure!(
        workspace.is_absolute(),
        "execution workspace must be absolute"
    );
    crate::era_fixture::directory(workspace)?;
    let root = fs::canonicalize(workspace)?;
    fs::create_dir(root.join("reports"))?;
    let bundle_root = root.join("bundle");
    fs::create_dir(&bundle_root)?;
    let bundle = specification::export(contract, requirements, &[])?;
    materialize(&bundle_root, &bundle)?;
    save(&root.join("specification.json"), &bundle)?;
    save(&root.join("identities.json"), &json!(identities))?;
    let started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    save(
        &root.join("run.json"),
        &json!({"format_version":1,"config_sha256":hex::encode(Sha256::digest(&input)),"suite_sha256":report::suite_sha256(),"environment":c.environment,"target":c.target,"adapter_mode":if c.adapter.is_some(){"candidate"}else{"explicit-reference-qualification"},"started_unix_seconds":started,"reports_imported":false,"required":requirements.len()}),
    )?;
    let mut execution = Execution {
        c: &c,
        root: root.clone(),
        dispatch,
        attempts: Vec::new(),
        reports: Vec::new(),
    };
    let result = (|| -> Result<()> {
        for group in &p.internals {
            let adapter = c
                .adapter
                .as_ref()
                .unwrap_or_else(|| &c.reference_adapters[&group.name]);
            let mut args = execution.common(&group.name, "vectors");
            args.extend(["--adapter".into(), text(&adapter.executable)?]);
            for argument in &adapter.arguments {
                args.push(format!("--adapter-arg={argument}"));
            }
            for corpus in &group.corpora {
                args.extend(["--corpus".into(), text(&bundle_root.join(corpus))?]);
            }
            for operation in &group.operations {
                args.extend(["--operation".into(), operation.clone()]);
            }
            execution.invoke(&group.name, args, true)?;
        }
        let base = execution.standard(&p, &bundle_root)?;
        execution.committee()?;
        execution.owned(&base)?;
        Ok(())
    })();
    let reports = execution
        .reports
        .iter()
        .map(|path| Ok(serde_json::from_slice::<Report>(&fs::read(path)?)?))
        .collect::<Result<Vec<_>>>()?;
    let coverage = if reports.is_empty() {
        None
    } else {
        Some(report::coverage(requirements, &reports)?)
    };
    let identity_check = identify(&c).map(|after| after == identities);
    let all_attempts = execution.attempts.iter().all(|v| v["passed"] == true);
    let complete = result.is_ok()
        && reports.len() == 37
        && all_attempts
        && identity_check.as_ref().is_ok_and(|ok| *ok)
        && coverage.as_ref().is_some_and(|v| v.exhaustive);
    save(
        &root.join("coverage.json"),
        &serde_json::to_value(&coverage)?,
    )?;
    save(
        &root.join("validated-specification.json"),
        &specification::export(contract, requirements, &reports)?,
    )?;
    save(
        &root.join("result.json"),
        &json!({"complete":complete,"required":requirements.len(),"covered":coverage.as_ref().map(|v|v.covered).unwrap_or(0),"reports":reports.len(),"checks":reports.iter().map(|r|r.evidence.len()).sum::<usize>(),"failed_checks":reports.iter().flat_map(|r|&r.evidence).filter(|e|!e.passed).count(),"setup_and_execution_error":result.err().map(|e|format!("{e:#}")),"identities_unchanged":identity_check.unwrap_or(false),"all_attempts_passed":all_attempts,"elapsed_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()-started,"authority_promoted":false}),
    )?;
    println!(
        "conform: complete={complete}; result {}",
        root.join("result.json").display()
    );
    Ok(complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(root: &Path) -> (Config, Vec<std::os::fd::OwnedFd>) {
        let tool = root.join("tool");
        fs::write(&tool, b"non-executable harness control").unwrap();
        let mut listeners = Vec::new();
        for _ in 0..3 {
            listeners.push(crate::owned_process::reserved_loopback().unwrap());
        }
        let urls: Vec<_> = listeners
            .iter()
            .map(|(_, address)| format!("http://{address}"))
            .collect();
        let launch = || Launch {
            executable: tool.clone(),
            arguments: vec![
                "{node_socket}".into(),
                "{byron_genesis}".into(),
                "{database}".into(),
            ],
            environment: BTreeMap::new(),
        };
        let hash = digest(&tool).unwrap();
        let config = Config {
            format_version: 1,
            environment: "executable-harness-control".into(),
            target: format!("{}/v2/", urls[0]),
            reference_target: format!("{}/v2/", urls[1]),
            faucet: format!("{}/", urls[2]),
            base_configs: root.into(),
            cluster_launch: Launch {
                executable: tool.clone(),
                arguments: vec![
                    "{cluster_configs}".into(),
                    "{cluster}".into(),
                    "{socket}".into(),
                    "{funds}".into(),
                ],
                environment: BTreeMap::new(),
            },
            candidate_launch: launch(),
            reference_launch: launch(),
            cardano_node: tool.clone(),
            cardano_cli: tool.clone(),
            key_oracle: tool.clone(),
            openssl: tool.clone(),
            trusted_sha256: [
                "factory",
                "reference-wallet",
                "node",
                "cli",
                "key-oracle",
                "openssl",
            ]
            .into_iter()
            .map(|n| (n.into(), hash.clone()))
            .collect(),
            adapter: Some(Adapter {
                executable: tool,
                arguments: Vec::new(),
                sha256: None,
            }),
            reference_adapters: BTreeMap::new(),
            timeout_seconds: 1,
        };
        (
            config,
            listeners
                .into_iter()
                .map(|(descriptor, _)| descriptor)
                .collect(),
        )
    }
    #[test]
    fn full_embedded_profiles_cover_registered_http_and_1241_internal_cases() {
        let contract = Contract::pinned().unwrap();
        let bundle = specification::export(&contract, &[], &[]).unwrap();
        let p = profiles().unwrap();
        let temp = tempfile::tempdir().unwrap();
        materialize(temp.path(), &bundle).unwrap();
        assert_eq!(p.http.len() + p.internals.len() + p.live.len(), 37);
        for name in &p.http {
            let suite: crate::scenarios::Suite = serde_json::from_slice(
                &fs::read(temp.path().join(format!("fixtures/{name}.json"))).unwrap(),
            )
            .unwrap();
            for case in suite.cases.iter().chain(&suite.cleanup) {
                assert!(report::registered_http(case).unwrap());
            }
        }
        let mut count = 0;
        for group in &p.internals {
            for name in &group.corpora {
                let path = temp.path().join(name);
                assert_eq!(digest(&path).unwrap(), bundle["corpora"][name]["sha256"]);
                let vectors: Vec<crate::adapter::Vector> =
                    serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                for vector in vectors.iter().filter(|v| {
                    group.operations.is_empty() || group.operations.contains(&v.operation)
                }) {
                    assert!(report::registered_vector(vector).unwrap(), "{}", vector.id);
                    count += 1;
                }
            }
        }
        assert_eq!(count, 1241);
    }
    #[test]
    fn bundle_rejects_traversal_digest_drift_content_drift_and_existing_files() {
        let temp = tempfile::tempdir().unwrap();
        let hash = hex::encode(Sha256::digest(b"[]"));
        let mut bundle = json!({"corpora":{"fixtures/control.json":{"source_text":"[]","sha256":hash,"contract":[]}}});
        let mut traversal = bundle.clone();
        traversal["corpora"]["fixtures/../../escape.json"] =
            traversal["corpora"]["fixtures/control.json"].clone();
        assert!(materialize(temp.path(), &traversal).is_err());
        bundle["corpora"]["fixtures/control.json"]["sha256"] = json!("wrong");
        assert!(materialize(temp.path(), &bundle).is_err());
        bundle["corpora"]["fixtures/control.json"]["sha256"] = json!(hash);
        bundle["corpora"]["fixtures/control.json"]["contract"] = json!([1]);
        assert!(materialize(temp.path(), &bundle).is_err());
        bundle["corpora"]["fixtures/control.json"]["contract"] = json!([]);
        // The earlier valid entry in the traversal attempt was exclusively written.
        let fresh = tempfile::tempdir().unwrap();
        materialize(fresh.path(), &bundle).unwrap();
        assert!(materialize(fresh.path(), &bundle).is_err());
    }
    #[test]
    fn launch_substitution_requires_whole_values_and_retains_database_ownership() {
        let temp = tempfile::tempdir().unwrap();
        let (mut c, _ports) = config(temp.path());
        let launch = expand(
            &c.candidate_launch,
            &[
                ("{node_socket}", "/owned/node.socket".into()),
                ("{byron_genesis}", "/owned/genesis.json".into()),
            ],
        )
        .unwrap();
        assert_eq!(
            launch.arguments,
            ["/owned/node.socket", "/owned/genesis.json", "{database}"]
        );
        c.candidate_launch.arguments[0] = "--socket={node_socket}".into();
        assert!(expand(&c.candidate_launch, &[]).is_err());
        c.candidate_launch.arguments[0] = "{unknown}".into();
        assert!(expand(&c.candidate_launch, &[]).is_err());
    }
    #[test]
    fn trusted_identity_checks_refuse_missing_pins_and_mutated_executables() {
        let temp = tempfile::tempdir().unwrap();
        let (mut c, _ports) = config(temp.path());
        assert!(identify(&c).is_ok());
        let pin = c.trusted_sha256.remove("node").unwrap();
        assert!(identify(&c).is_err());
        c.trusted_sha256.insert("node".into(), pin);
        fs::write(&c.cardano_node, b"changed").unwrap();
        assert!(identify(&c).is_err());
    }
    #[test]
    fn complete_adapter_modes_and_foreground_arguments_are_required() {
        let temp = tempfile::tempdir().unwrap();
        let (mut c, _ports) = config(temp.path());
        let p = profiles().unwrap();
        validate(&c, &p).unwrap();
        c.adapter = None;
        assert!(validate(&c, &p).is_err());
        for group in &p.internals {
            c.reference_adapters.insert(
                group.name.clone(),
                Adapter {
                    executable: c.cardano_cli.clone(),
                    arguments: Vec::new(),
                    sha256: Some(digest(&c.cardano_cli).unwrap()),
                },
            );
        }
        validate(&c, &p).unwrap();
        identify(&c).unwrap();
        c.reference_adapters.remove("keys");
        assert!(validate(&c, &p).is_err());
        c.candidate_launch.arguments[0] = "--socket={node_socket}".into();
        assert!(validate(&c, &p).is_err());
    }
    #[test]
    fn failed_execution_keeps_attempts_and_cannot_manufacture_coverage() {
        let temp = tempfile::tempdir().unwrap();
        let (c, _ports) = config(temp.path());
        let launch = |l: &Launch| json!({"executable":l.executable,"arguments":l.arguments,"environment":l.environment});
        let input = json!({"format_version":1,"environment":c.environment,"target":c.target,"reference_target":c.reference_target,"faucet":c.faucet,"base_configs":c.base_configs,"cluster_launch":launch(&c.cluster_launch),"candidate_launch":launch(&c.candidate_launch),"reference_launch":launch(&c.reference_launch),"cardano_node":c.cardano_node,"cardano_cli":c.cardano_cli,"key_oracle":c.key_oracle,"openssl":c.openssl,"trusted_sha256":c.trusted_sha256,"adapter":{"executable":c.adapter.as_ref().unwrap().executable},"timeout_seconds":1});
        let path = temp.path().join("implementation.json");
        fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
        let workspace = temp.path().join("run");
        let mut calls = 0;
        assert!(
            !run(&path, &workspace, &Contract::pinned().unwrap(), &[], |_| {
                calls += 1;
                Ok(false)
            })
            .unwrap()
        );
        assert_eq!(calls, 16);
        let result: Value =
            serde_json::from_slice(&fs::read(workspace.join("result.json")).unwrap()).unwrap();
        assert_eq!(result["reports"], 0);
        assert_eq!(result["covered"], 0);
        assert_eq!(result["complete"], false);
        assert!(result["setup_and_execution_error"].is_string());
        let attempts: Value =
            serde_json::from_slice(&fs::read(workspace.join("attempts.json")).unwrap()).unwrap();
        assert_eq!(attempts.as_array().unwrap().len(), 16);
        assert!(attempts
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["passed"] == false));
        assert!(run(
            &path,
            &workspace,
            &Contract::pinned().unwrap(),
            &[],
            |_| panic!("existing workspace must never dispatch")
        )
        .is_err());
    }
}
