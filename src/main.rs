use anyhow::{ensure, Context, Result};
use clap::{builder::TypedValueParser, Parser, Subcommand};
use serde_json::{json, Value};
use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
    time::Duration,
};
use wallet_conformance::{
    adapter::{self, Vector},
    api::{Api, Contract},
    live::{self, LiveOptions},
    report::{self, Report, Requirement},
    scenarios::{self, Suite},
};

#[derive(Parser)]
#[command(
    version,
    about = "Cardano wallet conformance: HTTP contracts, live-chain integration and independent internal vectors"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Args)]
struct LiveArgs {
    /// Verify real enactment and wallet fee/min-ADA behavior using the owned fixture.
    #[arg(long, requires_all = ["parameter_workspace", "faucet", "shelley_genesis", "byron_genesis"])]
    parameter_fixture: Option<PathBuf>,
    #[arg(long, requires = "parameter_fixture")]
    parameter_workspace: Option<PathBuf>,
    /// Run complete pool lifecycle controls using explicitly owned cluster keys.
    #[arg(long, requires_all = ["pool_workspace", "faucet", "shelley_genesis", "byron_genesis"])]
    pool_directory: Option<PathBuf>,
    #[arg(long, requires = "pool_directory", value_parser = clap::builder::OsStringValueParser::new().map(|value| Box::new(PathBuf::from(value))))]
    pool_workspace: Option<Box<PathBuf>>,
    /// Exercise sequential address gap boundaries with real funding and node accounting.
    #[arg(long, requires = "faucet")]
    discovery: bool,
    /// Check funded history time/order/limit/address filters and binary metadata.
    #[arg(long, requires_all = ["faucet", "shelley_genesis", "byron_genesis"])]
    history: bool,
    /// Use a transparent node relay and test disconnection instead of owned restart.
    #[arg(long, requires_all = ["wallet_launch", "faucet"])]
    node_disconnect_socket: Option<PathBuf>,
    /// Launch a foreground wallet from this JSON manifest and test crash/restart.
    #[arg(long, requires = "wallet_workspace")]
    wallet_launch: Option<PathBuf>,
    /// New private directory for the owned wallet database and generation logs.
    #[arg(long, requires = "wallet_launch")]
    wallet_workspace: Option<PathBuf>,
    /// Prove many-input balancing boundaries and real node acceptance.
    #[arg(long)]
    input_limits: bool,
    /// Register, change and retire vote delegation with independent node checks.
    #[arg(long)]
    voting: bool,
    /// Independently verify funded delegation-fee reads without submitting delegation.
    #[arg(long, requires = "faucet")]
    delegation_fees: bool,
    /// Reject empty-wallet pool joining using independently active node pool membership.
    #[arg(long, requires = "faucet")]
    pool_join_guard: bool,
    /// Delegate to this independently registered pool and withdraw actual nonzero rewards.
    #[arg(long, requires = "faucet")]
    stake_pool: Option<String>,
    /// Balance, sign and confirm an independently constructed partial payment.
    #[arg(long)]
    balance: bool,
    /// Check exact unsupported collateral input/return/total guards.
    #[arg(long)]
    collateral: bool,
    /// Check real-node lower bounds, expiry, relative seconds and default TTL.
    #[arg(long)]
    validity: bool,
    /// Public genesis for the controlled single-era validity cluster.
    #[arg(long)]
    shelley_genesis: Option<PathBuf>,
    /// Public Byron genesis anchoring the combined Cardano chain clock.
    #[arg(long)]
    byron_genesis: Option<PathBuf>,
    /// Verify routing, network and empty/funded wallet error precedence.
    #[arg(long)]
    precedence: bool,
    /// Verify CIP83 metadata against independent OpenSSL and real node history.
    #[arg(long)]
    metadata: bool,
    #[arg(long, default_value = "openssl")]
    openssl: PathBuf,
    /// Run simultaneous construction/submission and real conflicting-spend checks.
    #[arg(long)]
    concurrency: bool,
    /// Run funded Shelley fees, selection, legacy payment and migration checks.
    #[arg(long)]
    payments: bool,
    /// Run native mint/burn, asset inventory and node witness-rejection checks.
    #[arg(long)]
    assets: bool,
    /// Separate reference wallet used only to supply an external watch-only witness.
    #[arg(long)]
    external_signer: Option<String>,
    /// Run funded two-party shared activation and merged signing checks.
    #[arg(long)]
    shared: bool,
    /// Run funded Byron/Shelley payment and migration profiles as well.
    #[arg(long)]
    families: bool,
    /// Trusted node socket for independent chain and UTxO verification.
    #[arg(long)]
    node_socket: PathBuf,
    #[arg(long)]
    network_magic: u32,
    #[arg(long, default_value = "cardano-cli")]
    cardano_cli: PathBuf,
    #[arg(long)]
    target: String,
    #[arg(long, conflicts_with = "funded_mnemonic_env")]
    faucet: Option<String>,
    /// Name of an environment variable containing a funded TESTNET mnemonic.
    #[arg(long, conflicts_with = "faucet")]
    funded_mnemonic_env: Option<String>,
    #[arg(long)]
    environment: String,
    #[arg(long, default_value = "live-report.json")]
    report: PathBuf,
    #[arg(long, default_value_t = 180)]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 2_000_000)]
    amount: u64,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute the complete wallet specification against one configured implementation.
    #[cfg(target_os = "linux")]
    Conform {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
    },
    /// Prove real wallet rollback and reapplication on isolated native branches.
    #[cfg(target_os = "linux")]
    VerifyRollback {
        /// SHA-pinned actual Haskell key adapter for fresh public change derivation.
        #[arg(long)]
        key_oracle: PathBuf,
        #[arg(long)]
        base_cluster: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        cardano_node: PathBuf,
        #[arg(long)]
        cardano_cli: PathBuf,
        #[arg(long)]
        wallet_launch: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        environment: String,
        #[arg(long)]
        report: PathBuf,
        #[arg(long, default_value_t = 180)]
        timeout_seconds: u64,
    },
    /// Audit real isolated native branches from a gracefully closed common snapshot.
    #[cfg(target_os = "linux")]
    AuditForkFixture {
        #[arg(long)]
        base_cluster: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        cardano_node: PathBuf,
        #[arg(long)]
        cardano_cli: PathBuf,
        #[arg(long, default_value_t = 180)]
        timeout_seconds: u64,
    },
    /// Verify real pending persistence and deletion under owned producer controls.
    #[cfg(target_os = "linux")]
    VerifyPendingState {
        /// Prove persisted checkpoint reuse and catch-up after real offline funding.
        #[arg(long, conflicts_with_all = ["retry", "expiry", "byron"])]
        checkpoint: bool,
        /// Prove real scheduled retry after a short-lived native mempool conflict.
        #[arg(long, conflicts_with_all = ["expiry", "byron"], requires_all = ["adversary_wallet_launch", "adversary_target"])]
        retry: bool,
        #[arg(long, requires = "retry")]
        adversary_wallet_launch: Option<PathBuf>,
        #[arg(long, requires = "retry")]
        adversary_target: Option<String>,
        /// Prove genuine pending and confirmed Byron deletion for both wallet styles.
        #[arg(long, conflicts_with = "expiry")]
        byron: bool,
        /// Prove pending expiry instead of restart/deletion/reappearance.
        #[arg(long)]
        expiry: bool,
        #[arg(long)]
        cluster_launch: PathBuf,
        #[arg(long)]
        wallet_launch: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        cardano_node: PathBuf,
        #[arg(long)]
        cardano_cli: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        faucet: String,
        #[arg(long)]
        environment: String,
        #[arg(long)]
        report: PathBuf,
        #[arg(long, default_value_t = 180)]
        timeout_seconds: u64,
    },
    /// Verify actual wallet restoration, payments and certificates across a real fork.
    VerifyEraBoundary {
        #[arg(long)]
        base_cluster: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        cardano_node: PathBuf,
        #[arg(long)]
        cardano_cli: PathBuf,
        #[arg(long)]
        wallet_launch: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        environment: String,
        #[arg(long)]
        report: PathBuf,
        #[arg(long, default_value_t = 3)]
        conway_epoch: u64,
        #[arg(long, default_value_t = 180)]
        timeout_seconds: u64,
    },
    /// Audit a real scheduled Babbage→Conway fork using directly owned node children.
    AuditEraFixture {
        #[arg(long)]
        base_cluster: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        cardano_node: PathBuf,
        #[arg(long)]
        cardano_cli: PathBuf,
        #[arg(long, default_value_t = 3)]
        conway_epoch: u64,
        #[arg(long, default_value_t = 180)]
        timeout_seconds: u64,
    },
    /// Verify exact real registered-DRep reads around a fresh owned wallet cache.
    VerifyDrepLookup {
        #[arg(long)]
        node_socket: PathBuf,
        #[arg(long)]
        cardano_cli: PathBuf,
        #[arg(long)]
        fixture_receipt: PathBuf,
        #[arg(long)]
        wallet_launch: PathBuf,
        #[arg(long)]
        wallet_workspace: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        environment: String,
        #[arg(long)]
        report: PathBuf,
        #[arg(long, default_value_t = 240)]
        timeout_seconds: u64,
    },
    /// Register a real owned key DRep before starting a fresh wallet cache.
    PrepareDrepFixture {
        #[arg(long)]
        node_socket: PathBuf,
        #[arg(long)]
        faucet: String,
        #[arg(long)]
        cardano_cli: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long, default_value_t = 240)]
        timeout_seconds: u64,
    },
    /// Enact a real controlled Conway proposal with the owned committee fixture.
    EnactParameterUpdate {
        #[arg(long)]
        node_socket: PathBuf,
        #[arg(long)]
        fixture: PathBuf,
        #[arg(long)]
        faucet: String,
        #[arg(long)]
        cardano_cli: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 240)]
        timeout_seconds: u64,
    },
    /// Prepare a fresh private cluster configuration with an explicitly owned committee.
    PrepareParameterCluster {
        #[arg(long)]
        base_configs: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        cardano_cli: PathBuf,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// Prepare independently verified retirement of an explicitly owned registered fixture.
    RetirePoolFixture {
        #[arg(long)]
        node_socket: PathBuf,
        #[arg(long, default_value_t = 42)]
        network_magic: u32,
        #[arg(long)]
        cardano_cli: PathBuf,
        #[arg(long)]
        owned_cluster_pool: PathBuf,
        #[arg(long)]
        registration_directory: PathBuf,
        #[arg(long)]
        epoch: u64,
        #[arg(long)]
        output_directory: PathBuf,
        #[arg(long, default_value_t = 180)]
        timeout_seconds: u64,
    },
    /// Audit producer-only pause/resume in a fresh exclusively owned Linux cluster.
    AuditClusterControl {
        #[arg(long)]
        cluster_launch: PathBuf,
        #[arg(long)]
        cluster_workspace: PathBuf,
        #[arg(long)]
        cardano_node: PathBuf,
        #[arg(long)]
        cardano_cli: PathBuf,
        #[arg(long, default_value_t = 42)]
        network_magic: u32,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// Audit transparent connection faults against an independently advancing real node.
    AuditNodeProxy {
        #[arg(long)]
        node_socket: PathBuf,
        #[arg(long)]
        proxy_socket: PathBuf,
        #[arg(long)]
        network_magic: u32,
        #[arg(long, default_value = "cardano-cli")]
        cardano_cli: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
    /// Freeze actual wallet signed-size boundaries with independent CBOR checks.
    CaptureSizeProfiles {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        audit_directory: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Freeze actual Haskell withdrawal codecs from a public node-backed audit.
    CaptureRewardProfiles {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        audit_directory: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Register an explicitly owned local-cluster pool and save independent proof.
    PreparePoolFixture {
        #[arg(long, requires = "metadata_file")]
        metadata_url: Option<String>,
        #[arg(long, requires = "metadata_url")]
        metadata_file: Option<PathBuf>,
        #[arg(long)]
        owned_cluster_pool: PathBuf,
        #[arg(long)]
        node_socket: PathBuf,
        #[arg(long, default_value_t = 42)]
        network_magic: u32,
        #[arg(long, default_value = "cardano-cli")]
        cardano_cli: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        faucet: String,
        #[arg(long)]
        output_directory: PathBuf,
        #[arg(long, default_value_t = 150_000_000_000_000)]
        pledge: u64,
        #[arg(long, default_value_t = 180)]
        timeout_seconds: u64,
    },
    /// Freeze actual Conway ledger minimum fees and reference-script tiers.
    CaptureLedgerFees {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Freeze actual wallet collateral and mint/burn selection profiles.
    CaptureWalletSelections {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Generate valid-body and owned unfunded HTTP status cases.
    GenerateExtendedApi {
        #[arg(long)]
        output: PathBuf,
    },
    /// Freeze actual wallet witness and certificate profiles.
    CaptureWriterProfiles {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Freeze actual fee and minimum-ADA component profiles.
    CaptureBalanceProfiles {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Freeze actual wallet slot/time rounding boundary profiles.
    CaptureSlottingProfiles {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Capture actual wallet collateral-return and incomplete-payment codecs.
    CaptureBalancingProfiles {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Freeze actual wallet transaction, metadata and ledger signature profiles.
    CaptureLedgerProfiles {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Freeze address, script, codec and Byron payload profiles from Haskell.
    CaptureAddressProfiles {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Capture mnemonic, generation-factor and hardware profiles from Haskell.
    CaptureMnemonicProfiles {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Capture key boundary outputs from the pinned source-built Haskell adapter.
    CaptureKeyBoundaries {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Freeze actual wallet/database credential transitions from the pinned reference.
    CaptureCredentials {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Freeze production-cost encrypted-root answers from the pinned Haskell backend.
    CaptureRoots {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Freeze exact seeded selection answers from the pinned source-built Haskell oracle.
    CaptureSelections {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Capture primitive boundary vectors from pinned OpenSSL and Haskell binaries.
    CapturePrimitives {
        #[arg(long)]
        openssl: PathBuf,
        #[arg(long)]
        cardano_cli: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Generate negative response-status coverage without a funded wallet.
    GenerateApiStatuses {
        #[arg(long)]
        output: PathBuf,
    },
    /// Generate public HTTP key/address cases from frozen independent Haskell vectors.
    GenerateKeyApi {
        #[arg(long)]
        output: PathBuf,
    },
    /// Export the behavioral specification draft and explicit validation gaps.
    Specification {
        #[arg(long)]
        output: PathBuf,
        #[arg(long = "report")]
        reports: Vec<PathBuf>,
        #[arg(long)]
        require_complete: bool,
    },
    /// Generate negative API routing, content negotiation and syntax cases.
    GenerateApiRejections {
        #[arg(long)]
        output: PathBuf,
    },
    /// Regenerate the replayable, independent multiasset selection invariant corpus.
    GenerateSelections {
        #[arg(long)]
        output: PathBuf,
    },
    /// Capture key/address fixtures from the SHA-256-pinned Haskell reference tool.
    CaptureKeys {
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// List all pinned API operations and mandatory domain requirements.
    Inventory,
    /// Run declarative HTTP expectations, optionally comparing a reference wallet.
    Http {
        #[arg(long)]
        target: String,
        #[arg(long)]
        reference: Option<String>,
        #[arg(long, default_value = "fixtures/http.json")]
        suite: PathBuf,
        #[arg(long)]
        environment: String,
        #[arg(long, default_value = "http-report.json")]
        report: PathBuf,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
    },
    /// Require real block production, funding and ledger confirmation of a payment.
    Live(Box<LiveArgs>),
    /// Run independent vectors against an internal adapter, or check primitive oracle fixtures.
    Vectors {
        #[arg(long)]
        adapter: Option<PathBuf>,
        #[arg(long = "adapter-arg")]
        adapter_args: Vec<String>,
        #[arg(
            long,
            required_unless_present = "oracle_check",
            conflicts_with = "oracle_check"
        )]
        target: Option<String>,
        #[arg(
            long,
            required_unless_present = "oracle_check",
            conflicts_with = "oracle_check"
        )]
        environment: Option<String>,
        #[arg(long, conflicts_with = "adapter")]
        oracle_check: bool,
        #[arg(long = "corpus", required = true)]
        corpora: Vec<PathBuf>,
        /// Run only these operations; omitted vectors remain mandatory at the gate.
        #[arg(long = "operation")]
        operations: Vec<String>,
        #[arg(long, default_value = "vectors-report.json")]
        report: PathBuf,
        #[arg(long, default_value_t = 10)]
        timeout_seconds: u64,
    },
    /// Fail unless every pinned API polarity and domain requirement has passing evidence.
    Gate {
        #[arg(long = "report", required = true)]
        reports: Vec<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// A primitive-only protocol adapter for harness self-tests, not a wallet oracle.
    PrimitiveOracle,
}

fn requirements(contract: &Contract) -> Result<Vec<Requirement>> {
    let mut requirements: Vec<Requirement> =
        serde_json::from_str(include_str!("../fixtures/requirements.json"))?;
    let semantic_cases: std::collections::BTreeMap<String, Vec<String>> =
        serde_json::from_str(include_str!("../fixtures/semantic-obligations.json"))?;
    for (id, cases) in semantic_cases {
        requirements
            .iter_mut()
            .find(|requirement| requirement.id == id)
            .with_context(|| format!("unknown semantic requirement: {id}"))?
            .required_cases
            .extend(cases);
    }
    requirements.extend(contract.requirements());
    for corpus in [
        include_str!("../fixtures/vectors/primitives.json"),
        include_str!("../fixtures/vectors/primitive-boundaries.json"),
        include_str!("../fixtures/vectors/bip39-reference.json"),
        include_str!("../fixtures/vectors/cardano-wallet.json"),
        include_str!("../fixtures/vectors/passphrase-checks.json"),
        include_str!("../fixtures/vectors/signature-verification.json"),
        include_str!("../fixtures/vectors/haskell-selection.json"),
        include_str!("../fixtures/vectors/root-encryption.json"),
        include_str!("../fixtures/vectors/wallet-credentials.json"),
        include_str!("../fixtures/vectors/key-boundaries.json"),
        include_str!("../fixtures/vectors/mnemonic-profiles.json"),
        include_str!("../fixtures/vectors/address-profiles.json"),
        include_str!("../fixtures/vectors/ledger-profiles.json"),
        include_str!("../fixtures/vectors/balance-profiles.json"),
        include_str!("../fixtures/vectors/slotting-profiles.json"),
        include_str!("../fixtures/vectors/balancing-profiles.json"),
        include_str!("../fixtures/vectors/reward-profiles.json"),
        include_str!("../fixtures/vectors/signed-size-profiles.json"),
        include_str!("../fixtures/vectors/input-witness-count-profiles.json"),
        include_str!("../fixtures/vectors/ledger-fees.json"),
        include_str!("../fixtures/vectors/writer-profiles.json"),
        include_str!("../fixtures/vectors/metadata-encryption-profiles.json"),
        include_str!("../fixtures/vectors/wallet-selection.json"),
        include_str!("../fixtures/vectors/coin-selection.json"),
        include_str!("../fixtures/vectors/generated-selection.json"),
        include_str!("../fixtures/vectors/haskell-keys.json"),
    ] {
        for vector in serde_json::from_str::<Vec<Vector>>(corpus)? {
            for id in vector.requirements {
                let requirement = requirements
                    .iter_mut()
                    .find(|r| r.id == id)
                    .with_context(|| format!("unknown corpus requirement: {id}"))?;
                requirement.required_cases.push(vector.id.clone());
            }
        }
    }
    for source in [
        include_str!("../fixtures/http.json"),
        include_str!("../fixtures/http-rejections.json"),
        include_str!("../fixtures/http-signatures.json"),
        include_str!("../fixtures/http-network.json"),
        include_str!("../fixtures/http-keys.json"),
        include_str!("../fixtures/http-statuses.json"),
        include_str!("../fixtures/http-families.json"),
        include_str!("../fixtures/http-extended.json"),
        include_str!("../fixtures/http-governance-media.json"),
    ] {
        let suite: Suite = serde_json::from_str(source)?;
        for case in suite.cases.iter().chain(&suite.cleanup) {
            let mut ids = case.requirements.clone();
            ids.push("api.differential-reference".into());
            ids.push(format!(
                "api:{}:{}",
                case.operation,
                if case.expected_status < 300 {
                    "positive"
                } else {
                    "negative"
                }
            ));
            ids.push(format!(
                "api:{}:status:{}",
                case.operation, case.expected_status
            ));
            for id in ids {
                let requirement = requirements
                    .iter_mut()
                    .find(|r| r.id == id)
                    .with_context(|| format!("unknown scenario requirement: {id}"))?;
                requirement.required_cases.push(case.id.clone());
            }
        }
    }
    for requirement in &mut requirements {
        requirement.required_cases.sort();
        requirement.required_cases.dedup();
    }
    Ok(requirements)
}

fn save_report(report: &Report, path: &PathBuf) -> Result<bool> {
    fs::write(path, serde_json::to_vec_pretty(report)?)?;
    println!(
        "{} cases, {} failed; report: {}",
        report.evidence.len(),
        report.evidence.iter().filter(|e| !e.passed).count(),
        path.display()
    );
    Ok(report.passed())
}

fn run() -> Result<bool> {
    execute(Cli::parse())
}

fn execute(cli: Cli) -> Result<bool> {
    if matches!(cli.command, Commands::PrimitiveOracle) {
        let mut text = String::new();
        io::stdin().take(1_048_577).read_to_string(&mut text)?;
        ensure!(text.len() <= 1_048_576, "request exceeds size limit");
        let req: Value = serde_json::from_str(&text)?;
        ensure!(req["protocol_version"] == 1, "unsupported protocol");
        let mut result = adapter::primitive(
            req["operation"].as_str().context("missing operation")?,
            &req["input"],
        )?;
        result["id"] = req["id"].clone();
        result["protocol_version"] = json!(1);
        println!("{result}");
        return Ok(true);
    }
    let contract = Contract::pinned()?;
    match cli.command {
        #[cfg(target_os = "linux")]
        Commands::Conform { config, workspace } => wallet_conformance::executable::run(
            &config,
            &workspace,
            &contract,
            &requirements(&contract)?,
            |arguments| execute(Cli::try_parse_from(arguments)?),
        ),
        #[cfg(target_os = "linux")]
        Commands::VerifyRollback {
            key_oracle,
            base_cluster,
            workspace,
            cardano_node,
            cardano_cli,
            wallet_launch,
            target,
            environment,
            report,
            timeout_seconds,
        } => {
            let timeout = Duration::from_secs(timeout_seconds);
            let api = Api::new(&target, timeout)?;
            let result = wallet_conformance::live::verify_rollback(
                &api,
                &contract,
                &environment,
                wallet_conformance::live::RollbackOptions {
                    key_oracle: &key_oracle,
                    base: &base_cluster,
                    workspace: &workspace,
                    node: &cardano_node,
                    cli: &cardano_cli,
                    launch: serde_json::from_slice(&fs::read(wallet_launch)?)?,
                    timeout,
                },
            );
            save_report(&result, &report)
        }
        #[cfg(target_os = "linux")]
        Commands::AuditForkFixture {
            base_cluster,
            workspace,
            cardano_node,
            cardano_cli,
            timeout_seconds,
        } => {
            let receipt = wallet_conformance::fork_fixture::audit(
                &base_cluster,
                &workspace,
                &cardano_node,
                &cardano_cli,
                Duration::from_secs(timeout_seconds),
            )?;
            println!("native fork control audit: {}", receipt.display());
            Ok(true)
        }
        #[cfg(target_os = "linux")]
        Commands::VerifyPendingState {
            checkpoint,
            retry,
            adversary_wallet_launch,
            adversary_target,
            byron,
            expiry,
            cluster_launch,
            wallet_launch,
            workspace,
            cardano_node,
            cardano_cli,
            target,
            faucet,
            environment,
            report,
            timeout_seconds,
        } => {
            let timeout = Duration::from_secs(timeout_seconds);
            let api = Api::new(&target, timeout)?;
            let result = wallet_conformance::live::verify_pending_state(
                &api,
                &contract,
                &environment,
                wallet_conformance::live::PendingOptions {
                    checkpoint,
                    retry: if retry {
                        Some(wallet_conformance::live::RetryOptions {
                            launch: serde_json::from_slice(&fs::read(
                                adversary_wallet_launch.context("adversary launch missing")?,
                            )?)?,
                            target: adversary_target
                                .as_deref()
                                .context("adversary URL missing")?,
                        })
                    } else {
                        None
                    },
                    byron,
                    expiry,
                    cluster_launch: serde_json::from_slice(&fs::read(cluster_launch)?)?,
                    wallet_launch: serde_json::from_slice(&fs::read(wallet_launch)?)?,
                    workspace: &workspace,
                    node_executable: &cardano_node,
                    cli_executable: &cardano_cli,
                    faucet: &faucet,
                    timeout,
                },
            );
            save_report(&result, &report)
        }
        Commands::VerifyEraBoundary {
            base_cluster,
            workspace,
            cardano_node,
            cardano_cli,
            wallet_launch,
            target,
            environment,
            report,
            conway_epoch,
            timeout_seconds,
        } => {
            let timeout = Duration::from_secs(timeout_seconds);
            let api = Api::new(&target, timeout)?;
            let launch = serde_json::from_slice(&fs::read(wallet_launch)?)?;
            let result = wallet_conformance::live::verify_era_boundary(
                &api,
                &contract,
                &environment,
                wallet_conformance::era_fixture::Options {
                    base_cluster: &base_cluster,
                    workspace: &workspace,
                    node_executable: &cardano_node,
                    cli_executable: &cardano_cli,
                    conway_epoch,
                    timeout,
                },
                launch,
            );
            save_report(&result, &report)
        }
        Commands::AuditEraFixture {
            base_cluster,
            workspace,
            cardano_node,
            cardano_cli,
            conway_epoch,
            timeout_seconds,
        } => {
            let receipt =
                wallet_conformance::era_fixture::audit(wallet_conformance::era_fixture::Options {
                    base_cluster: &base_cluster,
                    workspace: &workspace,
                    node_executable: &cardano_node,
                    cli_executable: &cardano_cli,
                    conway_epoch,
                    timeout: Duration::from_secs(timeout_seconds),
                })?;
            println!("Scheduled era fixture audit: {}", receipt.display());
            Ok(true)
        }
        Commands::VerifyDrepLookup {
            node_socket,
            cardano_cli,
            fixture_receipt,
            wallet_launch,
            wallet_workspace,
            target,
            environment,
            report,
            timeout_seconds,
        } => {
            let timeout = Duration::from_secs(timeout_seconds);
            let node = wallet_conformance::node::NodeOracle {
                executable: cardano_cli,
                socket: node_socket,
                network_magic: 42,
            };
            let api = Api::new(&target, timeout)?;
            let launch = serde_json::from_slice(&fs::read(wallet_launch)?)?;
            let result = wallet_conformance::drep_lookup::run(
                &api,
                &contract,
                &environment,
                wallet_conformance::drep_lookup::Options {
                    node: &node,
                    fixture_receipt: &fixture_receipt,
                    launch,
                    workspace: &wallet_workspace,
                    timeout,
                },
            );
            save_report(&result, &report)
        }
        Commands::PrepareDrepFixture {
            node_socket,
            faucet,
            cardano_cli,
            workspace,
            timeout_seconds,
        } => {
            let node = wallet_conformance::node::NodeOracle {
                executable: cardano_cli,
                socket: node_socket,
                network_magic: 42,
            };
            let receipt = wallet_conformance::drep_fixture::prepare(
                &node,
                &faucet,
                &workspace,
                Duration::from_secs(timeout_seconds),
            )?;
            println!("DRep registration fixture: {}", receipt.display());
            Ok(true)
        }
        Commands::EnactParameterUpdate {
            node_socket,
            fixture,
            faucet,
            cardano_cli,
            output,
            timeout_seconds,
        } => {
            let node = wallet_conformance::node::NodeOracle {
                executable: cardano_cli,
                socket: node_socket,
                network_magic: 42,
            };
            let receipt = wallet_conformance::protocol_update::enact(
                &node,
                &fixture,
                &faucet,
                &output,
                Duration::from_secs(timeout_seconds),
            )?;
            println!("Parameter enactment fixture: {}", receipt.display());
            Ok(true)
        }
        Commands::PrepareParameterCluster {
            base_configs,
            workspace,
            cardano_cli,
            timeout_seconds,
        } => {
            let receipt = wallet_conformance::protocol_update::prepare(
                &base_configs,
                &workspace,
                &cardano_cli,
                Duration::from_secs(timeout_seconds),
            )?;
            println!("Parameter-update cluster fixture: {}", receipt.display());
            Ok(true)
        }
        Commands::RetirePoolFixture {
            node_socket,
            network_magic,
            cardano_cli,
            owned_cluster_pool,
            registration_directory,
            epoch,
            output_directory,
            timeout_seconds,
        } => {
            let node = wallet_conformance::node::NodeOracle {
                executable: cardano_cli,
                socket: node_socket,
                network_magic,
            };
            let receipt = wallet_conformance::pool_fixture::retire(
                &node,
                &owned_cluster_pool,
                &registration_directory,
                epoch,
                &output_directory,
                Duration::from_secs(timeout_seconds),
            )?;
            println!("Pool retirement fixture receipt: {}", receipt.display());
            Ok(true)
        }
        Commands::AuditClusterControl {
            cluster_launch,
            cluster_workspace,
            cardano_node,
            cardano_cli,
            network_magic,
            output,
            timeout_seconds,
        } => {
            wallet_conformance::cluster_control::audit(
                &cluster_launch,
                &cluster_workspace,
                &cardano_node,
                &cardano_cli,
                network_magic,
                Duration::from_secs(timeout_seconds),
                &output,
            )?;
            Ok(true)
        }
        Commands::AuditNodeProxy {
            node_socket,
            proxy_socket,
            network_magic,
            cardano_cli,
            output,
            timeout_seconds,
        } => wallet_conformance::node_proxy::audit(
            &wallet_conformance::node::NodeOracle {
                executable: cardano_cli,
                socket: node_socket,
                network_magic,
            },
            &proxy_socket,
            Duration::from_secs(timeout_seconds),
            &output,
        ),
        Commands::CaptureSizeProfiles {
            oracle,
            audit_directory,
            output,
        } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite an existing oracle corpus"
            );
            let vectors = wallet_conformance::signed_size::capture(&oracle, &audit_directory)?;
            fs::write(&output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} actual signed-size profiles to {}",
                vectors.len(),
                output.display()
            );
            Ok(true)
        }
        Commands::CaptureRewardProfiles {
            oracle,
            audit_directory,
            output,
        } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite an existing oracle corpus"
            );
            let vectors = wallet_conformance::rewards::capture(&oracle, &audit_directory)?;
            fs::write(&output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} reward profiles to {}",
                vectors.len(),
                output.display()
            );
            Ok(true)
        }
        Commands::PreparePoolFixture {
            metadata_url,
            metadata_file,
            owned_cluster_pool,
            node_socket,
            network_magic,
            cardano_cli,
            target,
            faucet,
            output_directory,
            pledge,
            timeout_seconds,
        } => {
            let metadata = match (metadata_url, metadata_file) {
                (None, None) => None,
                (Some(url), Some(path)) => {
                    let mut bytes = Vec::new();
                    fs::File::open(path)?.take(513).read_to_end(&mut bytes)?;
                    ensure!(bytes.len() <= 512, "metadata exceeds512bytes");
                    Some(wallet_conformance::pool_fixture::Metadata { url, bytes })
                }
                _ => anyhow::bail!("metadata URL and file must be supplied together"),
            };
            let receipt = wallet_conformance::pool_fixture::prepare_with_metadata(
                &wallet_conformance::pool_fixture::Options {
                    node: wallet_conformance::node::NodeOracle {
                        executable: cardano_cli,
                        socket: node_socket,
                        network_magic,
                    },
                    owned_pool: owned_cluster_pool,
                    target,
                    faucet,
                    output: output_directory,
                    timeout: Duration::from_secs(timeout_seconds),
                    pledge,
                },
                metadata.as_ref(),
            )?;
            println!("Pool fixture receipt: {}", receipt.display());
            Ok(true)
        }
        Commands::CaptureCredentials { oracle, output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite a wallet credential corpus"
            );
            let vectors = wallet_conformance::credentials::capture(&oracle)?;
            fs::write(output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} actual wallet credential vectors",
                vectors.len()
            );
            Ok(true)
        }
        Commands::CaptureRoots { oracle, output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite an encrypted-root corpus"
            );
            let vectors = wallet_conformance::reference::capture_roots(&oracle)?;
            fs::write(output, serde_json::to_vec_pretty(&vectors)?)?;
            println!("Captured {} Haskell encrypted-root vectors", vectors.len());
            Ok(true)
        }
        Commands::CaptureSelections { oracle, output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite a Haskell selection corpus"
            );
            let vectors = wallet_conformance::reference::capture_selections(&oracle)?;
            fs::write(output, serde_json::to_vec_pretty(&vectors)?)?;
            println!("Captured {} exact Haskell selection vectors", vectors.len());
            Ok(true)
        }
        Commands::CapturePrimitives {
            openssl,
            cardano_cli,
            output,
        } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite primitive oracle corpus"
            );
            let vectors =
                wallet_conformance::reference::capture_primitives(&openssl, &cardano_cli)?;
            fs::write(output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} independent primitive boundary vectors",
                vectors.len()
            );
            Ok(true)
        }
        Commands::GenerateApiStatuses { output } => {
            ensure!(!output.exists(), "refusing to overwrite API status corpus");
            fs::write(
                output,
                serde_json::to_vec_pretty(&wallet_conformance::generate::api_statuses(&contract))?,
            )?;
            Ok(true)
        }
        Commands::GenerateExtendedApi { output } => {
            ensure!(!output.exists(), "refusing to overwrite an HTTP corpus");
            fs::write(
                output,
                serde_json::to_vec_pretty(&wallet_conformance::http_extended::generate(
                    &contract,
                )?)?,
            )?;
            Ok(true)
        }
        Commands::GenerateKeyApi { output } => {
            ensure!(!output.exists(), "refusing to overwrite key API corpus");
            fs::write(
                output,
                serde_json::to_vec_pretty(&wallet_conformance::generate::key_api()?)?,
            )?;
            Ok(true)
        }
        Commands::Specification {
            output,
            reports,
            require_complete,
        } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite a specification export"
            );
            let reports: Vec<Report> = reports
                .iter()
                .map(|path| Ok(serde_json::from_slice(&fs::read(path)?)?))
                .collect::<Result<_>>()?;
            let specification = wallet_conformance::specification::export(
                &contract,
                &requirements(&contract)?,
                &reports,
            )?;
            let complete = specification["validation"]["exhaustive"] == true;
            fs::write(&output, serde_json::to_vec_pretty(&specification)?)?;
            println!(
                "Behavioral specification draft: {}; catalogue complete: {complete}",
                output.display()
            );
            Ok(!require_complete || complete)
        }
        Commands::GenerateApiRejections { output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite API rejection corpus"
            );
            fs::write(
                output,
                serde_json::to_vec_pretty(&wallet_conformance::generate::api_rejections(
                    &contract,
                ))?,
            )?;
            Ok(true)
        }
        Commands::GenerateSelections { output } => {
            ensure!(!output.exists(), "refusing to overwrite a selection corpus");
            fs::write(
                output,
                serde_json::to_vec_pretty(&wallet_conformance::generate::selections())?,
            )?;
            Ok(true)
        }
        Commands::CaptureAddressProfiles { oracle, output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite an existing oracle corpus"
            );
            let vectors = wallet_conformance::addresses::capture(&oracle)?;
            fs::write(&output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} address/script profiles to {}",
                vectors.len(),
                output.display()
            );
            Ok(true)
        }
        Commands::CaptureLedgerProfiles { oracle, output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite an existing oracle corpus"
            );
            let vectors = wallet_conformance::ledger::capture(&oracle)?;
            fs::write(&output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} ledger profiles to {}",
                vectors.len(),
                output.display()
            );
            Ok(true)
        }
        Commands::CaptureBalanceProfiles { oracle, output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite an existing oracle corpus"
            );
            let vectors = wallet_conformance::balance::capture(&oracle)?;
            fs::write(&output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} balance profiles to {}",
                vectors.len(),
                output.display()
            );
            Ok(true)
        }
        Commands::CaptureBalancingProfiles { oracle, output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite an existing oracle corpus"
            );
            let vectors = wallet_conformance::balancing::capture(&oracle)?;
            fs::write(&output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} balancing profiles to {}",
                vectors.len(),
                output.display()
            );
            Ok(true)
        }
        Commands::CaptureSlottingProfiles { oracle, output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite an existing oracle corpus"
            );
            let vectors = wallet_conformance::slotting::capture(&oracle)?;
            fs::write(&output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} slotting profiles to {}",
                vectors.len(),
                output.display()
            );
            Ok(true)
        }
        Commands::CaptureLedgerFees { oracle, output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite an existing oracle corpus"
            );
            let vectors = wallet_conformance::ledger_fees::capture(&oracle)?;
            fs::write(&output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} ledger fee profiles to {}",
                vectors.len(),
                output.display()
            );
            Ok(true)
        }
        Commands::CaptureWriterProfiles { oracle, output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite an existing oracle corpus"
            );
            let vectors = wallet_conformance::writer::capture(&oracle)?;
            fs::write(&output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} writer profiles to {}",
                vectors.len(),
                output.display()
            );
            Ok(true)
        }
        Commands::CaptureWalletSelections { oracle, output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite an existing oracle corpus"
            );
            let vectors = wallet_conformance::wallet_selection::capture(&oracle)?;
            fs::write(&output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} wallet selections to {}",
                vectors.len(),
                output.display()
            );
            Ok(true)
        }
        Commands::CaptureMnemonicProfiles { oracle, output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite an existing oracle corpus"
            );
            let vectors = wallet_conformance::mnemonics::capture(&oracle)?;
            fs::write(&output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} mnemonic/root profiles to {}",
                vectors.len(),
                output.display()
            );
            Ok(true)
        }
        Commands::CaptureKeyBoundaries { oracle, output } => {
            ensure!(
                !output.exists(),
                "refusing to overwrite an existing oracle corpus"
            );
            let vectors = wallet_conformance::keys::capture(&oracle)?;
            fs::write(&output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} key boundary vectors to {}",
                vectors.len(),
                output.display()
            );
            Ok(true)
        }
        Commands::CaptureKeys { oracle, output } => {
            let vectors = wallet_conformance::reference::capture_keys(&oracle)?;
            ensure!(
                !output.exists(),
                "refusing to overwrite an existing oracle corpus"
            );
            fs::write(&output, serde_json::to_vec_pretty(&vectors)?)?;
            println!(
                "Captured {} Haskell key/address vectors to {}",
                vectors.len(),
                output.display()
            );
            Ok(true)
        }
        Commands::Inventory => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"operations":contract.operations,"requirements":requirements(&contract)?})
                )?
            );
            Ok(true)
        }
        Commands::Http {
            target,
            reference,
            suite,
            environment,
            report,
            timeout_seconds,
        } => {
            let timeout = Duration::from_secs(timeout_seconds);
            let api = Api::new(&target, timeout)?;
            let reference = reference
                .as_ref()
                .map(|r| Api::new(r, timeout))
                .transpose()?;
            if let Some(reference) = &reference {
                ensure!(
                    api.label != reference.label,
                    "target and reference must be distinct wallet services"
                );
            }
            let suite: Suite = serde_json::from_slice(&fs::read(suite)?)?;
            save_report(
                &scenarios::run(&suite, &api, reference.as_ref(), &contract, &environment)?,
                &report,
            )
        }
        Commands::Live(options) => {
            let LiveArgs {
                parameter_fixture,
                parameter_workspace,
                pool_directory,
                pool_workspace,
                discovery,
                history,
                node_disconnect_socket,
                wallet_launch,
                wallet_workspace,
                input_limits,
                voting,
                delegation_fees,
                pool_join_guard,
                stake_pool,
                balance,
                collateral,
                validity,
                shelley_genesis,
                byron_genesis,
                precedence,
                metadata,
                openssl,
                concurrency,
                payments,
                assets,
                external_signer,
                shared,
                families,
                node_socket,
                network_magic,
                cardano_cli,
                target,
                faucet,
                funded_mnemonic_env,
                environment,
                report,
                timeout_seconds,
                amount,
            } = *options;
            let mnemonic = funded_mnemonic_env
                .map(|name| {
                    std::env::var(name)
                        .context("funded mnemonic environment variable is missing")
                        .map(|s| s.split_whitespace().map(str::to_owned).collect())
                })
                .transpose()?;
            let timeout = Duration::from_secs(timeout_seconds);
            let mut node_proxy = None;
            let mut owned_process = if let Some(manifest) = wallet_launch {
                wallet_conformance::owned_process::require_unused_listener(&target)?;
                let launch: wallet_conformance::owned_process::Launch =
                    serde_json::from_slice(&fs::read(manifest)?)?;
                if let Some(socket) = &node_disconnect_socket {
                    let socket_text = socket.to_str().context("non-UTF8 proxy socket path")?;
                    ensure!(
                        launch
                            .arguments
                            .iter()
                            .chain(launch.environment.values())
                            .any(|value| value == socket_text),
                        "disconnect wallet manifest must reference the exact proxy socket"
                    );
                    node_proxy = Some(wallet_conformance::node_proxy::SocketProxy::bind(
                        socket,
                        &node_socket,
                    )?);
                }
                let mut process = wallet_conformance::owned_process::WalletProcess::start(
                    launch,
                    wallet_workspace
                        .as_deref()
                        .context("owned wallet workspace missing")?,
                )?;
                process.wait_listener(&target, timeout)?;
                Some(process)
            } else {
                None
            };
            let api = Api::new(&target, timeout.min(Duration::from_secs(30)))?;
            save_report(
                &live::run(
                    &api,
                    &contract,
                    &LiveOptions {
                        node: wallet_conformance::node::NodeOracle {
                            executable: cardano_cli,
                            socket: node_socket,
                            network_magic,
                        },
                        timeout,
                        faucet,
                        funded_mnemonic: mnemonic,
                        amount,
                        families,
                        shared,
                        external_signer,
                        assets,
                        payments,
                        concurrency,
                        metadata,
                        precedence,
                        validity,
                        shelley_genesis,
                        byron_genesis,
                        balance,
                        collateral,
                        voting,
                        delegation_fees,
                        pool_join_guard,
                        stake_pool,
                        input_limits,
                        history,
                        discovery,
                        pool_directory,
                        pool_workspace: pool_workspace.map(|path| *path),
                        parameter_fixture,
                        parameter_workspace,
                        openssl,
                    },
                    &environment,
                    owned_process.as_mut(),
                    node_proxy.as_ref(),
                )?,
                &report,
            )
        }
        Commands::Vectors {
            adapter,
            adapter_args,
            target,
            environment,
            oracle_check,
            corpora,
            operations,
            report,
            timeout_seconds,
        } => {
            ensure!(
                adapter.is_some() || oracle_check,
                "provide --adapter or --oracle-check"
            );
            let mut vectors: Vec<Vector> = Vec::new();
            for corpus in corpora {
                vectors.extend(serde_json::from_slice::<Vec<Vector>>(&fs::read(corpus)?)?);
            }
            if !operations.is_empty() {
                vectors.retain(|vector| operations.contains(&vector.operation));
            }
            let target = target.unwrap_or_else(|| "harness-primitive-oracle".into());
            let environment = environment.unwrap_or_else(|| "harness-self-test".into());
            save_report(
                &adapter::run(
                    &vectors,
                    adapter.as_deref(),
                    &adapter_args,
                    Duration::from_secs(timeout_seconds),
                    &target,
                    &environment,
                )?,
                &report,
            )
        }
        Commands::Gate { reports, output } => {
            let reports: Vec<Report> = reports
                .iter()
                .map(|p| Ok(serde_json::from_slice(&fs::read(p)?)?))
                .collect::<Result<_>>()?;
            ensure!(
                reports
                    .iter()
                    .all(|r| !r.target.starts_with("harness-")
                        && r.environment != "harness-self-test"),
                "harness self-tests are not wallet conformance evidence"
            );
            let coverage = report::coverage(&requirements(&contract)?, &reports)?;
            let json = serde_json::to_string_pretty(&coverage)?;
            if let Some(output) = output {
                fs::write(output, &json)?;
            }
            println!("{json}");
            Ok(coverage.exhaustive)
        }
        Commands::PrimitiveOracle => unreachable!(),
    }
}

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    }
}
