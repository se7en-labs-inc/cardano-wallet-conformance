//! Explicit evidence and a fail-closed completeness gate.
use anyhow::{anyhow, ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub case: String,
    pub requirements: Vec<String>,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub format_version: u32,
    #[serde(alias = "reference_revision")]
    pub contract_reference_revision: String,
    #[serde(default)]
    pub suite_sha256: String,
    #[serde(default)]
    pub unregistered_inputs: Vec<String>,
    #[serde(default)]
    pub harness_self_test: bool,
    pub environment: String,
    pub target: String,
    pub evidence: Vec<Evidence>,
}

impl Report {
    pub fn new(target: impl Into<String>, environment: impl Into<String>) -> Self {
        Self {
            format_version: 1,
            contract_reference_revision: "2fc5c383c94bb907deaa0cd27b1b407f86224b6c".into(),
            suite_sha256: suite_sha256(),
            unregistered_inputs: Vec::new(),
            harness_self_test: false,
            target: target.into(),
            environment: environment.into(),
            evidence: Vec::new(),
        }
    }

    pub fn record(&mut self, case: &str, requirements: &[String], result: Result<()>) {
        self.evidence.push(Evidence {
            case: case.into(),
            requirements: requirements.to_vec(),
            passed: result.is_ok(),
            // Never include request/response bodies or secret values in diagnostics.
            detail: result
                .err()
                .map_or_else(|| "passed".into(), |e| e.to_string()),
        });
    }

    pub fn passed(&self) -> bool {
        !self.evidence.is_empty() && self.evidence.iter().all(|e| e.passed)
    }
}

/// Bind evidence to the executable assertions and shipped corpus, including
/// behavioral corrections. Legacy reports remain readable but cannot close gaps.
pub fn suite_sha256() -> String {
    let mut digest = Sha256::new();
    for source in [
        include_str!("api.rs"),
        include_str!("adapter.rs"),
        include_str!("live.rs"),
        include_str!("live/families.rs"),
        include_str!("live/watch_only.rs"),
        include_str!("live/assets.rs"),
        include_str!("live/stake_rewards.rs"),
        include_str!("live/concurrency.rs"),
        include_str!("live/metadata.rs"),
        include_str!("live/transport.rs"),
        include_str!("live/precedence.rs"),
        include_str!("live/validity.rs"),
        include_str!("live/balancing.rs"),
        include_str!("live/input_limits.rs"),
        include_str!("live/restart.rs"),
        include_str!("live/disconnect.rs"),
        include_str!("live/discovery.rs"),
        include_str!("live/pools.rs"),
        include_str!("live/parameters.rs"),
        include_str!("live/era_boundary.rs"),
        include_str!("live/pending.rs"),
        include_str!("live/pending_byron.rs"),
        include_str!("live/retry.rs"),
        include_str!("live/checkpoint.rs"),
        include_str!("live/rollback.rs"),
        include_str!("../fixtures/retry-payment-controls.json"),
        include_str!("../fixtures/history-status-control.json"),
        include_str!("live/delegation_fees.rs"),
        include_str!("live/pool_join_guard.rs"),
        include_str!("live/history.rs"),
        include_str!("live/voting.rs"),
        include_str!("../fixtures/voting-controls.json"),
        include_str!("../fixtures/stake-reward-controls.json"),
        include_str!("../fixtures/balancing-errors.json"),
        include_str!("../fixtures/balanced-control.json"),
        include_str!("../fixtures/validity-expired-error.json"),
        include_str!("../fixtures/validity-expired-transaction.json"),
        include_str!("node.rs"),
        include_str!("pool_fixture.rs"),
        include_str!("protocol_update.rs"),
        include_str!("drep_fixture.rs"),
        include_str!("drep_lookup.rs"),
        include_str!("era_fixture.rs"),
        include_str!("../fixtures/drep-node-control.json"),
        include_str!("../fixtures/pool-registration-control.json"),
        include_str!("../fixtures/parameter-proposal-control.json"),
        include_str!("../fixtures/parameter-network-control.json"),
        include_str!("scenarios.rs"),
        include_str!("transaction.rs"),
        include_str!("encoding.rs"),
        include_str!("report.rs"),
        include_str!("main.rs"),
        include_str!("executable.rs"),
        include_str!("../fixtures/execution-profiles.json"),
        include_str!("lib.rs"),
        include_str!("owned_process.rs"),
        include_str!("cluster_control.rs"),
        include_str!("node_proxy.rs"),
        include_str!("chain_observer.rs"),
        include_str!("fork_fixture.rs"),
        include_str!("../Cargo.toml"),
        include_str!("../Cargo.lock"),
        include_str!("specification.rs"),
        include_str!("generate.rs"),
        include_str!("reference.rs"),
        include_str!("../reference/HaskellAdapter.hs"),
        include_str!("credentials.rs"),
        include_str!("keys.rs"),
        include_str!("mnemonics.rs"),
        include_str!("addresses.rs"),
        include_str!("ledger.rs"),
        include_str!("balance.rs"),
        include_str!("ledger_fees.rs"),
        include_str!("../reference/FeeAdapter.hs"),
        include_str!("../reference/SizeAdapter.hs"),
        include_str!("../reference/WitnessCountAdapter.hs"),
        include_str!("../fixtures/vectors/input-witness-count-profiles.json"),
        include_str!("../fixtures/vectors/ledger-fees.json"),
        include_str!("writer.rs"),
        include_str!("wallet_selection.rs"),
        include_str!("../reference/SelectionAdapter.hs"),
        include_str!("../fixtures/vectors/wallet-selection.json"),
        include_str!("http_extended.rs"),
        include_str!("../reference/WriterAdapter.hs"),
        include_str!("../reference/MetadataAdapter.hs"),
        include_str!("../fixtures/vectors/metadata-encryption-profiles.json"),
        include_str!("../fixtures/vectors/writer-profiles.json"),
        include_str!("../reference/BalanceAdapter.hs"),
        include_str!("slotting.rs"),
        include_str!("balancing.rs"),
        include_str!("rewards.rs"),
        include_str!("signed_size.rs"),
        include_str!("../fixtures/vectors/signed-size-profiles.json"),
        include_str!("../fixtures/vectors/reward-profiles.json"),
        include_str!("../fixtures/vectors/balancing-profiles.json"),
        include_str!("../reference/SlottingAdapter.hs"),
        include_str!("../fixtures/vectors/slotting-profiles.json"),
        include_str!("../fixtures/vectors/balance-profiles.json"),
        include_str!("../reference/LedgerAdapter.hs"),
        include_str!("../fixtures/vectors/ledger-profiles.json"),
        include_str!("../reference/AddressAdapter.hs"),
        include_str!("../fixtures/vectors/address-profiles.json"),
        include_str!("bin/haskell-mnemonic-reference.rs"),
        include_str!("../reference/MnemonicAdapter.hs"),
        include_str!("../fixtures/vectors/mnemonic-profiles.json"),
        include_str!("../reference/KeyAdapter.hs"),
        include_str!("../fixtures/vectors/key-boundaries.json"),
        include_str!("../reference/WalletCredentialAdapter.hs"),
        include_str!("../reference/credential-faults.rs"),
        include_str!("../reference/wallet-toolchain.nix"),
        include_str!("../fixtures/api/openapi.yaml"),
        include_str!("../fixtures/api/haskell-corrections.json"),
        include_str!("../fixtures/api/retired-responses.json"),
        include_str!("../fixtures/requirements.json"),
        include_str!("../fixtures/semantic-obligations.json"),
        include_str!("../fixtures/provenance.json"),
        include_str!("../docs/adapter.md"),
        include_str!("../docs/live-contracts.md"),
        include_str!("../fixtures/http.json"),
        include_str!("../fixtures/http-rejections.json"),
        include_str!("../fixtures/http-signatures.json"),
        include_str!("../fixtures/http-network.json"),
        include_str!("../fixtures/http-keys.json"),
        include_str!("../fixtures/http-statuses.json"),
        include_str!("../fixtures/http-families.json"),
        include_str!("../fixtures/http-extended.json"),
        include_str!("../fixtures/http-governance-media.json"),
        include_str!("../fixtures/vectors/primitives.json"),
        include_str!("../fixtures/vectors/primitive-boundaries.json"),
        include_str!("../fixtures/vectors/bip39-reference.json"),
        include_str!("../fixtures/vectors/cardano-wallet.json"),
        include_str!("../fixtures/vectors/passphrase-checks.json"),
        include_str!("../fixtures/vectors/signature-verification.json"),
        include_str!("../fixtures/vectors/haskell-selection.json"),
        include_str!("../fixtures/vectors/root-encryption.json"),
        include_str!("../fixtures/vectors/wallet-credentials.json"),
        include_str!("../fixtures/vectors/coin-selection.json"),
        include_str!("../fixtures/vectors/generated-selection.json"),
        include_str!("../fixtures/vectors/haskell-keys.json"),
    ] {
        digest.update((source.len() as u64).to_be_bytes());
        digest.update(source.as_bytes());
    }
    hex::encode(digest.finalize())
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub id: String,
    pub description: String,
    #[serde(default)]
    pub required_cases: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Coverage {
    pub exhaustive: bool,
    pub required: usize,
    pub covered: usize,
    pub missing: Vec<String>,
    pub unexecuted_cases: BTreeMap<String, Vec<String>>,
    pub failures: Vec<String>,
}

/// Only passing, executed evidence counts. All supplied reports must agree on the target,
/// environment and pinned reference. Coverage is bounded by the catalogue, never a proof.
pub fn coverage(requirements: &[Requirement], reports: &[Report]) -> Result<Coverage> {
    ensure!(!requirements.is_empty(), "empty requirements catalogue");
    ensure!(!reports.is_empty(), "no execution reports supplied");
    let first = &reports[0];
    let mut ids = BTreeSet::new();
    for req in requirements {
        ensure!(ids.insert(&req.id), "duplicate requirement ID: {}", req.id);
    }
    let mut seen = BTreeSet::new();
    let mut passing_cases = BTreeSet::new();
    let mut failures = Vec::new();
    for report in reports {
        ensure!(report.format_version == 1, "unsupported report format");
        ensure!(
            report.unregistered_inputs.is_empty(),
            "unregistered or modified runtime inputs cannot establish conformance"
        );
        ensure!(
            report.suite_sha256 == suite_sha256(),
            "stale or missing suite fingerprint; rerun evidence"
        );
        ensure!(
            !report.harness_self_test,
            "harness self-tests cannot establish wallet conformance"
        );
        ensure!(
            report.target == first.target,
            "cannot combine different targets"
        );
        ensure!(
            report.environment == first.environment,
            "cannot combine environments"
        );
        ensure!(
            report.contract_reference_revision == first.contract_reference_revision,
            "reference revision mismatch"
        );
        ensure!(!report.evidence.is_empty(), "empty execution report");
        for e in &report.evidence {
            if e.passed {
                seen.extend(e.requirements.iter().cloned());
                for requirement in &e.requirements {
                    passing_cases.insert((requirement.clone(), e.case.clone()));
                }
            } else {
                failures.push(e.case.clone());
            }
        }
    }
    let missing: Vec<_> = requirements
        .iter()
        .filter(|r| {
            !seen.contains(&r.id)
                || r.required_cases
                    .iter()
                    .any(|case| !passing_cases.contains(&(r.id.clone(), case.clone())))
        })
        .map(|r| r.id.clone())
        .collect();
    Ok(Coverage {
        exhaustive: missing.is_empty() && failures.is_empty(),
        required: requirements.len(),
        covered: requirements.len() - missing.len(),
        missing,
        unexecuted_cases: requirements
            .iter()
            .filter_map(|requirement| {
                let missing: Vec<_> = requirement
                    .required_cases
                    .iter()
                    .filter(|case| {
                        !passing_cases.contains(&(requirement.id.clone(), (*case).clone()))
                    })
                    .cloned()
                    .collect();
                (!missing.is_empty()).then_some((requirement.id.clone(), missing))
            })
            .collect(),
        failures,
    })
}

type Registry = BTreeMap<String, serde_json::Value>;
type RegistryCache = OnceLock<std::result::Result<Registry, String>>;

fn registered(
    cache: &RegistryCache,
    id: &str,
    actual: serde_json::Value,
    load: impl FnOnce() -> Result<Registry>,
) -> Result<bool> {
    let expected = cache.get_or_init(|| load().map_err(|error| error.to_string()));
    let expected = expected
        .as_ref()
        .map_err(|error| anyhow!("invalid frozen input registry: {error}"))?;
    Ok(expected.get(id) == Some(&actual))
}

pub fn registered_http(case: &crate::scenarios::Case) -> Result<bool> {
    static CACHE: RegistryCache = OnceLock::new();
    registered(&CACHE, &case.id, serde_json::to_value(case)?, || {
        let mut registry = Registry::new();
        for source in [
            include_str!("../fixtures/http.json"),
            include_str!("../fixtures/http-network.json"),
            include_str!("../fixtures/http-signatures.json"),
            include_str!("../fixtures/http-keys.json"),
            include_str!("../fixtures/http-rejections.json"),
            include_str!("../fixtures/http-statuses.json"),
            include_str!("../fixtures/http-families.json"),
            include_str!("../fixtures/http-extended.json"),
            include_str!("../fixtures/http-governance-media.json"),
        ] {
            let suite: crate::scenarios::Suite = serde_json::from_str(source)?;
            for case in suite.cases.into_iter().chain(suite.cleanup) {
                let value = serde_json::to_value(&case)?;
                ensure!(
                    registry.insert(case.id, value).is_none(),
                    "duplicate frozen HTTP case ID"
                );
            }
        }
        Ok(registry)
    })
}

pub fn registered_vector(vector: &crate::adapter::Vector) -> Result<bool> {
    static CACHE: RegistryCache = OnceLock::new();
    registered(&CACHE, &vector.id, serde_json::to_value(vector)?, || {
        let mut registry = Registry::new();
        for source in [
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
            include_str!("../fixtures/vectors/haskell-keys.json"),
            include_str!("../fixtures/vectors/coin-selection.json"),
            include_str!("../fixtures/vectors/generated-selection.json"),
        ] {
            for vector in serde_json::from_str::<Vec<crate::adapter::Vector>>(source)? {
                let value = serde_json::to_value(&vector)?;
                ensure!(
                    registry.insert(vector.id, value).is_none(),
                    "duplicate frozen vector ID"
                );
            }
        }
        Ok(registry)
    })
}
