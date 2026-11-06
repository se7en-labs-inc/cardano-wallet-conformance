//! Reproducible behavioral specification export. Authority is never auto-promoted.
use crate::{
    api::Contract,
    report::{coverage, suite_sha256, Coverage, Report, Requirement},
};
use anyhow::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn export(
    contract: &Contract,
    requirements: &[Requirement],
    reports: &[Report],
) -> Result<Value> {
    let validation = if reports.is_empty() {
        Coverage {
            exhaustive: false,
            required: requirements.len(),
            covered: 0,
            missing: requirements.iter().map(|r| r.id.clone()).collect(),
            unexecuted_cases: requirements
                .iter()
                .map(|r| (r.id.clone(), r.required_cases.clone()))
                .collect(),
            failures: vec![],
        }
    } else {
        coverage(requirements, reports)?
    };
    let mut files = serde_json::Map::new();
    for (path, source) in [
        (
            "fixtures/vectors/signed-size-profiles.json",
            include_str!("../fixtures/vectors/signed-size-profiles.json"),
        ),
        (
            "fixtures/vectors/input-witness-count-profiles.json",
            include_str!("../fixtures/vectors/input-witness-count-profiles.json"),
        ),
        (
            "fixtures/vectors/reward-profiles.json",
            include_str!("../fixtures/vectors/reward-profiles.json"),
        ),
        (
            "fixtures/pool-registration-control.json",
            include_str!("../fixtures/pool-registration-control.json"),
        ),
        (
            "fixtures/parameter-proposal-control.json",
            include_str!("../fixtures/parameter-proposal-control.json"),
        ),
        (
            "fixtures/parameter-network-control.json",
            include_str!("../fixtures/parameter-network-control.json"),
        ),
        (
            "fixtures/voting-controls.json",
            include_str!("../fixtures/voting-controls.json"),
        ),
        (
            "fixtures/stake-reward-controls.json",
            include_str!("../fixtures/stake-reward-controls.json"),
        ),
        (
            "fixtures/retry-payment-controls.json",
            include_str!("../fixtures/retry-payment-controls.json"),
        ),
        (
            "fixtures/http-governance-media.json",
            include_str!("../fixtures/http-governance-media.json"),
        ),
        (
            "fixtures/vectors/ledger-fees.json",
            include_str!("../fixtures/vectors/ledger-fees.json"),
        ),
        (
            "fixtures/vectors/wallet-selection.json",
            include_str!("../fixtures/vectors/wallet-selection.json"),
        ),
        (
            "fixtures/http-extended.json",
            include_str!("../fixtures/http-extended.json"),
        ),
        (
            "fixtures/vectors/writer-profiles.json",
            include_str!("../fixtures/vectors/writer-profiles.json"),
        ),
        (
            "fixtures/vectors/balance-profiles.json",
            include_str!("../fixtures/vectors/balance-profiles.json"),
        ),
        (
            "fixtures/vectors/slotting-profiles.json",
            include_str!("../fixtures/vectors/slotting-profiles.json"),
        ),
        (
            "fixtures/vectors/balancing-profiles.json",
            include_str!("../fixtures/vectors/balancing-profiles.json"),
        ),
        (
            "fixtures/vectors/ledger-profiles.json",
            include_str!("../fixtures/vectors/ledger-profiles.json"),
        ),
        (
            "fixtures/vectors/address-profiles.json",
            include_str!("../fixtures/vectors/address-profiles.json"),
        ),
        (
            "fixtures/vectors/mnemonic-profiles.json",
            include_str!("../fixtures/vectors/mnemonic-profiles.json"),
        ),
        (
            "fixtures/vectors/key-boundaries.json",
            include_str!("../fixtures/vectors/key-boundaries.json"),
        ),
        (
            "fixtures/vectors/wallet-credentials.json",
            include_str!("../fixtures/vectors/wallet-credentials.json"),
        ),
        (
            "fixtures/vectors/root-encryption.json",
            include_str!("../fixtures/vectors/root-encryption.json"),
        ),
        (
            "fixtures/vectors/metadata-encryption-profiles.json",
            include_str!("../fixtures/vectors/metadata-encryption-profiles.json"),
        ),
        (
            "fixtures/http-families.json",
            include_str!("../fixtures/http-families.json"),
        ),
        (
            "fixtures/vectors/haskell-selection.json",
            include_str!("../fixtures/vectors/haskell-selection.json"),
        ),
        (
            "fixtures/vectors/signature-verification.json",
            include_str!("../fixtures/vectors/signature-verification.json"),
        ),
        (
            "fixtures/vectors/passphrase-checks.json",
            include_str!("../fixtures/vectors/passphrase-checks.json"),
        ),
        (
            "fixtures/http-statuses.json",
            include_str!("../fixtures/http-statuses.json"),
        ),
        (
            "fixtures/vectors/primitive-boundaries.json",
            include_str!("../fixtures/vectors/primitive-boundaries.json"),
        ),
        (
            "fixtures/semantic-obligations.json",
            include_str!("../fixtures/semantic-obligations.json"),
        ),
        (
            "fixtures/http-keys.json",
            include_str!("../fixtures/http-keys.json"),
        ),
        (
            "fixtures/provenance.json",
            include_str!("../fixtures/provenance.json"),
        ),
        (
            "fixtures/api/haskell-corrections.json",
            include_str!("../fixtures/api/haskell-corrections.json"),
        ),
        ("fixtures/http.json", include_str!("../fixtures/http.json")),
        (
            "fixtures/http-signatures.json",
            include_str!("../fixtures/http-signatures.json"),
        ),
        (
            "fixtures/http-rejections.json",
            include_str!("../fixtures/http-rejections.json"),
        ),
        (
            "fixtures/http-network.json",
            include_str!("../fixtures/http-network.json"),
        ),
        (
            "fixtures/vectors/primitives.json",
            include_str!("../fixtures/vectors/primitives.json"),
        ),
        (
            "fixtures/vectors/bip39-reference.json",
            include_str!("../fixtures/vectors/bip39-reference.json"),
        ),
        (
            "fixtures/vectors/cardano-wallet.json",
            include_str!("../fixtures/vectors/cardano-wallet.json"),
        ),
        (
            "fixtures/vectors/coin-selection.json",
            include_str!("../fixtures/vectors/coin-selection.json"),
        ),
        (
            "fixtures/vectors/generated-selection.json",
            include_str!("../fixtures/vectors/generated-selection.json"),
        ),
        (
            "fixtures/vectors/haskell-keys.json",
            include_str!("../fixtures/vectors/haskell-keys.json"),
        ),
    ] {
        files.insert(
            path.into(),
            json!({
                "sha256":hex::encode(Sha256::digest(source.as_bytes())),
                "source_text":source,
                "contract":serde_json::from_str::<Value>(source)?,
            }),
        );
    }
    let native_fork_control = json!({"source":"src/fork_fixture.rs","sha256":hex::encode(Sha256::digest(include_bytes!("fork_fixture.rs"))),"status":"control-only closed common snapshot and isolated native branches; rollback requires complete wallet assertions"});
    let mut exported = json!({
        "format_version":1,
        "status":"draft",
        "current_authority":"observed Haskell behavior and independent published vectors",
        "future_authority":"a separately reviewed and versioned specification generated from this suite",
        "suite_sha256":suite_sha256(),
        "scope":"HTTP API and wallet internals; CLI excluded; bounded by catalogue, corpus and executed environment",
        "response_schema_dialect":"OpenAPI 3.0 with nullable/exclusive bounds normalized to JSON Schema Draft 7",
        "effective_api":contract.effective_document(),
        "operations":contract.operations,
        "requirements":requirements,
        "adapter_protocol":include_str!("../docs/adapter.md"),
        "lifecycle_control":{"source":"src/owned_process.rs","sha256":hex::encode(Sha256::digest(include_bytes!("owned_process.rs"))),"status":"optional owned-wallet confirmed/key restart profile; pending persistence remains mandatory separately"},
        "node_connection_control":{"source":"src/node_proxy.rs","sha256":hex::encode(Sha256::digest(include_bytes!("node_proxy.rs"))),"status":"transparent connection control; wallet disconnect obligations require separate live evidence"},
        "checkpoint_point_observer":{"source":"src/chain_observer.rs","sha256":hex::encode(Sha256::digest(include_bytes!("chain_observer.rs"))),"status":"passive public point observations; checkpoint credit requires the complete owned offline catch-up workflow"},
        "drep_lookup":{"source":"src/drep_lookup.rs","sha256":hex::encode(Sha256::digest(include_bytes!("drep_lookup.rs"))),"node_control":serde_json::from_str::<Value>(include_str!("../fixtures/drep-node-control.json"))?,"node_control_sha256":hex::encode(Sha256::digest(include_bytes!("../fixtures/drep-node-control.json"))),"status":"fresh owned wallet lookup bracket; broader governance remains separately mandatory"},
        "corpora":files,
        "live_assertions":{
            "source":"src/live.rs",
            "sha256":hex::encode(Sha256::digest(include_bytes!("live.rs"))),
            "contract":include_str!("../docs/live-contracts.md"),
            "profiles":[
                {"source":"src/live/families.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/families.rs")))},
                {"source":"src/live/watch_only.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/watch_only.rs")))},
                {"source":"src/live/assets.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/assets.rs")))},
                {"source":"src/live/stake_rewards.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/stake_rewards.rs")))},
                {"source":"src/live/pending_byron.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/pending_byron.rs")))},
                {"source":"src/live/retry.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/retry.rs")))},
                {"source":"src/live/checkpoint.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/checkpoint.rs")))},
                {"source":"src/live/concurrency.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/concurrency.rs")))},
                {"source":"src/live/metadata.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/metadata.rs")))},
                {"source":"src/live/transport.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/transport.rs")))},
                {"source":"src/live/precedence.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/precedence.rs")))},
                {"source":"src/live/validity.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/validity.rs")))},
                {"source":"src/live/balancing.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/balancing.rs")))},
                {"source":"src/live/voting.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/voting.rs")))},
                {"source":"src/live/input_limits.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/input_limits.rs")))},
                {"source":"src/live/restart.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/restart.rs")))},
                {"source":"src/live/disconnect.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/disconnect.rs")))},
                {"source":"src/live/history.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/history.rs")))},
                {"source":"src/live/discovery.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/discovery.rs")))},
                {"source":"src/live/pools.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/pools.rs")))},
                {"source":"src/live/parameters.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/parameters.rs")))},
                {"source":"src/live/era_boundary.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/era_boundary.rs")))},
                {"source":"src/live/pending.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/pending.rs")))},
                {"source":"src/live/delegation_fees.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/delegation_fees.rs")))},
                {"source":"src/live/pool_join_guard.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/pool_join_guard.rs")))}
            ],
            "supplemental_node_rejection":{"status":500,"code":"created_invalid_transaction","node_causes":["InvalidWitnesses","BadInputsUTxO","OutsideValidityIntervalUTxO"],"source":"pinned Api/Http/Server/Error.hs ErrPostTxValidationError","documented_in_original_openapi":false,"counts_as_documented_api_status_evidence":false}
        },
        "fixture_tools":[
            {"source":"src/pool_fixture.rs","sha256":hex::encode(Sha256::digest(include_bytes!("pool_fixture.rs"))),"counts_as_conformance_evidence":false},
            {"source":"src/protocol_update.rs","sha256":hex::encode(Sha256::digest(include_bytes!("protocol_update.rs"))),"counts_as_conformance_evidence":false},
            {"source":"src/drep_fixture.rs","sha256":hex::encode(Sha256::digest(include_bytes!("drep_fixture.rs"))),"counts_as_conformance_evidence":false}
            ,{"source":"src/era_fixture.rs","sha256":hex::encode(Sha256::digest(include_bytes!("era_fixture.rs"))),"counts_as_conformance_evidence":false}
        ],
        "validation":validation,
        "execution_reports":reports,
        "promotion":"No automatic promotion: an incomplete export is a draft, and even complete bounded coverage requires explicit review before becoming authoritative."
    });
    exported["reviewed_retired_responses"] =
        serde_json::from_str::<Value>(include_str!("../fixtures/api/retired-responses.json"))?;
    exported["execution_profiles"] =
        serde_json::from_str::<Value>(include_str!("../fixtures/execution-profiles.json"))?;
    exported["executable_runner"] = json!({"source":"src/executable.rs","sha256":hex::encode(Sha256::digest(include_bytes!("executable.rs"))),"entrypoint":"wallet-conformance conform --config implementation.json --workspace /absolute/fresh/run","profiles":37,"historical_reports_imported":false,"skip_profiles_supported":false});
    exported["native_fork_control"] = native_fork_control;
    exported["live_assertions"]["profiles"].as_array_mut().unwrap().push(json!({"source":"src/live/rollback.rs","sha256":hex::encode(Sha256::digest(include_bytes!("live/rollback.rs")))}));
    exported["fixture_tools"].as_array_mut().unwrap().push(json!({"source":"src/fork_fixture.rs","sha256":hex::encode(Sha256::digest(include_bytes!("fork_fixture.rs"))),"counts_as_conformance_evidence":false}));
    Ok(exported)
}
