//! Exact DRep reads bracketed around a fresh owned wallet's cache startup.
use crate::{
    api::{request, Api, Contract},
    node::NodeOracle,
    owned_process::{Launch, WalletProcess},
    report::Report,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    path::Path,
    thread::sleep,
    time::{Duration, Instant},
};

fn expected(id: &str, hash: &str, deposit: u64, expiry: u64, epoch: u64) -> Value {
    json!({"id":id,"credential":{"type":"key_hash","hash":hash},
        "status":if expiry >= epoch {"active"}else{"inactive"},"expiry_epoch":expiry,
        "voting_power":{"quantity":"0","unit":"lovelace"},
        "deposit":{"quantity":deposit,"unit":"lovelace"},"anchor":null,"name":null,"metadata":null})
}
fn exact(actual: &Value, expected: &Value) -> Result<()> {
    ensure!(
        actual == expected,
        "registered DRep fields differ from independent node state"
    );
    Ok(())
}
fn body(response: crate::api::Response) -> Result<Value> {
    response.json.context("DRep response JSON missing")
}

pub struct Options<'a> {
    pub node: &'a NodeOracle,
    pub fixture_receipt: &'a Path,
    pub launch: Launch,
    pub workspace: &'a Path,
    pub timeout: Duration,
}

/// Owns only the foreground process it starts; private logs remain in workspace.
pub fn run(api: &Api, contract: &Contract, environment: &str, options: Options<'_>) -> Report {
    let mut report = Report::new(&api.label, environment);
    let result = exercise(api, contract, options);
    match result {
        Ok(proof) => {
            for (name, operation, status) in [
                ("detail", "getDRep", 200),
                ("absent", "getDRep", 404),
                ("list", "listDReps", 200),
                ("summary", "getDRepSummary", 200),
            ] {
                report.record(
                    &format!("drep:registered-{name}"),
                    &[
                        format!(
                            "api:{operation}:{}",
                            if status < 300 { "positive" } else { "negative" }
                        ),
                        format!("api:{operation}:status:{status}"),
                    ],
                    Ok(()),
                );
            }
            report.record("drep:stable-node-cache-bracket", &[], Ok(()));
            report.evidence.last_mut().unwrap().detail = proof.to_string();
            report.record(
                "governance:drep-queries",
                &["wallet.governance".into()],
                Ok(()),
            );
            report.evidence.last_mut().unwrap().detail = proof.to_string();
        }
        Err(error) => report.record("drep:lookup-workflow", &[], Err(error)),
    }
    report
}

fn exercise(api: &Api, contract: &Contract, options: Options<'_>) -> Result<Value> {
    let Options {
        node,
        fixture_receipt,
        launch,
        workspace,
        timeout,
    } = options;
    crate::owned_process::require_unused_listener(&api.label)?;
    ensure!(
        std::fs::metadata(fixture_receipt)?.len() <= 4_194_304,
        "DRep fixture receipt too large"
    );
    let fixture: Value = serde_json::from_slice(&std::fs::read(fixture_receipt)?)?;
    ensure!(
        fixture["kind"] == "owned-key-drep-registration-fixture"
            && fixture["counts_as_conformance_evidence"] == false,
        "invalid DRep fixture receipt kind"
    );
    let hash = fixture["credential_hash"]
        .as_str()
        .context("DRep fixture hash missing")?;
    let hash_bytes = hex::decode(hash)?;
    ensure!(hash_bytes.len() == 28, "invalid DRep fixture hash length");
    let mut bytes = vec![0x22];
    bytes.extend_from_slice(&hash_bytes);
    let id = crate::encoding::bech32_encode("drep", &bytes)?;
    ensure!(fixture["drep_id"] == id, "DRep fixture identity differs");
    let deposit = fixture["deposit"]
        .as_u64()
        .context("DRep fixture deposit missing")?;
    let deadline = Instant::now() + timeout;
    let tip = loop {
        let tip = node.query(&["tip"], timeout)?;
        if tip["slotsToEpochEnd"]
            .as_u64()
            .context("node epoch remaining slots missing")?
            >= 60
        {
            break tip;
        }
        ensure!(
            Instant::now() < deadline,
            "DRep startup epoch alignment timed out"
        );
        sleep(Duration::from_millis(200));
    };
    let epoch = tip["epoch"].as_u64().context("node epoch missing")?;
    let before = node.query(&["drep-state", "--all-dreps", "--include-stake"], timeout)?;
    let expiry = crate::drep_fixture::registration(&before, hash, deposit)?;
    let distribution = node.query(&["drep-stake-distribution", "--all-dreps"], timeout)?;
    ensure!(
        distribution == json!({}),
        "undelegated DRep distribution is not empty"
    );
    let mut process = WalletProcess::start(launch, workspace)?;
    process.wait_listener(&api.label, timeout)?;
    let pid = process.ensure_running()?;
    let wanted = expected(&id, hash, deposit, expiry, epoch);
    let actual = body(api.checked(
        contract,
        "getDRep",
        request("GET", format!("/dreps/{id}"), None),
        200,
    )?)?;
    exact(&actual, &wanted)?;
    let list = body(api.checked(contract, "listDReps", request("GET", "/dreps", None), 200)?)?;
    exact(&list, &json!([wanted]))?;
    let active = u64::from(expiry >= epoch);
    let summary = body(api.checked(
        contract,
        "getDRepSummary",
        request("GET", "/dreps/summary", None),
        200,
    )?)?;
    exact(
        &summary,
        &json!({"total_drep_stake":{"quantity":"0","unit":"lovelace"},
        "active_drep_count":active,"inactive_drep_count":1-active,"total_drep_count":1}),
    )?;
    let mut absent = bytes;
    absent[1] ^= 1;
    let absent = crate::encoding::bech32_encode("drep", &absent)?;
    let error = body(api.checked(
        contract,
        "getDRep",
        request("GET", format!("/dreps/{absent}"), None),
        404,
    )?)?;
    exact(
        &error,
        &json!({"code":"not_found","message":"No DRep found for the given identifier."}),
    )?;
    for (operation, path) in [
        ("listWallets", "/wallets"),
        ("listByronWallets", "/byron-wallets"),
        ("listSharedWallets", "/shared-wallets"),
    ] {
        ensure!(
            body(api.checked(contract, operation, request("GET", path, None), 200)?)? == json!([]),
            "DRep reads created or changed wallet lists"
        );
    }
    let after = node.query(&["drep-state", "--all-dreps", "--include-stake"], timeout)?;
    let distribution_after = node.query(&["drep-stake-distribution", "--all-dreps"], timeout)?;
    let tip_after = node.query(&["tip"], timeout)?;
    ensure!(
        before == after && distribution == distribution_after && tip_after["epoch"] == epoch,
        "node state or epoch changed across fresh DRep cache bracket"
    );
    process.ensure_running()?;
    let executable = process.executable_sha256().to_owned();
    process.stop()?;
    Ok(
        json!({"node_before":before,"node_after":after,"distribution":distribution,"tip_before":tip,"tip_after":tip_after,
        "lookup":actual,"list":list,"summary":summary,"absent_error":error,"owned_process_pid":pid,
        "executable_sha256":executable,"owned_process_stopped_and_reaped":true,
        "is_restart_persistence_evidence":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detail_preserves_exact_units_types_nulls_credential_status_and_expiry() {
        let good = expected("drep-fixture", &"ab".repeat(28), 500_000_000, 22, 2);
        exact(&good, &good).unwrap();
        for (pointer, value) in [
            ("/expiry_epoch", json!(23)),
            ("/credential/type", json!("script_hash")),
            ("/deposit/unit", json!("ada")),
            ("/voting_power/quantity", json!(0)),
            ("/status", json!("inactive")),
            ("/anchor", json!({})),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(exact(&bad, &good).is_err());
        }
        let mut bad = good.clone();
        bad.as_object_mut().unwrap().remove("name");
        assert!(exact(&bad, &good).is_err());
        assert_eq!(expected("id", "hash", 1, 2, 2)["status"], "active");
        assert_eq!(expected("id", "hash", 1, 2, 3)["status"], "inactive");
    }
}
