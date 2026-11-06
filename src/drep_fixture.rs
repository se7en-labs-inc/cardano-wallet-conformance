//! Real owned key-DRep registration; fixture construction is not wallet evidence.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    thread::sleep,
    time::{Duration, Instant},
};

fn certificate(raw: &[u8], key: &[u8], deposit: u64) -> Result<()> {
    ensure!(key.len() == 32, "invalid DRep public key length");
    let hash = crate::transaction::blake2b(key, 28)?;
    let mut expected = minicbor::Encoder::new(Vec::new());
    expected
        .array(4)?
        .u8(16)?
        .array(2)?
        .u8(0)?
        .bytes(&hash)?
        .u64(deposit)?
        .null()?;
    ensure!(
        raw == expected.into_writer(),
        "DRep registration type/credential/deposit/anchor/encoding differs"
    );
    Ok(())
}

pub(crate) fn registration(value: &Value, hash: &str, deposit: u64) -> Result<u64> {
    let entries = value.as_array().context("DRep state is not an array")?;
    ensure!(
        entries.len() == 1,
        "dedicated fixture requires exactly one DRep"
    );
    let entry = entries[0]
        .as_array()
        .context("DRep state entry is not a pair")?;
    ensure!(
        entry.len() == 2 && entry[0] == json!({"keyHash":hash}),
        "DRep credential differs"
    );
    let state = entry[1].as_object().context("DRep state object missing")?;
    ensure!(
        state.len() == 4
            && state.contains_key("stake")
            && state["anchor"].is_null()
            && state["deposit"] == deposit
            && (state["stake"].is_null() || state["stake"] == 0),
        "DRep node deposit/anchor/stake/fields differ"
    );
    state
        .get("expiry")
        .and_then(Value::as_u64)
        .context("DRep expiry epoch missing")
}

/// Requires an explicitly dedicated magic42 node and fresh private workspace.
pub fn prepare(
    node: &crate::node::NodeOracle,
    faucet_url: &str,
    workspace: &Path,
    timeout: Duration,
) -> Result<PathBuf> {
    ensure!(node.network_magic == 42, "DRep fixture requires magic42");
    ensure!(
        workspace.is_absolute() && !workspace.exists(),
        "DRep fixture requires a fresh absolute workspace"
    );
    fs::DirBuilder::new().mode(0o700).create(workspace)?;
    let private = workspace.join("private");
    let public = workspace.join("public");
    fs::DirBuilder::new().mode(0o700).create(&private)?;
    fs::DirBuilder::new().mode(0o700).create(&public)?;
    let command = |args: &[&str]| {
        let mut c = Command::new(&node.executable);
        c.arg("conway").args(args);
        c
    };
    for (name, args) in [
        ("payment", vec!["address", "key-gen"]),
        ("drep", vec!["governance", "drep", "key-gen"]),
    ] {
        crate::pool_fixture::run(
            command(&args)
                .arg("--verification-key-file")
                .arg(public.join(format!("{name}.vkey")))
                .arg("--signing-key-file")
                .arg(private.join(format!("{name}.skey"))),
            timeout,
        )?;
        fs::set_permissions(
            private.join(format!("{name}.skey")),
            fs::Permissions::from_mode(0o600),
        )?;
    }
    let (key_json, key) = crate::protocol_update::public_key(&public.join("drep.vkey"))?;
    let (_, payment) = crate::protocol_update::public_key(&public.join("payment.vkey"))?;
    let hash = crate::transaction::blake2b(&key, 28)?;
    let mut credential = vec![0x22];
    credential.extend_from_slice(&hash);
    let id = crate::encoding::bech32_encode("drep", &credential)?;
    let address_file = public.join("payment.address");
    crate::pool_fixture::run(
        command(&["address", "build", "--payment-verification-key-file"])
            .arg(public.join("payment.vkey"))
            .args(["--testnet-magic", "42", "--out-file"])
            .arg(&address_file),
        timeout,
    )?;
    let address = fs::read_to_string(address_file)?.trim().to_owned();
    let mut address_bytes = vec![0x60];
    address_bytes.extend_from_slice(&crate::transaction::blake2b(&payment, 28)?);
    ensure!(
        crate::encoding::bech32(&address)? == ("addr_test".to_owned(), address_bytes),
        "DRep fixture payment address differs from independent key hash"
    );
    let parameters = node.protocol_parameters(timeout)?;
    let deposit = parameters["dRepDeposit"]
        .as_u64()
        .context("node DRep deposit missing")?;
    let funding = deposit
        .checked_add(100_000_000)
        .context("DRep funding overflow")?;
    let cert_path = public.join("registration.cert");
    crate::pool_fixture::run(
        command(&[
            "governance",
            "drep",
            "registration-certificate",
            "--drep-verification-key-file",
        ])
        .arg(public.join("drep.vkey"))
        .arg("--key-reg-deposit-amt")
        .arg(deposit.to_string())
        .arg("--out-file")
        .arg(&cert_path),
        timeout,
    )?;
    certificate(
        &crate::protocol_update::certificate_bytes(&cert_path)?,
        &key,
        deposit,
    )?;
    let before_state = node.query(&["drep-state", "--all-dreps", "--include-stake"], timeout)?;
    ensure!(
        node.utxos(&address, timeout)?
            .as_object()
            .is_some_and(|v| v.is_empty()),
        "fresh DRep payment address already funded"
    );
    let faucet = crate::api::Api::new(faucet_url, timeout)?;
    let response = faucet.request(&crate::api::request("POST", "/send/faucet-assets", Some(json!({
        "batch-size":1,"assets":[{"address":address,"bundle":{"coin":funding,"assets":[]},"metadata":[]}]
    }))))?;
    ensure!(
        response.status == 204,
        "DRep fixture faucet rejected funding"
    );
    let deadline = Instant::now() + timeout;
    let before = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "DRep fixture funding timed out");
        let value = node.utxos(&address, remaining)?;
        let map = value.as_object().context("DRep funding UTxO map missing")?;
        if !map.is_empty() {
            ensure!(
                map.len() == 1
                    && map
                        .values()
                        .all(|v| v["address"] == address
                            && v["value"] == json!({"lovelace":funding})),
                "DRep funding input count/address/value/assets differs"
            );
            break value;
        }
        sleep(Duration::from_millis(200).min(deadline.saturating_duration_since(Instant::now())));
    };
    let submit = crate::protocol_update::Submit {
        node,
        fixture: workspace,
        output: &public,
        address,
        timeout,
    };
    let proof = submit.send(
        before,
        crate::protocol_update::Plan {
            label: "drep-registration",
            certificates: vec![cert_path],
            proposal: None,
            vote: None,
            signers: vec!["payment", "drep"],
            deposit,
        },
    )?;
    let after_state = node.query(&["drep-state", "--all-dreps", "--include-stake"], timeout)?;
    ensure!(
        before_state == json!([]),
        "DRep fixture node was not initially empty"
    );
    registration(&after_state, &hex::encode(&hash), deposit)?;
    ensure!(
        before_state != after_state,
        "confirmed DRep registration did not change node state"
    );
    let receipt = json!({
        "format_version":1,"kind":"owned-key-drep-registration-fixture",
        "counts_as_conformance_evidence":false,"suite_sha256":crate::report::suite_sha256(),
        "drep_id":id,"credential_hash":hex::encode(hash),"public_key":key_json,"deposit":deposit,
        "node_parameters":parameters,"node_state_before":before_state,"node_state_after":after_state,
        "registration":proof,
    });
    let path = public.join("receipt.json");
    fs::write(&path, serde_json::to_vec_pretty(&receipt)?)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observed_node_registration_rejects_credentials_deposit_stake_and_unknown_fields() {
        let value: Value =
            serde_json::from_str(include_str!("../fixtures/drep-node-control.json")).unwrap();
        let hash = value[0][0]["keyHash"].as_str().unwrap();
        assert_eq!(registration(&value, hash, 500_000_000).unwrap(), 22);
        assert!(registration(&value, &"00".repeat(28), 500_000_000).is_err());
        assert!(registration(&value, hash, 1).is_err());
        for (key, replacement) in [
            ("stake", json!(1)),
            ("anchor", json!({})),
            ("expiry", json!(-1)),
            ("extra", json!(0)),
        ] {
            let mut bad = value.clone();
            bad[0][1][key] = replacement;
            assert!(registration(&bad, hash, 500_000_000).is_err());
        }
    }
    #[test]
    fn registration_certificate_rejects_key_type_deposit_anchor_and_trailing_mutations() {
        let key = [7; 32];
        let hash = crate::transaction::blake2b(&key, 28).unwrap();
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(16)
            .unwrap()
            .array(2)
            .unwrap()
            .u8(0)
            .unwrap()
            .bytes(&hash)
            .unwrap()
            .u64(500_000_000)
            .unwrap()
            .null()
            .unwrap();
        let raw = e.into_writer();
        certificate(&raw, &key, 500_000_000).unwrap();
        assert!(certificate(&raw, &[8; 32], 500_000_000).is_err());
        assert!(certificate(&raw, &key, 500_000_001).is_err());
        for index in [1, 3, raw.len() - 1] {
            let mut bad = raw.clone();
            bad[index] ^= 1;
            assert!(certificate(&bad, &key, 500_000_000).is_err());
        }
        let mut bad = raw;
        bad.push(0);
        assert!(certificate(&bad, &key, 500_000_000).is_err());
    }
}
