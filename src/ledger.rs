//! Actual wallet transaction/metadata capture with independent byte and range laws.
use crate::{
    adapter::{self, Vector},
    transaction,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, time::Duration};

const ORACLE: &str = "5f9ad0a56fba7f4c60854d7a763de8d38ea39b3b1a56050d2e9659663d94026c";
fn bytes(v: &Value, field: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(
        v[field].as_str().context("missing hex bytes")?,
    )?)
}
fn number(v: &Value) -> Result<i128> {
    Ok(v.to_string().parse()?)
}
fn metadata_value(
    v: &Value,
    e: &mut minicbor::Encoder<Vec<u8>>,
    errors: &mut Vec<Value>,
    label: u64,
) -> Result<()> {
    match v["type"].as_str().context("missing metadata type")? {
        "number" => {
            let n = number(&v["value"])?;
            if n.unsigned_abs() > u128::from(u64::MAX) {
                errors
                    .push(json!({"label":label,"code":"number_out_of_range","actual":v["value"]}));
            } else {
                e.int(minicbor::data::Int::try_from(n)?)?;
            }
        }
        "text" => {
            let s = v["value"].as_str().context("missing metadata text")?;
            if s.len() > 64 {
                errors.push(json!({"label":label,"code":"text_too_long","actual":s.len()}));
            }
            e.str(s)?;
        }
        "bytes" => {
            let b = bytes(v, "hex")?;
            if b.len() > 64 {
                errors.push(json!({"label":label,"code":"bytes_too_long","actual":b.len()}));
            }
            e.bytes(&b)?;
        }
        "list" => {
            let items = v["items"].as_array().context("missing metadata list")?;
            e.array(items.len() as u64)?;
            for item in items {
                metadata_value(item, e, errors, label)?;
            }
        }
        "map" => {
            let items = v["entries"].as_array().context("missing metadata map")?;
            e.map(items.len() as u64)?;
            for item in items {
                metadata_value(&item["key"], e, errors, label)?;
                metadata_value(&item["value"], e, errors, label)?;
            }
        }
        _ => anyhow::bail!("unknown metadata kind"),
    }
    Ok(())
}
pub fn metadata(input: &Value) -> Result<Value> {
    let mut entries = BTreeMap::new();
    for entry in input["entries"]
        .as_array()
        .context("missing metadata entries")?
    {
        entries.insert(
            entry["label"].as_u64().context("invalid metadata label")?,
            &entry["value"],
        );
    }
    let mut e = minicbor::Encoder::new(Vec::new());
    e.map(entries.len() as u64)?;
    let mut errors = Vec::new();
    for (label, value) in entries {
        e.u64(label)?;
        metadata_value(value, &mut e, &mut errors, label)?;
    }
    Ok(if errors.is_empty() {
        json!({"valid":true,"cbor_hex":hex::encode(e.into_writer())})
    } else {
        json!({"valid":false,"errors":errors})
    })
}
pub fn transaction_id(raw: &[u8]) -> Result<String> {
    let mut d = minicbor::Decoder::new(raw);
    ensure!(
        d.array()?.is_some_and(|n| n >= 2),
        "invalid transaction envelope"
    );
    let start = d.position();
    d.skip()?;
    Ok(hex::encode(transaction::blake2b(
        &raw[start..d.position()],
        32,
    )?))
}
pub fn validate(vector: &Vector, actual: &Value) -> Result<()> {
    let Some(result) = actual.get("result") else {
        return Ok(());
    };
    match vector.operation.as_str() {
        "transaction.roundtrip" => {
            let raw = bytes(result, "cbor_hex")?;
            ensure!(
                result["transaction_id"] == transaction_id(&raw)?,
                "transaction ID differs from independent raw body hash"
            );
            ensure!(
                result["cbor_hex"] == vector.input["cbor_hex"],
                "canonical fixture changed during wallet round trip"
            );
        }
        "metadata.encode" => ensure!(
            *result == metadata(&vector.input)?,
            "metadata bytes/range/UTF-8 validation differs"
        ),
        "ledger.ed25519.verify" => {
            let pk: [u8; 32] = bytes(&vector.input, "public_key_hex")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid public key length"))?;
            let signature =
                ed25519_dalek::Signature::from_slice(&bytes(&vector.input, "signature_hex")?);
            let message = bytes(&vector.input, "message_hex")?;
            let valid = ed25519_dalek::VerifyingKey::from_bytes(&pk)
                .ok()
                .zip(signature.ok())
                .is_some_and(|(key, sig)| key.verify_strict(&message, &sig).is_ok());
            ensure!(
                result["valid"] == valid,
                "ledger signature profile differs from independent strict verification"
            );
        }
        _ => {}
    }
    Ok(())
}
struct Capture<'a> {
    binary: &'a Path,
    vectors: Vec<Vector>,
}
impl Capture<'_> {
    fn add(
        &mut self,
        id: &str,
        requirement: &str,
        operation: &str,
        input: Value,
        expected: Option<Value>,
    ) -> Result<Value> {
        let mut v=Vector {id:id.into(),requirements:if requirement.is_empty(){vec![]}else{vec![requirement.into()]},source:format!("Wallet2fc5c383; actual wallet-read transaction codecs, wallet metadata and ledger DSIGN; LedgerAdapter binary sha256:{ORACLE}; independent Rust CBOR/body hash/range/strict signature checks"),operation:operation.into(),input,expected:None,selection_invariants:false};
        let actual = adapter::invoke(self.binary, &[], &v, Duration::from_secs(30))?;
        ensure!(
            actual == adapter::invoke(self.binary, &[], &v, Duration::from_secs(30))?,
            "ledger oracle replay differs: {id}"
        );
        if let Some(expected) = expected {
            ensure!(
                actual == expected,
                "ledger boundary differs from expected outcome: {id}"
            );
        } else {
            ensure!(
                actual.get("result").is_some(),
                "valid ledger input rejected: {id}"
            );
        }
        validate(&v, &actual).with_context(|| format!("independent ledger check failed: {id}"))?;
        v.expected = Some(actual.clone());
        self.vectors.push(v);
        Ok(actual)
    }
}
pub fn capture(binary: &Path) -> Result<Vec<Vector>> {
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(binary)?)) == ORACLE,
        "ledger adapter differs from pinned oracle"
    );
    let mut c = Capture {
        binary,
        vectors: vec![],
    };
    let addresses: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/address-profiles.json"))?;
    let address = &addresses
        .iter()
        .find(|v| v.id == "address-byron-random")
        .context("missing Byron address")?
        .expected
        .as_ref()
        .unwrap()["result"]["address_hex"];
    let mut shelley = String::new();
    for era in [
        "byron", "shelley", "allegra", "mary", "alonzo", "babbage", "conway", "dijkstra",
    ] {
        let helper = Vector {
            id: format!("capture-{era}"),
            requirements: vec![],
            source: "capture-time actual wallet fixture generator".into(),
            operation: "fixture.transaction".into(),
            input: json!({"era":era,"address_hex":address,"input_txid_hex":"00".repeat(32),"input_index":0,"output_coin":1000000}),
            expected: None,
            selection_invariants: false,
        };
        let fixture = adapter::invoke(binary, &[], &helper, Duration::from_secs(30))?;
        let raw = fixture["result"]["cbor_hex"]
            .as_str()
            .context("fixture generator failed")?;
        c.add(
            &format!("tx-cbor-{era}"),
            "tx.serialization",
            "transaction.roundtrip",
            json!({"era":era,"cbor_hex":raw}),
            Some(json!({"result":fixture["result"]})),
        )?;
        if era == "shelley" {
            shelley = raw.into();
        }
    }
    for (id, raw) in [
        ("tx-cbor-indefinite", format!("9f{}ff", &shelley[2..])),
        ("tx-cbor-trailing-rejected", format!("{shelley}00")),
        (
            "tx-cbor-duplicate-key-rejected",
            format!(
                "83a5{}0200{}",
                &shelley[4..shelley.len() - 4],
                &shelley[shelley.len() - 4..]
            ),
        ),
        (
            "tx-cbor-truncated-rejected",
            shelley[..shelley.len() - 2].into(),
        ),
    ] {
        c.add(
            id,
            "tx.serialization",
            "transaction.roundtrip",
            json!({"era":"shelley","cbor_hex":raw}),
            Some(json!({"error":{"code":"decode_failed"}})),
        )?;
    }
    let n = |value: Value| json!({"type":"number","value":value});
    let text = |value: String| json!({"type":"text","value":value});
    let blob = |count: usize| json!({"type":"bytes","hex":"ab".repeat(count)});
    for (id, entries) in [
        (
            "metadata-cbor-golden",
            json!([{"label":42,"value":{"type":"map","entries":[{"key":text("message".into()),"value":{"type":"list","items":[n(json!(42)),blob(2),text("Cardano".into())]}}]}}]),
        ),
        (
            "metadata-label-boundaries",
            json!([{"label":u64::MAX,"value":n(json!(-i128::from(u64::MAX)))},{"label":0,"value":n(json!(u64::MAX))}]),
        ),
        (
            "metadata-text-64-bytes",
            json!([{"label":0,"value":text("é".repeat(32))}]),
        ),
        ("metadata-bytes-64", json!([{"label":0,"value":blob(64)}])),
        (
            "metadata-oversize-rejected",
            json!([{"label":0,"value":blob(65)}]),
        ),
        (
            "metadata-text-utf8-oversize-rejected",
            json!([{"label":0,"value":text("é".repeat(33))}]),
        ),
        (
            "metadata-number-positive-overflow",
            json!([{"label":0,"value":n(json!(u128::from(u64::MAX)+1))}]),
        ),
        (
            "metadata-number-negative-overflow",
            json!([{"label":0,"value":n(json!(-i128::from(u64::MAX)-1))}]),
        ),
        (
            "metadata-nested-errors",
            json!([{"label":0,"value":{"type":"list","items":[blob(65),text("x".repeat(65)),n(json!(u128::from(u64::MAX)+1))]}}]),
        ),
        ("metadata-empty", json!([])),
        (
            "metadata-duplicate-label-last-value",
            json!([{"label":1,"value":n(json!(2))},{"label":1,"value":n(json!(3))}]),
        ),
    ] {
        c.add(
            id,
            "tx.metadata",
            "metadata.encode",
            json!({"ledger_version":9,"entries":entries}),
            None,
        )?;
    }
    let primitives: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/primitives.json"))?;
    let valid = primitives
        .iter()
        .find(|v| v.id == "ed25519-rfc8032-1-verify")
        .context("missing RFC8032 vector")?
        .input
        .clone();
    c.add(
        "ledger-ed25519-rfc8032",
        "crypto.ed25519.noncanonical",
        "ledger.ed25519.verify",
        valid.clone(),
        Some(json!({"result":{"valid":true}})),
    )?;
    let wallet: Vec<Vector> = serde_json::from_str(include_str!(
        "../fixtures/vectors/signature-verification.json"
    ))?;
    let noncanonical = &wallet
        .iter()
        .find(|v| v.id == "wallet-verify-noncanonical-s-plus-l")
        .context("missing noncanonical signature")?
        .input;
    let mut nc = noncanonical.clone();
    nc["public_key_hex"] = json!(&noncanonical["xpub_hex"].as_str().unwrap()[..64]);
    nc.as_object_mut().unwrap().remove("xpub_hex");
    let mut small_r = valid.clone();
    small_r["signature_hex"] = json!(format!(
        "01{}{}",
        "00".repeat(31),
        &valid["signature_hex"].as_str().unwrap()[64..]
    ));
    let mut small_key = valid.clone();
    small_key["public_key_hex"] = json!(format!("01{}", "00".repeat(31)));
    for (id, input) in [
        ("ed25519-noncanonical-s", nc),
        ("ed25519-small-order-r", small_r),
        ("ed25519-small-order-public-key", small_key),
    ] {
        c.add(
            id,
            "crypto.ed25519.noncanonical",
            "ledger.ed25519.verify",
            input,
            Some(json!({"result":{"valid":false}})),
        )?;
    }
    Ok(c.vectors)
}
