//! Actual wallet witness/certificate capture and independent signature/CBOR laws.
use crate::{
    adapter::{self, Vector},
    addresses, ledger, transaction,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path, time::Duration};
const ORACLE: &str = "9d6548868037df4648ebc648aa0fc364ef538064ea8bb2e28072d7c92dac37f2";
fn bytes(value: &Value, field: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(
        value[field].as_str().context("missing hex bytes")?,
    )?)
}
fn native(hash: &Value) -> Value {
    json!({"type":"signature","key_hash_hex":hash})
}
fn credential(input: &Value) -> Result<(u8, Vec<u8>)> {
    if let Some(script) = input.get("stake_script").filter(|v| !v.is_null()) {
        Ok((
            1,
            transaction::blake2b(
                &addresses::script_bytes(&native(&script["key_hash_hex"]))?,
                28,
            )?,
        ))
    } else {
        let public = bytes(input, "stake_xpub_hex")?;
        ensure!(public.len() == 64, "invalid stake xpub");
        Ok((0, transaction::blake2b(&public[..32], 28)?))
    }
}
pub fn certificates(input: &Value) -> Result<Vec<String>> {
    let (kind, hash) = credential(input)?;
    let credential = |e: &mut minicbor::Encoder<Vec<u8>>| -> Result<()> {
        e.array(2)?.u8(kind)?.bytes(&hash)?;
        Ok(())
    };
    let action = input["action"].as_str().context("missing action")?;
    let mut certificates = vec![];
    if action == "join-registering" || action == "vote-registering" || action == "quit" {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(3)?.u8(if action == "quit" { 8 } else { 7 })?;
        credential(&mut e)?;
        e.u64(input["deposit"].as_u64().context("missing deposit")?)?;
        certificates.push(hex::encode(e.into_writer()));
    }
    if action == "join" || action == "join-registering" {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(3)?.u8(2)?;
        credential(&mut e)?;
        e.bytes(&bytes(input, "pool_hex")?)?;
        certificates.push(hex::encode(e.into_writer()));
    }
    if action == "vote" || action == "vote-registering" {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(3)?.u8(9)?;
        credential(&mut e)?;
        let drep = &input["drep"];
        match drep["type"].as_str().context("missing DRep kind")? {
            "abstain" => {
                e.array(1)?.u8(2)?;
            }
            "no-confidence" => {
                e.array(1)?.u8(3)?;
            }
            "key" | "script" => {
                e.array(2)?
                    .u8(if drep["type"] == "key" { 0 } else { 1 })?
                    .bytes(&bytes(drep, "hash_hex")?)?;
            }
            _ => anyhow::bail!("unknown DRep kind"),
        }
        certificates.push(hex::encode(e.into_writer()));
    }
    ensure!(!certificates.is_empty(), "unknown certificate action");
    Ok(certificates)
}
fn bootstrap_attributes(input: &Value) -> Result<Vec<u8>> {
    let address = bytes(input, "address_hex")?;
    let mut envelope = minicbor::Decoder::new(&address);
    ensure!(
        envelope.array()? == Some(2) && envelope.tag()?.as_u64() == 24,
        "invalid Byron envelope"
    );
    let mut body = minicbor::Decoder::new(envelope.bytes()?);
    ensure!(body.array()? == Some(3), "invalid Byron payload");
    body.bytes()?;
    let mut path = None;
    for _ in 0..body.map()?.context("indefinite address attributes")? {
        let key = body.u8()?;
        let bytes = body.bytes()?;
        if key == 1 {
            path = Some(bytes.to_vec());
        }
    }
    let magic = input["network_magic"].as_u64();
    let mut e = minicbor::Encoder::new(Vec::new());
    e.map(u64::from(path.is_some()) + u64::from(magic.is_some()))?;
    if let Some(path) = path {
        e.u8(1)?.bytes(&path)?;
    }
    if let Some(magic) = magic {
        let mut m = minicbor::Encoder::new(Vec::new());
        m.u64(magic)?;
        e.u8(2)?.bytes(&m.into_writer())?;
    }
    Ok(e.into_writer())
}
pub fn validate(vector: &Vector, actual: &Value) -> Result<()> {
    let Some(result) = actual.get("result") else {
        return Ok(());
    };
    let input = &vector.input;
    match vector.operation.as_str() {
        "wallet.certificates" => ensure!(
            result["certificates_cbor_hex"] == json!(certificates(input)?),
            "wallet certificate tags/credentials/deposits/DRep bytes differ"
        ),
        "witness.script" => {
            let script = addresses::script_bytes(&native(&input["script_key_hash_hex"]))?;
            let mut e = minicbor::Encoder::new(Vec::new());
            e.map(1)?
                .u8(1)?
                .tag(minicbor::data::Tag::new(258))?
                .array(1)?;
            let mut expected = e.into_writer();
            expected.extend(&script[1..]);
            ensure!(
                result["witnesses_cbor_hex"] == hex::encode(expected)
                    && result["script_hash_hex"] == hex::encode(transaction::blake2b(&script, 28)?),
                "native script witness set/hash differs"
            );
        }
        "witness.build" => {
            let raw = bytes(result, "witness_cbor_hex")?;
            let key = bytes(input, "xprv_hex")?;
            ensure!(key.len() == 128, "invalid legacy key");
            let mut d = minicbor::Decoder::new(&raw);
            let bootstrap = input["style"] == "Byron";
            ensure!(
                d.array()? == Some(if bootstrap { 4 } else { 2 }),
                "invalid witness tuple"
            );
            let public: [u8; 32] = d.bytes()?.try_into()?;
            let sig = ed25519_dalek::Signature::from_slice(d.bytes()?)?;
            let hash = hex::decode(ledger::transaction_id(&bytes(
                input,
                "transaction_cbor_hex",
            )?)?)?;
            ed25519_dalek::VerifyingKey::from_bytes(&public)?.verify_strict(&hash, &sig)?;
            ensure!(
                public == key[64..96],
                "witness public key differs from fixture key"
            );
            if bootstrap {
                ensure!(
                    d.bytes()? == &key[96..] && d.bytes()? == bootstrap_attributes(input)?,
                    "bootstrap chain code/attributes differ"
                );
            }
            ensure!(d.position() == raw.len(), "trailing witness bytes");
        }
        "witness.sign" => {
            let before = transaction::inspect(
                input["transaction_cbor_hex"]
                    .as_str()
                    .context("missing transaction")?,
                false,
            )?;
            let after = transaction::inspect(
                result["transaction_cbor_hex"]
                    .as_str()
                    .context("missing signed transaction")?,
                false,
            )?;
            let mut expected: BTreeSet<_> = before.verification_keys.into_iter().collect();
            if input["resolve_inputs"] != false {
                let key = bytes(input, "xprv_hex")?;
                ensure!(key.len() == 128, "invalid legacy key");
                expected.insert(hex::encode(&key[64..96]));
            }
            ensure!(
                after.id == before.id
                    && after.verification_keys.len() == expected.len()
                    && after.verification_keys.into_iter().collect::<BTreeSet<_>>() == expected,
                "wallet signing changed body, dropped or duplicated witnesses"
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
        requirements: &[&str],
        operation: &str,
        input: Value,
        expected: Option<Value>,
    ) -> Result<Value> {
        let mut vector=Vector{id:id.into(),requirements:requirements.iter().map(|s|(*s).into()).collect(),source:format!("Wallet2fc5c383 actual ledger witness builders, wallet signTransaction and delegation/voting certificate builders; WriterAdapter binary sha256:{ORACLE}; independent Rust raw-body/signature/credential/certificate CBOR laws"),operation:operation.into(),input,expected:None,selection_invariants:false};
        let actual = adapter::invoke(self.binary, &[], &vector, Duration::from_secs(30))?;
        ensure!(
            actual == adapter::invoke(self.binary, &[], &vector, Duration::from_secs(30))?,
            "writer oracle replay differs: {id}"
        );
        if let Some(expected) = expected {
            ensure!(actual == expected, "writer boundary differs: {id}");
        } else {
            ensure!(
                actual.get("result").is_some(),
                "valid writer input rejected: {id}"
            );
        }
        validate(&vector, &actual)
            .with_context(|| format!("independent writer law failed: {id}"))?;
        vector.expected = Some(actual.clone());
        self.vectors.push(vector);
        Ok(actual)
    }
}
pub fn capture(binary: &Path) -> Result<Vec<Vector>> {
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(binary)?)) == ORACLE,
        "writer adapter differs from pinned oracle"
    );
    let mut c = Capture {
        binary,
        vectors: vec![],
    };
    let mnemonics: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/mnemonic-profiles.json"))?;
    let root = |id: &str| -> Result<Value> {
        Ok(mnemonics
            .iter()
            .find(|v| v.id == id)
            .context("missing key fixture")?
            .expected
            .as_ref()
            .context("missing key golden")?["result"]
            .clone())
    };
    let first = root("shelley-second-factor")?;
    let second = root("ledger-root-golden")?;
    ensure!(
        first["xpub_hex"] != second["xpub_hex"],
        "merge fixture keys must be distinct"
    );
    let ledgers: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/ledger-profiles.json"))?;
    let tx = &ledgers
        .iter()
        .find(|v| v.id == "tx-cbor-conway")
        .context("missing Conway codec fixture")?
        .expected
        .as_ref()
        .unwrap()["result"]["cbor_hex"];
    let addresses: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/address-profiles.json"))?;
    let address = &addresses
        .iter()
        .find(|v| v.id == "address-byron-random")
        .context("missing Byron address")?
        .expected
        .as_ref()
        .unwrap()["result"]["address_hex"];
    let base = json!({"transaction_cbor_hex":tx,"xprv_hex":first["encrypted_xprv_hex"],"passphrase_hex":"","style":"Shelley","address_hex":address,"network_magic":42});
    c.add(
        "witness-vkey-golden",
        &["tx.witnesses"],
        "witness.build",
        base.clone(),
        None,
    )?;
    let mut bootstrap = base.clone();
    bootstrap["style"] = json!("Byron");
    c.add(
        "witness-bootstrap-golden",
        &["tx.witnesses"],
        "witness.build",
        bootstrap.clone(),
        None,
    )?;
    bootstrap["network_magic"] = Value::Null;
    c.add(
        "witness-bootstrap-mainnet",
        &["tx.witnesses"],
        "witness.build",
        bootstrap.clone(),
        None,
    )?;
    c.add(
        "witness-script-golden",
        &["tx.witnesses"],
        "witness.script",
        json!({"script_key_hash_hex":"11".repeat(28)}),
        None,
    )?;
    let signed = c.add(
        "witness-sign-first",
        &["tx.witnesses"],
        "witness.sign",
        base.clone(),
        None,
    )?;
    let mut duplicate = base.clone();
    duplicate["transaction_cbor_hex"] = signed["result"]["transaction_cbor_hex"].clone();
    c.add(
        "witness-duplicate",
        &["tx.witnesses"],
        "witness.sign",
        duplicate.clone(),
        Some(signed.clone()),
    )?;
    let mut merge = duplicate.clone();
    merge["xprv_hex"] = second["encrypted_xprv_hex"].clone();
    let merged = c.add(
        "witness-merge",
        &["tx.witnesses"],
        "witness.sign",
        merge.clone(),
        None,
    )?;
    ensure!(
        transaction::inspect(
            merged["result"]["transaction_cbor_hex"]
                .as_str()
                .context("missing merged transaction")?,
            true
        )?
        .verification_keys
        .len()
            == 2,
        "merge fixture must exercise two distinct witnesses"
    );
    let mut again = merge;
    again["transaction_cbor_hex"] = merged["result"]["transaction_cbor_hex"].clone();
    c.add(
        "witness-merge-idempotent",
        &["tx.witnesses"],
        "witness.sign",
        again,
        Some(merged),
    )?;
    let mut unresolved = duplicate;
    unresolved["resolve_inputs"] = json!(false);
    c.add(
        "witness-unresolved-preserves-existing",
        &["tx.witnesses"],
        "witness.sign",
        unresolved,
        Some(signed),
    )?;
    bootstrap["network_magic"] = json!(42);
    c.add(
        "witness-bootstrap-sign",
        &["tx.witnesses"],
        "witness.sign",
        bootstrap,
        None,
    )?;
    let mut bad = base.clone();
    bad["xprv_hex"] = json!("00".repeat(127));
    c.add(
        "witness-invalid-key",
        &["tx.witnesses"],
        "witness.build",
        bad,
        Some(json!({"error":{"code":"invalid_input"}})),
    )?;
    let mut bad = base;
    bad["transaction_cbor_hex"] = json!("ff");
    c.add(
        "witness-malformed-transaction",
        &["tx.witnesses"],
        "witness.build",
        bad,
        Some(json!({"error":{"code":"decode_failed"}})),
    )?;
    let base = json!({"era":"conway","stake_xpub_hex":first["xpub_hex"],"action":"vote","deposit":2000000,"pool_hex":"22".repeat(28),"drep":{"type":"abstain"}});
    for (id, changes, requirements) in [
        (
            "stake-register-delegate-golden",
            json!({"action":"join-registering"}),
            vec!["tx.delegation"],
        ),
        (
            "stake-delegate-golden",
            json!({"action":"join"}),
            vec!["tx.delegation"],
        ),
        (
            "stake-deposit-refund",
            json!({"action":"quit"}),
            vec!["tx.delegation"],
        ),
        (
            "governance-certificate-golden",
            json!({"action":"vote-registering"}),
            vec!["tx.governance"],
        ),
        ("governance-vote-abstain", json!({}), vec!["tx.governance"]),
        (
            "governance-vote-no-confidence",
            json!({"drep":{"type":"no-confidence"}}),
            vec!["tx.governance"],
        ),
        (
            "governance-vote-key",
            json!({"drep":{"type":"key","hash_hex":"33".repeat(28)}}),
            vec!["tx.governance"],
        ),
        (
            "governance-vote-script",
            json!({"drep":{"type":"script","hash_hex":"44".repeat(28)}}),
            vec!["tx.governance"],
        ),
        (
            "governance-stake-script",
            json!({"stake_script":{"key_hash_hex":"55".repeat(28)}}),
            vec!["tx.governance"],
        ),
        (
            "stake-script-register",
            json!({"action":"join-registering","stake_script":{"key_hash_hex":"55".repeat(28)}}),
            vec!["tx.delegation"],
        ),
        (
            "stake-zero-deposit",
            json!({"action":"quit","deposit":0}),
            vec!["tx.delegation"],
        ),
        (
            "stake-max-deposit",
            json!({"action":"quit","deposit":u64::MAX}),
            vec!["tx.delegation"],
        ),
    ] {
        let mut input = base.clone();
        input
            .as_object_mut()
            .unwrap()
            .extend(changes.as_object().unwrap().clone());
        c.add(id, &requirements, "wallet.certificates", input, None)?;
    }
    for (id, era, action, code, requirement) in [
        (
            "governance-era-rejection",
            "dijkstra",
            "vote",
            "unsupported_era",
            "tx.governance",
        ),
        (
            "stake-era-rejection",
            "dijkstra",
            "join",
            "unsupported_era",
            "tx.delegation",
        ),
        (
            "stake-deposit-required",
            "conway",
            "quit",
            "deposit_required",
            "tx.delegation",
        ),
        (
            "governance-deposit-required",
            "conway",
            "vote-registering",
            "deposit_required",
            "tx.governance",
        ),
    ] {
        let mut input = base.clone();
        input["era"] = json!(era);
        input["action"] = json!(action);
        input["deposit"] = Value::Null;
        c.add(
            id,
            &[requirement],
            "wallet.certificates",
            input,
            Some(json!({"error":{"code":code}})),
        )?;
    }
    Ok(c.vectors)
}
