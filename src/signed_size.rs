//! Actual wallet signed-size estimation checked against independent CBOR arithmetic.
use crate::{
    adapter::{self, Vector},
    ledger,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path, time::Duration};
const ORACLE: &str = "1870a2fbc67698bcaf52595c28651c65a5490fcaa52653aa424cc84d476dbce1";
fn uint(value: &Value, name: &str) -> Result<u64> {
    value[name]
        .as_u64()
        .context("missing signed-size unsigned quantity")
}
fn span<'a>(d: &mut minicbor::Decoder<'a>, raw: &'a [u8]) -> Result<&'a [u8]> {
    let start = d.position();
    d.skip()?;
    Ok(&raw[start..d.position()])
}
struct Parts<'a> {
    body: &'a [u8],
    witnesses: &'a [u8],
    auxiliary: &'a [u8],
}
fn parts(raw: &[u8]) -> Result<Parts<'_>> {
    let mut d = minicbor::Decoder::new(raw);
    ensure!(
        d.array()? == Some(4),
        "signed-size profile requires Conway tuple"
    );
    let body = span(&mut d, raw)?;
    let witnesses = span(&mut d, raw)?;
    d.bool()?;
    let auxiliary = span(&mut d, raw)?;
    ensure!(d.position() == raw.len(), "trailing signed-size CBOR");
    Ok(Parts {
        body,
        witnesses,
        auxiliary,
    })
}
fn encoded_key_size(key: u64) -> Result<u64> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.u64(key)?;
    Ok(e.into_writer().len() as u64)
}
fn input_count(body: &[u8]) -> Result<u64> {
    let mut d = minicbor::Decoder::new(body);
    let mut keys = BTreeSet::new();
    let mut inputs = None;
    for _ in 0..d.map()?.context("indefinite transaction body map")? {
        let key = d.u64()?;
        ensure!(keys.insert(key), "duplicate transaction body key");
        if key != 0 {
            d.skip()?;
            continue;
        }
        if d.datatype()? == minicbor::data::Type::Tag {
            ensure!(d.tag()?.as_u64() == 258, "wrong input set tag");
        }
        let count = d.array()?;
        let mut seen = BTreeSet::new();
        while count.is_none_or(|n| (seen.len() as u64) < n) {
            if count.is_none() && d.datatype()? == minicbor::data::Type::Break {
                d.skip()?;
                break;
            }
            ensure!(d.array()? == Some(2), "invalid size-profile input tuple");
            let hash = d.bytes()?;
            ensure!(hash.len() == 32, "invalid size-profile input hash");
            let index = d.u64()?;
            ensure!(
                index <= 65535 && seen.insert((hash.to_vec(), index)),
                "duplicate or invalid size-profile input"
            );
        }
        inputs = Some(seen.len() as u64);
    }
    ensure!(
        keys.contains(&1) && keys.contains(&2) && d.position() == body.len(),
        "missing body output/fee or trailing bytes"
    );
    inputs.context("missing transaction input set")
}
/// Independently reproduce ledger byte counts without verifying discarded signatures.
pub fn estimate(input: &Value) -> Result<Value> {
    let encoded = input["transaction_cbor_hex"]
        .as_str()
        .context("missing signed-size CBOR")?;
    let raw = hex::decode(encoded)?;
    let tx = parts(&raw)?;
    let count = input_count(tx.body)?;
    if input.get("input_count").is_some() {
        ensure!(
            uint(input, "input_count")? == count,
            "size profile input count differs"
        );
    }
    let keys = uint(input, "vkey_witnesses")?;
    let boots = uint(input, "bootstrap_witnesses")?;
    let maximum = uint(input, "maximum_transaction_bytes")?;
    let major = uint(input, "protocol_major")?;
    ensure!(
        keys <= 65536
            && boots <= 65536
            && maximum <= u64::from(u32::MAX)
            && (9..=12).contains(&major),
        "signed-size adapter bounds exceeded"
    );
    let mut d = minicbor::Decoder::new(tx.witnesses);
    let fields = d.map()?.context("indefinite witness map")?;
    let mut seen = BTreeSet::new();
    let (mut retained, mut retained_bytes) = (0, 0);
    for _ in 0..fields {
        let key = d.u64()?;
        ensure!(seen.insert(key), "duplicate witness key");
        let value = span(&mut d, tx.witnesses)?;
        if key != 0 && key != 2 {
            retained += 1;
            retained_bytes += encoded_key_size(key)? + value.len() as u64;
        }
    }
    ensure!(d.position() == tx.witnesses.len(), "trailing witness bytes");
    let mut e = minicbor::Encoder::new(Vec::new());
    e.map(retained + u64::from(keys > 0))?;
    // Actual ledger sets use tag258 and indefinite framing above23 members.
    let key_bytes = if keys == 0 {
        0
    } else {
        4 + (if keys <= 23 { 1 } else { 2 }) + 101 * keys
    };
    let witness_bytes = e.into_writer().len() as u64 + retained_bytes + key_bytes;
    let bootstrap_bytes = if boots == 0 { 0 } else { 4 + 180 * boots };
    let original = 1 + tx.body.len() as u64 + tx.witnesses.len() as u64 + tx.auxiliary.len() as u64;
    let estimated =
        1 + tx.body.len() as u64 + witness_bytes + tx.auxiliary.len() as u64 + bootstrap_bytes;
    Ok(
        json!({"original_ledger_bytes":original,"estimated_bytes":estimated,
        "bootstrap_bytes":bootstrap_bytes,"within_size_limit":estimated<=maximum,
        "transaction_id":ledger::transaction_id(&raw)?}),
    )
}
pub fn validate(vector: &Vector, actual: &Value) -> Result<()> {
    if vector.operation == "transaction.input-witness-count" {
        let raw = hex::decode(
            vector.input["transaction_cbor_hex"]
                .as_str()
                .context("missing witness-count CBOR")?,
        )?;
        let tx = parts(&raw)?;
        let mut d = minicbor::Decoder::new(tx.body);
        ensure!(
            d.map()? == Some(4),
            "witness-count profile has extra body fields"
        );
        for _ in 0..4 {
            ensure!(
                d.u64()? <= 3,
                "witness-count profile contains non-input witness sources"
            );
            d.skip()?;
        }
        let expected =
            json!({"result":{"vkey_witnesses":input_count(tx.body)?,"bootstrap_witnesses":0}});
        ensure!(
            *actual == expected,
            "actual per-input Haskell witness count differs"
        );
        return Ok(());
    }
    match actual.get("result") {
        Some(result) => ensure!(
            *result == estimate(&vector.input)?,
            "actual wallet signed-size law differs"
        ),
        None => ensure!(
            actual.get("error").is_some() && estimate(&vector.input).is_err(),
            "valid signed-size input unexpectedly rejected"
        ),
    }
    Ok(())
}

/// Canonical size-only transaction input: no UTxO or ledger admission claim.
pub fn partial(count: u64, indefinite: bool) -> Result<Vec<u8>> {
    ensure!(count <= 1000, "size prototype input bound exceeded");
    let address = crate::encoding::bech32(crate::balancing::DESTINATION)?.1;
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4)?
        .map(4)?
        .u8(0)?
        .tag(minicbor::data::Tag::new(258))?;
    if indefinite {
        e.begin_array()?;
    } else {
        e.array(count)?;
    }
    for index in 0..count {
        e.array(2)?.bytes(&[0x11; 32])?.u64(index)?;
    }
    if indefinite {
        e.end()?;
    }
    e.u8(1)?
        .array(1)?
        .array(2)?
        .bytes(&address)?
        .u64(2_000_000)?
        .u8(2)?
        .u64(170_000)?
        .u8(3)?
        .u64(6_000_000)?;
    e.map(0)?.bool(true)?.null()?;
    Ok(e.into_writer())
}
struct Capture<'a> {
    binary: &'a Path,
    vectors: Vec<Vector>,
}
impl Capture<'_> {
    fn add(&mut self, id: &str, input: Value, expected_error: Option<&str>) -> Result<()> {
        let mut vector=Vector{id:format!("signed-size-{id}"),requirements:vec!["selection.input-limits".into()],
            source:format!("Actual wallet cardano-balance-tx8975773 Sign.estimateSignedTxSize and ledger variable-list encoding; SizeAdapter sha256:{ORACLE}; independent Rust raw body/non-key witness/auxiliary size, key replacement, tag258/indefinite framing and bootstrap arithmetic. Size component only, not live input-limit admission."),
            operation:"transaction.size-estimate".into(),input,expected:None,selection_invariants:false};
        let actual = adapter::invoke(self.binary, &[], &vector, Duration::from_secs(60))?;
        ensure!(
            actual == adapter::invoke(self.binary, &[], &vector, Duration::from_secs(60))?,
            "size oracle replay differs"
        );
        if let Some(error) = expected_error {
            ensure!(
                actual == json!({"error":{"code":error}}),
                "size wrapper error differs"
            );
        } else {
            ensure!(
                actual.get("result").is_some(),
                "size oracle rejected valid prototype"
            );
        }
        validate(&vector, &actual).with_context(|| format!("size law failed for{id}"))?;
        vector.expected = Some(actual);
        self.vectors.push(vector);
        Ok(())
    }
}
pub fn capture(binary: &Path, audit: &Path) -> Result<Vec<Vector>> {
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(binary)?)) == ORACLE,
        "size oracle differs"
    );
    let mut capture = Capture {
        binary,
        vectors: Vec::new(),
    };
    for suffix in [
        "0",
        "1",
        "2",
        "23",
        "24",
        "255",
        "256",
        "65536",
        "bootstrap-1",
        "bootstrap-2",
        "bootstrap-23",
        "bootstrap-24",
        "bootstrap-65536",
        "bootstrap-existing-signed",
        "bootstrap-existing-unsigned",
        "invalid-count",
        "malformed",
        "maximum-0",
        "maximum-169",
        "maximum-170",
        "maximum-171",
        "maximum-4294967295",
        "nonkey-preserved",
        "protocol-12",
        "protocol-9",
        "signed-drop",
    ] {
        let source = std::fs::read(audit.join(format!("request-{suffix}.json")))?;
        let request: Value = serde_json::from_slice(&source)?;
        ensure!(
            request["operation"] == "transaction.size-estimate",
            "unexpected source-audit operation"
        );
        let expected_error = match suffix {
            "invalid-count" => Some("invalid_input"),
            "malformed" => Some("decode_failed"),
            _ => None,
        };
        capture.add(suffix, request["input"].clone(), expected_error)?;
    }
    for indefinite in [false, true] {
        let input = |count: u64| -> Result<Value> {
            Ok(
                json!({"transaction_cbor_hex":hex::encode(partial(count,indefinite)?),
            "vkey_witnesses":1,"bootstrap_witnesses":0,"maximum_transaction_bytes":16384,"protocol_major":12,
            "input_count":count,"indefinite_inputs":indefinite}),
            )
        };
        let mut counts = BTreeSet::from([0, 1, 23, 24, 255, 256, 400, 440, 450, 500, 1000]);
        let maximum = (0..=1000)
            .map(|n| Ok((n, estimate(&input(n)?)?)))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|(_, result)| result["within_size_limit"] == true)
            .map(|(n, _)| n)
            .max()
            .context("no within-limit size prototype")?;
        counts.extend([maximum - 1, maximum, maximum + 1]);
        for count in counts {
            capture.add(
                &format!("inputs-{count}-indefinite-{indefinite}"),
                input(count)?,
                None,
            )?;
        }
    }
    let base = capture.vectors[0].input.clone();
    for major in [10, 11] {
        let mut input = base.clone();
        input["protocol_major"] = json!(major);
        capture.add(&format!("protocol-{major}"), input, None)?;
    }
    let mut invalid_signature = capture
        .vectors
        .iter()
        .find(|v| v.id == "signed-size-signed-drop")
        .context("missing signed witness replacement control")?
        .input
        .clone();
    let mut raw = hex::decode(invalid_signature["transaction_cbor_hex"].as_str().unwrap())?;
    let length = raw.len();
    raw[length - 4] ^= 1;
    invalid_signature["transaction_cbor_hex"] = json!(hex::encode(raw));
    capture.add("discarded-invalid-signature", invalid_signature, None)?;
    let mut invalid_phase = base.clone();
    let mut raw = hex::decode(invalid_phase["transaction_cbor_hex"].as_str().unwrap())?;
    let length = raw.len();
    ensure!(
        raw[length - 2] == 0xf5,
        "unexpected phase/auxiliary framing"
    );
    raw[length - 2] = 0xf4;
    invalid_phase["transaction_cbor_hex"] = json!(hex::encode(raw));
    capture.add("phase2-invalid-flag", invalid_phase, None)?;
    for (id, field, value) in [
        ("invalid-bootstrap", "bootstrap_witnesses", json!(65537)),
        (
            "invalid-maximum",
            "maximum_transaction_bytes",
            json!(u64::from(u32::MAX) + 1),
        ),
        ("invalid-protocol-low", "protocol_major", json!(8)),
        ("invalid-protocol-high", "protocol_major", json!(13)),
        ("negative-keys", "vkey_witnesses", json!(-1)),
        ("invalid-hex", "transaction_cbor_hex", json!("zz")),
    ] {
        let mut input = base.clone();
        input[field] = value;
        capture.add(id, input, Some("invalid_input"))?;
    }
    Ok(capture.vectors)
}

#[cfg(test)]
mod tests {
    #[test]
    fn repeated_credentials_still_require_per_reference_mock_witnesses() {
        let vectors: Vec<Vector> = serde_json::from_str(include_str!(
            "../fixtures/vectors/input-witness-count-profiles.json"
        ))
        .unwrap();
        assert_eq!(vectors.len(), 12);
        for vector in vectors {
            let expected = vector.expected.as_ref().unwrap();
            validate(&vector, expected).unwrap();
            let count = expected["result"]["vkey_witnesses"].as_u64().unwrap();
            if count > 1 {
                assert!(validate(
                    &vector,
                    &json!({"result":{"vkey_witnesses":1,"bootstrap_witnesses":0}})
                )
                .is_err());
            }
            assert!(validate(
                &vector,
                &json!({"result":{"vkey_witnesses":count,"bootstrap_witnesses":1}})
            )
            .is_err());
        }
    }
    use super::*;
    fn vectors() -> Vec<Vector> {
        serde_json::from_str(include_str!(
            "../fixtures/vectors/signed-size-profiles.json"
        ))
        .unwrap()
    }
    #[test]
    fn actual_size_goldens_match_independent_byte_model_and_reject_changed_results() {
        let vectors = vectors();
        assert_eq!(vectors.len(), 64);
        for vector in &vectors {
            let actual = vector.expected.as_ref().unwrap();
            validate(vector, actual).unwrap();
            if let Some(result) = actual.get("result") {
                for field in [
                    "estimated_bytes",
                    "original_ledger_bytes",
                    "bootstrap_bytes",
                ] {
                    let mut changed = actual.clone();
                    changed["result"][field] = json!(result[field].as_u64().unwrap() + 1);
                    assert!(
                        validate(vector, &changed).is_err(),
                        "unverified size field{field}"
                    );
                }
                let mut changed = actual.clone();
                changed["result"]["within_size_limit"] =
                    json!(!result["within_size_limit"].as_bool().unwrap());
                assert!(validate(vector, &changed).is_err());
            }
        }
    }
    #[test]
    fn large_witness_sets_use_indefinite_not_generic_definite_header_growth() {
        let vectors = vectors();
        let find = |name: &str| {
            vectors
                .iter()
                .find(|v| v.id == format!("signed-size-{name}"))
                .unwrap()
        };
        let a = find("255").expected.as_ref().unwrap()["result"]["estimated_bytes"]
            .as_u64()
            .unwrap();
        let b = find("256").expected.as_ref().unwrap()["result"]["estimated_bytes"]
            .as_u64()
            .unwrap();
        assert_eq!(b - a, 101);
        let a = find("23").expected.as_ref().unwrap()["result"]["estimated_bytes"]
            .as_u64()
            .unwrap();
        let b = find("24").expected.as_ref().unwrap()["result"]["estimated_bytes"]
            .as_u64()
            .unwrap();
        assert_eq!(b - a, 102);
    }
    #[test]
    fn existing_payment_and_bootstrap_witnesses_are_replaced_but_scripts_remain() {
        let vectors = vectors();
        let find = |name: &str| {
            &vectors
                .iter()
                .find(|v| v.id == format!("signed-size-{name}"))
                .unwrap()
                .expected
                .as_ref()
                .unwrap()["result"]
        };
        assert_eq!(
            find("signed-drop")["estimated_bytes"],
            find("0")["estimated_bytes"]
        );
        assert_eq!(
            find("discarded-invalid-signature")["estimated_bytes"],
            find("signed-drop")["estimated_bytes"]
        );
        assert_eq!(find("phase2-invalid-flag"), find("0"));
        assert_ne!(
            find("signed-drop")["original_ledger_bytes"],
            find("0")["original_ledger_bytes"]
        );
        assert_eq!(
            find("bootstrap-existing-signed")["estimated_bytes"],
            find("bootstrap-existing-unsigned")["estimated_bytes"]
        );
        assert!(
            find("nonkey-preserved")["estimated_bytes"]
                .as_u64()
                .unwrap()
                > find("1")["estimated_bytes"].as_u64().unwrap()
        );
    }
    #[test]
    fn independent_size_boundary_uses_actual_bytes_and_exact_input_counts() {
        for indefinite in [false, true] {
            let base = |n| {
                json!({"transaction_cbor_hex":hex::encode(partial(n,indefinite).unwrap()),
                "input_count":n,"vkey_witnesses":1,"bootstrap_witnesses":0,
                "maximum_transaction_bytes":16384,"protocol_major":12})
            };
            assert_eq!(estimate(&base(434)).unwrap()["within_size_limit"], true);
            assert_eq!(estimate(&base(435)).unwrap()["within_size_limit"], false);
            let mut wrong = base(434);
            wrong["input_count"] = json!(435);
            assert!(estimate(&wrong).is_err());
            let size = estimate(&base(434)).unwrap()["estimated_bytes"]
                .as_u64()
                .unwrap();
            let mut exact = base(434);
            exact["maximum_transaction_bytes"] = json!(size);
            assert_eq!(estimate(&exact).unwrap()["within_size_limit"], true);
            exact["maximum_transaction_bytes"] = json!(size - 1);
            assert_eq!(estimate(&exact).unwrap()["within_size_limit"], false);
        }
    }
}
