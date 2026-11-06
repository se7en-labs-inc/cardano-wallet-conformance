//! Actual Conway minimum fees checked with independent CBOR sizing and rational arithmetic.
use crate::adapter::{self, Vector};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
const ORACLE: &str = "56e29eb99e518c0c130b0e85c4cccd3a3ca92b02f61fc57e0c99d2b443020766";
fn uint(v: &Value, field: &str) -> Result<u128> {
    Ok(u128::from(
        v[field].as_u64().context("missing bounded integer")?,
    ))
}
fn ratio(v: &Value) -> Result<(u128, u128)> {
    let n = uint(v, "numerator")?;
    let d = uint(v, "denominator")?;
    ensure!(d > 0, "zero denominator");
    Ok((n, d))
}
fn reference_fee(bytes: u128, price: &Value) -> Result<u128> {
    ensure!(bytes <= 200_000, "reference bytes exceed profile");
    let (mut per, mut den) = ratio(price)?;
    let mut remaining = bytes;
    let mut numerator = 0u128;
    while remaining > 0 {
        let count = remaining.min(25_600);
        numerator = numerator
            .checked_add(count.checked_mul(per).context("tier overflow")?)
            .context("tier overflow")?;
        remaining -= count;
        if remaining > 0 {
            numerator = numerator.checked_mul(5).context("tier overflow")?;
            den = den.checked_mul(5).context("tier overflow")?;
            per = per.checked_mul(6).context("tier overflow")?;
        }
    }
    Ok(numerator / den)
}
struct Parts<'a> {
    body: &'a [u8],
    witnesses: &'a [u8],
    auxiliary: &'a [u8],
    valid: bool,
}
fn item<'a>(d: &mut minicbor::Decoder<'a>, raw: &'a [u8]) -> Result<&'a [u8]> {
    let start = d.position();
    d.skip()?;
    Ok(&raw[start..d.position()])
}
fn parts(raw: &[u8]) -> Result<Parts<'_>> {
    let mut d = minicbor::Decoder::new(raw);
    ensure!(d.array()? == Some(4), "invalid Conway transaction envelope");
    let body = item(&mut d, raw)?;
    let witnesses = item(&mut d, raw)?;
    let valid = d.bool()?;
    let auxiliary = item(&mut d, raw)?;
    ensure!(d.position() == raw.len(), "trailing transaction bytes");
    Ok(Parts {
        body,
        witnesses,
        auxiliary,
        valid,
    })
}
fn units(witnesses: &[u8]) -> Result<Vec<Value>> {
    let mut d = minicbor::Decoder::new(witnesses);
    let count = d.map()?.context("indefinite witness map")?;
    let mut result = Vec::new();
    let mut found = false;
    for _ in 0..count {
        if d.u64()? != 5 {
            d.skip()?;
            continue;
        }
        ensure!(!found, "duplicate redeemer map");
        found = true;
        let count = d.map()?.context("indefinite redeemer map")?;
        for index in 0..count {
            ensure!(
                d.array()? == Some(2) && d.u64()? == 0 && d.u64()? == index,
                "unexpected spending redeemer purpose/index"
            );
            ensure!(
                d.array()? == Some(2) && d.i64()? == 0 && d.array()? == Some(2),
                "unexpected datum/execution envelope"
            );
            result.push(json!({"memory":d.u64()?,"steps":d.u64()?}));
        }
    }
    ensure!(d.position() == witnesses.len(), "trailing witnesses");
    Ok(result)
}
pub fn validate(vector: &Vector, actual: &Value) -> Result<()> {
    let Some(result) = actual.get("result") else {
        return Ok(());
    };
    let input = &vector.input;
    let before = hex::decode(
        input["transaction_cbor_hex"]
            .as_str()
            .context("missing transaction")?,
    )?;
    let after = hex::decode(
        result["transaction_cbor_hex"]
            .as_str()
            .context("missing returned transaction")?,
    )?;
    let original = parts(&before)?;
    let tx = parts(&after)?;
    ensure!(
        original.body == tx.body
            && original.auxiliary == tx.auxiliary
            && original.valid == tx.valid,
        "fee probe changed transaction body/auxiliary/validity"
    );
    let requested = input["execution_units"]
        .as_array()
        .context("missing execution units")?;
    let actual_units = units(tx.witnesses)?;
    if requested.is_empty() {
        ensure!(before == after, "fee probe changed existing witnesses");
    } else {
        ensure!(
            *requested == actual_units,
            "fee probe changed redeemer units"
        );
        // Strip only redeemers: all original witness fields must survive exactly.
        let fields = |raw: &[u8]| -> Result<Vec<(u64, Vec<u8>)>> {
            let mut d = minicbor::Decoder::new(raw);
            let count = d.map()?.context("indefinite witnesses")?;
            let mut out = Vec::new();
            for _ in 0..count {
                let key = d.u64()?;
                let value = item(&mut d, raw)?;
                if key != 5 {
                    out.push((key, value.to_vec()));
                }
            }
            Ok(out)
        };
        ensure!(
            fields(original.witnesses)? == fields(tx.witnesses)?,
            "fee probe changed non-redeemer witnesses"
        );
    }
    let mut size = minicbor::Encoder::new(Vec::new());
    size.array(3)?;
    let ledger_size =
        size.into_writer().len() + tx.body.len() + tx.witnesses.len() + tx.auxiliary.len();
    let (mn, md) = ratio(&input["memory_price"])?;
    let (sn, sd) = ratio(&input["step_price"])?;
    let (memory, steps) = actual_units
        .iter()
        .try_fold((0u128, 0u128), |(m, s), u| -> Result<_> {
            Ok((m + uint(u, "memory")?, s + uint(u, "steps")?))
        })?;
    let execution_num = memory
        .checked_mul(mn)
        .and_then(|v| v.checked_mul(sd))
        .and_then(|v| {
            steps
                .checked_mul(sn)
                .and_then(|s| s.checked_mul(md))
                .and_then(|s| v.checked_add(s))
        })
        .context("execution fee overflow")?;
    let execution_den = md
        .checked_mul(sd)
        .context("execution denominator overflow")?;
    let execution = execution_num / execution_den + u128::from(execution_num % execution_den != 0);
    let reference = reference_fee(
        uint(input, "reference_script_bytes")?,
        &input["reference_script_price"],
    )?;
    let minimum = uint(input, "coefficient")?
        .checked_mul(ledger_size as u128)
        .and_then(|v| v.checked_add(uint(input, "constant").ok()?))
        .and_then(|v| v.checked_add(execution))
        .and_then(|v| v.checked_add(reference))
        .context("minimum fee overflow")?;
    ensure!(
        result["ledger_size"] == json!(ledger_size)
            && result["execution_fee"] == json!(execution)
            && result["reference_script_fee"] == json!(reference)
            && result["minimum_fee"] == json!(minimum),
        "ledger fee/size/aggregate rounding differs"
    );
    ensure!(
        result["reference_stride"] == 25_600
            && result["reference_multiplier"] == json!({"numerator":6,"denominator":5}),
        "reference fee tier constants differ"
    );
    Ok(())
}
pub fn capture(binary: &Path) -> Result<Vec<Vector>> {
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(binary)?)) == ORACLE,
        "ledger fee oracle differs from pin"
    );
    let ledger: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/ledger-profiles.json"))?;
    let tx = ledger
        .iter()
        .find(|v| v.id == "tx-cbor-conway")
        .context("missing Conway fixture")?
        .input["cbor_hex"]
        .clone();
    let base = json!({"transaction_cbor_hex":tx,"coefficient":100,"constant":100000,"memory_price":{"numerator":577,"denominator":10000},"step_price":{"numerator":721,"denominator":10000000},"reference_script_price":{"numerator":15,"denominator":1},"reference_script_bytes":0,"execution_units":[]});
    let mut vectors = Vec::new();
    let mut add = |id: String, changes: Value, error: Option<&str>| -> Result<Value> {
        let mut input = base.clone();
        input
            .as_object_mut()
            .unwrap()
            .extend(changes.as_object().context("invalid changes")?.clone());
        let mut vector = Vector { id, requirements:vec!["tx.minimum-fee".into()], source:format!("Wallet2fc5c383; actual Conway ledger1.23 getMinFeeTx/sizeTxF/txscriptfee/tierRefScriptFee, FeeAdapter sha256:{ORACLE}; independently checked CBOR envelope and exact aggregate rational arithmetic; not node admission"),operation:"transaction.minimum-fee".into(),input,expected:None,selection_invariants:false };
        let actual = adapter::invoke(binary, &[], &vector, Duration::from_secs(30))?;
        ensure!(
            actual == adapter::invoke(binary, &[], &vector, Duration::from_secs(30))?,
            "fee oracle replay differs: {}",
            vector.id
        );
        if let Some(code) = error {
            ensure!(
                actual == json!({"error":{"code":code}}),
                "fee error differs: {}",
                vector.id
            );
        } else {
            ensure!(
                actual.get("result").is_some(),
                "fee oracle rejected valid input: {}",
                vector.id
            );
            validate(&vector, &actual)
                .with_context(|| format!("independent fee law: {}", vector.id))?;
        }
        vector.expected = Some(actual.clone());
        vectors.push(vector);
        Ok(actual)
    };
    for bytes in [0, 1, 25599, 25600, 25601, 51200, 51201, 200000] {
        for (name, n, d) in [("integer", 15, 1), ("fractional", 1, 10), ("zero", 0, 1)] {
            add(
                format!("ledger-fee-reference-{name}-{bytes}"),
                json!({"reference_script_bytes":bytes,"reference_script_price":{"numerator":n,"denominator":d}}),
                None,
            )?;
        }
    }
    for (name, changes) in [
        ("zero-coefficients", json!({"coefficient":0,"constant":0})),
        (
            "zero-unit-redeemer",
            json!({"execution_units":[{"memory":0,"steps":0}]}),
        ),
        (
            "production-execution",
            json!({"execution_units":[{"memory":14000000,"steps":10000000000u64}],"reference_script_bytes":51201}),
        ),
        (
            "ceiling-after-memory-plus-steps",
            json!({"execution_units":[{"memory":1,"steps":1}],"memory_price":{"numerator":1,"denominator":2},"step_price":{"numerator":1,"denominator":2}}),
        ),
        (
            "fraction-ceiling",
            json!({"execution_units":[{"memory":1,"steps":0}],"memory_price":{"numerator":1,"denominator":3}}),
        ),
    ] {
        add(format!("ledger-fee-{name}"), changes, None)?;
    }
    let split = add(
        "ledger-fee-ceiling-after-redeemer-sum".into(),
        json!({"execution_units":[{"memory":1,"steps":0},{"memory":1,"steps":0}],"memory_price":{"numerator":1,"denominator":2},"step_price":{"numerator":0,"denominator":1}}),
        None,
    )?;
    add(
        "ledger-fee-preserve-existing-redeemers".into(),
        json!({"transaction_cbor_hex":split["result"]["transaction_cbor_hex"],"memory_price":{"numerator":1,"denominator":2},"step_price":{"numerator":0,"denominator":1}}),
        None,
    )?;
    let writer: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/writer-profiles.json"))?;
    for (name, id) in [
        ("one-vkey", "witness-sign-first"),
        ("two-vkeys", "witness-merge"),
    ] {
        let signed = &writer
            .iter()
            .find(|v| v.id == id)
            .context("missing writer fixture")?
            .expected
            .as_ref()
            .context("missing writer result")?["result"]["transaction_cbor_hex"];
        add(
            format!("ledger-fee-{name}"),
            json!({"transaction_cbor_hex":signed}),
            None,
        )?;
    }
    for (name, changes, code) in [
        (
            "malformed-cbor",
            json!({"transaction_cbor_hex":"ff"}),
            "decode_failed",
        ),
        (
            "malformed-hex",
            json!({"transaction_cbor_hex":"xz"}),
            "invalid_input",
        ),
        (
            "zero-price-denominator",
            json!({"memory_price":{"numerator":1,"denominator":0}}),
            "invalid_input",
        ),
        (
            "reference-profile-limit",
            json!({"reference_script_bytes":200001}),
            "invalid_input",
        ),
    ] {
        add(format!("ledger-fee-{name}"), changes, Some(code))?;
    }
    Ok(vectors)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tier_rounding_is_final_floor() {
        assert_eq!(
            reference_fee(25601, &json!({"numerator":1,"denominator":10})).unwrap(),
            2560
        );
        assert_eq!(
            reference_fee(25601, &json!({"numerator":15,"denominator":1})).unwrap(),
            384018
        );
    }
    #[test]
    fn frozen_fees_reject_size_rounding_units_and_body_mutations() {
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../fixtures/vectors/ledger-fees.json")).unwrap();
        assert!(vectors.len() >= 35);
        for v in vectors
            .iter()
            .filter(|v| v.expected.as_ref().unwrap().get("result").is_some())
        {
            let actual = v.expected.as_ref().unwrap();
            validate(v, actual).unwrap();
            for field in [
                "minimum_fee",
                "ledger_size",
                "execution_fee",
                "reference_script_fee",
            ] {
                let mut changed = actual.clone();
                changed["result"][field] = json!(changed["result"][field].as_u64().unwrap() + 1);
                assert!(validate(v, &changed).is_err(), "{} {field}", v.id);
            }
        }
        let v = vectors
            .iter()
            .find(|v| v.id == "ledger-fee-ceiling-after-redeemer-sum")
            .unwrap();
        assert_eq!(v.expected.as_ref().unwrap()["result"]["execution_fee"], 1);
        let mut changed = v.clone();
        changed.input["execution_units"][0]["memory"] = json!(2);
        assert!(validate(&changed, v.expected.as_ref().unwrap()).is_err());
        let v = vectors
            .iter()
            .find(|v| v.id == "ledger-fee-zero-coefficients")
            .unwrap();
        let mut changed = v.clone();
        let mut tx = hex::decode(changed.input["transaction_cbor_hex"].as_str().unwrap()).unwrap();
        tx[10] ^= 1;
        changed.input["transaction_cbor_hex"] = json!(hex::encode(tx));
        assert!(validate(&changed, v.expected.as_ref().unwrap()).is_err());
    }
}
