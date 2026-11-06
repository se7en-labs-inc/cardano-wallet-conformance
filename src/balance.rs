//! Wallet fee/minimum-ADA component goldens and independent integer/CBOR laws.
use crate::adapter::{self, Vector};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
const ORACLE: &str = "e93a25718344e23de66cad102e3b65409c9e47282039e1935a3272a66e640cd2";
fn uint(v: &Value, field: &str) -> Result<u128> {
    Ok(u128::from(
        v[field].as_u64().context("missing u64 component value")?,
    ))
}
pub fn fee(input: &Value) -> Result<Value> {
    let vkeys = uint(input, "vkey_witnesses")?;
    let boots = uint(input, "bootstrap_witnesses")?;
    let vkey_bytes = 101 * vkeys + if vkeys > 0 { 4 } else { 0 };
    let bootstrap_bytes = 180 * boots + if boots > 0 { 4 } else { 0 };
    let estimated = uint(input, "transaction_bytes")? + vkey_bytes + bootstrap_bytes;
    let linear = estimated
        .checked_mul(uint(input, "coefficient")?)
        .context("linear fee arithmetic overflow")?;
    let memory = &input["memory_price"];
    let step = &input["step_price"];
    let md = uint(memory, "denominator")?;
    let sd = uint(step, "denominator")?;
    ensure!(md > 0 && sd > 0, "zero fee denominator");
    let numerator = uint(input, "execution_memory")?
        .checked_mul(uint(memory, "numerator")?)
        .and_then(|n| n.checked_mul(sd))
        .and_then(|m| {
            uint(input, "execution_steps")
                .ok()?
                .checked_mul(uint(step, "numerator").ok()?)?
                .checked_mul(md)?
                .checked_add(m)
        })
        .context("execution fee arithmetic overflow")?;
    let denominator = md.checked_mul(sd).context("price denominator overflow")?;
    let execution = numerator.div_ceil(denominator);
    let total = linear
        .checked_add(execution)
        .and_then(|n| n.checked_add(uint(input, "constant").ok()?))
        .context("total fee arithmetic overflow")?;
    Ok(
        json!({"vkey_witness_bytes":vkey_bytes,"bootstrap_witness_bytes":bootstrap_bytes,"estimated_bytes":estimated,"linear_fee":linear,"execution_fee":execution,"total_fee":total,"within_size_limit":estimated<=uint(input,"maximum_transaction_bytes")?}),
    )
}
/// Locate the coin term in canonical legacy-array or Babbage-map output bytes.
fn coin_span(raw: &[u8]) -> Result<(usize, usize, u64)> {
    let mut d = minicbor::Decoder::new(raw);
    match d.datatype()? {
        minicbor::data::Type::Array => {
            ensure!(
                d.array()?.is_some_and(|n| n == 2 || n == 3),
                "invalid output array"
            );
            d.skip()?;
        }
        minicbor::data::Type::Map => {
            let count = d.map()?.context("indefinite output map")?;
            let mut found = false;
            for _ in 0..count {
                let key = d.u8()?;
                if key == 1 {
                    found = true;
                    break;
                }
                d.skip()?;
            }
            ensure!(found, "missing output value");
        }
        _ => anyhow::bail!("invalid output envelope"),
    }
    if d.datatype()? == minicbor::data::Type::Array {
        ensure!(d.array()? == Some(2), "invalid multiasset value");
    }
    let start = d.position();
    let coin = d.u64()?;
    Ok((start, d.position(), coin))
}
pub fn validate(vector: &Vector, actual: &Value) -> Result<()> {
    let Some(result) = actual.get("result") else {
        return Ok(());
    };
    match vector.operation.as_str() {
        "fee.components" => ensure!(
            *result == fee(&vector.input)?,
            "wallet fee arithmetic/witness-size/rounding differs"
        ),
        "minimum-utxo" => {
            let raw = hex::decode(
                vector.input["output_cbor_hex"]
                    .as_str()
                    .context("missing output")?,
            )?;
            ensure!(
                result["output_cbor_hex"] == hex::encode(&raw),
                "canonical output changed"
            );
            let (start, end, coin) = coin_span(&raw)?;
            let mut e = minicbor::Encoder::new(Vec::new());
            e.u64(45_000_000_000_000_000)?;
            let wallet = [&raw[..start], e.writer().as_slice(), &raw[end..]].concat();
            let cost = uint(&vector.input, "coins_per_byte")?;
            let minimum = (160 + raw.len() as u128) * cost;
            ensure!(
                result["minimum_coin"] == json!(minimum)
                    && result["wallet_minimum_coin"] == json!((160 + wallet.len() as u128) * cost)
                    && result["wallet_output_cbor_hex"] == hex::encode(wallet)
                    && result["below_minimum"] == json!(u128::from(coin) < minimum),
                "ledger/wallet minimum ADA or conservative coin replacement differs"
            );
        }
        _ => {}
    }
    Ok(())
}
pub fn output(coin: u64, assets: bool, datum: bool, script: bool) -> Result<Vec<u8>> {
    let mut e = minicbor::Encoder::new(Vec::new());
    if datum || script {
        e.map(2 + u64::from(datum) + u64::from(script))?.u8(0)?;
    } else {
        e.array(2)?;
    }
    let mut address = vec![0x60];
    address.extend([0x11; 28]);
    e.bytes(&address)?;
    if datum || script {
        e.u8(1)?;
    }
    if assets {
        e.array(2)?
            .u64(coin)?
            .map(1)?
            .bytes(&[0x22; 28])?
            .map(2)?
            .bytes(&[])?
            .u64(1)?
            .bytes(&[0xab; 32])?
            .u64(23)?;
    } else {
        e.u64(coin)?;
    }
    if datum {
        e.u8(2)?
            .array(2)?
            .u8(1)?
            .tag(minicbor::data::Tag::new(24))?
            .bytes(&[0x18, 0x2a])?;
    }
    if script {
        let mut s = minicbor::Encoder::new(Vec::new());
        s.array(2)?.u8(0)?.array(2)?.u8(0)?.bytes(&[0x33; 28])?;
        e.u8(3)?
            .tag(minicbor::data::Tag::new(24))?
            .bytes(&s.into_writer())?;
    }
    Ok(e.into_writer())
}
pub fn capture(binary: &Path) -> Result<Vec<Vector>> {
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(binary)?)) == ORACLE,
        "balance adapter differs from pinned oracle"
    );
    let mut vectors = Vec::new();
    let mut add = |id: &str,
                   requirement: &str,
                   operation: &str,
                   input: Value,
                   expected: Option<Value>|
     -> Result<()> {
        let mut vector=Vector{id:id.into(),requirements:vec![requirement.into()],source:format!("Wallet2fc5c383; actual cardano-balance-tx8975773 fee/witness-size/minimum-coin helpers and ledger decoder/getMinCoinTxOut; BalanceAdapter binary sha256:{ORACLE}; independent Rust integer/CBOR-length laws"),operation:operation.into(),input,expected:None,selection_invariants:false};
        let actual = adapter::invoke(binary, &[], &vector, Duration::from_secs(30))?;
        ensure!(
            actual == adapter::invoke(binary, &[], &vector, Duration::from_secs(30))?,
            "balance oracle replay differs: {id}"
        );
        if let Some(expected) = expected {
            ensure!(actual == expected, "balance boundary differs: {id}");
        } else {
            ensure!(
                actual.get("result").is_some(),
                "valid balance input rejected: {id}"
            );
        }
        validate(&vector, &actual)
            .with_context(|| format!("independent balance law failed: {id}"))?;
        vector.expected = Some(actual);
        vectors.push(vector);
        Ok(())
    };
    let base = json!({"transaction_bytes":100,"vkey_witnesses":0,"bootstrap_witnesses":0,"coefficient":44,"constant":155381,"maximum_transaction_bytes":16384,"execution_memory":0,"execution_steps":0,"memory_price":{"numerator":577,"denominator":10000},"step_price":{"numerator":721,"denominator":10000000}});
    for (id, changes) in [
        ("fee-linear-boundaries", json!({"transaction_bytes":0})),
        ("fee-linear-byte-one", json!({"transaction_bytes":1})),
        ("fee-linear-u32-max", json!({"transaction_bytes":u32::MAX})),
        (
            "fee-zero-coefficients",
            json!({"coefficient":0,"constant":0}),
        ),
        ("fee-witness-count", json!({"vkey_witnesses":1})),
        ("fee-witness-count-23", json!({"vkey_witnesses":23})),
        ("fee-witness-count-24", json!({"vkey_witnesses":24})),
        (
            "fee-bootstrap-witness-count",
            json!({"bootstrap_witnesses":1}),
        ),
        (
            "fee-mixed-many-witnesses",
            json!({"vkey_witnesses":64,"bootstrap_witnesses":64}),
        ),
        (
            "fee-execution-units",
            json!({"execution_memory":14000000,"execution_steps":10000000000u64}),
        ),
        (
            "fee-rounding",
            json!({"execution_memory":1,"execution_steps":1,"memory_price":{"numerator":1,"denominator":2},"step_price":{"numerator":1,"denominator":2}}),
        ),
        (
            "fee-rounding-up",
            json!({"execution_memory":1,"memory_price":{"numerator":1,"denominator":3}}),
        ),
        ("fee-maximum-size", json!({"transaction_bytes":16384})),
        ("fee-size-over-maximum", json!({"transaction_bytes":16385})),
        (
            "fee-size-with-witness-exact",
            json!({"transaction_bytes":16279,"vkey_witnesses":1}),
        ),
        (
            "fee-size-with-witness-over",
            json!({"transaction_bytes":16280,"vkey_witnesses":1}),
        ),
    ] {
        let mut input = base.clone();
        input
            .as_object_mut()
            .unwrap()
            .extend(changes.as_object().unwrap().clone());
        add(id, "tx.minimum-fee", "fee.components", input, None)?;
    }
    for (id, coin, assets, datum, script, cost) in [
        ("min-utxo-ada", 1000000, false, false, false, 4310),
        ("min-utxo-native-assets", 1000000, true, false, false, 4310),
        ("min-utxo-datum", 1000000, false, true, false, 4310),
        (
            "min-utxo-reference-script",
            1000000,
            false,
            false,
            true,
            4310,
        ),
        ("min-utxo-protocol-change", 1000000, true, true, true, 5000),
        ("min-utxo-combined", 1000000, true, true, true, 4310),
        ("min-utxo-zero-cost", 0, false, false, false, 0),
        ("min-utxo-zero-coin", 0, false, false, false, 4310),
        ("min-utxo-coin-23", 23, false, false, false, 4310),
        ("min-utxo-coin-24", 24, false, false, false, 4310),
        ("min-utxo-coin-255", 255, false, false, false, 4310),
        ("min-utxo-coin-256", 256, false, false, false, 4310),
        (
            "min-utxo-coin-maximum",
            45000000000000000,
            false,
            false,
            false,
            4310,
        ),
        ("min-utxo-at-minimum", 849070, false, false, false, 4310),
        ("min-utxo-below-minimum", 849069, false, false, false, 4310),
    ] {
        add(
            id,
            "tx.min-utxo",
            "minimum-utxo",
            json!({"output_cbor_hex":hex::encode(output(coin,assets,datum,script)?),"coins_per_byte":cost}),
            None,
        )?;
    }
    add(
        "min-utxo-malformed-rejected",
        "tx.min-utxo",
        "minimum-utxo",
        json!({"output_cbor_hex":"ff","coins_per_byte":4310}),
        Some(json!({"error":{"code":"decode_failed"}})),
    )?;
    Ok(vectors)
}
