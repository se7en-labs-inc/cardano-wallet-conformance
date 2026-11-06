//! Canonical partial transactions and actual collateral-return codec goldens.
use crate::{
    adapter::{self, Vector},
    ledger,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
const ORACLE: &str = "5f9ad0a56fba7f4c60854d7a763de8d38ea39b3b1a56050d2e9659663d94026c";
pub const DESTINATION: &str = "addr_test1vzz6hulv54gzf2suy2u5gkvmt6ysasfdlvvegy3fmf969yc2mg7gf";
fn output(e: &mut minicbor::Encoder<Vec<u8>>, address: &[u8], coin: u64) -> Result<()> {
    e.array(2)?.bytes(address)?.u64(coin)?;
    Ok(())
}
/// Flags1/2/4 specify existing collateral inputs/return/total; these are inputs, not supported balancing results.
pub fn partial(address: &str, ttl: u64, flags: u8, conway: bool) -> Result<Vec<u8>> {
    ensure!(flags < 8, "invalid collateral flags");
    let address = crate::encoding::bech32(address)?.1;
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4)?.map(4 + u64::from(flags.count_ones()))?.u8(0)?;
    if conway {
        e.tag(minicbor::data::Tag::new(258))?;
    }
    e.array(0)?.u8(1)?.array(1)?;
    output(&mut e, &address, 2_000_000)?;
    e.u8(2)?.u8(0)?.u8(3)?.u64(ttl)?;
    if flags & 1 != 0 {
        e.u8(13)?;
        if conway {
            e.tag(minicbor::data::Tag::new(258))?;
        }
        e.array(1)?.array(2)?.bytes(&[0x22; 32])?.u8(0)?;
    }
    if flags & 2 != 0 {
        e.u8(16)?;
        output(&mut e, &address, 1_000_000)?;
    }
    if flags & 4 != 0 {
        e.u8(17)?.u64(1_000_000)?;
    }
    e.map(0)?.bool(true)?.null()?;
    Ok(e.into_writer())
}
pub fn validate(vector: &Vector, actual: &Value) -> Result<()> {
    ledger::validate(vector, actual)?;
    let raw = hex::decode(
        actual
            .pointer("/result/cbor_hex")
            .and_then(Value::as_str)
            .context("missing collateral result")?,
    )?;
    let mut d = minicbor::Decoder::new(&raw);
    ensure!(d.array()? == Some(4), "wrong collateral envelope");
    let mut fields = 0u8;
    for _ in 0..d.map()?.context("indefinite body")? {
        match d.u64()? {
            13 => {
                fields |= 1;
                if d.datatype()? == minicbor::data::Type::Tag {
                    ensure!(d.tag()?.as_u64() == 258, "wrong set tag");
                }
                ensure!(
                    d.array()? == Some(1)
                        && d.array()? == Some(2)
                        && d.bytes()? == [0x22; 32]
                        && d.u64()? == 0,
                    "collateral input differs"
                );
            }
            16 => {
                fields |= 2;
                ensure!(
                    d.array()? == Some(2)
                        && d.bytes()? == crate::encoding::bech32(DESTINATION)?.1
                        && d.u64()? == 1_000_000,
                    "collateral return differs"
                );
            }
            17 => {
                fields |= 4;
                ensure!(d.u64()? == 1_000_000, "total collateral differs");
            }
            _ => {
                d.skip()?;
            }
        }
    }
    ensure!(
        Some(u64::from(fields)) == vector.input["collateral_flags"].as_u64(),
        "collateral field presence differs"
    );
    Ok(())
}
pub fn capture(binary: &Path) -> Result<Vec<Vector>> {
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(binary)?)) == ORACLE,
        "ledger oracle differs"
    );
    let mut vectors = Vec::new();
    for (era, flags) in ["babbage", "conway"]
        .into_iter()
        .flat_map(|era| [1, 2, 4, 6, 7].into_iter().map(move |flags| (era, flags)))
        .chain(std::iter::once(("conway", 0)))
    {
        let id = if flags == 0 {
            "balance-partial-conway".into()
        } else {
            format!("collateral-codec-{era}-{flags}")
        };
        let mut v=Vector{id,requirements:vec![if flags==0{"tx.serialization".into()}else{"tx.collateral".into()}],source:format!("Wallet2fc5c383 actual wallet-read LedgerAdapter binary sha256:{ORACLE}; canonical partial/collateral field inputs; independent CBOR fields13/16/17 and original body hash; not successful collateral-return balancing or node admission"),operation:"transaction.roundtrip".into(),input:json!({"era":era,"collateral_flags":flags,"cbor_hex":hex::encode(partial(DESTINATION,6_000_000,flags,era=="conway")?)}),expected:None,selection_invariants:false};
        let actual = adapter::invoke(binary, &[], &v, Duration::from_secs(30))?;
        ensure!(
            actual == adapter::invoke(binary, &[], &v, Duration::from_secs(30))?,
            "collateral codec replay differs"
        );
        ledger::validate(&v, &actual)?;
        if flags != 0 {
            validate(&v, &actual)?;
        }
        ensure!(
            actual.get("result").is_some(),
            "wallet rejected partial transaction fixture"
        );
        v.expected = Some(actual);
        vectors.push(v);
    }
    Ok(vectors)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_return_fields_reject_changed_totals_and_missing_return() {
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../fixtures/vectors/balancing-profiles.json"))
                .unwrap();
        assert_eq!(vectors.len(), 11);
        for v in vectors.iter().filter(|v| v.input["collateral_flags"] == 7) {
            validate(v, v.expected.as_ref().unwrap()).unwrap();
            let mut changed = v.expected.clone().unwrap();
            let mut raw = hex::decode(changed["result"]["cbor_hex"].as_str().unwrap()).unwrap();
            let last = raw.len() - 4;
            raw[last] ^= 1;
            changed["result"]["transaction_id"] = json!(ledger::transaction_id(&raw).unwrap());
            changed["result"]["cbor_hex"] = json!(hex::encode(&raw));
            let mut altered = v.clone();
            altered.input["cbor_hex"] = json!(hex::encode(raw));
            assert!(ledger::validate(&altered, &changed).is_ok());
            assert!(validate(&altered, &changed).is_err());
            let raw = partial(DESTINATION, 6_000_000, 5, v.input["era"] == "conway").unwrap();
            altered.input["cbor_hex"] = json!(hex::encode(&raw));
            changed["result"]["cbor_hex"] = json!(hex::encode(&raw));
            changed["result"]["transaction_id"] = json!(ledger::transaction_id(&raw).unwrap());
            assert!(ledger::validate(&altered, &changed).is_ok());
            assert!(validate(&altered, &changed).is_err());
        }
        let base = partial(DESTINATION, 6_000_000, 0, true).unwrap();
        assert!(base.len() < partial(DESTINATION, 6_000_000, 7, true).unwrap().len());
    }
}
