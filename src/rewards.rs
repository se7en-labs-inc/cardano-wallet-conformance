//! Actual ledger withdrawal codecs with independent signatures and reward accounting.
use crate::{
    adapter::{self, Vector},
    encoding, ledger, node, transaction,
};
use anyhow::{ensure, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};
const ORACLE: &str = "5f9ad0a56fba7f4c60854d7a763de8d38ea39b3b1a56050d2e9659663d94026c";
fn text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .context("reward profile string missing")
}
fn number(value: &Value, pointer: &str) -> Result<u64> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .context("reward profile quantity missing")
}
fn decode(encoded: &str) -> Result<Vec<u8>> {
    if encoded.len().is_multiple_of(2) && encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(hex::decode(encoded)?)
    } else {
        Ok(base64::engine::general_purpose::STANDARD.decode(encoded)?)
    }
}
pub fn validate(vector: &Vector, actual: &Value) -> Result<()> {
    ledger::validate(vector, actual)?;
    let context = &vector.input["reward_context"];
    let encoded = text(actual, "/result/cbor_hex")?;
    let tx = transaction::inspect(encoded, false)?;
    ensure!(
        tx.id == text(context, "/transaction_id")?,
        "withdrawal differs from independent node transaction hash"
    );
    let stake = encoding::bech32(text(context, "/withdrawal/stake_address")?)?.1;
    ensure!(
        stake.len() == 29 && stake[0] == 0xe0,
        "withdrawal control needs exact testnet key credential"
    );
    let quantity = number(context, "/withdrawal/coin")?;
    ensure!(
        quantity > 0
            && transaction::withdrawals(encoded)?
                == BTreeMap::from([(hex::encode(&stake), quantity)]),
        "exact withdrawal reward address/quantity differs"
    );
    let input = text(context, "/input/reference")?;
    ensure!(
        tx.inputs == [input] && tx.fee == number(context, "/fee")? && tx.fee > 0,
        "withdrawal input or fee differs"
    );
    ensure!(
        transaction::certificates(encoded)?.is_empty(),
        "unexpected certificate in withdrawal-only control"
    );
    let output = encoding::bech32(text(context, "/output/address")?)?.1;
    ensure!(
        tx.outputs.len() == 1
            && tx.outputs[0].address_hex == hex::encode(&output)
            && tx.outputs[0].coin == number(context, "/output/coin")?
            && tx.outputs[0].assets.is_empty(),
        "withdrawal change/assets differ"
    );
    ensure!(
        u128::from(number(context, "/input/coin")?) + u128::from(quantity)
            == u128::from(tx.outputs[0].coin) + u128::from(tx.fee),
        "withdrawal does not conserve ADA"
    );
    let witnesses = number(context, "/witnesses")?;
    ensure!(
        tx.verification_keys.len() as u64 == witnesses && [0, 2].contains(&witnesses),
        "withdrawal witness count differs"
    );
    let payment = encoding::bech32(text(context, "/input/address")?)?.1;
    ensure!(
        payment.len() == 57
            && payment[0] == 0
            && payment[29..] == stake[1..]
            && output.len() == 57
            && output[0] == 0
            && output[29..] == stake[1..],
        "withdrawal input/change delegation ownership differs"
    );
    if witnesses == 2 {
        let hashes: BTreeSet<_> = tx
            .verification_keys
            .iter()
            .map(|key| transaction::blake2b(&hex::decode(key)?, 28))
            .collect::<Result<_>>()?;
        ensure!(
            hashes == BTreeSet::from([payment[1..29].to_vec(), stake[1..].to_vec()]),
            "withdrawal payment/stake witnesses differ from actual credentials"
        );
    }
    Ok(())
}

pub fn capture(binary: &Path, audit: &Path) -> Result<Vec<Vector>> {
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(binary)?)) == ORACLE,
        "ledger oracle differs"
    );
    let read = |name: &str| -> Result<Value> {
        Ok(serde_json::from_slice(&std::fs::read(audit.join(name))?)?)
    };
    let confirmed = read("withdrawal-confirmed.json")?;
    let node_before = read("node-before-withdrawal.json")?;
    let node_outputs = read("withdrawal-node-utxos.json")?;
    let txid = text(&confirmed, "/id")?;
    let output_address = text(&confirmed, "/outputs/0/address")?;
    let output_coin = number(&confirmed, "/outputs/0/amount/quantity")?;
    node::validate_payment(&node_outputs, txid, output_address, output_coin)?;
    ensure!(
        confirmed["status"] == "in_ledger"
            && confirmed["inputs"].as_array().is_some_and(|a| a.len() == 1)
            && confirmed["outputs"]
                .as_array()
                .is_some_and(|a| a.len() == 1)
            && confirmed["withdrawals"]
                .as_array()
                .is_some_and(|a| a.len() == 1)
            && confirmed["deposit_taken"]["quantity"] == 0
            && confirmed["deposit_returned"]["quantity"] == 0,
        "audit is not the independently confirmed single withdrawal control"
    );
    let stake_address = text(&confirmed, "/withdrawals/0/stake_address")?;
    let withdrawal = number(&confirmed, "/withdrawals/0/amount/quantity")?;
    ensure!(
        node_before[0]["address"] == stake_address
            && node_before[0]["rewardAccountBalance"] == withdrawal,
        "withdrawal does not match original node reward snapshot"
    );
    let mut audit_hashes = serde_json::Map::new();
    for name in [
        "construct.json",
        "sign.json",
        "withdrawal-confirmed.json",
        "node-before-withdrawal.json",
        "withdrawal-node-utxos.json",
    ] {
        audit_hashes.insert(
            name.into(),
            json!(hex::encode(Sha256::digest(std::fs::read(
                audit.join(name)
            )?))),
        );
    }
    let mut context = json!({"transaction_id":txid,"fee":number(&confirmed,"/fee/quantity")?,
        "input":{"reference":format!("{}#{}",text(&confirmed,"/inputs/0/id")?,number(&confirmed,"/inputs/0/index")?),
            "address":text(&confirmed,"/inputs/0/address")?,"coin":number(&confirmed,"/inputs/0/amount/quantity")?},
        "withdrawal":{"stake_address":stake_address,"coin":withdrawal},
        "output":{"address":output_address,"coin":output_coin},"audit_sha256":audit_hashes});
    let mut vectors = Vec::new();
    for (name, witnesses) in [("construct.json", 0), ("sign.json", 2)] {
        let response = read(name)?;
        let raw = decode(text(&response, "/transaction")?)?;
        context["witnesses"] = json!(witnesses);
        let mut vector=Vector{id:format!("reward-withdrawal-{}",if witnesses==0{"unsigned"}else{"signed"}),
            requirements:vec!["tx.delegation".into()],source:format!("Actual Conway withdrawal observed in public reference-reward-audit; unchanged wallet-read LedgerAdapter sha256:{ORACLE}; independently node-confirmed body hash, original reward snapshot, payment/stake Ed25519 witnesses and exact ADA conservation; component-only, no replacement for live withdrawal"),
            operation:"transaction.roundtrip".into(),input:json!({"era":"conway","cbor_hex":hex::encode(raw),"reward_context":context}),
            expected:None,selection_invariants:false};
        let actual = adapter::invoke(binary, &[], &vector, Duration::from_secs(30))?;
        ensure!(
            actual == adapter::invoke(binary, &[], &vector, Duration::from_secs(30))?,
            "withdrawal codec replay differs"
        );
        validate(&vector, &actual)?;
        vector.expected = Some(actual);
        vectors.push(vector);
    }
    Ok(vectors)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vectors() -> Vec<Vector> {
        serde_json::from_str(include_str!("../fixtures/vectors/reward-profiles.json")).unwrap()
    }
    fn alter(vector: &Vector, change: impl FnOnce(&mut [u8], usize, usize)) -> (Vector, Value) {
        let mut vector = vector.clone();
        let mut raw = hex::decode(vector.input["cbor_hex"].as_str().unwrap()).unwrap();
        let (mut address, mut quantity) = (None, None);
        let mut d = minicbor::Decoder::new(&raw);
        d.array().unwrap();
        for _ in 0..d.map().unwrap().unwrap() {
            if d.u64().unwrap() == 5 {
                assert_eq!(d.map().unwrap(), Some(1));
                let length = d.bytes().unwrap().len();
                address = Some(d.position() - length);
                quantity = Some(d.position());
                d.u64().unwrap();
            } else {
                d.skip().unwrap();
            }
        }
        change(&mut raw, address.unwrap(), quantity.unwrap());
        let txid = ledger::transaction_id(&raw).unwrap();
        vector.input["cbor_hex"] = json!(hex::encode(&raw));
        vector.input["reward_context"]["transaction_id"] = json!(txid);
        let actual = json!({"result":{"cbor_hex":hex::encode(raw),"transaction_id":txid}});
        ledger::validate(&vector, &actual).unwrap();
        (vector, actual)
    }
    #[test]
    fn actual_unsigned_and_signed_withdrawals_match_node_hash_and_witnesses() {
        let vectors = vectors();
        assert_eq!(vectors.len(), 2);
        for vector in &vectors {
            validate(vector, vector.expected.as_ref().unwrap()).unwrap();
        }
        assert_eq!(
            vectors[0].expected.as_ref().unwrap()["result"]["transaction_id"],
            vectors[1].expected.as_ref().unwrap()["result"]["transaction_id"]
        );
    }
    #[test]
    fn recomputed_codec_hashes_do_not_hide_changed_reward_maps_or_conservation() {
        let vector = &vectors()[0];
        let (mut changed, actual) = alter(vector, |raw, _, quantity| {
            // Original actual amount uses a nine-byte CBOR uint64.
            assert_eq!(raw[quantity], 0x1b);
            raw[quantity + 8] ^= 1;
        });
        assert!(validate(&changed, &actual).is_err());
        let amount = *transaction::withdrawals(actual["result"]["cbor_hex"].as_str().unwrap())
            .unwrap()
            .values()
            .next()
            .unwrap();
        changed.input["reward_context"]["withdrawal"]["coin"] = json!(amount);
        assert!(
            validate(&changed, &actual).is_err(),
            "matched mutated map must still fail conservation"
        );
        let (changed, actual) = alter(vector, |raw, address, _| raw[address + 28] ^= 1);
        assert!(validate(&changed, &actual).is_err());
    }
    #[test]
    fn codec_roundtrip_does_not_validate_a_corrupted_stake_signature() {
        let signed = &vectors()[1];
        let (changed, actual) = alter(signed, |raw, _, _| {
            let length = raw.len();
            raw[length - 4] ^= 1;
        });
        assert!(validate(&changed, &actual).is_err());
        let mut changed = signed.clone();
        changed.input["reward_context"]["witnesses"] = json!(0);
        assert!(validate(&changed, signed.expected.as_ref().unwrap()).is_err());
    }
    fn envelope(entries: &[(Vec<u8>, i64)]) -> String {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .map(4)
            .unwrap()
            .u8(0)
            .unwrap()
            .array(0)
            .unwrap()
            .u8(1)
            .unwrap()
            .array(0)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(0)
            .unwrap()
            .u8(5)
            .unwrap()
            .map(entries.len() as u64)
            .unwrap();
        for (address, amount) in entries {
            e.bytes(address).unwrap().i64(*amount).unwrap();
        }
        e.map(0).unwrap().bool(true).unwrap().null().unwrap();
        hex::encode(e.into_writer())
    }
    #[test]
    fn withdrawal_parser_rejects_duplicate_credentials_wrong_headers_and_negative_amounts() {
        let address = [vec![0xe0], vec![0; 28]].concat();
        assert_eq!(
            transaction::withdrawals(&envelope(&[(address.clone(), 1)])).unwrap(),
            BTreeMap::from([(hex::encode(&address), 1)])
        );
        assert!(
            transaction::withdrawals(&envelope(&[(address.clone(), 1), (address.clone(), 2)]))
                .is_err()
        );
        assert!(transaction::withdrawals(&envelope(&[(address.clone(), -1)])).is_err());
        assert!(transaction::withdrawals(&envelope(&[(vec![0xe0; 28], 1)])).is_err());
        let mut invalid = address;
        invalid[0] = 0xb0;
        assert!(transaction::withdrawals(&envelope(&[(invalid, 1)])).is_err());
    }
}
