//! Independent inspection of Shelley-family transaction CBOR and ledger witnesses.
//! The transaction body is hashed as received, never reconstructed by the candidate.
use anyhow::{ensure, Context, Result};
use base64::Engine;
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::{data::Type, Decoder};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub struct Output {
    pub address_hex: String,
    pub coin: u64,
    pub assets: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
pub struct Transaction {
    pub id: String,
    pub fee: u64,
    pub inputs: Vec<String>,
    pub outputs: Vec<Output>,
    pub verification_keys: Vec<String>,
}

pub fn blake2b(bytes: &[u8], length: usize) -> Result<Vec<u8>> {
    let mut hash = Blake2bVar::new(length)?;
    hash.update(bytes);
    let mut digest = vec![0; length];
    hash.finalize_variable(&mut digest)
        .map_err(|_| anyhow::anyhow!("invalid digest length"))?;
    Ok(digest)
}

fn array(d: &mut Decoder<'_>) -> Result<u64> {
    d.array()?
        .context("indefinite arrays are unsupported in this inspection profile")
}
fn map(d: &mut Decoder<'_>) -> Result<u64> {
    d.map()?
        .context("indefinite maps are unsupported in this inspection profile")
}
fn set_tag(d: &mut Decoder<'_>) -> Result<()> {
    if d.datatype()? == Type::Tag {
        ensure!(d.tag()?.as_u64() == 258, "unexpected CBOR set tag");
    }
    Ok(())
}

fn spending_inputs(d: &mut Decoder<'_>) -> Result<Vec<String>> {
    set_tag(d)?;
    let length = d.array()?;
    let mut inputs = Vec::new();
    let mut unique = BTreeSet::new();
    loop {
        if let Some(length) = length {
            if inputs.len() as u64 == length {
                break;
            }
        } else if d.datatype()? == Type::Break {
            d.skip()?;
            break;
        }
        ensure!(array(d)? == 2, "invalid transaction input");
        let txid = d.bytes()?;
        ensure!(txid.len() == 32, "invalid input transaction hash");
        let id = format!("{}#{}", hex::encode(txid), d.u64()?);
        ensure!(unique.insert(id.clone()), "duplicate transaction input");
        inputs.push(id);
    }
    Ok(inputs)
}

fn value(d: &mut Decoder<'_>) -> Result<(u64, BTreeMap<String, u64>)> {
    if d.datatype()? != Type::Array {
        return Ok((d.u64()?, BTreeMap::new()));
    }
    ensure!(array(d)? == 2, "invalid multiasset value tuple");
    let coin = d.u64()?;
    let mut assets = BTreeMap::new();
    let mut policies = BTreeSet::new();
    for _ in 0..map(d)? {
        let policy = d.bytes()?;
        ensure!(
            policy.len() == 28 && policies.insert(policy.to_vec()),
            "invalid or duplicate policy ID"
        );
        for _ in 0..map(d)? {
            let name = d.bytes()?;
            ensure!(name.len() <= 32, "asset name exceeds 32 bytes");
            let id = format!("{}.{}", hex::encode(policy), hex::encode(name));
            ensure!(assets.insert(id, d.u64()?).is_none(), "duplicate asset");
        }
    }
    Ok((coin, assets))
}

fn output(d: &mut Decoder<'_>) -> Result<Output> {
    let (mut address, mut amount) = (None, None);
    if d.datatype()? == Type::Map {
        let mut seen = BTreeSet::new();
        for _ in 0..map(d)? {
            let key = d.u64()?;
            ensure!(seen.insert(key), "duplicate output map key");
            match key {
                0 => address = Some(d.bytes()?.to_vec()),
                1 => amount = Some(value(d)?),
                _ => d.skip()?,
            }
        }
    } else {
        let size = array(d)?;
        ensure!((2..=3).contains(&size), "invalid output tuple");
        address = Some(d.bytes()?.to_vec());
        amount = Some(value(d)?);
        if size == 3 {
            d.skip()?;
        }
    }
    let address = address.context("output has no address")?;
    let (coin, assets) = amount.context("output has no value")?;
    ensure!(!address.is_empty(), "empty output address");
    Ok(Output {
        address_hex: hex::encode(address),
        coin,
        assets,
    })
}

/// Parse Shelley-family transaction CBOR (including canonical indefinite input sets) and verify
/// every vkey/bootstrap signature over the exact Blake2b-256 body hash.
/// A successful real-node submission is still required to validate ledger rules.
pub fn inspect(encoded: &str, require_witnesses: bool) -> Result<Transaction> {
    let bytes = if encoded.len().is_multiple_of(2) && encoded.bytes().all(|b| b.is_ascii_hexdigit())
    {
        hex::decode(encoded)?
    } else {
        base64::engine::general_purpose::STANDARD.decode(encoded)?
    };
    let mut d = Decoder::new(&bytes);
    let top = array(&mut d)?;
    ensure!((3..=4).contains(&top), "invalid transaction tuple length");
    let body_start = d.position();
    let mut body = d.clone();
    d.skip()?;
    let body_end = d.position();
    let hash = blake2b(&bytes[body_start..body_end], 32)?;
    let (mut fee, mut inputs, mut outputs) = (None, None, None);
    let mut seen = BTreeSet::new();
    for _ in 0..map(&mut body)? {
        let key = body.u64()?;
        ensure!(seen.insert(key), "duplicate transaction body key");
        match key {
            0 => {
                inputs = Some(spending_inputs(&mut body)?);
            }
            1 => {
                let mut xs = Vec::new();
                for _ in 0..array(&mut body)? {
                    xs.push(output(&mut body)?);
                }
                outputs = Some(xs);
            }
            2 => fee = Some(body.u64()?),
            _ => body.skip()?,
        }
    }
    ensure!(body.position() == body_end, "unexpected body encoding");
    let mut verification_keys = Vec::new();
    let mut witness_keys = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for _ in 0..map(&mut d)? {
        let key = d.u64()?;
        ensure!(seen.insert(key), "duplicate witness-set key");
        if key != 0 && key != 2 {
            d.skip()?;
            continue;
        }
        set_tag(&mut d)?;
        for _ in 0..array(&mut d)? {
            ensure!(
                array(&mut d)? == if key == 0 { 2 } else { 4 },
                "invalid witness tuple"
            );
            let public: [u8; 32] = d
                .bytes()?
                .try_into()
                .context("invalid witness public key length")?;
            let signature = Signature::from_slice(d.bytes()?)?;
            VerifyingKey::from_bytes(&public)?
                .verify_strict(&hash, &signature)
                .context("invalid transaction signature")?;
            ensure!(
                witness_keys.insert((key, public)),
                "duplicate witness public key"
            );
            verification_keys.push(hex::encode(public));
            if key == 2 {
                ensure!(d.bytes()?.len() == 32, "invalid bootstrap chain code");
                d.bytes()?;
            }
        }
    }
    for _ in 2..top {
        d.skip()?;
    }
    ensure!(
        d.position() == bytes.len(),
        "trailing transaction CBOR data"
    );
    ensure!(
        !require_witnesses || !verification_keys.is_empty(),
        "signed transaction has no verification-key witnesses"
    );
    Ok(Transaction {
        id: hex::encode(hash),
        fee: fee.context("missing transaction fee")?,
        inputs: inputs.context("missing transaction inputs")?,
        outputs: outputs.context("missing transaction outputs")?,
        verification_keys,
    })
}

/// Extract exact certificate bytes after validating the full transaction envelope.
pub fn certificates(encoded: &str) -> Result<Vec<String>> {
    inspect(encoded, false)?;
    let raw = if encoded.len().is_multiple_of(2) && encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(encoded)?
    } else {
        base64::engine::general_purpose::STANDARD.decode(encoded)?
    };
    let mut d = Decoder::new(&raw);
    array(&mut d)?;
    let mut certificates = Vec::new();
    for _ in 0..map(&mut d)? {
        if d.u64()? == 4 {
            set_tag(&mut d)?;
            for _ in 0..array(&mut d)? {
                let start = d.position();
                d.skip()?;
                certificates.push(hex::encode(&raw[start..d.position()]));
            }
        } else {
            d.skip()?;
        }
    }
    Ok(certificates)
}

/// Read exact reward-address/quantity pairs after validating the full envelope.
pub fn withdrawals(encoded: &str) -> Result<BTreeMap<String, u64>> {
    inspect(encoded, false)?;
    let raw = if encoded.len().is_multiple_of(2) && encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(encoded)?
    } else {
        base64::engine::general_purpose::STANDARD.decode(encoded)?
    };
    let mut d = Decoder::new(&raw);
    array(&mut d)?;
    let mut withdrawals = BTreeMap::new();
    for _ in 0..map(&mut d)? {
        if d.u64()? == 5 {
            for _ in 0..map(&mut d)? {
                let address = d.bytes()?;
                ensure!(
                    address.len() == 29 && [14, 15].contains(&(address[0] >> 4)),
                    "invalid reward address credential/length"
                );
                ensure!(
                    withdrawals.insert(hex::encode(address), d.u64()?).is_none(),
                    "duplicate withdrawal reward address"
                );
            }
        } else {
            d.skip()?;
        }
    }
    Ok(withdrawals)
}

/// Read exact lower/upper bounds after validating the transaction and its witnesses.
pub fn validity(encoded: &str) -> Result<(Option<u64>, Option<u64>)> {
    inspect(encoded, false)?;
    let raw = if encoded.len().is_multiple_of(2) && encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(encoded)?
    } else {
        base64::engine::general_purpose::STANDARD.decode(encoded)?
    };
    let mut d = Decoder::new(&raw);
    array(&mut d)?;
    let (mut lower, mut upper) = (None, None);
    for _ in 0..map(&mut d)? {
        match d.u64()? {
            3 => upper = Some(d.u64()?),
            8 => lower = Some(d.u64()?),
            _ => d.skip()?,
        }
    }
    Ok((lower, upper))
}

/// Read the exact signed mint/burn map from the original CBOR body.
pub fn mint_quantities(encoded: &str) -> Result<BTreeMap<String, i64>> {
    let raw = if encoded.len().is_multiple_of(2) && encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(encoded)?
    } else {
        base64::engine::general_purpose::STANDARD.decode(encoded)?
    };
    let mut d = Decoder::new(&raw);
    ensure!(array(&mut d)? == 4, "invalid Conway envelope");
    let mut result = BTreeMap::new();
    let mut found = false;
    for _ in 0..map(&mut d)? {
        if d.u64()? != 9 {
            d.skip()?;
            continue;
        }
        ensure!(!found, "duplicate mint map");
        found = true;
        for _ in 0..map(&mut d)? {
            let policy = d.bytes()?;
            ensure!(policy.len() == 28, "invalid mint policy length");
            for _ in 0..map(&mut d)? {
                let name = d.bytes()?;
                ensure!(name.len() <= 32, "mint name exceeds bound");
                let quantity = d.i64()?;
                ensure!(
                    quantity != 0
                        && result
                            .insert(
                                format!("{}.{}", hex::encode(policy), hex::encode(name)),
                                quantity
                            )
                            .is_none(),
                    "zero or duplicate mint asset"
                );
            }
        }
    }
    for _ in 0..3 {
        d.skip()?;
    }
    ensure!(d.position() == raw.len(), "trailing mint transaction bytes");
    Ok(result)
}

#[cfg(test)]
mod input_set_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn encoded_set(indefinite: bool) -> Vec<u8> {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.tag(minicbor::data::Tag::new(258)).unwrap();
        if indefinite {
            e.begin_array().unwrap();
        } else {
            e.array(24).unwrap();
        }
        for index in 0..24 {
            e.array(2)
                .unwrap()
                .bytes(&[index; 32])
                .unwrap()
                .u64(0)
                .unwrap();
        }
        if indefinite {
            e.end().unwrap();
        }
        e.into_writer()
    }
    fn signed(set: &[u8]) -> (String, String) {
        let mut body = vec![0xa3, 0];
        body.extend_from_slice(set);
        body.extend_from_slice(&[1, 0x80, 2, 1]);
        let hash = blake2b(&body, 32).unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let signature = key.sign(&hash);
        let mut witnesses = minicbor::Encoder::new(Vec::new());
        witnesses
            .map(1)
            .unwrap()
            .u8(0)
            .unwrap()
            .array(1)
            .unwrap()
            .array(2)
            .unwrap()
            .bytes(key.verifying_key().as_bytes())
            .unwrap()
            .bytes(&signature.to_bytes())
            .unwrap();
        let mut tx = vec![0x84];
        tx.extend(body);
        tx.extend(witnesses.into_writer());
        tx.extend([0xf5, 0xf6]);
        (hex::encode(tx), hex::encode(hash))
    }
    #[test]
    fn input_set_framing_preserves_raw_body_hash_and_real_signature() {
        let (definite, definite_hash) = signed(&encoded_set(false));
        let (indefinite, indefinite_hash) = signed(&encoded_set(true));
        let a = inspect(&definite, true).unwrap();
        let b = inspect(&indefinite, true).unwrap();
        assert_eq!(a.inputs, b.inputs);
        assert_eq!(a.inputs.len(), 24);
        assert_eq!(a.id, definite_hash);
        assert_eq!(b.id, indefinite_hash);
        assert_ne!(a.id, b.id);
        assert_eq!(a.verification_keys, b.verification_keys);
        // Reframing without re-signing must fail: the original body bytes are authoritative.
        let mut tampered = hex::decode(&definite).unwrap();
        let body_end = 1 + 2 + encoded_set(false).len() + 4;
        tampered.splice(3..body_end - 4, encoded_set(true));
        assert!(inspect(&hex::encode(tampered), true).is_err());
        assert!(inspect(&(indefinite + "00"), true).is_err());
    }
    #[test]
    fn input_set_rejects_duplicates_missing_break_and_malformed_tuples() {
        let valid = encoded_set(true);
        let mut missing_break = valid.clone();
        missing_break.pop();
        assert!(spending_inputs(&mut Decoder::new(&missing_break)).is_err());
        let mut duplicate = valid.clone();
        duplicate.splice(
            duplicate.len() - 1..duplicate.len() - 1,
            valid[4..40].iter().copied(),
        );
        assert!(spending_inputs(&mut Decoder::new(&duplicate)).is_err());
        for invalid in [
            vec![0x9f, 0x82, 0x58, 0x20],
            vec![0x9f, 0x9f, 0xff, 0xff],
            vec![0x9f, 0x81, 0xff],
            vec![0x9f, 0x82, 0x41, 0, 0, 0xff],
            vec![0x9f, 0x82, 0x58, 0x20, 0xff],
        ] {
            assert!(spending_inputs(&mut Decoder::new(&invalid)).is_err());
        }
    }
}
