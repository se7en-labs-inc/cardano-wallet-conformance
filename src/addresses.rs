//! Independent address/script byte laws and pinned Haskell component capture.
use crate::{
    adapter::{self, Vector},
    encoding, transaction,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
const ORACLE: &str = "f751ef54b76bf04781eed6ca96c7fb59b03f1e9ed8770fc9320776005ccc6147";
fn bytes(value: &Value, field: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(
        value[field].as_str().context("missing bytes")?,
    )?)
}

fn encode_script(script: &Value, encoder: &mut minicbor::Encoder<Vec<u8>>) -> Result<()> {
    match script["type"]
        .as_str()
        .context("missing native script type")?
    {
        "signature" => {
            encoder
                .array(2)?
                .u8(0)?
                .bytes(&bytes(script, "key_hash_hex")?)?;
        }
        "all" | "any" => {
            let children = script["scripts"]
                .as_array()
                .context("missing script children")?;
            encoder
                .array(2)?
                .u8(if script["type"] == "all" { 1 } else { 2 })?
                .array(children.len() as u64)?;
            for child in children {
                encode_script(child, encoder)?;
            }
        }
        "at_least" => {
            let children = script["scripts"]
                .as_array()
                .context("missing script children")?;
            encoder
                .array(3)?
                .u8(3)?
                .u64(script["required"].as_u64().context("missing threshold")?)?
                .array(children.len() as u64)?;
            for child in children {
                encode_script(child, encoder)?;
            }
        }
        "before" | "after" => {
            encoder
                .array(2)?
                .u8(if script["type"] == "before" { 5 } else { 4 })?
                .u64(script["slot"].as_u64().context("missing script slot")?)?;
        }
        _ => anyhow::bail!("unknown native script kind"),
    }
    Ok(())
}
pub fn script_bytes(script: &Value) -> Result<Vec<u8>> {
    let mut encoder = minicbor::Encoder::new(vec![0]);
    encode_script(script, &mut encoder)?;
    Ok(encoder.into_writer())
}
fn satisfied(script: &Value, input: &Value) -> Result<bool> {
    let children = || -> Result<&Vec<Value>> {
        script["scripts"]
            .as_array()
            .context("missing script children")
    };
    Ok(
        match script["type"].as_str().context("missing script kind")? {
            "signature" => input["signers"]
                .as_array()
                .context("missing signers")?
                .contains(&script["key_hash_hex"]),
            "all" => children()?
                .iter()
                .map(|s| satisfied(s, input))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .all(|b| b),
            "any" => children()?
                .iter()
                .map(|s| satisfied(s, input))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .any(|b| b),
            "at_least" => {
                children()?
                    .iter()
                    .map(|s| satisfied(s, input))
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .filter(|b| *b)
                    .count() as u64
                    >= script["required"].as_u64().context("missing threshold")?
            }
            "before" => input["invalid_hereafter"]
                .as_u64()
                .is_some_and(|upper| upper <= script["slot"].as_u64().unwrap()),
            "after" => input["invalid_before"]
                .as_u64()
                .is_some_and(|lower| lower >= script["slot"].as_u64().unwrap()),
            _ => anyhow::bail!("unknown native script kind"),
        },
    )
}
fn credential(value: &Value) -> Result<(bool, Vec<u8>)> {
    if value["type"] == "key" {
        let hash = bytes(value, "hash_hex")?;
        ensure!(hash.len() == 28, "invalid credential hash length");
        Ok((false, hash))
    } else {
        ensure!(value["type"] == "script", "invalid credential kind");
        Ok((
            true,
            transaction::blake2b(&script_bytes(&value["script"])?, 28)?,
        ))
    }
}
fn variable(value: u64) -> Vec<u8> {
    let mut n = value;
    let mut groups = vec![(n & 127) as u8];
    n >>= 7;
    while n > 0 {
        groups.push(((n & 127) as u8) | 128);
        n >>= 7;
    }
    groups.into_iter().rev().collect()
}
pub fn expected_address(input: &Value) -> Result<Vec<u8>> {
    let network = input["network_tag"]
        .as_u64()
        .context("missing network tag")?;
    ensure!(network < 16, "invalid network tag");
    let mut address = vec![network as u8];
    match input["kind"].as_str().context("missing address kind")? {
        "base" => {
            let (p, payment) = credential(&input["payment"])?;
            let (s, stake) = credential(&input["stake"])?;
            address[0] |= ((p as u8) + 2 * (s as u8)) << 4;
            address.extend(payment);
            address.extend(stake);
        }
        "enterprise" => {
            let (script, payment) = credential(&input["payment"])?;
            address[0] |= (6 + script as u8) << 4;
            address.extend(payment);
        }
        "reward" => {
            let (script, stake) = credential(&input["stake"])?;
            address[0] |= (14 + script as u8) << 4;
            address.extend(stake);
        }
        "pointer" => {
            let (script, payment) = credential(&input["payment"])?;
            address[0] |= (4 + script as u8) << 4;
            address.extend(payment);
            for field in ["slot", "transaction_index", "output_index"] {
                address.extend(variable(
                    input[field].as_u64().context("invalid pointer value")?,
                ));
            }
        }
        _ => anyhow::bail!("unknown address kind"),
    }
    Ok(address)
}
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 == 1 { 0xedb88320 } else { 0 };
        }
    }
    !crc
}
fn validate_byron(raw: &[u8], input: &Value) -> Result<()> {
    let mut envelope = minicbor::Decoder::new(raw);
    ensure!(
        envelope.array()? == Some(2) && envelope.tag()?.as_u64() == 24,
        "invalid Byron envelope"
    );
    let payload = envelope.bytes()?;
    let checksum = envelope.u32()?;
    ensure!(
        checksum == crc32(payload) && envelope.position() == raw.len(),
        "Byron CRC or trailing bytes mismatch"
    );
    let mut body = minicbor::Decoder::new(payload);
    ensure!(
        body.array()? == Some(3) && body.bytes()?.len() == 28,
        "invalid Byron payload root"
    );
    let attributes = body.map()?.context("indefinite Byron attributes")?;
    let (mut magic, mut path) = (None, false);
    for _ in 0..attributes {
        let tag = body.u8()?;
        let bytes = body.bytes()?;
        match tag {
            1 => path = true,
            2 => {
                let mut d = minicbor::Decoder::new(bytes);
                magic = Some(d.u64()?);
                ensure!(d.position() == bytes.len(), "trailing protocol magic");
            }
            _ => anyhow::bail!("unexpected Byron attribute"),
        }
    }
    ensure!(
        body.u8()? == 0 && body.position() == payload.len(),
        "invalid Byron address type"
    );
    ensure!(
        magic
            == if input["network"] == "mainnet" {
                None
            } else {
                Some(1)
            },
        "Byron network magic mismatch"
    );
    ensure!(
        path == (input["style"] == "Byron"),
        "Byron derivation-path attribute mismatch"
    );
    Ok(())
}

pub fn validate(vector: &Vector, actual: &Value) -> Result<()> {
    let Some(result) = actual.get("result") else {
        return Ok(());
    };
    let input = &vector.input;
    match vector.operation.as_str() {
        "native.script" => {
            let raw = script_bytes(&input["script"])?;
            ensure!(
                result["cbor_hex"] == hex::encode(&raw)
                    && result["hash_hex"] == hex::encode(transaction::blake2b(&raw, 28)?),
                "native script bytes/hash mismatch"
            );
            ensure!(
                result["satisfied"] == satisfied(&input["script"], input)?,
                "ledger native-script evaluation differs from independent truth conditions"
            );
        }
        "address.build" => {
            let expected = expected_address(input)?;
            let (hrp, raw) =
                encoding::bech32(result["address"].as_str().context("missing address")?)?;
            let prefix = if input["kind"] == "reward" {
                "stake"
            } else {
                "addr"
            };
            let expected_hrp = if input["network_tag"] == 1 {
                prefix.to_string()
            } else {
                format!("{prefix}_test")
            };
            ensure!(
                raw == expected
                    && result["address_hex"] == hex::encode(&raw)
                    && hrp == expected_hrp,
                "address header/credential/pointer/network mismatch"
            );
        }
        "address.byron" => {
            let raw = bytes(result, "address_hex")?;
            ensure!(
                encoding::base58_decode(
                    result["address"]
                        .as_str()
                        .context("missing Byron address")?
                )? == raw,
                "base58 Byron bytes mismatch"
            );
            validate_byron(&raw, input)?;
        }
        "encoding.bech32" => {
            if input["action"] == "encode" {
                ensure!(
                    result["text"]
                        == encoding::bech32_encode(
                            input["hrp"].as_str().context("missing HRP")?,
                            &bytes(input, "bytes_hex")?
                        )?,
                    "Bech32 encoding mismatch"
                );
            } else {
                let (hrp, raw) = encoding::bech32(input["text"].as_str().context("missing text")?)?;
                ensure!(
                    result["hrp"] == hrp && result["bytes_hex"] == hex::encode(raw),
                    "Bech32 decoding mismatch"
                );
            }
        }
        "encoding.base58" => {
            if input["action"] == "encode" {
                ensure!(
                    result["text"] == encoding::base58_encode(&bytes(input, "bytes_hex")?)?,
                    "base58 encoding mismatch"
                );
            } else {
                ensure!(
                    result["bytes_hex"]
                        == hex::encode(encoding::base58_decode(
                            input["text"].as_str().context("missing text")?
                        )?),
                    "base58 decoding mismatch"
                );
            }
        }
        "key.hash" => ensure!(
            result["hash_hex"]
                == hex::encode(transaction::blake2b(&bytes(input, "public_key_hex")?, 28)?),
            "credential key hash mismatch"
        ),
        "asset.fingerprint" => {
            let mut raw = bytes(input, "policy_hex")?;
            raw.extend(bytes(input, "asset_name_hex")?);
            ensure!(
                result["fingerprint"]
                    == encoding::bech32_encode("asset", &transaction::blake2b(&raw, 20)?)?,
                "asset fingerprint mismatch"
            );
        }
        "governance.identifier" => {
            if input["action"] == "encode" {
                let (hrp, raw) =
                    encoding::bech32(result["text"].as_str().context("missing identifier")?)?;
                let family = match input["role"].as_str().context("missing governance role")? {
                    "committee_hot" => 0,
                    "committee_cold" => 1,
                    "drep" => 2,
                    _ => anyhow::bail!("invalid governance role"),
                };
                let kind = if input["kind"] == "key" { 2 } else { 3 };
                let mut expected = vec![(family << 4) | kind];
                expected.extend(bytes(input, "hash_hex")?);
                ensure!(
                    raw == expected
                        && hrp
                            == match family {
                                0 => "cc_hot",
                                1 => "cc_cold",
                                _ => "drep",
                            },
                    "CIP-129 header/hash mismatch"
                );
            } else {
                let (_, raw) =
                    encoding::bech32(input["text"].as_str().context("missing identifier")?)?;
                ensure!(
                    raw.len() == 29 && result["hash_hex"] == hex::encode(&raw[1..]),
                    "CIP-129 decoded hash mismatch"
                );
            }
        }
        "byron.path-encrypt" => {
            let raw = bytes(result, "attributes_hex")?;
            let mut d = minicbor::Decoder::new(&raw);
            ensure!(
                d.map()? == Some(1)
                    && d.u8()? == 1
                    && d.bytes()?.len() > 16
                    && d.position() == raw.len(),
                "invalid encrypted path attributes"
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
        expectation: Option<Value>,
    ) -> Result<Value> {
        let mut vector=Vector{id:id.into(),requirements:requirements.iter().map(|s|(*s).into()).collect(),source:format!("Wallet2fc5c383; actual cardano-address/ledger/CBOR/codec functions; AddressAdapter sha256:{ORACLE}; independent Rust byte/hash/evaluation laws"),operation:operation.into(),input,expected:None,selection_invariants:false};
        let actual = adapter::invoke(self.binary, &[], &vector, Duration::from_secs(30))?;
        ensure!(
            actual == adapter::invoke(self.binary, &[], &vector, Duration::from_secs(30))?,
            "address oracle replay differs"
        );
        if let Some(expected) = expectation {
            ensure!(
                actual == expected,
                "address boundary differs from independent expected outcome: {id}"
            );
        } else {
            ensure!(
                actual.get("result").is_some(),
                "valid address/script profile rejected: {id}"
            );
        }
        validate(&vector, &actual)
            .with_context(|| format!("independent address check failed: {id}"))?;
        vector.expected = Some(actual.clone());
        self.vectors.push(vector);
        Ok(actual)
    }
}

pub fn capture(binary: &Path) -> Result<Vec<Vector>> {
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(binary)?)) == ORACLE,
        "address adapter differs from pinned oracle"
    );
    let mut c = Capture {
        binary,
        vectors: vec![],
    };
    let a = "11".repeat(28);
    let b = "22".repeat(28);
    let signature = |hash: &str| json!({"type":"signature","key_hash_hex":hash});
    let sa = signature(&a);
    let sb = signature(&b);
    let all = json!({"type":"all","scripts":[sa,sb]});
    let any = json!({"type":"any","scripts":[sa,sb]});
    let threshold =
        json!({"type":"at_least","required":2,"scripts":[sa,sb,{"type":"before","slot":1000}]});
    let before = json!({"type":"before","slot":1000});
    let after = json!({"type":"after","slot":100});
    let timed = json!({"type":"all","scripts":[sa,before,after]});
    for (id, script, signers, lo, hi) in [
        (
            "native-script-all",
            all.clone(),
            json!([a, b]),
            Some(100),
            Some(1000),
        ),
        (
            "native-script-any",
            any.clone(),
            json!([a]),
            Some(100),
            Some(1000),
        ),
        (
            "native-script-at-least",
            threshold.clone(),
            json!([a, b]),
            Some(100),
            Some(1000),
        ),
        (
            "native-script-before",
            before.clone(),
            json!([]),
            None,
            Some(1000),
        ),
        (
            "native-script-after",
            after.clone(),
            json!([]),
            Some(100),
            None,
        ),
        (
            "native-script-unsatisfied",
            all.clone(),
            json!([a]),
            Some(100),
            Some(1000),
        ),
        (
            "native-before-outside-bound",
            before.clone(),
            json!([]),
            None,
            Some(1001),
        ),
        (
            "native-after-outside-bound",
            after.clone(),
            json!([]),
            Some(99),
            None,
        ),
        (
            "native-before-unbounded",
            before.clone(),
            json!([]),
            None,
            None,
        ),
        (
            "native-policy-id",
            timed.clone(),
            json!([a]),
            Some(100),
            Some(1000),
        ),
    ] {
        c.add(
            id,
            &[if id == "native-policy-id" {
                "script.policy-id"
            } else {
                "script.native"
            }],
            "native.script",
            json!({"script":script,"signers":signers,"invalid_before":lo,"invalid_hereafter":hi}),
            None,
        )?;
    }
    for (id, script) in [
        ("native-empty-all", json!({"type":"all","scripts":[]})),
        ("native-empty-any", json!({"type":"any","scripts":[]})),
        (
            "native-threshold-zero",
            json!({"type":"at_least","required":0,"scripts":[]}),
        ),
        (
            "native-threshold-impossible",
            json!({"type":"at_least","required":2,"scripts":[sa]}),
        ),
    ] {
        c.add(
            id,
            &["script.native"],
            "native.script",
            json!({"script":script,"signers":[a],"invalid_before":100,"invalid_hereafter":1000}),
            None,
        )?;
    }
    c.add("native-threshold-overflow-rejected", &["script.native"], "native.script", json!({"script":{"type":"at_least","required":256,"scripts":[]},"signers":[],"invalid_before":null,"invalid_hereafter":null}), Some(json!({"error":{"code":"invalid_input"}})))?;
    let key_a = json!({"type":"key","hash_hex":a});
    let key_b = json!({"type":"key","hash_hex":b});
    let script_all = json!({"type":"script","script":all});
    for (id, payment, stake) in [
        ("address-base-script-key", script_all.clone(), key_b.clone()),
        ("address-base-key-script", key_a.clone(), script_all.clone()),
        (
            "address-base-script-script",
            script_all.clone(),
            script_all.clone(),
        ),
    ] {
        c.add(
            id,
            &["address.shelley"],
            "address.build",
            json!({"network_tag":0,"kind":"base","payment":payment,"stake":stake}),
            None,
        )?;
    }
    for (id, slot, tx, out) in [
        ("address-pointer", 128, 127, 128),
        ("address-pointer-zero", 0, 0, 0),
        ("address-pointer-u64-max", u64::MAX, u64::MAX, u64::MAX),
    ] {
        c.add(id,&["address.shelley"],"address.build",json!({"network_tag":0,"kind":"pointer","payment":key_a,"slot":slot,"transaction_index":tx,"output_index":out}),None)?;
    }
    c.add(
        "address-reward-script",
        &["address.shelley"],
        "address.build",
        json!({"network_tag":1,"kind":"reward","stake":script_all}),
        None,
    )?;
    for (id, script) in [
        ("address-shared-all", all),
        ("address-shared-any", any),
        ("address-shared-at-least", threshold),
        ("address-shared-timelock", timed),
    ] {
        c.add(id,&["address.shared"],"address.build",json!({"network_tag":0,"kind":"enterprise","payment":{"type":"script","script":script}}),None)?;
    }
    let mnemonic = bip39::Mnemonic::from_entropy(&[0; 16])?.to_string();
    let mut icarus = Value::Null;
    for (id, style, network) in [
        ("address-byron-random", "Byron", "mainnet"),
        ("address-byron-network-attributes", "Byron", "preprod"),
        ("address-byron-icarus", "Icarus", "mainnet"),
        ("address-byron-protocol-magic", "Icarus", "preprod"),
    ] {
        let actual=c.add(id,&["address.byron","address.network"],"address.byron",json!({"style":style,"mnemonic":mnemonic,"network":network,"account_index":2147483648u64,"address_index":0}),None)?;
        if style == "Icarus" {
            icarus = actual["result"].clone();
        }
    }
    let mut corrupt = bytes(&icarus, "address_hex")?;
    *corrupt.last_mut().context("empty Byron address")? ^= 1;
    c.add(
        "address-byron-crc-rejection",
        &["address.byron"],
        "address.inspect-byron",
        json!({"style":"Icarus","address_hex":hex::encode(corrupt)}),
        Some(json!({"error":{"code":"invalid_input"}})),
    )?;
    let path=c.add("byron-path-encrypt-golden",&["crypto.byron-payload"],"byron.path-encrypt",json!({"passphrase_hex":"00".repeat(32),"account_index":2147483648u64,"address_index":4294967295u64}),None)?;
    c.add(
        "byron-path-decrypt-golden",
        &["crypto.byron-payload"],
        "byron.path-decrypt",
        json!({"passphrase_hex":"00".repeat(32),"attributes_hex":path["result"]["attributes_hex"]}),
        Some(json!({"result":{"path":[2147483648u64,4294967295u64]}})),
    )?;
    c.add(
        "byron-path-authentication-failure",
        &["crypto.byron-payload"],
        "byron.path-decrypt",
        json!({"passphrase_hex":"01".repeat(32),"attributes_hex":path["result"]["attributes_hex"]}),
        Some(json!({"result":{"path":null}})),
    )?;
    c.add(
        "byron-path-malformed-cbor",
        &["crypto.byron-payload"],
        "byron.path-decrypt",
        json!({"passphrase_hex":"00".repeat(32),"attributes_hex":"ff"}),
        Some(json!({"error":{"code":"invalid_input"}})),
    )?;
    c.add(
        "base58-leading-zero",
        &["address.encoding"],
        "encoding.base58",
        json!({"action":"encode","bytes_hex":"000001"}),
        Some(json!({"result":{"text":"112"}})),
    )?;
    c.add(
        "base58-leading-zero-decode",
        &["address.encoding"],
        "encoding.base58",
        json!({"action":"decode","text":"112"}),
        Some(json!({"result":{"bytes_hex":"000001"}})),
    )?;
    c.add(
        "base58-malformed",
        &["address.encoding"],
        "encoding.base58",
        json!({"action":"decode","text":"0OIl"}),
        Some(json!({"error":{"code":"invalid_input"}})),
    )?;
    let canonical = encoding::bech32_encode("addr_test", &[0, 1, 2])?;
    let mut bad = canonical.clone();
    let last = bad.pop().unwrap();
    bad.push(if last == 'q' { 'p' } else { 'q' });
    for (id, text) in [
        ("bech32-checksum-rejected", bad),
        (
            "bech32-mixed-case-rejected",
            canonical.replacen('a', "A", 1),
        ),
        (
            "bech32-invalid-padding",
            encoding::bech32_from_words("addr_test", &[1])?,
        ),
    ] {
        c.add(
            id,
            &["address.encoding"],
            "encoding.bech32",
            json!({"action":"decode","text":text}),
            Some(json!({"error":{"code":"invalid_input"}})),
        )?;
    }
    c.add(
        "bech32-byte-encode",
        &["address.encoding"],
        "encoding.bech32",
        json!({"action":"encode","hrp":"addr_test","bytes_hex":"000102"}),
        None,
    )?;
    c.add(
        "bech32-byte-decode",
        &["address.encoding"],
        "encoding.bech32",
        json!({"action":"decode","text":canonical}),
        None,
    )?;
    for (id, role, kind) in [
        ("cip129-drep-key", "drep", "key"),
        ("cip129-drep-script", "drep", "script"),
        ("cip129-committee-hot", "committee_hot", "key"),
        ("cip129-committee-cold", "committee_cold", "key"),
    ] {
        let text = c.add(
            id,
            &["address.cip129"],
            "governance.identifier",
            json!({"action":"encode","role":role,"kind":kind,"hash_hex":a}),
            None,
        )?;
        c.add(
            &format!("{id}-decode"),
            &["address.cip129"],
            "governance.identifier",
            json!({"action":"decode","role":role,"kind":kind,"text":text["result"]["text"]}),
            Some(json!({"result":{"hash_hex":a}})),
        )?;
    }
    let mut invalid_header = vec![0xff];
    invalid_header.extend([0x11; 28]);
    c.add("cip129-header-rejected",&["address.cip129"],"governance.identifier",json!({"action":"decode","role":"drep","kind":"key","text":encoding::bech32_encode("drep",&invalid_header)?}),Some(json!({"error":{"code":"invalid_input"}})))?;
    c.add(
        "key-hash",
        &["script.policy-id"],
        "key.hash",
        json!({"public_key_hex":"11".repeat(32)}),
        None,
    )?;
    c.add(
        "asset-fingerprint",
        &["script.policy-id"],
        "asset.fingerprint",
        json!({"policy_hex":a,"asset_name_hex":"deadbeef"}),
        None,
    )?;
    c.add(
        "address-invalid-network-rejected",
        &["address.network"],
        "address.build",
        json!({"network_tag":16,"kind":"enterprise","payment":key_a}),
        Some(json!({"error":{"code":"invalid_input"}})),
    )?;
    c.add("address-short-credential-rejected", &["address.shelley"], "address.build", json!({"network_tag":0,"kind":"enterprise","payment":{"type":"key","hash_hex":"11".repeat(27)}}), Some(json!({"error":{"code":"invalid_input"}})))?;
    Ok(c.vectors)
}
