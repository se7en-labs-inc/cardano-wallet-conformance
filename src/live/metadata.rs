//! Actual CIP83 metadata, independent CBOR/hash checks and bounded OpenSSL decryption.
use super::{
    families::{FUNDING, SHELLEY},
    *,
};
use base64::Engine;
use std::{
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
};
const PASSWORD: &str = "conformance-test-passphrase";
const METADATA_PASSWORD: &str = "conformance-metadata-é";
fn raw_tx(encoded: &str) -> Result<Vec<u8>> {
    if encoded.len().is_multiple_of(2) && encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(hex::decode(encoded)?)
    } else {
        Ok(base64::engine::general_purpose::STANDARD.decode(encoded)?)
    }
}
fn value(raw: &[u8], d: &mut minicbor::Decoder<'_>, depth: usize) -> Result<Value> {
    ensure!(depth <= 64, "metadata depth exceeds profile");
    Ok(
        match raw.get(d.position()).context("missing metadatum")? >> 5 {
            0 | 1 => json!({"int":i128::from(d.int()?)}),
            2 => {
                let bytes = d.bytes()?;
                ensure!(bytes.len() <= 64, "metadata bytes exceed bound");
                json!({"bytes":hex::encode(bytes)})
            }
            3 => {
                let text = d.str()?;
                ensure!(text.len() <= 64, "metadata text exceeds bound");
                json!({"string":text})
            }
            4 => {
                let count = d.array()?.context("indefinite metadata list")?;
                ensure!(count <= 1024, "metadata list exceeds profile");
                let mut list = Vec::new();
                for _ in 0..count {
                    list.push(value(raw, d, depth + 1)?);
                }
                json!({"list":list})
            }
            5 => {
                let count = d.map()?.context("indefinite metadata map")?;
                ensure!(count <= 1024, "metadata map exceeds profile");
                let mut entries = Vec::new();
                for _ in 0..count {
                    entries.push(json!({"k":value(raw,d,depth+1)?,"v":value(raw,d,depth+1)?}));
                }
                json!({"map":entries})
            }
            _ => anyhow::bail!("invalid metadata CBOR type"),
        },
    )
}
fn internal(v: &Value) -> Result<Value> {
    let fields = v.as_object().context("metadata value is not object")?;
    ensure!(fields.len() == 1, "metadata value has conflicting types");
    let (kind, v) = fields.iter().next().unwrap();
    Ok(match kind.as_str() {
        "int" => json!({"type":"number","value":v}),
        "string" => json!({"type":"text","value":v}),
        "bytes" => json!({"type":"bytes","hex":v}),
        "list" => {
            json!({"type":"list","items":v.as_array().context("metadata list missing")?.iter().map(internal).collect::<Result<Vec<_>>>()?})
        }
        "map" => {
            json!({"type":"map","entries":v.as_array().context("metadata entries missing")?.iter().map(|entry| -> Result<Value> { Ok(json!({"key":internal(&entry["k"])?,"value":internal(&entry["v"])?})) }).collect::<Result<Vec<_>>>()?})
        }
        _ => anyhow::bail!("unknown detailed metadata type"),
    })
}
fn encode_metadata(metadata: &Value) -> Result<Vec<u8>> {
    let entries = metadata
        .as_object()
        .context("metadata labels missing")?
        .iter()
        .map(|(label, v)| -> Result<Value> {
            Ok(json!({"label":label.parse::<u64>()?,"value":internal(v)?}))
        })
        .collect::<Result<Vec<_>>>()?;
    let encoded = crate::ledger::metadata(&json!({"entries":entries}))?;
    ensure!(
        encoded["valid"] == true,
        "independent metadata encoder rejected values"
    );
    Ok(hex::decode(
        encoded["cbor_hex"]
            .as_str()
            .context("metadata CBOR missing")?,
    )?)
}
fn metadata_map(raw: &[u8], d: &mut minicbor::Decoder<'_>) -> Result<Value> {
    let count = d.map()?.context("indefinite metadata labels")?;
    ensure!(count <= 1024, "too many metadata labels");
    let mut result = serde_json::Map::new();
    for _ in 0..count {
        let label = d.u64()?.to_string();
        ensure!(
            result.insert(label, value(raw, d, 0)?).is_none(),
            "duplicate metadata label"
        );
    }
    Ok(Value::Object(result))
}
pub(super) fn extract(encoded: &str) -> Result<(Value, Vec<u8>)> {
    let raw = raw_tx(encoded)?;
    let mut d = minicbor::Decoder::new(&raw);
    ensure!(
        d.array()? == Some(4),
        "metadata transaction is not Conway envelope"
    );
    let mut expected = None;
    for _ in 0..d.map()?.context("indefinite transaction body")? {
        if d.u64()? == 7 {
            ensure!(expected.is_none(), "duplicate auxiliary hash");
            expected = Some(d.bytes()?.to_vec());
        } else {
            d.skip()?;
        }
    }
    d.skip()?;
    ensure!(d.bool()?, "metadata transaction phase2 flag is false");
    let auxiliary_start = d.position();
    ensure!(
        d.tag()?.as_u64() == 259 && d.map()? == Some(1) && d.u64()? == 0,
        "unexpected metadata-only auxiliary envelope"
    );
    let start = d.position();
    let metadata = metadata_map(&raw, &mut d)?;
    let bytes = raw[start..d.position()].to_vec();
    ensure!(d.position() == raw.len(), "trailing auxiliary bytes");
    ensure!(
        expected.context("body auxiliary hash missing")?
            == transaction::blake2b(&raw[auxiliary_start..], 32)?,
        "auxiliary hash differs from exact original bytes"
    );
    ensure!(
        encode_metadata(&metadata)? == bytes,
        "metadata CBOR differs from independent canonical encoding"
    );
    Ok((metadata, bytes))
}
fn pairs(metadata: &Value) -> Result<&Vec<Value>> {
    metadata["674"]["map"]
        .as_array()
        .context("CIP83 metadata map missing")
}
fn field<'a>(entries: &'a [Value], name: &str) -> Result<&'a Value> {
    let matches = entries
        .iter()
        .filter(|entry| entry["k"]["string"] == name)
        .collect::<Vec<_>>();
    ensure!(matches.len() == 1, "missing or duplicate CIP83 field");
    Ok(&matches[0]["v"])
}
fn ciphertext(metadata: &Value) -> Result<Vec<u8>> {
    let entries = pairs(metadata)?;
    ensure!(
        field(entries, "enc")? == &json!({"string":"basic"}),
        "CIP83 encryption method differs"
    );
    let mut encoded = String::new();
    let msg = field(entries, "msg")?;
    let chunks = msg["list"]
        .as_array()
        .context("encrypted message chunks missing")?;
    ensure!(!chunks.is_empty(), "empty encrypted message");
    for chunk in chunks {
        let text = chunk["string"]
            .as_str()
            .context("ciphertext chunk is not text")?;
        ensure!(
            !text.is_empty() && text.len() <= 64,
            "invalid ciphertext chunk length"
        );
        encoded.push_str(text);
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    ensure!(
        bytes.len() >= 32
            && bytes.starts_with(b"Salted__")
            && (bytes.len() - 16).is_multiple_of(16),
        "CIP83 salt/header/cipher block shape differs"
    );
    Ok(bytes)
}
fn openssl_decrypt(executable: &Path, cipher: &[u8], timeout: Duration) -> Result<Value> {
    ensure!(
        cipher.len() <= 4096,
        "cipher exceeds bounded process profile"
    );
    let mut child = Command::new(executable)
        .args([
            "enc",
            "-d",
            "-aes-256-cbc",
            "-pbkdf2",
            "-iter",
            "10000",
            "-md",
            "sha256",
            "-saltlen",
            "8",
            "-pass",
            "env:WALLET_CONFORMANCE_METADATA_PASSWORD",
        ])
        .env("WALLET_CONFORMANCE_METADATA_PASSWORD", METADATA_PASSWORD)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("cannot launch independent OpenSSL")?;
    let mut stdin = child.stdin.take().context("OpenSSL stdin missing")?;
    let stdout = child.stdout.take().context("OpenSSL stdout missing")?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(65537).read_to_end(&mut bytes).map(|_| bytes);
        let _ = tx.send(result);
    });
    if stdin.write_all(cipher).is_err() {
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("cannot send independent cipher input");
    }
    drop(stdin);
    let deadline = Instant::now() + timeout.min(Duration::from_secs(30));
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("independent metadata decryption timed out");
        }
        sleep(Duration::from_millis(10));
    };
    ensure!(status.success(), "independent OpenSSL decryption failed");
    let plaintext = rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .context("OpenSSL output did not close")??;
    ensure!(plaintext.len() <= 65536, "OpenSSL output exceeds bound");
    serde_json::from_slice(&plaintext).context("independent plaintext is not expected JSON")
}
impl Session<'_> {
    pub(super) fn exercise_metadata(&mut self, options: &LiveOptions) -> Result<()> {
        let mnemonic = || -> Result<Vec<String>> {
            Ok(bip39::Mnemonic::generate(15)?
                .words()
                .map(str::to_owned)
                .collect())
        };
        let id = self.create("conformance-encrypted-metadata", mnemonic()?)?;
        self.family_ready_balance(SHELLEY, &id, 0)?;
        let path = format!("/wallets/{id}");
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("{path}/addresses"),
            None,
            200,
        )?;
        self.family_fund(SHELLEY, &id, &text(&addresses, "/0/id")?, options)?;
        let template = json!({"cosigners":{"cosigner#0":"self"},"template":{"all":["cosigner#0"]}});
        let reader = self.call("postSharedWallet","POST","/shared-wallets",Some(json!({"name":"conformance-metadata-shared-reader","mnemonic_sentence":mnemonic()?,"passphrase":PASSWORD,"account_index":"0H","payment_script_template":template,"delegation_script_template":template})),201)?;
        let reader_id = text(&reader, "/id")?;
        self.poll(
            "getSharedWallet",
            &format!("/shared-wallets/{reader_id}"),
            |v| v["state"]["status"] == "ready",
        )?;
        let messages = json!(["wallet-conformance-public", "é".repeat(32)]);
        let detailed_messages = json!({"list":messages.as_array().unwrap().iter().map(|v| json!({"string":v})).collect::<Vec<_>>()});
        let original = json!({"0":{"bytes":"00ff".repeat(32)},"674":{"map":[{"k":{"string":"note"},"v":{"int":42}},{"k":{"string":"msg"},"v":detailed_messages}]},"18446744073709551615":{"string":"public-label-boundary"}});
        let construct = self.call("constructTransaction","POST",&format!("{path}/transactions-construct"),Some(json!({"metadata":original,"encrypt_metadata":{"passphrase":METADATA_PASSWORD,"method":"basic"}})),202)?;
        let unsigned = text(&construct, "/transaction")?;
        let fee = number(&construct, "/fee/quantity")?;
        let inspected = transaction::inspect(&unsigned, false)?;
        ensure!(fee > 0 && inspected.fee == fee, "metadata fee differs");
        let (encrypted, metadata_bytes) = extract(&unsigned)?;
        ensure!(
            encrypted["0"] == original["0"]
                && encrypted["18446744073709551615"] == original["18446744073709551615"]
                && field(pairs(&encrypted)?, "note")? == &json!({"int":42}),
            "encryption changed unrelated metadata"
        );
        ensure!(encrypted != original, "metadata was not encrypted");
        let binary = base64::engine::general_purpose::STANDARD
            .decode(text(&construct, "/coin_selection/metadata")?)?;
        ensure!(
            binary == metadata_bytes,
            "coin selection binary metadata differs from exact auxiliary CBOR"
        );
        ensure!(
            openssl_decrypt(&options.openssl, &ciphertext(&encrypted)?, self.timeout)? == messages,
            "independent AES/PBKDF2 plaintext differs"
        );
        for (op, decode_path) in [
            ("decodeTransaction", format!("{path}/transactions-decode")),
            (
                "decodeSharedTransaction",
                format!("/shared-wallets/{reader_id}/transactions-decode"),
            ),
        ] {
            let decoded = self.call(
                op,
                "POST",
                &decode_path,
                Some(json!({"transaction":unsigned})),
                202,
            )?;
            ensure!(
                decoded["id"] == inspected.id && decoded["metadata"] == encrypted,
                "encrypted metadata inspection differs"
            );
        }
        let correct = self.call("decodeTransaction","POST",&format!("{path}/transactions-decode"),Some(json!({"transaction":unsigned,"decrypt_metadata":{"passphrase":METADATA_PASSWORD,"method":"basic"}})),202)?;
        ensure!(
            correct["metadata"] == original,
            "wallet metadata decryption differs from original values"
        );
        let wrong = self.call("decodeTransaction","POST",&format!("{path}/transactions-decode"),Some(json!({"transaction":unsigned,"decrypt_metadata":{"passphrase":"wrong-metadata-password","method":"basic"}})),403)?;
        ensure!(
            wrong["code"] == "invalid_metadata_decryption",
            "wrong metadata password error differs"
        );
        let shared_path = format!("/shared-wallets/{reader_id}/transactions-decode");
        let shared = self.api.checked(self.contract,"decodeSharedTransaction",request("POST",&shared_path,Some(json!({"transaction":unsigned,"decrypt_metadata":{"passphrase":METADATA_PASSWORD,"method":"basic"}}))),500)?;
        ensure!(
            shared.raw == b"Something went wrong"
                && shared.media_type.as_deref() == Some("text/plain"),
            "shared metadata TODO body/media differ"
        );
        self.report.record(
            "live:shared-decryption-unsupported",
            &[
                "api:decodeSharedTransaction:status:500".into(),
                "api:decodeSharedTransaction:negative".into(),
            ],
            Ok(()),
        );
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("{path}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":PASSWORD})),
            202,
        )?;
        let signed = text(&signed, "/transaction")?;
        let verified = transaction::inspect(&signed, true)?;
        ensure!(
            verified.id == inspected.id && extract(&signed)? == (encrypted.clone(), metadata_bytes),
            "signing changed metadata/body"
        );
        let submitted = self.call(
            "submitTransaction",
            "POST",
            &format!("{path}/transactions-submit"),
            Some(json!({"transaction":signed})),
            202,
        )?;
        ensure!(
            submitted["id"] == verified.id,
            "metadata submission ID differs"
        );
        let history = self.family_confirm(SHELLEY, &id, &verified.id)?;
        ensure!(
            history["metadata"] == encrypted
                && history["direction"] == "outgoing"
                && number(&history, "/fee/quantity")? == fee,
            "confirmed binary/encrypted metadata or fee differs"
        );
        self.family_ready_balance(SHELLEY, &id, FUNDING - fee)?;
        for output in &verified.outputs {
            let bytes = hex::decode(&output.address_hex)?;
            let address = crate::encoding::bech32_encode("addr_test", &bytes)?;
            options
                .node
                .payment(&verified.id, &address, output.coin, self.timeout)?;
        }
        self.check_snapshot(&id, FUNDING - fee)?;
        self.report.record(
            "history:binary-metadata",
            &[
                "wallet.transaction-filtering".into(),
                "tx.metadata".into(),
                "chain.node-utxo-confirmation".into(),
            ],
            Ok(()),
        );
        self.report.record(
            "live:cip83-independent-decryption",
            &["tx.metadata".into()],
            Ok(()),
        );
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn transaction(metadata: &[u8]) -> String {
        let mut auxiliary = vec![0xd9, 0x01, 0x03, 0xa1, 0x00];
        auxiliary.extend(metadata);
        let mut body = minicbor::Encoder::new(Vec::new());
        body.map(1)
            .unwrap()
            .u8(7)
            .unwrap()
            .bytes(&transaction::blake2b(&auxiliary, 32).unwrap())
            .unwrap();
        let mut raw = vec![0x84];
        raw.extend(body.into_writer());
        raw.extend([0xa0, 0xf5]);
        raw.extend(auxiliary);
        hex::encode(raw)
    }
    #[test]
    fn extraction_uses_haskell_golden_and_rejects_auxiliary_hash_or_byte_mutations() {
        let fixtures: Vec<crate::adapter::Vector> =
            serde_json::from_str(include_str!("../../fixtures/vectors/ledger-profiles.json"))
                .unwrap();
        let hex = fixtures
            .iter()
            .find(|v| v.id == "metadata-cbor-golden")
            .unwrap()
            .expected
            .as_ref()
            .unwrap()["result"]["cbor_hex"]
            .as_str()
            .unwrap();
        let metadata = hex::decode(hex).unwrap();
        let encoded = transaction(&metadata);
        let (parsed, actual) = extract(&encoded).unwrap();
        assert_eq!(actual, metadata);
        assert_eq!(
            parsed,
            json!({"42":{"map":[{"k":{"string":"message"},"v":{"list":[{"int":42},{"bytes":"abab"},{"string":"Cardano"}]}}]}})
        );
        let mut raw = hex::decode(&encoded).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(extract(&hex::encode(&raw)).is_err());
        let mut raw = hex::decode(&encoded).unwrap();
        raw.push(0);
        assert!(extract(&hex::encode(&raw)).is_err());
        let mut raw = hex::decode(&encoded).unwrap();
        raw[8] ^= 1;
        assert!(extract(&hex::encode(&raw)).is_err());
    }
    #[test]
    fn ciphertext_format_requires_basic_unique_fields_bounded_chunks_and_salted_blocks() {
        let mut cipher = b"Salted__".to_vec();
        cipher.extend([0; 24]);
        let encrypted = json!({"674":{"map":[{"k":{"string":"msg"},"v":{"list":[{"string":base64::engine::general_purpose::STANDARD.encode(&cipher)}]}},{"k":{"string":"enc"},"v":{"string":"basic"}}]}});
        assert_eq!(ciphertext(&encrypted).unwrap(), cipher);
        let mut wrong = encrypted.clone();
        wrong["674"]["map"][1]["v"]["string"] = json!("other");
        assert!(ciphertext(&wrong).is_err());
        let mut wrong = encrypted.clone();
        wrong["674"]["map"]
            .as_array_mut()
            .unwrap()
            .push(encrypted["674"]["map"][1].clone());
        assert!(ciphertext(&wrong).is_err());
        let mut wrong = encrypted.clone();
        wrong["674"]["map"][0]["v"]["list"][0]["string"] = json!("A".repeat(65));
        assert!(ciphertext(&wrong).is_err());
        let mut wrong = encrypted;
        cipher[0] ^= 1;
        wrong["674"]["map"][0]["v"]["list"][0]["string"] =
            json!(base64::engine::general_purpose::STANDARD.encode(cipher));
        assert!(ciphertext(&wrong).is_err());
    }
}
