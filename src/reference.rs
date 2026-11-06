//! Capture deterministic key and address vectors from the independent Haskell
//! cardano-address executable, never from the replacement implementation.
use crate::{adapter::Vector, encoding, transaction};
use anyhow::{ensure, Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

const ORACLE_SHA256: &str = "7a9ea8a8c71356a3ab4671190e1cad863e8d701480cf36882dbef8db1870167f";

struct RootCapture<'a> {
    oracle: &'a Path,
    source: String,
    vectors: Vec<Vector>,
}

impl RootCapture<'_> {
    fn case(
        &mut self,
        id: &str,
        operation: &str,
        input: serde_json::Value,
        error: Option<&str>,
        public: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut vector = Vector {
            id: id.into(),
            requirements: vec!["crypto.root-key-encryption".into()],
            source: self.source.clone(),
            operation: operation.into(),
            input,
            expected: None,
            selection_invariants: false,
        };
        let timeout = std::time::Duration::from_secs(60);
        let actual = crate::adapter::invoke(self.oracle, &[], &vector, timeout)?;
        ensure!(
            actual == crate::adapter::invoke(self.oracle, &[], &vector, timeout)?,
            "root oracle failed deterministic replay: {id}"
        );
        if let Some(error) = error {
            ensure!(
                actual == json!({"error":{"code":error}}),
                "unexpected encrypted-root error: {id}"
            );
        } else {
            ensure!(
                actual["result"].is_object(),
                "encrypted-root oracle failed: {id}"
            );
            if let Some(public) = public {
                ensure!(
                    actual["result"]["xpub_hex"] == public,
                    "root public key differs from independent cardano-address golden: {id}"
                );
            }
            if operation == "root-key.check-v2" {
                ensure!(
                    actual == json!({"result":{"valid":true}}),
                    "root authentication failed: {id}"
                );
            }
            if operation == "root-key.sign-v2" {
                let public = hex::decode(
                    actual["result"]["xpub_hex"]
                        .as_str()
                        .context("missing root public key")?,
                )?;
                ensure!(public.len() == 64, "invalid root public key length");
                let key: [u8; 32] = public[..32].try_into()?;
                let signature = hex::decode(
                    actual["result"]["signature_hex"]
                        .as_str()
                        .context("missing signature")?,
                )?;
                let message = hex::decode(
                    vector.input["message_hex"]
                        .as_str()
                        .context("missing message")?,
                )?;
                ed25519_dalek::VerifyingKey::from_bytes(&key)?
                    .verify_strict(&message, &ed25519_dalek::Signature::from_slice(&signature)?)?;
            }
        }
        vector.expected = Some(actual.clone());
        self.vectors.push(vector);
        Ok(actual)
    }
}

fn root_envelope(parts: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(parts.len() as u64)?;
    for part in parts {
        encoder.bytes(part)?;
    }
    Ok(encoder.into_writer())
}

/// Freeze real production-cost Argon2id/XChaCha20-Poly1305 behavior. The only
/// randomness override is the documented test counter; KDF costs stay unchanged.
pub fn capture_roots(oracle: &Path) -> Result<Vec<Vector>> {
    const ORACLE: &str = "2a9fd2d0b24de402fee3787ec85600b159f1c66e7b1833afe8872b80cf12e1d2";
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(oracle)?)) == ORACLE,
        "root oracle differs from the pinned source-built Haskell driver"
    );
    let source = format!("Haskell cardano-crypto-wallet 0.2.0.0; package source sha256-jpHIKobCE2NI80SpHptUB7eY3MoWcMU+/DF3iVIDtXY=; wallet source 2fc5c383c94bb907deaa0cd27b1b407f86224b6c; oracle sha256:{ORACLE}; driver sha256:d8e116f43fb23ce85504f68e3eedfe4948c014cdea4f66ed088b0fbb14690a1c; production Argon2id 131072KiB/time3/parallelism4/output32; XChaCha20-Poly1305; deterministic counter-v1 test entropy only; independent cardano-address public keys and Rust strict signature checks");
    let mut capture = RootCapture {
        oracle,
        source,
        vectors: Vec::new(),
    };
    let keys: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/haskell-keys.json"))?;
    let root = keys
        .iter()
        .find(|v| v.id == "haskell-Shelley-root")
        .context("missing root golden")?
        .expected
        .as_ref()
        .context("missing root result")?;
    let master = root["result"]["xprv_hex"]
        .as_str()
        .context("missing master key")?;
    let public = root["result"]["xpub_hex"]
        .as_str()
        .context("missing public key")?;
    let passphrase = hex::encode("conformance root password");
    let created = capture.case(
        "root-encrypt-v2",
        "root-key.create-v2",
        json!({"master_key_hex":master,"passphrase_hex":passphrase,"randomness":"counter-v1"}),
        None,
        Some(public),
    )?;
    let key = created["result"]["key_hex"]
        .as_str()
        .context("missing ciphertext")?;
    let encoded = hex::decode(key)?;
    let mut decoder = minicbor::Decoder::new(&encoded);
    ensure!(decoder.array()? == Some(5), "invalid root envelope");
    let parts = (0..5)
        .map(|_| Ok(decoder.bytes()?.to_vec()))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        decoder.position() == encoded.len()
            && parts[0] == vec![0; 32]
            && parts[1] == [1, 0, 0, 0, 0, 0, 0, 0].repeat(3),
        "unexpected deterministic root entropy"
    );
    capture.case(
        "root-v2-parse",
        "root-key.parse",
        json!({"key_hex":key}),
        None,
        Some(public),
    )?;
    capture.case(
        "root-v2-check",
        "root-key.check-v2",
        json!({"key_hex":key,"passphrase_hex":passphrase}),
        None,
        None,
    )?;
    for operation in [
        "root-key.check-v2",
        "root-key.sign-v2",
        "root-key.change-v2",
        "root-key.derive-v2",
    ] {
        capture.case(if operation == "root-key.check-v2" { "root-decrypt-wrong-passphrase" } else { operation }, operation, json!({"key_hex":key,"passphrase_hex":"00","old_passphrase_hex":"00","new_passphrase_hex":"01","randomness":"counter-v1","message_hex":"","path":[0]}), Some("XPrvAuthenticationFailed"), None)?;
    }
    for (name, message) in [
        ("empty", String::new()),
        ("binary", "00ff80".into()),
        ("long", "a5".repeat(257)),
    ] {
        capture.case(
            &format!("root-v2-sign-{name}"),
            "root-key.sign-v2",
            json!({"key_hex":key,"passphrase_hex":passphrase,"message_hex":message}),
            None,
            Some(public),
        )?;
    }
    for (name, password) in [
        ("empty", String::new()),
        ("unicode", hex::encode("päss🔐e\u{301}")),
        ("binary", "0000ff80".into()),
    ] {
        let value = capture.case(
            &format!("root-v2-create-{name}"),
            "root-key.create-v2",
            json!({"master_key_hex":master,"passphrase_hex":password,"randomness":"counter-v1"}),
            None,
            Some(public),
        )?;
        capture.case(
            &format!("root-v2-check-{name}"),
            "root-key.check-v2",
            json!({"key_hex":value["result"]["key_hex"],"passphrase_hex":password}),
            None,
            None,
        )?;
    }
    let changed = capture.case("root-change-passphrase", "root-key.change-v2", json!({"key_hex":key,"old_passphrase_hex":passphrase,"new_passphrase_hex":"00ff","randomness":"counter-v1"}), None, Some(public))?;
    capture.case(
        "root-v2-changed-new-passphrase",
        "root-key.check-v2",
        json!({"key_hex":changed["result"]["key_hex"],"passphrase_hex":"00ff"}),
        None,
        None,
    )?;
    capture.case(
        "root-v2-changed-old-rejected",
        "root-key.check-v2",
        json!({"key_hex":changed["result"]["key_hex"],"passphrase_hex":passphrase}),
        Some("XPrvAuthenticationFailed"),
        None,
    )?;
    let rotated_signature = capture.case("root-v2-changed-signature", "root-key.sign-v2", json!({"key_hex":changed["result"]["key_hex"],"passphrase_hex":"00ff","message_hex":"00ff80"}), None, Some(public))?;
    ensure!(
        capture
            .vectors
            .iter()
            .find(|v| v.id == "root-v2-sign-binary")
            .and_then(|v| v.expected.as_ref())
            == Some(&rotated_signature),
        "passphrase rotation changed deterministic signature"
    );
    let unchanged = capture.case("root-v2-change-same-passphrase", "root-key.change-v2", json!({"key_hex":key,"old_passphrase_hex":passphrase,"new_passphrase_hex":passphrase,"randomness":"counter-v1"}), None, Some(public))?;
    ensure!(
        unchanged == created,
        "same-passphrase deterministic rewrap differs"
    );
    let child = keys
        .iter()
        .find(|v| v.id == "haskell-Shelley-0-0-0-private")
        .context("missing child golden")?
        .expected
        .as_ref()
        .context("missing child result")?;
    let child_public = child["result"]["xpub_hex"]
        .as_str()
        .context("missing child public key")?;
    let derived = capture.case("root-v2-derived-address-key", "root-key.derive-v2", json!({"key_hex":key,"passphrase_hex":passphrase,"path":[2147485500u32,2147485463u32,2147483648u32,0,0],"randomness":"counter-v1"}), None, Some(child_public))?;
    capture.case("root-v2-derived-signature", "root-key.sign-v2", json!({"key_hex":derived["result"]["key_hex"],"passphrase_hex":passphrase,"message_hex":"00ff80"}), None, Some(child_public))?;
    let max_child = keys
        .iter()
        .find(|v| v.id == "haskell-Shelley-2147483647-2-2147483647-private")
        .context("missing maximum-index child golden")?
        .expected
        .as_ref()
        .context("missing maximum-index child result")?;
    capture.case("root-v2-derived-maximum-index", "root-key.derive-v2", json!({"key_hex":key,"passphrase_hex":passphrase,"path":[2147485500u32,2147485463u32,4294967295u32,2,2147483647u32],"randomness":"counter-v1"}), None, max_child["result"]["xpub_hex"].as_str())?;
    for (index, name) in [
        (0, "salt"),
        (1, "nonce"),
        (2, "aad"),
        (3, "ciphertext"),
        (4, "tag"),
    ] {
        let mut modified = parts.clone();
        if index == 2 {
            let last = modified[index].len() - 1;
            modified[index][last] ^= 1;
        } else {
            modified[index][0] ^= 1;
        }
        capture.case(
            &if index == 3 {
                "root-ciphertext-tamper".into()
            } else {
                format!("root-v2-tamper-{name}")
            },
            "root-key.check-v2",
            json!({"key_hex":hex::encode(root_envelope(&modified)?),"passphrase_hex":passphrase}),
            Some("XPrvAuthenticationFailed"),
            None,
        )?;
        modified[index] = modified[index][1..].to_vec();
        capture.case(
            &format!("root-v2-short-{name}"),
            "root-key.parse",
            json!({"key_hex":hex::encode(root_envelope(&modified)?)}),
            Some("XPrvDecodeError"),
            None,
        )?;
    }
    // Preserve eight encoded AAD fields so each invalid parameter is isolated.
    let aad = &parts[2];
    let mut d = minicbor::Decoder::new(aad);
    ensure!(d.array()? == Some(8), "unexpected root AAD");
    let fields = (0..8)
        .map(|_| {
            let start = d.position();
            d.skip()?;
            Ok(aad[start..d.position()].to_vec())
        })
        .collect::<Result<Vec<_>>>()?;
    for index in [6, 7] {
        let mut changed = parts.clone();
        let mut altered = vec![0x88];
        for (i, field) in fields.iter().enumerate() {
            let mut field = field.clone();
            if i == index {
                let end = field.len() - 1;
                field[end] ^= 1;
            }
            altered.extend(field);
        }
        changed[2] = altered;
        capture.case(
            &format!("root-v2-tamper-aad-key-{index}"),
            "root-key.check-v2",
            json!({"key_hex":hex::encode(root_envelope(&changed)?),"passphrase_hex":passphrase}),
            Some("XPrvAuthenticationFailed"),
            None,
        )?;
    }
    // cborg's ordinary (non-Canonical) decoders accept overlong list lengths.
    let mut overlong_outer = vec![0x98, 5];
    overlong_outer.extend_from_slice(&encoded[1..]);
    let mut overlong_aad = parts.clone();
    overlong_aad[2] = [vec![0x98, 8], parts[2][1..].to_vec()].concat();
    for (name, bytes) in [
        ("outer", overlong_outer),
        ("aad", root_envelope(&overlong_aad)?),
    ] {
        capture.case(
            &format!("root-v2-overlong-{name}-parse"),
            "root-key.parse",
            json!({"key_hex":hex::encode(&bytes)}),
            None,
            Some(public),
        )?;
        capture.case(
            &format!("root-v2-overlong-{name}-auth"),
            "root-key.check-v2",
            json!({"key_hex":hex::encode(bytes),"passphrase_hex":passphrase}),
            None,
            None,
        )?;
    }
    for index in 0..8 {
        let mut replacement = minicbor::Encoder::new(Vec::new());
        match index {
            2 => {
                replacement.array(4)?.u32(4096)?.u8(1)?.u8(1)?.u8(32)?;
            }
            6 | 7 => {
                replacement.bytes(&[0; 31])?;
            }
            _ => {
                replacement.u16(999)?;
            }
        }
        let mut altered = vec![0x88];
        for (i, field) in fields.iter().enumerate() {
            altered.extend(if i == index {
                replacement.writer()
            } else {
                field
            });
        }
        let mut changed = parts.clone();
        changed[2] = altered;
        capture.case(
            &format!("root-v2-invalid-aad-field-{index}"),
            "root-key.parse",
            json!({"key_hex":hex::encode(root_envelope(&changed)?)}),
            Some("XPrvDecodeError"),
            None,
        )?;
    }
    for length in [0, 1, 127, 129, encoded.len() - 1] {
        let bytes = if length < encoded.len() {
            &encoded[..length]
        } else {
            &encoded
        };
        capture.case(
            &format!("root-v2-truncated-{length}"),
            "root-key.parse",
            json!({"key_hex":hex::encode(bytes)}),
            Some("XPrvDecodeError"),
            None,
        )?;
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    capture.case(
        "root-v2-trailing-data",
        "root-key.parse",
        json!({"key_hex":hex::encode(trailing)}),
        Some("XPrvDecodeError"),
        None,
    )?;
    for length in [0, 32, 95, 97, 128] {
        capture.case(&format!("root-v2-invalid-master-{length}"), "root-key.create-v2", json!({"master_key_hex":"00".repeat(length),"passphrase_hex":"","randomness":"counter-v1"}), Some("XPrvInvalidSecretKey"), None)?;
    }
    let legacy: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/cardano-wallet.json"))?;
    let legacy_key = legacy[0]
        .expected
        .as_ref()
        .context("missing legacy golden")?["result"]["xprv_hex"]
        .as_str()
        .context("missing legacy bytes")?;
    capture.case(
        "root-v1-parse",
        "root-key.parse",
        json!({"key_hex":legacy_key}),
        None,
        None,
    )?;
    capture.case(
        "root-v1-not-a-v2-key",
        "root-key.check-v2",
        json!({"key_hex":legacy_key,"passphrase_hex":""}),
        Some("XPrvDecodeError"),
        None,
    )?;
    capture.case(
        "root-v1-zero-serialization-parses",
        "root-key.parse",
        json!({"key_hex":"00".repeat(128)}),
        None,
        Some(&"00".repeat(64)),
    )?;
    capture.case(
        "root-v2-prefix-128-classified-v1",
        "root-key.parse",
        json!({"key_hex":hex::encode(&encoded[..128])}),
        None,
        None,
    )?;
    Ok(capture.vectors)
}

fn call(binary: &Path, args: &[&str], input: &str) -> Result<String> {
    call_bytes(binary, args, input.as_bytes())
}

fn call_bytes(binary: &Path, args: &[&str], input: &[u8]) -> Result<String> {
    let mut child = Command::new(binary)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .context("oracle stdin")?
        .write_all(input)?;
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "pinned Haskell key oracle command failed"
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn raw(encoded: &str) -> Result<String> {
    Ok(hex::encode(encoding::bech32(encoded)?.1))
}

/// Capture a matrix of root, hardened account, soft role/index, public child and
/// address outputs using a SHA-256-pinned Haskell executable from the verified release.
pub fn capture_keys(binary: &Path) -> Result<Vec<Vector>> {
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(binary)?)) == ORACLE_SHA256,
        "key oracle binary differs from the pinned cardano-address 4.0.2 release executable"
    );
    let source = format!(
        "Haskell cardano-address 4.0.2 from cardano-wallet v2026-09-16; binary sha256:{ORACLE_SHA256}; release archive sha256:318ca7e1b8d49249aeee0a6ee9dff92c095ae1ad5279133b4b70e8f3b39dbfb5"
    );
    let mut vectors = Vec::new();
    for (style, purpose) in [
        ("Shelley", 1852),
        ("Icarus", 44),
        ("Shared", 1854),
        ("Byron", 44),
    ] {
        let entropy = vec![0; if style == "Byron" { 16 } else { 20 }];
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)?.to_string();
        let root = call(binary, &["key", "from-recovery-phrase", style], &mnemonic)?;
        let root_public = call(binary, &["key", "public", "--with-chain-code"], &root)?;
        let requirement = match style {
            "Shelley" => "crypto.shelley-root",
            "Icarus" => "crypto.icarus-root",
            "Byron" => "crypto.byron-root",
            _ => "crypto.shared-root",
        };
        vectors.push(Vector {
            id: format!("haskell-{style}-root"),
            requirements: vec![requirement.into()],
            source: source.clone(),
            operation: "keys.derive".into(),
            input: json!({"style":style,"mnemonic":mnemonic,"path":[],"second_factor_hex":""}),
            expected: Some(
                json!({"result":{"xprv_hex":raw(&root)?,"xpub_hex":raw(&root_public)?}}),
            ),
            selection_invariants: false,
        });
        if style == "Byron" {
            for index in [0u32, 1, 0x7fff_ffff] {
                let path = format!("{index}H/{index}H");
                let child = call(binary, &["key", "child", &path], &root)?;
                let public = call(binary, &["key", "public", "--with-chain-code"], &child)?;
                vectors.push(Vector {
                    id:format!("haskell-{style}-child-{index}"),requirements:vec!["crypto.derivation-boundaries".into()],source:source.clone(),operation:"keys.derive".into(),
                    input:json!({"style":style,"mnemonic":mnemonic,"path":[index|0x8000_0000,index|0x8000_0000],"second_factor_hex":""}),
                    expected:Some(json!({"result":{"xprv_hex":raw(&child)?,"xpub_hex":raw(&public)?}})),selection_invariants:false,
                });
            }
            continue;
        }
        for account in [0u32, 0x7fff_ffff] {
            let account_path = format!("{purpose}H/1815H/{account}H");
            let account_private = call(binary, &["key", "child", &account_path], &root)?;
            let account_public = call(
                binary,
                &["key", "public", "--with-chain-code"],
                &account_private,
            )?;
            for role in [0u32, 1, 2] {
                for index in [0u32, 19, 0x7fff_ffff] {
                    let soft_path = format!("{role}/{index}");
                    let private = call(binary, &["key", "child", &soft_path], &account_private)?;
                    let public = call(binary, &["key", "public", "--with-chain-code"], &private)?;
                    let public_child =
                        call(binary, &["key", "child", &soft_path], &account_public)?;
                    ensure!(
                        raw(&public)? == raw(&public_child)?,
                        "Haskell public/private derivation disagrees"
                    );
                    let label = format!("haskell-{style}-{account}-{role}-{index}");
                    vectors.push(Vector {
                        id:format!("{label}-private"),requirements:vec!["crypto.derivation-boundaries".into()],source:source.clone(),operation:"keys.derive".into(),
                        input:json!({"style":style,"mnemonic":mnemonic,"path":[(purpose as u32)|0x8000_0000,1815u32|0x8000_0000,account|0x8000_0000,role,index],"second_factor_hex":""}),
                        expected:Some(json!({"result":{"xprv_hex":raw(&private)?,"xpub_hex":raw(&public)?}})),selection_invariants:false,
                    });
                    vectors.push(Vector {
                        id:format!("{label}-public"),requirements:vec!["crypto.public-private-derivation".into()],source:source.clone(),operation:"keys.derive-public".into(),
                        input:json!({"style":style,"parent_xpub_hex":raw(&account_public)?,"path":[role,index]}),
                        expected:Some(json!({"result":{"xpub_hex":raw(&public_child)?}})),selection_invariants:false,
                    });
                    if style == "Shelley" && role == 0 && account == 0 {
                        for network in [0u8, 1] {
                            let tag = network.to_string();
                            let address = call(
                                binary,
                                &["address", "payment", "--network-tag", &tag],
                                &public,
                            )?;
                            let raw_address = encoding::bech32(&address)?.1;
                            let public_bytes = encoding::bech32(&public)?.1;
                            ensure!(
                                public_bytes.len() == 64,
                                "invalid extended public key from oracle"
                            );
                            ensure!(
                                raw_address.len() == 29 && raw_address[0] == (0x60 | network),
                                "invalid enterprise address from oracle"
                            );
                            ensure!(
                                raw_address[1..] == transaction::blake2b(&public_bytes[..32], 28)?,
                                "address credential differs from independent key hash"
                            );
                            vectors.push(Vector {
                                id:format!("{label}-enterprise-{network}"),requirements:vec!["address.shelley".into(),"address.network".into(),"address.encoding".into()],source:source.clone(),operation:"address.enterprise".into(),
                                input:json!({"public_key_hex":hex::encode(&public_bytes[..32]),"network_tag":network}),
                                expected:Some(json!({"result":{"address":address,"address_hex":hex::encode(raw_address)}})),selection_invariants:false,
                            });
                        }
                    }
                }
            }
        }
    }
    let mnemonic = "vintage poem topic machine hazard cement dune glimpse fix brief account badge mass silly business";
    let root = call(
        binary,
        &["key", "from-recovery-phrase", "Shelley"],
        mnemonic,
    )?;
    let private = call(binary, &["key", "child", "1852H/1815H/0H/2/0"], &root)?;
    let public = call(binary, &["key", "public", "--without-chain-code"], &private)?;
    let signature = "680739414d89eb9f4377192171ce3990c7beea6132a04f327d7c954ae9e7fcfe747dd7b4b9b11acefa1aa75216b837fc81e59c24001b96356ba65598ec159d0c";
    let message = "1228cd0fea46f9a091172829f0c492c0516dceff67de08f585a4e048a28a6c9f";
    let pk: [u8; 32] = encoding::bech32(&public)?
        .1
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid metadata signing public key"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&pk)?
        .verify_strict(
            &hex::decode(message)?,
            &ed25519_dalek::Signature::from_slice(&hex::decode(signature)?)?,
        )
        .context("pinned Haskell metadata signature golden failed independent verification")?;
    vectors.push(Vector {
        id:"haskell-extended-signature-metadata".into(),requirements:vec!["crypto.extended-ed25519".into()],
        source:format!("{source}; signature from cardano-wallet 2fc5c383c94bb907deaa0cd27b1b407f86224b6c lib/integration/scenarios/Test/Integration/Scenario/API/Shelley/Wallets.hs WALLETS_SIGNATURES_01"),
        operation:"keys.sign-extended".into(),input:json!({"xprv_hex":raw(&private)?,"message_hex":message}),
        expected:Some(json!({"result":{"public_key_hex":hex::encode(pk),"signature_hex":signature}})),selection_invariants:false,
    });
    Ok(vectors)
}

pub fn capture_primitives(openssl: &Path, cardano_cli: &Path) -> Result<Vec<Vector>> {
    const OPENSSL_HASH: &str = "2109b64903b9af91f467d2c7a98d9c45d1328ea4a2ce8d7fb43f9f1fb7d247a0";
    const CLI_HASH: &str = "aeda024fef9dc0c5533885a192dd3fced865727164591aabce95d401bbbaf0c8";
    for (binary, digest) in [(openssl, OPENSSL_HASH), (cardano_cli, CLI_HASH)] {
        ensure!(
            hex::encode(Sha256::digest(std::fs::read(binary)?)) == digest,
            "primitive oracle binary digest mismatch"
        );
    }
    let openssl_source = format!("Nix-pinned OpenSSL 3.6.2 binary sha256:{OPENSSL_HASH}; independent digest/PBKDF2 capture, never harness primitive outputs");
    let cli_source = format!("Haskell cardano-cli 11.2.1.0 binary sha256:{CLI_HASH}; hash anchor-data --file-binary /dev/stdin; Blake2b-256");
    let mut vectors = Vec::new();
    for length in [
        0usize, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 255, 256, 1024, 4096,
    ] {
        let bytes: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
        for (algorithm, option, requirements) in [
            (
                "sha256",
                "-sha256",
                vec!["crypto.sha256.basic", "crypto.hash-boundaries"],
            ),
            (
                "sha512",
                "-sha512",
                vec!["crypto.sha512.basic", "crypto.hash-boundaries"],
            ),
            ("blake2b512", "-blake2b512", vec!["crypto.hash-boundaries"]),
            (
                "blake2b256",
                "",
                vec!["crypto.blake2b-256.basic", "crypto.hash-boundaries"],
            ),
        ] {
            let (digest, source) = if algorithm == "blake2b256" {
                (
                    call_bytes(
                        cardano_cli,
                        &["hash", "anchor-data", "--file-binary", "/dev/stdin"],
                        &bytes,
                    )?,
                    &cli_source,
                )
            } else {
                let result = call_bytes(openssl, &["dgst", option], &bytes)?;
                (
                    result
                        .split_whitespace()
                        .last()
                        .context("missing digest output")?
                        .to_string(),
                    &openssl_source,
                )
            };
            let expected_bytes = if algorithm == "sha256" || algorithm == "blake2b256" {
                32
            } else {
                64
            };
            ensure!(
                hex::decode(&digest)?.len() == expected_bytes,
                "invalid oracle digest size"
            );
            let mut input = json!({"message_hex":hex::encode(&bytes)});
            let operation = if algorithm.starts_with("blake2b") {
                input["output_bytes"] = json!(expected_bytes);
                "blake2b"
            } else {
                algorithm
            };
            vectors.push(Vector {
                id: format!("boundary-{algorithm}-{length}"),
                requirements: requirements.into_iter().map(str::to_owned).collect(),
                source: source.clone(),
                operation: operation.into(),
                input,
                expected: Some(json!({"result":{"hex":digest.to_lowercase()}})),
                selection_invariants: false,
            });
        }
    }
    for (id, operation, input) in [
        ("hash-malformed-hex", "sha256", json!({"message_hex":"0g"})),
        ("hash-odd-hex", "sha512", json!({"message_hex":"0"})),
        (
            "blake2b-zero-length",
            "blake2b",
            json!({"message_hex":"","output_bytes":0}),
        ),
        (
            "blake2b-oversize",
            "blake2b",
            json!({"message_hex":"","output_bytes":65}),
        ),
        (
            "blake2b-negative-length",
            "blake2b",
            json!({"message_hex":"","output_bytes":-1}),
        ),
    ] {
        vectors.push(Vector {
            id: id.into(),
            requirements: vec!["crypto.hash-boundaries".into()],
            source: "Adapter v1 hexadecimal and BLAKE2 parameter validation contract".into(),
            operation: operation.into(),
            input,
            expected: Some(json!({"error":{"code":"invalid_input"}})),
            selection_invariants: false,
        });
    }
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let password = format!("hexpass:{}", hex::encode(mnemonic));
    let salt = format!("hexsalt:{}", hex::encode("mnemonice\u{301}"));
    let seed = call(
        openssl,
        &[
            "kdf",
            "-keylen",
            "64",
            "-kdfopt",
            "digest:SHA512",
            "-kdfopt",
            "iter:2048",
            "-kdfopt",
            &password,
            "-kdfopt",
            &salt,
            "PBKDF2",
        ],
        "",
    )?
    .replace([':', '\n', '\r'], "")
    .to_lowercase();
    ensure!(
        hex::decode(&seed)?.len() == 64,
        "invalid PBKDF2 seed output"
    );
    for (id, passphrase) in [
        ("bip39-unicode-composed", "\u{e9}"),
        ("bip39-unicode-decomposed", "e\u{301}"),
    ] {
        vectors.push(Vector {
            id: id.into(),
            requirements: vec!["crypto.bip39.seed".into()],
            source: format!(
                "{openssl_source}; BIP39 NFKD e+U+0301 salt, 2048 iterations HMAC-SHA512"
            ),
            operation: "bip39.to-seed".into(),
            input: json!({"mnemonic":mnemonic,"passphrase":passphrase}),
            expected: Some(json!({"result":{"seed_hex":seed}})),
            selection_invariants: false,
        });
    }
    Ok(vectors)
}

/// Capture actual Haskell component outputs only after checking the source-built
/// reference binary. Independent Rust laws reject malformed successful answers.
pub fn capture_selections(oracle: &Path) -> Result<Vec<Vector>> {
    use crate::adapter::{self, HaskellSelectionInput, Selection};
    use std::time::Duration;
    const ORACLE: &str = "2f9dc7dece467de7e52f9d6d0cccf1c0989e0ad25b23bb456aacefe0decadb44";
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(oracle)?)) == ORACLE,
        "selection oracle binary differs from the pinned source-built Haskell driver"
    );
    let source = format!("Haskell cardano-coin-selection 176611048d5b9f33df19d106cd925d63a7858bb2 Balance.performSelection, source-built oracle sha256:{ORACLE}; driver source sha256:d5733b541d0d219473da3708a4b0b8c0cfd4843796a7b04c0ffe845870989aea; wallet source 2fc5c383c94bb907deaa0cd27b1b407f86224b6c; random 1.3.1, MonadRandom 0.6.2.1, mkStdGen signed 64-bit; constant minimum-fee/minimum-ADA and asset-count bundle-size callbacks");
    let mut vectors = Vec::new();
    for (mut vector, expected_error) in crate::generate::haskell_selection_requests() {
        let actual = adapter::invoke(oracle, &[], &vector, Duration::from_secs(30))?;
        let replay = adapter::invoke(oracle, &[], &vector, Duration::from_secs(30))?;
        ensure!(
            actual == replay,
            "Haskell seeded selection failed deterministic replay: {}",
            vector.id
        );
        if let Some(result) = actual.get("result") {
            ensure!(
                !expected_error,
                "Haskell unexpectedly selected an impossible fixture: {}",
                vector.id
            );
            let input: HaskellSelectionInput = serde_json::from_value(vector.input.clone())?;
            let selection: Selection = serde_json::from_value(result.clone())?;
            adapter::validate_haskell_selection(&input, &selection)
                .with_context(|| format!("Haskell capture invariant in {}", vector.id))?;
        } else {
            ensure!(
                expected_error,
                "Haskell failed a satisfiable capture fixture: {}",
                vector.id
            );
            ensure!(
                [
                    "empty_utxo",
                    "balance_insufficient",
                    "unable_to_construct_change"
                ]
                .contains(&actual["error"]["code"].as_str().unwrap_or("")),
                "unexpected Haskell selection error class: {}",
                vector.id
            );
        }
        vector.source = source.clone();
        vector.expected = Some(actual);
        vectors.push(vector);
    }
    Ok(vectors)
}
