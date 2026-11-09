//! Pinned-source key boundary capture and independent result checks.
use crate::adapter::{self, Vector};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};

/// Record executable identity without requiring reproducible compiler/linker output.
pub fn oracle_sha256(binary: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(std::fs::read(binary)?)))
}

/// Actual-Haskell public derivation; callers independently check the address credentials.
pub fn derive_public(
    binary: &Path,
    parent: &[u8],
    path: &[u32],
    timeout: Duration,
) -> Result<Vec<u8>> {
    ensure!(
        parent.len() == 64 && path.len() <= 5 && path.iter().all(|index| *index < 0x80000000),
        "invalid live public derivation key/path"
    );
    let digest = oracle_sha256(binary)?;
    let vector = Vector {
        id: "live-account-public-derivation".into(),
        requirements: Vec::new(),
        source: format!("actual Haskell key adapter sha256:{digest}"),
        operation: "keys.derive-public".into(),
        input: json!({"style":"Shelley","parent_xpub_hex":hex::encode(parent),"path":path}),
        expected: None,
        selection_invariants: false,
    };
    let result = adapter::invoke(binary, &[], &vector, timeout)?;
    ensure!(
        oracle_sha256(binary)? == digest,
        "key adapter changed during public derivation"
    );
    validate(&vector, &result)?;
    let public = hex::decode(
        result
            .pointer("/result/xpub_hex")
            .and_then(Value::as_str)
            .context("actual Haskell public derivation did not return an extended key")?,
    )?;
    ensure!(
        public.len() == 64,
        "actual Haskell public derivation returned a malformed key"
    );
    Ok(public)
}

pub fn validate(vector: &Vector, actual: &Value) -> Result<()> {
    let Some(result) = actual.get("result") else {
        return Ok(());
    };
    match vector.operation.as_str() {
        "keys.derive" | "keys.derive-public" => {
            let public = hex::decode(
                result["xpub_hex"]
                    .as_str()
                    .context("missing extended public key")?,
            )?;
            ensure!(public.len() == 64, "invalid extended public key length");
            let point: [u8; 32] = public[..32].try_into()?;
            ed25519_dalek::VerifyingKey::from_bytes(&point)?;
            if vector.operation == "keys.derive" {
                let private = hex::decode(
                    result["xprv_hex"]
                        .as_str()
                        .context("missing extended private key")?,
                )?;
                ensure!(private.len() == 96, "invalid extended private key length");
                ensure!(
                    private[64..] == public[32..],
                    "private/public chain codes disagree"
                );
            }
        }
        "keys.sign-extended" => {
            let public: [u8; 32] = hex::decode(
                result["public_key_hex"]
                    .as_str()
                    .context("missing signing public key")?,
            )?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signing key length"))?;
            let signature = hex::decode(
                result["signature_hex"]
                    .as_str()
                    .context("missing signature")?,
            )?;
            let message = hex::decode(
                vector.input["message_hex"]
                    .as_str()
                    .context("missing message")?,
            )?;
            ed25519_dalek::VerifyingKey::from_bytes(&public)?
                .verify_strict(&message, &ed25519_dalek::Signature::from_slice(&signature)?)?;
        }
        "byron.generate-root" => {
            let private = hex::decode(
                result["xprv_hex"]
                    .as_str()
                    .context("missing legacy private key")?,
            )?;
            ensure!(private.len() == 128, "invalid legacy private key length");
        }
        _ => {}
    }
    Ok(())
}

pub fn requests() -> Result<Vec<Vector>> {
    let keys: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/haskell-keys.json"))?;
    let roots: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/cardano-wallet.json"))?;
    let mut vectors = Vec::new();
    let mut add =
        |id: &str, requirement: &str, operation: &str, input: Value, expected: Option<Value>| {
            vectors.push(Vector {
                id: id.into(),
                requirements: vec![requirement.into()],
                source: "Pending pinned-source key capture".into(),
                operation: operation.into(),
                input,
                expected,
                selection_invariants: false,
            });
        };
    for (style, id, requirement) in [
        ("Shelley", "shelley-invalid-mnemonic", "crypto.shelley-root"),
        (
            "Shared",
            "shared-root-invalid-mnemonic",
            "crypto.shared-root",
        ),
        ("Icarus", "icarus-invalid-mnemonic", "crypto.icarus-root"),
        (
            "Byron",
            "byron-root-malformed-mnemonic",
            "crypto.byron-root",
        ),
    ] {
        add(
            id,
            requirement,
            "keys.derive",
            json!({"style":style,"mnemonic":"abandon ".repeat(12).trim(),"second_factor_hex":"","path":[]}),
            Some(json!({"error":{"code":"invalid_input"}})),
        );
    }
    let root = keys
        .iter()
        .find(|v| v.id == "haskell-Shelley-root")
        .context("missing root golden")?;
    for (id, path) in [
        ("derive-index-overflow-rejected", json!([4294967296u64])),
        ("derive-negative-index-rejected", json!([-1])),
        ("derive-fractional-index-rejected", json!([0.5])),
        (
            "derive-invalid-role-rejected",
            json!([2147485500u64, 2147485463u64, 2147483648u64, 3, 0]),
        ),
        ("derive-invalid-path-rejected", json!([0, 1, 2, 3, 4, 5])),
    ] {
        let mut input = root.input.clone();
        input["path"] = path;
        add(
            id,
            "crypto.derivation-boundaries",
            "keys.derive",
            input,
            Some(json!({"error":{"code":"invalid_input"}})),
        );
    }
    let public = keys
        .iter()
        .find(|v| v.operation == "keys.derive-public")
        .context("missing public golden")?;
    for (id, field, value) in [
        (
            "derive-hardened-from-public-rejected",
            "path",
            json!([2147483648u64]),
        ),
        (
            "derive-public-overflow-rejected",
            "path",
            json!([4294967296u64]),
        ),
        (
            "derive-public-malformed-key-rejected",
            "parent_xpub_hex",
            json!("00"),
        ),
    ] {
        let mut input = public.input.clone();
        input[field] = value;
        add(
            id,
            "crypto.derivation-boundaries",
            "keys.derive-public",
            input,
            Some(json!({"error":{"code":"invalid_input"}})),
        );
    }
    let signing = keys
        .iter()
        .find(|v| v.operation == "keys.sign-extended")
        .context("missing signing golden")?;
    for (id, field, value, expected) in [
        ("extended-sign-empty", "message_hex", json!(""), None),
        (
            "extended-sign-long",
            "message_hex",
            json!("a5".repeat(4097)),
            None,
        ),
        (
            "extended-sign-malformed-key",
            "xprv_hex",
            json!("00"),
            Some(json!({"error":{"code":"invalid_input"}})),
        ),
    ] {
        let mut input = signing.input.clone();
        input[field] = value;
        add(
            id,
            "crypto.extended-ed25519",
            "keys.sign-extended",
            input,
            expected,
        );
    }
    let mut input = roots
        .iter()
        .find(|v| v.id == "byron-root-no-passphrase")
        .context("missing Byron golden")?
        .input
        .clone();
    input["encryption_passphrase_hex"] =
        json!("4a87f05fe25a57c96ff5221863e61b91bcca566b853b616f55e5d2c18caa1a4c");
    add(
        "byron-root-encrypted",
        "crypto.byron-root",
        "byron.generate-root",
        input,
        Some(
            json!({"result":{"xprv_hex":"b842ae13cbb31b7d96910472bbed5c8729c764d66af81b48120a6a583eae55faf78c24765e0c9826f4d095f3e6addb4bda68df322b220d3c08b8a5b414232d101258854ab44b0cfda59bd68fbd87f280841a390068049df0f8a903c94ba65b7aa4762129a6c83acfda5b257eaeb73ec5fee1518b6674fdc7891fe23f06174421"}}),
        ),
    );
    Ok(vectors)
}

pub fn capture(binary: &Path) -> Result<Vec<Vector>> {
    let digest = oracle_sha256(binary)?;
    let mut vectors = requests()?;
    for vector in &mut vectors {
        let actual = adapter::invoke(binary, &[], vector, Duration::from_secs(30))?;
        ensure!(
            actual == adapter::invoke(binary, &[], vector, Duration::from_secs(30))?,
            "key oracle is not reproducible"
        );
        ensure!(
            oracle_sha256(binary)? == digest,
            "key adapter changed during capture"
        );
        validate(vector, &actual)?;
        if let Some(expected) = &vector.expected {
            ensure!(
                &actual == expected,
                "key boundary disagrees with independently specified expectation"
            );
        }
        if vector.operation == "keys.sign-extended" && actual.get("result").is_some() {
            let keys: Vec<Vector> =
                serde_json::from_str(include_str!("../fixtures/vectors/haskell-keys.json"))?;
            let golden = keys
                .iter()
                .find(|v| v.id == "haskell-extended-signature-metadata")
                .context("missing signature public key")?;
            ensure!(
                actual["result"]["public_key_hex"]
                    == golden
                        .expected
                        .as_ref()
                        .context("missing signature golden")?["result"]["public_key_hex"],
                "captured signature uses unexpected public key"
            );
        }
        vector.expected = Some(actual);
        vector.source = format!("Wallet source 2fc5c383c94bb907deaa0cd27b1b407f86224b6c; actual wallet root generators and cardano-addresses derivation/signing; reference/KeyAdapter.hs; binary sha256:{digest}; Byron encrypted root independently matches ByronSpec.hs generateTest2; strict Rust signature verification and pinned public-key cross-check");
    }
    Ok(vectors)
}

#[cfg(test)]
mod live_public_derivation_tests {
    use super::*;
    #[test]
    fn live_public_derivation_rejects_malformed_or_hardened_requests_before_execution() {
        let missing = Path::new("/deliberately-missing-public-derivation-oracle");
        for (parent, path) in [
            (vec![0; 63], vec![1, 0]),
            (vec![0; 64], vec![0x80000000]),
            (vec![0; 64], vec![0; 6]),
        ] {
            let error = derive_public(missing, &parent, &path, Duration::from_secs(1)).unwrap_err();
            assert!(error.to_string().contains("invalid live public derivation"));
        }
    }
    #[test]
    fn oracle_identity_records_rebuilt_bytes_without_a_historical_pin() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"first-build").unwrap();
        let first = oracle_sha256(file.path()).unwrap();
        assert_eq!(first, hex::encode(Sha256::digest(b"first-build")));
        std::fs::write(file.path(), b"rebuilt-helper").unwrap();
        let rebuilt = oracle_sha256(file.path()).unwrap();
        assert_eq!(rebuilt, hex::encode(Sha256::digest(b"rebuilt-helper")));
        assert_ne!(first, rebuilt);
    }
}
