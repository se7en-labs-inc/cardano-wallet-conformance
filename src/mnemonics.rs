//! Independent checks and capture templates for Haskell mnemonic/root profiles.
use crate::{
    adapter::{self, Vector},
    encoding, keys, transaction,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
const ORACLE: &str = "2b9c4740fde182225f7ccd47257b1a6681b50dc3da31ebc81cb03016bd2a86a1";

pub fn validate(vector: &Vector, actual: &Value) -> Result<()> {
    let Some(result) = actual.get("result") else {
        return Ok(());
    };
    match vector.operation.as_str() {
        "bip39.entropy-to-mnemonic" => {
            let mnemonic =
                bip39::Mnemonic::parse(result["mnemonic"].as_str().context("missing mnemonic")?)?;
            ensure!(
                hex::encode(mnemonic.to_entropy()) == vector.input["entropy_hex"],
                "mnemonic entropy does not round trip"
            );
        }
        "bip39.wallet-seed" | "bip39.to-seed" => {
            let mnemonic = bip39::Mnemonic::parse(
                vector.input["mnemonic"]
                    .as_str()
                    .context("missing mnemonic")?,
            )?;
            let password = vector.input["passphrase"]
                .as_str()
                .context("missing seed password")?;
            let seed = if vector.operation == "bip39.wallet-seed" {
                mnemonic.to_seed_normalized(password)
            } else {
                mnemonic.to_seed(password)
            };
            ensure!(
                result["seed_hex"] == hex::encode(seed),
                "raw wallet seed differs from independent PBKDF2 profile"
            );
        }
        "address.enterprise" => {
            let public = hex::decode(
                vector.input["public_key_hex"]
                    .as_str()
                    .context("missing public key")?,
            )?;
            ensure!(public.len() == 32, "invalid enterprise public key");
            let network = vector.input["network_tag"]
                .as_u64()
                .context("invalid network")?;
            ensure!(network < 16, "invalid network discriminant");
            let (hrp, address) =
                encoding::bech32(result["address"].as_str().context("missing address")?)?;
            ensure!(
                hrp == if network == 1 { "addr" } else { "addr_test" },
                "enterprise address HRP disagrees with network"
            );
            let mut expected = vec![0x60 | network as u8];
            expected.extend(transaction::blake2b(&public, 28)?);
            ensure!(
                address == expected && result["address_hex"] == hex::encode(&expected),
                "enterprise address credential or bytes disagree"
            );
        }
        "keys.generate-root-profile" => {
            let mut key = vector.clone();
            key.operation = "keys.derive".into();
            keys::validate(&key, actual)?;
            let public = hex::decode(
                result["xpub_hex"]
                    .as_str()
                    .context("missing root public key")?,
            )?;
            let private = hex::decode(
                result["encrypted_xprv_hex"]
                    .as_str()
                    .context("missing encrypted wallet root")?,
            )?;
            ensure!(private.len() == 128, "invalid encrypted root length");
            let mut signing = vector.clone();
            signing.operation = "keys.sign-extended".into();
            keys::validate(
                &signing,
                &json!({"result":{"public_key_hex":hex::encode(&public[..32]),"signature_hex":result["signature_hex"]}}),
            )?;
            if vector.input["path"]
                .as_array()
                .context("missing path")?
                .is_empty()
            {
                ensure!(
                    private[64..] == public[..],
                    "encrypted root public key/chain code changed"
                );
                if vector.input["encryption_passphrase_utf8"] == "" {
                    let raw =
                        hex::decode(result["xprv_hex"].as_str().context("missing root key")?)?;
                    ensure!(
                        private[..64] == raw[..64] && private[96..] == raw[64..],
                        "unencrypted wallet root serialization disagrees"
                    );
                }
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn requests() -> Result<Vec<Vector>> {
    let frozen: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/haskell-keys.json"))?;
    let mnemonic = frozen
        .iter()
        .find(|v| v.id == "haskell-Icarus-root")
        .context("missing independent root")?
        .input["mnemonic"]
        .clone();
    let mut vectors = Vec::new();
    let mut add = |id: &str, requirement: &str, operation: &str, input: Value| {
        vectors.push(Vector {
            id: id.into(),
            requirements: vec![requirement.into()],
            source: "Pending Haskell mnemonic capture".into(),
            operation: operation.into(),
            input,
            expected: None,
            selection_invariants: false,
        });
    };
    let profile = |style: &str, factor: &str, password: &str, path: Value| json!({"style":style,"mnemonic":mnemonic,"second_factor_hex":factor,"encryption_passphrase_utf8":password,"path":path,"message_hex":"00ff80"});
    for (style, id, requirement) in [
        ("Shelley", "shelley-second-factor", "crypto.shelley-root"),
        ("Shared", "shared-root-second-factor", "crypto.shared-root"),
        ("Icarus", "icarus-second-factor", "crypto.icarus-root"),
        ("Trezor", "trezor-root-second-factor", "crypto.trezor-root"),
    ] {
        add(
            id,
            requirement,
            "keys.generate-root-profile",
            profile(style, &"11".repeat(16), "", json!([])),
        );
    }
    for (style, prefix, requirement) in [
        ("Ledger", "ledger", "crypto.ledger-root"),
        ("Trezor", "trezor", "crypto.trezor-root"),
    ] {
        add(
            &format!("{prefix}-root-golden"),
            requirement,
            "keys.generate-root-profile",
            profile(style, "", "", json!([])),
        );
        add(
            &format!("{prefix}-child-golden"),
            requirement,
            "keys.generate-root-profile",
            profile(
                style,
                "",
                "",
                json!([2147483692u64, 2147485463u64, 2147483648u64, 0, 0]),
            ),
        );
    }
    add(
        "ledger-root-unicode",
        "crypto.ledger-root",
        "keys.generate-root-profile",
        profile("Ledger", "", "é🔐", json!([])),
    );
    add(
        "ledger-root-unicode-decomposed",
        "crypto.ledger-root",
        "keys.generate-root-profile",
        profile("Ledger", "", "e\u{301}🔐", json!([])),
    );
    for (id, password) in [
        ("wallet-seed-ascii", "TREZOR"),
        ("wallet-seed-unicode-composed", "é"),
        ("wallet-seed-unicode-decomposed", "e\u{301}"),
    ] {
        add(
            id,
            "crypto.bip39.seed",
            "bip39.wallet-seed",
            json!({"mnemonic":mnemonic,"passphrase":password}),
        );
    }
    Ok(vectors)
}

pub fn validate_relations(vectors: &[Vector]) -> Result<()> {
    let result = |id: &str| -> Result<&Value> {
        Ok(&vectors
            .iter()
            .find(|v| v.id == id)
            .context("missing related profile")?
            .expected
            .as_ref()
            .context("missing profile observation")?["result"])
    };
    let factor = result("shelley-second-factor")?;
    for id in [
        "shared-root-second-factor",
        "icarus-second-factor",
        "trezor-root-second-factor",
    ] {
        ensure!(
            result(id)?["xprv_hex"] == factor["xprv_hex"]
                && result(id)?["xpub_hex"] == factor["xpub_hex"],
            "equivalent component generation factors disagree"
        );
    }
    let frozen: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/haskell-keys.json"))?;
    for (id, golden) in [
        ("trezor-root-golden", "haskell-Icarus-root"),
        ("trezor-child-golden", "haskell-Icarus-0-0-0-private"),
    ] {
        let original = frozen
            .iter()
            .find(|v| v.id == golden)
            .context("missing independent Icarus golden")?
            .expected
            .as_ref()
            .context("missing Icarus observation")?;
        ensure!(
            result(id)?["xprv_hex"] == original["result"]["xprv_hex"]
                && result(id)?["xpub_hex"] == original["result"]["xpub_hex"],
            "wallet Trezor route differs from independently frozen Icarus keys"
        );
    }
    let plain = result("ledger-root-golden")?;
    for id in ["ledger-root-unicode", "ledger-root-unicode-decomposed"] {
        let encrypted = result(id)?;
        ensure!(
            plain["xprv_hex"] == encrypted["xprv_hex"]
                && plain["xpub_hex"] == encrypted["xpub_hex"],
            "wallet encryption password changed Ledger root identity"
        );
        ensure!(
            plain["encrypted_xprv_hex"] != encrypted["encrypted_xprv_hex"],
            "nonempty encryption password did not change stored root"
        );
    }
    ensure!(
        result("wallet-seed-unicode-composed")?["seed_hex"]
            != result("wallet-seed-unicode-decomposed")?["seed_hex"],
        "raw UTF-8 seed profile unexpectedly normalized Unicode"
    );
    Ok(())
}

pub fn capture(binary: &Path) -> Result<Vec<Vector>> {
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(binary)?)) == ORACLE,
        "mnemonic adapter differs from pinned source-built oracle"
    );
    let mut vectors = requests()?;
    for vector in &mut vectors {
        let actual = adapter::invoke(binary, &[], vector, Duration::from_secs(30))?;
        ensure!(
            actual.get("result").is_some(),
            "valid mnemonic/root profile failed"
        );
        ensure!(
            actual == adapter::invoke(binary, &[], vector, Duration::from_secs(30))?,
            "mnemonic oracle failed replay"
        );
        validate(vector, &actual)?;
        vector.expected = Some(actual);
        vector.source=format!("Wallet2fc5c383c94bb907deaa0cd27b1b407f86224b6c; Cardano.Mnemonic, Crypto.Encoding.BIP39 raw UTF-8, actual wallet Ledger/Icarus and cardano-address factor helpers; oracle sha256:{ORACLE}; signatures and profile relations independently checked in Rust");
    }
    validate_relations(&vectors)?;
    Ok(vectors)
}
