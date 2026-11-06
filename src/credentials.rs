//! Actual-wallet credential transition capture and independent observable laws.
use crate::adapter::{self, Vector};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};

const ORACLE: &str = "f63e63025466f42461010c8dab590378309363524a9bdca0370b51d18a912fbe";
const OLD: &str = "conformance-old-password";
const NEW: &str = "conformance-new-password";
const WRONG: &str = "wrong-password";

fn unlock(password: &str, callback_error: bool) -> Value {
    json!({"type":"unlock","passphrase_utf8":password,"callback_error":callback_error})
}

fn change(old: &str, new: &str) -> Value {
    json!({"type":"change","old_passphrase_utf8":old,"new_passphrase_utf8":new})
}

pub fn requests() -> Result<Vec<Vector>> {
    let keys: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/haskell-keys.json"))?;
    let mut vectors = Vec::new();
    for (flavor, style) in [
        ("shelley", "Shelley"),
        ("shared", "Shared"),
        ("byron", "Byron"),
        ("icarus", "Icarus"),
    ] {
        let root = keys
            .iter()
            .find(|v| v.id == format!("haskell-{style}-root"))
            .context("missing root oracle fixture")?;
        let mnemonic: Vec<_> = root.input["mnemonic"]
            .as_str()
            .context("missing mnemonic")?
            .split_whitespace()
            .collect();
        let mut add = |id: String,
                       scheme: &str,
                       password: &str,
                       initial: &str,
                       actions: Vec<Value>| {
            vectors.push(Vector {
                id,
                requirements: vec!["crypto.root-key-encryption".into()],
                source: "Pending capture from actual pinned Haskell wallet/database functions".into(),
                operation: "wallet.credentials".into(),
                input: json!({"flavor":flavor,"mnemonic":mnemonic,"scheme":scheme,"initial_format":initial,
                    "passphrase_utf8":password,"password_probes":[password,NEW,WRONG],"message_hex":"00ff80",
                    "randomness":"counter-v1","actions":actions}),
                expected: None,
                selection_invariants: false,
            });
        };
        for scheme in ["pbkdf2", "scrypt"] {
            for (name, password) in [
                ("nonempty", OLD),
                ("empty", ""),
                ("unicode", "päss🔐e\u{301}"),
            ] {
                let id = if flavor == "byron" && scheme == "scrypt" && name == "nonempty" {
                    "scrypt-migrate-pbkdf2".into()
                } else {
                    format!("credentials-{flavor}-{scheme}-{name}")
                };
                add(
                    id,
                    scheme,
                    password,
                    "v1",
                    vec![
                        unlock(WRONG, false),
                        unlock(password, false),
                        unlock(password, false),
                        change(WRONG, NEW),
                        change(password, NEW),
                        unlock(password, false),
                        unlock(NEW, false),
                    ],
                );
            }
            add(
                format!("credentials-{flavor}-{scheme}-callback-failure"),
                scheme,
                OLD,
                "v1",
                vec![unlock(OLD, true), unlock(OLD, false), unlock(WRONG, true)],
            );
            add(
                format!("credentials-{flavor}-{scheme}-same-password"),
                scheme,
                OLD,
                "v1",
                vec![change(OLD, OLD), unlock(OLD, false)],
            );
        }
        add(
            format!("credentials-{flavor}-normal-attachment"),
            "pbkdf2",
            OLD,
            "new",
            vec![
                unlock(OLD, false),
                unlock(WRONG, false),
                change(OLD, NEW),
                unlock(NEW, false),
            ],
        );
        add(
            format!("credentials-{flavor}-no-root-key"),
            "pbkdf2",
            OLD,
            "none",
            vec![unlock(OLD, false), change(OLD, NEW)],
        );
        if matches!(flavor, "shelley" | "shared") {
            for scheme in ["pbkdf2", "scrypt"] {
                for callback_error in [false, true] {
                    let mut first = unlock(OLD, callback_error);
                    first["fail_migration"] = json!(true);
                    let id = if flavor == "shelley" && scheme == "pbkdf2" && !callback_error {
                        "root-migration-failure-preserves-v1".to_owned()
                    } else {
                        format!("credentials-{flavor}-{scheme}-migration-failure-callback-{callback_error}")
                    };
                    add(
                        id,
                        scheme,
                        OLD,
                        "v1",
                        vec![first, unlock(OLD, false), unlock(OLD, false)],
                    );
                }
            }
        }
        if flavor == "shelley" {
            add("root-encrypt-v1".into(), "pbkdf2", OLD, "v1", vec![]);
            add(
                "root-decrypt-v1-correct".into(),
                "pbkdf2",
                OLD,
                "v1",
                vec![unlock(OLD, false)],
            );
            add(
                "root-decrypt-v1-wrong-passphrase".into(),
                "pbkdf2",
                OLD,
                "v1",
                vec![unlock(WRONG, false)],
            );
            add(
                "root-change-v1-passphrase".into(),
                "pbkdf2",
                OLD,
                "v1",
                vec![change(OLD, NEW), unlock(NEW, false)],
            );
            add(
                "root-migrate-v1-v2".into(),
                "scrypt",
                OLD,
                "v1",
                vec![unlock(OLD, false), unlock(OLD, false)],
            );
        }
    }
    vectors
        .iter_mut()
        .find(|v| v.id == "scrypt-migrate-pbkdf2")
        .context("missing legacy hash migration")?
        .requirements
        .push("crypto.passphrase-scrypt".into());
    Ok(vectors)
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .with_context(|| format!("missing credential field: {key}"))
}

fn root_public(flavor: &str, mnemonic: &Value) -> Result<String> {
    let style = match flavor {
        "shelley" => "Shelley",
        "shared" => "Shared",
        "byron" => "Byron",
        "icarus" => "Icarus",
        _ => anyhow::bail!("unknown credential flavor"),
    };
    let keys: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/haskell-keys.json"))?;
    let root = keys
        .iter()
        .find(|v| v.id == format!("haskell-{style}-root"))
        .context("missing public-key oracle")?;
    let words: Vec<_> = root.input["mnemonic"]
        .as_str()
        .context("missing oracle mnemonic")?
        .split_whitespace()
        .collect();
    ensure!(
        *mnemonic == json!(words),
        "credential mnemonic has no independent public-key oracle"
    );
    Ok(text(
        &root
            .expected
            .as_ref()
            .context("missing public-key result")?["result"],
        "xpub_hex",
    )?
    .into())
}

fn snapshot(
    value: &Value,
    format: &str,
    scheme: &str,
    password: &str,
    probes: &[Value],
    public: &str,
) -> Result<()> {
    ensure!(
        value["format"] == format,
        "incorrect persisted credential format"
    );
    ensure!(
        value["scheme"]
            == if format == "none" {
                Value::Null
            } else {
                json!(scheme)
            },
        "incorrect persisted credential scheme"
    );
    ensure!(
        value["password_hash_present"] == (format == "v1"),
        "incorrect credential hash presence"
    );
    let checks: Vec<_> = probes
        .iter()
        .map(|probe| json!(format != "none" && probe.as_str() == Some(password)))
        .collect();
    ensure!(
        value["password_checks"] == json!(checks),
        "credential password acceptance mismatch"
    );
    if format == "none" {
        ensure!(
            value["key_hex"].is_null() && value["xpub_hex"].is_null(),
            "missing-root state exposes key material"
        );
    } else {
        ensure!(
            value["xpub_hex"] == public,
            "credential public key differs from independent Haskell key golden"
        );
        let bytes = hex::decode(text(value, "key_hex")?)?;
        ensure!(
            (format == "v1" && bytes.len() == 128)
                || (format == "v2" && bytes.len() != 128 && bytes.len() > 128),
            "credential bytes do not match declared format"
        );
        if format == "v1" {
            ensure!(
                hex::encode(&bytes[64..]) == public,
                "legacy credential public-key serialization mismatch"
            );
        }
    }
    Ok(())
}

/// These laws assert expected outcomes and actual persisted state, in addition
/// to exact captured bytes. Successful migration precedes callback execution.
pub fn validate(vector: &Vector, actual: &Value) -> Result<()> {
    let input = &vector.input;
    let result = actual
        .get("result")
        .context("wallet credential operation failed")?;
    let flavor = text(input, "flavor")?;
    let modern = matches!(flavor, "shelley" | "shared");
    let public = root_public(flavor, &input["mnemonic"])?;
    let mut password = text(input, "passphrase_utf8")?;
    let mut format = match text(input, "initial_format")? {
        "none" => "none",
        "new" if modern => "v2",
        _ => "v1",
    };
    let mut scheme = if format == "v2" {
        "argon2id"
    } else {
        text(input, "scheme")?
    };
    let probes = input["password_probes"]
        .as_array()
        .context("missing password probes")?;
    let mut previous = &result["initial"];
    snapshot(previous, format, scheme, password, probes, &public)?;
    let actions = input["actions"]
        .as_array()
        .context("missing credential actions")?;
    let steps = result["steps"]
        .as_array()
        .context("missing credential observations")?;
    ensure!(
        steps.len() == actions.len(),
        "credential action/observation count mismatch"
    );
    let message = hex::decode(text(input, "message_hex")?)?;
    let key: [u8; 32] = hex::decode(&public)?[..32].try_into()?;
    let verifier = ed25519_dalek::VerifyingKey::from_bytes(&key)?;
    for (action, step) in actions.iter().zip(steps) {
        let change = text(action, "type")? == "change";
        let candidate = text(
            action,
            if change {
                "old_passphrase_utf8"
            } else {
                "passphrase_utf8"
            },
        )?;
        let authorized = format != "none" && candidate == password;
        let inject_failure = action["fail_migration"] == true;
        if inject_failure {
            ensure!(
                authorized && modern && format == "v1" && !change,
                "invalid migration fault precondition"
            );
            ensure!(step["migration_faults_consumed"] == 1 && step["migration_warnings"] == 1 && step["production_kdf_parameters"] == true, "migration fault or actual wallet warning was not observed under production parameters");
        } else {
            ensure!(
                [
                    "migration_faults_consumed",
                    "migration_warnings",
                    "production_kdf_parameters"
                ]
                .iter()
                .all(|field| step.get(*field).is_none()),
                "ordinary unlock claimed an unrequested migration fault"
            );
        }
        let migrating = authorized && modern && format == "v1" && !inject_failure;
        let callback_error = !change && action["callback_error"] == true;
        let expected_outcome = if format == "none" {
            "no_root_key"
        } else if !authorized {
            "wrong_passphrase"
        } else if callback_error {
            "action_failed"
        } else {
            "success"
        };
        ensure!(
            step["outcome"] == expected_outcome,
            "incorrect credential action outcome"
        );
        if authorized && !change {
            ensure!(
                step["callback"]["access"] == format,
                "callback observes wrong credential generation"
            );
            if !callback_error {
                ensure!(
                    step["callback"]["xpub_hex"] == public,
                    "callback public key mismatch"
                );
                let signature = hex::decode(text(&step["callback"], "signature_hex")?)?;
                verifier
                    .verify_strict(&message, &ed25519_dalek::Signature::from_slice(&signature)?)?;
            } else {
                ensure!(
                    step["callback"].get("signature_hex").is_none(),
                    "failing callback executed signing"
                );
            }
        } else {
            ensure!(
                step["callback"].is_null(),
                "unauthorized or change operation ran unlock callback"
            );
        }
        let changed = migrating || (authorized && change);
        let same_key = if authorized && change {
            !modern
                && text(action, "new_passphrase_utf8")? == password
                && (scheme == "pbkdf2" || password.is_empty())
        } else {
            !migrating
        };
        ensure!(
            step["credentials_unchanged"] == !changed && step["metadata_unchanged"] == !changed,
            "credential/metadata side effects mismatch"
        );
        ensure!(
            step["timestamp_unchanged"] == !(authorized && change),
            "credential timestamp changed unexpectedly"
        );
        ensure!(
            step["key_bytes_unchanged"] == same_key,
            "credential re-encryption behavior mismatch"
        );
        ensure!(
            (previous["key_hex"] == step["after"]["key_hex"]) == same_key,
            "claimed key-byte equality is false"
        );
        if migrating {
            format = "v2";
            scheme = "argon2id";
        }
        if authorized && change {
            password = text(action, "new_passphrase_utf8")?;
            format = if modern { "v2" } else { "v1" };
            scheme = if modern { "argon2id" } else { "pbkdf2" };
        }
        snapshot(&step["after"], format, scheme, password, probes, &public)?;
        previous = &step["after"];
    }
    Ok(())
}

pub fn capture(oracle: &Path) -> Result<Vec<Vector>> {
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(oracle)?)) == ORACLE,
        "credential oracle differs from the pinned Nix-built wallet reference adapter"
    );
    let source = format!("Actual Cardano.Wallet/SQLite credential transitions, wallet source 2fc5c383c94bb907deaa0cd27b1b407f86224b6c built through pinned Nix library; adapter sha256:f1e92df7df5967c3cb5e252fe74ffd05ad0bd267078e58905df12541c360f5e6; Rust fault shim sha256:97ccbdb4cf93109496c8f403f145d6c08f6dc64ff3f2e26e40fe9f74a2a05abc; executable sha256:{ORACLE}; production Argon2id; one-shot test-only backend fault when explicitly requested, ordinary calls delegate unchanged; counter-v1 test envelope entropy; actual password hash/key preparation and actual wallet warnings; independent cardano-address public keys and Rust strict signatures");
    let mut vectors = requests()?;
    for vector in &mut vectors {
        let actual = adapter::invoke(oracle, &[], vector, Duration::from_secs(120))?;
        validate(vector, &actual)
            .with_context(|| format!("wallet credential capture laws: {}", vector.id))?;
        ensure!(
            actual == adapter::invoke(oracle, &[], vector, Duration::from_secs(120))?,
            "credential capture failed deterministic replay: {}",
            vector.id
        );
        vector.source = source.clone();
        vector.expected = Some(actual);
    }
    Ok(vectors)
}
