//! Versioned internal adapter protocol, independent primitive vectors and selection invariants.
use crate::report::Report;
use anyhow::{anyhow, bail, ensure, Context, Result};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vector {
    pub id: String,
    pub requirements: Vec<String>,
    pub source: String,
    pub operation: String,
    pub input: Value,
    pub expected: Option<Value>,
    #[serde(default)]
    pub selection_invariants: bool,
}

fn bytes(input: &Value, key: &str) -> Result<Vec<u8>> {
    hex::decode(input[key].as_str().context("missing hex field")?)
        .context("invalid hexadecimal input")
}

/// Independent oracle for basic primitives only. It is not a replacement for the
/// Haskell wallet adapter and does not implement Cardano extended Ed25519 derivation.
pub fn primitive(operation: &str, input: &Value) -> Result<Value> {
    let result = (|| -> Result<Value> {
        Ok(match operation {
            "sha256" => json!({"hex": hex::encode(Sha256::digest(bytes(input, "message_hex")?))}),
            "sha512" => json!({"hex": hex::encode(Sha512::digest(bytes(input, "message_hex")?))}),
            "blake2b" => {
                let len = input["output_bytes"]
                    .as_u64()
                    .context("missing digest length")?;
                ensure!(len > 0 && len <= 64, "invalid digest length");
                let mut hasher = Blake2bVar::new(len as usize)?;
                hasher.update(&bytes(input, "message_hex")?);
                let mut output = vec![0; len as usize];
                hasher
                    .finalize_variable(&mut output)
                    .map_err(|_| anyhow!("digest output length"))?;
                json!({"hex": hex::encode(output)})
            }
            "ed25519.sign" => {
                let seed: [u8; 32] = bytes(input, "seed_hex")?
                    .try_into()
                    .map_err(|_| anyhow!("invalid seed length"))?;
                let key = SigningKey::from_bytes(&seed);
                json!({"public_key_hex": hex::encode(key.verifying_key().as_bytes()), "signature_hex": hex::encode(key.sign(&bytes(input, "message_hex")?).to_bytes())})
            }
            "ed25519.verify" => {
                let public: [u8; 32] = bytes(input, "public_key_hex")?
                    .try_into()
                    .map_err(|_| anyhow!("invalid public key length"))?;
                let signature = Signature::from_slice(&bytes(input, "signature_hex")?)?;
                let verified = VerifyingKey::from_bytes(&public)?
                    .verify_strict(&bytes(input, "message_hex")?, &signature)
                    .is_ok();
                json!({"valid": verified})
            }
            "bip39.entropy-to-mnemonic" => {
                let mnemonic = bip39::Mnemonic::from_entropy(&bytes(input, "entropy_hex")?)?;
                json!({"mnemonic": mnemonic.to_string()})
            }
            "bip39.to-seed" => {
                let mnemonic = bip39::Mnemonic::parse(
                    input["mnemonic"].as_str().context("missing mnemonic")?,
                )?;
                let passphrase = input["passphrase"]
                    .as_str()
                    .context("missing BIP39 passphrase")?;
                json!({"seed_hex": hex::encode(mnemonic.to_seed(passphrase))})
            }
            _ => bail!("unsupported primitive oracle operation"),
        })
    })();
    if operation.starts_with("ed25519.")
        || operation.starts_with("bip39.")
        || ["sha256", "sha512", "blake2b"].contains(&operation)
    {
        Ok(match result {
            Ok(value) => json!({"result": value}),
            Err(_) => json!({"error": {"code": "invalid_input"}}),
        })
    } else {
        result
    }
}

/// Run one adapter request without invoking a shell. Limit output and wall time;
/// diagnostics intentionally exclude adapter stderr and cryptographic material.
pub fn invoke(
    executable: &Path,
    args: &[String],
    vector: &Vector,
    timeout: Duration,
) -> Result<Value> {
    let mut child = Command::new(executable)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("cannot start internal adapter")?;
    let mut stdin = child.stdin.take().context("adapter stdin unavailable")?;
    let output = child.stdout.take().context("adapter stdout unavailable")?;
    let req = json!({"protocol_version":1,"id":vector.id,"operation":vector.operation,"input":vector.input});
    let input = serde_json::to_vec(&req)?;
    let (tx, rx) = mpsc::channel();
    // Concurrent bounded I/O prevents pipe deadlock when an adapter misbehaves.
    thread::spawn(move || {
        let result = (|| -> std::io::Result<Vec<u8>> {
            stdin.write_all(&input)?;
            stdin.write_all(b"\n")?;
            drop(stdin);
            let mut bytes = Vec::new();
            output.take(1_048_577).read_to_end(&mut bytes)?;
            Ok(bytes)
        })();
        let _ = tx.send(result);
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("internal adapter timed out");
        }
        thread::sleep(Duration::from_millis(10));
    };
    ensure!(status.success(), "internal adapter exited unsuccessfully");
    let bytes = rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .context("adapter output did not close")??;
    ensure!(bytes.len() <= 1_048_576, "adapter output exceeds 1 MiB");
    let mut response: Value =
        serde_json::from_slice(&bytes).context("adapter did not return one JSON object")?;
    ensure!(
        response["id"] == vector.id && response["protocol_version"] == 1,
        "adapter protocol/id mismatch"
    );
    let m = response
        .as_object_mut()
        .context("adapter response is not an object")?;
    m.remove("id");
    m.remove("protocol_version");
    ensure!(
        m.len() == 1 && (m.contains_key("result") || m.contains_key("error")),
        "adapter must return exactly one of result or error"
    );
    Ok(response)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub coin: u64,
    #[serde(default)]
    pub assets: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Utxo {
    pub id: String,
    pub value: Bundle,
    pub eligible: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionInput {
    pub utxos: Vec<Utxo>,
    pub outputs: Vec<Bundle>,
    pub fee: u64,
    pub minimum_change_coin: u64,
    pub maximum_inputs: usize,
    pub seed: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub inputs: Vec<String>,
    pub change: Vec<Bundle>,
    pub fee: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SelectionStrategy {
    Minimal,
    #[default]
    Optimal,
}

fn default_maximum_coin() -> u64 {
    45_000_000_000_000_000
}
fn default_maximum_token_quantity() -> u64 {
    i64::MAX as u64
}
fn default_maximum_assets() -> usize {
    32
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaskellSelectionInput {
    pub utxos: Vec<Utxo>,
    pub outputs: Vec<Bundle>,
    pub seed: u64,
    #[serde(default)]
    pub strategy: SelectionStrategy,
    pub minimum_fee: u64,
    pub minimum_change_coin: u64,
    #[serde(default = "default_maximum_coin")]
    pub maximum_output_coin: u64,
    #[serde(default = "default_maximum_token_quantity")]
    pub maximum_output_token_quantity: u64,
    #[serde(default = "default_maximum_assets")]
    pub maximum_assets_per_bundle: usize,
}

/// Independent laws for the pinned component profile, including ADA dust fees
/// and change splitting. Exact strategy/RNG output is compared separately.
pub fn validate_haskell_selection(
    input: &HaskellSelectionInput,
    selection: &Selection,
) -> Result<()> {
    let eligible_coin: u128 = input
        .utxos
        .iter()
        .filter(|utxo| utxo.eligible)
        .map(|utxo| u128::from(utxo.value.coin))
        .sum();
    ensure!(
        eligible_coin <= u128::from(input.maximum_output_coin),
        "component input ADA exceeds global bound"
    );
    ensure!(
        input.maximum_assets_per_bundle > 0
            && input.maximum_output_token_quantity > 0
            && input.maximum_output_coin > 0
            && input.maximum_output_coin >= input.minimum_change_coin,
        "invalid component constraints"
    );
    let extra_fee = u128::from(selection.fee)
        .checked_sub(u128::from(input.minimum_fee))
        .context("selection fee below component minimum")?;
    if selection.change.is_empty() {
        ensure!(
            extra_fee == 0 || extra_fee < u128::from(input.minimum_change_coin),
            "selection burned ADA that could fund change"
        );
    } else {
        ensure!(
            extra_fee <= u128::from(input.minimum_fee),
            "selection fee outside component cost bound"
        );
    }
    validate_selection(
        &SelectionInput {
            utxos: input.utxos.clone(),
            outputs: input.outputs.clone(),
            fee: selection.fee,
            minimum_change_coin: input.minimum_change_coin,
            maximum_inputs: input.utxos.len(),
            seed: input.seed,
        },
        selection,
    )?;
    for bundle in input.outputs.iter().chain(&selection.change) {
        ensure!(
            bundle.coin <= input.maximum_output_coin,
            "output ADA exceeds component bound"
        );
        ensure!(
            bundle
                .assets
                .values()
                .all(|quantity| *quantity <= input.maximum_output_token_quantity),
            "output token quantity exceeds component bound"
        );
        ensure!(
            bundle
                .assets
                .values()
                .filter(|quantity| **quantity > 0)
                .count()
                <= input.maximum_assets_per_bundle,
            "output asset count exceeds component bound"
        );
    }
    Ok(())
}

fn totals<'a>(bundles: impl IntoIterator<Item = &'a Bundle>) -> (u128, BTreeMap<String, u128>) {
    let mut coin = 0u128;
    let mut assets = BTreeMap::new();
    for bundle in bundles {
        coin += u128::from(bundle.coin);
        for (asset, quantity) in &bundle.assets {
            if *quantity > 0 {
                *assets.entry(asset.clone()).or_insert(0u128) += u128::from(*quantity);
            }
        }
    }
    (coin, assets)
}

/// Validate arbitrary candidate selections independently of the selection strategy.
/// Policy IDs and asset names are carried as canonical opaque keys in this adapter.
pub fn validate_selection(input: &SelectionInput, selection: &Selection) -> Result<()> {
    let mut universe = BTreeMap::new();
    for utxo in &input.utxos {
        ensure!(
            universe.insert(&utxo.id, utxo).is_none(),
            "duplicate UTxO fixture"
        );
    }
    ensure!(selection.fee == input.fee, "selection fee mismatch");
    ensure!(
        !selection.inputs.is_empty() && selection.inputs.len() <= input.maximum_inputs,
        "selection input count violates constraints"
    );
    let mut seen = BTreeSet::new();
    let mut selected = Vec::new();
    for id in &selection.inputs {
        ensure!(seen.insert(id), "duplicate selected input");
        let utxo = universe
            .get(id)
            .context("selected input is not in UTxO set")?;
        ensure!(utxo.eligible, "selected input is not eligible");
        selected.push(&utxo.value);
    }
    for change in &selection.change {
        ensure!(
            change.coin >= input.minimum_change_coin,
            "change below minimum ADA"
        );
        ensure!(
            change.coin > 0 || change.assets.values().any(|q| *q > 0),
            "empty change output"
        );
    }
    let (coin_in, assets_in) = totals(selected);
    let (coin_out, assets_out) = totals(input.outputs.iter().chain(&selection.change));
    ensure!(
        coin_in == coin_out + u128::from(selection.fee),
        "selection fails ADA conservation"
    );
    ensure!(
        assets_in == assets_out,
        "selection fails native-asset conservation"
    );
    Ok(())
}

/// Each vector must have independent provenance and exactly one expectation mode.
pub fn run(
    vectors: &[Vector],
    executable: Option<&Path>,
    args: &[String],
    timeout: Duration,
    target: &str,
    environment: &str,
) -> Result<Report> {
    ensure!(!vectors.is_empty(), "empty vector corpus");
    let mut ids = BTreeSet::new();
    let mut report = Report::new(target, environment);
    report.harness_self_test = executable.is_none();
    for vector in vectors {
        if !crate::report::registered_vector(vector)? {
            report.unregistered_inputs.push(vector.id.clone());
        }
        ensure!(ids.insert(&vector.id), "duplicate vector ID");
        ensure!(
            !vector.source.trim().is_empty() && !vector.requirements.is_empty(),
            "vector lacks provenance/requirements"
        );
        ensure!(
            vector.expected.is_some() != vector.selection_invariants,
            "vector must have exactly one expectation mode"
        );
        let result = (|| -> Result<()> {
            let actual = match executable {
                Some(path) => invoke(path, args, vector, timeout)?,
                None => primitive(&vector.operation, &vector.input)?,
            };
            if matches!(
                vector.operation.as_str(),
                "coin-selection.select" | "coin-selection.haskell"
            ) {
                if let Some(path) = executable {
                    let replay = invoke(path, args, vector, timeout)?;
                    ensure!(actual == replay, "seeded selection is not reproducible");
                }
            }
            if vector.operation == "coin-selection.haskell" {
                if let Some(result) = actual.get("result") {
                    validate_haskell_selection(
                        &serde_json::from_value(vector.input.clone())?,
                        &serde_json::from_value(result.clone())?,
                    )?;
                }
            }
            if vector.operation == "wallet.credentials" {
                crate::credentials::validate(vector, &actual)?;
            }
            if vector.operation == "selection.wallet" {
                crate::wallet_selection::validate(vector, &actual)?;
            }
            if vector.operation == "transaction.minimum-fee" {
                crate::ledger_fees::validate(vector, &actual)?;
            }
            if matches!(
                vector.operation.as_str(),
                "witness.build" | "witness.sign" | "witness.script" | "wallet.certificates"
            ) {
                crate::writer::validate(vector, &actual)?;
            }
            if matches!(vector.operation.as_str(), "fee.components" | "minimum-utxo") {
                crate::balance::validate(vector, &actual)?;
            }
            if vector.operation == "time.slot-boundary" {
                crate::slotting::validate(vector, &actual)?;
            }
            if matches!(
                vector.operation.as_str(),
                "transaction.size-estimate" | "transaction.input-witness-count"
            ) {
                crate::signed_size::validate(vector, &actual)?;
            }
            if vector.operation == "transaction.roundtrip"
                && vector.requirements.iter().any(|r| r == "tx.collateral")
            {
                crate::balancing::validate(vector, &actual)?;
            }
            if vector.operation == "transaction.roundtrip"
                && vector.input.get("reward_context").is_some()
            {
                crate::rewards::validate(vector, &actual)?;
            }
            if matches!(
                vector.operation.as_str(),
                "transaction.roundtrip" | "metadata.encode" | "ledger.ed25519.verify"
            ) {
                crate::ledger::validate(vector, &actual)?;
            }
            if matches!(
                vector.operation.as_str(),
                "native.script"
                    | "address.build"
                    | "address.byron"
                    | "address.inspect-byron"
                    | "byron.path-encrypt"
                    | "byron.path-decrypt"
                    | "encoding.bech32"
                    | "encoding.base58"
                    | "governance.identifier"
                    | "key.hash"
                    | "asset.fingerprint"
            ) {
                crate::addresses::validate(vector, &actual)?;
            }
            if matches!(
                vector.operation.as_str(),
                "bip39.entropy-to-mnemonic"
                    | "bip39.to-seed"
                    | "bip39.wallet-seed"
                    | "address.enterprise"
                    | "keys.generate-root-profile"
            ) {
                crate::mnemonics::validate(vector, &actual)?;
            }
            if matches!(
                vector.operation.as_str(),
                "keys.derive" | "keys.derive-public" | "keys.sign-extended" | "byron.generate-root"
            ) {
                crate::keys::validate(vector, &actual)?;
            }
            if vector.selection_invariants {
                let input: SelectionInput = serde_json::from_value(vector.input.clone())
                    .context("invalid selection fixture")?;
                let selected: Selection = serde_json::from_value(actual["result"].clone())
                    .context("adapter selection has wrong structure")?;
                validate_selection(&input, &selected)?;
            } else {
                ensure!(
                    Some(&actual) == vector.expected.as_ref(),
                    "internal result does not match independent vector"
                );
            }
            Ok(())
        })();
        report.record(&vector.id, &vector.requirements, result);
    }
    Ok(report)
}
