//! Independently verified on-chain fixture for an explicitly owned test cluster.
//! Fixture receipts are public observations, never candidate conformance passes.
use crate::{
    api::{request, Api, Contract},
    encoding,
    node::NodeOracle,
    report, transaction,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
const FUNDING: u64 = 100_000_000;

/// Expected metadata bytes; the HTTP server may intentionally serve different bytes.
pub struct Metadata {
    pub url: String,
    pub bytes: Vec<u8>,
}
impl Metadata {
    fn validate(&self) -> Result<()> {
        let url = reqwest::Url::parse(&self.url)?;
        ensure!(
            self.url.len() <= 64
                && matches!(url.scheme(), "http" | "https")
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none(),
            "invalid fixture metadata URL"
        );
        ensure!(
            self.bytes.len() <= 512 && serde_json::from_slice::<Value>(&self.bytes)?.is_object(),
            "invalid fixture metadata bytes"
        );
        Ok(())
    }
    fn hash(&self) -> Result<Vec<u8>> {
        transaction::blake2b(&self.bytes, 32)
    }
}

pub struct Options {
    pub node: NodeOracle,
    pub owned_pool: PathBuf,
    pub target: String,
    pub faucet: String,
    pub output: PathBuf,
    pub timeout: Duration,
    pub pledge: u64,
}

pub(crate) fn run(command: &mut Command, timeout: Duration) -> Result<Vec<u8>> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("cannot start trusted fixture CLI")?;
    let stdout = child.stdout.take().context("fixture CLI stdout missing")?;
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = send.send(result);
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("trusted fixture CLI timed out");
        }
        thread::sleep(Duration::from_millis(10));
    };
    ensure!(
        status.success(),
        "trusted fixture CLI failed; private stderr suppressed"
    );
    let result = receive
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .context("fixture CLI output did not close")??;
    ensure!(result.len() <= 1_048_576, "fixture CLI output exceeds1MiB");
    Ok(result)
}

fn read_json(path: &Path) -> Result<Value> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(1_048_577)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1_048_576, "fixture file exceeds1MiB");
    Ok(serde_json::from_slice(&bytes)?)
}
fn key(value: &Value) -> Result<Vec<u8>> {
    let raw = hex::decode(
        value["cborHex"]
            .as_str()
            .context("verification key CBOR missing")?,
    )?;
    let mut d = minicbor::Decoder::new(&raw);
    let key = d.bytes()?.to_vec();
    ensure!(
        key.len() == 32 && d.position() == raw.len(),
        "invalid verification key envelope"
    );
    Ok(key)
}
struct PublicKeys {
    operator: Vec<u8>,
    owner: Vec<u8>,
    vrf: Vec<u8>,
    payment: Vec<u8>,
}
fn certificate(value: &Value, keys: &PublicKeys, pledge: u64) -> Result<Vec<u8>> {
    certificate_with_metadata(value, keys, pledge, None)
}
fn certificate_with_metadata(
    value: &Value,
    keys: &PublicKeys,
    pledge: u64,
    metadata: Option<&Metadata>,
) -> Result<Vec<u8>> {
    let raw = hex::decode(
        value["cborHex"]
            .as_str()
            .context("registration CBOR missing")?,
    )?;
    let mut d = minicbor::Decoder::new(&raw);
    ensure!(
        d.array()? == Some(10) && d.u64()? == 3,
        "invalid pool certificate tuple/type"
    );
    ensure!(
        d.bytes()? == transaction::blake2b(&keys.operator, 28)?,
        "pool operator hash differs"
    );
    ensure!(
        d.bytes()? == transaction::blake2b(&keys.vrf, 32)?,
        "pool VRF hash differs"
    );
    ensure!(
        d.u64()? == pledge && d.u64()? == 0,
        "pool pledge/cost differs"
    );
    ensure!(
        d.tag()?.as_u64() == 30 && d.array()? == Some(2) && d.u64()? == 1 && d.u64()? == 10,
        "pool margin differs"
    );
    let owner = transaction::blake2b(&keys.owner, 28)?;
    let reward = d.bytes()?;
    ensure!(
        reward.len() == 29 && reward[0] == 0xe0 && reward[1..] == owner,
        "pool reward credential/network differs"
    );
    ensure!(
        d.tag()?.as_u64() == 258 && d.array()? == Some(1) && d.bytes()? == owner,
        "pool owners differ"
    );
    ensure!(d.array()? == Some(0), "unexpected pool relay");
    match metadata {
        None => {
            d.null()?;
        }
        Some(metadata) => {
            metadata.validate()?;
            ensure!(
                d.array()? == Some(2)
                    && d.str()? == metadata.url
                    && d.bytes()? == metadata.hash()?,
                "pool metadata URL/hash differs"
            );
        }
    }
    ensure!(d.position() == raw.len(), "trailing registration CBOR");
    Ok(raw)
}

fn funding(value: &Value, address: &str) -> Result<String> {
    let map = value.as_object().context("invalid fixture funding map")?;
    ensure!(map.len() == 1, "fixture needs exactly one funding input");
    let (reference, output) = map.iter().next().unwrap();
    ensure!(
        output["address"] == address && output["value"] == json!({"lovelace":FUNDING}),
        "fixture funding address/value/assets differ"
    );
    Ok(reference.clone())
}

fn confirmed(value: &Value, txid: &str, address: &str, amount: u64) -> Result<bool> {
    ensure!(
        txid.len() == 64 && txid.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid fixture transaction hash"
    );
    let map = value
        .as_object()
        .context("invalid fixture confirmation UTxO map")?;
    let matching: Vec<_> = map
        .iter()
        .filter(|(id, _)| {
            id.strip_prefix(txid)
                .is_some_and(|suffix| suffix.starts_with('#'))
        })
        .collect();
    if matching.is_empty() {
        return Ok(false);
    }
    crate::node::validate_payment(value, txid, address, amount)?;
    ensure!(
        matching.len() == 1
            && matching[0].0 == &format!("{txid}#0")
            && matching[0].1["value"] == json!({"lovelace":amount}),
        "confirmed fixture index/assets/output count differs"
    );
    Ok(true)
}
fn control(
    value: &Value,
    cert: &[u8],
    keys: &PublicKeys,
    reference: &str,
    address: &str,
    parameters: &Value,
) -> Result<transaction::Transaction> {
    let encoded = value["cborHex"]
        .as_str()
        .context("signed registration CBOR missing")?;
    let raw = hex::decode(encoded)?;
    let tx = transaction::inspect(encoded, true)?;
    ensure!(
        transaction::certificates(encoded)? == [hex::encode(cert)],
        "signed registration certificate changed"
    );
    ensure!(
        tx.inputs == [reference]
            && tx.outputs.len() == 1
            && tx.outputs[0].assets.is_empty()
            && tx.outputs[0].address_hex == hex::encode(encoding::bech32(address)?.1)
            && tx.outputs[0].coin.checked_add(tx.fee) == Some(FUNDING),
        "registration ADA/input/change differs"
    );
    let actual: BTreeSet<_> = tx.verification_keys.iter().cloned().collect();
    let expected = BTreeSet::from([
        hex::encode(&keys.operator),
        hex::encode(&keys.owner),
        hex::encode(&keys.payment),
    ]);
    ensure!(
        actual == expected && expected.len() == 3 && tx.verification_keys.len() == 3,
        "registration operator/owner/payment witnesses differ"
    );
    let fixed = parameters["txFeeFixed"]
        .as_u64()
        .context("node fixed fee missing")?;
    let per_byte = parameters["txFeePerByte"]
        .as_u64()
        .context("node per-byte fee missing")?;
    ensure!(
        u128::from(tx.fee) >= u128::from(fixed) + u128::from(per_byte) * raw.len() as u128,
        "registration fee below independent serialized-size minimum"
    );
    Ok(tx)
}

/// Re-register only an explicitly supplied, already node-known owned cluster pool.
pub fn prepare(options: &Options) -> Result<PathBuf> {
    prepare_with_metadata(options, None)
}

/// Metadata fixtures retain the original registration and confirmation controls.
pub fn prepare_with_metadata(options: &Options, metadata: Option<&Metadata>) -> Result<PathBuf> {
    if let Some(metadata) = metadata {
        metadata.validate()?;
    }
    ensure!(
        options.node.network_magic == 42,
        "pool fixture requires owned local-cluster magic42"
    );
    ensure!(
        !options.output.exists(),
        "refusing to overwrite fixture output"
    );
    let contract = Contract::pinned()?;
    let api = Api::new(&options.target, options.timeout)?;
    let pool_path = "/stake-pools?stake=100000000";
    let operator = read_json(&options.owned_pool.join("op.pub"))?;
    let owner = read_json(&options.owned_pool.join("stake.pub"))?;
    let vrf = read_json(&options.owned_pool.join("vrf.pub"))?;
    for name in ["op.prv", "stake.prv"] {
        ensure!(
            options.owned_pool.join(name).is_file(),
            "owned pool signing key missing"
        );
    }
    let operator_key = key(&operator)?;
    let pool_hash = transaction::blake2b(&operator_key, 28)?;
    let pool_id = encoding::bech32_encode("pool", &pool_hash)?;
    let pools = options.node.stake_pools(options.timeout)?;
    ensure!(
        pools
            .as_array()
            .context("invalid node pool list")?
            .contains(&json!(pool_id)),
        "owned pool does not already exist on this node"
    );
    let parameters = options.node.protocol_parameters(options.timeout)?;
    ensure!(
        parameters["stakePoolDeposit"] == 0,
        "pool fixture requires zero-deposit local cluster"
    );
    let response = api.checked(
        &contract,
        "listStakePools",
        request("GET", pool_path, None),
        200,
    )?;
    ensure!(
        !response
            .json
            .as_ref()
            .context("missing pool API response")?
            .as_array()
            .context("invalid wallet pool list")?
            .iter()
            .any(|v| v["id"] == pool_id),
        "pool is already wallet-visible; fixture requires fresh setup"
    );
    fs::DirBuilder::new().mode(0o700).create(&options.output)?;
    let private = options.output.join("private");
    fs::DirBuilder::new().mode(0o700).create(&private)?;
    let public = options.output.join("public");
    fs::create_dir(&public)?;
    let cli = |tail: &[&str]| {
        let mut command = Command::new(&options.node.executable);
        command.arg("conway").args(tail);
        command
    };
    let mut metadata_flags = Vec::new();
    let metadata_reference = if let Some(metadata) = metadata {
        let expected_file = public.join("metadata.expected.json");
        let hash_file = public.join("metadata.hash");
        fs::write(&expected_file, &metadata.bytes)?;
        run(
            cli(&["stake-pool", "metadata-hash", "--pool-metadata-file"])
                .arg(&expected_file)
                .arg("--out-file")
                .arg(&hash_file),
            options.timeout,
        )?;
        let cli_hash = fs::read_to_string(&hash_file)?.trim().to_owned();
        let independent_hash = hex::encode(metadata.hash()?);
        ensure!(
            cli_hash == independent_hash,
            "trusted CLI and Rust metadata hashes disagree"
        );
        metadata_flags.extend([
            "--metadata-url".to_owned(),
            metadata.url.clone(),
            "--metadata-hash".to_owned(),
            independent_hash.clone(),
        ]);
        Some(json!({"url":metadata.url,"hash":independent_hash}))
    } else {
        None
    };
    let payment_vkey = public.join("payment.vkey");
    let payment_skey = private.join("payment.skey");
    let address_file = public.join("payment.addr");
    run(
        cli(&["address", "key-gen", "--verification-key-file"])
            .arg(&payment_vkey)
            .arg("--signing-key-file")
            .arg(&payment_skey),
        options.timeout,
    )?;
    run(
        cli(&["address", "build", "--payment-verification-key-file"])
            .arg(&payment_vkey)
            .args(["--testnet-magic", "42", "--out-file"])
            .arg(&address_file),
        options.timeout,
    )?;
    let address = fs::read_to_string(&address_file)?.trim().to_owned();
    let payment = read_json(&payment_vkey)?;
    let keys = PublicKeys {
        operator: operator_key,
        owner: key(&owner)?,
        vrf: key(&vrf)?,
        payment: key(&payment)?,
    };
    let raw_address = encoding::bech32(&address)?.1;
    ensure!(
        raw_address.len() == 29
            && raw_address[0] == 0x60
            && raw_address[1..] == transaction::blake2b(&keys.payment, 28)?,
        "fixture payment credential/network differs"
    );
    let faucet = Api::new(&options.faucet, options.timeout)?;
    let funded = faucet.request(&request("POST","/send/faucet-assets",Some(json!({
        "batch-size":1,"assets":[{"address":address,"bundle":{"coin":FUNDING,"assets":[]},"metadata":[]}]}))))?;
    ensure!(funded.status == 204, "fixture faucet rejected funding");
    let deadline = Instant::now() + options.timeout;
    let observed = loop {
        let value = options.node.utxos(&address, options.timeout)?;
        let map = value.as_object().context("invalid fixture UTxO response")?;
        if !map.is_empty() {
            break value;
        }
        ensure!(Instant::now() < deadline, "fixture funding timed out");
        thread::sleep(Duration::from_millis(200));
    };
    let reference = funding(&observed, &address)?;
    let registration = public.join("registration.cert");
    run(
        cli(&[
            "stake-pool",
            "registration-certificate",
            "--cold-verification-key-file",
        ])
        .arg(options.owned_pool.join("op.pub"))
        .arg("--vrf-verification-key-file")
        .arg(options.owned_pool.join("vrf.pub"))
        .arg("--pool-pledge")
        .arg(options.pledge.to_string())
        .args([
            "--pool-cost",
            "0",
            "--pool-margin",
            "0.1",
            "--pool-reward-account-verification-key-file",
        ])
        .arg(options.owned_pool.join("stake.pub"))
        .arg("--pool-owner-stake-verification-key-file")
        .arg(options.owned_pool.join("stake.pub"))
        .args(&metadata_flags)
        .args(["--testnet-magic", "42", "--out-file"])
        .arg(&registration),
        options.timeout,
    )?;
    let registration_value = read_json(&registration)?;
    let cert = match metadata {
        None => certificate(&registration_value, &keys, options.pledge)?,
        Some(metadata) => {
            certificate_with_metadata(&registration_value, &keys, options.pledge, Some(metadata))?
        }
    };
    let body = public.join("registration.body");
    run(
        cli(&["transaction", "build", "--socket-path"])
            .arg(&options.node.socket)
            .args(["--testnet-magic", "42", "--tx-in"])
            .arg(&reference)
            .arg("--certificate-file")
            .arg(&registration)
            .arg("--change-address")
            .arg(&address)
            .args(["--witness-override", "3", "--out-file"])
            .arg(&body),
        options.timeout,
    )?;
    let signed = public.join("registration.signed");
    run(
        cli(&["transaction", "sign", "--tx-body-file"])
            .arg(&body)
            .arg("--signing-key-file")
            .arg(&payment_skey)
            .arg("--signing-key-file")
            .arg(options.owned_pool.join("op.prv"))
            .arg("--signing-key-file")
            .arg(options.owned_pool.join("stake.prv"))
            .args(["--testnet-magic", "42", "--out-file"])
            .arg(&signed),
        options.timeout,
    )?;
    let signed_value = read_json(&signed)?;
    let tx = control(
        &signed_value,
        &cert,
        &keys,
        &reference,
        &address,
        &parameters,
    )?;
    let reported_id = run(
        cli(&["transaction", "txid", "--output-text", "--tx-file"]).arg(&signed),
        options.timeout,
    )?;
    ensure!(
        std::str::from_utf8(&reported_id)?.trim() == tx.id,
        "CLI/body transaction hash differs"
    );
    run(
        cli(&["transaction", "submit", "--socket-path"])
            .arg(&options.node.socket)
            .args(["--testnet-magic", "42", "--tx-file"])
            .arg(&signed),
        options.timeout,
    )?;
    let deadline = Instant::now() + options.timeout;
    let after = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "fixture registration confirmation timed out"
        );
        let value = options.node.utxos(&address, remaining)?;
        if confirmed(&value, &tx.id, &address, tx.outputs[0].coin)? {
            break value;
        }
        ensure!(
            Instant::now() < deadline,
            "fixture registration confirmation timed out"
        );
        thread::sleep(
            Duration::from_millis(200).min(deadline.saturating_duration_since(Instant::now())),
        );
    };
    ensure!(
        !after
            .as_object()
            .context("invalid confirmed fixture UTxOs")?
            .contains_key(&reference),
        "registration funding input remains unspent"
    );
    let deadline = Instant::now() + options.timeout;
    let pool = loop {
        let response = api.checked(
            &contract,
            "listStakePools",
            request("GET", pool_path, None),
            200,
        )?;
        let value = response.json.context("missing wallet pool response")?;
        if let Some(pool) = value
            .as_array()
            .context("invalid wallet pool response")?
            .iter()
            .find(|pool| pool["id"] == pool_id)
        {
            break pool.clone();
        }
        ensure!(
            Instant::now() < deadline,
            "registered pool never became wallet-visible"
        );
        thread::sleep(Duration::from_millis(200));
    };
    let receipt = public.join("receipt.json");
    fs::write(
        &receipt,
        serde_json::to_vec_pretty(&json!({
            "format_version":1,"kind":"local-cluster-pool-fixture","counts_as_conformance_evidence":false,
            "suite_sha256":report::suite_sha256(),"pool_id":pool_id,"transaction_id":tx.id,
            "fee":tx.fee,"payment_address":address,"funding_before":observed,"utxos_after":after,
            "protocol_parameters":parameters,"wallet_pool":pool,"certificate":registration_value,
            "signed_transaction":signed_value,"operator":operator,"owner":owner,"vrf":vrf,"payment":payment,
            "registration_metadata":metadata_reference
        }))?,
    )?;
    Ok(receipt)
}

fn retirement_certificate(value: &Value, operator: &[u8], epoch: u64) -> Result<Vec<u8>> {
    let raw = hex::decode(
        value["cborHex"]
            .as_str()
            .context("retirement certificate CBOR missing")?,
    )?;
    let mut decoder = minicbor::Decoder::new(&raw);
    ensure!(
        decoder.array()? == Some(3)
            && decoder.u64()? == 4
            && decoder.bytes()? == transaction::blake2b(operator, 28)?
            && decoder.u64()? == epoch
            && decoder.position() == raw.len(),
        "retirement certificate type/operator/epoch differs"
    );
    Ok(raw)
}

/// Retire an owned fixture pool using only its independently confirmed change output.
/// This prepares public node-backed fixture evidence, not a wallet conformance pass.
pub fn retire(
    node: &NodeOracle,
    owned_pool: &Path,
    registration: &Path,
    epoch: u64,
    output: &Path,
    timeout: Duration,
) -> Result<PathBuf> {
    ensure!(
        node.network_magic == 42 && !output.exists(),
        "retirement requires fresh owned magic42 fixture output"
    );
    let receipt = read_json(&registration.join("public/receipt.json"))?;
    let keys = PublicKeys {
        operator: key(&receipt["operator"])?,
        owner: key(&receipt["owner"])?,
        vrf: key(&receipt["vrf"])?,
        payment: key(&receipt["payment"])?,
    };
    ensure!(
        key(&read_json(&owned_pool.join("op.pub"))?)? == keys.operator,
        "retirement operator differs from registered fixture"
    );
    let metadata = match receipt["registration_metadata"].as_object() {
        None => None,
        Some(value) => Some(Metadata {
            url: value
                .get("url")
                .and_then(Value::as_str)
                .context("fixture metadata URL missing")?
                .into(),
            bytes: fs::read(registration.join("public/metadata.expected.json"))?,
        }),
    };
    let pledge = receipt["wallet_pool"]["pledge"]["quantity"]
        .as_u64()
        .context("fixture pledge missing")?;
    let cert =
        certificate_with_metadata(&receipt["certificate"], &keys, pledge, metadata.as_ref())?;
    let original = receipt["funding_before"]
        .as_object()
        .context("fixture original funding missing")?;
    ensure!(
        original.len() == 1,
        "fixture original funding count differs"
    );
    let address = receipt["payment_address"]
        .as_str()
        .context("fixture payment address missing")?;
    let registered = control(
        &receipt["signed_transaction"],
        &cert,
        &keys,
        original.keys().next().unwrap(),
        address,
        &receipt["protocol_parameters"],
    )?;
    ensure!(
        receipt["transaction_id"] == registered.id,
        "registration receipt body hash differs"
    );
    let before = node.utxos(address, timeout)?;
    let amount = FUNDING
        .checked_sub(registered.fee)
        .context("invalid registration fee")?;
    ensure!(
        confirmed(&before, &registered.id, address, amount)?,
        "registration change is not independently available"
    );
    ensure!(
        before.as_object().is_some_and(|m| m.len() == 1),
        "retirement funding has extra inputs"
    );
    let reference = format!("{}#0", registered.id);
    let tip = node.query(&["tip"], timeout)?;
    let current_epoch = tip["epoch"].as_u64().context("node epoch missing")?;
    let parameters = node.protocol_parameters(timeout)?;
    let maximum = parameters["poolRetireMaxEpoch"]
        .as_u64()
        .context("retirement epoch bound missing")?;
    ensure!(
        epoch > current_epoch
            && epoch
                <= current_epoch
                    .checked_add(maximum)
                    .context("retirement bound overflow")?,
        "retirement epoch outside node bounds"
    );
    fs::DirBuilder::new().mode(0o700).create(output)?;
    let cli = |tail: &[&str]| {
        let mut command = Command::new(&node.executable);
        command.arg("conway").args(tail);
        command
    };
    let certificate_file = output.join("retirement.cert");
    run(
        cli(&[
            "stake-pool",
            "deregistration-certificate",
            "--cold-verification-key-file",
        ])
        .arg(owned_pool.join("op.pub"))
        .arg("--epoch")
        .arg(epoch.to_string())
        .arg("--out-file")
        .arg(&certificate_file),
        timeout,
    )?;
    let certificate_value = read_json(&certificate_file)?;
    let raw = retirement_certificate(&certificate_value, &keys.operator, epoch)?;
    let body = output.join("retirement.body");
    run(
        cli(&["transaction", "build", "--socket-path"])
            .arg(&node.socket)
            .args(["--testnet-magic", "42", "--tx-in"])
            .arg(&reference)
            .arg("--certificate-file")
            .arg(&certificate_file)
            .arg("--change-address")
            .arg(address)
            .args(["--witness-override", "2", "--out-file"])
            .arg(&body),
        timeout,
    )?;
    let signed = output.join("retirement.signed");
    run(
        cli(&["transaction", "sign", "--tx-body-file"])
            .arg(&body)
            .arg("--signing-key-file")
            .arg(registration.join("private/payment.skey"))
            .arg("--signing-key-file")
            .arg(owned_pool.join("op.prv"))
            .args(["--testnet-magic", "42", "--out-file"])
            .arg(&signed),
        timeout,
    )?;
    let signed_value = read_json(&signed)?;
    let encoded = signed_value["cborHex"]
        .as_str()
        .context("signed retirement missing")?;
    let tx = transaction::inspect(encoded, true)?;
    ensure!(
        transaction::certificates(encoded)? == [hex::encode(&raw)]
            && tx.inputs == [reference.clone()]
            && tx.outputs.len() == 1
            && tx.outputs[0].address_hex == hex::encode(encoding::bech32(address)?.1)
            && tx.outputs[0].assets.is_empty()
            && tx.outputs[0].coin.checked_add(tx.fee) == Some(amount),
        "retirement body/input/output/fee differs"
    );
    let expected_keys = BTreeSet::from([hex::encode(&keys.operator), hex::encode(&keys.payment)]);
    ensure!(
        expected_keys.len() == 2
            && tx.verification_keys.len() == 2
            && tx
                .verification_keys
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                == expected_keys,
        "retirement witnesses differ"
    );
    let fixed = parameters["txFeeFixed"]
        .as_u64()
        .context("node fixed fee missing")?;
    let per_byte = parameters["txFeePerByte"]
        .as_u64()
        .context("node fee coefficient missing")?;
    ensure!(
        u128::from(tx.fee)
            >= u128::from(fixed) + u128::from(per_byte) * hex::decode(encoded)?.len() as u128,
        "retirement fee below node minimum"
    );
    run(
        cli(&["transaction", "submit", "--socket-path"])
            .arg(&node.socket)
            .args(["--testnet-magic", "42", "--tx-file"])
            .arg(&signed),
        timeout,
    )?;
    let deadline = Instant::now() + timeout;
    let after = loop {
        let value = node.utxos(address, timeout)?;
        if confirmed(&value, &tx.id, address, tx.outputs[0].coin)? {
            break value;
        }
        ensure!(
            Instant::now() < deadline,
            "retirement confirmation timed out"
        );
        thread::sleep(Duration::from_millis(200));
    };
    ensure!(
        !after
            .as_object()
            .context("retirement UTxOs missing")?
            .contains_key(&reference),
        "retirement input remains unspent"
    );
    let public_receipt = output.join("receipt.json");
    fs::write(
        &public_receipt,
        serde_json::to_vec_pretty(
            &json!({"format_version":1,"kind":"owned-pool-retirement-fixture","counts_as_conformance_evidence":false,"suite_sha256":report::suite_sha256(),"pool_id":receipt["pool_id"],"epoch":epoch,"transaction_id":tx.id,"fee":tx.fee,"funding_before":before,"utxos_after":after,"certificate":certificate_value,"signed_transaction":signed_value,"protocol_parameters":parameters}),
        )?,
    )?;
    Ok(public_receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confirmation_retries_only_absence_and_checks_exact_node_output() {
        let id = "ab".repeat(32);
        let reference = format!("{id}#0");
        assert!(!confirmed(&json!({}), &id, "address", 100).unwrap());
        assert!(!confirmed(
            &json!({"unrelated#0":{"value":{"lovelace":100}}}),
            &id,
            "address",
            100
        )
        .unwrap());
        let mut observed = json!({&reference:{"address":"address","value":{"lovelace":100}}});
        assert!(confirmed(&observed, &id, "address", 100).unwrap());
        assert!(confirmed(&observed, &id, "wrong-address", 100).is_err());
        assert!(confirmed(&observed, &id, "address", 99).is_err());
        observed[&reference]["value"]["unexpected-policy"] = json!({"":1});
        assert!(confirmed(&observed, &id, "address", 100).is_err());
        let wrong_index = format!("{id}#1");
        assert!(confirmed(
            &json!({wrong_index:{"address":"address","value":{"lovelace":100}}}),
            &id,
            "address",
            100
        )
        .is_err());
        assert!(confirmed(&json!([]), &id, "address", 100).is_err());
    }
    fn fixture() -> (Value, PublicKeys, String, String) {
        let value: Value =
            serde_json::from_str(include_str!("../fixtures/pool-registration-control.json"))
                .unwrap();
        let keys = PublicKeys {
            operator: key(&value["operator"]).unwrap(),
            owner: key(&value["owner"]).unwrap(),
            vrf: key(&value["vrf"]).unwrap(),
            payment: key(&value["payment"]).unwrap(),
        };
        let first = value["funding"].as_object().unwrap().iter().next().unwrap();
        let (reference, address) = (
            first.0.clone(),
            first.1["address"].as_str().unwrap().to_owned(),
        );
        (value, keys, reference, address)
    }
    #[test]
    fn retirement_certificate_rejects_operator_epoch_kind_and_trailing_bytes() {
        let (_, keys, _, _) = fixture();
        let mut encoded = minicbor::Encoder::new(Vec::new());
        encoded
            .array(3)
            .unwrap()
            .u8(4)
            .unwrap()
            .bytes(&transaction::blake2b(&keys.operator, 28).unwrap())
            .unwrap()
            .u64(42)
            .unwrap();
        let raw = encoded.into_writer();
        let value = json!({"cborHex":hex::encode(&raw)});
        assert_eq!(
            retirement_certificate(&value, &keys.operator, 42).unwrap(),
            raw
        );
        assert!(retirement_certificate(&value, &keys.operator, 43).is_err());
        assert!(retirement_certificate(&value, &[0; 32], 42).is_err());
        for (index, replacement) in [(0, 0x82), (1, 5), (4, 0)] {
            let mut bad = raw.clone();
            bad[index] = replacement;
            assert!(retirement_certificate(
                &json!({"cborHex":hex::encode(bad)}),
                &keys.operator,
                42
            )
            .is_err());
        }
        let mut bad = raw;
        bad.push(0);
        assert!(
            retirement_certificate(&json!({"cborHex":hex::encode(bad)}), &keys.operator, 42)
                .is_err()
        );
    }
    #[test]
    fn metadata_certificate_rejects_url_hash_tuple_and_absence_mutations() {
        let (value, keys, _, _) = fixture();
        let pledge = value["pledge"].as_u64().unwrap();
        let metadata = Metadata { url:"http://127.0.0.1:12345/pool.json".into(), bytes:br#"{"ticker":"CFM","name":"Conformance","description":"Owned fixture","homepage":"https://example.com"}"#.to_vec() };
        let mut raw = certificate(&value["certificate"], &keys, pledge).unwrap();
        assert_eq!(raw.pop(), Some(0xf6));
        let mut suffix = minicbor::Encoder::new(Vec::new());
        suffix
            .array(2)
            .unwrap()
            .str(&metadata.url)
            .unwrap()
            .bytes(&metadata.hash().unwrap())
            .unwrap();
        raw.extend(suffix.into_writer());
        let certificate_json = json!({"cborHex":hex::encode(&raw)});
        assert_eq!(
            certificate_with_metadata(&certificate_json, &keys, pledge, Some(&metadata)).unwrap(),
            raw
        );
        assert!(certificate(&certificate_json, &keys, pledge).is_err());
        let wrong_url = Metadata {
            url: "http://127.0.0.1:12345/other.json".into(),
            bytes: metadata.bytes.clone(),
        };
        assert!(
            certificate_with_metadata(&certificate_json, &keys, pledge, Some(&wrong_url)).is_err()
        );
        let wrong_hash = Metadata {
            url: metadata.url.clone(),
            bytes: br#"{"name":"different"}"#.to_vec(),
        };
        assert!(
            certificate_with_metadata(&certificate_json, &keys, pledge, Some(&wrong_hash)).is_err()
        );
        raw.push(0);
        assert!(certificate_with_metadata(
            &json!({"cborHex":hex::encode(raw)}),
            &keys,
            pledge,
            Some(&metadata)
        )
        .is_err());
        assert!(Metadata {
            url: "file:///private".into(),
            bytes: metadata.bytes.clone()
        }
        .validate()
        .is_err());
        assert!(Metadata {
            url: metadata.url.clone(),
            bytes: vec![b' '; 513]
        }
        .validate()
        .is_err());
        assert!(Metadata {
            url: metadata.url.clone(),
            bytes: b"[]".to_vec()
        }
        .validate()
        .is_err());
    }
    #[test]
    fn actual_pool_registration_rejects_changed_credentials_funding_fees_and_witnesses() {
        let (value, mut keys, reference, address) = fixture();
        let cert = certificate(
            &value["certificate"],
            &keys,
            value["pledge"].as_u64().unwrap(),
        )
        .unwrap();
        funding(&value["funding"], &address).unwrap();
        let verified = control(
            &value["signed"],
            &cert,
            &keys,
            &reference,
            &address,
            &value["protocol_parameters"],
        )
        .unwrap();
        assert_eq!(
            verified.id,
            "64f90c9f5abc95e3986defceacf71b9626117079b2ed7a39b862f4e6f34fb3f3"
        );
        keys.vrf[0] ^= 1;
        assert!(certificate(
            &value["certificate"],
            &keys,
            value["pledge"].as_u64().unwrap()
        )
        .is_err());
        keys.vrf[0] ^= 1;
        keys.owner[0] ^= 1;
        assert!(certificate(
            &value["certificate"],
            &keys,
            value["pledge"].as_u64().unwrap()
        )
        .is_err());
        keys.owner[0] ^= 1;
        let mut changed = cert.clone();
        changed[0] ^= 1;
        assert!(control(
            &value["signed"],
            &changed,
            &keys,
            &reference,
            &address,
            &value["protocol_parameters"]
        )
        .is_err());
        assert!(control(
            &value["signed"],
            &cert,
            &keys,
            "wrong#0",
            &address,
            &value["protocol_parameters"]
        )
        .is_err());
        let mut parameters = value["protocol_parameters"].clone();
        parameters["txFeeFixed"] = json!(FUNDING);
        assert!(control(
            &value["signed"],
            &cert,
            &keys,
            &reference,
            &address,
            &parameters
        )
        .is_err());
        let mut signed = value["signed"].clone();
        let mut raw = hex::decode(signed["cborHex"].as_str().unwrap()).unwrap();
        let length = raw.len();
        raw[length - 4] ^= 1;
        signed["cborHex"] = json!(hex::encode(raw));
        assert!(control(
            &signed,
            &cert,
            &keys,
            &reference,
            &address,
            &value["protocol_parameters"]
        )
        .is_err());
        assert!(funding(&value["funding"], "wrong-address").is_err());
    }
}
