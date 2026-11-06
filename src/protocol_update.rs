//! Owned committee/configuration fixtures for genuine node parameter enactment.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

fn read(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(4_194_305)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4_194_304, "fixture file exceeds4MiB");
    Ok(bytes)
}
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}
pub(crate) fn public_key(path: &Path) -> Result<(Value, Vec<u8>)> {
    let value: Value = serde_json::from_slice(&read(path)?)?;
    let raw = hex::decode(
        value["cborHex"]
            .as_str()
            .context("public key CBOR missing")?,
    )?;
    let mut decoder = minicbor::Decoder::new(&raw);
    let bytes = decoder.bytes()?.to_vec();
    ensure!(
        bytes.len() == 32 && decoder.position() == raw.len(),
        "invalid public fixture key"
    );
    Ok((value, bytes))
}
fn copy_tree(source: &Path, target: &Path, count: &mut usize) -> Result<()> {
    ensure!(
        !source.starts_with("/nix/store"),
        "refusing to enumerate /nix/store"
    );
    fs::DirBuilder::new().mode(0o700).create(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        *count += 1;
        ensure!(*count <= 4096, "configuration tree too large");
        let kind = entry.file_type()?;
        ensure!(!kind.is_symlink(), "configuration symlinks are not allowed");
        let destination = target.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &destination, count)?;
        } else {
            ensure!(kind.is_file(), "configuration entry is not a regular file");
            write(&destination, &read(&entry.path())?)?;
        }
    }
    Ok(())
}
fn genesis(mut original: Value, cold_hash: &str) -> Result<Value> {
    ensure!(
        hex::decode(cold_hash)?.len() == 28,
        "invalid owned committee cold hash"
    );
    ensure!(
        original["constitution"].is_object(),
        "Conway constitution missing"
    );
    for field in ["dRepVotingThresholds", "poolVotingThresholds"] {
        let thresholds = original[field]
            .as_object_mut()
            .context("genesis voting thresholds missing")?;
        ensure!(
            !thresholds.is_empty() && thresholds.values().all(Value::is_number),
            "invalid genesis voting thresholds"
        );
        for value in thresholds.values_mut() {
            *value = json!(0);
        }
    }
    let mut members = serde_json::Map::new();
    members.insert(format!("keyHash-{cold_hash}"), json!(100));
    original["committee"] = json!({"members":members,"threshold":{"numerator":1,"denominator":1}});
    original["committeeMinSize"] = json!(1);
    original["govActionDeposit"] = json!(1_000_000);
    original["constitution"]["script"] = Value::Null;
    Ok(original)
}
pub(crate) fn certificate_bytes(path: &Path) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&read(path)?)?;
    Ok(hex::decode(
        value["cborHex"]
            .as_str()
            .context("fixture certificate CBOR missing")?,
    )?)
}
fn certificate_control(raw: &[u8], tag: u64, keys: &[&[u8]], deposit: Option<u64>) -> Result<()> {
    let mut decoder = minicbor::Decoder::new(raw);
    ensure!(
        decoder.array()? == Some(1 + keys.len() as u64 + u64::from(deposit.is_some()))
            && decoder.u64()? == tag,
        "fixture certificate tuple/type differs"
    );
    for key in keys {
        ensure!(
            key.len() == 32
                && decoder.array()? == Some(2)
                && decoder.u64()? == 0
                && decoder.bytes()? == crate::transaction::blake2b(key, 28)?,
            "fixture certificate credential differs"
        );
    }
    if let Some(deposit) = deposit {
        ensure!(
            decoder.u64()? == deposit,
            "fixture certificate deposit differs"
        );
    }
    ensure!(
        decoder.position() == raw.len(),
        "trailing fixture certificate bytes"
    );
    Ok(())
}
/// No process/PID is adopted or started; private keys remain under the fresh workspace.
pub fn prepare(base: &Path, workspace: &Path, cli: &Path, timeout: Duration) -> Result<PathBuf> {
    ensure!(
        workspace.is_absolute() && cli.is_absolute() && cli.is_file(),
        "fixture paths must be absolute"
    );
    let base = fs::canonicalize(base)?;
    ensure!(
        !base.starts_with("/nix/store"),
        "refusing to enumerate /nix/store"
    );
    fs::DirBuilder::new()
        .mode(0o700)
        .create(workspace)
        .context("parameter workspace must be fresh")?;
    let private = workspace.join("private");
    let public = workspace.join("public");
    fs::DirBuilder::new().mode(0o700).create(&private)?;
    fs::DirBuilder::new().mode(0o700).create(&public)?;
    let configs = workspace.join("config");
    copy_tree(&base, &configs, &mut 0)?;
    let command = |arguments: &[&str]| {
        let mut command = Command::new(cli);
        command.arg("conway").args(arguments);
        command
    };
    crate::pool_fixture::run(
        command(&[
            "governance",
            "committee",
            "key-gen-cold",
            "--cold-verification-key-file",
        ])
        .arg(public.join("committee-cold.vkey"))
        .arg("--cold-signing-key-file")
        .arg(private.join("committee-cold.skey")),
        timeout,
    )?;
    crate::pool_fixture::run(
        command(&[
            "governance",
            "committee",
            "key-gen-hot",
            "--verification-key-file",
        ])
        .arg(public.join("committee-hot.vkey"))
        .arg("--signing-key-file")
        .arg(private.join("committee-hot.skey")),
        timeout,
    )?;
    crate::pool_fixture::run(
        command(&["address", "key-gen", "--verification-key-file"])
            .arg(public.join("payment.vkey"))
            .arg("--signing-key-file")
            .arg(private.join("payment.skey")),
        timeout,
    )?;
    crate::pool_fixture::run(
        command(&["stake-address", "key-gen", "--verification-key-file"])
            .arg(public.join("return-stake.vkey"))
            .arg("--signing-key-file")
            .arg(private.join("return-stake.skey")),
        timeout,
    )?;
    let mut keys = serde_json::Map::new();
    for name in ["committee-cold", "committee-hot", "payment", "return-stake"] {
        let (value, _) = public_key(&public.join(format!("{name}.vkey")))?;
        keys.insert(name.into(), value);
    }
    let (_, cold) = public_key(&public.join("committee-cold.vkey"))?;
    let cold_hash = hex::encode(crate::transaction::blake2b(&cold, 28)?);
    let actual = crate::pool_fixture::run(
        command(&[
            "governance",
            "committee",
            "key-hash",
            "--verification-key-file",
        ])
        .arg(public.join("committee-cold.vkey")),
        timeout,
    )?;
    ensure!(
        std::str::from_utf8(&actual)?.trim() == cold_hash,
        "CLI and independent committee hashes differ"
    );
    let source = read(&base.join("conway-genesis.json"))?;
    let modified = genesis(serde_json::from_slice(&source)?, &cold_hash)?;
    let destination = configs.join("conway-genesis.json");
    // Only the new copied configuration is modified; the source tree stays intact.
    fs::write(&destination, serde_json::to_vec_pretty(&modified)?)?;
    let authorization = public.join("committee-authorization.cert");
    crate::pool_fixture::run(
        command(&[
            "governance",
            "committee",
            "create-hot-key-authorization-certificate",
            "--cold-verification-key-file",
        ])
        .arg(public.join("committee-cold.vkey"))
        .arg("--hot-verification-key-file")
        .arg(public.join("committee-hot.vkey"))
        .arg("--out-file")
        .arg(&authorization),
        timeout,
    )?;
    let registration = public.join("return-stake-registration.cert");
    crate::pool_fixture::run(
        command(&[
            "stake-address",
            "registration-certificate",
            "--stake-verification-key-file",
        ])
        .arg(public.join("return-stake.vkey"))
        .args(["--key-reg-deposit-amt", "1000000", "--out-file"])
        .arg(&registration),
        timeout,
    )?;
    let (_, hot) = public_key(&public.join("committee-hot.vkey"))?;
    let (_, stake) = public_key(&public.join("return-stake.vkey"))?;
    certificate_control(
        &certificate_bytes(&authorization)?,
        14,
        &[&cold, &hot],
        None,
    )?;
    certificate_control(
        &certificate_bytes(&registration)?,
        7,
        &[&stake],
        Some(1_000_000),
    )?;
    let address = crate::pool_fixture::run(
        command(&["address", "build", "--payment-verification-key-file"])
            .arg(public.join("payment.vkey"))
            .args(["--testnet-magic", "42"]),
        timeout,
    )?;
    let address = std::str::from_utf8(&address)?.trim();
    let (hrp, bytes) = crate::encoding::bech32(address)?;
    let (_, payment) = public_key(&public.join("payment.vkey"))?;
    ensure!(
        hrp == "addr_test"
            && bytes.len() == 29
            && bytes[0] == 0x60
            && bytes[1..] == crate::transaction::blake2b(&payment, 28)?,
        "fixture payment address differs"
    );
    write(&public.join("payment.addr"), address.as_bytes())?;
    let receipt = public.join("receipt.json");
    write(
        &receipt,
        &serde_json::to_vec_pretty(
            &json!({"format_version":1,"kind":"owned-committee-parameter-cluster","counts_as_conformance_evidence":false,"base_configs":base,"config_directory":configs,"source_conway_sha256":hex::encode(Sha256::digest(source)),"effective_conway_sha256":hex::encode(Sha256::digest(read(&destination)?)),"committee_cold_hash":cold_hash,"committee_expiry_epoch":100,"public_keys":keys,"payment_address":address,"effective_genesis":modified,"proposed_update":{"txFeePerByte":101,"utxoCostPerByte":4320,"stakePoolTargetNum":4}}),
        )?,
    )?;
    Ok(receipt)
}
fn proposal_bytes(stake: &[u8], url: &str, hash: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        stake.len() == 32 && hash.len() == 32,
        "invalid parameter proposal public fields"
    );
    let mut reward = vec![0xe0];
    reward.extend(crate::transaction::blake2b(stake, 28)?);
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4)?
        .u64(1_000_000)?
        .bytes(&reward)?
        .array(4)?
        .u8(0)?
        .null()?
        .map(3)?
        .u8(0)?
        .u64(101)?
        .u8(8)?
        .u8(4)?
        .u8(17)?
        .u64(4320)?
        .null()?
        .array(2)?
        .str(url)?
        .bytes(hash)?;
    Ok(e.into_writer())
}
fn vote_bytes(hot: &[u8], txid: &str) -> Result<Vec<u8>> {
    let txid = hex::decode(txid)?;
    ensure!(
        hot.len() == 32 && txid.len() == 32,
        "invalid parameter vote public fields"
    );
    let mut e = minicbor::Encoder::new(Vec::new());
    e.map(1)?
        .array(2)?
        .u8(0)?
        .bytes(&crate::transaction::blake2b(hot, 28)?)?
        .map(1)?
        .array(2)?
        .bytes(&txid)?
        .u8(0)?
        .array(2)?
        .u8(1)?
        .null()?;
    Ok(e.into_writer())
}
fn proposal_control(raw: &[u8], stake: &[u8], url: &str, hash: &[u8]) -> Result<()> {
    ensure!(
        raw == proposal_bytes(stake, url, hash)?,
        "parameter proposal fields differ from independent CBOR"
    );
    Ok(())
}
fn vote_control(raw: &[u8], hot: &[u8], txid: &str) -> Result<()> {
    ensure!(
        raw == vote_bytes(hot, txid)?,
        "committee yes vote fields differ from independent CBOR"
    );
    Ok(())
}
fn field(encoded: &str, key: u64) -> Result<Option<Vec<u8>>> {
    let raw = hex::decode(encoded)?;
    let mut d = minicbor::Decoder::new(&raw);
    ensure!(
        d.array()? == Some(4),
        "invalid governance transaction envelope"
    );
    let count = d.map()?.context("indefinite governance transaction body")?;
    let mut found = None;
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..count {
        let actual = d.u64()?;
        ensure!(seen.insert(actual), "duplicate governance body field");
        let start = d.position();
        d.skip()?;
        if actual == key {
            found = Some(raw[start..d.position()].to_vec());
        }
    }
    Ok(found)
}
struct AnchorServer {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    url: String,
}
impl AnchorServer {
    fn start(body: Vec<u8>) -> Result<Self> {
        use std::io::Write;
        use std::{
            net::TcpListener,
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            },
        };
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let url = format!(
            "http://127.0.0.1:{}/anchor.json",
            listener.local_addr()?.port()
        );
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
                        let mut request = Vec::new();
                        let mut buffer = [0; 512];
                        while !request.windows(4).any(|b| b == b"\r\n\r\n") && request.len() < 8192
                        {
                            match stream.read(&mut buffer) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => request.extend(&buffer[..n]),
                            }
                        }
                        if request.starts_with(b"GET /anchor.json ") {
                            let _=write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
                            let _ = stream.write_all(&body);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            stop,
            worker: Some(worker),
            url,
        })
    }
}
impl Drop for AnchorServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
pub(crate) struct Plan {
    pub(crate) label: &'static str,
    pub(crate) certificates: Vec<PathBuf>,
    pub(crate) proposal: Option<PathBuf>,
    pub(crate) vote: Option<PathBuf>,
    pub(crate) signers: Vec<&'static str>,
    pub(crate) deposit: u64,
}
pub(crate) struct Submit<'a> {
    pub(crate) node: &'a crate::node::NodeOracle,
    pub(crate) fixture: &'a Path,
    pub(crate) output: &'a Path,
    pub(crate) address: String,
    pub(crate) timeout: Duration,
}
impl Submit<'_> {
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(&self.node.executable);
        c.arg("conway").args(args);
        c
    }
    pub(crate) fn send(&self, before: Value, plan: Plan) -> Result<Value> {
        use std::collections::BTreeSet;
        let entries = before
            .as_object()
            .context("governance funding is not an object")?;
        ensure!(entries.len() == 1, "governance fixture requires one input");
        let (reference, input) = entries.iter().next().unwrap();
        let amount = input["value"]["lovelace"]
            .as_u64()
            .context("governance funding amount missing")?;
        ensure!(
            input["address"] == self.address && input["value"] == json!({"lovelace":amount}),
            "governance funding address/assets differ"
        );
        let body = self.output.join(format!("{}.body", plan.label));
        let signed = self.output.join(format!("{}.signed", plan.label));
        let mut build = self.command(&["transaction", "build", "--socket-path"]);
        build
            .arg(&self.node.socket)
            .args(["--testnet-magic", "42", "--tx-in"])
            .arg(reference)
            .arg("--change-address")
            .arg(&self.address)
            .arg("--witness-override")
            .arg(plan.signers.len().to_string())
            .arg("--out-file")
            .arg(&body);
        for certificate in &plan.certificates {
            build.arg("--certificate-file").arg(certificate);
        }
        if let Some(path) = &plan.proposal {
            build.arg("--proposal-file").arg(path);
        }
        if let Some(path) = &plan.vote {
            build.arg("--vote-file").arg(path);
        }
        let parameters = self.node.protocol_parameters(self.timeout)?;
        crate::pool_fixture::run(&mut build, self.timeout)?;
        let mut sign = self.command(&["transaction", "sign", "--tx-body-file"]);
        sign.arg(&body)
            .args(["--testnet-magic", "42", "--out-file"])
            .arg(&signed);
        let mut expected = BTreeSet::new();
        for name in &plan.signers {
            let (_, key) = public_key(&self.fixture.join("public").join(format!("{name}.vkey")))?;
            ensure!(
                expected.insert(hex::encode(key)),
                "duplicate governance signer"
            );
            sign.arg("--signing-key-file")
                .arg(self.fixture.join("private").join(format!("{name}.skey")));
        }
        crate::pool_fixture::run(&mut sign, self.timeout)?;
        let signed_value: Value = serde_json::from_slice(&read(&signed)?)?;
        let encoded = signed_value["cborHex"]
            .as_str()
            .context("governance signed CBOR missing")?;
        let tx = crate::transaction::inspect(encoded, true)?;
        ensure!(
            tx.inputs == [reference.clone()]
                && tx.outputs.len() == 1
                && tx.outputs[0].address_hex
                    == hex::encode(crate::encoding::bech32(&self.address)?.1)
                && tx.outputs[0].assets.is_empty()
                && tx.outputs[0]
                    .coin
                    .checked_add(tx.fee)
                    .and_then(|v| v.checked_add(plan.deposit))
                    == Some(amount),
            "governance input/output/deposit/fee conservation differs"
        );
        ensure!(
            tx.verification_keys.len() == expected.len()
                && tx
                    .verification_keys
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    == expected,
            "governance witness identities/count differ"
        );
        let certificates = plan
            .certificates
            .iter()
            .map(|p| Ok(hex::encode(certificate_bytes(p)?)))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            crate::transaction::certificates(encoded)? == certificates,
            "governance certificate bytes/order differ"
        );
        match &plan.proposal {
            Some(path) => {
                let raw = field(encoded, 20)?.context("proposal field missing")?;
                let mut d = minicbor::Decoder::new(&raw);
                if d.datatype()? == minicbor::data::Type::Tag {
                    ensure!(d.tag()?.as_u64() == 258, "unexpected proposal set tag");
                }
                ensure!(d.array()? == Some(1), "proposal count differs");
                let start = d.position();
                d.skip()?;
                ensure!(
                    raw[start..d.position()] == certificate_bytes(path)?
                        && d.position() == raw.len(),
                    "signed proposal differs"
                );
            }
            None => ensure!(
                field(encoded, 20)?.is_none(),
                "unexpected proposal in governance transaction"
            ),
        }
        match &plan.vote {
            Some(path) => ensure!(
                field(encoded, 19)? == Some(certificate_bytes(path)?),
                "signed voting procedures differ"
            ),
            None => ensure!(
                field(encoded, 19)?.is_none(),
                "unexpected vote in governance transaction"
            ),
        }
        let minimum = u128::from(
            parameters["txFeeFixed"]
                .as_u64()
                .context("node fixed fee missing")?,
        ) + u128::from(
            parameters["txFeePerByte"]
                .as_u64()
                .context("node per-byte fee missing")?,
        ) * hex::decode(encoded)?.len() as u128;
        ensure!(
            u128::from(tx.fee) >= minimum,
            "governance fee below actual signed-size minimum"
        );
        crate::pool_fixture::run(
            self.command(&["transaction", "submit", "--socket-path"])
                .arg(&self.node.socket)
                .args(["--testnet-magic", "42", "--tx-file"])
                .arg(&signed),
            self.timeout,
        )?;
        let deadline = std::time::Instant::now() + self.timeout;
        let after = loop {
            let value = self.node.utxos(&self.address, self.timeout)?;
            let key = format!("{}#0", tx.id);
            if value
                .as_object()
                .context("governance confirmed outputs missing")?
                .contains_key(&key)
            {
                crate::node::validate_payment(&value, &tx.id, &self.address, tx.outputs[0].coin)?;
                ensure!(
                    value.as_object().unwrap().len() == 1
                        && !value.as_object().unwrap().contains_key(reference)
                        && value[&key]["value"] == json!({"lovelace":tx.outputs[0].coin}),
                    "governance spent input/output differs"
                );
                break value;
            }
            ensure!(
                std::time::Instant::now() < deadline,
                "governance transaction confirmation timed out"
            );
            std::thread::sleep(Duration::from_millis(200));
        };
        let proof = json!({"label":plan.label,"transaction_id":tx.id,"fee":tx.fee,"deposit":plan.deposit,"node_parameters":parameters,"before":before,"after":after,"signed_transaction":signed_value});
        write(
            &self.output.join(format!("{}.receipt.json", plan.label)),
            &serde_json::to_vec_pretty(&proof)?,
        )?;
        Ok(proof)
    }
}
/// Enact a real controlled proposal. Fixture receipts never count as wallet conformance.
pub fn enact(
    node: &crate::node::NodeOracle,
    fixture: &Path,
    faucet: &str,
    output: &Path,
    timeout: Duration,
) -> Result<PathBuf> {
    ensure!(
        node.network_magic == 42 && output.is_absolute(),
        "parameter enactment requires owned magic42 fixture"
    );
    let prepared: Value = serde_json::from_slice(&read(&fixture.join("public/receipt.json"))?)?;
    ensure!(
        prepared["kind"] == "owned-committee-parameter-cluster",
        "unexpected committee fixture kind"
    );
    let (_, cold) = public_key(&fixture.join("public/committee-cold.vkey"))?;
    let (_, hot) = public_key(&fixture.join("public/committee-hot.vkey"))?;
    let (_, stake) = public_key(&fixture.join("public/return-stake.vkey"))?;
    let cold_hash = hex::encode(crate::transaction::blake2b(&cold, 28)?);
    ensure!(
        prepared["committee_cold_hash"] == cold_hash,
        "committee fixture identity differs"
    );
    let before_parameters = node.protocol_parameters(timeout)?;
    ensure!(
        before_parameters["txFeePerByte"] == 100
            && before_parameters["utxoCostPerByte"] == 4310
            && before_parameters["stakePoolTargetNum"] == 3
            && before_parameters["govActionDeposit"] == 1_000_000
            && before_parameters["stakeAddressDeposit"] == 1_000_000
            && before_parameters["committeeMinSize"] == 1,
        "node fixture parameters differ"
    );
    for key in ["dRepVotingThresholds", "poolVotingThresholds"] {
        ensure!(
            before_parameters[key]
                .as_object()
                .context("node fixture thresholds missing")?
                .values()
                .all(|v| v.as_f64() == Some(0.0)),
            "node fixture thresholds differ"
        );
    }
    let committee_before = node.query(&["committee-state"], timeout)?;
    let member_key = format!("keyHash-{cold_hash}");
    ensure!(
        committee_before["committee"]
            .as_object()
            .is_some_and(|m| m.len() == 1)
            && committee_before["committee"][&member_key]["expiration"] == 100
            && committee_before["committee"][&member_key]["status"] == "Active"
            && committee_before["committee"][&member_key]["hotCredsAuthStatus"]["tag"]
                == "MemberNotAuthorized"
            && committee_before["threshold"].as_f64() == Some(1.0),
        "actual owned committee state differs"
    );
    ensure!(
        committee_before["epoch"]
            .as_u64()
            .context("committee epoch missing")?
            .checked_add(10)
            .is_some_and(|epoch| epoch < 100),
        "insufficient committee lifetime; fixture must start fresh"
    );
    let governance_before = node.query(&["gov-state"], timeout)?;
    ensure!(
        governance_before["proposals"]
            .as_array()
            .is_some_and(|v| v.is_empty())
            && governance_before["constitution"]["script"].is_null(),
        "node governance fixture is not fresh or has a guardrail script"
    );
    let authorization = fixture.join("public/committee-authorization.cert");
    let registration = fixture.join("public/return-stake-registration.cert");
    certificate_control(
        &certificate_bytes(&authorization)?,
        14,
        &[&cold, &hot],
        None,
    )?;
    certificate_control(
        &certificate_bytes(&registration)?,
        7,
        &[&stake],
        Some(1_000_000),
    )?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .context("enactment output must be fresh")?;
    let address = prepared["payment_address"]
        .as_str()
        .context("fixture payment address missing")?
        .to_owned();
    let submit = Submit {
        node,
        fixture,
        output,
        address: address.clone(),
        timeout,
    };
    ensure!(
        node.utxos(&address, timeout)?
            .as_object()
            .is_some_and(|v| v.is_empty()),
        "committee payment address already funded"
    );
    let api = crate::api::Api::new(faucet, timeout)?;
    let funded=api.request(&crate::api::request("POST","/send/faucet-assets",Some(json!({"batch-size":1,"assets":[{"address":address,"bundle":{"coin":100_000_000,"assets":[]},"metadata":[]}]}))))?;
    ensure!(funded.status == 204, "committee faucet rejected funding");
    let deadline = std::time::Instant::now() + timeout;
    let funding = loop {
        let value = node.utxos(&address, timeout)?;
        if value
            .as_object()
            .context("committee funding map missing")?
            .len()
            == 1
        {
            ensure!(
                value
                    .as_object()
                    .unwrap()
                    .values()
                    .all(|v| v["address"] == address
                        && v["value"] == json!({"lovelace":100_000_000})),
                "committee funding differs"
            );
            break value;
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "committee funding timed out"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    let setup = submit.send(
        funding,
        Plan {
            label: "authorization",
            certificates: vec![registration, authorization],
            proposal: None,
            vote: None,
            signers: vec!["payment", "return-stake", "committee-cold"],
            deposit: 1_000_000,
        },
    )?;
    let committee_authorized = node.query(&["committee-state"], timeout)?;
    ensure!(
        committee_authorized["committee"][&member_key]["hotCredsAuthStatus"]["tag"]
            == "MemberAuthorized",
        "node did not authorize committee hot key"
    );
    let anchor = serde_json::to_vec(
        &json!({"title":"Owned conformance parameter update","parameters":{"txFeePerByte":101,"utxoCostPerByte":4320,"stakePoolTargetNum":4}}),
    )?;
    let anchor_hash = crate::transaction::blake2b(&anchor, 32)?;
    let anchor_file = output.join("anchor.json");
    write(&anchor_file, &anchor)?;
    crate::pool_fixture::run(
        Command::new(&node.executable)
            .args(["hash", "anchor-data", "--file-binary"])
            .arg(&anchor_file)
            .arg("--expected-hash")
            .arg(hex::encode(&anchor_hash)),
        timeout,
    )?;
    let server = AnchorServer::start(anchor)?;
    let proposal_file = output.join("proposal.json");
    crate::pool_fixture::run(
        submit
            .command(&[
                "governance",
                "action",
                "create-protocol-parameters-update",
                "--testnet",
                "--governance-action-deposit",
                "1000000",
                "--deposit-return-stake-verification-key-file",
            ])
            .arg(fixture.join("public/return-stake.vkey"))
            .args([
                "--anchor-url",
                &server.url,
                "--anchor-data-hash",
                &hex::encode(&anchor_hash),
                "--min-fee-linear",
                "101",
                "--number-of-pools",
                "4",
                "--utxo-cost-per-byte",
                "4320",
                "--out-file",
            ])
            .arg(&proposal_file),
        timeout,
    )?;
    proposal_control(
        &certificate_bytes(&proposal_file)?,
        &stake,
        &server.url,
        &anchor_hash,
    )?;
    let proposal = submit.send(
        setup["after"].clone(),
        Plan {
            label: "proposal",
            certificates: vec![],
            proposal: Some(proposal_file),
            vote: None,
            signers: vec!["payment"],
            deposit: 1_000_000,
        },
    )?;
    let governance_proposed = node.query(&["gov-state"], timeout)?;
    let txid = proposal["transaction_id"]
        .as_str()
        .context("proposal hash missing")?;
    let vote_file = output.join("vote.json");
    crate::pool_fixture::run(
        submit
            .command(&[
                "governance",
                "vote",
                "create",
                "--yes",
                "--governance-action-tx-id",
                txid,
                "--governance-action-index",
                "0",
                "--cc-hot-verification-key-file",
            ])
            .arg(fixture.join("public/committee-hot.vkey"))
            .arg("--out-file")
            .arg(&vote_file),
        timeout,
    )?;
    vote_control(&certificate_bytes(&vote_file)?, &hot, txid)?;
    let vote = submit.send(
        proposal["after"].clone(),
        Plan {
            label: "vote",
            certificates: vec![],
            proposal: None,
            vote: Some(vote_file),
            signers: vec!["payment", "committee-hot"],
            deposit: 0,
        },
    )?;
    let governance_voted = node.query(&["gov-state"], timeout)?;
    let deadline = std::time::Instant::now() + timeout;
    let after_parameters = loop {
        let value = node.protocol_parameters(timeout)?;
        if value["txFeePerByte"] == 101
            && value["utxoCostPerByte"] == 4320
            && value["stakePoolTargetNum"] == 4
        {
            break value;
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "parameter proposal did not enact"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    let mut unchanged_before = before_parameters.clone();
    let mut unchanged_after = after_parameters.clone();
    for key in ["txFeePerByte", "utxoCostPerByte", "stakePoolTargetNum"] {
        unchanged_before.as_object_mut().unwrap().remove(key);
        unchanged_after.as_object_mut().unwrap().remove(key);
    }
    ensure!(
        unchanged_before == unchanged_after,
        "unrequested node parameters changed during enactment"
    );
    let governance_after = node.query(&["gov-state"], timeout)?;
    let receipt = output.join("receipt.json");
    write(
        &receipt,
        &serde_json::to_vec_pretty(
            &json!({"format_version":1,"kind":"owned-committee-parameter-enactment","counts_as_conformance_evidence":false,"before_parameters":before_parameters,"after_parameters":after_parameters,"committee_before":committee_before,"committee_authorized":committee_authorized,"governance_before":governance_before,"governance_proposed":governance_proposed,"governance_voted":governance_voted,"governance_after":governance_after,"setup":setup,"proposal":proposal,"vote":vote,"proposal_id":txid,"anchor_hash":hex::encode(anchor_hash)}),
        )?,
    )?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_cli_parameter_proposal_and_vote_reject_mutated_public_fields() {
        let value: Value =
            serde_json::from_str(include_str!("../fixtures/parameter-proposal-control.json"))
                .unwrap();
        let key = |name: &str| {
            let raw = hex::decode(value[name]["cborHex"].as_str().unwrap()).unwrap();
            minicbor::Decoder::new(&raw).bytes().unwrap().to_vec()
        };
        let stake = key("stake");
        let hot = key("hot");
        let hash = hex::decode(value["anchor_hash"].as_str().unwrap()).unwrap();
        let url = value["url"].as_str().unwrap();
        let txid = value["txid"].as_str().unwrap();
        let proposal = hex::decode(value["proposal"]["cborHex"].as_str().unwrap()).unwrap();
        let vote = hex::decode(value["vote"]["cborHex"].as_str().unwrap()).unwrap();
        proposal_control(&proposal, &stake, url, &hash).unwrap();
        vote_control(&vote, &hot, txid).unwrap();
        assert!(proposal_control(&proposal, &hot, url, &hash).is_err());
        assert!(proposal_control(&proposal, &stake, "http://different", &hash).is_err());
        assert!(proposal_control(&proposal, &stake, url, &[1; 32]).is_err());
        let mut bad = proposal.clone();
        bad[3] ^= 1;
        assert!(proposal_control(&bad, &stake, url, &hash).is_err());
        assert!(vote_control(&vote, &stake, txid).is_err());
        assert!(vote_control(&vote, &hot, &"11".repeat(32)).is_err());
        let mut bad = vote.clone();
        let last = bad.len() - 2;
        bad[last] = 0;
        assert!(vote_control(&bad, &hot, txid).is_err());
    }
    #[test]
    fn committee_and_deposit_certificates_reject_type_key_deposit_and_trailing_mutations() {
        let cold = [1u8; 32];
        let hot = [2u8; 32];
        let mut encoded = minicbor::Encoder::new(Vec::new());
        encoded.array(3).unwrap().u64(14).unwrap();
        for key in [&cold, &hot] {
            encoded
                .array(2)
                .unwrap()
                .u8(0)
                .unwrap()
                .bytes(&crate::transaction::blake2b(key, 28).unwrap())
                .unwrap();
        }
        let raw = encoded.into_writer();
        certificate_control(&raw, 14, &[&cold, &hot], None).unwrap();
        assert!(certificate_control(&raw, 15, &[&cold, &hot], None).is_err());
        assert!(certificate_control(&raw, 14, &[&hot, &cold], None).is_err());
        let mut bad = raw.clone();
        bad.push(0);
        assert!(certificate_control(&bad, 14, &[&cold, &hot], None).is_err());
        let mut encoded = minicbor::Encoder::new(Vec::new());
        encoded
            .array(3)
            .unwrap()
            .u8(7)
            .unwrap()
            .array(2)
            .unwrap()
            .u8(0)
            .unwrap()
            .bytes(&crate::transaction::blake2b(&cold, 28).unwrap())
            .unwrap()
            .u64(1_000_000)
            .unwrap();
        let raw = encoded.into_writer();
        certificate_control(&raw, 7, &[&cold], Some(1_000_000)).unwrap();
        assert!(certificate_control(&raw, 7, &[&cold], Some(0)).is_err());
    }
    #[test]
    fn controlled_genesis_changes_only_explicit_fixture_policy() {
        let before = json!({"constitution":{"script":"old","anchor":{"url":"fixture"}},"dRepVotingThresholds":{"ppEconomicGroup":0.67},"poolVotingThresholds":{"ppSecurityGroup":0.51},"committee":{"old":true},"committeeMinSize":7,"govActionDeposit":100000000000u64,"unrelated":[1,2,3]});
        let hash = "ab".repeat(28);
        let after = genesis(before.clone(), &hash).unwrap();
        assert_eq!(after["unrelated"], before["unrelated"]);
        assert_eq!(
            after["constitution"]["anchor"],
            before["constitution"]["anchor"]
        );
        assert!(after["constitution"]["script"].is_null());
        assert_eq!(
            after["committee"]["members"][format!("keyHash-{hash}")],
            100
        );
        assert_eq!(
            after["committee"]["threshold"],
            json!({"numerator":1,"denominator":1})
        );
        assert_eq!(after["dRepVotingThresholds"]["ppEconomicGroup"], 0);
        assert_eq!(after["poolVotingThresholds"]["ppSecurityGroup"], 0);
        assert!(genesis(before, "ff").is_err());
    }
    #[test]
    fn config_copy_never_follows_symlinks_or_enumerates_nix_store() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("config.json"), b"{}").unwrap();
        let target = root.path().join("copy");
        copy_tree(&source, &target, &mut 0).unwrap();
        assert_eq!(read(&target.join("config.json")).unwrap(), b"{}");
        std::os::unix::fs::symlink(root.path(), source.join("outside")).unwrap();
        assert!(copy_tree(&source, &root.path().join("bad"), &mut 0).is_err());
        assert!(copy_tree(
            Path::new("/nix/store"),
            &root.path().join("forbidden"),
            &mut 0
        )
        .is_err());
        assert!(!root.path().join("forbidden").exists());
    }
}
