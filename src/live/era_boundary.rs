//! Actual wallet restoration, payment and certificates across a scheduled hard fork.
use super::{families::SHELLEY, *};
use crate::{
    era_fixture::{self, Observer},
    node::NodeOracle,
    owned_process::{Launch, WalletProcess},
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
};
const PASSWORD: &str = "conformance-test-passphrase";
const FUNDING: u64 = 100_000_000;

pub(super) fn public_key(id: &str) -> Result<Vec<u8>> {
    let vectors: Value =
        serde_json::from_str(include_str!("../../fixtures/vectors/haskell-keys.json"))?;
    let vector = vectors
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .context("missing frozen Haskell public key")?;
    let key = hex::decode(text(vector, "/expected/result/xpub_hex")?)?;
    ensure!(key.len() == 64, "frozen public key length differs");
    Ok(key[..32].to_vec())
}
pub(super) fn base_address() -> Result<String> {
    let mut raw = vec![0];
    for id in [
        "haskell-Shelley-0-0-0-private",
        "haskell-Shelley-0-2-0-private",
    ] {
        raw.extend_from_slice(&transaction::blake2b(&public_key(id)?, 28)?);
    }
    crate::encoding::bech32_encode("addr_test", &raw)
}
fn destination(byte: u8) -> Result<String> {
    let mut raw = vec![0x60];
    raw.extend_from_slice(&[byte; 28]);
    crate::encoding::bech32_encode("addr_test", &raw)
}
fn command(cli: &Path, era: &str, args: &[&str]) -> Command {
    let mut c = Command::new(cli);
    c.arg(era).args(args);
    c
}
fn encoded(value: &Value) -> Result<String> {
    Ok(hex::encode(assets::encoded_bytes(&text(
        value,
        "/transaction",
    )?)?))
}
fn history_core(value: &Value) -> Result<Value> {
    let mut values = value
        .as_array()
        .context("era history is not an array")?
        .clone();
    for tx in &mut values {
        tx.as_object_mut()
            .context("era history item is not an object")?
            .remove("depth");
    }
    Ok(Value::Array(values))
}
fn unsupported() -> Value {
    json!({"code":"node_not_yet_in_recent_era",
        "message":"This operation requires the node to be synchronised to a recent era, but the node is currently only synchronised to the Babbage era. Please wait until the node is fully synchronised and try again.",
        "info":{"node_era":"babbage","supported_recent_eras":["conway"]}})
}
fn certificate(tag: u8, stake: &[u8], deposit: u64) -> Result<Vec<u8>> {
    ensure!(
        [7, 8].contains(&tag) && stake.len() == 28,
        "invalid controlled stake certificate"
    );
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)?
        .u8(tag)?
        .array(2)?
        .u8(0)?
        .bytes(stake)?
        .u64(deposit)?;
    Ok(e.into_writer())
}
fn fee_floor(tx: &transaction::Transaction, raw: &str, pp: &Value) -> Result<()> {
    ensure!(
        u128::from(tx.fee)
            >= u128::from(number(pp, "/txFeeFixed")?)
                + u128::from(number(pp, "/txFeePerByte")?) * hex::decode(raw)?.len() as u128,
        "era fixture fee is below signed-size node minimum"
    );
    Ok(())
}
fn converge_fee(initial: u64, mut required: impl FnMut(u64) -> Result<u64>) -> Result<u64> {
    let mut fee = initial;
    for _ in 0..16 {
        let next = required(fee)?;
        if next == fee {
            return Ok(fee);
        }
        fee = next;
    }
    anyhow::bail!("signed-size fixture fee did not converge")
}
fn wait_output(
    node: &NodeOracle,
    txid: &str,
    address: &str,
    index: usize,
    coin: u64,
    timeout: Duration,
) -> Result<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "era output confirmation timed out");
        let value = node.utxos(address, remaining)?;
        let map = value.as_object().context("era node UTxO map missing")?;
        let matching: Vec<_> = map
            .keys()
            .filter(|k| k.starts_with(&format!("{txid}#")))
            .collect();
        if !matching.is_empty() {
            let reference = format!("{txid}#{index}");
            ensure!(
                matching.len() == 1
                    && matching[0] == &reference
                    && value[&reference]["address"] == address
                    && value[&reference]["value"] == json!({"lovelace":coin}),
                "era confirmed output index/address/value/assets differs"
            );
            crate::node::validate_payment(&value, txid, address, coin)?;
            return Ok(value);
        }
        sleep(Duration::from_millis(200).min(deadline.saturating_duration_since(Instant::now())));
    }
}

struct WalletObserver<'a> {
    session: Session<'a>,
    launch: Launch,
    process: Option<WalletProcess>,
    files: PathBuf,
    funder: String,
    funder_key: Vec<u8>,
    id: Option<String>,
    address: String,
    current: String,
    before: Value,
    funding_id: String,
}
impl WalletObserver<'_> {
    fn raw_payment(
        &self,
        node: &NodeOracle,
        era: &str,
        to: &str,
        coin: u64,
        label: &str,
    ) -> Result<Value> {
        let timeout = self.session.timeout;
        let before = node.utxos(&self.funder, timeout)?;
        let entries = before.as_object().context("era funder UTxOs missing")?;
        ensure!(entries.len() == 1, "era funder requires exactly one input");
        let (reference, input) = entries.iter().next().unwrap();
        let available = number(input, "/value/lovelace")?;
        ensure!(
            input["address"] == self.funder && input["value"] == json!({"lovelace":available}),
            "era funder assets/address differ"
        );
        let body = self.files.join(format!("{label}.body"));
        let signed = self.files.join(format!("{label}.signed"));
        if era == "babbage" {
            let help = crate::pool_fixture::run(
                Command::new(&node.executable).args([
                    "compatible",
                    "babbage",
                    "transaction",
                    "signed-transaction",
                    "--help",
                ]),
                timeout,
            )?;
            let help = std::str::from_utf8(&help)?;
            ensure!(
                help.contains("--fee")
                    && help.contains("--signing-key-file")
                    && help.contains("--tx-out"),
                "CLI lacks compatible Babbage signed construction"
            );
            let pp = node.protocol_parameters(timeout)?;
            let fixed = number(&pp, "/txFeeFixed")?;
            let rate = number(&pp, "/txFeePerByte")?;
            converge_fee(fixed, |fee| {
                let change = available
                    .checked_sub(coin)
                    .and_then(|v| v.checked_sub(fee))
                    .context("Babbage fixture fee exceeds available funds")?;
                crate::pool_fixture::run(
                    Command::new(&node.executable)
                        .args([
                            "compatible",
                            "babbage",
                            "transaction",
                            "signed-transaction",
                            "--tx-in",
                        ])
                        .arg(reference)
                        .arg("--tx-out")
                        .arg(format!("{to}+{coin}"))
                        .arg("--tx-out")
                        .arg(format!("{}+{change}", self.funder))
                        .arg("--fee")
                        .arg(fee.to_string())
                        .arg("--signing-key-file")
                        .arg(self.files.join("funder.skey"))
                        .args(["--testnet-magic", "42", "--out-file"])
                        .arg(&signed),
                    timeout,
                )?;
                let envelope: Value = serde_json::from_slice(&era_fixture::read(&signed)?)?;
                let raw = text(&envelope, "/cborHex")?;
                let tx = transaction::inspect(&raw, true)?;
                ensure!(
                    tx.fee == fee,
                    "compatible Babbage constructor changed explicit fee"
                );
                fixed
                    .checked_add(
                        rate.checked_mul(hex::decode(raw)?.len() as u64)
                            .context("fixture fee multiplication overflow")?,
                    )
                    .context("fixture fee overflow")
            })?;
        } else {
            crate::pool_fixture::run(
                command(
                    &node.executable,
                    era,
                    &["transaction", "build", "--socket-path"],
                )
                .arg(&node.socket)
                .args(["--testnet-magic", "42", "--tx-in"])
                .arg(reference)
                .arg("--tx-out")
                .arg(format!("{to}+{coin}"))
                .arg("--change-address")
                .arg(&self.funder)
                .args(["--witness-override", "1", "--out-file"])
                .arg(&body),
                timeout,
            )?;
            crate::pool_fixture::run(
                command(
                    &node.executable,
                    era,
                    &["transaction", "sign", "--tx-body-file"],
                )
                .arg(&body)
                .arg("--signing-key-file")
                .arg(self.files.join("funder.skey"))
                .args(["--testnet-magic", "42", "--out-file"])
                .arg(&signed),
                timeout,
            )?;
        }
        let envelope: Value = serde_json::from_slice(&era_fixture::read(&signed)?)?;
        let raw = text(&envelope, "/cborHex")?;
        let tx = transaction::inspect(&raw, true)?;
        ensure!(
            tx.inputs == [reference.clone()]
                && tx.verification_keys == [hex::encode(&self.funder_key)]
                && tx.outputs.len() == 2
                && tx.outputs.iter().all(|v| v.assets.is_empty())
                && tx.outputs[0].address_hex == hex::encode(crate::encoding::bech32(to)?.1)
                && tx.outputs[0].coin == coin
                && tx.outputs[1].address_hex
                    == hex::encode(crate::encoding::bech32(&self.funder)?.1)
                && tx
                    .outputs
                    .iter()
                    .try_fold(tx.fee, |sum, v| sum.checked_add(v.coin))
                    == Some(available)
                && transaction::certificates(&raw)?.is_empty(),
            "era funding/integration body, signature or conservation differs"
        );
        fee_floor(&tx, &raw, &node.protocol_parameters(timeout)?)?;
        crate::pool_fixture::run(
            command(
                &node.executable,
                if era == "babbage" { "conway" } else { era },
                &["transaction", "submit", "--socket-path"],
            )
            .arg(&node.socket)
            .args(["--testnet-magic", "42", "--tx-file"])
            .arg(&signed),
            timeout,
        )?;
        let recipient = wait_output(node, &tx.id, to, 0, coin, timeout)?;
        let change = wait_output(node, &tx.id, &self.funder, 1, tx.outputs[1].coin, timeout)?;
        ensure!(
            change.as_object().unwrap().len() == 1 && change.get(reference).is_none(),
            "era funding input not spent"
        );
        Ok(
            json!({"id":tx.id,"signed_transaction":envelope,"before":before,"recipient":recipient,"change":change,"fee":tx.fee}),
        )
    }
    fn snapshot(&mut self) -> Result<Value> {
        let id = self.id.clone().context("era wallet missing")?;
        let wallet = self
            .session
            .call("getWallet", "GET", &format!("/wallets/{id}"), None, 200)?;
        let utxo = self.session.call(
            "getWalletUtxoSnapshot",
            "GET",
            &format!("/wallets/{id}/utxo"),
            None,
            200,
        )?;
        let addresses = self.session.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{id}/addresses"),
            None,
            200,
        )?;
        let history = self.session.call(
            "listTransactions",
            "GET",
            &format!("/wallets/{id}/transactions"),
            None,
            200,
        )?;
        Ok(
            json!({"id":id,"balance":wallet["balance"],"assets":wallet["assets"],"utxo":utxo,"addresses":addresses,"history":history_core(&history)?}),
        )
    }
    fn signed(&mut self, unsigned: &str) -> Result<String> {
        let id = self.id.as_ref().context("era wallet missing")?;
        let signed = self.session.call(
            "signTransaction",
            "POST",
            &format!("/wallets/{id}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":PASSWORD,"encoding":"base16"})),
            202,
        )?;
        encoded(&signed)
    }
    fn accept(
        &mut self,
        node: &NodeOracle,
        raw: &str,
        previous: &str,
    ) -> Result<(transaction::Transaction, Value, Value)> {
        let tx = transaction::inspect(raw, true)?;
        let before = node.utxos(previous, self.session.timeout)?;
        let entries = before
            .as_object()
            .context("era wallet node funding missing")?;
        ensure!(
            entries.len() == 1 && tx.inputs == [entries.keys().next().unwrap().clone()],
            "era wallet selected an independently unknown input"
        );
        let id = self.id.clone().context("era wallet missing")?;
        let submit = self.session.call(
            "submitTransaction",
            "POST",
            &format!("/wallets/{id}/transactions-submit"),
            Some(json!({"transaction":raw})),
            202,
        )?;
        ensure!(submit["id"] == tx.id, "era submission ID differs");
        let confirmed = self.session.family_confirm(SHELLEY, &id, &tx.id)?;
        ensure!(
            confirmed["fee"] == json!({"quantity":tx.fee,"unit":"lovelace"}),
            "era wallet/node fee differs"
        );
        let mut proofs = Vec::new();
        for (index, output) in tx.outputs.iter().enumerate() {
            let bytes = hex::decode(&output.address_hex)?;
            let address = crate::encoding::bech32_encode("addr_test", &bytes)?;
            proofs.push(wait_output(
                node,
                &tx.id,
                &address,
                index,
                output.coin,
                self.session.timeout,
            )?);
        }
        ensure!(
            node.utxos(previous, self.session.timeout)?
                .get(&tx.inputs[0])
                .is_none(),
            "era wallet input remains unspent"
        );
        Ok((
            tx,
            confirmed,
            json!({"before":before,"outputs":proofs,"signed_cbor_hex":raw}),
        ))
    }
    fn stake_change(
        &mut self,
        node: &NodeOracle,
        register: bool,
        balance: u64,
    ) -> Result<(u64, Value)> {
        let timeout = self.session.timeout;
        let label = if register { "register" } else { "deregister" };
        let deposit = number(&node.protocol_parameters(timeout)?, "/stakeAddressDeposit")?;
        let stake = public_key("haskell-Shelley-0-2-0-private")?;
        let hash = transaction::blake2b(&stake, 28)?;
        let cert = self.files.join(format!("{label}.cert"));
        let command_name = if register {
            "registration-certificate"
        } else {
            "deregistration-certificate"
        };
        crate::pool_fixture::run(
            command(
                &node.executable,
                "conway",
                &[
                    "stake-address",
                    command_name,
                    "--stake-verification-key-file",
                ],
            )
            .arg(self.files.join("stake.vkey"))
            .arg("--key-reg-deposit-amt")
            .arg(deposit.to_string())
            .arg("--out-file")
            .arg(&cert),
            timeout,
        )?;
        let expected = certificate(if register { 7 } else { 8 }, &hash, deposit)?;
        ensure!(
            crate::protocol_update::certificate_bytes(&cert)? == expected,
            "era stake certificate differs from independent encoding"
        );
        let before = node.utxos(&self.current, timeout)?;
        let entries = before
            .as_object()
            .context("era certificate input missing")?;
        ensure!(
            entries.len() == 1
                && entries.values().next().unwrap()["value"] == json!({"lovelace":balance}),
            "era certificate balance differs"
        );
        let reference = entries.keys().next().unwrap();
        let body = self.files.join(format!("{label}.body"));
        crate::pool_fixture::run(
            command(
                &node.executable,
                "conway",
                &["transaction", "build", "--socket-path"],
            )
            .arg(&node.socket)
            .args(["--testnet-magic", "42", "--tx-in"])
            .arg(reference)
            .arg("--change-address")
            .arg(&self.current)
            .arg("--certificate-file")
            .arg(&cert)
            .args(["--witness-override", "2", "--out-file"])
            .arg(&body),
            timeout,
        )?;
        let envelope: Value = serde_json::from_slice(&era_fixture::read(&body)?)?;
        let unsigned = text(&envelope, "/cborHex")?;
        let original = transaction::inspect(&unsigned, false)?;
        let raw = self.signed(&unsigned)?;
        let signed = transaction::inspect(&raw, true)?;
        let mut witness_hashes = BTreeSet::new();
        for public in &signed.verification_keys {
            witness_hashes.insert(hex::encode(transaction::blake2b(
                &hex::decode(public)?,
                28,
            )?));
        }
        let address = crate::encoding::bech32(&self.current)?.1;
        let wanted: BTreeSet<_> = [hex::encode(&address[1..29]), hex::encode(&hash)]
            .into_iter()
            .collect();
        let (taken, refunded) = if register { (deposit, 0) } else { (0, deposit) };
        ensure!(
            signed.id == original.id
                && signed.inputs == [reference.clone()]
                && signed.outputs.len() == 1
                && signed.outputs[0].address_hex == hex::encode(&address)
                && signed.outputs[0].assets.is_empty()
                && signed.verification_keys.len() == 2
                && witness_hashes == wanted
                && transaction::certificates(&raw)? == [hex::encode(expected)]
                && u128::from(balance) + u128::from(refunded)
                    == u128::from(signed.outputs[0].coin)
                        + u128::from(signed.fee)
                        + u128::from(taken),
            "era certificate body/witness/deposit conservation differs"
        );
        fee_floor(&signed, &raw, &node.protocol_parameters(timeout)?)?;
        let previous = self.current.clone();
        let (tx, history, proof) = self.accept(node, &raw, &previous)?;
        ensure!(
            history["deposit_taken"] == json!({"quantity":taken,"unit":"lovelace"})
                && history["deposit_returned"] == json!({"quantity":refunded,"unit":"lovelace"})
                && history["amount"]
                    == json!({"quantity":(tx.fee+taken).abs_diff(refunded),"unit":"lovelace"})
                && history["direction"]
                    == if refunded > tx.fee + taken {
                        "incoming"
                    } else {
                        "outgoing"
                    },
            "era certificate wallet accounting differs"
        );
        let kind = if register {
            "register_reward_account"
        } else {
            "quit_pool"
        };
        ensure!(
            history["certificates"]
                == json!([{"certificate_type":kind,"reward_account_path":["1852H","1815H","0H","2","0"]}]),
            "era wallet certificate path/type differs"
        );
        let mut reward = vec![0xe0];
        reward.extend_from_slice(&hash);
        let reward = crate::encoding::bech32_encode("stake_test", &reward)?;
        let state = node.stake_address_info(&reward, timeout)?;
        let expected = if register {
            json!([{"address":reward,"govActionDeposits":{},"rewardAccountBalance":0,"stakeDelegation":null,"stakeRegistrationDeposit":deposit,"voteDelegation":null}])
        } else {
            json!([])
        };
        ensure!(
            state == expected,
            "era node stake registration/deposit/reward/delegation state differs"
        );
        self.session.family_ready_balance(
            SHELLEY,
            self.id.as_ref().unwrap(),
            tx.outputs[0].coin,
        )?;
        self.session
            .check_snapshot(self.id.as_ref().unwrap(), tx.outputs[0].coin)?;
        Ok((
            tx.outputs[0].coin,
            json!({"transaction_id":tx.id,"fee":tx.fee,"history":history,"node":proof,"stake_state":state}),
        ))
    }
}

impl Observer for WalletObserver<'_> {
    fn funding(&mut self, cli: &Path, root: &Path) -> Result<Option<(String, u64)>> {
        self.files = root.join("wallet-fixture");
        era_fixture::directory(&self.files)?;
        crate::pool_fixture::run(
            command(
                cli,
                "conway",
                &["address", "key-gen", "--verification-key-file"],
            )
            .arg(self.files.join("funder.vkey"))
            .arg("--signing-key-file")
            .arg(self.files.join("funder.skey")),
            self.session.timeout,
        )?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            self.files.join("funder.skey"),
            std::fs::Permissions::from_mode(0o600),
        )?;
        self.funder_key = crate::protocol_update::public_key(&self.files.join("funder.vkey"))?.1;
        let mut bytes = vec![0x60];
        bytes.extend_from_slice(&transaction::blake2b(&self.funder_key, 28)?);
        self.funder = crate::encoding::bech32_encode("addr_test", &bytes)?;
        let mut raw = minicbor::Encoder::new(Vec::new());
        raw.bytes(&public_key("haskell-Shelley-0-2-0-private")?)?;
        era_fixture::save(
            &self.files.join("stake.vkey"),
            &json!({"type":"StakeVerificationKeyShelley_ed25519","description":"public Haskell conformance vector","cborHex":hex::encode(raw.into_writer())}),
        )?;
        self.address = base_address()?;
        self.current = self.address.clone();
        Ok(Some((hex::encode(bytes), 200_000_000)))
    }
    fn before(&mut self, node: &NodeOracle, root: &Path, _tip: &Value) -> Result<Value> {
        let funding =
            self.raw_payment(node, "babbage", &self.address, FUNDING, "pre-fork-funding")?;
        self.funding_id = text(&funding, "/id")?;
        let mut launch = self.launch.clone();
        for arg in &mut launch.arguments {
            if arg == "{node_socket}" {
                *arg = node.socket.display().to_string();
            }
            if arg == "{byron_genesis}" {
                *arg = root.join("byron-genesis.json").display().to_string();
            }
        }
        let mut process = WalletProcess::start(launch, &root.join("wallet-runtime"))?;
        process.wait_listener(&self.session.api.label, self.session.timeout)?;
        era_fixture::save(
            &root.join("public/wallet-launch.json"),
            &json!({"pid":process.ensure_running()?,
            "executable_sha256":process.executable_sha256(),"owned_foreground_process":true}),
        )?;
        self.process = Some(process);
        let vectors: Value =
            serde_json::from_str(include_str!("../../fixtures/vectors/haskell-keys.json"))?;
        let mnemonic = vectors[0]["input"]["mnemonic"]
            .as_str()
            .context("published mnemonic missing")?
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        let id = self.session.create("conformance-era-boundary", mnemonic)?;
        self.id = Some(id.clone());
        self.session.family_ready_balance(SHELLEY, &id, FUNDING)?;
        self.session.check_snapshot(&id, FUNDING)?;
        let snapshot = self.snapshot()?;
        ensure!(
            snapshot["history"].as_array().is_some_and(|h| h.len() == 1
                && h[0]["id"] == self.funding_id
                && h[0]["status"] == "in_ledger"
                && h[0]["amount"] == json!({"quantity":FUNDING,"unit":"lovelace"}))
                && snapshot["addresses"].as_array().is_some_and(|a| a
                    .iter()
                    .any(|v| v["id"] == self.address && v["state"] == "used")),
            "pre-fork restoration history/address differs from independent funding"
        );
        let tip = node.query(&["tip"], self.session.timeout)?;
        ensure!(
            tip["era"] == "Babbage",
            "wallet did not restore before the hard fork"
        );
        let payment = json!({"payments":[{"address":destination(0x11)?,"amount":{"quantity":2_000_000,"unit":"lovelace"}}]});
        let error = self.session.call(
            "constructTransaction",
            "POST",
            &format!("/wallets/{id}/transactions-construct"),
            Some(payment),
            403,
        )?;
        ensure!(
            error == unsupported(),
            "pre-fork unsupported-era error differs from pinned Haskell"
        );
        ensure!(
            self.snapshot()? == snapshot,
            "unsupported-era construction changed wallet state"
        );
        let node_funding = node.utxos(&self.address, self.session.timeout)?;
        let before_end = node.query(&["tip"], self.session.timeout)?;
        ensure!(
            before_end["era"] == "Babbage",
            "pre-fork assertions crossed the boundary"
        );
        self.before = snapshot.clone();
        Ok(
            json!({"funding":funding,"snapshot":snapshot,"node_funding":node_funding,"tip":tip,"tip_after_guards":before_end,"unsupported_error":error}),
        )
    }
    fn after(&mut self, node: &NodeOracle, _root: &Path, tip: &Value) -> Result<Value> {
        let id = self.id.clone().context("era wallet missing")?;
        let height = number(tip, "/block")?;
        self.session
            .poll("getNetworkInformation", "/network/information", |v| {
                v.pointer("/node_tip/height/quantity")
                    .and_then(Value::as_u64)
                    .is_some_and(|h| h >= height)
                    && v["sync_progress"]["status"] == "ready"
            })?;
        ensure!(
            self.snapshot()? == self.before,
            "restored wallet changed across the boundary without a transaction"
        );
        let recipient = destination(0x11)?;
        let constructed = self.session.call("constructTransaction","POST",&format!("/wallets/{id}/transactions-construct"),
            Some(json!({"payments":[{"address":recipient,"amount":{"quantity":2_000_000,"unit":"lovelace"}}]})),202)?;
        let unsigned = encoded(&constructed)?;
        let original = transaction::inspect(&unsigned, false)?;
        let raw = self.signed(&unsigned)?;
        let signed = transaction::inspect(&raw, true)?;
        ensure!(
            signed.id == original.id
                && signed.verification_keys.len() == 1
                && transaction::certificates(&raw)?.is_empty()
                && signed.outputs.len() == 2
                && signed.outputs.iter().all(|o| o.assets.is_empty())
                && signed
                    .outputs
                    .iter()
                    .try_fold(signed.fee, |sum, o| sum.checked_add(o.coin))
                    == Some(FUNDING),
            "post-fork wallet payment body/conservation differs"
        );
        let recipient_hex = hex::encode(crate::encoding::bech32(&recipient)?.1);
        ensure!(
            signed
                .outputs
                .iter()
                .filter(|o| o.address_hex == recipient_hex && o.coin == 2_000_000)
                .count()
                == 1,
            "post-fork payment destination/value differs"
        );
        let original_address = crate::encoding::bech32(&self.address)?.1;
        ensure!(
            transaction::blake2b(&hex::decode(&signed.verification_keys[0])?, 28)?
                == original_address[1..29],
            "post-fork payment witness does not own restored funding"
        );
        let pp = node.protocol_parameters(self.session.timeout)?;
        let fee = parameters::fee_control(&raw, &pp, number(&constructed, "/fee/quantity")?)?;
        let previous = self.current.clone();
        let (tx, payment_history, payment_node) = self.accept(node, &raw, &previous)?;
        let change = tx
            .outputs
            .iter()
            .find(|o| o.address_hex != recipient_hex)
            .context("post-fork payment change missing")?;
        self.current =
            crate::encoding::bech32_encode("addr_test", &hex::decode(&change.address_hex)?)?;
        let balance = FUNDING - 2_000_000 - tx.fee;
        ensure!(
            change.coin == balance
                && payment_history["amount"]
                    == json!({"quantity":2_000_000+tx.fee,"unit":"lovelace"}),
            "post-fork payment wallet amount/change differs"
        );
        self.session.family_ready_balance(SHELLEY, &id, balance)?;
        self.session.check_snapshot(&id, balance)?;
        let mut reward = vec![0xe0];
        reward.extend_from_slice(&transaction::blake2b(
            &public_key("haskell-Shelley-0-2-0-private")?,
            28,
        )?);
        let reward = crate::encoding::bech32_encode("stake_test", &reward)?;
        ensure!(
            node.stake_address_info(&reward, self.session.timeout)? == json!([]),
            "pre-certificate reward account is not empty"
        );
        let (registered, registration) = self.stake_change(node, true, balance)?;
        let (final_balance, deregistration) = self.stake_change(node, false, registered)?;
        ensure!(
            final_balance
                == balance - number(&registration, "/fee")? - number(&deregistration, "/fee")?,
            "era final balance does not conserve all fees/refunded deposit"
        );
        let final_snapshot = self.snapshot()?;
        let history = final_snapshot["history"]
            .as_array()
            .context("final era history missing")?;
        let ids: BTreeSet<_> = history
            .iter()
            .map(|v| text(v, "/id"))
            .collect::<Result<_>>()?;
        let wanted: BTreeSet<_> = [
            self.funding_id.clone(),
            tx.id.clone(),
            text(&registration, "/transaction_id")?,
            text(&deregistration, "/transaction_id")?,
        ]
        .into_iter()
        .collect();
        ensure!(
            history.len() == 4
                && ids == wanted
                && history.iter().all(|v| v["status"] == "in_ledger"),
            "era complete history identity/status differs"
        );
        let pid = self
            .process
            .as_mut()
            .context("owned era wallet missing")?
            .ensure_running()?;
        self.session.call(
            "deleteWallet",
            "DELETE",
            &format!("/wallets/{id}"),
            None,
            204,
        )?;
        self.session.owned.clear();
        self.id = None;
        for (operation, path) in [
            ("listWallets", "/wallets"),
            ("listByronWallets", "/byron-wallets"),
            ("listSharedWallets", "/shared-wallets"),
        ] {
            ensure!(
                self.session.call(operation, "GET", path, None, 200)? == json!([]),
                "era cleanup wallet list is not empty"
            );
        }
        self.process.as_mut().unwrap().stop()?;
        self.process = None;
        let integration = self.raw_payment(
            node,
            "conway",
            &destination(0x44)?,
            1_000_000,
            "final-node-integration",
        )?;
        Ok(
            json!({"restoration_continuity":true,"payment":{"transaction_id":tx.id,"fee":fee,"history":payment_history,"node":payment_node},
            "registration":registration,"deregistration":deregistration,"final_snapshot":final_snapshot,
            "owned_wallet_pid":pid,"owned_wallet_stopped_and_reaped":true,"independent_node_integration_last":integration}),
        )
    }
}
impl Drop for WalletObserver<'_> {
    fn drop(&mut self) {
        for (operation, prefix, id) in std::mem::take(&mut self.session.owned).into_iter().rev() {
            let _ = self
                .session
                .call(operation, "DELETE", &format!("/{prefix}/{id}"), None, 204);
        }
        if let Some(process) = self.process.as_mut() {
            let _ = process.stop();
        }
    }
}

pub fn run(
    api: &Api,
    contract: &Contract,
    environment: &str,
    fixture: era_fixture::Options<'_>,
    launch: Launch,
) -> Report {
    let mut observer = WalletObserver {
        session: Session {
            api,
            contract,
            report: Report::new(&api.label, environment),
            owned: Vec::new(),
            timeout: fixture.timeout,
        },
        launch,
        process: None,
        files: PathBuf::new(),
        funder: String::new(),
        funder_key: Vec::new(),
        id: None,
        address: String::new(),
        current: String::new(),
        before: Value::Null,
        funding_id: String::new(),
    };
    let result = (|| -> Result<Value> {
        crate::owned_process::require_unused_listener(&api.label)?;
        let path = era_fixture::drive(fixture, &mut observer)?;
        Ok(serde_json::from_slice(&era_fixture::read(&path)?)?)
    })();
    match result {
        Ok(proof) => {
            for case in [
                "live:hard-fork-restore",
                "live:hard-fork-submit",
                "live:hard-fork-certificates",
            ] {
                observer
                    .session
                    .report
                    .record(case, &["chain.era-boundaries".into()], Ok(()));
            }
            observer
                .session
                .report
                .record("era:independent-node-integration-last", &[], Ok(()));
            observer.session.report.evidence.last_mut().unwrap().detail = proof.to_string();
        }
        Err(error) => {
            observer
                .session
                .report
                .record("era:wallet-boundary-workflow", &[], Err(error))
        }
    }
    std::mem::replace(
        &mut observer.session.report,
        Report::new(&api.label, environment),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fee_fixed_point_handles_cbor_width_changes_and_refuses_cycles() {
        let mut calls = Vec::new();
        let result = converge_fee(23, |fee| {
            calls.push(fee);
            let mut e = minicbor::Encoder::new(Vec::new());
            e.u64(fee)?;
            Ok(23 + e.into_writer().len() as u64)
        })
        .unwrap();
        assert_eq!(result, 25);
        assert_eq!(calls, vec![23, 24, 25]);
        assert!(converge_fee(0, |fee| Ok(1 - fee)).is_err());
        assert!(converge_fee(1, |_| Err(anyhow!("construction failed"))).is_err());
    }
    #[test]
    fn base_address_is_bound_to_frozen_independent_payment_and_stake_keys() {
        assert_eq!(hex::encode(crate::encoding::bech32(&base_address().unwrap()).unwrap().1),"0085abf3eca55024aa1c22b944599b5e890ec12dfb19941229da4ba293c3892366f174a76af9252f78368f5747d3055ab3568ea3b6bf40b01e");
        assert_ne!(destination(0x11).unwrap(), base_address().unwrap());
    }
    #[test]
    fn certificate_controls_preserve_kind_hash_deposit_and_history_only_drops_live_depth() {
        let stake = [3; 28];
        assert_ne!(
            certificate(7, &stake, 1_000_000).unwrap(),
            certificate(8, &stake, 1_000_000).unwrap()
        );
        assert_ne!(
            certificate(7, &stake, 1_000_000).unwrap(),
            certificate(7, &[4; 28], 1_000_000).unwrap()
        );
        assert!(certificate(16, &stake, 1_000_000).is_err());
        let a = json!([{"id":"same","depth":{"quantity":1},"fee":10}]);
        let b = json!([{"id":"same","depth":{"quantity":2},"fee":10}]);
        assert_eq!(history_core(&a).unwrap(), history_core(&b).unwrap());
        let mut bad = b;
        bad[0]["fee"] = json!(11);
        assert_ne!(history_core(&a).unwrap(), history_core(&bad).unwrap());
        assert_eq!(
            unsupported()["info"]["supported_recent_eras"],
            json!(["conway"])
        );
    }
}
