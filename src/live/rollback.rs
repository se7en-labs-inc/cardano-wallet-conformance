//! Actual native branch replacement and wallet rollback/reapplication semantics.
use super::{
    families::SHELLEY,
    history,
    pending::{mempool, mempool_state, same_tip},
    *,
};
use crate::{
    chain_observer::{Event, Observer, Point},
    era_fixture::{directory, read, save},
    fork_fixture::{Branch, Fixture},
    node::{NodeOracle, Tip},
    node_proxy::SocketProxy,
    owned_process::{Launch, WalletProcess},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};
const FUNDING: u64 = 100_000_000;
const PASSWORD: &str = "conformance-test-passphrase";

pub struct Options<'a> {
    pub base: &'a Path,
    pub workspace: &'a Path,
    pub node: &'a Path,
    pub cli: &'a Path,
    pub launch: Launch,
    pub key_oracle: &'a Path,
    pub timeout: Duration,
}
struct Funder {
    address: String,
    public: Vec<u8>,
    key: PathBuf,
    files: PathBuf,
}
#[derive(Debug, PartialEq, Eq)]
enum FundingState {
    Confirmed,
    Pending,
    Replayable,
}
struct FundingGuard<'a> {
    tx: &'a transaction::Transaction,
    recipient: &'a str,
    coin: u64,
    original_input: &'a Value,
}
/// Replace only a receipt already created by this owned fixture. The shared
/// fixture writer remains create-new; each intermediate file is create-new too.
fn update_funding_receipt(path: &Path, proof: &Value) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "funding receipt is not an owned regular file"
    );
    let next = path.with_extension("next.json");
    save(&next, proof)?;
    fs::rename(&next, path)?;
    Ok(())
}
impl FundingGuard<'_> {
    fn state(&self, outputs: &Value, input: &Value, pool: &Value) -> Result<FundingState> {
        let entries = outputs
            .as_object()
            .context("fixture funding outputs malformed")?;
        if entries
            .keys()
            .any(|key| key.starts_with(&format!("{}#", self.tx.id)))
        {
            crate::node::validate_asset_payment(
                outputs,
                &self.tx.id,
                self.recipient,
                self.coin,
                &BTreeMap::new(),
            )?;
            return Ok(FundingState::Confirmed);
        }
        ensure!(
            input == self.original_input,
            "fixture funding original input changed or was consumed without exact output"
        );
        let exists = pool["exists"]
            .as_bool()
            .context("fixture mempool membership missing")?;
        let slot = number(pool, "/slot")?;
        ensure!(
            *pool == json!({"exists":exists,"slot":slot,"txId":self.tx.id}),
            "fixture mempool identity/fields differ"
        );
        Ok(if exists {
            FundingState::Pending
        } else {
            FundingState::Replayable
        })
    }
}
impl Funder {
    fn create(cli: &Path, root: &Path, timeout: Duration) -> Result<Self> {
        directory(root)?;
        let public = root.join("public.vkey");
        let key = root.join("private.skey");
        crate::pool_fixture::run(
            Command::new(cli)
                .args(["conway", "address", "key-gen", "--verification-key-file"])
                .arg(&public)
                .arg("--signing-key-file")
                .arg(&key),
            timeout,
        )?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
        let public = crate::protocol_update::public_key(&public)?.1;
        let mut bytes = vec![0x60];
        bytes.extend(transaction::blake2b(&public, 28)?);
        Ok(Self {
            address: crate::encoding::bech32_encode("addr_test", &bytes)?,
            public,
            key,
            files: root.into(),
        })
    }
    fn pay(
        &self,
        node: &NodeOracle,
        to: &str,
        coin: u64,
        label: &str,
        timeout: Duration,
    ) -> Result<Value> {
        let before = node.utxos(&self.address, timeout)?;
        let entries = before
            .as_object()
            .context("rollback funder inputs missing")?;
        ensure!(
            entries.len() == 1,
            "rollback funder needs exactly one input"
        );
        let (reference, input) = entries.iter().next().unwrap();
        let available = number(input, "/value/lovelace")?;
        ensure!(
            input["value"] == json!({"lovelace":available}) && input["address"] == self.address,
            "rollback funder input assets/address differ"
        );
        let body = self.files.join(format!("{label}.body"));
        let signed = self.files.join(format!("{label}.signed"));
        crate::pool_fixture::run(
            Command::new(&node.executable)
                .args(["conway", "transaction", "build", "--socket-path"])
                .arg(&node.socket)
                .args(["--testnet-magic", "42", "--tx-in"])
                .arg(reference)
                .arg("--tx-out")
                .arg(format!("{to}+{coin}"))
                .arg("--change-address")
                .arg(&self.address)
                .args(["--witness-override", "1", "--out-file"])
                .arg(&body),
            timeout,
        )?;
        crate::pool_fixture::run(
            Command::new(&node.executable)
                .args(["conway", "transaction", "sign", "--tx-body-file"])
                .arg(&body)
                .arg("--signing-key-file")
                .arg(&self.key)
                .args(["--testnet-magic", "42", "--out-file"])
                .arg(&signed),
            timeout,
        )?;
        let envelope: Value = serde_json::from_slice(&read(&signed)?)?;
        let encoded = text(&envelope, "/cborHex")?;
        let tx = transaction::inspect(&encoded, true)?;
        ensure!(
            tx.inputs == [reference.clone()]
                && tx.verification_keys == [hex::encode(&self.public)]
                && tx.outputs.len() == 2
                && tx.outputs.iter().all(|output| output.assets.is_empty()),
            "rollback independent funder input/signature/output differs"
        );
        let target = hex::encode(crate::encoding::bech32(to)?.1);
        let own = hex::encode(crate::encoding::bech32(&self.address)?.1);
        ensure!(
            tx.outputs
                .iter()
                .filter(|output| output.address_hex == target && output.coin == coin)
                .count()
                == 1
                && tx
                    .outputs
                    .iter()
                    .filter(|output| output.address_hex == own)
                    .count()
                    == 1
                && tx
                    .outputs
                    .iter()
                    .try_fold(tx.fee, |sum, output| sum.checked_add(output.coin))
                    == Some(available),
            "rollback independent funder ownership/conservation differs"
        );
        ensure!(
            transaction::certificates(&encoded)?.is_empty(),
            "unexpected independent funder certificate"
        );
        let guard = FundingGuard {
            tx: &tx,
            recipient: to,
            coin,
            original_input: &before,
        };
        let receipt = self.files.join(format!("{label}.public-receipt.json"));
        let output = self.confirm_funding(node, &guard, &signed, &receipt, timeout)?;
        let after = node.utxos(&self.address, timeout)?;
        ensure!(
            after.as_object().is_some_and(|map| map.len() == 1) && after.get(reference).is_none(),
            "rollback independent funder input remains unspent"
        );
        Ok(
            json!({"transaction":tx,"signed_cbor":encoded,"before":before,"recipient":output,"change":after,"native_funding_receipt":serde_json::from_slice::<Value>(&read(&receipt)?)?}),
        )
    }

    /// Private fixture setup only. Wallet submissions never pass through this loop.
    fn confirm_funding(
        &self,
        node: &NodeOracle,
        guard: &FundingGuard<'_>,
        signed: &Path,
        receipt: &Path,
        timeout: Duration,
    ) -> Result<Value> {
        let original_bytes = read(signed)?;
        let envelope: Value = serde_json::from_slice(&original_bytes)?;
        let mut proof = json!({"kind":"private-native-fixture-funding","transaction":guard.tx,"signed_cbor":text(&envelope,"/cborHex")?,"original_input":guard.original_input,"admissions":[],"last_observation":null});
        save(receipt, &proof)?;
        let deadline = Instant::now() + timeout;
        let remaining = || -> Result<Duration> {
            let left = deadline.saturating_duration_since(Instant::now());
            ensure!(
                !left.is_zero(),
                "native fixture funding confirmation timed out"
            );
            Ok(left)
        };
        let result = (|| -> Result<Value> {
            let mut submitted_tip = node.tip(remaining()?)?;
            submit_native(node, signed, remaining()?)?;
            proof["admissions"]
                .as_array_mut()
                .unwrap()
                .push(json!({"attempt":1,"tip":tip_value(&submitted_tip)}));
            update_funding_receipt(receipt, &proof)?;
            let mut submitted_at = Instant::now();
            loop {
                let mut outputs = node.utxos(guard.recipient, remaining()?)?;
                let input = node.utxos(&self.address, remaining()?)?;
                // Inclusion can happen between the recipient and input queries.
                if input != *guard.original_input {
                    outputs = node.utxos(guard.recipient, remaining()?)?;
                }
                let before = number(&node.mempool_info(remaining()?)?, "/slot")?;
                let pool = node.query(&["tx-mempool", "tx-exists", &guard.tx.id], remaining()?)?;
                let after = number(&node.mempool_info(remaining()?)?, "/slot")?;
                let tip = node.tip(remaining()?)?;
                proof["last_observation"] = json!({"outputs":outputs,"input":input,"mempool":pool,"mempool_before_slot":before,"mempool_after_slot":after,"tip":tip_value(&tip)});
                update_funding_receipt(receipt, &proof)?;
                ensure!(
                    before <= number(&pool, "/slot")? && number(&pool, "/slot")? <= after,
                    "fixture mempool slot outside independent bracket"
                );
                match guard.state(&outputs, &input, &pool)? {
                    FundingState::Confirmed => return Ok(outputs),
                    FundingState::Replayable
                        if tip.height > submitted_tip.height
                            && submitted_at.elapsed() >= Duration::from_secs(1) =>
                    {
                        let attempts = proof["admissions"].as_array().unwrap().len();
                        ensure!(
                            attempts < 4,
                            "native fixture funding exhausted three exact replays"
                        );
                        ensure!(
                            read(signed)? == original_bytes,
                            "native fixture signed envelope changed before replay"
                        );
                        proof["before_replay"] = proof["last_observation"].clone();
                        let replay_guard = proof["before_replay"].clone();
                        update_funding_receipt(receipt, &proof)?;
                        let replay = submit_native(node, signed, remaining()?);
                        proof["admissions"].as_array_mut().unwrap().push(json!({"attempt":attempts+1,"tip":tip_value(&tip),"unchanged_signed_bytes":true,"guard":replay_guard,"accepted":replay.is_ok(),"error":replay.as_ref().err().map(|error|format!("{error:#}"))}));
                        update_funding_receipt(receipt, &proof)?;
                        if let Err(error) = replay {
                            let outputs = node.utxos(guard.recipient, remaining()?)?;
                            let input = node.utxos(&self.address, remaining()?)?;
                            proof["after_rejected_replay"] =
                                json!({"outputs":outputs,"input":input});
                            update_funding_receipt(receipt, &proof)?;
                            if guard.state(&outputs, &input, &json!({}))? == FundingState::Confirmed
                                && guard.tx.inputs.iter().all(|key| input.get(key).is_none())
                            {
                                return Ok(outputs);
                            }
                            return Err(error.context(
                                "native replay rejected without exact independent confirmation",
                            ));
                        }
                        submitted_tip = tip;
                        submitted_at = Instant::now();
                    }
                    _ => {}
                }
                sleep(Duration::from_millis(100).min(remaining()?));
            }
        })();
        proof["completed"] = json!(result.is_ok());
        if let Err(error) = &result {
            proof["error"] = json!(format!("{error:#}"));
        }
        update_funding_receipt(receipt, &proof)?;
        result
    }
}
fn submit_native(node: &NodeOracle, path: &Path, timeout: Duration) -> Result<()> {
    crate::pool_fixture::run(
        Command::new(&node.executable)
            .args(["conway", "transaction", "submit", "--socket-path"])
            .arg(&node.socket)
            .args(["--testnet-magic", "42", "--tx-file"])
            .arg(path),
        timeout,
    )?;
    Ok(())
}
fn stable(node: &NodeOracle, timeout: Duration) -> Result<Tip> {
    let deadline = Instant::now() + timeout;
    let mut tip = node.tip(timeout)?;
    let mut samples = 0;
    while samples < 3 {
        sleep(Duration::from_millis(100));
        let next = node.tip(timeout)?;
        if same_tip(&tip, &next).is_ok() {
            samples += 1;
        } else {
            samples = 0;
            tip = next;
        }
        ensure!(
            Instant::now() < deadline,
            "rollback paused tip did not stabilize"
        );
    }
    Ok(tip)
}
fn tip_value(tip: &Tip) -> Value {
    json!({"hash":tip.hash,"height":tip.height,"slot":tip.slot})
}
#[derive(serde::Serialize)]
struct Payment {
    id: String,
    encoded: String,
    file: PathBuf,
    source: String,
    destination: String,
    amount: u64,
    fee: u64,
    change_address: String,
    change: u64,
    input: String,
    funding: Value,
    public_derivation: Value,
}
struct PaymentRequest<'a> {
    wallet: &'a str,
    source: &'a str,
    destination: &'a str,
    amount: u64,
    label: &'a str,
}
struct RollbackContext<'a> {
    a: &'a Branch,
    b: &'a Branch,
    common: &'a Tip,
    proxy: &'a SocketProxy,
    observer: &'a Observer,
    process: &'a mut WalletProcess,
    genesis: &'a Path,
}
fn public_payment(value: &Value, payment: &Payment, status: &str) -> Result<()> {
    let fee = retry::payment(
        value,
        &payment.funding,
        &payment.destination,
        payment.amount,
        status,
    )?;
    let signed = transaction::inspect(&payment.encoded, true)?;
    ensure!(
        value["id"] == payment.id
            && signed.id == payment.id
            && fee == payment.fee
            && fee == signed.fee,
        "rollback public transaction ID/fee differs from signed body"
    );
    let outputs = value["outputs"]
        .as_array()
        .context("rollback public outputs missing")?;
    ensure!(
        outputs.len() == signed.outputs.len() && value["metadata"].is_null(),
        "rollback public output count/metadata differs from signed body"
    );
    for (actual, expected) in outputs.iter().zip(&signed.outputs) {
        ensure!(
            hex::encode(crate::encoding::bech32(&text(actual, "/address")?)?.1)
                == expected.address_hex
                && number(actual, "/amount/quantity")? == expected.coin,
            "rollback public ordered output differs from signed bytes"
        );
    }
    Ok(())
}
fn exact_balance(wallet: &Value, available: u64, total: u64) -> Result<()> {
    ensure!(
        wallet["balance"]
            == json!({"available":{"quantity":available,"unit":"lovelace"},"total":{"quantity":total,"unit":"lovelace"},"reward":{"quantity":0,"unit":"lovelace"}})
            && wallet["assets"] == json!({"available":[],"total":[]}),
        "rollback available/projected/reward/assets accounting differs"
    );
    Ok(())
}
fn identity(before: &Value, after: &Value) -> Result<()> {
    for field in [
        "id",
        "name",
        "address_pool_gap",
        "delegation",
        "passphrase",
        "assets",
    ] {
        ensure!(
            before["wallet"][field] == after["wallet"][field],
            "rollback changed wallet identity/credential/delegation/assets field {field}"
        );
    }
    ensure!(
        before["account_key"] == after["account_key"],
        "rollback changed account key"
    );
    for address in before["addresses"]
        .as_array()
        .context("rollback initial addresses missing")?
    {
        ensure!(
            after["addresses"]
                .as_array()
                .context("rollback recovered addresses missing")?
                .iter()
                .any(|known| known["id"] == address["id"]
                    && known["derivation_path"] == address["derivation_path"]),
            "rollback lost a previously known address/derivation"
        );
    }
    Ok(())
}
fn rollback_wire(
    snapshot: &crate::chain_observer::Snapshot,
    common: &Tip,
    a: &Tip,
    b: &Tip,
) -> Result<Value> {
    ensure!(
        snapshot.errors.is_empty(),
        "rollback observation errors: {:?}",
        snapshot.errors
    );
    ensure!(
        b.height > a.height
            && b.hash != a.hash
            && a.height > common.height
            && b.height > common.height,
        "native branches are not a genuine longer divergent pair"
    );
    for observed in &snapshot.observations {
        if let Event::Accepted {
            point: Point::Block { slot, hash },
            tip,
        } = &observed.event
        {
            let common_intersection = *slot <= common.slot
                && *slot < a.slot
                && (*slot != common.slot || *hash == common.hash)
                && tip.height == Some(b.height)
                && tip.point
                    == (Point::Block {
                        slot: b.slot,
                        hash: b.hash.clone(),
                    });
            if common_intersection && snapshot.observations.iter().any(|event|event.connection==observed.connection && matches!(&event.event,Event::RolledBack{point,tip:rollback_tip} if point==&Point::Block{slot:*slot,hash:hash.clone()} && rollback_tip==tip)){
                    return Ok(json!({"connection":observed.connection,"common_intersection":{"slot":slot,"hash":hash},"branch_a":tip_value(a),"branch_b":tip_value(b),"observation":snapshot}));
                }
        }
    }
    anyhow::bail!(
        "no actual accepted common intersection and RollBackward to the longer native branch"
    )
}
impl Session<'_> {
    fn rollback_note(&mut self, case: &str, proof: Value) {
        self.report.record(case, &[], Ok(()));
        self.report.evidence.last_mut().unwrap().detail = proof.to_string();
    }
    fn rollback_ready(&mut self, id: &str, tip: &Tip) -> Result<()> {
        self.poll("getWallet", &format!("/wallets/{id}"), |wallet| {
            wallet["state"]["status"] == "ready"
                && wallet["tip"]["absolute_slot_number"] == tip.slot
                && wallet["tip"]["height"] == json!({"quantity":tip.height,"unit":"block"})
        })?;
        Ok(())
    }
    fn rollback_payment(
        &mut self,
        request: PaymentRequest<'_>,
        node: &NodeOracle,
        files: &Path,
        oracle: &Path,
    ) -> Result<Payment> {
        let PaymentRequest {
            wallet: id,
            source,
            destination: to,
            amount,
            label,
        } = request;
        let funding = node.utxos(source, self.timeout)?;
        let entries = funding
            .as_object()
            .context("rollback source funding missing")?;
        ensure!(
            entries.len() == 1,
            "rollback needs exactly one source input"
        );
        let (input, output) = entries.iter().next().unwrap();
        ensure!(
            output["address"] == source && output["value"] == json!({"lovelace":FUNDING}),
            "rollback source value/assets differ"
        );
        let constructed = self.call(
            "constructTransaction",
            "POST",
            &format!("/wallets/{id}/transactions-construct"),
            Some(
                json!({"payments":[{"address":to,"amount":{"quantity":amount,"unit":"lovelace"}}]}),
            ),
            202,
        )?;
        let unsigned = text(&constructed, "/transaction")?;
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("/wallets/{id}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":PASSWORD,"encoding":"base16"})),
            202,
        )?;
        let encoded = text(&signed, "/transaction")?;
        ensure!(
            hex::encode(
                hex::decode(&encoded)
                    .context("rollback signing response ignored requested base16 encoding")?
            ) == encoded,
            "rollback signing response is not lowercase base16"
        );
        let tx = transaction::inspect(&encoded, true)?;
        ensure!(
            tx.id == transaction::inspect(&unsigned, false)?.id
                && tx.inputs == [input.clone()]
                && tx.verification_keys.len() == 1
                && tx.outputs.len() == 2
                && tx.outputs.iter().all(|output| output.assets.is_empty()),
            "rollback wallet body/input/signature/assets differ"
        );
        let credential = transaction::blake2b(&hex::decode(&tx.verification_keys[0])?, 28)?;
        let own = crate::encoding::bech32(source)?.1;
        ensure!(
            own.len() == 57 && own[0] == 0 && own[1..29] == credential,
            "rollback signature does not authorize source input"
        );
        let destination = hex::encode(crate::encoding::bech32(to)?.1);
        ensure!(
            tx.outputs
                .iter()
                .filter(|output| output.address_hex == destination && output.coin == amount)
                .count()
                == 1,
            "rollback destination payment differs"
        );
        let change = tx
            .outputs
            .iter()
            .find(|output| output.address_hex != destination)
            .context("rollback change missing")?;
        let change_bytes = hex::decode(&change.address_hex)?;
        ensure!(
            change_bytes.len() == 57
                && change_bytes[0] == 0
                && change_bytes[29..] == own[29..]
                && tx
                    .outputs
                    .iter()
                    .try_fold(tx.fee, |sum, output| sum.checked_add(output.coin))
                    == Some(FUNDING),
            "rollback change credential/conservation differs"
        );
        let change_address = crate::encoding::bech32_encode("addr_test", &change_bytes)?;
        let account = self.call(
            "getAccountKey",
            "GET",
            &format!("/wallets/{id}/keys?format=extended"),
            None,
            200,
        )?;
        let (hrp, account_key) = crate::encoding::bech32(
            account
                .as_str()
                .context("rollback account key is not text")?,
        )?;
        ensure!(
            hrp == "acct_xvk" && account_key.len() == 64,
            "rollback extended account key encoding differs"
        );
        let changes = constructed["coin_selection"]["change"]
            .as_array()
            .context("rollback constructed change list missing")?;
        ensure!(
            changes.len() == 1
                && changes[0]["address"] == change_address
                && changes[0]["derivation_path"] == json!(["1852H", "1815H", "0H", "1", "0"]),
            "rollback first internal change address/path differs"
        );
        let external = crate::keys::derive_public(oracle, &account_key, &[0, 0], self.timeout)?;
        let internal = crate::keys::derive_public(oracle, &account_key, &[1, 0], self.timeout)?;
        let stake = crate::keys::derive_public(oracle, &account_key, &[2, 0], self.timeout)?;
        ensure!(hex::encode(&external[..32])==tx.verification_keys[0] && transaction::blake2b(&internal[..32],28)?==change_bytes[1..29] && transaction::blake2b(&stake[..32],28)?==change_bytes[29..],"rollback input/change/stake credentials differ from independent pinned Haskell public derivation");
        let public_derivation = json!({"account_xpub_hex":hex::encode(&account_key),"source_path":[0,0],"source_xpub_hex":hex::encode(external),"change_path":[1,0],"change_xpub_hex":hex::encode(internal),"stake_path":[2,0],"stake_xpub_hex":hex::encode(stake),"oracle_sha256":crate::keys::oracle_sha256(oracle)?});
        ensure!(
            transaction::certificates(&encoded)?.is_empty(),
            "rollback payment has certificates"
        );
        let file = files.join(format!("{label}.signed"));
        save(
            &file,
            &json!({"type":"Tx ConwayEra","description":"public signed conformance transaction","cborHex":encoded}),
        )?;
        Ok(Payment {
            id: tx.id,
            encoded,
            file,
            source: source.into(),
            destination: to.into(),
            amount,
            fee: tx.fee,
            change_address,
            change: change.coin,
            input: input.clone(),
            funding,
            public_derivation,
        })
    }
    fn rollback_submit(&mut self, id: &str, payment: &Payment) -> Result<Value> {
        let submitted = self.call(
            "submitTransaction",
            "POST",
            &format!("/wallets/{id}/transactions-submit"),
            Some(json!({"transaction":payment.encoded})),
            202,
        )?;
        ensure!(
            submitted == json!({"id":payment.id}),
            "rollback submission ID differs"
        );
        let pending = self.call(
            "getTransaction",
            "GET",
            &format!("/wallets/{id}/transactions/{}", payment.id),
            None,
            200,
        )?;
        public_payment(&pending, payment, "pending")?;
        Ok(pending)
    }
    fn rollback_native_payment(&self, node: &NodeOracle, payment: &Payment) -> Result<Value> {
        node.payment(
            &payment.id,
            &payment.destination,
            payment.amount,
            self.timeout,
        )?;
        node.payment(
            &payment.id,
            &payment.change_address,
            payment.change,
            self.timeout,
        )?;
        let source = node.utxos(&payment.source, self.timeout)?;
        ensure!(
            source.get(&payment.input).is_none(),
            "rollback confirmed source input remains unspent"
        );
        Ok(
            json!({"source":source,"recipient":node.utxos(&payment.destination,self.timeout)?,"change":node.utxos(&payment.change_address,self.timeout)?}),
        )
    }
}

struct Setup {
    ids: Vec<String>,
    addresses: Vec<String>,
    baseline: BTreeMap<String, Value>,
    payments: Vec<Payment>,
    funding: Vec<Value>,
}
impl Session<'_> {
    fn rollback_setup(
        &mut self,
        seed: &NodeOracle,
        funder: &Funder,
        files: &Path,
        oracle: &Path,
    ) -> Result<Setup> {
        let mut ids = Vec::new();
        let mut addresses = Vec::new();
        let mut funding = Vec::new();
        for label in [
            "local-confirmed",
            "discovered-confirmed",
            "local-pending",
            "confirmed-recipient",
            "pending-recipient",
        ] {
            let id = self.create(
                &format!("conformance-rollback-{label}"),
                bip39::Mnemonic::generate(15)?
                    .words()
                    .map(str::to_owned)
                    .collect(),
            )?;
            self.family_ready_balance(SHELLEY, &id, 0)?;
            let list = self.call(
                "listAddresses",
                "GET",
                &format!("/wallets/{id}/addresses"),
                None,
                200,
            )?;
            let address = text(&list, "/0/id")?;
            ensure!(
                seed.utxos(&address, self.timeout)? == json!({}),
                "rollback wallet address not fresh"
            );
            ids.push(id);
            addresses.push(address);
        }
        for index in 0..3 {
            funding.push(funder.pay(
                seed,
                &addresses[index],
                FUNDING,
                &format!("fund-{index}"),
                self.timeout,
            )?);
            self.family_ready_balance(SHELLEY, &ids[index], FUNDING)?;
            self.check_snapshot(&ids[index], FUNDING)?;
        }
        let mut payments = Vec::new();
        for (index, recipient, amount) in [(0, 3, 2_000_000), (1, 3, 2_000_000), (2, 4, 3_000_000)]
        {
            payments.push(self.rollback_payment(
                PaymentRequest {
                    wallet: &ids[index],
                    source: &addresses[index],
                    destination: &addresses[recipient],
                    amount,
                    label: &format!("wallet-payment-{index}"),
                },
                seed,
                files,
                oracle,
            )?);
        }
        let mut baseline = BTreeMap::new();
        for id in &ids {
            baseline.insert(id.clone(), self.pending_snapshot(id)?);
        }
        self.rollback_note("rollback:common-funded-state",json!({"wallet_ids":ids,"addresses":addresses,"baseline":baseline,"payments":payments,"independent_funding":funding}));
        Ok(Setup {
            ids,
            addresses,
            baseline,
            payments,
            funding,
        })
    }
    fn rollback_branch(&mut self, setup: &Setup, context: RollbackContext<'_>) -> Result<Value> {
        let RollbackContext {
            a,
            b,
            common,
            proxy,
            observer,
            process,
            genesis,
        } = context;
        let ids = &setup.ids;
        let addresses = &setup.addresses;
        let c = &setup.payments[0];
        let x = &setup.payments[1];
        let p = &setup.payments[2];
        let pid = process.ensure_running()?;
        for (index, id) in ids.iter().enumerate() {
            self.family_ready_balance(SHELLEY, id, if index < 3 { FUNDING } else { 0 })?;
        }
        let initial_pause = a.pause(self.timeout)?;
        let initial_tip = stable(&a.node, self.timeout)?;
        self.rollback_ready(&ids[0], &initial_tip)?;
        let c_pending = self.rollback_submit(&ids[0], c)?;
        let c_pool = mempool(&a.node, &c.id, self.timeout)?;
        initial_pause.resume()?;
        let c_confirmed = self.family_confirm(SHELLEY, &ids[0], &c.id)?;
        public_payment(&c_confirmed, c, "in_ledger")?;
        submit_native(&a.node, &x.file, self.timeout)?;
        let x_confirmed = self.family_confirm(SHELLEY, &ids[1], &x.id)?;
        public_payment(&x_confirmed, x, "in_ledger")?;
        let a_pause = a.pause(self.timeout)?;
        let tip_a = stable(&a.node, self.timeout)?;
        let parameters: Value =
            serde_json::from_slice(&read(&genesis.join("shelley-genesis.json"))?)?;
        let coefficient = validity::decimal_ps(&parameters["activeSlotsCoeff"])?;
        ensure!(coefficient > 0, "zero native fork slot coefficient");
        let window = u64::try_from(
            u128::from(number(&parameters, "/securityParam")?) * 3 * 1_000_000_000_000
                / coefficient,
        )?;
        let acceptance = number(&c_confirmed, "/inserted_at/absolute_slot_number")?;
        ensure!(tip_a.slot.checked_sub(acceptance).is_some_and(|age|age<window),"confirmed-local fork control already passed finality; fixture cannot prove pending rollback");
        let p_pending = self.rollback_submit(&ids[2], p)?;
        let p_pool = mempool(&a.node, &p.id, self.timeout)?;
        let native_c = self.rollback_native_payment(&a.node, c)?;
        let native_x = self.rollback_native_payment(&a.node, x)?;
        ensure!(
            a.node.utxos(&p.source, self.timeout)? == p.funding,
            "A pending payment consumed its native funding"
        );
        self.family_ready_balance(SHELLEY, &ids[0], c.change)?;
        self.family_ready_balance(SHELLEY, &ids[1], x.change)?;
        self.family_ready_balance(SHELLEY, &ids[3], c.amount + x.amount)?;
        let mut state_a = BTreeMap::new();
        for id in ids {
            state_a.insert(id.clone(), self.pending_snapshot(id)?);
        }
        exact_balance(&state_a[&ids[2]]["wallet"], 0, p.change)?;
        let deadline = Instant::now() + self.timeout;
        loop {
            let tip = b.node.tip(self.timeout)?;
            if tip.height > tip_a.height && tip.hash != tip_a.hash {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "B did not become the longer divergent branch"
            );
            sleep(Duration::from_millis(100));
        }
        let b_pause = b.pause(self.timeout)?;
        let tip_b = stable(&b.node, self.timeout)?;
        ensure!(
            tip_b.height > tip_a.height && tip_b.hash != tip_a.hash,
            "B is not a longer divergent native branch"
        );
        let mut native_b = BTreeMap::new();
        for payment in &setup.payments {
            let funding = b.node.utxos(&payment.source, self.timeout)?;
            ensure!(
                funding == payment.funding,
                "B does not retain the exact common unspent funding input"
            );
            ensure!(
                b.node.utxos(&payment.change_address, self.timeout)? == json!({}),
                "B has A-only change outputs"
            );
            mempool_state(&b.node, &payment.id, self.timeout, false)?;
            native_b.insert(payment.source.clone(), funding);
        }
        ensure!(
            b.node.utxos(&addresses[3], self.timeout)? == json!({})
                && b.node.utxos(&addresses[4], self.timeout)? == json!({}),
            "B contains A-only recipient outputs"
        );
        self.rollback_note("rollback:observed-a-and-b-before-switch",json!({"common_tip":tip_value(common),"branch_a":tip_value(&tip_a),"branch_b":tip_value(&tip_b),"a_state":state_a,"a_native_confirmed_c":native_c,"a_native_discovered_x":native_x,"c_pending_before_confirmation":c_pending,"c_mempool_before_confirmation":c_pool,"p_pending_before_rollback":p_pending,"p_mempool":p_pool,"b_original_funding":native_b,"confirmed_local_acceptance":acceptance,"finality_window_slots":window}));
        proxy.pause(self.timeout)?;
        proxy.observe_while_paused(observer.clone())?;
        proxy.retarget_while_paused(&b.node.socket)?;
        proxy.resume()?;
        ensure!(
            process.ensure_running()? == pid,
            "wallet process changed during rollback"
        );
        for id in ids {
            self.rollback_ready(id, &tip_b)?;
        }
        let header = self.call(
            "getBlocksLatestHeader",
            "GET",
            "/blocks/latest/header",
            None,
            200,
        )?;
        ensure!(
            tip_b.matches_wallet_header(&header),
            "wallet chain source did not switch to exact B native header"
        );
        let mut state_b = BTreeMap::new();
        for id in ids {
            state_b.insert(id.clone(), self.pending_snapshot(id)?);
        }
        let c_rolled = self.call(
            "getTransaction",
            "GET",
            &format!("/wallets/{}/transactions/{}", ids[0], c.id),
            None,
            200,
        )?;
        let p_rolled = self.call(
            "getTransaction",
            "GET",
            &format!("/wallets/{}/transactions/{}", ids[2], p.id),
            None,
            200,
        )?;
        let wire = observer.snapshot();
        self.rollback_note("rollback:observed-b-wallet-state",json!({"wallet_pid":pid,"wallets":state_b,"local_confirmed_after_rollback":c_rolled,"local_pending_after_rollback":p_rolled,"observation":wire}));
        let rollback = rollback_wire(&wire, common, &tip_a, &tip_b)?;
        for id in ids {
            identity(&setup.baseline[id], &state_b[id])?;
        }
        public_payment(&c_rolled, c, "pending")?;
        public_payment(&p_rolled, p, "pending")?;
        ensure!(
            history::stable(&c_rolled) == history::stable(&c_pending)
                && history::stable(&p_rolled) == history::stable(&p_pending),
            "rollback changed stable local pending transaction data"
        );
        exact_balance(&state_b[&ids[0]]["wallet"], 0, c.change)?;
        exact_balance(&state_b[&ids[2]]["wallet"], 0, p.change)?;
        for index in [0, 2] {
            ensure!(
                state_b[&ids[index]]["utxo"]["entries"] == json!([]),
                "rollback pending funding became spendable in wallet snapshot"
            );
        }
        exact_balance(&state_b[&ids[1]]["wallet"], FUNDING, FUNDING)?;
        self.check_snapshot(&ids[1], FUNDING)?;
        for index in [3, 4] {
            exact_balance(&state_b[&ids[index]]["wallet"], 0, 0)?;
            ensure!(
                state_b[&ids[index]]["history"] == json!([]),
                "rollback retained A-only incoming history"
            );
            self.check_snapshot(&ids[index], 0)?;
        }
        let missing = self.call(
            "getTransaction",
            "GET",
            &format!("/wallets/{}/transactions/{}", ids[1], x.id),
            None,
            404,
        )?;
        ensure!(
            missing
                == json!({"code":"no_such_transaction","message":format!("I couldn't find a transaction with the given id: {}",x.id),"info":{"transaction_id":x.id}}),
            "rollback discovered-only transaction did not disappear with exact404"
        );
        ensure!(
            state_b[&ids[1]]["history"] == setup.baseline[&ids[1]]["history"],
            "rollback discovered sender history did not restore exactly"
        );
        for payment in &setup.payments {
            ensure!(
                b.node.utxos(&payment.source, self.timeout)? == payment.funding,
                "rollback changed B native unspent funding"
            );
        }
        self.rollback_note("rollback:pending-input-history-proofs",json!({"pending_local":c_rolled,"preserved_pending":p_rolled,"restored_discovered_sender":state_b[&ids[1]],"empty_recipients":[state_b[&ids[3]].clone(),state_b[&ids[4]].clone()],"native_original_inputs":native_b,"wire":rollback}));
        // Only the discovered transaction is explicitly replayed. Local entries retry themselves.
        submit_native(&b.node, &x.file, self.timeout)?;
        let x_pool = mempool(&b.node, &x.id, self.timeout)?;
        b_pause.resume()?;
        let mut confirmed = Vec::new();
        let mut final_native = Vec::new();
        for (index, payment) in setup.payments.iter().enumerate() {
            let value = self.family_confirm(SHELLEY, &ids[index], &payment.id)?;
            public_payment(&value, payment, "in_ledger")?;
            let observed = b.node.tip(self.timeout)?;
            let inserted_slot = number(&value, "/inserted_at/absolute_slot_number")?;
            let inserted_height = number(&value, "/inserted_at/height/quantity")?;
            ensure!(inserted_slot>tip_b.slot && inserted_slot<=observed.slot && inserted_height>tip_b.height && inserted_height<=observed.height && value["inserted_at"]["height"]["unit"]=="block","reapplied history does not identify a fresh B block after the rollback observation");
            self.family_ready_balance(SHELLEY, &ids[index], payment.change)?;
            final_native.push(self.rollback_native_payment(&b.node, payment)?);
            confirmed.push(value);
        }
        self.family_ready_balance(SHELLEY, &ids[3], c.amount + x.amount)?;
        self.family_ready_balance(SHELLEY, &ids[4], p.amount)?;
        let mut final_state = BTreeMap::new();
        for (index, id) in ids.iter().enumerate() {
            let before_snapshot = b.node.tip(self.timeout)?;
            let raw_wallet = self.call("getWallet", "GET", &format!("/wallets/{id}"), None, 200)?;
            let raw_history = self.call(
                "listTransactions",
                "GET",
                &format!("/wallets/{id}/transactions"),
                None,
                200,
            )?;
            let snapshot = self.pending_snapshot(id)?;
            let after_snapshot = b.node.tip(self.timeout)?;
            self.rollback_note("rollback:reapplied-wallet-snapshot", json!({"wallet_index":index,"wallet_id":id,"baseline":setup.baseline[id],"snapshot":snapshot,"raw_wallet":raw_wallet,"raw_history":raw_history,"native_before":tip_value(&before_snapshot),"native_after":tip_value(&after_snapshot)}));
            identity(&setup.baseline[id], &snapshot)?;
            let rows = snapshot["history"]
                .as_array()
                .context("final rollback history missing")?;
            let unique: BTreeSet<_> = rows
                .iter()
                .map(|row| text(row, "/id"))
                .collect::<Result<_>>()?;
            let coherent =
                rows.len() == unique.len() && rows.iter().all(|row| row["status"] == "in_ledger");
            if !coherent {
                // Diagnose the observed response without replacing or retrying
                // the strict assertion below. A clean later read cannot pass it.
                let followup = (|| -> Result<Value> {
                    let paused = b.pause(self.timeout)?;
                    let anchor = stable(&b.node, self.timeout)?;
                    self.rollback_ready(id, &anchor)?;
                    let wallet =
                        self.call("getWallet", "GET", &format!("/wallets/{id}"), None, 200)?;
                    let history = self.call(
                        "listTransactions",
                        "GET",
                        &format!("/wallets/{id}/transactions"),
                        None,
                        200,
                    )?;
                    let native = setup
                        .payments
                        .iter()
                        .map(|payment| b.node.utxos(&payment.destination, self.timeout))
                        .collect::<Result<Vec<_>>>()?;
                    same_tip(&anchor, &b.node.tip(self.timeout)?)?;
                    paused.resume()?;
                    Ok(
                        json!({"wallet_id":id,"anchor":tip_value(&anchor),"wallet":wallet,"history":history,"native_recipient_outputs":native,"original_failure_remains":true}),
                    )
                })();
                match followup {
                    Ok(proof) => {
                        self.rollback_note("rollback:invalid-history-quiescent-followup", proof)
                    }
                    Err(error) => self.report.record(
                        "rollback:invalid-history-quiescent-followup",
                        &[],
                        Err(error),
                    ),
                }
            }
            ensure!(
                coherent,
                "rollback reapplication duplicated history or left pending data"
            );
            let expected: BTreeSet<_> = if index < 3 {
                let mut initial = setup.baseline[id]["history"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| text(row, "/id"))
                    .collect::<Result<BTreeSet<_>>>()?;
                initial.insert(setup.payments[index].id.clone());
                initial
            } else if index == 3 {
                [c.id.clone(), x.id.clone()].into_iter().collect()
            } else {
                [p.id.clone()].into_iter().collect()
            };
            ensure!(
                unique == expected,
                "rollback reapplication history set differs"
            );
            for original in setup.baseline[id]["history"].as_array().unwrap() {
                ensure!(
                    rows.iter().find(|row| row["id"] == original["id"]) == Some(original),
                    "rollback changed original common-chain transaction history"
                );
            }
            let amount = if index < 3 {
                setup.payments[index].change
            } else if index == 3 {
                c.amount + x.amount
            } else {
                p.amount
            };
            exact_balance(&snapshot["wallet"], amount, amount)?;
            self.check_snapshot(id, amount)?;
            final_state.insert(id.clone(), snapshot);
        }
        let final_tip = b.node.tip(self.timeout)?;
        ensure!(
            final_tip.height > tip_b.height,
            "B did not forge reapplication blocks"
        );
        a_pause.resume()?;
        Ok(
            json!({"wallet_pid":pid,"common_tip":tip_value(common),"branch_a":tip_value(&tip_a),"branch_b_before_reapply":tip_value(&tip_b),"branch_b_after_reapply":tip_value(&final_tip),"payments":setup.payments,"funding":setup.funding,"before":state_a,"after_rollback":state_b,"final":final_state,"confirmed":confirmed,"final_native":final_native,"rollback":rollback,"discovered_replay_mempool":x_pool,"additional_local_submission_api_calls":0}),
        )
    }
}

pub fn run(api: &Api, contract: &Contract, environment: &str, options: Options<'_>) -> Report {
    let mut session = Session {
        api,
        contract,
        report: Report::new(&api.label, environment),
        owned: Vec::new(),
        timeout: options.timeout,
    };
    let mut seed = None;
    let mut branches = None;
    let mut proxy = None;
    let mut process = None;
    let mut funder = None;
    let observer = Observer::default();
    let result = (|| -> Result<Value> {
        crate::owned_process::require_unused_listener(&api.label)?;
        let oracle_sha = crate::keys::oracle_sha256(options.key_oracle)?;
        ensure!(
            options.workspace.is_absolute(),
            "rollback workspace must be absolute"
        );
        directory(options.workspace)?;
        let root = options.workspace.canonicalize()?;
        let independent =
            Funder::create(options.cli, &root.join("private-funder"), options.timeout)?;
        let funder_hex = hex::encode(crate::encoding::bech32(&independent.address)?.1);
        let fixture = Fixture::prepare(
            options.base,
            &root.join("native"),
            &funder_hex,
            3_000_000_000,
        )?;
        funder = Some(independent);
        seed = Some(fixture.seed(options.node, options.cli)?);
        let common = seed.as_mut().unwrap();
        common.ready(options.timeout)?;
        proxy = Some(SocketProxy::bind(
            &root.join("wallet-node.socket"),
            &common.node.socket,
        )?);
        let mut launch = options.launch;
        for value in launch
            .arguments
            .iter_mut()
            .chain(launch.environment.values_mut())
        {
            if value == "{node_socket}" {
                *value = root.join("wallet-node.socket").display().to_string();
            }
            if value == "{byron_genesis}" {
                *value = fixture
                    .genesis()
                    .join("byron-genesis.json")
                    .display()
                    .to_string();
            }
        }
        process = Some(WalletProcess::start(launch, &root.join("wallet-runtime"))?);
        let wallet = process.as_mut().unwrap();
        wallet.wait_listener(&api.label, options.timeout)?;
        session.rollback_note("rollback:owned-runtime",json!({"executable_sha256":wallet.executable_sha256(),"wallet_pid":wallet.ensure_running()?,"native_node_executable":options.node,"native_cli_executable":options.cli,"independent_key_oracle_sha256":oracle_sha}));
        let files = root.join("public-signed-transactions");
        directory(&files)?;
        let setup = session.rollback_setup(
            &common.node,
            funder.as_ref().unwrap(),
            &files,
            options.key_oracle,
        )?;
        let snapshot = common.close_for_snapshot(options.timeout)?;
        session.rollback_note(
            "rollback:closed-common-snapshot",
            json!({"tip":tip_value(&snapshot.tip),"nodes":snapshot.stopped_nodes}),
        );
        branches = Some(fixture.branches(&snapshot, options.node, options.cli)?);
        let (a, b) = branches.as_mut().unwrap();
        a.ready(options.timeout)?;
        b.ready(options.timeout)?;
        a.node.advancing(snapshot.tip.height, options.timeout)?;
        let relay = proxy.as_ref().unwrap();
        relay.pause(options.timeout)?;
        relay.retarget_while_paused(&a.node.socket)?;
        relay.resume()?;
        session.rollback_branch(
            &setup,
            RollbackContext {
                a,
                b,
                common: &snapshot.tip,
                proxy: relay,
                observer: &observer,
                process: wallet,
                genesis: fixture.genesis(),
            },
        )
    })();
    let completed = result.is_ok();
    match result {
        Ok(proof) => session.rollback_note("rollback:workflow", proof),
        Err(error) => session.report.record("rollback:workflow", &[], Err(error)),
    }
    // Quiesce native B before closing observed streams; resume for the independent final probe.
    {
        let paused = if let Some((_, b)) = branches.as_ref() {
            match b.pause(options.timeout) {
                Ok(guard) => Some(guard),
                Err(error) => {
                    session
                        .report
                        .record("rollback:pause-for-cleanup", &[], Err(error));
                    None
                }
            }
        } else {
            None
        };
        for (delete, prefix, id) in std::mem::take(&mut session.owned).into_iter().rev() {
            let removed = session
                .call(delete, "DELETE", &format!("/{prefix}/{id}"), None, 204)
                .map(|_| ());
            session
                .report
                .record("rollback:cleanup-owned-wallet", &[], removed);
        }
        if let Some(wallet) = process.as_mut() {
            session
                .report
                .record("rollback:stop-owned-wallet", &[], wallet.stop());
        }
        drop(proxy);
        let closed = observer.snapshot();
        if completed {
            let checked = (|| -> Result<()> {
                ensure!(
                    closed.errors.is_empty(),
                    "closed rollback observer errors: {:?}",
                    closed.errors
                );
                Ok(())
            })();
            session
                .report
                .record("rollback:closed-observation", &[], checked);
            session.report.evidence.last_mut().unwrap().detail =
                serde_json::to_string(&closed).unwrap();
        }
        if let Some(paused) = paused {
            session
                .report
                .record("rollback:resume-after-cleanup", &[], paused.resume());
        }
    }
    if completed {
        let checked = (|| -> Result<Value> {
            let (_, b) = branches
                .as_ref()
                .context("rollback final native B missing")?;
            let funder = funder
                .as_ref()
                .context("rollback independent funder missing")?;
            let public = ed25519_dalek::SigningKey::from_bytes(&[91; 32]).verifying_key();
            let mut address = vec![0x60];
            address.extend(transaction::blake2b(public.as_bytes(), 28)?);
            let address = crate::encoding::bech32_encode("addr_test", &address)?;
            ensure!(
                b.node.utxos(&address, options.timeout)? == json!({}),
                "final independent fork probe address is not empty"
            );
            let before = b.node.tip(options.timeout)?;
            let proof = funder.pay(
                &b.node,
                &address,
                2_000_000,
                "final-independent-probe",
                options.timeout,
            )?;
            let after = b.node.tip(options.timeout)?;
            ensure!(
                after.height > before.height,
                "final independent B probe did not advance"
            );
            Ok(json!({"before":tip_value(&before),"after":tip_value(&after),"proof":proof}))
        })();
        session.report.record(
            "rollback:independent-native-integration-last",
            &[],
            checked
                .as_ref()
                .map(|_| ())
                .map_err(|error| anyhow!("{error:#}")),
        );
        if let Ok(proof) = checked {
            session.report.evidence.last_mut().unwrap().detail = proof.to_string();
        }
    }
    if let Some((a, b)) = branches.as_mut() {
        session
            .report
            .record("rollback:stop-owned-branch-a", &[], a.stop().map(|_| ()));
        session
            .report
            .record("rollback:stop-owned-branch-b", &[], b.stop().map(|_| ()));
    }
    if let Some(common) = seed.as_mut() {
        session
            .report
            .record("rollback:stop-owned-seed", &[], common.stop().map(|_| ()));
    }
    if completed && session.report.passed() {
        for case in [
            "state:rollback-spent-inputs",
            "state:rollback-pending",
            "state:rollback-balance-history",
            "live:rollback-reapply",
        ] {
            session
                .report
                .record(case, &["wallet.rollback".into()], Ok(()));
            session.report.evidence.last_mut().unwrap().detail="Full distinct pending/input/history/native/reapplication proofs are retained in rollback:workflow and preceding observations; all owned cleanup and final native integration passed.".into();
        }
    }
    session.report
}

#[cfg(test)]
mod tests {
    use super::*;
    fn replay_cli(root: &Path, mode: &str) -> NodeOracle {
        use std::os::unix::fs::PermissionsExt;
        let cli = root.join("fixture-cli");
        let bash = std::env::split_paths(&std::env::var_os("PATH").expect("test PATH missing"))
            .map(|directory| directory.join("bash"))
            .find(|path| path.is_file())
            .expect("Bash missing from Nix test environment")
            .canonicalize()
            .unwrap();
        let script = r#"#!@BASH@
set -eu
fixture_root="$(dirname "$0")"
mode="$(cat "$fixture_root/mode")"
count=0
if [ -f "$fixture_root/submissions" ]; then count="$(cat "$fixture_root/submissions")"; fi
case "$1 $2 $3" in
  'conway transaction submit')
    while [ "$#" -gt 0 ]; do
      if [ "$1" = '--tx-file' ]; then shift; sha256sum "$1" >> "$fixture_root/hashes"; break; fi
      shift
    done
    count=$((count+1))
    printf '%s\n' "$count" > "$fixture_root/submissions"
    if [ "$count" -ge 2 ] && [ "$mode" != 'replay' ]; then exit 1; fi
    ;;
  'latest query tip')
    tips=20
    if [ -f "$fixture_root/tips" ]; then tips="$(cat "$fixture_root/tips")"; fi
    tips=$((tips+1))
    printf '%s\n' "$tips" > "$fixture_root/tips"
    printf '{"block":%s,"slot":%s,"hash":"@HASH@"}\n' "$tips" "$tips"
    ;;
  'latest query utxo')
    if [ "$mode" = 'tamper' ]; then printf '%s\n' 'changed bytes' > "$fixture_root/signed.json"; fi
    address="$5"
    if [ "$address" = 'recipient' ]; then
      if [ "$count" -ge 2 ] && [ "$mode" != 'reject-absent' ]; then
        printf '%s\n' '{"@ID@#0":{"address":"recipient","value":{"lovelace":50}}}'
      else printf '%s\n' '{}'; fi
    elif [ "$count" -ge 2 ] && [ "$mode" != 'reject-absent' ]; then
      printf '%s\n' '{"@ID@#1":{"address":"funder","value":{"lovelace":49}}}'
    else printf '%s\n' '{"parent#0":{"address":"funder","value":{"lovelace":100}}}'; fi
    ;;
  'latest query tx-mempool')
    if [ "$4" = 'info' ]; then printf '%s\n' '{"slot":99}';
    else printf '%s\n' '{"exists":false,"slot":99,"txId":"@ID@"}'; fi
    ;;
  *) exit 2 ;;
esac
"#
        .replace("@BASH@", bash.to_str().unwrap())
        .replace("@ID@", &"ab".repeat(32))
        .replace("@HASH@", &"ef".repeat(32));
        fs::write(&cli, script).unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("mode"), mode).unwrap();
        NodeOracle {
            executable: cli,
            socket: root.join("unused.socket"),
            network_magic: 42,
        }
    }
    #[test]
    fn native_fixture_replay_uses_identical_bytes_and_requires_exact_confirmation() {
        for mode in ["replay", "reject-confirm", "reject-absent", "tamper"] {
            let root = tempfile::tempdir().unwrap();
            let node = replay_cli(root.path(), mode);
            let funder = Funder {
                address: "funder".into(),
                public: vec![],
                key: root.path().join("unused.key"),
                files: root.path().into(),
            };
            let tx = transaction::Transaction {
                id: "ab".repeat(32),
                fee: 1,
                inputs: vec!["parent#0".into()],
                outputs: vec![],
                verification_keys: vec![],
            };
            let original = json!({"parent#0":{"address":"funder","value":{"lovelace":100}}});
            let guard = FundingGuard {
                tx: &tx,
                recipient: "recipient",
                coin: 50,
                original_input: &original,
            };
            let signed = root.path().join("signed.json");
            fs::write(&signed, b"{\"cborHex\":\"public-test-envelope\"}").unwrap();
            let receipt = root.path().join("receipt.json");
            let result =
                funder.confirm_funding(&node, &guard, &signed, &receipt, Duration::from_secs(5));
            let proof: Value = serde_json::from_slice(&read(&receipt).unwrap()).unwrap();
            let confirmed = matches!(mode, "replay" | "reject-confirm");
            assert_eq!(result.is_ok(), confirmed, "{mode}: {result:?}");
            assert_eq!(proof["completed"], json!(confirmed));
            let hashes = fs::read_to_string(root.path().join("hashes")).unwrap();
            let hashes: Vec<_> = hashes
                .lines()
                .map(|line| line.split_whitespace().next().unwrap())
                .collect();
            assert_eq!(hashes.len(), if mode == "tamper" { 1 } else { 2 });
            assert!(hashes.iter().all(|hash| *hash == hashes[0]));
            if mode == "reject-confirm" {
                assert_eq!(proof["admissions"][1]["accepted"], false);
                assert!(proof["after_rejected_replay"].is_object());
            }
            if mode == "tamper" {
                assert!(proof["error"]
                    .as_str()
                    .unwrap()
                    .contains("envelope changed"));
            }
        }
    }
    #[test]
    fn evolving_funding_receipts_replace_owned_files_without_following_links() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let receipt = root.path().join("fund.public.json");
        assert!(update_funding_receipt(&receipt, &json!({"phase":1})).is_err());
        save(&receipt, &json!({"phase":0})).unwrap();
        for phase in 1..=3 {
            update_funding_receipt(&receipt, &json!({"phase":phase})).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&read(&receipt).unwrap()).unwrap(),
                json!({"phase":phase})
            );
        }
        let linked = root.path().join("linked.json");
        symlink(&receipt, &linked).unwrap();
        assert!(update_funding_receipt(&linked, &json!({"phase":4})).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&read(&receipt).unwrap()).unwrap(),
            json!({"phase":3})
        );
    }
    #[test]
    fn private_funding_replay_requires_absent_output_exact_input_and_absent_mempool() {
        let tx = transaction::Transaction {
            id: "ab".repeat(32),
            fee: 1,
            inputs: vec!["original#0".into()],
            outputs: vec![],
            verification_keys: vec![],
        };
        let original = json!({"original#0":{"address":"funder","value":{"lovelace":100}}});
        let guard = FundingGuard {
            tx: &tx,
            recipient: "recipient",
            coin: 50,
            original_input: &original,
        };
        let pool = json!({"exists":false,"slot":10,"txId":tx.id});
        let unrelated = json!({format!("{}#0", "cd".repeat(32)):{"address":"recipient","value":{"lovelace":50}}});
        assert_eq!(
            guard.state(&unrelated, &original, &pool).unwrap(),
            FundingState::Replayable
        );
        let mut present = pool.clone();
        present["exists"] = json!(true);
        assert_eq!(
            guard.state(&json!({}), &original, &present).unwrap(),
            FundingState::Pending
        );
        assert!(guard.state(&json!({}), &json!({}), &pool).is_err());
        let mut changed = original.clone();
        changed["original#0"]["value"]["lovelace"] = json!(99);
        assert!(guard.state(&json!({}), &changed, &pool).is_err());
        let mut wrong = pool.clone();
        wrong["txId"] = json!("cd".repeat(32));
        assert!(guard.state(&json!({}), &original, &wrong).is_err());
        wrong = pool.clone();
        wrong["extra"] = json!(true);
        assert!(guard.state(&json!({}), &original, &wrong).is_err());
        assert!(guard.state(&json!([]), &original, &pool).is_err());
    }
    #[test]
    fn native_funding_confirmation_never_accepts_wrong_value_address_or_assets() {
        let tx = transaction::Transaction {
            id: "ab".repeat(32),
            fee: 1,
            inputs: vec![],
            outputs: vec![],
            verification_keys: vec![],
        };
        let original = json!({});
        let guard = FundingGuard {
            tx: &tx,
            recipient: "recipient",
            coin: 50,
            original_input: &original,
        };
        let key = format!("{}#0", tx.id);
        let valid = json!({&key:{"address":"recipient","value":{"lovelace":50}}});
        assert_eq!(
            guard.state(&valid, &json!({}), &json!({})).unwrap(),
            FundingState::Confirmed
        );
        let mut wrong = valid.clone();
        wrong[&key]["value"]["lovelace"] = json!(49);
        assert!(guard.state(&wrong, &original, &json!({})).is_err());
        wrong = valid.clone();
        wrong[&key]["address"] = json!("other");
        assert!(guard.state(&wrong, &original, &json!({})).is_err());
        wrong = valid;
        wrong[&key]["value"]["ef".repeat(28)] = json!({"":1});
        assert!(guard.state(&wrong, &original, &json!({})).is_err());
    }
    use crate::chain_observer::{Observation, Snapshot, Tip as WireTip};
    #[test]
    fn actual_native_branch_headers_require_matched_real_rollback_not_reconnection_or_origin() {
        // Public headers from reference-native-fork-control. Messages here are harness controls.
        let common = Tip {
            height: 2,
            slot: 6,
            hash: "1422bfef17deaf44016bf9d7e907d67e175d76348234c3000bb78efdd671fa5e".into(),
        };
        let a = Tip {
            height: 4,
            slot: 29,
            hash: "d65550bec1f22cf183f39a45ed77698b7d1baf7619bb58074a29b90e550b4a0a".into(),
        };
        let b = Tip {
            height: 6,
            slot: 27,
            hash: "f6458d57d355bb4c57207c898e0b562d378938c9ca1ea0611487e2b52f1f2d05".into(),
        };
        let point = Point::Block {
            slot: common.slot,
            hash: common.hash.clone(),
        };
        let tip = WireTip {
            point: Point::Block {
                slot: b.slot,
                hash: b.hash.clone(),
            },
            height: Some(b.height),
        };
        let valid = Snapshot {
            connections: 1,
            errors: Vec::new(),
            observations: vec![
                Observation {
                    connection: 7,
                    event: Event::Offered {
                        points: vec![point.clone()],
                    },
                },
                Observation {
                    connection: 7,
                    event: Event::Accepted {
                        point: point.clone(),
                        tip: tip.clone(),
                    },
                },
                Observation {
                    connection: 7,
                    event: Event::RolledBack {
                        point: point.clone(),
                        tip: tip.clone(),
                    },
                },
            ],
        };
        rollback_wire(&valid, &common, &a, &b).unwrap(); // Longer B can have an older tip slot.
        let mut missing = valid.clone();
        missing.observations.pop();
        assert!(rollback_wire(&missing, &common, &a, &b).is_err());
        let mut wrong_connection = valid.clone();
        wrong_connection.observations[2].connection = 8;
        assert!(rollback_wire(&wrong_connection, &common, &a, &b).is_err());
        let mut wrong_point = valid.clone();
        wrong_point.observations[2].event = Event::RolledBack {
            point: Point::Origin,
            tip: tip.clone(),
        };
        assert!(rollback_wire(&wrong_point, &common, &a, &b).is_err());
        let mut bad = valid.clone();
        bad.errors.push("truncated response".into());
        assert!(rollback_wire(&bad, &common, &a, &b).is_err());
        let mut weak = Tip {
            height: a.height,
            slot: b.slot,
            hash: b.hash.clone(),
        };
        assert!(rollback_wire(&valid, &common, &a, &weak).is_err());
        weak.height = b.height;
        weak.hash = a.hash.clone();
        assert!(rollback_wire(&valid, &common, &a, &weak).is_err());
        for point in [
            Point::Origin,
            Point::Block {
                slot: common.slot + 1,
                hash: common.hash.clone(),
            },
            Point::Block {
                slot: common.slot,
                hash: "ff".repeat(32),
            },
        ] {
            let mut invalid = valid.clone();
            invalid.observations[1].event = Event::Accepted {
                point: point.clone(),
                tip: tip.clone(),
            };
            invalid.observations[2].event = Event::RolledBack {
                point,
                tip: tip.clone(),
            };
            assert!(rollback_wire(&invalid, &common, &a, &b).is_err());
        }
    }
    #[test]
    fn rollback_preserves_known_key_and_derivation_but_allows_new_discovered_addresses() {
        let before = json!({"wallet":{"id":"owned","name":"control","address_pool_gap":20,"delegation":{},"passphrase":{"last_updated_at":"stable"},"assets":{"available":[],"total":[]}},"account_key":"same-public-account-key","addresses":[{"id":"known-public-address","derivation_path":["1852H","1815H","0H","0","0"],"state":"unused"}]});
        let mut after = before.clone();
        after["addresses"][0]["state"] = json!("used");
        after["addresses"].as_array_mut().unwrap().push(json!({"id":"new-public-change","derivation_path":["1852H","1815H","0H","1","0"],"state":"used"}));
        identity(&before, &after).unwrap();
        for pointer in [
            "/account_key",
            "/wallet/id",
            "/addresses/0/id",
            "/addresses/0/derivation_path/4",
        ] {
            let mut bad = after.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("different");
            assert!(identity(&before, &bad).is_err());
        }
        let mut bad = after;
        bad["addresses"] = json!([]);
        assert!(identity(&before, &bad).is_err());
        let wallet = json!({"balance":{"available":{"quantity":0,"unit":"lovelace"},"total":{"quantity":97_000_000,"unit":"lovelace"},"reward":{"quantity":0,"unit":"lovelace"}},"assets":{"available":[],"total":[]}});
        exact_balance(&wallet, 0, 97_000_000).unwrap();
        assert!(exact_balance(&wallet, FUNDING, 97_000_000).is_err());
        assert!(exact_balance(&wallet, 0, FUNDING).is_err());
    }
}
