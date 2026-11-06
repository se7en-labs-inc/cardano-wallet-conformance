//! Real pending persistence and forgetting under exclusively owned producer control.
use super::*;
use crate::{
    cluster_control::{port_shortage_after_timeout, Cluster, NodeDiscoveryTimeout},
    node::NodeOracle,
    owned_process::{Launch, WalletProcess},
};
use std::{collections::BTreeSet, fs, path::Path};
const FUNDING: u64 = 100_000_000;
const PAYMENT: u64 = 2_000_000;
const PASSWORD: &str = "conformance-test-passphrase";
const EXPIRY_SECONDS: u128 = 8;

pub struct Options<'a> {
    pub checkpoint: bool,
    pub expiry: bool,
    pub byron: bool,
    pub retry: Option<RetryOptions<'a>>,
    pub cluster_launch: Launch,
    pub wallet_launch: Launch,
    pub workspace: &'a Path,
    pub node_executable: &'a Path,
    pub cli_executable: &'a Path,
    pub faucet: &'a str,
    pub timeout: Duration,
}
pub struct RetryOptions<'a> {
    pub launch: Launch,
    pub target: &'a str,
}
pub(super) struct ExpiryClock {
    start_ps: u128,
    slot_ps: u128,
    epoch_length: u64,
    safe_slots: u64,
}
impl ExpiryClock {
    pub(super) fn load(runtime: &Path) -> Result<Self> {
        let shelley: Value =
            serde_json::from_slice(&fs::read(runtime.join("cluster/shelley-genesis.json"))?)?;
        let byron: Value =
            serde_json::from_slice(&fs::read(runtime.join("cluster/byron-genesis.json"))?)?;
        let start = validity::utc_ns(&text(&shelley, "/systemStart")?)?;
        let rounded = validity::rounded_posix_seconds(start);
        let seconds = number(&byron, "/startTime")?;
        ensure!(
            u128::from(seconds) == rounded,
            "expiry genesis rounding differs"
        );
        let epoch_length = number(&shelley, "/epochLength")?;
        ensure!(epoch_length > 0, "zero expiry epoch length");
        let coefficient = validity::decimal_ps(&shelley["activeSlotsCoeff"])?;
        ensure!(
            coefficient <= 1_000_000_000_000,
            "active slot coefficient exceeds one"
        );
        let safe_slots = u64::try_from(
            u128::from(number(&shelley, "/securityParam")?) * 3 * 1_000_000_000_000 / coefficient,
        )?;
        ensure!(safe_slots > 0, "zero expiry safe zone");
        Ok(Self {
            start_ps: u128::from(seconds) * 1_000_000_000_000,
            slot_ps: validity::decimal_ps(&shelley["slotLength"])?,
            epoch_length,
            safe_slots,
        })
    }
    pub(super) fn horizon(&self, upper: u64, tip: u64, now: u64) -> Result<Value> {
        let last = upper
            .checked_add(1)
            .context("expiry guard upper overflow")?;
        let horizon = tip
            .checked_add(self.safe_slots)
            .context("expiry guard horizon overflow")?;
        ensure!(tip <= now && now < upper && last < horizon,
            "expiry pause outside safe horizon: tip={tip}, now={now}, upper={upper}, horizon={horizon}");
        Ok(
            json!({"tip_slot":tip,"current_slot":now,"upper_slot":upper,"safe_slots":self.safe_slots,"exclusive_horizon_slot":horizon}),
        )
    }
    pub(super) fn now(&self) -> Result<u64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        u64::try_from(
            now.checked_mul(1000)
                .and_then(|v| v.checked_sub(self.start_ps))
                .context("expiry clock overflow/pre-genesis")?
                / self.slot_ps,
        )
        .context("expiry slot overflow")
    }
    pub(super) fn expiry(&self, pending: &Value, upper: u64) -> Result<()> {
        let actual = &pending["expires_at"];
        let time = text(actual, "/time")?;
        ensure!(
            validity::utc_ns(&time)? * 1000 == self.start_ps + u128::from(upper) * self.slot_ps,
            "expiry timestamp differs from public genesis/encoded slot"
        );
        ensure!(
            *actual
                == json!({"absolute_slot_number":upper,"epoch_number":upper/self.epoch_length,"slot_number":upper%self.epoch_length,"time":time}),
            "expiry slot/epoch fields differ"
        );
        Ok(())
    }
}
fn expired_history(pending: &Value, expired: &Value) -> Result<()> {
    let mut expected = history::stable(pending);
    expected["status"] = json!("expired");
    ensure!(
        history::stable(expired) == expected,
        "expiry changed stable transaction fields beyond status"
    );
    Ok(())
}
fn expiry_validity(actual: (Option<u64>, Option<u64>), upper: u64) -> Result<()> {
    let expected = (Some(0), Some(upper));
    ensure!(
        actual == expected,
        "expiry encoded validity differs: actual {actual:?}, expected {expected:?}"
    );
    Ok(())
}
fn wallet_fields(wallet: &Value) -> Value {
    Value::Object(
        [
            "id",
            "name",
            "address_pool_gap",
            "balance",
            "assets",
            "delegation",
            "passphrase",
        ]
        .into_iter()
        .map(|key| (key.into(), wallet[key].clone()))
        .collect(),
    )
}
fn accounting(wallet: &Value, available: u64, total: u64) -> Result<()> {
    ensure!(
        wallet["balance"]
            == json!({"available":{"quantity":available,"unit":"lovelace"},"total":{"quantity":total,"unit":"lovelace"},"reward":{"quantity":0,"unit":"lovelace"}}),
        "pending available/total/reward accounting differs"
    );
    ensure!(
        wallet["assets"] == json!({"available":[],"total":[]}),
        "pending assets differ"
    );
    Ok(())
}
pub(super) fn same_tip(a: &crate::node::Tip, b: &crate::node::Tip) -> Result<()> {
    ensure!(
        a.height == b.height && a.slot == b.slot && a.hash == b.hash,
        "producer-pause relay tip changed"
    );
    Ok(())
}
fn mempool_response(value: &Value, id: &str, before: u64, after: u64) -> Result<()> {
    mempool_membership(value, id, before, after, true)
}
fn mempool_membership(
    value: &Value,
    id: &str,
    before: u64,
    after: u64,
    exists: bool,
) -> Result<()> {
    let slot = number(value, "/slot")?;
    ensure!(
        before <= slot && slot <= after,
        "pending mempool slot outside independent monotone bracket"
    );
    ensure!(
        *value == json!({"exists":exists,"slot":slot,"txId":id}),
        "pending mempool identity/fields differ: {value}"
    );
    Ok(())
}
pub(super) fn mempool(node: &NodeOracle, id: &str, timeout: Duration) -> Result<Value> {
    mempool_state(node, id, timeout, true)
}
pub(super) fn mempool_state(
    node: &NodeOracle,
    id: &str,
    timeout: Duration,
    exists: bool,
) -> Result<Value> {
    let before = number(&node.mempool_info(timeout)?, "/slot")?;
    let value = node.query(&["tx-mempool", "tx-exists", id], timeout)?;
    let after = number(&node.mempool_info(timeout)?, "/slot")?;
    if exists {
        mempool_response(&value, id, before, after)?;
    } else {
        mempool_membership(&value, id, before, after, false)?;
    }
    Ok(value)
}
fn unspent(node: &Value, id: &str, tx: &transaction::Transaction) -> Result<()> {
    let entries = node
        .as_object()
        .context("pending node funding is not an object")?;
    ensure!(
        entries.len() == 1 && tx.inputs.len() == 1 && entries.contains_key(&tx.inputs[0]),
        "pending input does not match exact independent funding"
    );
    ensure!(
        !entries.keys().any(|key| key.starts_with(&format!("{id}#"))),
        "pending transaction already has ledger outputs"
    );
    Ok(())
}
fn final_node_probe(node: &NodeOracle, faucet: &str, timeout: Duration) -> Result<Value> {
    let vectors: Value =
        serde_json::from_str(include_str!("../../fixtures/vectors/haskell-keys.json"))?;
    let address = vectors
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "haskell-Shelley-0-0-0-enterprise-0")
        .context("independent node address missing")?["expected"]["result"]["address"]
        .as_str()
        .context("invalid independent node address")?;
    let height = node.height(timeout)?;
    node.advancing(height, timeout)?;
    let before = node.utxos(address, timeout)?;
    let response=Api::new(faucet,timeout)?.request(&request("POST","/send/faucet-assets",Some(json!({"batch-size":1,"assets":[{"address":address,"bundle":{"coin":FUNDING,"assets":[]},"metadata":[]}]}))))?;
    ensure!(
        response.status == 204,
        "final independent faucet probe rejected"
    );
    let deadline = Instant::now() + timeout;
    loop {
        let after = node.utxos(address, timeout)?;
        let fresh = after
            .as_object()
            .context("invalid final node UTxOs")?
            .keys()
            .filter(|key| before.get(*key).is_none())
            .collect::<Vec<_>>();
        ensure!(
            fresh.len() <= 1,
            "final independent faucet produced extra outputs"
        );
        if let Some(reference) = fresh.first() {
            let id = reference
                .split_once('#')
                .context("invalid final node reference")?
                .0;
            node.payment(id, address, FUNDING, timeout)?;
            return Ok(
                json!({"transaction_id":id,"address":address,"before":before,"after":after}),
            );
        }
        ensure!(
            Instant::now() < deadline,
            "final independent node probe not confirmed"
        );
        sleep(Duration::from_millis(200));
    }
}
impl Session<'_> {
    pub(super) fn pending_snapshot(&mut self, id: &str) -> Result<Value> {
        let wallet = self.call("getWallet", "GET", &format!("/wallets/{id}"), None, 200)?;
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{id}/addresses"),
            None,
            200,
        )?;
        let key = self.call(
            "getAccountKey",
            "GET",
            &format!("/wallets/{id}/keys?format=extended"),
            None,
            200,
        )?;
        let utxo = self.call(
            "getWalletUtxoSnapshot",
            "GET",
            &format!("/wallets/{id}/utxo"),
            None,
            200,
        )?;
        let history = self.call(
            "listTransactions",
            "GET",
            &format!("/wallets/{id}/transactions"),
            None,
            200,
        )?;
        let rows = history
            .as_array()
            .context("pending history is not an array")?;
        Ok(
            json!({"wallet":wallet_fields(&wallet),"addresses":addresses,"account_key":key,"utxo":utxo,"history":rows.iter().map(history::stable).collect::<Vec<_>>()}),
        )
    }
    fn pending_workflow(
        &mut self,
        node: &NodeOracle,
        cluster: &Cluster,
        process: &mut WalletProcess,
        faucet: &str,
        expiry_clock: Option<&ExpiryClock>,
    ) -> Result<Value> {
        let phrase = || -> Result<Vec<String>> {
            Ok(bip39::Mnemonic::generate(15)?
                .words()
                .map(str::to_owned)
                .collect())
        };
        let sender = self.create("conformance-pending-sender", phrase()?)?;
        let recipient = self.create("conformance-pending-recipient", phrase()?)?;
        self.family_ready_balance(families::SHELLEY, &sender, 0)?;
        self.family_ready_balance(families::SHELLEY, &recipient, 0)?;
        let source = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{sender}/addresses"),
            None,
            200,
        )?;
        let target = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{recipient}/addresses"),
            None,
            200,
        )?;
        let address = text(&source, "/0/id")?;
        let destination = text(&target, "/0/id")?;
        let funding_api = Api::new(faucet, self.timeout)?;
        let funded = funding_api.request(&request("POST","/send/faucet-assets",Some(json!({"batch-size":1,"assets":[{"address":address,"bundle":{"coin":FUNDING,"assets":[]},"metadata":[]}]}))))?;
        ensure!(funded.status == 204, "pending faucet funding rejected");
        self.family_ready_balance(families::SHELLEY, &sender, FUNDING)?;
        let funding = node.utxos(&address, self.timeout)?;
        let outputs = funding.as_object().context("pending funding missing")?;
        ensure!(
            outputs.len() == 1
                && outputs.values().all(|output| output["address"] == address
                    && output["value"] == json!({"lovelace":FUNDING})),
            "pending fixture funding differs"
        );
        let baseline = self.pending_snapshot(&sender)?;
        accounting(&baseline["wallet"], FUNDING, FUNDING)?;
        let confirmed_history = if expiry_clock.is_some() {
            let funding_id = outputs
                .keys()
                .next()
                .unwrap()
                .split_once('#')
                .context("invalid native funding reference")?
                .0;
            let record = self.call(
                "getTransaction",
                "GET",
                &format!("/wallets/{sender}/transactions/{funding_id}"),
                None,
                200,
            )?;
            ensure!(
                record["id"] == funding_id
                    && record["status"] == "in_ledger"
                    && record["direction"] == "incoming"
                    && record["amount"] == json!({"quantity":FUNDING,"unit":"lovelace"}),
                "native confirmed funding history differs"
            );
            history::status_rows(
                &baseline["history"],
                std::slice::from_ref(&record),
                false,
                None,
            )?;
            Some(record)
        } else {
            None
        };
        let upper = expiry_clock
            .map(|clock| -> Result<u64> {
                clock
                    .now()?
                    .checked_add(u64::try_from(
                        EXPIRY_SECONDS * 1_000_000_000_000 / clock.slot_ps,
                    )?)
                    .context("expiry upper overflow")
            })
            .transpose()?;
        let validity = upper.map_or_else(
            || json!({"quantity":600,"unit":"second"}),
            |slot| json!({"quantity":slot,"unit":"slot"}),
        );
        let constructed = self.call("constructTransaction","POST",&format!("/wallets/{sender}/transactions-construct"),Some(json!({"payments":[{"address":destination,"amount":{"quantity":PAYMENT,"unit":"lovelace"}}],"validity_interval":{"invalid_hereafter":validity}})),202)?;
        let unsigned = text(&constructed, "/transaction")?;
        let sign = json!({"transaction":unsigned,"passphrase":PASSWORD});
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("/wallets/{sender}/transactions-sign"),
            Some(sign.clone()),
            202,
        )?;
        let encoded = text(&signed, "/transaction")?;
        let tx = transaction::inspect(&encoded, true)?;
        if let Some(upper) = upper {
            expiry_validity(transaction::validity(&encoded)?, upper)?;
        }
        ensure!(
            tx.id == transaction::inspect(&unsigned, false)?.id
                && tx.verification_keys.len() == 1
                && tx.outputs.len() == 2,
            "pending body/signature/output shape differs"
        );
        let credential = transaction::blake2b(&hex::decode(&tx.verification_keys[0])?, 28)?;
        let source_bytes = crate::encoding::bech32(&address)?.1;
        ensure!(
            source_bytes.len() == 57 && source_bytes[1..29] == credential,
            "pending signer does not authorize funding"
        );
        unspent(&funding, &tx.id, &tx)?;
        let destination_hex = hex::encode(crate::encoding::bech32(&destination)?.1);
        ensure!(
            tx.outputs
                .iter()
                .filter(|o| o.address_hex == destination_hex && o.coin == PAYMENT)
                .count()
                == 1
                && tx.outputs.iter().all(|o| o.assets.is_empty()),
            "pending payment/assets differ"
        );
        let change = FUNDING
            .checked_sub(PAYMENT)
            .and_then(|v| v.checked_sub(tx.fee))
            .context("pending fee overflow")?;
        let other = tx
            .outputs
            .iter()
            .find(|o| o.address_hex != destination_hex)
            .context("pending change missing")?;
        let change_bytes = hex::decode(&other.address_hex)?;
        ensure!(
            other.coin == change
                && change_bytes.len() == 57
                && change_bytes[0] == 0
                && change_bytes[29..] == source_bytes[29..],
            "pending change/accounting differs"
        );
        let paused = cluster.pause(self.timeout)?;
        let mut stable = node.tip(self.timeout)?;
        let deadline = Instant::now() + self.timeout;
        let mut samples = 0;
        while samples < 3 {
            sleep(Duration::from_millis(200));
            let tip = node.tip(self.timeout)?;
            if same_tip(&stable, &tip).is_ok() {
                samples += 1;
            } else {
                samples = 0;
                stable = tip;
            }
            ensure!(
                Instant::now() < deadline,
                "paused producer tip did not stabilize"
            );
        }
        let expiry_horizon = expiry_clock
            .map(|clock| {
                clock.horizon(
                    upper.context("expiry bound missing")?,
                    stable.slot,
                    clock.now()?,
                )
            })
            .transpose()?;
        let submitted = self.call(
            "submitTransaction",
            "POST",
            &format!("/wallets/{sender}/transactions-submit"),
            Some(json!({"transaction":encoded})),
            202,
        )?;
        ensure!(
            submitted == json!({"id":tx.id}),
            "pending submission identity differs"
        );
        let path = format!("/wallets/{sender}/transactions/{}", tx.id);
        let pending = self.poll("getTransaction", &path, |value| {
            value["status"] == "pending"
        })?;
        ensure!(
            pending["id"] == tx.id
                && pending["direction"] == "outgoing"
                && pending["fee"] == json!({"quantity":tx.fee,"unit":"lovelace"}),
            "pending history identity/direction/fee differs"
        );
        let pool_before = mempool(node, &tx.id, self.timeout)?;
        ensure!(
            node.utxos(&address, self.timeout)? == funding,
            "pending submission spent node funding"
        );
        same_tip(&stable, &node.tip(self.timeout)?)?;
        let before = self.pending_snapshot(&sender)?;
        accounting(&before["wallet"], 0, change)?;
        let rows = before["history"].as_array().unwrap();
        ensure!(
            rows.len() == 2
                && rows
                    .iter()
                    .filter(|row| row["id"] == tx.id && row["status"] == "pending")
                    .count()
                    == 1,
            "pending list/history differs"
        );
        if let Some(clock) = expiry_clock {
            let confirmed_history = confirmed_history
                .as_ref()
                .context("confirmed history control missing")?;
            let pending_history =
                self.history_status_queries(&sender, confirmed_history, &pending, "pending")?;
            let upper = upper.context("expiry bound missing")?;
            clock.expiry(&pending, upper)?;
            ensure!(
                stable.slot < upper && clock.now()? < upper,
                "expiry fixture was not admitted before upper bound"
            );
            self.report.record("pending:admitted", &[], Ok(()));
            self.report.evidence.last_mut().unwrap().detail = json!({
                "transaction_id":tx.id,"signed_transaction":signed,"funding":funding,
                "upper_slot":upper,"expiry_window_seconds":EXPIRY_SECONDS,
                "expiry_horizon":expiry_horizon,"pending_state":before,
                "mempool_pending":pool_before,
                "stable_tip":{"slot":stable.slot,"height":stable.height,"hash":stable.hash}
            })
            .to_string();
            let deadline = Instant::now() + self.timeout;
            while clock.now()? <= upper {
                ensure!(Instant::now() < deadline, "wall clock did not reach expiry");
                same_tip(&stable, &node.tip(self.timeout)?)?;
                sleep(Duration::from_millis(200));
            }
            same_tip(&stable, &node.tip(self.timeout)?)?;
            paused.resume()?;
            let deadline = Instant::now() + self.timeout;
            let advanced = loop {
                let tip = node.tip(self.timeout)?;
                if tip.slot >= upper && tip.height > stable.height {
                    break tip;
                }
                ensure!(
                    Instant::now() < deadline,
                    "node did not advance past expiry"
                );
                sleep(Duration::from_millis(200));
            };
            self.report
                .record("pending:chain-after-expiry", &[], Ok(()));
            self.report.evidence.last_mut().unwrap().detail = json!({
                "upper_slot":upper,"advanced_tip":{"slot":advanced.slot,"height":advanced.height,"hash":advanced.hash}
            }).to_string();
            let expired = match self.poll("getTransaction", &path, |value| {
                value["status"] == "expired"
            }) {
                Ok(expired) => expired,
                Err(error) => {
                    let observation = (|| -> Result<Value> {
                        let snapshot = self.pending_snapshot(&sender)?;
                        let transaction = self.call("getTransaction", "GET", &path, None, 200)?;
                        let tip = node.tip(self.timeout)?;
                        let mempool =
                            node.query(&["tx-mempool", "tx-exists", &tx.id], self.timeout)?;
                        let funding = node.utxos(&address, self.timeout)?;
                        Ok(json!({"wallet_state":snapshot,"transaction":transaction,
                            "node_tip":{"slot":tip.slot,"height":tip.height,"hash":tip.hash},
                            "node_mempool":mempool,"node_funding":funding,"upper_slot":upper}))
                    })();
                    self.report.record(
                        "pending:expiry-timeout-observation",
                        &[],
                        observation
                            .as_ref()
                            .map(|_| ())
                            .map_err(|e| anyhow!("{e:#}")),
                    );
                    if let Ok(proof) = observation {
                        self.report.evidence.last_mut().unwrap().detail = proof.to_string();
                    }
                    return Err(error.context(format!(
                        "wallet did not expire transaction {} after signed upper slot {upper}",
                        tx.id
                    )));
                }
            };
            expired_history(&pending, &expired)?;
            self.family_ready_balance(families::SHELLEY, &sender, FUNDING)?;
            self.family_ready_balance(families::SHELLEY, &recipient, 0)?;
            let deadline = Instant::now() + self.timeout;
            let absent = loop {
                let before = number(&node.mempool_info(self.timeout)?, "/slot")?;
                let value = node.query(&["tx-mempool", "tx-exists", &tx.id], self.timeout)?;
                let after = number(&node.mempool_info(self.timeout)?, "/slot")?;
                mempool_membership(&value, &tx.id, before, after, value["exists"] == true)?;
                if value["exists"] == false {
                    break value;
                }
                ensure!(
                    Instant::now() < deadline,
                    "expired transaction remains in node mempool"
                );
                sleep(Duration::from_millis(200));
            };
            ensure!(
                node.utxos(&address, self.timeout)? == funding,
                "expired transaction consumed funding"
            );
            for output in &tx.outputs {
                let address = crate::encoding::bech32_encode(
                    "addr_test",
                    &hex::decode(&output.address_hex)?,
                )?;
                ensure!(
                    node.utxos(&address, self.timeout)? == json!({}),
                    "expired transaction created a ledger output"
                );
            }
            let expired_state = self.pending_snapshot(&sender)?;
            accounting(&expired_state["wallet"], FUNDING, FUNDING)?;
            let mut expected_rows = before["history"].clone();
            for row in expected_rows.as_array_mut().unwrap() {
                if row["id"] == tx.id {
                    row["status"] = json!("expired");
                }
            }
            ensure!(
                expired_state["history"] == expected_rows
                    && expired_state["utxo"] == baseline["utxo"]
                    && expired_state["account_key"] == baseline["account_key"],
                "expired history/input/key state differs"
            );
            let expired_history_queries =
                self.history_status_queries(&sender, confirmed_history, &expired, "expired")?;
            self.call("deleteTransaction", "DELETE", &path, None, 204)?;
            let missing = self.call("getTransaction", "GET", &path, None, 404)?;
            ensure!(
                missing
                    == json!({"code":"no_such_transaction","message":format!("I couldn't find a transaction with the given id: {}",tx.id),"info":{"transaction_id":tx.id}}),
                "expired deletion error differs"
            );
            let forgotten = self.pending_snapshot(&sender)?;
            accounting(&forgotten["wallet"], FUNDING, FUNDING)?;
            ensure!(
                forgotten["history"] == baseline["history"]
                    && forgotten["utxo"] == baseline["utxo"]
                    && forgotten["account_key"] == baseline["account_key"]
                    && node.utxos(&address, self.timeout)? == funding,
                "expired deletion changed baseline state"
            );
            history::status_rows(
                &forgotten["history"],
                std::slice::from_ref(confirmed_history),
                false,
                None,
            )?;
            self.report
                .record("pending:history-status-observation", &[], Ok(()));
            self.report.evidence.last_mut().unwrap().detail=json!({"pending":pending_history,"expired":expired_history_queries,"after_deletion":forgotten["history"],"native_funding":funding,"transaction_id":tx.id}).to_string();
            self.report.record(
                "live:pending-expiry",
                &["wallet.resubmission".into()],
                Ok(()),
            );
            return Ok(
                json!({"transaction_id":tx.id,"signed_transaction":signed,"funding":funding,"upper_slot":upper,"expiry_window_seconds":EXPIRY_SECONDS,"expiry_horizon":expiry_horizon,"stable_tip":{"height":stable.height,"slot":stable.slot,"hash":stable.hash},"advanced_tip":{"height":advanced.height,"slot":advanced.slot,"hash":advanced.hash},"mempool_pending":pool_before,"mempool_absent":absent,"pending_state":before,"expired":expired,"expired_state":expired_state,"forgotten":forgotten}),
            );
        }
        let old_pid = process.ensure_running()?;
        process.crash_restart()?;
        process.wait_listener(&self.api.label, self.timeout)?;
        let new_pid = process.ensure_running()?;
        ensure!(
            old_pid != new_pid,
            "pending restart did not replace process"
        );
        self.poll("getWallet", &format!("/wallets/{sender}"), |wallet| {
            wallet["state"]["status"] == "ready"
        })?;
        let after = self.pending_snapshot(&sender)?;
        ensure!(after == before, "restart changed exact pending state");
        let signed_after = self.call(
            "signTransaction",
            "POST",
            &format!("/wallets/{sender}/transactions-sign"),
            Some(sign),
            202,
        )?;
        ensure!(
            signed_after == signed,
            "pending restart changed deterministic signatures"
        );
        same_tip(&stable, &node.tip(self.timeout)?)?;
        let pool_after = mempool(node, &tx.id, self.timeout)?;
        ensure!(
            node.utxos(&address, self.timeout)? == funding,
            "restart changed node funding"
        );
        self.report
            .record("state:restart-pending", &["wallet.restart".into()], Ok(()));
        self.call("deleteTransaction", "DELETE", &path, None, 204)?;
        let missing = self.call("getTransaction", "GET", &path, None, 404)?;
        ensure!(
            missing
                == json!({"code":"no_such_transaction","message":format!("I couldn't find a transaction with the given id: {}",tx.id),"info":{"transaction_id":tx.id}}),
            "forgotten pending transaction error differs"
        );
        let forgotten = self.pending_snapshot(&sender)?;
        accounting(&forgotten["wallet"], FUNDING, FUNDING)?;
        ensure!(
            forgotten["history"] == baseline["history"]
                && forgotten["utxo"] == baseline["utxo"]
                && forgotten["account_key"] == baseline["account_key"],
            "forgetting pending changed baseline history/input/key state"
        );
        let pool_forgotten = mempool(node, &tx.id, self.timeout)?;
        ensure!(
            node.utxos(&address, self.timeout)? == funding,
            "forgetting pending spent node funding"
        );
        same_tip(&stable, &node.tip(self.timeout)?)?;
        self.report.record("pending:before-inclusion", &[], Ok(()));
        self.report.evidence.last_mut().unwrap().detail = json!({"transaction":tx,"signed_transaction":signed,"pending":pending,"funding":funding,"stable_tip":{"height":stable.height,"slot":stable.slot,"hash":stable.hash},"forgotten":forgotten,"mempool_after_forgetting":pool_forgotten}).to_string();
        paused.resume()?;
        node.advancing(stable.height, self.timeout)?;
        node.wait_payment(&tx.id, &destination, PAYMENT, self.timeout)?;
        let confirmed = self.family_confirm(families::SHELLEY, &sender, &tx.id)?;
        self.family_confirm(families::SHELLEY, &recipient, &tx.id)?;
        self.family_ready_balance(families::SHELLEY, &sender, change)?;
        self.family_ready_balance(families::SHELLEY, &recipient, PAYMENT)?;
        ensure!(
            confirmed["id"] == tx.id
                && confirmed["status"] == "in_ledger"
                && confirmed["inputs"] == pending["inputs"]
                && confirmed["outputs"] == pending["outputs"]
                && confirmed["fee"] == pending["fee"],
            "forgotten transaction did not reappear with exact confirmed fields"
        );
        for output in &tx.outputs {
            let address =
                crate::encoding::bech32_encode("addr_test", &hex::decode(&output.address_hex)?)?;
            node.payment(&tx.id, &address, output.coin, self.timeout)?;
        }
        ensure!(
            node.utxos(&address, self.timeout)?
                .as_object()
                .context("node funding map missing")?
                .keys()
                .all(|key| !tx.inputs.contains(key)),
            "confirmed pending input remains unspent"
        );
        let final_state = self.pending_snapshot(&sender)?;
        let final_ids: BTreeSet<_> = final_state["history"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| text(row, "/id"))
            .collect::<Result<_>>()?;
        ensure!(
            final_ids.len() == 2 && final_ids.contains(&tx.id),
            "reappeared history identities differ"
        );
        self.report
            .record("pending:forget-and-reappear", &[], Ok(()));
        Ok(
            json!({"transaction_id":tx.id,"signed_transaction":signed,"funding":funding,"pending_before":before,"pending_after_restart":after,"forgotten":forgotten,"confirmed":confirmed,"final_state":final_state,"old_wallet_pid":old_pid,"new_wallet_pid":new_pid,"stable_tip":{"height":stable.height,"slot":stable.slot,"hash":stable.hash},"mempool_before":pool_before,"mempool_after_restart":pool_after,"mempool_after_forget":pool_forgotten}),
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
    let mut cluster = None;
    let mut process = None;
    let mut adversary_process = None;
    let mut checkpoint_proxy = None;
    let mut successful_socket = None;
    let checkpoint_observer = crate::chain_observer::Observer::default();
    let result = (|| -> Result<Value> {
        crate::owned_process::require_unused_listener(&api.label)?;
        if let Some(retry) = &options.retry {
            crate::owned_process::require_unused_listener(retry.target)?;
            ensure!(
                reqwest::Url::parse(&api.label)?.port_or_known_default()
                    != reqwest::Url::parse(retry.target)?.port_or_known_default(),
                "retry services require distinct local ports"
            );
        }
        crate::era_fixture::directory(options.workspace)?;
        let root = fs::canonicalize(options.workspace)?;
        let mut attempt = 0;
        let runtime = loop {
            attempt += 1;
            let runtime = root.join(if attempt == 1 {
                "cluster-runtime".to_owned()
            } else {
                format!("cluster-runtime-retry-{attempt}")
            });
            cluster = Some(Cluster::start(options.cluster_launch.clone(), &runtime)?);
            let controlled = cluster.as_mut().unwrap();
            match controlled.discover(options.node_executable, &runtime, options.timeout) {
                Ok(()) => break runtime,
                Err(error) => {
                    let Some(observed) = error.downcast_ref::<NodeDiscoveryTimeout>() else {
                        return Err(error);
                    };
                    controlled
                        .stop()
                        .context("failed to stop incomplete fixture")?;
                    controlled.wait_stopped_nodes(Duration::from_secs(10))?;
                    let shortage =
                        port_shortage_after_timeout(&runtime, observed).with_context(|| {
                            format!("cannot prove recoverable port shortage after {error:#}")
                        })?;
                    let retry = attempt == 1 && shortage.is_some();
                    let receipt = json!({"attempt":attempt,"runtime":runtime,"error":format!("{error:#}"),"port_shortage":shortage,"owned_cluster_stopped_and_reaped":true,"observed_owned_nodes_absent":true,"wallet_started":false,"retry":retry});
                    crate::era_fixture::save(
                        &root.join(format!("fixture-initialization-{attempt}.json")),
                        &receipt,
                    )?;
                    session.report.record(
                        "pending:fixture-initialization-observation",
                        &[],
                        Ok(()),
                    );
                    session.report.evidence.last_mut().unwrap().detail = receipt.to_string();
                    if !retry {
                        return Err(error);
                    }
                }
            }
        };
        successful_socket = Some(runtime.join("node.socket"));
        let controlled = cluster.as_mut().unwrap();
        let node = NodeOracle {
            executable: options.cli_executable.into(),
            socket: runtime.join("node.socket"),
            network_magic: 42,
        };
        let faucet = Api::new(options.faucet, options.timeout)?;
        let deadline = Instant::now() + options.timeout;
        loop {
            let response = faucet.request(&request("GET", "/ready", None))?;
            ensure!(
                response.status == 200 && response.json.as_ref().is_some_and(Value::is_boolean),
                "owned faucet readiness response differs"
            );
            if response.json == Some(json!(true)) {
                break;
            }
            ensure!(Instant::now() < deadline, "owned faucet not ready");
            sleep(Duration::from_millis(200));
        }
        let (_fixture_paused, fixture_control) = controlled
            .pause(options.timeout)?
            .resume_one(options.timeout)?;
        session
            .report
            .record("pending:single-producer-fixture", &[], Ok(()));
        session.report.evidence.last_mut().unwrap().detail = fixture_control.to_string();
        node.advancing(node.height(options.timeout)?, options.timeout)?;
        if options.checkpoint {
            checkpoint_proxy = Some(crate::node_proxy::SocketProxy::bind(
                &root.join("checkpoint.socket"),
                &node.socket,
            )?);
        }
        let mut launch = options.wallet_launch;
        for value in &mut launch.arguments {
            if value == "{node_socket}" {
                *value = if options.checkpoint {
                    root.join("checkpoint.socket")
                } else {
                    node.socket.clone()
                }
                .display()
                .to_string();
            }
            if value == "{byron_genesis}" {
                *value = runtime
                    .join("cluster/byron-genesis.json")
                    .display()
                    .to_string();
            }
        }
        process = Some(WalletProcess::start(launch, &root.join("wallet-runtime"))?);
        let wallet = process.as_mut().unwrap();
        wallet.wait_listener(&api.label, options.timeout)?;
        let expiry_clock = (options.expiry || options.retry.is_some())
            .then(|| ExpiryClock::load(&runtime))
            .transpose()?;
        let proof = if options.checkpoint {
            session.checkpoint_workflow(
                &node,
                controlled,
                wallet,
                checkpoint_proxy
                    .as_ref()
                    .context("checkpoint relay missing")?,
                options.faucet,
                &checkpoint_observer,
            )?
        } else if let Some(retry) = options.retry {
            let mut launch = retry.launch;
            for value in &mut launch.arguments {
                if value == "{node_socket}" {
                    *value = node.socket.display().to_string();
                }
                if value == "{byron_genesis}" {
                    *value = runtime
                        .join("cluster/byron-genesis.json")
                        .display()
                        .to_string();
                }
            }
            adversary_process = Some(WalletProcess::start(
                launch,
                &root.join("adversary-runtime"),
            )?);
            let adversary = adversary_process.as_mut().unwrap();
            adversary.wait_listener(retry.target, options.timeout)?;
            let reference = Api::new(retry.target, options.timeout)?;
            let mut proof = session.retry_workflow(
                &node,
                controlled,
                options.faucet,
                &reference,
                expiry_clock.as_ref().context("retry clock missing")?,
            )?;
            proof["adversary_executable_sha256"] = json!(adversary.executable_sha256());
            proof
        } else if options.byron {
            session.byron_pending_workflow(&node, controlled, options.faucet)?
        } else {
            session.pending_workflow(
                &node,
                controlled,
                wallet,
                options.faucet,
                expiry_clock.as_ref(),
            )?
        };
        Ok(proof)
    })();
    let completed = result.is_ok();
    match result {
        Ok(proof) => {
            session.report.record("pending:workflow", &[], Ok(()));
            session.report.evidence.last_mut().unwrap().detail = proof.to_string();
        }
        Err(error) => session.report.record("pending:workflow", &[], Err(error)),
    }
    for (delete, prefix, id) in std::mem::take(&mut session.owned).into_iter().rev() {
        let result = session
            .call(delete, "DELETE", &format!("/{prefix}/{id}"), None, 204)
            .map(|_| ());
        session
            .report
            .record("pending:cleanup-owned-wallet", &[], result);
    }
    if let Some(wallet) = process.as_mut() {
        session
            .report
            .record("pending:stop-owned-wallet", &[], wallet.stop());
    }
    if let Some(wallet) = adversary_process.as_mut() {
        session
            .report
            .record("pending:stop-owned-adversary", &[], wallet.stop());
    }
    drop(checkpoint_proxy);
    if completed {
        let node = NodeOracle {
            executable: options.cli_executable.into(),
            socket: successful_socket.expect("completed fixture has a native socket"),
            network_magic: 42,
        };
        let result = final_node_probe(&node, options.faucet, options.timeout);
        session.report.record(
            "pending:independent-node-integration-last",
            &[],
            result.as_ref().map(|_| ()).map_err(|e| anyhow!("{e:#}")),
        );
        if let Ok(proof) = result {
            session.report.evidence.last_mut().unwrap().detail = proof.to_string();
        }
    }
    if let Some(owned) = cluster.as_mut() {
        session
            .report
            .record("pending:stop-owned-cluster", &[], owned.stop());
    }
    if options.expiry && completed {
        let proof = session
            .report
            .evidence
            .iter()
            .find(|e| e.case == "pending:history-status-observation" && e.passed)
            .map(|e| e.detail.clone());
        let validation = (|| -> Result<()> {
            ensure!(
                session.report.passed(),
                "history workflow, native integration or cleanup failed"
            );
            ensure!(proof.is_some(), "mixed-status history proof missing");
            Ok(())
        })();
        session.report.record(
            "history:status",
            &["wallet.transaction-filtering".into()],
            validation,
        );
        if let Some(proof) = proof {
            session.report.evidence.last_mut().unwrap().detail = proof;
        }
    }
    if options.checkpoint && completed {
        let observation = checkpoint_observer.snapshot();
        let result = (|| -> Result<()> {
            ensure!(
                session.report.passed(),
                "checkpoint workflow, native probe or cleanup failed"
            );
            ensure!(
                observation.errors.is_empty(),
                "checkpoint final observer errors: {:?}",
                observation.errors
            );
            Ok(())
        })();
        let detail=json!({"observation":observation,"validation_error":result.as_ref().err().map(|e|format!("{e:#}"))}).to_string();
        session.report.record(
            "state:restore-from-checkpoint",
            &["wallet.restoration".into()],
            result,
        );
        session.report.evidence.last_mut().unwrap().detail = detail;
    }
    session.report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expiry_pause_requires_live_admission_margin_inside_native_safe_zone() {
        let clock = ExpiryClock {
            start_ps: 0,
            slot_ps: 200_000_000_000,
            epoch_length: 120,
            safe_slots: 60,
        };
        let delta = u64::try_from(EXPIRY_SECONDS * 1_000_000_000_000 / clock.slot_ps).unwrap();
        assert_eq!(delta, 40);
        clock.horizon(100 + delta, 100, 104).unwrap();
        clock.horizon(158, 100, 104).unwrap();
        for (upper, tip, now) in [
            (250, 100, 104),
            (140, 70, 104),
            (140, 100, 140),
            (140, 100, 141),
            (140, 110, 109),
            (159, 100, 104),
            (u64::MAX, 100, 104),
            (u64::MAX - 1, u64::MAX - 2, u64::MAX - 2),
        ] {
            assert!(clock.horizon(upper, tip, now).is_err());
        }
    }
    #[test]
    fn expiry_matches_exact_genesis_slot_and_changes_only_history_status() {
        expiry_validity((Some(0), Some(143)), 143).unwrap();
        for actual in [
            (None, Some(143)),
            (Some(1), Some(143)),
            (Some(0), Some(142)),
            (Some(0), None),
        ] {
            assert!(expiry_validity(actual, 143).is_err());
        }
        let clock = ExpiryClock {
            start_ps: 0,
            slot_ps: 200_000_000_000,
            epoch_length: 120,
            safe_slots: 60,
        };
        let pending = json!({"id":"11".repeat(32),"status":"pending","fee":{"quantity":200000,"unit":"lovelace"},"expires_at":{"absolute_slot_number":143,"epoch_number":1,"slot_number":23,"time":"1970-01-01T00:00:28.6Z"}});
        clock.expiry(&pending, 143).unwrap();
        for (field, value) in [
            ("absolute_slot_number", json!(142)),
            ("epoch_number", json!(2)),
            ("slot_number", json!(24)),
            ("time", json!("1970-01-01T00:00:28.600000001Z")),
            ("extra", json!(0)),
        ] {
            let mut bad = pending.clone();
            bad["expires_at"][field] = value;
            assert!(clock.expiry(&bad, 143).is_err());
        }
        let mut expired = pending.clone();
        expired["status"] = json!("expired");
        expired_history(&pending, &expired).unwrap();
        assert!(expired_history(&pending, &pending).is_err());
        expired["fee"]["quantity"] = json!(200001);
        assert!(expired_history(&pending, &expired).is_err());
        let absent = json!({"exists":false,"slot":144,"txId":"11".repeat(32)});
        mempool_membership(&absent, &"11".repeat(32), 143, 145, false).unwrap();
        assert!(mempool_membership(&absent, &"11".repeat(32), 143, 145, true).is_err());
        assert!(mempool_membership(&absent, &"22".repeat(32), 143, 145, false).is_err());
        assert!(mempool_membership(&absent, &"11".repeat(32), 145, 146, false).is_err());
    }
    #[test]
    fn mempool_membership_requires_exact_fields_hash_and_independent_slot_bracket() {
        let id = "11".repeat(32);
        let good = json!({"exists":true,"slot":309,"txId":id});
        mempool_response(&good, &id, 308, 310).unwrap();
        mempool_response(&good, &id, 309, 309).unwrap();
        for (before, after) in [(310, 311), (307, 308), (310, 308)] {
            assert!(mempool_response(&good, &id, before, after).is_err());
        }
        for (field, value) in [
            ("exists", json!(false)),
            ("slot", json!(-1)),
            ("slot", json!("309")),
            ("txId", json!("22".repeat(32))),
            ("extra", json!(0)),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            assert!(mempool_response(&bad, &id, 308, 310).is_err());
        }
        for field in ["exists", "slot", "txId"] {
            let mut bad = good.clone();
            bad.as_object_mut().unwrap().remove(field);
            assert!(mempool_response(&bad, &id, 308, 310).is_err());
        }
    }
    #[test]
    fn pending_accounting_distinguishes_locked_inputs_and_projected_change() {
        let wallet = json!({"balance":{"available":{"quantity":0,"unit":"lovelace"},"total":{"quantity":97_800_000,"unit":"lovelace"},"reward":{"quantity":0,"unit":"lovelace"}},"assets":{"available":[],"total":[]}});
        accounting(&wallet, 0, 97_800_000).unwrap();
        assert!(accounting(&wallet, FUNDING, FUNDING).is_err());
        let mut bad = wallet.clone();
        bad["balance"]["total"]["unit"] = json!("ada");
        assert!(accounting(&bad, 0, 97_800_000).is_err());
        bad = wallet;
        bad["assets"]["available"] = json!([{"quantity":1}]);
        assert!(accounting(&bad, 0, 97_800_000).is_err());
    }
    #[test]
    fn stable_relay_requires_hash_slot_and_height() {
        let a = crate::node::Tip {
            height: 3,
            slot: 7,
            hash: "11".repeat(32),
        };
        let b = crate::node::Tip {
            height: 3,
            slot: 7,
            hash: "22".repeat(32),
        };
        assert!(same_tip(&a, &b).is_err());
        same_tip(&a, &a).unwrap();
    }
}
