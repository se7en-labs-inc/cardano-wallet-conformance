//! Genuine pending deletion and confirmed rejection for both Byron discovery styles.
use super::{
    families::{BYRON, SHELLEY},
    pending::{mempool, same_tip},
    *,
};
use crate::{cluster_control::Cluster, node::NodeOracle};
use std::collections::{BTreeMap, BTreeSet};
const FUNDING: u64 = 100_000_000;
const PAYMENT: u64 = 2_000_000;
const PASSWORD: &str = "conformance-test-passphrase";

fn balance(wallet: &Value, available: u64, total: u64) -> Result<()> {
    ensure!(
        number(wallet, "/balance/available/quantity")? == available
            && number(wallet, "/balance/total/quantity")? == total
            && wallet["balance"]["available"]["unit"] == "lovelace"
            && wallet["balance"]["total"]["unit"] == "lovelace"
            && wallet["assets"] == json!({"available":[],"total":[]}),
        "Byron pending balances/assets differ"
    );
    Ok(())
}
fn missing(value: &Value, id: &str) -> Result<()> {
    ensure!(
        *value
            == json!({"code":"no_such_transaction","message":format!("I couldn't find a transaction with the given id: {id}"),"info":{"transaction_id":id}}),
        "Byron forgotten transaction error differs"
    );
    Ok(())
}
impl Session<'_> {
    fn byron_pending_snapshot(&mut self, id: &str) -> Result<Value> {
        let path = format!("/byron-wallets/{id}");
        let wallet = self.call("getByronWallet", "GET", &path, None, 200)?;
        let stable_wallet: serde_json::Map<_, _> =
            ["id", "name", "balance", "assets", "passphrase"]
                .into_iter()
                .map(|key| (key.into(), wallet[key].clone()))
                .collect();
        let addresses = self.call(
            "listByronAddresses",
            "GET",
            &format!("{path}/addresses"),
            None,
            200,
        )?;
        let utxo = self.call(
            "getByronWalletUtxoSnapshot",
            "GET",
            &format!("{path}/utxo"),
            None,
            200,
        )?;
        let history = self.call(
            "listByronTransactions",
            "GET",
            &format!("{path}/transactions"),
            None,
            200,
        )?;
        let history: Vec<_> = history
            .as_array()
            .context("Byron pending history missing")?
            .iter()
            .map(history::stable)
            .collect();
        Ok(json!({"wallet":stable_wallet,"addresses":addresses,"utxo":utxo,"history":history}))
    }
    fn byron_pending_proof(&mut self, name: &str, proof: Value) {
        self.report.record(name, &[], Ok(()));
        self.report.evidence.last_mut().unwrap().detail = proof.to_string();
    }

    fn byron_confirmed_delete_control(
        &mut self,
        style: &str,
        destination: &str,
        node: &NodeOracle,
        faucet: &str,
    ) -> Result<Value> {
        let mnemonic: Vec<_> = bip39::Mnemonic::generate(if style == "random" { 12 } else { 15 })?
            .words()
            .map(str::to_owned)
            .collect();
        let created = self.call("postByronWallet", "POST", "/byron-wallets", Some(json!({"style":style,"name":format!("conformance-confirmed-{style}"),"mnemonic_sentence":mnemonic,"passphrase":PASSWORD})), 201)?;
        let id = text(&created, "/id")?;
        self.family_ready_balance(BYRON, &id, 0)?;
        let base = format!("/byron-wallets/{id}");
        let address = if style == "random" {
            text(
                &self.call(
                    "createAddress",
                    "POST",
                    &format!("{base}/addresses"),
                    Some(json!({"passphrase":PASSWORD,"address_index":2147495993u64})),
                    201,
                )?,
                "/id",
            )?
        } else {
            text(
                &self.call(
                    "listByronAddresses",
                    "GET",
                    &format!("{base}/addresses"),
                    None,
                    200,
                )?,
                "/0/id",
            )?
        };
        self.byron_bridge(&id, &address, node, faucet)?;
        let funding = node.utxos(&address, self.timeout)?;
        let entries = funding
            .as_object()
            .context("confirmed Byron funding missing")?;
        ensure!(
            entries.len() == 1,
            "confirmed Byron needs one funding input"
        );
        let (reference, funded) = entries.iter().next().unwrap();
        ensure!(
            funded["address"] == address && funded["value"] == json!({"lovelace":FUNDING}),
            "confirmed Byron funding identity/value differs"
        );
        let submitted = self.call("postByronTransaction", "POST", &format!("{base}/transactions"), Some(json!({"payments":[{"address":destination,"amount":{"quantity":PAYMENT,"unit":"lovelace"}}],"passphrase":PASSWORD})), 202)?;
        let txid = text(&submitted, "/id")?;
        let confirmed = self.family_confirm(BYRON, &id, &txid)?;
        let fee = number(&confirmed, "/fee/quantity")?;
        let change = FUNDING
            .checked_sub(PAYMENT)
            .and_then(|v| v.checked_sub(fee))
            .context("confirmed Byron fee underflow")?;
        let inputs = confirmed["inputs"]
            .as_array()
            .context("confirmed Byron inputs missing")?;
        ensure!(
            inputs.len() == 1
                && format!(
                    "{}#{}",
                    text(&inputs[0], "/id")?,
                    number(&inputs[0], "/index")?
                ) == *reference
                && inputs[0]["address"] == address
                && inputs[0]["assets"] == json!([])
                && number(&inputs[0], "/amount/quantity")? == FUNDING
                && fee > 0
                && confirmed["direction"] == "outgoing"
                && number(&confirmed, "/amount/quantity")? == PAYMENT + fee,
            "confirmed Byron input/amount/fee differs"
        );
        self.family_ready_balance(BYRON, &id, change)?;
        let before = self.byron_pending_snapshot(&id)?;
        balance(&before["wallet"], change, change)?;
        let owned: BTreeSet<_> = before["addresses"]
            .as_array()
            .context("confirmed Byron addresses missing")?
            .iter()
            .map(|v| text(v, "/id"))
            .collect::<Result<_>>()?;
        let mut outputs = BTreeMap::<String, u64>::new();
        for output in confirmed["outputs"]
            .as_array()
            .context("confirmed Byron outputs missing")?
        {
            let output_address = text(output, "/address")?;
            ensure!(
                (output_address == destination || owned.contains(&output_address))
                    && output["assets"] == json!([]),
                "confirmed Byron output ownership/assets differ"
            );
            let sum = outputs.entry(output_address).or_default();
            *sum = sum
                .checked_add(number(output, "/amount/quantity")?)
                .context("confirmed Byron output overflow")?;
        }
        ensure!(
            outputs.get(destination) == Some(&PAYMENT)
                && outputs.values().map(|v| u128::from(*v)).sum::<u128>() + u128::from(fee)
                    == u128::from(FUNDING),
            "confirmed Byron outputs/payment/conservation differ"
        );
        let mut native_after = BTreeMap::new();
        for (output_address, coin) in &outputs {
            node.payment(&txid, output_address, *coin, self.timeout)?;
            native_after.insert(
                output_address.clone(),
                node.utxos(output_address, self.timeout)?,
            );
        }
        let spent = node.utxos(&address, self.timeout)?;
        ensure!(
            !spent
                .as_object()
                .context("confirmed Byron spent map missing")?
                .contains_key(reference),
            "confirmed Byron funding remains unspent"
        );
        native_after.insert(address, spent);
        let path = format!("{base}/transactions/{txid}");
        let rejected = self.call("deleteByronTransaction", "DELETE", &path, None, 403)?;
        history::already_in_ledger(&rejected, &txid)?;
        ensure!(
            self.byron_pending_snapshot(&id)? == before,
            "fresh confirmed deletion changed Byron wallet/history state"
        );
        for (address, expected) in &native_after {
            ensure!(
                node.utxos(address, self.timeout)? == *expected,
                "fresh confirmed deletion changed Byron native UTxOs"
            );
        }
        Ok(
            json!({"transaction_id":txid,"never_forgotten":true,"confirmed":confirmed,"wallet_snapshot":before,"native_funding_before":funding,"native_outputs_after":native_after,"delete_error":rejected}),
        )
    }
    pub(super) fn byron_pending_workflow(
        &mut self,
        node: &NodeOracle,
        cluster: &Cluster,
        faucet: &str,
    ) -> Result<Value> {
        let phrase = || -> Result<Vec<String>> {
            Ok(bip39::Mnemonic::generate(15)?
                .words()
                .map(str::to_owned)
                .collect())
        };
        let recipient = self.create("conformance-Byron-pending-recipient", phrase()?)?;
        self.family_ready_balance(SHELLEY, &recipient, 0)?;
        let destination = text(
            &self.call(
                "listAddresses",
                "GET",
                &format!("/wallets/{recipient}/addresses"),
                None,
                200,
            )?,
            "/0/id",
        )?;
        let mut receipts = Vec::new();
        for (index, style) in ["random", "icarus"].into_iter().enumerate() {
            let mnemonic: Vec<_> =
                bip39::Mnemonic::generate(if style == "random" { 12 } else { 15 })?
                    .words()
                    .map(str::to_owned)
                    .collect();
            let created=self.call("postByronWallet","POST","/byron-wallets",Some(json!({"style":style,"name":format!("conformance-pending-{style}"),"mnemonic_sentence":mnemonic,"passphrase":PASSWORD})),201)?;
            let id = text(&created, "/id")?;
            self.family_ready_balance(BYRON, &id, 0)?;
            let base = format!("/byron-wallets/{id}");
            let address = if style == "random" {
                text(
                    &self.call(
                        "createAddress",
                        "POST",
                        &format!("{base}/addresses"),
                        Some(json!({"passphrase":PASSWORD,"address_index":2147495993u64})),
                        201,
                    )?,
                    "/id",
                )?
            } else {
                text(
                    &self.call(
                        "listByronAddresses",
                        "GET",
                        &format!("{base}/addresses"),
                        None,
                        200,
                    )?,
                    "/0/id",
                )?
            };
            self.byron_bridge(&id, &address, node, faucet)?;
            let funding = node.utxos(&address, self.timeout)?;
            ensure!(
                funding.as_object().is_some_and(|m| m.len() == 1)
                    && funding
                        .as_object()
                        .unwrap()
                        .values()
                        .all(|v| v["address"] == address
                            && v["value"] == json!({"lovelace":FUNDING})),
                "Byron pending funding differs"
            );
            let paused = cluster.pause(self.timeout)?;
            let deadline = Instant::now() + self.timeout;
            let mut stable = node.tip(self.timeout)?;
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
                    "Byron paused tip did not stabilize"
                );
            }
            let baseline = self.byron_pending_snapshot(&id)?;
            balance(&baseline["wallet"], FUNDING, FUNDING)?;
            let submitted=self.call("postByronTransaction","POST",&format!("{base}/transactions"),Some(json!({"payments":[{"address":destination,"amount":{"quantity":PAYMENT,"unit":"lovelace"}}],"passphrase":PASSWORD})),202)?;
            let txid = text(&submitted, "/id")?;
            let path = format!("{base}/transactions/{txid}");
            let pending = self.poll("getByronTransaction", &path, |v| v["status"] == "pending")?;
            let fee = number(&pending, "/fee/quantity")?;
            let change = FUNDING
                .checked_sub(PAYMENT)
                .and_then(|v| v.checked_sub(fee))
                .context("Byron pending fee underflow")?;
            ensure!(
                fee > 0
                    && number(&pending, "/amount/quantity")? == PAYMENT + fee
                    && pending["direction"] == "outgoing",
                "Byron pending amount/fee/direction differs"
            );
            let state = self.byron_pending_snapshot(&id)?;
            balance(&state["wallet"], 0, FUNDING - PAYMENT - fee)?;
            ensure!(
                state["utxo"]["entries"] == json!([]),
                "Byron pending funding is available in snapshot"
            );
            let pool = mempool(node, &txid, self.timeout)?;
            ensure!(
                node.utxos(&address, self.timeout)? == funding,
                "Byron pending funding changed before inclusion"
            );
            same_tip(&stable, &node.tip(self.timeout)?)?;
            self.byron_pending_proof(&format!("pending:byron-{style}-admitted"),json!({"pending":pending,"state":state,"mempool":pool,"funding":funding,"stable_tip":{"height":stable.height,"slot":stable.slot,"hash":stable.hash}}));
            self.call("deleteByronTransaction", "DELETE", &path, None, 204)?;
            missing(
                &self.call("getByronTransaction", "GET", &path, None, 404)?,
                &txid,
            )?;
            let forgotten = self.byron_pending_snapshot(&id)?;
            balance(&forgotten["wallet"], FUNDING, FUNDING)?;
            ensure!(
                forgotten["wallet"] == baseline["wallet"]
                    && forgotten["history"] == baseline["history"]
                    && forgotten["utxo"] == baseline["utxo"]
                    && forgotten["addresses"] == state["addresses"],
                "Byron forgetting changed identity/history/input/address state"
            );
            let pool_forgotten = mempool(node, &txid, self.timeout)?;
            ensure!(
                node.utxos(&address, self.timeout)? == funding,
                "Byron forgetting changed native funding"
            );
            same_tip(&stable, &node.tip(self.timeout)?)?;
            self.byron_pending_proof(
                &format!("pending:byron-{style}-forgotten"),
                json!({"forgotten":forgotten,"mempool_after_forget":pool_forgotten}),
            );
            paused.resume()?;
            let confirmed = self.family_confirm(BYRON, &id, &txid)?;
            let inputs = confirmed["inputs"]
                .as_array()
                .context("Byron confirmed inputs missing")?;
            ensure!(inputs.len() == 1, "Byron pending input count differs");
            let reference = format!(
                "{}#{}",
                text(&inputs[0], "/id")?,
                number(&inputs[0], "/index")?
            );
            ensure!(
                funding.get(&reference).is_some()
                    && inputs[0]["address"] == address
                    && number(&inputs[0], "/amount/quantity")? == FUNDING
                    && inputs[0]["assets"] == json!([]),
                "Byron confirmed input differs from native funding"
            );
            let final_state = self.byron_pending_snapshot(&id)?;
            let owned: BTreeSet<_> = final_state["addresses"]
                .as_array()
                .context("Byron confirmed addresses missing")?
                .iter()
                .map(|v| text(v, "/id"))
                .collect::<Result<_>>()?;
            let mut outputs = BTreeMap::<String, u64>::new();
            for output in confirmed["outputs"]
                .as_array()
                .context("Byron confirmed outputs missing")?
            {
                let address = text(output, "/address")?;
                ensure!(
                    (address == destination || owned.contains(&address))
                        && output["assets"] == json!([]),
                    "Byron confirmed output ownership/assets differ"
                );
                let total = outputs.entry(address).or_default();
                *total = total
                    .checked_add(number(output, "/amount/quantity")?)
                    .context("Byron output overflow")?;
            }
            ensure!(
                outputs.get(&destination) == Some(&PAYMENT)
                    && outputs.values().map(|v| u128::from(*v)).sum::<u128>() + u128::from(fee)
                        == u128::from(FUNDING)
                    && number(&confirmed, "/fee/quantity")? == fee,
                "Byron confirmed payment/conservation/fee differs"
            );
            let mut native_after = BTreeMap::new();
            for (address, coin) in &outputs {
                node.payment(&txid, address, *coin, self.timeout)?;
                native_after.insert(address.clone(), node.utxos(address, self.timeout)?);
            }
            let spent = node.utxos(&address, self.timeout)?;
            ensure!(
                !spent
                    .as_object()
                    .context("invalid Byron spent funding map")?
                    .contains_key(&reference),
                "Byron funding remains unspent after inclusion"
            );
            native_after.insert(address.clone(), spent);
            self.family_ready_balance(BYRON, &id, change)?;
            self.family_ready_balance(SHELLEY, &recipient, (2 * index as u64 + 1) * PAYMENT)?;
            let before_reject = self.byron_pending_snapshot(&id)?;
            let rejected = self.call("deleteByronTransaction", "DELETE", &path, None, 404)?;
            missing(&rejected, &txid)?;
            ensure!(
                self.byron_pending_snapshot(&id)? == before_reject,
                "Byron confirmed deletion changed stable wallet/history state"
            );
            for (address, expected) in &native_after {
                ensure!(
                    node.utxos(address, self.timeout)? == *expected,
                    "Byron confirmed deletion changed native UTxOs"
                );
            }
            receipts.push(json!({"style":style,"transaction_id":txid,"pending":pending,"forgotten":forgotten,"confirmed":confirmed,"final_state":before_reject,"native_outputs":native_after,"rediscovered_delete_error":rejected}));
            self.byron_pending_proof(
                &format!("pending:byron-{style}-rediscovered-delete-404"),
                receipts.last().unwrap().clone(),
            );
            let confirmed_control =
                self.byron_confirmed_delete_control(style, &destination, node, faucet)?;
            self.family_ready_balance(SHELLEY, &recipient, 2 * (index as u64 + 1) * PAYMENT)?;
            self.byron_pending_proof(
                &format!("pending:byron-{style}-fresh-confirmed-delete-403"),
                confirmed_control.clone(),
            );
            receipts.last_mut().unwrap()["fresh_confirmed_control"] = confirmed_control;
        }
        Ok(json!({"byron_pending":receipts}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byron_pending_balance_requires_reserved_funds_units_and_empty_assets() {
        let wallet = json!({"balance":{"available":{"quantity":0,"unit":"lovelace"},"total":{"quantity":97800000,"unit":"lovelace"}},"assets":{"available":[],"total":[]}});
        balance(&wallet, 0, 97800000).unwrap();
        for pointer in [
            "/balance/available/quantity",
            "/balance/total/quantity",
            "/balance/total/unit",
            "/assets/total",
        ] {
            let mut bad = wallet.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("wrong");
            assert!(balance(&bad, 0, 97800000).is_err());
        }
        let id = "11".repeat(32);
        let mut error = json!({"code":"no_such_transaction","message":format!("I couldn't find a transaction with the given id: {id}"),"info":{"transaction_id":id}});
        missing(&error, &id).unwrap();
        error["info"]["transaction_id"] = json!("22".repeat(32));
        assert!(missing(&error, &id).is_err());
    }
}
