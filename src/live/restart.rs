//! Confirmed state and key/address persistence across death of the owned wallet process.
use super::*;
use crate::owned_process::WalletProcess;
use std::collections::BTreeMap;

fn fields(value: &Value, names: &[&str]) -> Value {
    Value::Object(
        names
            .iter()
            .map(|name| ((*name).into(), value[*name].clone()))
            .collect(),
    )
}

impl Session<'_> {
    fn restart_snapshot(&mut self, id: &str, options: &LiveOptions) -> Result<Value> {
        let path = format!("/wallets/{id}");
        let wallet = self.poll("getWallet", &path, |value| {
            value["state"]["status"] == "ready"
        })?;
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("{path}/addresses"),
            None,
            200,
        )?;
        let key = self.call(
            "getAccountKey",
            "GET",
            &format!("{path}/keys?format=extended"),
            None,
            200,
        )?;
        let (hrp, raw_key) =
            crate::encoding::bech32(key.as_str().context("account key must be text")?)?;
        ensure!(
            hrp == "acct_xvk" && raw_key.len() == 64,
            "restart account key encoding differs"
        );
        ensure!(
            wallet["id"] == id,
            "restart wallet identity differs from created identity"
        );
        ed25519_dalek::VerifyingKey::from_bytes(raw_key[..32].try_into()?)?;
        let snapshot = self.call(
            "getWalletUtxoSnapshot",
            "GET",
            &format!("{path}/utxo"),
            None,
            200,
        )?;
        let statistics = self.call(
            "getUTxOsStatistics",
            "GET",
            &format!("{path}/statistics/utxos"),
            None,
            200,
        )?;
        let history = self.call(
            "listTransactions",
            "GET",
            &format!("{path}/transactions"),
            None,
            200,
        )?;
        let history = history
            .as_array()
            .context("restart history is not an array")?;
        ensure!(
            !history.is_empty() && history.iter().all(|tx| tx["status"] == "in_ledger"),
            "restart confirmed control requires nonempty confirmed history"
        );
        let stable_history: Vec<_> = history
            .iter()
            .map(|tx| {
                fields(
                    tx,
                    &[
                        "id",
                        "status",
                        "direction",
                        "amount",
                        "fee",
                        "inputs",
                        "outputs",
                        "metadata",
                        "inserted_at",
                        "pending_since",
                        "expires_at",
                        "deposit_taken",
                        "deposit_returned",
                        "withdrawals",
                        "script_validity",
                    ],
                )
            })
            .collect();
        let mut node = BTreeMap::new();
        for address in addresses
            .as_array()
            .context("restart addresses are not an array")?
        {
            let address = text(address, "/id")?;
            let utxos = options.node.utxos(&address, self.timeout)?;
            ensure!(utxos.is_object(), "restart node UTxOs are not an object");
            if !utxos.as_object().unwrap().is_empty() {
                node.insert(address, utxos);
            }
        }
        ensure!(
            !node.is_empty(),
            "restart confirmed control has no node funding"
        );
        Ok(json!({
            "wallet":fields(&wallet, &["id","name","address_pool_gap","balance","assets","delegation","passphrase"]),
            "addresses":addresses,"account_key":key,"utxo":snapshot,"statistics":statistics,
            "history":stable_history,"node_utxos":node
        }))
    }

    pub(super) fn exercise_restart(
        &mut self,
        options: &LiveOptions,
        process: &mut WalletProcess,
    ) -> Result<()> {
        let ids: Vec<_> = self
            .owned
            .iter()
            .map(|(_, prefix, id)| {
                ensure!(
                    *prefix == "wallets",
                    "restart only supports owned Shelley wallets"
                );
                Ok(id.clone())
            })
            .collect::<Result<_>>()?;
        ensure!(
            ids.len() == 2,
            "restart expects the basic profile's two owned wallets"
        );
        let mut sender = None;
        for id in &ids {
            if self.balance(id)? > options.amount + 2_000_000 {
                sender = Some(id.clone());
            }
        }
        let sender = sender.context("restart has no funded signing control")?;
        let recipient = ids.iter().find(|id| **id != sender).unwrap();
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{recipient}/addresses"),
            None,
            200,
        )?;
        let destination = text(&addresses, "/0/id")?;
        let constructed = self.call("constructTransaction", "POST", &format!("/wallets/{sender}/transactions-construct"),
            Some(json!({"payments":[{"address":destination,"amount":{"quantity":options.amount,"unit":"lovelace"}}]})), 202)?;
        let unsigned = text(&constructed, "/transaction")?;
        let unsigned_tx = transaction::inspect(&unsigned, false)?;
        let sign = json!({"transaction":unsigned,"passphrase":"conformance-test-passphrase"});
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("/wallets/{sender}/transactions-sign"),
            Some(sign.clone()),
            202,
        )?;
        let signed_tx = transaction::inspect(&text(&signed, "/transaction")?, true)?;
        ensure!(
            signed_tx.id == unsigned_tx.id && signed_tx.verification_keys.len() == 1,
            "restart signing control changed body or witness count"
        );
        let credential = transaction::blake2b(&hex::decode(&signed_tx.verification_keys[0])?, 28)?;
        for input in constructed["coin_selection"]["inputs"]
            .as_array()
            .context("restart selected inputs missing")?
        {
            let address = crate::encoding::bech32(&text(input, "/address")?)?.1;
            ensure!(
                address.len() == 57 && address[0] == 0 && address[1..29] == credential,
                "restart signature does not authorize selected funding inputs"
            );
        }
        let mut before = BTreeMap::new();
        for id in &ids {
            before.insert(id.clone(), self.restart_snapshot(id, options)?);
        }
        let old_pid = process.ensure_running()?;
        let node_before = options.node.tip(self.timeout)?;
        process.crash_restart()?;
        process.wait_listener(&self.api.label, self.timeout)?;
        let new_pid = process.ensure_running()?;
        ensure!(
            old_pid != new_pid,
            "restart did not replace the owned process"
        );
        self.poll("getNetworkInformation", "/network/information", |value| {
            value["sync_progress"]["status"] == "ready"
        })?;
        for id in &ids {
            let after = self.restart_snapshot(id, options)?;
            ensure!(
                before[id] == after,
                "restart changed persisted state for owned wallet {id}"
            );
        }
        let signed_after = self.call(
            "signTransaction",
            "POST",
            &format!("/wallets/{sender}/transactions-sign"),
            Some(sign),
            202,
        )?;
        ensure!(
            signed == signed_after,
            "restart changed deterministic signing response"
        );
        let after_tx = transaction::inspect(&text(&signed_after, "/transaction")?, true)?;
        ensure!(
            after_tx.id == signed_tx.id
                && after_tx.verification_keys == signed_tx.verification_keys,
            "restart changed independently verified key witnesses"
        );
        let node_after = options.node.tip(self.timeout)?;
        ensure!(
            node_after.height >= node_before.height,
            "restart control observed a node rollback"
        );
        for case in ["state:restart-confirmed", "state:restart-key-address-state"] {
            self.report.record(case, &["wallet.restart".into()], Ok(()));
            self.report.evidence.last_mut().unwrap().detail = json!({
                "assertion":"exact persisted snapshots and deterministic signature after owned crash/restart",
                "old_pid":old_pid,"new_pid":new_pid,"generation":process.generation(),
                "executable_sha256":process.executable_sha256(),"confirmed_snapshots":before,
                "signed_transaction":signed_after,"node_before":node_before.hash,"node_after":node_after.hash
            }).to_string();
        }
        Ok(())
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    #[test]
    fn published_mnemonic_wallet_identity_hashes_root_not_account() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../fixtures/vectors/haskell-keys.json")).unwrap();
        let root = vectors
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == "haskell-Shelley-root")
            .unwrap();
        let root = hex::decode(root["expected"]["result"]["xpub_hex"].as_str().unwrap()).unwrap();
        let http: Value =
            serde_json::from_str(include_str!("../../fixtures/http-keys.json")).unwrap();
        let identity = http["cases"][0]["assertions"]["/id"].as_str().unwrap();
        assert_eq!(
            hex::encode(transaction::blake2b(&root, 20).unwrap()),
            identity
        );
        let account = http["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == "key-api-get-account-extended")
            .unwrap();
        let account =
            hex::decode(account["assert_bech32"][""]["bytes_hex"].as_str().unwrap()).unwrap();
        assert_ne!(
            hex::encode(transaction::blake2b(&account, 20).unwrap()),
            identity
        );
    }
}
