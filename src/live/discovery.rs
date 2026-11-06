//! Sequential discovery at actual funded gap boundaries; other discovery cases stay mandatory.
use super::{
    families::{FUNDING, SHELLEY},
    *,
};
use std::collections::BTreeSet;

pub(super) fn addresses(
    value: &Value,
    count: usize,
    used: &BTreeSet<usize>,
    previous: &[String],
) -> Result<Vec<String>> {
    let rows = value
        .as_array()
        .context("discovery addresses are not an array")?;
    ensure!(rows.len() == count, "discovery pool size differs");
    let mut result = Vec::new();
    let mut unique = BTreeSet::new();
    let mut stake = None;
    for (index, row) in rows.iter().enumerate() {
        let id = text(row, "/id")?;
        let (hrp, bytes) = crate::encoding::bech32(&id)?;
        ensure!(
            hrp == "addr_test" && bytes.len() == 57 && bytes[0] == 0,
            "discovery address is not a testnet base-key address"
        );
        ensure!(unique.insert(bytes.clone()), "duplicate discovery address");
        let expected_stake = stake.get_or_insert_with(|| bytes[29..].to_vec());
        ensure!(
            expected_stake == &bytes[29..],
            "discovery stake credential changed"
        );
        ensure!(
            row["derivation_path"] == json!(["1852H", "1815H", "0H", "0", index.to_string()]),
            "discovery derivation path/index/order differs"
        );
        ensure!(
            row["state"]
                == if used.contains(&index) {
                    "used"
                } else {
                    "unused"
                },
            "discovery used state differs"
        );
        if let Some(before) = previous.get(index) {
            ensure!(
                before == &id,
                "discovery changed a previously derived address"
            );
        }
        result.push(id);
    }
    ensure!(
        previous.len() <= result.len(),
        "discovery lost previous addresses"
    );
    Ok(result)
}
impl Session<'_> {
    fn discovery_filters(&mut self, id: &str, full: &Value) -> Result<()> {
        for state in ["used", "unused"] {
            let actual = self.call(
                "listAddresses",
                "GET",
                &format!("/wallets/{id}/addresses?state={state}"),
                None,
                200,
            )?;
            let expected = Value::Array(
                full.as_array()
                    .context("missing discovery addresses")?
                    .iter()
                    .filter(|a| a["state"] == state)
                    .cloned()
                    .collect(),
            );
            ensure!(
                actual == expected,
                "discovery state filter changed order or membership"
            );
        }
        Ok(())
    }
    pub(super) fn exercise_discovery(&mut self, options: &LiveOptions) -> Result<()> {
        let mnemonic: Vec<_> = bip39::Mnemonic::generate(15)?
            .words()
            .map(str::to_owned)
            .collect();
        let wallet = self.call("postWallet", "POST", "/wallets", Some(json!({"name":"conformance-gap-discovery","mnemonic_sentence":mnemonic,"passphrase":"conformance-test-passphrase","address_pool_gap":10})), 201)?;
        let id = text(&wallet, "/id")?;
        self.family_ready_balance(SHELLEY, &id, 0)?;
        let path = format!("/wallets/{id}/addresses");
        let initial = self.call("listAddresses", "GET", &path, None, 200)?;
        let mut known = addresses(&initial, 10, &BTreeSet::new(), &[])?;
        self.discovery_filters(&id, &initial)?;
        let mut used = BTreeSet::new();
        let mut txids = BTreeSet::new();
        let mut receipts = Vec::new();
        let faucet = Api::new(
            options
                .faucet
                .as_ref()
                .context("discovery requires faucet")?,
            self.timeout,
        )?;
        for (round, index) in [9usize, 19].into_iter().enumerate() {
            let destination = known[index].clone();
            let before = options.node.utxos(&destination, self.timeout)?;
            ensure!(
                before.as_object().is_some_and(|m| m.is_empty()),
                "discovery destination is already funded"
            );
            let response = faucet.request(&request("POST", "/send/faucet-assets", Some(json!({"batch-size":1,"assets":[{"address":destination,"bundle":{"coin":FUNDING,"assets":[]},"metadata":[]}]}))))?;
            ensure!(response.status == 204, "discovery faucet rejected funding");
            let expected_balance = FUNDING * (round as u64 + 1);
            self.family_ready_balance(SHELLEY, &id, expected_balance)?;
            self.check_snapshot(&id, expected_balance)?;
            let utxos = options.node.utxos(&destination, self.timeout)?;
            let entries = utxos.as_object().context("discovery node UTxOs missing")?;
            ensure!(
                entries.len() == 1,
                "discovery expected one exact funding output"
            );
            let (input, output) = entries.iter().next().unwrap();
            let (txid, output_index) = input
                .split_once('#')
                .context("malformed discovery funding input")?;
            ensure!(
                hex::decode(txid)?.len() == 32 && output_index.parse::<u32>().is_ok(),
                "invalid discovery input identity"
            );
            ensure!(
                txids.insert(txid.to_owned()),
                "discovery funding transaction reused"
            );
            ensure!(
                output["address"] == destination && output["value"] == json!({"lovelace":FUNDING}),
                "discovery node output differs"
            );
            options
                .node
                .payment(txid, &destination, FUNDING, self.timeout)?;
            used.insert(index);
            let full = self.call("listAddresses", "GET", &path, None, 200)?;
            known = addresses(&full, (round + 2) * 10, &used, &known)?;
            self.discovery_filters(&id, &full)?;
            let history = self.call(
                "listTransactions",
                "GET",
                &format!("/wallets/{id}/transactions"),
                None,
                200,
            )?;
            let history_rows = history.as_array().context("discovery history missing")?;
            let actual_ids = history_rows
                .iter()
                .map(|v| text(v, "/id"))
                .collect::<Result<BTreeSet<_>>>()?;
            ensure!(
                history_rows.len() == round + 1 && actual_ids == txids,
                "discovery history membership differs"
            );
            for transaction in history_rows {
                ensure!(
                    transaction["status"] == "in_ledger"
                        && transaction["direction"] == "incoming"
                        && transaction["amount"] == json!({"quantity":FUNDING,"unit":"lovelace"}),
                    "discovery funding history differs"
                );
            }
            for used_index in &used {
                let all = options.node.utxos(&known[*used_index], self.timeout)?;
                ensure!(
                    all.as_object().is_some_and(|m| m.len() == 1)
                        && all
                            .as_object()
                            .unwrap()
                            .values()
                            .all(|v| v["value"] == json!({"lovelace":FUNDING})),
                    "previous discovery funding changed"
                );
            }
            receipts.push(json!({"funded_index":index,"balance":expected_balance,"addresses":full,"node_utxos":utxos,"history":history_rows.iter().map(history::stable).collect::<Vec<_>>()}));
        }
        self.report.record(
            "discovery-sequential-gap",
            &["wallet.discovery".into()],
            Ok(()),
        );
        self.report.evidence.last_mut().unwrap().detail = json!({"assertion":"gap10 discovery at two ledger-confirmed boundaries","initial_addresses":initial,"rounds":receipts}).to_string();
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(count: usize) -> Value {
        Value::Array((0..count).map(|index| { let mut bytes = vec![0;57]; bytes[1] = index as u8; json!({"id":crate::encoding::bech32_encode("addr_test", &bytes).unwrap(),"state":"unused","derivation_path":["1852H","1815H","0H","0",index.to_string()]}) }).collect())
    }
    #[test]
    fn boundary_validator_rejects_pool_path_network_duplicate_and_state_mutations() {
        let baseline = fixture(10);
        let known = addresses(&baseline, 10, &BTreeSet::new(), &[]).unwrap();
        assert!(addresses(&baseline, 20, &BTreeSet::new(), &[]).is_err());
        for pointer in [
            "/0/derivation_path/0",
            "/0/derivation_path/3",
            "/0/derivation_path/4",
            "/0/state",
        ] {
            let mut changed = baseline.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("wrong");
            assert!(addresses(&changed, 10, &BTreeSet::new(), &known).is_err());
        }
        let mut changed = baseline.clone();
        changed[1]["id"] = changed[0]["id"].clone();
        assert!(addresses(&changed, 10, &BTreeSet::new(), &[]).is_err());
        let mut changed = baseline.clone();
        let mut bytes = vec![0; 57];
        bytes[0] = 1;
        changed[0]["id"] = json!(crate::encoding::bech32_encode("addr", &bytes).unwrap());
        assert!(addresses(&changed, 10, &BTreeSet::new(), &[]).is_err());
        let mut changed = baseline.clone();
        changed[0]["id"] = fixture(11)[10]["id"].clone();
        assert!(addresses(&changed, 10, &BTreeSet::new(), &known).is_err());
        let mut extended = fixture(20);
        extended[9]["state"] = json!("used");
        assert!(addresses(&extended, 20, &BTreeSet::from([9]), &known).is_ok());
        assert!(addresses(&extended, 20, &BTreeSet::new(), &known).is_err());
    }
}
