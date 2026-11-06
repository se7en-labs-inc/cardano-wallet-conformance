//! Empty stake-pool joining requires an independently active and wallet-known pool.
use super::{families::SHELLEY, *};
use std::collections::{BTreeMap, BTreeSet};

fn active_pools(value: &Value) -> Result<BTreeSet<String>> {
    let values = value
        .as_array()
        .context("native active pool list is not an array")?;
    ensure!(!values.is_empty(), "native active pool list is empty");
    let mut pools = BTreeSet::new();
    for value in values {
        let pool = value
            .as_str()
            .context("native active pool ID is not a string")?;
        let (hrp, bytes) = crate::encoding::bech32(pool)?;
        ensure!(
            hrp == "pool" && bytes.len() == 28 && pools.insert(pool.to_owned()),
            "native pool credential/type/uniqueness differs"
        );
    }
    Ok(pools)
}
impl Session<'_> {
    fn pool_join_snapshot(&mut self, id: &str) -> Result<Value> {
        let mut snapshot = self.delegation_snapshot(id)?;
        let wallet = self.call("getWallet", "GET", &format!("/wallets/{id}"), None, 200)?;
        snapshot["name"] = wallet["name"].clone();
        snapshot["delegation"] = wallet["delegation"].clone();
        Ok(snapshot)
    }
    pub(super) fn exercise_pool_join_guard(&mut self, options: &LiveOptions) -> Result<()> {
        let owned = self.owned.len();
        let result = self.pool_join_guard_inner(options);
        let mut cleanup = Ok(());
        for (operation, prefix, id) in self.owned.split_off(owned).into_iter().rev() {
            if let Err(error) =
                self.call(operation, "DELETE", &format!("/{prefix}/{id}"), None, 204)
            {
                cleanup = Err(error);
            }
        }
        result.and(cleanup)
    }
    fn pool_join_guard_inner(&mut self, options: &LiveOptions) -> Result<()> {
        let native = options
            .node
            .query(&["stake-pools", "--output-json"], self.timeout)?;
        let pools = active_pools(&native)?;
        let pool = pools.first().unwrap().clone();
        let wallet_pools = self.poll("listStakePools", "/stake-pools?stake=0", |value| {
            value
                .as_array()
                .is_some_and(|rows| rows.iter().any(|p| p["id"] == pool))
        })?;
        let vectors: Value =
            serde_json::from_str(include_str!("../../fixtures/vectors/haskell-keys.json"))?;
        let mnemonic = vectors[0]["input"]["mnemonic"]
            .as_str()
            .context("published mnemonic missing")?
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        let id = self.create("conformance-empty-pool-join", mnemonic)?;
        self.family_ready_balance(SHELLEY, &id, 0)?;
        self.check_snapshot(&id, 0)?;
        let before = self.pool_join_snapshot(&id)?;
        ensure!(
            before["balance"]["available"] == json!({"quantity":0,"unit":"lovelace"})
                && before["balance"]["total"] == json!({"quantity":0,"unit":"lovelace"})
                && before["balance"]["reward"] == json!({"quantity":0,"unit":"lovelace"})
                && before["assets"] == json!({"available":[],"total":[]})
                && before["history"] == json!([])
                && before["utxo"] == json!({"entries":[]}),
            "empty pool-join wallet is not independently empty"
        );
        let addresses = discovery::addresses(&before["addresses"], 20, &BTreeSet::new(), &[])?;
        ensure!(
            addresses[0] == era_boundary::base_address()?,
            "empty pool-join wallet address does not match Haskell public keys"
        );
        let mut utxos_before = BTreeMap::new();
        for address in &addresses {
            let value = options.node.utxos(address, self.timeout)?;
            ensure!(
                value == json!({}),
                "empty pool-join address already has node UTxOs"
            );
            utxos_before.insert(address.clone(), value);
        }
        let mut reward = vec![0xe0];
        reward.extend_from_slice(&transaction::blake2b(
            &era_boundary::public_key("haskell-Shelley-0-2-0-private")?,
            28,
        )?);
        let reward = crate::encoding::bech32_encode("stake_test", &reward)?;
        ensure!(
            options.node.stake_address_info(&reward, self.timeout)? == json!([]),
            "empty pool-join wallet stake key is registered"
        );
        let controls: Value =
            serde_json::from_str(include_str!("../../fixtures/voting-controls.json"))?;
        let expected = controls
            .get("empty")
            .context("frozen empty-wallet error missing")?;
        let mut errors = Vec::new();
        for _ in 0..2 {
            let error = self.call(
                "joinStakePool",
                "PUT",
                &format!("/stake-pools/{pool}/wallets/{id}"),
                Some(json!({"passphrase":"conformance-test-passphrase"})),
                403,
            )?;
            ensure!(
                &error == expected,
                "empty pool-join error differs from pinned Haskell code/message/fields"
            );
            errors.push(error);
        }
        ensure!(
            self.pool_join_snapshot(&id)? == before,
            "rejected pool joining changed wallet state"
        );
        let mut utxos_after = BTreeMap::new();
        for address in &addresses {
            utxos_after.insert(address.clone(), options.node.utxos(address, self.timeout)?);
        }
        let native_after = options
            .node
            .query(&["stake-pools", "--output-json"], self.timeout)?;
        ensure!(
            utxos_before == utxos_after
                && active_pools(&native_after)? == pools
                && options.node.stake_address_info(&reward, self.timeout)? == json!([]),
            "rejected pool joining changed node pool/UTxO/stake state"
        );
        self.report
            .record("delegation:empty-known-pool-join", &[], Ok(()));
        self.report.evidence.last_mut().unwrap().detail=json!({"selected_active_pool":pool,"native_active_pools_before":native,
            "native_active_pools_after":native_after,"wallet_known_pools":wallet_pools,"errors":errors,
            "unchanged_wallet_snapshot":before,"node_utxos_before":utxos_before,"node_utxos_after":utxos_after,
            "stake_address":reward,"unregistered_stake_preserved":true}).to_string();
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_pool_parser_rejects_empty_duplicate_wrong_type_hrp_length_and_checksum() {
        let one = crate::encoding::bech32_encode("pool", &[1; 28]).unwrap();
        let two = crate::encoding::bech32_encode("pool", &[2; 28]).unwrap();
        assert_eq!(active_pools(&json!([one, two])).unwrap().len(), 2);
        for bad in [
            json!([]),
            json!({}),
            json!([null]),
            json!([one, one]),
            json!([crate::encoding::bech32_encode("addr", &[1; 28]).unwrap()]),
            json!([crate::encoding::bech32_encode("pool", &[1; 27]).unwrap()]),
            json!(["pool1invalid"]),
        ] {
            assert!(active_pools(&bad).is_err());
        }
    }
}
