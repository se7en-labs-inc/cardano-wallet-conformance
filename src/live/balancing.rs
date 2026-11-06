//! Actual partial-transaction balance API and unsupported collateral field guards.
use super::{
    families::{FUNDING, SHELLEY},
    *,
};
const PASSWORD: &str = "conformance-test-passphrase";
fn payload(destination: &str, ttl: u64, flags: u8) -> Result<Value> {
    Ok(
        json!({"transaction":hex::encode(crate::balancing::partial(destination,ttl,flags,true)?),"inputs":[],"redeemers":[]}),
    )
}
fn guard(flags: u8, value: &Value) -> Result<()> {
    let (code, message) = if flags & 1 != 0 {
        (
            "balance_tx_existing_collateral",
            "I cannot balance transactions with pre-defined collateral.",
        )
    } else if flags & 2 != 0 {
        ("balance_tx_existing_return_collateral","Balancing transactions with pre-defined collateral return outputs is not yet supported.")
    } else if flags & 4 != 0 {
        (
            "balance_tx_existing_total_collateral",
            "I cannot balance transactions with pre-defined total collateral.",
        )
    } else {
        anyhow::bail!("collateral guard has no field")
    };
    ensure!(
        value == &json!({"code":code,"message":message}),
        "collateral guard code/message/precedence differs from actual Haskell"
    );
    Ok(())
}
fn funded(value: &Value, funding: &str, destination: &str) -> Result<transaction::Transaction> {
    let tx = transaction::inspect(&text(value, "/transaction")?, false)?;
    ensure!(
        tx.inputs == [funding.to_owned()] && tx.verification_keys.is_empty() && tx.fee > 0,
        "balanced transaction input/witness/fee differs"
    );
    let expected = hex::encode(crate::encoding::bech32(destination)?.1);
    ensure!(
        tx.outputs
            .iter()
            .filter(|v| v.address_hex == expected && v.coin == 2_000_000)
            .count()
            == 1
            && tx.outputs.iter().all(|v| v.assets.is_empty()),
        "balanced requested payment/assets differ"
    );
    let total = tx.outputs.iter().try_fold(tx.fee, |sum, v| {
        sum.checked_add(v.coin)
            .context("balance accounting overflow")
    })?;
    ensure!(
        total == FUNDING,
        "balanced transaction does not conserve funded ADA"
    );
    Ok(tx)
}
impl Session<'_> {
    pub(super) fn exercise_collateral(&mut self, options: &LiveOptions) -> Result<()> {
        let mnemonic = bip39::Mnemonic::generate(15)?
            .words()
            .map(str::to_owned)
            .collect();
        let id = self.create("conformance-collateral-guards", mnemonic)?;
        self.family_ready_balance(SHELLEY, &id, 0)?;
        let ttl = options
            .node
            .tip(self.timeout)?
            .slot
            .checked_add(3000)
            .context("collateral TTL overflow")?;
        for flags in [1, 2, 4, 6, 7] {
            let value = self.call(
                "balanceTransaction",
                "POST",
                &format!("/wallets/{id}/transactions-balance"),
                Some(payload(crate::balancing::DESTINATION, ttl, flags)?),
                403,
            )?;
            guard(flags, &value)?;
            self.family_ready_balance(SHELLEY, &id, 0)?;
            ensure!(
                self.call(
                    "listTransactions",
                    "GET",
                    &format!("/wallets/{id}/transactions"),
                    None,
                    200
                )? == json!([]),
                "collateral guard inserted history"
            );
        }
        self.report
            .record("collateral-return", &["tx.collateral".into()], Ok(()));
        Ok(())
    }
    pub(super) fn exercise_balancing(&mut self, options: &LiveOptions) -> Result<()> {
        let mnemonic = || -> Result<Vec<String>> {
            Ok(bip39::Mnemonic::generate(15)?
                .words()
                .map(str::to_owned)
                .collect())
        };
        let sender = self.create("conformance-balance-sender", mnemonic()?)?;
        let recipient = self.create("conformance-balance-recipient", mnemonic()?)?;
        self.family_ready_balance(SHELLEY, &sender, 0)?;
        self.family_ready_balance(SHELLEY, &recipient, 0)?;
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{sender}/addresses"),
            None,
            200,
        )?;
        let address = text(&addresses, "/0/id")?;
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{recipient}/addresses"),
            None,
            200,
        )?;
        let destination = text(&addresses, "/0/id")?;
        let ttl = options
            .node
            .tip(self.timeout)?
            .slot
            .checked_add(3000)
            .context("balance TTL overflow")?;
        let body = payload(&destination, ttl, 0)?;
        let path = format!("/wallets/{sender}");
        let empty = self.call(
            "balanceTransaction",
            "POST",
            &format!("{path}/transactions-balance"),
            Some(body.clone()),
            403,
        )?;
        ensure!(
            empty
                == json!({"code":"no_utxos_available","message":"Unable to create a transaction because the wallet has no unspent transaction outputs (UTxOs) available. A transaction must spend at least one UTxO in order to be accepted for inclusion on the Cardano blockchain."}),
            "empty balancing error differs"
        );
        self.family_ready_balance(SHELLEY, &sender, 0)?;
        ensure!(
            self.call(
                "listTransactions",
                "GET",
                &format!("{path}/transactions"),
                None,
                200
            )? == json!([]),
            "empty balancing inserted history"
        );
        self.family_fund(SHELLEY, &sender, &address, options)?;
        let before = options.node.utxos(&address, self.timeout)?;
        let funding = before
            .as_object()
            .context("invalid node UTxOs")?
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        ensure!(funding.len() == 1, "balancing requires one funded input");
        let balanced = self.call(
            "balanceTransaction",
            "POST",
            &format!("{path}/transactions-balance"),
            Some(body),
            202,
        )?;
        let tx = funded(&balanced, &funding[0], &destination)?;
        let unsigned = text(&balanced, "/transaction")?;
        ensure!(
            transaction::validity(&unsigned)? == (None, Some(ttl)),
            "balancing changed TTL/lower bound"
        );
        self.family_ready_balance(SHELLEY, &sender, FUNDING)?;
        ensure!(
            options.node.utxos(&address, self.timeout)? == before,
            "unsigned balance consumed node funds"
        );
        let history = self.call(
            "listTransactions",
            "GET",
            &format!("{path}/transactions"),
            None,
            200,
        )?;
        let entries = history.as_array().context("invalid balanced history")?;
        ensure!(
            entries.len() == 1
                && entries[0]["id"] == funding[0].split('#').next().unwrap()
                && entries[0]["status"] == "in_ledger"
                && entries[0]["direction"] == "incoming",
            "unsigned balance inserted or changed transaction identities"
        );
        let decoded = self.call(
            "decodeTransaction",
            "POST",
            &format!("{path}/transactions-decode"),
            Some(json!({"transaction":unsigned})),
            202,
        )?;
        ensure!(decoded["id"] == tx.id, "decoded balanced body hash differs");
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("{path}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":PASSWORD})),
            202,
        )?;
        let encoded = text(&signed, "/transaction")?;
        let signed_tx = transaction::inspect(&encoded, true)?;
        ensure!(
            signed_tx.id == tx.id && signed_tx.verification_keys.len() == 1,
            "signing changed balanced body or witness count"
        );
        let accepted = self.call(
            "submitTransaction",
            "POST",
            &format!("{path}/transactions-submit"),
            Some(json!({"transaction":encoded})),
            202,
        )?;
        ensure!(accepted["id"] == tx.id, "balanced submission ID differs");
        self.family_confirm(SHELLEY, &sender, &tx.id)?;
        self.family_confirm(SHELLEY, &recipient, &tx.id)?;
        self.family_ready_balance(SHELLEY, &sender, FUNDING - 2_000_000 - tx.fee)?;
        self.family_ready_balance(SHELLEY, &recipient, 2_000_000)?;
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("{path}/addresses"),
            None,
            200,
        )?;
        for output in &tx.outputs {
            let output_address =
                if output.address_hex == hex::encode(crate::encoding::bech32(&destination)?.1) {
                    destination.clone()
                } else {
                    addresses
                        .as_array()
                        .context("missing sender address list")?
                        .iter()
                        .filter_map(|v| v["id"].as_str())
                        .find(|a| {
                            crate::encoding::bech32(a)
                                .is_ok_and(|(_, raw)| hex::encode(raw) == output.address_hex)
                        })
                        .context("balanced change is not owned")?
                        .to_owned()
                };
            options
                .node
                .payment(&tx.id, &output_address, output.coin, self.timeout)?;
        }
        ensure!(
            options
                .node
                .utxos(&address, self.timeout)?
                .as_object()
                .context("invalid spent UTxOs")?
                .get(&funding[0])
                .is_none(),
            "balanced control did not spend funding"
        );
        self.report
            .record("live:balanced-partial-payment", &[], Ok(()));
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_balanced_control_preserves_ttl_funding_and_payment() {
        let value: Value =
            serde_json::from_str(include_str!("../../fixtures/balanced-control.json")).unwrap();
        let tx = transaction::inspect(value["transaction"].as_str().unwrap(), false).unwrap();
        funded(&value, &tx.inputs[0], crate::balancing::DESTINATION).unwrap();
        assert_eq!(
            transaction::validity(value["transaction"].as_str().unwrap()).unwrap(),
            (None, Some(6_000_000))
        );
        assert!(funded(
            &value,
            &format!("{}#0", "00".repeat(32)),
            crate::balancing::DESTINATION
        )
        .is_err());
        assert!(funded(
            &value,
            &tx.inputs[0],
            "addr1vxz6hulv54gzf2suy2u5gkvmt6ysasfdlvvegy3fmf969yc3nuz8v"
        )
        .is_err());
    }
    #[test]
    fn collateral_errors_match_actual_source_and_guard_order() {
        let errors: Value =
            serde_json::from_str(include_str!("../../fixtures/balancing-errors.json")).unwrap();
        for flags in [1, 2, 4, 6, 7] {
            guard(flags, &errors[flags.to_string()]).unwrap();
        }
        assert!(guard(6, &errors["4"]).is_err());
        assert!(guard(7, &errors["2"]).is_err());
        let mut changed = errors["2"].clone();
        changed["code"] = json!("balance_tx_existing_collateral_return_outputs");
        assert!(guard(2, &changed).is_err());
        assert!(guard(0, &errors["1"]).is_err());
    }
}
