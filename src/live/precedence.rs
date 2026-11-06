//! Source-grounded routing, network and funded/empty-wallet error precedence.
use super::*;
use families::{FUNDING, SHELLEY};

const ZERO: &str = "0000000000000000000000000000000000000000";
const TEST: &str = "addr_test1vzz6hulv54gzf2suy2u5gkvmt6ysasfdlvvegy3fmf969yc2mg7gf";
const MAIN: &str = "addr1vxz6hulv54gzf2suy2u5gkvmt6ysasfdlvvegy3fmf969yc3nuz8v";
const EMPTY: &str = "Unable to create a transaction because the wallet has no unspent transaction outputs (UTxOs) available. A transaction must spend at least one UTxO in order to be accepted for inclusion on the Cardano blockchain.";
const SMALL: &str = "One of the outputs you've specified has an ada quantity that is below the minimum required. Either increase the ada quantity to at least the minimum, or specify an ada quantity of zero, in which case the wallet will automatically assign the correct minimum ada quantity to the output.";
fn payment(address: &str, amount: u64) -> Value {
    json!({"payments":[{"address":address,"amount":{"quantity":amount,"unit":"lovelace"}}]})
}
fn equal(actual: &Value, expected: Value) -> Result<()> {
    ensure!(
        actual == &expected,
        "precedence error differs from pinned exact envelope"
    );
    Ok(())
}
fn checked_depth(rows: &Value, before: u64, after: u64, node: u64) -> Result<(Value, Vec<u64>)> {
    ensure!(
        before <= after && after <= node,
        "invalid history tip bracket"
    );
    let mut stable = rows.clone();
    let mut depths = Vec::new();
    for row in stable
        .as_array_mut()
        .context("precedence history is not an array")?
    {
        ensure!(
            row["status"] == "in_ledger" && row["depth"]["unit"] == "block",
            "invalid confirmed history status/depth unit"
        );
        let inserted = number(row, "/inserted_at/height/quantity")?;
        let depth = number(row, "/depth/quantity")?;
        ensure!(
            depth >= before.saturating_sub(inserted) && depth <= after.saturating_sub(inserted),
            "history depth outside observed wallet/node bracket"
        );
        depths.push(depth);
        row["depth"]
            .as_object_mut()
            .context("invalid depth object")?
            .remove("quantity");
    }
    Ok((stable, depths))
}
fn unchanged_history(before: &(Value, Vec<u64>), after: &(Value, Vec<u64>)) -> Result<()> {
    ensure!(
        before.0 == after.0
            && before.1.len() == after.1.len()
            && before.1.iter().zip(&after.1).all(|(a, b)| a <= b),
        "precedence history changed or depth decreased"
    );
    Ok(())
}
pub(super) fn minimum(cost: u64) -> Result<u64> {
    let (_, address) = crate::encoding::bech32(TEST)?;
    let mut e = minicbor::Encoder::new(Vec::new());
    // Actual wallet min-coin profile replaces coin with maximum supply before sizing.
    e.array(2)?.bytes(&address)?.u64(45_000_000_000_000_000)?;
    cost.checked_mul(160 + e.writer().len() as u64)
        .context("minimum ADA overflow")
}
pub(super) fn small(minimum: u64) -> Value {
    json!({"code":"utxo_too_small","info":{"tx_output_index":0,"tx_output_lovelace_required_minimum":{"quantity":minimum,"unit":"lovelace"},"tx_output_lovelace_specified":{"quantity":1,"unit":"lovelace"}},"message":SMALL})
}
impl Session<'_> {
    fn precedence_history(&mut self, id: &str, options: &LiveOptions) -> Result<(Value, Vec<u64>)> {
        let path = format!("/wallets/{id}");
        let before = self.call("getWallet", "GET", &path, None, 200)?;
        let rows = self.call(
            "listTransactions",
            "GET",
            &format!("{path}/transactions"),
            None,
            200,
        )?;
        let after = self.call("getWallet", "GET", &path, None, 200)?;
        checked_depth(
            &rows,
            number(&before, "/tip/height/quantity")?,
            number(&after, "/tip/height/quantity")?,
            options.node.tip(self.timeout)?.height,
        )
    }
    pub(super) fn exercise_precedence(&mut self, options: &LiveOptions) -> Result<()> {
        let mut req = request(
            "POST",
            "/wallets/invalid-conformance-parameter/transactions-construct",
            None,
        );
        req.raw_body = Some("{".into());
        let response = self
            .api
            .checked(self.contract, "constructTransaction", req, 400)?;
        equal(
            body(&response)?,
            json!({"code":"bad_request","message":"wallet id should be a hex-encoded string of 40 characters"}),
        )?;
        self.report.record(
            "precedence:path-body",
            &["api.error-precedence".into()],
            Ok(()),
        );
        let response = self.call(
            "postTransaction",
            "POST",
            &format!("/wallets/{ZERO}/transactions"),
            Some({
                let mut body = payment(TEST, 2_000_000);
                body["passphrase"] = json!("wrong-but-valid-passphrase");
                body
            }),
            404,
        )?;
        equal(
            &response,
            json!({"code":"no_such_wallet","info":{"wallet_id":ZERO},"message":format!("I couldn't find a wallet with the given id: {ZERO}")}),
        )?;
        self.report.record(
            "precedence:wallet-passphrase",
            &["api.error-precedence".into()],
            Ok(()),
        );
        let (main_hrp, main) = crate::encoding::bech32(MAIN)?;
        let (test_hrp, test) = crate::encoding::bech32(TEST)?;
        ensure!(
            main_hrp == "addr"
                && test_hrp == "addr_test"
                && main[0] == 0x61
                && test[0] == 0x60
                && main[1..] == test[1..],
            "network fixtures differ beyond network tag"
        );
        let response = self.call(
            "constructTransaction",
            "POST",
            &format!("/wallets/{ZERO}/transactions-construct"),
            Some(payment(MAIN, 2_000_000)),
            400,
        )?;
        equal(
            &response,
            json!({"code":"bad_request","message":format!("Error in $.payments[0].address: parsing AddressAmount failed, (String '{MAIN}',TextDecodingError {{getTextDecodingError = 'Invalid network discrimination on address. Expecting Testnet but got Mainnet.'}})")}),
        )?;
        self.report.record(
            "address-cross-network-api-rejected",
            &["address.network".into()],
            Ok(()),
        );

        let mnemonic = bip39::Mnemonic::generate(15)?
            .words()
            .map(str::to_owned)
            .collect();
        let id = self.create("conformance-precedence", mnemonic)?;
        self.family_ready_balance(SHELLEY, &id, 0)?;
        let path = format!("/wallets/{id}/transactions-construct");
        let history_path = format!("/wallets/{id}/transactions");
        let empty_history = self.call("listTransactions", "GET", &history_path, None, 200)?;
        ensure!(empty_history == json!([]), "new wallet already has history");
        for amount in [1, 2_000_000] {
            let response = self.call(
                "constructTransaction",
                "POST",
                &path,
                Some(payment(TEST, amount)),
                403,
            )?;
            equal(
                &response,
                json!({"code":"no_utxos_available","message":EMPTY}),
            )?;
            self.family_ready_balance(SHELLEY, &id, 0)?;
            equal(
                &self.call("listTransactions", "GET", &history_path, None, 200)?,
                empty_history.clone(),
            )?;
        }
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{id}/addresses"),
            None,
            200,
        )?;
        let address = text(&addresses, "/0/id")?;
        self.family_fund(SHELLEY, &id, &address, options)?;
        let utxos = options.node.utxos(&address, self.timeout)?;
        let history = self.precedence_history(&id, options)?;
        ensure!(
            history.0.as_array().is_some_and(|h| h.len() == 1),
            "unexpected funded history"
        );
        let parameters = options.node.protocol_parameters(self.timeout)?;
        let cost = number(&parameters, "/utxoCostPerByte")?;
        ensure!(cost > 0, "zero protocol minimum UTxO cost");
        let response = self.call(
            "constructTransaction",
            "POST",
            &path,
            Some(payment(TEST, 1)),
            403,
        )?;
        equal(&response, small(minimum(cost)?))?;
        self.family_ready_balance(SHELLEY, &id, FUNDING)?;
        ensure!(
            options.node.utxos(&address, self.timeout)? == utxos,
            "rejected construction changed node UTxOs"
        );
        let after_rejection = self.precedence_history(&id, options)?;
        unchanged_history(&history, &after_rejection)?;
        let valid = self.call(
            "constructTransaction",
            "POST",
            &path,
            Some(payment(TEST, 2_000_000)),
            202,
        )?;
        ensure!(
            valid.pointer("/coin_selection/outputs/0/address") == Some(&json!(TEST))
                && valid.pointer("/coin_selection/outputs/0/amount/quantity")
                    == Some(&json!(2_000_000)),
            "control construction changed output"
        );
        self.family_ready_balance(SHELLEY, &id, FUNDING)?;
        ensure!(
            options.node.utxos(&address, self.timeout)? == utxos,
            "unsigned construction changed node UTxOs"
        );
        unchanged_history(&after_rejection, &self.precedence_history(&id, options)?)?;
        self.report.record(
            "precedence:funds-output",
            &["api.error-precedence".into()],
            Ok(()),
        );
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_bracket_preserves_unit_and_every_stable_field() {
        let rows = json!([{"id":"fixed", "status":"in_ledger", "depth":{"quantity":4,"unit":"block"},"inserted_at":{"height":{"quantity":10,"unit":"block"}}}]);
        let a = checked_depth(&rows, 13, 14, 15).unwrap();
        let mut advanced = rows.clone();
        advanced[0]["depth"]["quantity"] = json!(6);
        let b = checked_depth(&advanced, 15, 16, 17).unwrap();
        unchanged_history(&a, &b).unwrap();
        assert!(unchanged_history(&b, &a).is_err());
        assert!(checked_depth(&rows, 15, 16, 17).is_err());
        assert!(checked_depth(&rows, 13, 14, 13).is_err());
        advanced[0]["depth"]["unit"] = json!("slot");
        assert!(checked_depth(&advanced, 15, 16, 17).is_err());
        advanced[0]["depth"]["unit"] = json!("block");
        advanced[0]["id"] = json!("changed");
        assert!(unchanged_history(&a, &checked_depth(&advanced, 15, 16, 17).unwrap()).is_err());
    }
    #[test]
    fn funded_output_envelope_rejects_wrong_priority_minimum_and_index() {
        assert_eq!(minimum(4310).unwrap(), 866310);
        assert!(equal(&small(866310), small(minimum(4310).unwrap())).is_ok());
        assert!(equal(
            &json!({"code":"no_utxos_available","message":EMPTY}),
            small(866310)
        )
        .is_err());
        let mut changed = small(866310);
        changed["info"]["tx_output_index"] = json!(1);
        assert!(equal(&changed, small(866310)).is_err());
        assert!(equal(&small(866309), small(866310)).is_err());
        assert!(minimum(u64::MAX).is_err());
    }
}
