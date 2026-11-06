//! Funded history filters grounded in actual signatures, node tips and genesis time.
use super::{
    families::{FUNDING, SHELLEY},
    *,
};
use base64::Engine;
use std::collections::{BTreeMap, BTreeSet};

struct Clock {
    start: u128,
    slot: u128,
}
pub(super) fn already_in_ledger(response: &Value, id: &str) -> Result<()> {
    ensure!(
        response
            == &json!({
                "code":"transaction_already_in_ledger",
                "message":format!("The transaction with id: {id} cannot be forgotten as it is already in the ledger."),
                "info":{"transaction_id":id}
            }),
        "confirmed deletion rejection differs from pinned Haskell code/message/info"
    );
    Ok(())
}
fn missing_encryption_method(response: &Value) -> Result<()> {
    ensure!(
        response
            == &json!({"code":"invalid_metadata_decryption",
        "message":"It looks like the encrypted metadata has wrong structure. It is expected to have encryption method under 'enc' key - see CIP83."}),
        "plaintext metadata structure rejection differs from pinned Haskell"
    );
    Ok(())
}
pub(super) fn stable(value: &Value) -> Value {
    Value::Object(
        [
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
        ]
        .iter()
        .map(|field| ((*field).into(), value[*field].clone()))
        .collect(),
    )
}
pub(super) fn status_rows(
    actual: &Value,
    expected: &[Value],
    ascending: bool,
    limit: Option<usize>,
) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut expected = expected
        .iter()
        .map(|row| -> Result<_> {
            let id = text(row, "/id")?;
            ensure!(
                hex::decode(&id)?.len() == 32 && ids.insert(id.clone()),
                "invalid or duplicate expected history identity"
            );
            let slot = match text(row, "/status")?.as_str() {
                "in_ledger" => number(row, "/inserted_at/absolute_slot_number")?,
                "pending" | "expired" => number(row, "/pending_since/absolute_slot_number")?,
                _ => anyhow::bail!("unsupported history status"),
            };
            Ok((slot, id, stable(row)))
        })
        .collect::<Result<Vec<_>>>()?;
    expected.sort_by(|a, b| {
        if ascending {
            a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1))
        } else {
            b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1))
        }
    });
    if let Some(limit) = limit {
        expected.truncate(limit);
    }
    let actual = actual
        .as_array()
        .context("mixed-status history is not an array")?;
    ensure!(
        actual.len() == expected.len(),
        "mixed-status history count differs"
    );
    let mut seen = BTreeSet::new();
    for (row, (_, _, expected)) in actual.iter().zip(&expected) {
        ensure!(
            seen.insert(text(row, "/id")?) && stable(row) == *expected,
            "mixed-status history identity, status, order or stable fields differ"
        );
    }
    Ok(())
}
fn anchored(value: &Value, clock: &Clock) -> Result<u64> {
    let id = text(value, "/id")?;
    ensure!(
        hex::decode(id)?.len() == 32 && value["status"] == "in_ledger",
        "history identity/status differs"
    );
    let slot = number(value, "/inserted_at/absolute_slot_number")?;
    let time = validity::utc_ns(&text(value, "/inserted_at/time")?)?
        .checked_mul(1000)
        .context("history UTC overflow")?;
    let expected = clock
        .start
        .checked_add(
            u128::from(slot)
                .checked_mul(clock.slot)
                .context("history slot overflow")?,
        )
        .context("history time overflow")?;
    ensure!(
        time == expected,
        "history insertion time differs from trusted genesis/slot"
    );
    Ok(slot)
}
fn same_rows(actual: &Value, expected: &[Value], clock: &Clock) -> Result<()> {
    let actual = actual.as_array().context("history query is not an array")?;
    ensure!(
        actual.len() == expected.len(),
        "history filter count differs"
    );
    let mut seen = BTreeSet::new();
    for (actual, expected) in actual.iter().zip(expected) {
        anchored(actual, clock)?;
        ensure!(
            seen.insert(text(actual, "/id")?),
            "duplicate history result"
        );
        ensure!(
            stable(actual) == stable(expected),
            "history result identity/order/stable fields differ"
        );
    }
    Ok(())
}
fn selected(
    rows: &[Value],
    ascending: bool,
    start: Option<u64>,
    end: Option<u64>,
    limit: Option<usize>,
) -> Result<Vec<Value>> {
    let mut rows = rows
        .iter()
        .filter_map(|row| {
            let slot = row
                .pointer("/inserted_at/absolute_slot_number")
                .and_then(Value::as_u64)?;
            (start.is_none_or(|s| slot >= s) && end.is_none_or(|e| slot <= e))
                .then_some(row.clone())
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| row["inserted_at"]["absolute_slot_number"].as_u64().unwrap());
    if !ascending {
        rows.reverse();
    }
    if let Some(limit) = limit {
        rows.truncate(limit);
    }
    Ok(rows)
}
fn refers(row: &Value, address: &str) -> bool {
    ["inputs", "outputs"].iter().any(|field| {
        row[*field]
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value["address"] == address))
    })
}
impl Session<'_> {
    pub(super) fn history_status_queries(
        &mut self,
        id: &str,
        funding: &Value,
        submitted: &Value,
        status: &str,
    ) -> Result<Value> {
        ensure!(
            funding["status"] == "in_ledger"
                && submitted["status"] == status
                && matches!(status, "pending" | "expired"),
            "mixed history does not contain independently established statuses"
        );
        let expected = vec![funding.clone(), submitted.clone()];
        let mut queries = Vec::new();
        for (query, ascending, limit) in [
            ("", false, None),
            ("?order=ascending", true, None),
            ("?order=descending", false, None),
            ("?order=ascending&max_count=1", true, Some(1)),
            ("?order=descending&max_count=1", false, Some(1)),
            ("?max_count=0", false, Some(0)),
            ("?max_count=2", false, Some(2)),
        ] {
            let rows = self.call(
                "listTransactions",
                "GET",
                &format!("/wallets/{id}/transactions{query}"),
                None,
                200,
            )?;
            let validation = status_rows(&rows, &expected, ascending, limit);
            let proof = json!({"query":query,"status":status,"rows":rows,"expected_get_records":expected,"ascending":ascending,"limit":limit,"validation_error":validation.as_ref().err().map(|error|format!("{error:#}"))});
            self.report.record(
                "pending:history-status-query",
                &[],
                validation
                    .as_ref()
                    .map(|_| ())
                    .map_err(|error| anyhow!("{error:#}")),
            );
            self.report.evidence.last_mut().unwrap().detail = proof.to_string();
            validation?;
            queries.push(proof);
        }
        Ok(
            json!({"confirmed_get":stable(funding),"submitted_get":stable(submitted),"status":status,"queries":queries}),
        )
    }
    fn history_query(
        &mut self,
        id: &str,
        query: &str,
        expected: &[Value],
        clock: &Clock,
    ) -> Result<()> {
        let rows = self.call(
            "listTransactions",
            "GET",
            &format!("/wallets/{id}/transactions{query}"),
            None,
            200,
        )?;
        same_rows(&rows, expected, clock)
    }
    fn history_node(&mut self, id: &str, expected: u64, options: &LiveOptions) -> Result<Value> {
        self.family_ready_balance(SHELLEY, id, expected)?;
        self.check_snapshot(id, expected)?;
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{id}/addresses"),
            None,
            200,
        )?;
        let mut node = BTreeMap::new();
        let mut total = 0u64;
        for address in addresses.as_array().context("history addresses missing")? {
            let address = text(address, "/id")?;
            let outputs = options.node.utxos(&address, self.timeout)?;
            for (reference, output) in outputs.as_object().context("history node UTxOs invalid")? {
                let coin = number(output, "/value/lovelace")?;
                ensure!(
                    output["address"] == address && output["value"] == json!({"lovelace":coin}),
                    "history funding address/assets differ"
                );
                ensure!(
                    node.insert(reference.clone(), output.clone()).is_none(),
                    "duplicate history node reference"
                );
                total = total
                    .checked_add(coin)
                    .context("history node balance overflow")?;
            }
        }
        ensure!(
            total == expected,
            "history wallet balance differs from all owned node outputs"
        );
        Ok(json!(node))
    }
    fn history_payment(
        &mut self,
        id: &str,
        address: &str,
        metadata: &Value,
        before: u64,
        clock: &Clock,
        options: &LiveOptions,
    ) -> Result<(Value, Value, u64)> {
        let path = format!("/wallets/{id}");
        let construct = self.call("constructTransaction", "POST", &format!("{path}/transactions-construct"),
            Some(json!({"payments":[{"address":address,"amount":{"quantity":2_000_000,"unit":"lovelace"}}],"metadata":metadata})), 202)?;
        let unsigned = text(&construct, "/transaction")?;
        let tx = transaction::inspect(&unsigned, false)?;
        let (decoded, bytes) = metadata::extract(&unsigned)?;
        ensure!(
            decoded == *metadata
                && base64::engine::general_purpose::STANDARD
                    .decode(text(&construct, "/coin_selection/metadata")?)?
                    == bytes,
            "history metadata CBOR differs from exact public request/auxiliary hash"
        );
        ensure!(
            transaction::withdrawals(&unsigned)?.is_empty(),
            "history self-payment has withdrawals"
        );
        let utxos_before_decode = self.call(
            "getWalletUtxoSnapshot",
            "GET",
            &format!("{path}/utxo"),
            None,
            200,
        )?;
        ensure!(
            self.balance(id)? == before,
            "history construction changed wallet balance"
        );
        let mut node_before_decode = BTreeMap::new();
        for input in construct["coin_selection"]["inputs"]
            .as_array()
            .context("history selected inputs missing")?
        {
            let address = text(input, "/address")?;
            node_before_decode.insert(address.clone(), options.node.utxos(&address, self.timeout)?);
        }
        let metadata_rejection = self.call("decodeTransaction", "POST", &format!("{path}/transactions-decode"),
            Some(json!({"transaction":unsigned,"decrypt_metadata":{"passphrase":"conformance-structure-check","method":"basic"}})), 403)?;
        missing_encryption_method(&metadata_rejection)?;
        let decoded_control = self.call(
            "decodeTransaction",
            "POST",
            &format!("{path}/transactions-decode"),
            Some(json!({"transaction":unsigned})),
            202,
        )?;
        ensure!(
            decoded_control["id"] == tx.id && decoded_control["metadata"] == *metadata,
            "ordinary metadata decoding changed ID or metadata after structure rejection"
        );
        let utxos_after_decode = self.call(
            "getWalletUtxoSnapshot",
            "GET",
            &format!("{path}/utxo"),
            None,
            200,
        )?;
        ensure!(
            utxos_after_decode == utxos_before_decode && self.balance(id)? == before,
            "metadata structure rejection changed wallet funds"
        );
        for (address, snapshot) in &node_before_decode {
            ensure!(
                options.node.utxos(address, self.timeout)? == *snapshot,
                "metadata structure rejection changed independent funding UTxOs"
            );
        }
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("{path}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":"conformance-test-passphrase"})),
            202,
        )?;
        let encoded = text(&signed, "/transaction")?;
        let verified = transaction::inspect(&encoded, true)?;
        ensure!(
            verified.id == tx.id
                && verified.fee == number(&construct, "/fee/quantity")?
                && verified.fee > 0
                && metadata::extract(&encoded)? == (metadata.clone(), bytes.clone()),
            "history signing changed body/metadata/fee"
        );
        let keys = verified
            .verification_keys
            .iter()
            .map(|key| Ok(hex::encode(transaction::blake2b(&hex::decode(key)?, 28)?)))
            .collect::<Result<BTreeSet<_>>>()?;
        let mut required = BTreeSet::new();
        let mut inputs = BTreeMap::new();
        let mut input_total = 0u64;
        for input in construct["coin_selection"]["inputs"]
            .as_array()
            .context("history selected inputs missing")?
        {
            let address = text(input, "/address")?;
            let raw = crate::encoding::bech32(&address)?.1;
            ensure!(
                raw.len() == 57 && raw[0] == 0 && input["assets"] == json!([]),
                "history input type/assets differ"
            );
            required.insert(hex::encode(&raw[1..29]));
            let reference = format!("{}#{}", text(input, "/id")?, number(input, "/index")?);
            let node = options.node.utxos(&address, self.timeout)?;
            let coin = number(input, "/amount/quantity")?;
            ensure!(
                node[&reference]["address"] == address
                    && node[&reference]["value"] == json!({"lovelace":coin}),
                "history input differs from node"
            );
            ensure!(
                inputs.insert(reference, address).is_none(),
                "duplicate history selected input"
            );
            input_total = input_total
                .checked_add(coin)
                .context("history input overflow")?;
        }
        ensure!(
            keys == required
                && verified.inputs.iter().cloned().collect::<BTreeSet<_>>()
                    == inputs.keys().cloned().collect(),
            "history witnesses do not authorize exact node inputs"
        );
        let output_total = verified
            .outputs
            .iter()
            .try_fold(verified.fee, |total, output| {
                ensure!(output.assets.is_empty(), "history outputs have assets");
                total
                    .checked_add(output.coin)
                    .context("history output overflow")
            })?;
        ensure!(
            output_total == input_total,
            "history payment fails ADA conservation"
        );
        let node_before = options.node.tip(self.timeout)?;
        let accepted = self.call(
            "submitTransaction",
            "POST",
            &format!("{path}/transactions-submit"),
            Some(json!({"transaction":encoded})),
            202,
        )?;
        ensure!(
            accepted["id"] == verified.id,
            "history submission ID differs"
        );
        let confirmed = self.family_confirm(SHELLEY, id, &verified.id)?;
        let node_after = options.node.tip(self.timeout)?;
        let after = before
            .checked_sub(verified.fee)
            .context("history fee exceeds balance")?;
        self.family_ready_balance(SHELLEY, id, after)?;
        let utxos_before = self.call(
            "getWalletUtxoSnapshot",
            "GET",
            &format!("{path}/utxo"),
            None,
            200,
        )?;
        let mut node_delete_before = BTreeMap::new();
        for output in &verified.outputs {
            let destination =
                crate::encoding::bech32_encode("addr_test", &hex::decode(&output.address_hex)?)?;
            node_delete_before.insert(
                destination.clone(),
                options.node.utxos(&destination, self.timeout)?,
            );
        }
        let rejection = self.call(
            "deleteTransaction",
            "DELETE",
            &format!("{path}/transactions/{}", verified.id),
            None,
            403,
        )?;
        already_in_ledger(&rejection, &verified.id)?;
        let preserved = self.call(
            "getTransaction",
            "GET",
            &format!("{path}/transactions/{}", verified.id),
            None,
            200,
        )?;
        same_rows(&json!([preserved]), std::slice::from_ref(&confirmed), clock)?;
        ensure!(
            self.balance(id)? == after,
            "rejected confirmed deletion changed balance"
        );
        let utxos_after = self.call(
            "getWalletUtxoSnapshot",
            "GET",
            &format!("{path}/utxo"),
            None,
            200,
        )?;
        ensure!(
            utxos_after == utxos_before,
            "rejected confirmed deletion changed wallet UTxOs"
        );
        for (address, snapshot) in &node_delete_before {
            ensure!(
                options.node.utxos(address, self.timeout)? == *snapshot,
                "rejected confirmed deletion changed node UTxOs"
            );
        }
        let slot = anchored(&confirmed, clock)?;
        let height = number(&confirmed, "/inserted_at/height/quantity")?;
        ensure!(
            slot > node_before.slot
                && slot <= node_after.slot
                && height > node_before.height
                && height <= node_after.height,
            "history insertion is outside independent node submission/confirmation tips"
        );
        ensure!(
            confirmed["metadata"] == *metadata
                && confirmed["direction"] == "outgoing"
                && number(&confirmed, "/fee/quantity")? == verified.fee
                && number(&confirmed, "/amount/quantity")? == verified.fee,
            "confirmed history self-payment metadata/amount/fee differs"
        );
        let owned = self.call(
            "listAddresses",
            "GET",
            &format!("{path}/addresses"),
            None,
            200,
        )?;
        let owned = owned
            .as_array()
            .context("history ownership missing")?
            .iter()
            .map(|v| text(v, "/id"))
            .collect::<Result<BTreeSet<_>>>()?;
        let mut payment = 0u64;
        for output in &verified.outputs {
            let destination =
                crate::encoding::bech32_encode("addr_test", &hex::decode(&output.address_hex)?)?;
            ensure!(
                owned.contains(&destination),
                "history change/payment is not owned"
            );
            if destination == address {
                payment += output.coin;
            }
            options
                .node
                .payment(&verified.id, &destination, output.coin, self.timeout)?;
        }
        ensure!(payment == 2_000_000, "history self-payment amount differs");
        for (reference, address) in &inputs {
            ensure!(
                options
                    .node
                    .utxos(address, self.timeout)?
                    .get(reference)
                    .is_none(),
                "history input remains unspent"
            );
        }
        let node = self.history_node(id, after, options)?;
        Ok((
            confirmed,
            json!({"signed_transaction":signed,"metadata_cbor_hex":hex::encode(bytes),"node_outputs":node,
            "metadata_structure_rejection":metadata_rejection,"preserved_decode_utxos":utxos_after_decode,"preserved_decode_node_utxos":node_before_decode,
            "confirmed_delete_rejection":rejection,"preserved_wallet_utxos":utxos_after,"preserved_node_utxos":node_delete_before,
            "node_before":{"height":node_before.height,"slot":node_before.slot,"hash":node_before.hash},
            "node_after":{"height":node_after.height,"slot":node_after.slot,"hash":node_after.hash}}),
            after,
        ))
    }
    pub(super) fn exercise_history(&mut self, options: &LiveOptions) -> Result<()> {
        let byron: Value = serde_json::from_slice(&std::fs::read(
            options
                .byron_genesis
                .as_ref()
                .context("history requires Byron genesis")?,
        )?)?;
        let shelley: Value = serde_json::from_slice(&std::fs::read(
            options
                .shelley_genesis
                .as_ref()
                .context("history requires Shelley genesis")?,
        )?)?;
        let clock = Clock {
            start: u128::from(number(&byron, "/startTime")?) * 1_000_000_000_000,
            slot: validity::decimal_ps(&shelley["slotLength"])?,
        };
        let network = self.call(
            "getNetworkParameters",
            "GET",
            "/network/parameters",
            None,
            200,
        )?;
        ensure!(
            validity::utc_ns(&text(&network, "/blockchain_start_time")?)? * 1000 == clock.start
                && validity::decimal_ps(&network["slot_length"]["quantity"])? == clock.slot,
            "history wallet clock differs from trusted genesis"
        );
        ensure!(
            network["eras"]
                .as_object()
                .context("history eras missing")?
                .values()
                .all(|era| {
                    era["epoch_number"] == 0
                        && era["epoch_start_time"].as_str().is_some_and(|t| {
                            validity::utc_ns(t).is_ok_and(|t| t * 1000 == clock.start)
                        })
                }),
            "history requires controlled single-era slotting"
        );
        let mnemonic = bip39::Mnemonic::generate(15)?
            .words()
            .map(str::to_owned)
            .collect();
        let id = self.create("conformance-history", mnemonic)?;
        self.family_ready_balance(SHELLEY, &id, 0)?;
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{id}/addresses"),
            None,
            200,
        )?;
        let address = text(&addresses, "/0/id")?;
        let unused = text(&addresses, "/19/id")?;
        let before_fund = options.node.tip(self.timeout)?;
        self.family_fund(SHELLEY, &id, &address, options)?;
        let node = options.node.utxos(&address, self.timeout)?;
        let entries = node.as_object().context("history funding missing")?;
        ensure!(
            entries.len() == 1,
            "history requires one original funding output"
        );
        let (funding, index) = entries
            .keys()
            .next()
            .unwrap()
            .split_once('#')
            .context("invalid history funding reference")?;
        ensure!(
            index == "0"
                && entries.values().next().unwrap()["value"] == json!({"lovelace":FUNDING}),
            "history funding values differ"
        );
        let funding = self.family_confirm(SHELLEY, &id, funding)?;
        let after_fund = options.node.tip(self.timeout)?;
        let slot = anchored(&funding, &clock)?;
        ensure!(
            slot > before_fund.slot && slot <= after_fund.slot,
            "history funding insertion is outside node tip bracket"
        );
        let mut rows = vec![funding];
        let mut proofs = Vec::new();
        let mut balance = FUNDING;
        for index in 0..2 {
            let metadata = json!({"0":{"bytes":"00ff".repeat(32)},"1":{"int":-42},
                "674":{"list":[{"string":"é".repeat(32)},{"map":[{"k":{"bytes":"ff"},"v":{"int":u64::MAX}}]}]},
                "18446744073709551615":{"string":format!("history-{index}")}});
            let (confirmed, proof, after) =
                self.history_payment(&id, &address, &metadata, balance, &clock, options)?;
            rows.push(confirmed);
            proofs.push(proof);
            balance = after;
        }
        ensure!(
            rows.windows(2)
                .all(|r| r[0]["inserted_at"]["absolute_slot_number"].as_u64()
                    < r[1]["inserted_at"]["absolute_slot_number"].as_u64()),
            "history controls did not confirm in distinct increasing slots"
        );
        let descending = selected(&rows, false, None, None, None)?;
        self.history_query(&id, "", &descending, &clock)?;
        for ascending in [false, true] {
            let order = if ascending { "ascending" } else { "descending" };
            self.history_query(
                &id,
                &format!("?order={order}"),
                &selected(&rows, ascending, None, None, None)?,
                &clock,
            )?;
            for limit in 0..=4 {
                self.history_query(
                    &id,
                    &format!("?order={order}&max_count={limit}"),
                    &selected(&rows, ascending, None, None, Some(limit))?,
                    &clock,
                )?;
            }
        }
        for (start, end) in [
            (Some(0), Some(0)),
            (Some(1), Some(1)),
            (Some(2), Some(2)),
            (Some(0), Some(1)),
            (Some(1), Some(2)),
            (Some(1), None),
            (None, Some(1)),
        ] {
            let mut params = vec!["order=ascending".to_owned()];
            if let Some(i) = start {
                params.push(format!("start={}", text(&rows[i], "/inserted_at/time")?));
            }
            if let Some(i) = end {
                params.push(format!("end={}", text(&rows[i], "/inserted_at/time")?));
            }
            let low = start
                .map(|i| number(&rows[i], "/inserted_at/absolute_slot_number"))
                .transpose()?;
            let high = end
                .map(|i| number(&rows[i], "/inserted_at/absolute_slot_number"))
                .transpose()?;
            self.history_query(
                &id,
                &format!("?{}", params.join("&")),
                &selected(&rows, true, low, high, None)?,
                &clock,
            )?;
            params.push("max_count=1".into());
            self.history_query(
                &id,
                &format!("?{}", params.join("&")),
                &selected(&rows, true, low, high, Some(1))?,
                &clock,
            )?;
        }
        self.history_query(
            &id,
            "?start=1970-01-01T00:00:00Z&end=1970-01-01T00:00:01Z",
            &[],
            &clock,
        )?;
        self.history_query(&id, "?minWithdrawal=1", &[], &clock)?;
        self.history_query(&id, &format!("?address={unused}"), &[], &clock)?;
        let mut filter_addresses = BTreeSet::from([address.clone()]);
        for row in &rows {
            for output in row["outputs"]
                .as_array()
                .context("history outputs missing")?
            {
                filter_addresses.insert(text(output, "/address")?);
            }
        }
        for filter in filter_addresses {
            let expected = descending
                .iter()
                .filter(|row| refers(row, &filter))
                .cloned()
                .collect::<Vec<_>>();
            self.history_query(&id, &format!("?address={filter}"), &expected, &clock)?;
        }
        for row in &rows {
            let actual = self.call(
                "getTransaction",
                "GET",
                &format!("/wallets/{id}/transactions/{}", text(row, "/id")?),
                None,
                200,
            )?;
            same_rows(&json!([actual]), std::slice::from_ref(row), &clock)?;
        }
        self.history_node(&id, balance, options)?;
        for case in [
            "history:time-range",
            "history:order",
            "history:pagination",
            "history:binary-metadata",
        ] {
            self.report
                .record(case, &["wallet.transaction-filtering".into()], Ok(()));
            self.report.evidence.last_mut().unwrap().detail = json!({"assertion":"genesis/node-anchored history query laws and signed binary metadata",
                "wallet":id,"confirmed_rows":rows,"payment_proofs":proofs,"final_balance":balance}).to_string();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captured_mixed_status_rows_reject_missing_duplicate_wrong_status_and_changed_fields() {
        let control: Value =
            serde_json::from_str(include_str!("../../fixtures/history-status-control.json"))
                .unwrap();
        for field in ["pending_rows", "expired_rows"] {
            let rows = control[field].as_array().unwrap().clone();
            status_rows(&json!(rows), &rows, false, None).unwrap();
            let mut ascending = rows.clone();
            ascending.reverse();
            status_rows(&json!(ascending), &rows, true, None).unwrap();
            status_rows(&json!([rows[0]]), &rows, false, Some(1)).unwrap();
            status_rows(&json!([]), &rows, false, Some(0)).unwrap();
            assert!(status_rows(&json!([rows[0]]), &rows, false, None).is_err());
            assert!(status_rows(&json!([rows[0], rows[0]]), &rows, false, None).is_err());
            assert!(status_rows(&json!(ascending), &rows, false, None).is_err());
            for (pointer, value) in [
                ("/status", json!("in_ledger")),
                ("/id", json!("ff".repeat(32))),
                ("/fee/quantity", json!(0)),
                ("/metadata", json!({"unexpected":true})),
                ("/pending_since/absolute_slot_number", json!(0)),
            ] {
                let mut bad = rows.clone();
                *bad[0].pointer_mut(pointer).unwrap() = value;
                assert!(
                    status_rows(&json!(bad), &rows, false, None).is_err(),
                    "{field} {pointer}"
                );
            }
        }
    }
    #[test]
    fn equal_slot_history_uses_opposite_id_ties_and_global_limits() {
        let control: Value =
            serde_json::from_str(include_str!("../../fixtures/history-status-control.json"))
                .unwrap();
        let mut funding = control["pending_rows"][1].clone();
        let mut pending = control["pending_rows"][0].clone();
        funding["id"] = json!("22".repeat(32));
        pending["id"] = json!("11".repeat(32));
        pending["pending_since"] = funding["inserted_at"].clone();
        let expected = vec![funding.clone(), pending.clone()];
        status_rows(&json!([pending, funding]), &expected, false, None).unwrap();
        status_rows(&json!([funding, pending]), &expected, true, None).unwrap();
        status_rows(&json!([funding]), &expected, true, Some(1)).unwrap();
        assert!(status_rows(&json!([pending]), &expected, true, Some(1)).is_err());
        assert!(status_rows(&json!([pending, funding]), &expected, true, None).is_err());
    }
    #[test]
    fn plaintext_metadata_guard_requires_exact_error_fields() {
        let expected = json!({"code":"invalid_metadata_decryption",
            "message":"It looks like the encrypted metadata has wrong structure. It is expected to have encryption method under 'enc' key - see CIP83."});
        missing_encryption_method(&expected).unwrap();
        for field in ["code", "message"] {
            let mut changed = expected.clone();
            changed[field] = json!("wrong");
            assert!(missing_encryption_method(&changed).is_err());
        }
        let mut extra = expected;
        extra["extra"] = json!(true);
        assert!(missing_encryption_method(&extra).is_err());
    }
    #[test]
    fn confirmed_deletion_requires_exact_code_message_and_transaction_info() {
        let id = "11".repeat(32);
        let expected = json!({"code":"transaction_already_in_ledger",
            "message":format!("The transaction with id: {id} cannot be forgotten as it is already in the ledger."),
            "info":{"transaction_id":id}});
        already_in_ledger(&expected, &id).unwrap();
        for pointer in ["/code", "/message", "/info/transaction_id"] {
            let mut changed = expected.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("wrong");
            assert!(already_in_ledger(&changed, &id).is_err());
        }
        let mut extra = expected;
        extra["extra"] = json!(true);
        assert!(already_in_ledger(&extra, &id).is_err());
    }
    fn sample(slot: u64) -> Value {
        json!({"id":format!("{slot:064x}"),"status":"in_ledger","direction":"outgoing","amount":{"quantity":1,"unit":"lovelace"},
            "fee":{"quantity":1,"unit":"lovelace"},"metadata":{"0":{"bytes":"00ff"}},"inputs":[],"outputs":[],
            "inserted_at":{"absolute_slot_number":slot,"time":format!("2026-01-01T00:00:0{slot}Z")}})
    }
    #[test]
    fn history_oracle_rejects_wrong_order_truncation_identity_metadata_and_clock() {
        let clock = Clock {
            start: validity::utc_ns("2026-01-01T00:00:00Z").unwrap() * 1000,
            slot: 1_000_000_000_000,
        };
        let rows = vec![sample(1), sample(2), sample(3)];
        same_rows(&json!(rows), &rows, &clock).unwrap();
        let mut reversed = rows.clone();
        reversed.reverse();
        assert!(same_rows(&json!(reversed), &rows, &clock).is_err());
        assert!(same_rows(&json!(&rows[..2]), &rows, &clock).is_err());
        for pointer in ["/id", "/metadata/0/bytes", "/inserted_at/time"] {
            let mut changed = rows.clone();
            *changed[1].pointer_mut(pointer).unwrap() = json!("changed");
            assert!(same_rows(&json!(changed), &rows, &clock).is_err());
        }
        let mut forged = rows[0].clone();
        forged["inserted_at"]["time"] = rows[1]["inserted_at"]["time"].clone();
        assert!(same_rows(&json!([forged.clone()]), &[forged], &clock).is_err());
        let range = selected(&rows, true, Some(2), Some(3), Some(1)).unwrap();
        assert_eq!(range[0]["id"], rows[1]["id"]);
        assert!(selected(&rows, false, None, None, Some(0))
            .unwrap()
            .is_empty());
    }
}
