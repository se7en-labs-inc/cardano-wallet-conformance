//! Real scheduled retry after a transient, independently observed mempool conflict.
use super::{
    families::{Family, BYRON, SHELLEY},
    pending::{mempool, mempool_state, same_tip, ExpiryClock},
    *,
};
use crate::{cluster_control::Cluster, node::NodeOracle};
use std::collections::{BTreeMap, BTreeSet};
const PASSWORD: &str = "conformance-test-passphrase";
const FUNDING: u64 = 100_000_000;
const PAYMENT: u64 = 2_000_000;
const CONFLICT_PAYMENT: u64 = 3_000_000;

pub(super) fn payment(
    tx: &Value,
    funding: &Value,
    destination: &str,
    amount: u64,
    status: &str,
) -> Result<u64> {
    ensure!(
        tx["status"] == status && tx["direction"] == "outgoing",
        "retry transaction status/direction differs"
    );
    let id = text(tx, "/id")?;
    ensure!(
        hex::decode(&id)?.len() == 32,
        "retry transaction ID is not32bytes"
    );
    let native = funding
        .as_object()
        .context("retry native funding missing")?;
    ensure!(native.len() == 1, "retry needs one native funding input");
    let (reference, output) = native.iter().next().unwrap();
    ensure!(
        output["value"] == json!({"lovelace":FUNDING}),
        "retry native funding assets/value differ"
    );
    let inputs = tx["inputs"].as_array().context("retry inputs missing")?;
    ensure!(
        inputs.len() == 1
            && format!(
                "{}#{}",
                text(&inputs[0], "/id")?,
                number(&inputs[0], "/index")?
            ) == *reference
            && inputs[0]["address"] == output["address"]
            && inputs[0]["assets"] == json!([])
            && inputs[0]["amount"] == json!({"quantity":FUNDING,"unit":"lovelace"}),
        "retry input identity/quantity differs"
    );
    let fee = number(tx, "/fee/quantity")?;
    ensure!(
        fee > 0
            && tx["fee"]["unit"] == "lovelace"
            && tx["amount"]
                == json!({"quantity":amount.checked_add(fee).context("retry amount overflow")?,"unit":"lovelace"}),
        "retry fee/amount differs"
    );
    let outputs = tx["outputs"].as_array().context("retry outputs missing")?;
    ensure!(outputs.len() == 2, "retry output count differs");
    let mut total = 0u128;
    let mut payments = 0;
    for value in outputs {
        ensure!(
            value["assets"] == json!([]) && value["amount"]["unit"] == "lovelace",
            "retry output assets/unit differ"
        );
        let coin = number(value, "/amount/quantity")?;
        total += u128::from(coin);
        if value["address"] == destination {
            ensure!(coin == amount, "retry recipient amount differs");
            payments += 1;
        }
    }
    ensure!(
        payments == 1 && total + u128::from(fee) == u128::from(FUNDING),
        "retry payment/conservation differs"
    );
    ensure!(
        tx["withdrawals"] == json!([])
            && tx["certificates"] == json!([])
            && tx["deposit_taken"] == json!({"quantity":0,"unit":"lovelace"})
            && tx["deposit_returned"] == json!({"quantity":0,"unit":"lovelace"}),
        "unexpected retry withdrawal/certificate/deposit"
    );
    Ok(fee)
}
fn balance(value: &Value, available: u64, total: u64) -> Result<()> {
    ensure!(
        value["balance"]["available"] == json!({"quantity":available,"unit":"lovelace"})
            && value["balance"]["total"] == json!({"quantity":total,"unit":"lovelace"})
            && value["assets"] == json!({"available":[],"total":[]}),
        "retry reserved/available/projected balance differs"
    );
    Ok(())
}
fn addresses_operation(family: Family) -> &'static str {
    if family.prefix == SHELLEY.prefix {
        "listAddresses"
    } else {
        "listByronAddresses"
    }
}
fn wallet_at_tip(value: &Value, tip: &crate::node::Tip) -> bool {
    value["state"]["status"] == "ready"
        && value["tip"]["absolute_slot_number"].as_u64() == Some(tip.slot)
        && value["tip"]["height"]["quantity"].as_u64() == Some(tip.height)
        && value["tip"]["height"]["unit"] == "block"
}

impl Session<'_> {
    fn retry_proof(&mut self, name: &str, proof: Value) {
        self.report.record(name, &[], Ok(()));
        self.report.evidence.last_mut().unwrap().detail = proof.to_string();
    }
    fn retry_source(
        &mut self,
        fixture: &mut Session<'_>,
        style: &str,
        node: &NodeOracle,
        faucet: &str,
    ) -> Result<(Family, String, String)> {
        let family = if style == "shelley" { SHELLEY } else { BYRON };
        let mnemonic: Vec<_> = bip39::Mnemonic::generate(if style == "random" { 12 } else { 15 })?
            .words()
            .map(str::to_owned)
            .collect();
        let (id, other) = if style == "shelley" {
            (
                self.create("conformance-retry-shelley", mnemonic.clone())?,
                fixture.create("conformance-conflict-shelley", mnemonic)?,
            )
        } else {
            let created=self.call("postByronWallet","POST","/byron-wallets",Some(json!({"style":style,"name":format!("conformance-retry-{style}"),"mnemonic_sentence":mnemonic,"passphrase":PASSWORD})),201)?;
            let other=fixture.call("postByronWallet","POST","/byron-wallets",Some(json!({"style":style,"name":format!("conformance-conflict-{style}"),"mnemonic_sentence":mnemonic,"passphrase":PASSWORD})),201)?;
            (text(&created, "/id")?, text(&other, "/id")?)
        };
        ensure!(id == other, "retry clone wallet identity differs");
        self.family_ready_balance(family, &id, 0)?;
        fixture.family_ready_balance(family, &id, 0)?;
        let path = format!("/{}/{id}/addresses", family.prefix);
        let (address, other) = if style == "random" {
            let payload = json!({"passphrase":PASSWORD,"address_index":2147495993u64});
            (
                text(
                    &self.call("createAddress", "POST", &path, Some(payload.clone()), 201)?,
                    "/id",
                )?,
                text(
                    &fixture.call("createAddress", "POST", &path, Some(payload), 201)?,
                    "/id",
                )?,
            )
        } else {
            (
                text(
                    &self.call(addresses_operation(family), "GET", &path, None, 200)?,
                    "/0/id",
                )?,
                text(
                    &fixture.call(addresses_operation(family), "GET", &path, None, 200)?,
                    "/0/id",
                )?,
            )
        };
        ensure!(
            address == other && node.utxos(&address, self.timeout)? == json!({}),
            "retry clone address differs or is already funded"
        );
        if family.prefix == BYRON.prefix {
            self.byron_bridge(&id, &address, node, faucet)?;
        } else {
            let faucet = Api::new(faucet, self.timeout)?;
            let response=faucet.request(&request("POST","/send/faucet-assets",Some(json!({"batch-size":1,"assets":[{"address":address,"bundle":{"coin":FUNDING,"assets":[]},"metadata":[]}]}))))?;
            ensure!(
                response.status == 204,
                "retry Shelley faucet rejected funding"
            );
        }
        self.family_ready_balance(family, &id, FUNDING)?;
        fixture.family_ready_balance(family, &id, FUNDING)?;
        Ok((family, id, address))
    }
    fn retry_style(
        &mut self,
        node: &NodeOracle,
        cluster: &Cluster,
        faucet: &str,
        fixture: &mut Session<'_>,
        clock: &ExpiryClock,
        style: &str,
    ) -> Result<Value> {
        let (family, id, address) = self.retry_source(fixture, style, node, faucet)?;
        let funding = node.utxos(&address, self.timeout)?;
        let recipient = self.create(
            "conformance-retry-recipient",
            bip39::Mnemonic::generate(15)?
                .words()
                .map(str::to_owned)
                .collect(),
        )?;
        self.family_ready_balance(SHELLEY, &recipient, 0)?;
        let recipient_addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{recipient}/addresses"),
            None,
            200,
        )?;
        let first_destination = text(&recipient_addresses, "/0/id")?;
        let destination = text(&recipient_addresses, "/1/id")?;
        ensure!(
            destination != first_destination
                && node.utxos(&destination, self.timeout)? == json!({})
                && node.utxos(&first_destination, self.timeout)? == json!({}),
            "retry recipient addresses differ or are already funded"
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
                "retry paused relay did not stabilize"
            );
        }
        let wallet_path = format!("/{}/{id}", family.prefix);
        self.poll(family.wallet, &wallet_path, |v| wallet_at_tip(v, &stable))?;
        fixture.poll(family.wallet, &wallet_path, |v| wallet_at_tip(v, &stable))?;
        for header in [
            self.call(
                "getBlocksLatestHeader",
                "GET",
                "/blocks/latest/header",
                None,
                200,
            )?,
            fixture.call(
                "getBlocksLatestHeader",
                "GET",
                "/blocks/latest/header",
                None,
                200,
            )?,
        ] {
            ensure!(
                stable.matches_wallet_header(&header),
                "retry chain-source header differs from native node"
            );
        }
        let post_path = format!("{wallet_path}/transactions");
        let conflict=fixture.call(family.post,"POST",&post_path,Some(json!({"payments":[{"address":first_destination,"amount":{"quantity":CONFLICT_PAYMENT,"unit":"lovelace"}}],"passphrase":PASSWORD,"time_to_live":{"quantity":8,"unit":"second"}})),202)?;
        payment(
            &conflict,
            &funding,
            &first_destination,
            CONFLICT_PAYMENT,
            "pending",
        )?;
        let conflict_id = text(&conflict, "/id")?;
        let upper = number(&conflict, "/expires_at/absolute_slot_number")?;
        clock.expiry(&conflict, upper)?;
        let horizon = clock.horizon(upper, stable.slot, clock.now()?)?;
        let conflict_pool = mempool(node, &conflict_id, self.timeout)?;
        let rejected=self.call(family.post,"POST",&post_path,Some(json!({"payments":[{"address":destination,"amount":{"quantity":PAYMENT,"unit":"lovelace"}}],"passphrase":PASSWORD})),500)?;
        self.retry_proof(
            &format!("retry:{style}:node-rejection-response"),
            rejected.clone(),
        );
        let response = Response {
            status: 500,
            media_type: Some("application/json".into()),
            json: Some(rejected.clone()),
            raw: Vec::new(),
        };
        assets::node_failure(&response, "ConwayMempoolFailure")?;
        ensure!(
            text(&rejected, "/message")?
                .contains("All inputs are spent. Transaction has probably already been included"),
            "retry node rejection is not the observed all-inputs-spent conflict"
        );
        let rows = self.call(family.transactions, "GET", &post_path, None, 200)?;
        let rows: Vec<_> = rows
            .as_array()
            .context("retry history missing")?
            .iter()
            .filter(|v| v["status"] == "pending")
            .collect();
        ensure!(
            rows.len() == 1,
            "retry must retain exactly one target pending transaction"
        );
        let txid = text(rows[0], "/id")?;
        let pending = self.call(
            family.transaction,
            "GET",
            &format!("{post_path}/{txid}"),
            None,
            200,
        )?;
        let fee = payment(&pending, &funding, &destination, PAYMENT, "pending")?;
        ensure!(
            txid != conflict_id && number(&pending, "/expires_at/absolute_slot_number")? > upper,
            "retry target identity/long deadline differs"
        );
        let expected_balance = FUNDING
            .checked_sub(PAYMENT)
            .and_then(|v| v.checked_sub(fee))
            .context("retry projected balance underflow")?;
        let wallet = self.call(family.wallet, "GET", &wallet_path, None, 200)?;
        balance(&wallet, 0, expected_balance)?;
        let absent = mempool_state(node, &txid, self.timeout, false)?;
        ensure!(
            node.utxos(&address, self.timeout)? == funding,
            "rejected retry changed native funding"
        );
        same_tip(&stable, &node.tip(self.timeout)?)?;
        self.retry_proof(&format!("retry:{style}:admitted-conflict"),json!({"funding":funding,"adversary_transaction":conflict,"adversary_mempool":conflict_pool,"target_error":rejected,"target_pending":pending,"target_wallet":wallet,"target_mempool_absent":absent,"horizon":horizon,"stable_tip":{"height":stable.height,"slot":stable.slot,"hash":stable.hash}}));
        while clock.now()? <= upper {
            ensure!(
                Instant::now() < deadline,
                "retry conflict expiry deadline exceeded"
            );
            same_tip(&stable, &node.tip(self.timeout)?)?;
            sleep(Duration::from_millis(200));
        }
        paused.resume()?;
        let confirmed = self.family_confirm(family, &id, &txid)?;
        ensure!(
            payment(&confirmed, &funding, &destination, PAYMENT, "in_ledger")? == fee
                && number(&confirmed, "/expires_at/absolute_slot_number")?
                    == number(&pending, "/expires_at/absolute_slot_number")?,
            "retry changed target fee/expiry"
        );
        let tip = node.tip(self.timeout)?;
        ensure!(
            tip.slot > upper && tip.height > stable.height,
            "retry chain did not advance beyond conflict expiry"
        );
        let first_absent = mempool_state(node, &conflict_id, self.timeout, false)?;
        ensure!(
            node.utxos(&first_destination, self.timeout)? == json!({}),
            "expired adversary transaction created outputs"
        );
        let owned = self.call(
            addresses_operation(family),
            "GET",
            &format!("{wallet_path}/addresses"),
            None,
            200,
        )?;
        let owned: BTreeSet<_> = owned
            .as_array()
            .context("retry owned addresses missing")?
            .iter()
            .map(|v| text(v, "/id"))
            .collect::<Result<_>>()?;
        let mut outputs = BTreeMap::<String, u64>::new();
        for output in confirmed["outputs"].as_array().unwrap() {
            let output_address = text(output, "/address")?;
            ensure!(
                output_address == destination || owned.contains(&output_address),
                "retry change output is not owned"
            );
            let total = outputs.entry(output_address).or_default();
            *total = total
                .checked_add(number(output, "/amount/quantity")?)
                .context("retry output overflow")?;
        }
        let mut native_outputs = BTreeMap::new();
        for (output_address, amount) in &outputs {
            node.payment(&txid, output_address, *amount, self.timeout)?;
            native_outputs.insert(
                output_address.clone(),
                node.utxos(output_address, self.timeout)?,
            );
        }
        let spent = node.utxos(&address, self.timeout)?;
        ensure!(
            funding
                .as_object()
                .unwrap()
                .keys()
                .all(|reference| !spent.as_object().unwrap().contains_key(reference)),
            "retry funding remains unspent after confirmation"
        );
        self.family_ready_balance(family, &id, expected_balance)?;
        self.family_ready_balance(SHELLEY, &recipient, PAYMENT)?;
        let proof = json!({"style":style,"target_transaction_id":txid,"target_initial_error":rejected,"target_pending":pending,"target_confirmed":confirmed,"native_funding_before":funding,"native_funding_after":spent,"native_outputs":native_outputs,"adversary_transaction_id":conflict_id,"adversary_upper_slot":upper,"adversary_mempool_absent":first_absent,"advanced_tip":{"height":tip.height,"slot":tip.slot,"hash":tip.hash},"additional_target_submission_api_calls":0,"final_balance":expected_balance});
        self.retry_proof(
            &format!("retry:{style}:confirmed-automatically"),
            proof.clone(),
        );
        Ok(proof)
    }
    pub(super) fn retry_workflow(
        &mut self,
        node: &NodeOracle,
        cluster: &Cluster,
        faucet: &str,
        reference: &Api,
        clock: &ExpiryClock,
    ) -> Result<Value> {
        let mut fixture = Session {
            api: reference,
            contract: self.contract,
            report: Report::new(
                &reference.label,
                "adversary-fixture-only-no-candidate-credit",
            ),
            owned: Vec::new(),
            timeout: self.timeout,
        };
        let result = (|| -> Result<Vec<Value>> {
            let mut proofs = Vec::new();
            for style in ["shelley", "icarus", "random"] {
                proofs.push(self.retry_style(node, cluster, faucet, &mut fixture, clock, style)?);
            }
            Ok(proofs)
        })();
        let mut cleanup = Ok(());
        for (delete, prefix, id) in std::mem::take(&mut fixture.owned).into_iter().rev() {
            let removed = fixture
                .call(delete, "DELETE", &format!("/{prefix}/{id}"), None, 204)
                .map(|_| ());
            self.report.record(
                "retry:cleanup-adversary-wallet",
                &[],
                removed.as_ref().map(|_| ()).map_err(|e| anyhow!("{e:#}")),
            );
            if let Err(error) = removed {
                cleanup = Err(error);
            }
        }
        let proofs = result?;
        cleanup?;
        ensure!(
            fixture.report.passed(),
            "adversary fixture has a failed control"
        );
        let proof = json!({"styles":proofs,"adversary_fixture_only":true,"adversary_checks":fixture.report.evidence.len()});
        self.report.record(
            "live:pending-retry",
            &["wallet.resubmission".into()],
            Ok(()),
        );
        self.report.evidence.last_mut().unwrap().detail = proof.to_string();
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_wallet_slot_reference_requires_ready_exact_slot_height_and_unit() {
        let tip = crate::node::Tip {
            height: 130,
            slot: 311,
            hash: "64925d2ee49eb54a45c795166cb6e07f309a4fa0670aaa80233b4edca03d2e4b".into(),
        };
        let wallet = json!({"state":{"status":"ready"},"tip":{"absolute_slot_number":311,"height":{"quantity":130,"unit":"block"}}});
        assert!(wallet_at_tip(&wallet, &tip));
        for (pointer, value) in [
            ("/state/status", json!("syncing")),
            ("/tip/absolute_slot_number", json!(310)),
            ("/tip/height/quantity", json!(129)),
            ("/tip/height/unit", json!("slot")),
        ] {
            let mut bad = wallet.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(!wallet_at_tip(&bad, &tip));
        }
        assert!(!tip.matches_wallet_header(&wallet["tip"]));
        let header = json!({"header_hash":tip.hash,"slot_no":{"quantity":311,"unit":"slot"},"block_height":{"quantity":130,"unit":"block"}});
        assert!(tip.matches_wallet_header(&header));
    }
    #[test]
    fn actual_pending_and_confirmed_payment_controls_reject_input_output_fee_and_asset_mutations() {
        let controls: Value =
            serde_json::from_str(include_str!("../../fixtures/retry-payment-controls.json"))
                .unwrap();
        let destination = controls["destination"].as_str().unwrap();
        for (field, status) in [("pending", "pending"), ("confirmed", "in_ledger")] {
            payment(
                &controls[field],
                &controls["funding"],
                destination,
                PAYMENT,
                status,
            )
            .unwrap();
            for pointer in [
                "/inputs/0/amount/quantity",
                "/outputs/0/amount/quantity",
                "/fee/quantity",
                "/deposit_taken/quantity",
                "/inputs/0/id",
            ] {
                let mut bad = controls[field].clone();
                *bad.pointer_mut(pointer).unwrap() = json!(1);
                assert!(payment(&bad, &controls["funding"], destination, PAYMENT, status).is_err());
            }
            let mut bad = controls[field].clone();
            bad["outputs"][0]["assets"] = json!([{"quantity":1}]);
            assert!(payment(&bad, &controls["funding"], destination, PAYMENT, status).is_err());
            let mut bad = controls[field].clone();
            let input = bad["inputs"][0].clone();
            bad["inputs"].as_array_mut().unwrap().push(input);
            assert!(payment(&bad, &controls["funding"], destination, PAYMENT, status).is_err());
        }
    }
    #[test]
    fn retry_balance_requires_actual_reserved_funds_and_exact_units() {
        let wallet = json!({"balance":{"available":{"quantity":0,"unit":"lovelace"},"total":{"quantity":97870500,"unit":"lovelace"}},"assets":{"available":[],"total":[]}});
        balance(&wallet, 0, 97870500).unwrap();
        let mut bad = wallet.clone();
        bad["balance"]["available"]["quantity"] = json!(100000000);
        assert!(balance(&bad, 0, 97870500).is_err());
        let mut bad = wallet;
        bad["balance"]["total"]["unit"] = json!("ada");
        assert!(balance(&bad, 0, 97870500).is_err());
    }
}
