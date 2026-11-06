//! Actual committee enactment and pre/post wallet parameter, fee and min-ADA checks.
use super::{
    families::{FUNDING, SHELLEY},
    *,
};
use std::{fs, path::Path};
const DESTINATION: &str = "addr_test1vzz6hulv54gzf2suy2u5gkvmt6ysasfdlvvegy3fmf969yc2mg7gf";

fn mapping(wallet: &Value, node: &Value, shelley: &Value, byron: &Value, hash: &str) -> Result<()> {
    ensure!(
        wallet["genesis_block_hash"] == hash,
        "wallet genesis hash differs from trusted CLI"
    );
    let start = text(wallet, "/blockchain_start_time")?;
    ensure!(
        start.len() == 20
            && start.ends_with('Z')
            && validity::utc_ns(&start)?
                == u128::from(number(byron, "/startTime")?) * 1_000_000_000,
        "wallet start time differs from public Byron genesis"
    );
    ensure!(
        wallet["slot_length"]["unit"] == "second"
            && validity::decimal_ps(&wallet["slot_length"]["quantity"])?
                == validity::decimal_ps(&shelley["slotLength"])?
            && wallet["epoch_length"]
                == json!({"quantity":number(shelley,"/epochLength")?,"unit":"slot"})
            && wallet["security_parameter"]
                == json!({"quantity":number(shelley,"/securityParam")?,"unit":"block"}),
        "wallet slotting/security parameters differ from genesis"
    );
    ensure!(
        wallet["active_slot_coefficient"]["quantity"].as_f64()
            == shelley["activeSlotsCoeff"].as_f64().map(|v| v * 100.0)
            && wallet["active_slot_coefficient"]["unit"] == "percent"
            && wallet["decentralization_level"] == json!({"quantity":100,"unit":"percent"}),
        "wallet controlled-network coefficients differ"
    );
    ensure!(
        wallet["desired_pool_number"] == node["stakePoolTargetNum"]
            && wallet["maximum_collateral_input_count"] == node["maxCollateralInputs"]
            && wallet["minimum_collateral_percentage"] == node["collateralPercentage"]
            && wallet["maximum_token_bundle_size"]
                == json!({"quantity":number(node,"/maxValueSize")?,"unit":"byte"}),
        "wallet dynamic node parameters differ"
    );
    for (api, key) in [
        ("memory_unit_price", "priceMemory"),
        ("step_price", "priceSteps"),
    ] {
        ensure!(
            wallet["execution_unit_prices"][api]
                .as_f64()
                .map(f64::to_bits)
                == node["executionUnitPrices"][key].as_f64().map(f64::to_bits)
                && wallet["execution_unit_prices"][api].is_number(),
            "wallet execution price differs from node"
        );
    }
    let mut eras = serde_json::Map::new();
    for name in ["byron", "shelley", "allegra", "mary", "alonzo", "babbage"] {
        eras.insert(
            name.into(),
            json!({"epoch_number":0,"epoch_start_time":start}),
        );
    }
    ensure!(
        wallet["eras"] == Value::Object(eras),
        "wallet controlled epoch0 era boundaries differ"
    );
    Ok(())
}
pub(super) fn fee_control(encoded: &str, parameters: &Value, reported: u64) -> Result<Value> {
    let raw = assets::encoded_bytes(encoded)?;
    let tx = transaction::inspect(encoded, true)?;
    ensure!(
        tx.verification_keys.len() == 1,
        "pure payment witness count differs"
    );
    let size = crate::signed_size::estimate(
        &json!({"transaction_cbor_hex":hex::encode(&raw),"vkey_witnesses":1,"bootstrap_witnesses":0,"protocol_major":number(parameters,"/protocolVersion/major")?,"maximum_transaction_bytes":number(parameters,"/maxTxSize")?}),
    )?;
    let fee = number(parameters, "/txFeePerByte")?
        .checked_mul(number(&size, "/estimated_bytes")?)
        .and_then(|v| v.checked_add(parameters["txFeeFixed"].as_u64()?))
        .context("parameter fee overflow")?;
    ensure!(
        tx.fee == reported && tx.fee == fee && size["within_size_limit"] == true,
        "wallet fee differs from independently estimated signed size and node parameters"
    );
    Ok(json!({"size":size,"fee":fee,"signed_bytes":raw.len(),"transaction_id":tx.id}))
}
impl Session<'_> {
    fn parameter_snapshot(&mut self, options: &LiveOptions) -> Result<Value> {
        let byron_file = options
            .byron_genesis
            .as_ref()
            .context("public Byron genesis required")?;
        let shelley: Value = serde_json::from_slice(&fs::read(
            options
                .shelley_genesis
                .as_ref()
                .context("public Shelley genesis required")?,
        )?)?;
        let byron: Value = serde_json::from_slice(&fs::read(byron_file)?)?;
        let bytes = crate::pool_fixture::run(
            std::process::Command::new(&options.node.executable)
                .args(["byron", "genesis", "print-genesis-hash", "--genesis-json"])
                .arg(byron_file),
            self.timeout,
        )?;
        let hash = std::str::from_utf8(&bytes)?.trim();
        ensure!(
            hex::decode(hash)?.len() == 32,
            "trusted genesis hash encoding differs"
        );
        let deadline = Instant::now() + self.timeout;
        loop {
            let before = options.node.protocol_parameters(self.timeout)?;
            let wallet = self.call(
                "getNetworkParameters",
                "GET",
                "/network/parameters",
                None,
                200,
            )?;
            let after = options.node.protocol_parameters(self.timeout)?;
            ensure!(
                Instant::now() < deadline,
                "parameter snapshot never aligned"
            );
            if before != after {
                continue;
            }
            if wallet["desired_pool_number"] != after["stakePoolTargetNum"] {
                ensure!(
                    after["stakePoolTargetNum"] == 4 && wallet["desired_pool_number"] == 3,
                    "wallet pool target is neither prior nor enacted value"
                );
                sleep(Duration::from_millis(200));
                continue;
            }
            mapping(&wallet, &after, &shelley, &byron, hash)?;
            return Ok(
                json!({"wallet":wallet,"node":after,"genesis_hash":hash,"shelley_slotting":{"slotLength":shelley["slotLength"],"epochLength":shelley["epochLength"],"securityParam":shelley["securityParam"],"activeSlotsCoeff":shelley["activeSlotsCoeff"]},"byron_start":byron["startTime"]}),
            );
        }
    }
    fn parameter_payment(
        &mut self,
        options: &LiveOptions,
        parameters: &Value,
        label: &str,
    ) -> Result<Value> {
        let mnemonic = bip39::Mnemonic::generate(15)?
            .words()
            .map(str::to_owned)
            .collect();
        let id = self.create(&format!("conformance-parameters-{label}"), mnemonic)?;
        self.family_ready_balance(SHELLEY, &id, 0)?;
        let path = format!("/wallets/{id}");
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("{path}/addresses"),
            None,
            200,
        )?;
        let address = text(&addresses, "/0/id")?;
        self.family_fund(SHELLEY, &id, &address, options)?;
        let before = options.node.utxos(&address, self.timeout)?;
        let funding = before
            .as_object()
            .context("parameter wallet node funding missing")?;
        ensure!(
            funding.len() == 1,
            "parameter payment needs one funding input"
        );
        let reference = funding.keys().next().unwrap().clone();
        let minimum = precedence::minimum(number(parameters, "/utxoCostPerByte")?)?;
        let rejected=self.call("constructTransaction","POST",&format!("{path}/transactions-construct"),Some(json!({"payments":[{"address":DESTINATION,"amount":{"quantity":1,"unit":"lovelace"}}]})),403)?;
        ensure!(
            rejected == precedence::small(minimum),
            "minimum ADA error differs from actual node output-byte price"
        );
        ensure!(
            options.node.utxos(&address, self.timeout)? == before,
            "minimum ADA rejection spent funding"
        );
        self.family_ready_balance(SHELLEY, &id, FUNDING)?;
        self.check_snapshot(&id, FUNDING)?;
        ensure!(
            self.call(
                "listTransactions",
                "GET",
                &format!("{path}/transactions"),
                None,
                200
            )?
            .as_array()
            .is_some_and(|h| h.len() == 1),
            "minimum ADA rejection inserted history"
        );
        let construct=self.call("constructTransaction","POST",&format!("{path}/transactions-construct"),Some(json!({"payments":[{"address":DESTINATION,"amount":{"quantity":2_000_000,"unit":"lovelace"}}]})),202)?;
        let unsigned = text(&construct, "/transaction")?;
        let tx = transaction::inspect(&unsigned, false)?;
        let destination = hex::encode(crate::encoding::bech32(DESTINATION)?.1);
        ensure!(
            tx.inputs == [reference.clone()]
                && tx.verification_keys.is_empty()
                && tx.outputs.len() == 2
                && tx.outputs.iter().all(|o| o.assets.is_empty())
                && tx
                    .outputs
                    .iter()
                    .filter(|o| o.address_hex == destination && o.coin == 2_000_000)
                    .count()
                    == 1
                && tx
                    .outputs
                    .iter()
                    .try_fold(tx.fee, |sum, o| sum.checked_add(o.coin))
                    == Some(FUNDING),
            "parameter transaction input/output/conservation differs"
        );
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
                && verified.inputs == [reference]
                && verified.verification_keys.len() == 1,
            "parameter signing changed transaction/witness count"
        );
        let key = hex::decode(&verified.verification_keys[0])?;
        let (_, funding_bytes) = crate::encoding::bech32(&address)?;
        ensure!(
            funding_bytes.len() == 57 && funding_bytes[1..29] == transaction::blake2b(&key, 28)?,
            "parameter payment witness does not own funded address"
        );
        let fee_proof = fee_control(&encoded, parameters, number(&construct, "/fee/quantity")?)?;
        let submission = self.call(
            "submitTransaction",
            "POST",
            &format!("{path}/transactions-submit"),
            Some(json!({"transaction":encoded})),
            202,
        )?;
        ensure!(
            submission["id"] == verified.id,
            "parameter submitted hash differs"
        );
        let confirmed = self.family_confirm(SHELLEY, &id, &verified.id)?;
        options
            .node
            .payment(&verified.id, DESTINATION, 2_000_000, self.timeout)?;
        ensure!(
            options
                .node
                .utxos(&address, self.timeout)?
                .as_object()
                .is_some_and(|m| m.is_empty()),
            "parameter payment input remains unspent"
        );
        let remaining = FUNDING
            .checked_sub(2_000_000)
            .and_then(|v| v.checked_sub(verified.fee))
            .context("parameter payment exceeds funding")?;
        self.family_ready_balance(SHELLEY, &id, remaining)?;
        self.check_snapshot(&id, remaining)?;
        Ok(
            json!({"label":label,"node_parameters":parameters,"minimum_ada":minimum,"rejection":rejected,"funding":before,"constructed":construct,"signed":signed,"confirmed":history::stable(&confirmed),"fee_proof":fee_proof,"remaining":remaining}),
        )
    }
    pub(super) fn exercise_parameters(&mut self, options: &LiveOptions) -> Result<()> {
        let fixture = options
            .parameter_fixture
            .as_ref()
            .context("parameter fixture missing")?;
        let output = options
            .parameter_workspace
            .as_ref()
            .context("fresh parameter workspace missing")?;
        ensure!(
            !Path::new(output).exists(),
            "parameter workspace already exists"
        );
        let before = self.parameter_snapshot(options)?;
        ensure!(
            before["node"]["txFeePerByte"] == 100
                && before["node"]["utxoCostPerByte"] == 4310
                && before["node"]["stakePoolTargetNum"] == 3,
            "parameter fixture is not at initial state"
        );
        let old_payment = self.parameter_payment(options, &before["node"], "before")?;
        let receipt = crate::protocol_update::enact(
            &options.node,
            fixture,
            options
                .faucet
                .as_ref()
                .context("parameter fixture requires faucet")?,
            output,
            self.timeout,
        )?;
        let enactment: Value = serde_json::from_slice(&fs::read(receipt)?)?;
        let after = self.parameter_snapshot(options)?;
        ensure!(
            before["node"] == enactment["before_parameters"]
                && after["node"] == enactment["after_parameters"],
            "wallet/node snapshots differ from enacted parameter proof"
        );
        let new_payment = self.parameter_payment(options, &after["node"], "after")?;
        let old_min = number(&old_payment, "/minimum_ada")?;
        let new_min = number(&new_payment, "/minimum_ada")?;
        ensure!(
            old_min == 866_310 && new_min == 868_320,
            "pre/post minimum ADA boundary differs"
        );
        let old_fee = number(&old_payment, "/fee_proof/fee")?;
        let new_fee = number(&new_payment, "/fee_proof/fee")?;
        ensure!(
            new_fee > old_fee,
            "wallet fee failed to reflect higher per-byte cost"
        );
        self.report.record(
            "chain:node-wallet-protocol-parameters",
            &["chain.protocol-parameters".into()],
            Ok(()),
        );
        self.report.evidence.last_mut().unwrap().detail =
            json!({"before":before,"after":after}).to_string();
        self.report.record(
            "chain:protocol-parameter-update",
            &["chain.protocol-parameters".into()],
            Ok(()),
        );
        self.report.evidence.last_mut().unwrap().detail =
            json!({"enactment":enactment,"before_payment":old_payment,"after_payment":new_payment})
                .to_string();
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parameter_mapping_rejects_wrong_dynamic_parameters_prices_and_slotting() {
        let control: Value = serde_json::from_str(include_str!(
            "../../fixtures/parameter-network-control.json"
        ))
        .unwrap();
        let node = &control["node"];
        let wallet = &control["wallet"];
        let shelley = &control["shelley"];
        let byron = &control["byron"];
        let hash = wallet["genesis_block_hash"].as_str().unwrap();
        mapping(wallet, node, shelley, byron, hash).unwrap();
        for pointer in [
            "/desired_pool_number",
            "/maximum_collateral_input_count",
            "/minimum_collateral_percentage",
            "/slot_length/quantity",
            "/maximum_token_bundle_size/quantity",
            "/execution_unit_prices/memory_unit_price",
        ] {
            let mut wrong = wallet.clone();
            *wrong.pointer_mut(pointer).unwrap() = json!(999);
            assert!(mapping(&wrong, node, shelley, byron, hash).is_err());
        }
        let mut wrong = wallet.clone();
        wrong["eras"]["conway"] = json!({"epoch_number":0});
        assert!(mapping(&wrong, node, shelley, byron, hash).is_err());
    }
}
