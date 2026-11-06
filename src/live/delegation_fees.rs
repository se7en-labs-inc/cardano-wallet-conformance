//! Independent funded fee reads without executing the pending vote/delegation profile.
use super::{
    families::{FUNDING, SHELLEY},
    *,
};
use std::collections::BTreeSet;

fn empty() -> Result<Vec<u8>> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4)?
        .map(4)?
        .u8(0)?
        .tag(minicbor::data::Tag::new(258))?
        .array(0)?
        .u8(1)?
        .array(0)?
        .u8(2)?
        .u8(0)?
        .u8(3)?
        .u64(u64::MAX)?
        .map(0)?
        .bool(true)?
        .null()?;
    Ok(e.into_writer())
}
fn change() -> Result<Vec<u8>> {
    let mut bytes = vec![0];
    for id in [
        "haskell-Shelley-0-1-0-private",
        "haskell-Shelley-0-2-0-private",
    ] {
        bytes.extend_from_slice(&transaction::blake2b(&era_boundary::public_key(id)?, 28)?);
    }
    Ok(bytes)
}
fn shape(raw: &str, reference: &str, signed: bool) -> Result<transaction::Transaction> {
    let tx = transaction::inspect(raw, signed)?;
    ensure!(
        tx.inputs == [reference.to_owned()]
            && tx.outputs.len() == 1
            && tx.outputs[0].assets.is_empty()
            && tx.outputs[0].address_hex == hex::encode(change()?)
            && tx.outputs[0].coin.checked_add(tx.fee) == Some(FUNDING)
            && tx.fee > 0
            && tx.verification_keys.len() == usize::from(signed)
            && transaction::validity(raw)? == (None, Some(u64::MAX))
            && transaction::certificates(raw)?.is_empty(),
        "delegation fee prototype input/change/coin/fee/validity/witness differs"
    );
    let bytes = hex::decode(raw)?;
    let mut d = minicbor::Decoder::new(&bytes);
    ensure!(
        d.array()? == Some(4) && d.map()? == Some(4),
        "delegation fee prototype envelope/body differs"
    );
    let mut keys = BTreeSet::new();
    for _ in 0..4 {
        ensure!(keys.insert(d.u64()?), "duplicate fee prototype body key");
        d.skip()?;
    }
    ensure!(
        keys == BTreeSet::from([0, 1, 2, 3]),
        "extra fee prototype body field"
    );
    ensure!(
        d.map()? == Some(u64::from(signed)),
        "fee prototype witness fields differ"
    );
    if signed {
        ensure!(d.u64()? == 0, "fee prototype witness kind differs");
        d.skip()?;
    }
    ensure!(d.bool()?, "fee prototype script validity differs");
    d.null()?;
    ensure!(d.position() == bytes.len(), "fee prototype trailing data");
    Ok(tx)
}
fn estimate(value: &Value, fee: u64, deposit: u64) -> Result<()> {
    ensure!(
        value
            == &json!({"estimated_min":{"quantity":fee,"unit":"lovelace"},
        "estimated_max":{"quantity":fee,"unit":"lovelace"},"minimum_coins":[],
        "deposit":{"quantity":deposit,"unit":"lovelace"}}),
        "delegation fee percentiles/units/deposit differ from independent signed-size control"
    );
    Ok(())
}
impl Session<'_> {
    pub(super) fn delegation_snapshot(&mut self, id: &str) -> Result<Value> {
        let path = format!("/wallets/{id}");
        let wallet = self.call("getWallet", "GET", &path, None, 200)?;
        let utxo = self.call(
            "getWalletUtxoSnapshot",
            "GET",
            &format!("{path}/utxo"),
            None,
            200,
        )?;
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("{path}/addresses"),
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
        let history: Vec<_> = history
            .as_array()
            .context("delegation fee history missing")?
            .iter()
            .map(history::stable)
            .collect();
        Ok(
            json!({"id":id,"balance":wallet["balance"],"assets":wallet["assets"],"utxo":utxo,"addresses":addresses,"history":history}),
        )
    }
    pub(super) fn exercise_delegation_fees(&mut self, options: &LiveOptions) -> Result<()> {
        let existing = self.owned.len();
        let result = self.delegation_fees_inner(options);
        let mut cleanup = Ok(());
        for (operation, prefix, id) in self.owned.split_off(existing).into_iter().rev() {
            if let Err(error) =
                self.call(operation, "DELETE", &format!("/{prefix}/{id}"), None, 204)
            {
                cleanup = Err(error);
            }
        }
        result.and(cleanup)
    }
    fn delegation_fees_inner(&mut self, options: &LiveOptions) -> Result<()> {
        let vectors: Value =
            serde_json::from_str(include_str!("../../fixtures/vectors/haskell-keys.json"))?;
        let mnemonic = vectors[0]["input"]["mnemonic"]
            .as_str()
            .context("published mnemonic missing")?
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        let id = self.create("conformance-delegation-fees", mnemonic)?;
        self.family_ready_balance(SHELLEY, &id, 0)?;
        let path = format!("/wallets/{id}");
        let address = era_boundary::base_address()?;
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("{path}/addresses"),
            None,
            200,
        )?;
        ensure!(
            addresses[0]["id"] == address && addresses[0]["state"] == "unused",
            "fee wallet external0 does not match frozen Haskell public keys"
        );
        ensure!(
            options
                .node
                .utxos(&address, self.timeout)?
                .as_object()
                .is_some_and(|v| v.is_empty()),
            "fee control address is not independently fresh"
        );
        let mut reward = vec![0xe0];
        reward.extend_from_slice(&transaction::blake2b(
            &era_boundary::public_key("haskell-Shelley-0-2-0-private")?,
            28,
        )?);
        let reward = crate::encoding::bech32_encode("stake_test", &reward)?;
        ensure!(
            options.node.stake_address_info(&reward, self.timeout)? == json!([]),
            "fee control stake account is registered"
        );
        self.family_fund(SHELLEY, &id, &address, options)?;
        self.check_snapshot(&id, FUNDING)?;
        let before = options.node.utxos(&address, self.timeout)?;
        let map = before
            .as_object()
            .context("fee control node UTxOs missing")?;
        ensure!(
            map.len() == 1 && map.values().next().unwrap()["value"] == json!({"lovelace":FUNDING}),
            "fee control funding differs"
        );
        let reference = map.keys().next().unwrap().clone();
        let snapshot = self.delegation_snapshot(&id)?;
        let parameters_before = options.node.protocol_parameters(self.timeout)?;
        let deposit = number(&parameters_before, "/stakeAddressDeposit")?;
        let reported = self.call(
            "getDelegationFee",
            "GET",
            &format!("{path}/delegation-fees"),
            None,
            200,
        )?;
        let balanced = self.call(
            "balanceTransaction",
            "POST",
            &format!("{path}/transactions-balance"),
            Some(json!({"transaction":hex::encode(empty()?),"inputs":[],"redeemers":[]})),
            202,
        )?;
        let unsigned = hex::encode(assets::encoded_bytes(&text(&balanced, "/transaction")?)?);
        let original = shape(&unsigned, &reference, false)?;
        let signed=self.call("signTransaction","POST",&format!("{path}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":"conformance-test-passphrase","encoding":"base16"})),202)?;
        let encoded = hex::encode(assets::encoded_bytes(&text(&signed, "/transaction")?)?);
        let verified = shape(&encoded, &reference, true)?;
        ensure!(
            verified.id == original.id
                && verified.verification_keys
                    == [hex::encode(era_boundary::public_key(
                        "haskell-Shelley-0-0-0-private"
                    )?)],
            "fee control signing changed the body or funding witness"
        );
        let proof = parameters::fee_control(&encoded, &parameters_before, verified.fee)?;
        estimate(&reported, verified.fee, deposit)?;
        let repeated = self.call(
            "getDelegationFee",
            "GET",
            &format!("{path}/delegation-fees"),
            None,
            200,
        )?;
        estimate(&repeated, verified.fee, deposit)?;
        ensure!(
            options.node.protocol_parameters(self.timeout)? == parameters_before,
            "node parameters changed during independent fee read"
        );
        ensure!(
            options.node.utxos(&address, self.timeout)? == before
                && options.node.stake_address_info(&reward, self.timeout)? == json!([]),
            "fee reads/balancing/signing spent input or changed stake state"
        );
        self.family_ready_balance(SHELLEY, &id, FUNDING)?;
        self.check_snapshot(&id, FUNDING)?;
        ensure!(
            self.delegation_snapshot(&id)? == snapshot,
            "fee reads/balancing/signing changed wallet state"
        );
        self.report
            .record("delegation:fee-read-independent-size", &[], Ok(()));
        self.report.evidence.last_mut().unwrap().detail =
            json!({"estimate":reported,"signed_size":proof,"node_parameters":parameters_before,
            "funding":before,"signed_cbor_hex":encoded,"unchanged_snapshot":snapshot,
            "default_context_has_no_certificates":true,"submitted":false})
            .to_string();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn prototype(coin: u64, ttl: u64, extra: bool) -> String {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .map(if extra { 5 } else { 4 })
            .unwrap()
            .u8(0)
            .unwrap()
            .tag(minicbor::data::Tag::new(258))
            .unwrap()
            .array(1)
            .unwrap()
            .array(2)
            .unwrap()
            .bytes(&[0x22; 32])
            .unwrap()
            .u8(0)
            .unwrap()
            .u8(1)
            .unwrap()
            .array(1)
            .unwrap()
            .array(2)
            .unwrap()
            .bytes(&change().unwrap())
            .unwrap()
            .u64(coin)
            .unwrap()
            .u8(2)
            .unwrap()
            .u64(200_000)
            .unwrap()
            .u8(3)
            .unwrap()
            .u64(ttl)
            .unwrap();
        if extra {
            e.u8(5).unwrap().map(0).unwrap();
        }
        e.map(0).unwrap().bool(true).unwrap().null().unwrap();
        hex::encode(e.into_writer())
    }
    #[test]
    fn fee_prototype_rejects_wrong_input_coin_ttl_or_extra_body_fields() {
        let reference = format!("{}#0", "22".repeat(32));
        shape(
            &prototype(FUNDING - 200_000, u64::MAX, false),
            &reference,
            false,
        )
        .unwrap();
        assert!(shape(
            &prototype(FUNDING - 199_999, u64::MAX, false),
            &reference,
            false
        )
        .is_err());
        assert!(shape(
            &prototype(FUNDING - 200_000, u64::MAX - 1, false),
            &reference,
            false
        )
        .is_err());
        assert!(shape(
            &prototype(FUNDING - 200_000, u64::MAX, true),
            &reference,
            false
        )
        .is_err());
        assert!(shape(
            &prototype(FUNDING - 200_000, u64::MAX, false),
            "wrong#0",
            false
        )
        .is_err());
    }
    #[test]
    fn fee_read_preserves_exact_percentiles_units_deposit_and_empty_minimums() {
        let good = json!({"estimated_min":{"quantity":123000,"unit":"lovelace"},"estimated_max":{"quantity":123000,"unit":"lovelace"},
            "minimum_coins":[],"deposit":{"quantity":1_000_000,"unit":"lovelace"}});
        estimate(&good, 123000, 1_000_000).unwrap();
        for (pointer, value) in [
            ("/estimated_min/quantity", json!(123001)),
            ("/estimated_max/unit", json!("ada")),
            ("/deposit/quantity", json!(0)),
            ("/minimum_coins", json!([1])),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(estimate(&bad, 123000, 1_000_000).is_err());
        }
    }
}
