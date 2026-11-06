//! Conway voting, stake registration and refund through real wallet/node APIs.
use super::{
    families::{FUNDING, SHELLEY},
    *,
};
use std::collections::{BTreeMap, BTreeSet};
const PASSWORD: &str = "conformance-test-passphrase";

fn certificates_api(vote: Option<&str>, registering: bool) -> Value {
    let path = json!(["1852H", "1815H", "0H", "2", "0"]);
    let mut certs = Vec::new();
    if registering {
        certs
            .push(json!({"certificate_type":"register_reward_account","reward_account_path":path}));
    }
    certs.push(match vote {
        Some(vote) => {
            json!({"certificate_type":"cast_vote","reward_account_path":path,"vote":vote})
        }
        None => json!({"certificate_type":"quit_pool","reward_account_path":path}),
    });
    json!(certs)
}

fn accounting(value: &Value, deposit: u64, refund: u64, certs: &Value) -> Result<u64> {
    ensure!(
        value["status"] == "in_ledger",
        "vote transaction is not confirmed"
    );
    ensure!(
        value["certificates"] == *certs,
        "vote API certificates differ"
    );
    ensure!(
        number(value, "/deposit_taken/quantity")? == deposit
            && number(value, "/deposit_returned/quantity")? == refund,
        "stake deposit/refund differs"
    );
    let sum = |field: &str| -> Result<u128> {
        value[field]
            .as_array()
            .context("missing vote accounting field")?
            .iter()
            .try_fold(0u128, |sum, entry| {
                ensure!(
                    entry["amount"]["unit"] == "lovelace",
                    "vote quantity unit differs"
                );
                Ok(sum + u128::from(number(entry, "/amount/quantity")?))
            })
    };
    let fee = number(value, "/fee/quantity")?;
    ensure!(
        fee > 0 && value["fee"]["unit"] == "lovelace",
        "vote fee invalid"
    );
    ensure!(
        sum("inputs")? + sum("withdrawals")? + u128::from(refund)
            == sum("outputs")? + u128::from(fee) + u128::from(deposit),
        "vote ADA is not conserved"
    );
    ensure!(
        sum("withdrawals")? == 0,
        "unexpected rewards in no-pool voting control"
    );
    let inputs = value["inputs"].as_array().context("missing vote inputs")?;
    let mut unique = BTreeSet::new();
    ensure!(!inputs.is_empty(), "vote has no inputs");
    for input in inputs {
        ensure!(
            unique.insert((text(input, "/id")?, number(input, "/index")?)),
            "duplicate vote input"
        );
    }
    for field in ["inputs", "outputs"] {
        for item in value[field].as_array().unwrap() {
            ensure!(item["assets"] == json!([]), "unexpected vote native assets");
        }
    }
    Ok(fee)
}

fn stake_state(value: &Value, stake: &str, vote: Option<&str>, deposit: u64) -> Result<()> {
    let entries = value.as_array().context("invalid node stake response")?;
    if let Some(vote) = vote {
        ensure!(
            entries.len() == 1
                && entries[0]["address"] == stake
                && entries[0]["voteDelegation"] == vote
                && entries[0]["stakeDelegation"].is_null()
                && entries[0]["stakeRegistrationDeposit"] == deposit
                && entries[0]["rewardAccountBalance"] == 0,
            "node voting/deposit/reward state differs"
        );
    } else {
        ensure!(
            entries.is_empty(),
            "deregistered stake account still exists on node"
        );
    }
    Ok(())
}

impl Session<'_> {
    fn voting_utxos(
        &self,
        addresses: &[String],
        options: &LiveOptions,
    ) -> Result<BTreeMap<String, Value>> {
        let mut result = BTreeMap::new();
        for address in addresses {
            let utxos = options.node.utxos(address, self.timeout)?;
            for (id, value) in utxos.as_object().context("invalid vote node UTxO map")? {
                ensure!(
                    result.insert(id.clone(), value.clone()).is_none(),
                    "duplicate queried vote UTxO"
                );
            }
        }
        Ok(result)
    }

    fn voting_snapshot(
        &mut self,
        id: &str,
        addresses: &[String],
        options: &LiveOptions,
    ) -> Result<Value> {
        let wallet = self.call("getWallet", "GET", &format!("/wallets/{id}"), None, 200)?;
        let history = self.call(
            "listTransactions",
            "GET",
            &format!("/wallets/{id}/transactions"),
            None,
            200,
        )?;
        let history: BTreeSet<_> = history
            .as_array()
            .context("invalid voting history")?
            .iter()
            .map(|tx| Ok((text(tx, "/id")?, text(tx, "/status")?)))
            .collect::<Result<_>>()?;
        Ok(json!({"balance":wallet["balance"],"history":history,
            "utxos":self.voting_utxos(addresses,options)?}))
    }

    fn voting_settle(
        &mut self,
        id: &str,
        txid: &str,
        expected: (u64, u64, &Value),
        addresses: &mut Vec<String>,
        before: &BTreeMap<String, Value>,
        options: &LiveOptions,
    ) -> Result<Value> {
        let tx = self.family_confirm(SHELLEY, id, txid)?;
        accounting(&tx, expected.0, expected.1, expected.2)?;
        let owned = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{id}/addresses"),
            None,
            200,
        )?;
        let owned: BTreeSet<_> = owned
            .as_array()
            .context("invalid owned vote addresses")?
            .iter()
            .map(|v| text(v, "/id"))
            .collect::<Result<_>>()?;
        let mut totals = BTreeMap::<String, u64>::new();
        for output in tx["outputs"].as_array().unwrap() {
            let address = text(output, "/address")?;
            ensure!(owned.contains(&address), "vote change is not owned");
            let total = totals.entry(address).or_default();
            *total = total
                .checked_add(number(output, "/amount/quantity")?)
                .context("vote output overflow")?;
        }
        for (address, coin) in totals {
            options.node.payment(txid, &address, coin, self.timeout)?;
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        let after = self.voting_utxos(addresses, options)?;
        for input in tx["inputs"].as_array().unwrap() {
            let reference = format!("{}#{}", text(input, "/id")?, number(input, "/index")?);
            let observed = before
                .get(&reference)
                .context("vote spends independently unknown input")?;
            ensure!(
                observed["address"] == input["address"]
                    && number(observed, "/value/lovelace")? == number(input, "/amount/quantity")?
                    && !after.contains_key(&reference),
                "vote input identity/value/spending differs from node"
            );
        }
        Ok(tx)
    }

    pub(super) fn exercise_voting(&mut self, options: &LiveOptions) -> Result<()> {
        let controls: Value =
            serde_json::from_str(include_str!("../../fixtures/voting-controls.json"))?;
        let mnemonic = bip39::Mnemonic::generate(15)?
            .words()
            .map(str::to_owned)
            .collect();
        let id = self.create("conformance-voting", mnemonic)?;
        self.family_ready_balance(SHELLEY, &id, 0)?;
        let password = json!({"passphrase":PASSWORD});
        let vote_path = |vote: &str| format!("/dreps/{vote}/wallets/{id}");
        let quit_path = format!("/stake-pools/*/wallets/{id}");
        let empty = self.call(
            "joinDRep",
            "PUT",
            &vote_path("abstain"),
            Some(password.clone()),
            403,
        )?;
        ensure!(empty == controls["empty"], "empty vote error differs");
        let empty = self.call(
            "quitStakePool",
            "DELETE",
            &quit_path,
            Some(password.clone()),
            403,
        )?;
        ensure!(
            empty == controls["not_delegating"],
            "empty quit error differs"
        );
        self.family_ready_balance(SHELLEY, &id, 0)?;
        ensure!(
            self.call(
                "listTransactions",
                "GET",
                &format!("/wallets/{id}/transactions"),
                None,
                200
            )? == json!([]),
            "empty voting rejection inserted history"
        );
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{id}/addresses"),
            None,
            200,
        )?;
        let address = text(&addresses, "/0/id")?;
        self.family_fund(SHELLEY, &id, &address, options)?;
        let mut addresses = vec![address.clone()];
        let before = self.voting_utxos(&addresses, options)?;
        ensure!(
            before.len() == 1,
            "voting fixture is not independently isolated"
        );
        let deposit = number(
            &options.node.protocol_parameters(self.timeout)?,
            "/stakeAddressDeposit",
        )?;
        ensure!(
            deposit > 0 && deposit < FUNDING,
            "invalid voting stake deposit"
        );
        let estimate = self.call(
            "getDelegationFee",
            "GET",
            &format!("/wallets/{id}/delegation-fees"),
            None,
            200,
        )?;
        ensure!(
            number(&estimate, "/deposit/quantity")? == deposit
                && number(&estimate, "/estimated_min/quantity")? > 0
                && number(&estimate, "/estimated_min/quantity")?
                    <= number(&estimate, "/estimated_max/quantity")?,
            "delegation fee/deposit estimate differs from node parameters"
        );
        let keys = self.call(
            "listStakeKeys",
            "GET",
            &format!("/wallets/{id}/stake-keys"),
            None,
            200,
        )?;
        let stake = text(&keys, "/ours/0/key")?;
        let public = self.call(
            "getWalletKey",
            "GET",
            &format!("/wallets/{id}/keys/mutable_account/0?hash=false"),
            None,
            200,
        )?;
        let public =
            crate::encoding::bech32(public.as_str().context("invalid stake public key")?)?.1;
        ensure!(public.len() == 32, "invalid stake public key length");
        let hash = transaction::blake2b(&public, 28)?;
        let stake_bytes = crate::encoding::bech32(&stake)?.1;
        ensure!(
            stake_bytes.len() == 29 && stake_bytes[0] == 0xe0 && stake_bytes[1..] == hash,
            "stake address does not match independently hashed key"
        );
        let payment_bytes = crate::encoding::bech32(&address)?.1;
        ensure!(
            payment_bytes.len() == 57 && payment_bytes[29..] == hash,
            "funding delegation credential differs"
        );
        let unsigned = self.call(
            "constructTransaction",
            "POST",
            &format!("/wallets/{id}/transactions-construct"),
            Some(json!({"vote":"abstain"})),
            202,
        )?;
        let encoded = text(&unsigned, "/transaction")?;
        let tx = transaction::inspect(&encoded, false)?;
        let mut xpub = public.clone();
        xpub.extend([0u8; 32]); // Certificate writer consumes only the verification-key bytes.
        let certs = crate::writer::certificates(&json!({"action":"vote-registering",
            "stake_xpub_hex":hex::encode(xpub),"deposit":deposit,"drep":{"type":"abstain"}}))?;
        ensure!(
            transaction::certificates(&encoded)? == certs
                && tx.verification_keys.is_empty()
                && tx.inputs == before.keys().cloned().collect::<Vec<_>>()
                && tx.outputs.iter().map(|o| u128::from(o.coin)).sum::<u128>()
                    + u128::from(tx.fee)
                    + u128::from(deposit)
                    == u128::from(FUNDING),
            "constructed voting body/certificates/accounting differ"
        );
        self.family_ready_balance(SHELLEY, &id, FUNDING)?;
        ensure!(
            self.voting_utxos(&addresses, options)? == before,
            "unsigned vote spent node funds"
        );
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("/wallets/{id}/transactions-sign"),
            Some(json!({"transaction":encoded,"passphrase":PASSWORD})),
            202,
        )?;
        let encoded = text(&signed, "/transaction")?;
        let verified = transaction::inspect(&encoded, true)?;
        let hashes: BTreeSet<_> = verified
            .verification_keys
            .iter()
            .map(|key| transaction::blake2b(&hex::decode(key)?, 28))
            .collect::<Result<_>>()?;
        ensure!(
            verified.id == tx.id
                && transaction::certificates(&encoded)? == certs
                && hashes == BTreeSet::from([payment_bytes[1..29].to_vec(), hash])
                && verified.verification_keys.len() == 2,
            "voting signatures/body/stake witnesses differ"
        );
        let submitted = self.call(
            "submitTransaction",
            "POST",
            &format!("/wallets/{id}/transactions-submit"),
            Some(json!({"transaction":encoded})),
            202,
        )?;
        ensure!(submitted["id"] == tx.id, "vote submission hash differs");
        let confirmed = self.voting_settle(
            &id,
            &tx.id,
            (deposit, 0, &certificates_api(Some("abstain"), true)),
            &mut addresses,
            &before,
            options,
        )?;
        ensure!(
            number(&confirmed, "/fee/quantity")? == tx.fee
                && confirmed["outputs"].as_array().unwrap().len() == tx.outputs.len(),
            "confirmed voting body differs"
        );
        for (output, actual) in confirmed["outputs"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&tx.outputs)
        {
            ensure!(
                hex::encode(crate::encoding::bech32(&text(output, "/address")?)?.1)
                    == actual.address_hex
                    && number(output, "/amount/quantity")? == actual.coin
                    && actual.assets.is_empty(),
                "confirmed binary vote outputs differ"
            );
        }
        let mut remaining = FUNDING
            .checked_sub(deposit)
            .and_then(|n| n.checked_sub(tx.fee))
            .context("vote balance underflow")?;
        self.family_ready_balance(SHELLEY, &id, remaining)?;
        stake_state(
            &options.node.stake_address_info(&stake, self.timeout)?,
            &stake,
            Some("alwaysAbstain"),
            deposit,
        )?;
        self.poll("getWallet", &format!("/wallets/{id}"), |v| {
            v["delegation"]["active"]["status"] == "voting"
                && v["delegation"]["active"]["voting"] == "abstain"
        })?;
        let snapshot = self.voting_snapshot(&id, &addresses, options)?;
        let rejected = self.call(
            "joinDRep",
            "PUT",
            &vote_path("abstain"),
            Some(password.clone()),
            403,
        )?;
        ensure!(
            rejected == controls["duplicate"]
                && self.voting_snapshot(&id, &addresses, options)? == snapshot,
            "duplicate vote changed error or funds/history/node state"
        );
        let before = self.voting_utxos(&addresses, options)?;
        let accepted = self.call(
            "joinDRep",
            "PUT",
            &vote_path("no_confidence"),
            Some(password.clone()),
            202,
        )?;
        let vote_id = text(&accepted, "/id")?;
        let voted = self.voting_settle(
            &id,
            &vote_id,
            (0, 0, &certificates_api(Some("no_confidence"), false)),
            &mut addresses,
            &before,
            options,
        )?;
        remaining = remaining
            .checked_sub(number(&voted, "/fee/quantity")?)
            .context("revote balance underflow")?;
        self.family_ready_balance(SHELLEY, &id, remaining)?;
        stake_state(
            &options.node.stake_address_info(&stake, self.timeout)?,
            &stake,
            Some("alwaysNoConfidence"),
            deposit,
        )?;
        self.poll("getWallet", &format!("/wallets/{id}"), |v| {
            v["delegation"]["active"]["status"] == "voting"
                && v["delegation"]["active"]["voting"] == "no_confidence"
        })?;
        self.report
            .record("live:vote-delegate", &["tx.governance".into()], Ok(()));
        self.report
            .record("live:stake-register", &["tx.delegation".into()], Ok(()));
        self.report.record(
            "governance:vote-state",
            &["wallet.governance".into()],
            Ok(()),
        );
        let before = self.voting_utxos(&addresses, options)?;
        let accepted = self.call(
            "quitStakePool",
            "DELETE",
            &quit_path,
            Some(password.clone()),
            202,
        )?;
        let quit = self.voting_settle(
            &id,
            &text(&accepted, "/id")?,
            (0, deposit, &certificates_api(None, false)),
            &mut addresses,
            &before,
            options,
        )?;
        remaining = remaining
            .checked_add(deposit)
            .and_then(|n| n.checked_sub(number(&quit, "/fee/quantity").ok()?))
            .context("refund balance overflow")?;
        self.family_ready_balance(SHELLEY, &id, remaining)?;
        stake_state(
            &options.node.stake_address_info(&stake, self.timeout)?,
            &stake,
            None,
            deposit,
        )?;
        self.poll("getWallet", &format!("/wallets/{id}"), |v| {
            v["delegation"]["active"]["status"] == "not_delegating"
                && v["delegation"]["next"] == json!([])
        })?;
        let snapshot = self.voting_snapshot(&id, &addresses, options)?;
        let rejected = self.call("quitStakePool", "DELETE", &quit_path, Some(password), 403)?;
        ensure!(
            rejected == controls["not_delegating"]
                && self.voting_snapshot(&id, &addresses, options)? == snapshot,
            "duplicate quit changed error or state"
        );
        self.report
            .record("live:stake-deregister", &["tx.delegation".into()], Ok(()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_certificate_extraction_preserves_actual_haskell_writer_bytes() {
        let vectors: Vec<crate::adapter::Vector> =
            serde_json::from_str(include_str!("../../fixtures/vectors/writer-profiles.json"))
                .unwrap();
        for vector in vectors
            .iter()
            .filter(|v| v.operation == "wallet.certificates")
        {
            let Some(certs) = vector
                .expected
                .as_ref()
                .and_then(|v| v["result"]["certificates_cbor_hex"].as_array())
            else {
                continue;
            };
            let expected: Vec<_> = certs
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect();
            let mut e = minicbor::Encoder::new(Vec::new());
            e.array(4)
                .unwrap()
                .map(4)
                .unwrap()
                .u8(0)
                .unwrap()
                .array(0)
                .unwrap()
                .u8(1)
                .unwrap()
                .array(0)
                .unwrap()
                .u8(2)
                .unwrap()
                .u8(0)
                .unwrap()
                .u8(4)
                .unwrap()
                .tag(minicbor::data::Tag::new(258))
                .unwrap()
                .array(expected.len() as u64)
                .unwrap();
            for certificate in &expected {
                e.writer_mut().extend(hex::decode(certificate).unwrap());
            }
            e.map(0).unwrap().bool(true).unwrap().null().unwrap();
            let raw = e.into_writer();
            assert_eq!(
                transaction::certificates(&hex::encode(&raw)).unwrap(),
                expected
            );
            let mut trailing = raw;
            trailing.push(0);
            assert!(transaction::certificates(&hex::encode(trailing)).is_err());
        }
    }
    #[test]
    fn actual_vote_and_refund_accounting_rejects_changed_deposits_and_outputs() {
        let controls: Value =
            serde_json::from_str(include_str!("../../fixtures/voting-controls.json")).unwrap();
        for (name, deposit, refund, certs) in [
            (
                "abstain",
                1_000_000,
                0,
                certificates_api(Some("abstain"), true),
            ),
            ("quit", 0, 1_000_000, certificates_api(None, false)),
        ] {
            let mut tx = controls[name].clone();
            accounting(&tx, deposit, refund, &certs).unwrap();
            tx["outputs"][0]["amount"]["quantity"] = json!(1);
            assert!(accounting(&tx, deposit, refund, &certs).is_err());
            let mut tx = controls[name].clone();
            tx["deposit_returned"]["quantity"] = json!(refund + 1);
            assert!(accounting(&tx, deposit, refund, &certs).is_err());
        }
    }
    #[test]
    fn node_vote_state_rejects_wrong_vote_and_missing_refund() {
        let state = json!([{"address":"stake-test","voteDelegation":"alwaysAbstain",
            "stakeDelegation":null,"stakeRegistrationDeposit":1_000_000,"rewardAccountBalance":0}]);
        stake_state(&state, "stake-test", Some("alwaysAbstain"), 1_000_000).unwrap();
        assert!(stake_state(&state, "stake-test", Some("alwaysNoConfidence"), 1_000_000).is_err());
        assert!(stake_state(&state, "stake-test", None, 1_000_000).is_err());
        assert!(stake_state(&state, "stake-test", Some("alwaysAbstain"), 2_000_000).is_err());
    }
}
