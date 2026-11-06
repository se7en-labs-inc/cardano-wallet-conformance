//! Real pool delegation, nonzero reward withdrawal and deposit/refund accounting.
use super::{families::SHELLEY, *};
use std::collections::{BTreeMap, BTreeSet};
const PASSWORD: &str = "conformance-test-passphrase";
const FUNDING: u64 = 1_000_000_000_000;

fn quantities(tx: &Value, field: &str) -> Result<u64> {
    tx[field]
        .as_array()
        .context("missing stake accounting array")?
        .iter()
        .try_fold(0u64, |sum, value| {
            ensure!(
                value["amount"]["unit"] == "lovelace",
                "stake amount unit differs"
            );
            sum.checked_add(number(value, "/amount/quantity")?)
                .context("stake quantity overflow")
        })
}
fn certificates(pool: &str, joining: bool) -> Value {
    let path = json!(["1852H", "1815H", "0H", "2", "0"]);
    if joining {
        json!([
            {"certificate_type":"register_reward_account","reward_account_path":path},
            {"certificate_type":"join_pool","pool":pool,"reward_account_path":path},
            {"certificate_type":"cast_vote","vote":"abstain","reward_account_path":path}
        ])
    } else {
        json!([{"certificate_type":"quit_pool","reward_account_path":path}])
    }
}
fn accounting(tx: &Value, deposit: u64, refund: u64, certs: &Value, stake: &str) -> Result<u64> {
    ensure!(
        tx["status"] == "in_ledger" && tx["certificates"] == *certs,
        "stake history status/certificates differ"
    );
    ensure!(
        number(tx, "/deposit_taken/quantity")? == deposit
            && number(tx, "/deposit_returned/quantity")? == refund
            && tx["deposit_taken"]["unit"] == "lovelace"
            && tx["deposit_returned"]["unit"] == "lovelace",
        "stake deposit/refund differs"
    );
    let withdrawals = tx["withdrawals"]
        .as_array()
        .context("stake withdrawals missing")?;
    ensure!(
        withdrawals.len() <= 1 && withdrawals.iter().all(|w| w["stake_address"] == stake),
        "unexpected stake withdrawal identity/count"
    );
    for field in ["inputs", "outputs"] {
        ensure!(
            tx[field]
                .as_array()
                .context("stake inputs/outputs missing")?
                .iter()
                .all(|v| v["assets"] == json!([])),
            "unexpected stake native assets"
        );
    }
    let rewards = quantities(tx, "withdrawals")?;
    let fee = number(tx, "/fee/quantity")?;
    ensure!(
        fee > 0
            && tx["fee"]["unit"] == "lovelace"
            && u128::from(quantities(tx, "inputs")?) + u128::from(rewards) + u128::from(refund)
                == u128::from(quantities(tx, "outputs")?) + u128::from(fee) + u128::from(deposit),
        "stake ADA conservation differs"
    );
    Ok(rewards)
}
fn stake_state(value: &Value, stake: &str, pool: &str, deposit: u64) -> Result<u64> {
    let rows = value
        .as_array()
        .context("native stake response is not array")?;
    ensure!(
        rows.len() == 1
            && rows[0]["address"] == stake
            && rows[0]["stakeDelegation"]["stakePoolBech32"] == pool
            && rows[0]["stakeRegistrationDeposit"] == deposit
            && rows[0]["voteDelegation"] == "alwaysAbstain",
        "native stake delegation/vote/deposit differs"
    );
    let (_, pool_bytes) = crate::encoding::bech32(pool)?;
    ensure!(
        rows[0]["stakeDelegation"]["stakePoolHex"] == hex::encode(pool_bytes),
        "native pool hash differs"
    );
    number(&rows[0], "/rewardAccountBalance")
}

impl Session<'_> {
    fn stake_inputs(&mut self, id: &str, options: &LiveOptions) -> Result<BTreeMap<String, Value>> {
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{id}/addresses"),
            None,
            200,
        )?;
        let mut result = BTreeMap::new();
        for value in addresses.as_array().context("stake addresses missing")? {
            if value["state"] != "used" {
                continue;
            }
            let observed = options.node.utxos(&text(value, "/id")?, self.timeout)?;
            for (key, output) in observed.as_object().context("invalid stake UTxO map")? {
                ensure!(
                    result.insert(key.clone(), output.clone()).is_none(),
                    "duplicate native stake UTxO"
                );
            }
        }
        Ok(result)
    }
    fn stake_settle(
        &mut self,
        id: &str,
        txid: &str,
        before: &BTreeMap<String, Value>,
        options: &LiveOptions,
    ) -> Result<Value> {
        let tx = self.family_confirm(SHELLEY, id, txid)?;
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{id}/addresses"),
            None,
            200,
        )?;
        let owned: BTreeSet<_> = addresses
            .as_array()
            .context("missing owned stake addresses")?
            .iter()
            .map(|v| text(v, "/id"))
            .collect::<Result<_>>()?;
        let mut outputs = BTreeMap::<String, u64>::new();
        for output in tx["outputs"].as_array().context("stake outputs missing")? {
            let address = text(output, "/address")?;
            ensure!(owned.contains(&address), "stake output is not owned");
            let total = outputs.entry(address).or_default();
            *total = total
                .checked_add(number(output, "/amount/quantity")?)
                .context("stake output overflow")?;
        }
        for (address, coin) in outputs {
            options.node.payment(txid, &address, coin, self.timeout)?;
        }
        let after = self.stake_inputs(id, options)?;
        let mut seen = BTreeSet::new();
        for input in tx["inputs"].as_array().context("stake inputs missing")? {
            let reference = format!("{}#{}", text(input, "/id")?, number(input, "/index")?);
            let native = before
                .get(&reference)
                .context("stake input not independently observed")?;
            ensure!(
                seen.insert(reference.clone())
                    && !after.contains_key(&reference)
                    && native["address"] == input["address"]
                    && number(native, "/value/lovelace")? == number(input, "/amount/quantity")?,
                "stake input identity/value/spending differs"
            );
        }
        ensure!(!seen.is_empty(), "stake transaction has no inputs");
        Ok(tx)
    }
    fn stake_proof(&mut self, name: &str, requirements: &[String], proof: Value) {
        self.report.record(name, requirements, Ok(()));
        self.report.evidence.last_mut().unwrap().detail = proof.to_string();
    }
    pub(super) fn exercise_stake_rewards(&mut self, options: &LiveOptions) -> Result<()> {
        let pool = options
            .stake_pool
            .as_ref()
            .context("missing registered pool")?;
        let (hrp, pool_bytes) = crate::encoding::bech32(pool)?;
        ensure!(
            hrp == "pool" && pool_bytes.len() == 28,
            "invalid stake pool identity"
        );
        let pools = options.node.stake_pools(self.timeout)?;
        ensure!(
            pools
                .as_array()
                .context("native pool list missing")?
                .contains(&json!(pool)),
            "stake pool is not registered on node"
        );
        self.poll("listStakePools", "/stake-pools?stake=0", |v| {
            v.as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["id"] == *pool))
        })?;
        let mnemonic = bip39::Mnemonic::generate(15)?
            .words()
            .map(str::to_owned)
            .collect();
        let id = self.create("conformance-stake-rewards", mnemonic)?;
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
        let payment_bytes = crate::encoding::bech32(&address)?.1;
        let key = self.call(
            "getWalletKey",
            "GET",
            &format!("{path}/keys/mutable_account/0?hash=false"),
            None,
            200,
        )?;
        let public = crate::encoding::bech32(key.as_str().context("stake public key missing")?)?.1;
        let stake_hash = transaction::blake2b(&public, 28)?;
        ensure!(
            public.len() == 32 && payment_bytes.len() == 57 && payment_bytes[29..] == stake_hash,
            "stake/payment key linkage differs"
        );
        let mut stake_bytes = vec![0xe0];
        stake_bytes.extend(&stake_hash);
        let stake = crate::encoding::bech32_encode("stake_test", &stake_bytes)?;
        ensure!(
            options.node.stake_address_info(&stake, self.timeout)? == json!([]),
            "fresh stake credential already registered"
        );
        ensure!(
            options.node.utxos(&address, self.timeout)? == json!({}),
            "fresh stake wallet has native funds"
        );
        let faucet = Api::new(
            options
                .faucet
                .as_ref()
                .context("stake rewards require faucet")?,
            self.timeout,
        )?;
        let response=faucet.request(&request("POST","/send/faucet-assets",Some(json!({"batch-size":1,"assets":[{"address":address,"bundle":{"coin":FUNDING,"assets":[]},"metadata":[]}]}))))?;
        ensure!(response.status == 204, "stake funding rejected");
        self.family_ready_balance(SHELLEY, &id, FUNDING)?;
        let before = self.stake_inputs(&id, options)?;
        ensure!(
            before.len() == 1
                && before.values().next().unwrap()["value"] == json!({"lovelace":FUNDING}),
            "stake funding is not one exact native output"
        );
        let deposit = number(
            &options.node.protocol_parameters(self.timeout)?,
            "/stakeAddressDeposit",
        )?;
        let prototype=self.call("constructTransaction","POST",&format!("{path}/transactions-construct"),Some(json!({"delegations":[{"join":{"pool":pool,"stake_key_index":"0H"}}],"vote":"abstain"})),202)?;
        let unsigned = text(&prototype, "/transaction")?;
        let mut xpub = public.clone();
        xpub.extend([0u8; 32]);
        let mut expected_certs = crate::writer::certificates(
            &json!({"action":"join-registering","stake_xpub_hex":hex::encode(&xpub),"deposit":deposit,"pool_hex":hex::encode(&pool_bytes)}),
        )?;
        expected_certs.extend(crate::writer::certificates(
            &json!({"action":"vote","stake_xpub_hex":hex::encode(&xpub),"drep":{"type":"abstain"}}),
        )?);
        let initial = transaction::inspect(&unsigned, false)?;
        ensure!(
            transaction::certificates(&unsigned)? == expected_certs
                && initial.inputs == before.keys().cloned().collect::<Vec<_>>()
                && initial
                    .outputs
                    .iter()
                    .map(|v| u128::from(v.coin))
                    .sum::<u128>()
                    + u128::from(initial.fee)
                    + u128::from(deposit)
                    == u128::from(FUNDING),
            "stake prototype certificates/input/deposit/conservation differs"
        );
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("{path}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":PASSWORD})),
            202,
        )?;
        let encoded = text(&signed, "/transaction")?;
        let verified = transaction::inspect(&encoded, true)?;
        let hashes: BTreeSet<_> = verified
            .verification_keys
            .iter()
            .map(|v| transaction::blake2b(&hex::decode(v)?, 28))
            .collect::<Result<_>>()?;
        ensure!(
            verified.id == initial.id
                && transaction::certificates(&encoded)? == expected_certs
                && verified.verification_keys.len() == 2
                && hashes == BTreeSet::from([payment_bytes[1..29].to_vec(), stake_hash]),
            "stake prototype witnesses/body differ"
        );
        ensure!(
            self.stake_inputs(&id, options)? == before,
            "unsubmitted stake prototype spent funds"
        );
        let joined = self.call(
            "joinStakePool",
            "PUT",
            &format!("/stake-pools/{pool}/wallets/{id}"),
            Some(json!({"passphrase":PASSWORD})),
            202,
        )?;
        let joined = self.stake_settle(&id, &text(&joined, "/id")?, &before, options)?;
        ensure!(
            accounting(&joined, deposit, 0, &certificates(pool, true), &stake)? == 0,
            "initial join unexpectedly withdrew rewards"
        );
        let mut balance = FUNDING
            .checked_sub(deposit)
            .and_then(|v| v.checked_sub(number(&joined, "/fee/quantity").ok()?))
            .context("stake join balance underflow")?;
        self.family_ready_balance(SHELLEY, &id, balance)?;
        let native = options.node.stake_address_info(&stake, self.timeout)?;
        stake_state(&native, &stake, pool, deposit)?;
        self.stake_proof("live:stake-delegate",&["tx.delegation".into()],json!({"prototype_signed":encoded,"confirmed":joined,"native_stake":native,"native_funding_before":before}));
        self.report
            .record("live:stake-register", &["tx.delegation".into()], Ok(()));
        let deadline = Instant::now() + self.timeout;
        loop {
            let native = options.node.stake_address_info(&stake, self.timeout)?;
            let reward = stake_state(&native, &stake, pool, deposit)?;
            let wallet = self.call("getWallet", "GET", &path, None, 200)?;
            if reward > 0
                && wallet["delegation"]["active"]["target"] == *pool
                && wallet["delegation"]["active"]["status"] == "voting_and_delegating"
                && number(&wallet, "/balance/reward/quantity")? == reward
            {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "nonzero stake rewards/activation timed out"
            );
            sleep(Duration::from_secs(1));
        }
        let (constructed, reward, native_before) = loop {
            ensure!(
                Instant::now() < deadline,
                "stable withdrawal reward bracket timed out"
            );
            let tip = options.node.query(&["tip"], self.timeout)?;
            let native = options.node.stake_address_info(&stake, self.timeout)?;
            let reward = stake_state(&native, &stake, pool, deposit)?;
            let constructed = self.call(
                "constructTransaction",
                "POST",
                &format!("{path}/transactions-construct"),
                Some(json!({"withdrawal":"self"})),
                202,
            )?;
            let after = options.node.stake_address_info(&stake, self.timeout)?;
            let tip_after = options.node.query(&["tip"], self.timeout)?;
            if tip["epoch"] == tip_after["epoch"] && native == after && reward > 0 {
                break (constructed, reward, native);
            }
        };
        let before = self.stake_inputs(&id, options)?;
        let unsigned = text(&constructed, "/transaction")?;
        let initial = transaction::inspect(&unsigned, false)?;
        let withdrawals = BTreeMap::from([(hex::encode(&stake_bytes), reward)]);
        ensure!(
            transaction::withdrawals(&unsigned)? == withdrawals
                && transaction::certificates(&unsigned)?.is_empty()
                && initial.inputs == before.keys().cloned().collect::<Vec<_>>()
                && initial
                    .outputs
                    .iter()
                    .map(|v| u128::from(v.coin))
                    .sum::<u128>()
                    + u128::from(initial.fee)
                    == u128::from(balance) + u128::from(reward),
            "withdrawal body/reward/input/conservation differs"
        );
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("{path}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":PASSWORD})),
            202,
        )?;
        let encoded = text(&signed, "/transaction")?;
        let tx = transaction::inspect(&encoded, true)?;
        let mut expected_hashes = BTreeSet::from([stake_bytes[1..].to_vec()]);
        for input in before.values() {
            let address = crate::encoding::bech32(&text(input, "/address")?)?.1;
            ensure!(
                address.len() == 57 && address[29..] == stake_bytes[1..],
                "withdrawal funding stake credential differs"
            );
            expected_hashes.insert(address[1..29].to_vec());
        }
        let hashes: BTreeSet<_> = tx
            .verification_keys
            .iter()
            .map(|v| transaction::blake2b(&hex::decode(v)?, 28))
            .collect::<Result<_>>()?;
        ensure!(
            tx.id == initial.id
                && transaction::withdrawals(&encoded)? == withdrawals
                && transaction::certificates(&encoded)?.is_empty()
                && hashes == expected_hashes
                && tx.verification_keys.len() == expected_hashes.len(),
            "withdrawal signatures/body/reward differ"
        );
        let submitted = self.call(
            "submitTransaction",
            "POST",
            &format!("{path}/transactions-submit"),
            Some(json!({"transaction":encoded})),
            202,
        )?;
        ensure!(submitted["id"] == tx.id, "withdrawal submission ID differs");
        let confirmed = self.stake_settle(&id, &tx.id, &before, options)?;
        ensure!(
            accounting(&confirmed, 0, 0, &json!([]), &stake)? == reward
                && number(&confirmed, "/fee/quantity")? == tx.fee,
            "confirmed withdrawal differs"
        );
        self.node_asset_outputs(&tx, options)?;
        balance = balance
            .checked_add(reward)
            .and_then(|v| v.checked_sub(tx.fee))
            .context("withdrawal balance overflow")?;
        self.family_ready_balance(SHELLEY, &id, balance)?;
        let native_after = options.node.stake_address_info(&stake, self.timeout)?;
        stake_state(&native_after, &stake, pool, deposit)?;
        self.stake_proof("live:reward-withdrawal",&["tx.delegation".into()],json!({"transaction":encoded,"confirmed":confirmed,"native_before":native_before,"native_after":native_after,"native_inputs_before":before,"withdrawn":reward}));
        let before = self.stake_inputs(&id, options)?;
        let quit = self.call(
            "quitStakePool",
            "DELETE",
            &format!("/stake-pools/*/wallets/{id}"),
            Some(json!({"passphrase":PASSWORD})),
            202,
        )?;
        let quit = self.stake_settle(&id, &text(&quit, "/id")?, &before, options)?;
        let residual = accounting(&quit, 0, deposit, &certificates(pool, false), &stake)?;
        balance = balance
            .checked_add(residual)
            .and_then(|v| v.checked_add(deposit))
            .and_then(|v| v.checked_sub(number(&quit, "/fee/quantity").ok()?))
            .context("stake refund balance overflow")?;
        self.family_ready_balance(SHELLEY, &id, balance)?;
        ensure!(
            options.node.stake_address_info(&stake, self.timeout)? == json!([]),
            "quit left native stake credential registered"
        );
        let after = self.stake_inputs(&id, options)?;
        let native_total = after.values().try_fold(0u64, |sum, v| {
            sum.checked_add(number(v, "/value/lovelace")?)
                .context("stake final native balance overflow")
        })?;
        ensure!(
            native_total == balance,
            "final stake wallet/native balance differs"
        );
        self.stake_proof("live:stake-reward-refund",&["wallet.balance-conservation".into()],json!({"quit":quit,"withdrawn":reward,"residual_withdrawn":residual,"deposit_refunded":deposit,"final_balance":balance,"native_utxos":after}));
        self.report
            .record("live:stake-deregister", &["tx.delegation".into()], Ok(()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_reward_history_rejects_wrong_reward_account_deposit_and_conservation() {
        let controls: Value =
            serde_json::from_str(include_str!("../../fixtures/stake-reward-controls.json"))
                .unwrap();
        let tx = controls["withdrawal"].clone();
        let stake = tx["withdrawals"][0]["stake_address"].as_str().unwrap();
        assert_eq!(
            accounting(&tx, 0, 0, &json!([]), stake).unwrap(),
            141796456979
        );
        for pointer in [
            "/withdrawals/0/amount/quantity",
            "/fee/quantity",
            "/deposit_returned/quantity",
            "/outputs/0/amount/quantity",
        ] {
            let mut bad = tx.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(1);
            assert!(accounting(&bad, 0, 0, &json!([]), stake).is_err());
        }
        assert!(accounting(&tx, 0, 0, &json!([]), "another-stake-account").is_err());
    }
    #[test]
    fn actual_stake_state_requires_pool_vote_deposit_and_positive_reward_identity() {
        let controls: Value =
            serde_json::from_str(include_str!("../../fixtures/stake-reward-controls.json"))
                .unwrap();
        let state = controls["stake"].clone();
        let stake = state[0]["address"].as_str().unwrap();
        let pool = state[0]["stakeDelegation"]["stakePoolBech32"]
            .as_str()
            .unwrap();
        assert_eq!(
            stake_state(&state, stake, pool, 1000000).unwrap(),
            34223329488
        );
        for pointer in [
            "/0/stakeRegistrationDeposit",
            "/0/voteDelegation",
            "/0/stakeDelegation/stakePoolHex",
        ] {
            let mut bad = state.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("wrong");
            assert!(stake_state(&bad, stake, pool, 1000000).is_err());
        }
    }
}
