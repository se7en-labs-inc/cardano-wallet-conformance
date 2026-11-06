//! Candidate account-public-key wallet with a separately owned reference signer.
use super::{
    families::{FUNDING, SHELLEY},
    *,
};
const PASSWORD: &str = "conformance-test-passphrase";
impl Session<'_> {
    pub(super) fn exercise_watch_only(
        &mut self,
        options: &LiveOptions,
        environment: &str,
    ) -> Result<()> {
        let signer_url = options
            .external_signer
            .as_ref()
            .context("missing external signer URL")?;
        let signer_api = Api::new(signer_url, self.timeout.min(Duration::from_secs(30)))?;
        ensure!(
            signer_api.label.trim_end_matches('/') != self.api.label.trim_end_matches('/'),
            "external signer must be a separate service"
        );
        // These calls supply fixtures; their API evidence is deliberately never
        // merged into the candidate report.
        let mut signer = Session {
            api: &signer_api,
            contract: self.contract,
            report: Report::new(&signer_api.label, environment),
            owned: vec![],
            timeout: self.timeout,
        };
        let result = self.watch_only_transfer(&mut signer, options);
        for (delete, prefix, id) in std::mem::take(&mut signer.owned).into_iter().rev() {
            let cleanup = signer
                .call(delete, "DELETE", &format!("/{prefix}/{id}"), None, 204)
                .map(|_| ());
            self.report
                .record("live:external-signer-owned-cleanup", &[], cleanup);
        }
        result
    }
    fn watch_only_transfer(
        &mut self,
        signer: &mut Session<'_>,
        options: &LiveOptions,
    ) -> Result<()> {
        let mnemonic: Vec<String> = bip39::Mnemonic::generate(15)?
            .words()
            .map(str::to_owned)
            .collect();
        let owner = signer.create("conformance-external-owner", mnemonic)?;
        signer.family_ready_balance(SHELLEY, &owner, 0)?;
        let key = signer.call(
            "getAccountKey",
            "GET",
            &format!("/wallets/{owner}/keys?format=extended"),
            None,
            200,
        )?;
        let (hrp, account) =
            crate::encoding::bech32(key.as_str().context("external account key is not text")?)?;
        ensure!(
            hrp == "acct_xvk" && account.len() == 64,
            "external extended account key differs"
        );
        let watch = self.call("postWallet","POST","/wallets",Some(json!({"name":"conformance-funded-watch-only","account_public_key":hex::encode(&account),"address_pool_gap":20})),201)?;
        let watch_id = text(&watch, "/id")?;
        ensure!(
            watch_id == hex::encode(transaction::blake2b(&account, 20)?),
            "watch identity differs from account public-key hash"
        );
        ensure!(
            watch.get("passphrase").is_none(),
            "watch wallet unexpectedly has passphrase state"
        );
        self.family_ready_balance(SHELLEY, &watch_id, 0)?;
        let watch_path = format!("/wallets/{watch_id}");
        let owner_addresses = signer.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{owner}/addresses"),
            None,
            200,
        )?;
        let watch_addresses = self.call(
            "listAddresses",
            "GET",
            &format!("{watch_path}/addresses"),
            None,
            200,
        )?;
        ensure!(
            watch_addresses == owner_addresses,
            "watch and private account derive different address pools"
        );
        let funding = text(&watch_addresses, "/0/id")?;
        let index = watch_addresses
            .pointer("/0/derivation_path")
            .and_then(Value::as_array)
            .and_then(|p| p.last())
            .and_then(Value::as_str)
            .context("funding address has no derivation index")?;
        let derived = self.call(
            "getWalletKey",
            "GET",
            &format!("{watch_path}/keys/utxo_external/{index}"),
            None,
            200,
        )?;
        let (hrp, payment_key) =
            crate::encoding::bech32(derived.as_str().context("payment key is not text")?)?;
        ensure!(
            hrp == "addr_vk" && payment_key.len() == 32,
            "watch payment key encoding differs"
        );
        let (_, address_bytes) = crate::encoding::bech32(&funding)?;
        ensure!(
            address_bytes.len() >= 29
                && address_bytes[1..29] == transaction::blake2b(&payment_key, 28)?,
            "watch funding address does not match derived payment key"
        );
        let mnemonic = bip39::Mnemonic::generate(15)?
            .words()
            .map(str::to_owned)
            .collect();
        let recipient = self.create("conformance-watch-only-recipient", mnemonic)?;
        self.family_ready_balance(SHELLEY, &recipient, 0)?;
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{recipient}/addresses"),
            None,
            200,
        )?;
        let destination = text(&addresses, "/0/id")?;
        self.family_fund(SHELLEY, &watch_id, &funding, options)?;
        signer.family_ready_balance(SHELLEY, &owner, FUNDING)?;
        let constructed = self.call("constructTransaction","POST",&format!("{watch_path}/transactions-construct"),Some(json!({"payments":[{"address":destination,"amount":{"quantity":options.amount,"unit":"lovelace"}}]})),202)?;
        let unsigned = text(&constructed, "/transaction")?;
        let fee = number(&constructed, "/fee/quantity")?;
        let inspected = transaction::inspect(&unsigned, false)?;
        ensure!(
            inspected.fee == fee && fee > 0 && inspected.verification_keys.is_empty(),
            "watch construction fee/witnesses differ"
        );
        let selected = &constructed["coin_selection"];
        let sum = |name: &str| -> Result<u64> {
            selected[name]
                .as_array()
                .context("missing watch selection")?
                .iter()
                .try_fold(0u64, |a, v| {
                    a.checked_add(number(v, "/amount/quantity")?)
                        .context("watch selection overflow")
                })
        };
        ensure!(
            sum("inputs")?
                == sum("outputs")?
                    .checked_add(sum("change")?)
                    .and_then(|v| v.checked_add(fee))
                    .context("watch selection overflow")?
                && sum("outputs")? == options.amount,
            "watch selection does not conserve requested ADA"
        );
        let (_, destination_bytes) = crate::encoding::bech32(&destination)?;
        ensure!(
            inspected
                .outputs
                .iter()
                .any(|v| v.address_hex == hex::encode(&destination_bytes)
                    && v.coin == options.amount),
            "watch CBOR changes intended output"
        );
        let rejected = self.call(
            "signTransaction",
            "POST",
            &format!("{watch_path}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":PASSWORD})),
            403,
        )?;
        ensure!(
            rejected["code"] == "no_root_key",
            "watch signing error differs"
        );
        let signed = signer.call(
            "signTransaction",
            "POST",
            &format!("/wallets/{owner}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":PASSWORD})),
            202,
        )?;
        let signed = text(&signed, "/transaction")?;
        let verified = transaction::inspect(&signed, true)?;
        ensure!(
            verified.id == inspected.id
                && verified.fee == fee
                && verified.verification_keys == vec![hex::encode(payment_key)],
            "external witness changes body or does not match funded watch key"
        );
        let decoded = self.call(
            "decodeTransaction",
            "POST",
            &format!("{watch_path}/transactions-decode"),
            Some(json!({"transaction":signed})),
            202,
        )?;
        ensure!(
            decoded["id"] == verified.id && number(&decoded, "/fee/quantity")? == fee,
            "watch decoding changes signed transaction"
        );
        let submitted = self.call(
            "submitTransaction",
            "POST",
            &format!("{watch_path}/transactions-submit"),
            Some(json!({"transaction":signed})),
            202,
        )?;
        ensure!(
            submitted["id"] == verified.id,
            "watch submission changes transaction ID"
        );
        for (id, expected, direction) in [
            (&watch_id, FUNDING - options.amount - fee, "outgoing"),
            (&recipient, options.amount, "incoming"),
        ] {
            let confirmed = self.family_confirm(SHELLEY, id, &verified.id)?;
            ensure!(
                confirmed["direction"] == direction,
                "watch payment history direction differs"
            );
            self.family_ready_balance(SHELLEY, id, expected)?;
        }
        signer.family_confirm(SHELLEY, &owner, &verified.id)?;
        signer.family_ready_balance(SHELLEY, &owner, FUNDING - options.amount - fee)?;
        options
            .node
            .payment(&verified.id, &destination, options.amount, self.timeout)?;
        let final_state = self.call("getWallet", "GET", &watch_path, None, 200)?;
        ensure!(
            final_state.get("passphrase").is_none(),
            "watch submission introduced private-key state"
        );
        self.report.record(
            "live:watch-only-external-witness",
            &[
                "wallet.hardware-watch-only".into(),
                "tx.witnesses".into(),
                "tx.body-hash".into(),
                "wallet.balance-conservation".into(),
                "chain.node-utxo-confirmation".into(),
            ],
            Ok(()),
        );
        Ok(())
    }
}
