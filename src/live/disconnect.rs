//! Actual wallet catch-up after all node connections are severed by a transparent relay.
use super::{families::SHELLEY, *};
use crate::node_proxy::SocketProxy;
use std::collections::{BTreeMap, BTreeSet};
const FUNDING: u64 = 10_000_000;
const PAYMENT: u64 = 2_000_000;

fn history_ids(history: &Value) -> Result<BTreeSet<String>> {
    history
        .as_array()
        .context("disconnect history is not an array")?
        .iter()
        .map(|tx| {
            ensure!(
                tx["status"] == "in_ledger",
                "disconnect control has unconfirmed history"
            );
            text(tx, "/id")
        })
        .collect()
}
impl Session<'_> {
    pub(super) fn exercise_disconnect(
        &mut self,
        options: &LiveOptions,
        proxy: &SocketProxy,
    ) -> Result<()> {
        let ids: Vec<_> = self
            .owned
            .iter()
            .map(|(_, prefix, id)| {
                ensure!(
                    *prefix == "wallets",
                    "disconnect requires owned Shelley wallets"
                );
                Ok(id.clone())
            })
            .collect::<Result<_>>()?;
        ensure!(ids.len() == 2, "disconnect expects two basic owned wallets");
        let first = self.balance(&ids[0])?;
        let second = self.balance(&ids[1])?;
        let (wallet, recipient, before, recipient_before) = if first < second {
            (&ids[0], &ids[1], first, second)
        } else {
            (&ids[1], &ids[0], second, first)
        };
        let path = format!("/wallets/{wallet}");
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("{path}/addresses"),
            None,
            200,
        )?;
        let address = text(&addresses, "/0/id")?;
        let node_before = options.node.utxos(&address, self.timeout)?;
        let original = node_before
            .as_object()
            .context("disconnect node funding is not an object")?;
        ensure!(
            !original.is_empty(),
            "disconnect recipient has no confirmed funding"
        );
        let history = self.call(
            "listTransactions",
            "GET",
            &format!("{path}/transactions"),
            None,
            200,
        )?;
        let known_history = history_ids(&history)?;
        let active = proxy.statistics();
        ensure!(
            active.enabled && active.active_connections > 0 && active.upstream_failures == 0,
            "wallet did not establish real relay connections"
        );
        let paused = proxy.pause(self.timeout)?;
        // Resume even when a disconnected-state assertion fails, so owned-wallet cleanup can run.
        let disconnected = (|| -> Result<(String, Value, Value)> {
            let frozen = self.call(
                "getNetworkInformation",
                "GET",
                "/network/information",
                None,
                200,
            )?;
            let frozen_height = number(&frozen, "/node_tip/height/quantity")?;
            let faucet = Api::new(
                options
                    .faucet
                    .as_ref()
                    .context("disconnect requires faucet")?,
                self.timeout,
            )?;
            let response = faucet.request(&request("POST", "/send/faucet-assets", Some(json!({
                "batch-size":1,"assets":[{"address":address,"bundle":{"coin":FUNDING,"assets":[]},"metadata":[]}]
            }))))?;
            ensure!(
                response.status == 204,
                "disconnected-wallet funding was not accepted"
            );
            let deadline = Instant::now() + self.timeout;
            let (funding, confirmed) = loop {
                let current = options.node.utxos(&address, self.timeout)?;
                let entries = current
                    .as_object()
                    .context("invalid independent disconnected funding")?;
                ensure!(
                    original
                        .iter()
                        .all(|(id, output)| entries.get(id) == Some(output)),
                    "disconnected funding changed original node UTxOs"
                );
                let additions: Vec<_> = entries
                    .iter()
                    .filter(|(id, _)| !original.contains_key(*id))
                    .collect();
                if !additions.is_empty() {
                    ensure!(
                        additions.len() == 1
                            && additions[0].1["address"] == address
                            && additions[0].1["value"] == json!({"lovelace":FUNDING}),
                        "unexpected disconnected funding output"
                    );
                    let (hash, index) = additions[0]
                        .0
                        .split_once('#')
                        .context("invalid funding reference")?;
                    ensure!(
                        hex::decode(hash)?.len() == 32 && index.parse::<u64>().is_ok(),
                        "invalid funding identity"
                    );
                    break (hash.to_owned(), current);
                }
                ensure!(
                    Instant::now() < deadline,
                    "independent node did not confirm disconnected funding"
                );
                sleep(Duration::from_millis(100));
            };
            options.node.advancing(frozen_height, self.timeout)?;
            ensure!(
                self.balance(wallet)? == before,
                "disconnected wallet observed new funds"
            );
            let still_known = self.call(
                "listTransactions",
                "GET",
                &format!("{path}/transactions"),
                None,
                200,
            )?;
            ensure!(
                history_ids(&still_known)? == known_history,
                "disconnected history changed"
            );
            let missing = self.call(
                "getTransaction",
                "GET",
                &format!("{path}/transactions/{funding}"),
                None,
                404,
            )?;
            ensure!(
                missing["code"] == "no_such_transaction",
                "disconnected funding rejection code differs"
            );
            let frozen_after = self.call(
                "getNetworkInformation",
                "GET",
                "/network/information",
                None,
                200,
            )?;
            ensure!(
                number(&frozen_after, "/node_tip/height/quantity")? == frozen_height,
                "wallet node tip advanced through a disconnected relay"
            );
            let blocked = proxy.statistics();
            ensure!(
                !blocked.enabled
                    && blocked.active_connections == 0
                    && blocked.admitted_connections == paused.admitted_connections,
                "proxy admitted a connection while disabled"
            );
            Ok((
                funding,
                confirmed,
                json!({"wallet_tip":frozen["node_tip"],"statistics":blocked}),
            ))
        })();
        let resumed = proxy.resume();
        let (funding, confirmed_funding, frozen) = disconnected?;
        resumed?;
        self.family_confirm(SHELLEY, wallet, &funding)?;
        self.family_ready_balance(SHELLEY, wallet, before + FUNDING)?;
        ensure!(
            options.node.utxos(&address, self.timeout)? == confirmed_funding,
            "node funding changed during wallet catch-up"
        );
        let reconnected = proxy.statistics();
        ensure!(
            reconnected.enabled
                && reconnected.admitted_connections > paused.admitted_connections
                && reconnected.active_connections > 0
                && reconnected.upstream_failures == 0
                && reconnected.worker_panics == 0,
            "wallet did not reconnect cleanly through the real relay"
        );
        let recipient_addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{recipient}/addresses"),
            None,
            200,
        )?;
        let destination = text(&recipient_addresses, "/0/id")?;
        let construct = self.call("constructTransaction", "POST", &format!("{path}/transactions-construct"),
            Some(json!({"payments":[{"address":destination,"amount":{"quantity":PAYMENT,"unit":"lovelace"}}]})), 202)?;
        let unsigned = text(&construct, "/transaction")?;
        let tx = transaction::inspect(&unsigned, false)?;
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("{path}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":"conformance-test-passphrase"})),
            202,
        )?;
        let encoded = text(&signed, "/transaction")?;
        let signed_tx = transaction::inspect(&encoded, true)?;
        ensure!(
            signed_tx.id == tx.id && signed_tx.fee == number(&construct, "/fee/quantity")?,
            "reconnected signing changed body/fee"
        );
        let credentials = signed_tx
            .verification_keys
            .iter()
            .map(|key| Ok(hex::encode(transaction::blake2b(&hex::decode(key)?, 28)?)))
            .collect::<Result<BTreeSet<_>>>()?;
        let mut spent = BTreeMap::new();
        let mut required = BTreeSet::new();
        let mut input_total = 0u64;
        for input in construct["coin_selection"]["inputs"]
            .as_array()
            .context("disconnect selection inputs missing")?
        {
            let address = text(input, "/address")?;
            let raw = crate::encoding::bech32(&address)?.1;
            ensure!(
                raw.len() == 57 && raw[0] == 0,
                "unexpected reconnected input address"
            );
            required.insert(hex::encode(&raw[1..29]));
            let reference = format!("{}#{}", text(input, "/id")?, number(input, "/index")?);
            let node = options.node.utxos(&address, self.timeout)?;
            let coin = number(input, "/amount/quantity")?;
            ensure!(
                node[&reference]["address"] == address
                    && node[&reference]["value"] == json!({"lovelace":coin}),
                "reconnected input differs from independent node"
            );
            ensure!(
                spent.insert(reference, address).is_none(),
                "duplicate reconnected selected input"
            );
            input_total = input_total
                .checked_add(coin)
                .context("reconnected input total overflow")?;
        }
        ensure!(
            required == credentials
                && signed_tx.inputs.iter().cloned().collect::<BTreeSet<_>>()
                    == spent.keys().cloned().collect(),
            "reconnected witnesses/inputs do not authorize the exact node selection"
        );
        let total = signed_tx
            .outputs
            .iter()
            .try_fold(signed_tx.fee, |sum, output| {
                ensure!(
                    output.assets.is_empty(),
                    "unexpected reconnected output assets"
                );
                sum.checked_add(output.coin)
                    .context("reconnected output overflow")
            })?;
        ensure!(
            total == input_total && signed_tx.fee > 0,
            "reconnected payment does not conserve ADA"
        );
        let accepted = self.call(
            "submitTransaction",
            "POST",
            &format!("{path}/transactions-submit"),
            Some(json!({"transaction":encoded})),
            202,
        )?;
        ensure!(
            accepted["id"] == signed_tx.id,
            "reconnected submission ID differs"
        );
        self.family_confirm(SHELLEY, wallet, &signed_tx.id)?;
        self.family_confirm(SHELLEY, recipient, &signed_tx.id)?;
        self.family_ready_balance(SHELLEY, wallet, before + FUNDING - PAYMENT - signed_tx.fee)?;
        self.family_ready_balance(SHELLEY, recipient, recipient_before + PAYMENT)?;
        let owned_addresses = self.call(
            "listAddresses",
            "GET",
            &format!("{path}/addresses"),
            None,
            200,
        )?;
        let owned: BTreeSet<_> = owned_addresses
            .as_array()
            .context("reconnected addresses missing")?
            .iter()
            .map(|entry| text(entry, "/id"))
            .collect::<Result<_>>()?;
        let mut payment_total = 0u64;
        for output in &signed_tx.outputs {
            let output_address =
                crate::encoding::bech32_encode("addr_test", &hex::decode(&output.address_hex)?)?;
            if output_address == destination {
                payment_total += output.coin;
            } else {
                ensure!(
                    owned.contains(&output_address),
                    "reconnected change is not owned"
                );
            }
            options
                .node
                .payment(&signed_tx.id, &output_address, output.coin, self.timeout)?;
        }
        ensure!(
            payment_total == PAYMENT,
            "reconnected recipient amount differs"
        );
        for (reference, input_address) in &spent {
            ensure!(
                options
                    .node
                    .utxos(input_address, self.timeout)?
                    .get(reference)
                    .is_none(),
                "reconnected input remains unspent"
            );
        }
        self.check_snapshot(wallet, before + FUNDING - PAYMENT - signed_tx.fee)?;
        self.check_snapshot(recipient, recipient_before + PAYMENT)?;
        let mut final_node = BTreeMap::new();
        for (id, expected) in [
            (wallet, before + FUNDING - PAYMENT - signed_tx.fee),
            (recipient, recipient_before + PAYMENT),
        ] {
            let addresses = self.call(
                "listAddresses",
                "GET",
                &format!("/wallets/{id}/addresses"),
                None,
                200,
            )?;
            let mut total = 0u64;
            let mut snapshot = BTreeMap::new();
            for entry in addresses
                .as_array()
                .context("final disconnected wallet addresses missing")?
            {
                let address = text(entry, "/id")?;
                let utxos = options.node.utxos(&address, self.timeout)?;
                for (reference, output) in utxos.as_object().context("invalid final node UTxOs")? {
                    let coin = number(output, "/value/lovelace")?;
                    ensure!(
                        output["address"] == address && output["value"] == json!({"lovelace":coin}),
                        "unexpected final node address/assets"
                    );
                    ensure!(
                        snapshot.insert(reference.clone(), output.clone()).is_none(),
                        "duplicate final node UTxO"
                    );
                    total = total
                        .checked_add(coin)
                        .context("final node balance overflow")?;
                }
            }
            ensure!(
                total == expected,
                "reconnected wallet balance differs from all owned node UTxOs"
            );
            final_node.insert(id, snapshot);
        }
        self.report.record(
            "live:node-disconnect-reconnect",
            &["wallet.resubmission".into()],
            Ok(()),
        );
        self.report.evidence.last_mut().unwrap().detail = json!({"assertion":"real relay outage, independent funding, frozen wallet state, catch-up and signed confirmed payment",
            "funding_transaction":funding,"node_before":node_before,"node_funding":confirmed_funding,"frozen":frozen,
            "reconnected_statistics":reconnected,"signed_transaction":signed,"spent_inputs":spent,"final_node_utxos":final_node}).to_string();
        Ok(())
    }
}
