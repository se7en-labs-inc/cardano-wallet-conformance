//! Funded wallet-family compatibility through actual HTTP handlers and node UTxOs.
use super::*;
const PASSWORD: &str = "conformance-test-passphrase";
pub(super) const FUNDING: u64 = 100_000_000;
fn shared_wrong_passphrase(response: &Value, id: &str) -> Result<()> {
    ensure!(
        response
            == &json!({"code":"wrong_encryption_passphrase",
        "message":format!("The given encryption passphrase doesn't match the one I use to encrypt the root private key of the given wallet: {id}"),
        "info":{"wallet_id":id}}),
        "shared signing rejection code/message/wallet differs"
    );
    Ok(())
}
fn internal_discovery(before: &Value, after: &Value, change: &Value) -> Result<()> {
    let external =
        super::discovery::addresses(before, 21, &std::collections::BTreeSet::from([0]), &[])?;
    ensure!(
        change["derivation_path"] == json!(["1852H", "1815H", "0H", "1", "0"]),
        "first change derivation path differs"
    );
    let address = text(change, "/address")?;
    let (hrp, bytes) = crate::encoding::bech32(&address)?;
    let (_, first) = crate::encoding::bech32(&external[0])?;
    ensure!(
        hrp == "addr_test"
            && bytes.len() == 57
            && bytes[0] == 0
            && bytes[29..] == first[29..]
            && !external.contains(&address),
        "internal change credential/network differs"
    );
    let mut expected = before
        .as_array()
        .context("external discovery array missing")?
        .clone();
    expected.insert(
        1,
        json!({"id":address,"state":"used","derivation_path":change["derivation_path"]}),
    );
    ensure!(
        after == &Value::Array(expected),
        "confirmed internal discovery address/state/order differs"
    );
    Ok(())
}
#[derive(Clone, Copy)]
pub(super) struct Family {
    pub(super) prefix: &'static str,
    pub(super) wallet: &'static str,
    pub(super) transactions: &'static str,
    pub(super) transaction: &'static str,
    fee: &'static str,
    select: &'static str,
    pub(super) post: &'static str,
    plan: &'static str,
    migrate: &'static str,
}
pub(super) const SHELLEY: Family = Family {
    prefix: "wallets",
    wallet: "getWallet",
    transactions: "listTransactions",
    transaction: "getTransaction",
    fee: "postTransactionFee",
    select: "selectCoins",
    post: "postTransaction",
    plan: "createShelleyWalletMigrationPlan",
    migrate: "migrateShelleyWallet",
};
pub(super) const BYRON: Family = Family {
    prefix: "byron-wallets",
    wallet: "getByronWallet",
    transactions: "listByronTransactions",
    transaction: "getByronTransaction",
    fee: "postByronTransactionFee",
    select: "byronSelectCoins",
    post: "postByronTransaction",
    plan: "createByronWalletMigrationPlan",
    migrate: "migrateByronWallet",
};
fn sum(selection: &Value, field: &str) -> Result<u64> {
    selection[field]
        .as_array()
        .context("missing selection field")?
        .iter()
        .try_fold(0u64, |a, v| {
            a.checked_add(number(v, "/amount/quantity")?)
                .context("selection overflow")
        })
}
fn selection_fee(
    selection: &Value,
    destination: &str,
    expected_output: Option<u64>,
) -> Result<u64> {
    let inputs = sum(selection, "inputs")?;
    let outputs = sum(selection, "outputs")?;
    let change = sum(selection, "change")?;
    let fee = inputs
        .checked_sub(outputs)
        .and_then(|v| v.checked_sub(change))
        .context("selection creates ADA")?;
    ensure!(fee > 0, "selection has no fee");
    let mut unique = std::collections::BTreeSet::new();
    for input in selection["inputs"].as_array().unwrap() {
        ensure!(
            unique.insert((text(input, "/id")?, number(input, "/index")?)),
            "duplicate selected input"
        );
    }
    for field in ["inputs", "outputs", "change"] {
        for item in selection[field].as_array().unwrap() {
            ensure!(
                item["assets"] == json!([]),
                "unexpected native asset in ADA-only profile"
            );
        }
    }
    ensure!(
        selection["outputs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["address"] == destination),
        "selection changed payment destination"
    );
    if let Some(amount) = expected_output {
        ensure!(outputs == amount, "selection changed requested payment");
    }
    Ok(fee)
}
impl Session<'_> {
    fn shared_signing_state(&mut self, id: &str) -> Result<Value> {
        let path = format!("/shared-wallets/{id}");
        let wallet = self.call("getSharedWallet", "GET", &path, None, 200)?;
        ensure!(
            wallet["state"]["status"] == "ready"
                && number(&wallet, "/balance/available/quantity")? == FUNDING
                && number(&wallet, "/balance/total/quantity")? == FUNDING,
            "shared signing control is not ready with exact funding"
        );
        let addresses = self.call(
            "listSharedAddresses",
            "GET",
            &format!("{path}/addresses"),
            None,
            200,
        )?;
        let key = self.call(
            "getAccountKeyShared",
            "GET",
            &format!("{path}/keys?format=extended"),
            None,
            200,
        )?;
        let snapshot = self.call(
            "getSharedWalletUtxoSnapshot",
            "GET",
            &format!("{path}/utxo"),
            None,
            200,
        )?;
        let history = self.call(
            "listSharedTransactions",
            "GET",
            &format!("{path}/transactions"),
            None,
            200,
        )?;
        let history = history
            .as_array()
            .context("shared signing history is not an array")?;
        ensure!(
            history.len() == 1 && history[0]["status"] == "in_ledger",
            "shared signing control has unexpected pending/history records"
        );
        Ok(
            json!({"balance":wallet["balance"],"assets":wallet["assets"],"delegation":wallet["delegation"],
            "addresses":addresses,"account_key":key,"utxo":snapshot,
            "history":history.iter().map(history::stable).collect::<Vec<_>>()}),
        )
    }
    pub(super) fn family_confirm(&mut self, family: Family, id: &str, txid: &str) -> Result<Value> {
        let path = format!("/{}/{id}/transactions/{txid}", family.prefix);
        let deadline = Instant::now() + self.timeout;
        loop {
            self.contract.check_path(family.transaction, "GET", &path)?;
            let response = self.api.request(&request("GET", &path, None))?;
            self.contract.validate(family.transaction, &response)?;
            ensure!(
                [200, 404].contains(&response.status),
                "unexpected family confirmation status"
            );
            if response.status == 200 {
                let value = body(&response)?;
                ensure!(value["id"] == txid, "family confirmation ID differs");
                if value["status"] == "in_ledger" {
                    self.report.record(
                        &format!("live:{}:confirmed", family.transaction),
                        &[
                            format!("api:{}:positive", family.transaction),
                            format!("api:{}:status:200", family.transaction),
                        ],
                        Ok(()),
                    );
                    return Ok(value.clone());
                }
            }
            ensure!(
                Instant::now() < deadline,
                "family transaction confirmation timed out"
            );
            sleep(Duration::from_secs(1));
        }
    }
    pub(super) fn family_ready_balance(
        &mut self,
        family: Family,
        id: &str,
        amount: u64,
    ) -> Result<()> {
        self.poll(family.wallet, &format!("/{}/{id}", family.prefix), |v| {
            v["state"]["status"] == "ready"
                && v["balance"]["available"]["quantity"] == amount
                && v["balance"]["total"]["quantity"] == amount
        })?;
        Ok(())
    }
    pub(super) fn family_fund(
        &mut self,
        family: Family,
        id: &str,
        address: &str,
        options: &LiveOptions,
    ) -> Result<()> {
        if family.prefix == BYRON.prefix {
            return self.byron_bridge(
                id,
                address,
                &options.node,
                options
                    .faucet
                    .as_deref()
                    .context("Byron bridge requires faucet")?,
            );
        }
        let faucet = Api::new(
            options
                .faucet
                .as_ref()
                .context("family funding requires faucet")?,
            self.timeout,
        )?;
        let result = faucet.request(&request("POST","/send/faucet-assets",Some(json!({"batch-size":1,"assets":[{"address":address,"bundle":{"coin":FUNDING,"assets":[]},"metadata":[]}]}))))?;
        ensure!(result.status == 204, "family faucet rejected funding");
        self.family_ready_balance(family, id, FUNDING)?;
        let utxo = options.node.utxos(address, self.timeout)?;
        let entries = utxo
            .as_object()
            .context("node funding UTxO is not object")?;
        ensure!(!entries.is_empty(), "node funding UTxO is empty");
        let mut total = 0u64;
        for output in entries.values() {
            ensure!(output["address"] == address, "node funding address differs");
            total = total
                .checked_add(number(output, "/value/lovelace")?)
                .context("node funding overflow")?;
        }
        ensure!(total == FUNDING, "node funding total differs");
        Ok(())
    }
    pub(super) fn byron_bridge(
        &mut self,
        id: &str,
        destination: &str,
        node: &crate::node::NodeOracle,
        faucet: &str,
    ) -> Result<()> {
        let phrase = bip39::Mnemonic::generate(15)?
            .words()
            .map(str::to_owned)
            .collect();
        let bridge = self.create("conformance-owned-byron-bridge", phrase)?;
        self.family_ready_balance(SHELLEY, &bridge, 0)?;
        let path = format!("/wallets/{bridge}");
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("{path}/addresses"),
            None,
            200,
        )?;
        let address = text(&addresses, "/0/id")?;
        ensure!(
            node.utxos(destination, self.timeout)?
                .as_object()
                .is_some_and(|m| m.is_empty()),
            "Byron bridge destination already funded"
        );
        let faucet = Api::new(faucet, self.timeout)?;
        let response = faucet.request(&request("POST", "/send/faucet-assets", Some(json!({"batch-size":1,"assets":[{"address":address,"bundle":{"coin":2*FUNDING,"assets":[]},"metadata":[]}]}))))?;
        ensure!(
            response.status == 204,
            "bridge faucet rejected Shelley funding"
        );
        self.family_ready_balance(SHELLEY, &bridge, 2 * FUNDING)?;
        let before = node.utxos(&address, self.timeout)?;
        let entries = before.as_object().context("invalid bridge node UTxOs")?;
        ensure!(
            entries.len() == 1,
            "bridge requires exactly one funding input"
        );
        let (reference, output) = entries.iter().next().unwrap();
        ensure!(
            output["address"] == address && output["value"] == json!({"lovelace":2*FUNDING}),
            "bridge funding amount/assets/address differ"
        );
        let constructed = self.call("constructTransaction", "POST", &format!("{path}/transactions-construct"), Some(json!({"payments":[{"address":destination,"amount":{"quantity":FUNDING,"unit":"lovelace"}}]})), 202)?;
        let unsigned = text(&constructed, "/transaction")?;
        let body = transaction::inspect(&unsigned, false)?;
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("{path}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":PASSWORD})),
            202,
        )?;
        let encoded = text(&signed, "/transaction")?;
        let tx = transaction::inspect(&encoded, true)?;
        let recipient = hex::encode(crate::encoding::base58_decode(destination)?);
        let source_bytes = crate::encoding::bech32(&address)?.1;
        ensure!(
            tx.id == body.id
                && tx.inputs == [reference.clone()]
                && tx.verification_keys.len() == 1
                && transaction::blake2b(&hex::decode(&tx.verification_keys[0])?, 28)?
                    == source_bytes[1..29]
                && tx.outputs.len() == 2
                && tx.outputs.iter().all(|v| v.assets.is_empty())
                && tx
                    .outputs
                    .iter()
                    .filter(|v| v.address_hex == recipient && v.coin == FUNDING)
                    .count()
                    == 1
                && tx
                    .outputs
                    .iter()
                    .try_fold(tx.fee, |sum, v| sum.checked_add(v.coin))
                    == Some(2 * FUNDING),
            "bridge body/witness/output/conservation differs"
        );
        ensure!(
            number(&constructed, "/fee/quantity")? == tx.fee,
            "bridge API/binary fee differs"
        );
        let sent = self.call(
            "submitTransaction",
            "POST",
            &format!("{path}/transactions-submit"),
            Some(json!({"transaction":encoded})),
            202,
        )?;
        ensure!(sent["id"] == tx.id, "bridge submission hash differs");
        self.family_confirm(SHELLEY, &bridge, &tx.id)?;
        self.family_confirm(BYRON, id, &tx.id)?;
        self.family_ready_balance(BYRON, id, FUNDING)?;
        self.family_ready_balance(
            SHELLEY,
            &bridge,
            FUNDING
                .checked_sub(tx.fee)
                .context("bridge fee exceeds change")?,
        )?;
        node.payment(&tx.id, destination, FUNDING, self.timeout)?;
        ensure!(
            !node
                .utxos(&address, self.timeout)?
                .as_object()
                .context("invalid bridge spent-input state")?
                .contains_key(reference),
            "bridge funding input not spent"
        );
        let outputs = node.utxos(destination, self.timeout)?;
        ensure!(
            outputs.as_object().is_some_and(|m| m.len() == 1)
                && outputs[format!(
                    "{}#{}",
                    tx.id,
                    tx.outputs
                        .iter()
                        .position(|v| v.address_hex == recipient)
                        .unwrap()
                )]["value"]
                    == json!({"lovelace":FUNDING}),
            "bridge Byron node output count/assets differ"
        );
        Ok(())
    }
    pub(super) fn exercise_families(&mut self, options: &LiveOptions) -> Result<()> {
        self.exercise_family_styles(options, &["icarus", "random", "shelley"])
    }
    pub(super) fn exercise_payments(&mut self, options: &LiveOptions) -> Result<()> {
        self.exercise_family_styles(options, &["shelley"])
    }
    fn exercise_family_styles(&mut self, options: &LiveOptions, styles: &[&str]) -> Result<()> {
        let mnemonic = || -> Result<Vec<String>> {
            Ok(bip39::Mnemonic::generate(15)?
                .words()
                .map(str::to_owned)
                .collect())
        };
        let destination_wallet = self.create("conformance-family-destination", mnemonic()?)?;
        self.family_ready_balance(SHELLEY, &destination_wallet, 0)?;
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{destination_wallet}/addresses"),
            None,
            200,
        )?;
        let destination = text(&addresses, "/0/id")?;
        let mut destination_total = 0u64;
        for &style in styles {
            let family = if style == "shelley" { SHELLEY } else { BYRON };
            let id = if style == "shelley" {
                self.create("conformance-family-shelley", mnemonic()?)?
            } else {
                let phrase: Vec<String> =
                    bip39::Mnemonic::generate(if style == "random" { 12 } else { 15 })?
                        .words()
                        .map(str::to_owned)
                        .collect();
                let created = self.call("postByronWallet","POST","/byron-wallets",Some(json!({"style":style,"name":format!("conformance-funded-{style}"),"mnemonic_sentence":phrase,"passphrase":PASSWORD})),201)?;
                text(&created, "/id")?
            };
            self.family_ready_balance(family, &id, 0)?;
            let path = format!("/{}/{id}", family.prefix);
            let address = if style == "random" {
                let created = self.call(
                    "createAddress",
                    "POST",
                    &format!("{path}/addresses"),
                    Some(json!({"passphrase":PASSWORD,"address_index":2147495993u64})),
                    201,
                )?;
                text(&created, "/id")?
            } else {
                let addresses = self.call(
                    if style == "shelley" {
                        "listAddresses"
                    } else {
                        "listByronAddresses"
                    },
                    "GET",
                    &format!("{path}/addresses"),
                    None,
                    200,
                )?;
                text(&addresses, "/0/id")?
            };
            let initial_discovery = if style == "shelley" {
                let initial = self.call(
                    "listAddresses",
                    "GET",
                    &format!("{path}/addresses"),
                    None,
                    200,
                )?;
                Some(super::discovery::addresses(
                    &initial,
                    20,
                    &std::collections::BTreeSet::new(),
                    &[],
                )?)
            } else {
                None
            };
            self.family_fund(family, &id, &address, options)?;
            let discovery_before = if let Some(initial) = &initial_discovery {
                let before = self.call(
                    "listAddresses",
                    "GET",
                    &format!("{path}/addresses"),
                    None,
                    200,
                )?;
                super::discovery::addresses(
                    &before,
                    21,
                    &std::collections::BTreeSet::from([0]),
                    initial,
                )?;
                Some(before)
            } else {
                None
            };
            let mut change_discovery = None;
            let payment = json!({"payments":[{"address":destination,"amount":{"quantity":options.amount,"unit":"lovelace"}}]});
            let estimate = self.call(
                family.fee,
                "POST",
                &format!("{path}/payment-fees"),
                Some(payment.clone()),
                202,
            )?;
            let minimum = number(&estimate, "/estimated_min/quantity")?;
            let maximum = number(&estimate, "/estimated_max/quantity")?;
            ensure!(
                minimum > 0 && minimum <= maximum,
                "fee estimate interval invalid"
            );
            if style != "random" {
                let selection = self.call(
                    family.select,
                    "POST",
                    &format!("{path}/coin-selections/random"),
                    Some(payment.clone()),
                    200,
                )?;
                let fee = selection_fee(&selection, &destination, Some(options.amount))?;
                if style == "shelley" {
                    let changes = selection["change"]
                        .as_array()
                        .context("selection change missing")?;
                    ensure!(
                        changes.len() == 1
                            && changes[0]["derivation_path"]
                                == json!(["1852H", "1815H", "0H", "1", "0"]),
                        "first preview change path/count differs"
                    );
                    change_discovery = Some(changes[0].clone());
                }
                ensure!(
                    fee >= minimum && fee <= maximum,
                    "selection fee outside estimate"
                );
            }
            if let Some(before) = &discovery_before {
                let previewed = self.call(
                    "listAddresses",
                    "GET",
                    &format!("{path}/addresses"),
                    None,
                    200,
                )?;
                ensure!(
                    &previewed == before,
                    "fee/selection preview persisted internal discovery state"
                );
            }
            let mut signed_payment = payment;
            signed_payment["passphrase"] = json!(PASSWORD);
            let sent = self.call(
                family.post,
                "POST",
                &format!("{path}/transactions"),
                Some(signed_payment),
                202,
            )?;
            let txid = text(&sent, "/id")?;
            let confirmed = self.family_confirm(family, &id, &txid)?;
            let fee = number(&confirmed, "/fee/quantity")?;
            ensure!(
                fee >= minimum && fee <= maximum,
                "actual payment fee outside estimate"
            );
            ensure!(
                confirmed["direction"] == "outgoing",
                "wrong payment direction"
            );
            ensure!(
                confirmed["outputs"]
                    .as_array()
                    .context("missing payment outputs")?
                    .iter()
                    .any(|v| v["address"] == destination
                        && v["amount"]["quantity"] == options.amount),
                "payment output differs"
            );
            options
                .node
                .payment(&txid, &destination, options.amount, self.timeout)?;
            self.family_confirm(SHELLEY, &destination_wallet, &txid)?;
            destination_total += options.amount;
            self.family_ready_balance(SHELLEY, &destination_wallet, destination_total)?;
            let remaining = FUNDING
                .checked_sub(options.amount)
                .and_then(|v| v.checked_sub(fee))
                .context("payment exceeds balance")?;
            self.family_ready_balance(family, &id, remaining)?;
            if let (Some(before), Some(change)) = (&discovery_before, &change_discovery) {
                let after = self.call(
                    "listAddresses",
                    "GET",
                    &format!("{path}/addresses"),
                    None,
                    200,
                )?;
                internal_discovery(before, &after, change)?;
                let change_address = text(change, "/address")?;
                options
                    .node
                    .payment(&txid, &change_address, remaining, self.timeout)?;
                let change_utxos = options.node.utxos(&change_address, self.timeout)?;
                ensure!(
                    change_utxos.as_object().is_some_and(|m| m.len() == 1),
                    "internal change has unexpected node outputs"
                );
                let spent = options.node.utxos(&address, self.timeout)?;
                ensure!(
                    spent.as_object().is_some_and(|m| m.is_empty()),
                    "internal discovery funding input remains unspent"
                );
                self.check_snapshot(&id, remaining)?;
                self.report.record(
                    "discovery-internal-change",
                    &["wallet.discovery".into()],
                    Ok(()),
                );
                self.report.evidence.last_mut().unwrap().detail = json!({"assertion":"transient previews preserve external pool; confirmed internal0 becomes visible","before":before,"after":after,"selected_change":change,"node_change":change_utxos,"spent_funding":spent,"remaining":remaining,"transaction_id":txid}).to_string();
            }
            if style != "shelley" {
                self.report.record(
                    &format!("live:byron-{style}-spend"),
                    &["wallet.byron-migration".into()],
                    Ok(()),
                );
            }
            if style == "random" {
                self.report.record(
                    "discovery-random-byron",
                    &["wallet.discovery".into()],
                    Ok(()),
                );
            }
            let history = self.call(
                family.transactions,
                "GET",
                &format!("{path}/transactions"),
                None,
                200,
            )?;
            ensure!(
                history
                    .as_array()
                    .context("missing history")?
                    .iter()
                    .any(|tx| tx["id"] == txid && tx["status"] == "in_ledger"),
                "confirmed family payment absent from history"
            );
            let plan = self.call(
                family.plan,
                "POST",
                &format!("{path}/migrations/plan"),
                Some(json!({"addresses":[destination]})),
                202,
            )?;
            ensure!(
                number(&plan, "/balance_selected/ada/quantity")? == remaining
                    && number(&plan, "/balance_leftover/ada/quantity")? == 0
                    && plan["balance_selected"]["assets"] == json!([])
                    && plan["balance_leftover"]["assets"] == json!([]),
                "migration failed to select complete ADA balance"
            );
            let selections = plan["selections"]
                .as_array()
                .context("missing migration selections")?;
            ensure!(!selections.is_empty(), "empty migration plan");
            let mut plan_fee = 0u64;
            let mut selected = 0u64;
            for selection in selections {
                plan_fee = plan_fee
                    .checked_add(selection_fee(selection, &destination, None)?)
                    .context("plan fee overflow")?;
                selected = selected
                    .checked_add(sum(selection, "inputs")?)
                    .context("plan inputs overflow")?;
                ensure!(
                    sum(selection, "change")? == 0,
                    "migration creates source change"
                );
            }
            ensure!(
                plan_fee == number(&plan, "/total_fee/quantity")? && selected == remaining,
                "migration plan does not conserve funds"
            );
            let migrations = self.call(
                family.migrate,
                "POST",
                &format!("{path}/migrations"),
                Some(json!({"addresses":[destination],"passphrase":PASSWORD})),
                202,
            )?;
            let migrations = migrations
                .as_array()
                .context("missing migration transactions")?;
            ensure!(
                migrations.len() == selections.len(),
                "migration count differs from plan"
            );
            let mut migrated = 0u64;
            let mut actual_fees = 0u64;
            for tx in migrations {
                let txid = text(tx, "/id")?;
                let confirmed = self.family_confirm(family, &id, &txid)?;
                let actual_fee = number(&confirmed, "/fee/quantity")?;
                actual_fees = actual_fees
                    .checked_add(actual_fee)
                    .context("migration fee overflow")?;
                let amount = confirmed["outputs"]
                    .as_array()
                    .context("missing migration outputs")?
                    .iter()
                    .try_fold(0u64, |a, v| -> Result<u64> {
                        ensure!(v["address"] == destination, "migration changes destination");
                        a.checked_add(number(v, "/amount/quantity")?)
                            .context("migration output overflow")
                    })?;
                options
                    .node
                    .payment(&txid, &destination, amount, self.timeout)?;
                self.family_confirm(SHELLEY, &destination_wallet, &txid)?;
                migrated = migrated
                    .checked_add(amount)
                    .context("migration amount overflow")?;
            }
            ensure!(
                actual_fees == plan_fee && migrated.checked_add(actual_fees) == Some(remaining),
                "migration execution differs from conserved plan"
            );
            self.family_ready_balance(family, &id, 0)?;
            destination_total = destination_total
                .checked_add(migrated)
                .context("destination balance overflow")?;
            self.family_ready_balance(SHELLEY, &destination_wallet, destination_total)?;
            if style != "shelley" {
                self.report.record(
                    "live:byron-migrate",
                    &["wallet.byron-migration".into()],
                    Ok(()),
                );
            }
            self.report.record(
                &format!("live:funded-{style}-payment-migration"),
                &[
                    "wallet.balance-conservation".into(),
                    "chain.node-utxo-confirmation".into(),
                ],
                Ok(()),
            );
        }
        Ok(())
    }
}

const SHARED: Family = Family {
    prefix: "shared-wallets",
    wallet: "getSharedWallet",
    transactions: "listSharedTransactions",
    transaction: "getSharedTransaction",
    fee: "",
    select: "",
    post: "",
    plan: "",
    migrate: "",
};
fn check_shared_script(encoded: &str, address: &str, keys: &[String]) -> Result<()> {
    use base64::Engine;
    let raw = if encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(encoded)?
    } else {
        base64::engine::general_purpose::STANDARD.decode(encoded)?
    };
    let mut d = minicbor::Decoder::new(&raw);
    ensure!(d.array()? == Some(4), "shared transaction envelope differs");
    d.skip()?;
    let count = d.map()?.context("indefinite witnesses")?;
    let (_, address_bytes) = crate::encoding::bech32(address)?;
    ensure!(
        address_bytes.len() >= 29 && [1, 3, 7].contains(&(address_bytes[0] >> 4)),
        "funding address is not script payment address"
    );
    let expected_keys: std::collections::BTreeSet<_> = keys
        .iter()
        .map(|key| -> Result<_> { transaction::blake2b(&hex::decode(key)?, 28) })
        .collect::<Result<_>>()?;
    ensure!(
        expected_keys.len() == 2,
        "expected exactly two distinct signing keys"
    );
    let mut matched = false;
    for _ in 0..count {
        if d.u64()? != 1 {
            d.skip()?;
            continue;
        }
        if d.datatype()? == minicbor::data::Type::Tag {
            ensure!(d.tag()?.as_u64() == 258, "invalid native script set tag");
        }
        for _ in 0..d.array()?.context("indefinite native scripts")? {
            let start = d.position();
            let mut script = d.clone();
            d.skip()?;
            let bytes = &raw[start..d.position()];
            let mut domain = vec![0];
            domain.extend(bytes);
            if transaction::blake2b(&domain, 28)? != address_bytes[1..29] {
                continue;
            }
            ensure!(
                script.array()? == Some(2) && script.u64()? == 1 && script.array()? == Some(2),
                "payment script is not all-of-two"
            );
            let mut actual_keys = std::collections::BTreeSet::new();
            for _ in 0..2 {
                ensure!(
                    script.array()? == Some(2) && script.u64()? == 0,
                    "payment script has unexpected clause"
                );
                ensure!(
                    actual_keys.insert(script.bytes()?.to_vec()),
                    "payment script duplicates a key"
                );
            }
            ensure!(
                script.position() == d.position() && actual_keys == expected_keys,
                "payment script does not require both verified witnesses"
            );
            matched = true;
        }
    }
    ensure!(matched, "witness scripts do not match funded address hash");
    Ok(())
}
impl Session<'_> {
    pub(super) fn exercise_shared(&mut self, options: &LiveOptions) -> Result<()> {
        let destination_mnemonic = bip39::Mnemonic::generate(15)?
            .words()
            .map(str::to_owned)
            .collect();
        let recipient = self.create("conformance-shared-recipient", destination_mnemonic)?;
        self.family_ready_balance(SHELLEY, &recipient, 0)?;
        let recipient_addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{recipient}/addresses"),
            None,
            200,
        )?;
        let destination = text(&recipient_addresses, "/0/id")?;
        let payment = json!({"payments":[{"address":destination,"amount":{"quantity":options.amount,"unit":"lovelace"}}]});
        let mut parties = Vec::new();
        let mut account_keys = Vec::new();
        for index in 0..2 {
            let mnemonic: Vec<String> = bip39::Mnemonic::generate(15)?
                .words()
                .map(str::to_owned)
                .collect();
            let template = json!({"cosigners":{format!("cosigner#{index}"):"self"},"template":{"all":["cosigner#0","cosigner#1"]}});
            let created = self.call("postSharedWallet","POST","/shared-wallets",Some(json!({"name":format!("conformance-cosigner-{index}"),"mnemonic_sentence":mnemonic,"passphrase":PASSWORD,"account_index":"0H","payment_script_template":template,"delegation_script_template":template})),201)?;
            ensure!(
                created["state"]["status"] == "incomplete"
                    && created.get("balance").is_none()
                    && created.get("tip").is_none(),
                "pending shared state differs"
            );
            let id = text(&created, "/id")?;
            let rejected = self.call(
                "constructSharedTransaction",
                "POST",
                &format!("/shared-wallets/{id}/transactions-construct"),
                Some(payment.clone()),
                403,
            )?;
            ensure!(
                rejected["code"] == "shared_wallet_incomplete",
                "incomplete shared construction error differs"
            );
            let key = self.call(
                "getAccountKeyShared",
                "GET",
                &format!("/shared-wallets/{id}/keys?format=extended"),
                None,
                200,
            )?;
            let key = key
                .as_str()
                .context("shared account key is not text")?
                .to_owned();
            let (hrp, bytes) = crate::encoding::bech32(&key)?;
            ensure!(
                hrp == "acct_shared_xvk" && bytes.len() == 64,
                "shared account key encoding differs"
            );
            parties.push(id);
            account_keys.push(key);
        }
        ensure!(
            parties[0] != parties[1] && account_keys[0] != account_keys[1],
            "shared cosigners are not independent"
        );
        self.report.record(
            "shared:incomplete",
            &["wallet.shared-cosigners".into()],
            Ok(()),
        );
        for (index, id) in parties.iter().enumerate() {
            let peer = 1 - index;
            let patch = json!({format!("cosigner#{peer}"):account_keys[peer]});
            let payment_patch = self.call(
                "patchSharedWalletInPayment",
                "PATCH",
                &format!("/shared-wallets/{id}/payment-script-template"),
                Some(patch.clone()),
                200,
            )?;
            ensure!(
                payment_patch["state"]["status"] == "incomplete",
                "shared wallet activated before delegation cosigner patch"
            );
            {
                let (kind, op) = ("delegation", "patchSharedWalletInDelegation");
                let patched = self.call(
                    op,
                    "PATCH",
                    &format!("/shared-wallets/{id}/{kind}-script-template"),
                    Some(patch.clone()),
                    200,
                )?;
                ensure!(
                    patched[format!("{kind}_script_template")]["cosigners"]
                        [format!("cosigner#{peer}")]
                        == account_keys[peer],
                    "shared cosigner patch changed key"
                );
            }
            self.family_ready_balance(SHARED, id, 0)?;
        }
        let mut address_sets = Vec::new();
        for id in &parties {
            address_sets.push(self.call(
                "listSharedAddresses",
                "GET",
                &format!("/shared-wallets/{id}/addresses"),
                None,
                200,
            )?);
        }
        ensure!(
            address_sets[0] == address_sets[1],
            "shared parties derive different addresses"
        );
        let funding = text(&address_sets[0], "/0/id")?;
        self.report.record(
            "shared:activate",
            &["wallet.shared-cosigners".into()],
            Ok(()),
        );
        self.family_fund(SHARED, &parties[0], &funding, options)?;
        self.family_ready_balance(SHARED, &parties[1], FUNDING)?;
        self.report.record(
            "discovery-shared-cosigners",
            &["wallet.discovery".into()],
            Ok(()),
        );
        let path = format!("/shared-wallets/{}", parties[0]);
        let construct = self.call(
            "constructSharedTransaction",
            "POST",
            &format!("{path}/transactions-construct"),
            Some(payment),
            202,
        )?;
        let fee = number(&construct, "/fee/quantity")?;
        ensure!(
            selection_fee(
                &construct["coin_selection"],
                &destination,
                Some(options.amount)
            )? == fee,
            "shared selection fee differs"
        );
        let unsigned = text(&construct, "/transaction")?;
        let inspected = transaction::inspect(&unsigned, false)?;
        ensure!(inspected.fee == fee, "shared CBOR fee differs");
        let decoded = self.call(
            "decodeSharedTransaction",
            "POST",
            &format!("{path}/transactions-decode"),
            Some(json!({"transaction":unsigned})),
            202,
        )?;
        ensure!(
            decoded["id"] == inspected.id,
            "shared decoded transaction ID differs"
        );
        let node_before_rejection = options.node.utxos(&funding, self.timeout)?;
        for id in &parties {
            let before = self.shared_signing_state(id)?;
            let rejected = self.call(
                "signSharedTransaction",
                "POST",
                &format!("/shared-wallets/{id}/transactions-sign"),
                Some(json!({"transaction":unsigned,"passphrase":"incorrect-passphrase"})),
                403,
            )?;
            shared_wrong_passphrase(&rejected, id)?;
            ensure!(
                self.shared_signing_state(id)? == before,
                "rejected shared signing changed wallet state"
            );
            ensure!(
                options.node.utxos(&funding, self.timeout)? == node_before_rejection,
                "rejected shared signing changed independent funding UTxOs"
            );
            self.report.record(
                "shared:wrong-passphrase-preserved",
                &[
                    "api:signSharedTransaction:negative".into(),
                    "api:signSharedTransaction:status:403".into(),
                ],
                Ok(()),
            );
            self.report.evidence.last_mut().unwrap().detail = json!({"wallet":id,"rejection":rejected,
                "unsigned_transaction_id":inspected.id,"preserved_state":before,"node_utxos":node_before_rejection}).to_string();
        }
        let first = self.call(
            "signSharedTransaction",
            "POST",
            &format!("{path}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":PASSWORD})),
            202,
        )?;
        let partial = text(&first, "/transaction")?;
        let partial_inspected = transaction::inspect(&partial, true)?;
        ensure!(
            partial_inspected.id == inspected.id && partial_inspected.verification_keys.len() == 1,
            "first cosigner changed body or produced wrong witness count"
        );
        let rejected = self.call(
            "submitSharedTransaction",
            "POST",
            &format!("{path}/transactions-submit"),
            Some(json!({"transaction":partial})),
            403,
        )?;
        ensure!(
            rejected["code"] == "missing_witnesses_in_transaction"
                && rejected["info"]["detected_number_of_key_wits"] == 1
                && rejected["info"]["expected_number_of_key_wits"] == 2,
            "partial signature rejection differs"
        );
        self.report.record(
            "shared:partial-sign",
            &["wallet.shared-cosigners".into()],
            Ok(()),
        );
        let second = self.call(
            "signSharedTransaction",
            "POST",
            &format!("/shared-wallets/{}/transactions-sign", parties[1]),
            Some(json!({"transaction":partial,"passphrase":PASSWORD})),
            202,
        )?;
        let signed = text(&second, "/transaction")?;
        let signed_inspected = transaction::inspect(&signed, true)?;
        ensure!(
            signed_inspected.id == inspected.id
                && signed_inspected.verification_keys.len() == 2
                && signed_inspected
                    .verification_keys
                    .contains(&partial_inspected.verification_keys[0]),
            "second cosigner changed body or failed witness merge"
        );
        check_shared_script(&signed, &funding, &signed_inspected.verification_keys)?;
        let submitted = self.call(
            "submitSharedTransaction",
            "POST",
            &format!("{path}/transactions-submit"),
            Some(json!({"transaction":signed})),
            202,
        )?;
        ensure!(submitted["id"] == inspected.id, "shared submit ID differs");
        for id in &parties {
            let confirmed = self.family_confirm(SHARED, id, &inspected.id)?;
            ensure!(
                confirmed["direction"] == "outgoing" && number(&confirmed, "/fee/quantity")? == fee,
                "shared confirmed fee/direction differs"
            );
            self.family_ready_balance(SHARED, id, FUNDING - options.amount - fee)?;
        }
        self.family_confirm(SHELLEY, &recipient, &inspected.id)?;
        self.family_ready_balance(SHELLEY, &recipient, options.amount)?;
        options
            .node
            .payment(&inspected.id, &destination, options.amount, self.timeout)?;
        self.report.record(
            "live:shared-fully-signed",
            &[
                "wallet.shared-cosigners".into(),
                "chain.node-utxo-confirmation".into(),
                "wallet.balance-conservation".into(),
            ],
            Ok(()),
        );
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_wrong_password_requires_exact_code_message_and_wallet_info() {
        let id = "11".repeat(20);
        let expected = json!({"code":"wrong_encryption_passphrase",
            "message":format!("The given encryption passphrase doesn't match the one I use to encrypt the root private key of the given wallet: {id}"),
            "info":{"wallet_id":id}});
        shared_wrong_passphrase(&expected, &id).unwrap();
        for pointer in ["/code", "/message", "/info/wallet_id"] {
            let mut changed = expected.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("wrong");
            assert!(shared_wrong_passphrase(&changed, &id).is_err());
        }
        let mut extra = expected;
        extra["extra"] = json!(true);
        assert!(shared_wrong_passphrase(&extra, &id).is_err());
    }
    #[test]
    fn shared_payment_script_requires_both_verified_keys_and_funded_hash() {
        let keys = vec![hex::encode([1; 32]), hex::encode([2; 32])];
        let mut script = minicbor::Encoder::new(Vec::new());
        script.array(2).unwrap().u8(1).unwrap().array(2).unwrap();
        for key in &keys {
            script
                .array(2)
                .unwrap()
                .u8(0)
                .unwrap()
                .bytes(&transaction::blake2b(&hex::decode(key).unwrap(), 28).unwrap())
                .unwrap();
        }
        let script = script.into_writer();
        let mut domain = vec![0];
        domain.extend(&script);
        let mut address_bytes = vec![0x70];
        address_bytes.extend(transaction::blake2b(&domain, 28).unwrap());
        let address = crate::encoding::bech32_encode("addr_test", &address_bytes).unwrap();
        let mut raw = vec![0x84, 0xa0, 0xa1, 0x01, 0x81];
        raw.extend(&script);
        raw.extend([0xf5, 0xf6]);
        check_shared_script(&hex::encode(&raw), &address, &keys).unwrap();
        assert!(check_shared_script(
            &hex::encode(&raw),
            &address,
            &[keys[0].clone(), hex::encode([3; 32])]
        )
        .is_err());
        address_bytes[1] ^= 1;
        let wrong = crate::encoding::bech32_encode("addr_test", &address_bytes).unwrap();
        assert!(check_shared_script(&hex::encode(&raw), &wrong, &keys).is_err());
        raw[6] = 0;
        assert!(check_shared_script(&hex::encode(&raw), &address, &keys).is_err());
    }
    #[test]
    fn family_selection_rejects_duplicate_inputs_assets_and_redirected_outputs() {
        let selection = json!({"inputs":[{"id":"00","index":0,"amount":{"quantity":10000000},"assets":[]}],"outputs":[{"address":"destination","amount":{"quantity":2000000},"assets":[]}],"change":[{"address":"change","amount":{"quantity":7800000},"assets":[]}]});
        assert_eq!(
            selection_fee(&selection, "destination", Some(2000000)).unwrap(),
            200000
        );
        let mut bad = selection.clone();
        bad["inputs"]
            .as_array_mut()
            .unwrap()
            .push(selection["inputs"][0].clone());
        assert!(selection_fee(&bad, "destination", Some(2000000)).is_err());
        let mut bad = selection.clone();
        bad["outputs"][0]["address"] = json!("redirected");
        assert!(selection_fee(&bad, "destination", Some(2000000)).is_err());
        let mut bad = selection.clone();
        bad["change"][0]["assets"] = json!([{"quantity":1}]);
        assert!(selection_fee(&bad, "destination", Some(2000000)).is_err());
    }
    #[test]
    fn internal_discovery_rejects_changed_address_path_state_order_and_external_pool() {
        let address = |index: u8| {
            let mut bytes = vec![0; 57];
            bytes[1] = index;
            crate::encoding::bech32_encode("addr_test", &bytes).unwrap()
        };
        let before = Value::Array((0..21).map(|index| json!({"id":address(index),"state":if index == 0 {"used"} else {"unused"},"derivation_path":["1852H","1815H","0H","0",index.to_string()]})).collect());
        let change =
            json!({"address":address(99),"derivation_path":["1852H","1815H","0H","1","0"]});
        let mut rows = before.as_array().unwrap().clone();
        rows.insert(1, json!({"id":change["address"],"state":"used","derivation_path":change["derivation_path"]}));
        let after = Value::Array(rows);
        internal_discovery(&before, &after, &change).unwrap();
        for pointer in [
            "/1/id",
            "/1/state",
            "/1/derivation_path/3",
            "/1/derivation_path/4",
            "/2/state",
        ] {
            let mut bad = after.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("wrong");
            assert!(internal_discovery(&before, &bad, &change).is_err());
        }
        let mut bad = after.clone();
        bad.as_array_mut().unwrap().swap(0, 1);
        assert!(internal_discovery(&before, &bad, &change).is_err());
        let mut bad = after.clone();
        bad.as_array_mut().unwrap().pop();
        assert!(internal_discovery(&before, &bad, &change).is_err());
        let mut bad = change.clone();
        bad["address"] = before[0]["id"].clone();
        assert!(internal_discovery(&before, &after, &bad).is_err());
    }
}
