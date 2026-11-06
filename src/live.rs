//! Real-node integration: advancing chain, funded restore, transaction lifecycle and accounting.
use crate::{
    api::{request, Api, Contract, Response},
    report::Report,
    transaction,
};
use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    thread::sleep,
    time::{Duration, Instant},
};
mod assets;
mod balancing;
#[cfg(target_os = "linux")]
mod checkpoint;
mod concurrency;
mod delegation_fees;
mod disconnect;
mod discovery;
mod era_boundary;
pub use era_boundary::run as verify_era_boundary;
mod families;
mod history;
mod input_limits;
mod metadata;
mod parameters;
#[cfg(target_os = "linux")]
mod pending;
#[cfg(target_os = "linux")]
mod pending_byron;
#[cfg(target_os = "linux")]
mod retry;
#[cfg(target_os = "linux")]
mod rollback;
#[cfg(target_os = "linux")]
pub use pending::{run as verify_pending_state, Options as PendingOptions, RetryOptions};
#[cfg(target_os = "linux")]
pub use rollback::{run as verify_rollback, Options as RollbackOptions};
mod pool_join_guard;
mod pools;
mod precedence;
mod restart;
mod stake_rewards;
mod transport;
mod validity;
mod voting;
mod watch_only;

pub struct LiveOptions {
    pub node: crate::node::NodeOracle,
    pub timeout: Duration,
    pub faucet: Option<String>,
    pub funded_mnemonic: Option<Vec<String>>,
    pub amount: u64,
    pub families: bool,
    pub shared: bool,
    pub external_signer: Option<String>,
    pub assets: bool,
    pub payments: bool,
    pub concurrency: bool,
    pub metadata: bool,
    pub precedence: bool,
    pub validity: bool,
    pub shelley_genesis: Option<std::path::PathBuf>,
    pub byron_genesis: Option<std::path::PathBuf>,
    pub balance: bool,
    pub collateral: bool,
    pub voting: bool,
    pub delegation_fees: bool,
    pub pool_join_guard: bool,
    pub stake_pool: Option<String>,
    pub input_limits: bool,
    pub history: bool,
    pub discovery: bool,
    pub pool_directory: Option<std::path::PathBuf>,
    pub pool_workspace: Option<std::path::PathBuf>,
    pub parameter_fixture: Option<std::path::PathBuf>,
    pub parameter_workspace: Option<std::path::PathBuf>,
    pub openssl: std::path::PathBuf,
}

fn body(r: &Response) -> Result<&Value> {
    r.json.as_ref().context("missing JSON response")
}
fn text(v: &Value, p: &str) -> Result<String> {
    Ok(v.pointer(p)
        .and_then(Value::as_str)
        .context("missing string field")?
        .into())
}
fn number(v: &Value, p: &str) -> Result<u64> {
    v.pointer(p)
        .and_then(Value::as_u64)
        .context("missing unsigned integer field")
}
fn assert_eq_at(v: &Value, p: &str, expected: Value) -> Result<()> {
    ensure!(v.pointer(p) == Some(&expected), "unexpected value at {p}");
    Ok(())
}

struct Session<'a> {
    api: &'a Api,
    contract: &'a Contract,
    report: Report,
    owned: Vec<(&'static str, &'static str, String)>,
    timeout: Duration,
}

impl Session<'_> {
    fn call(
        &mut self,
        op: &str,
        method: &str,
        path: &str,
        payload: Option<Value>,
        status: u16,
    ) -> Result<Value> {
        let response = (|| -> Result<Response> {
            self.contract.check_path(op, method, path)?;
            let response = self.api.request(&request(method, path, payload))?;
            if ["postWallet", "postByronWallet", "postSharedWallet"].contains(&op)
                && response.status == 201
            {
                if let Some(id) = response.json.as_ref().and_then(|v| v["id"].as_str()) {
                    let (delete, prefix) = match op {
                        "postByronWallet" => ("deleteByronWallet", "byron-wallets"),
                        "postSharedWallet" => ("deleteSharedWallet", "shared-wallets"),
                        _ => ("deleteWallet", "wallets"),
                    };
                    self.owned.push((delete, prefix, id.into()));
                }
            }
            ensure!(
                response.status == status,
                "{op}: expected status {status}, received {}",
                response.status
            );
            self.contract.validate(op, &response)?;
            Ok(response)
        })();
        let req = format!(
            "api:{op}:{}",
            if status < 300 { "positive" } else { "negative" }
        );
        self.report.record(
            &format!("live:{op}"),
            &[req, format!("api:{op}:status:{status}")],
            response
                .as_ref()
                .map(|_| ())
                .map_err(|_| anyhow!("{op} failed contract/status/transport validation")),
        );
        let response = response?;
        Ok(response.json.unwrap_or(Value::Null))
    }

    fn poll(&mut self, op: &str, path: &str, predicate: impl Fn(&Value) -> bool) -> Result<Value> {
        let deadline = Instant::now() + self.timeout;
        loop {
            // Transient transport/schema/status failures are failures, not retryable passes.
            let response = self
                .api
                .checked(self.contract, op, request("GET", path, None), 200)?;
            let v = body(&response)?;
            if predicate(v) {
                self.report.record(
                    &format!("live:{op}:eventually"),
                    &[format!("api:{op}:positive"), format!("api:{op}:status:200")],
                    Ok(()),
                );
                return Ok(v.clone());
            }
            ensure!(
                Instant::now() < deadline,
                "{op} timed out waiting for chain state"
            );
            sleep(Duration::from_secs(1));
        }
    }

    fn create(&mut self, name: &str, mnemonic: Vec<String>) -> Result<String> {
        let v = self.call("postWallet", "POST", "/wallets", Some(json!({
            "name": name, "mnemonic_sentence": mnemonic, "passphrase": "conformance-test-passphrase",
            "address_pool_gap": 20
        })), 201)?;
        let id = text(&v, "/id")?;
        Ok(id)
    }

    fn balance(&mut self, id: &str) -> Result<u64> {
        number(
            &self.call("getWallet", "GET", &format!("/wallets/{id}"), None, 200)?,
            "/balance/available/quantity",
        )
    }

    fn check_snapshot(&mut self, id: &str, expected: u64) -> Result<()> {
        let snapshot = self.call(
            "getWalletUtxoSnapshot",
            "GET",
            &format!("/wallets/{id}/utxo"),
            None,
            200,
        )?;
        let entries = snapshot["entries"]
            .as_array()
            .context("missing UTxO entries")?;
        let total = entries.iter().try_fold(0u64, |sum, entry| {
            assert_eq_at(entry, "/ada/unit", json!("lovelace"))?;
            ensure!(
                entry["assets"] == json!([]),
                "unexpected assets in ADA-only snapshot"
            );
            sum.checked_add(number(entry, "/ada/quantity")?)
                .context("snapshot sum overflow")
        })?;
        ensure!(
            total == expected,
            "UTxO snapshot total differs from confirmed balance"
        );
        let statistics = self.call(
            "getUTxOsStatistics",
            "GET",
            &format!("/wallets/{id}/statistics/utxos"),
            None,
            200,
        )?;
        assert_eq_at(&statistics, "/total/quantity", json!(expected))?;
        assert_eq_at(&statistics, "/total/unit", json!("lovelace"))?;
        assert_eq_at(&statistics, "/scale", json!("log10"))?;
        let mut expected_distribution = std::collections::BTreeMap::<u64, u64>::new();
        let distribution = statistics["distribution"]
            .as_object()
            .context("missing histogram")?;
        let mut buckets = distribution
            .keys()
            .map(|key| Ok((key.parse::<u64>()?, 0u64)))
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
        for entry in entries {
            let coin = number(entry, "/ada/quantity")?;
            let bucket = *buckets
                .range(coin..)
                .next()
                .context("UTxO exceeds histogram buckets")?
                .0;
            *expected_distribution.entry(bucket).or_default() += 1;
        }
        for (bucket, expected_count) in &mut buckets {
            *expected_count = expected_distribution.get(bucket).copied().unwrap_or(0);
            ensure!(
                distribution[&bucket.to_string()] == json!(*expected_count),
                "UTxO histogram bucket mismatch"
            );
        }
        Ok(())
    }

    fn exercise(&mut self, options: &LiveOptions) -> Result<()> {
        let n = self.poll("getNetworkInformation", "/network/information", |v| {
            v.pointer("/sync_progress/status") == Some(&json!("ready"))
        })?;
        ensure!(
            n.pointer("/network_info/network_id") != Some(&json!("mainnet")),
            "live conformance requires a test network"
        );
        assert_eq_at(&n, "/wallet_mode", json!("node"))?;
        assert_eq_at(
            &n,
            "/network_info/protocol_magic",
            json!(options.node.network_magic),
        )?;
        let trusted_height = options.node.height(self.timeout)?;
        let height = number(&n, "/node_tip/height/quantity")?;
        self.poll("getNetworkInformation", "/network/information", |v| {
            v.pointer("/node_tip/height/quantity")
                .and_then(Value::as_u64)
                .is_some_and(|h| h > height)
        })?;
        options.node.advancing(trusted_height, self.timeout)?;
        self.report.record(
            "live:block-production",
            &["chain.block-production".into()],
            Ok(()),
        );
        let mut tips = std::collections::VecDeque::new();
        let deadline = Instant::now() + self.timeout;
        loop {
            tips.push_back(options.node.tip(self.timeout)?);
            let header = self.call(
                "getBlocksLatestHeader",
                "GET",
                "/blocks/latest/header",
                None,
                200,
            )?;
            assert_eq_at(&header, "/block_height/unit", json!("block"))?;
            assert_eq_at(&header, "/slot_no/unit", json!("slot"))?;
            tips.push_back(options.node.tip(self.timeout)?);
            if tips.iter().any(|tip| tip.matches_wallet_header(&header)) {
                break;
            }
            while tips.len() > 16 {
                tips.pop_front();
            }
            ensure!(
                Instant::now() < deadline,
                "wallet latest header does not match independently observed node tips"
            );
            sleep(Duration::from_millis(100));
        }
        self.report.record(
            "live:independent-latest-header",
            &["chain.header-consistency".into()],
            Ok(()),
        );
        self.call(
            "getNetworkParameters",
            "GET",
            "/network/parameters",
            None,
            200,
        )?;

        let mnemonic = options.funded_mnemonic.clone().unwrap_or(
            bip39::Mnemonic::generate(15)?
                .words()
                .map(str::to_owned)
                .collect(),
        );
        let sender = self.create("conformance-sender", mnemonic)?;
        let recipient_mnemonic = bip39::Mnemonic::generate(15)?
            .words()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let recipient = self.create("conformance-recipient", recipient_mnemonic.clone())?;
        for id in [&sender, &recipient] {
            self.poll("getWallet", &format!("/wallets/{id}"), |v| {
                v.pointer("/state/status") == Some(&json!("ready"))
            })?;
        }
        let sender_addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{sender}/addresses"),
            None,
            200,
        )?;
        let recipient_addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{recipient}/addresses"),
            None,
            200,
        )?;
        let destination = text(&recipient_addresses, "/0/id")?;
        if let Some(faucet) = &options.faucet {
            let faucet_api = Api::new(faucet, self.timeout)?;
            let r = faucet_api.request(&request("POST", "/send/faucet-assets", Some(json!({
                "batch-size": 1,
                "assets": [{"address": text(&sender_addresses, "/0/id")?, "bundle": {"coin": 100_000_000, "assets": []}, "metadata": []}]
            }))))?;
            ensure!(
                r.status == 204,
                "local-cluster faucet did not accept funding"
            );
        }
        let sender_path = format!("/wallets/{sender}");
        let funded = self.poll("getWallet", &sender_path, |v| {
            v.pointer("/balance/available/quantity")
                .and_then(Value::as_u64)
                .is_some_and(|x| x > options.amount.saturating_add(2_000_000))
                && v.pointer("/state/status") == Some(&json!("ready"))
        })?;
        let before_sender = number(&funded, "/balance/available/quantity")?;
        let before_recipient = self.balance(&recipient)?;
        let payment = json!({"payments": [{"address": destination, "amount": {"quantity": options.amount, "unit": "lovelace"}}]});
        let construct = self.call(
            "constructTransaction",
            "POST",
            &format!("{sender_path}/transactions-construct"),
            Some(payment.clone()),
            202,
        )?;
        let fee = number(&construct, "/fee/quantity")?;
        ensure!(fee > 0, "constructed transaction has zero fee");
        assert_eq_at(&construct, "/fee/unit", json!("lovelace"))?;
        // Coin selection must conserve ADA for a pure payment with no deposits/withdrawals.
        let selection = &construct["coin_selection"];
        let sum = |p: &str| -> Result<u64> {
            selection[p]
                .as_array()
                .context("missing coin selection array")?
                .iter()
                .try_fold(0u64, |a, x| {
                    a.checked_add(number(x, "/amount/quantity")?)
                        .context("coin selection amount overflow")
                })
        };
        let input_total = sum("inputs")?;
        let output_total = sum("outputs")?;
        let change_total = sum("change")?;
        ensure!(
            input_total
                == output_total
                    .checked_add(change_total)
                    .and_then(|x| x.checked_add(fee))
                    .context("coin selection total overflow")?,
            "coin selection fails ADA conservation"
        );
        ensure!(
            output_total == options.amount,
            "coin selection changed requested amount"
        );
        let inputs = selection["inputs"]
            .as_array()
            .context("missing selected inputs")?;
        let unique: std::collections::BTreeSet<_> = inputs
            .iter()
            .map(|v| (v["id"].to_string(), v["index"].to_string()))
            .collect();
        ensure!(
            unique.len() == inputs.len(),
            "coin selection selected an input twice"
        );
        self.report.record(
            "live:selection-conservation",
            &[
                "selection.ada-conservation".into(),
                "selection.unique-inputs".into(),
            ],
            Ok(()),
        );

        let unsigned = text(&construct, "/transaction")?;
        let decoded_unsigned = self.call(
            "decodeTransaction",
            "POST",
            &format!("{sender_path}/transactions-decode"),
            Some(json!({"transaction": unsigned})),
            202,
        )?;
        let inspected_unsigned = transaction::inspect(&unsigned, false)?;
        let selected_ids: std::collections::BTreeSet<_> = inputs
            .iter()
            .map(|input| format!("{}#{}", input["id"].as_str().unwrap_or(""), input["index"]))
            .collect();
        ensure!(
            selected_ids == inspected_unsigned.inputs.iter().cloned().collect(),
            "CBOR inputs differ from reported coin selection"
        );
        let destination_hex = hex::encode(crate::encoding::bech32(&destination)?.1);
        ensure!(
            inspected_unsigned.outputs.iter().any(
                |output| output.address_hex == destination_hex && output.coin == options.amount
            ),
            "CBOR does not pay the intended recipient"
        );
        assert_eq_at(&decoded_unsigned, "/id", json!(inspected_unsigned.id))?;
        ensure!(
            inspected_unsigned.fee == fee,
            "CBOR fee differs from API fee"
        );
        let unsigned_rejection = self.call(
            "submitTransaction",
            "POST",
            &format!("{sender_path}/transactions-submit"),
            Some(json!({"transaction":unsigned})),
            403,
        )?;
        assert_eq_at(
            &unsigned_rejection,
            "/code",
            json!("missing_witnesses_in_transaction"),
        )?;
        ensure!(
            self.balance(&sender)? == before_sender,
            "unsigned submission changed available balance"
        );
        self.report.record(
            "live:unsigned-submit-rejected",
            &["tx.invalid-signature".into()],
            Ok(()),
        );
        self.call(
            "signTransaction",
            "POST",
            &format!("{sender_path}/transactions-sign"),
            Some(json!({"transaction": unsigned, "passphrase":"incorrect-passphrase"})),
            403,
        )?;
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("{sender_path}/transactions-sign"),
            Some(json!({"transaction": unsigned, "passphrase":"conformance-test-passphrase"})),
            202,
        )?;
        let signed_tx = text(&signed, "/transaction")?;
        ensure!(
            signed_tx != unsigned,
            "signing returned unchanged transaction"
        );
        let inspected_signed = transaction::inspect(&signed_tx, true)?;
        ensure!(
            inspected_signed.id == inspected_unsigned.id,
            "signing changed the transaction body"
        );
        ensure!(
            inspected_signed.fee == fee,
            "signed CBOR fee differs from selection fee"
        );
        self.report.record(
            "live:independent-signature-verification",
            &["tx.witnesses".into(), "tx.body-hash".into()],
            Ok(()),
        );
        let decoded = self.call(
            "decodeTransaction",
            "POST",
            &format!("{sender_path}/transactions-decode"),
            Some(json!({"transaction": signed_tx})),
            202,
        )?;
        assert_eq_at(&decoded, "/fee/quantity", json!(fee))?;
        let submitted = self.call(
            "submitTransaction",
            "POST",
            &format!("{sender_path}/transactions-submit"),
            Some(json!({"transaction": signed_tx})),
            202,
        )?;
        let txid = text(&submitted, "/id")?;
        ensure!(
            txid == inspected_signed.id,
            "submitted transaction ID differs from independently hashed CBOR"
        );
        assert_eq_at(&decoded, "/id", json!(txid))?;
        let mut confirmed = Vec::new();
        for id in [&sender, &recipient] {
            let path = format!("/wallets/{id}/transactions/{txid}");
            // A recipient may not know the transaction until it observes its block.
            let deadline = Instant::now() + self.timeout;
            loop {
                let response = self.api.request(&request("GET", &path, None))?;
                self.contract.validate("getTransaction", &response)?;
                if response.status == 200 {
                    let tx = body(&response)?;
                    if tx["status"] == "in_ledger" {
                        ensure!(tx["id"] == txid, "confirmed transaction ID mismatch");
                        confirmed.push(tx.clone());
                        break;
                    }
                } else {
                    ensure!(response.status == 404, "unexpected confirmation response");
                }
                ensure!(
                    Instant::now() < deadline,
                    "transaction was not confirmed on both wallets"
                );
                sleep(Duration::from_secs(1));
            }
        }
        assert_eq_at(&confirmed[0], "/direction", json!("outgoing"))?;
        assert_eq_at(&confirmed[1], "/direction", json!("incoming"))?;
        assert_eq_at(&confirmed[0], "/fee/quantity", json!(fee))?;
        assert_eq_at(&confirmed[1], "/amount/quantity", json!(options.amount))?;
        options
            .node
            .payment(&txid, &destination, options.amount, self.timeout)?;
        self.report.record(
            "live:trusted-node-utxo-confirmation",
            &["chain.node-utxo-confirmation".into()],
            Ok(()),
        );
        let outputs = confirmed[0]["outputs"]
            .as_array()
            .context("missing confirmed outputs")?;
        ensure!(
            outputs.iter().any(|v| v["address"] == destination
                && v.pointer("/amount/quantity") == Some(&json!(options.amount))),
            "confirmed transaction missing intended payment"
        );
        // Poll balances independently of history worker scheduling.
        let want_sender = before_sender
            .checked_sub(options.amount)
            .and_then(|x| x.checked_sub(fee))
            .context("fee and payment exceed balance")?;
        let want_recipient = before_recipient
            .checked_add(options.amount)
            .context("recipient balance overflow")?;
        for (id, expected) in [(&sender, want_sender), (&recipient, want_recipient)] {
            self.poll("getWallet", &format!("/wallets/{id}"), |v| {
                v.pointer("/balance/available/quantity") == Some(&json!(expected))
            })?;
            self.check_snapshot(id, expected)?;
        }
        for change in selection["change"].as_array().context("missing change")? {
            options.node.payment(
                &txid,
                &text(change, "/address")?,
                number(change, "/amount/quantity")?,
                self.timeout,
            )?;
        }
        self.report.record(
            "live:utxo-snapshot-statistics",
            &["wallet.utxo-snapshot".into()],
            Ok(()),
        );
        self.report.record(
            "live:confirmed-transfer",
            &[
                "api:getTransaction:positive".into(),
                "api:getTransaction:status:200".into(),
                "chain.confirmation".into(),
                "tx.ledger-acceptance".into(),
                "wallet.balance-conservation".into(),
                "tx.payment-output".into(),
                "signing.wrong-passphrase".into(),
            ],
            Ok(()),
        );
        let before_restore_addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{recipient}/addresses"),
            None,
            200,
        )?;
        self.call(
            "deleteWallet",
            "DELETE",
            &format!("/wallets/{recipient}"),
            None,
            204,
        )?;
        self.owned.retain(|(_, _, id)| id != &recipient);
        let restored = self.create("conformance-recipient-restored", recipient_mnemonic)?;
        ensure!(restored == recipient, "restoration changed wallet identity");
        self.poll("getWallet", &format!("/wallets/{restored}"), |value| {
            value.pointer("/state/status") == Some(&json!("ready"))
                && value.pointer("/balance/available/quantity") == Some(&json!(want_recipient))
        })?;
        let restored_addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{restored}/addresses"),
            None,
            200,
        )?;
        ensure!(
            before_restore_addresses == restored_addresses,
            "restoration changed discovered addresses"
        );
        let restored_tx = self.call(
            "getTransaction",
            "GET",
            &format!("/wallets/{restored}/transactions/{txid}"),
            None,
            200,
        )?;
        for field in [
            "id",
            "status",
            "direction",
            "amount",
            "fee",
            "inputs",
            "outputs",
            "metadata",
            "inserted_at",
        ] {
            ensure!(
                restored_tx.get(field) == confirmed[1].get(field),
                "restoration changed transaction field {field}"
            );
        }
        self.check_snapshot(&restored, want_recipient)?;
        self.report.record(
            "live:restore-from-genesis",
            &["wallet.restoration".into()],
            Ok(()),
        );
        Ok(())
    }
}

/// The caller supplies real node-backed services. Missing funding is an error.
/// Cleanup is attempted even when the transaction scenario fails.
pub fn run(
    api: &Api,
    contract: &Contract,
    options: &LiveOptions,
    environment: &str,
    owned_process: Option<&mut crate::owned_process::WalletProcess>,
    node_proxy: Option<&crate::node_proxy::SocketProxy>,
) -> Result<Report> {
    ensure!(
        options.faucet.is_some() != options.funded_mnemonic.is_some(),
        "provide exactly one of local-cluster faucet or funded mnemonic"
    );
    ensure!(
        options.amount >= 2_000_000,
        "payment must be at least 2 ADA"
    );
    ensure!(
        !options.families || options.faucet.is_some(),
        "funded families require a dedicated local-cluster faucet"
    );
    ensure!(
        !options.shared || options.faucet.is_some(),
        "shared profile requires a dedicated local-cluster faucet"
    );
    ensure!(
        options.external_signer.is_none() || options.faucet.is_some(),
        "watch-only profile requires a dedicated local-cluster faucet"
    );
    ensure!(
        !options.assets || options.faucet.is_some(),
        "asset profile requires a dedicated local-cluster faucet"
    );
    ensure!(
        !options.payments || options.faucet.is_some(),
        "payment profile requires a dedicated local-cluster faucet"
    );
    ensure!(
        !options.concurrency || options.faucet.is_some(),
        "concurrency profile requires a dedicated local-cluster faucet"
    );
    ensure!(
        !options.metadata || options.faucet.is_some(),
        "metadata profile requires a dedicated local-cluster faucet"
    );
    ensure!(
        !options.precedence || options.faucet.is_some(),
        "precedence profile requires a dedicated local-cluster faucet"
    );
    ensure!(
        !options.validity
            || (options.faucet.is_some()
                && options.shelley_genesis.is_some()
                && options.byron_genesis.is_some()),
        "validity profile requires dedicated faucet and public Shelley genesis"
    );
    ensure!(
        !options.balance || options.faucet.is_some(),
        "balance profile requires dedicated local-cluster faucet"
    );
    ensure!(
        !options.voting || options.faucet.is_some(),
        "voting profile requires dedicated local-cluster faucet"
    );
    ensure!(
        !options.delegation_fees || options.faucet.is_some(),
        "delegation-fee reads require dedicated local-cluster faucet"
    );
    ensure!(
        !options.pool_join_guard || options.faucet.is_some(),
        "pool-join guard requires dedicated local-cluster faucet"
    );
    ensure!(
        !options.input_limits || options.faucet.is_some(),
        "input-limit profile requires dedicated faucet"
    );
    ensure!(
        !options.history
            || (options.faucet.is_some()
                && options.shelley_genesis.is_some()
                && options.byron_genesis.is_some()),
        "history profile requires dedicated faucet and public Byron/Shelley genesis"
    );
    ensure!(
        !options.discovery || options.faucet.is_some(),
        "discovery profile requires dedicated faucet"
    );
    ensure!(
        options.pool_directory.is_some() == options.pool_workspace.is_some(),
        "pool directory and fresh workspace must be supplied together"
    );
    ensure!(
        options.pool_directory.is_none()
            || (options.faucet.is_some()
                && options.shelley_genesis.is_some()
                && options.byron_genesis.is_some()),
        "pool lifecycle requires dedicated faucet and public genesis inputs"
    );
    ensure!(
        options.parameter_fixture.is_some() == options.parameter_workspace.is_some(),
        "parameter fixture and fresh workspace must be supplied together"
    );
    ensure!(
        options.parameter_fixture.is_none()
            || (options.faucet.is_some()
                && options.shelley_genesis.is_some()
                && options.byron_genesis.is_some()),
        "parameter updates require dedicated faucet and public genesis inputs"
    );
    let mut s = Session {
        api,
        contract,
        report: Report::new(&api.label, environment),
        owned: Vec::new(),
        timeout: options.timeout,
    };
    s.exercise_transport();
    let result = s.exercise(options);
    let basic_passed = result.is_ok();
    s.report.record("live:workflow", &[], result);
    if basic_passed {
        if let Some(proxy) = node_proxy {
            let result = s.exercise_disconnect(options, proxy);
            s.report.record("live:disconnect-workflow", &[], result);
        } else if let Some(process) = owned_process {
            let result = s.exercise_restart(options, process);
            s.report.record("live:restart-workflow", &[], result);
        }
    }
    if basic_passed && options.pool_join_guard {
        let result = s.exercise_pool_join_guard(options);
        s.report
            .record("live:pool-join-guard-workflow", &[], result);
    }
    if basic_passed && options.delegation_fees {
        let result = s.exercise_delegation_fees(options);
        s.report
            .record("live:delegation-fees-workflow", &[], result);
    }
    if basic_passed && options.parameter_fixture.is_some() {
        let result = s.exercise_parameters(options);
        s.report.record("live:parameters-workflow", &[], result);
    }
    if basic_passed && options.pool_directory.is_some() {
        let result = s.exercise_pools(options);
        s.report.record("live:pools-workflow", &[], result);
    }
    if basic_passed && options.discovery {
        let result = s.exercise_discovery(options);
        s.report.record("live:discovery-workflow", &[], result);
    }
    if basic_passed && options.input_limits {
        let result = s.exercise_input_limits(options);
        s.report.record("live:input-limits-workflow", &[], result);
    }
    if basic_passed && options.history {
        let result = s.exercise_history(options);
        s.report.record("live:history-workflow", &[], result);
    }
    if basic_passed && options.voting {
        let result = s.exercise_voting(options);
        s.report.record("live:voting-workflow", &[], result);
    }
    if basic_passed && options.balance {
        let result = s.exercise_balancing(options);
        s.report.record("live:balancing-workflow", &[], result);
    }
    if basic_passed && options.collateral {
        let result = s.exercise_collateral(options);
        s.report.record("live:collateral-workflow", &[], result);
    }
    if basic_passed && options.validity {
        let result = s.exercise_validity(options);
        s.report.record("live:validity-workflow", &[], result);
    }
    if basic_passed && options.precedence {
        let result = s.exercise_precedence(options);
        s.report.record("live:precedence-workflow", &[], result);
    }
    if basic_passed && options.metadata {
        let result = s.exercise_metadata(options);
        s.report.record("live:metadata-workflow", &[], result);
    }
    if basic_passed && options.concurrency {
        let result = s.exercise_concurrency(options);
        s.report.record("live:concurrency-workflow", &[], result);
    }
    if basic_passed && options.payments {
        let result = s.exercise_payments(options);
        s.report.record("live:payments-workflow", &[], result);
    }
    if basic_passed && options.assets {
        let result = s.exercise_assets(options);
        s.report.record("live:assets-workflow", &[], result);
    }
    if basic_passed && options.stake_pool.is_some() {
        let result = s.exercise_stake_rewards(options);
        s.report.record("live:stake-rewards-workflow", &[], result);
    }
    if basic_passed && options.external_signer.is_some() {
        let result = s.exercise_watch_only(options, environment);
        s.report.record("live:watch-only-workflow", &[], result);
    }
    if basic_passed && options.shared {
        let result = s.exercise_shared(options);
        s.report.record("live:shared-workflow", &[], result);
    }
    if basic_passed && options.families {
        let result = s.exercise_families(options);
        s.report.record("live:families-workflow", &[], result);
    }
    for (delete, prefix, id) in std::mem::take(&mut s.owned).into_iter().rev() {
        let result = s
            .call(delete, "DELETE", &format!("/{prefix}/{id}"), None, 204)
            .map(|_| ());
        s.report.record("live:cleanup-owned-wallet", &[], result);
    }
    Ok(s.report)
}

#[cfg(test)]
mod scheduling_tests {
    #[test]
    fn owned_fault_controls_precede_every_optional_wallet_profile() {
        let source = include_str!("live.rs");
        let run = &source[source.find("s.report.record(\"live:workflow\"").unwrap()..];
        let fault = run.find("s.exercise_disconnect(options, proxy)").unwrap();
        let restart = run.find("s.exercise_restart(options, process)").unwrap();
        for optional in [
            "s.exercise_pool_join_guard",
            "s.exercise_delegation_fees",
            "s.exercise_parameters",
            "s.exercise_pools",
            "s.exercise_discovery",
        ] {
            assert!(fault < run.find(optional).unwrap());
            assert!(restart < run.find(optional).unwrap());
        }
    }
}
