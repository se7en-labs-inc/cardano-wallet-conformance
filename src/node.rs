//! Independent node oracle using the trusted Haskell cardano-cli, not the wallet CLI.
use anyhow::{ensure, Context, Result};
use serde_json::Value;
use std::{
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

pub struct NodeOracle {
    pub executable: PathBuf,
    pub socket: PathBuf,
    pub network_magic: u32,
}

#[derive(Debug)]
pub struct Tip {
    pub height: u64,
    pub slot: u64,
    pub hash: String,
}

impl Tip {
    pub fn matches_wallet_header(&self, header: &Value) -> bool {
        header
            .pointer("/block_height/quantity")
            .and_then(Value::as_u64)
            == Some(self.height)
            && header.pointer("/slot_no/quantity").and_then(Value::as_u64) == Some(self.slot)
            && header["header_hash"].as_str() == Some(&self.hash)
    }
}

impl NodeOracle {
    pub fn mempool_info(&self, timeout: Duration) -> Result<Value> {
        self.query(&["tx-mempool", "info"], timeout)
    }
    pub fn stake_pools(&self, timeout: Duration) -> Result<Value> {
        self.query(&["stake-pools"], timeout)
    }
    pub fn stake_address_info(&self, address: &str, timeout: Duration) -> Result<Value> {
        self.query(&["stake-address-info", "--address", address], timeout)
    }
    pub fn protocol_parameters(&self, timeout: Duration) -> Result<Value> {
        self.query(&["protocol-parameters"], timeout)
    }
    pub(crate) fn query(&self, query: &[&str], timeout: Duration) -> Result<Value> {
        let mut child = Command::new(&self.executable)
            .args(["latest", "query"])
            .args(query)
            .arg("--socket-path")
            .arg(&self.socket)
            .arg("--testnet-magic")
            .arg(self.network_magic.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("cannot start trusted cardano-cli node query")?;
        let stdout = child
            .stdout
            .take()
            .context("node query stdout unavailable")?;
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .take(1_048_577)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = tx.send(result);
        });
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("trusted node query timed out");
            }
            thread::sleep(Duration::from_millis(10));
        };
        ensure!(status.success(), "trusted node query failed");
        let bytes = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .context("node query output did not close")??;
        ensure!(bytes.len() <= 1_048_576, "node query output exceeds 1 MiB");
        serde_json::from_slice(&bytes).context("trusted node query returned invalid JSON")
    }

    pub fn height(&self, timeout: Duration) -> Result<u64> {
        Ok(self.tip(timeout)?.height)
    }

    pub fn tip(&self, timeout: Duration) -> Result<Tip> {
        let value = self.query(&["tip"], timeout)?;
        let hash = value["hash"]
            .as_str()
            .context("trusted node tip has no hash")?;
        ensure!(
            hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid trusted tip hash"
        );
        Ok(Tip {
            height: value["block"]
                .as_u64()
                .context("trusted node tip has no block height")?,
            slot: value["slot"]
                .as_u64()
                .context("trusted node tip has no slot")?,
            hash: hash.into(),
        })
    }

    pub fn advancing(&self, before: u64, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.height(timeout)? > before {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "trusted node did not produce a new block"
            );
            thread::sleep(Duration::from_millis(200));
        }
    }

    pub fn payment(&self, txid: &str, address: &str, amount: u64, timeout: Duration) -> Result<()> {
        let utxos = self.utxos(address, timeout)?;
        validate_payment(&utxos, txid, address, amount)
    }

    /// Wait for exact pure-ADA inclusion; only absence is transient.
    /// State-preservation assertions should continue using `payment`.
    pub fn wait_payment(
        &self,
        txid: &str,
        address: &str,
        amount: u64,
        timeout: Duration,
    ) -> Result<()> {
        wait_payment_with(txid, address, amount, timeout, |remaining| {
            self.utxos(address, remaining)
        })
    }

    pub fn utxos(&self, address: &str, timeout: Duration) -> Result<Value> {
        self.query(&["utxo", "--address", address, "--output-json"], timeout)
    }

    pub fn payment_assets(
        &self,
        txid: &str,
        address: &str,
        amount: u64,
        assets: &std::collections::BTreeMap<String, u64>,
        timeout: Duration,
    ) -> Result<()> {
        validate_asset_payment(
            &self.utxos(address, timeout)?,
            txid,
            address,
            amount,
            assets,
        )
    }
}

fn wait_payment_with(
    txid: &str,
    address: &str,
    amount: u64,
    timeout: Duration,
    mut query: impl FnMut(Duration) -> Result<Value>,
) -> Result<()> {
    ensure!(
        txid.len() == 64 && txid.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid submitted transaction ID"
    );
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "exact native payment inclusion timed out"
        );
        let utxos = query(remaining)?;
        let entries = utxos
            .as_object()
            .context("trusted node UTxO result is not an object")?;
        if entries.keys().any(|id| {
            id.strip_prefix(txid)
                .is_some_and(|suffix| suffix.starts_with('#'))
        }) {
            return validate_asset_payment(&utxos, txid, address, amount, &Default::default());
        }
        thread::sleep(
            Duration::from_millis(200).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

/// Reconcile every native asset in matching node outputs, including empty names.
pub fn validate_asset_payment(
    utxos: &Value,
    txid: &str,
    address: &str,
    amount: u64,
    expected: &std::collections::BTreeMap<String, u64>,
) -> Result<()> {
    validate_payment(utxos, txid, address, amount)?;
    let mut actual = std::collections::BTreeMap::<String, u64>::new();
    for (id, output) in utxos.as_object().context("node UTxO is not object")? {
        if !id
            .strip_prefix(txid)
            .is_some_and(|suffix| suffix.starts_with('#'))
        {
            continue;
        }
        for (policy, tokens) in output["value"]
            .as_object()
            .context("node output value missing")?
        {
            if policy == "lovelace" {
                continue;
            }
            ensure!(
                hex::decode(policy)?.len() == 28,
                "node policy ID length differs"
            );
            for (name, quantity) in tokens.as_object().context("node token map missing")? {
                ensure!(
                    hex::decode(name)?.len() <= 32,
                    "node asset name exceeds bound"
                );
                let quantity = quantity.as_u64().context("node token quantity invalid")?;
                let total = actual.entry(format!("{policy}.{name}")).or_default();
                *total = total
                    .checked_add(quantity)
                    .context("node token total overflow")?;
            }
        }
    }
    ensure!(
        actual == *expected,
        "real node native asset quantities differ"
    );
    Ok(())
}

/// Verify exact transaction identity, output address and total ADA from the node's
/// own UTxO set. Wallet history alone is not evidence of ledger inclusion.
pub fn validate_payment(utxos: &Value, txid: &str, address: &str, amount: u64) -> Result<()> {
    ensure!(
        txid.len() == 64 && txid.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid submitted transaction ID"
    );
    let mut total = 0u64;
    let mut count = 0;
    for (id, output) in utxos
        .as_object()
        .context("trusted node UTxO result is not an object")?
    {
        if id
            .strip_prefix(txid)
            .is_some_and(|suffix| suffix.starts_with('#'))
        {
            ensure!(
                output["address"] == address,
                "trusted node output address mismatch"
            );
            let coin = output
                .pointer("/value/lovelace")
                .and_then(Value::as_u64)
                .context("trusted node output has no lovelace amount")?;
            total = total
                .checked_add(coin)
                .context("trusted node output amount overflow")?;
            count += 1;
        }
    }
    ensure!(
        count > 0,
        "submitted transaction is absent from the real node's recipient UTxO set"
    );
    ensure!(
        total == amount,
        "real node recipient amount differs from requested payment"
    );
    Ok(())
}
#[cfg(test)]
mod inclusion_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exact_inclusion_retries_absence_and_unrelated_transactions() {
        let id = "ab".repeat(32);
        let other = format!("{}#0", "cd".repeat(32));
        let exact = format!("{id}#0");
        let mut calls = 0;
        wait_payment_with(&id, "recipient", 2_000_000, Duration::from_secs(2), |_| {
            calls += 1;
            Ok(if calls == 1 {
                json!({&other:{"address":"recipient","value":{"lovelace":2_000_000}}})
            } else {
                json!({&exact:{"address":"recipient","value":{"lovelace":2_000_000}}})
            })
        })
        .unwrap();
        assert_eq!(calls, 2);
    }

    #[test]
    fn matching_invalid_outputs_and_query_errors_are_never_retried() {
        let id = "ab".repeat(32);
        let key = format!("{id}#0");
        let policy = "ef".repeat(28);
        for value in [
            json!([]),
            json!({&key:{"address":"wrong","value":{"lovelace":2_000_000}}}),
            json!({&key:{"address":"recipient","value":{"lovelace":1}}}),
            json!({&key:{"address":"recipient","value":{"lovelace":2_000_000,&policy:{"":1}}}}),
        ] {
            let mut calls = 0;
            assert!(
                wait_payment_with(&id, "recipient", 2_000_000, Duration::from_secs(1), |_| {
                    calls += 1;
                    Ok(value.clone())
                })
                .is_err()
            );
            assert_eq!(calls, 1);
        }
        let mut calls = 0;
        assert!(
            wait_payment_with(&id, "recipient", 2_000_000, Duration::from_secs(1), |_| {
                calls += 1;
                anyhow::bail!("query failure")
            })
            .is_err()
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn absent_output_times_out_within_one_deadline() {
        let started = Instant::now();
        assert!(wait_payment_with(
            &"ab".repeat(32),
            "recipient",
            2_000_000,
            Duration::from_millis(5),
            |_| Ok(json!({}))
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
