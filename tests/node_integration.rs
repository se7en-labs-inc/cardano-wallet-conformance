//! Opt-in real-node oracle integration. Missing configuration is an error, not a skip.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    thread::sleep,
    time::{Duration, Instant},
};
use wallet_conformance::{
    api::{request, Api},
    node::NodeOracle,
};

#[test]
fn real_node_faucet_creates_a_fresh_exact_recipient_utxo() -> Result<()> {
    let node = NodeOracle {
        executable: PathBuf::from(
            std::env::var("CONFORMANCE_CARDANO_CLI")
                .context("CONFORMANCE_CARDANO_CLI is required")?,
        ),
        socket: PathBuf::from(
            std::env::var("CONFORMANCE_NODE_SOCKET")
                .context("CONFORMANCE_NODE_SOCKET is required")?,
        ),
        network_magic: std::env::var("CONFORMANCE_NODE_MAGIC")
            .context("CONFORMANCE_NODE_MAGIC is required")?
            .parse()?,
    };
    let timeout = Duration::from_secs(60);
    let vectors: Value =
        serde_json::from_str(include_str!("../fixtures/vectors/haskell-keys.json"))?;
    let address = vectors
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "haskell-Shelley-0-0-0-enterprise-0")
        .context("missing public test address vector")?["expected"]["result"]["address"]
        .as_str()
        .context("missing oracle address")?;
    let height = node.height(timeout)?;
    node.advancing(height, timeout)?;
    let before = node.utxos(address, timeout)?;
    let before: BTreeSet<_> = before
        .as_object()
        .context("invalid node UTxO result")?
        .keys()
        .cloned()
        .collect();
    let faucet = Api::new(
        &std::env::var("CONFORMANCE_FAUCET_URL").context("CONFORMANCE_FAUCET_URL is required")?,
        timeout,
    )?;
    let response = faucet.request(&request("POST","/send/faucet-assets",Some(json!({
        "batch-size":1,"assets":[{"address":address,"bundle":{"coin":100_000_000,"assets":[]},"metadata":[]}]
    }))))?;
    ensure!(
        response.status == 204,
        "real cluster faucet rejected funding"
    );
    let deadline = Instant::now() + timeout;
    loop {
        let utxos = node.utxos(address, timeout)?;
        for id in utxos
            .as_object()
            .context("invalid node UTxO result")?
            .keys()
        {
            if !before.contains(id) {
                let txid = id.split('#').next().context("malformed node UTxO input")?;
                node.payment(txid, address, 100_000_000, timeout)?;
                return Ok(());
            }
        }
        ensure!(
            Instant::now() < deadline,
            "faucet payment was not observed independently on the node"
        );
        sleep(Duration::from_millis(200));
    }
}
