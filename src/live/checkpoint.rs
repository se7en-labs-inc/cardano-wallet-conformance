//! Real checkpoint negotiation and independently funded catch-up while the wallet is offline.
use super::{families::SHELLEY, pending::same_tip, *};
use crate::{
    chain_observer::{Event, Observer, Point},
    cluster_control::Cluster,
    node::{NodeOracle, Tip},
    node_proxy::SocketProxy,
    owned_process::{require_unused_listener, WalletProcess},
};
use std::{collections::BTreeSet, path::Path};
const INITIAL: u64 = 100_000_000;
const OFFLINE: u64 = 2_000_000;

fn stable_tip(node: &NodeOracle, timeout: Duration) -> Result<Tip> {
    let deadline = Instant::now() + timeout;
    let mut stable = node.tip(timeout)?;
    let mut samples = 0;
    while samples < 3 {
        sleep(Duration::from_millis(200));
        let next = node.tip(timeout)?;
        if same_tip(&stable, &next).is_ok() {
            samples += 1;
        } else {
            samples = 0;
            stable = next;
        }
        ensure!(
            Instant::now() < deadline,
            "checkpoint paused native tip did not stabilize"
        );
    }
    Ok(stable)
}
fn tip_json(tip: &Tip) -> Value {
    json!({"slot":tip.slot,"height":tip.height,"hash":tip.hash})
}
fn snapshot_transition(before: &Value, after: &Value, original: &str, added: &str) -> Result<()> {
    ensure!(
        before["account_key"] == after["account_key"] && before["addresses"] == after["addresses"],
        "checkpoint changed persisted keys/addresses"
    );
    let mut wallet = before["wallet"].clone();
    ensure!(
        wallet["balance"]
            == json!({"available":{"quantity":INITIAL,"unit":"lovelace"},"total":{"quantity":INITIAL,"unit":"lovelace"},"reward":{"quantity":0,"unit":"lovelace"}}),
        "checkpoint initial balance differs"
    );
    wallet["balance"]["available"]["quantity"] = json!(INITIAL + OFFLINE);
    wallet["balance"]["total"]["quantity"] = json!(INITIAL + OFFLINE);
    ensure!(
        wallet == after["wallet"],
        "checkpoint changed wallet identity/state or catch-up balance"
    );
    let old = before["history"]
        .as_array()
        .context("checkpoint old history missing")?;
    let new = after["history"]
        .as_array()
        .context("checkpoint new history missing")?;
    ensure!(
        old.len() == 1 && old[0]["id"] == original && new.len() == 2,
        "checkpoint history identities/count differ"
    );
    ensure!(
        new.iter().find(|v| v["id"] == original) == Some(&old[0]),
        "checkpoint changed original confirmed history"
    );
    let added = new
        .iter()
        .find(|v| v["id"] == added)
        .context("checkpoint missing offline payment history")?;
    ensure!(
        added["status"] == "in_ledger"
            && added["direction"] == "incoming"
            && added["amount"] == json!({"quantity":OFFLINE,"unit":"lovelace"}),
        "checkpoint offline payment accounting differs"
    );
    let mut expected = before["utxo"]["entries"]
        .as_array()
        .context("checkpoint old UTxO entries missing")?
        .clone();
    expected.push(json!({"ada":{"quantity":OFFLINE,"unit":"lovelace"},"assets":[]}));
    let sorted = |entries: &[Value]| -> Result<Vec<String>> {
        let mut out = entries
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        out.sort();
        Ok(out)
    };
    ensure!(
        sorted(&expected)?
            == sorted(
                after["utxo"]["entries"]
                    .as_array()
                    .context("checkpoint new UTxO entries missing")?
            )?,
        "checkpoint UTxO snapshot differs from exact offline addition"
    );
    Ok(())
}
fn accepted_checkpoint(
    snapshot: &crate::chain_observer::Snapshot,
    before: &Tip,
    after: &Tip,
) -> Result<Value> {
    ensure!(
        snapshot.errors.is_empty(),
        "checkpoint observation errors: {:?}",
        snapshot.errors
    );
    ensure!(
        after.height > before.height && after.slot > before.slot,
        "checkpoint has no actual offline chain advance"
    );
    for event in &snapshot.observations {
        if let Event::Accepted {
            point: Point::Block { slot, hash },
            tip,
        } = &event.event
        {
            if *slot > 0 && *slot <= before.slot {
                if let Point::Block {
                    slot: tip_slot,
                    hash: tip_hash,
                } = &tip.point
                {
                    if *tip_slot == after.slot
                        && tip_hash == &after.hash
                        && tip.height == Some(after.height)
                    {
                        return Ok(
                            json!({"connection":event.connection,"checkpoint":{"slot":slot,"hash":hash},"native_tip":tip_json(after),"observation":snapshot}),
                        );
                    }
                }
            }
        }
    }
    anyhow::bail!("no actual accepted pre-stop non-genesis checkpoint at the advanced native tip")
}
impl Session<'_> {
    fn checkpoint_wallet_tip(&mut self, id: &str, tip: &Tip) -> Result<()> {
        self.poll("getWallet", &format!("/wallets/{id}"), |v| {
            v["state"]["status"] == "ready"
                && v["tip"]["absolute_slot_number"] == tip.slot
                && v["tip"]["height"] == json!({"quantity":tip.height,"unit":"block"})
        })?;
        let header = self.call(
            "getBlocksLatestHeader",
            "GET",
            "/blocks/latest/header",
            None,
            200,
        )?;
        ensure!(
            tip.matches_wallet_header(&header),
            "checkpoint chain-source header differs from native hash/slot/height"
        );
        Ok(())
    }
    fn checkpoint_fund(
        &self,
        node: &NodeOracle,
        faucet: &str,
        address: &str,
        amount: u64,
        before: &Value,
    ) -> Result<(String, Value)> {
        let response=Api::new(faucet,self.timeout)?.request(&request("POST","/send/faucet-assets",Some(json!({"batch-size":1,"assets":[{"address":address,"bundle":{"coin":amount,"assets":[]},"metadata":[]}]}))))?;
        ensure!(response.status == 204, "checkpoint faucet funding rejected");
        let deadline = Instant::now() + self.timeout;
        loop {
            let after = node.utxos(address, self.timeout)?;
            let entries = after
                .as_object()
                .context("checkpoint native funding missing")?;
            let old = before
                .as_object()
                .context("checkpoint native baseline missing")?;
            ensure!(
                old.iter()
                    .all(|(key, value)| entries.get(key) == Some(value)),
                "checkpoint funding changed an existing native input"
            );
            let fresh: Vec<_> = entries
                .iter()
                .filter(|(key, _)| !old.contains_key(*key))
                .collect();
            ensure!(
                fresh.len() <= 1,
                "checkpoint faucet created extra owned outputs"
            );
            if let Some((reference, output)) = fresh.first() {
                ensure!(
                    output["address"] == address && output["value"] == json!({"lovelace":amount}),
                    "checkpoint exact incoming native output differs"
                );
                let id = reference
                    .split_once('#')
                    .context("checkpoint invalid native reference")?
                    .0
                    .to_owned();
                node.payment(&id, address, amount, self.timeout)?;
                return Ok((id, after));
            }
            ensure!(
                Instant::now() < deadline,
                "checkpoint native funding timeout"
            );
            sleep(Duration::from_millis(200));
        }
    }
    pub(super) fn checkpoint_workflow(
        &mut self,
        node: &NodeOracle,
        cluster: &Cluster,
        process: &mut WalletProcess,
        proxy: &SocketProxy,
        faucet: &str,
        observer: &Observer,
    ) -> Result<Value> {
        let id = self.create(
            "conformance-checkpoint",
            bip39::Mnemonic::generate(15)?
                .words()
                .map(str::to_owned)
                .collect(),
        )?;
        self.family_ready_balance(SHELLEY, &id, 0)?;
        let addresses = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{id}/addresses"),
            None,
            200,
        )?;
        let address = text(&addresses, "/0/id")?;
        ensure!(
            node.utxos(&address, self.timeout)? == json!({}),
            "checkpoint wallet is not fresh"
        );
        let (original, funding) =
            self.checkpoint_fund(node, faucet, &address, INITIAL, &json!({}))?;
        self.family_ready_balance(SHELLEY, &id, INITIAL)?;
        self.family_confirm(SHELLEY, &id, &original)?;
        let paused = cluster.pause(self.timeout)?;
        let before_tip = stable_tip(node, self.timeout)?;
        self.checkpoint_wallet_tip(&id, &before_tip)?;
        let before = self.pending_snapshot(&id)?;
        let old_pid = process.ensure_running()?;
        process.stop()?;
        ensure!(
            !Path::new(&format!("/proc/{old_pid}")).exists(),
            "checkpoint old owned child still exists"
        );
        require_unused_listener(&self.api.label)?;
        proxy.pause(self.timeout)?;
        proxy.observe_while_paused(observer.clone())?;
        proxy.resume()?;
        self.report
            .record("checkpoint:stopped-with-persisted-state", &[], Ok(()));
        self.report.evidence.last_mut().unwrap().detail=json!({"old_pid":old_pid,"pre_stop_tip":tip_json(&before_tip),"snapshot":before,"native_funding":funding}).to_string();
        paused.resume()?;
        node.advancing(before_tip.height, self.timeout)?;
        let (added, native_after) =
            self.checkpoint_fund(node, faucet, &address, OFFLINE, &funding)?;
        ensure!(
            process.ensure_running().is_err(),
            "checkpoint wallet restarted during offline funding"
        );
        require_unused_listener(&self.api.label)?;
        let paused = cluster.pause(self.timeout)?;
        let after_tip = stable_tip(node, self.timeout)?;
        ensure!(
            after_tip.slot > before_tip.slot && after_tip.height > before_tip.height,
            "checkpoint offline chain did not advance"
        );
        process.restart_stopped()?;
        let new_pid = process.ensure_running()?;
        ensure!(
            old_pid != new_pid,
            "checkpoint did not restart a distinct owned child"
        );
        process.wait_listener(&self.api.label, self.timeout)?;
        self.family_ready_balance(SHELLEY, &id, INITIAL + OFFLINE)?;
        self.checkpoint_wallet_tip(&id, &after_tip)?;
        let after = self.pending_snapshot(&id)?;
        snapshot_transition(&before, &after, &original, &added)?;
        let snapshot = observer.snapshot();
        let checkpoint = accepted_checkpoint(&snapshot, &before_tip, &after_tip)?;
        ensure!(
            node.utxos(&address, self.timeout)? == native_after,
            "checkpoint catch-up changed independent funding"
        );
        let known: BTreeSet<_> = addresses
            .as_array()
            .unwrap()
            .iter()
            .map(|v| text(v, "/id"))
            .collect::<Result<_>>()?;
        ensure!(
            known.contains(&address),
            "checkpoint funded address is not owned"
        );
        same_tip(&after_tip, &node.tip(self.timeout)?)?;
        self.call(
            "deleteWallet",
            "DELETE",
            &format!("/wallets/{id}"),
            None,
            204,
        )?;
        self.owned
            .retain(|(_, prefix, wallet)| !(*prefix == "wallets" && wallet == &id));
        process.stop()?;
        proxy.pause(self.timeout)?;
        let closed = observer.snapshot();
        accepted_checkpoint(&closed, &before_tip, &after_tip)?;
        let proof = json!({"wallet_id":id,"old_wallet_pid":old_pid,"new_wallet_pid":new_pid,"before":before,"after":after,"original_transaction":original,"offline_transaction":added,"native_before":funding,"native_after":native_after,"pre_stop_tip":tip_json(&before_tip),"post_offline_tip":tip_json(&after_tip),"checkpoint":checkpoint,"closed_observation":closed,"executable_sha256":process.executable_sha256()});
        paused.resume()?;
        self.report
            .record("checkpoint:restored-and-caught-up", &[], Ok(()));
        self.report.evidence.last_mut().unwrap().detail = proof.to_string();
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_observer::{Observation, Snapshot, Tip as WireTip};
    #[test]
    fn checkpoint_credit_rejects_origin_future_point_wrong_native_hash_and_observer_errors() {
        let before = Tip {
            slot: 100,
            height: 20,
            hash: "aa".repeat(32),
        };
        let after = Tip {
            slot: 120,
            height: 30,
            hash: "bb".repeat(32),
        };
        let observation = |point, tip| Snapshot {
            connections: 1,
            errors: Vec::new(),
            observations: vec![Observation {
                connection: 9,
                event: Event::Accepted { point, tip },
            }],
        };
        let advanced = WireTip {
            point: Point::Block {
                slot: 120,
                hash: after.hash.clone(),
            },
            height: Some(30),
        };
        let checkpoint = Point::Block {
            slot: 99,
            hash: "cc".repeat(32),
        };
        accepted_checkpoint(
            &observation(checkpoint.clone(), advanced.clone()),
            &before,
            &after,
        )
        .unwrap();
        for point in [
            Point::Origin,
            Point::Block {
                slot: 0,
                hash: "cc".repeat(32),
            },
            Point::Block {
                slot: 101,
                hash: "cc".repeat(32),
            },
        ] {
            assert!(
                accepted_checkpoint(&observation(point, advanced.clone()), &before, &after)
                    .is_err()
            );
        }
        for tip in [
            WireTip {
                point: Point::Block {
                    slot: 120,
                    hash: "dd".repeat(32),
                },
                height: Some(30),
            },
            WireTip {
                point: Point::Block {
                    slot: 119,
                    hash: after.hash.clone(),
                },
                height: Some(30),
            },
            WireTip {
                point: advanced.point.clone(),
                height: Some(29),
            },
        ] {
            assert!(
                accepted_checkpoint(&observation(checkpoint.clone(), tip), &before, &after)
                    .is_err()
            );
        }
        let mut invalid = observation(checkpoint, advanced);
        invalid.errors.push("truncated observed stream".into());
        assert!(accepted_checkpoint(&invalid, &before, &after).is_err());
        assert!(accepted_checkpoint(&invalid, &before, &before).is_err());
    }
}
