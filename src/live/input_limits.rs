//! Real preselected-input size boundary, independently sized and node-confirmed.
use super::{families::SHELLEY, *};
use anyhow::Context as _;
use std::collections::{BTreeMap, BTreeSet};
const COIN: u64 = 1_000_000;
const TOTAL: u64 = 600 * COIN;
const SURPLUS: u64 = 12 * COIN;
const PASSWORD: &str = "conformance-test-passphrase";
type References = Vec<(String, u64)>;
fn references(value: &Value, address: &str) -> Result<References> {
    let entries = value
        .as_object()
        .context("invalid many-input funding map")?;
    ensure!(
        entries.len() == 600,
        "many-input funding does not have600outputs"
    );
    let mut groups = BTreeMap::<String, BTreeSet<u64>>::new();
    let mut result = Vec::new();
    for (reference, output) in entries {
        ensure!(
            output["address"] == address && output["value"] == json!({"lovelace":COIN}),
            "many-input funding address/value/assets differ"
        );
        let (id, index) = reference
            .split_once('#')
            .context("malformed funding reference")?;
        ensure!(hex::decode(id)?.len() == 32, "funding hash length differs");
        let index = index.parse::<u64>()?;
        groups.entry(id.into()).or_default().insert(index);
        result.push((id.into(), index));
    }
    ensure!(
        groups.len() == 6
            && groups
                .values()
                .all(|indices| *indices == (0..100).collect()),
        "funding is not six100-output batches"
    );
    result.sort();
    Ok(result)
}
fn raw_partial(inputs: &[(String, u64)], destination: &str, ttl: u64) -> Result<Vec<u8>> {
    ensure!(
        (23..=600).contains(&inputs.len()),
        "input probe is outside source-grounded bracket"
    );
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4)?
        .map(4)?
        .u8(0)?
        .tag(minicbor::data::Tag::new(258))?
        .begin_array()?;
    for (hash, index) in inputs {
        e.array(2)?.bytes(&hex::decode(hash)?)?.u64(*index)?;
    }
    e.end()?
        .u8(1)?
        .array(1)?
        .array(2)?
        .bytes(&crate::encoding::bech32(destination)?.1)?
        .u64(inputs.len() as u64 * COIN - SURPLUS)?
        .u8(2)?
        .u8(0)?
        .u8(3)?
        .u64(ttl)?;
    e.map(0)?.bool(true)?.null()?;
    Ok(e.into_writer())
}
fn shape(encoded: &str) -> Result<()> {
    let raw = hex::decode(encoded).or_else(|_| {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| hex::FromHexError::InvalidStringLength)
    })?;
    let mut d = minicbor::Decoder::new(&raw);
    ensure!(
        d.array()? == Some(4) && d.map()? == Some(4),
        "size control has extra transaction fields"
    );
    let mut keys = BTreeSet::new();
    for _ in 0..4 {
        let key = d.u64()?;
        ensure!(keys.insert(key), "duplicate size control key");
        match key {
            0 => {
                ensure!(d.tag()?.as_u64() == 258, "size control input tag differs");
                let length = d.array()?;
                let mut count = 0;
                loop {
                    if let Some(length) = length {
                        if count == length {
                            break;
                        }
                    } else if d.datatype()? == minicbor::data::Type::Break {
                        d.skip()?;
                        break;
                    }
                    ensure!(
                        d.array()? == Some(2) && d.bytes()?.len() == 32,
                        "size control input pair/hash differs"
                    );
                    d.u64()?;
                    count += 1;
                }
                ensure!(
                    count > 0
                        && match length {
                            Some(n) => n <= 23,
                            None => count > 23,
                        },
                    "size control input framing differs"
                );
            }
            1 => {
                ensure!(
                    d.array()? == Some(2),
                    "size control must have requested and change outputs"
                );
                for _ in 0..2 {
                    ensure!(
                        d.array()? == Some(2),
                        "size control output has datum/script/alternate framing"
                    );
                    ensure!(
                        d.bytes()?.len() == 57,
                        "size control output is not a base address"
                    );
                    d.u64()?;
                }
            }
            2 | 3 => {
                d.u64()?;
            }
            _ => anyhow::bail!("unexpected size control field"),
        }
    }
    ensure!(
        keys == BTreeSet::from([0, 1, 2, 3]) && d.map()? == Some(0) && d.bool()?,
        "size control fields/witnesses/validity differ"
    );
    d.null()?;
    ensure!(d.position() == raw.len(), "trailing size control bytes");
    Ok(())
}
struct Balanced {
    encoded: String,
    tx: transaction::Transaction,
    size: u64,
    change: usize,
}
struct Context<'a> {
    references: &'a References,
    destination: &'a str,
    funding_address: &'a str,
    ttl: u64,
    parameters: &'a Value,
}
fn sized(encoded: &str, context: &Context<'_>) -> Result<u64> {
    use base64::Engine;
    let raw = hex::decode(encoded).or_else(|_| {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| hex::FromHexError::InvalidStringLength)
    })?;
    let count = transaction::inspect(encoded, false)?.inputs.len();
    let result = crate::signed_size::estimate(&json!({"transaction_cbor_hex":hex::encode(raw),
        "vkey_witnesses":count,"bootstrap_witnesses":0,"protocol_major":number(context.parameters,"/protocolVersion/major")?,
        "maximum_transaction_bytes":number(context.parameters,"/maxTxSize")?}))?;
    number(&result, "/estimated_bytes")
}
fn selected_inputs(
    inputs: &[String],
    count: usize,
    context: &Context<'_>,
    exact: bool,
) -> Result<usize> {
    ensure!(
        count <= context.references.len(),
        "requested inputs exceed funding"
    );
    let known: Vec<_> = context
        .references
        .iter()
        .map(|(hash, index)| format!("{hash}#{index}"))
        .collect();
    let selected: BTreeSet<_> = inputs.iter().cloned().collect();
    ensure!(selected.len() == inputs.len(), "duplicate selected input");
    ensure!(
        known[..count]
            .iter()
            .all(|reference| selected.contains(reference)),
        "preselected input omitted"
    );
    let canonical: Vec<_> = known
        .iter()
        .filter(|reference| selected.contains(*reference))
        .cloned()
        .collect();
    ensure!(
        inputs == canonical,
        "selected input ineligible or noncanonical"
    );
    ensure!(
        !exact || inputs == &known[..count],
        "final input boundary contains extra inputs"
    );
    Ok(inputs.len())
}
fn balanced(value: &Value, count: usize, context: &Context<'_>) -> Result<Balanced> {
    let encoded = text(value, "/transaction")?;
    shape(&encoded)
        .with_context(|| format!("returned unsigned size-control transaction: {encoded}"))?;
    let tx = transaction::inspect(&encoded, false)?;
    let selected = selected_inputs(&tx.inputs, count, context, false)?;
    ensure!(
        tx.verification_keys.is_empty() && tx.outputs.len() == 2,
        "size control witness/output shape differs"
    );
    ensure!(
        transaction::validity(&encoded)? == (None, Some(context.ttl)),
        "size control changed TTL"
    );
    let destination = hex::encode(crate::encoding::bech32(context.destination)?.1);
    let payment = count as u64 * COIN - SURPLUS;
    let requested: Vec<_> = tx
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, output)| output.address_hex == destination && output.coin == payment)
        .collect();
    ensure!(
        requested.len() == 1 && tx.outputs.iter().all(|o| o.assets.is_empty()),
        "size control payment/assets differ"
    );
    let change = 1 - requested[0].0;
    let change_address = hex::decode(&tx.outputs[change].address_hex)?;
    let source = crate::encoding::bech32(context.funding_address)?.1;
    ensure!(
        source.len() == 57
            && change_address.len() == 57
            && change_address[0] == 0
            && change_address[29..] == source[29..],
        "size change stake credential differs"
    );
    let size = sized(&encoded, context)?;
    ensure!(
        size <= number(context.parameters, "/maxTxSize")?,
        "balanced transaction exceeds independent size limit"
    );
    let fee = number(context.parameters, "/txFeeFixed")?
        .checked_add(
            number(context.parameters, "/txFeePerByte")?
                .checked_mul(size)
                .context("size fee overflow")?,
        )
        .context("size fee overflow")?;
    ensure!(
        tx.fee == fee
            && tx.outputs[change].coin.checked_add(tx.fee)
                == Some(SURPLUS + (selected - count) as u64 * COIN),
        "size fee/change conservation differs"
    );
    Ok(Balanced {
        encoded,
        tx,
        size,
        change,
    })
}
fn unsigned_width(value: u64) -> Result<usize> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.u64(value)?;
    Ok(e.into_writer().len())
}
fn boundary(control: &Balanced, count: usize, context: &Context<'_>) -> Result<u64> {
    selected_inputs(&control.tx.inputs, count, context, true)?;
    let mut e = minicbor::Encoder::new(Vec::new());
    let (hash, index) = &context.references[count];
    e.array(2)?.bytes(&hex::decode(hash)?)?.u64(*index)?;
    // Each distinct input reference adds a conservative mock witness, even when
    // the physical signing credential is shared. Above23, ledger sets add a break.
    let base = control.size + e.into_writer().len() as u64 + 101 + u64::from(count == 23);
    let old_widths = unsigned_width(count as u64 * COIN - SURPLUS)?
        + unsigned_width(control.tx.fee)?
        + unsigned_width(control.tx.outputs[control.change].coin)?;
    let mut next = base;
    let mut converged = false;
    for _ in 0..16 {
        let fee = number(context.parameters, "/txFeeFixed")?
            + number(context.parameters, "/txFeePerByte")? * next;
        let change = SURPLUS
            .checked_sub(fee)
            .context("next probe cannot cover fee/change")?;
        let widths = unsigned_width((count as u64 + 1) * COIN - SURPLUS)?
            + unsigned_width(fee)?
            + unsigned_width(change)?;
        let updated = (base as i64 + widths as i64 - old_widths as i64).try_into()?;
        if updated == next {
            converged = true;
            break;
        }
        next = updated;
    }
    ensure!(converged, "adjacent size fee/framing did not converge");
    ensure!(
        next > number(context.parameters, "/maxTxSize")?,
        "rejected next input could fit independent size limit"
    );
    Ok(next)
}
impl Session<'_> {
    fn input_limit_state(
        &mut self,
        id: &str,
        address: &str,
        original: &Value,
        options: &LiveOptions,
    ) -> Result<()> {
        self.family_ready_balance(SHELLEY, id, TOTAL)?;
        ensure!(
            options.node.utxos(address, self.timeout)? == *original,
            "unsigned size probe changed node funding"
        );
        let history = self.call(
            "listTransactions",
            "GET",
            &format!("/wallets/{id}/transactions"),
            None,
            200,
        )?;
        let wanted: BTreeSet<_> = original
            .as_object()
            .unwrap()
            .keys()
            .map(|id| id.split('#').next().unwrap())
            .collect();
        let entries = history.as_array().context("invalid size probe history")?;
        let actual: BTreeSet<_> = entries
            .iter()
            .map(|v| text(v, "/id"))
            .collect::<Result<_>>()?;
        ensure!(
            actual == wanted.iter().map(|s| s.to_string()).collect()
                && entries.len() == 6
                && entries
                    .iter()
                    .all(|v| v["status"] == "in_ledger" && v["direction"] == "incoming"),
            "unsigned size probe changed funding history identities/statuses"
        );
        Ok(())
    }
    fn input_limit_probe(
        &mut self,
        id: &str,
        count: usize,
        context: &Context<'_>,
    ) -> Result<Option<Balanced>> {
        let result = (|| -> Result<(Option<Balanced>, u16, Value)> {
            let path = format!("/wallets/{id}/transactions-balance");
            self.contract
                .check_path("balanceTransaction", "POST", &path)?;
            let request = request(
                "POST",
                path,
                Some(
                    json!({"transaction":hex::encode(raw_partial(&context.references[..count],context.destination,context.ttl)?),"inputs":[],"redeemers":[]}),
                ),
            );
            let response = self.api.request(&request)?;
            ensure!(
                [202, 403].contains(&response.status),
                "size probe unexpected status{}",
                response.status
            );
            self.contract.validate("balanceTransaction", &response)?;
            let value = body(&response)?;
            if response.status == 403 {
                ensure!(
                    *value
                        == json!({"code":"transaction_is_too_big","message":"I was not able to balance the transaction without exceeding the maximum transaction size."}),
                    "size guard differs: {value}"
                );
                Ok((None, 403, value.clone()))
            } else {
                let control = balanced(value, count, context)?;
                Ok((Some(control), 202, value.clone()))
            }
        })();
        let requirements = if let Ok((_, status, _)) = &result {
            vec![
                format!("api:balanceTransaction:status:{status}"),
                format!(
                    "api:balanceTransaction:{}",
                    if *status == 202 {
                        "positive"
                    } else {
                        "negative"
                    }
                ),
            ]
        } else {
            vec![]
        };
        self.report.record(
            &format!("live:size-probe-{count}"),
            &requirements,
            result.as_ref().map(|_| ()).map_err(|e| anyhow!("{e:#}")),
        );
        let (control, status, value) = result?;
        self.report.evidence.last_mut().unwrap().detail =
            json!({"input_count":count,"status":status,
            "estimated_bytes":control.as_ref().map(|v|v.size),"response":value})
            .to_string();
        Ok(control)
    }
    pub(super) fn exercise_input_limits(&mut self, options: &LiveOptions) -> Result<()> {
        let mnemonic = || -> Result<Vec<String>> {
            Ok(bip39::Mnemonic::generate(15)?
                .words()
                .map(str::to_owned)
                .collect())
        };
        let sender = self.create("conformance-input-limit-sender", mnemonic()?)?;
        let recipient = self.create("conformance-input-limit-recipient", mnemonic()?)?;
        self.family_ready_balance(SHELLEY, &sender, 0)?;
        self.family_ready_balance(SHELLEY, &recipient, 0)?;
        let source = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{sender}/addresses"),
            None,
            200,
        )?;
        let address = text(&source, "/0/id")?;
        let target = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{recipient}/addresses"),
            None,
            200,
        )?;
        let destination = text(&target, "/0/id")?;
        let parameters = options.node.protocol_parameters(self.timeout)?;
        ensure!(
            number(&parameters, "/maxTxSize")? == 16384,
            "controlled input-limit profile needs16384-byte protocol maximum"
        );
        let faucet = Api::new(
            options
                .faucet
                .as_ref()
                .context("input-limit faucet missing")?,
            self.timeout,
        )?;
        let asset = json!({"address":address,"bundle":{"coin":COIN,"assets":[]},"metadata":[]});
        ensure!(
            faucet
                .request(&request(
                    "POST",
                    "/send/faucet-assets",
                    Some(json!({"batch-size":100,"assets":vec![asset;600]}))
                ))?
                .status
                == 204,
            "many-input faucet rejected funding"
        );
        self.family_ready_balance(SHELLEY, &sender, TOTAL)?;
        let original = options.node.utxos(&address, self.timeout)?;
        let references = references(&original, &address)?;
        let ttl = options
            .node
            .tip(self.timeout)?
            .slot
            .checked_add(3000)
            .context("size probe TTL overflow")?;
        let context = Context {
            references: &references,
            destination: &destination,
            funding_address: &address,
            ttl,
            parameters: &parameters,
        };
        self.input_limit_state(&sender, &address, &original, options)?;
        let (mut low, mut high) = (23, 600);
        let mut accepted = self
            .input_limit_probe(&sender, low, &context)?
            .context("23-input anchor rejected")?;
        ensure!(
            self.input_limit_probe(&sender, high, &context)?.is_none(),
            "600-input oversized anchor accepted"
        );
        self.input_limit_state(&sender, &address, &original, options)?;
        while high - low > 1 {
            let mid = (low + high) / 2;
            if let Some(control) = self.input_limit_probe(&sender, mid, &context)? {
                low = mid;
                accepted = control;
            } else {
                high = mid;
            }
            self.input_limit_state(&sender, &address, &original, options)?;
        }
        let next_size = boundary(&accepted, low, &context)?;
        ensure!(
            options.node.protocol_parameters(self.timeout)? == parameters,
            "protocol parameters changed during size controls"
        );
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("/wallets/{sender}/transactions-sign"),
            Some(json!({"transaction":accepted.encoded,"passphrase":PASSWORD})),
            202,
        )?;
        let encoded = text(&signed, "/transaction")?;
        let tx = transaction::inspect(&encoded, true)?;
        let source = crate::encoding::bech32(&address)?.1;
        ensure!(
            tx.id == accepted.tx.id
                && tx.verification_keys.len() == 1
                && transaction::blake2b(&hex::decode(&tx.verification_keys[0])?, 28)?
                    == source[1..29]
                && sized(&encoded, &context)? == accepted.size,
            "boundary signature/body/size differs"
        );
        let submitted = self.call(
            "submitTransaction",
            "POST",
            &format!("/wallets/{sender}/transactions-submit"),
            Some(json!({"transaction":encoded})),
            202,
        )?;
        ensure!(submitted["id"] == tx.id, "boundary submitted hash differs");
        self.family_confirm(SHELLEY, &sender, &tx.id)?;
        self.family_confirm(SHELLEY, &recipient, &tx.id)?;
        let payment = low as u64 * COIN - SURPLUS;
        self.family_ready_balance(SHELLEY, &sender, TOTAL - payment - tx.fee)?;
        self.family_ready_balance(SHELLEY, &recipient, payment)?;
        let known = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{sender}/addresses"),
            None,
            200,
        )?;
        for output in &tx.outputs {
            let output_address =
                if output.address_hex == hex::encode(crate::encoding::bech32(&destination)?.1) {
                    destination.clone()
                } else {
                    known
                        .as_array()
                        .context("missing size change ownership list")?
                        .iter()
                        .filter_map(|v| v["id"].as_str())
                        .find(|address| {
                            crate::encoding::bech32(address)
                                .is_ok_and(|(_, raw)| hex::encode(raw) == output.address_hex)
                        })
                        .context("size change is not wallet-owned")?
                        .to_owned()
                };
            options
                .node
                .payment(&tx.id, &output_address, output.coin, self.timeout)?;
        }
        let remainder = options.node.utxos(&address, self.timeout)?;
        let mut expected = original.as_object().unwrap().clone();
        for reference in &tx.inputs {
            ensure!(
                expected.remove(reference).is_some(),
                "boundary spends unknown funding reference"
            );
        }
        ensure!(
            remainder == json!(expected),
            "node remaining funding differs after boundary spend"
        );
        let detail=json!({"maximum_bytes":16384,"accepted_inputs":low,"rejected_inputs":high,"accepted_bytes":accepted.size,
            "predicted_next_bytes":next_size,"fee":tx.fee,"transaction_id":tx.id,"signed_transaction":signed,
            "parameters":parameters,"funding_before":original,"funding_after":remainder}).to_string();
        for id in [
            "selection-maximum-inputs-boundary",
            "selection-maximum-size-boundary",
        ] {
            self.report
                .record(id, &["selection.input-limits".into()], Ok(()));
            self.report.evidence.last_mut().unwrap().detail = detail.clone();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn input_set_framing_obeys_23_item_threshold_and_rejects_malformed_controls() {
        fn control(count: u64, indefinite: bool) -> Vec<u8> {
            let mut e = minicbor::Encoder::new(Vec::new());
            e.array(4)
                .unwrap()
                .map(4)
                .unwrap()
                .u8(0)
                .unwrap()
                .tag(minicbor::data::Tag::new(258))
                .unwrap();
            if indefinite {
                e.begin_array().unwrap();
            } else {
                e.array(count).unwrap();
            }
            for index in 0..count {
                e.array(2)
                    .unwrap()
                    .bytes(&[0; 32])
                    .unwrap()
                    .u64(index)
                    .unwrap();
            }
            if indefinite {
                e.end().unwrap();
            }
            e.u8(1).unwrap().array(2).unwrap();
            for _ in 0..2 {
                e.array(2)
                    .unwrap()
                    .bytes(&[0; 57])
                    .unwrap()
                    .u64(COIN)
                    .unwrap();
            }
            e.u8(2)
                .unwrap()
                .u64(100000)
                .unwrap()
                .u8(3)
                .unwrap()
                .u64(6000)
                .unwrap()
                .map(0)
                .unwrap()
                .bool(true)
                .unwrap()
                .null()
                .unwrap();
            e.into_writer()
        }
        let valid = control(23, false);
        shape(&hex::encode(&valid)).unwrap();
        let large = control(24, true);
        shape(&hex::encode(&large)).unwrap();
        for bad in [control(23, true), control(24, false), control(0, false)] {
            assert!(shape(&hex::encode(bad)).is_err());
        }
        for (position, byte) in [(5, 3), (7, 0x83), (9, 31), (42, 0x20)] {
            let mut bad = valid.clone();
            bad[position] = byte;
            assert!(shape(&hex::encode(bad)).is_err());
        }
        let mut bad = valid.clone();
        bad.drain(3..6);
        assert!(shape(&hex::encode(bad)).is_err());
        let mut bad = large;
        assert_eq!(bad.remove(7 + 24 * 36), 0xff);
        assert!(shape(&hex::encode(bad)).is_err());
        let mut bad = valid;
        bad.push(0);
        assert!(shape(&hex::encode(bad)).is_err());
    }
    fn funding(address: &str) -> Value {
        let mut map = serde_json::Map::new();
        for group in 0..6 {
            for index in 0..100 {
                map.insert(
                    format!("{group:064x}#{index}"),
                    json!({"address":address,"value":{"lovelace":COIN}}),
                );
            }
        }
        json!(map)
    }
    #[test]
    fn funding_requires_six_complete_batches_and_sorts_numeric_indices() {
        let mut original = funding("funding");
        let refs = references(&original, "funding").unwrap();
        assert_eq!(refs.len(), 600);
        assert_eq!(refs[2].1, 2);
        assert_eq!(refs[10].1, 10);
        let key = format!("{:064x}#0", 0);
        original[&key]["value"]["lovelace"] = json!(COIN + 1);
        assert!(references(&original, "funding").is_err());
        let mut original = funding("funding");
        let output = original.as_object_mut().unwrap().remove(&key).unwrap();
        original
            .as_object_mut()
            .unwrap()
            .insert(format!("{:064x}#100", 0), output);
        assert!(references(&original, "funding").is_err());
    }
    fn mock_balanced(count: usize, fee: u64, context: &Context<'_>) -> String {
        mock_selected(count, count, fee, context)
    }
    fn mock_selected(count: usize, requested: usize, fee: u64, context: &Context<'_>) -> String {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .map(4)
            .unwrap()
            .u8(0)
            .unwrap()
            .tag(minicbor::data::Tag::new(258))
            .unwrap()
            .begin_array()
            .unwrap();
        for (hash, index) in &context.references[..count] {
            e.array(2)
                .unwrap()
                .bytes(&hex::decode(hash).unwrap())
                .unwrap()
                .u64(*index)
                .unwrap();
        }
        e.end().unwrap().u8(1).unwrap().array(2).unwrap();
        for (address, coin) in [
            (context.destination, requested as u64 * COIN - SURPLUS),
            (
                context.funding_address,
                SURPLUS + (count - requested) as u64 * COIN - fee,
            ),
        ] {
            e.array(2)
                .unwrap()
                .bytes(&crate::encoding::bech32(address).unwrap().1)
                .unwrap()
                .u64(coin)
                .unwrap();
        }
        e.u8(2)
            .unwrap()
            .u64(fee)
            .unwrap()
            .u8(3)
            .unwrap()
            .u64(context.ttl)
            .unwrap()
            .map(0)
            .unwrap()
            .bool(true)
            .unwrap()
            .null()
            .unwrap();
        hex::encode(e.into_writer())
    }
    #[test]
    fn boundary_and_fee_checks_reject_conserved_but_incorrect_fees_and_extra_fields() {
        let rewards: Vec<crate::adapter::Vector> =
            serde_json::from_str(include_str!("../../fixtures/vectors/reward-profiles.json"))
                .unwrap();
        let source = rewards[0].input["reward_context"]["input"]["address"]
            .as_str()
            .unwrap();
        let destination = rewards[0].input["reward_context"]["output"]["address"]
            .as_str()
            .unwrap();
        let refs = references(&funding(source), source).unwrap();
        let parameters = json!({"protocolVersion":{"major":12},"maxTxSize":16384,"txFeeFixed":100000,"txFeePerByte":100});
        let context = Context {
            references: &refs,
            destination,
            funding_address: source,
            ttl: 6000,
            parameters: &parameters,
        };
        let maximum = (23..=600)
            .filter(|count| {
                sized(&mock_balanced(*count, 1_000_000, &context), &context).unwrap() <= 16384
            })
            .max()
            .unwrap();
        let oversized_size = sized(&mock_balanced(600, 1_000_000, &context), &context).unwrap();
        let oversized_fee = 100000 + 100 * oversized_size;
        assert!(oversized_size > 16384);
        assert!(SURPLUS.checked_sub(oversized_fee).unwrap() >= COIN);
        assert_eq!(23 * COIN - SURPLUS, 11 * COIN);
        let size = sized(&mock_balanced(maximum, 1_000_000, &context), &context).unwrap();
        let fee = 100000 + 100 * size;
        let encoded = mock_balanced(maximum, fee, &context);
        let control = balanced(&json!({"transaction":encoded}), maximum, &context).unwrap();
        assert!(boundary(&control, maximum, &context).unwrap() > 16384);
        let selected = 38;
        let requested = 23;
        let extra_size = sized(
            &mock_selected(selected, requested, 1_000_000, &context),
            &context,
        )
        .unwrap();
        let extra_fee = 100000 + 100 * extra_size;
        let extra = balanced(
            &json!({"transaction":mock_selected(selected,requested,extra_fee,&context)}),
            requested,
            &context,
        )
        .unwrap();
        assert_eq!(extra.tx.inputs.len(), selected);
        assert!(boundary(&extra, requested, &context).is_err());
        assert!(balanced(
            &json!({"transaction":mock_selected(selected,requested,extra_fee+1,&context)}),
            requested,
            &context
        )
        .is_err());
        let canonical = extra.tx.inputs;
        let mut missing = canonical.clone();
        missing.remove(0);
        assert!(selected_inputs(&missing, requested, &context, false).is_err());
        let mut duplicate = canonical.clone();
        duplicate.push(canonical[0].clone());
        assert!(selected_inputs(&duplicate, requested, &context, false).is_err());
        let mut foreign = canonical.clone();
        foreign.push(format!("{}#0", "ff".repeat(32)));
        assert!(selected_inputs(&foreign, requested, &context, false).is_err());
        let mut unordered = canonical;
        unordered.swap(0, 1);
        assert!(selected_inputs(&unordered, requested, &context, false).is_err());
        assert!(balanced(
            &json!({"transaction":mock_balanced(maximum,fee+1,&context)}),
            maximum,
            &context
        )
        .is_err());
        assert!(shape(&hex::encode(
            raw_partial(&refs[..maximum], destination, context.ttl).unwrap()
        ))
        .is_err());
        let wrong = Context {
            ttl: context.ttl + 1,
            ..context
        };
        assert!(balanced(&json!({"transaction":control.encoded}), maximum, &wrong).is_err());
    }
}
