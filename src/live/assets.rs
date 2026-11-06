//! Wallet-native mint/burn with independently checked policy, quantities and node rejection.
use super::{
    families::{BYRON, FUNDING, SHELLEY},
    *,
};
use std::collections::BTreeMap;
const PASSWORD: &str = "conformance-test-passphrase";
pub(super) fn encoded_bytes(encoded: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    if encoded.len().is_multiple_of(2) && encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(hex::decode(encoded)?)
    } else {
        Ok(base64::engine::general_purpose::STANDARD.decode(encoded)?)
    }
}
fn corrupt_witness(encoded: &str, public: &[u8]) -> Result<String> {
    let mut raw = encoded_bytes(encoded)?;
    let mut d = minicbor::Decoder::new(&raw);
    ensure!(d.array()? == Some(4), "invalid witness mutation envelope");
    let start = d.position();
    d.skip()?;
    let body_end = d.position();
    let before = transaction::blake2b(&raw[start..body_end], 32)?;
    let mut mutation = None;
    for _ in 0..d.map()?.context("indefinite witness map")? {
        if d.u64()? != 0 {
            d.skip()?;
            continue;
        }
        if d.datatype()? == minicbor::data::Type::Tag {
            ensure!(d.tag()?.as_u64() == 258, "invalid witness set tag");
        }
        for _ in 0..d.array()?.context("indefinite vkeys")? {
            ensure!(d.array()? == Some(2), "invalid vkey tuple");
            let key = d.bytes()?;
            let signature = d.bytes()?;
            ensure!(signature.len() == 64, "invalid witness signature length");
            if key == public {
                ensure!(mutation.is_none(), "duplicate policy witness");
                mutation = Some(d.position() - signature.len());
            }
        }
    }
    raw[mutation.context("policy witness missing")?] ^= 1;
    ensure!(
        before == transaction::blake2b(&raw[start..body_end], 32)?,
        "witness mutation changed body"
    );
    Ok(hex::encode(raw))
}
fn native_quantities(value: &Value) -> Result<BTreeMap<String, u64>> {
    let mut result = BTreeMap::new();
    for asset in value.as_array().context("asset quantities are not array")? {
        let policy = text(asset, "/policy_id")?;
        let name = text(asset, "/asset_name")?;
        ensure!(
            hex::decode(&policy)?.len() == 28 && hex::decode(&name)?.len() <= 32,
            "invalid asset identity"
        );
        let quantity = number(asset, "/quantity")?;
        let count = result.entry(format!("{policy}.{name}")).or_insert(0u64);
        *count = count
            .checked_add(quantity)
            .context("asset quantity overflow")?;
    }
    Ok(result)
}
fn node_rejection(response: &Response) -> Result<()> {
    node_failure(response, "InvalidWitnesses")
}
fn output_address(raw: &[u8]) -> Result<String> {
    let header = *raw.first().context("empty asset output address")?;
    if header == 0x82 {
        let mut decoder = minicbor::Decoder::new(raw);
        ensure!(
            decoder.array()? == Some(2),
            "invalid Byron address envelope"
        );
        ensure!(decoder.tag()?.as_u64() == 24, "invalid Byron payload tag");
        let payload = decoder.bytes()?;
        ensure!(
            decoder.u32()? == crate::addresses::crc32(payload),
            "invalid Byron address checksum"
        );
        ensure!(
            decoder.position() == raw.len(),
            "trailing Byron address bytes"
        );
        crate::encoding::base58_encode(raw)
    } else {
        ensure!(header >> 4 <= 7, "unsupported asset output address");
        crate::encoding::bech32_encode(
            if header & 15 == 1 {
                "addr"
            } else {
                "addr_test"
            },
            raw,
        )
    }
}

fn asset_identity(value: &Value, policy: &str, name: &str) -> Result<()> {
    let mut bytes = hex::decode(policy)?;
    ensure!(bytes.len() == 28, "asset policy length differs");
    let name_bytes = hex::decode(name)?;
    ensure!(name_bytes.len() <= 32, "asset name exceeds ledger bound");
    bytes.extend(name_bytes);
    let fingerprint = crate::encoding::bech32_encode("asset", &transaction::blake2b(&bytes, 20)?)?;
    ensure!(
        value["policy_id"] == policy
            && value["asset_name"] == name
            && value["fingerprint"] == fingerprint
            && value["metadata"].is_null(),
        "asset identity/fingerprint/metadata differs"
    );
    Ok(())
}
pub(super) fn node_failure(response: &Response, cause: &str) -> Result<()> {
    ensure!(
        response.status == 500 && response.media_type.as_deref() == Some("application/json"),
        "node rejection status/media differs from pinned handler"
    );
    let value = body(response)?;
    ensure!(
        value["code"] == "created_invalid_transaction",
        "node rejection code differs"
    );
    let message = text(value, "/message")?;
    ensure!(message.starts_with("The submitted transaction was rejected by the local node. Here's an error message that may help with debugging: ") && message.contains(cause),"node rejection does not prove expected ledger cause");
    Ok(())
}
impl Session<'_> {
    fn asset_state(&mut self, id: &str, expected: &BTreeMap<String, u64>) -> Result<()> {
        let wallet = self.call("getWallet", "GET", &format!("/wallets/{id}"), None, 200)?;
        ensure!(
            native_quantities(&wallet["assets"]["available"])? == *expected
                && native_quantities(&wallet["assets"]["total"])? == *expected,
            "wallet asset balances differ"
        );
        let snapshot = self.call(
            "getWalletUtxoSnapshot",
            "GET",
            &format!("/wallets/{id}/utxo"),
            None,
            200,
        )?;
        let mut total = BTreeMap::<String, u64>::new();
        let mut ada = 0u64;
        for entry in snapshot["entries"]
            .as_array()
            .context("missing asset UTxOs")?
        {
            ada = ada
                .checked_add(number(entry, "/ada/quantity")?)
                .context("snapshot ADA overflow")?;
            for (id, quantity) in native_quantities(&entry["assets"])? {
                let sum = total.entry(id).or_default();
                *sum = sum
                    .checked_add(quantity)
                    .context("snapshot token overflow")?;
            }
        }
        ensure!(
            total == *expected && ada == number(&wallet, "/balance/available/quantity")?,
            "multiasset UTxO snapshot differs from wallet balance"
        );
        Ok(())
    }
    pub(super) fn node_asset_outputs(
        &self,
        tx: &transaction::Transaction,
        options: &LiveOptions,
    ) -> Result<()> {
        let mut grouped = BTreeMap::<String, (u64, BTreeMap<String, u64>)>::new();
        for output in &tx.outputs {
            let bytes = hex::decode(&output.address_hex)?;
            let address = output_address(&bytes)?;
            let (coin, assets) = grouped.entry(address).or_default();
            *coin = coin
                .checked_add(output.coin)
                .context("output ADA overflow")?;
            for (id, quantity) in &output.assets {
                let count = assets.entry(id.clone()).or_default();
                *count = count
                    .checked_add(*quantity)
                    .context("output asset overflow")?;
            }
        }
        for (address, (coin, assets)) in grouped {
            options
                .node
                .payment_assets(&tx.id, &address, coin, &assets, self.timeout)?;
        }
        Ok(())
    }
    pub(super) fn exercise_assets(&mut self, options: &LiveOptions) -> Result<()> {
        let mnemonic = bip39::Mnemonic::generate(15)?
            .words()
            .map(str::to_owned)
            .collect();
        let id = self.create("conformance-native-assets", mnemonic)?;
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
        self.family_fund(SHELLEY, &id, &address, options)?;
        let policy_key = self.call(
            "postPolicyKey",
            "POST",
            &format!("{path}/policy-key"),
            Some(json!({"passphrase":PASSWORD})),
            202,
        )?;
        let (hrp, policy_public) =
            crate::encoding::bech32(policy_key.as_str().context("policy key is not text")?)?;
        ensure!(
            hrp == "policy_vk" && policy_public.len() == 32,
            "policy verification key differs"
        );
        let mut script = minicbor::Encoder::new(Vec::new());
        script
            .array(2)?
            .u8(0)?
            .bytes(&transaction::blake2b(&policy_public, 28)?)?;
        let mut domain = vec![0];
        domain.extend(script.into_writer());
        let policy = hex::encode(transaction::blake2b(&domain, 28)?);
        let returned = self.call(
            "postPolicyId",
            "POST",
            &format!("{path}/policy-id"),
            Some(json!({"policy_script_template":"cosigner#0"})),
            202,
        )?;
        ensure!(
            returned["policy_id"] == policy,
            "policy ID differs from independent native script hash"
        );
        let mut balance = FUNDING;
        for burning in [false, true] {
            let (name, operations, quantities, expected) = if !burning {
                (
                    "mint",
                    json!([
                        {"policy_script_template":"cosigner#0","asset_name":"","operation":{"mint":{"receiving_address":address,"quantity":100}}},
                        {"policy_script_template":"cosigner#0","asset_name":"ab12","operation":{"mint":{"receiving_address":address,"quantity":100}}}
                    ]),
                    BTreeMap::from([
                        (format!("{policy}."), 100i64),
                        (format!("{policy}.ab12"), 100),
                    ]),
                    BTreeMap::from([
                        (format!("{policy}."), 100u64),
                        (format!("{policy}.ab12"), 100),
                    ]),
                )
            } else {
                (
                    "burn",
                    json!([
                        {"policy_script_template":"cosigner#0","asset_name":"","operation":{"burn":{"quantity":100}}},
                        {"policy_script_template":"cosigner#0","asset_name":"ab12","operation":{"burn":{"quantity":40}}}
                    ]),
                    BTreeMap::from([
                        (format!("{policy}."), -100i64),
                        (format!("{policy}.ab12"), -40),
                    ]),
                    BTreeMap::from([(format!("{policy}.ab12"), 60u64)]),
                )
            };
            let constructed = self.call(
                "constructTransaction",
                "POST",
                &format!("{path}/transactions-construct"),
                Some(json!({"mint_burn":operations})),
                202,
            )?;
            let unsigned = text(&constructed, "/transaction")?;
            let inspected = transaction::inspect(&unsigned, false)?;
            let fee = number(&constructed, "/fee/quantity")?;
            ensure!(
                fee > 0
                    && inspected.fee == fee
                    && transaction::mint_quantities(&unsigned)? == quantities,
                "constructed mint/burn quantities or fee differ"
            );
            let signed = self.call(
                "signTransaction",
                "POST",
                &format!("{path}/transactions-sign"),
                Some(json!({"transaction":unsigned,"passphrase":PASSWORD})),
                202,
            )?;
            let signed = text(&signed, "/transaction")?;
            let verified = transaction::inspect(&signed, true)?;
            ensure!(
                verified.id == inspected.id
                    && transaction::mint_quantities(&signed)? == quantities
                    && verified
                        .verification_keys
                        .contains(&hex::encode(&policy_public)),
                "mint/burn signer changes body or omits policy witness"
            );
            if !burning {
                let corrupt = corrupt_witness(&signed, &policy_public)?;
                ensure!(
                    transaction::inspect(&corrupt, true).is_err()
                        && transaction::mint_quantities(&corrupt)? == quantities,
                    "corrupt policy witness did not fail independent verification"
                );
                let rejected = self.api.request(&request(
                    "POST",
                    format!("{path}/transactions-submit"),
                    Some(json!({"transaction":corrupt})),
                ))?;
                node_rejection(&rejected)?;
                let utxo = options.node.utxos(&address, self.timeout)?;
                ensure!(
                    utxo.as_object()
                        .context("node UTxO missing")?
                        .keys()
                        .all(|key| !key.starts_with(&format!("{}#", verified.id))),
                    "rejected mint appeared in node UTxO"
                );
                self.family_ready_balance(SHELLEY, &id, balance)?;
                self.asset_state(&id, &BTreeMap::new())?;
                self.report.record(
                    "live:mint-invalid-witness-rejected",
                    &["tx.mint-burn".into()],
                    Ok(()),
                );
                self.report.record(
                    "live:corrupt-witness-rejected",
                    &["tx.invalid-signature".into()],
                    Ok(()),
                );
            }
            let submitted = if !burning {
                let mut req = request("POST", "/proxy/transactions", None);
                req.raw_body_hex = Some(hex::encode(encoded_bytes(&signed)?));
                self.contract
                    .check_path("postExternalTransaction", "POST", &req.path)?;
                let response = self.api.request(&req)?;
                ensure!(
                    response.status == 202,
                    "binary proxy did not accept valid mint"
                );
                self.contract
                    .validate("postExternalTransaction", &response)?;
                self.report.record(
                    "live:postExternalTransaction:binary",
                    &[
                        "api:postExternalTransaction:positive".into(),
                        "api:postExternalTransaction:status:202".into(),
                    ],
                    Ok(()),
                );
                body(&response)?.clone()
            } else {
                self.call(
                    "submitTransaction",
                    "POST",
                    &format!("{path}/transactions-submit"),
                    Some(json!({"transaction":signed})),
                    202,
                )?
            };
            ensure!(
                submitted["id"] == verified.id,
                "mint/burn submission ID differs"
            );
            let confirmed = self.family_confirm(SHELLEY, &id, &verified.id)?;
            ensure!(
                number(&confirmed, "/fee/quantity")? == fee,
                "confirmed mint/burn fee differs"
            );
            balance = balance
                .checked_sub(fee)
                .context("mint/burn fee exceeds balance")?;
            self.family_ready_balance(SHELLEY, &id, balance)?;
            self.asset_state(&id, &expected)?;
            self.node_asset_outputs(&verified, options)?;
            self.report.record(
                &format!("live:native-{name}"),
                &[
                    "tx.mint-burn".into(),
                    "wallet.balance-conservation".into(),
                    "chain.node-utxo-confirmation".into(),
                ],
                Ok(()),
            );
            if !burning {
                for asset_name in ["", "ab12"] {
                    let asset = self.call(
                        if asset_name.is_empty() {
                            "getAssetDefault"
                        } else {
                            "getAsset"
                        },
                        "GET",
                        &format!(
                            "{path}/assets/{policy}{}",
                            if asset_name.is_empty() {
                                String::new()
                            } else {
                                format!("/{asset_name}")
                            }
                        ),
                        None,
                        200,
                    )?;
                    let mut bytes = hex::decode(&policy)?;
                    bytes.extend(hex::decode(asset_name)?);
                    let fingerprint = crate::encoding::bech32_encode(
                        "asset",
                        &transaction::blake2b(&bytes, 20)?,
                    )?;
                    ensure!(
                        asset["policy_id"] == policy
                            && asset["asset_name"] == asset_name
                            && asset["fingerprint"] == fingerprint,
                        "asset identity/CIP14 fingerprint differs"
                    );
                }
                self.report.record(
                    "live:multiasset-utxo-snapshot",
                    &["wallet.utxo-snapshot".into()],
                    Ok(()),
                );
            }
        }
        self.byron_asset_receipts(&id, &policy, &policy_public, balance, options)?;
        Ok(())
    }

    fn byron_asset_receipts(
        &mut self,
        source: &str,
        policy: &str,
        policy_public: &[u8],
        mut balance: u64,
        options: &LiveOptions,
    ) -> Result<()> {
        const COIN: u64 = 10_000_000;
        let quantities = BTreeMap::from([
            (format!("{policy}."), 17u64),
            (format!("{policy}.ab12"), 29),
        ]);
        let mint: BTreeMap<_, _> = quantities
            .iter()
            .map(|(key, value)| (key.clone(), *value as i64))
            .collect();
        for style in ["random", "icarus"] {
            let mnemonic: Vec<_> =
                bip39::Mnemonic::generate(if style == "random" { 12 } else { 15 })?
                    .words()
                    .map(str::to_owned)
                    .collect();
            let created = self.call("postByronWallet", "POST", "/byron-wallets", Some(json!({"style":style,"name":format!("conformance-assets-{style}"),"mnemonic_sentence":mnemonic,"passphrase":PASSWORD})), 201)?;
            let id = text(&created, "/id")?;
            self.family_ready_balance(BYRON, &id, 0)?;
            let path = format!("/byron-wallets/{id}");
            let address = if style == "random" {
                text(
                    &self.call(
                        "createAddress",
                        "POST",
                        &format!("{path}/addresses"),
                        Some(json!({"passphrase":PASSWORD,"address_index":2147495993u64})),
                        201,
                    )?,
                    "/id",
                )?
            } else {
                text(
                    &self.call(
                        "listByronAddresses",
                        "GET",
                        &format!("{path}/addresses"),
                        None,
                        200,
                    )?,
                    "/0/id",
                )?
            };
            let destination = hex::encode(crate::encoding::base58_decode(&address)?);
            let before = self.call(
                "getWalletUtxoSnapshot",
                "GET",
                &format!("/wallets/{source}/utxo"),
                None,
                200,
            )?;
            let payment_assets = json!([{"policy_id":policy,"asset_name":"","quantity":17},{"policy_id":policy,"asset_name":"ab12","quantity":29}]);
            let constructed = self.call("constructTransaction", "POST", &format!("/wallets/{source}/transactions-construct"), Some(json!({"payments":[{"address":address,"amount":{"quantity":COIN,"unit":"lovelace"},"assets":payment_assets}],"mint_burn":[{"policy_script_template":"cosigner#0","asset_name":"","operation":{"mint":{"quantity":17}}},{"policy_script_template":"cosigner#0","asset_name":"ab12","operation":{"mint":{"quantity":29}}}]})), 202)?;
            let unsigned = text(&constructed, "/transaction")?;
            let unsigned_tx = transaction::inspect(&unsigned, false)?;
            let signed = self.call(
                "signTransaction",
                "POST",
                &format!("/wallets/{source}/transactions-sign"),
                Some(json!({"transaction":unsigned,"passphrase":PASSWORD})),
                202,
            )?;
            let signed = text(&signed, "/transaction")?;
            let tx = transaction::inspect(&signed, true)?;
            ensure!(
                tx.id == unsigned_tx.id
                    && tx.fee == number(&constructed, "/fee/quantity")?
                    && tx.verification_keys.contains(&hex::encode(policy_public))
                    && transaction::mint_quantities(&signed)? == mint,
                "Byron asset body/signature/mint/fee differs"
            );
            let received: Vec<_> = tx
                .outputs
                .iter()
                .filter(|output| output.address_hex == destination)
                .collect();
            ensure!(
                !received.is_empty()
                    && received.iter().map(|output| output.coin).sum::<u64>() == COIN,
                "Byron asset recipient ADA differs"
            );
            let mut tokens = BTreeMap::<String, u64>::new();
            for output in &received {
                for (key, quantity) in &output.assets {
                    *tokens.entry(key.clone()).or_default() += quantity;
                }
            }
            ensure!(tokens == quantities, "Byron asset recipient tokens differ");
            let mut native_inputs = BTreeMap::<String, Value>::new();
            for input in constructed["coin_selection"]["inputs"]
                .as_array()
                .context("missing Byron asset selection inputs")?
            {
                let address = text(input, "/address")?;
                let observed = options.node.utxos(&address, self.timeout)?;
                for (reference, output) in
                    observed.as_object().context("invalid native input map")?
                {
                    native_inputs.insert(reference.clone(), output.clone());
                }
            }
            let mut input_coin = 0u128;
            let mut input_tokens = BTreeMap::<String, u128>::new();
            let mut input_addresses = std::collections::BTreeSet::new();
            let mut unique_inputs = std::collections::BTreeSet::new();
            for reference in &tx.inputs {
                ensure!(
                    unique_inputs.insert(reference),
                    "duplicate Byron asset input"
                );
                let output = native_inputs
                    .get(reference)
                    .context("Byron asset input absent from native UTxOs")?;
                input_addresses.insert(text(output, "/address")?);
                input_coin += u128::from(number(output, "/value/lovelace")?);
                for (policy, names) in output["value"]
                    .as_object()
                    .context("missing native input value")?
                {
                    if policy == "lovelace" {
                        continue;
                    }
                    for (name, quantity) in names
                        .as_object()
                        .context("invalid native input token map")?
                    {
                        *input_tokens.entry(format!("{policy}.{name}")).or_default() +=
                            u128::from(quantity.as_u64().context("invalid native input quantity")?);
                    }
                }
            }
            ensure!(
                !unique_inputs.is_empty(),
                "Byron asset transaction has no funding inputs"
            );
            let output_coin: u128 = tx
                .outputs
                .iter()
                .map(|output| u128::from(output.coin))
                .sum();
            ensure!(
                input_coin == output_coin + u128::from(tx.fee),
                "Byron asset ADA conservation differs"
            );
            for (key, quantity) in &quantities {
                *input_tokens.entry(key.clone()).or_default() += u128::from(*quantity);
            }
            let mut output_tokens = BTreeMap::<String, u128>::new();
            for output in &tx.outputs {
                for (key, quantity) in &output.assets {
                    *output_tokens.entry(key.clone()).or_default() += u128::from(*quantity);
                }
            }
            ensure!(
                input_tokens == output_tokens,
                "Byron asset mint conservation differs"
            );
            let submitted = self.call(
                "submitTransaction",
                "POST",
                &format!("/wallets/{source}/transactions-submit"),
                Some(json!({"transaction":signed})),
                202,
            )?;
            ensure!(
                submitted["id"] == tx.id,
                "Byron asset submission ID differs"
            );
            let sender = self.family_confirm(SHELLEY, source, &tx.id)?;
            let receiver = self.family_confirm(BYRON, &id, &tx.id)?;
            ensure!(
                number(&sender, "/fee/quantity")? == tx.fee
                    && number(&receiver, "/amount/quantity")? == COIN
                    && receiver["direction"] == "incoming",
                "Byron asset confirmed history differs"
            );
            self.node_asset_outputs(&tx, options)?;
            for address in input_addresses {
                let after = options.node.utxos(&address, self.timeout)?;
                let after = after
                    .as_object()
                    .context("invalid native spent input map")?;
                ensure!(
                    tx.inputs
                        .iter()
                        .all(|reference| !after.contains_key(reference)),
                    "Byron asset funding input remains unspent"
                );
            }
            balance = balance
                .checked_sub(COIN)
                .and_then(|v| v.checked_sub(tx.fee))
                .context("Byron asset funding underflow")?;
            self.family_ready_balance(SHELLEY, source, balance)?;
            self.asset_state(source, &BTreeMap::from([(format!("{policy}.ab12"), 60)]))?;
            self.family_ready_balance(BYRON, &id, COIN)?;
            let wallet = self.call("getByronWallet", "GET", &path, None, 200)?;
            ensure!(
                native_quantities(&wallet["assets"]["available"])? == quantities
                    && native_quantities(&wallet["assets"]["total"])? == quantities,
                "Byron wallet asset balances differ"
            );
            let snapshot = self.call(
                "getByronWalletUtxoSnapshot",
                "GET",
                &format!("{path}/utxo"),
                None,
                200,
            )?;
            let mut snapshot_tokens = BTreeMap::<String, u64>::new();
            let mut snapshot_coin = 0;
            for entry in snapshot["entries"]
                .as_array()
                .context("missing Byron snapshot entries")?
            {
                snapshot_coin += number(entry, "/ada/quantity")?;
                for (key, quantity) in native_quantities(&entry["assets"])? {
                    *snapshot_tokens.entry(key).or_default() += quantity;
                }
            }
            ensure!(
                snapshot_coin == COIN && snapshot_tokens == quantities,
                "Byron snapshot differs from ledger receipt"
            );
            let list = self.call(
                "listByronAssets",
                "GET",
                &format!("{path}/assets"),
                None,
                200,
            )?;
            let list = list.as_array().context("Byron asset list is not array")?;
            ensure!(list.len() == 2, "Byron asset list cardinality differs");
            for name in ["", "ab12"] {
                let matching: Vec<_> = list
                    .iter()
                    .filter(|asset| asset["policy_id"] == policy && asset["asset_name"] == name)
                    .collect();
                ensure!(
                    matching.len() == 1,
                    "Byron asset list identity duplicated or missing"
                );
                asset_identity(matching[0], policy, name)?;
                let suffix = if name.is_empty() {
                    String::new()
                } else {
                    format!("/{name}")
                };
                let asset = self.call(
                    if name.is_empty() {
                        "getByronAssetDefault"
                    } else {
                        "getByronAsset"
                    },
                    "GET",
                    &format!("{path}/assets/{policy}{suffix}"),
                    None,
                    200,
                )?;
                asset_identity(&asset, policy, name)?;
                ensure!(&asset == matching[0], "Byron asset lookup/list disagree");
            }
            self.report
                .record(&format!("live:byron-{style}-native-assets"), &[], Ok(()));
            self.report
                .evidence
                .last_mut()
                .context("missing Byron proof check")?
                .detail = json!({"transaction":signed,"txid":tx.id,"destination":address,"received_assets":quantities,"source_before":before,"native_inputs_before":native_inputs,"destination_snapshot":snapshot,"wallet":wallet}).to_string();
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byron_output_address_preserves_goldens_and_rejects_checksum_and_trailing_bytes() {
        let vectors: Vec<crate::adapter::Vector> =
            serde_json::from_str(include_str!("../../fixtures/vectors/address-profiles.json"))
                .unwrap();
        for vector in vectors.iter().filter(|v| v.operation == "address.byron") {
            let golden = &vector.expected.as_ref().unwrap()["result"];
            let raw = hex::decode(golden["address_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                output_address(&raw).unwrap(),
                golden["address"].as_str().unwrap()
            );
            let mut bad = raw.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert!(output_address(&bad).is_err());
            let mut trailing = raw;
            trailing.push(0);
            assert!(output_address(&trailing).is_err());
        }
        assert!(output_address(&[]).is_err());
    }

    #[test]
    fn asset_lookup_identity_rejects_swapped_name_fingerprint_and_metadata() {
        let policy = "11".repeat(28);
        let mut bytes = hex::decode(&policy).unwrap();
        bytes.extend(hex::decode("ab12").unwrap());
        let good = json!({"policy_id":policy,"asset_name":"ab12","fingerprint":crate::encoding::bech32_encode("asset", &transaction::blake2b(&bytes,20).unwrap()).unwrap(),"metadata":null});
        asset_identity(&good, &policy, "ab12").unwrap();
        for (field, bad_value) in [
            ("policy_id", json!("22".repeat(28))),
            ("asset_name", json!("")),
            ("fingerprint", json!("asset1wrong")),
            ("metadata", json!({"name":"unexpected"})),
        ] {
            let mut bad = good.clone();
            bad[field] = bad_value;
            assert!(asset_identity(&bad, &policy, "ab12").is_err());
        }
    }
    #[test]
    fn policy_witness_mutation_preserves_body_and_breaks_real_golden_signature() {
        let fixtures: Vec<crate::adapter::Vector> =
            serde_json::from_str(include_str!("../../fixtures/vectors/writer-profiles.json"))
                .unwrap();
        let signed = fixtures
            .iter()
            .find(|v| v.id == "witness-sign-first")
            .unwrap()
            .expected
            .as_ref()
            .unwrap()["result"]["transaction_cbor_hex"]
            .as_str()
            .unwrap();
        let before = transaction::inspect(signed, true).unwrap();
        let corrupt =
            corrupt_witness(signed, &hex::decode(&before.verification_keys[0]).unwrap()).unwrap();
        assert!(transaction::inspect(&corrupt, true).is_err());
        assert_eq!(
            transaction::mint_quantities(signed).unwrap(),
            transaction::mint_quantities(&corrupt).unwrap()
        );
        assert!(corrupt_witness(signed, &[0; 32]).is_err());
    }
    #[test]
    fn node_rejection_requires_pinned_status_code_and_actual_invalid_witness_cause() {
        let mut response = Response {
            status: 500,
            media_type: Some("application/json".into()),
            json: Some(
                json!({"code":"created_invalid_transaction","message":"The submitted transaction was rejected by the local node. Here's an error message that may help with debugging: InvalidWitnessesUTXOW"}),
            ),
            raw: vec![],
        };
        node_rejection(&response).unwrap();
        let mut unformatted = response.clone();
        unformatted.json.as_mut().unwrap()["message"] = json!("The submitted transaction was rejected by the local node. Here's an error message that may help with debugging:\nInvalidWitnessesUTXOW");
        assert!(node_rejection(&unformatted).is_err());
        response.status = 403;
        assert!(node_rejection(&response).is_err());
        response.status = 500;
        response.json.as_mut().unwrap()["message"] = json!("different rejection");
        assert!(node_rejection(&response).is_err());
    }
}
