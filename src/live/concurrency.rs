//! Concurrent wallet calls with strict arbitration and independent ledger evidence.
use super::{
    assets::node_failure,
    families::{FUNDING, SHELLEY},
    *,
};
use crate::api::Request;
use std::sync::Barrier;
const PASSWORD: &str = "conformance-test-passphrase";
const ALL_SPENT: &str =
    "ConwayMempoolFailure \"All inputs are spent. Transaction has probably already been included\"";
fn all_spent(response: &Response) -> Result<()> {
    node_failure(response, ALL_SPENT)?;
    let message = text(body(response)?, "/message")?;
    ensure!(
        body(response)? == &json!({"code":"created_invalid_transaction","message":message}),
        "unexpected conflicting-spend error fields"
    );
    Ok(())
}
fn parallel(api: &Api, requests: [Request; 2]) -> Result<[Response; 2]> {
    let barrier = Barrier::new(3);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            api.request(&requests[0])
        });
        let second = scope.spawn(|| {
            barrier.wait();
            api.request(&requests[1])
        });
        barrier.wait();
        Ok([
            first
                .join()
                .map_err(|_| anyhow!("first concurrent request panicked"))??,
            second
                .join()
                .map_err(|_| anyhow!("second concurrent request panicked"))??,
        ])
    })
}
fn arbitration(
    responses: &[Response; 2],
    ids: &[String; 2],
) -> Result<(usize, usize, &'static str)> {
    ensure!(
        responses.iter().filter(|r| r.status == 202).count() == 1,
        "concurrent admission must accept exactly one transaction"
    );
    let winner = usize::from(responses[1].status == 202);
    let loser = 1 - winner;
    ensure!(
        body(&responses[winner])?["id"] == ids[winner],
        "accepted concurrent transaction ID differs"
    );
    let variant = match responses[loser].status {
        500 => {
            all_spent(&responses[loser])?;
            "node-all-inputs-spent"
        }
        403 => {
            ensure!(
                responses[loser].media_type.as_deref() == Some("application/json")
                    && body(&responses[loser])?["code"] == "foreign_transaction",
                "spent-input ownership rejection differs"
            );
            "confirmed-spent-input-foreign"
        }
        _ => anyhow::bail!("unexpected concurrent loser status"),
    };
    Ok((winner, loser, variant))
}
fn construction(
    value: &Value,
    funding: &str,
    destination: &str,
    amount: u64,
) -> Result<transaction::Transaction> {
    let encoded = text(value, "/transaction")?;
    let tx = transaction::inspect(&encoded, false)?;
    ensure!(
        tx.inputs == vec![funding.to_owned()] && tx.verification_keys.is_empty(),
        "concurrent construction changed funded input or added signatures"
    );
    ensure!(
        tx.fee > 0 && number(value, "/fee/quantity")? == tx.fee,
        "concurrent construction fee differs"
    );
    let sum = |name: &str| -> Result<u64> {
        value["coin_selection"][name]
            .as_array()
            .context("missing concurrent selection")?
            .iter()
            .try_fold(0u64, |a, v| {
                ensure!(
                    v["assets"] == json!([]),
                    "unexpected asset in concurrent ADA selection"
                );
                a.checked_add(number(v, "/amount/quantity")?)
                    .context("concurrent selection overflow")
            })
    };
    ensure!(
        sum("inputs")? == FUNDING
            && sum("outputs")? == amount
            && sum("outputs")?
                .checked_add(sum("change")?)
                .and_then(|v| v.checked_add(tx.fee))
                == Some(FUNDING),
        "concurrent selection fails ADA conservation"
    );
    let address = hex::encode(crate::encoding::bech32(destination)?.1);
    let mut sent = 0u64;
    let mut total = 0u64;
    for output in &tx.outputs {
        ensure!(
            output.assets.is_empty(),
            "concurrent CBOR unexpectedly contains assets"
        );
        total = total
            .checked_add(output.coin)
            .context("concurrent output overflow")?;
        if output.address_hex == address {
            sent = sent.checked_add(output.coin).context("payment overflow")?;
        }
    }
    ensure!(
        sent == amount && total.checked_add(tx.fee) == Some(FUNDING),
        "concurrent CBOR changes payment or creates/destroys ADA"
    );
    Ok(tx)
}
impl Session<'_> {
    pub(super) fn exercise_concurrency(&mut self, options: &LiveOptions) -> Result<()> {
        let second_amount = options
            .amount
            .checked_add(1_000_000)
            .context("concurrent payment overflow")?;
        ensure!(
            second_amount < FUNDING - 2_000_000,
            "concurrent payment leaves no fee/change margin"
        );
        let mnemonic = || -> Result<Vec<String>> {
            Ok(bip39::Mnemonic::generate(15)?
                .words()
                .map(str::to_owned)
                .collect())
        };
        let sender = self.create("conformance-concurrent-sender", mnemonic()?)?;
        let recipient = self.create("conformance-concurrent-recipient", mnemonic()?)?;
        self.family_ready_balance(SHELLEY, &sender, 0)?;
        self.family_ready_balance(SHELLEY, &recipient, 0)?;
        let sender_path = format!("/wallets/{sender}");
        let sender_addresses = self.call(
            "listAddresses",
            "GET",
            &format!("{sender_path}/addresses"),
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
        let funding_address = text(&sender_addresses, "/0/id")?;
        let destination = text(&recipient_addresses, "/0/id")?;
        self.family_fund(SHELLEY, &sender, &funding_address, options)?;
        let utxo = options.node.utxos(&funding_address, self.timeout)?;
        let entries = utxo
            .as_object()
            .context("node funding UTxO is not object")?;
        ensure!(
            entries.len() == 1,
            "concurrency fixture must have exactly one funding UTxO"
        );
        let funding = entries.keys().next().unwrap().clone();
        let amounts = [options.amount, second_amount];
        let construct_path = format!("{sender_path}/transactions-construct");
        self.contract
            .check_path("constructTransaction", "POST", &construct_path)?;
        let requests = amounts.map(|amount| request("POST",&construct_path,Some(json!({"payments":[{"address":destination,"amount":{"quantity":amount,"unit":"lovelace"}}]}))));
        let responses = parallel(self.api, requests)?;
        let mut constructed = Vec::new();
        let mut ids = Vec::new();
        for index in 0..2 {
            ensure!(
                responses[index].status == 202,
                "concurrent construction was rejected"
            );
            self.contract
                .validate("constructTransaction", &responses[index])?;
            let value = body(&responses[index])?.clone();
            let tx = construction(&value, &funding, &destination, amounts[index])?;
            ids.push(tx.id);
            constructed.push(value);
            self.report.record(
                "live:constructTransaction:concurrent",
                &[
                    "api:constructTransaction:positive".into(),
                    "api:constructTransaction:status:202".into(),
                ],
                Ok(()),
            );
        }
        ensure!(
            ids[0] != ids[1],
            "distinct concurrent payments have identical IDs"
        );
        self.family_ready_balance(SHELLEY, &sender, FUNDING)?;
        self.report.record(
            "live:concurrent-construct",
            &["wallet.concurrent-spend".into()],
            Ok(()),
        );
        let mut signed = Vec::new();
        for index in 0..2 {
            let result = self.call(
                "signTransaction",
                "POST",
                &format!("{sender_path}/transactions-sign"),
                Some(
                    json!({"transaction":constructed[index]["transaction"],"passphrase":PASSWORD}),
                ),
                202,
            )?;
            let encoded = text(&result, "/transaction")?;
            let tx = transaction::inspect(&encoded, true)?;
            ensure!(
                tx.id == ids[index] && tx.verification_keys.len() == 1,
                "concurrent signing changes body or witness count"
            );
            let payment_hash = transaction::blake2b(&hex::decode(&tx.verification_keys[0])?, 28)?;
            let address_bytes = crate::encoding::bech32(&funding_address)?.1;
            ensure!(
                address_bytes.get(1..29) == Some(payment_hash.as_slice()),
                "concurrent witness does not match funded payment credential"
            );
            signed.push(encoded);
        }
        self.family_ready_balance(SHELLEY, &sender, FUNDING)?;
        let submit_path = format!("{sender_path}/transactions-submit");
        self.contract
            .check_path("submitTransaction", "POST", &submit_path)?;
        let requests =
            [0, 1].map(|i| request("POST", &submit_path, Some(json!({"transaction":signed[i]}))));
        let submitted = parallel(self.api, requests)?;
        let ids: [String; 2] = ids
            .try_into()
            .map_err(|_| anyhow!("missing concurrent IDs"))?;
        let (winner, loser, variant) = arbitration(&submitted, &ids)?;
        for response in &submitted {
            if response.status != 500 {
                self.contract.validate("submitTransaction", response)?;
            }
        }
        self.report.record(
            "live:submitTransaction:concurrent",
            &[
                "api:submitTransaction:positive".into(),
                "api:submitTransaction:status:202".into(),
            ],
            Ok(()),
        );
        for (id, direction) in [(&sender, "outgoing"), (&recipient, "incoming")] {
            let confirmed = self.family_confirm(SHELLEY, id, &ids[winner])?;
            ensure!(
                confirmed["direction"] == direction,
                "concurrent winning history direction differs"
            );
        }
        let winner_fee = number(&constructed[winner], "/fee/quantity")?;
        let remaining = FUNDING
            .checked_sub(amounts[winner])
            .and_then(|v| v.checked_sub(winner_fee))
            .context("winning payment exceeds funding")?;
        self.family_ready_balance(SHELLEY, &sender, remaining)?;
        self.family_ready_balance(SHELLEY, &recipient, amounts[winner])?;
        options
            .node
            .payment(&ids[winner], &destination, amounts[winner], self.timeout)?;
        ensure!(
            !options
                .node
                .utxos(&funding_address, self.timeout)?
                .as_object()
                .context("invalid spent funding UTxOs")?
                .contains_key(&funding),
            "original conflicting-spend funding input remains unspent"
        );
        let recipient_utxo = options.node.utxos(&destination, self.timeout)?;
        ensure!(
            recipient_utxo
                .as_object()
                .context("recipient node UTxO missing")?
                .keys()
                .all(|key| !key.starts_with(&format!("{}#", ids[loser]))),
            "losing concurrent payment appeared in node UTxO"
        );
        self.call(
            "getTransaction",
            "GET",
            &format!("{sender_path}/transactions/{}", ids[loser]),
            None,
            404,
        )?;
        let mut rejected_request = request("POST", "/proxy/transactions", None);
        use base64::Engine;
        let bytes = if signed[loser].len().is_multiple_of(2)
            && signed[loser].bytes().all(|b| b.is_ascii_hexdigit())
        {
            hex::decode(&signed[loser])?
        } else {
            base64::engine::general_purpose::STANDARD.decode(&signed[loser])?
        };
        rejected_request.raw_body_hex = Some(hex::encode(bytes));
        self.contract
            .check_path("postExternalTransaction", "POST", &rejected_request.path)?;
        let response = self.api.request(&rejected_request)?;
        all_spent(&response)?;
        self.contract
            .validate("postExternalTransaction", &response)?;
        self.report.record(
            "live:proxy-conflicting-spend-status",
            &[
                "api:postExternalTransaction:status:500".into(),
                "api:postExternalTransaction:negative".into(),
            ],
            Ok(()),
        );
        self.family_ready_balance(SHELLEY, &sender, remaining)?;
        for change in constructed[winner]["coin_selection"]["change"]
            .as_array()
            .context("missing winning change")?
        {
            let change_address = text(change, "/address")?;
            let derivation = change["derivation_path"]
                .as_array()
                .context("missing change derivation")?;
            ensure!(
                derivation.len() >= 2 && derivation[derivation.len() - 2] == "1",
                "winning change is not internal role1"
            );
            options.node.payment(
                &ids[winner],
                &change_address,
                number(change, "/amount/quantity")?,
                self.timeout,
            )?;
            self.poll(
                "listAddresses",
                &format!("{sender_path}/addresses"),
                |addresses| {
                    addresses.as_array().is_some_and(|items| {
                        items.iter().any(|entry| {
                            entry["id"] == change_address
                                && entry["state"] == "used"
                                && entry["derivation_path"] == change["derivation_path"]
                        })
                    })
                },
            )?;
        }
        self.check_snapshot(&sender, remaining)?;
        self.report.record(
            "discovery-internal-change",
            &["wallet.discovery".into()],
            Ok(()),
        );
        self.report
            .record(&format!("live:concurrent-submit:{variant}"), &[], Ok(()));
        self.report.record(
            "live:concurrent-submit",
            &["wallet.concurrent-spend".into()],
            Ok(()),
        );
        self.report.record(
            "live:conflicting-spend",
            &[
                "tx.double-spend".into(),
                "wallet.balance-conservation".into(),
                "chain.node-utxo-confirmation".into(),
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
    fn construction_laws_reject_changed_fees_amounts_inputs_and_selection_totals() {
        let payment = [vec![0x60], vec![0x11; 28]].concat();
        let change = [vec![0x60], vec![0x22; 28]].concat();
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .map(3)
            .unwrap()
            .u8(0)
            .unwrap()
            .array(1)
            .unwrap()
            .array(2)
            .unwrap()
            .bytes(&[0; 32])
            .unwrap()
            .u8(0)
            .unwrap()
            .u8(1)
            .unwrap()
            .array(2)
            .unwrap()
            .array(2)
            .unwrap()
            .bytes(&payment)
            .unwrap()
            .u64(2_000_000)
            .unwrap()
            .array(2)
            .unwrap()
            .bytes(&change)
            .unwrap()
            .u64(97_800_000)
            .unwrap()
            .u8(2)
            .unwrap()
            .u64(200_000)
            .unwrap()
            .map(0)
            .unwrap()
            .bool(true)
            .unwrap()
            .null()
            .unwrap();
        let value = json!({"transaction":hex::encode(e.into_writer()),"fee":{"quantity":200000},"coin_selection":{"inputs":[{"amount":{"quantity":100000000},"assets":[]}],"outputs":[{"amount":{"quantity":2000000},"assets":[]}],"change":[{"amount":{"quantity":97800000},"assets":[]}]}});
        let funding = format!("{}#0", "00".repeat(32));
        let destination = crate::encoding::bech32_encode("addr_test", &payment).unwrap();
        construction(&value, &funding, &destination, 2_000_000).unwrap();
        let mut changed = value.clone();
        changed["fee"]["quantity"] = json!(200001);
        assert!(construction(&changed, &funding, &destination, 2_000_000).is_err());
        let mut changed = value.clone();
        changed["coin_selection"]["change"][0]["amount"]["quantity"] = json!(97800001);
        assert!(construction(&changed, &funding, &destination, 2_000_000).is_err());
        assert!(construction(&value, &funding, &destination, 3_000_000).is_err());
        assert!(construction(
            &value,
            &format!("{}#1", "00".repeat(32)),
            &destination,
            2_000_000
        )
        .is_err());
    }
    fn response(status: u16, value: Value) -> Response {
        Response {
            status,
            media_type: Some("application/json".into()),
            json: Some(value),
            raw: vec![],
        }
    }
    #[test]
    fn arbitration_rejects_double_accept_double_reject_wrong_ids_and_unrelated_errors() {
        let ids = ["first".into(), "second".into()];
        let mut responses = [
            response(202, json!({"id":"first"})),
            response(
                500,
                json!({"code":"created_invalid_transaction","message":"The submitted transaction was rejected by the local node. Here's an error message that may help with debugging: ConwayMempoolFailure \"All inputs are spent. Transaction has probably already been included\""}),
            ),
        ];
        assert_eq!(
            arbitration(&responses, &ids).unwrap(),
            (0, 1, "node-all-inputs-spent")
        );
        responses[1] = response(202, json!({"id":"second"}));
        assert!(arbitration(&responses, &ids).is_err());
        responses[0].status = 500;
        responses[1].status = 500;
        assert!(arbitration(&responses, &ids).is_err());
        responses[0] = response(202, json!({"id":"wrong"}));
        responses[1] = response(403, json!({"code":"foreign_transaction"}));
        assert!(arbitration(&responses, &ids).is_err());
        responses[0].json = Some(json!({"id":"first"}));
        assert_eq!(
            arbitration(&responses, &ids).unwrap(),
            (0, 1, "confirmed-spent-input-foreign")
        );
        responses[1].json = Some(json!({"code":"wrong_encryption_passphrase"}));
        assert!(arbitration(&responses, &ids).is_err());
    }
    #[test]
    fn transport_releases_both_calls_before_waiting_for_either_response() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let api = Api::new(
            &format!("http://{}/v2/", listener.local_addr().unwrap()),
            Duration::from_secs(3),
        )
        .unwrap();
        let server = std::thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let (mut second, _) = listener.accept().unwrap();
            for stream in [&mut first, &mut second] {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut raw = [0; 4096];
                assert!(stream.read(&mut raw).unwrap() > 0);
                stream
                    .write_all(
                        b"HTTP/1.1 204 Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap();
            }
        });
        let responses = parallel(
            &api,
            [request("GET", "/one", None), request("GET", "/two", None)],
        )
        .unwrap();
        assert!(responses.iter().all(|r| r.status == 204));
        server.join().unwrap();
    }
}
