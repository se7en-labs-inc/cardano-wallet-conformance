//! Real ledger interval guards, exact clock brackets and same-transaction admission.
use super::{
    families::{FUNDING, SHELLEY},
    *,
};
use std::time::{SystemTime, UNIX_EPOCH};
const PASSWORD: &str = "conformance-test-passphrase";
const PICO: u128 = 1_000_000_000_000;
const PREFIX: &str = "The submitted transaction was rejected by the local node. Here's an error message that may help with debugging: HardForkApplyTxErrFromEra S (S (S (S (S (S (Z (WrapApplyTxErr {unwrapApplyTxErr = ConwayApplyTxError (ConwayUtxowFailure (UtxoFailure (";
const SUFFIX: &str = "))) :| [])})))))))";
/// The pinned cluster's roundPOSIXSecondsToInt uses nearest, ties-to-even.
pub(super) fn rounded_posix_seconds(nanoseconds: u128) -> u128 {
    let whole = nanoseconds / 1_000_000_000;
    let fraction = nanoseconds % 1_000_000_000;
    whole + u128::from(fraction > 500_000_000 || (fraction == 500_000_000 && whole % 2 == 1))
}
fn leap(y: u32) -> bool {
    y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))
}
pub(super) fn utc_ns(s: &str) -> Result<u128> {
    let s = s.strip_suffix('Z').context("genesis UTC must end in Z")?;
    let (date, time) = s.split_once('T').context("invalid genesis UTC")?;
    let date = date
        .split('-')
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let time = time.split(':').collect::<Vec<_>>();
    ensure!(
        date.len() == 3 && time.len() == 3,
        "invalid genesis UTC fields"
    );
    let (y, m, d) = (date[0], date[1], date[2]);
    ensure!(
        (1970..=9999).contains(&y) && (1..=12).contains(&m),
        "genesis date outside profile"
    );
    let lengths = [
        31,
        if leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    ensure!(d > 0 && d <= lengths[m as usize - 1], "invalid genesis day");
    let hour = time[0].parse::<u32>()?;
    let minute = time[1].parse::<u32>()?;
    let (second, fraction) = time[2].split_once('.').unwrap_or((time[2], ""));
    let second = second.parse::<u32>()?;
    ensure!(
        hour < 24
            && minute < 60
            && second < 60
            && fraction.len() <= 9
            && fraction.bytes().all(|b| b.is_ascii_digit()),
        "invalid genesis time"
    );
    let ns = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u128>()? * 10u128.pow(9 - fraction.len() as u32)
    };
    let days = (1970..y)
        .map(|year| if leap(year) { 366u128 } else { 365 })
        .sum::<u128>()
        + lengths[..m as usize - 1]
            .iter()
            .map(|v| u128::from(*v))
            .sum::<u128>()
        + u128::from(d - 1);
    Ok((days * 86400 + u128::from(hour * 3600 + minute * 60 + second)) * 1_000_000_000 + ns)
}
pub(super) fn decimal_ps(v: &Value) -> Result<u128> {
    let raw = v
        .as_number()
        .context("slot length is not numeric")?
        .to_string();
    let (mantissa, exponent) = raw.split_once(['e', 'E']).unwrap_or((&raw, "0"));
    let exponent = exponent.parse::<i32>()?;
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    ensure!(
        whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit()),
        "invalid decimal slot length"
    );
    let coefficient = format!("{whole}{fraction}").parse::<u128>()?;
    let scale = 12i32
        .checked_add(exponent)
        .and_then(|v| v.checked_sub(fraction.len() as i32))
        .context("decimal scale overflow")?;
    let factor = 10u128
        .checked_pow(scale.unsigned_abs())
        .context("decimal precision outside profile")?;
    let result = if scale >= 0 {
        coefficient
            .checked_mul(factor)
            .context("slot length overflow")?
    } else {
        ensure!(
            coefficient.is_multiple_of(factor),
            "sub-picosecond slot length"
        );
        coefficient / factor
    };
    ensure!(result > 0, "zero slot length");
    Ok(result)
}
struct Clock {
    start: u128,
    slot: u128,
}
impl Clock {
    fn at(&self, time: SystemTime, seconds: u64, ceiling: bool) -> Result<u64> {
        let ns = time
            .duration_since(UNIX_EPOCH)?
            .as_nanos()
            .checked_sub(self.start)
            .context("time precedes genesis")?;
        let ps = ns
            .checked_mul(1000)
            .and_then(|v| v.checked_add(u128::from(seconds) * PICO))
            .context("clock arithmetic overflow")?;
        u64::try_from(if ceiling {
            ps.div_ceil(self.slot)
        } else {
            ps / self.slot
        })
        .context("slot overflow")
    }
}
fn rejected(response: &Response, lower: u64, upper: u64, tip: u64, now: u64) -> Result<()> {
    assets::node_failure(response, "OutsideValidityIntervalUTxO")?;
    let marker = format!("OutsideValidityIntervalUTxO (ValidityInterval {{invalidBefore = SJust (SlotNo {lower}), invalidHereafter = SJust (SlotNo {upper})}}) (SlotNo ");
    let message = text(body(response)?, "/message")?;
    let slot = message
        .strip_prefix(&format!("{PREFIX}{marker}"))
        .and_then(|v| v.strip_suffix(SUFFIX))
        .context("validity rejection envelope/bounds differ")?
        .parse::<u64>()?;
    ensure!(
        slot >= tip && slot <= now && (slot < lower || slot >= upper),
        "node validity rejection slot does not prove interval guard"
    );
    ensure!(
        body(response)? == &json!({"code":"created_invalid_transaction","message":message}),
        "unexpected node error fields"
    );
    Ok(())
}
fn bounds(lower: u64, upper: u64) -> Value {
    json!({"invalid_before":{"quantity":lower,"unit":"slot"},"invalid_hereafter":{"quantity":upper,"unit":"slot"}})
}
impl Session<'_> {
    fn validity_build(
        &mut self,
        id: &str,
        destination: &str,
        funding: &str,
        interval: Option<Value>,
    ) -> Result<(String, transaction::Transaction, (SystemTime, SystemTime))> {
        let mut payload = json!({"payments":[{"address":destination,"amount":{"quantity":2_000_000,"unit":"lovelace"}}]});
        if let Some(interval) = interval {
            payload["validity_interval"] = interval;
        }
        let before = SystemTime::now();
        let value = self.call(
            "constructTransaction",
            "POST",
            &format!("/wallets/{id}/transactions-construct"),
            Some(payload),
            202,
        )?;
        let after = SystemTime::now();
        let unsigned = text(&value, "/transaction")?;
        let unsigned_tx = transaction::inspect(&unsigned, false)?;
        ensure!(
            unsigned_tx.inputs == [funding.to_owned()] && unsigned_tx.verification_keys.is_empty(),
            "validity construct changed funding or added witnesses"
        );
        ensure!(
            number(&value, "/fee/quantity")? == unsigned_tx.fee && unsigned_tx.fee > 0,
            "validity fee differs"
        );
        let destination_hex = hex::encode(crate::encoding::bech32(destination)?.1);
        ensure!(
            unsigned_tx
                .outputs
                .iter()
                .any(|v| v.address_hex == destination_hex && v.coin == 2_000_000)
                && unsigned_tx.outputs.iter().all(|v| v.assets.is_empty()),
            "validity payment output differs"
        );
        let total = unsigned_tx
            .outputs
            .iter()
            .try_fold(unsigned_tx.fee, |sum, v| {
                sum.checked_add(v.coin)
                    .context("validity accounting overflow")
            })?;
        ensure!(
            total == FUNDING,
            "validity construction creates or loses ADA"
        );
        let signed = self.call(
            "signTransaction",
            "POST",
            &format!("/wallets/{id}/transactions-sign"),
            Some(json!({"transaction":unsigned,"passphrase":PASSWORD})),
            202,
        )?;
        let signed = text(&signed, "/transaction")?;
        let tx = transaction::inspect(&signed, true)?;
        ensure!(
            tx.id == unsigned_tx.id && tx.verification_keys.len() == 1,
            "signing changed body or witness count"
        );
        let decoded = self.call(
            "decodeTransaction",
            "POST",
            &format!("/wallets/{id}/transactions-decode"),
            Some(json!({"transaction":signed})),
            202,
        )?;
        let (lower, upper) = transaction::validity(&signed)?;
        ensure!(
            decoded["id"] == tx.id
                && decoded["validity_interval"]
                    == bounds(lower.unwrap_or(0), upper.context("missing TTL")?),
            "decoded validity differs from exact signed body"
        );
        Ok((signed, tx, (before, after)))
    }
    fn validity_unchanged(
        &mut self,
        id: &str,
        address: &str,
        funding: &str,
        utxos: &Value,
        options: &LiveOptions,
    ) -> Result<()> {
        self.family_ready_balance(SHELLEY, id, FUNDING)?;
        ensure!(
            &options.node.utxos(address, self.timeout)? == utxos,
            "rejected/unsigned validity call changed UTxOs"
        );
        let history = self.call(
            "listTransactions",
            "GET",
            &format!("/wallets/{id}/transactions"),
            None,
            200,
        )?;
        let entries = history.as_array().context("missing history array")?;
        ensure!(
            entries.len() == 1
                && entries[0]["id"] == funding.split('#').next().unwrap()
                && entries[0]["status"] == "in_ledger"
                && entries[0]["direction"] == "incoming"
                && entries[0].pointer("/amount/quantity") == Some(&json!(FUNDING)),
            "failed/unsigned validity call changed funded history"
        );
        Ok(())
    }
    pub(super) fn exercise_validity(&mut self, options: &LiveOptions) -> Result<()> {
        let genesis: Value = serde_json::from_slice(&std::fs::read(
            options
                .shelley_genesis
                .as_ref()
                .context("validity requires public Shelley genesis")?,
        )?)?;
        let start = text(&genesis, "/systemStart")?;
        let shelley_start = utc_ns(&start)?;
        let byron: Value = serde_json::from_slice(&std::fs::read(
            options
                .byron_genesis
                .as_ref()
                .context("validity requires public Byron genesis")?,
        )?)?;
        let byron_seconds = number(&byron, "/startTime")?;
        let rounded = rounded_posix_seconds(shelley_start);
        ensure!(
            u128::from(byron_seconds) == rounded,
            "cluster genesis start-time rounding differs"
        );
        let clock = Clock {
            start: u128::from(byron_seconds) * 1_000_000_000,
            slot: decimal_ps(&genesis["slotLength"])?,
        };
        let network = self.call(
            "getNetworkParameters",
            "GET",
            "/network/parameters",
            None,
            200,
        )?;
        ensure!(
            utc_ns(&text(&network, "/blockchain_start_time")?)? == clock.start
                && decimal_ps(&network["slot_length"]["quantity"])? == clock.slot,
            "wallet slotting differs from trusted genesis"
        );
        ensure!(
            network["eras"]
                .as_object()
                .context("missing eras")?
                .values()
                .all(|v| v["epoch_number"] == 0
                    && v["epoch_start_time"]
                        .as_str()
                        .is_some_and(|s| utc_ns(s).is_ok_and(|t| t == clock.start))),
            "validity profile requires single-era cluster slotting"
        );
        let mnemonic = || -> Result<Vec<String>> {
            Ok(bip39::Mnemonic::generate(15)?
                .words()
                .map(str::to_owned)
                .collect())
        };
        let sender = self.create("conformance-validity-sender", mnemonic()?)?;
        let recipient = self.create("conformance-validity-recipient", mnemonic()?)?;
        self.family_ready_balance(SHELLEY, &sender, 0)?;
        self.family_ready_balance(SHELLEY, &recipient, 0)?;
        let a = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{sender}/addresses"),
            None,
            200,
        )?;
        let address = text(&a, "/0/id")?;
        let a = self.call(
            "listAddresses",
            "GET",
            &format!("/wallets/{recipient}/addresses"),
            None,
            200,
        )?;
        let destination = text(&a, "/0/id")?;
        self.family_fund(SHELLEY, &sender, &address, options)?;
        let utxos = options.node.utxos(&address, self.timeout)?;
        let keys: Vec<_> = utxos
            .as_object()
            .context("invalid UTxO map")?
            .keys()
            .cloned()
            .collect();
        ensure!(keys.len() == 1, "validity requires one exact funded input");
        let funding = &keys[0];
        // Defaults and relative seconds use exact request-time brackets, never tolerances.
        for relative in [false, true] {
            let (signed,_,(before,after)) = self.validity_build(&sender,&destination,funding,relative.then(||json!({"invalid_before":{"quantity":0,"unit":"second"},"invalid_hereafter":{"quantity":90,"unit":"second"}})))?;
            let (lower, upper) = transaction::validity(&signed)?;
            let lower = lower.unwrap_or(0);
            let upper = upper.context("default/relative TTL missing")?;
            if relative {
                ensure!(
                    (clock.at(before, 0, true)?..=clock.at(after, 0, true)?).contains(&lower),
                    "relative lower bound outside clock bracket"
                );
            } else {
                ensure!(lower == 0, "default lower bound differs");
            }
            let ttl = if relative { 90 } else { 7200 };
            ensure!(
                (clock.at(before, ttl, true)?..=clock.at(after, ttl, true)?).contains(&upper),
                "TTL outside exact clock bracket"
            );
            self.validity_unchanged(&sender, &address, funding, &utxos, options)?;
        }
        for interval in [
            bounds(2, 1),
            json!({"invalid_before":{"quantity":-1,"unit":"second"},"invalid_hereafter":{"quantity":0,"unit":"second"}}),
        ] {
            let response = self.call("constructTransaction","POST",&format!("/wallets/{sender}/transactions-construct"),Some(json!({"payments":[{"address":destination,"amount":{"quantity":2_000_000,"unit":"lovelace"}}],"validity_interval":interval})),403)?;
            ensure!(
                response
                    == json!({"code":"invalid_validity_bounds","message":"Attempted to create a transaction with invalid validity bounds. Please make sure that the 'invalid_before' bound precedes the 'invalid_hereafter' bound, and that you have not used negative time values."}),
                "invalid validity error differs"
            );
            self.validity_unchanged(&sender, &address, funding, &utxos, options)?;
        }
        for expired in [(0, 1), (1, 1)] {
            let (signed, _, _) = self.validity_build(
                &sender,
                &destination,
                funding,
                Some(bounds(expired.0, expired.1)),
            )?;
            ensure!(
                transaction::validity(&signed)? == (Some(expired.0), Some(expired.1)),
                "expired CBOR interval differs"
            );
            let tip = number(&options.node.mempool_info(self.timeout)?, "/slot")?;
            let response = self.api.request(&request(
                "POST",
                format!("/wallets/{sender}/transactions-submit"),
                Some(json!({"transaction":signed})),
            ))?;
            rejected(
                &response,
                expired.0,
                expired.1,
                tip,
                number(&options.node.mempool_info(self.timeout)?, "/slot")?,
            )?;
            self.validity_unchanged(&sender, &address, funding, &utxos, options)?;
        }
        self.report.record(
            "live:expired-transaction-rejected",
            &["tx.validity-interval".into()],
            Ok(()),
        );
        let lower = clock
            .at(SystemTime::now(), 0, true)?
            .checked_add(50)
            .context("lower bound overflow")?;
        let upper = lower.checked_add(600).context("upper bound overflow")?;
        let (signed, tx, _) =
            self.validity_build(&sender, &destination, funding, Some(bounds(lower, upper)))?;
        ensure!(
            transaction::validity(&signed)? == (Some(lower), Some(upper)),
            "future CBOR interval differs"
        );
        let tip = number(&options.node.mempool_info(self.timeout)?, "/slot")?;
        let response = self.api.request(&request(
            "POST",
            format!("/wallets/{sender}/transactions-submit"),
            Some(json!({"transaction":signed})),
        ))?;
        let now = clock.at(SystemTime::now(), 0, false)?;
        ensure!(
            now < lower,
            "future fixture crossed its lower bound before rejection"
        );
        rejected(
            &response,
            lower,
            upper,
            tip,
            number(&options.node.mempool_info(self.timeout)?, "/slot")?,
        )?;
        self.validity_unchanged(&sender, &address, funding, &utxos, options)?;
        let deadline = Instant::now() + self.timeout;
        while options.node.tip(self.timeout)?.slot < lower {
            ensure!(
                Instant::now() < deadline,
                "node did not reach validity lower bound"
            );
            sleep(Duration::from_millis(200));
        }
        let accepted = self.call(
            "submitTransaction",
            "POST",
            &format!("/wallets/{sender}/transactions-submit"),
            Some(json!({"transaction":signed})),
            202,
        )?;
        ensure!(
            accepted["id"] == tx.id,
            "same signed transaction admission ID differs"
        );
        self.family_confirm(SHELLEY, &sender, &tx.id)?;
        self.family_confirm(SHELLEY, &recipient, &tx.id)?;
        self.family_ready_balance(SHELLEY, &sender, FUNDING - 2_000_000 - tx.fee)?;
        self.family_ready_balance(SHELLEY, &recipient, 2_000_000)?;
        for output in &tx.outputs {
            // The sender's base addresses may include newly discovered change addresses.
            let all = self.call(
                "listAddresses",
                "GET",
                &format!("/wallets/{sender}/addresses"),
                None,
                200,
            )?;
            let output_address =
                if output.address_hex == hex::encode(crate::encoding::bech32(&destination)?.1) {
                    destination.clone()
                } else {
                    all.as_array()
                        .context("missing sender addresses")?
                        .iter()
                        .filter_map(|v| v["id"].as_str())
                        .find(|a| {
                            crate::encoding::bech32(a)
                                .is_ok_and(|(_, b)| hex::encode(b) == output.address_hex)
                        })
                        .context("change output is not owned")?
                        .to_owned()
                };
            options
                .node
                .payment(&tx.id, &output_address, output.coin, self.timeout)?;
        }
        ensure!(
            options
                .node
                .utxos(&address, self.timeout)?
                .as_object()
                .context("invalid spent UTxOs")?
                .get(funding)
                .is_none(),
            "confirmed control did not spend funding"
        );
        self.report.record(
            "validity-lower-bound",
            &["tx.validity-interval".into()],
            Ok(()),
        );
        self.report
            .record("validity-ttl", &["tx.validity-interval".into()], Ok(()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cluster_genesis_rounding_handles_upper_fraction_and_half_even() {
        assert_eq!(
            rounded_posix_seconds(utc_ns("2026-11-04T23:23:44.913065319Z").unwrap()),
            1_793_834_625
        );
        for (ns, expected) in [
            (0, 0),
            (499_999_999, 0),
            (500_000_000, 0),
            (500_000_001, 1),
            (1_499_999_999, 1),
            (1_500_000_000, 2),
            (2_500_000_000, 2),
            (2_999_999_999, 3),
        ] {
            assert_eq!(rounded_posix_seconds(ns), expected);
        }
    }
    #[test]
    fn genesis_clock_is_exact_at_fractional_slots_and_calendar_boundaries() {
        assert_eq!(utc_ns("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            utc_ns("2000-03-01T00:00:00Z").unwrap() - utc_ns("2000-02-28T00:00:00Z").unwrap(),
            172_800_000_000_000
        );
        assert_eq!(
            utc_ns("2100-03-01T00:00:00Z").unwrap() - utc_ns("2100-02-28T00:00:00Z").unwrap(),
            86_400_000_000_000
        );
        assert!(utc_ns("2100-02-29T00:00:00Z").is_err());
        assert!(utc_ns("2026-11-03T24:00:00Z").is_err());
        assert_eq!(utc_ns("1970-01-01T00:00:00.000000001Z").unwrap(), 1);
        let clock = Clock {
            start: 0,
            slot: decimal_ps(&json!(0.2)).unwrap(),
        };
        assert_eq!(clock.slot, 200_000_000_000);
        assert_eq!(
            decimal_ps(&serde_json::from_str::<Value>("2e-1").unwrap()).unwrap(),
            clock.slot
        );
        let t = UNIX_EPOCH + Duration::from_nanos(200000000);
        assert_eq!(clock.at(t, 0, true).unwrap(), 1);
        assert_eq!(clock.at(t + Duration::from_nanos(1), 0, true).unwrap(), 2);
        assert_eq!(clock.at(t - Duration::from_nanos(1), 0, false).unwrap(), 0);
        assert_eq!(clock.at(t, 7200, true).unwrap(), 36001);
    }
    #[test]
    fn node_guard_requires_exact_bounds_slot_cause_and_envelope() {
        let actual: Value =
            serde_json::from_str(include_str!("../../fixtures/validity-expired-error.json"))
                .unwrap();
        let captured = Response {
            status: 500,
            media_type: Some("application/json".into()),
            json: Some(actual),
            raw: vec![],
        };
        assert!(rejected(&captured, 0, 1, 677, 681).is_ok());
        let signed: Value = serde_json::from_str(include_str!(
            "../../fixtures/validity-expired-transaction.json"
        ))
        .unwrap();
        assert_eq!(
            transaction::validity(signed["transaction"].as_str().unwrap()).unwrap(),
            (Some(0), Some(1))
        );
        let message=format!("{PREFIX}OutsideValidityIntervalUTxO (ValidityInterval {{invalidBefore = SJust (SlotNo 0), invalidHereafter = SJust (SlotNo 1)}}) (SlotNo 20{SUFFIX}");
        let mut r = Response {
            status: 500,
            media_type: Some("application/json".into()),
            json: Some(json!({"code":"created_invalid_transaction","message":message})),
            raw: vec![],
        };
        assert!(rejected(&r, 0, 1, 18, 21).is_ok());
        assert!(rejected(&r, 0, 2, 18, 21).is_err());
        assert!(rejected(&r, 0, 1, 21, 22).is_err());
        assert!(rejected(&r, 0, 1, 18, 19).is_err());
        r.status = 403;
        assert!(rejected(&r, 0, 1, 18, 21).is_err());
    }
}
