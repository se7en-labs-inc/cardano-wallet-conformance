//! Actual wallet slot/time goldens with independent exact picosecond arithmetic.
use crate::adapter::{self, Vector};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
const ORACLE: &str = "c86c3e29e91f1110891681cc62802101f0d03fccc5c451eb5d4ef0a8332092af";
fn expected(input: &Value) -> Value {
    let parsed = (|| -> Option<Value> {
        let slot = input["slot_length_picos"].as_u64()?;
        let time = input["elapsed_picos"].as_u64()?;
        let epoch = input["epoch_length"].as_u64()?;
        if slot == 0
            || slot > 1_000_000_000_000_000
            || epoch == 0
            || epoch > u64::from(u32::MAX)
            || time / slot == u64::MAX
        {
            return None;
        }
        Some(
            json!({"result":{"floor_slot":time/slot,"ceiling_slot":time.div_ceil(slot),"floor_time_picos":time-time%slot}}),
        )
    })();
    parsed.unwrap_or_else(|| json!({"error":{"code":"invalid_input"}}))
}
pub fn validate(vector: &Vector, actual: &Value) -> Result<()> {
    ensure!(
        actual == &expected(&vector.input),
        "slot/time oracle differs from exact independent integer boundary law"
    );
    Ok(())
}
pub fn capture(binary: &Path) -> Result<Vec<Vector>> {
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(binary)?)) == ORACLE,
        "slotting oracle binary differs"
    );
    let mut vectors = Vec::new();
    let mut add = |id: String, input: Value| -> Result<()> {
        let mut vector = Vector {id,requirements:vec!["tx.validity-interval".into()],source:format!("Wallet2fc5c383 actual Primitive.Slotting mkSingleEraInterpreter/ongoingSlotAt/ceilingSlotAt/slotToUTCTime; picosecond-exact single-era wrapper, not a hard-fork claim; SlottingAdapter sha256:{ORACLE}; independent Rust quotient/remainder/ceiling laws"),operation:"time.slot-boundary".into(),input,expected:None,selection_invariants:false};
        let actual = adapter::invoke(binary, &[], &vector, Duration::from_secs(30))?;
        ensure!(
            actual == adapter::invoke(binary, &[], &vector, Duration::from_secs(30))?,
            "slot/time oracle replay differs"
        );
        validate(&vector, &actual)
            .with_context(|| format!("slot/time boundary failed: {}", vector.id))?;
        vector.expected = Some(actual);
        vectors.push(vector);
        Ok(())
    };
    for slot in [
        200_000_000_000u64,
        1_000_000_000_000,
        1_500_000_000_000,
        333_333_333_333,
    ] {
        for index in [0u64, 1, 2, 119, 120, 121, 21_600] {
            for delta in [-1i64, 0, 1] {
                let Some(time) = (slot * index).checked_add_signed(delta) else {
                    continue;
                };
                let id = if slot == 200_000_000_000 && index == 0 && delta == 0 {
                    "validity-slot-time-boundary".into()
                } else {
                    format!("slot-time-{slot}-{index}-{delta}")
                };
                add(
                    id,
                    json!({"slot_length_picos":slot,"elapsed_picos":time,"epoch_length":120}),
                )?;
            }
        }
    }
    for (id, input) in [
        (
            "negative-time",
            json!({"slot_length_picos":200000000000u64,"elapsed_picos":-1,"epoch_length":120}),
        ),
        (
            "zero-slot",
            json!({"slot_length_picos":0,"elapsed_picos":0,"epoch_length":120}),
        ),
        (
            "zero-epoch",
            json!({"slot_length_picos":200000000000u64,"elapsed_picos":0,"epoch_length":0}),
        ),
        (
            "huge-epoch",
            json!({"slot_length_picos":200000000000u64,"elapsed_picos":0,"epoch_length":4294967296u64}),
        ),
        (
            "slot-overflow",
            json!({"slot_length_picos":1,"elapsed_picos":u64::MAX,"epoch_length":120}),
        ),
        (
            "missing-field",
            json!({"elapsed_picos":0,"epoch_length":120}),
        ),
        (
            "upper-time",
            json!({"slot_length_picos":1000000000000u64,"elapsed_picos":u64::MAX,"epoch_length":120}),
        ),
    ] {
        add(format!("slot-time-{id}"), input)?;
    }
    Ok(vectors)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_profiles_have_real_boundaries_and_reject_mutated_results() {
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../fixtures/vectors/slotting-profiles.json"))
                .unwrap();
        assert_eq!(vectors.len(), 87);
        assert!(vectors
            .iter()
            .any(|v| v.id == "validity-slot-time-boundary"));
        for vector in vectors {
            let actual = vector.expected.as_ref().unwrap();
            validate(&vector, actual).unwrap();
            if actual.get("result").is_some() {
                let mut changed = actual.clone();
                changed["result"]["ceiling_slot"] =
                    json!(actual["result"]["ceiling_slot"].as_u64().unwrap() + 1);
                assert!(validate(&vector, &changed).is_err());
            }
        }
    }
    #[test]
    fn rounding_never_rounds_down_after_a_boundary() {
        let mut vector = Vector {
            id: "boundary".into(),
            requirements: vec![],
            source: "unit".into(),
            operation: "time.slot-boundary".into(),
            input: json!({"slot_length_picos":200000000000u64,"elapsed_picos":200000000001u64,"epoch_length":120}),
            expected: None,
            selection_invariants: false,
        };
        let actual = expected(&vector.input);
        assert_eq!(actual["result"]["ceiling_slot"], 2);
        assert!(validate(&vector, &actual).is_ok());
        let mut changed = actual.clone();
        changed["result"]["ceiling_slot"] = json!(1);
        assert!(validate(&vector, &changed).is_err());
        changed = actual.clone();
        changed["result"]["floor_time_picos"] = json!(200000000001u64);
        assert!(validate(&vector, &changed).is_err());
        vector.input["elapsed_picos"] = json!(200000000000u64);
        assert_eq!(expected(&vector.input)["result"]["ceiling_slot"], 1);
    }
}
