use serde_json::json;
use wallet_conformance::{adapter::Vector, balance, report};
fn profiles() -> Vec<Vector> {
    serde_json::from_str(include_str!("../fixtures/vectors/balance-profiles.json")).unwrap()
}
#[test]
fn actual_wallet_fee_and_minimum_ada_goldens_obey_independent_laws() {
    let vectors = profiles();
    assert_eq!(vectors.len(), 32);
    for vector in vectors {
        assert!(report::registered_vector(&vector).unwrap());
        balance::validate(&vector, vector.expected.as_ref().unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", vector.id));
    }
}
#[test]
fn fee_and_minimum_ada_checks_reject_rounding_witness_and_conservative_estimate_mutations() {
    let vectors = profiles();
    for (id, field, value) in [
        ("fee-rounding", "execution_fee", json!(2)),
        ("fee-witness-count-24", "vkey_witness_bytes", json!(2425)),
        (
            "fee-size-with-witness-over",
            "within_size_limit",
            json!(true),
        ),
        ("min-utxo-ada", "wallet_minimum_coin", json!(849070)),
        ("min-utxo-at-minimum", "below_minimum", json!(true)),
        ("min-utxo-datum", "minimum_coin", json!(0)),
        (
            "min-utxo-reference-script",
            "wallet_output_cbor_hex",
            json!("00"),
        ),
    ] {
        let vector = vectors.iter().find(|v| v.id == id).unwrap();
        let mut actual = vector.expected.clone().unwrap();
        actual["result"][field] = value;
        assert!(balance::validate(vector, &actual).is_err(), "{id}");
    }
}
#[test]
fn minimum_ada_tracks_serialized_coin_boundaries_and_exact_threshold() {
    let vectors = profiles();
    let get = |id: &str| {
        &vectors
            .iter()
            .find(|v| v.id == id)
            .unwrap()
            .expected
            .as_ref()
            .unwrap()["result"]
    };
    assert_eq!(
        get("min-utxo-coin-24")["minimum_coin"].as_u64().unwrap()
            - get("min-utxo-coin-23")["minimum_coin"].as_u64().unwrap(),
        4310
    );
    assert_eq!(
        get("min-utxo-coin-256")["minimum_coin"].as_u64().unwrap()
            - get("min-utxo-coin-255")["minimum_coin"].as_u64().unwrap(),
        4310
    );
    assert_eq!(get("min-utxo-at-minimum")["below_minimum"], false);
    assert_eq!(get("min-utxo-below-minimum")["below_minimum"], true);
    assert_eq!(
        get("min-utxo-coin-23")["wallet_minimum_coin"],
        get("min-utxo-coin-maximum")["wallet_minimum_coin"]
    );
}

#[test]
fn fee_overflow_and_zero_denominators_fail_without_panicking() {
    let vectors = profiles();
    let mut input = vectors
        .iter()
        .find(|v| v.id == "fee-witness-count")
        .unwrap()
        .input
        .clone();
    input["transaction_bytes"] = json!(u64::MAX);
    input["coefficient"] = json!(u64::MAX);
    assert!(balance::fee(&input).is_err());
    input = vectors[0].input.clone();
    input["memory_price"]["denominator"] = json!(0);
    assert!(balance::fee(&input).is_err());
}
