use serde_json::json;
use wallet_conformance::{adapter::Vector, report, wallet_selection};
fn profiles() -> Vec<Vector> {
    serde_json::from_str(include_str!("../fixtures/vectors/wallet-selection.json")).unwrap()
}
#[test]
fn actual_wallet_selection_goldens_obey_conservation_collateral_and_error_laws() {
    let vectors = profiles();
    assert_eq!(vectors.len(), 34);
    for vector in vectors {
        assert!(report::registered_vector(&vector).unwrap());
        wallet_selection::validate(&vector, vector.expected.as_ref().unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", vector.id));
    }
}
#[test]
fn selection_checks_reject_ineligible_assets_missing_value_rounded_shortfall_and_caps() {
    let vectors = profiles();
    let eligible = vectors
        .iter()
        .find(|v| v.id == "collateral-eligibility")
        .unwrap();
    for ids in [json!([3]), json!([4]), json!([2, 2]), json!([])] {
        let mut actual = eligible.expected.clone().unwrap();
        actual["result"]["collateral"] = ids;
        assert!(wallet_selection::validate(eligible, &actual).is_err());
    }
    let mut wrong = eligible.clone();
    wrong.input["maximum_collateral_inputs"] = json!(0);
    assert!(wallet_selection::validate(&wrong, eligible.expected.as_ref().unwrap()).is_err());
    let rounding = vectors
        .iter()
        .find(|v| v.id == "collateral-percentage-rounding")
        .unwrap();
    let mut wrong = rounding.clone();
    wrong.input["utxos"][1]["coin"] = json!(300001);
    assert!(wallet_selection::validate(&wrong, rounding.expected.as_ref().unwrap()).is_err());
    let mint = vectors
        .iter()
        .find(|v| v.id == "mint-burn-quantity-boundaries")
        .unwrap();
    let mut actual = mint.expected.clone().unwrap();
    actual["result"]["change"][0]["asset_quantity"] = json!(0);
    assert!(wallet_selection::validate(mint, &actual).is_err());
    let insufficient = vectors
        .iter()
        .find(|v| v.id == "collateral-insufficient")
        .unwrap();
    let mut actual = insufficient.expected.clone().unwrap();
    actual["error"]["minimum_collateral"] = json!(300001);
    assert!(wallet_selection::validate(insufficient, &actual).is_err());
}
#[test]
fn wallet_error_precedence_and_ordinary_collateral_overlap_remain_explicit() {
    let vectors = profiles();
    let get = |id: &str| {
        vectors
            .iter()
            .find(|v| v.id == id)
            .unwrap()
            .expected
            .as_ref()
            .unwrap()
    };
    assert_eq!(
        get("wallet-selection-empty-with-payment")["error"]["code"],
        "balance_insufficient"
    );
    assert_eq!(get("wallet-selection-empty")["error"]["code"], "empty_utxo");
    assert_eq!(
        get("wallet-selection-insufficient-fee")["error"]["code"],
        "unable_to_construct_change"
    );
    assert_eq!(
        get("collateral-insufficient")["error"]["minimum_collateral"],
        300002
    );
    assert_eq!(
        get("collateral-overlap-ordinary-input")["result"]["inputs"],
        get("collateral-overlap-ordinary-input")["result"]["collateral"]
    );
}
