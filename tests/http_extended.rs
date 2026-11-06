use serde_json::{json, Value};
use wallet_conformance::{
    api::{Contract, Response},
    http_extended, report,
    scenarios::Suite,
};
#[test]
fn extended_matrix_is_reproducible_registered_and_bound_to_real_api_routes() {
    let contract = Contract::pinned().unwrap();
    let frozen: Value =
        serde_json::from_str(include_str!("../fixtures/http-extended.json")).unwrap();
    assert_eq!(http_extended::generate(&contract).unwrap(), frozen);
    let suite: Suite = serde_json::from_value(frozen).unwrap();
    assert_eq!(suite.cases.len() + suite.cleanup.len(), 85);
    for case in suite.cases.iter().chain(&suite.cleanup) {
        assert!(report::registered_http(case).unwrap());
        assert!(contract
            .operation(&case.operation)
            .unwrap()
            .statuses
            .contains(&case.expected_status));
    }
    let balance = suite
        .cases
        .iter()
        .find(|c| c.id == "extended-unknown-balanceTransaction")
        .unwrap();
    assert_eq!(balance.request.body.as_ref().unwrap()["inputs"], json!([]));
    assert_eq!(
        balance.request.body.as_ref().unwrap()["redeemers"],
        json!([])
    );
    let address = suite
        .cases
        .iter()
        .find(|c| c.id == "extended-random-address")
        .unwrap();
    assert!(
        address.request.body.as_ref().unwrap()["address_index"]
            .as_u64()
            .unwrap()
            >= 2147483648
    );
}
#[test]
fn approved_corrections_preserve_strict_error_alternatives_and_required_request_fields() {
    let contract = Contract::pinned().unwrap();
    let op = contract.operation("postMaintenanceAction").unwrap();
    assert!(op.statuses.contains(&400));
    assert!(!op.statuses.contains(&404));
    let required = &contract.effective_document()["components"]["schemas"]
        ["ApiBalanceTransactionPostData"]["required"];
    for name in ["transaction", "inputs", "redeemers"] {
        assert!(required.as_array().unwrap().contains(&json!(name)));
    }
    for code in ["no_utxos_available", "cannot_cover_fee", "made_up_error"] {
        let body = json!({"code":code,"message":"public test fixture"});
        let response = Response {
            status: 403,
            media_type: Some("application/json".into()),
            raw: serde_json::to_vec(&body).unwrap(),
            json: Some(body),
        };
        assert_eq!(
            contract.validate("getDelegationFee", &response).is_ok(),
            code != "made_up_error"
        );
    }
}
