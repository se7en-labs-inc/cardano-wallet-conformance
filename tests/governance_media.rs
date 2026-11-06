use serde_json::json;
use wallet_conformance::{
    api::{Contract, Response},
    report,
    scenarios::Suite,
};

#[test]
fn governance_media_cases_are_registered_and_reject_other_error_codes() {
    let contract = Contract::pinned().unwrap();
    let suite: Suite =
        serde_json::from_str(include_str!("../fixtures/http-governance-media.json")).unwrap();
    assert_eq!(suite.cases.len(), 4);
    for case in &suite.cases {
        assert!(report::registered_http(case).unwrap());
        let mut response = Response {
            status: case.expected_status,
            media_type: Some("application/json".into()),
            raw: vec![],
            json: Some(json!({
                "code": case.assertions["/code"],
                "message": case.assertions["/message"],
            })),
        };
        contract.validate(&case.operation, &response).unwrap();
        response.json.as_mut().unwrap()["code"] = json!("no_such_wallet");
        assert!(contract.validate(&case.operation, &response).is_err());
    }
}

#[test]
fn approved_collateral_code_overlay_accepts_haskell_and_rejects_old_spelling() {
    let contract = Contract::pinned().unwrap();
    for (code, accepted) in [
        ("balance_tx_existing_return_collateral", true),
        ("balance_tx_existing_collateral", true),
        ("balance_tx_existing_total_collateral", true),
        ("balance_tx_existing_collateral_return_outputs", false),
        ("invented_error", false),
    ] {
        let response = Response {
            status: 403,
            media_type: Some("application/json".into()),
            raw: vec![],
            json: Some(json!({"code":code,"message":"source-grounded test error"})),
        };
        assert_eq!(
            contract.validate("balanceTransaction", &response).is_ok(),
            accepted
        );
    }
    assert!(include_str!("../fixtures/api/openapi.yaml")
        .contains("enum: [\"balance_tx_existing_collateral_return_outputs\"]"));
}
