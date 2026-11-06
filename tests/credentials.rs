use serde_json::{json, Value};
use wallet_conformance::{adapter::Vector, credentials};

fn corpus() -> Vec<Vector> {
    serde_json::from_str(include_str!("../fixtures/vectors/wallet-credentials.json")).unwrap()
}

#[test]
fn frozen_credential_observations_satisfy_independent_transition_and_signature_laws() {
    let vectors = corpus();
    assert_eq!(vectors.len(), 61);
    for vector in vectors {
        credentials::validate(&vector, vector.expected.as_ref().unwrap())
            .unwrap_or_else(|error| panic!("{}: {error}", vector.id));
    }
}

#[test]
fn credential_laws_reject_false_migration_claims_password_checks_and_signatures() {
    let vectors = corpus();
    let correct = vectors
        .iter()
        .find(|v| v.id == "root-decrypt-v1-correct")
        .unwrap();
    for (pointer, value) in [
        ("/result/steps/0/credentials_unchanged", json!(true)),
        ("/result/steps/0/metadata_unchanged", json!(true)),
        ("/result/steps/0/timestamp_unchanged", json!(false)),
        ("/result/steps/0/callback/access", json!("v2")),
        ("/result/initial/password_checks/0", json!(false)),
        (
            "/result/steps/0/callback/signature_hex",
            json!("00".repeat(64)),
        ),
    ] {
        let mut forged = correct.expected.as_ref().unwrap().clone();
        *forged.pointer_mut(pointer).unwrap() = value;
        assert!(
            credentials::validate(correct, &forged).is_err(),
            "accepted forged observation at {pointer}"
        );
    }
    let wrong = vectors
        .iter()
        .find(|v| v.id == "root-decrypt-v1-wrong-passphrase")
        .unwrap();
    let mut forged = wrong.expected.as_ref().unwrap().clone();
    forged["result"]["steps"][0]["callback"] = json!({"access":"v1"});
    assert!(credentials::validate(wrong, &forged).is_err());
    let mut changed_mnemonic: Vector =
        serde_json::from_value(serde_json::to_value(correct).unwrap()).unwrap();
    changed_mnemonic.input["mnemonic"][0] = Value::String("zoo".into());
    assert!(credentials::validate(&changed_mnemonic, correct.expected.as_ref().unwrap()).is_err());
}

#[test]
fn migration_fault_preservation_requires_actual_warning_and_successful_retry() {
    let vectors = corpus();
    let fault = vectors
        .iter()
        .find(|v| v.id == "root-migration-failure-preserves-v1")
        .unwrap();
    let expected = fault.expected.as_ref().unwrap();
    assert_eq!(expected["result"]["steps"][0]["after"]["format"], "v1");
    assert_eq!(expected["result"]["steps"][1]["after"]["format"], "v2");
    for (pointer, value) in [
        ("/result/steps/0/migration_faults_consumed", json!(0)),
        ("/result/steps/0/migration_warnings", json!(0)),
        ("/result/steps/0/production_kdf_parameters", json!(false)),
        ("/result/steps/0/credentials_unchanged", json!(false)),
        ("/result/steps/0/after/format", json!("v2")),
        ("/result/steps/1/after/format", json!("v1")),
    ] {
        let mut changed = expected.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            credentials::validate(fault, &changed).is_err(),
            "accepted forged fault observation at {pointer}"
        );
    }
}
