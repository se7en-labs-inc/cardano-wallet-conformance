use serde_json::json;
use wallet_conformance::{adapter::Vector, mnemonics};
fn profiles() -> Vec<Vector> {
    serde_json::from_str(include_str!("../fixtures/vectors/mnemonic-profiles.json")).unwrap()
}
#[test]
fn frozen_profiles_obey_signature_serialization_and_cross_profile_laws() {
    let vectors = profiles();
    assert_eq!(vectors.len(), 13);
    let templates = mnemonics::requests().unwrap();
    for vector in &vectors {
        assert!(wallet_conformance::report::registered_vector(vector).unwrap());
        assert_eq!(
            vector.input,
            templates.iter().find(|v| v.id == vector.id).unwrap().input
        );
        mnemonics::validate(vector, vector.expected.as_ref().unwrap()).unwrap();
    }
    mnemonics::validate_relations(&vectors).unwrap();
}
#[test]
fn profile_laws_reject_corrupted_signatures_keys_and_unicode_conflation() {
    let vectors = profiles();
    let ledger = vectors
        .iter()
        .find(|v| v.id == "ledger-root-golden")
        .unwrap();
    for (field, value) in [
        ("signature_hex", json!("00".repeat(64))),
        ("encrypted_xprv_hex", json!("00".repeat(128))),
    ] {
        let mut actual = ledger.expected.as_ref().unwrap().clone();
        actual["result"][field] = value;
        assert!(mnemonics::validate(ledger, &actual).is_err());
    }
    let mut changed = vectors.clone();
    let composed = changed
        .iter()
        .find(|v| v.id == "wallet-seed-unicode-composed")
        .unwrap()
        .expected
        .clone();
    changed
        .iter_mut()
        .find(|v| v.id == "wallet-seed-unicode-decomposed")
        .unwrap()
        .expected = composed;
    assert!(mnemonics::validate_relations(&changed).is_err());
}
