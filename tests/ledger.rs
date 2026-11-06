use serde_json::json;
use wallet_conformance::{adapter::Vector, ledger, report};
fn profiles() -> Vec<Vector> {
    serde_json::from_str(include_str!("../fixtures/vectors/ledger-profiles.json")).unwrap()
}
#[test]
fn wallet_codec_metadata_and_ledger_signature_goldens_obey_independent_laws() {
    let vectors = profiles();
    assert_eq!(vectors.len(), 27);
    for vector in vectors {
        assert!(report::registered_vector(&vector).unwrap());
        ledger::validate(&vector, vector.expected.as_ref().unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", vector.id));
    }
}
#[test]
fn independent_ledger_checks_reject_mutated_hashes_metadata_ranges_and_signatures() {
    let vectors = profiles();
    for (id, field, value) in [
        ("tx-cbor-conway", "transaction_id", json!("00".repeat(32))),
        ("metadata-cbor-golden", "cbor_hex", json!("a0")),
        ("metadata-oversize-rejected", "valid", json!(true)),
        ("ed25519-noncanonical-s", "valid", json!(true)),
        ("ed25519-small-order-public-key", "valid", json!(true)),
    ] {
        let vector = vectors.iter().find(|v| v.id == id).unwrap();
        let mut actual = vector.expected.clone().unwrap();
        actual["result"][field] = value;
        assert!(ledger::validate(vector, &actual).is_err(), "{id}");
    }
}
#[test]
fn metadata_symmetric_integer_and_utf8_boundaries_are_independent_of_json_encoding() {
    for (n, valid) in [
        (-i128::from(u64::MAX) - 1, false),
        (-i128::from(u64::MAX), true),
        (i128::from(u64::MAX), true),
        (i128::from(u64::MAX) + 1, false),
    ] {
        assert_eq!(
            ledger::metadata(&json!({"entries":[{"label":0,"value":{"type":"number","value":n}}]}))
                .unwrap()["valid"],
            valid
        );
    }
    for (count, valid) in [(32, true), (33, false)] {
        assert_eq!(
            ledger::metadata(
                &json!({"entries":[{"label":0,"value":{"type":"text","value":"é".repeat(count)}}]})
            )
            .unwrap()["valid"],
            valid
        );
    }
    assert!(ledger::transaction_id(&[0xff]).is_err());
}
