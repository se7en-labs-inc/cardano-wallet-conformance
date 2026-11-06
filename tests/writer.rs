use serde_json::json;
use wallet_conformance::{adapter::Vector, report, transaction, writer};
fn profiles() -> Vec<Vector> {
    serde_json::from_str(include_str!("../fixtures/vectors/writer-profiles.json")).unwrap()
}
#[test]
fn actual_wallet_writer_goldens_obey_independent_signature_and_certificate_laws() {
    let vectors = profiles();
    assert_eq!(vectors.len(), 28);
    for vector in vectors {
        assert!(report::registered_vector(&vector).unwrap());
        writer::validate(&vector, vector.expected.as_ref().unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", vector.id));
    }
}
#[test]
fn merge_really_preserves_two_distinct_signatures_and_duplicate_signing_is_idempotent() {
    let vectors = profiles();
    let get = |id: &str| vectors.iter().find(|v| v.id == id).unwrap();
    let merged = get("witness-merge");
    let result = merged.expected.as_ref().unwrap();
    let tx = transaction::inspect(
        result["result"]["transaction_cbor_hex"].as_str().unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(tx.verification_keys.len(), 2);
    assert_ne!(tx.verification_keys[0], tx.verification_keys[1]);
    assert!(
        writer::validate(merged, get("witness-sign-first").expected.as_ref().unwrap()).is_err()
    );
    assert_eq!(
        get("witness-duplicate").expected,
        get("witness-sign-first").expected
    );
    assert_eq!(get("witness-merge-idempotent").expected, merged.expected);
    let mut actual = result.clone();
    let mut raw = hex::decode(actual["result"]["transaction_cbor_hex"].as_str().unwrap()).unwrap();
    let public = hex::decode(&tx.verification_keys[0]).unwrap();
    let pos = raw.windows(32).position(|w| w == public).unwrap();
    raw[pos + 34] ^= 1;
    actual["result"]["transaction_cbor_hex"] = json!(hex::encode(raw));
    assert!(writer::validate(merged, &actual).is_err());
}
#[test]
fn writer_checks_reject_bootstrap_attributes_script_hashes_and_certificate_mutations() {
    let vectors = profiles();
    let bootstrap = vectors
        .iter()
        .find(|v| v.id == "witness-bootstrap-golden")
        .unwrap();
    let mut actual = bootstrap.expected.clone().unwrap();
    let mut raw = hex::decode(actual["result"]["witness_cbor_hex"].as_str().unwrap()).unwrap();
    *raw.last_mut().unwrap() ^= 1;
    actual["result"]["witness_cbor_hex"] = json!(hex::encode(raw));
    assert!(writer::validate(bootstrap, &actual).is_err());
    for (id, field, value) in [
        (
            "witness-script-golden",
            "script_hash_hex",
            json!("00".repeat(28)),
        ),
        (
            "governance-certificate-golden",
            "certificates_cbor_hex",
            json!([]),
        ),
        (
            "stake-deposit-refund",
            "certificates_cbor_hex",
            json!(["00"]),
        ),
    ] {
        let vector = vectors.iter().find(|v| v.id == id).unwrap();
        let mut actual = vector.expected.clone().unwrap();
        actual["result"][field] = value;
        assert!(writer::validate(vector, &actual).is_err(), "{id}");
    }
}
