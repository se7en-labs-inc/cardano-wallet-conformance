use serde_json::json;
use wallet_conformance::{adapter::Vector, keys};

fn goldens() -> Vec<Vector> {
    serde_json::from_str(include_str!("../fixtures/vectors/haskell-keys.json")).unwrap()
}

#[test]
fn independent_key_goldens_have_matching_public_private_children_and_valid_signatures() {
    let vectors = goldens();
    let mut pairs = 0;
    for vector in &vectors {
        keys::validate(vector, vector.expected.as_ref().unwrap()).unwrap();
        if let Some(prefix) = vector.id.strip_suffix("-public") {
            let private = vectors
                .iter()
                .find(|v| v.id == format!("{prefix}-private"))
                .unwrap();
            assert_eq!(
                vector.expected.as_ref().unwrap()["result"]["xpub_hex"],
                private.expected.as_ref().unwrap()["result"]["xpub_hex"]
            );
            pairs += 1;
        }
    }
    assert_eq!(pairs, 54);
}

#[test]
fn key_checks_reject_chain_code_and_signature_mutations() {
    let vectors = goldens();
    let private = vectors
        .iter()
        .find(|v| v.id == "haskell-Shelley-root")
        .unwrap();
    let mut actual = private.expected.as_ref().unwrap().clone();
    let mut bytes = hex::decode(actual["result"]["xprv_hex"].as_str().unwrap()).unwrap();
    bytes[64] ^= 1;
    actual["result"]["xprv_hex"] = json!(hex::encode(bytes));
    assert!(keys::validate(private, &actual).is_err());
    let signing = vectors
        .iter()
        .find(|v| v.operation == "keys.sign-extended")
        .unwrap();
    let mut actual = signing.expected.as_ref().unwrap().clone();
    actual["result"]["signature_hex"] = json!("00".repeat(64));
    assert!(keys::validate(signing, &actual).is_err());
    let mut changed: Vector =
        serde_json::from_value(serde_json::to_value(signing).unwrap()).unwrap();
    changed.input["message_hex"] = json!("ff");
    assert!(keys::validate(&changed, signing.expected.as_ref().unwrap()).is_err());
}

#[test]
fn frozen_key_boundaries_are_registered_and_preserve_expected_rejections() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/key-boundaries.json")).unwrap();
    assert_eq!(vectors.len(), 16);
    let templates = keys::requests().unwrap();
    for vector in vectors {
        assert!(wallet_conformance::report::registered_vector(&vector).unwrap());
        let template = templates.iter().find(|v| v.id == vector.id).unwrap();
        assert_eq!(template.input, vector.input);
        if let Some(expected) = &template.expected {
            assert_eq!(Some(expected), vector.expected.as_ref());
        }
        keys::validate(&vector, vector.expected.as_ref().unwrap()).unwrap();
    }
}
