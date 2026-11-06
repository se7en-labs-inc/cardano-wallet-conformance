use serde_json::{json, Value};
use wallet_conformance::{adapter::Vector, addresses, encoding};
fn profiles() -> Vec<Vector> {
    serde_json::from_str(include_str!("../fixtures/vectors/address-profiles.json")).unwrap()
}
#[test]
fn frozen_address_script_profiles_obey_independent_byte_and_evaluation_laws() {
    let vectors = profiles();
    assert_eq!(vectors.len(), 56);
    for vector in vectors {
        assert!(wallet_conformance::report::registered_vector(&vector).unwrap());
        addresses::validate(&vector, vector.expected.as_ref().unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", vector.id));
    }
}
#[test]
fn address_script_checks_reject_changed_evaluation_hashes_headers_and_crc() {
    let vectors = profiles();
    let native = vectors
        .iter()
        .find(|v| v.id == "native-script-all")
        .unwrap();
    for (field, value) in [
        ("satisfied", json!(false)),
        ("hash_hex", json!("00".repeat(28))),
        ("cbor_hex", json!("00")),
    ] {
        let mut actual = native.expected.clone().unwrap();
        actual["result"][field] = value;
        assert!(addresses::validate(native, &actual).is_err());
    }
    let reward = vectors
        .iter()
        .find(|v| v.id == "address-reward-script")
        .unwrap();
    let mut actual = reward.expected.clone().unwrap();
    let bytes = hex::decode(actual["result"]["address_hex"].as_str().unwrap()).unwrap();
    actual["result"]["address"] = json!(encoding::bech32_encode("addr", &bytes).unwrap());
    assert!(addresses::validate(reward, &actual).is_err());
    let byron = vectors
        .iter()
        .find(|v| v.id == "address-byron-icarus")
        .unwrap();
    let mut actual = byron.expected.clone().unwrap();
    let mut bytes = hex::decode(actual["result"]["address_hex"].as_str().unwrap()).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    actual["result"]["address_hex"] = json!(hex::encode(&bytes));
    actual["result"]["address"] = json!(encoding::base58_encode(&bytes).unwrap());
    assert!(addresses::validate(byron, &actual).is_err());
    let cip = vectors.iter().find(|v| v.id == "cip129-drep-key").unwrap();
    let mut actual = cip.expected.clone().unwrap();
    let mut bytes = vec![0xff];
    bytes.extend([0x11; 28]);
    actual["result"]["text"] = json!(encoding::bech32_encode("drep", &bytes).unwrap());
    assert!(addresses::validate(cip, &actual).is_err());
}
#[test]
fn codecs_preserve_known_bip173_and_base58_vectors_and_reject_padding() {
    assert_eq!(
        encoding::bech32("A12UEL5L").unwrap(),
        ("a".to_owned(), vec![])
    );
    assert_eq!(encoding::bech32_encode("a", &[]).unwrap(), "a12uel5l");
    assert!(encoding::bech32(&encoding::bech32_from_words("addr_test", &[1]).unwrap()).is_err());
    assert_eq!(
        encoding::base58_encode(b"Hello World").unwrap(),
        "JxF12TrwUP45BMd"
    );
    assert_eq!(
        encoding::base58_decode("JxF12TrwUP45BMd").unwrap(),
        b"Hello World"
    );
    assert_eq!(encoding::base58_decode("112").unwrap(), vec![0, 0, 1]);
    assert!(encoding::base58_decode("0OIl").is_err());
    let malformed: Value = json!({"type":"after","slot":null});
    assert!(addresses::script_bytes(&malformed).is_err());
}
