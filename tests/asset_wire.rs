use serde_json::json;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};
use wallet_conformance::{
    api::{Api, Request},
    node, transaction,
};
#[test]
fn binary_request_preserves_bytes_and_rejects_conflicting_or_invalid_encodings() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let api = Api::new(
        &format!("http://{}/v2/", listener.local_addr().unwrap()),
        Duration::from_secs(3),
    )
    .unwrap();
    let mut request = Request {
        method: "POST".into(),
        path: "/proxy/transactions".into(),
        raw_body_hex: Some("00ff0a".into()),
        ..Default::default()
    };
    request.raw_body = Some("text".into());
    assert!(api
        .request(&request)
        .unwrap_err()
        .to_string()
        .contains("mutually exclusive"));
    request.raw_body = None;
    request.body = Some(json!({}));
    assert!(api
        .request(&request)
        .unwrap_err()
        .to_string()
        .contains("mutually exclusive"));
    request.body = None;
    request.raw_body_hex = Some("xz".into());
    assert!(api
        .request(&request)
        .unwrap_err()
        .to_string()
        .contains("invalid hexadecimal"));
    request.raw_body_hex = Some("00ff0a".into());
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut raw = Vec::new();
        let boundary = loop {
            let mut bytes = [0u8; 1024];
            let count = stream.read(&mut bytes).unwrap();
            assert!(count > 0);
            raw.extend_from_slice(&bytes[..count]);
            if let Some(start) = raw.windows(4).position(|v| v == b"\r\n\r\n") {
                if raw.len() >= start + 7 {
                    break start + 4;
                }
            }
        };
        let headers = String::from_utf8(raw[..boundary].to_vec())
            .unwrap()
            .to_ascii_lowercase();
        assert!(headers.starts_with("post /v2/proxy/transactions http/1.1\r\n"));
        assert!(headers.contains("content-type: application/octet-stream\r\n"));
        assert!(headers.contains("content-length: 3\r\n"));
        assert_eq!(&raw[boundary..], &[0, 255, 10]);
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    assert_eq!(api.request(&request).unwrap().status, 204);
    server.join().unwrap();
}
#[test]
fn node_asset_confirmation_rejects_wrong_names_quantities_or_unexpected_assets() {
    let txid = "ab".repeat(32);
    let policy = "12".repeat(28);
    let mut utxo = json!({format!("{txid}#0"):{"address":"addr","value":{"lovelace":2000000,&policy:{"":100,"abcd":60}}}});
    let expected = BTreeMap::from([(format!("{policy}."), 100), (format!("{policy}.abcd"), 60)]);
    node::validate_asset_payment(&utxo, &txid, "addr", 2000000, &expected).unwrap();
    utxo[format!("{txid}#0")]["value"][&policy]["abcd"] = json!(59);
    assert!(node::validate_asset_payment(&utxo, &txid, "addr", 2000000, &expected).is_err());
    utxo[format!("{txid}#0")]["value"][&policy]["abcd"] = json!(60);
    utxo[format!("{txid}#0")]["value"][&policy]["ff"] = json!(1);
    assert!(node::validate_asset_payment(&utxo, &txid, "addr", 2000000, &expected).is_err());
    assert!(node::validate_asset_payment(&utxo, &txid, "addr", 1999999, &expected).is_err());
}
#[test]
fn mint_map_checks_signed_burns_empty_names_duplicates_and_trailing_bytes() {
    let build = |duplicate: bool| {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .map(1)
            .unwrap()
            .u8(9)
            .unwrap()
            .map(1)
            .unwrap()
            .bytes(&[0x12; 28])
            .unwrap()
            .map(2)
            .unwrap()
            .bytes(&[])
            .unwrap()
            .i64(-100)
            .unwrap()
            .bytes(if duplicate { &[] } else { &[0xab, 0xcd] })
            .unwrap()
            .i64(60)
            .unwrap()
            .map(0)
            .unwrap()
            .bool(true)
            .unwrap()
            .null()
            .unwrap();
        e.into_writer()
    };
    let raw = build(false);
    assert_eq!(
        transaction::mint_quantities(&hex::encode(&raw)).unwrap(),
        BTreeMap::from([
            (format!("{}.", "12".repeat(28)), -100),
            (format!("{}.abcd", "12".repeat(28)), 60)
        ])
    );
    assert!(transaction::mint_quantities(&hex::encode(build(true))).is_err());
    let mut bad = raw;
    bad.push(0);
    assert!(transaction::mint_quantities(&hex::encode(bad)).is_err());
}
