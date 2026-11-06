use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::Command,
    thread,
    time::Duration,
};
use wallet_conformance::{
    adapter::{self, Selection, SelectionInput, Vector},
    api::{Api, Contract, Response},
    report::{coverage, Report, Requirement},
    scenarios::{self, Suite},
};

fn response(value: Value) -> Response {
    Response {
        status: 200,
        media_type: Some("application/json".into()),
        raw: serde_json::to_vec(&value).unwrap(),
        json: Some(value),
    }
}

fn contract() -> Contract {
    Contract::load(
        r#"
openapi: 3.0.3
components:
  schemas:
    Wallet: &wallet
      type: object
      required: [id, name]
      properties:
        id: {type: string}
        name: {type: string}
        optional: {type: string, nullable: true}
paths:
  /wallets:
    post:
      operationId: postWallet
      responses:
        201:
          description: Created
          content:
            application/json:
              schema: *wallet
  /wallets/{walletId}:
    delete:
      operationId: deleteWallet
      responses:
        204: {description: Deleted}
"#,
    )
    .unwrap()
}

#[test]
fn schema_rejects_missing_fields_and_wrong_types_but_accepts_nullable() {
    let c = contract();
    let mut r = response(json!({"id":"a","name":"wallet","optional":null}));
    r.status = 201;
    c.validate("postWallet", &r).unwrap();
    for v in [
        json!({"id":"a"}),
        json!({"id":"a","name":42}),
        json!({"id":"a","name":"wallet","optional":false}),
    ] {
        r.json = Some(v);
        assert!(c.validate("postWallet", &r).is_err());
    }
    r.status = 500;
    assert!(c.validate("postWallet", &r).is_err());
}

#[test]
fn pinned_contract_is_complete_and_path_binding_is_checked() {
    let c = Contract::pinned().unwrap();
    assert_eq!(c.operations.len(), 96);
    assert_eq!(
        c.operations["putByronWallet"].statuses,
        vec![200, 400, 404, 406, 415]
    );
    for operation in [
        "deleteWallet",
        "deleteByronWallet",
        "deleteSharedWallet",
        "deleteTransaction",
        "deleteByronTransaction",
        "putWalletPassphrase",
        "putByronWalletPassphrase",
    ] {
        assert!(!c.operations[operation].statuses.contains(&406));
        assert!(c.operations[operation].statuses.contains(&204));
    }
    assert_eq!(
        c.effective_document()["paths"]["/byron-wallets/{walletId}"]["put"]["responses"]["200"]
            ["content"]["application/json"]["schema"],
        c.effective_document()["components"]["schemas"]["ApiByronWallet"]
    );
    c.check_path("getWallet", "GET", "/wallets/abc").unwrap();
    assert!(c.check_path("getWallet", "DELETE", "/wallets/abc").is_err());
    assert!(c
        .check_path("getWallet", "GET", "/byron-wallets/abc")
        .is_err());
    assert!(c.check_path("getWallet", "GET", "/wallets/").is_err());
}

#[test]
fn differential_comparison_does_not_hide_structure_null_or_order() {
    let a = response(json!({"time":"a","xs":[1,2],"n":9007199254740993u64}));
    let mut b = response(json!({"time":"b","xs":[1,2],"n":9007199254740993u64}));
    let ignore = BTreeMap::from([("/time".into(), "service timestamp".into())]);
    scenarios::compare(&a, &b, &ignore).unwrap();
    for value in [
        json!({"time":"b","xs":[2,1],"n":9007199254740993u64}),
        json!({"time":null,"xs":[1,2],"n":9007199254740993u64}),
        json!({"xs":[1,2],"n":9007199254740993u64}),
        json!({"time":"b","xs":[1,2],"n":9007199254740992u64}),
    ] {
        b.json = Some(value);
        assert!(scenarios::compare(&a, &b, &ignore).is_err());
    }
    assert!(scenarios::compare(
        &a,
        &a,
        &BTreeMap::from([("/xs".into(), "hide array".into())])
    )
    .is_err());
    assert!(scenarios::compare(
        &a,
        &a,
        &BTreeMap::from([("".into(), "hide everything".into())])
    )
    .is_err());
}

fn serve(responses: Vec<(u16, Value)>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/v2/", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for (status, body) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut one = [0];
                stream.read_exact(&mut one).unwrap();
                header.push(one[0]);
            }
            let header = String::from_utf8(header).unwrap();
            let length: usize = header
                .lines()
                .find_map(|l| {
                    l.to_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            let mut request_body = vec![0; length];
            stream.read_exact(&mut request_body).unwrap();
            requests.push(header.lines().next().unwrap().into());
            let body = if status == 204 {
                Vec::new()
            } else {
                serde_json::to_vec(&body).unwrap()
            };
            write!(stream,"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
            stream.write_all(&body).unwrap();
        }
        requests
    });
    (base, handle)
}

#[test]
fn cleanup_runs_after_created_wallet_response_fails_its_schema() {
    let suite: Suite = serde_json::from_value(json!({"name":"cleanup", "cases":[
        {"id":"create","operation":"postWallet","request":{"method":"POST","path":"/wallets","body":{"secret":"DO_NOT_REPORT_THIS"}},"expected_status":201,"capture":{"id":"/id"}}
    ],"cleanup":[{"id":"cleanup","operation":"deleteWallet","request":{"method":"DELETE","path":"/wallets/${id}"},"expected_status":204}]})).unwrap();
    let (base, handle) = serve(vec![(201, json!({"id":"owned-id"})), (204, Value::Null)]);
    let api = Api::new(&base, Duration::from_secs(2)).unwrap();
    let report = scenarios::run(&suite, &api, None, &contract(), "mock-harness").unwrap();
    assert!(!report.passed());
    assert!(!report.evidence[0].passed);
    assert!(report.evidence[1].passed);
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains("DO_NOT_REPORT_THIS"));
    assert_eq!(
        handle.join().unwrap(),
        vec![
            "POST /v2/wallets HTTP/1.1",
            "DELETE /v2/wallets/owned-id HTTP/1.1"
        ]
    );
}

#[test]
fn matching_broken_servers_are_not_conformant() {
    let suite: Suite = serde_json::from_value(json!({"name":"broken", "cases":[
        {"id":"create","operation":"postWallet","request":{"method":"POST","path":"/wallets"},"expected_status":201}
    ]})).unwrap();
    let (t, th) = serve(vec![(500, json!({"error":"broken"}))]);
    let (r, rh) = serve(vec![(500, json!({"error":"broken"}))]);
    let report = scenarios::run(
        &suite,
        &Api::new(&t, Duration::from_secs(2)).unwrap(),
        Some(&Api::new(&r, Duration::from_secs(2)).unwrap()),
        &contract(),
        "mock-harness",
    )
    .unwrap();
    assert!(!report.passed());
    th.join().unwrap();
    rh.join().unwrap();
}

fn selection() -> (SelectionInput, Selection) {
    let input = serde_json::from_value(json!({"utxos":[
        {"id":"a#0","eligible":true,"value":{"coin":10000000,"assets":{"policy.asset":7}}},
        {"id":"b#0","eligible":false,"value":{"coin":10000000}}
    ],"outputs":[{"coin":2000000,"assets":{"policy.asset":3}}],"fee":200000,"minimum_change_coin":1000000,"maximum_inputs":1,"seed":42})).unwrap();
    let output = serde_json::from_value(json!({"inputs":["a#0"],"fee":200000,"change":[{"coin":7800000,"assets":{"policy.asset":4}}]})).unwrap();
    (input, output)
}

#[test]
fn selection_rejects_ada_asset_fee_input_and_change_mutations() {
    let (input, output) = selection();
    adapter::validate_selection(&input, &output).unwrap();
    for mutation in 0..7 {
        let (_, mut bad) = selection();
        match mutation {
            0 => bad.change[0].coin += 1,
            1 => {
                bad.change[0].assets.insert("policy.asset".into(), 5);
            }
            2 => bad.inputs.push("a#0".into()),
            3 => bad.inputs[0] = "b#0".into(),
            4 => bad.inputs[0] = "unknown#0".into(),
            5 => bad.fee += 1,
            _ => bad.change[0].coin = 1,
        }
        assert!(
            adapter::validate_selection(&input, &bad).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn selection_accounting_preserves_large_integers_and_many_bundles() {
    for coin in [u64::MAX, 9007199254740993, 10_000_000] {
        let (mut input, mut output) = selection();
        input.utxos[0].value.coin = coin;
        output.change[0].coin = coin - 2_000_000 - 200_000;
        adapter::validate_selection(&input, &output).unwrap();
        output.change[0].coin -= 1;
        assert!(adapter::validate_selection(&input, &output).is_err());
    }
}

#[test]
fn independent_primitive_vectors_and_tampering_detection() {
    let mut vectors: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/primitives.json")).unwrap();
    assert!(adapter::run(
        &vectors,
        None,
        &[],
        Duration::from_secs(1),
        "harness-oracle",
        "harness-self-test"
    )
    .unwrap()
    .passed());
    vectors[0].expected = Some(json!({"result":{"hex":"wrong"}}));
    let report = adapter::run(
        &vectors,
        None,
        &[],
        Duration::from_secs(1),
        "harness-oracle",
        "harness-self-test",
    )
    .unwrap();
    assert!(!report.passed());
    assert!(!report.evidence[0].passed);
}

#[test]
fn adapter_process_roundtrip_and_malformed_output_fail_closed() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/primitives.json")).unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_wallet-conformance"));
    let result = adapter::invoke(
        binary,
        &["primitive-oracle".into()],
        &vectors[0],
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(Some(result), vectors[0].expected);
    assert!(adapter::invoke(
        binary,
        &["--version".into()],
        &vectors[0],
        Duration::from_secs(5)
    )
    .is_err());
}

#[test]
fn adapter_timeouts_are_bounded() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/primitives.json")).unwrap();
    let start = std::time::Instant::now();
    let result = adapter::invoke(
        Path::new("sh"),
        &["-c".into(), "sleep 2".into()],
        &vectors[0],
        Duration::from_millis(50),
    );
    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn coverage_never_passes_empty_missing_failed_or_mixed_runs() {
    let requirements = vec![
        Requirement {
            id: "crypto.signature".into(),
            description: "signature vectors".into(),
            ..Default::default()
        },
        Requirement {
            id: "chain.confirmation".into(),
            description: "real chain".into(),
            ..Default::default()
        },
    ];
    assert!(coverage(&requirements, &[]).is_err());
    let mut report = Report::new("candidate", "conway-linux");
    assert!(coverage(&requirements, &[report]).is_err());
    report = Report::new("candidate", "conway-linux");
    report.record("signature", &["crypto.signature".into()], Ok(()));
    let c = coverage(&requirements, &[report]).unwrap();
    assert!(!c.exhaustive);
    assert_eq!(c.missing, vec!["chain.confirmation"]);
    let mut report = Report::new("candidate", "conway-linux");
    report.record(
        "all",
        &["crypto.signature".into(), "chain.confirmation".into()],
        Ok(()),
    );
    assert!(coverage(&requirements, &[report]).unwrap().exhaustive);
    let mut a = Report::new("a", "conway-linux");
    a.record("x", &[], Ok(()));
    let mut b = Report::new("b", "conway-linux");
    b.record("y", &[], Ok(()));
    assert!(coverage(&requirements, &[a, b]).is_err());
}

#[test]
fn template_expansion_preserves_json_types_and_unknowns_fail() {
    let vars = BTreeMap::from([
        ("amount".into(), json!(9007199254740993u64)),
        ("wallet".into(), json!("abc")),
        ("words".into(), json!(["one", "two"])),
    ]);
    assert_eq!(
        scenarios::expand(
            &json!({"amount":"${amount}","words":"${words}","path":"/wallets/${wallet}"}),
            &vars
        )
        .unwrap(),
        json!({"amount":9007199254740993u64,"words":["one","two"],"path":"/wallets/abc"})
    );
    assert!(scenarios::expand(&json!("${missing}"), &vars).is_err());
}

#[test]
fn cli_inventory_and_harness_evidence_cannot_pass_exhaustive_gate() {
    let binary = env!("CARGO_BIN_EXE_wallet-conformance");
    let output = Command::new(binary).arg("inventory").output().unwrap();
    assert!(output.status.success());
    let inventory: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(inventory["operations"].as_object().unwrap().len(), 96);
    assert_eq!(inventory["requirements"].as_array().unwrap().len(), 643);
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("report.json");
    let mut report = Report::new("harness-oracle", "harness-self-test");
    report.record("primitive", &[], Ok(()));
    std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
    let output = Command::new(binary)
        .args(["gate", "--report"])
        .arg(path)
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn bech32_checksum_padding_case_and_long_cardano_addresses() {
    use wallet_conformance::encoding::bech32;
    assert_eq!(bech32("A12UEL5L").unwrap(), ("a".into(), Vec::new()));
    assert!(bech32("a12UEL5L").is_err());
    assert!(bech32("A12UEL5Q").is_err());
    let (hrp, bytes) =
        bech32("addr_test1vqrlltfahghjxl5sy5h5mvfrrlt6me5fqphhwjqvj5jd88cccqcek").unwrap();
    assert_eq!(hrp, "addr_test");
    assert_eq!(bytes.len(), 29);
    assert_eq!(bytes[0], 0x60);
}

#[test]
fn cbor_body_hash_and_witness_verification_reject_altered_body_signature_and_trailing_bytes() {
    use ed25519_dalek::{Signer, SigningKey};
    use wallet_conformance::transaction;
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut body = minicbor::Encoder::new(Vec::new());
    body.map(3)
        .unwrap()
        .u8(0)
        .unwrap()
        .array(1)
        .unwrap()
        .array(2)
        .unwrap()
        .bytes(&[9; 32])
        .unwrap()
        .u8(0)
        .unwrap()
        .u8(1)
        .unwrap()
        .array(1)
        .unwrap()
        .array(2)
        .unwrap()
        .bytes(&[0x60; 29])
        .unwrap()
        .u64(2_000_000)
        .unwrap()
        .u8(2)
        .unwrap()
        .u64(200_000)
        .unwrap();
    let body = body.into_writer();
    let hash = transaction::blake2b(&body, 32).unwrap();
    let signature = key.sign(&hash).to_bytes();
    let mut witnesses = minicbor::Encoder::new(Vec::new());
    witnesses
        .map(1)
        .unwrap()
        .u8(0)
        .unwrap()
        .tag(minicbor::data::Tag::new(258))
        .unwrap()
        .array(1)
        .unwrap()
        .array(2)
        .unwrap()
        .bytes(key.verifying_key().as_bytes())
        .unwrap()
        .bytes(&signature)
        .unwrap();
    let witnesses = witnesses.into_writer();
    let mut cbor = vec![0x84];
    cbor.extend(&body);
    cbor.extend(&witnesses);
    cbor.extend([0xf5, 0xf6]);
    let parsed = transaction::inspect(&hex::encode(&cbor), true).unwrap();
    assert_eq!(parsed.id, hex::encode(hash));
    assert_eq!(parsed.fee, 200_000);
    assert_eq!(parsed.outputs[0].coin, 2_000_000);
    let signature_position = cbor.windows(64).position(|x| x == signature).unwrap();
    let mut bad = cbor.clone();
    bad[signature_position] ^= 1;
    assert!(transaction::inspect(&hex::encode(bad), true).is_err());
    let mut bad = cbor.clone();
    bad[7] ^= 1;
    assert!(transaction::inspect(&hex::encode(bad), true).is_err());
    cbor.push(0);
    assert!(transaction::inspect(&hex::encode(cbor), true).is_err());
}

#[test]
fn requirement_needs_every_attached_vector_not_one_family_example() {
    let req = Requirement {
        id: "crypto".into(),
        description: "all golden cases".into(),
        required_cases: vec!["first".into(), "second".into()],
    };
    let mut report = Report::new("candidate", "test");
    report.record("first", &["crypto".into()], Ok(()));
    assert!(!coverage(&[req], &[report]).unwrap().exhaustive);
}

#[test]
fn generated_selection_matrix_has_valid_replayable_models_and_rejects_mutations() {
    for vector in wallet_conformance::generate::selections() {
        let input: SelectionInput = serde_json::from_value(vector.input).unwrap();
        let mut totals = BTreeMap::<String, u64>::new();
        let mut coin = 0u64;
        let mut ids = Vec::new();
        for utxo in &input.utxos {
            if utxo.eligible {
                ids.push(utxo.id.clone());
                coin += utxo.value.coin;
                for (asset, quantity) in &utxo.value.assets {
                    *totals.entry(asset.clone()).or_default() += quantity;
                }
            }
        }
        for output in &input.outputs {
            coin -= output.coin;
            for (asset, quantity) in &output.assets {
                *totals.get_mut(asset).unwrap() -= quantity;
            }
        }
        coin -= input.fee;
        let mut selected = Selection {
            inputs: ids,
            fee: input.fee,
            change: vec![adapter::Bundle {
                coin,
                assets: totals,
            }],
        };
        adapter::validate_selection(&input, &selected).unwrap();
        selected.change[0].coin += 1;
        assert!(adapter::validate_selection(&input, &selected).is_err());
    }
}

#[test]
fn frozen_haskell_keys_have_expected_lengths_chain_codes_and_unique_ids() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/haskell-keys.json")).unwrap();
    assert_eq!(vectors.len(), 122);
    let mut ids = std::collections::BTreeSet::new();
    for vector in vectors {
        assert!(ids.insert(vector.id));
        assert!(vector.source.contains("sha256:"));
        let expected = &vector.expected.unwrap()["result"];
        if let Some(private) = expected["xprv_hex"].as_str() {
            let private = hex::decode(private).unwrap();
            let public = hex::decode(expected["xpub_hex"].as_str().unwrap()).unwrap();
            assert_eq!(private.len(), 96);
            assert_eq!(public.len(), 64);
            assert_eq!(&private[64..], &public[32..]);
        }
        if let Some(address) = expected["address"].as_str() {
            assert_eq!(
                hex::encode(wallet_conformance::encoding::bech32(address).unwrap().1),
                expected["address_hex"]
            );
        }
    }
}

#[test]
fn uri_template_response_schemas_compile_without_weakening_validation() {
    let c = Contract::load(
        r#"
openapi: 3.0.3
paths:
  /wallets/{walletId}:
    get:
      operationId: getWallet
      responses:
        200:
          description: Wallet
          content:
            application/json:
              schema:
                type: object
                required: [name]
                properties:
                  name: {type: string}
"#,
    )
    .unwrap();
    c.validate("getWallet", &response(json!({"name":"a"})))
        .unwrap();
    assert!(c
        .validate("getWallet", &response(json!({"name":42})))
        .is_err());
}

#[test]
fn custom_headers_do_not_append_implicit_json_accept_or_content_type() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
        }
        let header = String::from_utf8(header).unwrap().to_lowercase();
        assert_eq!(
            header.lines().filter(|x| x.starts_with("accept:")).count(),
            1
        );
        assert_eq!(
            header
                .lines()
                .filter(|x| x.starts_with("content-type:"))
                .count(),
            1
        );
        assert!(header.contains("accept: application/x-conformance-unsupported"));
        assert!(header.contains("content-type: application/octet-stream"));
        assert!(!header.contains("application/json"));
        let mut body = [0; 1];
        stream.read_exact(&mut body).unwrap();
        stream
            .write_all(b"HTTP/1.1 204 Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let api = Api::new(&base, Duration::from_secs(3)).unwrap();
    let req = wallet_conformance::api::Request {
        method: "POST".into(),
        path: "/proxy/transactions".into(),
        raw_body: Some("{".into()),
        headers: BTreeMap::from([
            (
                "Accept".into(),
                "application/x-conformance-unsupported".into(),
            ),
            ("Content-Type".into(), "application/octet-stream".into()),
        ]),
        ..Default::default()
    };
    assert_eq!(api.request(&req).unwrap().status, 204);
    handle.join().unwrap();
}

#[test]
fn wallet_creation_normalizes_only_after_observing_terminal_ready_state() {
    for (family, create, get, delete) in [
        ("wallets", "postWallet", "getWallet", "deleteWallet"),
        (
            "byron-wallets",
            "postByronWallet",
            "getByronWallet",
            "deleteByronWallet",
        ),
        (
            "shared-wallets",
            "postSharedWallet",
            "getSharedWallet",
            "deleteSharedWallet",
        ),
    ] {
        let suite: Suite = serde_json::from_value(json!({"name":"settle","cases":[
        {"id":"create","operation":create,"request":{"method":"POST","path":format!("/{family}")},"expected_status":201,"settle_wallet_state":true,"capture":{"id":"/id"}}
    ],"cleanup":[{"id":"cleanup","operation":delete,"request":{"method":"DELETE","path":format!("/{family}/${{id}}")},"expected_status":204}]})).unwrap();
        let c = Contract::load(
            &r#"
openapi: 3.0.3
paths:
  /wallets:
    post:
      operationId: postWallet
      responses:
        201:
          description: Created
          content:
            application/json:
              schema: {type: object, required: [id, state]}
  /wallets/{walletId}:
    get:
      operationId: getWallet
      responses:
        200:
          description: Wallet
          content:
            application/json:
              schema: {type: object, required: [id, state]}
    delete:
      operationId: deleteWallet
      responses:
        204: {description: Deleted}
"#
            .replace("/wallets", &format!("/{family}"))
            .replace("postWallet", create)
            .replace("getWallet", get)
            .replace("deleteWallet", delete),
        )
        .unwrap();
        let ready = json!({"id":"same-id","state":{"status":"ready"}});
        let (target, th) = serve(vec![
            (201, ready.clone()),
            (200, ready.clone()),
            (204, Value::Null),
        ]);
        let (reference, rh) = serve(vec![
            (
                201,
                json!({"id":"same-id","state":{"status":"syncing","progress":{"quantity":42}}}),
            ),
            (200, ready),
            (204, Value::Null),
        ]);
        let report = scenarios::run(
            &suite,
            &Api::new(&target, Duration::from_secs(2)).unwrap(),
            Some(&Api::new(&reference, Duration::from_secs(2)).unwrap()),
            &c,
            "mock-harness",
        )
        .unwrap();
        assert!(report.passed());
        assert!(th.join().unwrap()[1].starts_with(&format!("GET /v2/{family}/same-id")));
        assert!(rh.join().unwrap()[1].starts_with(&format!("GET /v2/{family}/same-id")));
    }
}

#[test]
fn trusted_node_evidence_rejects_fabricated_confirmation_amount_address_and_transaction() {
    use wallet_conformance::node::validate_payment;
    let txid = "ab".repeat(32);
    let key = format!("{txid}#0");
    let utxo = json!({&key:{"address":"test-recipient","value":{"lovelace":2_000_000}}});
    validate_payment(&utxo, &txid, "test-recipient", 2_000_000).unwrap();
    assert!(validate_payment(&json!({}), &txid, "test-recipient", 2_000_000).is_err());
    assert!(validate_payment(&utxo, &"cd".repeat(32), "test-recipient", 2_000_000).is_err());
    assert!(validate_payment(&utxo, &txid, "wrong-recipient", 2_000_000).is_err());
    assert!(validate_payment(&utxo, &txid, "test-recipient", 1_999_999).is_err());
}

#[test]
fn specification_retains_exact_contracts_and_marks_unexecuted_drafts() {
    let contract = Contract::pinned().unwrap();
    let requirements = vec![Requirement {
        id: "tx.ledger-acceptance".into(),
        description: "A real submitted payment confirms".into(),
        required_cases: vec!["live:confirmed-transfer".into()],
    }];
    let draft = wallet_conformance::specification::export(&contract, &requirements, &[]).unwrap();
    assert_eq!(draft["status"], "draft");
    assert_eq!(draft["validation"]["covered"], 0);
    assert_eq!(draft["validation"]["exhaustive"], false);
    assert_eq!(draft["validation"]["missing"][0], "tx.ledger-acceptance");
    assert!(draft["corpora"]["fixtures/vectors/primitives.json"]["contract"].is_array());
    assert_eq!(
        draft["live_assertions"]["contract"],
        include_str!("../docs/live-contracts.md")
    );
    let modules: std::collections::BTreeSet<_> = include_str!("../src/live.rs")
        .lines()
        .filter_map(|line| line.strip_prefix("mod ").and_then(|v| v.strip_suffix(';')))
        .map(|name| format!("src/live/{name}.rs"))
        .collect();
    let mut exported = std::collections::BTreeSet::new();
    for profile in draft["live_assertions"]["profiles"].as_array().unwrap() {
        use sha2::Digest;
        let path = profile["source"].as_str().unwrap();
        assert!(exported.insert(path.to_owned()), "duplicate live profile");
        let source = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap();
        assert_eq!(profile["sha256"], hex::encode(sha2::Sha256::digest(source)));
    }
    assert_eq!(
        modules, exported,
        "every executable live profile must be exported"
    );
    let mut report = Report::new("reference-wallet", "real-node");
    report.record(
        "live:confirmed-transfer",
        &["tx.ledger-acceptance".into()],
        Ok(()),
    );
    report.suite_sha256 = "stale".into();
    assert!(
        wallet_conformance::specification::export(&contract, &requirements, &[report]).is_err()
    );
}

#[test]
fn http_key_golden_rejects_equal_but_wrong_implementations() {
    let address = "addr_test1vzz6hulv54gzf2suy2u5gkvmt6ysasfdlvvegy3fmf969yc2mg7gf";
    let contract = Contract::load("openapi: 3.0.3\npaths:\n  /key:\n    get:\n      operationId: key\n      responses:\n        200:\n          content:\n            application/json:\n              schema: {type: string}\n").unwrap();
    for expected in [
        "6085abf3eca55024aa1c22b944599b5e890ec12dfb19941229da4ba293",
        "00",
    ] {
        let suite: Suite = serde_json::from_value(json!({"name":"key golden","cases":[{
            "id":"key","operation":"key","request":{"method":"GET","path":"/key"},
            "expected_status":200,"assert_bech32":{"":{"hrp":"addr_test","bytes_hex":expected}}
        }]}))
        .unwrap();
        let (target, target_thread) = serve(vec![(200, json!(address))]);
        let (reference, reference_thread) = serve(vec![(200, json!(address))]);
        let report = scenarios::run(
            &suite,
            &Api::new(&target, Duration::from_secs(2)).unwrap(),
            Some(&Api::new(&reference, Duration::from_secs(2)).unwrap()),
            &contract,
            "harness-self-test",
        )
        .unwrap();
        assert_eq!(report.passed(), expected != "00");
        target_thread.join().unwrap();
        reference_thread.join().unwrap();
    }
}

#[test]
fn explicit_absence_rejects_null_even_when_both_services_agree() {
    let contract = Contract::load("openapi: 3.0.3\npaths:\n  /wallet:\n    get:\n      operationId: wallet\n      responses:\n        200:\n          content:\n            application/json:\n              schema: {type: object}\n").unwrap();
    let suite: Suite = serde_json::from_value(json!({"name":"absence", "cases":[{
        "id":"watch-only","operation":"wallet","request":{"method":"GET","path":"/wallet"},
        "expected_status":200,"absent":["/passphrase"]
    }]}))
    .unwrap();
    for (body, expected) in [
        (json!({"id":"watch"}), true),
        (json!({"id":"watch","passphrase":null}), false),
    ] {
        let (target, target_thread) = serve(vec![(200, body.clone())]);
        let (reference, reference_thread) = serve(vec![(200, body)]);
        let report = scenarios::run(
            &suite,
            &Api::new(&target, Duration::from_secs(2)).unwrap(),
            Some(&Api::new(&reference, Duration::from_secs(2)).unwrap()),
            &contract,
            "harness-self-test",
        )
        .unwrap();
        assert_eq!(report.passed(), expected);
        target_thread.join().unwrap();
        reference_thread.join().unwrap();
    }
}

#[test]
fn latest_header_requires_matching_hash_height_and_slot() {
    let tip = wallet_conformance::node::Tip {
        height: 42,
        slot: 100,
        hash: "ab".repeat(32),
    };
    let header = json!({"block_height":{"quantity":42},"slot_no":{"quantity":100},"header_hash":"ab".repeat(32)});
    assert!(tip.matches_wallet_header(&header));
    for pointer in [
        "/block_height/quantity",
        "/slot_no/quantity",
        "/header_hash",
    ] {
        let mut tampered = header.clone();
        *tampered.pointer_mut(pointer).unwrap() = if pointer == "/header_hash" {
            json!("cd".repeat(32))
        } else {
            json!(0)
        };
        assert!(!tip.matches_wallet_header(&tampered));
    }
}

#[test]
fn modified_runtime_expectation_cannot_reuse_a_registered_case_id_to_pass_the_gate() {
    let contract = Contract::load("openapi: 3.0.3\npaths:\n  /wallets/{walletId}/transactions:\n    get:\n      operationId: listTransactions\n      responses:\n        200:\n          content:\n            application/json:\n              schema: {type: array}\n").unwrap();
    let source: Value = serde_json::from_str(include_str!("../fixtures/http.json")).unwrap();
    let mut case = source["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "empty-transactions")
        .unwrap()
        .clone();
    let original: scenarios::Case = serde_json::from_value(case.clone()).unwrap();
    assert!(wallet_conformance::report::registered_http(&original).unwrap());
    case["assertions"] = json!({});
    case["request"]["path"] = json!("/wallets/fake/transactions");
    let suite: Suite = serde_json::from_value(json!({"name":"weakened","cases":[case]})).unwrap();
    let (target, server) = serve(vec![(200, json!(["wrong unexpected transaction"]))]);
    let report = scenarios::run(
        &suite,
        &Api::new(&target, Duration::from_secs(2)).unwrap(),
        None,
        &contract,
        "development",
    )
    .unwrap();
    assert!(report.passed()); // Development assertions ran successfully.
    assert_eq!(report.unregistered_inputs, vec!["empty-transactions"]);
    let requirements = vec![Requirement {
        id: "api:listTransactions:positive".into(),
        description: "registered empty history".into(),
        required_cases: vec!["empty-transactions".into()],
    }];
    assert!(coverage(&requirements, &[report]).is_err());
    server.join().unwrap();
}

#[test]
fn haskell_selection_laws_allow_bounded_dust_but_reject_excess_fee_and_unsplit_change() {
    let profile = json!({"utxos":[{"id":"i","value":{"coin":2300000},"eligible":true}],
        "outputs":[{"coin":2000000}],"seed":42,"strategy":"minimal","minimum_fee":200000,"minimum_change_coin":1000000});
    let input: adapter::HaskellSelectionInput = serde_json::from_value(profile.clone()).unwrap();
    let mut selected: Selection =
        serde_json::from_value(json!({"inputs":["i"],"change":[],"fee":300000})).unwrap();
    adapter::validate_haskell_selection(&input, &selected).unwrap();
    let mut larger_dust = profile.clone();
    larger_dust["utxos"][0]["value"]["coin"] = json!(2800000);
    selected.fee = 800000;
    adapter::validate_haskell_selection(&serde_json::from_value(larger_dust).unwrap(), &selected)
        .unwrap();
    let mut excessive = profile;
    excessive["utxos"][0]["value"]["coin"] = json!(3200000);
    selected.fee = 1200000;
    assert!(adapter::validate_haskell_selection(
        &serde_json::from_value(excessive).unwrap(),
        &selected
    )
    .is_err());

    let profile = json!({"utxos":[{"id":"i","value":{"coin":10000000,"assets":{"a":11,"b":1}},"eligible":true}],
        "outputs":[{"coin":2000000}],"seed":0,"minimum_fee":200000,"minimum_change_coin":1000000});
    let selected: Selection = serde_json::from_value(
        json!({"inputs":["i"],"change":[{"coin":7800000,"assets":{"a":11,"b":1}}],"fee":200000}),
    )
    .unwrap();
    adapter::validate_haskell_selection(
        &serde_json::from_value(profile.clone()).unwrap(),
        &selected,
    )
    .unwrap();
    for (field, bound) in [
        ("maximum_output_token_quantity", 10),
        ("maximum_assets_per_bundle", 1),
    ] {
        let mut constrained = profile.clone();
        constrained[field] = json!(bound);
        assert!(adapter::validate_haskell_selection(
            &serde_json::from_value(constrained).unwrap(),
            &selected
        )
        .is_err());
    }
}

#[test]
fn adjacent_large_negative_metadata_integers_never_compare_equal() {
    let first: Value = serde_json::from_str("{\"metadata\":-18446744073709551616}").unwrap();
    let second: Value = serde_json::from_str("{\"metadata\":-18446744073709551615}").unwrap();
    assert!(scenarios::compare(
        &response(first.clone()),
        &response(second),
        &BTreeMap::new()
    )
    .is_err());
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        "{\"metadata\":-18446744073709551616}"
    );
}

#[test]
fn extreme_response_number_cannot_abort_owned_wallet_cleanup() {
    let contract = Contract::load("openapi: 3.0.3\npaths:\n  /wallets:\n    post:\n      operationId: postWallet\n      responses:\n        201:\n          content:\n            application/json:\n              schema:\n                type: object\n                properties:\n                  amount: {type: number, minimum: 0}\n  /wallets/{walletId}:\n    delete:\n      operationId: deleteWallet\n      responses:\n        204: {description: deleted}\n").unwrap();
    let suite: Suite = serde_json::from_value(json!({"name":"numeric failure cleanup","cases":[{
        "id":"create","operation":"postWallet","request":{"method":"POST","path":"/wallets"},
        "expected_status":201,"capture":{"wallet":"/id"}
    }],"cleanup":[{"id":"delete","operation":"deleteWallet","request":{"method":"DELETE","path":"/wallets/${wallet}"},"expected_status":204}]})).unwrap();
    let extreme: Value = serde_json::from_str("{\"id\":\"owned\",\"amount\":1e10000}").unwrap();
    let (target, server) = serve(vec![(201, extreme), (204, Value::Null)]);
    let report = scenarios::run(
        &suite,
        &Api::new(&target, Duration::from_secs(2)).unwrap(),
        None,
        &contract,
        "harness-self-test",
    )
    .unwrap();
    assert!(!report.evidence[0].passed);
    assert!(report.evidence[1].passed);
    assert!(server.join().unwrap()[1].starts_with("DELETE /v2/wallets/owned "));
}

fn epoch_snapshot(epoch: u64, next: u64, time: &str) -> Value {
    json!({"network_tip":{"epoch_number":epoch},"next_epoch":{"epoch_number":next,"epoch_start_time":time}})
}

fn check_epoch_samples(target: Vec<Value>, reference: Vec<Value>, passes: bool) {
    let contract = Contract::load("openapi: 3.0.3\npaths:\n  /network/information:\n    get:\n      operationId: getNetworkInformation\n      responses:\n        200:\n          content:\n            application/json:\n              schema: {type: object}\n").unwrap();
    let suite: Suite = serde_json::from_value(json!({"name":"epoch", "cases":[{
        "id":"epoch","operation":"getNetworkInformation",
        "request":{"method":"GET","path":"/network/information"},
        "expected_status":200,"align_network_epoch":true
    }]}))
    .unwrap();
    let (target_count, reference_count) = (target.len(), reference.len());
    let (target, t) = serve(target.into_iter().map(|v| (200, v)).collect());
    let (reference, r) = serve(reference.into_iter().map(|v| (200, v)).collect());
    let report = scenarios::run(
        &suite,
        &Api::new(&target, Duration::from_secs(2)).unwrap(),
        Some(&Api::new(&reference, Duration::from_secs(2)).unwrap()),
        &contract,
        "mock-harness",
    )
    .unwrap();
    assert_eq!(report.passed(), passes, "{:?}", report.evidence);
    assert_eq!(t.join().unwrap().len(), target_count);
    assert_eq!(r.join().unwrap().len(), reference_count);
}

#[test]
fn epoch_boundary_resamples_until_matching_epochs() {
    let later = epoch_snapshot(10, 11, "2026-11-02T00:00:00Z");
    check_epoch_samples(
        vec![epoch_snapshot(9, 10, "2026-11-01T00:00:00Z"), later.clone()],
        vec![later.clone(), later],
        true,
    );
}

#[test]
fn epoch_sampling_rejects_invalid_successor_without_retry() {
    check_epoch_samples(
        vec![epoch_snapshot(9, 11, "2026-11-02T00:00:00Z")],
        vec![epoch_snapshot(10, 11, "2026-11-02T00:00:00Z")],
        false,
    );
}

#[test]
fn epoch_sampling_compares_same_epoch_timestamps_strictly() {
    check_epoch_samples(
        vec![epoch_snapshot(9, 10, "2026-11-01T00:00:00Z")],
        vec![epoch_snapshot(9, 10, "2026-11-02T00:00:00Z")],
        false,
    );
}

#[test]
fn epoch_sampling_is_bounded() {
    check_epoch_samples(
        vec![epoch_snapshot(9, 10, "2026-11-01T00:00:00Z"); 4],
        vec![epoch_snapshot(10, 11, "2026-11-02T00:00:00Z"); 4],
        false,
    );
}
