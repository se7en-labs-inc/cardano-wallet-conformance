//! Reproducible invariant cases independent of any candidate selection strategy.
use crate::adapter::Vector;
use serde_json::json;

/// Generate varied multiasset, multi-output selection problems with fixed seeds.
/// This checks semantic invariants; exact Haskell strategy equivalence needs
/// additional captured seeded oracle vectors, tracked separately by the gate.
pub fn selections() -> Vec<Vector> {
    let a = format!("{}.00", "11".repeat(28));
    let b = format!("{}.ff", "22".repeat(28));
    (0..256u64).map(|seed| {
        let quantity = seed+100;
        let coin_a = 10_000_000+seed*1_009;
        let coin_b = 15_000_000+seed*97;
        Vector {
            id:format!("selection-generated-{seed:03}"),
            requirements:vec!["selection.ada-conservation".into(),"selection.asset-conservation".into(),"selection.unique-inputs".into(),"selection.minimum-change".into(),"selection.input-limits".into(),"selection.multi-output".into(),"selection.replay".into()],
            source:format!("Independent generated constraints, generator v1, seed {seed}; two distinct required native assets force both eligible inputs; ineligible UTxO must never be selected"),
            operation:"coin-selection.select".into(),
            input:json!({
                "utxos":[
                    {"id":"a#0","eligible":true,"value":{"coin":coin_a,"assets":{&a:quantity}}},
                    {"id":"b#0","eligible":true,"value":{"coin":coin_b,"assets":{&b:quantity+1}}},
                    {"id":"spent#0","eligible":false,"value":{"coin":1_000_000_000,"assets":{&a:quantity*10,&b:quantity*10}}}
                ],
                "outputs":[{"coin":2_000_000+seed,"assets":{&a:1+seed%10}},{"coin":3_000_000+seed,"assets":{&b:2+seed%10}}],
                "fee":200_000+seed,"minimum_change_coin":1_000_000,"maximum_inputs":2,"seed":seed
            }),
            expected:None,selection_invariants:true,
        }
    }).collect()
}

/// Derive deterministic routing, media-negotiation and syntax rejection cases
/// from every operation with an applicable documented error. These are negative
/// tests only; they do not substitute for successful funded feature workflows.
pub fn api_rejections(contract: &crate::api::Contract) -> serde_json::Value {
    let mut cases = Vec::new();
    for op in contract.operations.values() {
        let mut path = op.path.clone();
        let mut has_parameter = false;
        while let Some(start) = path.find('{') {
            let end = start
                + path[start..]
                    .find('}')
                    .expect("well formed pinned API path");
            path.replace_range(start..=end, "invalid-conformance-parameter");
            has_parameter = true;
        }
        let mut headers = serde_json::Map::new();
        let (status, raw_body) = if has_parameter && op.statuses.contains(&400) {
            (400, None)
        } else if ["POST", "PUT", "PATCH"].contains(&op.method.as_str())
            && op.statuses.contains(&400)
        {
            (400, Some("{"))
        } else if op.statuses.contains(&406) && op.method == "GET" {
            path = op.path.clone();
            while let Some(start) = path.find('{') {
                let end = start
                    + path[start..]
                        .find('}')
                        .expect("well formed pinned API path");
                let parameter = &path[start + 1..end];
                let replacement = match parameter {
                    "walletId" => "00".repeat(20),
                    "transactionId" => "00".repeat(32),
                    "policyId" => "00".repeat(28),
                    "assetName" => "00".into(),
                    "role" => "utxo_external".into(),
                    "index" => "0".into(),
                    _ => "0".into(),
                };
                path.replace_range(start..=end, &replacement);
            }
            headers.insert(
                "Accept".into(),
                json!("application/x-conformance-unsupported"),
            );
            (406, None)
        } else if op.id == "listStakePools" {
            path.push_str("?stake=invalid");
            (400, None)
        } else {
            continue;
        };
        let mut request = json!({"method":op.method,"path":path,"headers":headers});
        // Supplying malformed JSON prevents missing Content-Type from taking
        // precedence for verbs with request bodies, even with invalid path IDs.
        if ["POST", "PUT", "PATCH"].contains(&op.method.as_str()) {
            request["raw_body"] = json!(raw_body.unwrap_or("{"));
            if op.id == "postExternalTransaction" {
                request["headers"]["Content-Type"] = json!("application/octet-stream");
            }
        }
        cases.push(json!({"id":format!("generated-reject-{}",op.id),"operation":op.id,"request":request,"expected_status":status}));
    }
    json!({"name":"Pinned API syntax and negotiation rejections","cases":cases})
}

/// Cross-check the wallet's public key API against cardano-address captures.
/// The golden inputs are already frozen and independently checksummed in the corpus.
pub fn key_api() -> anyhow::Result<serde_json::Value> {
    use anyhow::Context;
    use serde_json::Value;
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/haskell-keys.json"))?;
    let vector = |id: &str| -> anyhow::Result<&Vector> {
        vectors
            .iter()
            .find(|vector| vector.id == id)
            .context("missing Haskell key golden")
    };
    let public = |id: &str| -> anyhow::Result<String> {
        Ok(vector(id)?
            .expected
            .as_ref()
            .context("missing expected result")?["result"]["xpub_hex"]
            .as_str()
            .context("missing xpub")?
            .into())
    };
    let root = vector("haskell-Shelley-root")?;
    let lifecycle: Value = serde_json::from_str(include_str!("../fixtures/http.json"))?;
    let mut create = lifecycle["cases"][3].clone();
    create["id"] = json!("key-api-create");
    create["request"]["body"]["mnemonic_sentence"] = json!(root.input["mnemonic"]
        .as_str()
        .context("missing mnemonic")?
        .split_whitespace()
        .collect::<Vec<_>>());
    create["request"]["body"]["name"] = json!("conformance");
    create["assertions"]["/id"] = json!(hex::encode(crate::transaction::blake2b(
        &hex::decode(public("haskell-Shelley-root")?)?,
        20,
    )?));
    let mut cases = vec![create];
    for account in [0u32, 0x7fffffff] {
        let reference = vector(&format!("haskell-Shelley-{account}-0-0-public"))?;
        let account_hex = reference.input["parent_xpub_hex"]
            .as_str()
            .context("missing account key")?;
        for extended in [false, true] {
            let format = if extended { "extended" } else { "non_extended" };
            let hrp = if extended { "acct_xvk" } else { "acct_vk" };
            let expected = if extended {
                account_hex
            } else {
                &account_hex[..64]
            };
            cases.push(json!({
                "id":format!("key-api-account-{account}-{format}"),
                "source":reference.source,
                "operation":"postAccountKey",
                "request":{"method":"POST","path":format!("/wallets/${{wallet_id}}/keys/{account}H"),"body":{"passphrase":"${passphrase}","format":format}},
                "expected_status":202,
                "assert_bech32":{"":{"hrp":hrp,"bytes_hex":expected}}
            }));
            if account == 0 {
                cases.push(json!({
                    "id":format!("key-api-get-account-{format}"),"source":reference.source,
                    "operation":"getAccountKey",
                    "request":{"method":"GET","path":format!("/wallets/${{wallet_id}}/keys?format={format}")},
                    "expected_status":200,"assert_bech32":{"":{"hrp":hrp,"bytes_hex":expected}}
                }));
            }
        }
    }
    for (role, role_name, hrp) in [
        (0, "utxo_external", "addr_vk"),
        (1, "utxo_internal", "addr_vk"),
        (2, "mutable_account", "stake_vk"),
    ] {
        for index in [0u32, 19, 0x7fffffff] {
            let reference = vector(&format!("haskell-Shelley-0-{role}-{index}-private"))?;
            let key = public(&reference.id)?;
            for hashed in [false, true] {
                let expected = if hashed {
                    hex::encode(crate::transaction::blake2b(&hex::decode(&key[..64])?, 28)?)
                } else {
                    key[..64].into()
                };
                let encoded_hrp = if hashed {
                    format!("{hrp}h")
                } else {
                    hrp.into()
                };
                let mut case = json!({
                    "id":format!("key-api-role-{role}-{index}-hash-{hashed}"),"source":reference.source,
                    "operation":"getWalletKey",
                    "request":{"method":"GET","path":format!("/wallets/${{wallet_id}}/keys/{role_name}/{index}?hash={hashed}")},
                    "expected_status":200,"assert_bech32":{"":{"hrp":encoded_hrp,"bytes_hex":expected}}
                });
                if index == 0 && !hashed && role != 1 {
                    case["capture"] = json!({if role == 0 { "payment_vk" } else { "stake_vk" }:""});
                }
                cases.push(case);
            }
        }
    }
    let payment_hash = crate::transaction::blake2b(
        &hex::decode(&public("haskell-Shelley-0-0-0-private")?[..64])?,
        28,
    )?;
    let stake_hash = crate::transaction::blake2b(
        &hex::decode(&public("haskell-Shelley-0-2-0-private")?[..64])?,
        28,
    )?;
    for (name, body, bytes, hrp) in [
        (
            "base",
            json!({"payment":"${payment_vk}","stake":"${stake_vk}"}),
            [vec![0], payment_hash.clone(), stake_hash.clone()].concat(),
            "addr_test",
        ),
        (
            "enterprise",
            json!({"payment":"${payment_vk}"}),
            [vec![0x60], payment_hash].concat(),
            "addr_test",
        ),
        (
            "reward",
            json!({"stake":"${stake_vk}"}),
            [vec![0xe0], stake_hash].concat(),
            "stake_test",
        ),
    ] {
        cases.push(json!({
            "id":format!("key-api-address-{name}"),
            "source":"CIP-0019 header/payload construction with frozen Haskell key bytes and independent Blake2b-224",
            "operation":"postAnyAddress","request":{"method":"POST","path":"/addresses","body":body},
            "expected_status":202,"assert_bech32":{"/address":{"hrp":hrp,"bytes_hex":hex::encode(&bytes)}},
            "requirements":["address.shelley","address.network","address.encoding"],
            "capture":{format!("{name}_address"):"/address"}
        }));
        cases.push(json!({
            "id":format!("key-api-inspect-{name}"),"operation":"inspectAddress",
            "request":{"method":"GET","path":format!("/addresses/${{{name}_address}}")},
            "expected_status":200,"assertions":{"/network_tag":0}
        }));
    }
    let account_hex = vector("haskell-Shelley-0-0-0-public")?.input["parent_xpub_hex"]
        .as_str()
        .context("missing account golden")?;
    cases.push(json!({
        "id":"key-api-passphrase-wrong-old","operation":"putWalletPassphrase",
        "request":{"method":"PUT","path":"/wallets/${wallet_id}/passphrase","body":{"old_passphrase":"incorrect-passphrase","new_passphrase":"conformance-updated-passphrase"}},
        "expected_status":403,"assertions":{"/code":"wrong_encryption_passphrase"}
    }));
    cases.push(json!({
        "id":"key-api-passphrase-change","operation":"putWalletPassphrase",
        "request":{"method":"PUT","path":"/wallets/${wallet_id}/passphrase","body":{"old_passphrase":"${passphrase}","new_passphrase":"conformance-updated-passphrase"}},
        "expected_status":204
    }));
    cases.push(json!({
        "id":"key-api-old-passphrase-rejected","operation":"postAccountKey",
        "request":{"method":"POST","path":"/wallets/${wallet_id}/keys/0H","body":{"passphrase":"${passphrase}","format":"extended"}},
        "expected_status":403,"assertions":{"/code":"wrong_encryption_passphrase"}
    }));
    cases.push(json!({
        "id":"key-api-new-passphrase-derives-same-key","operation":"postAccountKey",
        "request":{"method":"POST","path":"/wallets/${wallet_id}/keys/0H","body":{"passphrase":"conformance-updated-passphrase","format":"extended"}},
        "expected_status":202,"assert_bech32":{"":{"hrp":"acct_xvk","bytes_hex":account_hex}}
    }));
    cases.push(json!({
        "id":"key-api-original-addresses","operation":"listAddresses",
        "request":{"method":"GET","path":"/wallets/${wallet_id}/addresses"},
        "expected_status":200,"capture":{"original_addresses":""}
    }));
    let mut remove = lifecycle["cleanup"][0].clone();
    remove["id"] = json!("key-api-delete-private-wallet");
    cases.push(remove);
    let mut watch = lifecycle["cases"][3].clone();
    watch["id"] = json!("key-api-watch-only-create");
    watch["request"]["body"] =
        json!({"name":"conformance","account_public_key":account_hex,"address_pool_gap":20});
    watch["capture"] = json!({"watch_wallet_id":"/id"});
    watch["assertions"] = json!({"/id":hex::encode(crate::transaction::blake2b(&hex::decode(account_hex)?,20)?),"/name":"conformance"});
    watch["absent"] = json!(["/passphrase"]);
    cases.push(watch);
    cases.push(json!({
        "id":"key-api-watch-only-addresses","operation":"listAddresses",
        "request":{"method":"GET","path":"/wallets/${watch_wallet_id}/addresses"},
        "expected_status":200,"assertions":{"":"${original_addresses}"},
        "requirements":["wallet.hardware-watch-only"]
    }));
    cases.push(json!({
        "id":"key-api-watch-only-private-derivation-rejected","operation":"postAccountKey",
        "request":{"method":"POST","path":"/wallets/${watch_wallet_id}/keys/0H","body":{"passphrase":"conformance-updated-passphrase","format":"extended"}},
        "expected_status":403,"assertions":{"/code":"no_root_key"},
        "requirements":["wallet.hardware-watch-only"]
    }));
    let mut cleanup = lifecycle["cleanup"][0].clone();
    cleanup["id"] = json!("key-api-cleanup");
    cleanup["request"]["path"] = json!("/wallets/${watch_wallet_id}");
    Ok(
        json!({"name":"Independent Haskell key/account/address HTTP matrix","cases":cases,"cleanup":[cleanup]}),
    )
}

/// Negative status matrix. Syntactically valid captures avoid accidentally testing
/// parameter parsing instead of content negotiation or unknown-wallet handling.
pub fn api_statuses(contract: &crate::api::Contract) -> serde_json::Value {
    let mut cases = Vec::new();
    for operation in contract.operations.values() {
        let mut path = operation.path.clone();
        let mut supported = true;
        while let Some(start) = path.find('{') {
            let end = start + path[start..].find('}').expect("pinned path capture");
            let name = &path[start + 1..end];
            let value = match name {
                "walletId" => "00".repeat(20),
                "transactionId" => "00".repeat(32),
                "policyId" => "00".repeat(28),
                "assetName" => "00".into(),
                "role" => "utxo_external".into(),
                "index"
                    if operation.id == "postAccountKey"
                        || operation.id == "postAccountKeyShared" =>
                {
                    "0H".into()
                }
                "index" => "0".into(),
                "addressId" => {
                    "addr_test1vzz6hulv54gzf2suy2u5gkvmt6ysasfdlvvegy3fmf969yc2mg7gf".into()
                }
                _ => {
                    supported = false;
                    break;
                }
            };
            path.replace_range(start..=end, &value);
        }
        if !supported {
            continue;
        }
        if operation.id == "listStakePools" {
            path.push_str("?stake=1000000");
        }
        let with_body = contract.effective_document()["paths"][&operation.path]
            [operation.method.to_lowercase()]["requestBody"]
            .is_object();
        for status in [400, 404, 406, 415] {
            // NoContent handlers do not negotiate a response representation.
            // Retain these precedence probes after removing unreachable 406s
            // from the corrected contract.
            let no_content = matches!(
                operation.id.as_str(),
                "deleteByronTransaction"
                    | "deleteByronWallet"
                    | "deleteSharedWallet"
                    | "deleteTransaction"
                    | "deleteWallet"
                    | "putByronWalletPassphrase"
                    | "putWalletPassphrase"
            );
            if (!operation.statuses.contains(&status) && !(status == 406 && no_content))
                || (status == 400 || status == 415) && !with_body
                || status == 404
                    && ((with_body && operation.id != "quitStakePool")
                        || !operation.path.contains("{walletId}"))
            {
                continue;
            }
            let accept = if operation.id == "signMetadata" {
                "application/octet-stream"
            } else {
                "application/json"
            };
            let mut req =
                json!({"method":operation.method,"path":path,"headers":{"Accept":accept}});
            if with_body {
                req["raw_body"] = json!(if status == 400 { "{" } else { "{}" });
                req["headers"]["Content-Type"] =
                    json!(if operation.id == "postExternalTransaction" {
                        "application/octet-stream"
                    } else {
                        "application/json"
                    });
            }
            if status == 406 {
                req["headers"]["Accept"] = json!("application/x-conformance-unsupported");
            }
            if status == 415 {
                req["headers"]["Content-Type"] = json!("application/x-conformance-unsupported");
            }
            if status == 404 && operation.id == "quitStakePool" {
                req["raw_body"] = json!("{\"passphrase\":\"conformance-test-passphrase\"}");
            }
            let (expected_status, precedence) = if status == 406
                && [
                    "deleteByronTransaction",
                    "deleteByronWallet",
                    "deleteSharedWallet",
                    "deleteTransaction",
                    "deleteWallet",
                    "importAddress",
                ]
                .contains(&operation.id.as_str())
            {
                (404, true)
            } else if status == 406
                && ["putByronWalletPassphrase", "putWalletPassphrase"]
                    .contains(&operation.id.as_str())
            {
                (400, true)
            } else {
                (status, false)
            };
            cases.push(json!({
                "id":if precedence { format!("precedence-{}-unsupported-accept", operation.id) } else { format!("status-{}-{status}", operation.id) },"operation":operation.id,
                "request":req,"expected_status":expected_status,
                "requirements":if precedence { vec!["api.error-precedence"] } else { vec![] },
                "source":"Independent malformed JSON, unsupported media or valid unknown-wallet request; exact error bodies additionally compared against Haskell"
            }));
        }
        if operation.id == "importAddress" {
            cases.push(json!({
                "id":"precedence-importAddress-unused-body", "operation":operation.id,
                "request":{"method":"PUT","path":path,"raw_body":"{"},
                "expected_status":404,"assertions":{"/code":"no_such_wallet"},
                "requirements":["api.error-precedence"],
                "source":"Observed Haskell body-free PUT ignores supplied malformed body and checks wallet identity"
            }));
        }
    }
    json!({"name":"API malformed body, unknown wallet and content negotiation status matrix","cases":cases})
}

/// Inputs for exact Haskell strategy/RNG capture. Expected values are obtained
/// only from the pinned external Haskell executable, never this generator.
pub fn haskell_selection_requests() -> Vec<(Vector, bool)> {
    use serde_json::Value;
    let a = format!("{}.01", "11".repeat(28));
    let b = format!("{}.02", "22".repeat(28));
    let base = json!({
        "utxos":[
            {"id":"u0#0","eligible":true,"value":{"coin":5000000,"assets":{&a:4}}},
            {"id":"u1#0","eligible":true,"value":{"coin":6000000,"assets":{&a:6}}},
            {"id":"u2#0","eligible":true,"value":{"coin":7000000,"assets":{&b:3}}},
            {"id":"u3#0","eligible":true,"value":{"coin":8000000,"assets":{&a:2,&b:7}}},
            {"id":"u4#0","eligible":true,"value":{"coin":20000000}},
            {"id":"u5#0","eligible":true,"value":{"coin":3000000,"assets":{&b:1}}},
            {"id":"u6#0","eligible":true,"value":{"coin":12000000,"assets":{&a:12,&b:2}}},
            {"id":"u7#0","eligible":true,"value":{"coin":30000000}},
            {"id":"excluded#0","eligible":false,"value":{"coin":1000000000,"assets":{&a:999,&b:999}}}
        ],
        "outputs":[{"coin":2000000,"assets":{&a:5}},{"coin":3000000,"assets":{&b:2}}],
        "minimum_fee":200000,"minimum_change_coin":1000000,"seed":0,"strategy":"optimal"
    });
    let requirements = [
        "selection.seeded-oracle",
        "selection.ada-conservation",
        "selection.asset-conservation",
        "selection.unique-inputs",
        "selection.minimum-change",
        "selection.multi-output",
        "selection.replay",
    ];
    let make = |id: String, input: Value, error: bool| {
        let mut bound_requirements: Vec<String> =
            requirements.iter().map(|id| (*id).into()).collect();
        if id == "haskell-selection-insufficient-fee" {
            bound_requirements.push("selection.insufficient-funds".into());
        }
        (
            Vector {
                id,
                requirements: bound_requirements,
                source:
                    "Pending independent Haskell capture; not an executable expected-answer fixture"
                        .into(),
                operation: "coin-selection.haskell".into(),
                input,
                expected: None,
                selection_invariants: false,
            },
            error,
        )
    };
    let mut cases = Vec::new();
    for strategy in ["minimal", "optimal"] {
        for seed in (0..64u64).chain([i64::MAX as u64, 1u64 << 63, u64::MAX]) {
            let mut input = base.clone();
            input["seed"] = json!(seed);
            input["strategy"] = json!(strategy);
            cases.push(make(
                format!("haskell-selection-{strategy}-{seed}"),
                input.clone(),
                false,
            ));
            if seed < 4 {
                input["utxos"].as_array_mut().unwrap().reverse();
                cases.push(make(
                    format!("haskell-selection-{strategy}-{seed}-permuted"),
                    input,
                    false,
                ));
            }
        }
    }
    let simple = |coin: u64| {
        json!({"utxos":[{"id":"u#0","eligible":true,"value":{"coin":coin}}],
        "outputs":[{"coin":2000000}],"minimum_fee":200000,"minimum_change_coin":1000000,"seed":42,"strategy":"optimal"})
    };
    cases.push(make(
        "haskell-selection-dust-ada".into(),
        simple(2300000),
        false,
    ));
    cases.push(make(
        "haskell-selection-large-dust-ada".into(),
        simple(2800000),
        false,
    ));
    cases.push(make(
        "haskell-selection-dust-threshold-minus-one".into(),
        simple(3199999),
        false,
    ));
    cases.push(make(
        "haskell-selection-dust-threshold-exact".into(),
        simple(3200000),
        false,
    ));
    cases.push(make(
        "haskell-selection-insufficient-fee".into(),
        simple(2000000),
        true,
    ));
    cases.push(make(
        "haskell-selection-insufficient-ada".into(),
        simple(1000000),
        true,
    ));
    let mut empty = simple(0);
    empty["utxos"] = json!([]);
    cases.push(make("haskell-selection-empty".into(), empty.clone(), true));
    empty["outputs"] = json!([]);
    cases.push(make(
        "haskell-selection-empty-no-outputs".into(),
        empty,
        true,
    ));
    let mut native_dust = simple(2300000);
    native_dust["utxos"][0]["value"]["assets"] = json!({&a:2});
    native_dust["outputs"][0]["assets"] = json!({&a:1});
    cases.push(make(
        "haskell-selection-dust-native".into(),
        native_dust,
        true,
    ));
    let mut absent_asset = simple(10000000);
    absent_asset["outputs"][0]["assets"] = json!({&a:1});
    cases.push(make(
        "haskell-selection-insufficient-asset".into(),
        absent_asset,
        true,
    ));
    let mut coin_split = simple(20000000);
    coin_split["outputs"] = json!([{"coin":2000000},{"coin":3000000}]);
    cases.push(make(
        "haskell-selection-change-coin-distribution".into(),
        coin_split,
        false,
    ));
    let mut token_split = simple(20000000);
    token_split["utxos"][0]["value"]["assets"] = json!({&a:100});
    token_split["outputs"][0]["assets"] = json!({&a:1});
    token_split["maximum_output_token_quantity"] = json!(10);
    cases.push(make(
        "haskell-selection-change-token-split".into(),
        token_split,
        false,
    ));
    let mut asset_split = simple(20000000);
    let assets: serde_json::Map<String, Value> = (0..10u8)
        .map(|index| {
            (
                format!("{}.{}", "33".repeat(28), hex::encode([index])),
                json!(1),
            )
        })
        .collect();
    asset_split["utxos"][0]["value"]["assets"] = json!(assets);
    asset_split["maximum_assets_per_bundle"] = json!(2);
    cases.push(make(
        "haskell-selection-change-asset-split".into(),
        asset_split,
        false,
    ));
    let mut wide_coin = simple(0);
    wide_coin["utxos"] = json!([
        {"id":"a#0","eligible":true,"value":{"coin":22500000000000001u64,"assets":{&a:1}}},
        {"id":"b#0","eligible":true,"value":{"coin":22499999999999998u64,"assets":{&b:1}}}
    ]);
    wide_coin["outputs"][0]["assets"] = json!({&a:1,&b:1});
    let mut wide_case = make(
        "haskell-selection-wide-coin-totals".into(),
        wide_coin,
        false,
    );
    wide_case
        .0
        .requirements
        .push("selection.large-quantities".into());
    cases.push(wide_case);
    let mut wide_tokens = simple(0);
    let c = format!("{}.03", "33".repeat(28));
    let d = format!("{}.04", "44".repeat(28));
    wide_tokens["utxos"] = json!([
        {"id":"a#0","eligible":true,"value":{"coin":10000000,"assets":{&a:i64::MAX as u64,&b:1}}},
        {"id":"b#0","eligible":true,"value":{"coin":10000000,"assets":{&a:i64::MAX as u64,&c:1}}},
        {"id":"c#0","eligible":true,"value":{"coin":10000000,"assets":{&a:i64::MAX as u64,&d:1}}}
    ]);
    wide_tokens["outputs"][0]["assets"] = json!({&a:1,&b:1,&c:1,&d:1});
    let mut wide_case = make(
        "haskell-selection-wide-token-totals".into(),
        wide_tokens,
        false,
    );
    wide_case
        .0
        .requirements
        .push("selection.large-quantities".into());
    cases.push(wide_case);
    cases
}

#[cfg(test)]
mod requirement_binding_tests {
    use super::*;
    #[test]
    fn actual_fee_shortfall_is_bound_to_insufficient_funds() {
        let frozen: Vec<Vector> =
            serde_json::from_str(include_str!("../fixtures/vectors/haskell-selection.json"))
                .unwrap();
        let actual = frozen
            .iter()
            .find(|v| v.id == "haskell-selection-insufficient-fee")
            .unwrap();
        let generated = haskell_selection_requests()
            .into_iter()
            .find(|(v, _)| v.id == actual.id)
            .unwrap()
            .0;
        assert!(actual
            .requirements
            .iter()
            .any(|r| r == "selection.insufficient-funds"));
        assert_eq!(generated.requirements, actual.requirements);
        assert_eq!(generated.input, actual.input);
        assert_eq!(
            actual.expected.as_ref().unwrap(),
            &json!({"error":{"code":"unable_to_construct_change","required_cost":200000,"shortfall":200000}})
        );
    }
}
