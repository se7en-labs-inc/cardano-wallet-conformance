//! Valid-body status and owned unfunded lifecycle cases for the pinned HTTP API.
use crate::{adapter::Vector, api::Contract, encoding};
use anyhow::{Context, Result};
use serde_json::{json, Value};

fn case(
    id: &str,
    operation: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
    status: u16,
) -> Value {
    let mut request = json!({"method":method,"path":path});
    if let Some(body) = body {
        request["body"] = body;
    }
    json!({"id":id,"operation":operation,"request":request,"expected_status":status,"source":"Pinned Haskell handlers; valid public encodings and owned empty wallets; exact differential responses and independent status/schema checks"})
}
fn delegation_guards() -> Result<Vec<Value>> {
    let controls: Value = serde_json::from_str(include_str!("../fixtures/voting-controls.json"))?;
    let ignore = json!({
        "/passphrase/last_updated_at":"creation time belongs to each service",
        "/tip/absolute_slot_number":"services can observe different tips",
        "/tip/epoch_number":"services can observe different tips",
        "/tip/height/quantity":"services can observe different tips",
        "/tip/slot_number":"services can observe different tips",
        "/tip/time":"services can observe different tips"
    });
    let mut before = case(
        "extended-delegation-guards-wallet-before",
        "getWallet",
        "GET",
        "/wallets/${extended_shelley}",
        None,
        200,
    );
    before["assertions"] = json!({"/id":"${extended_shelley}","/name":"conformance","/state/status":"ready",
        "/balance/available":{"quantity":0,"unit":"lovelace"},"/balance/total":{"quantity":0,"unit":"lovelace"},
        "/balance/reward":{"quantity":0,"unit":"lovelace"}});
    before["capture"] = json!({"extended_guard_balance":"/balance","extended_guard_assets":"/assets",
        "extended_guard_delegation":"/delegation","extended_guard_name":"/name"});
    before["ignore"] = ignore.clone();
    before["source"]=json!("Pinned empty voting-controls.json errors and Haskell IO.Delegation guards; terminal-ready owned empty wallet on both services");
    let mut addresses = case(
        "extended-delegation-guards-addresses-before",
        "listAddresses",
        "GET",
        "/wallets/${extended_shelley}/addresses",
        None,
        200,
    );
    addresses["capture"] = json!({"extended_guard_addresses":""});
    addresses["source"]=json!("Complete owned wallet address bytes/state/order retained across rejected delegation requests");
    let mut utxo = case(
        "extended-delegation-guards-utxo-before",
        "getWalletUtxoSnapshot",
        "GET",
        "/wallets/${extended_shelley}/utxo",
        None,
        200,
    );
    utxo["capture"] = json!({"extended_guard_utxo":""});
    utxo["assertions"] = json!({"":{"entries":[]}});
    utxo["source"] =
        json!("Independently empty source wallet; rejected requests must not create UTxOs");
    let mut history = case(
        "extended-delegation-guards-history-before",
        "listTransactions",
        "GET",
        "/wallets/${extended_shelley}/transactions",
        None,
        200,
    );
    history["assertions"] = json!({"":[]});
    history["source"]=json!("Empty history before any vote/pool transaction; no pending insertion is permitted on failure");
    let mut vote = case(
        "extended-vote-empty-403",
        "joinDRep",
        "PUT",
        "/dreps/abstain/wallets/${extended_shelley}",
        Some(json!({"passphrase":"${passphrase}"})),
        403,
    );
    vote["assertions"] =
        json!({"":controls.get("empty").context("frozen empty-vote error missing")?});
    vote["absent"] = json!(["/info"]);
    vote["source"]=json!("Actual pinned Haskell voting-controls.json empty response, already observed before the separately pending funded cast_vote schema failure");
    let mut quit = case(
        "extended-quit-not-delegating-403",
        "quitStakePool",
        "DELETE",
        "/stake-pools/*/wallets/${extended_shelley}",
        Some(json!({"passphrase":"${passphrase}"})),
        403,
    );
    quit["assertions"] =
        json!({"":controls.get("not_delegating").context("frozen not-delegating error missing")?});
    quit["absent"] = json!(["/info"]);
    quit["source"]=json!("Actual pinned Haskell voting-controls.json not_delegating response; no funded delegation or schema correction is invoked");
    let mut after = case(
        "extended-delegation-guards-wallet-after",
        "getWallet",
        "GET",
        "/wallets/${extended_shelley}",
        None,
        200,
    );
    after["assertions"] = json!({"/id":"${extended_shelley}","/name":"${extended_guard_name}","/state/status":"ready",
        "/balance":"${extended_guard_balance}","/assets":"${extended_guard_assets}","/delegation":"${extended_guard_delegation}"});
    after["ignore"] = ignore;
    after["source"]=json!("Exact owned wallet identity/name/balance/assets/delegation preservation after both rejected requests");
    let mut addresses_after = case(
        "extended-delegation-guards-addresses-after",
        "listAddresses",
        "GET",
        "/wallets/${extended_shelley}/addresses",
        None,
        200,
    );
    addresses_after["assertions"] = json!({"":"${extended_guard_addresses}"});
    addresses_after["source"]=json!("Complete address/state/order array must remain byte-for-byte equal to the pre-request capture");
    let mut utxo_after = case(
        "extended-delegation-guards-utxo-after",
        "getWalletUtxoSnapshot",
        "GET",
        "/wallets/${extended_shelley}/utxo",
        None,
        200,
    );
    utxo_after["assertions"] = json!({"":"${extended_guard_utxo}"});
    utxo_after["source"] = json!("Complete UTxO snapshot must remain exactly empty and unchanged");
    let mut history_after = case(
        "extended-delegation-guards-history-after",
        "listTransactions",
        "GET",
        "/wallets/${extended_shelley}/transactions",
        None,
        200,
    );
    history_after["assertions"] = json!({"":[]});
    history_after["source"] =
        json!("Both rejected actions must leave history empty with no pending transaction");
    Ok(vec![
        before,
        addresses,
        utxo,
        history,
        vote,
        quit,
        after,
        addresses_after,
        utxo_after,
        history_after,
    ])
}
pub fn generate(contract: &Contract) -> Result<Value> {
    let codec: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/ledger-profiles.json"))?;
    let tx = codec
        .iter()
        .find(|v| v.id == "tx-cbor-conway")
        .context("missing Conway transaction")?
        .expected
        .as_ref()
        .unwrap()["result"]["cbor_hex"]
        .clone();
    let keys: Vec<Vector> =
        serde_json::from_str(include_str!("../fixtures/vectors/haskell-keys.json"))?;
    let shared = keys
        .iter()
        .find(|v| v.id == "haskell-Shared-0-0-0-public")
        .context("missing shared account key")?;
    let shared_key = encoding::bech32_encode(
        "acct_shared_xvk",
        &hex::decode(
            shared.input["parent_xpub_hex"]
                .as_str()
                .context("missing account xpub")?,
        )?,
    )?;
    let destination = "addr_test1vzz6hulv54gzf2suy2u5gkvmt6ysasfdlvvegy3fmf969yc2mg7gf";
    let payments = json!([{"address":destination,"amount":{"quantity":1000000,"unit":"lovelace"}}]);
    let passphrase = json!({"passphrase":"${passphrase}"});
    let mut cases = vec![];
    // Only documented unknown-wallet statuses enter this slice. Newly found
    // undocumented statuses require their own evidence-backed contract review.
    for (id, body) in [
        ("putWallet", json!({"name":"unknown"})),
        ("putByronWallet", json!({"name":"unknown"})),
        ("putSharedWallet", json!({"name":"unknown"})),
        (
            "putWalletPassphrase",
            json!({"old_passphrase":"${passphrase}","new_passphrase":"${passphrase}"}),
        ),
        (
            "putByronWalletPassphrase",
            json!({"old_passphrase":"${passphrase}","new_passphrase":"${passphrase}"}),
        ),
        (
            "createShelleyWalletMigrationPlan",
            json!({"addresses":[destination]}),
        ),
        (
            "createByronWalletMigrationPlan",
            json!({"addresses":[destination]}),
        ),
        (
            "migrateShelleyWallet",
            json!({"addresses":[destination],"passphrase":"${passphrase}"}),
        ),
        (
            "migrateByronWallet",
            json!({"addresses":[destination],"passphrase":"${passphrase}"}),
        ),
        (
            "postTransaction",
            json!({"payments":payments,"passphrase":"${passphrase}"}),
        ),
        (
            "postByronTransaction",
            json!({"payments":payments,"passphrase":"${passphrase}"}),
        ),
        ("postTransactionFee", json!({"payments":payments})),
        ("postByronTransactionFee", json!({"payments":payments})),
        ("selectCoins", json!({"payments":payments})),
        ("byronSelectCoins", json!({"payments":payments})),
        ("constructTransaction", json!({"payments":payments})),
        ("constructSharedTransaction", json!({"payments":payments})),
        ("decodeTransaction", json!({"transaction":tx})),
        ("decodeSharedTransaction", json!({"transaction":tx})),
        (
            "signTransaction",
            json!({"transaction":tx,"passphrase":"${passphrase}"}),
        ),
        (
            "signSharedTransaction",
            json!({"transaction":tx,"passphrase":"${passphrase}"}),
        ),
        ("submitTransaction", json!({"transaction":tx})),
        ("submitSharedTransaction", json!({"transaction":tx})),
        (
            "balanceTransaction",
            json!({"transaction":tx,"inputs":[],"redeemers":[]}),
        ),
        (
            "patchSharedWalletInPayment",
            json!({"cosigner#1":shared_key}),
        ),
        (
            "patchSharedWalletInDelegation",
            json!({"cosigner#1":shared_key}),
        ),
        ("joinDRep", passphrase.clone()),
        ("joinStakePool", passphrase.clone()),
    ] {
        let op = contract.operation(id)?;
        if !op.statuses.contains(&404) {
            continue;
        }
        let path = op
            .path
            .replace("{walletId}", &"00".repeat(20))
            .replace("{stakePoolId}", &"00".repeat(28))
            .replace("{drepId}", "abstain");
        cases.push(case(
            &format!("extended-unknown-{id}"),
            id,
            &op.method,
            &path,
            Some(body),
            404,
        ));
    }
    let lifecycle: Value = serde_json::from_str(include_str!("../fixtures/http.json"))?;
    let families: Value = serde_json::from_str(include_str!("../fixtures/http-families.json"))?;
    let mut created = vec![];
    for (source, id, variable) in [
        (&lifecycle, "create-wallet", "extended_shelley"),
        (&families, "family-random-create", "extended_random"),
        (&families, "family-icarus-create", "extended_icarus"),
        (&families, "family-shared-active-create", "extended_shared"),
    ] {
        let mut create = source["cases"]
            .as_array()
            .context("missing lifecycle cases")?
            .iter()
            .find(|c| c["id"] == id)
            .context("missing lifecycle create")?
            .clone();
        create["id"] = json!(format!("extended-create-{variable}"));
        create["capture"] = json!({variable:"/id"});
        create["settle_wallet_state"] = json!(true);
        let body = create["request"]["body"].clone();
        let method = create["request"]["method"].as_str().unwrap();
        let path = create["request"]["path"].as_str().unwrap().to_owned();
        let duplicate = case(
            &format!("extended-duplicate-{variable}"),
            create["operation"].as_str().unwrap(),
            method,
            &path,
            Some(body),
            409,
        );
        cases.push(create);
        cases.push(duplicate);
        created.push((variable, path));
    }
    let account = keys
        .iter()
        .find(|v| v.id == "haskell-Shelley-0-0-0-public")
        .context("missing public-only wallet key")?
        .input["parent_xpub_hex"]
        .clone();
    let mut watch = lifecycle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "create-wallet")
        .unwrap()
        .clone();
    watch["id"] = json!("extended-create-watch-only");
    watch["request"]["body"] =
        json!({"name":"conformance","account_public_key":account,"address_pool_gap":20});
    watch["capture"] = json!({"extended_watch":"/id"});
    watch["settle_wallet_state"] = json!(true);
    watch["absent"] = json!(["/passphrase"]);
    cases.push(watch);
    created.push(("extended_watch", "/wallets".into()));
    for (id, op, method, path, body, status) in [
        (
            "extended-policy-absent",
            "getPolicyKey",
            "GET",
            "/wallets/${extended_watch}/policy-key",
            None,
            403,
        ),
        (
            "extended-policy-id-absent",
            "postPolicyId",
            "POST",
            "/wallets/${extended_watch}/policy-id",
            Some(json!({"policy_script_template":"cosigner#0"})),
            403,
        ),
        (
            "extended-policy-create",
            "postPolicyKey",
            "POST",
            "/wallets/${extended_shelley}/policy-key",
            Some(passphrase.clone()),
            202,
        ),
        (
            "extended-policy-read",
            "getPolicyKey",
            "GET",
            "/wallets/${extended_shelley}/policy-key",
            None,
            200,
        ),
        (
            "extended-policy-id",
            "postPolicyId",
            "POST",
            "/wallets/${extended_shelley}/policy-id",
            Some(json!({"policy_script_template":{"all":["cosigner#0"]}})),
            202,
        ),
        (
            "extended-stake-keys",
            "listStakeKeys",
            "GET",
            "/wallets/${extended_shelley}/stake-keys",
            None,
            200,
        ),
        (
            "extended-stake-fee-unfunded",
            "getDelegationFee",
            "GET",
            "/wallets/${extended_shelley}/delegation-fees",
            None,
            403,
        ),
        (
            "extended-random-address",
            "createAddress",
            "POST",
            "/byron-wallets/${extended_random}/addresses",
            Some(json!({"passphrase":"${passphrase}","address_index":2147495993u32})),
            201,
        ),
        (
            "extended-icarus-random-address-forbidden",
            "createAddress",
            "POST",
            "/byron-wallets/${extended_icarus}/addresses",
            Some(json!({"passphrase":"${passphrase}","address_index":2147495993u32})),
            403,
        ),
        (
            "extended-random-import-owned",
            "importAddress",
            "PUT",
            "/byron-wallets/${extended_random}/addresses/${extended_random_address}",
            None,
            204,
        ),
        (
            "extended-random-import-owned-bulk",
            "importAddresses",
            "PUT",
            "/byron-wallets/${extended_random}/addresses",
            Some(json!({"addresses":["${extended_random_address}"]})),
            204,
        ),
        (
            "extended-random-import-foreign",
            "importAddress",
            "PUT",
            "/byron-wallets/${extended_random}/addresses/${extended_foreign_address}",
            None,
            403,
        ),
        (
            "extended-random-import-foreign-bulk",
            "importAddresses",
            "PUT",
            "/byron-wallets/${extended_random}/addresses",
            Some(json!({"addresses":["${extended_foreign_address}"]})),
            403,
        ),
        (
            "extended-shared-active-payment-patch",
            "patchSharedWalletInPayment",
            "PATCH",
            "/shared-wallets/${extended_shared}/payment-script-template",
            Some(json!({"cosigner#1":shared_key})),
            403,
        ),
        (
            "extended-shared-active-delegation-patch",
            "patchSharedWalletInDelegation",
            "PATCH",
            "/shared-wallets/${extended_shared}/delegation-script-template",
            Some(json!({"cosigner#1":shared_key})),
            403,
        ),
        (
            "extended-smash-invalid-url",
            "getCurrentSmashHealth",
            "GET",
            "/smash/health?url=invalid",
            None,
            400,
        ),
        (
            "extended-drep-absent",
            "getDRep",
            "GET",
            "/dreps/abstain",
            None,
            404,
        ),
        (
            "extended-settings-none",
            "putSettings",
            "PUT",
            "/settings",
            Some(json!({"settings":{"pool_metadata_source":"none"}})),
            204,
        ),
        (
            "extended-maintenance",
            "postMaintenanceAction",
            "POST",
            "/stake-pools/maintenance-actions",
            Some(json!({"maintenance_action":"gc_stake_pools"})),
            204,
        ),
    ] {
        if id == "extended-random-address" {
            let mut c = case(id, op, method, path, body, status);
            c["capture"] = json!({"extended_random_address":"/id"});
            cases.push(c);
            cases.push(case(
                "extended-icarus-addresses",
                "listByronAddresses",
                "GET",
                "/byron-wallets/${extended_icarus}/addresses",
                None,
                200,
            ));
            let last = cases.last_mut().unwrap();
            last["capture"] = json!({"extended_foreign_address":"/0/id"});
        } else {
            cases.push(case(id, op, method, path, body, status));
        }
    }
    for (id, op, path, body) in [
        (
            "extended-shelley-selection-empty",
            "selectCoins",
            "/wallets/${extended_shelley}/coin-selections/random",
            json!({"payments":payments}),
        ),
        (
            "extended-byron-selection-empty",
            "byronSelectCoins",
            "/byron-wallets/${extended_icarus}/coin-selections/random",
            json!({"payments":payments}),
        ),
        (
            "extended-shelley-payment-empty",
            "postTransaction",
            "/wallets/${extended_shelley}/transactions",
            json!({"payments":payments,"passphrase":"${passphrase}"}),
        ),
        (
            "extended-byron-payment-empty",
            "postByronTransaction",
            "/byron-wallets/${extended_icarus}/transactions",
            json!({"payments":payments,"passphrase":"${passphrase}"}),
        ),
        (
            "extended-shelley-fee-empty",
            "postTransactionFee",
            "/wallets/${extended_shelley}/payment-fees",
            json!({"payments":payments}),
        ),
        (
            "extended-byron-fee-empty",
            "postByronTransactionFee",
            "/byron-wallets/${extended_icarus}/payment-fees",
            json!({"payments":payments}),
        ),
        (
            "extended-shelley-construct-empty",
            "constructTransaction",
            "/wallets/${extended_shelley}/transactions-construct",
            json!({"payments":payments}),
        ),
        (
            "extended-shared-construct-empty",
            "constructSharedTransaction",
            "/shared-wallets/${extended_shared}/transactions-construct",
            json!({"payments":payments}),
        ),
        (
            "extended-shelley-migration-plan-empty",
            "createShelleyWalletMigrationPlan",
            "/wallets/${extended_shelley}/migrations/plan",
            json!({"addresses":[destination]}),
        ),
        (
            "extended-byron-migration-plan-empty",
            "createByronWalletMigrationPlan",
            "/byron-wallets/${extended_icarus}/migrations/plan",
            json!({"addresses":[destination]}),
        ),
        (
            "extended-shelley-migration-empty",
            "migrateShelleyWallet",
            "/wallets/${extended_shelley}/migrations",
            json!({"addresses":[destination],"passphrase":"${passphrase}"}),
        ),
        (
            "extended-byron-migration-empty",
            "migrateByronWallet",
            "/byron-wallets/${extended_icarus}/migrations",
            json!({"addresses":[destination],"passphrase":"${passphrase}"}),
        ),
    ] {
        cases.push(case(id, op, "POST", path, Some(body), 403));
    }
    let guard_offset = cases
        .iter()
        .position(|v| v["id"] == "extended-stake-fee-unfunded")
        .context("missing empty guard insertion point")?;
    cases.splice(guard_offset..guard_offset, delegation_guards()?);
    let mut malformed = case(
        "extended-maintenance-malformed",
        "postMaintenanceAction",
        "POST",
        "/stake-pools/maintenance-actions",
        None,
        400,
    );
    malformed["request"]["raw_body"] = json!("{");
    malformed["assertions"] = json!({"/code":"bad_request"});
    cases.push(malformed);
    for entry in &mut cases {
        if entry["id"] == "extended-stake-fee-unfunded" {
            entry["assertions"] = json!({"/code":"no_utxos_available"});
        }
    }
    let cleanup = created
        .into_iter()
        .map(|(variable, path)| {
            let op = if path == "/wallets" {
                "deleteWallet"
            } else if path == "/shared-wallets" {
                "deleteSharedWallet"
            } else {
                "deleteByronWallet"
            };
            case(
                &format!("extended-cleanup-{variable}"),
                op,
                "DELETE",
                &format!("{path}/${{{variable}}}"),
                None,
                204,
            )
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"name":"Valid-body unknown-wallet, owned policy/address and unfunded status matrix","cases":cases,"cleanup":cleanup}),
    )
}
