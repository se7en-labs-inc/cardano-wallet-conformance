//! Declarative HTTP cases with captures, independent expectations and differential checks.
use crate::{
    api::{Api, Contract, Request, Response},
    report::Report,
};
use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    thread::sleep,
    time::{Duration, Instant},
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    pub name: String,
    pub cases: Vec<Case>,
    #[serde(default)]
    pub cleanup: Vec<Case>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub source: Option<String>,
    pub operation: String,
    pub request: Request,
    pub expected_status: u16,
    pub expected_body_bytes: Option<usize>,
    pub expected_raw_hex: Option<String>,
    pub verify_signature: Option<SignatureCheck>,
    pub eventually_seconds: Option<u64>,
    #[serde(default)]
    pub settle_wallet_state: bool,
    #[serde(default)]
    pub align_network_epoch: bool,
    #[serde(default)]
    pub assertions: BTreeMap<String, Value>,
    #[serde(default)]
    pub assert_bech32: BTreeMap<String, Bech32Check>,
    #[serde(default)]
    pub absent: Vec<String>,
    #[serde(default)]
    pub capture: BTreeMap<String, String>,
    #[serde(default)]
    pub ignore: BTreeMap<String, String>,
    #[serde(default)]
    pub requirements: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bech32Check {
    pub hrp: String,
    pub bytes_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureCheck {
    pub public_key: String,
    pub message_hex: String,
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn difference(a: &Value, b: &Value, path: &str) -> Option<String> {
    if a == b {
        return None;
    }
    match (a, b) {
        (Value::Object(a), Value::Object(b)) => {
            for key in a.keys().chain(b.keys()) {
                let child = format!("{}/{}", path, key.replace('~', "~0").replace('/', "~1"));
                match (a.get(key), b.get(key)) {
                    (Some(a), Some(b)) => {
                        if let Some(path) = difference(a, b, &child) {
                            return Some(path);
                        }
                    }
                    _ => return Some(child),
                }
            }
            None
        }
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => a
            .iter()
            .zip(b)
            .enumerate()
            .find_map(|(i, (a, b))| difference(a, b, &format!("{path}/{i}"))),
        _ => Some(if path.is_empty() {
            "/".into()
        } else {
            path.into()
        }),
    }
}

/// Ignore only explicit, existing scalar values with a reason and identical types.
/// Whole arrays/objects cannot be erased to hide incompatible structures.
pub fn compare(a: &Response, b: &Response, ignore: &BTreeMap<String, String>) -> Result<()> {
    ensure!(a.status == b.status, "differential status mismatch");
    ensure!(
        a.media_type == b.media_type,
        "differential media type mismatch"
    );
    match (&a.json, &b.json) {
        (Some(a), Some(b)) => {
            let (mut a, mut b) = (a.clone(), b.clone());
            for (pointer, reason) in ignore {
                ensure!(
                    !pointer.is_empty() && !reason.trim().is_empty(),
                    "ignore requires a non-root pointer and reason"
                );
                if a.pointer(pointer).is_none() && b.pointer(pointer).is_none() {
                    continue;
                }
                let av = a
                    .pointer_mut(pointer)
                    .context("ignored reference field is absent")?;
                let bv = b
                    .pointer_mut(pointer)
                    .context("ignored target field is absent")?;
                ensure!(
                    !av.is_object() && !av.is_array() && kind(av) == kind(bv),
                    "ignored field has incompatible type"
                );
                *av = Value::Null;
                *bv = Value::Null;
            }
            if let Some(path) = difference(&a, &b, "") {
                return Err(anyhow!("differential JSON mismatch at {path}"));
            }
        }
        (None, None) => ensure!(
            ignore.is_empty() && a.raw == b.raw,
            "differential raw body mismatch"
        ),
        _ => return Err(anyhow!("differential response encoding mismatch")),
    }
    Ok(())
}

pub fn expand(v: &Value, vars: &BTreeMap<String, Value>) -> Result<Value> {
    match v {
        Value::String(s) => {
            if let Some(key) = s.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
                if !key.contains("${") {
                    return vars
                        .get(key)
                        .cloned()
                        .context("undefined template variable");
                }
            }
            let mut s = s.clone();
            for (k, v) in vars {
                if let Some(v) = v.as_str() {
                    s = s.replace(&format!("${{{k}}}"), v);
                }
            }
            ensure!(!s.contains("${"), "undefined template variable");
            Ok(Value::String(s))
        }
        Value::Array(xs) => Ok(Value::Array(
            xs.iter().map(|v| expand(v, vars)).collect::<Result<_>>()?,
        )),
        Value::Object(m) => Ok(Value::Object(
            m.iter()
                .map(|(k, v)| Ok((k.clone(), expand(v, vars)?)))
                .collect::<Result<_>>()?,
        )),
        v => Ok(v.clone()),
    }
}

fn execute(
    case: &Case,
    api: &Api,
    contract: &Contract,
    vars: &mut BTreeMap<String, Value>,
    owned: &mut std::collections::BTreeSet<String>,
) -> Result<Response> {
    let req = &case.request;
    let path = expand(&Value::String(req.path.clone()), vars)?
        .as_str()
        .context("path must be string")?
        .to_string();
    let body = req.body.as_ref().map(|v| expand(v, vars)).transpose()?;
    contract.check_path(&case.operation, &req.method, &path)?;
    let expanded_request = Request {
        method: req.method.clone(),
        path,
        body,
        raw_body: req.raw_body.clone(),
        raw_body_hex: req.raw_body_hex.clone(),
        headers: req.headers.clone(),
    };
    let mut response = api.request(&expanded_request)?;
    let value = response.json.as_ref().unwrap_or(&Value::Null);
    // Retain ownership and captures before schema/assertion checks so cleanup can
    // remove a successfully created wallet even if its response is nonconformant.
    if response.status == 201
        && ["postWallet", "postByronWallet", "postSharedWallet"].contains(&case.operation.as_str())
    {
        let id = value["id"].as_str().context("created wallet has no id")?;
        owned.insert(format!("{}/{id}", case.request.path.trim_end_matches('/')));
    }
    ensure!(
        response.status == case.expected_status,
        "unexpected HTTP status: expected {}, received {}",
        case.expected_status,
        response.status
    );
    for (name, pointer) in &case.capture {
        let v = value.pointer(pointer).context("capture field absent")?;
        ensure!(!vars.contains_key(name), "capture variable already exists");
        vars.insert(name.clone(), v.clone());
    }
    contract.validate(&case.operation, &response)?;
    if let Some(length) = case.expected_body_bytes {
        ensure!(
            response.raw.len() == length,
            "unexpected response body length"
        );
    }
    if let Some(hex) = &case.expected_raw_hex {
        ensure!(
            response.raw == hex::decode(hex)?,
            "response bytes differ from independent golden"
        );
    }
    if let Some(check) = &case.verify_signature {
        let public_key = expand(&json!(check.public_key), vars)?;
        let bytes = crate::encoding::bech32(
            public_key
                .as_str()
                .context("verification key must be encoded text")?,
        )?
        .1;
        let public: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("verification key must have 32 bytes"))?;
        let signature = ed25519_dalek::Signature::from_slice(&response.raw)?;
        ed25519_dalek::VerifyingKey::from_bytes(&public)?
            .verify_strict(&hex::decode(&check.message_hex)?, &signature)
            .context("independent metadata signature verification failed")?;
    }
    for (pointer, expected) in &case.assert_bech32 {
        let value = response
            .json
            .as_ref()
            .and_then(|value| value.pointer(pointer))
            .and_then(Value::as_str)
            .context("missing encoded response field")?;
        let (hrp, bytes) = crate::encoding::bech32(value)?;
        ensure!(
            hrp == expected.hrp && hex::encode(bytes) == expected.bytes_hex,
            "independent Bech32 golden mismatch at {pointer}"
        );
    }
    if case.eventually_seconds.is_some() {
        ensure!(
            req.method == "GET" && case.capture.is_empty() && !case.assertions.is_empty(),
            "eventual assertions require a read-only GET with no captures"
        );
    }
    let deadline = Instant::now() + Duration::from_secs(case.eventually_seconds.unwrap_or(0));
    loop {
        let result = (|| -> Result<()> {
            let value = response.json.as_ref().unwrap_or(&Value::Null);
            for (pointer, expected) in &case.assertions {
                ensure!(
                    value.pointer(pointer) == Some(&expand(expected, vars)?),
                    "assertion mismatch at {pointer}"
                );
            }
            for pointer in &case.absent {
                ensure!(
                    !pointer.is_empty() && value.pointer(pointer).is_none(),
                    "expected absent field at {pointer}"
                );
            }
            Ok(())
        })();
        if result.is_ok() {
            break;
        }
        if Instant::now() >= deadline {
            return result.map(|_| response);
        }
        sleep(Duration::from_millis(100));
        response = api.checked(
            contract,
            &case.operation,
            expanded_request.clone(),
            case.expected_status,
        )?;
    }
    if case.settle_wallet_state {
        let (get_operation, family) = match case.operation.as_str() {
            "postWallet" => ("getWallet", "wallets"),
            "postByronWallet" => ("getByronWallet", "byron-wallets"),
            "postSharedWallet" => ("getSharedWallet", "shared-wallets"),
            _ => anyhow::bail!("wallet-state settling requires wallet creation"),
        };
        let id = response
            .json
            .as_ref()
            .and_then(|v| v["id"].as_str())
            .context("created wallet has no ID")?
            .to_string();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let snapshot = api.checked(
                contract,
                get_operation,
                crate::api::request("GET", format!("/{family}/{id}"), None),
                200,
            )?;
            let snapshot = snapshot.json.context("wallet snapshot is not JSON")?;
            if snapshot.pointer("/state/status") == Some(&json!("ready")) {
                // Both initial states were independently schema-checked. Compare
                // their observed terminal state, preserving all stable POST fields.
                response
                    .json
                    .as_mut()
                    .context("wallet response is not JSON")?["state"] = snapshot["state"].clone();
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "created wallet did not reach ready state"
            );
            sleep(Duration::from_millis(100));
        }
    }
    if case.align_network_epoch {
        network_epoch(&response)?;
    }
    Ok(response)
}

fn network_epoch(response: &Response) -> Result<u64> {
    let body = response
        .json
        .as_ref()
        .context("network information is not JSON")?;
    let epoch = body
        .pointer("/network_tip/epoch_number")
        .and_then(Value::as_u64)
        .context("invalid network-tip epoch")?;
    let next = body
        .pointer("/next_epoch/epoch_number")
        .and_then(Value::as_u64)
        .context("invalid next epoch")?;
    ensure!(
        epoch.checked_add(1) == Some(next),
        "next epoch must succeed network-tip epoch"
    );
    Ok(epoch)
}

/// Run all cases; cleanup executes even after an assertion or transport failure.
pub fn run(
    suite: &Suite,
    target: &Api,
    reference: Option<&Api>,
    contract: &Contract,
    environment: &str,
) -> Result<Report> {
    ensure!(!suite.cases.is_empty(), "empty scenario suite");
    let mut ids = std::collections::BTreeSet::new();
    for case in suite.cases.iter().chain(&suite.cleanup) {
        ensure!(ids.insert(&case.id), "duplicate case ID");
        ensure!(
            !case.align_network_epoch
                || (case.operation == "getNetworkInformation"
                    && case.request.method == "GET"
                    && case.request.body.is_none()
                    && case.request.raw_body.is_none()
                    && case.expected_status == 200
                    && case.capture.is_empty()
                    && !case.settle_wallet_state
                    && case.eventually_seconds.is_none()),
            "epoch alignment requires a read-only network-information case"
        );
        ensure!(
            !case.settle_wallet_state
                || (matches!(
                    case.operation.as_str(),
                    "postWallet" | "postByronWallet" | "postSharedWallet"
                ) && case.expected_status == 201),
            "wallet-state settling requires successful wallet creation"
        );
        contract.operation(&case.operation)?;
        ensure!(
            case.expected_status < 500
                || (case.expected_status == 500
                    && contract.operation(&case.operation)?.statuses.contains(&500)),
            "undocumented server errors cannot be passing expectations"
        );
    }
    let mnemonic = bip39::Mnemonic::generate(15)?;
    let initial = BTreeMap::from([
        (
            "mnemonic".into(),
            json!(mnemonic.words().collect::<Vec<_>>()),
        ),
        (
            "mnemonic12".into(),
            json!(bip39::Mnemonic::generate(12)?.words().collect::<Vec<_>>()),
        ),
        (
            "mnemonic24".into(),
            json!(bip39::Mnemonic::generate(24)?.words().collect::<Vec<_>>()),
        ),
        (
            "mnemonic_peer".into(),
            json!(bip39::Mnemonic::generate(15)?.words().collect::<Vec<_>>()),
        ),
        ("passphrase".into(), json!("conformance-test-passphrase")),
    ]);
    let (mut tv, mut rv) = (initial.clone(), initial);
    let mut report = Report::new(&target.label, environment);
    for case in suite.cases.iter().chain(&suite.cleanup) {
        if !crate::report::registered_http(case)? {
            report.unregistered_inputs.push(case.id.clone());
        }
    }
    let mut owned_target = std::collections::BTreeSet::new();
    let mut owned_reference = std::collections::BTreeSet::new();
    for case in suite.cases.iter().chain(&suite.cleanup) {
        let cleanup = suite.cleanup.iter().any(|x| std::ptr::eq(x, case));
        let execute_owned = |api: &Api,
                             vars: &mut BTreeMap<String, Value>,
                             owned: &mut std::collections::BTreeSet<String>|
         -> Result<Response> {
            if cleanup && case.request.method == "DELETE" {
                let path = expand(&json!(case.request.path), vars)?;
                let path = path.as_str().context("invalid cleanup path")?;
                ensure!(
                    owned.contains(path),
                    "cleanup can delete only wallets created by this run"
                );
            }
            execute(case, api, contract, vars, owned)
        };
        let actual = execute_owned(target, &mut tv, &mut owned_target);
        let reference_result =
            reference.map(|api| execute_owned(api, &mut rv, &mut owned_reference));
        let result = match (actual, reference_result) {
            (Ok(mut a), Some(Ok(mut b))) => (|| {
                if case.align_network_epoch {
                    let mut retries = 0;
                    while network_epoch(&a)? != network_epoch(&b)? {
                        ensure!(
                            retries < 3,
                            "network-tip epochs did not align after four sample pairs"
                        );
                        retries += 1;
                        sleep(Duration::from_millis(100));
                        a = execute_owned(target, &mut tv, &mut owned_target)?;
                        b = execute_owned(
                            reference.context("missing reference")?,
                            &mut rv,
                            &mut owned_reference,
                        )
                        .map_err(|_| {
                            anyhow!("reference case failed its independent expectations")
                        })?;
                    }
                }
                compare(&b, &a, &case.ignore)
            })(),
            (Ok(_), None) => Ok(()),
            (Err(e), _) => Err(e),
            (_, Some(Err(_))) => Err(anyhow!(
                "reference case failed its independent expectations"
            )),
        };
        let mut requirements = case.requirements.clone();
        let polarity = if case.expected_status < 300 {
            "positive"
        } else {
            "negative"
        };
        requirements.push(format!("api:{}:{polarity}", case.operation));
        requirements.push(format!(
            "api:{}:status:{}",
            case.operation, case.expected_status
        ));
        if reference.is_some() {
            requirements.push("api.differential-reference".into());
        }
        report.record(&case.id, &requirements, result);
    }
    Ok(report)
}
