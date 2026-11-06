//! Pinned OpenAPI contract inventory and independent HTTP response validation.
use anyhow::{anyhow, bail, ensure, Context, Result};
use reqwest::{blocking::Client, redirect::Policy, Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Duration};

#[derive(Debug, Clone, Serialize)]
pub struct Operation {
    pub id: String,
    pub method: String,
    pub path: String,
    pub statuses: Vec<u16>,
}

pub struct Contract {
    document: Value,
    pub operations: BTreeMap<String, Operation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corrections {
    format_version: u32,
    source_sha256: String,
    corrections: Vec<Correction>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Correction {
    id: String,
    before: String,
    after: String,
}

fn corrected_source(source: &str, manifest: &str) -> Result<String> {
    let manifest: Corrections = serde_json::from_str(manifest)?;
    ensure!(
        manifest.format_version == 1,
        "unsupported correction format"
    );
    ensure!(
        hex::encode(Sha256::digest(source.as_bytes())) == manifest.source_sha256,
        "correction source digest mismatch"
    );
    let mut corrected = source.to_owned();
    for correction in manifest.corrections {
        ensure!(
            !correction.before.is_empty() && corrected.matches(&correction.before).count() == 1,
            "correction {} must match exactly once",
            correction.id
        );
        corrected = corrected.replacen(&correction.before, &correction.after, 1);
    }
    Ok(corrected)
}

fn pointer_part(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

// OpenAPI 3.0 uses a JSON Schema dialect: translate its nullable and boolean
// exclusive bounds to Draft 7 without weakening required fields or oneOf.
fn normalize(v: &mut Value) {
    match v {
        Value::Array(xs) => xs.iter_mut().for_each(normalize),
        Value::Object(m) => {
            for x in m.values_mut() {
                normalize(x);
            }
            for (exclusive, bound) in [
                ("exclusiveMinimum", "minimum"),
                ("exclusiveMaximum", "maximum"),
            ] {
                if let Some(Value::Bool(ex)) = m.get(exclusive).cloned() {
                    m.remove(exclusive);
                    if ex {
                        if let Some(n) = m.remove(bound) {
                            m.insert(exclusive.into(), n);
                        }
                    }
                }
            }
            if m.remove("nullable") == Some(Value::Bool(true)) {
                let original = Value::Object(m.clone());
                m.clear();
                m.insert("anyOf".into(), json!([original, {"type":"null"}]));
            }
        }
        _ => {}
    }
}

impl Contract {
    pub fn load(yaml: &str) -> Result<Self> {
        let mut document: serde_yaml::Value =
            serde_yaml::from_str(yaml).context("invalid OpenAPI YAML")?;
        document.apply_merge().context("invalid YAML merge")?;
        let mut document = serde_json::to_value(document).context("OpenAPI conversion failed")?;
        ensure!(
            document["openapi"]
                .as_str()
                .is_some_and(|s| s.starts_with("3.0.")),
            "expected OpenAPI 3.0"
        );
        normalize(&mut document);
        let mut operations = BTreeMap::new();
        for (path, item) in document["paths"]
            .as_object()
            .context("missing OpenAPI paths")?
        {
            for method in [
                "get", "post", "put", "delete", "patch", "head", "options", "trace",
            ] {
                if let Some(op) = item.get(method) {
                    let id = op["operationId"]
                        .as_str()
                        .context("operation without operationId")?
                        .to_string();
                    ensure!(!operations.contains_key(&id), "duplicate operationId");
                    operations.insert(
                        id.clone(),
                        Operation {
                            id,
                            method: method.to_uppercase(),
                            path: path.clone(),
                            statuses: op["responses"]
                                .as_object()
                                .context("missing operation responses")?
                                .keys()
                                .filter_map(|s| s.parse().ok())
                                .collect(),
                        },
                    );
                }
            }
        }
        ensure!(!operations.is_empty(), "empty OpenAPI inventory");
        Ok(Self {
            document,
            operations,
        })
    }

    pub fn pinned() -> Result<Self> {
        Self::load(&corrected_source(
            include_str!("../fixtures/api/openapi.yaml"),
            include_str!("../fixtures/api/haskell-corrections.json"),
        )?)
    }

    /// Every explicit documented HTTP response, including 5xx above 500.
    pub fn requirements(&self) -> Vec<crate::report::Requirement> {
        let mut result = Vec::new();
        for op in self.operations.values() {
            for polarity in ["positive", "negative"] {
                if polarity == "negative" && !op.statuses.iter().any(|s| (400..=599).contains(s)) {
                    continue;
                }
                result.push(crate::report::Requirement {
                    id: format!("api:{}:{polarity}", op.id),
                    description: format!(
                        "{} {}: {polarity} behavior with independent assertions",
                        op.method, op.path
                    ),
                    required_cases: Vec::new(),
                });
            }
            for status in op.statuses.iter().filter(|s| (200..=599).contains(*s)) {
                result.push(crate::report::Requirement {
                    id: format!("api:{}:status:{status}", op.id),
                    description: format!("{} {} documented status {status}", op.method, op.path),
                    required_cases: Vec::new(),
                });
            }
        }
        result
    }

    pub fn operation(&self, id: &str) -> Result<&Operation> {
        self.operations
            .get(id)
            .ok_or_else(|| anyhow!("unknown operation: {id}"))
    }

    /// Effective behavioral contract; response schemas use Draft 7 normalization.
    pub fn effective_document(&self) -> &Value {
        &self.document
    }

    pub fn check_path(&self, id: &str, method: &str, path: &str) -> Result<()> {
        let op = self.operation(id)?;
        ensure!(method == op.method, "method does not match operation {id}");
        let actual = path.split('?').next().unwrap_or(path);
        let xs: Vec<_> = actual.split('/').collect();
        let ts: Vec<_> = op.path.split('/').collect();
        ensure!(xs.len() == ts.len(), "path does not match operation {id}");
        for (t, x) in ts.iter().zip(xs) {
            ensure!(
                (t.starts_with('{') && t.ends_with('}') && !x.is_empty()) || *t == x,
                "path does not match operation {id}"
            );
        }
        Ok(())
    }

    pub fn validate(&self, id: &str, response: &Response) -> Result<()> {
        let op = self.operation(id)?;
        let root = format!(
            "/paths/{}/{}/responses",
            pointer_part(&op.path),
            op.method.to_lowercase()
        );
        let status = response.status.to_string();
        let responses = self
            .document
            .pointer(&root)
            .context("operation has no responses")?;
        let key = if responses.get(&status).is_some() {
            status
        } else {
            "default".into()
        };
        let spec = responses
            .get(&key)
            .context("undocumented response status")?;
        let content = spec.get("content").and_then(Value::as_object);
        if let Some(content) = content {
            let media = response
                .media_type
                .as_deref()
                .context("missing response content type")?;
            ensure!(
                content.contains_key(media),
                "undocumented response media type"
            );
            let schema_path = format!(
                "{root}/{}/content/{}/schema",
                pointer_part(&key),
                pointer_part(media)
            );
            ensure!(
                self.document.pointer(&schema_path).is_some(),
                "missing response schema"
            );
            let mut schema = self.document.clone();
            schema
                .as_object_mut()
                .context("invalid schema document")?
                .insert(
                    "x-conformance-response".into(),
                    self.document
                        .pointer(&schema_path)
                        .context("missing response schema")?
                        .clone(),
                );
            schema
                .as_object_mut()
                .context("invalid schema document")?
                .insert(
                    "$ref".into(),
                    Value::String("#/x-conformance-response".into()),
                );
            let validator = jsonschema::options()
                .with_draft(jsonschema::Draft::Draft7)
                .build(&schema)
                .map_err(|error| anyhow!("invalid response schema for {id}: {error}"))?;
            let binary_value;
            let value = if media == "application/octet-stream" {
                let spec = self
                    .document
                    .pointer(&schema_path)
                    .context("missing binary schema")?;
                ensure!(
                    spec["type"] == "string" && spec["format"] == "binary",
                    "unsupported binary response schema"
                );
                // One character per byte preserves raw binary length constraints.
                binary_value = Value::String(response.raw.iter().map(|b| char::from(*b)).collect());
                &binary_value
            } else if media == "text/plain" {
                binary_value = Value::String(std::str::from_utf8(&response.raw)?.to_owned());
                &binary_value
            } else {
                response.json.as_ref().context("expected a JSON response")?
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                validator
                    .validate(value)
                    .map_err(|error| error.instance_path.to_string())
            }))
            .map_err(|_| anyhow!("response schema evaluation failed"))?;
            if let Err(path) = result {
                bail!("response schema mismatch at {path}");
            }
        } else {
            ensure!(response.raw.is_empty(), "unexpected response body");
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub media_type: Option<String>,
    pub json: Option<Value>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Option<Value>,
    pub raw_body: Option<String>,
    pub raw_body_hex: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

pub struct Api {
    client: Client,
    base: Url,
    pub label: String,
}

impl Api {
    pub fn new(base: &str, timeout: Duration) -> Result<Self> {
        let mut base = Url::parse(base).context("invalid wallet URL")?;
        ensure!(
            ["http", "https"].contains(&base.scheme()),
            "unsupported wallet URL scheme"
        );
        ensure!(
            base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none(),
            "wallet URL must not contain credentials, query or fragment"
        );
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let client = Client::builder()
            .timeout(timeout)
            .redirect(Policy::none())
            .build()?;
        Ok(Self {
            client,
            label: base.to_string(),
            base,
        })
    }

    pub fn request(&self, req: &Request) -> Result<Response> {
        ensure!(
            req.path.starts_with('/') && !req.path.starts_with("//"),
            "request path must be absolute within the API"
        );
        ensure!(
            usize::from(req.body.is_some())
                + usize::from(req.raw_body.is_some())
                + usize::from(req.raw_body_hex.is_some())
                <= 1,
            "body, raw_body and raw_body_hex are mutually exclusive"
        );
        let url = self.base.join(req.path.trim_start_matches('/'))?;
        ensure!(
            url.origin() == self.base.origin() && url.path().starts_with(self.base.path()),
            "request escaped API base URL"
        );
        let mut builder = self
            .client
            .request(Method::from_bytes(req.method.as_bytes())?, url);
        if !req
            .headers
            .keys()
            .any(|key| key.eq_ignore_ascii_case("accept"))
        {
            builder = builder.header("Accept", "application/json");
        }
        for (k, v) in &req.headers {
            builder = builder.header(k, v);
        }
        if let Some(body) = &req.body {
            builder = builder.json(body);
        }
        if let Some(body) = &req.raw_body {
            if !req
                .headers
                .keys()
                .any(|key| key.eq_ignore_ascii_case("content-type"))
            {
                builder = builder.header("Content-Type", "application/json");
            }
            builder = builder.body(body.clone());
        }
        if let Some(encoded) = &req.raw_body_hex {
            let bytes = hex::decode(encoded).context("invalid hexadecimal request body")?;
            if !req
                .headers
                .keys()
                .any(|key| key.eq_ignore_ascii_case("content-type"))
            {
                builder = builder.header("Content-Type", "application/octet-stream");
            }
            builder = builder.body(bytes);
        }
        let response = builder
            .send()
            .map_err(|_| anyhow!("HTTP transport failure"))?;
        let status = response.status().as_u16();
        let media_type = response
            .headers()
            .get("content-type")
            .and_then(|x| x.to_str().ok())
            .map(|x| x.split(';').next().unwrap_or(x).trim().to_lowercase());
        let raw = response
            .bytes()
            .map_err(|_| anyhow!("failed to read HTTP response"))?
            .to_vec();
        let json = if raw.is_empty()
            || !media_type
                .as_deref()
                .is_some_and(|m| m == "application/json" || m.ends_with("+json"))
        {
            None
        } else {
            serde_json::from_slice(&raw).ok()
        };
        Ok(Response {
            status,
            media_type,
            json,
            raw,
        })
    }

    pub fn checked(
        &self,
        contract: &Contract,
        operation: &str,
        req: Request,
        status: u16,
    ) -> Result<Response> {
        contract.check_path(operation, &req.method, &req.path)?;
        let response = self.request(&req)?;
        ensure!(
            response.status == status,
            "{operation}: expected status {status}, received {}",
            response.status
        );
        contract.validate(operation, &response)?;
        Ok(response)
    }
}

pub fn request(method: &str, path: impl Into<String>, body: Option<Value>) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        body,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_response_substitutions_are_exactly_operation_scoped() {
        let original = Contract::load(include_str!("../fixtures/api/openapi.yaml")).unwrap();
        let mut old: Corrections =
            serde_json::from_str(include_str!("../fixtures/api/haskell-corrections.json")).unwrap();
        // This regression concerns the earlier approved batch, before the later
        // explicit source-stale retirement. Preserve its historical assertions.
        old.corrections
            .retain(|c| !c.id.starts_with("reviewed-source-stale-"));
        let earlier = json!({"format_version":old.format_version,"source_sha256":old.source_sha256,"corrections":old.corrections.iter().map(|c|json!({"id":c.id,"before":c.before,"after":c.after})).collect::<Vec<_>>()});
        let actual = Contract::load(
            &corrected_source(
                include_str!("../fixtures/api/openapi.yaml"),
                &earlier.to_string(),
            )
            .unwrap(),
        )
        .unwrap();
        let without_batch = Corrections {
            format_version: old.format_version,
            source_sha256: old.source_sha256,
            corrections: old
                .corrections
                .into_iter()
                .filter(|c| {
                    ![
                        "haskell-owned-vote-certificate",
                        "shared-decode-observed-todo",
                        "unreachable-submission-mempool-full",
                    ]
                    .contains(&c.id.as_str())
                })
                .collect(),
        };
        // Compare against the complete previous overlay, rather than the original's older known defects.
        let manifest = json!({"format_version":without_batch.format_version,"source_sha256":without_batch.source_sha256,"corrections":without_batch.corrections.iter().map(|c| json!({"id":c.id,"before":c.before,"after":c.after})).collect::<Vec<_>>()});
        let previous = Contract::load(
            &corrected_source(
                include_str!("../fixtures/api/openapi.yaml"),
                &manifest.to_string(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut changed = Vec::new();
        for (id, op) in &actual.operations {
            if previous.operations[id].statuses != op.statuses {
                changed.push(id.as_str());
            }
        }
        assert_eq!(
            changed,
            [
                "decodeSharedTransaction",
                "postByronTransaction",
                "postExternalTransaction",
                "postTransaction"
            ]
        );
        for op in [
            "postByronTransaction",
            "postExternalTransaction",
            "postTransaction",
        ] {
            assert!(original.operations[op].statuses.contains(&425));
            assert!(!actual.operations[op].statuses.contains(&425));
            assert!(actual.operations[op].statuses.contains(&500));
            let mut r = Response {
                status: 500,
                media_type: Some("application/json".into()),
                json: Some(
                    json!({"code":"created_invalid_transaction","message":"node rejection"}),
                ),
                raw: vec![],
            };
            actual.validate(op, &r).unwrap();
            r.json.as_mut().unwrap()["code"] = json!("mempool_is_full");
            assert!(actual.validate(op, &r).is_err());
        }
        let mut r = Response {
            status: 500,
            media_type: Some("text/plain".into()),
            json: None,
            raw: b"Something went wrong".to_vec(),
        };
        actual.validate("decodeSharedTransaction", &r).unwrap();
        assert!(actual.validate("decodeTransaction", &r).is_err());
        r.raw.push(b'!');
        assert!(actual.validate("decodeSharedTransaction", &r).is_err());
        r.raw = vec![255];
        assert!(actual.validate("decodeSharedTransaction", &r).is_err());
        let mut schema = actual.document.clone();
        schema["$ref"] = json!("#/x-certificate");
        let validator = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft7)
            .build(&schema)
            .unwrap();
        let good = json!({"certificate_type":"cast_vote","reward_account_path":["1852H","1815H","0H","2","0"],"vote":"abstain"});
        assert!(validator.is_valid(&good));
        for pointer in ["/vote", "/reward_account_path", "/certificate_type"] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("invented");
            assert!(!validator.is_valid(&bad));
        }
        let mut missing = good;
        missing.as_object_mut().unwrap().remove("vote");
        assert!(!validator.is_valid(&missing));
        let count = |c: &Contract, include500: bool| -> usize {
            c.operations
                .values()
                .map(|op| {
                    1 + usize::from(
                        op.statuses
                            .iter()
                            .any(|s| (400..=if include500 { 500 } else { 499 }).contains(s)),
                    ) + op
                        .statuses
                        .iter()
                        .filter(|s| (200..=if include500 { 500 } else { 499 }).contains(*s))
                        .count()
                })
                .sum()
        };
        assert_eq!(count(&previous, false) + 1, count(&actual, true));
        assert!(original.operations["postSharedWallet"]
            .statuses
            .contains(&500));
        assert_eq!(
            original.operations["postSharedWallet"].statuses,
            actual.operations["postSharedWallet"].statuses
        );
        let shared_error = Response {
            status: 500,
            media_type: Some("application/json".into()),
            json: Some(json!({"code":"missing_reward_account","message":"missing reward account"})),
            raw: vec![],
        };
        actual.validate("postSharedWallet", &shared_error).unwrap();
    }

    #[test]
    fn reviewed_retirements_remove_only_three_responses_and_preserve_original() {
        let original = include_str!("../fixtures/api/openapi.yaml");
        let registry: Value =
            serde_json::from_str(include_str!("../fixtures/api/retired-responses.json")).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(original.as_bytes())),
            registry["original_openapi_sha256"]
        );
        let mut prior: Value =
            serde_json::from_str(include_str!("../fixtures/api/haskell-corrections.json")).unwrap();
        prior["corrections"].as_array_mut().unwrap().retain(|c| {
            !c["id"]
                .as_str()
                .unwrap()
                .starts_with("reviewed-source-stale-")
        });
        let before =
            Contract::load(&corrected_source(original, &prior.to_string()).unwrap()).unwrap();
        let after = Contract::pinned().unwrap();
        let original = Contract::load(original).unwrap();
        let retired = [
            ("postSharedWallet", 500),
            ("patchSharedWalletInPayment", 503),
            ("patchSharedWalletInDelegation", 503),
        ];
        for (name, op) in &before.operations {
            let mut expected = op.statuses.clone();
            for (retired_name, status) in retired {
                if name == retired_name {
                    assert!(original.operations[name].statuses.contains(&status));
                    assert!(expected.contains(&status));
                    expected.retain(|s| *s != status);
                }
            }
            assert_eq!(after.operations[name].statuses, expected, "{name}");
        }
        assert_eq!(before.requirements().len() + 82, 646);
        assert_eq!(after.requirements().len() + 82, 643);
        for (name, status) in retired {
            let response = Response {
                status,
                media_type: Some("application/json".into()),
                json: Some(
                    json!({"code":if status==500 {"missing_reward_account"}else{"wallet_metadata_not_found"},"message":"retired"}),
                ),
                raw: vec![],
            };
            assert!(after.validate(name, &response).is_err());
            assert!(!after
                .requirements()
                .iter()
                .any(|r| r.id == format!("api:{name}:status:{status}")));
        }
    }

    #[test]
    fn inventory_includes_server_errors_above_500_and_negative_only_routes() {
        let contract=Contract::load("openapi: 3.0.0\npaths:\n  /probe:\n    get:\n      operationId: serverFailure\n      responses:\n        501: {description: unimplemented}\n        503: {description: unavailable}\n        599: {description: extension}\n").unwrap();
        let ids: Vec<_> = contract.requirements().into_iter().map(|r| r.id).collect();
        for suffix in [
            "positive",
            "negative",
            "status:501",
            "status:503",
            "status:599",
        ] {
            assert!(ids.contains(&format!("api:serverFailure:{suffix}")));
        }
        assert_eq!(ids.len(), 5);
    }

    #[test]
    fn pre_era_error_requires_actual_haskell_info_fields() {
        let contract = Contract::pinned().unwrap();
        let mut response = Response {
            status: 403,
            media_type: Some("application/json".into()),
            json: Some(
                json!({"code":"node_not_yet_in_recent_era","message":"node era","info":{"node_era":"babbage","supported_recent_eras":["conway"]}}),
            ),
            raw: vec![],
        };
        contract
            .validate("constructTransaction", &response)
            .unwrap();
        response.json.as_mut().unwrap()["info"] =
            json!({"node_era":"babbage","recent_eras":["conway"]});
        assert!(contract
            .validate("constructTransaction", &response)
            .is_err());
        response.json.as_mut().unwrap()["info"] =
            json!({"node_era":"invented","supported_recent_eras":["conway"]});
        assert!(contract
            .validate("constructTransaction", &response)
            .is_err());
    }

    #[test]
    fn delegation_status_requires_the_actual_haskell_constructor_spelling() {
        let contract = Contract::pinned().unwrap();
        let mut schema = contract.document.clone();
        schema["$ref"] = json!("#/x-delegationStatus");
        let validator = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft7)
            .build(&schema)
            .unwrap();
        for status in [
            "not_delegating",
            "delegating",
            "voting",
            "voting_and_delegating",
        ] {
            assert!(validator.is_valid(&json!(status)));
        }
        for status in ["delegating_and_voting", "unknown", ""] {
            assert!(!validator.is_valid(&json!(status)));
        }
    }

    #[test]
    fn behavioral_corrections_preserve_owned_union_constraints() {
        let contract = Contract::pinned().unwrap();
        for anchor in ["x-transactionInputsGeneral", "x-transactionOutputsGeneral"] {
            let mut schema = contract.document.clone();
            schema["$ref"] = json!(format!("#/{anchor}"));
            let validator = jsonschema::options()
                .with_draft(jsonschema::Draft::Draft7)
                .build(&schema)
                .unwrap();
            let mut item = json!({
                "id":"00".repeat(32), "index":0, "address":"addr_test1example",
                "amount":{"quantity":2000000,"unit":"lovelace"},
                "derivation_path":["1852H","1815H","0H","0","0"]
            });
            assert!(validator.is_valid(&json!([item])));
            item["derivation_path"] = json!([]);
            assert!(!validator.is_valid(&json!([item])));
            item.as_object_mut().unwrap().remove("derivation_path");
            assert!(validator.is_valid(&json!([item])));
            item["index"] = json!(-1);
            item["amount"]["quantity"] = json!(-1);
            assert!(!validator.is_valid(&json!([item])));
        }
        let mut error = Response {
            status: 400,
            media_type: Some("application/json".into()),
            json: Some(json!({"code":"bad_request","message":"invalid input"})),
            raw: vec![],
        };
        for operation in [
            "listTransactions",
            "listByronTransactions",
            "listSharedTransactions",
            "listStakePools",
        ] {
            contract.validate(operation, &error).unwrap();
        }
        error.json = Some(json!({"code":"invented_error","message":"invalid input"}));
        assert!(contract.validate("listStakePools", &error).is_err());
        assert!(contract
            .operation("submitTransaction")
            .unwrap()
            .statuses
            .contains(&403));
        assert!(!contract
            .operation("postExternalTransaction")
            .unwrap()
            .statuses
            .contains(&403));
    }

    #[test]
    fn corrections_reject_source_drift_and_ambiguous_edits() {
        let source = include_str!("../fixtures/api/openapi.yaml");
        let manifest = include_str!("../fixtures/api/haskell-corrections.json");
        assert!(corrected_source(&format!("{source}\n"), manifest).is_err());
        let mut manifest: Value = serde_json::from_str(manifest).unwrap();
        manifest["corrections"][0]["before"] = json!("type: object");
        assert!(corrected_source(source, &manifest.to_string()).is_err());
    }
}
