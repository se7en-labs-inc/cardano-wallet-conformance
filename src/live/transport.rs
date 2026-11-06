//! Exact public error envelopes from the pinned Haskell HTTP error handler.
use super::*;

fn expected(status: u16) -> Value {
    let (code, message) = match status {
        400 => ("bad_request", "Unexpected end-of-input, expecting record key literal or }"),
        404 => ("not_found", "I couldn't find the requested endpoint. If the endpoint contains path parameters, please ensure they are well-formed, otherwise I won't be able to route them correctly."),
        405 => ("method_not_allowed", "You've reached a known endpoint but I don't know how to handle the HTTP method specified. Please double-check both the endpoint and the method: one of them is likely to be incorrect (for example: POST instead of PUT, or GET instead of POST...)."),
        406 => ("not_acceptable", "It seems as though you don't accept 'application/json', but unfortunately I only speak 'application/json'! Please double-check your 'Accept' request header and make sure it's set to 'application/json'."),
        415 => ("unsupported_media_type", "I'm really sorry but I only understand 'application/json'. I need you to tell me what language you're speaking in order for me to understand your message. Please double-check your 'Content-Type' request header and make sure it's set to 'application/json'."),
        _ => unreachable!("immutable transport status"),
    };
    json!({"code":code,"message":message})
}

fn validate(response: &Response, status: u16) -> Result<()> {
    ensure!(response.status == status, "unexpected transport status");
    ensure!(
        response.media_type.as_deref() == Some("application/json"),
        "unexpected transport media"
    );
    ensure!(
        response.json.as_ref() == Some(&expected(status)),
        "transport error differs from pinned Haskell envelope"
    );
    Ok(())
}

fn requirement(case: &str) -> &'static str {
    if case.starts_with("transport:") {
        "api.transport-errors"
    } else {
        "api.error-precedence"
    }
}

impl Session<'_> {
    pub(super) fn exercise_transport(&mut self) {
        for (case, method, path, raw, header, status, operation) in [
            (
                "transport:unknown-method",
                "OPTIONS",
                "/wallets",
                None,
                None,
                405,
                None,
            ),
            (
                "transport:unknown-path",
                "GET",
                "/conformance-unknown-endpoint",
                None,
                None,
                404,
                None,
            ),
            (
                "transport:malformed-json",
                "POST",
                "/wallets",
                Some("{"),
                None,
                400,
                Some("postWallet"),
            ),
            (
                "transport:unsupported-content-type",
                "POST",
                "/wallets",
                Some("{}"),
                Some(("Content-Type", "text/plain")),
                415,
                Some("postWallet"),
            ),
            (
                "transport:unsupported-accept",
                "GET",
                "/wallets",
                None,
                Some(("Accept", "text/plain")),
                406,
                Some("listWallets"),
            ),
            (
                "precedence:media-body",
                "POST",
                "/wallets",
                Some("{"),
                Some(("Content-Type", "text/plain")),
                415,
                Some("postWallet"),
            ),
        ] {
            let result = (|| -> Result<()> {
                let mut req = request(method, path, None);
                req.raw_body = raw.map(str::to_owned);
                if let Some((name, value)) = header {
                    req.headers.insert(name.into(), value.into());
                }
                if let Some(op) = operation {
                    self.contract.check_path(op, method, path)?;
                }
                let response = self.api.request(&req)?;
                validate(&response, status)?;
                if let Some(op) = operation {
                    self.contract.validate(op, &response)?;
                }
                Ok(())
            })();
            self.report
                .record(case, &[requirement(case).into()], result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_records_close_only_complete_catalogue_groups() {
        let catalogue: std::collections::BTreeMap<String, Vec<String>> =
            serde_json::from_str(include_str!("../../fixtures/semantic-obligations.json")).unwrap();
        let requirements: Vec<crate::report::Requirement> =
            serde_json::from_str(include_str!("../../fixtures/requirements.json")).unwrap();
        let mut selected: Vec<_> = requirements
            .into_iter()
            .filter(|r| ["api.transport-errors", "api.error-precedence"].contains(&r.id.as_str()))
            .collect();
        for r in &mut selected {
            r.required_cases = catalogue[&r.id].clone();
        }
        let mut report = Report::new("binding-regression", "self-test");
        for case in &catalogue["api.transport-errors"] {
            report.record(case, &[requirement(case).into()], Ok(()));
        }
        report.record(
            "precedence:media-body",
            &[requirement("precedence:media-body").into()],
            Ok(()),
        );
        let coverage = crate::report::coverage(&selected, &[report]).unwrap();
        assert_eq!(coverage.covered, 1);
        assert_eq!(coverage.missing, ["api.error-precedence"]);
        let mut report = Report::new("binding-regression", "self-test");
        for case in catalogue["api.transport-errors"].iter().skip(1) {
            report.record(case, &[requirement(case).into()], Ok(()));
        }
        assert_eq!(
            crate::report::coverage(&selected, &[report])
                .unwrap()
                .covered,
            0
        );
    }

    #[test]
    fn malformed_json_requires_the_observed_parser_branch() {
        let mut response = Response {
            status: 400,
            media_type: Some("application/json".into()),
            json: Some(expected(400)),
            raw: vec![],
        };
        assert!(validate(&response, 400).is_ok());
        response.json.as_mut().unwrap()["message"] = json!("I couldn't understand the content of your message. If your message is intended to be in JSON format, please check that the JSON is valid.");
        assert!(validate(&response, 400).is_err());
    }

    #[test]
    fn exact_transport_envelope_rejects_wrong_priority_and_extra_fields() {
        let mut response = Response {
            status: 415,
            media_type: Some("application/json".into()),
            json: Some(expected(415)),
            raw: vec![],
        };
        assert!(validate(&response, 415).is_ok());
        response.json = Some(expected(400));
        assert!(validate(&response, 415).is_err());
        response.json = Some(expected(415));
        response.json.as_mut().unwrap()["extra"] = json!(true);
        assert!(validate(&response, 415).is_err());
        response.json = Some(expected(415));
        response.media_type = Some("text/plain".into());
        assert!(validate(&response, 415).is_err());
    }
}
