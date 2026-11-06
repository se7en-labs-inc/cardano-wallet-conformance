//! Standard-profile normalization boundary; cryptographic outputs come from Haskell.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};
use unicode_normalization::UnicodeNormalization;
use wallet_conformance::adapter::{invoke, Vector};

fn normalize(operation: &mut String, input: &mut Value) -> Result<()> {
    if operation == "bip39.to-seed" {
        for field in ["mnemonic", "passphrase"] {
            let text = input[field]
                .as_str()
                .context("missing standard seed input")?;
            input[field] = json!(text.nfkd().collect::<String>());
        }
        *operation = "bip39.wallet-seed".into();
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let oracle = PathBuf::from(args.next().context("Haskell oracle path required")?);
    ensure!(args.next().is_none(), "expected exactly one oracle path");
    let mut raw = Vec::new();
    std::io::stdin().take(1_048_577).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 1_048_576, "reference input exceeds limit");
    let request: Value = serde_json::from_slice(&raw)?;
    ensure!(
        request["protocol_version"] == 1,
        "unsupported protocol version"
    );
    let id = request["id"].as_str().context("missing request ID")?;
    let mut operation = request["operation"]
        .as_str()
        .context("missing operation")?
        .to_owned();
    let mut input = request["input"].clone();
    normalize(&mut operation, &mut input)?;
    let vector = Vector {
        id: id.into(),
        operation,
        input,
        requirements: vec![],
        source: String::new(),
        expected: None,
        selection_invariants: false,
    };
    let result = invoke(&oracle, &[], &vector, Duration::from_secs(30));
    let mut response = json!({"protocol_version":1,"id":id});
    match result {
        Ok(result) => {
            let object = result.as_object().context("invalid oracle envelope")?;
            for (field, value) in object {
                response[field] = value.clone();
            }
        }
        Err(_) => response["error"] = json!({"code":"internal_error"}),
    }
    std::io::stdout().write_all(&serde_json::to_vec(&response)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalization_is_limited_to_the_standard_profile() {
        for original in [
            "bip39.to-seed",
            "bip39.wallet-seed",
            "keys.generate-root-profile",
        ] {
            let mut operation = original.to_owned();
            let before =
                json!({"mnemonic":"abandon", "passphrase":"é", "encryption_passphrase_utf8":"é"});
            let mut input = before.clone();
            normalize(&mut operation, &mut input).unwrap();
            if original == "bip39.to-seed" {
                assert_eq!(operation, "bip39.wallet-seed");
                assert_eq!(input["passphrase"], "e\u{301}");
                assert_eq!(
                    input["encryption_passphrase_utf8"],
                    before["encryption_passphrase_utf8"]
                );
            } else {
                assert_eq!(operation, original);
                assert_eq!(input, before);
            }
        }
    }
}
