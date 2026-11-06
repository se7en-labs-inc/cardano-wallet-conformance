//! Actual wallet collateral selection and independent conservation/eligibility laws.
use crate::adapter::{self, Vector};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};
const ORACLE: &str = "08406fef161c9722fe5407774133e10708cfdea5273ba4fe32b96475b406871e";
fn uint(v: &Value, field: &str) -> Result<u128> {
    Ok(u128::from(
        v[field].as_u64().context("missing u64 selection value")?,
    ))
}
fn sum(values: &[Value], field: &str) -> Result<u128> {
    values.iter().try_fold(0, |n, v| Ok(n + uint(v, field)?))
}
pub fn validate(vector: &Vector, actual: &Value) -> Result<()> {
    let input = &vector.input;
    let utxos = input["utxos"].as_array().context("missing UTxOs")?;
    let known = utxos
        .iter()
        .map(|u| Ok((uint(u, "id")?, u)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(known.len() == utxos.len(), "duplicate input fixture ID");
    let chosen = |ids: &Value, field: &str| -> Result<Vec<Value>> {
        let ids = ids.as_array().context("missing selection IDs")?;
        let mut seen = BTreeSet::new();
        ids.iter()
            .map(|id| {
                let id = u128::from(id.as_u64().context("invalid selected ID")?);
                ensure!(seen.insert(id), "duplicate selected ID");
                let u = *known.get(&id).context("unknown selected UTxO")?;
                ensure!(u[field] == true, "selected unavailable UTxO");
                if field == "collateral" {
                    ensure!(
                        uint(u, "asset_quantity")? == 0,
                        "selected native-asset collateral"
                    );
                }
                Ok(u.clone())
            })
            .collect()
    };
    let cap = uint(input, "maximum_collateral_inputs")?;
    let percentage = uint(input, "collateral_percentage")?;
    let minimum_fee = uint(input, "minimum_fee")?;
    if let Some(error) = actual.get("error") {
        match error["code"].as_str().context("missing selection error")? {
            "insufficient_collateral" => {
                let largest = chosen(&error["largest_available"], "collateral")?;
                let minimum = uint(error, "minimum_collateral")?;
                ensure!(
                    input["collateral_required"] == true
                        && largest.len() as u128 <= cap
                        && minimum > sum(&largest, "coin")?
                        && minimum >= (minimum_fee * percentage).div_ceil(100),
                    "invalid insufficient-collateral evidence"
                );
                if uint(input, "minimum_change_coin")? == 0 {
                    ensure!(
                        minimum == (minimum_fee * percentage).div_ceil(100),
                        "collateral requirement rounding differs from constant-fee profile"
                    );
                }
            }
            "empty_utxo" => ensure!(
                !utxos.iter().any(|u| u["inputs"] == true),
                "nonempty ordinary UTxO misclassified empty"
            ),
            "balance_insufficient" => {
                let available = utxos
                    .iter()
                    .filter(|u| u["inputs"] == true)
                    .cloned()
                    .collect::<Vec<_>>();
                let outputs = input["outputs"].as_array().context("missing outputs")?;
                ensure!(
                    sum(&available, "coin")? < sum(outputs, "coin")? + minimum_fee
                        || sum(&available, "asset_quantity")? + uint(input, "mint_quantity")?
                            < sum(outputs, "asset_quantity")? + uint(input, "burn_quantity")?,
                    "sufficient value misclassified insufficient"
                );
            }
            "unable_to_construct_change" => {
                let available = utxos
                    .iter()
                    .filter(|u| u["inputs"] == true)
                    .cloned()
                    .collect::<Vec<_>>();
                let outputs = input["outputs"].as_array().context("missing outputs")?;
                ensure!(
                    sum(&available, "coin")? >= sum(outputs, "coin")?
                        && sum(&available, "coin")? < sum(outputs, "coin")? + minimum_fee,
                    "fee-shortfall profile has no independent shortage"
                );
            }
            _ => anyhow::bail!("unexpected selection profile error"),
        }
        return Ok(());
    }
    let result = actual.get("result").context("missing selection result")?;
    let selected = chosen(&result["inputs"], "inputs")?;
    ensure!(!selected.is_empty(), "selection has no ordinary inputs");
    let collateral = chosen(&result["collateral"], "collateral")?;
    ensure!(
        collateral.len() as u128 <= cap,
        "collateral input cap exceeded"
    );
    let fee = uint(result, "fee")?;
    ensure!(fee >= minimum_fee, "fee below minimum");
    let outputs = result["outputs"]
        .as_array()
        .context("missing selected outputs")?;
    let change = result["change"].as_array().context("missing change")?;
    ensure!(
        result["outputs"] == input["outputs"],
        "selection changed user outputs"
    );
    ensure!(
        sum(&selected, "coin")? == sum(outputs, "coin")? + sum(change, "coin")? + fee,
        "ADA selection conservation failed"
    );
    ensure!(
        sum(&selected, "asset_quantity")? + uint(input, "mint_quantity")?
            == sum(outputs, "asset_quantity")?
                + sum(change, "asset_quantity")?
                + uint(input, "burn_quantity")?,
        "mint/burn asset conservation failed"
    );
    for c in change {
        ensure!(
            uint(c, "coin")? >= uint(input, "minimum_change_coin")?,
            "change below minimum"
        );
    }
    if uint(input, "minimum_change_coin")? == 0 {
        ensure!(
            fee == minimum_fee,
            "zero-minimum change unexpectedly became excess fee"
        );
    }
    if input["collateral_required"] == true {
        ensure!(
            sum(&collateral, "coin")? >= (fee * percentage).div_ceil(100),
            "collateral percentage/rounding violated"
        );
    } else {
        ensure!(
            collateral.is_empty(),
            "collateral selected when not required"
        );
    }
    Ok(())
}
pub fn capture(binary: &Path) -> Result<Vec<Vector>> {
    ensure!(
        hex::encode(Sha256::digest(std::fs::read(binary)?)) == ORACLE,
        "wallet selection adapter differs from pinned oracle"
    );
    let base = json!({"utxos":[{"id":1,"coin":10000000,"asset_quantity":0,"inputs":true,"collateral":false},{"id":2,"coin":300002,"asset_quantity":0,"inputs":false,"collateral":true}],"outputs":[{"coin":1000000,"asset_quantity":0}],"minimum_fee":200001,"minimum_change_coin":0,"maximum_collateral_inputs":1,"collateral_percentage":150,"collateral_required":true,"mint_quantity":0,"burn_quantity":0,"seed":0,"strategy":"minimal"});
    let mut requests = Vec::new();
    let mut add = |id: &str, requirement: &str, input: Value, error: Option<&str>| {
        requests.push((
            id.to_owned(),
            requirement.to_owned(),
            input,
            error.map(str::to_owned),
        ));
    };
    add(
        "collateral-percentage-rounding",
        "tx.collateral",
        base.clone(),
        None,
    );
    let mut ineligible = base.clone();
    ineligible["utxos"].as_array_mut().unwrap().extend([
        json!({"id":3,"coin":1000000000,"asset_quantity":1,"inputs":false,"collateral":true}),
        json!({"id":4,"coin":1000000000,"asset_quantity":0,"inputs":false,"collateral":false}),
    ]);
    add("collateral-eligibility", "tx.collateral", ineligible, None);
    let mut insufficient = base.clone();
    insufficient["utxos"][1]["coin"] = json!(300001);
    add(
        "collateral-insufficient",
        "tx.collateral",
        insufficient.clone(),
        Some("insufficient_collateral"),
    );
    add(
        "selection-insufficient-collateral",
        "selection.insufficient-funds",
        insufficient,
        Some("insufficient_collateral"),
    );
    let mut zero = base.clone();
    zero["maximum_collateral_inputs"] = json!(0);
    add(
        "collateral-zero-cap",
        "tx.collateral",
        zero,
        Some("insufficient_collateral"),
    );
    let mut split = base.clone();
    split["utxos"][1]["coin"] = json!(150001);
    split["utxos"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":3,"coin":150001,"asset_quantity":0,"inputs":false,"collateral":true}));
    add(
        "collateral-one-input-limit",
        "tx.collateral",
        split.clone(),
        Some("insufficient_collateral"),
    );
    split["maximum_collateral_inputs"] = json!(2);
    add(
        "collateral-two-input-boundary",
        "tx.collateral",
        split,
        None,
    );
    let mut overlap = base.clone();
    overlap["utxos"].as_array_mut().unwrap().pop();
    overlap["utxos"][0]["collateral"] = json!(true);
    add(
        "collateral-overlap-ordinary-input",
        "tx.collateral",
        overlap,
        None,
    );
    let mut optional = base.clone();
    optional["collateral_required"] = json!(false);
    optional["maximum_collateral_inputs"] = json!(0);
    add("collateral-not-required", "tx.collateral", optional, None);
    for (id, percentage) in [
        ("collateral-percent-zero", 0),
        ("collateral-percent-one", 1),
        ("collateral-percent-100", 100),
        ("collateral-percent-200", 200),
    ] {
        let mut input = base.clone();
        input["collateral_percentage"] = json!(percentage);
        input["utxos"][1]["coin"] = json!(1000000);
        add(id, "tx.collateral", input, None);
    }
    for seed in [1, u64::MAX] {
        let mut input = base.clone();
        input["seed"] = json!(seed);
        add(
            &format!("collateral-seed-{seed}"),
            "tx.collateral",
            input,
            None,
        );
    }
    let mut optimal = base.clone();
    optimal["strategy"] = json!("optimal");
    add(
        "collateral-optimal-strategy",
        "tx.collateral",
        optimal,
        None,
    );
    for quantity in [
        0,
        1,
        23,
        24,
        u64::from(u32::MAX),
        i64::MAX as u64,
        (i64::MAX as u64) + 1,
    ] {
        let mut mint = base.clone();
        mint["mint_quantity"] = json!(quantity);
        mint["outputs"][0]["asset_quantity"] = json!(quantity / 2);
        let id = if quantity == i64::MAX as u64 {
            "mint-burn-quantity-boundaries".to_owned()
        } else {
            format!("wallet-mint-quantity-{quantity}")
        };
        add(&id, "tx.mint-burn", mint, None);
        let mut burn = base.clone();
        burn["burn_quantity"] = json!(quantity);
        burn["utxos"][0]["asset_quantity"] = json!(quantity);
        add(
            &format!("wallet-burn-quantity-{quantity}"),
            "tx.mint-burn",
            burn,
            None,
        );
    }
    let mut empty = base.clone();
    empty["utxos"][0]["inputs"] = json!(false);
    add(
        "wallet-selection-empty-with-payment",
        "selection.insufficient-funds",
        empty.clone(),
        Some("balance_insufficient"),
    );
    empty["outputs"] = json!([]);
    empty["minimum_fee"] = json!(0);
    empty["collateral_required"] = json!(false);
    add(
        "wallet-selection-empty",
        "selection.insufficient-funds",
        empty,
        Some("empty_utxo"),
    );
    let mut small = base;
    small["utxos"][0]["coin"] = json!(900000);
    add(
        "wallet-selection-insufficient-output",
        "selection.insufficient-funds",
        small.clone(),
        Some("balance_insufficient"),
    );
    small["utxos"][0]["coin"] = json!(1000000);
    add(
        "wallet-selection-insufficient-fee",
        "selection.insufficient-funds",
        small,
        Some("unable_to_construct_change"),
    );
    let mut vectors = Vec::new();
    for (id, requirement, input, error) in requests {
        let mut vector=Vector{id:id.clone(),requirements:vec![requirement],source:format!("Wallet2fc5c383 actual cardano-balance-tx8975773 wallet performSelection/asCollateral with declared constant-cost callbacks and seeded MonadRandom; SelectionAdapter binary sha256:{ORACLE}; independent Rust conservation/eligibility/cap/ceil laws"),operation:"selection.wallet".into(),input,expected:None,selection_invariants:false};
        let actual = adapter::invoke(binary, &[], &vector, Duration::from_secs(30))?;
        ensure!(
            actual == adapter::invoke(binary, &[], &vector, Duration::from_secs(30))?,
            "wallet selection replay differs: {id}"
        );
        match error {
            Some(code) => ensure!(
                actual["error"]["code"] == code,
                "selection error differs: {id}"
            ),
            None => ensure!(
                actual.get("result").is_some(),
                "valid wallet selection rejected: {id}"
            ),
        }
        validate(&vector, &actual).with_context(|| format!("wallet selection law failed: {id}"))?;
        vector.expected = Some(actual);
        vectors.push(vector);
    }
    Ok(vectors)
}
