use anyhow::{Context, Result};
use num_bigint::BigUint;
use serde_json::Value;
use std::{env, fs};

fn limbs_from_decimal(s: &str) -> [u64; 4] {
    let mut value = BigUint::parse_bytes(s.as_bytes(), 10).expect("invalid decimal");
    let base = BigUint::from(1u128 << 64);
    let mut limbs = [0u64; 4];
    for limb in limbs.iter_mut() {
        let rem = (&value % &base).to_u64_digits();
        *limb = rem.get(0).copied().unwrap_or(0);
        value /= &base;
    }
    limbs
}

fn main() -> Result<()> {
    let path = env::args().nth(1).expect("usage: analyze_hashout <path>");
    let contents = fs::read_to_string(path).context("read json")?;
    let json: Value = serde_json::from_str(&contents).context("parse json")?;
    let entries = json["proof"]["wires_cap"].as_array().expect("wires_cap array");
    for (idx, entry) in entries.iter().take(3).enumerate() {
        if let Some(dec) = entry.as_str() {
            let limbs = limbs_from_decimal(dec);
            println!("wires_cap[{idx}] -> {:?}", limbs);
        }
    }
    Ok(())
}
