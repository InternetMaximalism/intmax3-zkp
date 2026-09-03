//! End-to-end test: validity proof → WrapperCircuit → MLE/WHIR v2 → on-chain verification
//!
//! Run with:
//!   cargo test --test mle_onchain_e2e --release -- --nocapture
//!
//! This test:
//! 1. Generates a Plonky2 validity proof
//! 2. Wraps it 2x with WrapperCircuit (PoseidonBN128)
//! 3. Generates a canonical compact MLE/WHIR v2 proof via plonky2_mle
//! 4. Exports the strict v2 fixture and proof-free deployment configuration
//! 5. Runs Forge tests that verify the compact bytes via the pinned v2 adapter

use std::{path::PathBuf, process::Command};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn contracts_dir() -> PathBuf {
    repo_root().join("contracts")
}

fn run_checked(cmd: &mut Command, label: &str) {
    eprintln!("[e2e] Running: {label}");
    let output = cmd.output().unwrap_or_else(|err| {
        panic!("{label} failed to start: {err}");
    });

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        panic!(
            "{label} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        );
    }
    for line in stderr.lines() {
        if line.starts_with("[e2e]") {
            eprintln!("  {line}");
        }
    }
    for line in stdout.lines() {
        if line.contains("PASS") || line.contains("FAIL") || line.contains("gas:") {
            eprintln!("  {line}");
        }
    }
}

#[cfg_attr(debug_assertions, ignore = "run with --release")]
#[test]
fn validity_proof_mle_onchain_e2e() {
    eprintln!("=== MLE On-chain E2E Test ===");
    eprintln!("Pipeline: validity proof → WrapperCircuit → MLE/WHIR v2 → on-chain verify");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 1: Generate all fixtures via Rust
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 1: Generate fixtures (validity proof → wrapper → MLE/WHIR v2)");

    // Always let Cargo freshness-check the generator and its cryptographic dependencies. Running
    // an already-present target/release binary directly could silently exercise an older protocol
    // after a source or lockfile change.
    let mut gen_cmd = Command::new("cargo");
    gen_cmd
        .current_dir(repo_root())
        .arg("run")
        .arg("--release")
        .arg("--locked")
        .arg("--offline")
        .arg("--bin")
        .arg("generate_e2e_fixture");
    run_checked(
        &mut gen_cmd,
        "cargo run --release --locked --offline generate_e2e_fixture",
    );

    // Verify fixture was created
    let fixture_path = contracts_dir().join("test/data/mle_fixture.json");
    assert!(fixture_path.exists(), "mle_fixture.json not generated");
    eprintln!("[e2e] Fixtures generated successfully");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 2: ACTUALLY verify the freshly generated fixture on-chain via Forge.
    //
    // B-1: previously this test asserted only that mle_fixture.json existed. We now drive the real
    // pinned Solidity v2 adapter against the just-generated compact bytes: a corrupted proof makes
    // `forge test` exit non-zero, which `run_checked` turns into a test failure.
    // `MleFinalizeE2ETest` additionally drives postBlock→finalize with verification enabled.
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 2: on-chain verification via Forge (pinned MleVerifierV2)");

    let forge_available = Command::new("forge")
        .arg("--version")
        .current_dir(contracts_dir())
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    assert!(
        forge_available,
        "`forge` is required: the release E2E must not pass without on-chain MleVerifierV2 verification"
    );

    let mut forge_cmd = Command::new("forge");
    forge_cmd
        .current_dir(contracts_dir())
        .arg("test")
        .arg("--offline")
        .arg("--match-contract")
        .arg("MleE2ETest|MleFinalizeE2ETest")
        .arg("-vv");
    run_checked(
        &mut forge_cmd,
        "forge test MleE2ETest|MleFinalizeE2ETest (real pinned MleVerifierV2)",
    );

    eprintln!("=== MLE/WHIR V2 ON-CHAIN VERIFICATION PASSED ===");
}
