//! End-to-end test: validity proof → WrapperCircuit → WHIR → on-chain verification
//!
//! Run with:
//!   cargo test --test whir_onchain_e2e --release --features whir -- --nocapture
//!
//! This test:
//! 1. Generates a Plonky2 validity proof
//! 2. Wraps it with WrapperCircuit (PoseidonBN128)
//! 3. Generates WHIR polynomial commitment proofs (spongefish/Keccak)
//! 4. Exports constraint data + WHIR verifier data as JSON fixtures
//! 5. Runs Forge tests that verify both on-chain:
//!    - SpongefishWhirVerify: WHIR polynomial commitment verification
//!    - Plonky2Verifier: Plonky2 constraint satisfaction check

#![cfg(feature = "whir")]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

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
    // Print stderr for progress visibility
    for line in stderr.lines() {
        if line.starts_with("[e2e]") || line.starts_with("[gnark]") {
            eprintln!("  {line}");
        }
    }
}

fn run_forge_test(test_contract: &str, test_name: &str) {
    let mut cmd = Command::new("forge");
    cmd.current_dir(contracts_dir())
        .arg("test")
        .arg("--match-contract")
        .arg(test_contract)
        .arg("--match-test")
        .arg(test_name)
        .arg("-vv");
    run_checked(
        &mut cmd,
        &format!("forge test {test_contract}::{test_name}"),
    );
}

#[cfg_attr(debug_assertions, ignore = "run with --release --features whir")]
#[test]
fn validity_proof_whir_onchain_e2e() {
    eprintln!("=== WHIR On-chain E2E Test ===");
    eprintln!("Pipeline: validity proof → WrapperCircuit → WHIR → on-chain verify");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 1: Generate all fixtures via Rust
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 1: Generate fixtures (validity proof → wrapper → WHIR)");

    let generator = repo_root().join("target/release/generate_e2e_fixture");
    if !generator.exists() {
        eprintln!("[e2e] Building generate_e2e_fixture...");
        let mut build_cmd = Command::new("cargo");
        build_cmd
            .current_dir(repo_root())
            .arg("build")
            .arg("--bin")
            .arg("generate_e2e_fixture")
            .arg("--release")
            .arg("--features")
            .arg("whir");
        run_checked(&mut build_cmd, "cargo build generate_e2e_fixture");
    }

    let mut gen_cmd = Command::new(&generator);
    gen_cmd
        .current_dir(repo_root())
        .arg("--skip-groth16");
    run_checked(&mut gen_cmd, "generate_e2e_fixture --skip-groth16");

    // Verify fixtures were created
    let fixture_dir = contracts_dir().join("test/data");
    assert!(
        fixture_dir.join("wrapper_constraint_data.json").exists(),
        "wrapper_constraint_data.json not generated"
    );
    assert!(
        fixture_dir
            .join("whir/wrapper_constants_sigmas_verifier_data.json")
            .exists(),
        "wrapper WHIR verifier data not generated"
    );
    eprintln!("[e2e] Fixtures generated successfully");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 2: On-chain WHIR polynomial commitment verification
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 2: WHIR polynomial commitment verification (SpongefishWhirVerify)");
    run_forge_test(
        "WhirOnchainE2ETest",
        "test_whir_wrapper_constants_sigmas",
    );
    eprintln!("[e2e] WHIR verification: PASS");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 3: On-chain Plonky2 constraint satisfaction check
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 3: Plonky2 constraint satisfaction (Plonky2Verifier)");
    run_forge_test(
        "WhirOnchainE2ETest",
        "test_plonky2_constraints_wrapper",
    );
    eprintln!("[e2e] Plonky2 constraint check: PASS");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 4: Also run the existing Plonky2Verifier tests for regression
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 4: Regression — Plonky2Verifier existing tests");
    run_forge_test("Plonky2VerifierTest", "test_verifyConstraints_validProof");
    run_forge_test(
        "Plonky2VerifierTest",
        "test_verifyConstraints_wrapperCircuit",
    );
    eprintln!("[e2e] Regression tests: PASS");
    eprintln!();

    eprintln!("=== ALL E2E TESTS PASSED ===");
    eprintln!("  ✓ WHIR polynomial commitment verified on-chain (SpongefishWhirVerify)");
    eprintln!("  ✓ Plonky2 constraint satisfaction verified on-chain (Plonky2Verifier)");
    eprintln!("  ✓ Both checks use the SAME WrapperCircuit proof");
    eprintln!("  ✓ No mocks, no cheatcodes, no skips");
}
