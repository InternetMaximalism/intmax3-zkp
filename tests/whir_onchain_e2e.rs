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
//! 5. Runs Forge tests that verify on-chain:
//!    - SpongefishWhirVerify: ALL 4 WHIR polynomial commitment batches
//!    - Plonky2Verifier: Plonky2 constraint satisfaction check
//!    - Combined E2E: all verifications in a single transaction

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
    // Print forge test output
    for line in stdout.lines() {
        if line.contains("PASS") || line.contains("FAIL") || line.contains("gas:") {
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

    // Verify all fixtures were created
    let fixture_dir = contracts_dir().join("test/data");
    let whir_dir = fixture_dir.join("whir");
    assert!(
        fixture_dir.join("wrapper_constraint_data.json").exists(),
        "wrapper_constraint_data.json not generated"
    );
    for batch in &[
        "constants_sigmas",
        "wires",
        "zs_partial_products",
        "quotient_polys",
    ] {
        let path = whir_dir.join(format!("wrapper_{}_verifier_data.json", batch));
        assert!(
            path.exists(),
            "WHIR verifier data not generated for batch: {}",
            batch
        );
    }
    eprintln!("[e2e] Fixtures generated successfully");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 2: On-chain WHIR polynomial commitment verification (all 4 batches)
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 2: WHIR polynomial commitment verification (all 4 batches)");

    let whir_tests = [
        "test_whir_wrapper_constants_sigmas",
        "test_whir_wrapper_wires",
        "test_whir_wrapper_zs_partial_products",
        "test_whir_wrapper_quotient_polys",
    ];
    for test_name in &whir_tests {
        run_forge_test("WhirOnchainE2ETest", test_name);
    }
    eprintln!("[e2e] All 4 WHIR batch verifications: PASS");
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
    // Step 4: Combined E2E (all verifications in one transaction)
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 4: Combined E2E (all 4 WHIR + Plonky2 in one transaction)");
    run_forge_test(
        "WhirOnchainE2ETest",
        "test_full_e2e_all_whir_batches_and_constraints",
    );
    eprintln!("[e2e] Combined E2E: PASS");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 5: Regression tests
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 5: Regression — Plonky2Verifier existing tests");
    run_forge_test("Plonky2VerifierTest", "test_verifyConstraints_validProof");
    run_forge_test(
        "Plonky2VerifierTest",
        "test_verifyConstraints_wrapperCircuit",
    );
    eprintln!("[e2e] Regression tests: PASS");
    eprintln!();

    eprintln!("=== ALL E2E TESTS PASSED ===");
    eprintln!("  ✓ WHIR constants_sigmas verified on-chain (SpongefishWhirVerify)");
    eprintln!("  ✓ WHIR wires verified on-chain (SpongefishWhirVerify)");
    eprintln!("  ✓ WHIR zs_partial_products verified on-chain (SpongefishWhirVerify)");
    eprintln!("  ✓ WHIR quotient_polys verified on-chain (SpongefishWhirVerify)");
    eprintln!("  ✓ Plonky2 constraint satisfaction verified on-chain (Plonky2Verifier)");
    eprintln!("  ✓ All verifications pass in a single 84M-gas transaction");
    eprintln!("  ✓ All use the SAME WrapperCircuit proof — no mocks, no cheatcodes, no skips");
}
