//! End-to-end test: validity proof → 2x WrapperCircuit → MLE → on-chain verification
//!
//! Run with:
//!   cargo test --test mle_onchain_e2e --release -- --nocapture
//!
//! This test:
//! 1. Generates a Plonky2 validity proof
//! 2. Wraps it 2x with WrapperCircuit (PoseidonBN128)
//! 3. Generates MLE proof via plonky2_mle
//! 4. Exports MLE fixture data as JSON
//! 5. Runs Forge tests that verify on-chain via MleVerifier

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
    eprintln!("Pipeline: validity proof → 2x WrapperCircuit → MLE → on-chain verify");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 1: Generate all fixtures via Rust
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 1: Generate fixtures (validity proof → 2x wrapper → MLE)");

    let generator = repo_root().join("target/release/generate_e2e_fixture");
    if !generator.exists() {
        eprintln!("[e2e] Building generate_e2e_fixture...");
        let mut build_cmd = Command::new("cargo");
        build_cmd
            .current_dir(repo_root())
            .arg("build")
            .arg("--bin")
            .arg("generate_e2e_fixture")
            .arg("--release");
        run_checked(&mut build_cmd, "cargo build generate_e2e_fixture");
    }

    let mut gen_cmd = Command::new(&generator);
    gen_cmd.current_dir(repo_root());
    run_checked(&mut gen_cmd, "generate_e2e_fixture");

    // Verify fixture was created
    let fixture_path = contracts_dir().join("test/data/mle_fixture.json");
    assert!(fixture_path.exists(), "mle_fixture.json not generated");
    eprintln!("[e2e] Fixtures generated successfully");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 2: ACTUALLY verify the freshly generated fixture on-chain via Forge.
    //
    // B-1: previously this test asserted only that mle_fixture.json EXISTS, so a broken MLE proof
    // in the fixture would still pass — the docstring's "verify on-chain via MleVerifier" was a
    // lie. We now drive the real Solidity `MleVerifier` against the just-generated fixture: a
    // corrupted or unsound proof makes `forge test` exit non-zero, which `run_checked` turns
    // into a panic (=this test fails). `MleFinalizeE2ETest` additionally drives the full
    // postBlock→finalize path with MLE verification ON, so the fixture is exercised through the
    // production finalize entry point.
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 2: on-chain verification via Forge (MleVerifier)");

    let forge_available = Command::new("forge")
        .arg("--version")
        .current_dir(contracts_dir())
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !forge_available {
        // EXPLICIT skip (never a silent green): on-chain verification did NOT run. This only fires
        // when Foundry is genuinely absent — install it to exercise the real verifier.
        eprintln!(
            "[e2e] WARNING: `forge` not found — SKIPPING on-chain MleVerifier verification. \
             This is NOT a pass of the on-chain verifier; install Foundry to run the real check."
        );
        return;
    }

    let mut forge_cmd = Command::new("forge");
    forge_cmd
        .current_dir(contracts_dir())
        .arg("test")
        .arg("--match-contract")
        .arg("MleE2ETest|MleFinalizeE2ETest")
        .arg("-vv");
    run_checked(
        &mut forge_cmd,
        "forge test MleE2ETest|MleFinalizeE2ETest (real on-chain MleVerifier)",
    );

    eprintln!("=== MLE ON-CHAIN VERIFICATION PASSED (real MleVerifier) ===");
}
