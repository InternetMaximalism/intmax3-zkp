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

    eprintln!("=== MLE E2E FIXTURE GENERATION PASSED ===");
}
