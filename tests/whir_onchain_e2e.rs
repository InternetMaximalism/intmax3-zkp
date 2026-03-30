#![cfg(feature = "whir")]

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn run_checked(cmd: &mut Command, label: &str) {
    let output = cmd.output().unwrap_or_else(|err| {
        panic!("{label} failed to start: {err}");
    });

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "{label} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        );
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn contracts_dir() -> PathBuf {
    repo_root().join("contracts")
}

fn generator_bin() -> PathBuf {
    if let Ok(bin) = env::var("CARGO_BIN_EXE_generate_e2e_fixture") {
        return PathBuf::from(bin);
    }

    let release_bin = repo_root().join("target/release/generate_e2e_fixture");
    if release_bin.exists() {
        return release_bin;
    }

    let debug_bin = repo_root().join("target/debug/generate_e2e_fixture");
    if debug_bin.exists() {
        return debug_bin;
    }

    panic!(
        "generate_e2e_fixture binary not found. Run with `cargo test --release --features whir`."
    );
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
    let generator = generator_bin();
    assert!(
        Path::new(&generator).exists(),
        "missing generator binary: {}",
        generator.display()
    );

    // Rust-side proving pipeline: validity proof -> wrapper -> WHIR/constraint data export.
    let mut gen_cmd = Command::new(generator);
    gen_cmd.current_dir(repo_root());
    run_checked(&mut gen_cmd, "generate_e2e_fixture");

    // On-chain verification pieces for the same fixture family:
    // 1. real WHIR verifier
    // 2. piHash binding between Groth16 and WHIR
    // 3. Plonky2 constraint checker using exported wrapper openings/challenges
    run_forge_test("E2E_RealGroth16Test", "test_realWhir_verifies");
    run_forge_test("E2E_RealGroth16Test", "test_e2e_piHash_binding");
    run_forge_test("Plonky2VerifierTest", "test_verifyConstraints_validProof");
}
