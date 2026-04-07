# Test Fixture Generation

All fixture files in this directory are generated artifacts and are not tracked
in git. Regenerate them with the commands below before running tests.

## Prerequisites

- Rust toolchain (stable)
- [plonky2-whir-verifier](https://github.com/InternetMaximalism/plonky2-whir-verifier)
  cloned at the repository root on the `canonicalplonky2` branch:
  ```
  git clone -b canonicalplonky2 https://github.com/InternetMaximalism/plonky2-whir-verifier.git
  ```
- gnark binary at `gnark/gnark` (only needed for Groth16 E2E fixtures)

## Quick Start

```bash
# 1. WHIR + Plonky2 unified proof fixtures (required for most tests)
cd plonky2-whir-verifier
cargo run --bin generate_fixture --release

# 2. E2E fixtures: validity circuit wrapper + WHIR proof (without Groth16)
cd ..   # back to repo root
cargo run --bin generate_e2e_fixture --release --features whir -- --skip-groth16

# 3. E2E fixtures: full pipeline including gnark Groth16 (requires gnark binary)
cargo run --bin generate_e2e_fixture --release --features whir
```

## Generated Files

### Step 1: `plonky2-whir-verifier/generate_fixture`

Uses a generic Poseidon hash-chain test circuit (degree_bits=4).

| File | Description |
|---|---|
| `test_proof.json` | Unified WHIR-Plonky2 proof (transcript, hints, evaluations, bridge data, circuit config, public inputs) |
| `test_constraint_data.json` | Plonky2 circuit constraint data (gates, wires, selectors) |
| `whir/test_combined_verifier_data.json` | Combined WHIR verifier data (Merkle roots, round params) |

### Step 2: `generate_e2e_fixture --skip-groth16`

Uses the real intmax3 validity circuit (degree_bits=16) wrapped via WrapperCircuit.

| File | Description |
|---|---|
| `e2e_fixture.json` | Plonky2 validity proof, public inputs, piHash |
| `wrapper_constraint_data.json` | Wrapper circuit constraint data (degree_bits=13) |
| `whir/wrapper_whir_proof.json` | WHIR proof for the wrapper circuit |
| `whir/wrapper_combined_verifier_data.json` | Combined WHIR verifier data for wrapper |
| `whir/wrapper_constants_sigmas_verifier_data.json` | WHIR batch: constants + sigmas |
| `whir/wrapper_wires_verifier_data.json` | WHIR batch: wires |
| `whir/wrapper_zs_partial_products_verifier_data.json` | WHIR batch: zs + partial products |
| `whir/wrapper_quotient_polys_verifier_data.json` | WHIR batch: quotient polynomials |

### Step 3: `generate_e2e_fixture` (full)

Same as step 2, plus gnark Groth16 wrapping.

| File | Description |
|---|---|
| `e2e_groth16.json` | gnark Groth16 proof, commitments, public inputs |

## Which Tests Need Which Fixtures

| Test suite | Required fixtures |
|---|---|
| `IntmaxRollupTest` (50 tests) | Step 1 |
| `FraudProofPartialCorruptionTest` (21 tests) | Step 1 |
| `E2E_RealGroth16Test` (2 tests) | Steps 2 + 3 |
