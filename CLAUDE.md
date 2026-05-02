# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

intmax3-zkp is a zero-knowledge proof system for the INTMAX3 rollup protocol. It combines FRI-based STARK proofs (Plonky2) for validity proof generation, Solidity smart contracts (Foundry) for L1 settlement, post-quantum signatures (SPHINCS+ with Poseidon), and WHIR/Groth16 proof wrapping.

**Stack:** Rust 2024 edition (nightly-2025-03-23) + Solidity 0.8.29 (Foundry, Prague EVM)

## Build & Test Commands

```bash
# Rust
cargo build --release
cargo test --release                    # Tests MUST run in release mode (debug is ignored via cfg_attr)
cargo test --release -- --nocapture     # With stdout
cargo test --release -p intmax3-zkp --lib <test_name>  # Single unit test
cargo test --test e2e --release         # End-to-end integration test
cargo bench --bench proof_bench         # Proof generation benchmarks
cargo bench --bench degree_report       # Circuit complexity report

# Formatting & Linting
cargo fmt
cargo clippy --release

# Solidity contracts (from contracts/ directory)
cd contracts && forge install
forge test -vvv
forge build

# WASM (CPU-only)
cargo run -r --bin generate_wasm_fixtures
wasm-pack build --release --target web

# WASM (with WebGPU acceleration)
wasm-pack build --release --target web -- --features gpu_merkle

# Browser testing
npm install           # First time only
node server.js        # Serves at https://localhost:8000
# Open https://localhost:8000 in Chrome, click "Run Withdrawal Proof" or "Run Balance Processor Flow"
```

**Important:** All Rust tests use `#[cfg_attr(debug_assertions, ignore = "run with --release")]` — they will be skipped in debug mode.

## Development Guidelines

### No Mocks or Dummies

**Never create mock or dummy implementations for cryptographic verification.**

This includes:
- Functions named `_mock*`, `mock*`, `Mock*`
- Functions named `_dummy*`, `dummy*`, `Dummy*`
- `vm.mockCall()` to fake precompile responses (ecPairing, BLS12-381, etc.)
- Fake proof data (placeholder curve points, zero-filled proofs, etc.)
- Fake verifying keys that don't correspond to a real circuit setup

Tests that require cryptographic verification (Groth16, WHIR, KZG) must use
real pre-generated proof fixtures. If fixtures are not yet available, the test
should not exist yet — do not write it with mocked crypto and call it a test.

**Acceptable in tests:**
- `vm.blobhashes()` to set up EIP-4844 blob transaction context (environment setup, not crypto faking)
- Helper contracts that implement real interfaces with simple fixed behavior (e.g., `FixedReturnForcedTxLogic`)
- `vm.prank()`, `vm.deal()`, `vm.expectRevert()` and other standard Foundry cheatcodes

## WASM / Browser Architecture

### Branch: `lita-fork-integration`

The browser proving setup uses the Lita plonky2 fork (`InternetMaximalism/Lita-Plonky2`, branch `wasm-zkp3`) which adds WebGPU-accelerated Merkle tree hashing via GPU compute shaders (WGSL).

### Three optimization layers

1. **SIMD128** — field arithmetic acceleration (enabled via `.cargo/config.toml` target features)
2. **Multi-threading** — Web Workers + `wasm-bindgen-rayon` thread pool (requires HTTPS + COEP/COOP headers)
3. **WebGPU** — GPU Poseidon hashing for FRI Merkle trees during `prove()` (enabled via `gpu_merkle` feature)

### Key WASM files

- `src/lib.rs` — `#[wasm_bindgen]` entry points: `run_single_withdrawal_proof()`, `run_balance_processor_flow()`, `init_gpu_merkle()`
- `.cargo/config.toml` — WASM target flags (atomics, SIMD, 4GB max memory, 16MB stack)
- `index.html` — Browser test runner UI
- `test-worker.js` — Web Worker that initializes WASM, thread pool, GPU, and dispatches proof actions
- `server.js` — HTTPS dev server with COEP/COOP headers for SharedArrayBuffer

### WASM memory constraints

WASM32 has a **4GB hard limit** on linear memory. The proof pipeline uses ~4GB at peak. Key mitigations:
- **Strategic `drop()` calls** in `src/lib.rs` — circuit data, witnesses, and proofs are dropped as soon as no longer needed between proving steps
- **Memory-pressure CPU fallback** — when WASM memory exceeds 3.5GB, Merkle tree construction falls back from GPU to CPU (GPU path requires extra staging buffer)
- **RawLayerAccessor** — GPU readback reads hashes on-the-fly from mapped staging buffer instead of allocating intermediate Vecs (~32MB saved)
- `prove_async()` is mandatory in WASM with `gpu_merkle`; sync `prove()` panics

### GPU Merkle tree details

- GPU shader writes **cap** hashes in canonical form, **nodes** in Montgomery form
- Only input + nodes buffers need Montgomery-to-canonical conversion after GPU execution; cap does NOT
- Trees with < 65536 leaves fall back to CPU (GPU overhead not worth it)
- The `gpu_merkle` feature propagates to plonky2, starky, and plonky2_keccak

## Architecture

### Four Proof Types

1. **Balance Proofs** (`src/circuits/balance/`) — User account state (spend, send-tx, receive-transfer, receive-deposit). Uses recursive IVC via a switch board circuit that routes to sub-circuits, coordinated by `balance_processor.rs`.

2. **Validity Proofs** (`src/circuits/validity/`) — Block-level consensus. Two chains: block hash chain (account tree updates + SPHINCS+ signature verification) and deposit hash chain. Main circuit in `validity_circuit.rs` binds initial/final state commitments. Public inputs = `keccak256(ValidityPublicInputs)` for on-chain binding.

3. **Withdrawal Proofs** (`src/circuits/withdraw/`) — Extract transfers from balance proofs and aggregate N withdrawals via chain circuit.

4. **On-Chain Verification** (`contracts/src/IntmaxRollup.sol`) — L1 contract with `postBlock()`, `deposit()`, `submit()`, `finalize()` steps. Verifies WHIR + Groth16 + KZG in parallel.

### Key Modules

- `src/common/` — Core types: Block, Deposit, Transfer, Tx, UserId, PrivateState, PublicState, and Merkle trees (account, deposit, tx, transfer, indexed)
- `src/ethereum_types/` — Ethereum-compatible types (Address, Bytes32, U256) as u32 arrays for Plonky2 compatibility
- `src/utils/` — Poseidon hash, cyclic recursion helpers, serialization, hash chains, tree abstractions
- `src/wrapper_config/` — Plonky2 circuit config (PoseidonGoldilocksConfig, F=Goldilocks, D=2)
- `src/circuits/test_utils/` — Witness generators and native SPHINCS+ signing for tests

### Circuit Patterns

- **Config:** `PoseidonGoldilocksConfig` with Goldilocks field, degree-2 extensions (`F = GoldilocksField, const D: usize = 2`)
- **Recursion:** Cyclic recursion via `RecursivelyVerifiable` trait and `cyclic.rs` utilities
- **Public Input Binding:** Proofs bind to on-chain state via `keccak256(ValidityPublicInputs)` → WHIR evaluations → Groth16 public inputs
- **Witness Pattern:** Separate `*Witness` structs for circuit inputs; `*WitnessGenerator` for building them in tests

### Dependencies

- `plonky2` (Lita fork, `wasm-zkp3` branch) — FRI-based STARK system with WebGPU support
- `plonky2_u32`, `plonky2_bn254`, `plonky2_keccak` — Extension circuits (lita-xyz forks)
- `sphincsplus-circuits`, `sphincsplus-poseidon`, `sphincsplus-params` — Post-quantum signatures

### Solidity Contracts

- `IntmaxRollup.sol` — Main rollup contract (6-step verification pipeline)
- `BlobKZGVerifier.sol` — EIP-2537 KZG multi-point opening
- `Groth16Verifier.sol` — BN254 Groth16 pairing verification
- Foundry config: optimizer on (200 runs), via_ir enabled, Prague EVM

## Code Style

- `rustfmt.toml`: `imports_granularity = "Crate"`, `wrap_comments = true`, `comment_width = 150`
- Rust nightly required (pinned in `rust-toolchain.toml`)
