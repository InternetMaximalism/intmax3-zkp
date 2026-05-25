# Plonky3 migration notes

This repository is not a small `plonky2` consumer. The current circuit stack depends on
`plonky2` proof objects, verifier-data public inputs, cyclic recursion, `plonky2_u32`,
`plonky2_keccak`, and the current wrapper/export pipeline.

As of 2026-05-25, the migration target in this repository is:

- Recursion API: `p3_recursion::FriRecursionBackend`
- Field: `KoalaBear`
- In-circuit hash: `Poseidon2`
- Commitment scheme: FRI
- Recursive challenge extension: degree 4
- Base proof family for migrated application circuits: `p3_batch_stark` via `p3_circuit`
- Recursive compression and aggregation: `build_and_prove_next_layer` and
  `build_and_prove_aggregation_layer`

## Why this backend

The backend choice is based on the official Plonky3 sources:

- Plonky3 recursion exposes a unified recursion API around `FriRecursionBackend` and documents
  recursive verification for `p3-uni-stark` and `p3-batch-stark` proofs.
- The official recursion README examples use `koala-bear` in the sample commands and accept
  `koala-bear`, `baby-bear`, and `goldilocks`, with `poseidon2` as the default hash.
- The recursion book's configuration guide marks `KoalaBear` as the recommended base field and
  describes degree-4 extensions as the standard recursion stack.
- The published recursion benchmarks in the book are reported on `KoalaBear` with degree-4
  extensions.
- The main Plonky3 README highlights SIMD support for the 31-bit fields (`BabyBear` and
  `KoalaBear`) and separately documents `Goldilocks`.
- `p3-whir` exists in the main Plonky3 workspace, but the official recursion crate exposes only
  `FriRecursionBackend` and documents in-circuit FRI verification, not WHIR recursion.
- `p3-circle` is a valid Plonky3 proof system, but the public recursion flow is documented around
  the FRI recursion backend, not Circle recursion.

The `KoalaBear + Poseidon2 + FriRecursionBackend + D=4` recommendation is therefore partly
source-backed and partly an engineering inference:

- Source-backed:
  - official recursion entry point is `FriRecursionBackend`
  - recursion examples accept `koala-bear|baby-bear|goldilocks`
  - recursion examples default to `poseidon2`
  - recursion configuration marks `KoalaBear` as recommended
  - recursion examples and benchmarks use degree-4 recursion as the standard path
- Inference:
  - prefer `KoalaBear` over `Goldilocks` for new recursive layers because the official examples and
    benchmark snippets lean on the optimized 31-bit field path
  - prefer `KoalaBear` over `BabyBear` here because the recursion README uses `koala-bear` as the
    sample field in all three recursive examples
  - do not choose `Whir` for the first full migration because the current official recursion stack
    does not expose a WHIR-based recursive verifier API yet
  - do not choose `KoalaBear` quintic recursion (`D=5`) for the first full migration because the
    official examples explicitly note that quintic ZK mode is not wired up, while this repository
    needs end-to-end ZK flows

## Current scope in this repo

The migration surface measured in the current tree is:

- `src/**/*.rs`: 38,711 lines
- `src/circuits/**/*.rs`: 21,221 lines
- Rust files in `src/`, `tests/`, `benches/` that directly import `plonky2`/`plonky2_*`: 108
- explicit proof-verification hooks in `src/`: 60
- direct references to `plonky2_keccak`, `plonky2_u32`, `plonky2_bn254`, or `starky`: 16

## Hard blockers to a direct rewrite

### 1. The recursion model changes

This codebase is built around `plonky2` proof recursion inside a `CircuitBuilder<F, D>` API:

- `src/utils/recursively_verifiable.rs`
- `src/utils/cyclic.rs`
- `src/utils/dummy.rs`
- `src/utils/wrapper.rs`

Plonky3 recursion does not preserve that shape. The official recursion stack is STARK-native and
uses a fixed recursive verifier circuit built with `p3_circuit` / `p3_recursion`, not a drop-in
replacement for `plonky2::plonk::CircuitBuilder`.

### Chosen recursion method for this repo

The migration target is not "cyclic recursion rewritten in-place". The chosen Plonky3 recursion
method is:

1. Express application circuits as `p3_circuit` circuits and prove them as `p3_batch_stark`
   proofs.
2. Replace single-proof recursive wrappers with `build_and_prove_next_layer`, producing a recursive
   batch-STARK proof that verifies the previous proof.
3. Replace proof-merging wrappers with `build_and_prove_aggregation_layer`, using 2-to-1 recursive
   aggregation where the current Plonky2 code combines child proofs.
4. Keep the recursive verifier on `KoalaBear + Poseidon2 + FRI + degree-4` through the first
   end-to-end migration.

This means the target architecture is "base batch-STARKs plus a fixed recursive verifier", not a
Plonky2-style embedded verifier target carried through the same gadget APIs.

### 2. The circuit DSL changes

Large parts of the code assume:

- `ProofWithPublicInputs`
- `ProofWithPublicInputsTarget`
- `VerifierCircuitData`
- `VerifierCircuitTarget`
- `builder.verify_proof::<C>(...)`
- cyclic verifier-data packing into public inputs

Those abstractions are not preserved as-is in the public Plonky3 recursion API.

### 3. Gadget dependencies are `plonky2`-specific

This repo also depends on:

- `plonky2_u32` for 32-bit limb arithmetic in `src/ethereum_types/*`
- `plonky2_keccak` for native and circuit Keccak hashing
- `plonky2_bn254` / wrapper configuration code
- `starky`

These must be re-expressed on Plonky3 primitives or replaced with new gadgets/AIRs.

### 4. External proof consumers will break

The current stack includes:

- `gnark/main.go`
- `contracts/src/Plonky2Verifier.sol`
- wrapper/fixture exporters

Even if the Rust circuits were ported, the emitted proof format would no longer match the current
Plonky2-based wrapper/verifier pipeline.

## Migration order

To keep the repository buildable, the recommended rewrite order is:

1. Freeze the target backend and recursion strategy.
2. Replace `src/utils/{cyclic,recursively_verifiable,dummy,wrapper}.rs` with Plonky3-native
   recursion helpers built around `build_and_prove_next_layer` /
   `build_and_prove_aggregation_layer`.
3. Port the field/u32/hash gadget layer:
   - `src/ethereum_types/*`
   - `src/utils/leafable_hasher.rs`
   - `src/utils/trees/*`
4. Rewrite non-recursive leaf circuits onto `p3_circuit` first, only dropping to custom AIRs when a
   circuit proves too expensive in the generic circuit prover.
5. Rebuild recursive aggregation circuits:
   - `src/circuits/balance/*`
   - `src/circuits/validity/*`
   - `src/circuits/withdraw/*`
   - `src/utils/hash_chain/*`
6. Redesign serialization/wrapper/export paths for the new proof system.
7. Replace or remove the Plonky2-specific on-chain / gnark verification path.

## Implemented in this repo now

The repository now contains an initial, working Plonky3 proving path under:

- `src/plonky3/config.rs`
- `src/plonky3/hash.rs`
- `src/plonky3/hash_chain.rs`
- `src/plonky3/private_state.rs`
- `src/plonky3/recursion.rs`
- `src/plonky3/send_tx.rs`
- `src/plonky3/utils/*`

What it does:

- uses `KoalaBear + Poseidon2 + D4 width-16`
- hashes arbitrary `u64` input vectors by first splitting each `u64` into four 16-bit limbs
- proves and verifies the hash relation with the official `p3-circuit` / `p3-circuit-prover`
  stack
- proves and verifies a `PrivateState` commitment through that bridge
- proves a validated native `send tx` statement by hashing the normalized statement directly from
  Plonky3-side data structures
- uses a compact `send tx` recursive path by default, while keeping a decomposed
  `prev_balance` / `update_public_state` / `tx_settlement` aggregation path for comparison and
  profiling
- compresses the resulting batch-STARK proof through one recursive layer using
  `FriRecursionBackend`
- replaces the old `wrapper` / `recursively_verifiable` responsibilities with Plonky3-native
  `wrap_recursion_output`, `verify_recursion_output`, and `aggregate_recursion_outputs`
- replaces the old cyclic hash-chain accumulator with a Plonky3 aggregation tree under
  `src/plonky3/hash_chain.rs`

Important limitation:

- this is a migration bridge, not a bit-for-bit replacement of the existing Plonky2
  `PoseidonHashOut::hash_inputs_u64` semantics
- the bridge currently re-encodes each `u64` as four 16-bit KoalaBear limbs before hashing
- therefore, existing Plonky2 proofs / fixtures / verifier contracts are not interchangeable with
  the new Plonky3 path yet
- `src/plonky3/hash_chain.rs` is the Plonky3 counterpart of `src/utils/hash_chain/*`, but the
  validity / balance / withdraw application circuits under `src/circuits/**` are still on the old
  Plonky2 recursion stack
- `src/plonky3/send_tx.rs` is a native Plonky3 statement circuit, but it still stops at statement
  consistency plus recursive wrapping / optional aggregation of decomposed `send tx`
  sub-statements; it does not yet verify the full predecessor proofs, Merkle updates, and
  settlement gadgets from `src/circuits/balance/send_tx_circuit.rs`
- the `prove_end` aggregation smoke test is intentionally left ignored in the default test run
  because recursive aggregation is currently too slow in debug mode for a normal inner-loop test

## Sources

- Plonky3 recursion book: https://plonky3.github.io/Plonky3-recursion/introduction.html
- Plonky3 recursion quick start: https://plonky3.github.io/Plonky3-recursion/getting_started/quick_start.html
- Plonky3 recursion configuration guide: https://plonky3.github.io/Plonky3-recursion/user_guide/configuration.html
- Plonky3 recursion benchmark appendix: https://plonky3.github.io/Plonky3-recursion/appendix/benchmark.html
- Plonky3 recursion README: https://github.com/Plonky3/Plonky3-recursion/blob/main/README.md
- Plonky3 recursion example showing quintic ZK limitation:
  https://github.com/Plonky3/Plonky3-recursion/blob/main/recursion/examples/recursive_fibonacci.rs
- Plonky3 README: https://github.com/Plonky3/Plonky3/blob/main/README.md
- Plonky3 WHIR crate:
  https://github.com/Plonky3/Plonky3/blob/main/whir/src/lib.rs
