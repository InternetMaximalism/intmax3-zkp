# Plonky3 migration notes

This repository is not a small `plonky2` consumer. The current circuit stack depends on
`plonky2` proof objects, verifier-data public inputs, cyclic recursion, `plonky2_u32`,
`plonky2_keccak`, and the current wrapper/export pipeline.

As of 2026-05-24, the migration target in this repository is:

- Recursion API: `p3_recursion::FriRecursionBackend`
- Field: `KoalaBear`
- In-circuit hash: `Poseidon2`
- Commitment scheme: FRI

## Why this backend

The backend choice is based on the official Plonky3 sources:

- Plonky3 recursion exposes a unified recursion API around `FriRecursionBackend` and documents
  recursive verification for `p3-uni-stark` and `p3-batch-stark` proofs.
- The official recursion README examples use `koala-bear` in the sample commands and accept
  `koala-bear`, `baby-bear`, and `goldilocks`, with `poseidon2` as the default hash.
- The main Plonky3 README highlights SIMD support for the 31-bit fields (`BabyBear` and
  `KoalaBear`) and separately documents `Goldilocks`.
- `p3-circle` is a valid Plonky3 proof system, but the public recursion flow is documented around
  the FRI recursion backend, not Circle recursion.

The `KoalaBear + Poseidon2 + FriRecursionBackend` recommendation is therefore partly source-backed
and partly an engineering inference:

- Source-backed:
  - official recursion entry point is `FriRecursionBackend`
  - recursion examples accept `koala-bear|baby-bear|goldilocks`
  - recursion examples default to `poseidon2`
- Inference:
  - prefer `KoalaBear` over `Goldilocks` for new recursive layers because the official examples and
    benchmark snippets lean on the optimized 31-bit field path
  - prefer `KoalaBear` over `BabyBear` here because the recursion README uses `koala-bear` as the
    sample field in all three recursive examples

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
   recursion helpers.
3. Port the field/u32/hash gadget layer:
   - `src/ethereum_types/*`
   - `src/utils/leafable_hasher.rs`
   - `src/utils/trees/*`
4. Rewrite non-recursive leaf circuits onto Plonky3 primitives/AIRs.
5. Rebuild recursive aggregation circuits:
   - `src/circuits/balance/*`
   - `src/circuits/validity/*`
   - `src/circuits/withdraw/*`
   - `src/utils/hash_chain/*`
6. Redesign serialization/wrapper/export paths for the new proof system.
7. Replace or remove the Plonky2-specific on-chain / gnark verification path.

## Implemented in this repo now

The repository now contains an initial, working Plonky3 proving path under:

- `src/plonky3/hash.rs`
- `src/plonky3/private_state.rs`

What it does:

- uses `KoalaBear + Poseidon2 + D1 width-16 + quintic extension witnesses`
- hashes arbitrary `u64` input vectors by first splitting each `u64` into four 16-bit limbs
- proves and verifies the hash relation with the official `p3-circuit` / `p3-circuit-prover`
  stack
- proves and verifies a `PrivateState` commitment through that bridge

Important limitation:

- this is a migration bridge, not a bit-for-bit replacement of the existing Plonky2
  `PoseidonHashOut::hash_inputs_u64` semantics
- the bridge currently re-encodes each `u64` as four 16-bit KoalaBear limbs before hashing
- therefore, existing Plonky2 proofs / fixtures / verifier contracts are not interchangeable with
  the new Plonky3 path yet

## Sources

- Plonky3 recursion book: https://plonky3.github.io/Plonky3-recursion/introduction.html
- Plonky3 recursion README: https://github.com/Plonky3/Plonky3-recursion/blob/main/README.md
- Plonky3 README: https://github.com/Plonky3/Plonky3/blob/main/README.md
