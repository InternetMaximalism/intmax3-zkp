# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

intmax3-zkp is a zero-knowledge proof system for the INTMAX3 rollup protocol. It combines FRI-based STARK proofs (Plonky2) for validity proof generation, Solidity smart contracts (Foundry) for L1 settlement, post-quantum signatures (SPHINCS+ with Poseidon), and a multilinear (MLE) PCS with WHIR for the on-chain wrapper proof.

**Stack:** Rust 2024 edition (nightly-2025-03-23) + Solidity 0.8.29 (Foundry, Prague EVM)

## Secrets & Key Handling (MANDATORY)

A real Ethereum private key (testnet/Sepolia deployer) is stored at `.claude/priv`.
`.claude/` is gitignored (`.gitignore:63`) and `.claude/priv` is also listed explicitly
(`.gitignore` "Secrets" block), so the key is never committed — keep it that way.

- **NEVER read the key's contents.** Do not `cat`/`Read`/`head`/`tail`/`grep` the file, and never let its value enter the model context, a tool result, a commit, or any external/network call. Leaking it once is irreversible — anyone can drain the funds. Existence checks via `ls` only.
- **Hand the key to local processes directly**, never through the assistant: e.g. `cast wallet import <name> --interactive` (keystore), then `forge script ... --account <name>`; or `--private-key "$(cat .claude/priv)"` so the *shell* expands it — do not echo, print, or write the value anywhere.
- Never put the key (or command output containing it) in responses, commit messages, or files. The derived **address** is public and fine to record.
- Store any new secret under `.claude/` or another gitignored path.

## Build & Test Commands

```bash
# Rust
cargo build --release
cargo test --release                    # Tests MUST run in release mode (debug is ignored via cfg_attr)
cargo test --release -- --nocapture     # With stdout
cargo test --release -p intmax3-zkp --lib <test_name>  # Single unit test
cargo test --test e2e --release         # End-to-end integration test
cargo test --test mle_onchain_e2e --release  # MLE/WHIR on-chain E2E (drives Forge inside)
cargo bench --bench proof_bench         # Proof generation benchmarks
cargo bench --bench degree_report       # Circuit complexity report

# Formatting & Linting
cargo fmt
cargo clippy --release

# Solidity contracts (from contracts/ directory)
cd contracts && forge install
forge test -vvv
forge build
# Skip the (slow) gnark Groth16 fixture test:
SKIP_GROTH16=true forge test

# WASM (CPU-only)
cargo run -r --bin generate_wasm_fixtures
wasm-pack build --release --target web

# WASM (with WebGPU acceleration) — pending the v2 MleVerifier migration; see "Known follow-up" below
# wasm-pack build --release --target web -- --features gpu_merkle

# Browser testing
npm install           # First time only
node server.js        # Serves at https://localhost:8000
# Open https://localhost:8000 in Chrome, click "Run Withdrawal Proof" or "Run Balance Processor Flow"
```

**Important:** All Rust tests use `#[cfg_attr(debug_assertions, ignore = "run with --release")]` — they will be skipped in debug mode.

## Development Guidelines

### No Mocks or Dummies

### 1. Default to Planning Mode
- Switch to planning mode for every non-simple task (those with 3 or more steps or design choices)
- If issues arise, halt and revise the plan immediately — never force progress
- Apply planning mode to verification and confirmation processes, not just construction
- Draft thorough specifications in advance to eliminate ambiguity
- **For any change touching proof logic, cryptographic protocols, or security-sensitive components: write a full threat model before writing any code**

### 2. Subagent Approach to Maintain Clear Main Context
- Delegate investigation, discovery, and parallel evaluations to subagents
- For complex or ambiguous issues, allocate additional reasoning through subagents
- Assign a single responsibility per subagent for concentrated, focused analysis
- **Use dedicated subagents for security review — separate from the implementation subagent. Never let the same subagent both implement and security-review its own work**
- Spin up an explicit "attacker subagent" for any protocol-level design or change (see §Adversarial Thinking)

### 3. Task Oversight
1. **Prioritize Planning**: Document the strategy in `tasks/todo.md` with verifiable, falsifiable elements
2. **Approve the Plan**: Consult the user before beginning execution
3. **Monitor Advancement**: Check off elements as they are completed
4. **Clarify Modifications**: Provide a high-level summary at each phase
5. **Record Outcomes**: Include an assessment in `tasks/todo.md`
6. **Log Insights**: Update `tasks/lessons.md` after adjustments — but never suppress a security concern to reduce "interruption frequency"

**Acceptable in tests:**
- `vm.blobhashes()` to set up EIP-4844 blob transaction context (environment setup, not crypto faking)
- Helper contracts that implement real interfaces with simple fixed behavior (e.g., `FixedReturnForcedTxLogic`)
- `vm.prank()`, `vm.deal()`, `vm.expectRevert()` and other standard Foundry cheatcodes

## Architecture

### Four Proof Types

1. **Balance Proofs** (`src/circuits/balance/`) — User account state (spend, send-tx, receive-transfer, receive-deposit). Uses recursive IVC via a switch board circuit that routes to sub-circuits, coordinated by `balance_processor.rs`.

2. **Validity Proofs** (`src/circuits/validity/`) — Block-level consensus. Two chains: block hash chain (user tree updates + SPHINCS+ signature verification) and deposit hash chain. Main circuit in `validity_circuit.rs` binds initial/final state commitments. Public inputs = `keccak256(ValidityPublicInputs)` for on-chain binding.

3. **Withdrawal Proofs** (`src/circuits/withdraw/`) — Extract transfers from balance proofs and aggregate N withdrawals via chain circuit.

4. **On-Chain Verification** (`contracts/src/IntmaxRollup.sol`) — L1 contract with `postBlock()`, `deposit()`, `submit()`, `finalize()` steps. Verifies the MLE+WHIR wrapper proof and Groth16 in parallel.

### Wrapper proof pipeline (Rust → on-chain)

The validity proof is wrapped via `WrapperCircuit` and then committed/opened via the upstream `plonky2_mle` integration (`mle_prove` → `MleProof<F>`), which is verified on-chain by `@mle/MleVerifier.sol` from the `polygon-plonky2` submodule (`contracts/lib/polygon-plonky2`, pinned via Cargo `[patch]`). The MLE pipeline binds WHIR's commitment root into the Keccak Fiat-Shamir transcript so all MLE challenges (alpha/beta/gamma/tau/tau_perm/batchR) are bound to the committed polynomial — replacing the legacy in-tree `whir_plonky2_prover.rs` wrapper that left ζ-openings unbound to the WHIR commitment.

### Key Modules

- `src/common/` — Core types: Block, Deposit, Transfer, Tx, UserId, PrivateState, PublicState, and Merkle trees (account, deposit, tx, transfer, indexed)
- `src/ethereum_types/` — Ethereum-compatible types (Address, Bytes32, U256) as u32 arrays for Plonky2 compatibility
- `src/utils/` — Poseidon hash, cyclic recursion helpers, serialization, hash chains, tree abstractions, and the MLE prover wrapper (`mle_prover.rs`)
- `src/wrapper_config/` — Plonky2 circuit config (PoseidonGoldilocksConfig, F=Goldilocks, D=2)
- `src/circuits/test_utils/` — Witness generators and native SPHINCS+ signing for tests

### Circuit Patterns

- **Config:** `PoseidonGoldilocksConfig` with Goldilocks field, degree-2 extensions (`F = GoldilocksField, const D: usize = 2`)
- **Recursion:** Cyclic recursion via `RecursivelyVerifiable` trait and `cyclic.rs` utilities
- **Public Input Binding:** Proofs bind to on-chain state via `keccak256(ValidityPublicInputs)` → MLE/WHIR evaluations → Groth16 public inputs
- **Witness Pattern:** Separate `*Witness` structs for circuit inputs; `*WitnessGenerator` for building them in tests

### Dependencies

- `plonky2`, `starky`, `plonky2_mle` (polygon-plonky2 submodule at `contracts/lib/polygon-plonky2`, pinned via `[patch]`) — FRI-based STARK system and the multilinear (MLE) PCS with WHIR
- `plonky2_u32`, `plonky2_bn254`, `plonky2_keccak` — Extension circuits (`mleintroduction` branches, paired with the submodule pin)
- `sphincsplus-circuits`, `sphincsplus-poseidon`, `sphincsplus-params` — Post-quantum signatures

### Solidity Contracts

- `IntmaxRollup.sol` — Main rollup contract (6-step verification pipeline)
- `@mle/MleVerifier.sol` (via `contracts/lib/polygon-plonky2/mle/contracts/src/`, Foundry remapping `@mle/=lib/polygon-plonky2/mle/contracts/src/`) — MLE proof + WHIR PCS verification
- `BlobKZGVerifier.sol` — EIP-2537 KZG multi-point opening
- `Groth16Verifier.sol` / `GnarkGroth16Verifier.sol` — BN254 Groth16 pairing verification
- Foundry config: optimizer on (200 runs), via_ir enabled, Prague EVM

## WASM / Browser Architecture

The browser proving setup runs against the same `polygon-plonky2` submodule pin used for native builds. WebGPU-accelerated Merkle hashing is **not yet enabled on this branch** — see the "Known follow-up" section below.

### Three optimization layers (current state)

1. **SIMD128** — field arithmetic acceleration (enabled via `.cargo/config.toml` target features)
2. **Multi-threading** — Web Workers + `wasm-bindgen-rayon` thread pool (requires HTTPS + COEP/COOP headers)
3. **WebGPU** — *(pending)* GPU Poseidon hashing for FRI Merkle trees during `prove()` (`gpu_merkle` feature, currently disabled — see "Known follow-up")

### Key WASM files

- `src/lib.rs` — `#[wasm_bindgen]` entry points: `run_single_withdrawal_proof()`, `run_balance_processor_flow()`, `init_gpu_merkle()`
- `src/wasm_demo.rs` — Browser proving entry implementations
- `.cargo/config.toml` — WASM target flags (atomics, SIMD, 4GB max memory, 16MB stack)
- `index.html` — Browser test runner UI
- `test-worker.js` — Web Worker that initializes WASM, thread pool, GPU, and dispatches proof actions
- `server.js` — HTTPS dev server with COEP/COOP headers for SharedArrayBuffer

### WASM memory constraints

WASM32 has a **4GB hard limit** on linear memory. The proof pipeline uses ~4GB at peak. Key mitigations:
- **Strategic `drop()` calls** in `src/lib.rs` — circuit data, witnesses, and proofs are dropped as soon as no longer needed between proving steps
- **Memory-pressure CPU fallback** *(GPU path only)* — when WASM memory exceeds 3.5GB, Merkle tree construction falls back from GPU to CPU
- `prove_async()` is mandatory in WASM with `gpu_merkle`; sync `prove()` panics on that path

### Known follow-up: gpu_merkle re-enable

The `gpu_merkle` feature is intentionally not exposed in `Cargo.toml` on this branch. Re-enabling it requires bumping the `polygon-plonky2` submodule to `940ce731` (PR #11 `feat/wasm-webgpu-merkle` merge) or later, which simultaneously introduces the v2 MLE-verifier soundness fixes (R2-#1 gate binding, R2-#2 logUp) that change `MleVerifier.verify`'s signature (new `gatesDigest`, `whirEvals` consolidated into `MleProof`). A coordinated migration across `IntmaxRollup.sol`, `IntmaxRollup.t.sol`, `MleE2E.t.sol`, `generate_e2e_fixture.rs`, and `mle_fixture.json` is tracked as a separate PR.

## Code Style

- `rustfmt.toml`: `imports_granularity = "Crate"`, `wrap_comments = true`, `comment_width = 150`
- Rust nightly required (pinned in `rust-toolchain.toml`)

---

## Workflow Coordination

### 1. Default to Planning Mode
- Switch to planning mode for every non-simple task (those with 3 or more steps or design choices)
- If issues arise, halt and revise the plan immediately — never force progress
- Apply planning mode to verification and confirmation processes, not just construction
- Draft thorough specifications in advance to eliminate ambiguity
- **For any change touching proof logic, cryptographic protocols, or security-sensitive components: write a full threat model before writing any code**

### 2. Subagent Approach to Maintain Clear Main Context
- Delegate investigation, discovery, and parallel evaluations to subagents
- For complex or ambiguous issues, allocate additional reasoning through subagents
- Assign a single responsibility per subagent for concentrated, focused analysis
- **Use dedicated subagents for security review — separate from the implementation subagent. Never let the same subagent both implement and security-review its own work**
- Spin up an explicit "attacker subagent" for any protocol-level design or change (see §Adversarial Thinking)

### 3. Task Oversight
1. **Prioritize Planning**: Document the strategy in `tasks/todo.md` with verifiable, falsifiable elements
2. **Approve the Plan**: Consult the user before beginning execution
3. **Monitor Advancement**: Check off elements as they are completed
4. **Clarify Modifications**: Provide a high-level summary at each phase
5. **Record Outcomes**: Include an assessment in `tasks/todo.md`
6. **Log Insights**: Update `tasks/lessons.md` after adjustments — but never suppress a security concern to reduce "interruption frequency"

---

## Security-Critical Mindset

### The Core Principle
**"It works" and "it is secure" are entirely different claims.** Never conflate them. A passing test suite is not evidence of cryptographic soundness. When in doubt, stop and surface the question to the user — this is always the correct action.

### 1. Critical Security Thinking
- Before declaring any task complete, explicitly ask: *"What could go wrong if an adversary sees this output / controls this input / replays this message?"*
- Treat every assumption as a potential vulnerability until it is justified
- If you cannot articulate the security argument for a design decision, do not proceed — escalate to the user
- Complexity is not an excuse to skip security reasoning; if something is hard to analyze, that itself is a security concern
- **Never silently work around a failing security check. A failing check is a signal, not an obstacle.**

### 2. Adversarial Thinking (Attacker Subagent)
For every protocol design, proof system change, or cryptographic interface, spawn a dedicated subagent with the following mandate:

```
You are an adversary. Your goal is to break soundness, completeness, or zero-knowledge.
Enumerate:
  - Malformed inputs the prover or verifier might accept incorrectly
  - Transcript manipulations that bypass Fiat-Shamir binding
  - Evaluation point collisions or reuse across sub-protocols
  - Batch opening attacks (e.g., linear combination forgery)
  - Missing domain separation that allows cross-protocol attacks
  - Timing or side-channel leakage in non-constant-time code
Report every suspicion, no matter how speculative.
```

This subagent's output must be reviewed before any implementation is merged.

### 3. Cryptographic Invariant Checklist
Before completing any task that touches cryptographic code, verify **all** of the following. If any item cannot be confirmed, stop and report.

**Fiat-Shamir Transform**
- [ ] Every message included in the proof is also absorbed into the transcript, in the correct order
- [ ] The transcript is domain-separated (protocol ID, version, context string)
- [ ] No value is used as a challenge before it is derived from the transcript
- [ ] The challenge derivation is deterministic and not reused across invocations

**Polynomial Commitment Binding**
- [ ] The evaluation point used in the commitment proof is the same point derived from the verifier's challenge (e.g., from sumcheck output) — not a separately derived point
- [ ] Batch opening random scalars are freshly derived and not reused across protocols
- [ ] The commitment scheme is binding: the prover cannot open to two different values at the same point

**Sumcheck Protocol**
- [ ] The claimed sum matches the polynomial being proved
- [ ] The verifier's random challenges at each round are derived after the prover's message for that round
- [ ] The final evaluation is verified against an external oracle (e.g., WHIR), not trusted from the prover

**Permutation / Copy Constraints**
- [ ] The grand product or multilinear permutation argument covers all wires
- [ ] β and γ challenges are derived after all wire commitments are fixed
- [ ] "Next row" semantics are correct for the chosen arithmetization (univariate vs. multilinear)

**Fiat-Shamir × Commitment Binding**
- [ ] The evaluation point `r` and the commitment opening are bound to the same transcript
- [ ] There is no gap where the prover can choose the evaluation point after seeing the commitment randomness

**General**
- [ ] No cryptographic primitive is implemented from scratch — use audited libraries
- [ ] All randomness comes from a cryptographically secure source, explicitly documented
- [ ] Security parameter choices are documented and approved, never changed silently

### 4. Test Coverage: Always Maximize Patterns
- **Correctness tests** are necessary but not sufficient — they do not cover adversarial inputs
- For every function, write tests in the following categories:
  1. Happy path (expected valid inputs)
  2. Boundary cases (empty, max-size, all-zeros, all-ones)
  3. **Malformed prover behavior** (wrong evaluation, tampered commitment, replayed transcript)
  4. **Cross-protocol confusion** (reused challenges, mismatched evaluation points)
  5. **Randomized / property-based tests** — generate hundreds of random valid and invalid instances
- Aim for test patterns that **would catch a subtle soundness bug**, not just implementation bugs
- Use parameterized tests to run the same security check across multiple field sizes, curve parameters, or protocol variants
- Document what each test is *intended to prove about security*, not just what it checks mechanically

### 5. Unexpected Test Results → Security-First Hypothesis
When any test produces an unexpected result:

**Default hypothesis: this is a security problem, not an implementation bug.**

Follow this protocol before attempting a fix:
1. **Do not modify the test** to make it pass
2. Ask: *"Could an adversary trigger this condition intentionally?"*
3. Ask: *"Does this reveal an incorrect assumption in the security argument?"*
4. Document the unexpected result in `tasks/todo.md` with the security hypothesis
5. Spawn a subagent to analyze the failure from an adversarial perspective
6. **Only after ruling out a security issue** proceed to treat it as a normal bug

If the root cause is unclear after analysis, **stop and report to the user** with a full description of the unexpected behavior and the hypotheses considered.

---

## Fundamental Guidelines

- **Security over Speed**: A correct incomplete implementation is always preferable to an incorrect complete one
- **Escalate, Don't Patch**: If a fix to a cryptographic component is not fully understood, do not apply it — surface the question
- **No Unauthorized Heavy Computation**: Never run model training, large-scale tests, or heavy computation without explicit user permission
- **Limited Scope**: Changes must affect only what is necessary; prevent introduction of new attack surface
- **No Silent Workarounds**: Never disable, skip, or weaken a security check to make progress. Always escalate

---

## Documentation Standards

- **All documentation, comments, commit messages, and notes must be written in English**
- Security assumptions must be stated explicitly in comments adjacent to the code that relies on them
- Every cryptographic protocol step must reference the corresponding line in the specification or paper
- When a design decision has a non-obvious security rationale, document it inline: `// SECURITY: ...`
- When a piece of code is intentionally left simple to minimize attack surface, note it: `// INTENTIONALLY SIMPLE: ...`
