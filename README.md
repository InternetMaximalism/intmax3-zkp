# intmax3-zkp

Zero-knowledge proof circuits and L1 settlement contracts for the INTMAX3 rollup protocol, built with [Plonky2](https://github.com/0xPolygonZero/plonky2) and [Foundry](https://book.getfoundry.sh/).

## System Architecture

```
                         Off-chain (L2)                          │           On-chain (L1)
                                                                 │
  ┌──────────┐    ┌──────────┐    ┌──────────┐                   │   ┌──────────────────────────┐
  │  User A  │───▶│Aggregator│───▶│  Block    │──── postBlock() ─┼──▶│  IntmaxRollup Contract   │
  │  User B  │    │          │    │ (local_ids│     (calldata)   │   │                          │
  │  ...     │    └──────────┘    │  tx_root) │                  │   │  blockHashChain          │
  └──────────┘                    └─────┬─────┘                  │   │  depositHashChain        │
                                        │                        │   │  latestFinalizedStateRoot│
  ┌──────────┐                          ▼                        │   │                          │
  │ Depositor│── deposit() ────────────────────────── deposit()──┼──▶│  blockHashChainAt[n]     │
  └──────────┘                          │                        │   └────────────┬─────────────┘
                                        ▼                        │                │
                                  ┌───────────┐                  │                │ finalize()
                                  │ Validity  │                  │                │
                                  │ Proof     │── submit() ──────┼──▶ EIP-4844 blob
                                  │ (Plonky2) │   (blob TX)      │   + on-chain commitment
                                  └───────────┘                  │
                                        │                        │
                                        ▼                        │
                                  ┌───────────┐                  │
                                  │   WHIR    │                  │
                                  │  wrapper  │── finalize() ────┼──▶ Verify & accept stateRoot
                                  └───────────┘                  │
```

## Proof Pipeline

The system produces four independent proof types that work together:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          VALIDITY PROOF PIPELINE                            │
│                                                                             │
│  Block 1          Block 2          Block N                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐                               │
│  │local_ids │    │local_ids │    │local_ids │                               │
│  │tx_root   │    │tx_root   │    │tx_root   │                               │
│  │SPHINCS+  │    │SPHINCS+  │    │SPHINCS+  │                               │
│  │signatures│    │signatures│    │signatures│                               │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘                               │
│       │               │               │                                     │
│       ▼               ▼               ▼                                     │
│  ┌─────────────────────────────────────────┐                                │
│  │      Block Hash Chain Circuit           │ ◄── account tree updates       │
│  │  (UpdateAccountTree + SPHINCS+ verify)  │     + signature verification   │
│  └─────────────────┬───────────────────────┘                                │
│                    │                                                        │
│                    ▼                                                        │
│  ┌─────────────────────────────────────────┐                                │
│  │         Validity Circuit                │                                │
│  │  public_input = keccak256(              │                                │
│  │    initial_block_number,                │                                │
│  │    initial_block_chain,                 │                                │
│  │    initial_ext_commitment,  ◄── must == latestFinalizedStateRoot         │
│  │    final_block_number,                  │                                │
│  │    final_block_chain,       ◄── must == on-chain blockHashChainAt[n]     │
│  │    final_ext_commitment,    ◄── becomes new latestFinalizedStateRoot     │
│  │    prover                               │                                │
│  │  )                                      │                                │
│  └─────────────────────────────────────────┘                                │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                          BALANCE PROOF PIPELINE                             │
│                                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │  Spend   │    │ Send Tx  │    │ Receive  │    │ Receive  │              │
│  │  Proof   │───▶│  Proof   │    │ Transfer │    │ Deposit  │              │
│  │ (solvency│    │ (block   │    │  Proof   │    │  Proof   │              │
│  │  +nonce) │    │  incl.)  │    │          │    │          │              │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘              │
│       │               │               │               │                    │
│       └───────────────┴───────────────┴───────────────┘                    │
│                               │                                            │
│                               ▼                                            │
│                    ┌──────────────────────┐                                 │
│                    │   Balance Proof      │ (recursive IVC)                 │
│                    │   (private state)    │                                 │
│                    └──────────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         WITHDRAWAL PROOF PIPELINE                           │
│                                                                             │
│  Balance Proof ──▶ Single Withdrawal ──▶ Withdrawal Chain ──▶ Final Proof   │
│  (after send)      (extract transfer)    (aggregate N)        (+ L1 state)  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## On-chain Public Input Binding

Every value in the validity proof's public inputs is bound to on-chain state:

```
┌─ On-chain Storage ───────────────────────────────────────────────────────┐
│                                                                          │
│  blockHashChainAt[n]  ◄─── postBlock() computes keccak256 of:           │
│                              prev_hash ‖ aggregator_id ‖ timestamp ‖     │
│                              local_ids ‖ tx_tree_root ‖ deposit_chain   │
│                                                                          │
│  depositHashChain     ◄─── deposit() computes keccak256 of:             │
│                              prev_hash ‖ depositor ‖ recipient ‖         │
│                              token_index ‖ amount ‖ aux_data             │
│                                                                          │
│  latestFinalizedStateRoot ◄── finalize() sets to final_ext_commitment   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
                    ▲                                    ▲
                    │ must match                         │ must match
                    │                                    │
┌─ ValidityPublicInputs ──────────────────────────────────────────────────┐
│                                                                          │
│  initialBlockNumber ──────── block number at proof start                 │
│  initialBlockChain  ──────── == blockHashChainAt[initialBlockNumber]     │
│  initialExtCommitment ────── == latestFinalizedStateRoot (chain link)    │
│  finalBlockNumber ────────── block number at proof end                   │
│  finalBlockChain  ────────── == blockHashChainAt[finalBlockNumber]       │
│  finalExtCommitment ──────── == stateRoot (the value being accepted)     │
│  prover ──────────────────── address of the proof submitter              │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
                    │
                    │ keccak256
                    ▼
┌─ Plonky2 Proof ──────────────────────────────────────────────────────────┐
│  public_input = keccak256(ValidityPublicInputs)   (single bytes32)       │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 │ must ==
                                 ▼
┌─ WHIR Statement ─────────────────────────────────────────────────────────┐
│  evaluations[0] = keccak256(ValidityPublicInputs)                        │
│  (binds WHIR proof to the same plonky2 circuit instance)                 │
└──────────────────────────────────────────────────────────────────────────┘
                                 │
                                 │ must ==
                                 ▼
┌─ Groth16 Public Inputs ────────────────────────────────────────────────┐
│  pubInputs[0] = keccak256(ValidityPublicInputs)                        │
│  (binds Groth16 proof to the same plonky2 circuit instance)            │
└────────────────────────────────────────────────────────────────────────┘
```

## L1 Contract Functions

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          IntmaxRollup.sol                                │
│                                                                         │
│  ┌─────────────────┐  Aggregators post blocks; local_ids in calldata    │
│  │  postBlock()    │  → updates blockHashChain on-chain                 │
│  │  ~81k gas       │  → blockHashChainAt[n] snapshot stored             │
│  └─────────────────┘                                                    │
│                                                                         │
│  ┌─────────────────┐  Users queue deposits                              │
│  │  deposit()      │  → updates depositHashChain on-chain               │
│  │  ~55k gas       │                                                    │
│  └─────────────────┘                                                    │
│                                                                         │
│  ┌─────────────────┐  Sequencer posts validity proof in EIP-4844 blob   │
│  │  submit()       │  → stores commitment (2 storage slots)             │
│  │  ~75k gas       │  → commitment = keccak(blobHash‖proofHash‖len‖SR)  │
│  └─────────────────┘                                                    │
│                                                                         │
│  ┌─────────────────┐  Anyone can verify and finalize                    │
│  │  finalize()     │  1. Commitment check                               │
│  │  ~1.6M gas      │  2. ValidityPIs ↔ on-chain state                  │
│  │                 │  3. WHIR evaluations[0] == keccak(ValidityPIs)     │
│  └─────────────────┘  4. KZG blob binding (EIP-2537)                    │
│                       5. WHIR proof verification                        │
│                       6. Groth16 proof verification                     │
│  ┌─────────────────┐                                                    │
│  │  verify()       │  WHIR + Groth16 (no binding, no KZG)              │
│  │  ~842k gas      │                                                    │
│  └─────────────────┘                                                    │
│                                                                         │
│  ┌─────────────────┐                                                    │
│  │  fraudProof()   │  Same as finalize() but returns bool               │
│  └─────────────────┘                                                    │
│                                                                         │
│  Dependencies:                                                          │
│  ├── BlobKZGVerifier.sol   (EIP-2537 BLS12-381 multi-point KZG opening) │
│  ├── Groth16Verifier.sol   (BN254 ecPairing-based Groth16 verification) │
│  └── sol-whir              (WHIR polynomial commitment verification)    │
└─────────────────────────────────────────────────────────────────────────┘
```

## SPHINCS+ Post-Quantum Signature Verification

The validity circuit enforces [SPHINCS+](https://github.com/InternetMaximalism/aggregated_SPHINCS_plus) (SPX-128s Poseidon) signatures in the `UpdateAccountTree` sub-circuit:

```
Per user slot i in a block:

  is_active       = (local_id_i ≠ 0)              ── not a padding slot
  should_update   = is_active AND (prev ≠ block_number)  ── first inclusion this block
  has_pk_hash     = (pk_hash ≠ [0,0,0,0])         ── user has registered a key
  should_verify   = should_update AND has_pk_hash

  if should_verify:
      assert Poseidon(pub_seed ‖ pub_root) == account_leaf.pk_hash
      assert SPHINCS+_verify(signature_i, M_i, pub_key_i) == true

  Message:  M_i = [block_number ‖ aggregator_id ‖ local_id_i ‖ tx_tree_root]
                 = 11 Goldilocks field elements = 88 bytes
```

**SPHINCS+ parameters (SPX-128s Poseidon):**

| Parameter | Value |
|-----------|-------|
| Security level | 128-bit post-quantum |
| Hash | Poseidon (Goldilocks field) |
| `N` (byte security) | 16 |
| Hypertree layers `D` | 7 |
| FORS trees `k`, height `a` | 14, 12 |
| WOTS+ chain length | 35 |
| Signature size | 7 856 bytes |
| Public key size | 32 bytes |

## Data Structures

### Account Tree

```
AccountTree (sparse Merkle tree, leaf index = user_id)

  AccountLeaf {
      index: u32,             // next empty send leaf index
      prev: BlockNumber,      // last block that updated this account
      send_tree_root: Hash,   // root of user's send tree
      pk_hash: Hash,          // Poseidon(SPHINCS+ pub_seed ‖ pub_root)
  }                           // pk_hash == 0 means unregistered (no sig required)
```

### Extended Public State (the "state root")

```
ExtendedPublicState {
    inner: PublicState {
        block_number,
        timestamp,
        account_tree_root,     ◄── includes all AccountLeaf updates
        deposit_tree_root,
        prev_public_state_root,
    },
    block_hash_chain,          ◄── keccak chain of all blocks (includes local_ids)
    deposit_hash_chain,        ◄── keccak chain of all deposits
    deposit_count,
}

state_root = Poseidon(ExtendedPublicState)   ← this is final_ext_commitment
```

### Block Hash Chain

```
block_hash_chain[n] = keccak256(
    block_hash_chain[n-1]       (32 bytes)
    ‖ aggregator_id             ( 4 bytes)
    ‖ timestamp                 ( 8 bytes)
    ‖ local_ids[0..num_users]   ( 4 × num_users bytes)   ◄── the ID list
    ‖ tx_tree_root              (32 bytes)
    ‖ deposit_hash_chain        (32 bytes)
)
```

## Project Layout

```
intmax3-zkp/
├── src/
│   ├── circuits/
│   │   ├── balance/               # Balance proof circuits (spend, send, receive, deposit)
│   │   ├── validity/
│   │   │   ├── block_hash_chain/  # Block step, update_account_tree (SPHINCS+), validity
│   │   │   └── deposit_hash_chain/# Deposit step circuit
│   │   ├── withdraw/              # Single withdrawal, chain, final proof
│   │   └── test_utils/            # BlockWitnessGenerator, BalanceWitnessGenerator,
│   │                              # sphincs_sign (native SPHINCS+ for tests)
│   ├── common/                    # Block, Deposit, Tx, UserId, trees
│   └── utils/                     # Poseidon, Merkle trees, conversion helpers
├── contracts/                     # Foundry project
│   ├── src/
│   │   ├── IntmaxRollup.sol       # Main rollup contract (postBlock, deposit, submit, finalize)
│   │   ├── BlobKZGVerifier.sol    # EIP-2537 KZG multi-point opening
│   │   └── Groth16Verifier.sol    # BN254 Groth16 verification (ecAdd/ecMul/ecPairing)
│   └── test/
│       └── IntmaxRollup.t.sol     # 16 Foundry tests
├── tests/
│   ├── e2e.rs                     # End-to-end: deposit → transfer → withdrawal → validity
│   ├── wasm_proofs.rs             # WASM browser proof tests
│   └── fixtures/                  # Pre-serialized circuit binaries (.bin)
├── index.html                     # Browser test runner UI
├── test-worker.js                 # Web Worker for WASM proof execution
├── server.js                      # HTTPS dev server (COEP/COOP headers)
├── self_certs/                    # Self-signed TLS certificates (generated locally)
└── .cargo/config.toml             # WASM target flags (atomics, SIMD, memory limits)
```

## Requirements

- Rust nightly (`nightly-2025-03-23`, managed via `rust-toolchain.toml`)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/) (for WebAssembly builds and tests)
- [Node.js](https://nodejs.org/) (for the browser test server)
- [OpenSSL](https://www.openssl.org/) (for generating self-signed TLS certificates)
- [Foundry](https://book.getfoundry.sh/) (for Solidity contract tests)
- Chrome (for browser testing; WebGPU support required for GPU acceleration)

## Build & Test

### Rust (ZKP circuits)

```bash
cargo build --release
cargo test --release          # 140 unit tests + e2e integration test
```

### WASM (Browser)

#### 1. Generate circuit fixtures (first time only)

Pre-serializes circuits to `.bin` files so the browser loads them via `from_bytes()` instead of building at runtime.

```bash
cargo run --release --bin generate_wasm_fixtures
```

This produces `tests/fixtures/*.bin` (~711MB total). Requires 32GB+ RAM.

#### 2. Generate self-signed TLS certificates

HTTPS is required for `SharedArrayBuffer` (COEP/COOP headers only work over HTTPS).

```bash
mkdir -p self_certs
openssl req -x509 -newkey rsa:2048 \
  -keyout self_certs/key.pem \
  -out self_certs/cert.pem \
  -days 365 -nodes \
  -subj '/CN=localhost'
```

#### 3. Build WASM

```bash
# CPU-only
wasm-pack build --release --target web

# With WebGPU acceleration (recommended)
wasm-pack build --release --target web -- --features gpu_merkle
```

#### 4. Install dependencies and start server

```bash
npm install
node server.js
```

#### 5. Run in browser

Open https://localhost:8000 in Chrome (accept the self-signed certificate).

- **Run Withdrawal Proof** — full withdrawal proof pipeline (deposit, spend, send-tx, single withdrawal, chain step, chain final)
- **Run Balance Processor Flow** — balance processor flow with deposit, spend, send-tx, and receive-transfer

### Solidity (L1 contracts)

```bash
cd contracts
forge install                 # install sol-whir, forge-std dependencies
forge test -vvv               # 16 tests
```

## Browser Proving Architecture

The browser proving setup uses three optimization layers on top of WASM:

| Layer | Speedup | How |
|-------|---------|-----|
| SIMD128 | ~2-4x | Field arithmetic acceleration via 128-bit vector instructions |
| Multi-threading | ~4-8x | Web Workers + `wasm-bindgen-rayon` thread pool |
| WebGPU | ~4-16x | GPU Poseidon hashing for FRI Merkle trees during `prove()` |

Circuits are pre-serialized offline (`generate_wasm_fixtures`) and loaded via `from_bytes()`. This eliminates runtime circuit construction — only `prove()` methods and `WithdrawalProcessor::new()` run at runtime in the browser.

### Key files

| File | Purpose |
|------|---------|
| `src/lib.rs` | `#[wasm_bindgen]` entry points: `run_single_withdrawal_proof()`, `run_balance_processor_flow()`, `init_gpu_merkle()` |
| `.cargo/config.toml` | WASM target flags (atomics, SIMD, 4GB max memory, 16MB stack) |
| `index.html` | Browser test runner UI |
| `test-worker.js` | Web Worker: WASM init, thread pool, GPU init, proof dispatch |
| `server.js` | HTTPS dev server with COEP/COOP headers for SharedArrayBuffer |

### WASM memory constraints

WASM32 has a **4GB hard limit** on linear memory. The proof pipeline uses ~4GB at peak. Key mitigations:
- **Strategic `drop()` calls** in `src/lib.rs` — circuit data, witnesses, and proofs are freed as soon as no longer needed
- **Memory-pressure CPU fallback** — GPU Merkle falls back to CPU when WASM memory exceeds 3.5GB
- **Zero-copy GPU readback** — hashes read on-the-fly from mapped staging buffer instead of allocating intermediate Vecs

## Benchmarks

### ZKP Proof Generation (release mode, Apple M-series)

| Proof | Time |
|-------|------|
| Deposit balance proof | 1.16 s |
| Spend proof (internal transfer) | 0.28 s |
| Send-tx proof (internal transfer) | 1.14 s |
| Receive-transfer proof | 1.43 s |
| Spend proof (withdrawal) | 0.26 s |
| Send-tx proof (withdrawal) | 1.12 s |
| Single withdrawal proof | 1.50 s |
| Withdrawal chain proof | 2.68 s |
| Withdrawal final proof | 2.31 s |
| Block hash-chain proof (block 1) | 8.06 s |
| Block hash-chain proof (block 2) | 5.27 s |
| Block hash-chain proof (block 3) | 5.43 s |
| Validity proof | 2.28 s |
| **End-to-end total** | **~83 s** |

### L1 Contract Gas Costs

| Function | Gas | Storage Writes |
|----------|-----|---------------|
| `postBlock()` | ~81k | 2 slots (blockHashChain, blockHashChainAt[n]) |
| `deposit()` | ~55k | 1 slot (pendingDepositHashChain) |
| `submit()` | ~75k | 2 slots (commitment, submitter+finalized) |
| `finalize()` | ~1.6M | 2 slots (finalized flag, latestFinalizedStateRoot) |
| `verify()` | ~842k | 0 (view) |

> **Note on gas costs:** WHIR, Groth16, and KZG precompiles are currently mocked in Foundry tests
> (see "Current Limitations" below). Real gas costs will differ once live proofs are integrated.

## Current Limitations and TODO

### Mocked proof verification in tests

The Foundry tests currently **mock** the following precompile / external calls:

| Component | What is mocked | Why |
|-----------|---------------|-----|
| **WHIR** | `WhirVerifierWrapper.verify()` returns `true` | The WHIR proof fixture from sol-whir is a standalone test polynomial, not a wrapped Plonky2 proof. For `finalize()` tests we mock the wrapper so that the patched `statement.evaluations[0]` (which carries the plonky2 public input hash) passes without a real WHIR prover. |
| **Groth16** | BN254 `ecPairing` precompile (0x08) returns `1` | No Groth16 proving key or wrapper circuit exists yet. The `Groth16Verifier.sol` library is correct (standard 4-pairing check using ecAdd/ecMul/ecPairing), but there is no circuit that wraps Plonky2 verification into an R1CS suitable for Groth16 proving. |
| **KZG** | BLS12-381 precompiles (0x0b, 0x0d, 0x11) return valid | EIP-2537 precompiles are not available in Foundry's EVM. The `BlobKZGVerifier.sol` library is correct but can only be tested on a live Pectra-enabled chain. |

The `verify()` test for a standalone WHIR proof **does use the real WHIR verifier** (not mocked) and passes against the sol-whir test fixture. Only the `finalize()` / `fraudProof()` pipeline mocks WHIR because the statement must carry the plonky2 public input hash.

### What is needed to remove the mocks

The recursive proof pipeline is being built in [whirtest](https://github.com/leohio/whirtest):

```
Plonky2 validity proof
        │
        ├──▶ WHIR wrapper (polynomial commitment of the Plonky2 proof)
        │    └── prover: encode proof as polynomial, commit, prove
        │    └── verifier: sol-whir on-chain (already integrated)
        │
        └──▶ Groth16 wrapper (succinct SNARK of the Plonky2 verifier)
             └── circuit: Plonky2 verifier expressed as R1CS/Circom or Gnark
             └── setup: Groth16 trusted setup for the wrapper circuit
             └── prover: generate Groth16 proof with Plonky2 public inputs
             └── verifier: Groth16Verifier.sol on-chain (already integrated)
```

Once the whirtest repository produces real WHIR and Groth16 proofs that wrap
a Plonky2 validity proof:

1. Replace `_mockWhirVerifierTrue()` with the real WHIR proof whose
   `statement.evaluations[0] == keccak256(ValidityPublicInputs)`.
2. Replace `_mockGroth16Pairing()` / `_dummyGroth16()` with a real Groth16
   proof and verifying key whose `pubInputs[0] == keccak256(ValidityPublicInputs)`.
3. Replace `_mockBLSPrecompiles()` with real KZG opening proofs (requires
   Pectra-enabled testnet or mainnet fork).

No changes to `IntmaxRollup.sol` are required — the contract already enforces
the full 6-step verification pipeline. Only the test fixtures need to be
updated with real proofs.

## Dependencies

| Crate / Library | Purpose |
|-----------------|---------|
| [plonky2](https://github.com/InternetMaximalism/Lita-Plonky2) (Lita fork, `wasm-zkp3` branch) | ZK proof system (FRI-based STARK) with WebGPU support |
| [plonky2_u32](https://github.com/lita-xyz/plonky2-u32), [plonky2_bn254](https://github.com/lita-xyz/plonky2_bn254), [plonky2_keccak](https://github.com/lita-xyz/plonky2_keccak) | Extension circuits (lita-xyz forks) |
| [sphincsplus-circuits](https://github.com/InternetMaximalism/aggregated_SPHINCS_plus) | In-circuit SPHINCS+ signature verification |
| [sphincsplus-poseidon](https://github.com/InternetMaximalism/aggregated_SPHINCS_plus) | Native SPHINCS+ hash primitives |
| [sol-whir](https://github.com/leohio/whirtest) | On-chain WHIR polynomial commitment verification |
| [forge-std](https://github.com/foundry-rs/forge-std) | Foundry test framework |
