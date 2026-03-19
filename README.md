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
│  │  (mocked WHIR)  │  3. WHIR evaluations[0] == keccak(ValidityPIs)    │
│  └─────────────────┘  4. KZG blob binding (EIP-2537)                    │
│                       5. WHIR proof verification                        │
│  ┌─────────────────┐                                                    │
│  │  verify()       │  Pure WHIR check (no binding, no KZG)              │
│  │  ~804k gas      │                                                    │
│  └─────────────────┘                                                    │
│                                                                         │
│  ┌─────────────────┐                                                    │
│  │  fraudProof()   │  Same as finalize() but returns bool               │
│  └─────────────────┘                                                    │
│                                                                         │
│  Dependencies:                                                          │
│  ├── BlobKZGVerifier.sol  (EIP-2537 BLS12-381 multi-point KZG opening)  │
│  └── sol-whir (WHIR polynomial commitment verification)                 │
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
│   │   └── BlobKZGVerifier.sol    # EIP-2537 KZG multi-point opening
│   └── test/
│       └── IntmaxRollup.t.sol     # 16 Foundry tests
├── tests/
│   └── e2e.rs                     # End-to-end: deposit → transfer → withdrawal → validity
└── docs/
    └── spec.md                    # Protocol specification
```

## Requirements

- Rust nightly (`nightly-2025-03-23`, managed via `rust-toolchain.toml`)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/) (for WebAssembly builds and tests)
- [Foundry](https://book.getfoundry.sh/) (for Solidity contract tests)

## Build & Test

### Rust (ZKP circuits)

```bash
cargo build --release
cargo test --release          # 140 unit tests + e2e integration test
```

### WASM

```bash
cargo run -r --bin generate_wasm_fixtures
wasm-pack test --release --firefox --headless
```

### Solidity (L1 contracts)

```bash
cd contracts
forge install                 # install sol-whir, forge-std dependencies
forge test -vvv               # 16 tests
```

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
| `verify()` | ~804k | 0 (view) |

## Dependencies

| Crate / Library | Purpose |
|-----------------|---------|
| [plonky2](https://github.com/0xPolygonZero/plonky2) | ZK proof system (FRI-based STARK) |
| [sphincsplus-circuits](https://github.com/InternetMaximalism/aggregated_SPHINCS_plus) | In-circuit SPHINCS+ signature verification |
| [sphincsplus-poseidon](https://github.com/InternetMaximalism/aggregated_SPHINCS_plus) | Native SPHINCS+ hash primitives |
| [sol-whir](https://github.com/leohio/whirtest) | On-chain WHIR polynomial commitment verification |
| [forge-std](https://github.com/foundry-rs/forge-std) | Foundry test framework |
