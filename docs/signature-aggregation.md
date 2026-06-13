# Signature Aggregation & Parallel Proving

Multi-signature support and parallelized SPHINCS+ signature verification for the INTMAX3 rollup.

## Overview

The signature aggregation system enables:
1. **Multi-sig accounts** — each account can have up to 8 public keys with a configurable threshold
2. **Parallel signature verification** — independent batches of signatures are proven concurrently
3. **Parallel user tree updates** — tree updates are proven in flat parallel blocks

The combined architecture processes **1000 SPHINCS+ signatures in ~140 seconds** with 20 CPU cores.

## Account Model

### Key Set Tree

Each account has a `KeySetTree` — a Merkle tree (height 3, max 8 leaves) of public key hashes:

```
Account (user_id)
├── index: u32              (next send leaf index)
├── prev: BlockNumber       (last block number)
├── send_tree_root: Hash    (send history)
├── pk_set_root: Hash  ◄─── Merkle root of KeySetTree
└── threshold: u32     ◄─── minimum signatures required (1..8)

KeySetTree (height=3, max 8 keys)
├── leaf 0: PkLeaf { pk_hash: Poseidon(pub_seed || pub_root) }
├── leaf 1: PkLeaf { pk_hash: ... }
├── ...
└── leaf 7: PkLeaf { pk_hash: ... }
```

A transaction is authorized when `threshold` or more distinct keys have valid SPHINCS+ signatures.

## Architecture

Two independent pipelines run concurrently:

```
╔══════════════════════════════════════════════════════════════════╗
║  Pipeline 1: Signature Verification                             ║
║                                                                  ║
║  [Parallel — N workers]              [Linear — 1 worker]        ║
║                                                                  ║
║  SigBatch₁ (users 1-25)  ─┐                                    ║
║  SigBatch₂ (users 26-50) ─┼──▶ SigMerge ──▶ merge_proof        ║
║  SigBatch₃ (users 51-75) ─┤    (~0.45s/step)                   ║
║  ...                       │                                     ║
║  SigBatch₄₀ (users 976+) ─┘                                    ║
║                                                                  ║
║  Each batch: sig_verify + finalize steps (~1.4s/step)           ║
║  Account tree is READ-ONLY → full parallelism                   ║
╠══════════════════════════════════════════════════════════════════╣
║  Pipeline 2: User Tree Updates                                ║
║                                                                  ║
║  [Parallel — N workers]              [Linear — 1 worker]        ║
║                                                                  ║
║  ApplyBlock₁ (users 1-20)  ─┐                                   ║
║  ApplyBlock₂ (users 21-40) ─┼──▶ ApplyMerge ──▶ apply_proof    ║
║  ...                         │    (~0.45s/step)                  ║
║  ApplyBlock₅₀ (users 981+) ─┘                                   ║
║                                                                  ║
║  Flat circuits (no cyclic recursion) → ~0.24s/block             ║
╚══════════════════════════════════════════════════════════════════╝

Total time ≈ max(Pipeline 1, Pipeline 2) ≈ 140s with 20 workers
```

## Circuit Modules

### Sequential Pipeline (single-threaded baseline)

| Module | Purpose | Time/step |
|--------|---------|-----------|
| `sig_agg_step` | Full sequential: SPHINCS+ verify + user tree update | ~1.4s |
| `sig_agg_circuit` | Cyclic wrapper for sig_agg_step | — |
| `sig_agg_processor` | Orchestrator for sequential pipeline | — |

### Parallel Pipeline (optimized)

**Signature Verification:**

| Module | Purpose | Time/step |
|--------|---------|-----------|
| `sig_batch_step` | Parallelizable: SPHINCS+ verify + finalize (read-only tree) | ~1.4s |
| `sig_batch_circuit` | Cyclic wrapper for sig_batch_step | — |
| `sig_merge_step` | Linear: absorbs batch proofs, combines verified_users_hash | ~0.45s |
| `sig_merge_circuit` | Cyclic wrapper for sig_merge_step | — |

**User Tree Updates:**

| Module | Purpose | Time/step |
|--------|---------|-----------|
| `user_apply_block` | Flat parallel: N users' Merkle tree updates (no recursion) | ~0.24s |
| `user_apply_block_pis` | Public inputs for flat block proofs | — |
| `user_apply_step` | Linear: absorbs block proofs, chains roots | ~0.45s |
| `user_apply_circuit` | Cyclic wrapper for apply merge | — |
| `user_apply_pis` | Public inputs for merge result | — |

**Orchestrator:**

| Module | Purpose |
|--------|---------|
| `parallel_sig_processor` | Unified API for both pipelines |

## Key Design Decisions

### Why split into SigBatch + UserApply?

The original `sig_agg_step` updates the user tree during finalize. This creates a **sequential dependency**: each user's tree update changes the root, blocking the next user.

By splitting:
- **SigBatch** treats the user tree as read-only (snapshot at block start) → fully parallelizable
- **UserApply** handles tree updates separately, also parallelizable (flat proofs with pre-computed intermediate roots)

### Why flat proofs for UserApply?

Each step in a cyclic recursion chain takes ~1.4s minimum (dominated by recursive proof verification overhead). For 1000 users sequentially, that's 1400s — far too slow.

Flat proofs (no cyclic recursion) process N users in one shot. Gate count scales with N, but there's no per-step proof verification overhead. A 20-user flat block proves in ~0.24s.

### Hash chain binding

The two pipelines produce independent proofs that must be bound:

- **SigMerge** produces `verified_users_hash` — a Poseidon hash chain of all verified user IDs, combined at the batch level: `H(merge_hash || batch_hash)`
- **UserApply** produces its own `users_hash` — built per-user within each block: `H(prev || user_id)`

The on-chain verifier or a binding circuit checks that both cover the same user set.

## Benchmarks (Measured)

Single-step timings (Apple Silicon, release mode):

| Operation | Time |
|-----------|------|
| SigBatch step (sig_verify, with SPHINCS+) | 1.37-1.44s |
| SigBatch step (finalize, no SPHINCS+) | 1.36-1.38s |
| SigMerge step (absorb batch proof) | 0.44-0.45s |
| UserApplyBlock (20-slot, flat) | 0.24s |
| ApplyMerge step (absorb block proof) | 0.45s |
| Circuit construction (ParallelSigProcessor::new) | ~5.1s |

### Estimated wall-clock time for N signatures (20 workers):

| Signatures | SigBatch | SigMerge | ApplyBlock | ApplyMerge | **Total** |
|-----------|----------|----------|------------|------------|-----------|
| 100 | 14s | 1.8s | 0.24s | 2.3s | **~14s** |
| 500 | 70s | 9s | 0.6s | 11s | **~70s** |
| 1000 | 140s | 18s | 0.6s | 23s | **~140s** |

> SigBatch dominates. SigMerge and ApplyMerge are pipelined (start as soon as first batch/block completes).

## File Layout

```
src/circuits/validity/signature_aggregation/
├── mod.rs
├── sig_agg_step.rs           # Sequential: SPHINCS+ verify + tree update
├── sig_agg_pis.rs            # Sequential public inputs
├── sig_agg_circuit.rs        # Sequential cyclic wrapper
├── sig_agg_processor.rs      # Sequential orchestrator
├── sig_batch_step.rs         # Parallel: SPHINCS+ verify (read-only tree)
├── sig_batch_pis.rs          # Batch public inputs
├── sig_batch_circuit.rs      # Batch cyclic wrapper
├── sig_merge_step.rs         # Linear: merge batch proofs
├── sig_merge_pis.rs          # Merge public inputs
├── sig_merge_circuit.rs      # Merge cyclic wrapper
├── user_apply_block.rs    # Flat parallel: tree updates
├── user_apply_block_pis.rs# Block public inputs
├── user_apply_step.rs     # Linear: merge block proofs
├── user_apply_pis.rs      # Apply merge public inputs
├── user_apply_circuit.rs  # Apply merge cyclic wrapper
└── parallel_sig_processor.rs # Unified orchestrator API

src/common/
├── key_set.rs                # KeySetTree, PkLeaf, PkLeafTarget
└── trees/account_tree.rs     # UserLeaf (extended with pk_set_root, threshold)
```
