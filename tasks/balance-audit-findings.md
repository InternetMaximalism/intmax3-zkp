# intmax3 Balance Subsystem — Audit Findings

**Date:** 2026-04-20
**Scope:** `src/circuits/balance/**` and its dependencies in `src/common/trees/**`, `src/utils/trees/**`.
**Method:** Static review following `/Users/plasma/.claude/plans/glowing-waddling-crystal.md`. Each hypothesis confirmed/invalidated by reading the cited circuit code.

## Summary

| ID | Severity | Title | Status |
|---|---|---|---|
| BAL-CRIT-001 | **Critical** | Duplicate nullifier insertion via empty position in `IndexedInsertionProof` | **Fixed (regression tests pass, e2e pass)** |
| BAL-INFO-01 | Info | `spend_circuit` does not carry `user_id`/pubkey — binding relies on private_commitment chain | Invalidated (safe by design) |
| BAL-INFO-02 | Info | `send_tx_circuit` accepts `is_valid = false` spend proofs with no private state advancement | Invalidated (defense-in-depth OK) |
| BAL-INFO-03 | Info | `update_private_state` does not require "empty" leaf on asset tree updates | Invalidated — asset tree is sparse-updated by index, existence is implicit |
| BAL-INFO-04 | Info | `calculate_recipient_from_user_id` only replaces 1 tag byte after Poseidon | Invalidated — 248-bit collision resistance remains, domain-separation intact |

Only **one** finding is live. It is Critical and directly enables fund loss.

---

## BAL-CRIT-001 — Duplicate nullifier insertion via empty position in `IndexedInsertionProof`

### Fix applied (2026-04-20)

`src/utils/trees/indexed_merkle_tree/leaf.rs` `impl Leafable for IndexedMerkleLeaf { fn empty_leaf() }` changed from `Self::default()` (all zeros — same as the sentinel) to:

```rust
Self {
    next_index: u64::MAX,
    key: U256::from_u32_slice(&[u32::MAX; 8]).expect(...),
    next_key: U256::default(),
    value: 0,
}
```

Effects:
- Every unoccupied tree position now stores a hash that differs from the sentinel's hash (the sentinel is still `IndexedMerkleLeaf::default()`, pushed explicitly by `IndexedMerkleTree::new`).
- An attacker trying the original attack (presenting `prev_low_leaf = (0, 0, 0, 0)` at an empty slot) fails the Merkle-layer check: `low_leaf_proof.verify` sees `default.hash() != empty_leaf.hash()` at empty positions.
- An adapted attacker presenting `prev_low_leaf = empty_leaf` (the new non-zero value) passes the Merkle layer but fails the bound check `prev_low_leaf.key < new_key`, because `key = U256::MAX`.
- `tests/nullifier_duplicate_insertion_poc.rs` converted into two regression tests; both pass — they explicitly assert the malicious witness is rejected.
- `cargo test --lib --release utils::trees` — 45/45 pass. `test_indexed_merkle_tree_insertion` still passes — normal insertion path unaffected.
- `cargo test --lib --release balance::` — 11/11 pass. `cargo test --lib --release withdraw::` — 4/4 pass. `cargo test --lib --release validity::` — 10/10 pass.
- `cargo test --test e2e --release e2e_deposit_validity_withdrawal` — pass. Full deposit → validity → withdrawal pipeline still works end-to-end.

### Severity
**Critical** — unbounded inflation of a user's L2 balance; arbitrary withdrawal.

### Affected files
- `src/utils/trees/indexed_merkle_tree/insertion.rs:129-205` (native `get_new_root`/`verify`)
- `src/utils/trees/indexed_merkle_tree/insertion.rs:271-321` (circuit `get_new_root`)
- `src/utils/trees/indexed_merkle_tree/leaf.rs:46-56` (`empty_leaf() == default()`)
- `src/utils/trees/indexed_merkle_tree/mod.rs:25-30` (`IndexedMerkleTree::new` pushes `default()` as the sentinel)
- `src/common/trees/nullifier_tree.rs` (thin wrapper used by receive_transfer and receive_deposit)

Callers that rely on this primitive and are therefore **all exploitable**:
- `src/circuits/balance/receive_transfer_circuit.rs` — transfer nullifier insertion
- `src/circuits/balance/receive_deposit_circuit.rs` — deposit nullifier insertion
- `src/circuits/balance/common/update_private_state.rs:138-142` — shared gadget for both

### Root cause

`IndexedMerkleLeaf::empty_leaf()` returns `Self::default()` — all zeros. In `IndexedMerkleTree::new(height)` the tree pushes `IndexedMerkleLeaf::default()` into position 0 as a sentinel. Because
```
sentinel_hash == IndexedMerkleLeaf::default().hash() == empty_leaf.hash()
              == MerkleTree::zero_hashes[0]
```
every **unused** position in the tree has the exact same leaf hash as the sentinel. A prover can therefore present any unused position as the "previous low leaf" (`prev_low_leaf`) required by the insertion proof.

`IndexedInsertionProof::get_new_root` performs four checks:
1. `prev_low_leaf.key < key` — passes for any nonzero key because `prev_low_leaf = empty_leaf = (0,0,0,0)`.
2. `key < prev_low_leaf.next_key || prev_low_leaf.next_key == 0` — passes via the "null terminator" clause (`next_key == 0`).
3. `low_leaf_proof.verify(prev_low_leaf, low_leaf_index, prev_root)` — passes because every empty position genuinely hashes to `empty_leaf.hash()`.
4. `leaf_proof.verify(empty_leaf, self.index, temp_root)` — passes for the same reason on another empty position.

Crucially, **no constraint ever checks that `prev_low_leaf` is the unique predecessor of `key` in the linked list**. The tree's linked-list invariant is assumed, never verified. The prover is free to carve out an isolated sub-chain `(empty_pos_A) -> (empty_pos_B)` that shares the same `key` as an already-inserted leaf.

### Proof of concept

A native-Rust integration test was added at `tests/nullifier_duplicate_insertion_poc.rs`. It:
1. Reconstructs the tree state after a legitimate insertion of nullifier `N`.
2. Builds a malicious `IndexedInsertionProof` that uses `empty_leaf` as `prev_low_leaf` and two unused positions (2 and 3) for `low_leaf_index`/`index`.
3. Calls `IndexedInsertionProof::get_new_root(N, 0, root_after_legit)` — it **succeeds** and returns a new root.
4. Asserts that the resulting tree has two leaves with `key == N` (the original at position 1 and the duplicate at position 3), confirming the linked list is broken.
5. Generalises to several different keys and position pairs to rule out a pathological single case.

Run:
```
cargo test --test nullifier_duplicate_insertion_poc --release
```
Result on 2026-04-20: **both tests pass** — the bug is concretely reproducible.

The circuit `get_new_root` (`insertion.rs:271-321`) is a direct translation of the native logic: every step (`is_lt`, `assert_one`, `merkle_proof.verify`, `get_root`) has the same semantics. Any proof that passes the native check will also pass the circuit check with an appropriately constructed witness.

### Adversary scenario (end-to-end fund loss)

1. Alice has legitimately received one transfer/deposit for amount `X` of token `T`. Her private state has asset_tree[T] = X, nullifier_tree contains one legit entry for the transfer's nullifier `N`.
2. Alice constructs a malicious `receive_transfer` (or `receive_deposit`) witness that reuses the same transfer and nullifier `N`:
   - The witness references the same block / same tx / same transfer leaf (everything upstream validates).
   - The asset-tree update adds another `X` to asset_tree[T].
   - The nullifier-tree update uses the **malicious `IndexedInsertionProof` described above**, inserting `N` a second time into two empty positions.
3. The `receive_transfer_circuit` (or `receive_deposit_circuit`) accepts the witness because the circuit's nullifier insertion gadget (`NullifierInsertionProofTarget::get_new_root` → `IndexedInsertionProofTarget::get_new_root`) does not detect the duplicate.
4. Alice now holds a balance proof with asset_tree[T] = 2X.
5. Steps 2–4 can be repeated `N` times; the cost is O(1) per iteration because every unused slot in the 2^32 nullifier tree is fair game.
6. Alice spends the inflated balance and withdraws via the existing withdrawal pipeline. The rollup contract pays out `N·X` of token `T` even though only `X` was ever deposited or sent.

This attack is feasible against **any** user who ever received at least one transfer/deposit; it requires only the ability to construct a zk witness, which every user by assumption has.

### Remediation options (not implemented — left to maintainers)

Each option below eliminates the ambiguity between sentinel and empty positions, but they differ in invariants.

1. **Change `empty_leaf` to a non-default value**: set `empty_leaf()` to something like `IndexedMerkleLeaf { next_index: u64::MAX, next_key: U256::MAX, ..default() }` so empty positions hash differently from any valid insertion proof's `prev_low_leaf`. Requires updating `zero_hashes` computation and all tests.
2. **Assert `low_leaf_index < leaves_count`**: add a monotonic "leaves inserted" counter to the public inputs and range-check `low_leaf_index < count` inside the circuit. Requires carrying `count` through every caller (nullifier tree, account tree, etc.).
3. **Prove non-membership of `key`**: the existing IMT design intends `prev_low_leaf` to also be a non-membership witness for `key`, but fails to enforce that `prev_low_leaf` is the *actual* predecessor. A stronger construction (e.g., proving both that the key is absent from every relevant slot, or using an append-only linked-list accumulator that verifies chain consistency) would close the gap. Substantially more work.
4. **Use a "sparse set" primitive**: replace `IndexedMerkleTree` for nullifiers with a Merkle-tree-backed set that stores `key → 1` and requires the insertion to prove that the old leaf at `Hash(key) mod 2^h` was empty. Incompatible with the current tree schema.

Option 1 is the smallest diff and the most likely to get the fix landed quickly; option 2 is the most robust. Option 3 is what the paper-level design should always have done.

### Scope propagation
- Nullifier tree (receive_transfer, receive_deposit) — **directly exploitable**.
- Account tree — uses `SparseMerkleTree<AccountLeaf>` (see `src/common/trees/account_tree.rs:145`), **not** `IndexedMerkleTree`. **Not affected by this specific bug** but should be audited separately for its own soundness.
- Any other consumer of `IndexedMerkleTree` must be checked: `grep -R IndexedMerkleTree src/` shows only the nullifier tree uses it today.

---

## Invalidated hypotheses (kept for audit trail)

### BAL-INFO-01 — spend_circuit lacks explicit signer binding (H-5)

Reviewed `src/circuits/balance/spend_circuit.rs`. Spend PIs carry `(prev_private_commitment, new_private_commitment, tx, is_valid)` but no `user_id`/pubkey. Authentication happens at the balance-proof level: `send_tx_circuit.rs:200` connects `prev.user_id == tx_settlement.user_id`, and `tx_settlement` separately proves the `(user_id, tx)` tuple is present in a block via the account tree's send_tree. At validity-chain level, that block's local_ids are bound to SPHINCS+ signatures over the corresponding pks. The chain is complete — the balance layer doesn't need to know about pubkeys directly. **Invalidated.**

### BAL-INFO-02 — send_tx path when `spend_pis.is_valid = false` (H-2)

Reviewed `src/circuits/balance/send_tx_circuit.rs:216-227` and spend circuit `is_valid` derivation (`spend_circuit.rs:183`: `is_valid = (tx_nonce == prev.nonce)`). When `is_valid` is false, `send_tx` keeps `prev.private_commitment` and `prev.block_r`. The public_state advances but the private state is truly unchanged — no spend is applied, no asset-tree update, no sent_tx_tree entry committed to. An "invalid send" therefore cannot be replayed into double-spend. **Invalidated.**

### BAL-INFO-03 — asset tree update does not check the leaf was previously empty (H-7)

Reviewed `src/circuits/balance/common/update_private_state.rs:144-153`. The asset tree is **dense by index** (index = `token_index`; every index has a balance, defaulting to 0). `asset_merkle_proof.verify(prev_balance, token_index, prev_root)` constrains that `prev_balance` is the value **currently** stored at `token_index`. The new leaf is `prev_balance + amount` written back at the same index. There is no need for an "empty" check because this is an in-place update, not an insertion. **Invalidated.**

### BAL-INFO-04 — recipient hash tag-byte overwrite (H-1)

Reviewed `src/circuits/balance/common/recipient.rs:29-55`. `calculate_recipient_from_user_id` computes `H = Poseidon(USER_ID_DOMAIN, user_id, salt)` then replaces `H[0]` with `USER_ID_TAG` (=1) to domain-separate from the address recipient variant. The overwrite reduces the effective collision-resistance of the recipient from 256 bits to 248 bits — still far above the 128-bit security threshold. `user_id.value` (one Goldilocks field element, u63) is absorbed whole; `salt` is `PoseidonHashOut` (4 field elements, ~256 bits entropy). Preimage attack on the recipient (finding `(user_id', salt')` hashing to a given recipient) costs ~2^248 Poseidon evaluations — infeasible. **Invalidated.**

---

## Files examined (in scope, clean on this pass)

| File | Verdict |
|---|---|
| `balance_circuit.rs` | Sound IVC wrapper; PIs propagated via `register_public_inputs` |
| `balance_pis.rs` | PI serialization consistent; bytewise layout matches on-chain consumers |
| `balance_processor.rs` | Orchestrator, not a constraint source |
| `send_tx_circuit.rs` | Block-r monotonicity and private_commitment chain correct (BAL-INFO-02) |
| `spend_circuit.rs` | Solvency, nonce-inc, sent-tx empty-slot check all present |
| `common/tx_settlement.rs` | Verifies spend proof + account state chain; not re-audited in detail but structurally sound |
| `common/update_private_state.rs` | Asset update correct (BAL-INFO-03); **vulnerable via nullifier_proof → BAL-CRIT-001** |
| `common/update_public_state.rs` | Public state merkle transition verified |
| `common/recipient.rs` | Recipient hash binding safe (BAL-INFO-04) |
| `common/deposit_witness.rs` | Not deeply re-audited; structurally clean |
| `common/transfer_witness.rs` | Not deeply re-audited; structurally clean |
| `common/account_state.rs` | Not deeply re-audited; structurally clean |

## Files NOT re-audited in this pass (follow-up recommended)

- `switch_board.rs` (one-hot dispatch; spot-check showed `assert_one` is present but full PI-per-branch flow was not traced end-to-end)
- `receive_transfer_circuit.rs` (1043 lines; only read enough to confirm it calls the nullifier insertion gadget — the BAL-CRIT-001 exploit only requires this)
- `receive_deposit_circuit.rs` (690 lines; same)
- `account_tree.rs` / sparse-merkle tree circuit (out of the balance scope, but should be audited before production for its own potential soundness issues — see H-similar bugs below)

## Cross-cutting follow-ups

- `src/common/trees/account_tree.rs` uses `SparseMerkleTree`. It is NOT affected by BAL-CRIT-001 but should be independently audited — especially whether inserting an `AccountLeaf` at `user_id` requires proving the old leaf was `empty_leaf` and whether `AccountLeaf::default()` collides with any legitimate state.
- The same indexed-merkle-tree primitive is used nowhere else in the current source, but if it is ever used for sent_tx_tree, deposit_tree, or any other uniqueness tree, BAL-CRIT-001 applies verbatim. Grep before extending.

## Reproduction artifacts

- `tests/nullifier_duplicate_insertion_poc.rs` — self-contained integration test, exercises the bug purely via public API with no circuit build (native verification suffices because the native `get_new_root` mirrors the circuit).

---

## Next steps

1. Present BAL-CRIT-001 to the maintainers with this report and the PoC test.
2. Choose a remediation (options 1 or 2 recommended).
3. After fix, extend the audit to the follow-up files listed above.
4. Re-run the PoC against the fix — it must fail.
5. Revisit the audit plan in `/Users/plasma/.claude/plans/glowing-waddling-crystal.md` for the other four subsystems (validity/block, validity/signature, withdraw, deposit_chain) and spawn attacker subagents per that plan.
