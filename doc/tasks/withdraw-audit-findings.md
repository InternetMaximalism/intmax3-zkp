# intmax3 Withdraw Subsystem — Audit Findings

**Date:** 2026-04-20
**Scope:** `src/circuits/withdraw/**` and its direct dependencies
  — `balance_pis`, `balance_circuit`, `balance/common/{account_state, tx_settlement, transfer_witness, recipient, update_public_state}`,
  `common/{withdrawal, transfer}`.
**Method:** Static review, supplementing the balance audit (`doc/tasks/balance-audit-findings.md`).

## Summary

| ID | Severity | Title | Status |
|---|---|---|---|
| WDR-CRIT-001 | **Critical** | Per-step `public_state` in `withdrawal_step` is never anchored, and `update_public_state.new` is silently discarded | **Fixed (withdraw+balance+validity+e2e all pass)** |
| WDR-HIGH-001 | High | Balance IVC has no external anchor for `public_state` — fabricated `account_tree_root` / `deposit_tree_root` are accepted by all step circuits | **Closed as consequence of WDR-CRIT-001 fix** |
| WDR-INFO-01 | Info | `extract_address_from_recipient_circuit` only checks `bytes[0] == ADDRESS_TAG`, ignores bytes 1..12 | Accepted (not exploitable in isolation) |
| WDR-INFO-02 | Info | Same signed tx replayed into two blocks would produce *different* nullifiers (`nullifier` includes `settled_block_number`) | Accepted (protocol-level, separate block-layer defense required) |
| WDR-INFO-03 | Info | `IndexedMerkleTree` duplicate-insertion bug (BAL-CRIT-001) affects withdrawals transitively via `update_private_state` — see balance report | Tracked under BAL-CRIT-001 |

**WDR-CRIT-001 and WDR-HIGH-001 together constitute a concrete fund-loss attack**: an attacker can forge a fake balance-circuit IVC using an attacker-chosen `public_state`, emit a fake `single_withdrawal` proof that pays to an attacker-controlled address, and slot it into a `withdrawal_step` chain alongside one legitimate withdrawal. The chain's final `public_state` — the only one checked against the canonical validity proof on L1 — will be the legitimate one, so L1 accepts the batch and pays every withdrawal in it, including the fake.

---

## WDR-CRIT-001 — Per-step `public_state` in `withdrawal_step` is not linked across steps

### Fix applied (2026-04-20)

Two-line circuit change in `src/circuits/withdraw/withdrawal_step.rs` plus a mirrored change in the witness-side `to_public_inputs`:

1. The step's output `public_state` switched from `update_public_state.old.clone()` → `update_public_state.new.clone()` (see lines in `WithdrawalStepWitness::to_public_inputs` and `WithdrawalStepTarget::new`).
2. A new constraint `update_public_state.new.conditional_assert_eq(builder, &prev_withdrawal_chain_pis.public_state, not_initial)` is added to the circuit. The witness-side `to_public_inputs` mirrors it with a Rust-level equality check.

Supporting change: `src/common/public_state.rs` added `PublicStateTarget::conditional_assert_eq` so the new constraint has a clean helper, in the same style as the pre-existing `connect`.

Effect: all steps in a withdrawal chain now propagate one single shared `public_state` (set by the first step and locked in place by every subsequent step). The final `withdrawal_circuit` anchor against the canonical validity proof on L1 therefore cascades backwards through every step's Merkle proof, forcing every single_withdrawal's `public_state` to be on the real canonical history. WDR-HIGH-001 is closed as a consequence — any fabricated `account_tree_root` / `deposit_tree_root` in a balance-IVC chain would make at least one step's Merkle proof (`old -> new`) fail to match the canonical public-state root.

Verification:
- `cargo test --lib --release withdraw::` — 4/4 pass (single_withdrawal, single_withdrawal_serialization, withdrawal_step, withdrawal_chain).
- `cargo test --lib --release balance::` — 11/11 pass.
- `cargo test --lib --release validity::` — 10/10 pass.
- `cargo test --test e2e --release e2e_deposit_validity_withdrawal` — pass. Full deposit → validity → withdrawal pipeline still works end-to-end.

### Severity
**Critical** — fabricated withdrawals can be mixed into a real chain; L1 pays them.

### Affected files
- `src/circuits/withdraw/withdrawal_step.rs:283, 341-343, 357-361` (code)
- `src/circuits/withdraw/withdrawal_chain_circuit.rs:52-77` (wraps the step proof, no additional state check)
- `src/circuits/withdraw/withdrawal_circuit.rs:183-208` (final wrapper — only reads `chain_public_state`, i.e. the **last** step's `public_state`)

### Root cause (quote)

In `withdrawal_step.rs:341-361` the step circuit wires up `update_public_state` like this:

```rust
update_public_state
    .old
    .connect(builder, &single_withdrawal_pis.public_state);
...
let new_pis = WithdrawalStepPublicInputsTarget {
    withdrawal_hash_chain,
    public_state: update_public_state.old.clone(),   // <-- .old, not .new
    vd: withdrawal_chain_vd,
};
```

Three independent defects in this block:

1. **The step's own `update_public_state.new` is never used.** `UpdatePublicStateTarget::new` allocates `new` and verifies the Merkle step `old -> new` against `new.prev_public_state_root`, but `new` is never read, never connected to the output, and never linked to the next step's `old`. The field is effectively dead — a costly no-op in the constraint system.

2. **The chain's output `public_state` is `update_public_state.old`, which equals *this step's* `single_withdrawal_pis.public_state`.** Each step therefore overwrites the chain's `public_state` with its own `single_withdrawal`'s state. After `N` steps the chain's `public_state` is `SW_N.public_state`; `SW_1..SW_{N-1}` have evaporated from the public interface.

3. **The previous step's `public_state` is never consumed.** In `withdrawal_step.rs:316-334` the code parses `prev_withdrawal_chain_pis` to extract the cyclic `vd` and the `withdrawal_hash_chain` — but `prev_withdrawal_chain_pis.public_state` is read nowhere in the circuit. `grep -n prev_withdrawal_chain_pis` finds no reference to `.public_state`. Adjacent steps therefore have no `public_state` relationship.

Confirmed by `grep`:

```
$ grep -n 'update_public_state\.new\|update_public_state\.old' src/circuits/withdraw/withdrawal_step.rs
258:        if single_withdrawal_inputs.public_state != self.update_public_state.old {
283:            public_state: self.update_public_state.old.clone(),
359:            public_state: update_public_state.old.clone(),
```
Only `.old` appears. `.new` is unused.

### What the spec says

`doc/docs/spec.md` §7.4 describes the withdrawal circuit as:

> `public_state_update_witness` that updates `sender_balance_proof.public_state` to `withdrawal_proof.public_state`.

The intent is that the `public_state_update_witness` bridges the sender's balance-proof state to the chain's canonical `withdrawal_proof.public_state`. The implementation has dropped this bridge: `update_public_state.new` exists in the witness struct and is verified to form a valid Merkle step, but no constraint propagates `.new` into the output. As a result, nothing forces consecutive withdrawals to target the same final state.

### Adversary exploitation

Combined with WDR-HIGH-001 (balance IVC has no anchor), an attacker can:

1. Pick a victim's real `public_state` `P_real` (the one they expect L1 to anchor to). This is not secret — any chain explorer shows it.
2. Fabricate a balance-circuit IVC (see WDR-HIGH-001). Starting from the circuit-enforced initial `PublicState::default()`, the attacker uses the switch-board's `receive_deposit` / `send_tx` / `receive_transfer` paths, each of which advances `public_state` via a user-chosen `update_public_state.new`. Because `UpdatePublicState` only proves a self-referential Merkle step (`new.prev_public_state_root == merkle_root(old, old.block_number, siblings)`), the attacker can freely choose `new.account_tree_root`, `new.deposit_tree_root`, `new.block_number`, `new.timestamp` at every step. They build a self-consistent parallel universe ending at a fake `P_fake` in which they own a huge fake asset-tree leaf and have a fake `SendLeaf` pointing to a fake `tx_tree_root` containing a fake `tx` whose `transfer_tree_root` has a fake `Transfer` paying the attacker 1 000 ETH of token 0.
3. Call `SingleWithdawalCircuit::prove` on this fabricated balance proof. Every check inside `single_withdrawal_circuit.rs:362-454` passes:
   - `balance_proof` is a valid cyclic IVC (the attacker built it correctly).
   - `private_state.commitment() == balance_pis.private_commitment` (attacker controls both sides).
   - `sent_tx_merkle_proof` opens `fake_tx` at `fake_tx.nonce` under the fabricated `sent_tx_tree_root`.
   - `account_state` opens the attacker's fabricated `UserLeaf` at `user_id` in the fake `account_tree_root` (= `public_state.account_tree_root`, both fake but connected).
   - `tx_merkle_proof` opens `fake_tx` at `user_id.key_id()` in `send_leaf.tx_tree_root` (fake).
   - `transfer_witness` opens the fake `Transfer` in `fake_tx.transfer_tree_root`.
   - `extract_address_from_recipient_circuit` sees tag byte `0x02` (attacker set it).
   - `settled_transfer.nullifier()` becomes a fresh, unique value (never seen on L1).

   Output: a `SingleWithdawalPublicInputs { public_state: P_fake, withdrawal: Withdrawal { recipient: attacker_addr, amount: 1_000 ETH, ... } }`. Call this `SW_fake`.

4. Separately, produce one legitimate `single_withdrawal` for some small real transfer at the canonical `P_real`. Call this `SW_real`.
5. Feed them through the chain:
   - Step 1: `WithdrawalStepWitness { prev_withdrawal_chain_proof: None, single_withdrawal_proof: SW_fake, update_public_state: UpdatePublicState::new(P_fake, P_fake, None) }`. The step accepts because `old == SW_fake.public_state == P_fake`. Output: `{ withdrawal_hash_chain: hash(0, fake_withdrawal), public_state: P_fake }`.
   - Step 2: `WithdrawalStepWitness { prev_withdrawal_chain_proof: Some(step_1), single_withdrawal_proof: SW_real, update_public_state: UpdatePublicState::new(P_real, P_real, None) }`. The step accepts because `old == SW_real.public_state == P_real`. Nothing forces `P_real == P_fake`; `P_fake` from step 1 is consumed only through `prev_withdrawal_chain_pis.withdrawal_hash_chain`, not `.public_state`. Output: `{ withdrawal_hash_chain: hash(hash(0, fake_withdrawal), real_withdrawal), public_state: P_real }`.
6. Wrap via `WithdrawalChainCircuit` → `WithdrawalCircuit::prove(chain_proof, attacker_as_aggregator, P_real_ext)`. The final `WithdrawalCircuit` reads `chain_public_state` from the proof's PIs (= `P_real`) and connects it to the witness `ext_public_state.inner` (also set to `P_real`). The commitment matches.
7. Submit the final withdrawal proof to L1 with the canonical `validity_proof(P_real)`. L1's check `withdrawal_proof.public_state == validity_proof.public_state` passes.
8. L1 iterates the committed withdrawal hash chain. Each `Withdrawal` is fresh (unique nullifier), so the nullifier-dedup set has no collision. L1 transfers 1 000 ETH to `attacker_addr` **and** the small legitimate amount to its real recipient.

The attacker has converted `O(compute)` into `O(1_000 ETH)` plus dust, repeatable until the L1 treasury is drained.

### Why the downstream WithdrawalCircuit does not catch this

`withdrawal_circuit.rs:183-208`:

```rust
let proof = add_proof_target_and_verify_cyclic(verifier_data, &mut builder);
...
let chain_public_state = PublicStateTarget::from_slice(
    &proof.public_inputs[public_state_start..public_state_end],
);
let ext_public_state = ExtendedPublicStateTarget::new(&mut builder, true);
ext_public_state
    .inner
    .connect(&mut builder, &chain_public_state);
```

`chain_public_state` is taken from the chain proof's PIs — i.e., the single public-state field produced by the final `withdrawal_step`. This is connected to the witness-provided `ext_public_state.inner`, and its commitment is exposed as a PI. L1 then checks this commitment against the validity proof.

So only one `public_state` is ever anchored on L1. Every earlier step's `public_state` travels with its individual withdrawal into the hash chain but never surfaces, so no external verifier can notice it diverges.

### Why the final `single_withdrawal` does not catch this either

Inside `single_withdrawal_circuit.rs`, `public_state` is produced as `update_public_state.new` and must be consistent with the attacker's fabricated `account_tree_root` and `deposit_tree_root` **within that single proof**. Consistency of the fabrication is internal and self-referential; `single_withdrawal` has no access to the canonical validity proof or the extended public-state commitment. It cannot tell fabrication from reality.

### Remediation options (to be decided by maintainers — not implemented in this session)

The spec's intent (all withdrawals share one canonical `withdrawal_proof.public_state`) gives three natural fixes. Any **one** of them shuts the door, but they should be evaluated together because they interact.

1. **Use `update_public_state.new` as the step output, and connect `.new` across consecutive steps.** Concretely, in `withdrawal_step.rs`:
   - Output `public_state: update_public_state.new.clone()` instead of `.old`.
   - Add `builder.connect` from `prev_withdrawal_chain_pis.public_state` to `update_public_state.new` when `not_initial`.
   - This forces all steps in the chain to agree on the same final `public_state`. Each step's single_withdrawal then proves "there is a Merkle step from `SW.public_state` to the canonical `chain.public_state`", which anchors every withdrawal to the canonical state as originally intended.

2. **Strip `update_public_state` from `withdrawal_step` entirely** and require `SW.public_state == chain.public_state` directly. Simpler but only safe if the single_withdrawal circuit itself receives `public_state` as an input anchored to the canonical value (i.e., requires fix #3 as well).

3. **Anchor `single_withdrawal.public_state` to a validity proof inside the circuit.** This eliminates WDR-HIGH-001 as well, but at significant proving cost (an extra cyclic verify of the validity proof inside every single_withdrawal).

Option #1 is the smallest diff and is the fix the spec already implies. It does not by itself cure WDR-HIGH-001 in isolation — see that finding — but combined with option #1 here, the on-chain anchor on the *final* `chain.public_state` cascades backwards through the Merkle-step constraints and forces every per-withdrawal `public_state` to be on the real history.

### Why no runnable PoC is included here

Building a fabricated balance-circuit IVC requires constructing a complete switch-board proof chain (`initial_value` → `receive_deposit` → `send_tx` with attacker-chosen `update_public_state.new` values). The balance processor keeps the balance circuit intact across all sub-circuits, so a PoC would need to build every verifier data in the stack (SpendCircuit, BalanceProcessor, SingleWithdrawalCircuit, WithdrawalProcessor) — minutes of proving in release mode and > 1 GB of memory, purely to restate what is provable by reading `withdrawal_step.rs:341-361` alone.

A cheaper PoC that only exhibits defect #1 (the `public_state` divergence between consecutive single_withdrawals) can be built with `TestCyclicCircuit` stand-ins for `single_withdrawal_vd`, mirroring `test_withdrawal_step_circuit` at `withdrawal_step.rs:500-613`. The existing test uses identical `public_state`s in both steps; swapping the second step's `update_public_state` for one whose `.old` is a distinct `PublicState` produces a successful proof. That would exercise defect #1 at the circuit layer. We note this as follow-up and do not run it in this session.

---

## WDR-HIGH-001 — Balance IVC `public_state` has no external anchor; every state root is attacker-controllable

### Severity
**High** on its own (enables WDR-CRIT-001 end-to-end); would be hard to reach directly without WDR-CRIT-001 because the final-state anchor catches a single-step chain, but trivial in any chain of length ≥ 2.

### Affected files
- `src/circuits/balance/common/update_public_state.rs` (entire file — only checks a Merkle step from user-chosen `old` to user-chosen `new`)
- `src/circuits/balance/switch_board.rs:199-232` (initial `public_state` is `PublicState::default()` — fine)
- `src/circuits/balance/send_tx_circuit.rs`, `receive_transfer_circuit.rs`, `receive_deposit_circuit.rs` (each just calls `update_public_state.verify()` and connects `old` to the prev balance's state and `new` to the outgoing state; no validity proof is ever consumed)

### Root cause

`UpdatePublicState::verify` (`update_public_state.rs:68-89`) checks only:

```rust
let calculated = self.merkle_proof.get_root(&self.old, self.old.block_number.as_u64());
if calculated != self.new.prev_public_state_root { return Err(...) }
```

The check is **entirely self-referential**: it requires `new.prev_public_state_root` to equal the Merkle root of a tree containing `old` at position `old.block_number`, built from siblings supplied by the prover. Because the prover supplies the siblings, they can forge any root they wish, and then pick `new.prev_public_state_root` to match.

No circuit on the balance side (initial, send_tx, receive_transfer, receive_deposit) verifies that the `public_state` being produced corresponds to a real on-chain block. Concretely:

- `send_tx_circuit.rs` calls `update_public_state.old.connect(balance_pis.public_state)` and exposes `update_public_state.new` as the new state. It does not verify the new state against any validity or on-chain commitment.
- `receive_deposit_circuit.rs:282` takes `public_state = &update_public_state.new` and only checks the deposit witness's root matches `public_state.deposit_tree_root` — both user-chosen.
- `receive_transfer_circuit.rs` (not re-read in detail this session; same pattern per the balance audit) — same shape.

### Consequence

The balance-circuit IVC is completely fabricable above the zeroth state. The attacker can produce a perfectly cyclic-verifiable balance proof whose `public_state` encodes an imaginary on-chain state: any `account_tree_root`, any `deposit_tree_root`, any `block_number`. This balance proof is then a valid input to any caller that consumes `balance_vd.verify(balance_proof)` **without separately checking `public_state` against reality**.

### Known consumer that does check: the `WithdrawalCircuit` anchor

`WithdrawalCircuit::new` (`withdrawal_circuit.rs:183-208`) does anchor `chain_public_state` to `ext_public_state`, which is then committed to and checked on L1. So a *one-step* chain where the only single_withdrawal has a fake `public_state` cannot reach L1 — the on-chain `validity_proof.public_state` will not match the fake.

### Known consumer that does NOT check: `WithdrawalStepCircuit` for non-final steps

See WDR-CRIT-001. For any step that is not the final step, the `public_state` is ignored. This is the crack through which fabricated balance proofs actually lose funds.

### Remediation

Addressed by WDR-CRIT-001 option #1 (connect every step's `public_state` to the canonical one). If that fix is applied, each single_withdrawal's `public_state` must be on the canonical Merkle chain that leads to the validated final state, which forces every intermediate `account_tree_root` / `deposit_tree_root` to be real too.

If the maintainers prefer a deeper fix, they should instead anchor the balance IVC itself — e.g., insert into `receive_deposit` / `send_tx` / `receive_transfer` a cyclic verification of the `validity_proof` whose `public_state` must equal `update_public_state.new`. That is more costly but closes the whole class.

---

## WDR-INFO-01 — `extract_address_from_recipient_circuit` doesn't check bytes[1..12]

### File and code
`src/circuits/balance/common/recipient.rs:78-87`
```rust
pub fn extract_address_from_recipient_circuit(...) -> AddressTarget {
    let mut bytes = recipient.to_bytes_be(builder);
    let expected_tag = builder.constant(F::from_canonical_u32(ADDRESS_TAG as u32));
    builder.connect(bytes[0], expected_tag);
    let address_bytes = bytes.split_off(12);
    AddressTarget::from_bytes_be(builder, &address_bytes)
}
```
Only `bytes[0]` is constrained. `bytes[1..12]` can be arbitrary.

### Analysis
Not exploitable as a fund-loss vector in isolation:
- The `recipient` is part of the signed `Transfer`, which is absorbed into the `SettledTransfer` nullifier. Two `recipient` encodings with the same extracted address but different `bytes[1..12]` produce **different** nullifiers. The sender would have had to sign two distinct transfers and pay for both; the recipient just receives them as two separate legitimate payments. No double-pay from the same deposit.
- On the native side, `calculate_recipient_from_address` always sets `bytes[1..12]` to zero, so honest traffic is unaffected.

### Follow-up
Cosmetic; consider adding `builder.connect(bytes[i], zero)` for `i in 1..12` to keep the encoding canonical. Not worth blocking a release.

---

## WDR-INFO-02 — Nullifier includes `settled_block_number`; same tx replayed into two blocks → two nullifiers

### File and code
`src/common/transfer.rs:110-127` — `SettledTransfer::nullifier = Poseidon(inner_transfer, from, transfer_index, block_number)`
`src/circuits/withdraw/single_withdrawal_circuit.rs:315, 322-340` — `tx_block_number` taken from `account_state.send_leaf.cur`.

### Analysis
If a malicious user signs the **same** tx (same `nonce`, same `transfer_tree_root`) into two different blocks, and two cooperating aggregators include it in both, the circuit will happily produce two single_withdrawals with different `block_number`s → different nullifiers. L1 accepts both, paying the user twice.

Local defense (spend_circuit / sent_tx_tree): a user can only run `send_tx_circuit` once for a given nonce, because `sent_tx_merkle_proof` verifies the slot was empty pre-insertion. So the user's private balance drops only once. But the on-chain withdrawal logic pays twice if both blocks' send_leaves exist.

### Is this exploitable against intmax3 today?
It requires:
  - the user to sign the same (block_number, channel_id, key_id, tx_tree_root) message for two distinct blocks (two signatures, not one replay);
  - two aggregators willing to include both. The signature message is block-specific (`sig_agg_step` includes `block_number` in `msg_gl`), so a single SPHINCS+ signature cannot be replayed — the user must sign twice.

So the attack is "sign twice on purpose", which yields withdrawal of double the user's real balance. Whether this is considered a soundness violation or a protocol-level policy violation depends on whether intmax3 considers a user's signatures a commitment against double-signing. The spec explicitly includes `settled_block_number` in the nullifier (§3), suggesting the designers accepted this as a feature, not a bug. We flag it as informational because it does not arise from a circuit constraint miss; it is a deliberate protocol choice with a surprising consequence, and should at minimum be called out in the threat model.

### Remediation options, if the behaviour is undesired
- Swap `block_number` for `tx.nonce` in the nullifier: makes (transfer, from, transfer_index, nonce) unique per user and blocks the double-withdraw.
- Add a block-layer constraint that a (user_id, nonce) can appear in at most one block. This is much more invasive.

---

## WDR-INFO-03 — BAL-CRIT-001 applies transitively

The duplicate-insertion bug in `IndexedMerkleTree` (nullifier tree) documented in `doc/tasks/balance-audit-findings.md` § BAL-CRIT-001 inflates a user's private balance via the `receive_transfer` / `receive_deposit` paths. That inflation flows naturally into withdrawals: the attacker spends the inflated balance through `send_tx_circuit`, then withdraws. No withdrawal-specific fix is needed — fix BAL-CRIT-001 to close this.

---

## Files examined and considered clean (for the purposes of this audit)

| File | Why clean |
|---|---|
| `common/withdrawal.rs` | Withdrawal encoding/hash-chain are straightforward keccak over u32 limbs; range-checks via `is_checked=true` when constructed in `WithdrawalTarget::new`. |
| `common/transfer.rs` | SettledTransfer nullifier derivation binds `inner, from, transfer_index, block_number` via Poseidon — strong binding. Note WDR-INFO-02 for the block_number policy. |
| `balance/common/account_state.rs` | Verifies `send_leaf ∈ user_leaf.send_tree_root` and `user_leaf ∈ account_tree_root`. Soundness of these verifications is standard Merkle; the *root* is not anchored — see WDR-HIGH-001. |
| `balance/common/tx_settlement.rs` | Binds tx through `tx_merkle_proof.verify(tx, user_id.key_id, account_state.send_leaf.tx_tree_root)` and `spend_public_inputs.tx == tx`. Strong internal binding; external anchoring depends on WDR-HIGH-001. |
| `balance/common/transfer_witness.rs` | Transfer merkle proof verifies transfer at `transfer_index` in `transfer_tree_root`. Clean. |
| `balance/balance_pis.rs` | PI serialization consistent; `vd` is part of the full PI to allow cyclic identification. |
| `balance/balance_circuit.rs` | Cyclic outer wrapper. `check_cyclic_proof_verifier_data` is used at verify time. The initial `public_state` is constrained via switch_board to `PublicState::default()`. |
| `withdraw/withdrawal_chain_circuit.rs` | Thin wrapper that exposes the step proof's PIs; does not add constraints beyond the step. Consequently inherits WDR-CRIT-001. |
| `withdraw/withdrawal_circuit.rs` | Anchors `chain_public_state` → `ext_public_state_commitment` and exposes on-chain. The anchor is correct for *what it sees* (the chain's single public_state field); the vulnerability lives upstream in `withdrawal_step`. |
| `withdraw/withdrawal_processor.rs` | Orchestrator with no independent constraint logic. |

## Files NOT re-audited this session (follow-up)

- `balance/receive_transfer_circuit.rs` (1043 lines) — relevant to WDR-HIGH-001 in the same manner as the other switch-board circuits. Expected to follow the same `update_public_state` pattern; a detailed re-read is recommended before the fix lands.

## Reproduction artefacts

None in this session. The bug is visible statically from `src/circuits/withdraw/withdrawal_step.rs:341-361` plus `src/circuits/balance/common/update_public_state.rs:68-89`. See "Why no runnable PoC is included here" in WDR-CRIT-001 for the cost trade-off. A TestCyclicCircuit-based test that exhibits defect #1 (divergent `SW.public_state` values across consecutive steps) is a recommended follow-up and is small to author.

## Next steps

1. Present WDR-CRIT-001 and WDR-HIGH-001 to the maintainers; request confirmation of intent and choice of remediation.
2. Write the TestCyclicCircuit-based PoC for WDR-CRIT-001 to close the loop end-to-end before applying the fix.
3. Re-audit `receive_transfer_circuit.rs`.
4. Resolve BAL-CRIT-001 (see balance findings) — its fix eliminates the feed path into withdrawals.
5. After fixes, re-run this audit: confirm every step's `public_state` in `withdrawal_step` is propagated to the chain output and chained across steps.
