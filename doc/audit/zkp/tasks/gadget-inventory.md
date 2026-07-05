# Gadget-layer inventory — src/common/ + src/utils/ CircuitBuilder files

**Why this file exists.** The audit's file universe (tasks/todo.md) stops at
`src/circuits/`. A meta-audit found that **33 files** under `src/common/` and
`src/utils/` also use `CircuitBuilder` (grep `CircuitBuilder`, 2026-07-02) and
were neither inventoried, modeled, nor explicitly excluded — even though the
circuit models *depend* on their gate-level behavior. This file closes that
gap honestly: every file gets a status, and every unmodeled assertion-emitting
gadget gets a risk rating (what breaks if it is wrong).

**Statuses.**
- `MODELED-in-<file>` — line-by-line Lean model with soundness theorem exists.
- `NEWLY-MODELED-in-<file>` — modeled by this work package (WP-GADGET).
- `SUBSUMED` — every emitted constraint is an instance of the generic gate
  semantics already trusted/proved in `Core/Builder.lean` (connect /
  assert / select / range_check / is_equal / conditional_assert_eq) or of a
  proved generic pattern (`Plumbing.pi_roundtrip_two`, the cyclic-vd binding
  `BalanceCircuit.cyclic_sound`), with **no protocol invariant of its own**;
  justification given per row.
- `TODO (risk)` — emits a constraint pattern that is NOT covered by any model
  or generic argument; risk = what breaks if the gadget is unsound.

**Counts:** 6 MODELED · 4 NEWLY-MODELED · 20 SUBSUMED · 3 TODO
(1 of the TODOs, `poseidon_hash_out.rs`, is *partially* newly modeled).

---

## src/common/ (15 files)

| File | LOC | Constraints emitted | Coverage status |
|---|---|---|---|
| `balance_state.rs` | 704 | NONE. `settled_tx_chain_push_circuit` (:326-339) is deterministic keccak wiring; caller preconditions documented at :325. | SUBSUMED — no assertions; the chain-push semantics are modeled where consumed (`SendTxCircuit.lean`, `BalancePis.lean`) with keccak uninterpreted. |
| `block.rs` | 450 | `BlockTarget::new` (:182-219): `range_check(channel_id, CHANNEL_ID_BITS)` (:189), per-key `range_check` (:200), `U64Target::new(is_checked)` (:192). `hash_with_prev_hash` (:250-270) deterministic keccak. | SUBSUMED — only width-pinning `range_check` (generic `Builder.rangeCheck`) + deterministic hash; protocol use of the block hash is modeled in `BlockStep.lean` / `SmallBlockMessage.lean`. Caveat: soundness assumes consumers pass `is_checked=true` (same caller-audit class as F-ACCT-1; BlockStep instantiation does). |
| `channel_id.rs` | 312 | `new` (:147-156) / `from_parts` (:168-177): `range_check(·, CHANNEL_ID_BITS)`; `is_equal` (:231-237); **`enforce_ge` (:247-254) = sub + range_check(diff)**; `enforce_gt` (:256-268); `conditional_ge/gt` (:270-296). | **TODO (MEDIUM)** — see TODO-1 below. |
| `channel_registration.rs` | 359 | NONE. `channel_reg_hash_with_prev_hash_circuit` (:219-244) is deterministic keccak preimage assembly (word-aligned layout, :161-169). | SUBSUMED — no assertions; sole circuit consumer is `channel_reg_*` (explicitly out of audit scope). |
| `deposit.rs` | 243 | `DepositTarget::new` (:118-141): `range_check(token_index, 32)` (:128) + cascaded `U63/BlockNumber/Address/Bytes32/U256::new(is_checked)`. Hash/nullifier (:173-210) deterministic. | SUBSUMED — width pinning only; deposit semantics modeled in `DepositStep.lean` / `ReceiveDepositCircuit.lean`. |
| `private_state.rs` | 166 | NONE. `new` (:141-152) allocates; `commitment` (:134-139) deterministic Poseidon. | SUBSUMED — commitment determinism = uninterpreted `poseidon`; consumed model: `UpdatePrivateState.lean`. |
| `public_state.rs` | 703 | `is_equal` (:307-328): 5 per-field `is_equal` + 4-`and` tree; `connect` (:330-343); `conditional_assert_eq` (:347-369); `new(is_checked)` (:226-237) cascades range checks. | **NEWLY-MODELED-in `Zkp/Circuits/Common/PublicStateEq.lean`** — `publicStateEq_sound` proves out=1 ↔ ALL 5 fields equal (discharges F-PUBST-1). `connect`/`conditional_assert_eq` are per-limb generic gates (SUBSUMED). |
| `salt.rs` | 84 | NONE. `new` (:54-59) allocation; `connect` (:65-71) delegates to generic per-limb connect. | SUBSUMED — no assertions of its own. |
| `transfer.rs` | 282 | NONE (deterministic only). `TransferTarget::connect` (:155-164) generic connects; `poseidon_hash` (:185-190) / `SettledTransferTarget::nullifier` (:228-234) deterministic Poseidon. | SUBSUMED — **but explicitly load-bearing**: `Transfer::to_u64_vec` (:68-79) hashes the FULL 32-byte `recipient` (first in the preimage), which is fact (1) of the F-RECIP-1 adjudication (distinct padding ⇒ distinct nullifier). Verified again 2026-07-02: `:69-71` chains `recipient.to_u64_vec()` in full. Any future change truncating this layout re-opens F-RECIP-1. |
| `trees/channel_tree.rs` | 295 | `ChannelLeafTarget::new` (:242-259): `range_check(index, SEND_TREE_HEIGHT)` (:248) + cascaded U63 checks; leaf hash (:137-148) = domain tag `CHANNEL_LEAF_DOMAIN` + deterministic Poseidon. | SUBSUMED — width pinning + tagged hash; leaf semantics modeled in `AccountState.lean` (account tree = channel tree). Domain-tag distinctness relies on `natLit` faithfulness (known WP-CORE item). |
| `trees/key_tree.rs` | 172 | NONE. `MemberLeafTarget::new` (:102-110) allocation; leaf hash (:150-161) = `MEMBER_LEAF_DOMAIN` tag + deterministic Poseidon. | SUBSUMED — no assertions; circuit consumer is channel-reg (out of scope). |
| `trees/nullifier_tree.rs` | 159 | `NullifierInsertionProofTarget::get_new_root` (:121-141) delegates to indexed insertion; `verify` (:143-158) adds `connect(expected_new_root, new_root)` (:157). | MODELED-in `Core/IndexedMerkle.lean` (F-NULL-1 discharged: strict bracketing + empty-slot sentinel). |
| `tx.rs` | 560 | NONE. `TxTarget/ChannelActionTarget/TxV2Target::new` allocate; `connect` (:115-123) generic; hashes deterministic Poseidon. | SUBSUMED — no assertions of its own. |
| `u63.rs` | 289 | `new` (:116-125): `range_check(value, 63)` (:122); `from_parts` (:137-153): range checks on high/low/value; `connect` (:201-207); `is_equal` (:209-215); **`enforce_ge` (:225-232) = sub + range_check(diff, 63)**; `enforce_gt` (:234-246); `conditional_ge/gt` (:248-274). | **TODO (MEDIUM)** — see TODO-1 below. `is_equal`/`connect` themselves are generic gates (and `is_equal` is the field-1 gadget of `PublicStateEq.lean`). |
| `withdrawal.rs` | 192 | `WithdrawalTarget::new` (:127-146): `range_check(token_index, 32)` (:134) + cascaded checks; `hash_with_prev_hash` (:169-183) deterministic keccak. | SUBSUMED — width pinning + deterministic fold; withdrawal semantics modeled in `SingleWithdrawalCircuit.lean` / `WithdrawalStep.lean`. |

## src/utils/ (18 files)

| File | LOC | Constraints emitted | Coverage status |
|---|---|---|---|
| `cyclic.rs` | 295 | `verify_proof` (:145, :243), `conditionally_verify_cyclic_proof_or_dummy` (:188); vd layout `vd_vec_len` (:26-28); `num_public_inputs = pis_len + vd_vec_len` (:249). | SUBSUMED — **role: this IS the verifier-data fixed-point machinery** that the audit's cyclic abstraction (`BalanceCircuit.cyclic_sound`: `proofVd = selfVd` ⇒ recursion closes over the same circuit) trusts. The machinery itself is upstream plonky2 (`check_cyclic_proof_verifier_data`); modeling it further would be modeling plonky2 internals, which the audit's trusted base explicitly leaves uninterpreted. Recorded so the trust boundary is visible, not silent. |
| `dummy.rs` | 92 | `conditionally_verify_proof` → `verify_proof` (:57); dummy circuit degree pinned (:75-76, :90). | SUBSUMED — same cyclic/conditional-verification trust class as `cyclic.rs`; no protocol invariant of its own. |
| `hash_chain/chain_end_circuit.rs` | 164 | `add_proof_target_and_verify_cyclic` (:133); output PI = keccak(last_hash ++ proof_submitter) (:134-141), deterministic. | SUBSUMED — cyclic wrapper + deterministic PI re-expose (`pi_roundtrip_two` pattern); `proof_submitter` is intentionally prover-chosen (reward address) and bound into the output hash. Role documented in `HashChain.lean` header. |
| `hash_chain/cyclic_chain_circuit.rs` | 149 | `assert_bool` via `add_virtual_bool_target_safe` (:51); inner-proof verify (:53); `conditionally_verify_cyclic_proof_or_dummy` (:62-68); limb connects (:70); **base-case pin `conditional_assert_eq(is_first_step, prev_hash, 0)` (:72-73)**. | **NEWLY-MODELED-in `Zkp/Circuits/Common/HashChain.lean`** — `first_step_pins_prev`, `zero_prev_does_not_force_first` (converse NOT constrained — computational only), `chain_integrity`. |
| `hash_chain/hash_chain_processor.rs` | 89 | NONE (orchestration: prove_chain/prove_end wiring, :54-88). | SUBSUMED — no constraints; documented in `HashChain.lean` header. |
| `hash_chain/hash_inner_circuit.rs` | 70 | `add_proof_target_and_verify` (:42); `hash = keccak(prev_hash ++ single.pis)` (:43-47) deterministic; PIs `[prev_hash, hash]` (:46-47). | **NEWLY-MODELED-in `HashChain.lean`** — appears as premise (1) of `Accepted` (`hash = keccakChain prevHash content`). |
| `hash_chain/mod.rs` | 42 | NONE. `hash_with_prev_hash{,_circuit}` (:23-26, :28-42) deterministic keccak fold. | **NEWLY-MODELED-in `HashChain.lean`** — the opaque `keccakChain`. |
| `leafable.rs` | 194 | NONE (trait + deterministic hash impls). | SUBSUMED — no assertions. |
| `leafable_hasher.rs` | 262 | `conditional_assert_eq_hash` (:135-142 Poseidon, :196-202 Keccak) — per-limb `conditional_assert_eq`. | SUBSUMED — pure instances of `Builder.condAssertEq`; no invariant of its own. |
| `logic.rs` | 302 | `conditional_assert_true` (:24-34): one arithmetic gate `condition·(1−target)` + `assert_zero` (:33). `conditional_and` (:36-45), `select_vec` (:47-78): deterministic select/add wiring, no assertions. | SUBSUMED — `cond·(1−t)=0` ⇒ `cond=0 ∨ t=1` is exactly `mul_eq_zero` (integral-domain axiom), used inline where consumers are modeled (e.g. ReceiveTransfer's validity assert). NOTE: `conditional_and`/`select_vec` outputs are `new_unsafe` — boolean-ness of results is a *caller* obligation, as already handled per consumer model. |
| `poseidon_hash_out.rs` | 589 | `connect` (:133-141); `conditional_assert_eq` (:143-152); `is_equal` (:204-216, and-fold); `to_hash_out` (:318-327) = `reduce_to_hash_out` (:303-317, deterministic mul_const_add) + round-trip `connect` (:324); **`safe_split_lo_and_hi` (:330-347)**: `split_low_high` + `is_equal(hi, 2^32−1)` + `assert_zero(is_hi_max·lo)` (:343-345) forcing the canonical 32-bit split. | **PARTIAL**: `is_equal` fold NEWLY-MODELED-in `PublicStateEq.lean` (`LimbsEqFold`); `connect`/`conditional_assert_eq` SUBSUMED (generic per-limb gates). **`safe_split_lo_and_hi` / `to_hash_out` / bare `reduce_to_hash_out`: TODO (MEDIUM-HIGH)** — see TODO-2 below. |
| `recursively_verifiable.rs` | 87 | `verify_proof` (:28, :66), `connect_hashes`/`connect_merkle_caps` (:61-64), conditional variants (:82, :85). | SUBSUMED — the vd-binding wrappers abstracted by `BalanceCircuit.cyclic_sound`; same trust class as `cyclic.rs`. |
| `trees/get_root.rs` | 256 | NONE. Root-from-full-leaves circuits are deterministic two_to_one folds. | SUBSUMED — determinism = uninterpreted hash; consumers (tx-tree root recomputation) modeled at their call sites. |
| `trees/incremental_merkle_tree.rs` | 711 | `verify` (:169) / `conditional_verify` (:187) — delegate to `MerkleProofTarget`. | MODELED-in `Core/Merkle.lean` (inclusion fold + index decomposition). |
| `trees/indexed_merkle_tree/insertion.rs` | 444 | `assert_one(is_key_lower_bounded)` (:287), `assert_one(is_key_upper_bounded_or_next_key_zero)` (:294), membership `verify` (:296, :311-312), conditional variants (:341-375). | MODELED-in `Core/IndexedMerkle.lean` (strict bracketing `low.key < key < low.next_key`; discharges F-NULL-1). |
| `trees/indexed_merkle_tree/leaf.rs` | 159 | NONE (hash + constants; empty leaf = `key=U256::MAX` sentinel, :68-75). | MODELED-in `Core/IndexedMerkle.lean` (`empty_leaf_cannot_be_low`). |
| `trees/merkle_tree.rs` | 619 | `verify` (:237-252): `get_root` fold + `connect_hash` (:251); `conditional_verify` (:254-275): per-limb `conditional_assert_eq` (:269-274). | MODELED-in `Core/Merkle.lean`. |
| `trees/sparse_merkle_tree.rs` | 799 | `verify` (:188) / `conditional_verify` (:205-206) — delegate to `MerkleProofTarget`. | MODELED-in `Core/Merkle.lean` (same proof gadget; sparse indexing is native-side). |
| `wrapper.rs` | 58 | `verify_proof` (:28); PI re-registration (:36-46) deterministic. | SUBSUMED — identity proof-wrapping (`pi_roundtrip_two` + plain verification); no invariant of its own. |

---

## TODO details & risk ratings

### TODO-1 — `u63.rs` / `channel_id.rs` comparison gadgets (`enforce_ge/gt`, `conditional_ge/gt`) — **MEDIUM**

`enforce_ge` (u63.rs:225-232; channel_id.rs:247-254) proves `a ≥ b` by range-checking
`a − b` to the operand width (63 resp. `CHANNEL_ID_BITS`). Soundness is an
**arithmetic-in-Goldilocks argument**, not a syntactic one: it needs (i) both
operands already range-checked to the same width `k`, and (ii)
`p − 2^k > 2^k` (true for Goldilocks with k=63: a wraparound difference lands in
`[p − 2^k, p)`, outside the check). Neither (i) nor (ii) is representable in the
current abstract model (`Builder.rangeCheck` over an opaque `repr`), so the
audit currently **trusts** these gadgets exactly as it trusts `U256.is_lt`
(residual-trust note in F-NULL-1).

**What breaks if wrong:** block-number ordering. Consumers (all in balance
circuits): `send_tx_circuit.rs:252,257`, `receive_transfer_circuit.rs:441-460`,
`receive_deposit_circuit.rs:311-323`. A prover who can satisfy `enforce_gt`
with `new ≤ prev` can rewind/replay the balance-proof block cursor (`block_r`)
— e.g. re-receive a transfer already received, or re-order sends — a
fund-relevant forgery. Also `from_parts` (u63.rs:137-153) canonical-split
uniqueness belongs to the same class. **Action:** WP-CORE `repr`-level model
(the planned characteristic-explicit layer) should state and prove the
`p − 2^63 > 2^63` argument once and instantiate it at these call sites.

### TODO-2 — `poseidon_hash_out.rs` Bytes32↔HashOut conversion — **MEDIUM-HIGH**

Three related gadgets:
1. `safe_split_lo_and_hi` (:330-347): eliminates the double decomposition of
   `x < 2^32` (`hi=0,lo=x` vs `hi=2^32−1,lo=x+1`) by asserting `hi=2^32−1 ⇒ lo=0`
   (:343-345). Its correctness (and the claim in the comment that this still
   admits every field value) is again a Goldilocks-characteristic argument
   (`p = 2^64 − 2^32 + 1`) outside the abstract model.
2. `to_hash_out` (:318-327): binds the conversion canonically via the
   round-trip `connect` (:324) through `from_hash_out`/`safe_split`.
3. **Bare `reduce_to_hash_out` (:303-317) has NO canonicity constraint**: it
   maps limb pairs by `hi·2^32 + lo` deterministically; with 32-bit limbs the
   image covers `[0, 2^64−1] mod p`, which is **not injective** (values `x` and
   `x − p` collide for `x ≥ p`). Consumer `tx_settlement.rs:289` calls the bare
   variant on `send_leaf.tx_tree_root` (a `Bytes32` from the account leaf).

**What breaks if wrong:** hash-out aliasing — two distinct `Bytes32` tx-tree
roots reducing to the same `HashOut` would let a prover open a settlement
against a different root than the one committed in the send leaf (whether the
colliding second preimage is *reachable* depends on the range constraints on
that Bytes32's limbs at its creation site — not yet audited). This is the
sharpest genuinely-open question in this inventory. **Action:** model
`safe_split_lo_and_hi` + `to_hash_out` under the WP-CORE characteristic layer,
and audit every `reduce_to_hash_out` call site (`tx_settlement.rs:155` native /
`:289` circuit) for whether non-canonical limb values are excluded upstream.

### TODO-3 — `channel_id.rs` conditional comparisons in excluded-scope consumers — **LOW**

The `conditional_ge/gt` variants (channel_id.rs:270-296) are consumed mainly by
channel-scope circuits (out of audit scope). Listed separately so that if the
channel scope is ever pulled in, this row flips to the TODO-1 treatment
automatically rather than being rediscovered.

---

## Cross-checks recorded

- `public_state.rs:307-328` is_equal ANDs **all five** fields (block_number,
  timestamp, account_tree_root, deposit_tree_root, prev_public_state_root) —
  machine-checked: `PublicStateEq.publicStateEq_sound` /
  `publicStateEq_iff_struct_eq`. **F-PUBST-1 discharged.**
- `cyclic_chain_circuit.rs:71-73` pins `is_first_step = 1 ⇒ prev_hash = 0`
  (one direction only; converse is computational) — machine-checked:
  `HashChain.first_step_pins_prev`, `HashChain.chain_integrity`,
  non-theorem witness `zero_prev_does_not_force_first`.
- Direct consumers of the `utils/hash_chain` accumulator today:
  `poseidon_sig/list.rs:186-196` (`ListCircuit`) and `chain_end_circuit.rs`.
  The validity chains (`deposit_hash_chain_circuit.rs`,
  `block_hash_chain_circuit.rs`, `channel_reg_chain_processor.rs`) do NOT use
  this gadget — they carry initial/final chain values in PIs, anchored
  on-chain at `IntmaxRollup.sol:1466-1467`
  (`initialExtCommitment == latestFinalizedStateRoot`,
  `initialBlockChain == blockHashChainAt[initialBlockNumber]`).
- `transfer.rs:68-79` hashes the full 32-byte recipient — the F-RECIP-1
  adjudication premise still holds on this branch.
