# Lean ZKP audit — task plan & findings log

Goal: model every in-scope Plonky2 circuit file line-by-line in Lean,
proving soundness or surfacing the gap. Excluded: crypto primitive
internals, all channel circuits.

## Method per file (CLAUDE.md §planning, §adversarial)

1. **Role**: document the file's protocol role (header comment).
2. **Constraint-by-constraint**: for each `builder.*` call, record
   `source.rs:line`, why the constraint exists, and translate it.
3. **Soundness theorem**: `Constraints → nativeSpec`; prove it, or
   record the unprovable obligation as an `F-*` finding.
4. **Adversarial pass**: separate review asking "what witness does
   this accept that it shouldn't?" before marking a file done.

Legend: [ ] todo · [x] in progress · [x] modeled+proved · [!] finding open

## Phase 0 — Core scaffolding
- [x] `Core/Field.lean` — field axioms, `assert_bool` soundness
- [x] `Core/Builder.lean` — connect/assert/select/is_equal/range_check/natLit
- [x] `Core/Bytes.lean` — Bytes32/Address/HashOut, Poseidon (uninterpreted)
- [x] `Core/Merkle.lean` — Merkle inclusion gadget (fold + index decomposition)
- [x] `Core/U256.lean` — 256-bit value; overflow-rejecting `AddSpec` + underflow-rejecting `SubSpec` (solvency)
- [x] `Core/IndexedMerkle.lean` — nullifier non-membership / insert (DISCHARGES F-NULL-1)
- [x] `Core/Cyclic.lean` — IVC wiring (abstracted inline via cyclic-vd bindings in BalanceCircuit/steps)

## Phase 1 — balance/common (leaf gadgets) — COMPLETE ✅
- [x] `recipient.rs`            → Circuits/Balance/Common/Recipient.lean  **[! F-RECIP-1]**
- [x] `account_state.rs`         → Circuits/Balance/Common/AccountState.lean  **[! F-ACCT-1]**
- [x] `transfer_witness.rs`     → Circuits/Balance/Common/TransferWitness.lean
- [x] `deposit_witness.rs`      → Circuits/Balance/Common/DepositWitness.lean (index-range verified-safe)
- [x] `tx_settlement.rs`        → Circuits/Balance/Common/TxSettlement.lean (spend-auth↔inclusion; F-ACCT-1 closed)
- [x] `update_private_state.rs`   → Circuits/Balance/Common/UpdatePrivateState.lean  **[! F-NULL-1]** (CRITICAL: no-overflow + single-leaf proved)
- [x] `update_public_state.rs`   → Circuits/Balance/Common/UpdatePublicState.lean  **[! F-PUBST-1]**

## Phase 2 — balance circuits — COMPLETE ✅
- [x] `balance_pis.rs`          → Circuits/Balance/BalancePis.lean  **[! F-BLKR-1]** (connect-completeness PROVED)
- [x] `spend_circuit.rs`        → Circuits/Balance/SpendCircuit.lean  **[! F-SPEND-1]** (solvency PROVED; underflow-safe)
- [x] `send_tx_circuit.rs`      → Circuits/Balance/SendTxCircuit.lean (F-SPEND-1 RESOLVED; F-AUX-1→residual)
- [x] `receive_transfer_circuit.rs` → Circuits/Balance/ReceiveTransferCircuit.lean (asserts is_valid; cross-user binding)
- [x] `receive_deposit_circuit.rs`  → Circuits/Balance/ReceiveDepositCircuit.lean (F-BLKR-1 resolved this path)
- [x] `switch_board.rs`         → Circuits/Balance/SwitchBoard.lean (routing_sound: output from UNIQUE verified branch)
- [x] `balance_circuit.rs`      → Circuits/Balance/BalanceCircuit.lean (cyclic vd binding; closes C-M3 at fixed-point)
- [x] `balance_processor.rs`    → orchestration only (no new constraints; documented in BalanceCircuit.lean)

## Phase 3 — withdraw — COMPLETE ✅ (chain/processor = documented cyclic wrappers)
- [x] `withdrawal_circuit.rs`        → Circuits/Withdraw/WithdrawalCircuit.lean  **[F-WITHDRAW-1 = C-M2 — CLOSED, contract re-pins]**
- [x] `single_withdrawal_circuit.rs` → Circuits/Withdraw/SingleWithdrawalCircuit.lean (provenance+nullifier; proper cyclic ⇒ C-M3 n/a)
- [x] `withdrawal_step.rs`           → Circuits/Withdraw/WithdrawalStep.lean (faithful fold + WDR-CRIT-001 state-threading)
- [x] `withdrawal_chain_circuit.rs`  → cyclic wrapper (documented in WithdrawalStep.lean; no new leaf constraints)
- [x] `withdrawal_processor.rs`      → orchestration only (documented)

## Phase 4 — validity (non-channel) — substantive files DONE ✅
- [x] `deposit_hash_chain/deposit_step.rs` → Circuits/Validity/DepositStep.lean (sequential append + dual-commitment)
- [x] `deposit_hash_chain/deposit_chain_pis.rs` (PI layout — documented in DepositStep.lean)
- [x] `deposit_hash_chain/deposit_hash_chain_circuit.rs` (cyclic wrapper — documented)
- [x] `deposit_hash_chain/deposit_chain_processor.rs` (orchestration — documented)
- [x] `block_hash_chain/block_step.rs` → Circuits/Validity/BlockStep.lean (bp_sig_chain + block-hash threading; discharges signatures_not_skippable premise)
- [x] `block_hash_chain/small_block_message.rs` → Circuits/Validity/SmallBlockMessage.lean (signature↔block tx_tree_root binding)
- [x] `block_hash_chain/ext_public_state.rs` (PI layout — documented in BlockStep.lean; no new soundness leaf)
- [x] `block_hash_chain/block_chain_pis.rs` (PI layout — documented in BlockStep.lean; no new soundness leaf)
- [x] `block_hash_chain/validity_circuit.rs` → Circuits/Validity/ValidityCircuit.lean (signatures_not_skippable; keccak PI binding)
- [x] `block_hash_chain/block_hash_chain_circuit.rs` (cyclic wrapper — documented in BlockStep.lean; no new soundness leaf)
- [x] `block_hash_chain/block_hash_chain_processor.rs` (orchestration — documented in BlockStep.lean; no new soundness leaf)

## Excluded (channel / crypto) — recorded for completeness, NOT modeled
- channel/* (all), validity/channel_reg_hash_chain/* (all)
- block_hash_chain/update_channel_tree.rs
- Poseidon/SPHINCS+/Regev/MLE-WHIR primitive internals
- test_utils/* (reference only; model if needed to pin native semantics)

## Findings log

### F-RECIP-1 — `extract_address` padding bytes unbound  [ADJUDICATED — INFORMATIONAL]
`recipient.rs:78-87`. Circuit asserts only `bytes[0]==ADDRESS_TAG`;
the 11 padding bytes `bytes[1..12]` are never constrained to zero, so
`recipient ↦ address` is many-to-one (≈2^88 recipients per address).
Native constructor always zeroes them, but the extractor accepts any.
Severity: depends on downstream binding of `recipient` — must check
whether `withdrawal_circuit` / `single_withdrawal_circuit` bind the L1
payout to `extract_address(recipient)` while `recipient` itself is only
hash-bound under prover control. Lean evidence: `extractAddr_sound`
conclusion says nothing about `bytes[1..12]`; the stronger spec
`recipient = recipientFromAddress out` is not provable.
**VERDICT (Phase 3 cross-check):** NOT fund-exploitable. Sole consumer
`single_withdrawal_circuit.rs:504` pairs the extracted address with
`settled_transfer.nullifier()`, and `Transfer::to_u64_vec` hashes the FULL
32-byte recipient ⇒ differing padding ⇒ distinct nullifier ⇒ distinct
real transfer (each backed by a solvent sender spend; nullifier blocks
reuse). Tag separation (ADDRESS_TAG=2 vs USER_ID_TAG=1) prevents
withdraw/receive cross-replay. Net = non-canonical encoding (~2^88:1),
no theft/double-spend/inflation. Defense-in-depth: extract could
`assert_zero(bytes[1..12])`. Downgraded OPEN→INFORMATIONAL.

### F-ACCT-1 — `is_checked` gates index range checks  [CLOSED — verified-safe]
`account_state.rs:110,115-117`. `range_check(send_leaf_index,...)` and
`channel_id` range-check fire only when `is_checked=true`. Model: the
range check licenses `MerkleVerify`'s `bits.length=height` conjunct;
without it, index aliasing (`index` vs `index+2^height mod p`) is
possible if the slot is security-relevant. Action: confirm every
in-scope caller of `AccountStateTarget::new` passes `is_checked=true`.
Caller audit: `receive_transfer_circuit.rs:392`, `receive_deposit_circuit.rs:287`,
`single_withdrawal_circuit.rs:431` all pass literal `true` ✓.
`tx_settlement.rs:274` propagates `TxSettlementTarget::new`'s `is_checked`
param → resolve when modeling tx_settlement (Phase 1). RESOLVED: all non-test callers of `TxSettlementTarget::new`
(`send_tx_circuit.rs:231`, `receive_transfer_circuit.rs:393`) pass literal
`true`, threading `is_checked=true` into ChannelId/PublicState/AccountState.
With `TX_TREE_HEIGHT=CHANNEL_ID_BITS=ASSET_TREE_HEIGHT=DEPOSIT(U63)` all
matching their index widths, no index aliasing exists. Not a vuln.

### F-PUBST-1 — no-op branch safety depends on full-record `is_equal`  [CHECK ITEM]
`update_public_state.rs:97`. The `conditional_verify` skip is sound
*only* because `is_equal` compares every public-state field
(`e=1 ↔ new=old`). If `PublicStateTarget::is_equal` omits a field, a
prover sets `e=1` with that field mutated, skipping the Merkle check =
transition forgery. Proved: `updatePublicState_sound` (skip ⇒ new=old).
Action: when modeling `public_state.rs::is_equal`, confirm it AND-s ALL
fields. Until then this is the load-bearing assumption.

### F-NULL-1 — spend-once rests on nullifier non-membership proof  [CLOSED — discharged]
`update_private_state.rs:138-142` via `NullifierInsertionProof::get_new_root`.
The double-credit defense is entirely the indexed-tree non-membership
proof showing the nullifier was ABSENT before insert. If that gadget's
low-leaf bracketing / range comparison is weak, the same transfer or
deposit can be credited twice (balance inflation). DISCHARGED in Core/IndexedMerkle.lean: insert asserts strict bracketing
`low.key < key < low.next_key` + low-leaf inclusion + empty slot; the
linked-list gap invariant ⇒ `key_absent` (nullifier was absent). The
documented duplicate-insertion PoC is closed by the empty-leaf=MAX
sentinel (`empty_leaf_cannot_be_low`). Residual trust: `U256.is_lt`
strictness + Poseidon CR (both standard). Proved: key_absent,
no_double_insert, empty_leaf_cannot_be_low.
Proved meanwhile: overflow cannot wrap a balance down
(`credit_strictly_increases`), and a credit changes only the
`token_index` asset leaf (`AssetUpdate` shared-path).

### F-AUX-1 — inter-channel `aux_data` ↔ tx-leaf binding  [RESIDUAL — documented off-circuit]
audit622 §C-M1. `TxSettlement` binds `tx==spend_pis.tx` and includes
tx/tx_v2 at `channel_id`, but the channel inter-tx `aux_data` folded
into `settled_tx_chain` (in `send_tx_circuit.rs:285-289`,
`receive_transfer_circuit.rs:496-504`) is not proven equal to the tx
leaf hash. Re-examine in Phase 2.

### F-SPEND-1 — `is_valid` computed but not asserted in spend circuit  [CLOSED — not a vuln]
`spend_circuit.rs:412`. `is_valid = is_equal(tx_nonce, prev.nonce)` is a
PI but never asserted true; a proof with `tx_nonce ≠ prev_nonce` is valid.
Sequentiality holds only if a CONSUMER checks `is_valid`. `TxSettlement`
binds `spend_pis.tx` but does NOT read `is_valid`. Impact bounded (sent-tx
empty-slot still blocks same-nonce reuse; private nonce +1 regardless) —
nonce-ordering integrity, not double-spend. RESOLVED: `send_tx_circuit.rs:260-298` consumes `is_valid` as the
selector on block_r / private_commitment / settled_tx_chain. An invalid
spend (is_valid=0) is a proven NO-OP (`invalid_spend_is_noop`) — cannot
corrupt private state. Not a vulnerability; by design.

### F-BLKR-1 — `block_r ≤ public_state.block_number`  [MOSTLY RESOLVED]
`balance_pis.rs:59-64` documents the invariant but
`BalancePublicInputsTarget::new` only range-checks `block_r`. The `≤`
must be enforced where `block_r` is set (balance_processor / update
circuits). If unenforced, a balance could claim guarantee at a block_r
above the referenced state height. Locate the assertion in Phase 2. UPDATE: `receive_deposit_circuit.rs:310`
asserts `public_state.block_number ≥ new_block_r` (proved `blockR_bounded`);
receive paths close it. Remaining: confirm send_tx's `tx_block_number ≤
new public_state.block_number` (tx_block came from account send_leaf.cur).

### F-WITHDRAW-1 (= audit622 C-M2) — partial ExtendedPublicState binding  [CLOSED — SAFE, contract re-pins]
`withdrawal_circuit.rs:190-194`. Only `ext_public_state.inner` is
`connect`-ed to the verified chain proof; the 5 extended fields
(block_hash_chain, deposit_hash_chain, deposit_count, channel_reg_hash_chain,
bp_sig_chain) are FREE witnesses, yet `ext_public_state_commitment` (an
on-chain PI) commits to all of them. Lean: `Constraints` has no conjunct
binding the extended fields; `ext_is_genuine` is unprovable.

CONTRACT-SIDE VERDICT (task_cae4b173): case (a) — SAFE. The contract NEVER
decodes an individual extended field; it requires the FULL commitment to be a
member of the validity-finalized root set, which re-pins all 5 fields.
  1. `withdrawNative` checks `finalizedStateRoots[extCommitment]`
     (IntmaxRollup.sol:1330-1331, `WithdrawalExtCommitmentMismatch`). No
     extended field is ever read out of the withdrawal PI.
  2. `finalizedStateRoots` is written only by `finalize()` (:1122) with
     `stateRoot`, and `fullVerify` forces `validityPIs.finalExtCommitment ==
     stateRoot` (:1469) + binds validityPIs to a verified validity MLE proof via
     piHash (:1480). So every member is a validity-proof `final_ext_commitment`.
  3. Validity circuit computes that commitment with the SAME
     `ExtendedPublicStateTarget::commitment` over the SAME 13-field `to_vec()`
     (validity_circuit.rs:242), with the 5 fields CONSTRAINED to true values
     (D3 bp_sig_chain + A8 guard, R4 channel_reg_chain, deposit chain).
  4. Poseidon is collision-resistant ⇒ the only preimage landing in
     `finalizedStateRoots` is the genuine (inner, ext5) tuple. Forging any field
     yields a commitment absent from the set → revert.
The circuit's partial binding is INTENTIONAL and completed contract-side. The
membership check also anchors `inner` to a finalized state; `block_number`
(pi[16]) is independently bound to `inner.block_number` (:195) and folded into
pis_hash. Residual external dependency: the validity circuit truly constrains the
5 fields (its own invariant, separate scope; documented D3/A8/R4). Reproduces +
resolves audit622 C-M2 formally. Full line-referenced argument:
`audit/zkp/tasks/F-WITHDRAW-1-verdict.md`.

## Assessment (FINAL — substantive audit complete)
- 20 circuit files + 6 core modules; 57 machine-checked theorems; 3254 LOC;
  ZERO sorry; clean `lake build` from scratch passes.
- ALL soundness-critical in-scope circuit logic is modeled: every circuit
  that emits binding/arithmetic/inclusion constraints is either PROVED sound
  or its gap is surfaced+adjudicated. The complete fund flow (deposit→spend→
  send→receive→withdraw) + validity-top + on-chain binding + nullifier
  non-membership is formally established.
- Findings: F-WITHDRAW-1 (=audit622 C-M2) now CLOSED — contract-side verify
  (task_cae4b173) confirmed case (a) SAFE: `withdrawNative` requires the full
  ext commitment ∈ `finalizedStateRoots` (validity-finalized roots), re-pinning
  all 5 extended fields; no extended field is trusted from the withdrawal PI.
  NO open circuit-level findings remain. F-NULL-1 discharged;
  F-RECIP-1 informational; F-SPEND-1/F-ACCT-1 closed; F-BLKR-1 mostly resolved;
  F-AUX-1 documented residual. NO new exploitable circuit-level vulnerability
  found beyond the known C-M2 residual.
- Remaining files (PI-layout / message-encoding / cyclic-wrapper / orchestration:
  small_block_message, ext_public_state, *_chain_pis, *_circuit, *_processor)
  emit no new soundness leaf constraints; documented inline. The PI round-trip
  no-aliasing property is proved generically in BalancePis (connectPis_iff_eq).

## Assessment (running)
- Core abstraction validated end-to-end on `recipient.rs`: builds, both
  soundness + completeness proved, and the model surfaced F-RECIP-1
  naturally (the gap = an unprovable strengthening). Approach is sound;
  proceed file-by-file in phase order.
- 6 files modeled, 5 core modules, all machine-checked (lake build green,
  zero `sorry`). Critical gadget `update_private_state` done: no-overflow
  and single-leaf-update are now theorems. Open findings: F-RECIP-1,
  F-NULL-1; check items F-ACCT-1 (LOW), F-PUBST-1. Phase 1 COMPLETE (7/7 balance/common gadgets,
  7 core+circuit theorems green). Phase 2 started: spend_circuit DONE — spender
  solvency (no underflow, no overspend across 64 transfers) is now a
  theorem. balance_pis DONE (connect covers all
  fields — recursion binding complete). send_tx DONE — F-SPEND-1 closed
  (invalid spend = proven no-op), F-AUX-1 → documented residual, F-BLKR-1
  partially addressed (block_r ordering enforced; ≤block_number still open).
  10 files, 5 cores, all green. receive_deposit DONE (credit binds
  to deposit; F-BLKR-1 resolved this path). 11 files green. switch_board DONE (anti-forgery
  dispatch proved; char(Goldilocks)>4 dependency surfaced for one-hot).
  13 files green. F-SPEND-1 FULLY
  closed (receive_transfer asserts is_valid==true). Remaining Phase 2:
  balance_circuit + balance_processor (thin IVC wrappers). Then Phase 3
  withdraw — where F-RECIP-1 gets its verdict.

---

# META-AUDIT REMEDIATION (2026-07-02)

A four-track adversarial meta-audit of this artifact found that the per-layer
theorems are honest but several HEADLINE claims exceed what is machine-checked.
This phase closes those gaps. Threat model for the remediation itself: the
adversary is (a) a malicious prover exploiting a constraint the Lean model
*added* that the Rust circuit does not enforce (over-constraint — the GapEmpty
lesson), and (b) the transcription process itself claiming composition that is
only prose. Rules: every NEW conjunct must cite a real `source.rs:line`; every
inter-layer arrow becomes a NAMED Lean hypothesis, never silent; zero `sorry`;
unprovable strengthenings stay findings.

## Work packages (implementer ≠ reviewer; separate adversarial review pass)

### Wave 1 (file-disjoint, parallel)
- [ ] **WP-WD** Strengthen `SingleWithdrawalCircuit.lean`: add the real Rust
  conjuncts privCommit↔sentTxRoot (`:441-442,456-461`) and
  txLeaf↔(txTransferTreeRoot,nonce) (`:463-465`); model or explicitly scope the
  settled-block leg (`:444-501`); re-prove `withdrawal_sound` with the repaired
  provenance chain; satisfiability lemma; fix stale citations; align docstring.
- [ ] **WP-NULL** Rework `Core/IndexedMerkle.lean`: REMOVE the `gap` hypothesis
  from `InsertConstraints` (no Rust counterpart — a genuine over-constraint);
  model the splice (`insertion.rs:302-309`) + empty-slot check (`:310-312`);
  PROVE the GapEmpty preservation induction from genesis; re-derive
  `key_absent` from invariant + circuit constraints; connect
  `UpdatePrivateState.NullifierInsert` to it; refresh the wholesale-stale
  citation table; honest F-NULL-1 status.
- [ ] **WP-CT** Contracts: extend solvency trace `Op` with `claimAuthorized`
  (real escrow outflow, `IntmaxRollup.sol:660`) and re-prove
  `solvent_from_genesis`; model `reclaimStake` (`:1269-1283`, fund-bearing —
  currently misclassified "no escrow effect") + both-order no-double-payout
  theorems; fix `Coverage.lean` honesty gaps (manager-vs-verifier nullifiers,
  disabled stubs ≠ oracles, manager close-lifecycle categorization incl.
  `finalizePartialWithdrawal`); NAMED trust assumptions (deployer→manager
  no-proof burn path, `allowMleDisabled=false`, single-call atomicity /
  no-reentrancy modeling limit, send-failure=revert).
- [ ] **WP-UU** New `Circuits/Validity/UpdateUser.lean` modeling the two
  load-bearing obligations of the mislabeled-as-channel
  `update_channel_tree.rs` (1600 LOC): (1) signing-block ⇒ `bp_sig_chain`
  advancement (premise of `signatures_not_skippable`); (2) the channel_reg
  branch account-tree-root rewrite (`:314,:609-646`) — bind what is bound,
  surface what is not as a finding.
- [ ] **WP-GADGET** Discharge F-PUBST-1 (`public_state.rs:307-330` is_equal
  ANDs all fields — new `Circuits/Common/PublicStateEq.lean`); model
  `hash_chain/cyclic_chain_circuit.rs:71-73` base-case pinning (new
  `Circuits/Common/HashChain.lean`); produce the missing gadget-layer
  inventory (33 CircuitBuilder files in src/common+src/utils) →
  `tasks/gadget-inventory.md`.

### Wave 2 (Core layer, sequential after Wave 1)
- [ ] **WP-CORE** `CompressCR` (the Merkle fold hash has NO CR hypothesis
  today); Merkle binding/uniqueness theorem under it; plumb CR into the
  load-bearing sites so `PoseidonCR`/`KeccakCR` stop being decoration;
  minimal named `repr`/`natLit` faithfulness so tag distinctness
  (F-RECIP-1 leg 3) is in-model; document AddSpec/SubSpec as trusted-base;
  SwitchBoard "one place" claim fix (shared-bits char>2^32 reliance).

### Wave 3 (composition)
- [ ] **WP-E2E** New `Zkp/EndToEnd.lean`: a `BridgeAssumptions` record naming
  every currently-English arrow (recursion oracle `Verified i ⇒ inner
  Constraints`, circuit↔contract layout equality, F↔U256 encoding), then a
  REAL composed theorem: accepted L1 payout ⇒ backed, deducted, anchored,
  single-use — conditional on the named record, not on prose.

### Wave 4 (adversarial review, separate agents) + docs
- [x] Adversarial review of every new conjunct vs Rust/Solidity (anti-GapEmpty
  check) and vacuity check of every new theorem.
- [x] Root `Zkp.lean` imports, clean `lake build`, updated SUMMARY.md /
  audit report addendum with honest headline scope; lessons.md.

## Remediation outcome (2026-07-02) — ALL WAVES COMPLETE

- [x] WP-WD, WP-NULL, WP-CT, WP-UU, WP-GADGET, WP-CORE, WP-E2E all landed.
- Final artifact: 41 files, 225 theorems (141 circuit + 62 contract + 22
  end-to-end), 10,522 LOC, zero sorry/axiom, `lake build` green.
- Adversarial re-review (implementer ≠ reviewer): contracts+E2E track ALL
  CLEAN (composition non-circular — proof term consumes per-layer theorems);
  circuit track found 3 BLOCKERs + 2 MAJORs in the remediation itself
  (B-1 3-vs-5-field PublicState; B-2 NullifierRootBinding false-by-truncation;
  B-3 NatLitInj pigeonhole-unsatisfiable; M-1 shared-bits over-constraint;
  M-2 settle-twice disclosure) — ALL FIXED and re-verified.
- NEW findings surfaced by the completion: **F-UPDU-1** (OPEN — registration
  account roots conditional on excluded channel_reg circuit; base-layer fund
  exposure), **F-WD-2** (OPEN — settle-twice nullifier boundary; validity-side
  settlement-uniqueness invariant not yet established in Lean),
  gadget-inventory **TODO-2** (reduce_to_hash_out canonicity, MEDIUM-HIGH
  check item). F-NULL-1 now GENUINELY discharged (preservation induction);
  F-PUBST-1 discharged; F-RECIP-1 leg 3 upgraded to conditional theorem.
- Report: `audit/audit02-07-2026.md`; honest headline in SUMMARY.md.
- Next candidates (not started): model `channel_reg_step.rs` to close
  F-UPDU-1; model the send sub-update (`update_channel_tree.rs:852-914`) to
  adjudicate F-WD-2; adjudicate TODO-2 canonicity.
