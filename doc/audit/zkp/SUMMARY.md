# intmax3-zkp — Lean formalization: audit summary

> **Current alignment, 2026-09-05:** this file retains a historical audit summary, not a
> current end-to-end certification. [Current scope and assumptions](../lean-current-safety.md)
> describe the new parent `c533e710` / submodule `b569e0d7` transition models. Current proof
> dependencies and source bindings are machine-checked separately. Historical `EndToEnd`
> includes removed operations and must not be quoted as a proof of the entire current system.

> ## ⚠ STALENESS / TARGET-COMMIT BANNER (added 2026-08-26)
>
> A Lean model verifies THE CODE IT WAS WRITTEN AGAINST, not the working
> tree. This corpus was audited against the codebase up to commit
> `2c358ae` (2026-08-20). Production has moved since — notably `fd467ea`
> (2026-08-24, sig-cluster: member cap 16 → 8, IMCM close-commitment
> re-layout) and the now-retired detail2 §Q direct member-set-update prototype. Divergences
> found by the 2026-08-26 review are catalogued in
> `doc/audit/audit25-08-2026.md` Part 4.3; the load-bearing ones
> (constants, the §Q-falsified `member_set_immutable`, the contract line
> map) were re-synced on 2026-08-26 and are marked in-file. Sections not
> marked re-synced describe the `2c358ae` code. `lake build` green means
> the PROOFS are consistent — it does not mean the MODEL matches today's
> code; check this banner's date against `git log` before trusting a
> line cite. Both Lean corpora now build in CI on every push.


**Scope:** Plonky2 ZKP circuits + L1 Solidity contracts, excluding
cryptographic-primitive internals (Poseidon/Falcon-512/Regev/MLE-WHIR —
uninterpreted; the signature scheme migrated SPHINCS+ → Falcon-512 after this
corpus was cut, see the banner). The channel-registration chain circuit
(`channel_reg_hash_chain/channel_reg_step.rs`) is now IN scope
(`Circuits.ChannelRegStep`), closing the former F-UPDU-1 residual. The
`update_channel_tree.rs` base-layer per-block update circuit is likewise modeled.
The on-chain gate-constraint evaluator
(`mle/contracts/src/Plonky2GateEvaluator.sol`) is in scope for the
`ExponentiationGate` family (`Core.Exponentiation`); the other gate evaluators
in that file are not modeled here.
**Artifact:** `doc/audit/zkp/` — 45 `.lean` files, 257 `theorem` declarations,
12,067 LOC (recounted 2026-08-26), **zero `sorry` / zero `axiom`**, clean
`lake build` (now also run in CI on every push, together with the
design-level corpus `doc/architecture-audit/`).
Counts are reproducible:
`find Zkp Zkp.lean -name '*.lean' | wc -l`,
`grep -rh '^theorem ' Zkp Zkp.lean | wc -l`,
`find Zkp Zkp.lean -name '*.lean' | xargs wc -l | tail -1`.

**Method:** each circuit is a predicate `Constraints → Prop` (one conjunct per
`builder.*` gate, citing `source.rs:line`); soundness is `Constraints → spec`.
A *provable* theorem = the circuit binds what it must; an *unprovable
strengthening* = the missing constraint = a candidate finding. Each
`Constraints` structure carries a **satisfiability lemma** (anti-over-constraint
guard). Every inter-layer arrow is a **named hypothesis**, never prose. The
artifact went through an adversarial meta-audit (4 independent tracks) and a
remediation wave (2026-07-02); all BLOCKER/MAJOR review findings are fixed —
see `doc/audit/audit02-07-2026.md`.

## Bottom line

The user fund flow — **deposit → spend → send → receive → withdraw** — plus
validity-top, on-chain binding, and nullifier non-membership is established
sound **per layer** by machine-checked theorems, and **composed end-to-end**
by `EndToEnd.end_to_end_payout_sound`: a single machine-checked theorem,
conditional on the explicit `BridgeAssumptions` record (proof-system oracle,
recursion oracle, PI-layout equality, CR/characteristic idealizations — every
field named and justified in `Zkp/EndToEnd.lean`). What is NOT covered is
enumerated in the RESIDUAL TRUST SURFACE block there. **F-UPDU-1**
(registration-block account roots conditional on the channel_reg chain circuit)
is now **CLOSED** — that circuit is modeled in `Circuits.ChannelRegStep`
(`tree_and_chain_share_member_set` + `chain_determines_tree`). **F-WD-2**
(settle-twice nullifier) is also **CLOSED** by a circuit fix (Option B, see below).

**LIVENESS DISCLAIMER (added 2026-08-26 — audit25-08-2026 Part 4.3(A)):**
"sound" above is SOUNDNESS ONLY — no theorem in THIS corpus shows an honest
user CAN exit. The corpus's positive-direction results are isolated
`*_satisfiable` witnesses with no adversary. That axis — whose absence let the
gate-8 "honest exit impossible on every real deployment" class survive every
suite — is now covered at DESIGN level in `doc/architecture-audit/`
(`ChannelSafetyClose` honest_close_terminates, `ChannelSafetyPW`
honest_partial_withdraw_pays, `ChannelSafetyIC` honest_window_accepted,
`ChannelSafetyQ` honest_member_can_rotate / honest_join_accepted); an
implementation-level honest-exit pass over the contract models remains open.
For the historical 2026-08-26 audit (sig-cluster 8, then-active §Q member-set updates, §P
aggregated windows) see `doc/audit/audit25-08-2026.md`. Direct MSU and the late-proof/post-close
extra-credit lanes are not current exit mechanisms; the old positive design witnesses do not
establish today's exit liveness. Use the dated current alignment above for the new bounded scope.

## Soundness theorems (selected)

| Property | Theorem | File |
|---|---|---|
| No balance inflation (overflow rejected) | `add_no_wrap`, `credit_strictly_increases` | U256, UpdatePrivateState |
| Spender solvency (no overspend, ≤64 transfers) | `deducts_solvent` | SpendCircuit |
| Credit touches ONLY the indexed leaf (under `CompressCR`+`PowTwoInj`) | `assetUpdate_preserves_other`, `assetUpdate_new_leaf_binding` | UpdatePrivateState |
| Merkle binding: "IS the committed leaf" | `merkleVerify_binding`, `fold_inj` | Merkle |
| Invalid spend is a no-op | `invalid_spend_is_noop` | SendTxCircuit |
| Receive requires a valid sender spend | `requires_valid_sender_spend` | ReceiveTransferCircuit |
| Tx inclusion unavoidable | `inclusion_unavoidable` | TxSettlement |
| IVC dispatch: output from the unique verified branch | `routing_sound`, `routing_sound_genesis` | SwitchBoard |
| Withdrawal provenance chain (transfer→tx leaf→sent-tx tree→privCommit) | `withdrawal_sound` (repaired 2026-07-02) | SingleWithdrawalCircuit |
| Withdrawal aggregation: faithful fold + single state | `fold_faithful`, `state_threaded` | WithdrawalStep |
| Deposit chain: sequential append, no gaps/dups | `sequential_append` | DepositStep |
| Signatures non-skippable (computed gate) | `signatures_not_skippable` | ValidityCircuit |
| Signing block ⇒ exactly one accumulator fold, no reset/skip | `signing_block_advances`, `later_slots_preserve` | UpdateUser (NEW) |
| Member-set binding in the historical §Q model (SUPERSEDED 2026-09-02; production now forbids direct MSU entirely) | `member_set_immutable_outside_update`, `member_root_change_requires_msu` | UpdateUser (historical only) |
| Registration root-swap: what block_step binds | `registration_root_swap_anchored` | UpdateUser (NEW) |
| Nullifier invariant PRESERVED from genesis (spend-once induction) | `genesis_inv`, `insert_preserves_inv`, `reachable_key_absent` | IndexedMerkle (repaired) |
| PublicState.is_equal ANDs all 5 fields (F-PUBST-1) | `publicStateEq_sound` | PublicStateEq (NEW) |
| Hash-chain base-case pinning (one-directional, honestly) | `first_step_pins_prev`, `chain_integrity` | HashChain (NEW) |
| Tag separation USER_ID≠ADDRESS (under `ReprFaithful`) | `tag_separation` | Recipient |
| PI layout no-aliasing (round-trip) | `pi_roundtrip_two` | Plumbing |
| Recursion-binding completeness of PIs | `connectPis_iff_eq` | BalancePis |
| On-chain `ExponentiationGate` evaluator IS the plonky2 evaluator (register-carrying loop ≡ indexed spec) | `solEval_eq_rust`, `solLoop_eq` | Exponentiation (NEW) |
| Exponentiation ladder computes `base ^ (Σ_j bit_j·2^j)` — LE wires, BE ladder (under the imported booleanity hypothesis) | `output_pow`, `ivOf_pow` | Exponentiation (NEW) |
| The gate imposes NO booleanity on power bits (adding one would break completeness) | `sat_for_any_bits` | Exponentiation (NEW) |
| `prev` squares the intermediate-value WIRE, not the previously computed value — the two are different functions | `prev_variants_differ`, `sat_iv_eq_ivOf` | Exponentiation (NEW) |

## Combined-system safety (circuits + L1 contract)

`Zkp/Contracts/` models `IntmaxRollup.sol` / `ChannelSettlementManager.sol`
(Solidity as `Option`-returning transitions; `require`/checked-math = revert;
crypto verifiers = uninterpreted oracles; named trust assumptions in
`Contracts/Assumptions.lean`). Key theorems:

| Property | Theorem | File |
|---|---|---|
| Global solvency incl. burn claims: Σ ETH out ≤ Σ ETH in | `solvent_from_genesis` (3-op trace: dep/wd/claim) | IntmaxRollupSolvency |
| Per-call withdraw ≤ escrow | `withdrawNative_solvency`, `withdrawLoop_solvency` | IntmaxRollupWithdraw |
| No double-withdraw (CEI nullifier) | `withdrawLeaf_nullifier_once`, `withdrawLeaf_consumes` | IntmaxRollupWithdraw |
| No payout without a verified+anchored proof (withdrawNative path ONLY) | `withdrawNative_requires_proof` | IntmaxRollupWithdraw |
| Finalized roots written ONLY by verified validity proofs | `finalize_only_on_valid`; lifted to all reachable states by `erun_finalized_provenance` | IntmaxRollupWithdraw, EndToEnd |
| Burn path: HISTORICAL — `claimAuthorizedWithdrawal` DELETED 2026-07-28; the theorems remain as the record of what the removed function admitted and why it must not return | `claimAuthorized_escrow_conservation`, `burn_drain_satisfiable` (drain exhibited in-model) | IntmaxRollupWithdraw, Assumptions |
| reclaimStake: fund-bearing, both-order no-double-payout | `no_double_payout_{refund,slash}_then_reclaim` + converses | IntmaxRollupStake |
| Stake single-resolution + conservation | `no_double_payout_*`, `stake_conserved` | IntmaxRollupStake |
| Channel payout cap (Σ out ≤ Σ pulled) | `claim_preserves_cap`, `pull_preserves_cap` | ChannelSettlementManager |
| Partial-withdrawal pipeline gates (proof + window + single-use key) | `finalizePartial_authorizes`, `partial_chain_key_single_use` | ChannelSettlementManager |

**End-to-end (now a THEOREM, not prose):** `EndToEnd.end_to_end_payout_sound`
— for every accepted `withdrawNative` in a reachable contract state, under
`BridgeAssumptions`: (a) each paid leaf is backed by a WithdrawalCircuit
witness whose PIs encode it; (b) via `withdrawal_sound`, it carries a transfer
committed through the full provenance chain into a balance commitment
(amount-only binding to the deduction — same-sender lineage is NOT
established, disclosed); (c) anchored to a finalized root with trace-proved
provenance and validity backing (`signatures_not_skippable` fires on any
account-root change); (d) single-use on-chain (nullifier consumed, cross-call);
(e) bounded by `Σ out ≤ Σ in` over the whole history. The composition was
adversarially reviewed for circularity: the proof term consumes the per-layer
theorems; no proved conclusion is restated as an assumption field.

> Contract coverage: `Coverage.lean` categorizes the historical target's remaining lines in all
> THREE contracts (including the Manager close lifecycle and the now-retired §Q
> `applyMemberSetUpdate` / `verifyMemberSetUpdate` entries; line map
> RE-POINTED 2026-08-26 after drifting ~300-350 lines). `verifySpecialClose` /
> `verifyLateOutgoingDebit` are classified DISABLED STUB (forgeable `_matches`
> stubs, inert via manager-side hard-disable) — NOT oracles. The map is a
> CATALOG, not a proof (its marker theorem says so explicitly).

## Findings

| ID | Severity | Status | Summary |
|---|---|---|---|
| **F-UPDU-1** | MEDIUM | **CLOSED (2026-07-06)** | Registration-block account roots: `block_step` binds continuity/block-number/R6/G6 around the root swap; the remaining `reg.channelTreeRoot ↔ reg.channelRegHashChain` relation lived in the channel_reg chain circuit. That circuit is now modeled in `Circuits.ChannelRegStep`: `tree_and_chain_share_member_set` discharges the closing constraint (one shared `members` list feeds both the tree leaf's `memberRoot` and the chain's `regDigest`; R5 freshness; index=channel_id), and `chain_determines_tree` proves the L1-committed reg-hash chain PINS the Poseidon channel_tree_root the account root swaps to (keccak-CR + `PowTwoInj F 32`). Base-layer exposure closed to named standard assumptions. |
| **F-UPDU-2** | MEDIUM | **OPEN (flagged 2026-08-26)** | `UpdateUser.lean`'s per-slot bp-signature fold sections model the pre-M2′ wiring; `fd467ea` replaced it with a block-level thermometer N-of-N over the full 8-leaf recomputed member set (strictly STRONGER bindings; still exactly one fold per signing block). The abstraction `EndToEnd` consumes (opaque `accumulate`, one-fold dichotomy) remains sound; the in-file banner marks exactly which sections describe the old shape. Full re-model tracked in audit25-08-2026 Part 3. |
| **F-WD-2** | MEDIUM | **CLOSED (fix, Option B)** | Settle-twice nullifier: the nullifier preimage keyed on the settlement `block_number` (`send_leaf.cur`), so a tx settled into two blocks yielded two distinct nullifiers for one deduction (double withdrawal / double receive-credit, capped by global solvency). **Fixed** by re-keying the `SettledTransfer` preimage from `block_number` to the sender `tx.nonce` (`transfer.rs`), a settlement-independent one-time identifier bound to the deduction (sent-tx tree slot at index=nonce, spend_circuit empty-slot check). Two settlements now yield the IDENTICAL nullifier → caught by the on-chain `withdrawalNullifierUsed` set / recipient indexed merkle. Threat-modeled + attacker-red-teamed (GO) + adversarially reviewed (GO); Lean single-use re-derived from nonce-binding; **verified end-to-end by real proof generation** (`e2e_deposit_validity_withdrawal` ok 129s, `validity_proof_mle_onchain_e2e` ok 60s, forge 174/175). Corrected-Option-A (per-channel settled-nonce SET — NOT strict-increase, which the red-team found is a liveness bug) recorded as optional defense-in-depth, not required for the fund-safety closure. |
| F-WITHDRAW-1 (=C-M2) | Medium | **Closed** | 5 free extended fields re-pinned contract-side (`finalizedStateRoots` membership); the composition consumes only the re-pinned commitment, never a free field. |
| F-NULL-1 | — | **Discharged (genuinely, 2026-07-02)** | Preservation induction now PROVED: `genesis_inv` + `insert_preserves_inv` + `reachable_key_absent`. The former `gap`-as-hypothesis over-constraint is removed; `InsertConstraints` is circuit-gates-only. Key-injectivity found necessary (gap-emptiness alone is not inductive). |
| F-PUBST-1 | — | **Discharged** | `PublicStateTarget::is_equal` ANDs all 5 fields — `publicStateEq_sound`. |
| F-RECIP-1 | Info | Adjudicated | Padding many-to-one; not fund-exploitable. Leg 3 (tag separation) upgraded from prose to conditional theorem (`tag_separation` under `ReprFaithful`). |
| F-SPEND-1 | — | Closed | `is_valid` consumed (no-op + receive asserts). |
| F-ACCT-1 | — | Closed | `is_checked` true at all callers; widths match heights. |
| F-BLKR-1 | Low | Mostly resolved | `block_r ≤ block_number` on receive paths. |
| F-AUX-1 | — | Residual (by design) | `aux_data == tx_leaf_hash` enforced off-circuit at co-sign. |

## Trusted base (honest enumeration — see Field.lean header)

- `CField` (commutative integral domain; no characteristic axiom).
- Booleanity of the `ExponentiationGate` power-bit wires (`output_pow`'s `hb`):
  supplied by `BaseSumGate<2>` / `ConstantGate` plus the copy-constraint
  argument, NOT by the exponentiation gate itself (`sat_for_any_bits`).
- Opaque primitives: hashes (Poseidon/keccak/compress + per-struct leaf
  hashes — cross-domain separation is itself an idealization, noted in
  Bytes.lean), `repr`, `natLit`, `U256`/`uval`.
- Spec-level axiomatizations-by-definition: `U256.AddSpec`/`SubSpec`
  (justified by the carry/borrow zero-pins, u256.rs:292/:320).
- Named hypothesis families, each TRUE for the intended instantiation or an
  explicitly-caveated idealization: CR (`PoseidonCR`, `CompressCR`, `KeccakCR`,
  `NullifierRootBinding` — bounded to the 2^32 support), characteristic
  (`PowTwoInj F k`, k ≤ 63; char>4 one-hot), faithfulness (`ReprFaithful`,
  bounded `NatLitInj`), accumulator idealizations (`AccumulateNoFixpoint`,
  `AccumulateNeverEmpty`), totality (`AddTotal`/`SubTotal`).
- Contract-side named trust (Contracts/Assumptions.lean): the burn-path
  authorization-legitimacy assumption is SUPERSEDED — its target function was
  deleted 2026-07-28 and the assumption is retained only as the historical
  record (with the correction that `legit` was false-by-construction even for
  the honest manager); `allowMleDisabled=false`
  (constructor-enforced), single-call atomicity (reentrancy is outside the
  model; rests on `nonReentrant`+CEI in Solidity), ETH send-failure = revert.
- `BridgeAssumptions` (EndToEnd.lean): proof-system oracle, per-boundary
  recursion oracles (the balance IVC induction is named as not
  machine-checked), PI-layout equality (differential-test-backed),
  cross-module opaque identifications.

## Coverage

Every file under `src/circuits/` (non-channel) is modeled or mapped
(`Circuits/Plumbing.lean`); the constraint-emitting gadget layer under
`src/common/` + `src/utils/` (33 files) is inventoried with per-file status
and risk ratings in `tasks/gadget-inventory.md` (3 TODOs remain, risk-rated:
`enforce_ge/gt` characteristic argument, `reduce_to_hash_out` canonicity at
`tx_settlement.rs:289`, channel-scope comparisons). All contract lines
categorized in `Contracts/Coverage.lean`. On the on-chain side,
`Plonky2GateEvaluator._evalExponentiation` (gate id 8) is modeled in
`Core/Exponentiation.lean`; the remaining thirteen gate evaluators in that
file are covered by differential tests only — see
`doc/audit/audit12-08-2026.md`.
