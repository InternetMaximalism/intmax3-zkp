# intmax3-zkp — Lean formalization: audit summary

**Scope:** Plonky2 ZKP circuits + L1 Solidity contracts, excluding
cryptographic-primitive internals (Poseidon/SPHINCS+/Regev/MLE-WHIR —
uninterpreted). The channel-registration chain circuit
(`channel_reg_hash_chain/channel_reg_step.rs`) is now IN scope
(`Circuits.ChannelRegStep`), closing the former F-UPDU-1 residual. The
`update_channel_tree.rs` base-layer per-block update circuit is likewise modeled.
**Artifact:** `doc/audit/zkp/` — 42 Lean files, **228 machine-checked theorems**
(144 circuit + 62 contract + 22 end-to-end composition), 10,522 LOC,
**zero `sorry` / zero `axiom`**, clean `lake build` from scratch.

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
| Member-set immutability (producer cannot rotate members) | `member_set_immutable` | UpdateUser (NEW) |
| Registration root-swap: what block_step binds | `registration_root_swap_anchored` | UpdateUser (NEW) |
| Nullifier invariant PRESERVED from genesis (spend-once induction) | `genesis_inv`, `insert_preserves_inv`, `reachable_key_absent` | IndexedMerkle (repaired) |
| PublicState.is_equal ANDs all 5 fields (F-PUBST-1) | `publicStateEq_sound` | PublicStateEq (NEW) |
| Hash-chain base-case pinning (one-directional, honestly) | `first_step_pins_prev`, `chain_integrity` | HashChain (NEW) |
| Tag separation USER_ID≠ADDRESS (under `ReprFaithful`) | `tag_separation` | Recipient |
| PI layout no-aliasing (round-trip) | `pi_roundtrip_two` | Plumbing |
| Recursion-binding completeness of PIs | `connectPis_iff_eq` | BalancePis |

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
| Burn path: solvency-safe but PROOF-FREE (trust-gated) | `claimAuthorized_safe`, `burn_drain_satisfiable` (drain exhibited in-model) | IntmaxRollupWithdraw, Assumptions |
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

> Contract coverage: `Coverage.lean` categorizes all remaining lines of all
> THREE contracts (incl. the Manager close lifecycle). `verifySpecialClose` /
> `verifyLateOutgoingDebit` are classified DISABLED STUB (forgeable `_matches`
> stubs, inert via manager-side hard-disable) — NOT oracles.

## Findings

| ID | Severity | Status | Summary |
|---|---|---|---|
| **F-UPDU-1** | MEDIUM | **CLOSED (2026-07-06)** | Registration-block account roots: `block_step` binds continuity/block-number/R6/G6 around the root swap; the remaining `reg.channelTreeRoot ↔ reg.channelRegHashChain` relation lived in the channel_reg chain circuit. That circuit is now modeled in `Circuits.ChannelRegStep`: `tree_and_chain_share_member_set` discharges the closing constraint (one shared `members` list feeds both the tree leaf's `memberRoot` and the chain's `regDigest`; R5 freshness; index=channel_id), and `chain_determines_tree` proves the L1-committed reg-hash chain PINS the Poseidon channel_tree_root the account root swaps to (keccak-CR + `PowTwoInj F 32`). Base-layer exposure closed to named standard assumptions. |
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
- Contract-side named trust (Contracts/Assumptions.lean): burn-path
  authorization legitimacy (deployer→manager; violation = provable in-model
  drain, `burn_drain_satisfiable`), `allowMleDisabled=false`
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
categorized in `Contracts/Coverage.lean`.
