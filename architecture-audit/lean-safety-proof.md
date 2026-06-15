# Lean Safety Proof for abstract.md — Explanation, Threat Model, Limitations

The 4 safety properties of `abstract.md` (the minimal specification) formalized in Lean 4 and machine-checked is
[`ChannelSafety.lean`](./ChannelSafety.lean). This document records how to read it, its trust base, and the
limitations found in adversarial review.

## Verification Method

```bash
cd architecture-audit
lean ChannelSafety.lean   # Lean 4.10.0 / core only (mathlib not used). exit 0 = all theorems verified
```

`sorry` / `axiom` / `native_decide` are not used (confirmed via grep). All claims are checked by the Lean kernel.

## Threat Model

- **Adversary**: at most 2 of the 3 channel members, the Block Producer (BP), and any party external to the channel.
  These can send arbitrary messages, arbitrary `BalanceState`, and arbitrary close/challenge submissions.
- **What is protected**: the **safety side** of the 4 properties in abstract.md §0
  (no finalization of invalid state, supply conservation, no nullifier reuse, withdrawal cap, no stale close).
- **Trust base (assumed unbreakable)**: forgery of SPHINCS+ signatures, breaking the ZK soundness of
  balanceProof / validityProof, L1 contract bugs, L1 censorship. These are stated explicitly as A1–A4 in the file header
  in the form of hypotheses. **Liveness (timeout reachability, L1 inclusion, delivery) is out of scope.**

## Theorem ↔ Specification Correspondence Table

| abstract.md | Property | Lean theorem | Content |
|---|---|---|---|
| §3.1 / §4.1 | Authorization | `authorization` | If at least one honest member exists, a finalized (all-signed) state is necessarily valid |
| §3.1 | Authorization | `confirmed_unique_per_version` | A finalized state of the same version is unique |
| §3.2 / §4.3 | solvency | `channelTx_preserves_validity` | In-channel transfers preserve balance and non-negativity (total = provenTotal invariant) |
| §3.4 / §4.3 | solvency | `interSend_preserves_validity` | The post-subtraction state is valid and provenTotal monotonically decreases (sender side) |
| §3.4 invariant / §4.1 | Authorization | `atomicity_no_loss_shift` | Transfer authorization ⇒ finalization of the post-subtraction state (no loss shifting) ※ making assumption explicit, see note M below |
| §3.4 | Authorization | `atomicity_comember_unaffected` | Subtraction is borne only by the sender; co-member balances unchanged |
| §3.3 / §4.2 | no-double-spend | `apply_conservation` / `exec_conservation` | Supply change = Σdeposit − Σburn (transfer cannot mint) |
| §2.3 / §4.2 | no-double-spend | `no_double_settlement` | The same nullifier (bound by block number) cannot be settled twice ※M1 |
| §3.3.1 / §4.3 | solvency | `apply_nonneg` / `exec_nonneg` | Under the rangeProof condition, all balances remain non-negative invariantly |
| §3.5.4 / §4.2 C2,C5 | Withdrawal cap | `close_no_overdraw` | Σwithdrawal ≤ withdrawCap ≤ actual L2 balance (assuming burn success ※M2) |
| §3.5.4 / §4.2 C1 | no-double-spend | `close_boundary_no_double_spend` | L1 withdrawal + remaining L2 spendable ≤ pre-close balance (no boundary double spend) |
| §3.5.4 + §3.5.5 | no-double-spend | `exec_exit_bound` | close burn + total of all late claims ≤ initial supply + Σdeposit (aggregate solvency) |
| §3.5.2–3.5.3 / §4.4 | Exit | `challenge_latest_wins` | If the latest finalized state is submitted, close with a stale state is impossible |
| Overall composition | 1–4 | `end_to_end_close_safety` | Each party's receipt ≤ agreed balance, total withdrawal ≤ actual balance, cap = agreed total (no excess or shortfall) |
| — | Non-vacuity | §9 Sanity (`oneHonestModel` etc.) | Witness that the assumptions are not contradictory (the proof is not vacuous) |

## Trust Base (Summary of File Header A1–A4)

- **A1** SPHINCS+ unforgeability (signature = predicate `signsState`)
- **A2** ZK soundness of balanceProof / validityProof (embedded in the transition system as the `hsolv`-side condition)
- **A3** Discipline of honest members (sign only valid, 1 version 1 state, stop signing after requestClose)
- **A4** Correctness of the L1 contract (all-signature check, monotonic version replacement, Σwithdrawal ≤ cap)

## Adversarial Review Findings and Responses (2026-06-10)

An audit by an adversarial review subagent, separate from the implementation, was conducted. Findings and actions:

**Fixed (reflected in code/wording)**
1. `interSend_preserves_validity` did not use `0 ≤ amount` → added
   "provenTotal monotonically decreases" to the conclusion, making the assumption substantive (corresponds to §4.3 monotonic update).
2. There was no aggregate solvency theorem for close + late claim → added `exec_exit_bound`.
   Proved that the attack "the same L2 balance backs both the close withdrawal and the late claim" is impossible at the ledger layer.
3. The witness of non-vacuity only had the all-honest configuration → added
   `oneHonestModel` with 1 honest member + 2 unconstrained adversaries.
4. The docstrings of `atomicity_no_loss_shift` / `close_no_overdraw` / `no_double_settlement` /
   `challenge_latest_wins` could read as stronger than the proof content → clarified the boundary between assumptions and conclusions.

**Stated explicitly as model limitations (header M1–M4; candidates for future strengthening)**
- **M1 — 1 block 1 settlement abstraction**: `no_double_settlement` derives uniqueness from the block number alone.
  Since the real system batches multiple txs into 1 block via `TxV2Tree`, in-block uniqueness depends on
  `nullifier()`'s `transfer_index` / `from`. This is not modeled.
  *Strengthening proposal*: make a block a list of ops and prove uniqueness from `(block_number, transfer_index, from)`.
- **M2 — provenTotal and ledger not connected**: `BalanceState.provenTotal` is a free value at the state layer, and
  "a proof cannot prove beyond the actual balance" (A2) takes effect only at exit time via `hsolv`.
  Therefore `close_no_overdraw` assumes "the L2 burn succeeded" (it is not derived).
  *Strengthening proposal*: introduce a predicate connecting `provenTotal ≤ spendable` and theorematize the backing at signing time.
- **M3 — OneStatePerVersion is a discipline assumption**: a race where an honest member signs different states
  of the same version due to concurrent transfers or crash recovery is not ruled out by the text of §3.1 alone. The protocol implementation side must
  guarantee single-threaded signing / persistence (recommend adding to the spec).
- **M4 — receiver-side / lateBalanceProof individual management not modeled**: `flowReceive3` (provenTotal-increasing side) and
  "lateBalanceProof is stored on-chain as a separate variable from finalBalanceProof" (§3.5.5) are not modeled individually;
  the aggregate upper bound of `exec_exit_bound` is used as a substitute. Formalization of the receiver-side rejection of forged balanceProof (§3.4 flowReceive3
  step 1) is a future task.

**Implications for the specification (abstract.md) side**
- §3.1 should explicitly state "prohibition of double-signing the same version (including crash recovery)" (M3).
- It should be made explicit that the in-block uniqueness of the §2.3 nullifier depends on `transfer_index`/`from`
  as the basis for double-spend prevention (M1).

## Conclusion

The safety side of the 4 properties of abstract.md is **all machine-verified** under the A1–A4 trust base and the M1–M4
abstractions. The points where the proof remains at "making assumptions explicit" (atomic signing rule, burn success) are
stated explicitly in the docstrings and the header; these can be read as a list of verification items to be ensured on the
implementation (circuit / L1 contract) side.
