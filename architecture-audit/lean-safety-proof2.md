# Lean safety proof of abstract2.md (Lattice version) — explanation, threat model, limitations

[`ChannelSafety2.lean`](./ChannelSafety2.lean) is the Lean 4 formalization and machine verification of the
safety properties of `abstract2.md` (v2 = Lattice/Regev confidential version). It **reuses, via import**, the v1 proof
[`ChannelSafety.lean`](./ChannelSafety.lean), and assumes the prerequisite knowledge of the v1 explanation
[`lean-safety-proof.md`](./lean-safety-proof.md).

## Verification method (2-step build)

```bash
cd architecture-audit
lean ChannelSafety.lean -o ChannelSafety.olean   # Compile v1 (reused part)
LEAN_PATH=$PWD lean ChannelSafety2.lean          # v2 body. exit 0 = all theorems verified
```

Lean 4.10.0 / core only. No use of `sorry` / `axiom`.

## Reuse from v1 and new parts

| Category | Content |
|---|---|
| **Reuse (import)** | base-layer ledger transition system and all theorems (supply conservation, balance non-negativity, nullifier uniqueness, aggregated exit upper bound), close game (`L1CloseRule`, `close_no_overdraw`, boundary double-spend), `Member` type and lemma group |
| **New (v2)** | `Ct` (plaintext semantics of Regev ciphertext), `EncBalanceState` (encrypted balance state), `Tag` (H2: internal / txRoot), tagged signature model, `ChannelUpdate`/`UpdateProven` (channelUpdateZKP soundness contract), **receiver side** `applyReceive`, inter-channel conservation law, structural atomicity, challenge game and close composition theorem over encrypted state |

## What v2 newly proves (diff from v1)

1. **Structural atomicity** — in v1, "atomicity of root signature and subtraction-state signature" was an
   **assumption** named `AtomicSigModel.atomic` (v1 audit finding 5). In v2, because the signed object is a pair
   `hash(H1, H2)`, we machine-verified via `bridgeToV1` that "from any v2 signature model a v1
   `AtomicSigModel` can be constructed, and the `atomic` field is **proven**".
   * Note however that this is a claim over the predicate model; binding to the contents of the tree that enters the root is a separate problem (M6, described below).
2. **Formalization of the receiver side** (partial resolution of v1 M4) — `applyReceive` +
   `receive_preserves_validity` (assumes only the fact `RecipientVerified` that the receiver can actually verify).
3. **Inter-channel conservation law** `interChannel_conservation` /
   `interChannel_conservation_bound` — by the equal-magnitude opposite-sign senderΔ and recipientΔ (channelUpdateZKP),
   the sum of the sender-side + receiver-side channel totals is conserved. The `_bound` version makes explicit the binding that "both sides open the same
   `TxLeafHash` commitment" as A1 (collision resistance = injectivity of `commit`).
4. **Tagged challenge / close composition** — `challenge_latest_wins2`, `end_to_end_close_safety2`
   (withdrawal is each party's proof of their own encrypted balance via `withdrawClaimZKP`, no cooperation of others needed).

## Theorem ↔ specification correspondence table (v2 new part)

| abstract2.md | Property | Lean theorem |
|---|---|---|
| §3.1 / §4.1 | authorization | `authorization2`, `confirmed_unique_per_version2` |
| §3.2 / §4.3 | solvency | `channelTx2_preserves_validity` |
| §3.4 / §4.3 | solvency | `send_preserves_validity` (including provenTotal monotone decrease) |
| §3.4 flowReceive3 | solvency | `receive_preserves_validity` (NEW) |
| §4.3 delta both-wings binding | conservation law | `interChannel_conservation(_bound)` (NEW) |
| §3.3.2 / §4.1 | authorization | `TransferAuthorized2`, `authorized_send_state_valid`, `bridgeToV1` (NEW: turning the v1 assumption into a theorem) |
| §3.3.5 | composition | `settled_transfer_guarantees` (`hcircuit` is an assumption, M6) |
| §3.5.2–3.5.3 / §4.4 | exit | `challenge_latest_wins2` |
| §3.5.4 | composition | `end_to_end_close_safety2` |
| — | non-vacuity | §9 Sanity (`sampleUpdate_proven`, `oneHonestModel2`, etc.) |

For the base layer (the no-double-spend family of §4.2), the v1 theorems apply as-is.

## Trust base (A1–A6)

- **A1** SPHINCS+ unforgeability + collision resistance of `hash(H1,H2)` (the signature binds the (state, tag) pair)
- **A2** ZK soundness (balanceProof / validityProof / channelUpdateZKP / withdrawClaimZKP)
- **A3** honest-member discipline (sign only valid, 1 version 1 state, freeze after close)
- **A4** correctness of the L1 contract
- **A5** correctness of the lattice homomorphism (**including the absence of noise overflow and modulo-p wraparound** — see finding 6 below)
- **A6** Regev IND-CPA (confidentiality = property 5. Out of model. Structural fact: the base-layer `Ledger` type
  has no per-member data)

## Second adversarial review findings and responses (2026-06-11)

Audit by an adversarial subagent separate from the implementation. 16 findings, 6 of which CRITICAL.

**Reflected in code**
- Finding 10: weaken the assumption of `receive_preserves_validity` to
  `RecipientVerified`, which the receiver can actually verify (the sender-side balance is not visible to the receiver, so it is removed from the assumptions).
- Finding 8: promote the "binding via variable sharing" of the inter-channel conservation law to
  an explicit commitment-injectivity (A1) assumption in `interChannel_conservation_bound`.
- Findings 1, 2, 14, 15: correct the docstrings of `settled_transfer_guarantees` / `bridgeToV1` / A6
  (clarify the boundary between assumption and conclusion, and that they are claims over the predicate model).
- Findings 5, 6: establish M5 anew, and add the non-disclosure of noise/wraparound to A5.

**Made explicit as model limitations (header M1–M7)**
- **M5** (findings 5, 14): `ValidEncState` is a predicate over everyone's plaintext, but an actual honest member
  can **only verify their own component + ZKP**. In-channel misallocation is, per the spec itself, an explicitly accepted risk.
  The conclusion of `authorization2` should be read as "what the honest check + the aggregation of A2 give".
- **M6** (findings 1, 2): `TransferAuthorized2` only binds the state to the bare root number, and
  **the agreement between the contents of the root's tree (TxLeafHash) and the subtraction** is unmodeled. `hcircuit` is a free hypothesis.
  Formalizing the validity-circuit constraints (parameterizing `Apply` by the signature model and the tx tree) is the main goal of v3.
- **M4 revised** (findings 9, 13): what is formalized on the receiver side is **accounting only**. The mechanism that prevents
  the **double credit** of the same settled tx (balanceProof recomputation) **is unmodeled**.

**Spec (abstract2.md)-level issues — fix recommended**
- **M7 / finding 11 (most important)**: at flowSend1 step 6, the post-subtraction state is finalized with everyone's signature
  **before L1 inclusion**. If the tx did not enter a block, a version v+1
  state with everyone's signature exists that includes a "subtraction that was not settled", and since the close game takes the highest version,
  **a subtraction for a transfer that never happened is forced at close**. Countermeasures: (a) require an L1 inclusion proof
  for close adoption of a `.txRoot`-tagged state, (b) advance the internal version only after inclusion is confirmed.
- **Finding 12**: the **retry / version-reassignment semantics** on transfer failure **are undefined**. Retry at the same version
  contradicts `OneStatePerVersion` (M3), and the honest member gets stuck. Explicit specification is needed, e.g. consuming a version
  per attempt.
- **Finding 3**: `H1 = hash(BalanceState)` includes `balanceProof`, but at signing time (step 6) the
  post-subtraction `balanceProof'` is not yet generated (it is generated at step 8). It should be specified that **H1 commits to
  `(encBalances, stateVersion, public inputs)` excluding the proof object**.
- **Finding 4**: the numerical collision between the reserved value `H2 = 0` and `tx_tree_root` (empty-tree root, etc.) and domain separation
  are unspecified. We recommend verification that rejects `H2 = 0` on the inter-channel path, and a domain-separation tag for the signed object.

## Revision (2026-06-11, reflecting findings 3, 5 into the spec)

We resolved audit finding 3 (H1 proof cycle) and finding 5 (missing in-channel range ZKP = M5)
**as spec changes to abstract2.md**, and made the model follow them:

1. **Making `channelTxZKP` (in-channel range ZKP) mandatory** — the sender proves "their own encrypted balance after the update ≥ 0",
   and it is added to the mandatory verification items of co-sign (abstract2.md §2.2 / §3.2).
   - Lean: introduce `ChannelTxProven` (ZKP soundness contract, A2) and replace the assumption of `channelTx2_preserves_validity`
     with it. Now the assumptions of that theorem become **all verifiable facts**, and inductive maintenance from a valid state
     holds (M5 resolved).
   - New theorem `claims_exactly_fill_cap`: in a valid finalized state, Σ(non-negative components) = `withdrawCap` holds
     **exactly** — recording the blocking of the "close-withdrawal hijacking" attack via negative balance components.
2. **state↔balanceProof binding via `settledTxChain`** — `H1` commits not to the proof object but to the
   hash chain of settle history (`TxLeafHash` / deposit hash). The balance circuit exposes the same chain
   in its public input, and L1 cross-checks for agreement at close/challenge (abstract2.md §2.1 / §3.5).
   - **Why a nullifier cannot be used**: the nullifier's preimage includes `block_number`, so it cannot be computed at
     signing time (flowSend1 step 6, before block posting). `TxLeafHash` is known, so there is no
     timing problem. Double-settle prevention via `block_number` binding is continued by the base-layer nullifier.
   - Lean §9: `chainOf_injective` (A1 collision resistance ⇒ chain agreement ⇒ same settle history) and
     `chain_binding_resolves_attachment` (a proof whose chain agrees proves exactly the total amount of the history that the state
     presupposes) machine-verify the soundness of the binding.

With this, the open spec issues are reduced to the 3 points of **M7 (signed-but-unsettled race), retry/version semantics,
and H2 domain separation**.

## Conclusion

The main improvements of v2 (structuring of signature atomicity, receiver-side conservation law) were backed by machine verification.
On the other hand, the review identified **4 unspecified points remaining in the spec itself** (M7's signed-but-unsettled race,
retry semantics, H1's proof cycle, H2 domain separation). For these, the recommended order is to first update the spec side in abstract3,
and then have the formalization follow with the v3 model (`Apply` signature parameterization, tx-tree binding,
receive replay prevention).
