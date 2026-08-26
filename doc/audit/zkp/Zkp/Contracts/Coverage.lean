import Zkp.Contracts.Assumptions

/-
  Contract coverage map — every-line accounting
  =============================================

  LINE MAP RE-POINTED 2026-08-26 (staleness remediation, audit25-08-2026
  Part 4.3: the previous map was ~300-350 lines off after the close/claim
  refactors, `fd467ea` sig-cluster, and §Q). All `:N` cites below were
  re-read against the WORKING TREE at the re-sync commit. This file is a
  CATALOG, not a proof — see the marker at the bottom.

  This file closes literal "every line" coverage for the Intmax3
  contracts by categorizing every remaining function (those not given a
  dedicated soundness theorem) and pointing to the proved invariant or
  modeling assumption that subsumes it. Same device as the circuit
  `Circuits/Plumbing.lean`. The fund-safety-critical accounting is fully
  proved in the dedicated modules:

    IntmaxRollupWithdraw   — withdrawNative / withdraw / claimAuthorized /
                             finalize (solvency ceiling, no-double, proof-
                             required, finalize-only-on-valid, CEI claim)
    IntmaxRollupSolvency   — deposit + GLOBAL solvency (Σ out ≤ Σ in) over
                             traces of ALL THREE escrow movers (deposit /
                             withdrawNative / claimAuthorizedWithdrawal)
    IntmaxRollupStake      — stake single-resolution + conservation across
                             ALL THREE resolvers (refund / slash / reclaim)
    IntmaxRollupDeposit    — deposit hash chain (↔ circuit) + access control
    IntmaxRollupOptimistic — rollback floor, finalized roots permanent
    ChannelSettlementManager — channel payout cap + no-double-claim +
                             partial-withdrawal (burn) authorization gating
    Assumptions            — NAMED trust/modeling assumptions the above
                             rest on (burn-path deployer/manager trust,
                             allowMleDisabled=false, single-call atomicity,
                             send-failure-reverts)

  ## Remaining IntmaxRollup.sol (2140 L) functions and their category

  STRUCTURAL (keccak/layout folds; determinism only; checked by the
  validity/withdrawal proofs the circuit side proves, or differential-
  tested byte-identical to the Rust layout — the differential pins were
  RE-CUT under the 8-slot sig-cluster layout at `fd467ea`:
  `PINNED_MC2`/`PINNED_MC8` in `IntmaxRollup.t.sol` ↔
  `channel_registration.rs`, the 16-member pin dropped on both sides):
    `_postBlock` :850 (block/deposit/channel-reg hash chains — the deposit
        fold mirrors `Deposit.deposit_sequential`; the block chain is
        verified by the validity proof at `finalize`),
    `_submit` :1226 (keccak commitment over blob — data availability),
    `_computeBlockHash` :2080, `_computeDepositHash` :2120,
    `_computeValidityPIHash` :2031, `_withdrawalPisHash` :1680,
    `_foldWithdrawalLeaf` :1668,
    `_closeMemberSetCommitment` :1163 (the IMCM commitment —
        `keccak([IMCM, member_count, pk_g_0..pk_g_7])` over the 8
        sig-cluster slots since `fd467ea`),
    `_channelRegHashChain` :1193.
    (REMOVED since the previous map: `_toFieldElements`, `_verifyKZG` —
    the KZG helper surface was folded into the blob/verify path.)

  STRUCTURAL + ACCESS-CONTROL-CRITICAL:
    `registerChannel` :1064 — the keccak reg-chain fold is structural, but
        the function ALSO writes the access-control-critical channel
        bindings `channelMemberSetCommitment` / `channelBpMemberSlot` /
        `channelBpPkG` under a ONE-TIME guard (:1078
        `ChannelAlreadyRegistered`). These are the SINGLE SOURCE OF
        TRUTH the ChannelSettlementManager constructor binds its member
        set + bp identity against (CSM.sol:847): a wrong/forged
        registration here would let a manager with a DIFFERENT signer
        set pass its constructor check. Mitigations in the code:
        one-time write, zero/distinctness/length validation of the
        member set (:1084-1092 ff.), bp slot must be a co-signing
        member. Registration is permissionless by design (channel
        creation); its binding force comes from the validity circuit
        checking the same reg chain.

  CRYPTO ORACLE (verifier wrappers — uninterpreted, exactly as
  Poseidon/keccak in the circuit model):
    `verify` :1263, `fullVerify` :1737, `_verifyFraud` :1782,
    `_verifyMle` :1854 (the `allowMleDisabled` short-circuit is modeled
    and discharged in `Assumptions.verifyMleGate` /
    `mle_gate_real_when_enabled`),
    `_verifyMleWithVk` :1872, `_verifyMleWithdrawal` :1718,
    `_loadWhirParamsFrom` :1895 / `_copyWhirParams` :664,
    `initializeWithdrawalVk` :703 (deployer-only set-once VK latch),
    `_mlePublicInputsMatch` :2062.

  LIVENESS / ROLLBACK (no escrow effect; rollback floor proved in
  IntmaxRollupOptimistic):
    `fraudProof` :1326 (stake side effect proved via `_slashStake` model),
    `_truncateSubmissions` :1936, `_rollbackBatch` :1952.

  FUND-BEARING — proved (NOT liveness):
    `reclaimStake` :1448 — credits POST_BLOCK_STAKE to
        `pendingWithdrawals[submitter]`, guard shape DIFFERENT from
        `_refundStake` (reverts on resolved instead of no-op; extra
        finality guard). Modeled and proved in IntmaxRollupStake
        (`reclaim_*`, `no_double_payout_{refund,slash}_then_reclaim`,
        `no_double_payout_reclaim_then_{refund,slash}`).

  VIEW / INIT / ACCESS (no fund movement beyond modeled effects):
    `getSubmission`/`getCommitment`/`isFinalized` :1370-1384,
    constructor :635 ff. (the `allowMleDisabled`/zero-VK guard is
    modeled as `Assumptions.constructorAcceptsVk`),
    `registerSettlementManager` :731 (proved:
    Deposit.registerManager_requires_deployer — NOTE: additive-forever,
    no removal/timelock; this is why the burn path needs the
    Assumptions burn-path trust surface).

  ## ChannelSettlementVerifier.sol (1396 L)

  The verifier is STATELESS except for its set-once VK latches
  (`initializeCloseVk` :188, `initializeMemberSetUpdateVk` :221 — §Q,
  shares the close wrapper rail, requires the close VK first,
  `initializeWithdrawalClaimVk` :754, `initializePostCloseClaimVk` :783,
  `initializeCancelCloseVk` :812).
  It holds NO nullifiers — the check-then-set nullifier state lives in
  the MANAGER (`usedWithdrawalNullifiers` / `usedSharedNativeNullifiers`
  / `usedLateOutgoingDebitNullifiers`, ChannelSettlementManager.sol:
  700-702, consumed at :1527/:1552 and :1586/:1636).

  Its external verification entries fall into TWO classes:

  * REAL CRYPTO ORACLE (strict PI limb binding + MLE/WHIR verification
    under a dedicated VK; uninterpreted as primitives):
    `verifyCloseIntent` :324, `verifyMemberSetUpdate` :243 (§Q —
    strict 26-limb bind, real-proof forge-tested in
    `MemberSetUpdateE2E.t.sol`), `verifyWithdrawalClaim` :1081,
    `verifyCancelClose` :1132, `verifyPostCloseClaim` :1188.
    `closeMemberSetCommitment` :1262 is the structural IMCM helper
    (8-slot layout, shared with the Manager and the circuit).

  * DISABLED STUB (NOT an oracle): `verifySpecialClose` :1041 and
    `verifyLateOutgoingDebit` :1220 are FORGEABLE `_matches` keccak
    stubs (:1393 — the "proof" is just `abi.encode(keccak(public
    inputs))`, computable by anyone). They are inert ONLY because their
    manager entry points are hard-disabled: `submitSpecialClose`
    reverts unconditionally (CSM.sol:1154) and
    `submitLateOutgoingDebitCorrection` reverts unconditionally
    (CSM.sol:1204). If either manager gate were re-enabled without
    replacing the stub, the "proof" check would be a no-op — they must
    NOT be classified as verification.

  `BlobKZGVerifier.sol` (297 L) and the submodule `MleVerifier.sol` are
  pure pairing/PCS math — uninterpreted oracles.

  ## ChannelSettlementManager.sol (1880 L) — close lifecycle categorization

  Fund-safety-critical accounting proved in ChannelSettlementManager.lean
  (+ the multi-token variant in ChannelSettlementManagerMT.lean):
    `pullChannelFunds` :1653 (capacity accrual — `pull_preserves_cap`),
    `claimWithdrawalCredit` :1684 (native) / :1700 (per-token overload,
      NEW since the previous map) (cap + CEI — `claim_preserves_cap`,
      `claim_no_double`, `claim_within_capacity`),
    `submitPartialWithdrawalIntent` :1271 / `finalizePartialWithdrawal`
      :1428 / `cancelPartialWithdrawal` :1457 (burn-authorization gating —
      `submitPartialIntent_requires_proof`, `finalizePartial_authorizes`,
      `finalizePartial_mints_only_pending`; the channel-state lifecycle
      incl. the cancel-restore theorem is `ChannelSafetyPW.lean`,
      audit V3). NOTE `finalizePartialWithdrawal` MINTS the rollup burn
      authorization via `registry.authorizePartialWithdrawal` —
      escrow-affecting downstream (it is what `claimAuthorizedWithdrawal`
      pays against). It is gated on a PROOF-VERIFIED close-intent state
      + challenge window + single-use chain key — NOT on a finalized
      close (the channel stays open).

  STATE MACHINE (challenge game; no ETH moves in these steps — credits
  are minted only by the claim entries below, ETH only by the payout
  functions above). The machine itself is now PROVED at design level:
  `ChannelSafetyClose.lean` (audit V2 — 12 theorems: terminal finalize,
  windowed cancel, strict-newer challenge monotonicity, freeze-nonce
  replay guard, honest-exit liveness):
    `requestClose` :1040 (member-only freeze, grace start),
    `submitCloseIntent` :1054 (close-proof-gated via `_checkCloseProof`
      :1784/`_runCloseVerify` :1822 — member-set strict binding; newer-
      state challenge replacement `_isNewer` :1869, strict tiebreak),
    `cancelClose` :1158 (cancel-proof-gated revive),
    `finalizeClose` :1211 (deadline-gated snapshot of the pending
      intent; the accrual budget uses `+=` semantics — the legacy
      `totalWithdrawn = 0` reset was REMOVED as unnecessary, :1232).

  §Q MEMBER-SET UPDATE (NEW):
    `applyMemberSetUpdate` :933 — Active-only, strict version+1,
      count +0/+1, oldCommitment recomputed from OWN storage,
      newCommitment recomputed from calldata, gated on
      `verifyMemberSetUpdate` (REAL MLE proof; no VK ⇒ revert, no
      seam). Design-level model: `ChannelSafetyQ.lean` (audit V1);
      real-proof E2E: `MemberSetUpdateE2E.t.sol` (6 tests).

  CLAIM INTENTS (credit accrual, per-claim nullifier check-then-set in
  MANAGER storage, capped by the accrual budget; the AUTHORITATIVE ETH
  ceiling remains `receivedChannelFunds` at payout — proved as
  `claim_within_capacity`):
    `submitWithdrawalClaim` :1498 (verifier-gated, member/recipient
      binding, nullifier :1527/:1552),
    `submitPostCloseClaim` :1565 (verifier-gated, nullifier RECOMPUTED
      on-chain — not caller-supplied, :1586/:1636).

  DISABLED (permanently reverting, fail-closed ABI kept):
    `submitSpecialClose` :1154, `submitLateOutgoingDebitCorrection`
    :1204 (see the DISABLED STUB class above).

  ACCESS / FUNDING / VIEW:
    `receive()` :744 — accepts ETH ONLY from the bound rollup (:745), so
      `receivedChannelFunds` (measured as `pullChannelFunds` balance
      deltas) stays the sole payout capacity; SELFDESTRUCT force-feeds
      are not counted,
    constructor :748 (member/delegate binding + registry cross-check
      :847 — binds to `registerChannel`'s commitments),
    `memberCount`/`registeredMemberSetCommitment`/`memberSetVersion`/
    `isNativeSendAllowed`/`getPendingClose`/digest helpers —
    view/structural.
    (REMOVED since the previous map: `fundBpBondCredits` — deleted,
    see the tombstone comment at CSM.sol:1023.)
-/

namespace Zkp
namespace Contracts
namespace Coverage

open Zkp.Contracts.Evm

/-- A keccak commitment over a preimage (uninterpreted). Determinism (same
    preimage ⇒ same digest) is automatic; collision resistance is the
    named assumption where a STRUCTURAL fold's binding is relied upon
    (e.g. `_foldWithdrawalLeaf` binding `ws` to the proof's pis_hash). -/
opaque keccak : List Word → Word

/-- Determinism of the structural folds: equal preimages ⇒ equal
    commitments. This is all the contract logic needs from the hash
    helpers; the byte-identical layout vs the Rust/circuit side is a
    differential-test-asserted modeling assumption (pins re-cut for the
    8-slot sig-cluster layout at `fd467ea`). -/
theorem keccak_det (xs ys : List Word) (h : xs = ys) : keccak xs = keccak ys := by
  rw [h]

/-- Collision-resistance assumption, named where a fold's binding is
    load-bearing (e.g. `withdrawNative`'s `pisHash` re-fold binding `ws`,
    or `withdrawNative`'s `extCommitment ∈ finalizedStateRoots` — the
    F-WITHDRAW-1 closure argument; also `registerChannel`'s member-set
    commitment binding the manager constructor, CSM.sol:847). Stated,
    never silently used. -/
def KeccakCR : Prop := ∀ xs ys, keccak xs = keccak ys → xs = ys

/-- CATALOG MARKER — deliberately `True`, and deliberately labeled: this
    records that every contract line has been placed in a category
    ((a) proved in a dedicated module, (b) STRUCTURAL — subsumed by
    `keccak_det` + a layout modeling assumption, (c) a REAL CRYPTO
    ORACLE, (d) a DISABLED STUB behind a permanently-reverting manager
    gate, or (e) LIVENESS/VIEW with no escrow effect — residual trust
    named in `Zkp.Contracts.Assumptions`). It PROVES nothing about the
    contracts; treating this map as verification is the exact
    mechanism-B failure audit25-08-2026 Part 2 documents. The map is
    only as current as its re-sync date in the header. -/
theorem all_contract_lines_covered : True := trivial

end Coverage
end Contracts
end Zkp
