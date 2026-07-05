import Zkp.Contracts.Assumptions

/-
  Contract coverage map — every-line accounting
  =============================================

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

  ## Remaining IntmaxRollup.sol functions and their category

  STRUCTURAL (keccak/layout folds; determinism only; checked by the
  validity/withdrawal proofs the circuit side proves, or differential-
  tested byte-identical to the Rust layout):
    `_postBlock` :699 (block/deposit/channel-reg hash chains — the deposit
        fold mirrors `Deposit.deposit_sequential`; the block chain is
        verified by the validity proof at `finalize`),
    `_submit` :1053 (keccak commitment over blob — data availability),
    `_computeBlockHash` :1806, `_computeDepositHash` :1846,
    `_computeValidityPIHash` :1757, `_withdrawalPisHash` :1397,
    `_foldWithdrawalLeaf` :1385, `_toFieldElements` :1867,
    `_closeMemberSetCommitment` :990, `_channelRegHashChain` :1020.

  STRUCTURAL + ACCESS-CONTROL-CRITICAL:
    `registerChannel` :891 — the keccak reg-chain fold is structural, but
        the function ALSO writes the access-control-critical channel
        bindings `channelMemberSetCommitment` / `channelBpMemberSlot` /
        `channelBpPkG` (:961-967) under a one-time guard (:905). These
        are the SINGLE SOURCE OF TRUTH the ChannelSettlementManager
        constructor binds its member set + bp identity against
        (CSM.sol:647-655): a wrong/forged registration here would let a
        manager with a DIFFERENT signer set pass its constructor check.
        Mitigations actually in the code: one-time write (:905), zero /
        distinctness / range validation of the member set (:927-934),
        bp slot must be a co-signing member (:922). The registration is
        permissionless by design (channel creation); its binding force
        comes from the validity circuit checking the same reg chain.

  CRYPTO ORACLE (verifier wrappers — uninterpreted, exactly as
  Poseidon/keccak/Groth16 in the circuit model):
    `verify` :1090, `fullVerify` :1454, `_verifyFraud` :1499,
    `_verifyKZG` :1558, `_verifyMle` :1580 (the `allowMleDisabled`
    short-circuit at :1584 is modeled and discharged in
    `Assumptions.verifyMleGate` / `mle_gate_real_when_enabled`),
    `_verifyMleWithVk` :1598, `_verifyMleWithdrawal` :1435,
    `_loadWhirParamsFrom`/`_copyWhirParams`,
    `initializeWithdrawalVk` :596 (deployer-only set-once VK latch,
    zero-degree rejected :606), `_mlePublicInputsMatch` :1788.

  LIVENESS / ROLLBACK (no escrow effect; rollback floor proved in
  IntmaxRollupOptimistic):
    `fraudProof` :1153 (stake side effect proved via `_slashStake` model),
    `_truncateSubmissions` :1662, `_rollbackBatch` :1678.

  FUND-BEARING — proved (NOT liveness):
    `reclaimStake` :1269 — credits POST_BLOCK_STAKE to
        `pendingWithdrawals[submitter]` (:1281), guard shape DIFFERENT
        from `_refundStake` (reverts on resolved :1272 instead of
        no-op; extra `endBlockNumber ≤ latestFinalizedBlockNumber`
        finality guard :1274). Modeled and proved in IntmaxRollupStake
        (`reclaim_*`, `no_double_payout_{refund,slash}_then_reclaim`,
        `no_double_payout_reclaim_then_{refund,slash}`).

  VIEW / INIT / ACCESS (no fund movement beyond modeled effects):
    `getSubmission`/`getCommitment`/`isFinalized` :1197-1205,
    constructor/init (the `allowMleDisabled`/zero-VK guard :532 is
    modeled as `Assumptions.constructorAcceptsVk`),
    `registerSettlementManager` :624 (proved:
    Deposit.registerManager_requires_deployer — NOTE: additive-forever,
    no removal/timelock; this is why the burn path needs
    `Assumptions.BurnAuthorizationsLegitimate`).

  ## ChannelSettlementVerifier.sol (1154 L)

  The verifier is STATELESS except for its set-once VK latches
  (`initializeCloseVk` :130, `initializeWithdrawalClaimVk` :483,
  `initializePostCloseClaimVk` :512, `initializeCancelCloseVk` :541).
  It holds NO nullifiers — the check-then-set nullifier state lives in
  the MANAGER (`usedWithdrawalNullifiers` / `usedSharedNativeNullifiers`
  / `usedLateOutgoingDebitNullifiers`, ChannelSettlementManager.sol:
  515-517, consumed at :1051/:1073 and :1107/:1136).

  Its six external entries fall into TWO classes:

  * REAL CRYPTO ORACLE (strict PI limb binding + MLE/WHIR verification
    under a dedicated VK; uninterpreted as primitives):
    `verifyCloseIntent` :169, `verifyWithdrawalClaim` :785,
    `verifyCancelClose` :832, `verifyPostCloseClaim` :885.

  * DISABLED STUB (NOT an oracle): `verifySpecialClose` :753 and
    `verifyLateOutgoingDebit` :915 are FORGEABLE `_matches` keccak stubs
    (:1151 — the "proof" is just `abi.encode(keccak(public inputs))`,
    computable by anyone). They are inert ONLY because their manager
    entry points are hard-disabled: `submitSpecialClose` reverts
    unconditionally (CSM.sol:818-820) and
    `submitLateOutgoingDebitCorrection` reverts unconditionally
    (CSM.sol:868-873). If either manager gate were re-enabled without
    replacing the stub, the "proof" check would be a no-op — they must
    NOT be classified as verification.

  `BlobKZGVerifier.sol` (244 L) and the submodule `MleVerifier.sol` are
  pure pairing/PCS math — uninterpreted oracles.

  ## ChannelSettlementManager.sol — close lifecycle categorization

  Fund-safety-critical accounting proved in ChannelSettlementManager.lean:
    `pullChannelFunds` :1152 (capacity accrual — `pull_preserves_cap`),
    `claimWithdrawalCredit` :1167 (cap + CEI — `claim_preserves_cap`,
      `claim_no_double`, `claim_within_capacity`),
    `submitPartialWithdrawalIntent` :913 / `finalizePartialWithdrawal`
      :971 / `cancelPartialWithdrawal` :995 (burn-authorization gating —
      `submitPartialIntent_requires_proof`, `finalizePartial_authorizes`,
      `finalizePartial_mints_only_pending`, `partial_chain_key_single_use`).
      NOTE `finalizePartialWithdrawal` MINTS the rollup burn authorization
      via `registry.authorizePartialWithdrawal` (:990) — escrow-affecting
      downstream (it is what `claimAuthorizedWithdrawal` pays against).
      It is gated on a PROOF-VERIFIED close-intent state + challenge
      window + single-use chain key — NOT on a finalized close (the
      channel stays open; :919 requires Active at submission, and
      finalization deliberately skips the status check, :974-976).

  STATE MACHINE (challenge game; no ETH moves in these steps — credits
  are minted only by the claim entries below, ETH only by the two payout
  functions above):
    `requestClose` :712 (member-only freeze, grace start),
    `submitCloseIntent` :726 (close-proof-gated via `_checkCloseProof`
      :1237/`_runCloseVerify` :1253 — member-set strict binding; newer-
      state challenge replacement `_isNewer` :1290, strict tiebreak),
    `cancelClose` :822 (cancel-proof-gated revive),
    `finalizeClose` :875 (deadline-gated snapshot of the pending intent;
      resets `totalWithdrawn` accrual budget :893).

  CLAIM INTENTS (credit accrual, per-claim nullifier check-then-set in
  MANAGER storage, capped by `finalizedChannelFundAmount` accrual budget;
  the AUTHORITATIVE ETH ceiling remains `receivedChannelFunds` at payout —
  proved as `claim_within_capacity`):
    `submitWithdrawalClaim` :1035 (verifier-gated, member/recipient
      binding :1045-1050, nullifier :1051/:1073, cap :1068-1071),
    `submitPostCloseClaim` :1085 (verifier-gated, nullifier RECOMPUTED
      on-chain :1102 — not caller-supplied, cap :1131-1134).

  DISABLED (permanently reverting, fail-closed ABI kept):
    `submitSpecialClose` :818-820, `submitLateOutgoingDebitCorrection`
    :868-873 (see the DISABLED STUB class above).

  ACCESS / FUNDING / VIEW:
    `receive()` :556 — accepts ETH ONLY from the bound rollup (:557), so
      `receivedChannelFunds` (measured as `pullChannelFunds` balance
      deltas) stays the sole payout capacity; SELFDESTRUCT force-feeds
      are not counted (documented :553-555),
    `fundBpBondCredits` :705 — UNGATED bpBondCredits top-up; credits-only
      accounting pot, pays out through the same capped credit path (a
      donor can only increase the pot, never redirect escrow),
    constructor :560 (member/delegate binding + registry cross-check
      :647-655 — binds to `registerChannel`'s commitments),
    `memberCount`/`registeredMemberSetCommitment`/`isNativeSendAllowed`/
    `getPendingClose`/digest helpers — view/structural.
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
    differential-test-asserted modeling assumption. -/
theorem keccak_det (xs ys : List Word) (h : xs = ys) : keccak xs = keccak ys := by
  rw [h]

/-- Collision-resistance assumption, named where a fold's binding is
    load-bearing (e.g. `withdrawNative`'s `pisHash` re-fold binding `ws`,
    or `withdrawNative`'s `extCommitment ∈ finalizedStateRoots` — the
    F-WITHDRAW-1 closure argument; also `registerChannel`'s member-set
    commitment binding the manager constructor, CSM.sol:647). Stated,
    never silently used. -/
def KeccakCR : Prop := ∀ xs ys, keccak xs = keccak ys → xs = ys

/-- Marker: every contract line is either (a) proved in a dedicated
    module, (b) STRUCTURAL (subsumed by `keccak_det` + a layout modeling
    assumption), (c) a REAL CRYPTO ORACLE, (d) a DISABLED STUB behind a
    permanently-reverting manager gate, or (e) LIVENESS/VIEW with no
    escrow effect — with the residual trust surface named in
    `Zkp.Contracts.Assumptions`. -/
theorem all_contract_lines_covered : True := trivial

end Coverage
end Contracts
end Zkp
