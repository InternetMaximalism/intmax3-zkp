// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseSettlementBase} from "./CloseSettlementBase.sol";
import {CloseTestLib} from "./CloseTestLib.sol";

/// @title CloseLifecycleHardening
/// @notice Regression fences for the 2026-08-28 audit's close-lifecycle findings on
///         `ChannelSettlementManager`: C-3 (one `cancelClose` bricked the channel forever), C-2
///         (post-close claim double-credits an already-applied transfer), H-3 (the challenge-window
///         ladder). The H-6 fences (the Manager's partial-withdrawal era/ordering gates) were removed
///         on 2026-10-09 with that path: a burn is paid by the rollup on its base withdrawal proof
///         alone and ordered against a close by the `CloseFundingMaterializer` journal, pinned in
///         `SignerIndependentExit.t.sol`.
///
/// @dev Every test here is written to FAIL if its guard is reverted. Each one names the guard it
///      pins in its own doc comment so a future edit that removes the guard cannot quietly also
///      remove the evidence.
contract CloseLifecycleHardeningTest is CloseSettlementBase {
    uint32 internal constant TOKEN_INDEX = 0;

    // ─────────────────────────────────────────────────────────────────────────
    // helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _cancelProof(ChannelSettlementManager.CancelCloseRequest memory request)
        internal view returns (bytes memory)
    {
        ChannelSettlementManager.PendingClose memory pending = manager.getPendingClose();
        uint64 closeFinalStateVersion = pending.active && pending.closeIntentDigest == request.closeIntentDigest
            ? pending.finalStateVersion
            : 0;
        return CloseTestLib.proofWithLimbs(
            verifier.expectedCancelCloseLimbs(
                CHANNEL_ID,
                request.closeIntentDigest,
                manager.registeredMemberSetCommitment(),
                closeFinalStateVersion,
                request.revivedStateVersion,
                request.revivedChannelStateDigest
            )
        );
    }

    function _cancelRequest(bytes32 closeIntentDigest, uint64 revivedVersion)
        internal pure returns (ChannelSettlementManager.CancelCloseRequest memory)
    {
        return ChannelSettlementManager.CancelCloseRequest({
            closeIntentDigest: closeIntentDigest,
            revivedStateVersion: revivedVersion,
            revivedChannelStateDigest: keccak256(abi.encodePacked("revived", revivedVersion))
        });
    }

    /// An era-1 close intent at an explicit `(epoch, stateVersion)`. Era 1 is the ONLY era a real
    /// close proof can carry: the close PI is `signedState.close_freeze_nonce + 1` and no shipped
    /// code ever advances a `ChannelState.close_freeze_nonce` past 0 (audit C-3).
    function _intentAt(uint64 epoch, uint64 stateVersion)
        internal pure returns (ChannelSettlementManager.CloseIntent memory intent)
    {
        intent = _intent(1, epoch, 22, 1);
        intent.finalStateVersion = stateVersion;
        intent.finalChannelStateDigest = keccak256(abi.encodePacked("final_state", epoch, stateVersion));
    }

    /// The deadline boundary has one owner: replacement. At `now == deadline`, finalization must
    /// fail and a strictly-newer close must still land, so transaction ordering cannot choose the
    /// settled state. The replacement itself becomes finalizable only strictly after its deadline.
    function test_closeDeadlineEqualityBelongsToReplacementNotFinalize() public {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory stale = _intentAt(9, 10);
        manager.submitCloseIntent(stale, _closeProof(stale));

        uint64 staleDeadline = manager.getPendingClose().challengeDeadline;
        vm.warp(staleDeadline);

        bytes32 finalizeDigest = manager.getPendingClose().closeIntentDigest;
        uint64 finalizeGeneration = manager.closeRequestGeneration();
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowOpen.selector);
        manager.finalizeCloseGuarded(finalizeDigest, finalizeGeneration);

        ChannelSettlementManager.CloseIntent memory newer = _intentAt(9, 11);
        manager.submitCloseIntent(newer, _closeProof(newer));
        assertEq(manager.getPendingClose().finalStateVersion, 11, "replacement owns equality");

        uint64 newerDeadline = manager.getPendingClose().challengeDeadline;
        vm.warp(newerDeadline);
        finalizeDigest = manager.getPendingClose().closeIntentDigest;
        finalizeGeneration = manager.closeRequestGeneration();
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowOpen.selector);
        manager.finalizeCloseGuarded(finalizeDigest, finalizeGeneration);

        vm.warp(uint256(newerDeadline) + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(manager.finalizedStateVersion(), 11, "newer state settles after strict deadline");
    }

    /// Drive a full close of the channel at `(epoch, stateVersion)`, from Active to Closed.
    function _closeAt(uint64 epoch, uint64 stateVersion) internal {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intentAt(epoch, stateVersion);
        manager.submitCloseIntent(intent, _closeProof(intent));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
    }

    /// A public finalizer must never sign an argument-free capability that can be redirected to a
    /// replacement close between preflight and mining. The guarded digest loses no lifecycle state
    /// when the pending close moves, while the exact replacement remains permissionlessly
    /// finalizable after its deadline.
    function test_finalizeCloseGuarded_replacementCannotRedirectTransaction() public {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory stale = _intentAt(9, 10);
        manager.submitCloseIntent(stale, _closeProof(stale));
        bytes32 staleDigest = manager.getPendingClose().closeIntentDigest;
        uint64 generation = manager.closeRequestGeneration();

        ChannelSettlementManager.CloseIntent memory newer = _intentAt(9, 11);
        manager.submitCloseIntent(newer, _closeProof(newer));
        ChannelSettlementManager.PendingClose memory replacement = manager.getPendingClose();
        assertTrue(replacement.closeIntentDigest != staleDigest, "test requires a distinct replacement");
        vm.warp(replacement.challengeDeadline + 1);

        vm.expectRevert(ChannelSettlementManager.CloseIntentDigestMismatch.selector);
        manager.finalizeCloseGuarded(staleDigest, generation);
        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending));
        assertEq(manager.getPendingClose().closeIntentDigest, replacement.closeIntentDigest, "mismatch is non-mutating");

        manager.finalizeCloseGuarded(replacement.closeIntentDigest, generation);
        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.Closed));
        assertEq(manager.finalizedCloseIntentDigest(), replacement.closeIntentDigest);
    }


    // ─────────────────────────────────────────────────────────────────────────
    // C-3 — one `cancelClose` must not brick the channel forever
    // ─────────────────────────────────────────────────────────────────────────

    /// THE C-3 fence. Drives requestClose -> submitCloseIntent -> cancelClose -> requestClose ->
    /// submitCloseIntent and asserts the SECOND close is still possible, all the way to
    /// `finalizeClose`.
    ///
    /// PINS: `currentCloseFreezeNonce -= 1` in `cancelClose`. Without it the counter is left at 2
    /// while every producible signed state still carries era 0, so the second `submitCloseIntent`
    /// reverts `InvalidFreezeNonce` and the channel is
    /// permanently unclosable with no emergency exit. Note both intents carry era 1: era 2 is
    /// unreachable outside `#[cfg(test)]`, so a test that re-closes at era 2 proves nothing.
    function test_C3_cancelClose_thenReclose_stillPossible() external {
        // ── round 1: freeze, close intent, cancel ──
        _requestCloseAndElapseGrace();
        assertEq(manager.currentCloseFreezeNonce(), 1, "requestClose bumps the era");

        ChannelSettlementManager.CloseIntent memory first = _intentAt(9, 12);
        manager.submitCloseIntent(first, _closeProof(first));

        manager.cancelClose(
            _cancelRequest(manager.computeCloseIntentDigest(first), 13),
            _cancelProof(_cancelRequest(manager.computeCloseIntentDigest(first), 13))
        );
        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.Active)
        );
        // ── round 2: the channel must still be closable by an ORDINARY era-1 proof ──
        //
        // Deliberately NOT asserting the counter here first: the whole point is that the next two
        // calls must SUCCEED. Without the restore, `submitCloseIntent` reverts `InvalidFreezeNonce`
        // — the brick itself — which is the failure this test is meant to surface.
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory second = _intentAt(10, 30);
        manager.submitCloseIntent(second, _closeProof(second));
        assertTrue(manager.getPendingClose().active, "the second close intent was accepted");
        assertEq(manager.currentCloseFreezeNonce(), 1, "the era is 1 again, not 2");

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.Closed),
            "the channel settles; C-3's permanent lock is gone"
        );
        assertEq(manager.finalizedStateVersion(), 30);
    }

    /// A signed request/finalize raw transaction must name a manager-lifetime era that cancellation
    /// can never restore. This deliberately re-submits the identical close intent, so the digest
    /// and proof-bound freeze nonce are the same in both eras; only the guarded request floor and
    /// monotone request generation distinguish them.
    function test_staleMemberRequestAndFinalizeRawCannotReplayAfterCancel() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intentAt(9, 12);
        manager.submitCloseIntent(intent, _closeProof(intent));
        bytes32 digest = manager.getPendingClose().closeIntentDigest;
        uint64 staleGeneration = manager.closeRequestGeneration();
        assertEq(staleGeneration, 1, "first request generation");

        ChannelSettlementManager.CancelCloseRequest memory cancellation = _cancelRequest(digest, 13);
        manager.cancelClose(cancellation, _cancelProof(cancellation));
        assertEq(manager.currentCloseFreezeNonce(), 0, "proof era is restored for liveness");
        assertEq(manager.closeRequestGeneration(), staleGeneration, "generation is never restored");

        // Exact old member-request calldata is permanently invalid even though the freeze nonce
        // returned to zero. A fresh request pins the monotone cancellation floor.
        vm.prank(alice);
        vm.expectRevert(ChannelSettlementManager.InvalidFreezeNonce.selector);
        manager.requestClose(0, 0);
        vm.prank(alice);
        manager.requestClose(0, 13);
        assertEq(manager.closeRequestGeneration(), staleGeneration + 1, "fresh request advances generation");

        vm.warp(block.timestamp + GRACE);
        manager.submitCloseIntent(intent, _closeProof(intent));
        assertEq(manager.getPendingClose().closeIntentDigest, digest, "test requires digest reuse");
        vm.warp(uint256(manager.getPendingClose().challengeDeadline) + 1);

        // The legacy unguarded selector is absent from the production ABI. Its exact old calldata
        // reaches no function and therefore fails without touching the new close era.
        (bool legacyFinalizeAccepted,) = address(manager).call(abi.encodeWithSignature("finalizeClose()"));
        assertFalse(legacyFinalizeAccepted, "legacy unguarded finalize selector must stay removed");
        vm.expectRevert(ChannelSettlementManager.CloseIntentDigestMismatch.selector);
        manager.finalizeCloseGuarded(digest, staleGeneration);

        manager.finalizeCloseGuarded(digest, staleGeneration + 1);
        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.Closed));
    }

    /// The griefer's exact play: withhold the completed signature set, let an honest member close,
    /// then cancel. `cancelClose` has no `msg.sender` restriction, so ANY address can do this — and
    /// after the fix it costs the channel nothing but a fresh grace window.
    ///
    /// PINS: the same decrement, under repetition. Without it the era drifts up by one per cancel
    /// and the assertion on round 3's counter fails immediately.
    function test_C3_repeatedCancelsDoNotDriftTheEra() external {
        for (uint64 round = 0; round < 3; round++) {
            _requestCloseAndElapseGrace();
            assertEq(manager.currentCloseFreezeNonce(), 1, "era is always 1 inside a frozen round");

            ChannelSettlementManager.CloseIntent memory intent = _intentAt(9, 12);
            manager.submitCloseIntent(intent, _closeProof(intent));

            bytes32 digest = manager.computeCloseIntentDigest(intent);
            // A stranger cancels: no msg.sender gate exists on this path.
            //
            // A2026-08-28 ROUND 2 (A1): each round must now exhibit a STRICTLY NEWER revived
            // version than every previous cancel — `13 + round`, not a replayed 13. That is the
            // whole A1 fix, and this test is the reason the property is stated as "the era does not
            // drift across repeated HONEST cycles": an honest party who really does hold newer
            // material each round is unaffected by the floor, which is what is pinned here.
            uint64 revived = 13 + round;
            vm.prank(mallory);
            manager.cancelClose(
                _cancelRequest(digest, revived), _cancelProof(_cancelRequest(digest, revived))
            );
            assertEq(
                manager.highestCancelledRevivedStateVersion(),
                revived,
                "A1: the cancel consumed its material and the floor advanced"
            );

            assertEq(manager.currentCloseFreezeNonce(), 0, "era restored, round-independent");
            assertEq(manager.closeRequestedAt(), 0);
            assertEq(manager.closeChallengeHorizon(), 0, "the era's H-3 horizon dies with it");
            assertTrue(manager.isNativeSendAllowed(0), "era-0 signed states can send again");
        }
    }

    /// C-3 defence in depth (audit §5 "Cancel monotonicity"): the on-chain
    /// `revivedStateVersion > pendingClose.finalStateVersion` re-assertion.
    ///
    /// PINS: the `revivedStateVersion <= pendingClose.finalStateVersion -> CloseNotNewer` guard.
    /// The property is asserted in-circuit (`cancel_close_circuit.rs:461-467`), but with the mock
    /// MLE verdict standing in for a compromised/regressed proof system, removing the on-chain
    /// guard lets an EQUAL and even an OLDER revived version cancel a close — i.e. revive the
    /// channel into a stale head. Both directions are exercised.
    function test_C3_cancelClose_requiresStrictlyNewerRevivedVersion() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intentAt(9, 20);
        manager.submitCloseIntent(intent, _closeProof(intent));
        bytes32 digest = manager.computeCloseIntentDigest(intent);

        // equal — precompute the proof so expectRevert arms on `cancelClose`, not on the view calls.
        ChannelSettlementManager.CancelCloseRequest memory equalReq = _cancelRequest(digest, 20);
        bytes memory equalProof = _cancelProof(equalReq);
        vm.expectRevert(ChannelSettlementManager.CloseNotNewer.selector);
        manager.cancelClose(equalReq, equalProof);

        // older
        ChannelSettlementManager.CancelCloseRequest memory olderReq = _cancelRequest(digest, 19);
        bytes memory olderProof = _cancelProof(olderReq);
        vm.expectRevert(ChannelSettlementManager.CloseNotNewer.selector);
        manager.cancelClose(olderReq, olderProof);

        assertTrue(manager.getPendingClose().active, "the close survived both bad cancels");

        // strictly newer is accepted
        ChannelSettlementManager.CancelCloseRequest memory ok = _cancelRequest(digest, 21);
        manager.cancelClose(ok, _cancelProof(ok));
        assertFalse(manager.getPendingClose().active);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // H-3 — the challenge-window ladder must be bounded
    // ─────────────────────────────────────────────────────────────────────────

    /// The era's FIRST intent still gets exactly one full `challengePeriod`, and the honest member
    /// who uses the whole of it can still land a replacement — the property the ladder cap must not
    /// break.
    ///
    /// PINS: the `min(now + challengePeriod, closeChallengeHorizon)` clamp being a MINIMUM of 2x,
    /// not a hard cut at 1x. A clamp that anchored the horizon at `challengePeriod` instead of
    /// `2 * challengePeriod` would fail the last assertion.
    function test_H3_firstIntentKeepsAFullWindowAndOneReplacementFits() external {
        _requestCloseAndElapseGrace();
        // TEST INTEGRITY: `vm.getBlockTimestamp()`, not `block.timestamp` — see the note on
        // `test_H3_replacementLadderCannotOutrunTheEraHorizon` for the via-IR CSE hazard.
        uint64 t0 = uint64(vm.getBlockTimestamp());

        ChannelSettlementManager.CloseIntent memory first = _intentAt(9, 12);
        manager.submitCloseIntent(first, _closeProof(first));
        assertEq(
            manager.getPendingClose().challengeDeadline,
            t0 + CHALLENGE_PERIOD,
            "the first intent is unclamped: a full challenge period"
        );
        assertEq(manager.closeChallengeHorizon(), t0 + 2 * CHALLENGE_PERIOD, "horizon anchored here");

        // An honest member consumes the ENTIRE budgeted window before landing its newer state.
        vm.warp(t0 + CHALLENGE_PERIOD);
        ChannelSettlementManager.CloseIntent memory better = _intentAt(9, 13);
        manager.submitCloseIntent(better, _closeProof(better));
        assertEq(manager.getPendingClose().finalStateVersion, 13, "the newer state replaced it");
        assertEq(
            manager.getPendingClose().challengeDeadline,
            t0 + 2 * CHALLENGE_PERIOD,
            "and it still receives a full further window, up to the horizon"
        );
    }

    /// THE H-3 fence. A griefer walks up the version ladder, landing each replacement as late as the
    /// window legally allows. Exit must still be reachable inside the era's absolute horizon.
    ///
    /// PINS: the clamp in `_storePendingClose`. Reverting it to the unconditional
    /// `block.timestamp + challengePeriod` makes each of the 12 replacements buy another full day,
    /// so the deadline bound fails on the third iteration and the final elapsed-time assertion fails
    /// by an order of magnitude. ALSO PINS the A2 response floor: every rung the ladder admits is
    /// asserted to carry at least `MIN_CLOSE_RESPONSE_SECS` of answerable time.
    ///
    /// R3-2 (round 3): admission now runs to the horizon rather than stopping `minResponse` short of
    /// it, and the guarantee is delivered by flooring each admitted rung's deadline instead of by
    /// refusing the rung. The ladder's absolute end therefore moves from `horizon` to
    /// `horizon + MIN_CLOSE_RESPONSE_SECS` — still a fixed cap, independent of the number of rungs,
    /// which is the property H-3 exists to provide.
    ///
    /// TEST INTEGRITY: every "what time is it now" read goes through `vm.getBlockTimestamp()`, NOT
    /// `block.timestamp`. Under `via_ir = true` the Yul optimizer treats `TIMESTAMP` as movable and
    /// common-subexpression-eliminates two reads separated by a `vm.warp` into ONE — measured in
    /// this repo: `b = block.timestamp; vm.warp(+12345); a = block.timestamp; a - b` folds to the
    /// literal `0` while both reads report the post-warp value. The previous form of this test read
    /// `block.timestamp` before the ladder and again after it, so the closing
    /// `assertLe(block.timestamp, horizon)` was at risk of degenerating to `assertLe(t, t + 2*CP)`
    /// — an assertion that cannot fail. The cheatcode is a staticcall and cannot be folded away.
    function test_H3_replacementLadderCannotOutrunTheEraHorizon() external {
        _requestCloseAndElapseGrace();
        uint64 t0 = uint64(vm.getBlockTimestamp());
        uint64 horizon = t0 + 2 * CHALLENGE_PERIOD;
        uint64 minResponse = manager.MIN_CLOSE_RESPONSE_SECS();

        ChannelSettlementManager.CloseIntent memory first = _intentAt(9, 12);
        manager.submitCloseIntent(first, _closeProof(first));

        uint64 version = 12;
        uint64 rungs = 0;
        bool reachedHorizon = false;
        for (uint256 i = 0; i < 12; i++) {
            uint64 deadline = manager.getPendingClose().challengeDeadline;
            assertLe(
                deadline,
                horizon + minResponse,
                "no replacement may push the deadline past the era horizon + one response interval"
            );
            // R3-2: a rung is admissible while `now <= min(challengeDeadline, horizon)`. The
            // round-2 form of this line stopped at `horizon - minResponse`, which is the blackout
            // R3-2 removed; the latest legal landing is now the horizon itself.
            uint64 latest = deadline < horizon ? deadline : horizon;
            if (vm.getBlockTimestamp() > latest || reachedHorizon) break;
            vm.warp(latest);
            reachedHorizon = latest == horizon;
            version += 1;
            ChannelSettlementManager.CloseIntent memory rung = _intentAt(9, version);
            manager.submitCloseIntent(rung, _closeProof(rung));
            rungs += 1;
            // A2, THE PROPERTY (unchanged, now delivered by the deadline floor rather than by the
            // admission bar): no admitted rung may be finalizable in the block that stored it.
            assertGe(
                manager.getPendingClose().challengeDeadline - vm.getBlockTimestamp(),
                minResponse,
                "A2: every admitted rung keeps a usable response window"
            );
        }

        assertGt(rungs, 0, "the ladder is not vacuous: replacements really were admitted");
        assertTrue(reachedHorizon, "the ladder was actually walked all the way to the horizon");
        assertLe(
            vm.getBlockTimestamp(),
            horizon,
            "every rung of the ladder landed within the era's absolute horizon"
        );

        // R3-4: the last rung's already-budgeted response tail remains open to a strictly-newer
        // close (cancel material may have been consumed in an earlier era), but that response must
        // not move the fixed `horizon + minResponse` end.
        ChannelSettlementManager.CloseIntent memory tooLate = _intentAt(9, version + 1);
        bytes memory tooLateProof = _closeProof(tooLate);
        vm.warp(uint256(horizon) + 1);
        assertGe(
            manager.getPendingClose().challengeDeadline,
            vm.getBlockTimestamp(),
            "the raw deadline check alone would still admit this rung"
        );
        manager.submitCloseIntent(tooLate, tooLateProof);
        assertEq(
            manager.getPendingClose().challengeDeadline,
            horizon + minResponse,
            "tail replacement must not extend the absolute end"
        );

        // It closes permanently one second after that fixed end.
        vm.warp(uint256(horizon) + minResponse + 1);
        ChannelSettlementManager.CloseIntent memory afterEnd = _intentAt(9, version + 2);
        bytes memory afterEndProof = _closeProof(afterEnd);
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowClosed.selector);
        manager.submitCloseIntent(afterEnd, afterEndProof);

        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.Closed),
            "exit is reachable strictly after the final response deadline"
        );
        assertEq(
            vm.getBlockTimestamp(),
            uint256(horizon) + minResponse + 1,
            "finalization is one timestamp after horizon + MIN_CLOSE_RESPONSE_SECS"
        );
    }

    /// The horizon is per-era, not per-manager: a cancelled era leaves no residue that would shrink
    /// the next era's challenge game.
    ///
    /// PINS: `closeChallengeHorizon = 0` in `cancelClose` plus the re-anchor on the next era's first
    /// intent. A stale horizon would clamp the new era's first deadline into the past, making a
    /// fresh close instantly finalizable with NO challenge window at all — a worse bug than H-3.
    function test_H3_horizonIsReanchoredPerEra() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory first = _intentAt(9, 12);
        manager.submitCloseIntent(first, _closeProof(first));
        bytes32 digest = manager.computeCloseIntentDigest(first);
        manager.cancelClose(_cancelRequest(digest, 13), _cancelProof(_cancelRequest(digest, 13)));
        assertEq(manager.closeChallengeHorizon(), 0, "cleared on cancel");

        // A long time later, a fresh era must get a FULL window — not a deadline in the past.
        vm.warp(block.timestamp + 30 days);
        _requestCloseAndElapseGrace();
        uint64 t1 = uint64(block.timestamp);
        ChannelSettlementManager.CloseIntent memory second = _intentAt(10, 30);
        manager.submitCloseIntent(second, _closeProof(second));
        assertEq(manager.getPendingClose().challengeDeadline, t1 + CHALLENGE_PERIOD);
        assertEq(manager.closeChallengeHorizon(), t1 + 2 * CHALLENGE_PERIOD);
        bytes32 finalizeDigest = manager.getPendingClose().closeIntentDigest;
        uint64 finalizeGeneration = manager.closeRequestGeneration();
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowOpen.selector);
        manager.finalizeCloseGuarded(finalizeDigest, finalizeGeneration);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // C-2 — the post-close claim double-credit path
    // ─────────────────────────────────────────────────────────────────────────

    /// The legacy inclusion-only statement cannot establish that an incoming delta was absent
    /// from the closing ciphertext. Reject its 57 limbs before any second credit is accrued.
    function test_C2_legacyInclusionOnlyProofCannotCreateSecondCredit() external {
        bytes32 d = _finalizeDefault(); // fund = 75

        // Alice's ordinary claim credits her decrypted final slot balance.
        ChannelSettlementManager.WithdrawalClaim memory wc = _withdrawalClaim(d, USER_A, alice, 30);
        manager.submitWithdrawalClaim(wc, _withdrawalClaimProof(wc));
        assertEq(manager.withdrawalCredits(0, alice), 30);
        assertEq(manager.totalWithdrawn(0), 30);

        // The second credit for that same delta is refused outright.
        ChannelSettlementManager.PostCloseClaim memory pc =
            _postCloseClaim(d, keccak256("incoming_tx"), USER_B, bob, 5);
        bytes memory pcProof = _postCloseClaimProof(pc);
        uint256[] memory current = abi.decode(pcProof, (uint256[]));
        uint256[] memory legacy = new uint256[](57);
        for (uint256 i; i < 57; ++i) legacy[i] = current[i];
        pcProof = abi.encode(legacy);
        vm.expectRevert(bytes("claim pi len"));
        manager.submitPostCloseClaim(pc, pcProof);

        assertEq(manager.withdrawalCredits(0, bob), 0, "no double credit");
        assertEq(manager.totalWithdrawn(0), 30, "the rejected legacy proof leaves the budget untouched");
    }

    /// Residual claims enforce close/token identity, including before any zero-value accrual.
    function test_C2_residualClaimChecksCloseAndToken() external {
        bytes32 d = _finalizeDefault();

        // wrong close digest
        ChannelSettlementManager.PostCloseClaim memory wrongDigest =
            _postCloseClaim(keccak256("not_the_close"), keccak256("itx"), USER_B, bob, 5);
        bytes memory p1 = _postCloseClaimProof(wrongDigest);
        vm.expectRevert(ChannelSettlementManager.CloseIntentDigestMismatch.selector);
        manager.submitPostCloseClaim(wrongDigest, p1);

        // unregistered token
        ChannelSettlementManager.PostCloseClaim memory badToken =
            _postCloseClaim(d, keccak256("itx"), USER_B, bob, 5, 999);
        bytes memory p2 = _postCloseClaimProof(badToken);
        vm.expectRevert(ChannelSettlementManager.TokenRegistryMismatch.selector);
        manager.submitPostCloseClaim(badToken, p2);

        // zero amount
        ChannelSettlementManager.PostCloseClaim memory zero =
            _postCloseClaim(d, keccak256("itx"), USER_B, bob, 0);
        bytes memory p3 = _postCloseClaimProof(zero);

        manager.submitPostCloseClaim(zero, p3);
    }

    /// Ordinary claims still preserve their replay guard, cap and real payout.
    function test_C2_withdrawalClaimPathIsUnaffected() external {
        bytes32 d = _finalizeDefault(); // fund = 75

        ChannelSettlementManager.WithdrawalClaim memory wc = _withdrawalClaim(d, USER_A, alice, 75);
        manager.submitWithdrawalClaim(wc, _withdrawalClaimProof(wc));

        // replay of the same nullifier is still refused
        bytes memory replay = _withdrawalClaimProof(wc);
        vm.expectRevert(ChannelSettlementManager.NullifierAlreadyUsed.selector);
        manager.submitWithdrawalClaim(wc, replay);

        // and the cap still binds
        ChannelSettlementManager.WithdrawalClaim memory over = _withdrawalClaim(d, USER_B, bob, 1);
        bytes memory overProof = _withdrawalClaimProof(over);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.submitWithdrawalClaim(over, overProof);

        // real ETH still reaches the member
        _fundAndPull(registry, manager, 75);
        vm.prank(alice);
        assertEq(manager.claimWithdrawalCredit(wc.withdrawalNullifier), 75);
        assertEq(alice.balance, 75, "the surviving exit path pays");
    }
}
