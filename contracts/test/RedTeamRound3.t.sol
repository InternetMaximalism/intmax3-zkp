// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseSettlementBase} from "./CloseSettlementBase.sol";
import {CloseTestLib} from "./CloseTestLib.sol";

/// @title RedTeamRound3
/// @notice ROUND-3 adversarial probes against the ROUND-2 guards A1 / A2 in
///         `ChannelSettlementManager`. Every `test_R3_BREAK_*` PASSES by demonstrating an attack
///         the round-2 guard does NOT stop (the assertion IS the exploit). Every `test_R3_REFUTED_*`
///         PASSES by confirming a guard holds against an attack that was tried and failed.
///         The A3 (authorized-burn high-water) and A4 (partial-withdrawal cancel) probes were
///         removed on 2026-10-09 together with the Manager's partial-withdrawal path: a burn is paid
///         by the rollup on its base withdrawal proof alone and ordered against a close by the
///         `CloseFundingMaterializer` journal (see `SignerIndependentExit.t.sol`).
contract RedTeamRound3Test is CloseSettlementBase {
    uint32 internal constant TOKEN_INDEX = 0;

    address internal eve = makeAddr("eve_withholding_coordinator");

    // ── helpers (mirrored from CloseLifecycleRedTeam.t.sol) ──────────────────

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

    function _intentAt(uint64 epoch, uint64 stateVersion)
        internal pure returns (ChannelSettlementManager.CloseIntent memory intent)
    {
        intent = _intent(1, epoch, 22, 1);
        intent.finalStateVersion = stateVersion;
        intent.finalChannelStateDigest = keccak256(abi.encodePacked("final_state", epoch, stateVersion));
    }

    // ════════════════════════════════════════════════════════════════════════
    // BREAK 1 — A1 x A3: the C-3 permanent brick.  *** MOOT (2026-10-09) ***
    //
    //   A3 was the Manager's authorized-burn high-water mark; combined with A1's
    //   spent cancel floor it could make `ClosePending` terminal. The Manager no
    //   longer has a partial-withdrawal path or any burn mark, so no
    //   version-dependent refusal exists at close admission or finalization. The
    //   two controls below pin that the A1 floor alone never blocks an exit and
    //   that a close settles at its own whole-state vector.
    // ════════════════════════════════════════════════════════════════════════

    /// A stale close with no other activity settles at its own FULL declared cap: the Manager never
    /// adjusts a settled vector.
    function test_R3_A1_staleCloseSettlesAtItsOwnFullDeclaredCap() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory stale = _intentAt(9, 28);
        manager.submitCloseIntent(stale, _closeProof(stale));
        vm.warp(uint256(manager.closeChallengeHorizon()) + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(
            manager.finalizedChannelFundAmount(TOKEN_INDEX),
            DEFAULT_FUND_AMOUNT,
            "the settled cap is the close state's own vector"
        );
    }

    /// CONTROL for BREAK 1: the spent A1 floor alone is harmless; the stale close simply settles.
    function test_R3_BREAK_A1xA3_control_withoutTheBurnMarkTheCloseSettles() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory stale1 = _intentAt(9, 28);
        manager.submitCloseIntent(stale1, _closeProof(stale1));
        bytes32 d1 = manager.computeCloseIntentDigest(stale1);
        manager.cancelClose(_cancelRequest(d1, 30), _cancelProof(_cancelRequest(d1, 30)));
        assertEq(manager.highestCancelledRevivedStateVersion(), 30, "floor spent");

        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory stale2 = _intentAt(9, 28);
        manager.submitCloseIntent(stale2, _closeProof(stale2));
        vm.warp(uint256(manager.closeChallengeHorizon()) + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(manager.finalizedStateVersion(), 28, "settles; the A1 floor alone is inert");
    }

    // ════════════════════════════════════════════════════════════════════════
    // BREAK 2 — A2: `MIN_CLOSE_RESPONSE_SECS` is a blackout, not a response
    //           window.  *** FIXED (R3-2) ***
    //
    //   THE ATTACK AS FOUND. A2's stated property was "every admitted rung leaves
    //   a usable response interval". The intended response to a rung IS a
    //   replacement close intent -- and A2 was precisely the rule that refused
    //   replacements in the final `MIN_CLOSE_RESPONSE_SECS` before the horizon.
    //   So the guard closed the very lane it claimed to keep open, and it did so
    //   for a FULL HOUR rather than for the zero seconds the pre-A2 defect cost.
    //
    //   THE FIX (round 3, R3-2). The constant is moved off the ADMISSION rule and
    //   onto the WINDOW: `submitCloseIntent` now admits every replacement up to
    //   the era's absolute horizon, and `_storePendingClose` floors each admitted
    //   rung's `challengeDeadline` at `now + minResponse`. No honest replacement
    //   landing before the horizon is refused, and no rung is unanswerable. The
    //   ladder's absolute end moves from `horizon` to `horizon + minResponse` --
    //   a fixed overshoot independent of the number of rungs, so H-3's property
    //   (the ladder cannot be walked indefinitely) is preserved.
    // ════════════════════════════════════════════════════════════════════════

    /// BLOCKED (passes = the attack no longer works). Body preserved VERBATIM through the setup;
    /// only the verdict changed. Eve's rung still lands one second before the first deadline, and
    /// the honest v12 still surfaces at `horizon - 3599` -- which round 2 refused. It is now
    /// ADMITTED, and the honest state is what settles.
    function test_R3_BREAK_A2_finalHourIsAReplacementBlackout() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory rung0 = _intentAt(9, 10);
        manager.submitCloseIntent(rung0, _closeProof(rung0));
        uint64 horizon = manager.closeChallengeHorizon();

        // Eve's rung, landing one second before the first deadline.
        vm.warp(uint256(manager.getPendingClose().challengeDeadline) - 1);
        ChannelSettlementManager.CloseIntent memory rung1 = _intentAt(9, 11);
        vm.prank(eve);
        manager.submitCloseIntent(rung1, _closeProof(rung1));
        assertEq(
            manager.getPendingClose().challengeDeadline,
            horizon - 1,
            "the rung's deadline is one second short of the horizon"
        );

        // The honest party surfaces the strictly newer v12 well inside that deadline...
        vm.warp(uint256(horizon) - 3599);
        assertLt(
            vm.getBlockTimestamp(),
            uint256(manager.getPendingClose().challengeDeadline),
            "we are INSIDE the pending challenge deadline"
        );
        ChannelSettlementManager.CloseIntent memory honest = _intentAt(9, 12);
        // ...and R3-2 ADMITS it. Round 2 reverted `ChallengeWindowClosed` here.
        manager.submitCloseIntent(honest, _closeProof(honest));
        assertEq(manager.getPendingClose().finalStateVersion, 12, "the honest replacement landed");
        // It also gets a USABLE window rather than the clamped stub: at `horizon - 3599` the raw
        // clamp would have been `horizon` (1 s short of minResponse), so the floor is what bites.
        assertEq(
            manager.getPendingClose().challengeDeadline,
            uint64(vm.getBlockTimestamp()) + manager.MIN_CLOSE_RESPONSE_SECS(),
            "R3-2: the admitted rung's deadline is floored at now + minResponse"
        );

        // Eve's stale v11 does NOT settle; the honest v12 does.
        vm.warp(uint256(manager.getPendingClose().challengeDeadline) + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(manager.finalizedStateVersion(), 12, "the honest state settled, not the griefer's");
    }

    /// Walk the replacement ladder to the era's absolute horizon the way a griefer would: land each
    /// rung at the LATEST admissible instant (the current deadline, clamped to the horizon). Returns
    /// the next unused state version. Ends with a rung landed at exactly `closeChallengeHorizon`.
    function _walkLadderToHorizon(uint64 version) internal returns (uint64) {
        uint256 horizon = uint256(manager.closeChallengeHorizon());
        while (true) {
            uint256 dl = uint256(manager.getPendingClose().challengeDeadline);
            uint256 at = dl < horizon ? dl : horizon;
            vm.warp(at);
            ChannelSettlementManager.CloseIntent memory rung = _intentAt(9, version);
            manager.submitCloseIntent(rung, _closeProof(rung));
            version += 1;
            if (at == horizon) return version;
        }
    }

    /// The former blackout band, swept. Round 2 refused EVERY replacement in
    /// `(horizon - minResponse, horizon]`; R3-2 admits all of them, and gives each one at least
    /// `minResponse` in which to be answered. Mutation pin for the admission change: restoring the
    /// `now + minResponse > horizon` bar fails at the first iteration.
    function test_R3_FIXED_A2_theFormerBlackoutBandIsFullyOpen() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory rung0 = _intentAt(9, 10);
        manager.submitCloseIntent(rung0, _closeProof(rung0));
        uint64 horizon = manager.closeChallengeHorizon();
        uint64 minResp = manager.MIN_CLOSE_RESPONSE_SECS();
        assertEq(minResp, 3600, "MIN_CLOSE_RESPONSE_SECS");

        // Reach the band: one rung landed at the first deadline pushes the pending deadline to
        // `horizon - 1`, so the whole former blackout is reachable by the clock.
        vm.warp(uint256(manager.getPendingClose().challengeDeadline));
        ChannelSettlementManager.CloseIntent memory reach = _intentAt(9, 11);
        manager.submitCloseIntent(reach, _closeProof(reach));

        // Every instant round 2 refused is now admitted, down to and including the horizon itself.
        uint64 version = 12;
        uint256[7] memory offsets = [uint256(3599), 3000, 2400, 1800, 1200, 600, 0];
        for (uint256 i = 0; i < offsets.length; i++) {
            vm.warp(uint256(horizon) - offsets[i]);
            ChannelSettlementManager.CloseIntent memory rung = _intentAt(9, version);
            manager.submitCloseIntent(rung, _closeProof(rung));
            assertEq(manager.getPendingClose().finalStateVersion, version, "admitted in the band");
            assertGe(
                uint256(manager.getPendingClose().challengeDeadline),
                vm.getBlockTimestamp() + minResp,
                "R3-2: every admitted rung gets at least minResponse to be answered in"
            );
            version += 1;
        }
        assertEq(
            manager.getPendingClose().challengeDeadline,
            horizon + minResp,
            "the rung at the horizon ends the ladder exactly minResponse past it"
        );
    }

    /// The H-3 property must not weaken: the ladder is still ABSOLUTELY bounded. R3-4 opens the
    /// already-budgeted tail to strictly-newer responses, but no replacement can move the fixed
    /// `horizon + minResponse` end by one second.
    function test_R3_FIXED_A2_ladderIsStillBoundedAtHorizonPlusMinResponse() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory rung0 = _intentAt(9, 10);
        manager.submitCloseIntent(rung0, _closeProof(rung0));
        uint64 horizon = manager.closeChallengeHorizon();
        uint64 minResp = manager.MIN_CLOSE_RESPONSE_SECS();

        uint64 nextVersion = _walkLadderToHorizon(11);
        uint64 deadline = manager.getPendingClose().challengeDeadline;
        assertEq(deadline, horizon + minResp, "ladder end is the absolute cap");

        // R3-4: one second into the tail, a strictly-newer state is admissible and wins, but its
        // deadline stays pinned to the same absolute end rather than buying another response rung.
        vm.warp(uint256(horizon) + 1);
        assertLt(vm.getBlockTimestamp(), uint256(deadline), "the response window is still open");
        ChannelSettlementManager.CloseIntent memory extra = _intentAt(9, nextVersion);
        manager.submitCloseIntent(extra, _closeProof(extra));
        assertEq(manager.getPendingClose().challengeDeadline, deadline, "tail response cannot extend end");

        // Only after the fixed end is every further rung refused.
        vm.warp(uint256(deadline) + 1);
        ChannelSettlementManager.CloseIntent memory tooLate = _intentAt(9, nextVersion + 1);
        bytes memory tooLateProof = _closeProof(tooLate);
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowClosed.selector);
        manager.submitCloseIntent(tooLate, tooLateProof);

        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(manager.finalizedStateVersion(), nextVersion, "tail replacement is what settles");
    }

    /// R3-4 composition regression: an earlier era consumed cancel(v30), so a later final stale
    /// rung cannot be answered by cancel. The v30 close replacement must remain usable during the
    /// fixed response tail, and must not extend that tail.
    function test_R3_FIXED_A1xA2_spentCancelVersionCanReplaceInResponseTail() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory era1 = _intentAt(9, 27);
        manager.submitCloseIntent(era1, _closeProof(era1));
        bytes32 d1 = manager.getPendingClose().closeIntentDigest;
        manager.cancelClose(_cancelRequest(d1, 30), _cancelProof(_cancelRequest(d1, 30)));
        assertEq(manager.highestCancelledRevivedStateVersion(), 30, "v30 cancel consumed");

        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory stale = _intentAt(9, 27);
        manager.submitCloseIntent(stale, _closeProof(stale));
        uint64 horizon = manager.closeChallengeHorizon();
        uint64 nextVersion = _walkLadderToHorizon(28);
        assertEq(nextVersion, 30, "v29 is the final stale rung at the horizon");
        uint64 absoluteEnd = horizon + manager.MIN_CLOSE_RESPONSE_SECS();
        assertEq(manager.getPendingClose().challengeDeadline, absoluteEnd);

        vm.warp(uint256(horizon) + 1);
        bytes32 d2 = manager.getPendingClose().closeIntentDigest;
        ChannelSettlementManager.CancelCloseRequest memory spent = _cancelRequest(d2, 30);
        bytes memory spentProof = _cancelProof(spent);
        vm.expectRevert(ChannelSettlementManager.CancelCloseReplay.selector);
        manager.cancelClose(spent, spentProof);

        ChannelSettlementManager.CloseIntent memory head = _intentAt(9, 30);
        manager.submitCloseIntent(head, _closeProof(head));
        assertEq(manager.getPendingClose().finalStateVersion, 30, "spent cancel material still replaces");
        assertEq(manager.getPendingClose().challengeDeadline, absoluteEnd, "tail remains fixed");

        vm.warp(uint256(absoluteEnd) + 1);
        ChannelSettlementManager.CloseIntent memory tooLate = _intentAt(9, 31);
        bytes memory tooLateProof = _closeProof(tooLate);
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowClosed.selector);
        manager.submitCloseIntent(tooLate, tooLateProof);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(manager.finalizedStateVersion(), 30, "newest available state settles");
    }

    /// The original A2 defect must stay fixed: a rung landing at exactly the horizon may NOT be
    /// finalized in the same block. Round 2 fixed this by refusing the rung; R3-2 fixes it by
    /// giving the rung a window. Mutation pin for the deadline floor in `_storePendingClose`.
    function test_R3_FIXED_A2_rungAtTheHorizonIsNotSameBlockFinalizable() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory rung0 = _intentAt(9, 10);
        manager.submitCloseIntent(rung0, _closeProof(rung0));
        uint64 horizon = manager.closeChallengeHorizon();

        _walkLadderToHorizon(11);
        assertEq(vm.getBlockTimestamp(), uint256(horizon), "the last rung landed AT the horizon");

        bytes32 guardedDigest = manager.getPendingClose().closeIntentDigest;
        uint64 guardedGeneration = manager.closeRequestGeneration();
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowOpen.selector);
        manager.finalizeCloseGuarded(guardedDigest, guardedGeneration);
        assertEq(
            uint256(manager.getPendingClose().challengeDeadline),
            vm.getBlockTimestamp() + manager.MIN_CLOSE_RESPONSE_SECS(),
            "no zero-length last rung: it gets a full minResponse"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // REFUTATIONS — attacks that were tried and FAILED. These pass by confirming
    // the round-2 guard holds.
    // ═════════════════════════════════════════════════════════════════════════

    /// REFUTED (A1 holds). The A1 floor cannot be raised by an outsider without a verifying cancel
    /// proof at that version: `revivedStateVersion` is strict-bound into the cancel PI vector, so a
    /// caller who declares v9999 while presenting a v31 proof is rejected and the floor does not
    /// move.
    function test_R3_REFUTED_A1_floorCannotBeRaisedWithoutMatchingProof() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intentAt(9, 10);
        manager.submitCloseIntent(intent, _closeProof(intent));
        bytes32 d = manager.computeCloseIntentDigest(intent);

        ChannelSettlementManager.CancelCloseRequest memory lie = _cancelRequest(d, 9999);
        bytes memory wrongProof = _cancelProof(_cancelRequest(d, 31));
        vm.expectRevert();
        manager.cancelClose(lie, wrongProof);
        assertEq(manager.highestCancelledRevivedStateVersion(), 0, "floor unmoved");
    }

    /// REFUTED (A1 holds). The A1 floor is genuinely read nowhere on a close/exit path: with the
    /// floor at 30, a v20 close still requests, submits and finalizes.
    function test_R3_REFUTED_A1_floorAloneNeverBlocksAnExit() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory a = _intentAt(9, 10);
        manager.submitCloseIntent(a, _closeProof(a));
        bytes32 d = manager.computeCloseIntentDigest(a);
        manager.cancelClose(_cancelRequest(d, 30), _cancelProof(_cancelRequest(d, 30)));
        assertEq(manager.highestCancelledRevivedStateVersion(), 30, "floor high");

        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory b = _intentAt(9, 20);
        manager.submitCloseIntent(b, _closeProof(b));
        vm.warp(vm.getBlockTimestamp() + CHALLENGE_PERIOD + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(manager.finalizedStateVersion(), 20, "exit liveness is unconditional in A1 alone");
    }

}
