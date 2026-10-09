// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseSettlementBase} from "./CloseSettlementBase.sol";
import {CloseTestLib} from "./CloseTestLib.sol";

/// @title CloseLifecycleRedTeam
/// @notice ADVERSARIAL probes against the 2026-08-28 C-3 / C-2 / H-3 / H-6 fixes.
///         Some of these PASS by demonstrating an attack the fixes do NOT stop (they are
///         written so the assertion IS the exploit); others PASS by confirming a fix holds.
///         Each test's doc comment states which.
///
/// ROUND-2 STATUS. The four ATTACK probes below all landed, and all four are now closed by the
/// round-2 guards in `ChannelSettlementManager`:
///   - ATTACK 1 (both forms)   -> A1, `CancelCloseReplay` (the monotone
///                                `highestCancelledRevivedStateVersion` floor in `cancelClose`)
///   - ATTACK 2                -> A2, `ChallengeWindowClosed` (the `MIN_CLOSE_RESPONSE_SECS`
///                                admission floor in `submitCloseIntent`)
///   - ATTACK 3 (H-6 burn/close double draw) -> moot since 2026-10-09: the Manager has no
///                                partial-withdrawal path. A burn is paid by the rollup on its base
///                                withdrawal proof alone and ordered against a close by the
///                                `CloseFundingMaterializer` journal (no post to a frozen channel;
///                                close backing anchored at or after the last posted block), pinned
///                                in `SignerIndependentExit.t.sol`. Its probes and the A4
///                                partial-withdrawal cancel probes were removed.
/// Each ATTACK body is preserved VERBATIM up to the exact call that used to succeed; that call is
/// now wrapped in `vm.expectRevert` with the guard's own selector, so the file keeps working as the
/// regression pin for the attacks it found. Removing a guard makes its probe fail again.
contract CloseLifecycleRedTeamTest is CloseSettlementBase {
    uint32 internal constant TOKEN_INDEX = 0;

    address internal eve = makeAddr("eve_no_relationship_to_the_channel");

    // ── helpers (mirrored from CloseLifecycleHardening.t.sol) ────────────────

    function _cancelProof(ChannelSettlementManager.CancelCloseRequest memory request)
        internal view returns (bytes memory)
    {
        ChannelSettlementManager.PendingClose memory pending = manager.getPendingClose();
        uint64 closeFinalStateVersion = pending.active && pending.closeIntentDigest == request.closeIntentDigest
            ? pending.finalStateVersion
            : 0;
        return _cancelProofAt(request, closeFinalStateVersion);
    }

    function _cancelProofAt(
        ChannelSettlementManager.CancelCloseRequest memory request,
        uint64 closeFinalStateVersion
    ) internal view returns (bytes memory) {
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

    // ═════════════════════════════════════════════════════════════════════════
    // ATTACK 1 — C-3 x H-3: the cancel/re-close cycle is unbounded, the cancel
    //            proof is replayable, and the H-3 horizon does not bound it.
    // ═════════════════════════════════════════════════════════════════════════

    /// EXPLOIT (passes = attack works). `cancelClose` has no `msg.sender` gate, no
    /// challenge-window bound, and NO anti-replay on the cancel proof. Before the C-3 fix that was
    /// a ONE-SHOT capability: the first cancel left `currentCloseFreezeNonce` permanently ahead of
    /// every producible state, so nobody (attacker included) could ever open another era. The C-3
    /// restore makes eras cyclable — and therefore makes the SAME cancel proof reusable an
    /// unbounded number of times.
    ///
    /// Attacker: `eve`, who is NOT a member, NOT a delegate, and never was. She holds exactly one
    /// (closeIntentDigest, revivedStateVersion=21) cancel proof — in the real system, the completed
    /// N-of-N signature set for v21 that a coordinator withheld (audit C-3's own scenario).
    /// Alice, honest, holds only v20 and wants out.
    ///
    /// Result: alice can never finalize a close. Eve pays gas only — the identical calldata is
    /// replayed every round. `closeChallengeHorizon` is reset to 0 by each cancel, so H-3's
    /// absolute per-era horizon bounds nothing across eras.
    function test_ATTACK_cancelReCloseCycleIsUnboundedAndTheProofIsReplayed() external {
        // Eve's one-time cost: a single cancel proof for the intent alice will keep submitting.
        ChannelSettlementManager.CloseIntent memory honestIntent = _intentAt(9, 20);
        bytes32 digest = manager.computeCloseIntentDigest(honestIntent);
        ChannelSettlementManager.CancelCloseRequest memory req = _cancelRequest(digest, 21);
        bytes memory replayedProof = _cancelProofAt(req, honestIntent.finalStateVersion);

        // NOTE: read via the cheatcode, not `block.timestamp` — under via-IR the Yul
        // optimizer treats TIMESTAMP as movable and CSEs the two reads to a constant 0 delta.
        uint256 startTime = vm.getBlockTimestamp();
        uint256 ROUNDS = 25;
        uint256 roundsEveSurvived = 0;

        for (uint256 i = 0; i < ROUNDS; i++) {
            uint64 freezeNonce = manager.currentCloseFreezeNonce();
            uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
            vm.prank(alice);
            manager.requestClose(freezeNonce, cancellationFloor);
            vm.warp(block.timestamp + GRACE);
            manager.submitCloseIntent(honestIntent, _closeProof(honestIntent));

            // H-3's horizon is live for this era...
            assertGt(manager.closeChallengeHorizon(), 0, "horizon armed");

            // ...and eve erases it immediately. No window bound on cancelClose: she does not even
            // have to wait. Same request struct, same proof bytes, every single round.
            //
            // ROUND 2 (A1): the FIRST replay still works — one cancel proof is one legitimate
            // cancel, and A1 deliberately does not take that away. Every replay AFTER it is refused
            // by the monotone floor, because it exhibits no material newer than the cancel that
            // already consumed v21. Eve's censorship collapses from unbounded to a single round.
            if (i == 0) {
                vm.prank(eve);
                manager.cancelClose(req, replayedProof);
                roundsEveSurvived += 1;
            } else {
                vm.prank(eve);
                vm.expectRevert(ChannelSettlementManager.CancelCloseReplay.selector);
                manager.cancelClose(req, replayedProof);
                break;
            }

            assertEq(manager.closeChallengeHorizon(), 0, "H-3 horizon cleared -> bounds nothing");
            assertEq(
                uint8(manager.channelStatus()),
                uint8(ChannelSettlementManager.ChannelLifecycleStatus.Active),
                "back to Active: the era is cyclable"
            );
            assertEq(manager.currentCloseFreezeNonce(), 0, "era restored -> next round is legal");
        }

        emit log_named_uint("rounds eve could actually censor", roundsEveSurvived);
        emit log_named_uint("total elapsed seconds", vm.getBlockTimestamp() - startTime);
        assertEq(roundsEveSurvived, 1, "A1: one cancel proof buys exactly one cancel, not 25");

        // And the honest close eve was censoring goes through — A1 gates CANCELS, never CLOSES, so
        // alice still exits with the only state she holds (v20), floor or no floor. This is the
        // property the round-1 "minimum close state version" latch could NOT have provided.
        assertTrue(manager.getPendingClose().active, "alice's close survived the failed cancel");
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(
            uint8(manager.channelStatus()),
            uint8(ChannelSettlementManager.ChannelLifecycleStatus.Closed),
            "BLOCKED: exit is reachable; censorship is bounded by signed material, not by gas"
        );
        assertEq(manager.finalizedStateVersion(), 20, "and alice, not eve, chose the settled state");
    }

    /// EXPLOIT, minimal form (passes = attack works). The single fact behind ATTACK 1: one cancel
    /// proof cancels the same `closeIntentDigest` twice. There is no nullifier, used-set, or
    /// per-era binding on a cancel proof.
    function test_ATTACK_oneCancelProofIsAcceptedTwiceForTheSameDigest() external {
        ChannelSettlementManager.CloseIntent memory intent = _intentAt(9, 20);
        bytes32 digest = manager.computeCloseIntentDigest(intent);
        ChannelSettlementManager.CancelCloseRequest memory req = _cancelRequest(digest, 21);
        bytes memory proof = _cancelProofAt(req, intent.finalStateVersion);

        _requestCloseAndElapseGrace();
        manager.submitCloseIntent(intent, _closeProof(intent));
        vm.prank(eve);
        manager.cancelClose(req, proof); // round 1

        _requestCloseAndElapseGrace();
        manager.submitCloseIntent(intent, _closeProof(intent));
        vm.prank(eve);
        // ROUND 2 (A1): round 2 — IDENTICAL calldata — is now refused. The floor was raised to 21
        // by round 1, and `21 <= 21` is not "strictly newer material".
        vm.expectRevert(ChannelSettlementManager.CancelCloseReplay.selector);
        manager.cancelClose(req, proof);

        assertEq(
            manager.highestCancelledRevivedStateVersion(), 21, "round 1 consumed the v21 material"
        );
        assertEq(
            uint8(manager.channelStatus()),
            uint8(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending),
            "BLOCKED: the cancel proof is a one-shot capability again"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // ATTACK 2 — H-3: the clamp removes the guaranteed response window from the
    //            LAST ladder rung. A replacement landing exactly at the horizon
    //            is finalizable in the SAME block, with a zero-length window.
    // ═════════════════════════════════════════════════════════════════════════

    /// EXPLOIT (passes = attack works). `_storePendingClose` clamps
    /// `challengeDeadline = min(now + challengePeriod, closeChallengeHorizon)`. The replacement
    /// branch admits an intent while `now <= pendingClose.challengeDeadline`, and the deadline can
    /// equal the horizon — so a rung landing at exactly `t == horizon` gets
    /// `challengeDeadline == block.timestamp` and the historical `finalizeClose()` boundary
    /// allowed same-block settlement. Finalization now requires a strictly later timestamp.
    ///
    /// Before the H-3 fix every rung bought a full fresh `challengePeriod`, so the final rung
    /// always left honest members one whole window to answer it. The clamp trades ladder LENGTH
    /// for per-rung RESPONSE TIME: the attacker now picks the settled state with zero opportunity
    /// for an on-chain reply. This is a narrowing the H-3 rationale does not mention (its comment
    /// claims the cap is "liveness-restoring without narrowing the interval the stale-close
    /// defence was sized for").
    function test_ATTACK_lastLadderRungGetsAZeroLengthChallengeWindow() external {
        _requestCloseAndElapseGrace();
        uint256 t0 = vm.getBlockTimestamp();

        // Rung 1 — anchors the era horizon at t0 + 2*challengePeriod.
        ChannelSettlementManager.CloseIntent memory r1 = _intentAt(9, 10);
        manager.submitCloseIntent(r1, _closeProof(r1));
        uint64 horizon = manager.closeChallengeHorizon();
        assertEq(horizon, t0 + 2 * CHALLENGE_PERIOD, "horizon anchored at the first intent");

        // Rung 2 — landed at the last legal instant of rung 1's window.
        vm.warp(t0 + CHALLENGE_PERIOD);
        ChannelSettlementManager.CloseIntent memory r2 = _intentAt(9, 11);
        manager.submitCloseIntent(r2, _closeProof(r2));
        assertEq(manager.getPendingClose().challengeDeadline, horizon, "rung 2 clamped to the horizon");

        // Rung 3 — landed at exactly the horizon. `now > challengeDeadline` is the revert
        // condition, so `now == deadline` is admitted, and the clamp then handed the replacement a
        // deadline equal to NOW.
        //
        // ROUND 2 (A2) refused the RUNG. ROUND 3 (R3-2) refuses the ZERO-LENGTH WINDOW instead: the
        // rung is admitted (refusing it was itself an attack — see
        // `RedTeamRound3.t.sol::test_R3_BREAK_A2_finalHourIsAReplacementBlackout`, where the refusal
        // is what let a griefer's stale state settle), and `_storePendingClose` floors its deadline
        // at `now + MIN_CLOSE_RESPONSE_SECS`. The attack's actual harm — "zero opportunity for an
        // on-chain reply" — is what is blocked, and it is blocked without denying anyone the reply.
        vm.warp(horizon);
        ChannelSettlementManager.CloseIntent memory r3 = _intentAt(9, 12);
        uint64 minResponse = manager.MIN_CLOSE_RESPONSE_SECS();
        manager.submitCloseIntent(r3, _closeProof(r3));
        assertEq(
            manager.getPendingClose().challengeDeadline,
            uint64(vm.getBlockTimestamp()) + minResponse,
            "BLOCKED: the rung at the horizon is NOT zero-length; it carries a full response window"
        );
        // Same-block finalization — the whole point of the attack — is refused.
        bytes32 guardedDigest = manager.getPendingClose().closeIntentDigest;
        uint64 guardedGeneration = manager.closeRequestGeneration();
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowOpen.selector);
        manager.finalizeCloseGuarded(guardedDigest, guardedGeneration);

        // And the reply is genuinely available for that whole interval: `cancelClose` needs the
        // identical material a replacement would and has no window bound.
        vm.warp(uint256(horizon) + minResponse - 1);
        bytes32 r3Digest = manager.computeCloseIntentDigest(r3);
        manager.cancelClose(_cancelRequest(r3Digest, 13), _cancelProof(_cancelRequest(r3Digest, 13)));
        assertEq(
            uint8(manager.channelStatus()),
            uint8(ChannelSettlementManager.ChannelLifecycleStatus.Active),
            "BLOCKED: the attacker's rung was answerable, so it did not get to pick the settled state"
        );
    }

    /// The A2 property stated directly, independent of the ladder: EVERY admitted replacement has a
    /// strictly positive, usable window between its storage and its finalizability.
    ///
    /// PINS (as rewritten by R3-2): `MIN_CLOSE_RESPONSE_SECS` and the deadline FLOOR in
    /// `_storePendingClose`. Delete the floor and the rung landing at the horizon is stored with
    /// `challengeDeadline == block.timestamp`, i.e. finalizable in the same block, and the
    /// assertions below fail. The guard R3-2 removed — the `now + minResponse > horizon` ADMISSION
    /// bar — is pinned in the opposite direction here: restoring it makes the admissions below
    /// revert.
    function test_A2_everyAdmittedReplacementKeepsAUsableWindow() external {
        _requestCloseAndElapseGrace();
        uint64 t0 = uint64(vm.getBlockTimestamp());
        uint64 minResponse = manager.MIN_CLOSE_RESPONSE_SECS();

        ChannelSettlementManager.CloseIntent memory r1 = _intentAt(9, 10);
        manager.submitCloseIntent(r1, _closeProof(r1));
        uint64 horizon = manager.closeChallengeHorizon();

        // One intermediate rung, landed at r1's deadline, pushes the pending deadline out to the
        // horizon — the state in which the raw deadline check no longer binds and only A2 does.
        vm.warp(t0 + CHALLENGE_PERIOD);
        ChannelSettlementManager.CloseIntent memory r2 = _intentAt(9, 11);
        manager.submitCloseIntent(r2, _closeProof(r2));
        assertEq(manager.getPendingClose().challengeDeadline, horizon, "deadline is at the horizon");

        // The instant round 2 treated as "the last admissible" one. The window it earns is
        // unchanged — a full MIN_CLOSE_RESPONSE_SECS — but it is now the FLOOR that provides it,
        // not the clamp.
        vm.warp(horizon - minResponse);
        ChannelSettlementManager.CloseIntent memory last = _intentAt(9, 12);
        manager.submitCloseIntent(last, _closeProof(last));
        assertEq(
            manager.getPendingClose().challengeDeadline - vm.getBlockTimestamp(),
            minResponse,
            "the rung still carries a full MIN_CLOSE_RESPONSE_SECS"
        );
        // Same-block finalization — the whole point of the attack — is refused.
        bytes32 guardedDigest = manager.getPendingClose().closeIntentDigest;
        uint64 guardedGeneration = manager.closeRequestGeneration();
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowOpen.selector);
        manager.finalizeCloseGuarded(guardedDigest, guardedGeneration);

        // R3-2: one second later a replacement IS admitted — round 2 refused it, and that refusal
        // was the blackout. It too carries a full response window.
        vm.warp(horizon - minResponse + 1);
        ChannelSettlementManager.CloseIntent memory late = _intentAt(9, 13);
        manager.submitCloseIntent(late, _closeProof(late));
        assertEq(
            manager.getPendingClose().challengeDeadline - vm.getBlockTimestamp(),
            minResponse,
            "every admitted rung, at every instant up to the horizon, keeps a usable window"
        );

        // R3-4: the already-budgeted response tail also admits a strictly-newer replacement, but
        // it cannot extend the fixed horizon+minResponse end.
        vm.warp(uint256(horizon) + 1);
        ChannelSettlementManager.CloseIntent memory tooLate = _intentAt(9, 14);
        bytes memory tooLateProof = _closeProof(tooLate);
        manager.submitCloseIntent(tooLate, tooLateProof);
        assertEq(
            manager.getPendingClose().challengeDeadline,
            horizon + minResponse,
            "tail response cannot extend the absolute end"
        );

        // Strict deadline ownership adds exactly one timestamp so replacement and finalization
        // cannot both win at equality. After it, admission is permanently closed.
        vm.warp(uint256(manager.getPendingClose().challengeDeadline));
        guardedDigest = manager.getPendingClose().closeIntentDigest;
        guardedGeneration = manager.closeRequestGeneration();
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowOpen.selector);
        manager.finalizeCloseGuarded(guardedDigest, guardedGeneration);
        vm.warp(uint256(manager.getPendingClose().challengeDeadline) + 1);
        ChannelSettlementManager.CloseIntent memory afterEnd = _intentAt(9, 15);
        bytes memory afterEndProof = _closeProof(afterEnd);
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowClosed.selector);
        manager.submitCloseIntent(afterEnd, afterEndProof);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertLe(
            vm.getBlockTimestamp(),
            uint256(horizon) + minResponse + 1,
            "exit lands one timestamp after the final response interval"
        );
        // v14 — the R3-4 response in the already-budgeted tail — is what settles.
        assertEq(manager.finalizedStateVersion(), 14);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // REFUTATIONS — probes that FAILED to break the fixes. These pass by
    // confirming the defence.
    // ═════════════════════════════════════════════════════════════════════════

    /// REFUTED (fix holds). The C-3 soundness claim — `requestClose(+1) -> submitCloseIntent* ->
    /// cancelClose(-1)` is a NO-OP on the machine — is checked field by field against EVERY piece
    /// of close-lifecycle storage the round trip touches, including a replacement ladder in the
    /// middle. Nothing is left behind.
    function test_REFUTED_C3_roundTripIsAGenuineStorageNoOp() external {
        uint64 nonce0 = manager.currentCloseFreezeNonce();
        uint8 status0 = uint8(manager.channelStatus());
        uint64 requestedAt0 = manager.closeRequestedAt();
        uint64 horizon0 = manager.closeChallengeHorizon();
        bool pending0 = manager.getPendingClose().active;
        bool nativeAllowed0 = manager.isNativeSendAllowed(nonce0);

        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory a = _intentAt(9, 10);
        manager.submitCloseIntent(a, _closeProof(a));
        ChannelSettlementManager.CloseIntent memory b = _intentAt(9, 11);
        manager.submitCloseIntent(b, _closeProof(b)); // a replacement rung, for good measure
        bytes32 digest = manager.computeCloseIntentDigest(b);
        manager.cancelClose(_cancelRequest(digest, 12), _cancelProof(_cancelRequest(digest, 12)));

        assertEq(manager.currentCloseFreezeNonce(), nonce0, "era restored");
        assertEq(uint8(manager.channelStatus()), status0, "status restored");
        assertEq(manager.closeRequestedAt(), requestedAt0, "closeRequestedAt restored");
        assertEq(manager.closeChallengeHorizon(), horizon0, "H-3 horizon restored");
        assertEq(manager.getPendingClose().active, pending0, "pendingClose cleared");
        assertEq(manager.isNativeSendAllowed(nonce0), nativeAllowed0, "send gate restored");
    }

    /// REFUTED (fix holds). The `currentCloseFreezeNonce -= 1` underflow. `cancelClose` requires
    /// `pendingClose.active`, which only `submitCloseIntent` sets, which requires ClosePending,
    /// which only `requestClose` sets — and it always bumps first. Every route to `cancelClose`
    /// with a zero counter is refused BEFORE the decrement.
    function test_REFUTED_C3_decrementCannotUnderflow() external {
        assertEq(manager.currentCloseFreezeNonce(), 0, "counter starts at zero");

        // No pending close: refused at the first guard, BEFORE the decrement.
        ChannelSettlementManager.CancelCloseRequest memory bogus =
            _cancelRequest(bytes32(uint256(1)), 12);
        bytes memory bogusProof = _cancelProof(bogus);
        vm.expectRevert(ChannelSettlementManager.CloseNotActive.selector);
        manager.cancelClose(bogus, bogusProof);

        // After finalizeClose the pendingClose is deleted, so a post-settlement cancel cannot
        // reach the decrement either (this is what would otherwise underflow AND resurrect a
        // Closed channel).
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intentAt(9, 10);
        manager.submitCloseIntent(intent, _closeProof(intent));
        bytes32 digest = manager.computeCloseIntentDigest(intent);
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(manager.currentCloseFreezeNonce(), 1, "settled era is NOT unwound");

        ChannelSettlementManager.CancelCloseRequest memory late = _cancelRequest(digest, 12);
        bytes memory lateProof = _cancelProof(late);
        vm.expectRevert(ChannelSettlementManager.CloseNotActive.selector);
        manager.cancelClose(late, lateProof);
        assertEq(
            uint8(manager.channelStatus()),
            uint8(ChannelSettlementManager.ChannelLifecycleStatus.Closed),
            "a settled close cannot be cancelled back into Active"
        );
    }

    /// REFUTED (fix holds). The invariant that makes the H-3 clamp safe:
    /// `pendingClose.active => closeChallengeHorizon != 0`. If a replacement could ever be stored
    /// while the horizon read zero, `min(natural, 0) = 0` would put the deadline in the past and
    /// make the close instantly finalizable with NO window. Both routes out of `pendingClose.active`
    /// (cancelClose, finalizeClose) zero the horizon and clear pendingClose together, so the
    /// horizon is always re-anchored by the next era's first intent.
    function test_REFUTED_H3_horizonIsNeverZeroWhileACloseIsPending() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory a = _intentAt(9, 10);
        manager.submitCloseIntent(a, _closeProof(a));
        assertGt(manager.closeChallengeHorizon(), 0, "armed on the first intent");

        bytes32 digest = manager.computeCloseIntentDigest(a);
        manager.cancelClose(_cancelRequest(digest, 12), _cancelProof(_cancelRequest(digest, 12)));
        assertEq(manager.closeChallengeHorizon(), 0, "cleared with the era");
        assertFalse(manager.getPendingClose().active, "and pendingClose went with it");

        // Next era re-anchors from scratch: a full window, not a stale clamp into the past.
        _requestCloseAndElapseGrace();
        uint256 t = block.timestamp;
        manager.submitCloseIntent(a, _closeProof(a));
        assertEq(manager.closeChallengeHorizon(), t + 2 * CHALLENGE_PERIOD, "re-anchored");
        assertEq(manager.getPendingClose().challengeDeadline, t + CHALLENGE_PERIOD, "full window");
    }

    /// Closed-state and version-2 guards reject premature or legacy residual claims atomically.
    function test_C2_closedStateAndUnappliedStatementVersionAreRequired() external {
        // Before any close. (Proofs are PRECOMPUTED so `expectRevert` arms on the claim call
        // itself and not on a helper's external view call.)
        ChannelSettlementManager.PostCloseClaim memory early =
            _postCloseClaim(bytes32(0), keccak256("inc"), USER_A, alice, 1);
        bytes memory junk = CloseTestLib.proofWithLimbs(new uint256[](1));
        vm.expectRevert(ChannelSettlementManager.CloseNotActive.selector);
        manager.submitPostCloseClaim(early, junk);

        bytes32 closeDigest = _finalizeDefault();

        // After a real close, with a well-formed claim and a WELL-FORMED, verifier-accepted proof.
        ChannelSettlementManager.PostCloseClaim memory claim =
            _postCloseClaim(closeDigest, keccak256("inc"), USER_B, bob, 1);
        bytes memory good = _postCloseClaimProof(claim);
        uint256[] memory wrongVersion = abi.decode(good, (uint256[]));
        wrongVersion[57] = 1;
        good = abi.encode(wrongVersion);
        vm.expectRevert(bytes("claim limb mismatch"));
        manager.submitPostCloseClaim(claim, good);

        // A rejected proof creates neither credit nor a consumed nullifier.
        assertEq(manager.withdrawalCredits(TOKEN_INDEX, bob), 0, "no post-close credit exists");
        assertFalse(
            manager.usedSharedNativeNullifiers(
                _expectedSharedNativeNullifier(closeDigest, claim.incomingTxHash, claim.receiverPkG)
            ),
            "failed verification must leave the IMCK nullifier available"
        );
    }

    /// REFUTED (fix holds). C-2 traded theft for nothing: the per-token accrual budget the
    /// post-close path used to share is now fully available to withdrawal claims, so no value
    /// that a withdrawal claim can prove becomes unpayable. The manager holds no state that only
    /// the disabled path could have paid out.
    function test_REFUTED_C2_disablingStrandsNoWithdrawableValue() external {
        bytes32 closeDigest = _finalizeWithFund(DEFAULT_FUND_AMOUNT);
        _fundAndPull(registry, manager, DEFAULT_FUND_AMOUNT);

        // The whole fund is still claimable through the surviving path.
        ChannelSettlementManager.WithdrawalClaim memory c =
            _withdrawalClaim(closeDigest, USER_A, alice, uint64(DEFAULT_FUND_AMOUNT));
        manager.submitWithdrawalClaim(c, _withdrawalClaimProof(c));
        assertEq(
            manager.withdrawalCredits(TOKEN_INDEX, alice),
            DEFAULT_FUND_AMOUNT,
            "the entire per-token cap remains reachable without the post-close path"
        );
        assertEq(manager.totalWithdrawn(TOKEN_INDEX), DEFAULT_FUND_AMOUNT, "cap fully consumed");
    }

    /// A1 NON-LOCKOUT, stated directly and separately from the attack: the floor gates CANCELS and
    /// nothing else. With the floor raised as high as any party can raise it, an honest member
    /// holding only an OLD state still completes the whole close lifecycle.
    ///
    /// This is the property the round-1 "minimum close state version" latch could not provide, and
    /// the reason that latch was rejected: it gated CLOSES, so only the canceller (the withholding
    /// coordinator) could satisfy it afterwards.
    function test_A1_floorNeverBlocksAnHonestCloseOrExit() external {
        // Eve raises the floor as high as she likes.
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory bait = _intentAt(9, 10);
        manager.submitCloseIntent(bait, _closeProof(bait));
        bytes32 d = manager.computeCloseIntentDigest(bait);
        vm.prank(eve);
        manager.cancelClose(_cancelRequest(d, 9_999), _cancelProof(_cancelRequest(d, 9_999)));
        assertEq(manager.highestCancelledRevivedStateVersion(), 9_999, "floor is maximal");

        // Alice, holding only v20 — far BELOW the floor — still closes and exits.
        uint64 freezeNonce = manager.currentCloseFreezeNonce();
        uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
        vm.prank(alice);
        manager.requestClose(freezeNonce, cancellationFloor);
        vm.warp(block.timestamp + GRACE);
        ChannelSettlementManager.CloseIntent memory honest = _intentAt(9, 20);
        manager.submitCloseIntent(honest, _closeProof(honest));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());

        assertEq(
            uint8(manager.channelStatus()),
            uint8(ChannelSettlementManager.ChannelLifecycleStatus.Closed),
            "exit liveness is unconditional in the A1 floor"
        );
        assertEq(manager.finalizedStateVersion(), 20, "and at the honest member's own state");
    }
}
