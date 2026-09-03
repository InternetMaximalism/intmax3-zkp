// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {CloseSettlementBase} from "./CloseSettlementBase.sol";
import {CloseTestLib} from "./CloseTestLib.sol";

/// @title RedTeamRound3
/// @notice ROUND-3 adversarial probes against the ROUND-2 guards A1 / A2 / A4 in
///         `ChannelSettlementManager`. Every `test_R3_BREAK_*` PASSES by demonstrating an attack
///         the round-2 guard does NOT stop (the assertion IS the exploit). Every `test_R3_REFUTED_*`
///         PASSES by confirming a guard holds against an attack that was tried and failed.
contract RedTeamRound3Test is CloseSettlementBase {
    bytes32 internal constant TX_LEAF = keccak256("r3_burn_tx_leaf");
    bytes32 internal constant PREV_CHAIN = keccak256("r3_prev_settled_tx_chain");
    bytes32 internal constant PW_NULLIFIER = keccak256("r3_pw_nullifier");
    uint32 internal constant TOKEN_INDEX = 0;
    uint256 internal constant PW_AMOUNT = 5;

    address internal eve = makeAddr("eve_withholding_coordinator");

    // ── helpers (mirrored from CloseLifecycleRedTeam.t.sol) ──────────────────

    function _cancelProof(ChannelSettlementManager.CancelCloseRequest memory request)
        internal view returns (MleVerifier.MleProof memory)
    {
        ChannelSettlementManager.PendingClose memory pending = manager.getPendingClose();
        uint64 closeFinalStateVersion = pending.active && pending.closeIntentDigest == request.closeIntentDigest
            ? pending.finalStateVersion
            : manager.pendingPartialWithdrawalStateVersion();
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

    function _baseRecipient(address recipient) internal pure returns (bytes32) {
        return bytes32((uint256(2) << 248) | uint256(uint160(recipient)));
    }

    function _burnDescriptor() internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(0x494d4432),
                uint32(CHANNEL_ID),
                PW_BASE_NONCE,
                TX_LEAF,
                _baseRecipient(alice),
                TOKEN_INDEX,
                PW_AMOUNT
            )
        );
    }

    function _authorizedWithdrawal()
        internal view returns (ChannelSettlementManager.AuthorizedWithdrawal memory)
    {
        return ChannelSettlementManager.AuthorizedWithdrawal({
            recipient: alice,
            tokenIndex: TOKEN_INDEX,
            amount: PW_AMOUNT,
            baseNonce: PW_BASE_NONCE,
            nullifier: PW_NULLIFIER,
            auxData: _burnDescriptor(),
            txLeaf: TX_LEAF
        });
    }

    function _expectedAuthDigest() internal view returns (bytes32) {
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        return keccak256(
            abi.encodePacked(
                bytes4(0x49505732), w.recipient, w.tokenIndex, w.amount, w.auxData
            )
        );
    }

    function _pwIntent(uint64 epoch, uint64 stateVersion)
        internal view returns (ChannelSettlementManager.CloseIntent memory intent)
    {
        intent = _intentAt(epoch, stateVersion);
        intent.channelFundAmounts[0] = DEFAULT_FUND_AMOUNT - PW_AMOUNT;
        intent.finalSettledTxChain =
            keccak256(abi.encodePacked(uint32(0x494d5443), PREV_CHAIN, _burnDescriptor()));
    }

    function _submitPw(uint64 epoch, uint64 stateVersion) internal {
        ChannelSettlementManager.CloseIntent memory intent = _pwIntent(epoch, stateVersion);
        manager.submitPartialWithdrawalIntent(
            intent, _closeProof(intent), PREV_CHAIN, _authorizedWithdrawal()
        );
    }

    function _submitPwAndElapse(uint64 epoch, uint64 stateVersion) internal {
        _submitPw(epoch, stateVersion);
        vm.warp(vm.getBlockTimestamp() + CHALLENGE_PERIOD + 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // BREAK 1 — A1 x A3: the C-3 permanent brick, reintroduced.  *** FIXED ***
    //
    //   THE ATTACK AS FOUND. A3's non-brick argument was "two permissionless
    //   remedies remain open ... challenge-replace it while the window is open,
    //   or `cancelClose` it, which has no window bound at all ... the material
    //   they need provably exists". A1's manager-lifetime floor CONSUMES exactly
    //   that material: once a cancel has been spent at version v, no later cancel
    //   at v is admissible EVER. Combined with an A3 refusal after the replacement
    //   window shut, every exit from `ClosePending` closed simultaneously.
    //
    //   THE FIX, round 3 (R3-1): `finalizeClose` settled the stale close and
    //   deducted the burn from its cap. THE FIX NOW (exact-vector exit): the
    //   version-dependent refusal lives at ADMISSION only. `submitCloseIntent`
    //   refuses a close below the authorized burn state before anything is
    //   installed (`CloseOlderThanAuthorizedBurn`), so the latch that made
    //   `ClosePending` terminal can never be armed; the burn state itself (or a
    //   strictly newer whole state) is admissible, and `finalizeClose` keeps NO
    //   version-dependent revert. The four latches cannot conjoin, and no cap is
    //   ever synthesized from two state generations.
    // ════════════════════════════════════════════════════════════════════════

    /// BLOCKED (passes = the attack no longer works). The setup that used to wedge the channel is
    /// preserved; only step ORDER and verdict changed, because a v28 close can no longer be
    /// installed once the v30 burn exists — so the A1 floor must be spent first.
    ///
    /// ACTORS: `alice` (any `isMemberRecipient` party). SUPPLY MODEL: the newest N-of-N-signed
    /// state in existence is v30, and v28 is an older signed state every member retains. No party
    /// can manufacture v31.
    ///
    /// ORDERING:
    ///   1. a stale close at v28 is submitted and cancelled with the head v30
    ///      -> `highestCancelledRevivedStateVersion = 30`      [A1's floor, AT the supply top]
    ///   2. a burn committed in the head state v30 is authorized while the channel is Active
    ///      -> `authorizedBurn{Epoch,StateVersion} = (9, 30)`  [A3's high-water mark]
    ///   3. the SAME stale close at v28 is submitted again -> REFUSED at admission, nothing installed
    ///   4. the burn state v30 — the only material at the top — is installed and left to run out
    ///
    /// RESULT: the three OTHER latches are exactly as armed as when the attack landed --
    /// `cancelClose(v30)` reverts (`CloseNotNewer`: v30 is not newer than the pending v30),
    /// `submitCloseIntent(v30)` reverts `ChallengeWindowClosed`, `requestClose` reverts
    /// `ChannelAlreadyFrozen` -- and it does not matter, because `finalizeClose` SETTLES the one
    /// authenticated whole state, whose vector already excludes the burn.
    function test_R3_BREAK_A1xA3_staleCloseNeverInstallsSoClosePendingIsNotTerminal() external {
        // ── 1. a stale close at v28; the honest holder of v30 cancels it. This is the NORMAL,
        //      intended use of `cancelClose` -- and it spends the top of the version supply.
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory stale1 = _intentAt(9, 28);
        manager.submitCloseIntent(stale1, _closeProof(stale1));
        bytes32 d1 = manager.computeCloseIntentDigest(stale1);
        manager.cancelClose(_cancelRequest(d1, 30), _cancelProof(_cancelRequest(d1, 30)));
        assertEq(manager.highestCancelledRevivedStateVersion(), 30, "A1 floor now at the supply top");
        assertEq(
            uint8(manager.channelStatus()),
            uint8(ChannelSettlementManager.ChannelLifecycleStatus.Active),
            "channel revived"
        );

        // ── 2. the honest burn at the head state v30 is authorized (channel Active).
        _submitPwAndElapse(9, 30);
        manager.finalizePartialWithdrawal();
        assertEq(manager.authorizedBurnStateVersion(), 30, "A3 mark at the head");
        assertEq(manager.authorizedBurnAmount(TOKEN_INDEX), PW_AMOUNT, "gross telemetry retained");

        // ── 3. the identical stale close is submitted again: refused before it is installed.
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory stale2 = _intentAt(9, 28);
        MleVerifier.MleProof memory stale2Proof = _closeProof(stale2);
        vm.expectRevert(ChannelSettlementManager.CloseOlderThanAuthorizedBurn.selector);
        manager.submitCloseIntent(stale2, stale2Proof);
        assertFalse(manager.getPendingClose().active, "the latch is never armed: nothing installed");
        assertEq(
            uint8(manager.channelStatus()),
            uint8(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending),
            "era open, no pending close"
        );
        assertEq(manager.finalizedChannelFundAmount(TOKEN_INDEX), 0, "no stale cap created");

        // ── 4. the burn state itself is admissible, and the window is allowed to expire.
        ChannelSettlementManager.CloseIntent memory head = _pwIntent(9, 30);
        manager.submitCloseIntent(head, _closeProof(head));
        bytes32 d2 = manager.computeCloseIntentDigest(head);
        uint64 horizon = manager.closeChallengeHorizon();
        uint64 absoluteEnd = horizon + manager.MIN_CLOSE_RESPONSE_SECS();
        vm.warp(uint256(absoluteEnd) + 1);

        // ── the three OTHER latches remain exactly as armed as when the attack landed. ──────
        // (b) the newest material that exists cannot cancel a close AT that same state.
        ChannelSettlementManager.CancelCloseRequest memory rescue = _cancelRequest(d2, 30);
        MleVerifier.MleProof memory rescueProof = _cancelProof(rescue);
        vm.expectRevert(ChannelSettlementManager.CloseNotNewer.selector);
        manager.cancelClose(rescue, rescueProof);

        // (c) the replacement lane is shut past the fixed response-tail end -- even with the head.
        ChannelSettlementManager.CloseIntent memory again = _pwIntent(9, 30);
        MleVerifier.MleProof memory againProof = _closeProof(again);
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowClosed.selector);
        manager.submitCloseIntent(again, againProof);

        // (d) no new era can be opened.
        uint64 freezeNonce = manager.currentCloseFreezeNonce();
        uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
        vm.prank(alice);
        vm.expectRevert(ChannelSettlementManager.ChannelAlreadyFrozen.selector);
        manager.requestClose(freezeNonce, cancellationFloor);

        // ── (a) THE EXIT. `finalizeClose` has no version-dependent revert: it settles.
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(
            uint8(manager.channelStatus()),
            uint8(ChannelSettlementManager.ChannelLifecycleStatus.Closed),
            "ClosePending is NOT terminal; finalizeClose is always a reachable exit"
        );
        assertEq(manager.finalizedStateVersion(), 30, "the whole burn state settled");
        assertFalse(manager.getPendingClose().active, "pendingClose consumed");

        // ── and the double-draw A3 existed to stop is STILL stopped: the settled cap is the burn
        //    state's own post-burn vector, not a pre-burn vector with a deduction bolted on.
        assertEq(
            manager.finalizedChannelFundAmount(TOKEN_INDEX),
            DEFAULT_FUND_AMOUNT - PW_AMOUNT,
            "the settled vector already excludes the authorized burn"
        );
        assertEq(manager.authorizedBurnAmount(TOKEN_INDEX), PW_AMOUNT, "gross telemetry retained");
    }

    /// MUTATION PIN for the R3-1 fix. The deduction must be REAL, not a no-op: with the same facts
    /// but NO authorized burn, the very same stale close settles at the FULL declared cap. The
    /// difference between the two caps is exactly the burn amount, so a deduction that silently did
    /// nothing (or that deducted from the wrong base token) fails here.
    function test_R3_FIXED_A1xA3_deductionIsExactlyTheAuthorizedBurn() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory stale = _intentAt(9, 28);
        manager.submitCloseIntent(stale, _closeProof(stale));
        vm.warp(uint256(manager.closeChallengeHorizon()) + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(
            manager.finalizedChannelFundAmount(TOKEN_INDEX),
            DEFAULT_FUND_AMOUNT,
            "no burn authorized => no deduction"
        );
    }

    /// CONTROL for BREAK 1, isolating A1. Identical facts, except the A1 floor is never spent.
    ///
    /// Round 2 used this control to argue "the A3 refusal IS a deferral because `cancelClose` at
    /// v30 rescues the channel" -- which A1 then falsified. Under the exact-vector exit the premise
    /// is moot in the other direction: the stale close is refused at admission REGARDLESS of the
    /// floor (it reads nothing A1 writes), so there is never a pending stale close to rescue, and
    /// the era still has its exit without any cancel -- the burn state itself settles.
    function test_R3_BREAK_A1xA3_control_refusalIsIndependentOfTheSpentFloor() external {
        _submitPwAndElapse(9, 30);
        manager.finalizePartialWithdrawal();

        _requestCloseAndElapseGrace();
        assertEq(manager.highestCancelledRevivedStateVersion(), 0, "floor unspent");
        ChannelSettlementManager.CloseIntent memory stale = _intentAt(9, 28);
        MleVerifier.MleProof memory staleProof = _closeProof(stale);
        vm.expectRevert(ChannelSettlementManager.CloseOlderThanAuthorizedBurn.selector);
        manager.submitCloseIntent(stale, staleProof);
        assertFalse(manager.getPendingClose().active, "refused with the floor unspent too");
        assertEq(manager.highestCancelledRevivedStateVersion(), 0, "the refusal touches no floor");

        // No cancel is needed for the exit: the burn state is admitted and settles.
        ChannelSettlementManager.CloseIntent memory head = _pwIntent(9, 30);
        manager.submitCloseIntent(head, _closeProof(head));
        vm.warp(uint256(manager.closeChallengeHorizon()) + manager.MIN_CLOSE_RESPONSE_SECS() + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(
            uint8(manager.channelStatus()),
            uint8(ChannelSettlementManager.ChannelLifecycleStatus.Closed),
            "the era exits through the one authenticated whole state"
        );
        assertEq(manager.finalizedChannelFundAmount(TOKEN_INDEX), DEFAULT_FUND_AMOUNT - PW_AMOUNT);
    }

    /// CONTROL for BREAK 1, isolating A3. Identical facts, except no burn is ever authorized. The
    /// spent A1 floor alone is harmless: the stale close simply settles.
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
        MleVerifier.MleProof memory tooLateProof = _closeProof(tooLate);
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
        MleVerifier.MleProof memory spentProof = _cancelProof(spent);
        vm.expectRevert(ChannelSettlementManager.CancelCloseReplay.selector);
        manager.cancelClose(spent, spentProof);

        ChannelSettlementManager.CloseIntent memory head = _intentAt(9, 30);
        manager.submitCloseIntent(head, _closeProof(head));
        assertEq(manager.getPendingClose().finalStateVersion, 30, "spent cancel material still replaces");
        assertEq(manager.getPendingClose().challengeDeadline, absoluteEnd, "tail remains fixed");

        vm.warp(uint256(absoluteEnd) + 1);
        ChannelSettlementManager.CloseIntent memory tooLate = _intentAt(9, 31);
        MleVerifier.MleProof memory tooLateProof = _closeProof(tooLate);
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

    // ════════════════════════════════════════════════════════════════════════
    // BREAK 3 — A4: the per-burn mark disarms the DEFENDER, not the attacker.
    //           *** MITIGATED (R3-3) ***
    //
    //   THE ATTACK AS FOUND. Before A4, `cancelPartialWithdrawal` compared only
    //   against the PENDING record, so an honest member could replay ONE cancel
    //   proof against every re-submission of the same stale burn. A4 removed
    //   exactly that replay -- while re-submitting the burn intent stayed free
    //   (the single-use chainKey guard was deliberately deleted). The attrition
    //   was therefore inverted: the attacker needed no new material, the defender
    //   needed a strictly newer N-of-N-signed state EVERY round.
    //
    //   THE FIX (round 3, R3-3), and its honest limit. A permanent bar on
    //   re-submitting a cancelled burn is NOT available: a burn can only ever be
    //   submitted at its own state version (the descriptor must be the LAST push
    //   in the proof-bound settled-tx chain), so such a bar permanently strands an
    //   already-debited burn -- the R3-1 lock class in a new lane. Instead the
    //   re-submission is ADMITTED but carries a LONGER window: a cancel arms
    //   `cancelledPartialWithdrawalReviewUntil[burnKey] = now + 2*challengePeriod`,
    //   and a re-submission of that logical burn takes it as the floor on its deadline.
    //   Nothing is refused, nothing is stranded, and each attrition round is paid
    //   for in the ATTACKER's wall-clock instead of the DEFENDER's material.
    //
    //   It is a mitigation, not a block, and that is correct: authorizing a
    //   chain-bound burn is the RIGHT outcome. See the corrected claim in
    //   `cancelPartialWithdrawal` -- source channel/base nonce/recipient/token/amount are
    //   IMD2-pinned to the
    //   N-of-N-signed chain, an append-only entry is not un-committed by a later
    //   state, and an authorization pays nothing on its own (every payout needs a
    //   real withdrawal proof and a single-use proof-derived nullifier). The cancel
    //   lane is a LIVENESS aid against a griefer's wrong-nullifier submission, not
    //   a soundness gate. What made R3-3 dangerous was that the forced burn raised
    //   A3's mark and armed R3-1; R3-1's deduction removes that entirely.
    // ════════════════════════════════════════════════════════════════════════

    /// BLOCKED-IN-ROUND-2 (passes = the round-2 attrition no longer runs at round-2 speed). Body
    /// preserved VERBATIM through the setup; only the verdict changed.
    ///
    /// ACTORS: `eve` pushing a stale burn at v20, the honest members holding the head v30.
    ///
    /// ORDERING: eve submits the stale burn; the honest side cancels it with v30 (the ONLY material
    /// they have). Eve re-submits the byte-identical intent -- same `closeIntentDigest`, same
    /// `authDigest`. The honest cancel at v30 is still refused by A4's own mark. But the
    /// re-submission now inherits the review deadline the cancel armed, so eve does NOT get the burn
    /// authorized one challenge period later: the defender has `2 * challengePeriod` from the cancel
    /// to obtain newer material, and with it the veto lands.
    function test_R3_BREAK_A4_attritionForcesTheStaleBurnThrough() external {
        uint256 t0 = vm.getBlockTimestamp();

        // Round 1: eve's stale burn, vetoed by the honest head state.
        vm.prank(eve);
        _submitPw(9, 20);
        bytes32 pwDigest = manager.pendingPartialWithdrawalCloseIntentDigest();
        bytes32 burnKey = manager.pendingPartialWithdrawalBurnKey();

        ChannelSettlementManager.CancelCloseRequest memory veto = _cancelRequest(pwDigest, 30);
        manager.cancelPartialWithdrawal(veto, _cancelProof(veto));
        assertFalse(manager.partialWithdrawalPending(), "round 1: the stale burn is vetoed");
        assertEq(
            manager.cancelledPartialWithdrawalRevivedVersion(burnKey),
            30,
            "A4 consumed the DEFENDER's material"
        );
        // R3-3: and it armed the review window on the logical burn key.
        assertEq(
            manager.cancelledPartialWithdrawalReviewUntil(burnKey),
            t0 + 2 * CHALLENGE_PERIOD,
            "R3-3: the cancel arms a review deadline for this logical burn"
        );

        // Round 2: the identical intent, re-submitted for free.
        vm.prank(eve);
        _submitPw(9, 20);
        assertEq(manager.pendingPartialWithdrawalBurnKey(), burnKey, "logical burn key is stable");
        assertEq(
            manager.pendingPartialWithdrawalCloseIntentDigest(),
            pwDigest,
            "a burn is a historical fact: byte-identical digest"
        );
        // R3-3: it is ADMITTED (refusing it would strand an already-debited burn) but it inherits
        // the review deadline instead of the ordinary one-period window.
        assertEq(
            manager.pendingPartialWithdrawalDeadline(),
            t0 + 2 * CHALLENGE_PERIOD,
            "R3-3: the re-submission carries the extended window, not a fresh short one"
        );

        // The honest side still has nothing newer than v30 right now, and A4 still refuses.
        ChannelSettlementManager.CancelCloseRequest memory veto2 = _cancelRequest(pwDigest, 30);
        MleVerifier.MleProof memory veto2Proof = _cancelProof(veto2);
        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalCancelReplay.selector);
        manager.cancelPartialWithdrawal(veto2, veto2Proof);

        // Round 2's finalize at one challenge period -- the moment the attack used to win -- is now
        // refused: the window has not run out.
        vm.warp(t0 + CHALLENGE_PERIOD + 1);
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowOpen.selector);
        manager.finalizePartialWithdrawal();
        assertFalse(
            registry.partialWithdrawalAuthorized(_expectedAuthDigest()),
            "BLOCKED: the stale burn is NOT authorized on eve's schedule"
        );

        // The defender spends the extra window obtaining a strictly newer signed state (an ordinary
        // event in a live channel) and the veto lands.
        vm.warp(t0 + CHALLENGE_PERIOD + 2);
        ChannelSettlementManager.CancelCloseRequest memory veto3 = _cancelRequest(pwDigest, 31);
        manager.cancelPartialWithdrawal(veto3, _cancelProof(veto3));
        assertFalse(manager.partialWithdrawalPending(), "round 2: the veto lands after all");
        assertEq(manager.authorizedBurnStateVersion(), 0, "A3's mark was never raised");
    }

    /// CONTROL for BREAK 3: with A4's mark not yet set for this burn, the SAME veto succeeds, and
    /// the FIRST submission of a burn is never delayed -- the review floor is armed only by a cancel.
    function test_R3_BREAK_A4_control_theFirstVetoAlwaysWorks() external {
        uint256 t0 = vm.getBlockTimestamp();
        vm.prank(eve);
        _submitPw(9, 20);
        bytes32 pwDigest = manager.pendingPartialWithdrawalCloseIntentDigest();
        bytes32 burnKey = manager.pendingPartialWithdrawalBurnKey();
        assertEq(manager.cancelledPartialWithdrawalRevivedVersion(burnKey), 0, "mark unset");
        assertEq(
            manager.pendingPartialWithdrawalDeadline(),
            t0 + CHALLENGE_PERIOD,
            "R3-3 never delays a first submission"
        );
        ChannelSettlementManager.CancelCloseRequest memory veto = _cancelRequest(pwDigest, 30);
        manager.cancelPartialWithdrawal(veto, _cancelProof(veto));
        assertFalse(manager.partialWithdrawalPending(), "vetoed");
    }

    /// R3-3 must not become the strand it replaces. However long the attrition runs, the burn stays
    /// SUBMITTABLE and, absent a veto, AUTHORIZABLE: the review window only delays, it never refuses.
    /// This is the anti-lock pin for the R3-3 guard.
    function test_R3_FIXED_A4_reviewWindowDelaysButNeverStrands() external {
        uint256 t0 = vm.getBlockTimestamp();
        vm.prank(eve);
        _submitPw(9, 20);
        bytes32 pwDigest = manager.pendingPartialWithdrawalCloseIntentDigest();
        ChannelSettlementManager.CancelCloseRequest memory veto = _cancelRequest(pwDigest, 30);
        manager.cancelPartialWithdrawal(veto, _cancelProof(veto));

        // Re-submission is ADMITTED -- never refused, whatever the cancel history.
        vm.prank(eve);
        _submitPw(9, 20);
        assertTrue(manager.partialWithdrawalPending(), "the burn is re-submittable, not stranded");

        // Past the extended window, with no veto, it authorizes normally.
        vm.warp(t0 + 2 * CHALLENGE_PERIOD + 1);
        manager.finalizePartialWithdrawal();
        assertTrue(
            registry.partialWithdrawalAuthorized(_expectedAuthDigest()),
            "the burn's L1 authorization is delayed, never denied"
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
        MleVerifier.MleProof memory wrongProof = _cancelProof(_cancelRequest(d, 31));
        vm.expectRevert();
        manager.cancelClose(lie, wrongProof);
        assertEq(manager.highestCancelledRevivedStateVersion(), 0, "floor unmoved");
    }

    /// REFUTED (A1 holds). The A1 floor is genuinely read nowhere on a close/exit path: with the
    /// floor at 30 and the A3 mark unset, a v20 close still requests, submits and finalizes.
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

    /// REFUTED (A4 holds against replay). The attack A4 was written for is genuinely dead: one
    /// cancel proof cannot veto the same burn twice.
    function test_R3_REFUTED_A4_replayIsDead() external {
        _submitPw(9, 20);
        bytes32 pwDigest = manager.pendingPartialWithdrawalCloseIntentDigest();
        ChannelSettlementManager.CancelCloseRequest memory v = _cancelRequest(pwDigest, 30);
        manager.cancelPartialWithdrawal(v, _cancelProof(v));

        _submitPw(9, 20);
        MleVerifier.MleProof memory p = _cancelProof(v);
        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalCancelReplay.selector);
        manager.cancelPartialWithdrawal(v, p);
    }

    /// REFUTED (A3 holds in its own direction). A close at EXACTLY the burn's version is not
    /// refused -- the guard is strict, so an honest head-of-chain close still settles.
    function test_R3_REFUTED_A3_closeAtTheBurnVersionIsNotRefused() external {
        _submitPwAndElapse(9, 30);
        manager.finalizePartialWithdrawal();

        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory head = _intentAt(9, 30);
        manager.submitCloseIntent(head, _closeProof(head));
        vm.warp(vm.getBlockTimestamp() + CHALLENGE_PERIOD + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        assertEq(manager.finalizedStateVersion(), 30, "A3 is strict, not >=");
    }
}
