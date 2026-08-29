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
        return CloseTestLib.proofWithLimbs(
            verifier.expectedCancelCloseLimbs(
                CHANNEL_ID,
                request.closeIntentDigest,
                manager.registeredMemberSetCommitment(),
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
    }

    function _baseRecipient(address recipient) internal pure returns (bytes32) {
        return bytes32((uint256(2) << 248) | uint256(uint160(recipient)));
    }

    function _burnDescriptor() internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(0x494d4244), TX_LEAF, _baseRecipient(alice), TOKEN_INDEX, PW_AMOUNT
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
            nullifier: PW_NULLIFIER,
            auxData: _burnDescriptor(),
            txLeaf: TX_LEAF
        });
    }

    function _expectedAuthDigest() internal view returns (bytes32) {
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        return keccak256(
            abi.encodePacked(
                bytes4(0x494d5057), w.nullifier, w.recipient, w.tokenIndex, w.amount, w.auxData
            )
        );
    }

    function _pwIntent(uint64 epoch, uint64 stateVersion)
        internal view returns (ChannelSettlementManager.CloseIntent memory intent)
    {
        intent = _intentAt(epoch, stateVersion);
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
    // BREAK 1 — A1 x A3: the C-3 permanent brick, reintroduced.  *** FIXED (R3-1) ***
    //
    //   THE ATTACK AS FOUND. A3's non-brick argument was "two permissionless
    //   remedies remain open ... challenge-replace it while the window is open,
    //   or `cancelClose` it, which has no window bound at all ... the material
    //   they need provably exists". A1's manager-lifetime floor CONSUMES exactly
    //   that material: once a cancel has been spent at version v, no later cancel
    //   at v is admissible EVER. Combined with an A3 refusal after the replacement
    //   window shut, every exit from `ClosePending` closed simultaneously.
    //
    //   THE FIX (round 3, R3-1). A3 no longer REFUSES the settlement; it ADJUSTS
    //   THE AMOUNT. `finalizeClose` settles and deducts the already-authorized
    //   burn from the per-token accrual cap, so the double-draw A3 exists to stop
    //   is still stopped while `finalizeClose` keeps NO version-dependent revert.
    //   `ClosePending` therefore always has a reachable exit and the four latches
    //   can no longer conjoin. `CloseOlderThanAuthorizedBurn` is gone.
    // ════════════════════════════════════════════════════════════════════════

    /// BLOCKED (passes = the attack no longer works). The body is preserved VERBATIM through the
    /// exact setup that used to wedge the channel; only the verdict changed.
    ///
    /// ACTORS: `alice` (any `isMemberRecipient` party). SUPPLY MODEL: the newest N-of-N-signed
    /// state in existence is v30, and v28 is an older signed state every member retains. No party
    /// can manufacture v31.
    ///
    /// ORDERING (unchanged):
    ///   1. a burn committed in the head state v30 is authorized while the channel is Active
    ///      -> `authorizedBurn{Epoch,StateVersion} = (9, 30)`  [A3's high-water mark]
    ///   2. a stale close at v28 is submitted and cancelled with the head v30
    ///      -> `highestCancelledRevivedStateVersion = 30`      [A1's floor, now AT the supply top]
    ///   3. the SAME stale close at v28 is submitted again and left to run out its window
    ///
    /// RESULT (round 3): the three OTHER latches are exactly as armed as when the attack landed --
    /// `cancelClose(v30)` still reverts `CancelCloseReplay`, `submitCloseIntent(v30)` still reverts
    /// `ChallengeWindowClosed`, `requestClose` still reverts `ChannelAlreadyFrozen` -- and it no
    /// longer matters, because `finalizeClose` SETTLES. The funds are distributable, and the burn
    /// is deducted from the cap so it cannot be drawn twice.
    function test_R3_BREAK_A1xA3_closePendingIsTerminal() external {
        // ── 1. the honest burn at the head state v30 is authorized (channel Active).
        _submitPwAndElapse(9, 30);
        manager.finalizePartialWithdrawal();
        assertEq(manager.authorizedBurnStateVersion(), 30, "A3 mark at the head");
        assertEq(manager.authorizedBurnAmount(TOKEN_INDEX), PW_AMOUNT, "R3-1 ledger accrued");

        // ── 2. a stale close at v28; the honest holder of v30 cancels it. This is the NORMAL,
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

        // ── 3. the identical stale close is submitted again and the window is allowed to expire.
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory stale2 = _intentAt(9, 28);
        manager.submitCloseIntent(stale2, _closeProof(stale2));
        bytes32 d2 = manager.computeCloseIntentDigest(stale2);
        uint64 horizon = manager.closeChallengeHorizon();
        vm.warp(uint256(horizon) + 1);

        // ── the three OTHER latches remain exactly as armed as when the attack landed. ──────
        // (b) A1 still refuses the cancel with the newest material that exists.
        ChannelSettlementManager.CancelCloseRequest memory rescue = _cancelRequest(d2, 30);
        MleVerifier.MleProof memory rescueProof = _cancelProof(rescue);
        vm.expectRevert(ChannelSettlementManager.CancelCloseReplay.selector);
        manager.cancelClose(rescue, rescueProof);

        // (c) the replacement lane is still shut past the horizon -- even with the head state.
        ChannelSettlementManager.CloseIntent memory head = _intentAt(9, 30);
        MleVerifier.MleProof memory headProof = _closeProof(head);
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowClosed.selector);
        manager.submitCloseIntent(head, headProof);

        // (d) no new era can be opened.
        vm.prank(alice);
        vm.expectRevert(ChannelSettlementManager.ChannelAlreadyFrozen.selector);
        manager.requestClose();

        // ── (a) THE EXIT. Round 2 reverted `CloseOlderThanAuthorizedBurn` here, and that is what
        //    made the state terminal. Round 3 settles.
        manager.finalizeClose();
        assertEq(
            uint8(manager.channelStatus()),
            uint8(ChannelSettlementManager.ChannelLifecycleStatus.Closed),
            "R3-1: ClosePending is NOT terminal; finalizeClose is always a reachable exit"
        );
        assertEq(manager.finalizedStateVersion(), 28, "the stale close settled");
        assertFalse(manager.getPendingClose().active, "pendingClose consumed");

        // ── and the double-draw A3 existed to stop is STILL stopped: the settled cap excludes
        //    the burn that was already authorized on L1.
        assertEq(
            manager.finalizedChannelFundAmount(TOKEN_INDEX),
            DEFAULT_FUND_AMOUNT - PW_AMOUNT,
            "R3-1: the authorized burn is deducted, not double-drawn"
        );
        assertEq(manager.authorizedBurnAmount(TOKEN_INDEX), 0, "ledger consumed exactly once");
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
        manager.finalizeClose();
        assertEq(
            manager.finalizedChannelFundAmount(TOKEN_INDEX),
            DEFAULT_FUND_AMOUNT,
            "no burn authorized => no deduction"
        );
    }

    /// CONTROL for BREAK 1, isolating A1 as the guard that removed the last exit. Identical facts,
    /// except step 2's cancel is omitted so the A1 floor is never raised.
    ///
    /// ROUND 3: the premise this control established -- "the A3 refusal IS a deferral because
    /// `cancelClose` at v30 rescues the channel" -- no longer has to carry any weight, because
    /// there is no refusal to defer. `finalizeClose` settles directly, and `cancelClose` is a
    /// SECOND exit rather than the only one.
    function test_R3_BREAK_A1xA3_control_withoutTheSpentFloorTheCancelRescues() external {
        _submitPwAndElapse(9, 30);
        manager.finalizePartialWithdrawal();

        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory stale = _intentAt(9, 28);
        manager.submitCloseIntent(stale, _closeProof(stale));
        bytes32 d = manager.computeCloseIntentDigest(stale);
        vm.warp(uint256(manager.closeChallengeHorizon()) + 1);

        assertEq(manager.highestCancelledRevivedStateVersion(), 0, "floor unspent");
        manager.cancelClose(_cancelRequest(d, 30), _cancelProof(_cancelRequest(d, 30)));
        assertEq(
            uint8(manager.channelStatus()),
            uint8(ChannelSettlementManager.ChannelLifecycleStatus.Active),
            "the very same call rescues when the floor is unspent"
        );
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
        manager.finalizeClose();
        assertEq(manager.finalizedStateVersion(), 28, "settles; the A1 floor alone is inert");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // BREAK 2 — A2: `MIN_CLOSE_RESPONSE_SECS` is a blackout, not a response window.
    //
    //   A2's stated property is "every admitted rung leaves a usable response
    //   interval". The intended response to a rung IS a replacement close intent
    //   -- and A2 is precisely the rule that refuses replacements in the final
    //   `MIN_CLOSE_RESPONSE_SECS` before the horizon. So the guard closes the
    //   very lane it claims to keep open, and it does so for a FULL HOUR rather
    //   than for the zero seconds the pre-A2 defect cost.
    // ═════════════════════════════════════════════════════════════════════════

    /// EXPLOIT (passes = attack works). ACTORS: `eve` (a griefer holding v11; every close intent is
    /// permissionless once an era is open) and the honest holder of v12.
    ///
    /// ORDERING: era opened at T0 (horizon = T0 + 2*CHALLENGE_PERIOD). Eve lands a rung at v11 just
    /// before the first deadline, pushing `challengeDeadline` to `horizon - 1`. The honest party
    /// surfaces v12 at `horizon - 3599` -- INSIDE the deadline Eve's own rung created.
    ///
    /// RESULT: the honest replacement is refused with `ChallengeWindowClosed` by A2, and Eve's v11
    /// settles. WITHOUT A2 the very same transaction is admitted (asserted below by re-running the
    /// clock to `horizon - 3601`, the last instant A2 tolerates). A2 therefore converted the final
    /// 3,600 s of every era from "replacements admitted" into "replacements refused" -- a NEW
    /// denial 3,600 s wide, in exchange for closing a 0 s one.
    function test_R3_BREAK_A2_finalHourIsAReplacementBlackout() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory rung0 = _intentAt(9, 10);
        manager.submitCloseIntent(rung0, _closeProof(rung0));
        uint64 horizon = manager.closeChallengeHorizon();

        // Eve's rung, landing one second before the first deadline: the new deadline clamps to
        // `horizon - 1`, so by the pre-A2 rule the lane stays open until `horizon - 1`.
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
        MleVerifier.MleProof memory honestProof = _closeProof(honest);
        // ...and A2 refuses it.
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowClosed.selector);
        manager.submitCloseIntent(honest, honestProof);

        // Eve's stale v11 settles unopposed.
        vm.warp(uint256(horizon) + 1);
        manager.finalizeClose();
        assertEq(manager.finalizedStateVersion(), 11, "the griefer's state settled, not v12");
    }

    /// The same transaction, two seconds earlier on the clock, is ADMITTED. This pins that the
    /// refusal above is A2's `block.timestamp + minResponse > closeChallengeHorizon` rule and
    /// nothing else, and measures the blackout at exactly MIN_CLOSE_RESPONSE_SECS.
    function test_R3_BREAK_A2_blackoutWidthIsExactlyMinCloseResponseSecs() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory rung0 = _intentAt(9, 10);
        manager.submitCloseIntent(rung0, _closeProof(rung0));
        uint64 horizon = manager.closeChallengeHorizon();

        vm.warp(uint256(manager.getPendingClose().challengeDeadline) - 1);
        ChannelSettlementManager.CloseIntent memory rung1 = _intentAt(9, 11);
        vm.prank(eve);
        manager.submitCloseIntent(rung1, _closeProof(rung1));

        // The last instant A2 tolerates: horizon - MIN_CLOSE_RESPONSE_SECS.
        uint64 minResp = manager.MIN_CLOSE_RESPONSE_SECS();
        assertEq(minResp, 3600, "MIN_CLOSE_RESPONSE_SECS");
        vm.warp(uint256(horizon) - minResp);
        ChannelSettlementManager.CloseIntent memory honest = _intentAt(9, 12);
        manager.submitCloseIntent(honest, _closeProof(honest));
        assertEq(manager.getPendingClose().finalStateVersion, 12, "admitted one second earlier");

        // ...and the deadline it earns is the horizon, i.e. an interval in which NO further
        // replacement is admissible. The "usable response interval" A2 claims to restore does not
        // exist for the lane that matters.
        assertEq(manager.getPendingClose().challengeDeadline, horizon, "deadline == horizon");
        vm.warp(vm.getBlockTimestamp() + 1);
        ChannelSettlementManager.CloseIntent memory reply = _intentAt(9, 13);
        MleVerifier.MleProof memory replyProof = _closeProof(reply);
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowClosed.selector);
        manager.submitCloseIntent(reply, replyProof);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // BREAK 3 — A4: the per-burn mark disarms the DEFENDER, not the attacker.
    //
    //   Before A4, `cancelPartialWithdrawal` compared only against the PENDING
    //   record, so an honest member could replay ONE cancel proof against every
    //   re-submission of the same stale burn. A4 removed exactly that replay --
    //   while re-submitting the burn intent stayed free (the single-use chainKey
    //   guard was deliberately deleted). The attrition is therefore inverted:
    //   the attacker needs no new material, the defender needs a strictly newer
    //   N-of-N-signed state EVERY round.
    // ═════════════════════════════════════════════════════════════════════════

    /// EXPLOIT (passes = attack works). ACTORS: `eve` pushing a stale burn intent at v20 (the burn
    /// itself is a historical fact she holds), the honest members holding the head v30.
    ///
    /// ORDERING: eve submits the stale burn; the honest side cancels it with v30 (the ONLY material
    /// they have). Eve re-submits the byte-identical intent -- same `closeIntentDigest`. The honest
    /// cancel at v30 is now refused by A4's own mark, and the stale burn is authorized on the
    /// deadline.
    ///
    /// RESULT: two transactions from eve beat the defence outright. A4's comment says of this lane
    /// "losing it means a stale burn is authorized" and calls that the reason the burn lane may not
    /// have A1's global floor -- but the per-burn floor produces the same outcome after one round.
    function test_R3_BREAK_A4_attritionForcesTheStaleBurnThrough() external {
        // Round 1: eve's stale burn, vetoed by the honest head state.
        vm.prank(eve);
        _submitPw(9, 20);
        bytes32 pwDigest = manager.pendingPartialWithdrawalCloseIntentDigest();

        ChannelSettlementManager.CancelCloseRequest memory veto = _cancelRequest(pwDigest, 30);
        manager.cancelPartialWithdrawal(veto, _cancelProof(veto));
        assertFalse(manager.partialWithdrawalPending(), "round 1: the stale burn is vetoed");
        assertEq(
            manager.cancelledPartialWithdrawalRevivedVersion(pwDigest),
            30,
            "A4 consumed the DEFENDER's material"
        );

        // Round 2: the identical intent, re-submitted for free.
        vm.prank(eve);
        _submitPw(9, 20);
        assertEq(
            manager.pendingPartialWithdrawalCloseIntentDigest(),
            pwDigest,
            "a burn is a historical fact: byte-identical digest"
        );

        // The honest side has nothing newer than v30. A4 refuses the only veto available.
        ChannelSettlementManager.CancelCloseRequest memory veto2 = _cancelRequest(pwDigest, 30);
        MleVerifier.MleProof memory veto2Proof = _cancelProof(veto2);
        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalCancelReplay.selector);
        manager.cancelPartialWithdrawal(veto2, veto2Proof);

        // The stale burn is authorized on the rollup.
        vm.warp(vm.getBlockTimestamp() + CHALLENGE_PERIOD + 1);
        manager.finalizePartialWithdrawal();
        assertTrue(
            registry.partialWithdrawalAuthorized(_expectedAuthDigest()),
            "the stale burn eve could not push in round 1 is authorized in round 2"
        );
        // ...and it moved A3's high-water mark with it, arming BREAK 1.
        assertEq(manager.authorizedBurnStateVersion(), 20, "A3 mark raised by the forced burn");
    }

    /// CONTROL for BREAK 3: with A4's mark not yet set for this burn, the SAME veto succeeds. The
    /// only difference between the two rounds above is the mark A4 introduced.
    function test_R3_BREAK_A4_control_theFirstVetoAlwaysWorks() external {
        vm.prank(eve);
        _submitPw(9, 20);
        bytes32 pwDigest = manager.pendingPartialWithdrawalCloseIntentDigest();
        assertEq(manager.cancelledPartialWithdrawalRevivedVersion(pwDigest), 0, "mark unset");
        ChannelSettlementManager.CancelCloseRequest memory veto = _cancelRequest(pwDigest, 30);
        manager.cancelPartialWithdrawal(veto, _cancelProof(veto));
        assertFalse(manager.partialWithdrawalPending(), "vetoed");
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
        manager.finalizeClose();
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
        manager.finalizeClose();
        assertEq(manager.finalizedStateVersion(), 30, "A3 is strict, not >=");
    }
}
