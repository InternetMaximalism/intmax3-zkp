// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CloseSettlementBase} from "./CloseSettlementBase.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";

/// @title ChannelSettlementLiveness — Category B (liveness) state-machine boundary pins.
/// @notice The two-step close (requestClose -> submitCloseIntent -> finalizeClose) deliberately makes
///         requestClose a MEMBER-only, ONE-WAY freeze, while submitCloseIntent / finalizeClose are
///         PERMISSIONLESS (proof-gated). These tests pin the resulting liveness properties so a
///         regression that (a) added an un-gated abort, (b) member-gated the progress functions
///         (re-introducing a censor-able close), or (c) broke the send-freeze, would be caught.
///
///         SECURITY framing: the only liveness risk surfaced here is the ACCEPTED two-step-close
///         boundary — once a member freezes, the channel is frozen until SOMEONE drives it to Closed
///         (or cancels it back with a newer-state proof). Crucially, ANY party holding a valid proof
///         can drive that progress, so a silent/malicious requester cannot strand the others' funds:
///         the honest members close it out themselves. The tests document both halves.
contract ChannelSettlementLivenessTest is CloseSettlementBase {
    // ── B7: send-freeze semantics ──

    /// While Active and the supplied freeze nonce matches, native sends are allowed.
    function test_B7_isNativeSendAllowed_true_when_active_matching_nonce() external view {
        // Fresh channel: status Active, currentCloseFreezeNonce == 0.
        assertTrue(manager.isNativeSendAllowed(0), "active + matching nonce => sends allowed");
    }

    /// A stale (mismatched) freeze nonce is rejected even while Active (replay guard).
    function test_B7_isNativeSendAllowed_false_on_nonce_mismatch() external view {
        assertFalse(manager.isNativeSendAllowed(1), "wrong freeze nonce => sends blocked");
    }

    /// requestClose freezes the channel: sends are blocked for EVERY nonce while ClosePending.
    function test_B7_freeze_blocks_sends_during_close_pending() external {
        vm.prank(alice);
        manager.requestClose();
        assertFalse(manager.isNativeSendAllowed(0), "frozen: old nonce blocked");
        assertFalse(manager.isNativeSendAllowed(1), "frozen: new nonce also blocked (status != Active)");
    }

    // ── B6: requestClose is member-only and one-way ──

    /// A non-member cannot freeze the channel (no freeze-grief from outsiders).
    function test_B6_requestClose_member_only() external {
        vm.prank(mallory);
        vm.expectRevert(ChannelSettlementManager.NotChannelMember.selector);
        manager.requestClose();
    }

    /// requestClose cannot be repeated to re-freeze / extend the grace window.
    function test_B6_double_requestClose_reverts() external {
        vm.prank(alice);
        manager.requestClose();
        vm.prank(bob);
        vm.expectRevert(ChannelSettlementManager.ChannelAlreadyFrozen.selector);
        manager.requestClose();
    }

    /// ONE-WAY FREEZE: after requestClose with no intent yet, there is NO path back to Active — cancel
    /// needs a pendingClose, which only exists once an intent is submitted. This pins that a freeze can
    /// only be resolved forward (close) or by a cancel proof against a submitted intent, never by a
    /// silent "undo". (A regression adding an un-gated abort would let a member toggle the freeze.)
    function test_B6_freeze_has_no_abort_without_pendingClose() external {
        vm.prank(alice);
        manager.requestClose();

        ChannelSettlementManager.CancelCloseRequest memory req = ChannelSettlementManager.CancelCloseRequest({
            closeIntentDigest: bytes32(uint256(1)),
            revivedStateVersion: 99,
            revivedChannelStateDigest: keccak256("revived")
        });
        // No pendingClose exists yet => cancelClose fails closed.
        MleVerifier.MleProof memory empty;
        vm.expectRevert(ChannelSettlementManager.CloseNotActive.selector);
        manager.cancelClose(req, empty);

        // Status is still ClosePending (frozen), not silently reverted to Active.
        assertEq(
            uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending),
            "channel remains frozen (one-way until close/cancel-with-proof)"
        );
    }

    // ── B6: progress functions are PERMISSIONLESS (liveness recovery) ──

    /// A non-member (or any relayer) holding a valid close proof can drive the frozen channel forward,
    /// so a silent/malicious requester cannot strand the channel: honest parties close it themselves.
    function test_B6_frozen_channel_is_progressable_by_anyone() external {
        // Member freezes, then goes silent.
        vm.prank(alice);
        manager.requestClose();
        vm.warp(block.timestamp + GRACE);

        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        MleVerifier.MleProof memory proof = _closeProof(intent); // build BEFORE prank (view calls)

        // A NON-MEMBER relays the valid intent — submitCloseIntent is proof-gated, not member-gated.
        vm.prank(mallory);
        manager.submitCloseIntent(intent, proof);

        // After the challenge window, ANYONE can finalize.
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        vm.prank(mallory);
        manager.finalizeClose();

        assertEq(
            uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.Closed),
            "frozen channel was driven to Closed by a non-member relayer (liveness recovery)"
        );
        assertTrue(manager.finalizedCloseIntentDigest() != bytes32(0), "close finalized");
    }

    /// submitCloseIntent before the grace window elapses fails closed (the requester cannot also
    /// instantly ram through a stale state — the grace lets honest members surface a newer one).
    function test_B6_submitCloseIntent_before_grace_reverts() external {
        vm.prank(alice);
        manager.requestClose();
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        MleVerifier.MleProof memory proof = _closeProof(intent);
        vm.expectRevert(ChannelSettlementManager.GracePeriodNotElapsed.selector);
        manager.submitCloseIntent(intent, proof);
    }
}
