// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier
} from "../src/ChannelSettlementManager.sol";

contract MockChannelSettlementVerifier is IChannelSettlementVerifier {
    bool public closeResult = true;
    bool public cancelResult = true;
    bool public postCloseClaimResult = true;

    function setResults(bool close_, bool cancel_, bool claim_) external {
        closeResult = close_;
        cancelResult = cancel_;
        postCloseClaimResult = claim_;
    }

    function verifyCloseIntent(
        uint256,
        uint64,
        uint64,
        bytes32,
        uint256,
        bytes32,
        bytes32,
        uint64,
        bytes calldata
    ) external view returns (bool) {
        return closeResult;
    }

    function verifyCancelClose(
        uint256,
        bytes32,
        bytes32,
        bytes32,
        bytes32,
        bytes calldata
    ) external view returns (bool) {
        return cancelResult;
    }

    function verifyPostCloseClaim(
        uint256,
        bytes32,
        bytes32,
        uint256,
        address,
        uint256,
        bytes32,
        bytes calldata
    ) external view returns (bool) {
        return postCloseClaimResult;
    }
}

contract ChannelSettlementManagerTest is Test {
    MockChannelSettlementVerifier internal verifier;
    ChannelSettlementManager internal manager;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    uint256 internal constant CHANNEL_ID = 0x000300000009;
    uint64 internal constant CHALLENGE_PERIOD = 1 days;

    function setUp() external {
        verifier = new MockChannelSettlementVerifier();
        manager = new ChannelSettlementManager(
            CHANNEL_ID,
            CHALLENGE_PERIOD,
            verifier
        );
    }

    function _withdrawals()
        internal
        view
        returns (ChannelSettlementManager.Withdrawal[] memory withdrawals)
    {
        withdrawals = new ChannelSettlementManager.Withdrawal[](2);
        withdrawals[0] = ChannelSettlementManager.Withdrawal({
            recipient: alice,
            amount: 50
        });
        withdrawals[1] = ChannelSettlementManager.Withdrawal({
            recipient: bob,
            amount: 25
        });
    }

    function _intent(
        uint64 closeNonce,
        uint64 finalEpoch
    ) internal view returns (ChannelSettlementManager.CloseIntent memory intent) {
        intent = ChannelSettlementManager.CloseIntent({
            closeNonce: closeNonce,
            finalEpoch: finalEpoch,
            finalChannelStateDigest: keccak256("final_state"),
            channelFundAmount: 75,
            channelFundIntmaxStateRoot: keccak256("intmax_root"),
            settlementDigest: manager.computeSettlementDigest(_withdrawals()),
            snapshotBlockNumber: 77
        });
    }

    function test_submit_and_finalize_close() external {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9);

        manager.submitCloseIntent(intent, hex"01");
        assertTrue(manager.getPendingClose().active);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose(_withdrawals());

        assertEq(manager.finalizedEpoch(), 9);
        assertEq(manager.finalizedChannelFundAmount(), 75);
        assertEq(manager.withdrawalCredits(alice), 50);
        assertEq(manager.withdrawalCredits(bob), 25);

        vm.prank(alice);
        uint256 claimed = manager.claimWithdrawalCredit();
        assertEq(claimed, 50);
        assertEq(manager.withdrawalCredits(alice), 0);
    }

    function test_newer_close_replaces_pending_close() external {
        manager.submitCloseIntent(_intent(1, 9), hex"01");
        bytes32 oldDigest = manager.getPendingClose().closeIntentDigest;

        ChannelSettlementManager.CloseIntent memory newer = _intent(2, 10);
        newer.finalChannelStateDigest = keccak256("newer_state");
        manager.submitCloseIntent(newer, hex"02");

        assertTrue(manager.getPendingClose().active);
        assertEq(manager.getPendingClose().finalEpoch, 10);
        assertTrue(manager.getPendingClose().closeIntentDigest != oldDigest);
    }

    function test_cancel_close_clears_pending_intent() external {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9);
        manager.submitCloseIntent(intent, hex"01");

        ChannelSettlementManager.CancelCloseRequest memory request =
            ChannelSettlementManager.CancelCloseRequest({
                closeIntentDigest: manager.computeCloseIntentDigest(intent),
                revivedInterChannelTxDigest: keccak256("revived_tx"),
                revivedTxHash: keccak256("tx_hash"),
                revivedSeal: keccak256("seal")
            });

        manager.cancelClose(request, hex"cafe");
        assertFalse(manager.getPendingClose().active);
    }

    function test_post_close_claim_credits_late_incoming_amount() external {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9);
        manager.submitCloseIntent(intent, hex"01");
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose(_withdrawals());

        ChannelSettlementManager.PostCloseClaim memory claim =
            ChannelSettlementManager.PostCloseClaim({
                closeIntentDigest: manager.computeCloseIntentDigest(intent),
                incomingTxHash: keccak256("late_tx"),
                receiverId: 0x00030000000c,
                recipient: alice,
                amount: 9,
                personalNullifier: keccak256("personal_nullifier")
            });

        manager.submitPostCloseClaim(claim, hex"beef");
        assertEq(manager.withdrawalCredits(alice), 59);

        vm.expectRevert(ChannelSettlementManager.NullifierAlreadyUsed.selector);
        manager.submitPostCloseClaim(claim, hex"beef");
    }
}
