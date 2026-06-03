// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier
} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";

contract ChannelSettlementManagerTest is Test {
    ChannelSettlementVerifier internal verifier;
    ChannelSettlementManager internal manager;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");

    bytes5 internal constant CHANNEL_ID = hex"0003000009";
    bytes5 internal constant BP_KEY_ID = hex"000000000a";
    bytes10 internal constant USER_A = hex"0003000009000000000a";
    bytes10 internal constant USER_B = hex"0003000009000000000b";
    bytes10 internal constant USER_C = hex"0003000009000000000c";
    uint64 internal constant CHALLENGE_PERIOD = 1 days;
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 9;
    uint256 internal constant INITIAL_BP_BOND = 25;

    function setUp() external {
        verifier = new ChannelSettlementVerifier();

        ChannelSettlementManager.MemberBinding[] memory bindings =
            new ChannelSettlementManager.MemberBinding[](3);
        bindings[0] = ChannelSettlementManager.MemberBinding({userId: USER_A, recipient: alice});
        bindings[1] = ChannelSettlementManager.MemberBinding({userId: USER_B, recipient: bob});
        bindings[2] = ChannelSettlementManager.MemberBinding({userId: USER_C, recipient: carol});

        manager = new ChannelSettlementManager(
            CHANNEL_ID,
            BP_KEY_ID,
            CHALLENGE_PERIOD,
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)),
            bindings
        );
    }

    function _proofFor(bytes32 piHash) internal pure returns (bytes memory) {
        return abi.encode(piHash);
    }

    function _intent(
        uint64 closeNonce,
        uint64 finalEpoch,
        uint64 finalSmallBlockNumber,
        uint64 closeFreezeNonce
    ) internal pure returns (ChannelSettlementManager.CloseIntent memory intent) {
        intent = ChannelSettlementManager.CloseIntent({
            closeNonce: closeNonce,
            finalEpoch: finalEpoch,
            finalSmallBlockNumber: finalSmallBlockNumber,
            closeFreezeNonce: closeFreezeNonce,
            finalChannelStateDigest: keccak256("final_state"),
            finalChannelBalanceRoot: keccak256("channel_balance_root"),
            channelFundAmount: 75,
            channelFundIntmaxStateRoot: keccak256("intmax_root"),
            burnTxHash: keccak256("burn_tx"),
            closeWithdrawalDigest: keccak256("burn_backed_close"),
            snapshotMediumBlockNumber: 77
        });
    }

    function _withdrawalClaim(
        bytes32 closeIntentDigest,
        bytes10 userId,
        address recipient,
        uint64 amount
    ) internal pure returns (ChannelSettlementManager.WithdrawalClaim memory claim) {
        claim = ChannelSettlementManager.WithdrawalClaim({
            closeIntentDigest: closeIntentDigest,
            userId: userId,
            recipient: recipient,
            userAmountDigest: keccak256(abi.encodePacked(userId, amount)),
            amount: amount,
            withdrawalNullifier: keccak256(abi.encodePacked("withdraw", closeIntentDigest, userId))
        });
    }

    function test_hash_helpers_are_stable() external view {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        bytes32 closePiHash = verifier.closePIHash(
            CHANNEL_ID,
            intent.closeNonce,
            intent.finalEpoch,
            intent.finalSmallBlockNumber,
            intent.closeFreezeNonce,
            intent.finalChannelStateDigest,
            intent.finalChannelBalanceRoot,
            intent.channelFundAmount,
            intent.channelFundIntmaxStateRoot,
            intent.burnTxHash,
            intent.closeWithdrawalDigest,
            intent.snapshotMediumBlockNumber
        );
        assertTrue(closePiHash != bytes32(0));

        assertTrue(
            verifier.specialClosePIHash(
                CHANNEL_ID,
                BP_KEY_ID,
                keccak256("root"),
                33,
                10,
                15
            ) != bytes32(0)
        );

        assertTrue(
            verifier.withdrawalClaimPIHash(
                CHANNEL_ID,
                keccak256("close"),
                keccak256("root"),
                USER_A,
                alice,
                keccak256("amount"),
                9,
                keccak256("nullifier")
            ) != bytes32(0)
        );

        assertTrue(
            verifier.cancelPIHash(
                CHANNEL_ID,
                keccak256("close"),
                keccak256("small_block"),
                keccak256("revived"),
                keccak256("tx_hash"),
                keccak256("seal")
            ) != bytes32(0)
        );

        assertTrue(
            verifier.postCloseClaimPIHash(
                CHANNEL_ID,
                keccak256("close"),
                keccak256("incoming"),
                USER_B,
                bob,
                keccak256("receiver_amount"),
                keccak256("shared_nullifier"),
                9
            ) != bytes32(0)
        );
    }

    function test_submit_finalize_withdraw_and_post_close_claim() external {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        manager.submitCloseIntent(
            intent,
            _proofFor(
                verifier.closePIHash(
                    CHANNEL_ID,
                    intent.closeNonce,
                    intent.finalEpoch,
                    intent.finalSmallBlockNumber,
                    intent.closeFreezeNonce,
                    intent.finalChannelStateDigest,
                    intent.finalChannelBalanceRoot,
                    intent.channelFundAmount,
                    intent.channelFundIntmaxStateRoot,
                    intent.burnTxHash,
                    intent.closeWithdrawalDigest,
                    intent.snapshotMediumBlockNumber
                )
            )
        );

        assertEq(uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending));
        assertFalse(manager.isNativeSendAllowed(0));

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();

        assertEq(uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.Closed));
        bytes32 closeIntentDigest = manager.finalizedCloseIntentDigest();

        ChannelSettlementManager.WithdrawalClaim memory aliceClaim = _withdrawalClaim(
            closeIntentDigest,
            USER_A,
            alice,
            30
        );
        manager.submitWithdrawalClaim(
            aliceClaim,
            _proofFor(
                verifier.withdrawalClaimPIHash(
                    CHANNEL_ID,
                    closeIntentDigest,
                    manager.finalizedChannelBalanceRoot(),
                    USER_A,
                    alice,
                    aliceClaim.userAmountDigest,
                    aliceClaim.amount,
                    aliceClaim.withdrawalNullifier
                )
            )
        );

        ChannelSettlementManager.PostCloseClaim memory postCloseClaim = ChannelSettlementManager
            .PostCloseClaim({
                closeIntentDigest: closeIntentDigest,
                incomingTxHash: keccak256("incoming_tx"),
                receiverUserId: USER_B,
                recipient: bob,
                receiverAmountDigest: keccak256("receiver_amount"),
                sharedNativeNullifier: keccak256("shared_nullifier"),
                amount: 5
            });
        manager.submitPostCloseClaim(
            postCloseClaim,
            _proofFor(
                verifier.postCloseClaimPIHash(
                    CHANNEL_ID,
                    closeIntentDigest,
                    postCloseClaim.incomingTxHash,
                    USER_B,
                    bob,
                    postCloseClaim.receiverAmountDigest,
                    postCloseClaim.sharedNativeNullifier,
                    postCloseClaim.amount
                )
            )
        );

        assertEq(manager.withdrawalCredits(alice), 30);
        assertEq(manager.withdrawalCredits(bob), 5);
    }

    function test_special_close_slashes_bp_and_freezes_channel() external {
        ChannelSettlementManager.SpecialClose memory specialClose = ChannelSettlementManager
            .SpecialClose({
                offendingBpKeyId: BP_KEY_ID,
                fullySignedSmallBlockRoot: keccak256("small_block_root"),
                smallBlockNumber: 33,
                signedMediumBlockNumber: 10,
                latestFinalizedMediumBlockNumber: 15
            });

        manager.submitSpecialClose(
            specialClose,
            _proofFor(
                verifier.specialClosePIHash(
                    CHANNEL_ID,
                    BP_KEY_ID,
                    specialClose.fullySignedSmallBlockRoot,
                    specialClose.smallBlockNumber,
                    specialClose.signedMediumBlockNumber,
                    specialClose.latestFinalizedMediumBlockNumber
                )
            )
        );

        assertEq(uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending));
        assertEq(manager.currentCloseFreezeNonce(), 1);
        assertEq(manager.bpBondCredits(), INITIAL_BP_BOND - SPECIAL_CLOSE_PENALTY);
        assertEq(manager.withdrawalCredits(address(this)), SPECIAL_CLOSE_PENALTY);
    }

    function test_cancel_close_restores_active_channel() external {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        manager.submitCloseIntent(
            intent,
            _proofFor(
                verifier.closePIHash(
                    CHANNEL_ID,
                    intent.closeNonce,
                    intent.finalEpoch,
                    intent.finalSmallBlockNumber,
                    intent.closeFreezeNonce,
                    intent.finalChannelStateDigest,
                    intent.finalChannelBalanceRoot,
                    intent.channelFundAmount,
                    intent.channelFundIntmaxStateRoot,
                    intent.burnTxHash,
                    intent.closeWithdrawalDigest,
                    intent.snapshotMediumBlockNumber
                )
            )
        );

        bytes32 closeIntentDigest = manager.computeCloseIntentDigest(intent);
        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager
            .CancelCloseRequest({
                closeIntentDigest: closeIntentDigest,
                revivedSmallBlockRoot: keccak256("small_block"),
                revivedInterChannelTxDigest: keccak256("revived_tx"),
                revivedTxHash: keccak256("tx_hash"),
                revivedSeal: keccak256("seal")
            });

        manager.cancelClose(
            request,
            _proofFor(
                verifier.cancelPIHash(
                    CHANNEL_ID,
                    closeIntentDigest,
                    request.revivedSmallBlockRoot,
                    request.revivedInterChannelTxDigest,
                    request.revivedTxHash,
                    request.revivedSeal
                )
            )
        );

        assertEq(uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.Active));
        assertEq(manager.currentCloseFreezeNonce(), 1);
        assertTrue(manager.isNativeSendAllowed(1));
    }

    function test_late_outgoing_debit_correction_invalidates_pending_close() external {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        manager.submitCloseIntent(
            intent,
            _proofFor(
                verifier.closePIHash(
                    CHANNEL_ID,
                    intent.closeNonce,
                    intent.finalEpoch,
                    intent.finalSmallBlockNumber,
                    intent.closeFreezeNonce,
                    intent.finalChannelStateDigest,
                    intent.finalChannelBalanceRoot,
                    intent.channelFundAmount,
                    intent.channelFundIntmaxStateRoot,
                    intent.burnTxHash,
                    intent.closeWithdrawalDigest,
                    intent.snapshotMediumBlockNumber
                )
            )
        );

        bytes32 closeIntentDigest = manager.computeCloseIntentDigest(intent);
        ChannelSettlementManager.LateOutgoingDebitCorrection memory correction =
            ChannelSettlementManager.LateOutgoingDebitCorrection({
                closeIntentDigest: closeIntentDigest,
                sourceTxHash: keccak256("source_tx"),
                senderUserId: USER_C,
                senderAmountDigest: keccak256("sender_amount"),
                debitNullifier: keccak256("debit_nullifier"),
                amount: 7
            });

        manager.submitLateOutgoingDebitCorrection(
            correction,
            _proofFor(
                verifier.lateOutgoingDebitPIHash(
                    CHANNEL_ID,
                    closeIntentDigest,
                    correction.sourceTxHash,
                    USER_C,
                    correction.senderAmountDigest,
                    correction.debitNullifier,
                    correction.amount
                )
            )
        );

        assertEq(uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.Active));
        assertEq(manager.currentCloseFreezeNonce(), 1);
    }

    function test_special_close_then_submit_and_finalize_normal_close() external {
        ChannelSettlementManager.SpecialClose memory specialClose = ChannelSettlementManager
            .SpecialClose({
                offendingBpKeyId: BP_KEY_ID,
                fullySignedSmallBlockRoot: keccak256("small_block_root"),
                smallBlockNumber: 33,
                signedMediumBlockNumber: 10,
                latestFinalizedMediumBlockNumber: 15
            });
        manager.submitSpecialClose(
            specialClose,
            _proofFor(
                verifier.specialClosePIHash(
                    CHANNEL_ID,
                    BP_KEY_ID,
                    specialClose.fullySignedSmallBlockRoot,
                    specialClose.smallBlockNumber,
                    specialClose.signedMediumBlockNumber,
                    specialClose.latestFinalizedMediumBlockNumber
                )
            )
        );

        ChannelSettlementManager.CloseIntent memory intent = _intent(2, 10, 40, 1);
        manager.submitCloseIntent(
            intent,
            _proofFor(
                verifier.closePIHash(
                    CHANNEL_ID,
                    intent.closeNonce,
                    intent.finalEpoch,
                    intent.finalSmallBlockNumber,
                    intent.closeFreezeNonce,
                    intent.finalChannelStateDigest,
                    intent.finalChannelBalanceRoot,
                    intent.channelFundAmount,
                    intent.channelFundIntmaxStateRoot,
                    intent.burnTxHash,
                    intent.closeWithdrawalDigest,
                    intent.snapshotMediumBlockNumber
                )
            )
        );

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();
        assertEq(manager.finalizedEpoch(), 10);
        assertEq(manager.finalizedSmallBlockNumber(), 40);
        assertEq(manager.finalizedBurnTxHash(), intent.burnTxHash);
    }
}
