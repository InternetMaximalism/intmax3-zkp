// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier
} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";

contract ChannelSettlementManagerTest is Test {
    // Redeclared for vm.expectEmit.
    event CloseRequested(
        address indexed requester,
        uint64 closeRequestedAt,
        uint64 closeFreezeNonce
    );

    ChannelSettlementVerifier internal verifier;
    ChannelSettlementManager internal manager;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    address internal mallory = makeAddr("mallory");

    bytes4 internal constant CHANNEL_ID = hex"00000009";
    bytes4 internal constant BP_KEY_ID = hex"0000000a";
    bytes8 internal constant USER_A = hex"000000090000000a";
    bytes8 internal constant USER_B = hex"000000090000000b";
    bytes8 internal constant USER_C = hex"000000090000000c";
    uint64 internal constant CHALLENGE_PERIOD = 1 days;
    uint64 internal constant GRACE = 600;
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 9;
    uint256 internal constant INITIAL_BP_BOND = 25;

    // Shared Rust<->Solidity CloseIntent digest test vector. The same fully-populated intent is
    // hashed by `CloseIntent::signing_digest()` in src/common/channel.rs
    // (close_intent_digest_matches_solidity_shared_vector) and MUST produce this constant.
    bytes32 internal constant SHARED_VECTOR_DIGEST =
        0xa2679bf7c2d9c08c45b6fdd39202456707cbdcf3e1667a45fb493a717b37d264;

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
        intent = _intentWithVersion(
            closeNonce,
            finalEpoch,
            finalSmallBlockNumber,
            closeFreezeNonce,
            12
        );
    }

    function _intentWithVersion(
        uint64 closeNonce,
        uint64 finalEpoch,
        uint64 finalSmallBlockNumber,
        uint64 closeFreezeNonce,
        uint64 finalStateVersion
    ) internal pure returns (ChannelSettlementManager.CloseIntent memory intent) {
        intent = ChannelSettlementManager.CloseIntent({
            closeNonce: closeNonce,
            finalEpoch: finalEpoch,
            finalSmallBlockNumber: finalSmallBlockNumber,
            closeFreezeNonce: closeFreezeNonce,
            finalChannelStateDigest: keccak256("final_state"),
            finalBalanceStateH1: keccak256("balance_state_h1"),
            channelFundAmount: 75,
            channelFundIntmaxStateRoot: keccak256("intmax_root"),
            burnTxHash: keccak256("burn_tx"),
            closeWithdrawalDigest: keccak256("burn_backed_close"),
            snapshotMediumBlockNumber: 77,
            finalStateVersion: finalStateVersion,
            finalSettledTxChain: keccak256("settled_tx_chain")
        });
    }

    function _closeProof(
        ChannelSettlementManager.CloseIntent memory intent
    ) internal view returns (bytes memory) {
        return _proofFor(
            verifier.closePIHash(
                CHANNEL_ID,
                intent.closeNonce,
                intent.finalEpoch,
                intent.finalSmallBlockNumber,
                intent.closeFreezeNonce,
                intent.finalChannelStateDigest,
                intent.finalBalanceStateH1,
                intent.channelFundAmount,
                intent.channelFundIntmaxStateRoot,
                intent.burnTxHash,
                intent.closeWithdrawalDigest,
                intent.snapshotMediumBlockNumber,
                intent.finalStateVersion,
                intent.finalSettledTxChain
            )
        );
    }

    function _submitClose(ChannelSettlementManager.CloseIntent memory intent) internal {
        manager.submitCloseIntent(intent, _closeProof(intent));
    }

    /// Two-step close preamble: a member freezes the channel and the grace window elapses.
    function _requestCloseAndElapseGrace() internal {
        vm.prank(alice);
        manager.requestClose();
        vm.warp(block.timestamp + GRACE);
    }

    function _withdrawalClaim(
        bytes32 closeIntentDigest,
        bytes8 userId,
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
            intent.finalBalanceStateH1,
            intent.channelFundAmount,
            intent.channelFundIntmaxStateRoot,
            intent.burnTxHash,
            intent.closeWithdrawalDigest,
            intent.snapshotMediumBlockNumber,
            intent.finalStateVersion,
            intent.finalSettledTxChain
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
                keccak256("shared_nullifier"),
                9
            ) != bytes32(0)
        );
    }

    /// Shared Rust<->Solidity test vector: `computeCloseIntentDigest` must be byte-identical to
    /// Rust `CloseIntent::signing_digest()` (IMCI). The Rust side asserts the same constant in
    /// src/common/channel.rs::close_intent_digest_matches_solidity_shared_vector. The intent's
    /// channel id slots (header + channel_fund_snapshot) are this manager's CHANNEL_ID (9).
    function test_close_intent_digest_matches_rust_shared_vector() external view {
        ChannelSettlementManager.CloseIntent memory intent = ChannelSettlementManager.CloseIntent({
            closeNonce: 0x1111111122222222,
            finalEpoch: 0x3333333344444444,
            finalSmallBlockNumber: 0x5555555566666666,
            closeFreezeNonce: 0x7777777788888888,
            finalChannelStateDigest: 0x0000000100000002000000030000000400000005000000060000000700000008,
            finalBalanceStateH1: 0x000000090000000a0000000b0000000c0000000d0000000e0000000f00000010,
            channelFundAmount: 0x0000001100000012000000130000001400000015000000160000001700000018,
            channelFundIntmaxStateRoot: 0x000000190000001a0000001b0000001c0000001d0000001e0000001f00000020,
            burnTxHash: 0x0000002100000022000000230000002400000025000000260000002700000028,
            closeWithdrawalDigest: 0x000000290000002a0000002b0000002c0000002d0000002e0000002f00000030,
            snapshotMediumBlockNumber: 0x99999999aaaaaaaa,
            finalStateVersion: 0xbbbbbbbbcccccccc,
            finalSettledTxChain: 0x0000003100000032000000330000003400000035000000360000003700000038
        });
        assertEq(manager.computeCloseIntentDigest(intent), SHARED_VECTOR_DIGEST);
    }

    function test_request_close_freezes_channel_and_emits() external {
        assertTrue(manager.isNativeSendAllowed(0));

        vm.expectEmit(true, false, false, true);
        emit CloseRequested(alice, uint64(block.timestamp), 1);
        vm.prank(alice);
        manager.requestClose();

        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
        );
        assertEq(manager.closeRequestedAt(), uint64(block.timestamp));
        assertEq(manager.currentCloseFreezeNonce(), 1);
        // The freeze halts native sends for every nonce.
        assertFalse(manager.isNativeSendAllowed(0));
        assertFalse(manager.isNativeSendAllowed(1));
    }

    function test_request_close_reverts_for_non_member() external {
        vm.prank(mallory);
        vm.expectRevert(ChannelSettlementManager.NotChannelMember.selector);
        manager.requestClose();
    }

    function test_request_close_reverts_when_already_pending() external {
        vm.prank(alice);
        manager.requestClose();

        vm.prank(bob);
        vm.expectRevert(ChannelSettlementManager.ChannelAlreadyFrozen.selector);
        manager.requestClose();
    }

    function test_request_close_reverts_when_closed() external {
        _requestCloseAndElapseGrace();
        _submitClose(_intent(1, 9, 22, 1));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();

        vm.prank(alice);
        vm.expectRevert(ChannelSettlementManager.ChannelClosed.selector);
        manager.requestClose();
    }

    function test_submit_close_intent_reverts_from_active_without_request() external {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        bytes memory proof = _closeProof(intent);
        vm.expectRevert(ChannelSettlementManager.CloseNotRequested.selector);
        manager.submitCloseIntent(intent, proof);
    }

    function test_submit_close_intent_grace_period_boundary() external {
        vm.prank(alice);
        manager.requestClose();
        uint256 requestedAt = block.timestamp;

        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        bytes memory proof = _closeProof(intent);

        // At +599s the grace window has not elapsed.
        vm.warp(requestedAt + GRACE - 1);
        vm.expectRevert(ChannelSettlementManager.GracePeriodNotElapsed.selector);
        manager.submitCloseIntent(intent, proof);

        // At exactly +600s it has.
        vm.warp(requestedAt + GRACE);
        manager.submitCloseIntent(intent, proof);
        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
        );
    }

    function test_challenge_replacement_uses_epoch_then_state_version() external {
        _requestCloseAndElapseGrace();
        _submitClose(_intentWithVersion(1, 9, 22, 1, 5));

        // Challenge path needs no fresh grace: the replacement lands in the same block as the
        // first intent.
        _submitClose(_intentWithVersion(2, 9, 23, 1, 6));
        ChannelSettlementManager.PendingClose memory pending = manager.getPendingClose();
        assertEq(pending.finalStateVersion, 6);

        // Same epoch, lower version: rejected.
        ChannelSettlementManager.CloseIntent memory lower = _intentWithVersion(3, 9, 24, 1, 5);
        bytes memory lowerProof = _closeProof(lower);
        vm.expectRevert(ChannelSettlementManager.CloseNotNewer.selector);
        manager.submitCloseIntent(lower, lowerProof);

        // Same epoch, equal version: rejected (strict tiebreak).
        ChannelSettlementManager.CloseIntent memory equalVersion =
            _intentWithVersion(3, 9, 24, 1, 6);
        bytes memory equalProof = _closeProof(equalVersion);
        vm.expectRevert(ChannelSettlementManager.CloseNotNewer.selector);
        manager.submitCloseIntent(equalVersion, equalProof);

        // Higher epoch wins even with a lower state version.
        _submitClose(_intentWithVersion(4, 10, 25, 1, 2));
        pending = manager.getPendingClose();
        assertEq(pending.finalEpoch, 10);
        assertEq(pending.finalStateVersion, 2);
    }

    function test_tampered_version_or_chain_fails_close_proof() external {
        _requestCloseAndElapseGrace();

        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        bytes memory proof = _closeProof(intent);
        bytes32 originalChain = intent.finalSettledTxChain;
        uint64 originalVersion = intent.finalStateVersion;

        // Tampering with finalSettledTxChain after the proof was computed must fail.
        intent.finalSettledTxChain = keccak256("forged_chain");
        vm.expectRevert(ChannelSettlementManager.InvalidCloseProof.selector);
        manager.submitCloseIntent(intent, proof);
        intent.finalSettledTxChain = originalChain;

        // Tampering with finalStateVersion must fail too.
        intent.finalStateVersion = originalVersion + 1;
        vm.expectRevert(ChannelSettlementManager.InvalidCloseProof.selector);
        manager.submitCloseIntent(intent, proof);
        intent.finalStateVersion = originalVersion;

        // The untampered intent still goes through.
        manager.submitCloseIntent(intent, proof);
    }

    function test_finalize_records_version_chain_and_h1() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intentWithVersion(1, 9, 22, 1, 41);
        _submitClose(intent);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();

        assertEq(manager.finalizedStateVersion(), 41);
        assertEq(manager.finalizedSettledTxChain(), intent.finalSettledTxChain);
        assertEq(manager.finalizedBalanceStateH1(), intent.finalBalanceStateH1);
        assertEq(manager.closeRequestedAt(), 0);
    }

    function test_cancel_then_reclose_requires_fresh_request_and_grace() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        _submitClose(intent);

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
        assertEq(manager.closeRequestedAt(), 0);

        // Re-closing straight away is barred: the channel is Active again.
        ChannelSettlementManager.CloseIntent memory reclose = _intent(2, 10, 30, 2);
        bytes memory recloseProof = _closeProof(reclose);
        vm.expectRevert(ChannelSettlementManager.CloseNotRequested.selector);
        manager.submitCloseIntent(reclose, recloseProof);

        // A fresh requestClose starts a fresh grace window.
        vm.prank(bob);
        manager.requestClose();
        assertEq(manager.currentCloseFreezeNonce(), 2);
        vm.expectRevert(ChannelSettlementManager.GracePeriodNotElapsed.selector);
        manager.submitCloseIntent(reclose, recloseProof);

        vm.warp(block.timestamp + GRACE);
        manager.submitCloseIntent(reclose, recloseProof);
        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
        );
    }

    function test_submit_finalize_withdraw_and_post_close_claim() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        _submitClose(intent);

        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
        );
        assertFalse(manager.isNativeSendAllowed(0));

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();

        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.Closed)
        );
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
                    manager.finalizedBalanceStateH1(),
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

        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
        );
        assertEq(manager.currentCloseFreezeNonce(), 1);
        assertEq(manager.closeRequestedAt(), uint64(block.timestamp));
        assertEq(manager.bpBondCredits(), INITIAL_BP_BOND - SPECIAL_CLOSE_PENALTY);
        assertEq(manager.withdrawalCredits(address(this)), SPECIAL_CLOSE_PENALTY);
    }

    function test_cancel_close_restores_active_channel() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        _submitClose(intent);

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

        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.Active)
        );
        assertEq(manager.currentCloseFreezeNonce(), 1);
        assertEq(manager.closeRequestedAt(), 0);
        assertTrue(manager.isNativeSendAllowed(1));
    }

    function test_late_outgoing_debit_correction_invalidates_pending_close() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        _submitClose(intent);

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

        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.Active)
        );
        assertEq(manager.currentCloseFreezeNonce(), 1);
        assertEq(manager.closeRequestedAt(), 0);
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
        bytes memory proof = _closeProof(intent);

        // A special close is a freeze request: the first intent obeys the same grace window.
        vm.expectRevert(ChannelSettlementManager.GracePeriodNotElapsed.selector);
        manager.submitCloseIntent(intent, proof);

        vm.warp(block.timestamp + GRACE);
        manager.submitCloseIntent(intent, proof);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();
        assertEq(manager.finalizedEpoch(), 10);
        assertEq(manager.finalizedSmallBlockNumber(), 40);
        assertEq(manager.finalizedBurnTxHash(), intent.burnTxHash);
    }
}
