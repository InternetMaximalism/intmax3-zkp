// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    ChannelSettlementManager
} from "../src/ChannelSettlementManager.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";

contract ChannelSettlementManagerTest is Test {
    ChannelSettlementVerifier internal realVerifier;
    ChannelSettlementManager internal manager;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    uint64 internal constant CHANNEL_ID = 0x000300000009;
    uint64 internal constant CHALLENGE_PERIOD = 1 days;
    uint256 internal constant BN254_FIELD_P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant BN254_SCALAR_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() external {
        realVerifier = new ChannelSettlementVerifier();

        ChannelSettlementManager.MemberBinding[]
            memory bindings = new ChannelSettlementManager.MemberBinding[](2);
        bindings[0] = ChannelSettlementManager.MemberBinding({
            memberId: 0x00030000000A,
            recipient: alice
        });
        bindings[1] = ChannelSettlementManager.MemberBinding({
            memberId: 0x00030000000B,
            recipient: bob
        });
        manager = new ChannelSettlementManager(
            CHANNEL_ID,
            CHALLENGE_PERIOD,
            realVerifier,
            bindings
        );
    }

    function _g2Gen() internal pure returns (uint256[2][2] memory) {
        return [
            [uint256(0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed),
             uint256(0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2)],
            [uint256(0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa),
             uint256(0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b)]
        ];
    }

    function _groth16ProofFor(uint256[] memory inputs)
        internal
        view
        returns (Groth16Verifier.Proof memory proof)
    {
        uint256 scalar = 1;
        for (uint256 i = 0; i < inputs.length; i++) {
            scalar = addmod(scalar, inputs[i], BN254_SCALAR_R);
        }

        uint256[3] memory mulInput;
        mulInput[0] = 1;
        mulInput[1] = 2;
        mulInput[2] = scalar;

        uint256[2] memory vkX;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x07, mulInput, 0x60, vkX, 0x40)
        }
        require(ok, "ecMul failed");

        proof.a = [uint256(1), uint256(2)];
        proof.b = _g2Gen();
        proof.c = [vkX[0], BN254_FIELD_P - vkX[1]];
    }

    function _proofBytesForPIHash(bytes32 piHash) internal view returns (bytes memory) {
        uint256[] memory inputs = new uint256[](8);
        uint256[8] memory fixedInputs;
        uint256 h = uint256(piHash);
        for (uint256 i = 0; i < 8; i++) {
            uint256 limb = (h >> (224 - i * 32)) & 0xFFFFFFFF;
            inputs[i] = limb;
            fixedInputs[i] = limb;
        }

        Groth16Verifier.Proof memory proof = _groth16ProofFor(inputs);
        return abi.encode(proof.a, proof.b, proof.c, fixedInputs);
    }

    function _withdrawals()
        internal
        view
        returns (ChannelSettlementManager.SettledWithdrawal[] memory withdrawals)
    {
        withdrawals = new ChannelSettlementManager.SettledWithdrawal[](2);
        withdrawals[0] = ChannelSettlementManager.SettledWithdrawal({
            memberId: 0x00030000000A,
            recipient: alice,
            userAmountDigest: keccak256("alice_amount"),
            amount: 50
        });
        withdrawals[1] = ChannelSettlementManager.SettledWithdrawal({
            memberId: 0x00030000000B,
            recipient: bob,
            userAmountDigest: keccak256("bob_amount"),
            amount: 25
        });
    }

    function _intent(
        uint64 closeNonce,
        uint64 finalEpoch
    ) internal view returns (ChannelSettlementManager.CloseIntent memory intent) {
        bytes32 finalChannelStateDigest = keccak256("final_state");
        bytes32 intmaxRoot = keccak256("intmax_root");
        intent = ChannelSettlementManager.CloseIntent({
            closeNonce: closeNonce,
            finalEpoch: finalEpoch,
            finalChannelStateDigest: finalChannelStateDigest,
            channelFundAmount: 75,
            channelFundIntmaxStateRoot: intmaxRoot,
            settlementDigest: manager.computeSettlementDigest(
                finalChannelStateDigest,
                intmaxRoot,
                _withdrawals()
            ),
            snapshotBlockNumber: 77
        });
    }

    function test_real_verifier_hash_helpers_are_stable() external view {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9);
        bytes32 closePiHash = realVerifier.closePIHash(
            CHANNEL_ID,
            intent.closeNonce,
            intent.finalEpoch,
            intent.finalChannelStateDigest,
            intent.channelFundAmount,
            intent.channelFundIntmaxStateRoot,
            intent.settlementDigest,
            intent.snapshotBlockNumber
        );
        assertTrue(closePiHash != bytes32(0));

        bytes32 cancelPiHash = realVerifier.cancelPIHash(
            CHANNEL_ID,
            keccak256("close"),
            keccak256("revived"),
            keccak256("tx_hash"),
            keccak256("seal")
        );
        assertTrue(cancelPiHash != bytes32(0));

        bytes32 claimPiHash = realVerifier.postCloseClaimPIHash(
            CHANNEL_ID,
            keccak256("close"),
            keccak256("incoming"),
            0x00030000000A,
            alice,
            9,
            keccak256("nullifier")
        );
        assertTrue(claimPiHash != bytes32(0));
    }

    function test_real_verifier_accepts_synthetic_proofs() external {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9);
        bytes32 closePiHash = realVerifier.closePIHash(
            CHANNEL_ID,
            intent.closeNonce,
            intent.finalEpoch,
            intent.finalChannelStateDigest,
            intent.channelFundAmount,
            intent.channelFundIntmaxStateRoot,
            intent.settlementDigest,
            intent.snapshotBlockNumber
        );
        assertTrue(
            realVerifier.verifyCloseIntent(
                CHANNEL_ID,
                intent.closeNonce,
                intent.finalEpoch,
                intent.finalChannelStateDigest,
                intent.channelFundAmount,
                intent.channelFundIntmaxStateRoot,
                intent.settlementDigest,
                intent.snapshotBlockNumber,
                _proofBytesForPIHash(closePiHash)
            )
        );

        bytes32 cancelPiHash = realVerifier.cancelPIHash(
            CHANNEL_ID,
            keccak256("close"),
            keccak256("revived"),
            keccak256("tx_hash"),
            keccak256("seal")
        );
        assertTrue(
            realVerifier.verifyCancelClose(
                CHANNEL_ID,
                keccak256("close"),
                keccak256("revived"),
                keccak256("tx_hash"),
                keccak256("seal"),
                _proofBytesForPIHash(cancelPiHash)
            )
        );

        bytes32 claimPiHash = realVerifier.postCloseClaimPIHash(
            CHANNEL_ID,
            keccak256("close"),
            keccak256("incoming"),
            0x00030000000A,
            alice,
            9,
            keccak256("nullifier")
        );
        assertTrue(
            realVerifier.verifyPostCloseClaim(
                CHANNEL_ID,
                keccak256("close"),
                keccak256("incoming"),
                0x00030000000A,
                alice,
                9,
                keccak256("nullifier"),
                _proofBytesForPIHash(claimPiHash)
            )
        );
    }

    function test_submit_and_finalize_close() external {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9);

        manager.submitCloseIntent(
            intent,
            _proofBytesForPIHash(
                realVerifier.closePIHash(
                    CHANNEL_ID,
                    intent.closeNonce,
                    intent.finalEpoch,
                    intent.finalChannelStateDigest,
                    intent.channelFundAmount,
                    intent.channelFundIntmaxStateRoot,
                    intent.settlementDigest,
                    intent.snapshotBlockNumber
                )
            )
        );
        assertTrue(manager.getPendingClose().active);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose(_withdrawals());

        assertEq(manager.finalizedEpoch(), 9);
        assertEq(manager.finalizedChannelFundAmount(), 75);
        assertEq(manager.withdrawalCredits(alice), 50);
        assertEq(manager.withdrawalCredits(bob), 25);
    }

    function test_newer_close_replaces_pending_close() external {
        ChannelSettlementManager.CloseIntent memory first = _intent(1, 9);
        manager.submitCloseIntent(
            first,
            _proofBytesForPIHash(
                realVerifier.closePIHash(
                    CHANNEL_ID,
                    first.closeNonce,
                    first.finalEpoch,
                    first.finalChannelStateDigest,
                    first.channelFundAmount,
                    first.channelFundIntmaxStateRoot,
                    first.settlementDigest,
                    first.snapshotBlockNumber
                )
            )
        );
        bytes32 oldDigest = manager.getPendingClose().closeIntentDigest;

        ChannelSettlementManager.CloseIntent memory newer = _intent(2, 10);
        newer.finalChannelStateDigest = keccak256("newer_state");
        newer.settlementDigest = manager.computeSettlementDigest(
            newer.finalChannelStateDigest,
            newer.channelFundIntmaxStateRoot,
            _withdrawals()
        );
        manager.submitCloseIntent(
            newer,
            _proofBytesForPIHash(
                realVerifier.closePIHash(
                    CHANNEL_ID,
                    newer.closeNonce,
                    newer.finalEpoch,
                    newer.finalChannelStateDigest,
                    newer.channelFundAmount,
                    newer.channelFundIntmaxStateRoot,
                    newer.settlementDigest,
                    newer.snapshotBlockNumber
                )
            )
        );

        assertTrue(manager.getPendingClose().active);
        assertEq(manager.getPendingClose().finalEpoch, 10);
        assertTrue(manager.getPendingClose().closeIntentDigest != oldDigest);
    }

    function test_cancel_close_clears_pending_intent() external {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9);
        manager.submitCloseIntent(
            intent,
            _proofBytesForPIHash(
                realVerifier.closePIHash(
                    CHANNEL_ID,
                    intent.closeNonce,
                    intent.finalEpoch,
                    intent.finalChannelStateDigest,
                    intent.channelFundAmount,
                    intent.channelFundIntmaxStateRoot,
                    intent.settlementDigest,
                    intent.snapshotBlockNumber
                )
            )
        );

        ChannelSettlementManager.CancelCloseRequest memory request =
            ChannelSettlementManager.CancelCloseRequest({
                closeIntentDigest: manager.computeCloseIntentDigest(intent),
                revivedInterChannelTxDigest: keccak256("revived_tx"),
                revivedTxHash: keccak256("tx_hash"),
                revivedSeal: keccak256("seal")
            });

        manager.cancelClose(
            request,
            _proofBytesForPIHash(
                realVerifier.cancelPIHash(
                    CHANNEL_ID,
                    request.closeIntentDigest,
                    request.revivedInterChannelTxDigest,
                    request.revivedTxHash,
                    request.revivedSeal
                )
            )
        );
        assertFalse(manager.getPendingClose().active);
    }

    function test_post_close_claim_credits_late_incoming_amount() external {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9);
        manager.submitCloseIntent(
            intent,
            _proofBytesForPIHash(
                realVerifier.closePIHash(
                    CHANNEL_ID,
                    intent.closeNonce,
                    intent.finalEpoch,
                    intent.finalChannelStateDigest,
                    intent.channelFundAmount,
                    intent.channelFundIntmaxStateRoot,
                    intent.settlementDigest,
                    intent.snapshotBlockNumber
                )
            )
        );
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose(_withdrawals());

        ChannelSettlementManager.PostCloseClaim memory claim =
            ChannelSettlementManager.PostCloseClaim({
                closeIntentDigest: manager.computeCloseIntentDigest(intent),
                incomingTxHash: keccak256("late_tx"),
                receiverId: 0x00030000000A,
                recipient: alice,
                amount: 9,
                personalNullifier: keccak256("personal_nullifier")
            });

        manager.submitPostCloseClaim(
            claim,
            _proofBytesForPIHash(
                realVerifier.postCloseClaimPIHash(
                    CHANNEL_ID,
                    claim.closeIntentDigest,
                    claim.incomingTxHash,
                    claim.receiverId,
                    claim.recipient,
                    claim.amount,
                    claim.personalNullifier
                )
            )
        );
        assertEq(manager.withdrawalCredits(alice), 59);
    }
}
