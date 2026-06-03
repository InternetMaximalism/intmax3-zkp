// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IChannelSettlementVerifier} from "./ChannelSettlementManager.sol";

contract ChannelSettlementVerifier is IChannelSettlementVerifier {
    uint32 internal constant CLOSE_INTENT_DOMAIN = 0x494d4349;
    uint32 internal constant SPECIAL_CLOSE_DOMAIN = 0x494d5343;
    uint32 internal constant CANCEL_CLOSE_DOMAIN = 0x494d434e;
    uint32 internal constant POST_CLOSE_CLAIM_DOMAIN = 0x494d4350;
    uint32 internal constant WITHDRAWAL_CLAIM_DOMAIN = 0x494d4357;
    uint32 internal constant LATE_OUTGOING_DEBIT_DOMAIN = 0x494d4c44;

    function verifyCloseIntent(
        bytes5 channelId,
        uint64 closeNonce,
        uint64 finalEpoch,
        uint64 finalSmallBlockNumber,
        uint64 closeFreezeNonce,
        bytes32 finalChannelStateDigest,
        bytes32 finalChannelBalanceRoot,
        uint256 channelFundAmount,
        bytes32 channelFundIntmaxStateRoot,
        bytes32 burnTxHash,
        bytes32 closeWithdrawalDigest,
        uint64 snapshotMediumBlockNumber,
        bytes calldata proof
    ) external pure returns (bool) {
        return _matches(
            proof,
            closePIHash(
                channelId,
                closeNonce,
                finalEpoch,
                finalSmallBlockNumber,
                closeFreezeNonce,
                finalChannelStateDigest,
                finalChannelBalanceRoot,
                channelFundAmount,
                channelFundIntmaxStateRoot,
                burnTxHash,
                closeWithdrawalDigest,
                snapshotMediumBlockNumber
            )
        );
    }

    function verifySpecialClose(
        bytes5 channelId,
        bytes5 offendingBpKeyId,
        bytes32 fullySignedSmallBlockRoot,
        uint64 smallBlockNumber,
        uint64 signedMediumBlockNumber,
        uint64 latestFinalizedMediumBlockNumber,
        bytes calldata proof
    ) external pure returns (bool) {
        return _matches(
            proof,
            specialClosePIHash(
                channelId,
                offendingBpKeyId,
                fullySignedSmallBlockRoot,
                smallBlockNumber,
                signedMediumBlockNumber,
                latestFinalizedMediumBlockNumber
            )
        );
    }

    function verifyWithdrawalClaim(
        bytes5 channelId,
        bytes32 closeIntentDigest,
        bytes32 finalChannelBalanceRoot,
        bytes10 userId,
        address recipient,
        bytes32 userAmountDigest,
        uint64 amount,
        bytes32 withdrawalNullifier,
        bytes calldata proof
    ) external pure returns (bool) {
        return _matches(
            proof,
            withdrawalClaimPIHash(
                channelId,
                closeIntentDigest,
                finalChannelBalanceRoot,
                userId,
                recipient,
                userAmountDigest,
                amount,
                withdrawalNullifier
            )
        );
    }

    function verifyCancelClose(
        bytes5 channelId,
        bytes32 closeIntentDigest,
        bytes32 revivedSmallBlockRoot,
        bytes32 revivedInterChannelTxDigest,
        bytes32 revivedTxHash,
        bytes32 revivedSeal,
        bytes calldata proof
    ) external pure returns (bool) {
        return _matches(
            proof,
            cancelPIHash(
                channelId,
                closeIntentDigest,
                revivedSmallBlockRoot,
                revivedInterChannelTxDigest,
                revivedTxHash,
                revivedSeal
            )
        );
    }

    function verifyPostCloseClaim(
        bytes5 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes10 receiverUserId,
        address recipient,
        bytes32 receiverAmountDigest,
        bytes32 sharedNativeNullifier,
        uint64 amount,
        bytes calldata proof
    ) external pure returns (bool) {
        return _matches(
            proof,
            postCloseClaimPIHash(
                channelId,
                closeIntentDigest,
                incomingTxHash,
                receiverUserId,
                recipient,
                receiverAmountDigest,
                sharedNativeNullifier,
                amount
            )
        );
    }

    function verifyLateOutgoingDebit(
        bytes5 channelId,
        bytes32 closeIntentDigest,
        bytes32 sourceTxHash,
        bytes10 senderUserId,
        bytes32 senderAmountDigest,
        bytes32 debitNullifier,
        uint64 amount,
        bytes calldata proof
    ) external pure returns (bool) {
        return _matches(
            proof,
            lateOutgoingDebitPIHash(
                channelId,
                closeIntentDigest,
                sourceTxHash,
                senderUserId,
                senderAmountDigest,
                debitNullifier,
                amount
            )
        );
    }

    function closePIHash(
        bytes5 channelId,
        uint64 closeNonce,
        uint64 finalEpoch,
        uint64 finalSmallBlockNumber,
        uint64 closeFreezeNonce,
        bytes32 finalChannelStateDigest,
        bytes32 finalChannelBalanceRoot,
        uint256 channelFundAmount,
        bytes32 channelFundIntmaxStateRoot,
        bytes32 burnTxHash,
        bytes32 closeWithdrawalDigest,
        uint64 snapshotMediumBlockNumber
    ) public pure returns (bytes32) {
        bytes32 closeIntentDigest = keccak256(
            abi.encodePacked(
                bytes4(CLOSE_INTENT_DOMAIN),
                channelId,
                closeNonce,
                finalEpoch,
                finalSmallBlockNumber,
                closeFreezeNonce,
                finalChannelStateDigest,
                finalChannelBalanceRoot,
                channelId,
                channelFundAmount,
                channelFundIntmaxStateRoot,
                burnTxHash,
                closeWithdrawalDigest,
                snapshotMediumBlockNumber
            )
        );
        return keccak256(
            abi.encodePacked(
                channelId,
                closeNonce,
                finalEpoch,
                finalSmallBlockNumber,
                closeFreezeNonce,
                finalChannelStateDigest,
                finalChannelBalanceRoot,
                channelFundAmount,
                channelFundIntmaxStateRoot,
                burnTxHash,
                closeWithdrawalDigest,
                closeIntentDigest,
                snapshotMediumBlockNumber
            )
        );
    }

    function specialClosePIHash(
        bytes5 channelId,
        bytes5 offendingBpKeyId,
        bytes32 fullySignedSmallBlockRoot,
        uint64 smallBlockNumber,
        uint64 signedMediumBlockNumber,
        uint64 latestFinalizedMediumBlockNumber
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(SPECIAL_CLOSE_DOMAIN),
                channelId,
                offendingBpKeyId,
                fullySignedSmallBlockRoot,
                smallBlockNumber,
                signedMediumBlockNumber,
                latestFinalizedMediumBlockNumber
            )
        );
    }

    function withdrawalClaimPIHash(
        bytes5 channelId,
        bytes32 closeIntentDigest,
        bytes32 finalChannelBalanceRoot,
        bytes10 userId,
        address recipient,
        bytes32 userAmountDigest,
        uint64 amount,
        bytes32 withdrawalNullifier
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(WITHDRAWAL_CLAIM_DOMAIN),
                closeIntentDigest,
                channelId,
                finalChannelBalanceRoot,
                userId,
                recipient,
                userAmountDigest,
                withdrawalNullifier,
                amount
            )
        );
    }

    function cancelPIHash(
        bytes5 channelId,
        bytes32 closeIntentDigest,
        bytes32 revivedSmallBlockRoot,
        bytes32 revivedInterChannelTxDigest,
        bytes32 revivedTxHash,
        bytes32 revivedSeal
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(CANCEL_CLOSE_DOMAIN),
                channelId,
                closeIntentDigest,
                revivedSmallBlockRoot,
                revivedInterChannelTxDigest,
                revivedTxHash,
                revivedSeal
            )
        );
    }

    function postCloseClaimPIHash(
        bytes5 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes10 receiverUserId,
        address recipient,
        bytes32 receiverAmountDigest,
        bytes32 sharedNativeNullifier,
        uint64 amount
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(POST_CLOSE_CLAIM_DOMAIN),
                closeIntentDigest,
                channelId,
                incomingTxHash,
                receiverUserId,
                recipient,
                receiverAmountDigest,
                sharedNativeNullifier,
                amount
            )
        );
    }

    function lateOutgoingDebitPIHash(
        bytes5 channelId,
        bytes32 closeIntentDigest,
        bytes32 sourceTxHash,
        bytes10 senderUserId,
        bytes32 senderAmountDigest,
        bytes32 debitNullifier,
        uint64 amount
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(LATE_OUTGOING_DEBIT_DOMAIN),
                closeIntentDigest,
                channelId,
                sourceTxHash,
                senderUserId,
                senderAmountDigest,
                debitNullifier,
                amount
            )
        );
    }

    function _matches(bytes calldata proof, bytes32 expected) internal pure returns (bool) {
        return proof.length == 32 && abi.decode(proof, (bytes32)) == expected;
    }
}
