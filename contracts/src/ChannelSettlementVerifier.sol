// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IChannelSettlementVerifier} from "./ChannelSettlementManager.sol";

/// @dev Stub proof verifier: each `verify*` recomputes the expected public-input hash and
/// matches it against the supplied "proof" bytes. The `*PIHash` preimages are byte-exact
/// mirrors of the Rust public-input limb vectors (`to_u64_vec()`, big-endian u32 words) in
/// `src/circuits/channel/*_pis.rs`, with the protocol domain word prepended.
contract ChannelSettlementVerifier is IChannelSettlementVerifier {
    uint32 internal constant CLOSE_INTENT_DOMAIN = 0x494d4349;
    uint32 internal constant SPECIAL_CLOSE_DOMAIN = 0x494d5343;
    uint32 internal constant CANCEL_CLOSE_DOMAIN = 0x494d434e;
    uint32 internal constant POST_CLOSE_CLAIM_DOMAIN = 0x494d4350;
    uint32 internal constant WITHDRAWAL_CLAIM_DOMAIN = 0x494d4357;
    uint32 internal constant LATE_OUTGOING_DEBIT_DOMAIN = 0x494d4c44;

    function verifyCloseIntent(
        bytes4 channelId,
        uint64 closeNonce,
        uint64 finalEpoch,
        uint64 finalSmallBlockNumber,
        uint64 closeFreezeNonce,
        bytes32 finalChannelStateDigest,
        bytes32 finalBalanceStateH1,
        uint256 channelFundAmount,
        bytes32 channelFundIntmaxStateRoot,
        bytes32 burnTxHash,
        bytes32 closeWithdrawalDigest,
        uint64 snapshotMediumBlockNumber,
        uint64 finalStateVersion,
        bytes32 finalSettledTxChain,
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
                finalBalanceStateH1,
                channelFundAmount,
                channelFundIntmaxStateRoot,
                burnTxHash,
                closeWithdrawalDigest,
                snapshotMediumBlockNumber,
                finalStateVersion,
                finalSettledTxChain
            )
        );
    }

    function verifySpecialClose(
        bytes4 channelId,
        bytes4 offendingBpKeyId,
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
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 finalBalanceStateH1,
        bytes8 userId,
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
                finalBalanceStateH1,
                userId,
                recipient,
                userAmountDigest,
                amount,
                withdrawalNullifier
            )
        );
    }

    function verifyCancelClose(
        bytes4 channelId,
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
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes8 receiverUserId,
        address recipient,
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
                sharedNativeNullifier,
                amount
            )
        );
    }

    function verifyLateOutgoingDebit(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 sourceTxHash,
        bytes8 senderUserId,
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

    /// @dev OUTER keccak mirror of the 77-limb `ChannelClosePublicInputs.to_u64_vec()`
    /// (src/circuits/channel/close_pis.rs, post-P7): the legacy 67 limbs — channelId(1),
    /// closeNonce(2), finalEpoch(2), finalSmallBlockNumber(2), closeFreezeNonce(2),
    /// finalChannelStateDigest(8), finalBalanceStateH1(8), channelFundAmount(8),
    /// channelFundIntmaxStateRoot(8), burnTxHash(8), closeWithdrawalDigest(8),
    /// closeIntentDigest(8), snapshotMediumBlockNumber(2) — followed by
    /// split_u64(finalStateVersion)(2) and finalSettledTxChain(8). Each limb is one big-endian
    /// u32 word, so `abi.encodePacked` of the typed fields reproduces the byte stream exactly.
    ///
    /// The INNER keccak (`closeIntentDigest`) mirrors the Rust IMCI preimage
    /// (`CloseIntent::signing_digest()`, src/common/channel.rs) including the
    /// `channel_fund_snapshot.channel_id` slot (second `channelId`) and the appended
    /// finalStateVersion / finalSettledTxChain tail (detail2 §C-8).
    function closePIHash(
        bytes4 channelId,
        uint64 closeNonce,
        uint64 finalEpoch,
        uint64 finalSmallBlockNumber,
        uint64 closeFreezeNonce,
        bytes32 finalChannelStateDigest,
        bytes32 finalBalanceStateH1,
        uint256 channelFundAmount,
        bytes32 channelFundIntmaxStateRoot,
        bytes32 burnTxHash,
        bytes32 closeWithdrawalDigest,
        uint64 snapshotMediumBlockNumber,
        uint64 finalStateVersion,
        bytes32 finalSettledTxChain
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
                finalBalanceStateH1,
                channelId,
                channelFundAmount,
                channelFundIntmaxStateRoot,
                burnTxHash,
                closeWithdrawalDigest,
                snapshotMediumBlockNumber,
                finalStateVersion,
                finalSettledTxChain
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
                finalBalanceStateH1,
                channelFundAmount,
                channelFundIntmaxStateRoot,
                burnTxHash,
                closeWithdrawalDigest,
                closeIntentDigest,
                snapshotMediumBlockNumber,
                finalStateVersion,
                finalSettledTxChain
            )
        );
    }

    function specialClosePIHash(
        bytes4 channelId,
        bytes4 offendingBpKeyId,
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

    /// @dev Mirrors the 42-limb `WithdrawalClaimPublicInputs.to_u64_vec()`
    /// (src/circuits/channel/withdrawal_claim_pis.rs): closeIntentDigest(8), channelId(1),
    /// finalBalanceStateH1(8), userId(2), recipient(5), userAmountDigest(8),
    /// withdrawalNullifier(8), amount(2) — with the IMCW domain word prepended.
    function withdrawalClaimPIHash(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 finalBalanceStateH1,
        bytes8 userId,
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
                finalBalanceStateH1,
                userId,
                recipient,
                userAmountDigest,
                withdrawalNullifier,
                amount
            )
        );
    }

    /// @dev Mirrors the 41-limb `CancelClosePublicInputs.to_u64_vec()`
    /// (src/circuits/channel/cancel_close_pis.rs): channelId(1), closeIntentDigest(8),
    /// revivedSmallBlockRoot(8), revivedInterChannelTxDigest(8), revivedTxHash(8),
    /// revivedSeal(8) — with the IMCN domain word prepended.
    function cancelPIHash(
        bytes4 channelId,
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

    /// @dev Mirrors the 34-limb `PostCloseClaimPublicInputs.to_u64_vec()`
    /// (src/circuits/channel/post_close_claim_pis.rs): closeIntentDigest(8),
    /// receiverChannelId(1), incomingTxHash(8), receiverUserId(2), recipient(5),
    /// sharedNativeNullifier(8), amount(2) — with the IMCP domain word prepended.
    /// The legacy `receiverAmountDigest` slot was removed: the v2 Rust PI no longer exposes the
    /// receiver's ciphertext digest (the E-3 claim proof binds the ciphertext in-circuit).
    function postCloseClaimPIHash(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes8 receiverUserId,
        address recipient,
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
                sharedNativeNullifier,
                amount
            )
        );
    }

    function lateOutgoingDebitPIHash(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 sourceTxHash,
        bytes8 senderUserId,
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
