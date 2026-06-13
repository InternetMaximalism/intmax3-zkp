// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IChannelSettlementVerifier} from "./ChannelSettlementManager.sol";

/// @dev Stub proof verifier: each `verify*` recomputes the expected public-input hash and
/// matches it against the supplied "proof" bytes. The `*PIHash` preimages are byte-exact
/// mirrors of the Rust public-input limb vectors (`to_u64_vec()`, big-endian u32 words) in
/// `src/circuits/channel/*_pis.rs`, with the protocol domain word prepended.
///
/// F7 (one SPHINCS+ key per member): member identity is the SPHINCS+ pubkey hash (bytes32, 8
/// limbs); the legacy `bytes8 userId` (2 limbs) is removed from the withdrawal / post-close
/// claims, and the close PI appends a `memberSetCommitment` (keccak over the 3 members' pubkey
/// hashes) so L1 binds the verified signing keys to the channel's registered member set.
contract ChannelSettlementVerifier is IChannelSettlementVerifier {
    uint32 internal constant CLOSE_INTENT_DOMAIN = 0x494d4349;
    uint32 internal constant SPECIAL_CLOSE_DOMAIN = 0x494d5343;
    uint32 internal constant CANCEL_CLOSE_DOMAIN = 0x494d434e;
    uint32 internal constant POST_CLOSE_CLAIM_DOMAIN = 0x494d4350;
    uint32 internal constant WITHDRAWAL_CLAIM_DOMAIN = 0x494d4357;
    uint32 internal constant LATE_OUTGOING_DEBIT_DOMAIN = 0x494d4c44;
    /// "IMCM" — close-circuit member-set commitment domain (mirrors Rust
    /// `CLOSE_MEMBER_SET_DOMAIN` / `close_member_set_commitment`, src/common/channel.rs).
    uint32 internal constant CLOSE_MEMBER_SET_DOMAIN = 0x494d434d;

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
        bytes32 memberSetCommitment,
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
                finalSettledTxChain,
                memberSetCommitment
            )
        );
    }

    function verifySpecialClose(
        bytes4 channelId,
        uint8 offendingBpMemberSlot,
        bytes32 offendingBpSphincsPubkeyHash,
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
                offendingBpMemberSlot,
                offendingBpSphincsPubkeyHash,
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
        bytes32 memberSphincsPubkeyHash,
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
                memberSphincsPubkeyHash,
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
        bytes32 receiverSphincsPubkeyHash,
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
                receiverSphincsPubkeyHash,
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
        bytes32 senderSphincsPubkeyHash,
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
                senderSphincsPubkeyHash,
                senderAmountDigest,
                debitNullifier,
                amount
            )
        );
    }

    /// @dev OUTER keccak mirror of the 85-limb `ChannelClosePublicInputs.to_u64_vec()`
    /// (src/circuits/channel/close_pis.rs, post-F7): the legacy 67 limbs — channelId(1),
    /// closeNonce(2), finalEpoch(2), finalSmallBlockNumber(2), closeFreezeNonce(2),
    /// finalChannelStateDigest(8), finalBalanceStateH1(8), channelFundAmount(8),
    /// channelFundIntmaxStateRoot(8), burnTxHash(8), closeWithdrawalDigest(8),
    /// closeIntentDigest(8), snapshotMediumBlockNumber(2) — followed by
    /// split_u64(finalStateVersion)(2), finalSettledTxChain(8) and the appended
    /// memberSetCommitment(8). Each limb is one big-endian u32 word, so `abi.encodePacked` of
    /// the typed fields reproduces the byte stream exactly.
    ///
    /// The INNER keccak (`closeIntentDigest`) mirrors the Rust IMCI preimage
    /// (`CloseIntent::signing_digest()`, src/common/channel.rs) including the
    /// `channel_fund_snapshot.channel_id` slot (second `channelId`) and the appended
    /// finalStateVersion / finalSettledTxChain tail (detail2 §C-8). It is NOT member-bearing, so
    /// it is byte-for-byte unchanged by F7 (the shared close-intent vector is preserved).
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
        bytes32 finalSettledTxChain,
        bytes32 memberSetCommitment
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
                finalSettledTxChain,
                memberSetCommitment
            )
        );
    }

    /// @dev F7 member-set commitment: keccak([IMCM, sphincsPubkeyHash[0..2]]) over the 3 members'
    /// SPHINCS+ pubkey hashes in slot order. Byte-for-byte mirror of Rust
    /// `close_member_set_commitment` (src/common/channel.rs): one big-endian u32 word per limb,
    /// so `abi.encodePacked(bytes4(domain), bytes32, bytes32, bytes32)` reproduces the preimage.
    function closeMemberSetCommitment(
        bytes32 sphincsPubkeyHash0,
        bytes32 sphincsPubkeyHash1,
        bytes32 sphincsPubkeyHash2
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(CLOSE_MEMBER_SET_DOMAIN),
                sphincsPubkeyHash0,
                sphincsPubkeyHash1,
                sphincsPubkeyHash2
            )
        );
    }

    /// @dev Mirrors the Rust `SpecialClose::signing_digest()` (IMSC, src/common/channel.rs): the
    /// block-proposer identity is now `offendingBpMemberSlot`(1 u32 limb) + the proposer's
    /// `offendingBpSphincsPubkeyHash`(8 limbs), replacing the legacy `offendingBpKeyId`(1 limb).
    function specialClosePIHash(
        bytes4 channelId,
        uint8 offendingBpMemberSlot,
        bytes32 offendingBpSphincsPubkeyHash,
        bytes32 fullySignedSmallBlockRoot,
        uint64 smallBlockNumber,
        uint64 signedMediumBlockNumber,
        uint64 latestFinalizedMediumBlockNumber
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(SPECIAL_CLOSE_DOMAIN),
                channelId,
                uint32(offendingBpMemberSlot),
                offendingBpSphincsPubkeyHash,
                fullySignedSmallBlockRoot,
                smallBlockNumber,
                signedMediumBlockNumber,
                latestFinalizedMediumBlockNumber
            )
        );
    }

    /// @dev Mirrors the 48-limb `WithdrawalClaimPublicInputs.to_u64_vec()`
    /// (src/circuits/channel/withdrawal_claim_pis.rs): closeIntentDigest(8), channelId(1),
    /// finalBalanceStateH1(8), memberSphincsPubkeyHash(8), recipient(5), userAmountDigest(8),
    /// withdrawalNullifier(8), amount(2) — with the IMCW domain word prepended. F7: the legacy
    /// userId(2 limbs) is replaced by the member's SPHINCS+ pubkey hash (8 limbs).
    function withdrawalClaimPIHash(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 finalBalanceStateH1,
        bytes32 memberSphincsPubkeyHash,
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
                memberSphincsPubkeyHash,
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
    /// revivedSeal(8) — with the IMCN domain word prepended. F7: unchanged (no member id in PI).
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

    /// @dev Mirrors the 40-limb `PostCloseClaimPublicInputs.to_u64_vec()`
    /// (src/circuits/channel/post_close_claim_pis.rs): closeIntentDigest(8),
    /// receiverChannelId(1), incomingTxHash(8), receiverSphincsPubkeyHash(8), recipient(5),
    /// sharedNativeNullifier(8), amount(2) — with the IMCP domain word prepended. F7: the legacy
    /// receiverUserId(2 limbs) is replaced by the receiver's SPHINCS+ pubkey hash (8 limbs).
    function postCloseClaimPIHash(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverSphincsPubkeyHash,
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
                receiverSphincsPubkeyHash,
                recipient,
                sharedNativeNullifier,
                amount
            )
        );
    }

    /// @dev Late-outgoing-debit correction PI (Solidity-side challenge primitive). F7: the
    /// sender identity is the member's SPHINCS+ pubkey hash (8 limbs), replacing the legacy
    /// senderUserId(2 limbs), so it keys off the same identity the Manager binds to the member
    /// set.
    function lateOutgoingDebitPIHash(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 sourceTxHash,
        bytes32 senderSphincsPubkeyHash,
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
                senderSphincsPubkeyHash,
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
