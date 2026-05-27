// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IChannelSettlementVerifier {
    function verifyCloseIntent(
        uint256 channelId,
        uint64 closeNonce,
        uint64 finalEpoch,
        bytes32 finalChannelStateDigest,
        uint256 channelFundAmount,
        bytes32 channelFundIntmaxStateRoot,
        bytes32 settlementDigest,
        uint64 snapshotBlockNumber,
        bytes calldata proof
    ) external view returns (bool);

    function verifyCancelClose(
        uint256 channelId,
        bytes32 closeIntentDigest,
        bytes32 revivedInterChannelTxDigest,
        bytes32 revivedTxHash,
        bytes32 revivedSeal,
        bytes calldata proof
    ) external view returns (bool);

    function verifyPostCloseClaim(
        uint256 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        uint256 receiverId,
        address recipient,
        uint256 amount,
        bytes32 personalNullifier,
        bytes calldata proof
    ) external view returns (bool);
}

contract ChannelSettlementManager {
    error InvalidChannelId();
    error InvalidCloseProof();
    error InvalidCancelProof();
    error InvalidPostCloseClaimProof();
    error CloseNotActive();
    error CloseAlreadyFinalized();
    error ChallengeWindowOpen();
    error ChallengeWindowClosed();
    error CloseNotNewer();
    error SettlementDigestMismatch();
    error SettlementTotalMismatch();
    error CloseIntentDigestMismatch();
    error NullifierAlreadyUsed();
    error NoWithdrawalCredit();

    event CloseSubmitted(
        bytes32 indexed closeIntentDigest,
        uint64 indexed closeNonce,
        uint64 indexed finalEpoch,
        uint256 channelFundAmount,
        uint64 challengeDeadline
    );

    event CloseCancelled(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed revivedTxHash,
        bytes32 revivedSeal
    );

    event CloseFinalized(
        bytes32 indexed closeIntentDigest,
        uint64 indexed finalEpoch,
        uint256 channelFundAmount
    );

    event PostCloseClaimAccepted(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed personalNullifier,
        address indexed recipient,
        uint256 amount
    );

    event WithdrawalClaimed(address indexed recipient, uint256 amount);

    struct CloseIntent {
        uint64 closeNonce;
        uint64 finalEpoch;
        bytes32 finalChannelStateDigest;
        uint256 channelFundAmount;
        bytes32 channelFundIntmaxStateRoot;
        bytes32 settlementDigest;
        uint64 snapshotBlockNumber;
    }

    struct Withdrawal {
        address recipient;
        uint256 amount;
    }

    struct CancelCloseRequest {
        bytes32 closeIntentDigest;
        bytes32 revivedInterChannelTxDigest;
        bytes32 revivedTxHash;
        bytes32 revivedSeal;
    }

    struct PostCloseClaim {
        bytes32 closeIntentDigest;
        bytes32 incomingTxHash;
        uint256 receiverId;
        address recipient;
        uint256 amount;
        bytes32 personalNullifier;
    }

    struct PendingClose {
        bool active;
        uint64 closeNonce;
        uint64 finalEpoch;
        uint64 challengeDeadline;
        bytes32 closeIntentDigest;
        bytes32 finalChannelStateDigest;
        uint256 channelFundAmount;
        bytes32 channelFundIntmaxStateRoot;
        bytes32 settlementDigest;
        uint64 snapshotBlockNumber;
    }

    uint256 public immutable channelId;
    uint64 public immutable challengePeriod;
    IChannelSettlementVerifier public immutable verifier;

    PendingClose public pendingClose;
    bytes32 public finalizedCloseIntentDigest;
    bytes32 public finalizedChannelStateDigest;
    uint64 public finalizedEpoch;
    uint256 public finalizedChannelFundAmount;

    mapping(address => uint256) public withdrawalCredits;
    mapping(bytes32 => bool) public usedPersonalNullifiers;

    constructor(
        uint256 channelId_,
        uint64 challengePeriod_,
        IChannelSettlementVerifier verifier_
    ) {
        channelId = channelId_;
        challengePeriod = challengePeriod_;
        verifier = verifier_;
    }

    function computeSettlementDigest(
        Withdrawal[] memory withdrawals
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(withdrawals));
    }

    function computeCloseIntentDigest(
        CloseIntent memory intent
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                channelId,
                intent.closeNonce,
                intent.finalEpoch,
                intent.finalChannelStateDigest,
                intent.channelFundAmount,
                intent.channelFundIntmaxStateRoot,
                intent.settlementDigest,
                intent.snapshotBlockNumber
            )
        );
    }

    function submitCloseIntent(
        CloseIntent calldata intent,
        bytes calldata proof
    ) external {
        _checkCloseProof(intent, proof);

        if (pendingClose.active) {
            if (block.timestamp > pendingClose.challengeDeadline) {
                revert ChallengeWindowClosed();
            }
            if (!_isNewer(intent, pendingClose)) {
                revert CloseNotNewer();
            }
        } else if (finalizedCloseIntentDigest != bytes32(0)) {
            revert CloseAlreadyFinalized();
        }

        bytes32 closeIntentDigest = computeCloseIntentDigest(intent);
        pendingClose = PendingClose({
            active: true,
            closeNonce: intent.closeNonce,
            finalEpoch: intent.finalEpoch,
            challengeDeadline: uint64(block.timestamp + challengePeriod),
            closeIntentDigest: closeIntentDigest,
            finalChannelStateDigest: intent.finalChannelStateDigest,
            channelFundAmount: intent.channelFundAmount,
            channelFundIntmaxStateRoot: intent.channelFundIntmaxStateRoot,
            settlementDigest: intent.settlementDigest,
            snapshotBlockNumber: intent.snapshotBlockNumber
        });

        emit CloseSubmitted(
            closeIntentDigest,
            intent.closeNonce,
            intent.finalEpoch,
            intent.channelFundAmount,
            pendingClose.challengeDeadline
        );
    }

    function cancelClose(
        CancelCloseRequest calldata request,
        bytes calldata proof
    ) external {
        if (!pendingClose.active) {
            revert CloseNotActive();
        }
        if (request.closeIntentDigest != pendingClose.closeIntentDigest) {
            revert CloseIntentDigestMismatch();
        }
        if (
            !verifier.verifyCancelClose(
                channelId,
                request.closeIntentDigest,
                request.revivedInterChannelTxDigest,
                request.revivedTxHash,
                request.revivedSeal,
                proof
            )
        ) {
            revert InvalidCancelProof();
        }

        bytes32 closeIntentDigest = pendingClose.closeIntentDigest;
        delete pendingClose;
        emit CloseCancelled(
            closeIntentDigest,
            request.revivedTxHash,
            request.revivedSeal
        );
    }

    function finalizeClose(Withdrawal[] calldata withdrawals) external {
        if (!pendingClose.active) {
            revert CloseNotActive();
        }
        if (block.timestamp < pendingClose.challengeDeadline) {
            revert ChallengeWindowOpen();
        }
        if (computeSettlementDigest(withdrawals) != pendingClose.settlementDigest) {
            revert SettlementDigestMismatch();
        }

        uint256 total;
        for (uint256 i = 0; i < withdrawals.length; i++) {
            total += withdrawals[i].amount;
            withdrawalCredits[withdrawals[i].recipient] += withdrawals[i].amount;
        }
        if (total != pendingClose.channelFundAmount) {
            revert SettlementTotalMismatch();
        }

        finalizedCloseIntentDigest = pendingClose.closeIntentDigest;
        finalizedChannelStateDigest = pendingClose.finalChannelStateDigest;
        finalizedEpoch = pendingClose.finalEpoch;
        finalizedChannelFundAmount = pendingClose.channelFundAmount;

        emit CloseFinalized(
            pendingClose.closeIntentDigest,
            pendingClose.finalEpoch,
            pendingClose.channelFundAmount
        );

        delete pendingClose;
    }

    function submitPostCloseClaim(
        PostCloseClaim calldata claim,
        bytes calldata proof
    ) external {
        if (finalizedCloseIntentDigest == bytes32(0)) {
            revert CloseNotActive();
        }
        if (claim.closeIntentDigest != finalizedCloseIntentDigest) {
            revert CloseIntentDigestMismatch();
        }
        if (usedPersonalNullifiers[claim.personalNullifier]) {
            revert NullifierAlreadyUsed();
        }
        if (
            !verifier.verifyPostCloseClaim(
                channelId,
                claim.closeIntentDigest,
                claim.incomingTxHash,
                claim.receiverId,
                claim.recipient,
                claim.amount,
                claim.personalNullifier,
                proof
            )
        ) {
            revert InvalidPostCloseClaimProof();
        }

        usedPersonalNullifiers[claim.personalNullifier] = true;
        withdrawalCredits[claim.recipient] += claim.amount;
        emit PostCloseClaimAccepted(
            claim.closeIntentDigest,
            claim.personalNullifier,
            claim.recipient,
            claim.amount
        );
    }

    function claimWithdrawalCredit() external returns (uint256 amount) {
        amount = withdrawalCredits[msg.sender];
        if (amount == 0) {
            revert NoWithdrawalCredit();
        }
        withdrawalCredits[msg.sender] = 0;
        emit WithdrawalClaimed(msg.sender, amount);
    }

    function getPendingClose() external view returns (PendingClose memory) {
        return pendingClose;
    }

    function _checkCloseProof(
        CloseIntent calldata intent,
        bytes calldata proof
    ) internal view {
        if (
            !verifier.verifyCloseIntent(
                channelId,
                intent.closeNonce,
                intent.finalEpoch,
                intent.finalChannelStateDigest,
                intent.channelFundAmount,
                intent.channelFundIntmaxStateRoot,
                intent.settlementDigest,
                intent.snapshotBlockNumber,
                proof
            )
        ) {
            revert InvalidCloseProof();
        }
    }

    function _isNewer(
        CloseIntent calldata intent,
        PendingClose memory current
    ) internal pure returns (bool) {
        return
            intent.finalEpoch > current.finalEpoch ||
            (
                intent.finalEpoch == current.finalEpoch &&
                intent.closeNonce > current.closeNonce
            );
    }
}
