// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IChannelSettlementVerifier {
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
    ) external pure returns (bool);

    function verifySpecialClose(
        bytes5 channelId,
        bytes5 offendingBpKeyId,
        bytes32 fullySignedSmallBlockRoot,
        uint64 smallBlockNumber,
        uint64 signedMediumBlockNumber,
        uint64 latestFinalizedMediumBlockNumber,
        bytes calldata proof
    ) external pure returns (bool);

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
    ) external pure returns (bool);

    function verifyCancelClose(
        bytes5 channelId,
        bytes32 closeIntentDigest,
        bytes32 revivedSmallBlockRoot,
        bytes32 revivedInterChannelTxDigest,
        bytes32 revivedTxHash,
        bytes32 revivedSeal,
        bytes calldata proof
    ) external pure returns (bool);

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
    ) external pure returns (bool);

    function verifyLateOutgoingDebit(
        bytes5 channelId,
        bytes32 closeIntentDigest,
        bytes32 sourceTxHash,
        bytes10 senderUserId,
        bytes32 senderAmountDigest,
        bytes32 debitNullifier,
        uint64 amount,
        bytes calldata proof
    ) external pure returns (bool);
}

contract ChannelSettlementManager {
    error InvalidChannelId();
    error InvalidBpKeyId();
    error InvalidMemberBinding();
    error DuplicateRegisteredMember();
    error InvalidCloseProof();
    error InvalidSpecialCloseProof();
    error InvalidWithdrawalClaimProof();
    error InvalidCancelProof();
    error InvalidPostCloseClaimProof();
    error InvalidLateOutgoingDebitProof();
    error InvalidFreezeNonce();
    error InvalidSpecialCloseWindow();
    error InvalidBpForSpecialClose();
    error ChannelNotClosable();
    error CloseNotActive();
    error CloseAlreadyFinalized();
    error ChallengeWindowOpen();
    error ChallengeWindowClosed();
    error CloseNotNewer();
    error CloseIntentDigestMismatch();
    error NullifierAlreadyUsed();
    error WithdrawalCapExceeded();
    error NoWithdrawalCredit();
    error RecipientMismatch();
    error ChannelAlreadyFrozen();
    error ChannelClosed();

    enum ChannelLifecycleStatus {
        Active,
        ClosePending,
        Closed
    }

    event CloseSubmitted(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed burnTxHash,
        uint64 indexed closeNonce,
        uint64 finalEpoch,
        uint64 closeFreezeNonce,
        uint256 channelFundAmount,
        uint64 challengeDeadline
    );

    event SpecialCloseSubmitted(
        bytes32 indexed specialCloseDigest,
        bytes5 indexed offendingBpKeyId,
        bytes32 indexed fullySignedSmallBlockRoot,
        uint64 smallBlockNumber,
        uint256 slashedAmount,
        uint64 closeFreezeNonce
    );

    event CloseCancelled(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed revivedTxHash,
        bytes32 revivedSeal
    );

    event LateOutgoingDebitAccepted(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed sourceTxHash,
        bytes32 indexed debitNullifier,
        uint64 amount
    );

    event CloseFinalized(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed burnTxHash,
        uint64 indexed finalEpoch,
        uint256 channelFundAmount
    );

    event WithdrawalClaimAccepted(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed withdrawalNullifier,
        bytes10 indexed userId,
        address recipient,
        uint256 amount
    );

    event PostCloseClaimAccepted(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed sharedNativeNullifier,
        bytes10 indexed receiverUserId,
        address recipient,
        uint256 amount
    );

    event WithdrawalClaimed(address indexed recipient, uint256 amount);

    struct CloseIntent {
        uint64 closeNonce;
        uint64 finalEpoch;
        uint64 finalSmallBlockNumber;
        uint64 closeFreezeNonce;
        bytes32 finalChannelStateDigest;
        bytes32 finalChannelBalanceRoot;
        uint256 channelFundAmount;
        bytes32 channelFundIntmaxStateRoot;
        bytes32 burnTxHash;
        bytes32 closeWithdrawalDigest;
        uint64 snapshotMediumBlockNumber;
    }

    struct SpecialClose {
        bytes5 offendingBpKeyId;
        bytes32 fullySignedSmallBlockRoot;
        uint64 smallBlockNumber;
        uint64 signedMediumBlockNumber;
        uint64 latestFinalizedMediumBlockNumber;
    }

    struct MemberBinding {
        bytes10 userId;
        address recipient;
    }

    struct WithdrawalClaim {
        bytes32 closeIntentDigest;
        bytes10 userId;
        address recipient;
        bytes32 userAmountDigest;
        uint64 amount;
        bytes32 withdrawalNullifier;
    }

    struct CancelCloseRequest {
        bytes32 closeIntentDigest;
        bytes32 revivedSmallBlockRoot;
        bytes32 revivedInterChannelTxDigest;
        bytes32 revivedTxHash;
        bytes32 revivedSeal;
    }

    struct PostCloseClaim {
        bytes32 closeIntentDigest;
        bytes32 incomingTxHash;
        bytes10 receiverUserId;
        address recipient;
        bytes32 receiverAmountDigest;
        bytes32 sharedNativeNullifier;
        uint64 amount;
    }

    struct LateOutgoingDebitCorrection {
        bytes32 closeIntentDigest;
        bytes32 sourceTxHash;
        bytes10 senderUserId;
        bytes32 senderAmountDigest;
        bytes32 debitNullifier;
        uint64 amount;
    }

    struct PendingClose {
        bool active;
        uint64 closeNonce;
        uint64 finalEpoch;
        uint64 finalSmallBlockNumber;
        uint64 closeFreezeNonce;
        uint64 challengeDeadline;
        bytes32 closeIntentDigest;
        bytes32 finalChannelStateDigest;
        bytes32 finalChannelBalanceRoot;
        uint256 channelFundAmount;
        bytes32 channelFundIntmaxStateRoot;
        bytes32 burnTxHash;
        bytes32 closeWithdrawalDigest;
        uint64 snapshotMediumBlockNumber;
    }

    bytes5 public immutable channelId;
    bytes5 public immutable bpKeyId;
    uint64 public immutable challengePeriod;
    uint256 public immutable specialClosePenalty;
    IChannelSettlementVerifier public immutable verifier;

    ChannelLifecycleStatus public channelStatus;
    uint64 public currentCloseFreezeNonce;
    uint256 public bpBondCredits;

    PendingClose public pendingClose;
    bytes32 public latestSpecialCloseDigest;
    bytes32 public finalizedCloseIntentDigest;
    bytes32 public finalizedChannelStateDigest;
    bytes32 public finalizedChannelBalanceRoot;
    bytes32 public finalizedBurnTxHash;
    bytes32 public finalizedCloseWithdrawalDigest;
    bytes32 public finalizedChannelFundIntmaxStateRoot;
    uint64 public finalizedEpoch;
    uint64 public finalizedSmallBlockNumber;
    uint256 public finalizedChannelFundAmount;
    uint256 public totalWithdrawn;

    mapping(address => uint256) public withdrawalCredits;
    mapping(bytes32 => bool) public usedWithdrawalNullifiers;
    mapping(bytes32 => bool) public usedSharedNativeNullifiers;
    mapping(bytes32 => bool) public usedLateOutgoingDebitNullifiers;
    mapping(bytes10 => address) public registeredRecipientOf;
    mapping(bytes10 => uint256) public registeredMemberIndexPlusOne;
    bytes10[] public registeredUserIds;

    constructor(
        bytes5 channelId_,
        bytes5 bpKeyId_,
        uint64 challengePeriod_,
        uint256 specialClosePenalty_,
        uint256 initialBpBondCredits_,
        IChannelSettlementVerifier verifier_,
        MemberBinding[] memory memberBindings
    ) {
        if (channelId_ == bytes5(0)) revert InvalidChannelId();
        if (bpKeyId_ == bytes5(0)) revert InvalidBpKeyId();

        channelId = channelId_;
        bpKeyId = bpKeyId_;
        challengePeriod = challengePeriod_;
        specialClosePenalty = specialClosePenalty_;
        bpBondCredits = initialBpBondCredits_;
        verifier = verifier_;
        channelStatus = ChannelLifecycleStatus.Active;

        for (uint256 i = 0; i < memberBindings.length; i++) {
            MemberBinding memory binding = memberBindings[i];
            if (
                binding.userId == bytes10(0) ||
                binding.recipient == address(0) ||
                _userChannelId(binding.userId) != channelId_
            ) {
                revert InvalidMemberBinding();
            }
            if (registeredMemberIndexPlusOne[binding.userId] != 0) {
                revert DuplicateRegisteredMember();
            }
            registeredRecipientOf[binding.userId] = binding.recipient;
            registeredMemberIndexPlusOne[binding.userId] = registeredUserIds.length + 1;
            registeredUserIds.push(binding.userId);
        }
    }

    function memberCount() external view returns (uint256) {
        return registeredUserIds.length;
    }

    function isNativeSendAllowed(uint64 suppliedCloseFreezeNonce) external view returns (bool) {
        return
            channelStatus == ChannelLifecycleStatus.Active &&
            suppliedCloseFreezeNonce == currentCloseFreezeNonce;
    }

    function fundBpBondCredits(uint256 amount) external {
        bpBondCredits += amount;
    }

    function submitCloseIntent(
        CloseIntent calldata intent,
        bytes calldata proof
    ) external {
        if (channelStatus == ChannelLifecycleStatus.Closed) revert ChannelClosed();
        _checkCloseProof(intent, proof);

        if (pendingClose.active) {
            if (block.timestamp > pendingClose.challengeDeadline) {
                revert ChallengeWindowClosed();
            }
            if (intent.closeFreezeNonce != currentCloseFreezeNonce) {
                revert InvalidFreezeNonce();
            }
            if (!_isNewer(intent, pendingClose)) {
                revert CloseNotNewer();
            }
        } else {
            if (channelStatus == ChannelLifecycleStatus.Active) {
                if (intent.closeFreezeNonce != currentCloseFreezeNonce + 1) {
                    revert InvalidFreezeNonce();
                }
                currentCloseFreezeNonce = intent.closeFreezeNonce;
                channelStatus = ChannelLifecycleStatus.ClosePending;
            } else if (intent.closeFreezeNonce != currentCloseFreezeNonce) {
                revert InvalidFreezeNonce();
            }
        }

        bytes32 closeIntentDigest = computeCloseIntentDigest(intent);
        pendingClose = PendingClose({
            active: true,
            closeNonce: intent.closeNonce,
            finalEpoch: intent.finalEpoch,
            finalSmallBlockNumber: intent.finalSmallBlockNumber,
            closeFreezeNonce: intent.closeFreezeNonce,
            challengeDeadline: uint64(block.timestamp + challengePeriod),
            closeIntentDigest: closeIntentDigest,
            finalChannelStateDigest: intent.finalChannelStateDigest,
            finalChannelBalanceRoot: intent.finalChannelBalanceRoot,
            channelFundAmount: intent.channelFundAmount,
            channelFundIntmaxStateRoot: intent.channelFundIntmaxStateRoot,
            burnTxHash: intent.burnTxHash,
            closeWithdrawalDigest: intent.closeWithdrawalDigest,
            snapshotMediumBlockNumber: intent.snapshotMediumBlockNumber
        });

        emit CloseSubmitted(
            closeIntentDigest,
            intent.burnTxHash,
            intent.closeNonce,
            intent.finalEpoch,
            intent.closeFreezeNonce,
            intent.channelFundAmount,
            pendingClose.challengeDeadline
        );
    }

    function submitSpecialClose(
        SpecialClose calldata specialClose,
        bytes calldata proof
    ) external {
        if (channelStatus != ChannelLifecycleStatus.Active) revert ChannelAlreadyFrozen();
        if (specialClose.offendingBpKeyId != bpKeyId) revert InvalidBpForSpecialClose();
        if (
            specialClose.latestFinalizedMediumBlockNumber <
            specialClose.signedMediumBlockNumber + 5
        ) revert InvalidSpecialCloseWindow();
        if (
            !verifier.verifySpecialClose(
                channelId,
                specialClose.offendingBpKeyId,
                specialClose.fullySignedSmallBlockRoot,
                specialClose.smallBlockNumber,
                specialClose.signedMediumBlockNumber,
                specialClose.latestFinalizedMediumBlockNumber,
                proof
            )
        ) revert InvalidSpecialCloseProof();

        currentCloseFreezeNonce += 1;
        channelStatus = ChannelLifecycleStatus.ClosePending;
        uint256 slashedAmount = specialClosePenalty;
        if (slashedAmount > bpBondCredits) {
            slashedAmount = bpBondCredits;
        }
        bpBondCredits -= slashedAmount;
        withdrawalCredits[msg.sender] += slashedAmount;

        latestSpecialCloseDigest = computeSpecialCloseDigest(specialClose);
        emit SpecialCloseSubmitted(
            latestSpecialCloseDigest,
            specialClose.offendingBpKeyId,
            specialClose.fullySignedSmallBlockRoot,
            specialClose.smallBlockNumber,
            slashedAmount,
            currentCloseFreezeNonce
        );
    }

    function cancelClose(
        CancelCloseRequest calldata request,
        bytes calldata proof
    ) external {
        if (!pendingClose.active) revert CloseNotActive();
        if (request.closeIntentDigest != pendingClose.closeIntentDigest) {
            revert CloseIntentDigestMismatch();
        }
        if (
            !verifier.verifyCancelClose(
                channelId,
                request.closeIntentDigest,
                request.revivedSmallBlockRoot,
                request.revivedInterChannelTxDigest,
                request.revivedTxHash,
                request.revivedSeal,
                proof
            )
        ) revert InvalidCancelProof();

        bytes32 closeIntentDigest = pendingClose.closeIntentDigest;
        delete pendingClose;
        channelStatus = ChannelLifecycleStatus.Active;
        emit CloseCancelled(
            closeIntentDigest,
            request.revivedTxHash,
            request.revivedSeal
        );
    }

    function submitLateOutgoingDebitCorrection(
        LateOutgoingDebitCorrection calldata correction,
        bytes calldata proof
    ) external {
        if (!pendingClose.active) revert CloseNotActive();
        if (correction.closeIntentDigest != pendingClose.closeIntentDigest) {
            revert CloseIntentDigestMismatch();
        }
        if (usedLateOutgoingDebitNullifiers[correction.debitNullifier]) {
            revert NullifierAlreadyUsed();
        }
        if (
            !verifier.verifyLateOutgoingDebit(
                channelId,
                correction.closeIntentDigest,
                correction.sourceTxHash,
                correction.senderUserId,
                correction.senderAmountDigest,
                correction.debitNullifier,
                correction.amount,
                proof
            )
        ) revert InvalidLateOutgoingDebitProof();

        usedLateOutgoingDebitNullifiers[correction.debitNullifier] = true;
        bytes32 closeIntentDigest = pendingClose.closeIntentDigest;
        delete pendingClose;
        channelStatus = ChannelLifecycleStatus.Active;

        emit LateOutgoingDebitAccepted(
            closeIntentDigest,
            correction.sourceTxHash,
            correction.debitNullifier,
            correction.amount
        );
    }

    function finalizeClose() external {
        if (!pendingClose.active) revert CloseNotActive();
        if (block.timestamp < pendingClose.challengeDeadline) {
            revert ChallengeWindowOpen();
        }

        finalizedCloseIntentDigest = pendingClose.closeIntentDigest;
        finalizedChannelStateDigest = pendingClose.finalChannelStateDigest;
        finalizedChannelBalanceRoot = pendingClose.finalChannelBalanceRoot;
        finalizedBurnTxHash = pendingClose.burnTxHash;
        finalizedCloseWithdrawalDigest = pendingClose.closeWithdrawalDigest;
        finalizedChannelFundIntmaxStateRoot = pendingClose.channelFundIntmaxStateRoot;
        finalizedEpoch = pendingClose.finalEpoch;
        finalizedSmallBlockNumber = pendingClose.finalSmallBlockNumber;
        finalizedChannelFundAmount = pendingClose.channelFundAmount;
        totalWithdrawn = 0;
        channelStatus = ChannelLifecycleStatus.Closed;

        emit CloseFinalized(
            pendingClose.closeIntentDigest,
            pendingClose.burnTxHash,
            pendingClose.finalEpoch,
            pendingClose.channelFundAmount
        );

        delete pendingClose;
    }

    function submitWithdrawalClaim(
        WithdrawalClaim calldata claim,
        bytes calldata proof
    ) external {
        if (channelStatus != ChannelLifecycleStatus.Closed) revert CloseNotActive();
        if (claim.closeIntentDigest != finalizedCloseIntentDigest) {
            revert CloseIntentDigestMismatch();
        }
        if (registeredRecipientOf[claim.userId] != claim.recipient) {
            revert RecipientMismatch();
        }
        if (usedWithdrawalNullifiers[claim.withdrawalNullifier]) {
            revert NullifierAlreadyUsed();
        }
        if (
            !verifier.verifyWithdrawalClaim(
                channelId,
                claim.closeIntentDigest,
                finalizedChannelBalanceRoot,
                claim.userId,
                claim.recipient,
                claim.userAmountDigest,
                claim.amount,
                claim.withdrawalNullifier,
                proof
            )
        ) revert InvalidWithdrawalClaimProof();

        uint256 newTotalWithdrawn = totalWithdrawn + claim.amount;
        if (newTotalWithdrawn > finalizedChannelFundAmount) {
            revert WithdrawalCapExceeded();
        }
        totalWithdrawn = newTotalWithdrawn;
        usedWithdrawalNullifiers[claim.withdrawalNullifier] = true;
        withdrawalCredits[claim.recipient] += claim.amount;

        emit WithdrawalClaimAccepted(
            claim.closeIntentDigest,
            claim.withdrawalNullifier,
            claim.userId,
            claim.recipient,
            claim.amount
        );
    }

    function submitPostCloseClaim(
        PostCloseClaim calldata claim,
        bytes calldata proof
    ) external {
        if (channelStatus != ChannelLifecycleStatus.Closed) revert CloseNotActive();
        if (claim.closeIntentDigest != finalizedCloseIntentDigest) {
            revert CloseIntentDigestMismatch();
        }
        if (registeredRecipientOf[claim.receiverUserId] != claim.recipient) {
            revert RecipientMismatch();
        }
        if (usedSharedNativeNullifiers[claim.sharedNativeNullifier]) {
            revert NullifierAlreadyUsed();
        }
        if (
            !verifier.verifyPostCloseClaim(
                channelId,
                claim.closeIntentDigest,
                claim.incomingTxHash,
                claim.receiverUserId,
                claim.recipient,
                claim.receiverAmountDigest,
                claim.sharedNativeNullifier,
                claim.amount,
                proof
            )
        ) revert InvalidPostCloseClaimProof();

        usedSharedNativeNullifiers[claim.sharedNativeNullifier] = true;
        withdrawalCredits[claim.recipient] += claim.amount;
        emit PostCloseClaimAccepted(
            claim.closeIntentDigest,
            claim.sharedNativeNullifier,
            claim.receiverUserId,
            claim.recipient,
            claim.amount
        );
    }

    function claimWithdrawalCredit() external returns (uint256 amount) {
        amount = withdrawalCredits[msg.sender];
        if (amount == 0) revert NoWithdrawalCredit();
        withdrawalCredits[msg.sender] = 0;
        emit WithdrawalClaimed(msg.sender, amount);
    }

    function getPendingClose() external view returns (PendingClose memory) {
        return pendingClose;
    }

    function computeCloseIntentDigest(
        CloseIntent memory intent
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(0x494d4349),
                channelId,
                intent.closeNonce,
                intent.finalEpoch,
                intent.finalSmallBlockNumber,
                intent.closeFreezeNonce,
                intent.finalChannelStateDigest,
                intent.finalChannelBalanceRoot,
                channelId,
                intent.channelFundAmount,
                intent.channelFundIntmaxStateRoot,
                intent.burnTxHash,
                intent.closeWithdrawalDigest,
                intent.snapshotMediumBlockNumber
            )
        );
    }

    function computeSpecialCloseDigest(
        SpecialClose memory specialClose
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(0x494d5343),
                channelId,
                specialClose.offendingBpKeyId,
                specialClose.fullySignedSmallBlockRoot,
                specialClose.smallBlockNumber,
                specialClose.signedMediumBlockNumber,
                specialClose.latestFinalizedMediumBlockNumber
            )
        );
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
                intent.finalSmallBlockNumber,
                intent.closeFreezeNonce,
                intent.finalChannelStateDigest,
                intent.finalChannelBalanceRoot,
                intent.channelFundAmount,
                intent.channelFundIntmaxStateRoot,
                intent.burnTxHash,
                intent.closeWithdrawalDigest,
                intent.snapshotMediumBlockNumber,
                proof
            )
        ) revert InvalidCloseProof();
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

    function _userChannelId(bytes10 userId) internal pure returns (bytes5) {
        return bytes5(userId);
    }
}
