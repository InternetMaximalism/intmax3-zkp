// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IChannelSettlementVerifier {
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
    ) external pure returns (bool);

    function verifySpecialClose(
        bytes4 channelId,
        bytes4 offendingBpKeyId,
        bytes32 fullySignedSmallBlockRoot,
        uint64 smallBlockNumber,
        uint64 signedMediumBlockNumber,
        uint64 latestFinalizedMediumBlockNumber,
        bytes calldata proof
    ) external pure returns (bool);

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
    ) external pure returns (bool);

    function verifyCancelClose(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 revivedSmallBlockRoot,
        bytes32 revivedInterChannelTxDigest,
        bytes32 revivedTxHash,
        bytes32 revivedSeal,
        bytes calldata proof
    ) external pure returns (bool);

    function verifyPostCloseClaim(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes8 receiverUserId,
        address recipient,
        bytes32 sharedNativeNullifier,
        uint64 amount,
        bytes calldata proof
    ) external pure returns (bool);

    function verifyLateOutgoingDebit(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 sourceTxHash,
        bytes8 senderUserId,
        bytes32 senderAmountDigest,
        bytes32 debitNullifier,
        uint64 amount,
        bytes calldata proof
    ) external pure returns (bool);
}

contract ChannelSettlementManager {
    error InvalidChannelId();
    error InvalidBpKeyId();
    error InvalidChallengePeriod();
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
    error NotChannelMember();
    error CloseNotRequested();
    error GracePeriodNotElapsed();

    enum ChannelLifecycleStatus {
        Active,
        ClosePending,
        Closed
    }

    event CloseRequested(
        address indexed requester,
        uint64 closeRequestedAt,
        uint64 closeFreezeNonce
    );

    event CloseSubmitted(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed burnTxHash,
        uint64 indexed closeNonce,
        uint64 finalEpoch,
        uint64 closeFreezeNonce,
        uint256 channelFundAmount,
        uint64 challengeDeadline,
        uint64 finalStateVersion,
        bytes32 finalSettledTxChain
    );

    event SpecialCloseSubmitted(
        bytes32 indexed specialCloseDigest,
        bytes4 indexed offendingBpKeyId,
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
        uint256 channelFundAmount,
        uint64 finalStateVersion,
        bytes32 finalSettledTxChain
    );

    event WithdrawalClaimAccepted(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed withdrawalNullifier,
        bytes8 indexed userId,
        address recipient,
        uint256 amount
    );

    event PostCloseClaimAccepted(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed sharedNativeNullifier,
        bytes8 indexed receiverUserId,
        address recipient,
        uint256 amount
    );

    event WithdrawalClaimed(address indexed recipient, uint256 amount);

    /// @dev Mirror of Rust `CloseIntent` (src/common/channel.rs), minus the channel id (this
    /// contract is per-channel; `channelId` is the immutable).
    ///
    /// Chain-matching division of labor (abstract2 §3.5.2, detail2 §H-2): L1 only CARRIES and
    /// BINDS `finalSettledTxChain` (it is part of the IMCI digest and the close-proof public
    /// inputs). The semantic equality `balance_pis.settled_tx_chain ==
    /// close_pis.final_settled_tx_chain` — i.e. that the closing balance state really settled
    /// exactly this tx chain — is enforced INSIDE the plonky2 close circuit (P7), not here.
    struct CloseIntent {
        uint64 closeNonce;
        uint64 finalEpoch;
        uint64 finalSmallBlockNumber;
        uint64 closeFreezeNonce;
        bytes32 finalChannelStateDigest;
        /// `h1()` of the final hidden `BalanceState` (rename of the legacy
        /// `finalChannelBalanceRoot`; detail2 §C-3).
        bytes32 finalBalanceStateH1;
        uint256 channelFundAmount;
        bytes32 channelFundIntmaxStateRoot;
        bytes32 burnTxHash;
        bytes32 closeWithdrawalDigest;
        uint64 snapshotMediumBlockNumber;
        /// `state_version` of the final balance state — challenge ordering compares
        /// `(finalEpoch, finalStateVersion)` (detail2 §H-4).
        uint64 finalStateVersion;
        /// `settled_tx_chain` of the final balance state (detail2 §H-2; see the struct doc).
        bytes32 finalSettledTxChain;
    }

    struct SpecialClose {
        bytes4 offendingBpKeyId;
        bytes32 fullySignedSmallBlockRoot;
        uint64 smallBlockNumber;
        uint64 signedMediumBlockNumber;
        uint64 latestFinalizedMediumBlockNumber;
    }

    struct MemberBinding {
        bytes8 userId;
        address recipient;
    }

    struct WithdrawalClaim {
        bytes32 closeIntentDigest;
        bytes8 userId;
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
        bytes8 receiverUserId;
        address recipient;
        bytes32 sharedNativeNullifier;
        uint64 amount;
    }

    struct LateOutgoingDebitCorrection {
        bytes32 closeIntentDigest;
        bytes32 sourceTxHash;
        bytes8 senderUserId;
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
        bytes32 finalBalanceStateH1;
        uint256 channelFundAmount;
        bytes32 channelFundIntmaxStateRoot;
        bytes32 burnTxHash;
        bytes32 closeWithdrawalDigest;
        uint64 snapshotMediumBlockNumber;
        uint64 finalStateVersion;
        bytes32 finalSettledTxChain;
    }

    /// @notice Grace period between `requestClose()` and the first `submitCloseIntent` of the
    /// frozen era (abstract2 §2.5: "10 minutes after the freeze request is when the close
    /// process can start").
    ///
    /// SECURITY: the grace window guarantees every member observes the freeze (no further
    /// `isNativeSendAllowed` sends) and has time to gossip its newest signed state BEFORE any
    /// close intent can be recorded. Without it, the requester could freeze and immediately
    /// submit a stale state, racing honest members' newer versions.
    uint64 public constant GRACE_BEFORE_PROCESS_SECS = 600;

    /// @notice Reference challenge period (abstract2 §3.5: 1 day). The constructor argument is
    /// kept for test configurability but MUST be nonzero.
    uint64 public constant CHALLENGE_PERIOD_SECS = 86_400;

    bytes4 public immutable channelId;
    bytes4 public immutable bpKeyId;
    uint64 public immutable challengePeriod;
    uint256 public immutable specialClosePenalty;
    IChannelSettlementVerifier public immutable verifier;

    ChannelLifecycleStatus public channelStatus;
    uint64 public currentCloseFreezeNonce;
    uint64 public closeRequestedAt;
    uint256 public bpBondCredits;

    PendingClose public pendingClose;
    bytes32 public latestSpecialCloseDigest;
    bytes32 public finalizedCloseIntentDigest;
    bytes32 public finalizedChannelStateDigest;
    bytes32 public finalizedBalanceStateH1;
    bytes32 public finalizedBurnTxHash;
    bytes32 public finalizedCloseWithdrawalDigest;
    bytes32 public finalizedChannelFundIntmaxStateRoot;
    bytes32 public finalizedSettledTxChain;
    uint64 public finalizedEpoch;
    uint64 public finalizedSmallBlockNumber;
    uint64 public finalizedStateVersion;
    uint256 public finalizedChannelFundAmount;
    uint256 public totalWithdrawn;

    mapping(address => uint256) public withdrawalCredits;
    mapping(bytes32 => bool) public usedWithdrawalNullifiers;
    mapping(bytes32 => bool) public usedSharedNativeNullifiers;
    mapping(bytes32 => bool) public usedLateOutgoingDebitNullifiers;
    mapping(bytes8 => address) public registeredRecipientOf;
    mapping(bytes8 => uint256) public registeredMemberIndexPlusOne;
    mapping(address => bool) public isMemberRecipient;
    bytes8[] public registeredUserIds;

    constructor(
        bytes4 channelId_,
        bytes4 bpKeyId_,
        uint64 challengePeriod_,
        uint256 specialClosePenalty_,
        uint256 initialBpBondCredits_,
        IChannelSettlementVerifier verifier_,
        MemberBinding[] memory memberBindings
    ) {
        if (channelId_ == bytes4(0)) revert InvalidChannelId();
        if (bpKeyId_ == bytes4(0)) revert InvalidBpKeyId();
        // SECURITY: a zero challenge period would let any pending close finalize in the same
        // block, voiding the whole challenge game.
        if (challengePeriod_ == 0) revert InvalidChallengePeriod();

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
                binding.userId == bytes8(0) ||
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
            isMemberRecipient[binding.recipient] = true;
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

    /// @notice Step 1 of the two-step close (abstract2 §3.5): a registered member freezes the
    /// channel. The first close intent can only be processed after
    /// `GRACE_BEFORE_PROCESS_SECS`.
    function requestClose() external {
        if (channelStatus == ChannelLifecycleStatus.Closed) revert ChannelClosed();
        if (channelStatus != ChannelLifecycleStatus.Active) revert ChannelAlreadyFrozen();
        if (!isMemberRecipient[msg.sender]) revert NotChannelMember();

        currentCloseFreezeNonce += 1;
        channelStatus = ChannelLifecycleStatus.ClosePending;
        closeRequestedAt = uint64(block.timestamp);
        emit CloseRequested(msg.sender, closeRequestedAt, currentCloseFreezeNonce);
    }

    /// @notice Step 2 of the two-step close: record (or challenge-replace) a close intent.
    /// Direct submission from `Active` is disallowed — `requestClose()` must run first
    /// (abstract2 §3.5).
    function submitCloseIntent(
        CloseIntent calldata intent,
        bytes calldata proof
    ) external {
        if (channelStatus == ChannelLifecycleStatus.Closed) revert ChannelClosed();
        _checkCloseProof(intent, proof);

        if (pendingClose.active) {
            // Challenge path: a newer signed state replaces the pending one.
            //
            // SECURITY: the grace period deliberately does NOT apply here — challenges race the
            // fixed `challengeDeadline`, and re-imposing the grace delay would shrink the
            // effective challenge window for honest members holding a newer state.
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
                // Two-step close (abstract2 §3.5): the freeze must be requested first.
                revert CloseNotRequested();
            }
            // First intent of the frozen era: the grace window must have elapsed so all
            // members had time to observe the freeze and surface their newest state.
            if (block.timestamp < uint256(closeRequestedAt) + GRACE_BEFORE_PROCESS_SECS) {
                revert GracePeriodNotElapsed();
            }
            if (intent.closeFreezeNonce != currentCloseFreezeNonce) {
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
            finalBalanceStateH1: intent.finalBalanceStateH1,
            channelFundAmount: intent.channelFundAmount,
            channelFundIntmaxStateRoot: intent.channelFundIntmaxStateRoot,
            burnTxHash: intent.burnTxHash,
            closeWithdrawalDigest: intent.closeWithdrawalDigest,
            snapshotMediumBlockNumber: intent.snapshotMediumBlockNumber,
            finalStateVersion: intent.finalStateVersion,
            finalSettledTxChain: intent.finalSettledTxChain
        });

        emit CloseSubmitted(
            closeIntentDigest,
            intent.burnTxHash,
            intent.closeNonce,
            intent.finalEpoch,
            intent.closeFreezeNonce,
            intent.channelFundAmount,
            pendingClose.challengeDeadline,
            intent.finalStateVersion,
            intent.finalSettledTxChain
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
        // A special close IS a freeze request: the first close intent of this frozen era is
        // subject to the same grace window as a member-requested close.
        closeRequestedAt = uint64(block.timestamp);
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
        // Restoring Active ends the frozen era; a future close needs a fresh requestClose()
        // (and therefore a fresh grace window).
        closeRequestedAt = 0;
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
        // Restoring Active ends the frozen era (see cancelClose).
        closeRequestedAt = 0;

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
        finalizedBalanceStateH1 = pendingClose.finalBalanceStateH1;
        finalizedBurnTxHash = pendingClose.burnTxHash;
        finalizedCloseWithdrawalDigest = pendingClose.closeWithdrawalDigest;
        finalizedChannelFundIntmaxStateRoot = pendingClose.channelFundIntmaxStateRoot;
        finalizedSettledTxChain = pendingClose.finalSettledTxChain;
        finalizedEpoch = pendingClose.finalEpoch;
        finalizedSmallBlockNumber = pendingClose.finalSmallBlockNumber;
        finalizedStateVersion = pendingClose.finalStateVersion;
        finalizedChannelFundAmount = pendingClose.channelFundAmount;
        totalWithdrawn = 0;
        channelStatus = ChannelLifecycleStatus.Closed;
        closeRequestedAt = 0;

        emit CloseFinalized(
            pendingClose.closeIntentDigest,
            pendingClose.burnTxHash,
            pendingClose.finalEpoch,
            pendingClose.channelFundAmount,
            pendingClose.finalStateVersion,
            pendingClose.finalSettledTxChain
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
                finalizedBalanceStateH1,
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

    /// @dev Byte-exact mirror of Rust `CloseIntent::signing_digest()` (src/common/channel.rs,
    /// IMCI domain): keccak over big-endian u32 words. `abi.encodePacked` of
    /// bytes4/uint64/bytes32/uint256 reproduces the BE word stream exactly. The second
    /// `channelId` is the Rust `channel_fund_snapshot.channel_id` slot (this contract pins both
    /// to its own channel). `finalStateVersion` and `finalSettledTxChain` are appended at the
    /// END of the legacy preimage (detail2 §C-8).
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
                intent.finalBalanceStateH1,
                channelId,
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
                intent.finalBalanceStateH1,
                intent.channelFundAmount,
                intent.channelFundIntmaxStateRoot,
                intent.burnTxHash,
                intent.closeWithdrawalDigest,
                intent.snapshotMediumBlockNumber,
                intent.finalStateVersion,
                intent.finalSettledTxChain,
                proof
            )
        ) revert InvalidCloseProof();
    }

    /// @dev Challenge ordering: lexicographic strict `(finalEpoch, finalStateVersion)`.
    ///
    /// SECURITY: within one epoch the channel layer guarantees at most ONE fully-signed
    /// balance state per `state_version` (OneStatePerVersion; ChannelSafety2.lean
    /// `challenge_latest_wins2`, detail2 §H-4), so "higher version" is well-defined and the
    /// honest member's newest state always wins a challenge. The tiebreak is STRICT `>` —
    /// re-submitting an equal `(epoch, version)` pair is rejected (`CloseNotNewer`), which
    /// prevents challenge-window extension by replaying the pending state.
    function _isNewer(
        CloseIntent calldata intent,
        PendingClose memory current
    ) internal pure returns (bool) {
        return
            intent.finalEpoch > current.finalEpoch ||
            (
                intent.finalEpoch == current.finalEpoch &&
                intent.finalStateVersion > current.finalStateVersion
            );
    }

    function _userChannelId(bytes8 userId) internal pure returns (bytes4) {
        return bytes4(userId);
    }
}
