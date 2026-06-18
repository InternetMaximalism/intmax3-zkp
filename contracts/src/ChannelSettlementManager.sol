// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MleVerifier} from "@mle/MleVerifier.sol";

/// @dev File-scope close-PI field bundle passed across the manager→verifier boundary as ONE
/// calldata struct. Collapsing the 14 close-intent scalars into a single argument keeps the
/// `verifyCloseIntent` external call under the via-IR stack-too-deep limit (the delegate-account
/// change pushed the previously-positional 17-arg signature over). The field set + order mirror the
/// Rust `CloseIntent` / close-PI vector exactly.
struct CloseProofFields {
    bytes4 channelId;
    uint64 closeNonce;
    uint64 finalEpoch;
    uint64 finalSmallBlockNumber;
    uint64 closeFreezeNonce;
    bytes32 finalChannelStateDigest;
    bytes32 finalBalanceStateH1;
    uint256 channelFundAmount;
    bytes32 channelFundIntmaxStateRoot;
    bytes32 burnTxHash;
    bytes32 closeWithdrawalDigest;
    uint64 snapshotMediumBlockNumber;
    uint64 finalStateVersion;
    bytes32 finalSettledTxChain;
    /// Stage 3: `settled_tx_accumulator_root` of the final balance state (inserted in the close PI
    /// vector immediately after `finalSettledTxChain`; rides in the signed H1, NOT in the
    /// close-intent digest preimage).
    bytes32 finalSettledTxAccumulatorRoot;
    bytes32 memberSetCommitment;
    /// Packed `(memberCount << 8) | delegateCount` (delegate account).
    uint16 memberAndDelegateCount;
}

interface IChannelSettlementVerifier {
    /// Phase A: the close intent is verified by a REAL MLE/WHIR proof of the plonky2 close circuit
    /// (not a stub). The proof is the wrapped close `MleVerifier.MleProof` whose `publicInputs` are
    /// the 87 raw close limbs the verifier rebinds. `view` (reads the close VK), not `pure`.
    function verifyCloseIntent(
        CloseProofFields calldata fields,
        MleVerifier.MleProof calldata proof
    ) external view returns (bool);

    function verifySpecialClose(
        bytes4 channelId,
        uint8 offendingBpMemberSlot,
        bytes32 offendingBpPkG,
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
        bytes32 memberPkG,
        address recipient,
        bytes32 userAmountDigest,
        uint64 amount,
        bytes32 withdrawalNullifier,
        MleVerifier.MleProof calldata mleProof
    ) external view returns (bool);

    /// Phase C1 (CORRECTED): cancelClose is verified by a REAL MLE/WHIR proof of the plonky2
    /// cancel-close circuit. `memberSetCommitment` is the channel's REGISTERED member-set
    /// commitment (injected by the manager, NOT a caller field — Finding D fix). `view` (reads the
    /// cancel VK), not `pure`.
    function verifyCancelClose(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 memberSetCommitment,
        uint64 revivedStateVersion,
        bytes32 revivedChannelStateDigest,
        MleVerifier.MleProof calldata mleProof
    ) external view returns (bool);

    function verifyPostCloseClaim(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverPkG,
        address recipient,
        bytes32 sharedNativeNullifier,
        uint64 amount,
        bytes32 finalBalanceStateH1,
        bytes32 finalSettledTxAccumulatorRoot,
        MleVerifier.MleProof calldata mleProof
    ) external view returns (bool);

    function verifyLateOutgoingDebit(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 sourceTxHash,
        bytes32 senderPkG,
        bytes32 senderAmountDigest,
        bytes32 debitNullifier,
        uint64 amount,
        bytes calldata proof
    ) external pure returns (bool);

    function closeMemberSetCommitment(
        bytes32[16] memory memberPkGs,
        uint8 memberCount
    ) external pure returns (bytes32);
}

/// @notice Read-only view of the rollup's per-channel registration (the SINGLE SOURCE OF TRUTH for
/// a channel's member set + block-proposer identity). Finding E: the close-path
/// `ChannelSettlementManager` binds its own member set + bp to these values in its constructor, so
/// the validity-path (registration) and close-path authenticate the SAME signer set. Satisfied by
/// `IntmaxRollup`'s public mappings `channelMemberSetCommitment`/`channelBpMemberSlot`/
/// `channelBpPkG`.
interface IChannelRegistry {
    function channelMemberSetCommitment(uint32 channelId) external view returns (bytes32);
    function channelBpMemberSlot(uint32 channelId) external view returns (uint8);
    function channelBpPkG(uint32 channelId) external view returns (bytes32);
    /// @notice Pull-payment claim on the rollup. The channel close pays the channel's native ETH
    ///         to THIS manager (recipient == manager) via `IntmaxRollup.withdrawNative`, crediting
    ///         the rollup's `pendingWithdrawals[manager]`; `pullChannelFunds` then calls this to
    ///         move that ETH into the manager so it can be split among members.
    function withdraw() external;
}

contract ChannelSettlementManager {
    /// One SPHINCS+ key per member (D6 pad-to-MAX): a channel has between 2 and
    /// `MAX_MEMBER_COUNT` ACTIVE members, identified by their SPHINCS+ pubkey hash (bytes32), slot
    /// order 0..memberCount. Slots `memberCount..MAX_MEMBER_COUNT` are zero padding. Mirrors the
    /// Rust `MAX_CHANNEL_MEMBERS` constant (src/constants.rs).
    uint256 internal constant MAX_MEMBER_COUNT = 16;
    uint256 internal constant MIN_MEMBER_COUNT = 2;

    error InvalidChannelId();
    error InvalidBpMemberSlot();
    error InvalidChallengePeriod();
    error InvalidMemberBinding();
    error DuplicateRegisteredMember();
    error InvalidMemberCount();
    /// Finding E: the manager's member set / bp does not equal the rollup's on-chain registration.
    error MemberSetMismatch();
    error BpMismatch();
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
    /// Only the bound rollup (`registry`) may send native ETH to this manager (via its `withdraw`).
    error OnlyRollup();
    /// A native ETH transfer out of the manager failed.
    error TransferFailed();
    /// Reentrancy guard tripped.
    error Reentrant();
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
        bytes32 indexed offendingBpPkG,
        bytes32 indexed fullySignedSmallBlockRoot,
        uint8 offendingBpMemberSlot,
        uint64 smallBlockNumber,
        uint256 slashedAmount,
        uint64 closeFreezeNonce
    );

    event CloseCancelled(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed revivedChannelStateDigest,
        uint64 revivedStateVersion
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
        bytes32 indexed memberPkG,
        address recipient,
        uint256 amount
    );

    event PostCloseClaimAccepted(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed sharedNativeNullifier,
        bytes32 indexed receiverPkG,
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
        /// Stage 3: `settled_tx_accumulator_root` of the final balance state. Carried + bound by the
        /// close proof (it is in the signed H1, hence the close PI vector), but NOT part of the
        /// close-intent digest preimage (the digest predates Stage 3). `finalizeClose` stores it as
        /// `finalizedSettledTxAccumulatorRoot`; `submitPostCloseClaim` passes it to the verifier.
        bytes32 finalSettledTxAccumulatorRoot;
    }

    struct SpecialClose {
        uint8 offendingBpMemberSlot;
        bytes32 offendingBpPkG;
        bytes32 fullySignedSmallBlockRoot;
        uint64 smallBlockNumber;
        uint64 signedMediumBlockNumber;
        uint64 latestFinalizedMediumBlockNumber;
    }

    /// F7: a member is identified by its SPHINCS+ pubkey hash (bytes32), no longer a `bytes8
    /// userId`. The recipient is the L1 withdrawal address for that member.
    struct MemberBinding {
        bytes32 pkG;
        address recipient;
    }

    struct WithdrawalClaim {
        bytes32 closeIntentDigest;
        bytes32 memberPkG;
        address recipient;
        bytes32 userAmountDigest;
        uint64 amount;
        bytes32 withdrawalNullifier;
    }

    /// Phase C1 (CORRECTED): a cancel proves the members N-of-N signed a HIGHER-version channel
    /// state (`revivedChannelStateDigest` at `revivedStateVersion > close.finalStateVersion`), so
    /// the pending close froze a stale state. The legacy revived-tx fields
    /// (revivedSmallBlockRoot/revivedInterChannelTxDigest/revivedTxHash/revivedSeal) are dropped.
    struct CancelCloseRequest {
        bytes32 closeIntentDigest;
        uint64 revivedStateVersion;
        bytes32 revivedChannelStateDigest;
    }

    /// @dev HAZARD #8 (Phase B-D): `sharedNativeNullifier` is NO LONGER a caller-supplied field —
    ///      the manager RECOMPUTES it from keccak(IMCK, closeIntentDigest, incomingTxHash,
    ///      receiverPkG) so the double-claim nullifier is a deterministic function of the claimed
    ///      tx (no attacker-chosen opaque value). The in-circuit derivation produces the SAME value
    ///      and the proof's PI is strict-bound to it.
    struct PostCloseClaim {
        bytes32 closeIntentDigest;
        bytes32 incomingTxHash;
        bytes32 receiverPkG;
        address recipient;
        uint64 amount;
    }

    /// "IMCK" — post-close shared-native nullifier domain. MUST equal Rust
    /// `POST_CLOSE_NULLIFIER_DOMAIN` (src/common/channel.rs) and the in-circuit constant so the
    /// recomputed nullifier matches the proof's bound PI byte-for-byte.
    uint32 internal constant POST_CLOSE_NULLIFIER_DOMAIN = 0x494d434b;

    /// @dev Recompute the post-close shared-native nullifier exactly as the Rust
    ///      `PostCloseIncomingClaim::derive_shared_native_nullifier` and the in-circuit keccak do:
    ///      keccak over the IMCK domain word + closeIntentDigest(8 u32) + incomingTxHash(8 u32) +
    ///      receiverPkG(8 u32). Each bytes32 is 8 big-endian u32 words, so `abi.encodePacked` of the
    ///      domain (bytes4) + the three bytes32 reproduces the preimage byte stream.
    function _deriveSharedNativeNullifier(
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverPkG
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(POST_CLOSE_NULLIFIER_DOMAIN),
                closeIntentDigest,
                incomingTxHash,
                receiverPkG
            )
        );
    }

    struct LateOutgoingDebitCorrection {
        bytes32 closeIntentDigest;
        bytes32 sourceTxHash;
        bytes32 senderPkG;
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
        /// Stage 3: the final balance state's settled-tx accumulator root (see `CloseIntent`).
        bytes32 finalSettledTxAccumulatorRoot;
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
    /// F7: the block-proposer member is identified by its slot (0..MEMBER_COUNT) and its SPHINCS+
    /// pubkey hash, replacing the legacy `bpKeyId`.
    uint8 public immutable bpMemberSlot;
    bytes32 public immutable bpPkG;
    uint64 public immutable challengePeriod;
    uint256 public immutable specialClosePenalty;
    IChannelSettlementVerifier public immutable verifier;

    /// @notice Finding E: the rollup registry holding this channel's authoritative member set + bp
    /// (the validity-path registration). The constructor asserts this manager's member set + bp
    /// EQUAL the registry's, making them PROVABLY the same signer set.
    /// DEPLOYMENT-INTEGRITY ASSUMPTION (review LOW-2): the equality guarantee holds only when
    /// `registry` is the real `IntmaxRollup` and `channelId` is the intended channel. Both are
    /// deployer-supplied constructor args with no on-chain back-link from the rollup. Integrators
    /// MUST verify `registry()` and `channelId()` on the deployed manager before funding a channel.
    IChannelRegistry public immutable registry;

    /// @notice The number of ACTIVE members (2..=MAX_MEMBER_COUNT). Mirrors the Rust
    /// `ChannelRecord.member_count` (src/common/channel.rs).
    uint8 public immutable activeMemberCount;

    /// @notice The number of DELEGATE participants (delegate account). Mirrors the Rust
    /// `ChannelRecord.delegate_count` / `BalanceState.delegate_count`. Delegates do NOT co-sign and
    /// are NOT part of `memberBindings`/`memberPkGs`/the IMCM commitment, but `delegateCount` is a
    /// committed limb in the close-proof public inputs (H1 binds it immediately after
    /// `memberCount`), so the manager must pin it to verify the close proof. Invariant:
    /// `activeMemberCount + activeDelegateCount <= MAX_MEMBER_COUNT`.
    uint8 public immutable activeDelegateCount;

    /// @notice The channel's registered member SPHINCS+ pubkey hashes in slot order, ZERO-padded to
    /// MAX_MEMBER_COUNT (D6 pad-to-MAX). Active slots (`< activeMemberCount`) are nonzero and
    /// pairwise-distinct; padding slots are zero. Mirrors the Rust
    /// `ChannelRecord.member_pk_gs` (src/common/channel.rs). The close proof is
    /// bound to exactly this set via the in-circuit `memberSetCommitment`.
    bytes32[MAX_MEMBER_COUNT] public memberPkGs;

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
    /// @notice Stage 3: the finalized close's settled-tx accumulator root — the source-tx inclusion
    /// anchor `submitPostCloseClaim` passes to the verifier (the post-close claim proves a Merkle
    /// inclusion of `incomingTxHash` against it).
    bytes32 public finalizedSettledTxAccumulatorRoot;
    uint64 public finalizedEpoch;
    uint64 public finalizedSmallBlockNumber;
    uint64 public finalizedStateVersion;
    /// @notice The channel-fund amount DECLARED by the finalized close intent. SECURITY: this is a
    ///         non-authoritative hint / secondary accrual bound only. The AUTHORITATIVE solvency cap
    ///         is `receivedChannelFunds` (real ETH pulled from the rollup), enforced at payout.
    uint256 public finalizedChannelFundAmount;
    /// @notice Σ of accepted withdrawal/post-close claim amounts (intent-level accrual bound).
    uint256 public totalWithdrawn;

    /// @notice Real native ETH this manager has pulled from the rollup for this channel's close
    ///         (cumulative `pullChannelFunds` balance deltas). SECURITY: this — NOT the intent's
    ///         declared `finalizedChannelFundAmount` — is the authoritative cross-channel solvency
    ///         ceiling: `claimWithdrawalCredit` enforces Σ paid out ≤ receivedChannelFunds, so the
    ///         manager can never pay members more ETH than the channel actually received on L1.
    uint256 public receivedChannelFunds;
    /// @notice Σ native ETH actually paid out via `claimWithdrawalCredit` (the payout-side cap base).
    uint256 public totalCreditedOut;

    mapping(address => uint256) public withdrawalCredits;
    mapping(bytes32 => bool) public usedWithdrawalNullifiers;
    mapping(bytes32 => bool) public usedSharedNativeNullifiers;
    mapping(bytes32 => bool) public usedLateOutgoingDebitNullifiers;
    /// F7: member identity is the SPHINCS+ pubkey hash (bytes32).
    mapping(bytes32 => address) public registeredRecipientOf;
    mapping(bytes32 => uint256) public registeredMemberIndexPlusOne;
    mapping(address => bool) public isMemberRecipient;
    bytes32[] public registeredMemberPkGs;

    /// @notice Emitted when real native ETH is pulled from the rollup into this manager.
    event ChannelFundsPulled(uint256 amount, uint256 totalReceived);

    // --- Reentrancy guard (the manager moves native ETH in pullChannelFunds/claimWithdrawalCredit) ---
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status = _NOT_ENTERED;

    modifier nonReentrant() {
        if (_status == _ENTERED) revert Reentrant();
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    /// @notice Accept native ETH ONLY from the bound rollup (its `withdraw()` pays this manager via
    ///         a low-level call). SECURITY: restricting the sender keeps `receivedChannelFunds`
    ///         (measured as the `pullChannelFunds` balance delta) the sole source of payout capacity
    ///         and prevents stray/forced ETH from being mistaken for real channel funds. (SELFDESTRUCT
    ///         force-feeds are still possible but are NOT counted — only `pullChannelFunds` deltas
    ///         increment `receivedChannelFunds`, and payouts are capped by it.)
    receive() external payable {
        if (msg.sender != address(registry)) revert OnlyRollup();
    }

    constructor(
        bytes4 channelId_,
        uint8 bpMemberSlot_,
        bytes32 bpPkG_,
        uint8 delegateCount_,
        uint64 challengePeriod_,
        uint256 specialClosePenalty_,
        uint256 initialBpBondCredits_,
        IChannelSettlementVerifier verifier_,
        IChannelRegistry registry_,
        MemberBinding[] memory memberBindings,
        // Delegate account: (pk_g -> recipient) bindings for the `delegateCount_` delegates. Empty
        // when delegateCount_ == 0. Delegates are registered for the WITHDRAWAL path only — they are
        // EXCLUDED from memberPkGs / the IMCM member-set commitment (they do not co-sign).
        MemberBinding[] memory delegateBindings
    ) {
        if (channelId_ == bytes4(0)) revert InvalidChannelId();
        // D6 pad-to-MAX: 2..=MAX_MEMBER_COUNT active members are registered, slot order. Slots
        // beyond `memberBindings.length` stay zero (padding).
        if (
            memberBindings.length < MIN_MEMBER_COUNT ||
            memberBindings.length > MAX_MEMBER_COUNT
        ) revert InvalidMemberCount();
        // F7: the block-proposer slot must be a valid ACTIVE member index, and its pubkey hash
        // nonzero. SECURITY: bpMemberSlot must be < the active member count (not just MAX), or a
        // padding slot could masquerade as the proposer.
        if (uint256(bpMemberSlot_) >= memberBindings.length) revert InvalidBpMemberSlot();
        if (bpPkG_ == bytes32(0)) revert InvalidBpMemberSlot();
        // SECURITY: a zero challenge period would let any pending close finalize in the same
        // block, voiding the whole challenge game.
        if (challengePeriod_ == 0) revert InvalidChallengePeriod();

        channelId = channelId_;
        bpMemberSlot = bpMemberSlot_;
        bpPkG = bpPkG_;
        challengePeriod = challengePeriod_;
        specialClosePenalty = specialClosePenalty_;
        bpBondCredits = initialBpBondCredits_;
        verifier = verifier_;
        registry = registry_;
        channelStatus = ChannelLifecycleStatus.Active;
        activeMemberCount = uint8(memberBindings.length);
        // Delegate account: members + delegates must fit in the fixed MAX_MEMBER_COUNT slots.
        if (uint256(memberBindings.length) + uint256(delegateCount_) > MAX_MEMBER_COUNT) {
            revert InvalidMemberCount();
        }
        activeDelegateCount = delegateCount_;

        for (uint256 i = 0; i < memberBindings.length; i++) {
            MemberBinding memory binding = memberBindings[i];
            if (
                binding.pkG == bytes32(0) ||
                binding.recipient == address(0)
            ) {
                revert InvalidMemberBinding();
            }
            if (registeredMemberIndexPlusOne[binding.pkG] != 0) {
                revert DuplicateRegisteredMember();
            }
            registeredRecipientOf[binding.pkG] = binding.recipient;
            registeredMemberIndexPlusOne[binding.pkG] =
                registeredMemberPkGs.length + 1;
            registeredMemberPkGs.push(binding.pkG);
            memberPkGs[i] = binding.pkG;
            isMemberRecipient[binding.recipient] = true;
        }
        // The block-proposer pubkey hash must be the member registered at its slot.
        if (memberPkGs[bpMemberSlot_] != bpPkG_) {
            revert InvalidBpMemberSlot();
        }

        // Delegate account: register delegate (pk_g -> recipient) bindings for the withdrawal path.
        // Extracted to its own frame (via-IR stack) and AFTER the member loop so delegate pk_g
        // distinctness is checked against members too. Delegates are NOT pushed to
        // registeredMemberPkGs / memberPkGs, so the IMCM member-set commitment stays member-only.
        _registerDelegates(delegateBindings);

        // Finding E: bind this manager's member set + bp to the rollup's on-chain registration (the
        // validity-path single source of truth). SECURITY: without this, the validity proof and the
        // close proof could authenticate DIFFERENT signer sets for the same channel. The close-form
        // IMCM commitment over the just-built `memberPkGs`/`activeMemberCount` MUST
        // equal the commitment the rollup recorded at `registerChannel` (computed with the SAME
        // fixed-16 keccak preimage), and the bp identity MUST match.
        //
        // DEPLOYMENT ORDER: `registerChannel(channelId, ...)` on the rollup MUST run BEFORE this
        // manager is deployed; otherwise the registry returns bytes32(0) and this reverts.
        uint32 channelIdU32 = uint32(channelId_);
        if (registeredMemberSetCommitment() != registry.channelMemberSetCommitment(channelIdU32)) {
            revert MemberSetMismatch();
        }
        if (
            bpMemberSlot_ != registry.channelBpMemberSlot(channelIdU32) ||
            bpPkG_ != registry.channelBpPkG(channelIdU32)
        ) {
            revert BpMismatch();
        }
    }

    /// @dev Register the delegate (pk_g -> recipient) bindings (delegate account). Delegates own a
    /// balance slot and withdraw their member-attested final balance via the SAME WithdrawalClaim a
    /// member uses, so their presence (`registeredMemberIndexPlusOne != 0`), recipient binding, and
    /// payout authorization (`isMemberRecipient`) must be recorded. SECURITY: a delegate pk_g must be
    /// distinct from every member AND every other delegate (the `!= 0` check covers both, since
    /// members are registered first); delegates are NOT added to `registeredMemberPkGs`/`memberPkGs`,
    /// so the IMCM member-set commitment and the N-of-N co-sign set stay member-only. The index value
    /// is only a non-zero presence marker (the active-slot index+1); it is never used as an array
    /// index. TRUST: delegate bindings are deployer-asserted (not re-checked against the registry
    /// IMCM, which is member-only) — consistent with DLG-2 (the delegate already trusts the members
    /// for its member-attested final balance).
    function _registerDelegates(MemberBinding[] memory delegateBindings) private {
        if (delegateBindings.length != activeDelegateCount) revert InvalidMemberCount();
        for (uint256 j = 0; j < delegateBindings.length; j++) {
            MemberBinding memory d = delegateBindings[j];
            if (d.pkG == bytes32(0) || d.recipient == address(0)) {
                revert InvalidMemberBinding();
            }
            if (registeredMemberIndexPlusOne[d.pkG] != 0) {
                revert DuplicateRegisteredMember();
            }
            registeredRecipientOf[d.pkG] = d.recipient;
            // Active-slot index+1 (members occupy 1..activeMemberCount): non-zero presence marker.
            registeredMemberIndexPlusOne[d.pkG] = uint256(activeMemberCount) + j + 1;
            isMemberRecipient[d.recipient] = true;
        }
    }

    function memberCount() external view returns (uint256) {
        return registeredMemberPkGs.length;
    }

    /// @notice The close-circuit member-set commitment for this channel's registered members
    /// (D6 pad-to-MAX FIXED form): keccak([IMCM, activeMemberCount, memberPkGs[0..15]])
    /// over ALL MAX_MEMBER_COUNT slots in slot order (padding zeroed). The close proof's in-circuit
    /// commitment MUST equal this value (enforced in `_checkCloseProof`), binding the verified
    /// signing keys to the registered member set (no non-member-key substitution).
    function registeredMemberSetCommitment() public view returns (bytes32) {
        return verifier.closeMemberSetCommitment(memberPkGs, activeMemberCount);
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
        MleVerifier.MleProof calldata proof
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
        // Isolated frame for the 15-field PendingClose build (via-IR stack limit).
        _storePendingClose(intent, closeIntentDigest);

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

    /// @dev Isolated frame for the 15-field PendingClose construction (keeps `submitCloseIntent`
    /// under the via-IR stack limit once the close path threads `delegateCount`).
    function _storePendingClose(
        CloseIntent calldata intent,
        bytes32 closeIntentDigest
    ) internal {
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
            finalSettledTxChain: intent.finalSettledTxChain,
            finalSettledTxAccumulatorRoot: intent.finalSettledTxAccumulatorRoot
        });
    }

    function submitSpecialClose(
        SpecialClose calldata specialClose,
        bytes calldata proof
    ) external {
        if (channelStatus != ChannelLifecycleStatus.Active) revert ChannelAlreadyFrozen();
        // F7: the offending proposer must be this channel's registered block-proposer (slot and
        // pubkey hash).
        if (
            specialClose.offendingBpMemberSlot != bpMemberSlot ||
            specialClose.offendingBpPkG != bpPkG
        ) revert InvalidBpForSpecialClose();
        if (
            specialClose.latestFinalizedMediumBlockNumber <
            specialClose.signedMediumBlockNumber + 5
        ) revert InvalidSpecialCloseWindow();
        if (
            !verifier.verifySpecialClose(
                channelId,
                specialClose.offendingBpMemberSlot,
                specialClose.offendingBpPkG,
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
            specialClose.offendingBpPkG,
            specialClose.fullySignedSmallBlockRoot,
            specialClose.offendingBpMemberSlot,
            specialClose.smallBlockNumber,
            slashedAmount,
            currentCloseFreezeNonce
        );
    }

    function cancelClose(
        CancelCloseRequest calldata request,
        MleVerifier.MleProof calldata proof
    ) external {
        if (!pendingClose.active) revert CloseNotActive();
        if (request.closeIntentDigest != pendingClose.closeIntentDigest) {
            revert CloseIntentDigestMismatch();
        }
        // SECURITY (Finding D): the manager injects the channel's REGISTERED member-set commitment
        // (NOT a caller request field), exactly as the close path does via `_runCloseVerify`. The
        // verifier strict-binds the proof's in-circuit member-set commitment to this value, so the
        // members who signed the higher-version revived state are the channel's registered members.
        if (
            !verifier.verifyCancelClose(
                channelId,
                request.closeIntentDigest,
                registeredMemberSetCommitment(),
                request.revivedStateVersion,
                request.revivedChannelStateDigest,
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
            request.revivedChannelStateDigest,
            request.revivedStateVersion
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
                correction.senderPkG,
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
        finalizedSettledTxAccumulatorRoot = pendingClose.finalSettledTxAccumulatorRoot;
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
        MleVerifier.MleProof calldata proof
    ) external {
        if (channelStatus != ChannelLifecycleStatus.Closed) revert CloseNotActive();
        if (claim.closeIntentDigest != finalizedCloseIntentDigest) {
            revert CloseIntentDigestMismatch();
        }
        // F7: the claiming member's pubkey hash must be a registered channel member, and the
        // recipient must match the registration.
        if (registeredMemberIndexPlusOne[claim.memberPkG] == 0) {
            revert NotChannelMember();
        }
        if (registeredRecipientOf[claim.memberPkG] != claim.recipient) {
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
                claim.memberPkG,
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
            claim.memberPkG,
            claim.recipient,
            claim.amount
        );
    }

    function submitPostCloseClaim(
        PostCloseClaim calldata claim,
        MleVerifier.MleProof calldata proof
    ) external {
        if (channelStatus != ChannelLifecycleStatus.Closed) revert CloseNotActive();
        if (claim.closeIntentDigest != finalizedCloseIntentDigest) {
            revert CloseIntentDigestMismatch();
        }
        if (registeredMemberIndexPlusOne[claim.receiverPkG] == 0) {
            revert NotChannelMember();
        }
        if (registeredRecipientOf[claim.receiverPkG] != claim.recipient) {
            revert RecipientMismatch();
        }
        // HAZARD #8: RECOMPUTE the shared-native nullifier (it is NOT a caller-supplied field). The
        // in-circuit derivation uses the SAME keccak preimage and the proof's PI is strict-bound to
        // it, so the value passed to the verifier is the one the proof actually committed.
        bytes32 sharedNativeNullifier = _deriveSharedNativeNullifier(
            claim.closeIntentDigest,
            claim.incomingTxHash,
            claim.receiverPkG
        );
        if (usedSharedNativeNullifiers[sharedNativeNullifier]) {
            revert NullifierAlreadyUsed();
        }
        if (
            !verifier.verifyPostCloseClaim(
                channelId,
                claim.closeIntentDigest,
                claim.incomingTxHash,
                claim.receiverPkG,
                claim.recipient,
                sharedNativeNullifier,
                claim.amount,
                // Stage 3: the finalized receiver-pk-bind anchor (H1) + source-tx inclusion anchor
                // (accumulator root). The in-circuit recompute + Merkle inclusion are bound to these.
                finalizedBalanceStateH1,
                finalizedSettledTxAccumulatorRoot,
                proof
            )
        ) revert InvalidPostCloseClaimProof();

        // Cap accrual against the (intent-declared) channel fund, mirroring submitWithdrawalClaim.
        // SECURITY: post-close claims share the SAME accrual budget as withdrawal claims — without
        // this, post-close claims could mint unbounded credits past the channel fund. (The
        // authoritative ETH ceiling is still `receivedChannelFunds`, enforced at payout.)
        uint256 newTotalWithdrawn = totalWithdrawn + claim.amount;
        if (newTotalWithdrawn > finalizedChannelFundAmount) {
            revert WithdrawalCapExceeded();
        }
        totalWithdrawn = newTotalWithdrawn;
        usedSharedNativeNullifiers[sharedNativeNullifier] = true;
        withdrawalCredits[claim.recipient] += claim.amount;
        emit PostCloseClaimAccepted(
            claim.closeIntentDigest,
            sharedNativeNullifier,
            claim.receiverPkG,
            claim.recipient,
            claim.amount
        );
    }

    /// @notice Pull this channel's native ETH from the rollup into the manager. Permissionless: it
    ///         only moves the manager's own `pendingWithdrawals[manager]` (credited when the close
    ///         paid this manager via `IntmaxRollup.withdrawNative`). The balance delta is added to
    ///         `receivedChannelFunds` — the authoritative payout ceiling.
    /// @dev nonReentrant; measures balance before/after the external `registry.withdraw()` call.
    function pullChannelFunds() external nonReentrant returns (uint256 pulled) {
        uint256 balBefore = address(this).balance;
        registry.withdraw(); // rollup pays pendingWithdrawals[manager] to this contract (receive())
        pulled = address(this).balance - balBefore;
        receivedChannelFunds += pulled;
        emit ChannelFundsPulled(pulled, receivedChannelFunds);
    }

    /// @notice Claim a member's accrued credit as real native ETH (pull-payment).
    /// @dev SECURITY: the GLOBAL cross-channel solvency invariant is enforced HERE —
    ///      `totalCreditedOut + amount <= receivedChannelFunds` — so the manager can never pay out
    ///      more ETH than it actually received from the rollup for this channel, regardless of any
    ///      inflated intent or intra-channel mis-accounting (those are accepted intra-channel risks).
    ///      CEI: credit zeroed + paid-out accumulator bumped BEFORE the external transfer;
    ///      nonReentrant for defense in depth.
    function claimWithdrawalCredit() external nonReentrant returns (uint256 amount) {
        amount = withdrawalCredits[msg.sender];
        if (amount == 0) revert NoWithdrawalCredit();
        if (totalCreditedOut + amount > receivedChannelFunds) revert WithdrawalCapExceeded();
        withdrawalCredits[msg.sender] = 0;
        totalCreditedOut += amount;
        emit WithdrawalClaimed(msg.sender, amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    function getPendingClose() external view returns (PendingClose memory) {
        return pendingClose;
    }

    /// @dev Byte-exact mirror of Rust `CloseIntent::signing_digest()` (src/common/channel.rs,
    /// IMCI domain): keccak over big-endian u32 words. `abi.encodePacked` of
    /// bytes4/uint64/bytes32/uint256 reproduces the BE word stream exactly. The second
    /// `channelId` is the Rust `channel_fund_snapshot.channel_id` slot (this contract pins both
    /// to its own channel). `finalStateVersion` and `finalSettledTxChain` are appended at the
    /// END of the legacy preimage (detail2 §C-8). F7: unchanged (not member-bearing).
    function computeCloseIntentDigest(
        CloseIntent memory intent
    ) public view returns (bytes32) {
        // Built in two concatenated chunks so via-IR can free the intermediate field slots
        // (stack-too-deep otherwise after the close path threads delegateCount elsewhere). The byte
        // stream is identical to a single abi.encodePacked of all limbs in order.
        return keccak256(
            bytes.concat(
                abi.encodePacked(
                    bytes4(0x494d4349),
                    channelId,
                    intent.closeNonce,
                    intent.finalEpoch,
                    intent.finalSmallBlockNumber,
                    intent.closeFreezeNonce,
                    intent.finalChannelStateDigest,
                    intent.finalBalanceStateH1
                ),
                abi.encodePacked(
                    channelId,
                    intent.channelFundAmount,
                    intent.channelFundIntmaxStateRoot,
                    intent.burnTxHash,
                    intent.closeWithdrawalDigest,
                    intent.snapshotMediumBlockNumber,
                    intent.finalStateVersion,
                    intent.finalSettledTxChain
                )
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
                uint32(specialClose.offendingBpMemberSlot),
                specialClose.offendingBpPkG,
                specialClose.fullySignedSmallBlockRoot,
                specialClose.smallBlockNumber,
                specialClose.signedMediumBlockNumber,
                specialClose.latestFinalizedMediumBlockNumber
            )
        );
    }

    function _checkCloseProof(
        CloseIntent calldata intent,
        MleVerifier.MleProof calldata proof
    ) internal view {
        // F4/F7 SECURITY: the close proof's in-circuit `memberSetCommitment` must equal this
        // channel's registered member-set commitment, AND the close proof's `memberCount` /
        // `delegateCount` limbs must equal this channel's `activeMemberCount` / `activeDelegateCount`,
        // so a close can only finalize with the channel's registered SPHINCS+ members at the
        // registered member/delegate split (no non-member-key substitution, no active/padding- or
        // member/delegate-boundary forgery). All are part of the close-proof public inputs
        // (closePIHash, 87 limbs incl. the appended delegateCount).
        if (!_runCloseVerify(intent, proof)) revert InvalidCloseProof();
    }

    /// @dev Isolated frame for the 17-arg `verifyCloseIntent` marshaling (keeps `_checkCloseProof`
    /// and `submitCloseIntent` under the via-IR stack limit once `delegateCount` is appended).
    function _runCloseVerify(
        CloseIntent calldata intent,
        MleVerifier.MleProof calldata proof
    ) internal view returns (bool) {
        CloseProofFields memory fields = CloseProofFields({
            channelId: channelId,
            closeNonce: intent.closeNonce,
            finalEpoch: intent.finalEpoch,
            finalSmallBlockNumber: intent.finalSmallBlockNumber,
            closeFreezeNonce: intent.closeFreezeNonce,
            finalChannelStateDigest: intent.finalChannelStateDigest,
            finalBalanceStateH1: intent.finalBalanceStateH1,
            channelFundAmount: intent.channelFundAmount,
            channelFundIntmaxStateRoot: intent.channelFundIntmaxStateRoot,
            burnTxHash: intent.burnTxHash,
            closeWithdrawalDigest: intent.closeWithdrawalDigest,
            snapshotMediumBlockNumber: intent.snapshotMediumBlockNumber,
            finalStateVersion: intent.finalStateVersion,
            finalSettledTxChain: intent.finalSettledTxChain,
            // Stage 3: the accumulator root is a close PI limb (in the signed H1); the close proof's
            // strict limb bind rejects a submitted value != the real signed one.
            finalSettledTxAccumulatorRoot: intent.finalSettledTxAccumulatorRoot,
            memberSetCommitment: registeredMemberSetCommitment(),
            // Delegate account: pack the two registered counts into the uint16 the verifier expects.
            memberAndDelegateCount: (uint16(activeMemberCount) << 8) | uint16(activeDelegateCount)
        });
        return verifier.verifyCloseIntent(fields, proof);
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
}
