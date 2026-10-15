// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20, SafeERC20Lib} from "./SafeERC20.sol";
import {IPinnedMleVerifierV2} from "./IPinnedMleVerifierV2.sol";

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
    /// Multi-token (§N-6, TM-11): the full registry-aligned per-token fund vector, ALWAYS full
    /// width (zero-padded past `tokenCount`). Replaces the single `channelFundAmount`; slot 0 (the
    /// genesis token) is the burn denomination and feeds the `channelFundAmount` close-PI limbs.
    /// Together with `tokenRegistry` / `tokenCount`, the 80-word segment is bound through the
    /// member-signed IMCH and close PI `tokenFundsDigest` limbs (verifier recompute).
    uint256[10] channelFundAmounts;
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
    /// The channel's registered ACTIVE COSIGNER count. STRICT-equality-bound to close-PI limb 93 —
    /// see `ChannelSettlementVerifier._expectedCloseLimbs` (B-2 A-6: this one is non-negotiable).
    uint8 memberCount;
    /// Floor for close-PI limb 94: the verifier requires `limb94 >= minDelegateCount`. Delegates may join after deployment (appended, never removed),
    /// so a larger proven count is a legitimate later state.
    /// Widened from the old packed `uint8` half so counts above 255 remain representable.
    uint32 minDelegateCount;
    /// Multi-token (§N-6): channel-local slot t → BASE token index, zero-padded past `tokenCount`.
    /// Bound (with `tokenCount` and `channelFundAmounts`) to the member-signed close PI
    /// `tokenFundsDigest` limbs by the verifier's on-chain recompute (TM-11), so the per-token
    /// settlement keys the Manager stores are proof-enforced, not caller-declared.
    uint32[10] tokenRegistry;
    /// Multi-token (§N-6): number of ACTIVE token slots (1..=10; in-circuit bounded).
    uint8 tokenCount;
}

interface IChannelSettlementVerifier {
    /// @notice The immutable close-statement adapter owned by this settlement verifier.
    /// @dev Managers cache this exact address in their constructors so the large compact proof is
    ///      relayed only once (manager -> adapter), while the settlement verifier still owns the
    ///      canonical 103-limb application binding.
    function closeMleVerifier() external view returns (IPinnedMleVerifierV2);

    /// Phase A: the close intent is verified by a canonical compact v2 MLE/WHIR proof. The pinned
    /// circuit adapter returns the 103 authenticated public-input limbs that the verifier rebinds.
    function verifyCloseIntent(CloseProofFields calldata fields, bytes calldata compactProof)
        external
        view
        returns (bool);

    /// @notice Bind all authenticated close public inputs to the supplied application fields.
    /// @dev This stateless entry point has no authority by itself. A caller must first obtain
    ///      `publicInputs` from this verifier's immutable `closeMleVerifier`; the Manager enforces
    ///      that composition with its own constructor-pinned adapter.
    function bindCloseIntentPublicInputs(CloseProofFields calldata fields, uint256[] calldata publicInputs)
        external
        pure
        returns (bool);

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
        uint8 tokenSlot,
        uint32 tokenIndex,
        bytes32 withdrawalNullifier,
        bytes calldata compactProof
    ) external view returns (bool);

    /// Phase C1 (CORRECTED): cancelClose is verified by a REAL MLE/WHIR proof of the plonky2
    /// cancel-close circuit. `memberSetCommitment` is the channel's REGISTERED member-set
    /// commitment (injected by the manager, NOT a caller field — Finding D fix). `view` (reads the
    /// cancel VK), not `pure`.
    function verifyCancelClose(
        bytes4 channelId,
        bytes32 closeIntentDigest,
        bytes32 memberSetCommitment,
        uint64 closeFinalStateVersion,
        uint64 revivedStateVersion,
        bytes32 revivedChannelStateDigest,
        bytes calldata compactProof
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
        uint32 tokenIndex,
        bytes calldata compactProof
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

    function closeMemberSetCommitment(bytes32[8] memory memberPkGs, uint8 memberCount) external pure returns (bytes32);

    /// @notice Canonical Rust-compatible IMTF digest over the complete fixed-width close fund
    ///         vectors. The Manager snapshots this exact proof-bound digest at finalization so its
    ///         later IMCF close-funding authorization cannot be built from adjusted accounting
    ///         caps or a truncated registry.
    function tokenFundsDigest(uint32[10] memory tokenRegistry, uint8 tokenCount, uint256[10] memory amounts)
        external
        pure
        returns (bytes32);
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
    /// @notice True only for an extended state root finalized by this exact rollup instance.
    ///         Close proofs bind their channel-fund snapshot to one such root; checking through
    ///         the immutable registry prevents a valid proof over another rollup's history from
    ///         becoming backing authority for this manager.
    function isFinalizedStateRoot(bytes32 stateRoot) external view returns (bool);
    /// @notice Pull-payment claim on the rollup. The channel close pays the channel's native ETH
    ///         to THIS manager (recipient == manager) via `IntmaxRollup.withdrawNative`, crediting
    ///         the rollup's `pendingWithdrawals[manager]`; `pullChannelFunds` then calls this to
    ///         move that ETH into the manager so it can be split among members.
    function withdraw(uint256 amount) external;
    /// @notice Pull-payment ERC-20 claim (multitoken §N-7): the ERC-20 mirror of `withdraw(amount)`.
    ///         `IntmaxRollup.withdrawERC20` credits `pendingTokenWithdrawals[t][manager]`;
    ///         `pullChannelTokenFunds(t)` calls this to move the tokens into the manager.
    function withdrawToken(uint32 tokenIndex, uint256 amount) external;
    /// @notice The rollup's SET-ONCE `tokenIndex → ERC-20` registry (multitoken §N-7, TM-10b).
    ///         SECURITY: the manager resolves payout token addresses through THIS single registry —
    ///         it deliberately keeps NO second (potentially divergent/mutable) copy of the mapping.
    function tokenAddressOf(uint32 tokenIndex) external view returns (IERC20);
}

/// @dev Channel-scoped close journal kept in the immutable materializer satellite. Calling it
///      directly saves scarce Rollup runtime bytes while the Rollup still invokes the same journal
///      at every post/rollback and authenticates every escrow mutation to this exact contract.
interface ICloseFundingMaterializerState {
    function freezeFromManager(uint32 channelId, uint64 generation) external;
    function unfreezeFromManager(uint32 channelId, uint64 generation) external;
    function materializedChannelExit(uint32 channelId) external view returns (bytes32);
    function requireSignedHeadBacking(uint32 channelId, bytes32 settledTxChain, bytes32 tokenFundsDigest) external view;
}

// The protocol challenge period, at FILE level so deploy tooling can reference it before any
// manager exists (Solidity cannot read a contract's constant through the contract type).
// `ChannelSettlementManager.CHALLENGE_PERIOD_SECS` aliases this — there is exactly one 86,400 in
// the codebase, and both the constructor floor and `script/DeployConfig.sol` read it. See the
// documentation on that alias for the security argument.
uint64 constant CHALLENGE_PERIOD_SECS_FLOOR = 86_400;

// Chain id of the local development network (anvil's default) — the only chain on which a
// sub-floor challenge period is permitted. File-level for the same reason as above.
uint256 constant SETTLEMENT_LOCAL_DEVNET_CHAIN_ID = 31337;

contract ChannelSettlementManager {
    error ReleaseRuntimeUnavailable();
    error InvalidSettlementVerifier();
    error InvalidCloseFundingMaterializer();
    error OnlyCloseFundingMaterializer();
    error CooperativeCloseFundingDeprecated();

    /// One SPHINCS+ key per member (D6 pad-to-MAX): a channel has between 2 and
    /// `MAX_MEMBER_COUNT` ACTIVE members, identified by their SPHINCS+ pubkey hash (bytes32), slot
    /// order 0..memberCount. Slots `memberCount..MAX_MEMBER_COUNT` are zero padding. Mirrors the
    /// Rust `MAX_SIG_CLUSTER` constant (src/constants.rs); the 1024-slot balance capacity is separate.
    uint256 internal constant MAX_MEMBER_COUNT = 8;
    uint256 internal constant MIN_MEMBER_COUNT = 2;
    /// Balance-state participant capacity.  Unlike `MAX_MEMBER_COUNT`, this includes delegates.
    /// The participant identity tree has a fixed ten-level shape (2**10 leaves), matching Rust's
    /// `MAX_CHANNEL_MEMBERS`.  Keeping the full set in ONE immutable root avoids an O(1024)
    /// constructor SSTORE bill that cannot fit safely inside a mainnet block.
    uint256 internal constant MAX_PARTICIPANT_COUNT = 1024;
    uint256 internal constant PARTICIPANT_TREE_DEPTH = 10;
    uint32 internal constant PARTICIPANT_LEAF_DOMAIN = 0x494d5052; // "IMPR"
    uint32 internal constant PARTICIPANT_NODE_DOMAIN = 0x494d504e; // "IMPN"
    /// Fixed per-channel token capacity — the width of every `channelFundAmounts` / `tokenRegistry`
    /// array here. MUST equal Rust `MAX_CHANNEL_TOKENS` (src/constants.rs) and
    /// `ChannelSettlementVerifier.MAX_CHANNEL_TOKENS`, or the TFD recompute would disagree.
    uint256 internal constant MAX_CHANNEL_TOKENS = 10;
    /// "IMCF" — terminal close-funding aux-data domain. MUST equal Rust
    /// `src/close_funding.rs::CLOSE_FUNDING_DOMAIN`.

    error InvalidChannelId();
    error InvalidBpMemberSlot();
    error InvalidChallengePeriod();
    /// The deployer supplied a challenge period below the protocol floor on a non-local chain.
    /// `supplied` / `required` are carried so a failed deploy names the value it must be raised to.
    error ChallengePeriodTooShort(uint64 supplied, uint64 required);
    error InvalidMemberBinding();
    error DuplicateRegisteredMember();
    error InvalidMemberCount();
    error InvalidParticipantRoot();
    error InvalidParticipantProof();
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
    /// A1: the cancel does not exhibit strictly newer material than a previous cancel — i.e. it is a
    /// REPLAY of an already-consumed cancel proof. See `cancelClose`.
    error CancelCloseReplay();
    error CloseIntentDigestMismatch();
    /// M-9: ABI-retained close metadata must use the single representation authenticated by the
    /// close circuit: nonce == freeze nonce and zero snapshot/burn sentinels.
    error NonCanonicalCloseMetadata();
    error NullifierAlreadyUsed();
    error WithdrawalCapExceeded();
    error NoWithdrawalCredit();
    error InsufficientWithdrawalCredit();
    error WithdrawalPayoutRecipientMismatch();
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
    /// P6-A / detail2 §H-3: `submitSpecialClose` (C2) is DISABLED — its on-chain verification is a
    /// forgeable `_matches` stub, so a SOUND proof of BP non-inclusion (a cross-layer commitment in
    /// the validity/rollup layer) does not yet exist. Re-enable only once that commitment lands.
    error SpecialCloseDisabled();
    /// P6-A / detail2 §H-3: `submitLateOutgoingDebitCorrection` (C3) is DISABLED — redundant. Double
    /// withdrawal is already prevented by the in-circuit nullifier used-sets (check-then-set CEI) at
    /// every payout path, and stale closes by `cancelClose` (C1); its verifier is also a stub.
    error LateOutgoingDebitDisabled();
    // --- Multi-token settlement (multitoken Phase 3, §N-6, TM-3/TM-8) ---
    /// A claim's `tokenSlot` must address an ACTIVE slot of the finalized registry (TM-8:
    /// `token_slot < token_count` is enforced at the circuit, the verifier bind AND here at the
    /// Manager cap lookup — fail-closed at every layer).
    error TokenSlotOutOfRange();
    /// The claim's base `tokenIndex` must equal the finalized registry at its `tokenSlot`
    /// (defense-in-depth: the circuit already enforces `token_index == registry[token_slot]`
    /// against the H1-committed registry; this re-checks against the TFD-bound finalized copy).
    error TokenRegistryMismatch();
    /// The close intent's supplied token metadata is malformed (tokenCount outside 1..=10).
    error TokenCountOutOfRange();
    /// ERC-20 fund pulling / payout needs an L1-registered token address for the index.
    error TokenIndexNotRegisteredOnRollup();
    error ChannelFundStateRootNotFinalized(bytes32 stateRoot);
    error ChannelFundingMismatch(uint32 tokenIndex, uint256 expected, uint256 observed);
    error ChannelFundsAlreadyReceived(uint32 tokenIndex);
    error CloseFundingAlreadyAuthorized(uint32 tokenIndex);
    error CloseFundingProofNotMaterialized(uint32 tokenIndex);
    error CloseFundingAuxMismatch();
    error TokenPayoutAmountMismatch();

    enum ChannelLifecycleStatus {
        Active,
        ClosePending,
        Closed
    }

    event CloseRequested(address indexed requester, uint64 closeRequestedAt, uint64 closeFreezeNonce);

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
        bytes32 indexed closeIntentDigest, bytes32 indexed revivedChannelStateDigest, uint64 revivedStateVersion
    );

    event LateOutgoingDebitAccepted(
        bytes32 indexed closeIntentDigest, bytes32 indexed sourceTxHash, bytes32 indexed debitNullifier, uint64 amount
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
        uint256 amount,
        uint32 tokenIndex
    );

    event PostCloseClaimAccepted(
        bytes32 indexed closeIntentDigest,
        bytes32 indexed sharedNativeNullifier,
        bytes32 indexed receiverPkG,
        address recipient,
        uint256 amount,
        uint32 tokenIndex
    );

    event WithdrawalClaimed(
        bytes32 indexed withdrawalNullifier, address indexed recipient, uint32 indexed tokenIndex, uint256 amount
    );

    /// @dev Mirror of Rust `CloseIntent` (src/common/channel.rs), minus the channel id (this
    /// contract is per-channel; `channelId` is the immutable).
    ///
    /// Chain-matching division of labor (abstract2 §3.5.2, detail2 §H-2): L1 only CARRIES and
    /// BINDS `finalSettledTxChain` through the member-signed IMCH and close-proof public inputs.
    /// The semantic equality `balance_pis.settled_tx_chain ==
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
        /// Multi-token (§N-6): registry-aligned per-token channel funds (Rust
        /// `ChannelFund.amounts`), ALWAYS full 10-wide (zero-padded). Slot 0 = the genesis-token
        /// burn denomination. SECURITY: bound — together with `tokenRegistry`/`tokenCount` — to
        /// the close proof's `tokenFundsDigest` PI by the verifier's on-chain recompute (TM-11),
        /// while the member-signed IMCH also commits to the resulting balance state.
        uint256[10] channelFundAmounts;
        /// Multi-token (§N-6): channel-local slot → BASE token index (Rust
        /// `BalanceState.token_registry`), zero-padded past `tokenCount`. Bound through the
        /// `tokenFundsDigest` PI recompute and, in-circuit, through the member-signed H1.
        uint32[10] tokenRegistry;
        /// Multi-token (§N-6): number of ACTIVE token slots (1..=10).
        uint8 tokenCount;
        bytes32 channelFundIntmaxStateRoot;
        /// Canonical zero sentinel: the close proof does not authenticate a live L2 burn. Actual
        /// withdrawals are authorized through the independent withdrawal-proof/nullifier lane.
        bytes32 burnTxHash;
        bytes32 closeWithdrawalDigest;
        /// Canonical zero sentinel: the signed ChannelState has no medium-block snapshot field.
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
        /// Multi-token (§N-6): the claimed LOCAL token slot (per-(member, token) claims). Strict-
        /// bound to PI limb 48; in-circuit it one-hot selects the claimed ciphertext position and
        /// is a limb of the IMW2 nullifier (TM-5).
        uint8 tokenSlot;
        /// Multi-token (§N-6): the BASE token index this claim pays in. SECURITY: the effective
        /// value is the PROOF's — the verifier strict-binds this field to PI limb 49, which the
        /// circuit forces equal to the H1-committed `registry[tokenSlot]` — so a caller supplying
        /// any other value fails the bind (never a caller choice, review m8). The Manager
        /// additionally re-checks it against the TFD-bound finalized registry.
        uint32 tokenIndex;
        bytes32 withdrawalNullifier;
    }

    /// @notice Immutable payout coordinates created by one accepted withdrawal proof. The record
    ///         is deleted before value transfer, so the public getter returns amount == 0 after a
    ///         successful payout (and for a nullifier that never existed).
    struct WithdrawalPayout {
        address recipient;
        uint32 tokenIndex;
        uint256 amount;
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
        /// TM-16 (§N-6): the BASE token the anchored incoming tx moved. PROOF-BOUND (PI limb 56,
        /// strict-bound by the Verifier; in-circuit it IS ids limb 5 of the `incomingTxHash`
        /// recompute) — a caller lying here fails the limb bind. Replaces the genesis-token pin.
        uint32 tokenIndex;
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
    function _deriveSharedNativeNullifier(bytes32 closeIntentDigest, bytes32 incomingTxHash, bytes32 receiverPkG)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(bytes4(POST_CLOSE_NULLIFIER_DOMAIN), closeIntentDigest, incomingTxHash, receiverPkG)
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
        /// Multi-token (§N-6, TM-3): the PROOF-BOUND per-token fund vector + registry + count (the
        /// strict limb bind at `submitCloseIntent` forced their TFD recompute to equal the close
        /// PI's member-signed `tokenFundsDigest`, TM-11). `finalizeClose` converts these into the
        /// per-BASE-token `finalizedChannelFundAmount` accrual caps. Replaces the single
        /// `channelFundAmount` (residual single-asset variable, TM-3).
        uint256[10] channelFundAmounts;
        uint32[10] tokenRegistry;
        uint8 tokenCount;
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

    /// @notice The protocol challenge period (abstract2 §3.5: 1 day) — and, on every chain except
    /// the local devnet, the enforced FLOOR for the constructor's `challengePeriod_` argument.
    ///
    /// SECURITY: this window is the ONLY interval in which an honest member can replace a stale
    /// close intent (`submitCloseIntent` with a newer state, gated at `challengeDeadline`) or cancel
    /// it (`cancelClose`, which also requires `pendingClose.active` and is therefore destroyed by
    /// `finalizeClose`). Both remedies require a freshly generated MLE/WHIR proof — minutes of
    /// proving — plus a transaction that lands before the deadline. `finalizeClose()` is
    /// permissionless the instant the deadline passes, so a window shorter than the time needed to
    /// prove-and-land is not a weaker challenge game: it is NO challenge game, and the submitter of
    /// a stale intent keeps the difference. That is fund MIS-ALLOCATION among channel members, not
    /// a liveness inconvenience, which is why the floor is enforced in the constructor rather than
    /// left to deploy scripts.
    uint64 public constant CHALLENGE_PERIOD_SECS = CHALLENGE_PERIOD_SECS_FLOOR;

    /// @notice A2 (round 2, REWRITTEN by R3-2 in round 3): the minimum response interval every
    /// ADMITTED challenge-replacement is guaranteed. It is a FLOOR ON THE DEADLINE
    /// (`_storePendingClose`), NOT an admission bar.
    ///
    /// SECURITY (A2 — the H-3 clamp's zero-length last rung): `_storePendingClose` sets
    /// `challengeDeadline = min(now + challengePeriod, closeChallengeHorizon)`, and the replacement
    /// branch admits a rung at `now == pendingClose.challengeDeadline`. A rung landing at exactly
    /// `now == closeChallengeHorizon` therefore received `challengeDeadline == block.timestamp`, and
    /// the historical `finalizeClose()` equality boundary settled it IN THE SAME BLOCK.
    /// The attacker picked the settled state with literally zero opportunity for an on-chain reply —
    /// a narrowing the H-3 rationale explicitly denied.
    ///
    /// CORRECTION (R3-2): round 2 spent this constant on the ADMISSION rule — refusing any
    /// replacement with `now + minResponse > horizon` — and claimed that restored "every admitted
    /// rung leaves a usable response interval". IT DID THE OPPOSITE. The response to a rung IS a
    /// replacement close intent, so the rule converted the final `minResponse` of every era from
    /// "replacements admitted" into "replacements refused": a griefer's rung landing one second
    /// before the first deadline made an honest strictly-newer state, surfacing well inside that
    /// deadline, unsubmittable, and the griefer's stale state settled
    /// (`RedTeamRound3.t.sol::test_R3_BREAK_A2_finalHourIsAReplacementBlackout`). The value is now
    /// applied where it was always meant to be — as the floor on the admitted rung's own deadline.
    /// R3-4 additionally keeps strictly-newer replacement open through the already-budgeted tail:
    /// relying only on `cancelClose` was unsound when an earlier era had consumed the same revived
    /// version. Tail replacements are clamped to the SAME `horizon + minResponse` absolute end, so
    /// they restore that response lane without reviving the unbounded ladder.
    ///
    /// THE VALUE, against this repo's own measured costs. Answering a rung costs (a) generating a
    /// fresh close proof — `a3_close_prover_builds_and_verifies_real_close_proof`, 79.3 s
    /// (`doc/tasks/falcon-sig-phase5-notes.md:263`) — and (b) landing a transaction whose on-chain
    /// MLE+WHIR verify alone is ~11.2M gas (`doc/architecture-audit/detail2-implementation-notes.md:294`),
    /// i.e. better than a third of a 30M-gas block, so inclusion is a multi-block bid, not a
    /// next-block certainty. 3,600 s is ~45x the measured proving time and leaves ~300 blocks of
    /// inclusion headroom. It is deliberately NOT larger: it is subtracted from the tail of the
    /// challenge game, so it must stay negligible against `CHALLENGE_PERIOD_SECS` (86,400 s) — at
    /// 1/24 of one window and 1/48 of the 2x horizon, it costs the ladder ~2% of its span.
    uint64 public constant MIN_CLOSE_RESPONSE_SECS = 3_600;

    /// @notice Chain id of the local development network (anvil's default).
    ///
    /// SECURITY: the ONLY chain on which `challengePeriod_` may fall below `CHALLENGE_PERIOD_SECS`.
    /// The end-to-end tests must be able to drive a full close→challenge→finalize lifecycle without
    /// waiting a day of wall-clock (they advance time with `evm_increaseTime`/`vm.warp`, but the CLI
    /// E2Es drive a real anvil node), so the short window has to remain reachable SOMEWHERE. Scoping
    /// it to 31337 makes "short challenge period" structurally unshippable to a public chain: it is
    /// not a policy the deployer can opt out of, and it holds for any deployment tooling — hand-
    /// rolled, factory, or a future script — not just the scripts in `contracts/script/`.
    /// 31337 is not a public network; the same idiom already gates the mock-verifier deploy scripts.
    uint256 internal constant LOCAL_DEVNET_CHAIN_ID = SETTLEMENT_LOCAL_DEVNET_CHAIN_ID;

    bytes4 public immutable channelId;
    /// F7: the block-proposer member is identified by its slot (0..MEMBER_COUNT) and its SPHINCS+
    /// pubkey hash, replacing the legacy `bpKeyId`.
    uint8 public immutable bpMemberSlot;
    /// Release posture: seeded by the constructor and frozen for the lifetime of this deployment.
    /// Member-set updates are fail-closed until the validity layer and this Manager can consume one
    /// canonical, finalized transition atomically. The slot index itself never moves.
    bytes32 public bpPkG;
    uint64 public immutable challengePeriod;
    uint256 public immutable specialClosePenalty;
    IChannelSettlementVerifier public immutable verifier;
    /// @notice The close adapter derived from `verifier` exactly once during construction.
    /// @dev The Manager calls it directly so the ~195 KiB compact proof crosses one parent ABI
    ///      boundary instead of two. Its authenticated 103-limb result is still passed through the
    ///      settlement verifier's complete canonical/equality binding before any state mutation.
    IPinnedMleVerifierV2 public immutable closeMleVerifier;

    /// @notice Finding E: the rollup registry holding this channel's authoritative member set + bp
    /// (the validity-path registration). The constructor asserts this manager's member set + bp
    /// EQUAL the registry's, making them PROVABLY the same signer set.
    /// DEPLOYMENT-INTEGRITY ASSUMPTION (review LOW-2): the equality guarantee holds only when
    /// `registry` is the real `IntmaxRollup` and `channelId` is the intended channel. Both are
    /// deployer-supplied constructor args with no on-chain back-link from the rollup. Integrators
    /// MUST verify `registry()` and `channelId()` on the deployed manager before funding a channel.
    IChannelRegistry public immutable registry;

    /// @notice The number of ACTIVE members (2..=MAX_MEMBER_COUNT). Mirrors the Rust
    /// `ChannelRecord.member_count` (src/common/channel.rs). Seeded by the constructor and frozen
    /// for this deployment. Membership changes require closing and replacing the channel.
    uint8 public activeMemberCount;

    /// @notice The number of delegates frozen into the authenticated live snapshot at deployment.
    /// `ChannelRecord.delegate_count` / `BalanceState.delegate_count` AT THAT MOMENT. Delegates do
    /// NOT co-sign and are NOT part of `memberBindings`/`memberPkGs`/the IMCM commitment.
    ///
    /// This is the FLOOR of the close path's delegate count: `ChannelSettlementVerifier` requires
    /// close-PI limb 94 to be at least this value. Delegates keep joining after
    /// deployment — they are appended by cosigner-signed states and never leave — so a state with
    /// more delegates closes normally; one with fewer would drop registered delegates and is rejected.
    /// Joins are refused only while a deployment is PREPARED (the deploy must match one snapshot).
    /// Deployment invariant: `activeMemberCount + activeDelegateCount <= 1024`.
    uint16 public immutable activeDelegateCount;

    /// @notice Number/root of the slot-ordered member+delegate identity snapshot taken at
    /// deployment (a prefix of every later state: delegates only append).  Leaves are `keccak256(IMPR || uint16(slot) || pkG || recipient)`, padded by
    /// raw zero leaves to 1024; nodes are `keccak256(IMPN || left || right)`.  Only the at-most-eight
    /// cosigners are materialized in mappings below.  A participant registered at deployment proves
    /// its slot binding against this root to request a close on its own (`requestCloseAsParticipant`),
    /// keeping a 1024-participant deployment constant-storage. A delegate that joined later is not in
    /// this root: it is closed like any delegate of the original design (by a registered participant
    /// or cosigner), and it claims its balance from the H1-bound leaf exactly as registered ones do.
    uint16 public immutable activeParticipantCount;
    bytes32 public immutable participantRoot;

    /// @notice The channel's registered member SPHINCS+ pubkey hashes in slot order, ZERO-padded to
    /// MAX_MEMBER_COUNT (D6 pad-to-MAX). Active slots (`< activeMemberCount`) are nonzero and
    /// pairwise-distinct; padding slots are zero. Mirrors the Rust
    /// `ChannelRecord.member_pk_gs` (src/common/channel.rs). The close proof is
    /// bound to exactly this set via the in-circuit `memberSetCommitment`.
    bytes32[MAX_MEMBER_COUNT] public memberPkGs;

    ChannelLifecycleStatus public channelStatus;
    uint64 public currentCloseFreezeNonce;
    /// @notice Monotone manager-lifetime request generation. Unlike the proof-bound freeze nonce,
    /// this is never restored by cancelClose, so delayed request/finalize raw transactions cannot
    /// become valid again when a later close era reuses the same signed state and digest.
    uint64 public closeRequestGeneration;
    uint64 public closeRequestedAt;
    /// @notice H-3: the ABSOLUTE end of the current frozen era's challenge game, anchored at the
    /// era's FIRST close intent and NOT moved by any replacement. Zero while no intent is pending.
    /// See `_storePendingClose` for the ladder attack this bounds and the choice of horizon.
    uint64 public closeChallengeHorizon;
    /// @notice A1 (round 2): the highest `revivedStateVersion` that any successful `cancelClose` has
    /// ever consumed. MONOTONE for the manager's lifetime — never reset by a cancel, a finalize, or
    /// an era change (that is the whole point: `cancelClose` restores the era counter, so anything
    /// per-era is replayable). It is also an expected-value guard for close requests, but never a
    /// minimum-state-version gate on close proofs. See the A1 block in `cancelClose` for the
    /// non-lockout argument.
    uint64 public highestCancelledRevivedStateVersion;
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

    // -----------------------------------------------------------------------
    // Multi-token settlement accounting (multitoken Phase 3, §N-6, TM-3).
    //
    // SECURITY (TM-3, P3): EVERY accounting variable below is keyed by the BASE token index
    // (never a channel-local slot) — no residual single-asset variable remains. Token-t claims are
    // accrued against token-t funds and paid ONLY from token-t received value; the per-token
    // CapInv `totalCreditedOut[t] + amount <= receivedChannelFunds[t]` at the payout site is the
    // Solidity image of `ChannelSettlementManagerMT.lean`'s `execMT_payout_ceiling` machine (the
    // Lean op-to-site table maps claimMT→submit*Claim accrual, pullMT→pullChannel*Funds,
    // pullCreditMT→claimWithdrawalCredit — the cap lives at the payout site, as deployed).
    // -----------------------------------------------------------------------

    /// @notice Per-BASE-token channel-fund amounts DECLARED by the finalized close intent (set in
    ///         `finalizeClose` from the TFD-bound (registry, amounts) vectors). SECURITY: a
    ///         non-authoritative accrual bound only — the AUTHORITATIVE per-token solvency cap is
    ///         `receivedChannelFunds[t]` (real value pulled from the rollup), enforced at payout.
    mapping(uint32 => uint256) public finalizedChannelFundAmount;
    /// Additional base funds proved received after the immutable closing snapshot.
    mapping(uint32 => uint256) public lateIncomingFundAmount;
    /// @notice Σ accepted withdrawal/post-close claim amounts per base token (accrual bound).
    mapping(uint32 => uint256) public totalWithdrawn;

    /// @notice Real value this manager has accepted as CHANNEL backing per base token (the capped
    ///         portion of `pullChannelFunds` / `pullChannelTokenFunds` balance deltas; index 0 =
    ///         native ETH). A mixed Rollup recipient ledger may pay surplus in the same atomic pull;
    ///         that surplus is deliberately not recorded here and cannot increase member capacity.
    ///         SECURITY: this — NOT the intent-declared `finalizedChannelFundAmount[t]` — is the
    ///         authoritative cross-channel/cross-token solvency ceiling: `claimWithdrawalCredit`
    ///         enforces Σ token-t payouts ≤ receivedChannelFunds[t], so the manager can never pay
    ///         members more of ANY asset than the channel actually received on L1 in THAT asset
    ///         (no cross-token draw, TM-3).
    mapping(uint32 => uint256) public receivedChannelFunds;
    /// @notice Σ value actually paid out per base token via `claimWithdrawalCredit`.
    mapping(uint32 => uint256) public totalCreditedOut;

    /// @notice Aggregate accrued credits per (base token, recipient), retained only for accounting
    ///         and views. Payout authority is the nullifier-scoped `withdrawalPayouts` record.
    mapping(uint32 => mapping(address => uint256)) public withdrawalCredits;

    /// @notice Exact proof-accepted payout keyed by withdrawal nullifier. A successful claim
    ///         deletes this record atomically before transferring value.
    mapping(bytes32 => WithdrawalPayout) public withdrawalPayouts;

    /// @notice The finalized close's token registry (channel-local slot → base token index) and
    ///         active count, stored TFD-bound at `finalizeClose`. `finalizedTokenRegistry` is
    ///         exposed via the auto-getter (per-index).
    uint32[10] public finalizedTokenRegistry;
    uint8 public finalizedTokenCount;
    /// @notice Exact IMTF digest of the proof-bound full-width vectors that settled. Every field
    ///         comes from one authenticated state; settlement never synthesizes a vector by
    ///         combining a close with a different state generation.
    bytes32 public finalizedTokenFundsDigest;
    /// @notice The only contract allowed to materialize the complete signed-head vector. The old
    ///         terminal-child/IPW2 route is retired: this immutable calls the rollup's one-shot
    ///         whole-state path and never asks cosigners for another channel signature.
    address public immutable closeFundingMaterializer;

    mapping(bytes32 => bool) public usedWithdrawalNullifiers;
    mapping(bytes32 => bool) public usedSharedNativeNullifiers;
    mapping(bytes32 => bool) public usedLateOutgoingDebitNullifiers;

    /// F7: member identity is the SPHINCS+ pubkey hash (bytes32).
    mapping(bytes32 => address) public registeredRecipientOf;
    mapping(bytes32 => uint256) public registeredMemberIndexPlusOne;
    mapping(address => bool) public isMemberRecipient;
    bytes32[] public registeredMemberPkGs;

    /// @notice Emitted when real value (ETH: tokenIndex 0; else ERC-20) is pulled from the rollup
    /// into this manager.
    event ChannelFundsPulled(uint32 indexed tokenIndex, uint256 amount, uint256 totalReceived);

    // --- Reentrancy guard (the manager moves native ETH in pullChannelFunds/claimWithdrawalCredit) ---
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status = _NOT_ENTERED;

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        if (_status == _ENTERED) revert Reentrant();
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        _status = _NOT_ENTERED;
    }

    /// @dev A short-window manager is a local-devnet artifact. Constructor
    ///      checks alone do not cover state/code migration or a later chain-id
    ///      transition, so every live state transition and value sink repeats
    ///      the release boundary at runtime.
    modifier releaseRuntime() {
        _requireReleaseRuntime();
        _;
    }

    function _requireReleaseRuntime() private view {
        if (block.chainid != LOCAL_DEVNET_CHAIN_ID && challengePeriod < CHALLENGE_PERIOD_SECS) {
            revert ChallengePeriodTooShort(challengePeriod, CHALLENGE_PERIOD_SECS);
        }
    }

    /// @notice Accept native ETH ONLY from the bound rollup (its `withdraw(amount)` pays this manager via
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
        uint16 delegateCount_,
        bytes32 participantRoot_,
        uint64 challengePeriod_,
        uint256 specialClosePenalty_,
        uint256 initialBpBondCredits_,
        IChannelSettlementVerifier verifier_,
        IChannelRegistry registry_,
        address closeFundingMaterializer_,
        MemberBinding[] memory memberBindings
    ) {
        if (channelId_ == bytes4(0)) revert InvalidChannelId();
        // D6 pad-to-MAX: 2..=MAX_MEMBER_COUNT active members are registered, slot order. Slots
        // beyond `memberBindings.length` stay zero (padding).
        if (memberBindings.length < MIN_MEMBER_COUNT || memberBindings.length > MAX_MEMBER_COUNT) {
            revert InvalidMemberCount();
        }
        // F7: the block-proposer slot must be a valid ACTIVE member index, and its pubkey hash
        // nonzero. SECURITY: bpMemberSlot must be < the active member count (not just MAX), or a
        // padding slot could masquerade as the proposer.
        if (uint256(bpMemberSlot_) >= memberBindings.length) revert InvalidBpMemberSlot();
        if (bpPkG_ == bytes32(0)) revert InvalidBpMemberSlot();
        // SECURITY: a zero challenge period would let any pending close finalize in the same
        // block, voiding the whole challenge game.
        if (challengePeriod_ == 0) revert InvalidChallengePeriod();
        // SECURITY (fund mis-allocation, not liveness): a nonzero-but-tiny window voids the
        // challenge game just as completely as zero does — see CHALLENGE_PERIOD_SECS. Every deploy
        // script in this repo used to hardcode 1 second because the anvil E2Es cannot wait a day;
        // that value is now confined to the local devnet BY THE CONTRACT, so it cannot be carried
        // to a public chain by a script edit, a copied script, or bespoke deploy tooling. This is a
        // deployment-time floor is repeated by `releaseRuntime` because state/code can be migrated
        // without executing this initcode. `challengePeriod` is immutable and has no setter, so a
        // short manager moved off the devnet remains identifiable and fails closed.
        if (block.chainid != LOCAL_DEVNET_CHAIN_ID && challengePeriod_ < CHALLENGE_PERIOD_SECS) {
            revert ChallengePeriodTooShort(challengePeriod_, CHALLENGE_PERIOD_SECS);
        }

        channelId = channelId_;
        bpMemberSlot = bpMemberSlot_;
        bpPkG = bpPkG_;
        challengePeriod = challengePeriod_;
        specialClosePenalty = specialClosePenalty_;
        bpBondCredits = initialBpBondCredits_;
        if (address(verifier_).code.length == 0) revert InvalidSettlementVerifier();
        IPinnedMleVerifierV2 derivedCloseMleVerifier;
        try verifier_.closeMleVerifier() returns (IPinnedMleVerifierV2 adapter) {
            derivedCloseMleVerifier = adapter;
        } catch {
            revert InvalidSettlementVerifier();
        }
        if (address(derivedCloseMleVerifier).code.length == 0) revert InvalidSettlementVerifier();
        verifier = verifier_;
        closeMleVerifier = derivedCloseMleVerifier;
        registry = registry_;
        if (closeFundingMaterializer_ == address(0) || closeFundingMaterializer_.code.length == 0) {
            revert InvalidCloseFundingMaterializer();
        }
        closeFundingMaterializer = closeFundingMaterializer_;
        channelStatus = ChannelLifecycleStatus.Active;
        activeMemberCount = uint8(memberBindings.length);
        uint256 participantCount = uint256(memberBindings.length) + uint256(delegateCount_);
        if (participantCount > MAX_PARTICIPANT_COUNT) {
            revert InvalidMemberCount();
        }
        activeDelegateCount = delegateCount_;
        activeParticipantCount = uint16(participantCount);

        for (uint256 i = 0; i < memberBindings.length; i++) {
            MemberBinding memory binding = memberBindings[i];
            if (binding.pkG == bytes32(0) || binding.recipient == address(0)) {
                revert InvalidMemberBinding();
            }
            if (registeredMemberIndexPlusOne[binding.pkG] != 0) {
                revert DuplicateRegisteredMember();
            }
            registeredRecipientOf[binding.pkG] = binding.recipient;
            registeredMemberIndexPlusOne[binding.pkG] = registeredMemberPkGs.length + 1;
            registeredMemberPkGs.push(binding.pkG);
            memberPkGs[i] = binding.pkG;
            isMemberRecipient[binding.recipient] = true;
        }
        // The block-proposer pubkey hash must be the member registered at its slot.
        if (memberPkGs[bpMemberSlot_] != bpPkG_) {
            revert InvalidBpMemberSlot();
        }

        // A zero root is accepted only as a backwards-compatible constructor convenience for a
        // member-only channel, where the contract can derive the complete tree itself.  A
        // delegate-bearing deployment MUST supply the authenticated live-snapshot root: deriving
        // it from an on-chain delegate array would reintroduce the unscalable deployment path this
        // root replaces.
        if (participantRoot_ == bytes32(0)) {
            if (delegateCount_ != 0) revert InvalidParticipantRoot();
            participantRoot_ = _memberOnlyParticipantRoot(memberBindings);
        }
        if (participantRoot_ == bytes32(0)) revert InvalidParticipantRoot();
        participantRoot = participantRoot_;

        // Finding E: bind this manager's member set + bp to the rollup's on-chain registration (the
        // validity-path single source of truth). SECURITY: without this, the validity proof and the
        // close proof could authenticate DIFFERENT signer sets for the same channel. The close-form
        // IMCM commitment over the just-built `memberPkGs`/`activeMemberCount` MUST
        // equal the commitment the rollup recorded at `registerChannel` (computed with the SAME
        // fixed-8 keccak preimage), and the bp identity MUST match.
        //
        // DEPLOYMENT ORDER: `registerChannel(channelId, ...)` on the rollup MUST run BEFORE this
        // manager is deployed; otherwise the registry returns bytes32(0) and this reverts.
        uint32 channelIdU32 = uint32(channelId_);
        if (registeredMemberSetCommitment() != registry.channelMemberSetCommitment(channelIdU32)) {
            revert MemberSetMismatch();
        }
        if (
            bpMemberSlot_ != registry.channelBpMemberSlot(channelIdU32) || bpPkG_ != registry.channelBpPkG(channelIdU32)
        ) {
            revert BpMismatch();
        }
    }

    function participantLeaf(uint16 slot, bytes32 pkG_, address recipient_) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes4(PARTICIPANT_LEAF_DOMAIN), slot, pkG_, recipient_));
    }

    function _participantNode(bytes32 left, bytes32 right) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes4(PARTICIPANT_NODE_DOMAIN), left, right));
    }

    function _memberOnlyParticipantRoot(MemberBinding[] memory bindings) private pure returns (bytes32) {
        bytes32[1024] memory nodes;
        for (uint256 i = 0; i < bindings.length; i++) {
            nodes[i] = participantLeaf(uint16(i), bindings[i].pkG, bindings[i].recipient);
        }
        uint256 width = MAX_PARTICIPANT_COUNT;
        while (width > 1) {
            for (uint256 i = 0; i < width; i += 2) {
                nodes[i >> 1] = _participantNode(nodes[i], nodes[i + 1]);
            }
            width >>= 1;
        }
        return nodes[0];
    }

    function _isParticipant(uint16 slot, bytes32 pkG_, address recipient_, bytes32[10] calldata siblings)
        private
        view
        returns (bool)
    {
        if (uint256(slot) >= uint256(activeParticipantCount) || pkG_ == bytes32(0) || recipient_ == address(0)) {
            return false;
        }
        bytes32 node = participantLeaf(slot, pkG_, recipient_);
        uint256 index = uint256(slot);
        for (uint256 level = 0; level < PARTICIPANT_TREE_DEPTH; level++) {
            node =
                ((index & 1) == 0) ? _participantNode(node, siblings[level]) : _participantNode(siblings[level], node);
            index >>= 1;
        }
        return node == participantRoot;
    }

    function memberCount() external view returns (uint256) {
        return registeredMemberPkGs.length;
    }

    /// @notice The close-circuit member-set commitment for this channel's registered members
    /// (D6 pad-to-MAX FIXED form): keccak([IMCM, activeMemberCount, memberPkGs[0..7]])
    /// over ALL MAX_MEMBER_COUNT slots in slot order (padding zeroed). The close proof's in-circuit
    /// commitment MUST equal this value (enforced in `_checkCloseProof`), binding the verified
    /// signing keys to the registered member set (no non-member-key substitution).
    function registeredMemberSetCommitment() public view returns (bytes32) {
        return verifier.closeMemberSetCommitment(memberPkGs, activeMemberCount);
    }

    // RETIRED: `applyMemberSetUpdate(...)` is intentionally absent from the production ABI.
    // Historical construction code is isolated under `src/deprecated/member_set_update`; changing
    // participants requires closing this channel and migrating into a newly registered channel.

    function isNativeSendAllowed(uint64 suppliedCloseFreezeNonce) external view returns (bool) {
        if (block.chainid != LOCAL_DEVNET_CHAIN_ID && challengePeriod < CHALLENGE_PERIOD_SECS) return false;
        return channelStatus == ChannelLifecycleStatus.Active && suppliedCloseFreezeNonce == currentCloseFreezeNonce;
    }

    // REMOVED: `fundBpBondCredits(uint256)`.
    //
    // SECURITY: it was `external`, NON-payable and UNGATED — anyone could inflate `bpBondCredits`
    // by an arbitrary amount for free, with no value ever transferred. It was harmless only
    // because nothing reads that variable on a payout path (its sole consumer, the special-close
    // slash, is permanently reverted), i.e. an unauthenticated writer to an accounting variable
    // that was one wiring change away from becoming a free over-credit.
    //
    // Removed rather than gated, for the same reason `claimAuthorizedWithdrawal` was removed:
    // delete the capability instead of constraining it. If the special-close path is ever
    // implemented, the bond pot must be funded by a function that is BOTH access-controlled AND
    // `payable` with `msg.value == amount`, so the credited number is backed by real ETH — a
    // non-payable "fund" function can never be that.

    /// @notice Step 1 of the two-step close for a cosigner whose deployment binding is materialized
    /// in the small on-chain mapping.  The first close intent can only be processed after
    /// `GRACE_BEFORE_PROCESS_SECS`.
    function requestClose(uint64 expectedCurrentCloseFreezeNonce, uint64 expectedHighestCancelledRevivedStateVersion)
        external
        releaseRuntime
    {
        if (
            currentCloseFreezeNonce != expectedCurrentCloseFreezeNonce
                || highestCancelledRevivedStateVersion != expectedHighestCancelledRevivedStateVersion
        ) revert InvalidFreezeNonce();
        if (!isMemberRecipient[msg.sender]) revert NotChannelMember();
        _requestClose();
    }

    /// @notice The same unilateral freeze right for any participant, including a delegate.  The
    /// fixed-depth proof authenticates `(slot, pkG, msg.sender)` against the immutable live-snapshot
    /// root without storing up to 1024 delegate bindings in contract storage. The two expected
    /// era values make a journaled raw request one-shot across both a foreign freeze and a later
    /// cancel: `currentCloseFreezeNonce` is restored by cancel for protocol liveness, whereas
    /// `highestCancelledRevivedStateVersion` is monotone and prevents the old calldata becoming
    /// valid again after that restoration.
    function requestCloseAsParticipant(
        uint16 slot,
        bytes32 pkG_,
        bytes32[10] calldata siblings,
        uint64 expectedCurrentCloseFreezeNonce,
        uint64 expectedHighestCancelledRevivedStateVersion
    ) external releaseRuntime {
        if (
            currentCloseFreezeNonce != expectedCurrentCloseFreezeNonce
                || highestCancelledRevivedStateVersion != expectedHighestCancelledRevivedStateVersion
        ) revert InvalidFreezeNonce();
        if (!_isParticipant(slot, pkG_, msg.sender, siblings)) revert InvalidParticipantProof();
        _requestClose();
    }

    function _requestClose() private {
        if (channelStatus == ChannelLifecycleStatus.Closed) revert ChannelClosed();
        if (channelStatus != ChannelLifecycleStatus.Active) revert ChannelAlreadyFrozen();

        closeRequestGeneration += 1;
        currentCloseFreezeNonce += 1;
        channelStatus = ChannelLifecycleStatus.ClosePending;
        closeRequestedAt = uint64(block.timestamp);
        // Atomic with the local transition: a revert in the rollup-side exact manager/channel
        // binding unwinds the nonce, generation and status writes above. Once frozen, no new block
        // for this channel can race the signed head being closed.
        ICloseFundingMaterializerState(closeFundingMaterializer)
            .freezeFromManager(uint32(channelId), closeRequestGeneration);
        emit CloseRequested(msg.sender, closeRequestedAt, currentCloseFreezeNonce);
    }

    /// @notice Step 2 of the two-step close: record (or challenge-replace) a close intent.
    /// Direct submission from `Active` is disallowed — `requestClose()` must run first
    /// (abstract2 §3.5).
    function submitCloseIntent(CloseIntent calldata intent, bytes calldata compactProof) external releaseRuntime {
        if (channelStatus == ChannelLifecycleStatus.Closed) revert ChannelClosed();
        // Multi-token: cheap structural bound BEFORE the proof check (defense-in-depth; the
        // strict TFD limb bind would reject an out-of-range count anyway, since the in-circuit
        // token_count is constrained to 1..=10 and keccak is collision-resistant).
        if (intent.tokenCount == 0 || intent.tokenCount > 10) revert TokenCountOutOfRange();
        _checkCloseProof(intent, compactProof);

        bytes32 closeIntentDigest = computeCloseIntentDigest(intent);
        if (pendingClose.active) {
            // Challenge path: a newer signed state replaces the pending one.
            //
            // SECURITY: the grace period deliberately does NOT apply here — challenges race the
            // fixed `challengeDeadline`, and re-imposing the grace delay would shrink the
            // effective challenge window for honest members holding a newer state.
            if (block.timestamp > pendingClose.challengeDeadline) {
                revert ChallengeWindowClosed();
            }
            // ── SECURITY (A2, round 2 — the H-3 clamp's zero-length last rung; REWRITTEN by R3-2).
            //
            //    THE DEFECT A2 FOUND, and which is still real: the deadline check above alone admits
            //    a rung landing at `now == challengeDeadline == closeChallengeHorizon`, which
            //    `_storePendingClose` then clamped to `challengeDeadline == now`; before the strict
            //    finalization boundary this was same-block finalizable, with no reply interval.
            //
            //    WHY ROUND 2's FIX WAS WRONG (R3-2,
            //    `RedTeamRound3.t.sol::test_R3_BREAK_A2_finalHourIsAReplacementBlackout`). Round 2
            //    refused any replacement with `block.timestamp + minResponse > closeChallengeHorizon`.
            //    But the response to a rung IS a replacement close intent — so that rule CLOSED THE
            //    VERY LANE it claimed to keep open, and it closed it for a full `minResponse` rather
            //    than for the zero seconds the original defect cost. Measured: an attacker's rung
            //    lands one second before the first deadline, an honest strictly-newer state surfaces
            //    at `horizon - 3599` INSIDE that deadline, is refused, and the attacker's stale state
            //    settles unopposed. On the devnet branch it was half the ladder.
            //
            //    THE R3-2 RULE — admit to the horizon and guarantee a deadline floor instead of
            //    refusing the rung. R3-4 then opens the already-budgeted tail to strictly-newer
            //    responses while clamping all of them to one fixed absolute end. The combination
            //    bounds the ladder at `closeChallengeHorizon + minResponse`, independent of the
            //    number of rungs, versus the unbounded per-rung extension H-3 was introduced to kill.
            //
            //    THE RESPONSE TAIL (R3-4). A rung landing at the horizon cannot rely only on
            //    `cancelClose`: the same revived version may already have been consumed by an
            //    earlier era's lifetime replay floor. The already-budgeted `minResponse` tail is
            //    therefore also open to strictly-newer replacements. `_storePendingClose` clamps
            //    every replacement in that tail to the SAME absolute end, so this does not extend
            //    the ladder. It merely makes the advertised response interval usable even after a
            //    prior cancel consumed the responder's version.
            //
            //    The floor degrades to `challengePeriod` on the local devnet, where the constructor
            //    permits a sub-`CHALLENGE_PERIOD_SECS` window: a fixed 3,600 s would exceed the whole
            //    2x horizon there and stretch the ladder well past it. On every other chain
            //    `challengePeriod >= 86,400`, so the effective floor is exactly
            //    `MIN_CLOSE_RESPONSE_SECS` and the overshoot is 1/48 of the horizon.
            uint256 minResponse = challengePeriod < MIN_CLOSE_RESPONSE_SECS ? challengePeriod : MIN_CLOSE_RESPONSE_SECS;
            uint256 absoluteEnd = uint256(closeChallengeHorizon) + minResponse;
            if (block.timestamp > absoluteEnd) {
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
            // SECURITY (H-3, challenge-window ladder): the era's ABSOLUTE horizon is anchored
            // HERE — at the first intent — and never again. Anchoring it to `closeRequestedAt`
            // instead would be strictly worse: nothing bounds how long a griefer may wait before
            // submitting the first intent, so a first intent landing just under the horizon would
            // inherit a near-zero challenge window and settle a stale state unopposed.
            closeChallengeHorizon = uint64(block.timestamp + 2 * uint256(challengePeriod));
        }

        // Isolated frame for the 15-field PendingClose build (via-IR stack limit).
        _storePendingClose(intent, closeIntentDigest);

        emit CloseSubmitted(
            closeIntentDigest,
            intent.burnTxHash,
            intent.closeNonce,
            intent.finalEpoch,
            intent.closeFreezeNonce,
            // Genesis-token (slot 0) fund = the burn denomination; the full vector is TFD-bound.
            intent.channelFundAmounts[0],
            pendingClose.challengeDeadline,
            intent.finalStateVersion,
            intent.finalSettledTxChain
        );
    }

    /// @dev Isolated frame for the 15-field PendingClose construction (keeps `submitCloseIntent`
    /// under the via-IR stack limit once the close path threads `delegateCount`).
    ///
    /// SECURITY (H-3 — the challenge-window ladder): this runs on BOTH the first-intent and the
    /// challenge-replacement branch, so the naive `block.timestamp + challengePeriod` bought every
    /// legal replacement another FULL window. `_isNewer` only forbids replaying the SAME state; it
    /// does not stop walking up the version ladder, and §M-7 batching makes intermediate versions
    /// cheap — so exit was delayable for as many days as there were submittable versions. The
    /// deadline is now clamped to `closeChallengeHorizon`, an absolute value fixed at the era's
    /// FIRST intent and never moved by a replacement.
    ///
    /// HORIZON = first intent + 2 * challengePeriod. Justification: `challengePeriod` is, by the
    /// definition at `CHALLENGE_PERIOD_SECS`, the time an honest member needs to observe a pending
    /// intent, generate an MLE/WHIR proof for a newer state, and land it. An honest member's clock
    /// starts no later than the era's first intent (they were already warned by `requestClose` a
    /// full `GRACE_BEFORE_PROCESS_SECS` earlier), so 2x gives them their full budgeted window PLUS
    /// one entire spare window of replacement headroom — strictly MORE than the single window the
    /// unladdered path guaranteed. Landing the true newest state ends the game outright
    /// (`_isNewer` is strict), so the extra window is what a member who was still proving when a
    /// replacement landed needs. The cap is therefore liveness-restoring without narrowing the
    /// interval the stale-close defence was sized for.
    ///
    /// CORRECTION (A2, round 2): the sentence above was FALSE for the final rung as originally
    /// shipped. The clamp does narrow each rung's window as the horizon is approached, and a rung
    /// admitted at exactly the horizon got a ZERO-length one — same-block finalizable.
    ///
    /// CORRECTION (R3-2, round 3): round 2 restored the claim by having `submitCloseIntent` REFUSE
    /// any replacement that could not leave `MIN_CLOSE_RESPONSE_SECS` before the horizon. That was
    /// the wrong lever — the response to a rung IS a replacement, so the rule denied the response it
    /// was protecting, for a full `minResponse` (see the R3-2 block in `submitCloseIntent`). The
    /// guarantee is now enforced HERE, on the WINDOW rather than on the ADMISSION: before the
    /// horizon each admitted rung's deadline is floored at `now + minResponse`. R3-4 admits
    /// strictly-newer responses during the resulting tail but clamps them to the same
    /// `closeChallengeHorizon + minResponse` absolute end — the cap H-3 was introduced to obtain.
    function _storePendingClose(CloseIntent calldata intent, bytes32 closeIntentDigest) internal {
        uint256 naturalDeadline = block.timestamp + challengePeriod;
        uint256 horizon = closeChallengeHorizon;
        uint256 deadline = naturalDeadline < horizon ? naturalDeadline : horizon;
        // R3-2: floor the clamped deadline so no admitted rung is unanswerable. `minResponse`
        // degrades to `challengePeriod` on the devnet (see the constant), and `challengePeriod` is
        // never below it elsewhere — so for the era's FIRST intent, where `naturalDeadline` is
        // `now + challengePeriod` and always at-or-below the horizon it just set, this floor is a
        // no-op. It bites only on a late rung, exactly where the zero-length window was.
        uint256 minResponse = challengePeriod < MIN_CLOSE_RESPONSE_SECS ? challengePeriod : MIN_CLOSE_RESPONSE_SECS;
        uint256 floorDeadline = block.timestamp + minResponse;
        if (deadline < floorDeadline) deadline = floorDeadline;
        // R3-4: the response tail is an admission window, not another extension rung. A
        // replacement landing after `horizon` keeps the one fixed `horizon + minResponse` end.
        uint256 absoluteEnd = horizon + minResponse;
        if (deadline > absoluteEnd) deadline = absoluteEnd;
        pendingClose = PendingClose({
            active: true,
            closeNonce: intent.closeNonce,
            finalEpoch: intent.finalEpoch,
            finalSmallBlockNumber: intent.finalSmallBlockNumber,
            closeFreezeNonce: intent.closeFreezeNonce,
            challengeDeadline: uint64(deadline),
            closeIntentDigest: closeIntentDigest,
            finalChannelStateDigest: intent.finalChannelStateDigest,
            finalBalanceStateH1: intent.finalBalanceStateH1,
            // Multi-token (TM-3/TM-11): the full TFD-bound settlement vectors.
            channelFundAmounts: intent.channelFundAmounts,
            tokenRegistry: intent.tokenRegistry,
            tokenCount: intent.tokenCount,
            channelFundIntmaxStateRoot: intent.channelFundIntmaxStateRoot,
            burnTxHash: intent.burnTxHash,
            closeWithdrawalDigest: intent.closeWithdrawalDigest,
            snapshotMediumBlockNumber: intent.snapshotMediumBlockNumber,
            finalStateVersion: intent.finalStateVersion,
            finalSettledTxChain: intent.finalSettledTxChain,
            finalSettledTxAccumulatorRoot: intent.finalSettledTxAccumulatorRoot
        });
    }

    /// @notice DISABLED (P6-A / detail2 §H-3, C2). Permanently reverts.
    /// @dev SECURITY: the BP-censorship special-close was gated only by `verifier.verifySpecialClose`,
    ///      a tautological `_matches` stub (the "proof" is just `keccak(public inputs)`, computable by
    ///      anyone), so anyone could fabricate the accusation, slash an honest BP and freeze the
    ///      channel (freeze-grief). A SOUND proof of the fault requires non-inclusion of the BP-signed
    ///      block in the finalized medium-block chain — a cross-layer commitment that lives in the
    ///      validity/`IntmaxRollup` layer and does not exist yet. Until it does, the entry point is
    ///      reverted. Safety while disabled: only the (stub-gated) slash+freeze is unavailable; no
    ///      member funds move, and `bpBondCredits` is a separate, possibly-unfunded pot. The stub
    ///      verifier (`ChannelSettlementVerifier.verifySpecialClose`) is left in place but unreachable.
    ///      The signature (and ABI selector) is kept so callers fail closed with a clear error.
    function submitSpecialClose(SpecialClose calldata, bytes calldata) external pure {
        revert SpecialCloseDisabled();
    }

    function cancelClose(CancelCloseRequest calldata request, bytes calldata compactProof) external releaseRuntime {
        if (!pendingClose.active) revert CloseNotActive();
        if (request.closeIntentDigest != pendingClose.closeIntentDigest) {
            revert CloseIntentDigestMismatch();
        }
        // SECURITY (audit 2026-08-28 §5, "Cancel monotonicity" — defence in depth): the cancel
        // circuit already asserts `close_final_state_version < revived_state_version` with a
        // U64-correct comparator (`cancel_close_circuit.rs`) and connects the explicit closing
        // version PI to the proof while recomputing the IMCS ID that L1 pins to
        // `pendingClose.closeIntentDigest`. That made the
        // property SINGLE-LAYER: a VK swap, a verifier regression, or a mis-keyed statement would
        // silently remove the only barrier against cancelling a close with an OLDER state — i.e.
        // reviving a channel into a stale head. Re-asserted here so the property survives any
        // failure confined to the proof system. Cheap check BEFORE the expensive verify.
        if (request.revivedStateVersion <= pendingClose.finalStateVersion) {
            revert CloseNotNewer();
        }
        // ── SECURITY (A1, round 2 — the replayable cancel proof): a cancel must exhibit material
        //    strictly NEWER than any cancel already performed on this manager.
        //
        //    THE ATTACK the C-3 restore opened. `cancelClose` has no `msg.sender` gate, no
        //    challenge-window bound, and (before this line) no proof consumption. That was harmless
        //    only while the first cancel was a ONE-SHOT: it left `currentCloseFreezeNonce`
        //    permanently ahead of every producible state, bricking the channel for everyone. C-3
        //    correctly restored the counter — but a restored counter makes eras CYCLABLE, and a
        //    cyclable era turns one cancel proof into a REUSABLE capability. A non-member replays
        //    the identical `(closeIntentDigest, revivedStateVersion)` calldata every round: the
        //    honest member re-closes at the only state they hold, eve cancels it again, forever, for
        //    gas alone. Measured by the red team: 25 rounds in 15,000 s, under 9% of ONE 172,800 s
        //    H-3 era horizon — and each cancel zeroes `closeChallengeHorizon`, so H-3 bounds a
        //    single era and nothing across them.
        //
        //    THE FLOOR. `highestCancelledRevivedStateVersion` is monotone for the manager's
        //    lifetime. Eve's v21 proof raises it to 21 and then fails its own check; to cancel
        //    again she must exhibit an N-of-N-signed state at v22+, which she cannot manufacture —
        //    N-of-N includes the honest members she is censoring. Censorship is therefore bounded
        //    by the number of DISTINCT signed versions she holds, and every honest member controls
        //    the supply of those by declining to sign. It is not bounded by her gas budget.
        //
        //    WHY THIS IS NOT THE LATCH C-3 REJECTED. The rejected variant was a floor on CLOSES —
        //    a "minimum close state version" that `submitCloseIntent` had to clear. Clearing it
        //    required the COMPLETED N-of-N set over the revived state, which by construction only
        //    the canceller holds; in the C-3 scenario the canceller IS the withholding coordinator,
        //    so it converted "bricked for everyone" into "closable only by the attacker". This
        //    floor gates `cancelClose` and is equality-read by request entry points only;
        //    `submitCloseIntent`, finalization and every payout path remain untouched by it. So:
        //      - an HONEST CLOSE is never blocked. A member holding only v20 still runs
        //        `requestClose -> submitCloseIntent(v20) -> finalizeClose` with the floor at any
        //        value. Exit liveness — the property the C-3 brick destroyed — is preserved
        //        unconditionally, which is exactly what the rejected latch could not say.
        //      - an HONEST CANCEL is blocked only by material at least as new as its own. The floor
        //        rises solely to a version some party has PROVEN an N-of-N signature set exists at;
        //        a canceller wanting past it needs one strictly newer signed state, and channel
        //        state versions advance by exactly the N-of-N signing the honest members
        //        themselves perform. It can never be raised to an unreachable value by an outsider.
        //
        //    RESIDUAL (accepted, documented): if a withholding coordinator spends their v21 proof
        //    to cancel, an honest member later holding only v21 cannot cancel a fresh stale close
        //    with it. Their remedy is the one the design already relies on — challenge-replace
        //    inside the (A2-guaranteed) window, or let the close settle and exit. The failure mode
        //    is "the channel closes at a state one version older than the head", a bounded
        //    mis-allocation already inside the stale-close challenge game's threat model — not the
        //    unbounded exit censorship this line removes, and not a lockout.
        if (request.revivedStateVersion <= highestCancelledRevivedStateVersion) {
            revert CancelCloseReplay();
        }
        // SECURITY (Finding D): the manager injects the channel's REGISTERED member-set commitment
        // (NOT a caller request field), exactly as the close path does via `_runCloseVerify`. The
        // verifier strict-binds the proof's in-circuit member-set commitment to this value, so the
        // members who signed the higher-version revived state are the channel's registered members.
        if (!verifier.verifyCancelClose(
                channelId,
                request.closeIntentDigest,
                registeredMemberSetCommitment(),
                pendingClose.finalStateVersion,
                request.revivedStateVersion,
                request.revivedChannelStateDigest,
                compactProof
            )) revert InvalidCancelProof();

        // A1: CONSUME the material. Effect placed after the verify so the floor only ever advances
        // on a cancel that actually happened.
        highestCancelledRevivedStateVersion = request.revivedStateVersion;

        bytes32 closeIntentDigest = pendingClose.closeIntentDigest;
        // Exact-generation thaw occurs while this manager still exposes ClosePending. A delayed
        // cancel from an older era cannot unfreeze a later request because closeRequestGeneration
        // is deliberately never restored.
        ICloseFundingMaterializerState(closeFundingMaterializer)
            .unfreezeFromManager(uint32(channelId), closeRequestGeneration);
        delete pendingClose;
        channelStatus = ChannelLifecycleStatus.Active;
        // Restoring Active ends the frozen era; a future close needs a fresh requestClose()
        // (and therefore a fresh grace window).
        closeRequestedAt = 0;
        // H-3: the era is over — its absolute challenge horizon must not survive into the next one.
        closeChallengeHorizon = 0;
        // ── SECURITY (C-3, audit 2026-08-28 / close-detached-signing-design §8.4 "T-7a"): UNWIND
        //    the era bump that `requestClose()` made, because this cancel unwinds that close.
        //
        //    THE BUG. The close PI is `signedState.close_freeze_nonce + 1`
        //    (`close_circuit.rs:587-589`) and `submitCloseIntent` demands strict equality with this
        //    counter. NO shipped code ever advances a `ChannelState.close_freeze_nonce`: the block
        //    producer and the live-balance service actively REJECT a changed era
        //    (`block_producer.rs:678,777`, `live_balance_service.rs:1760`), the wallet copies it
        //    (`wallet_core.rs:2632`), and the only `+ 1` outside `CloseIntent::new` is inside
        //    `#[cfg(test)]`. So without this restore, ONE cancel leaves the counter at k while
        //    every producible state still carries k-1: no close intent can ever satisfy the
        //    equality again, and there is no
        //    emergency exit — all channel funds permanently locked. And it is an ATTACK, not just a
        //    footgun: `cancelClose` has no `msg.sender` restriction, a cancel proof needs no key
        //    material, so a coordinator who withholds a completed signature set for v_{N+1} can let
        //    an honest member close at v_N and then cancel — one transaction, channel bricked.
        //
        //    WHY THE RESTORE IS SOUND, not merely liveness-restoring. The era fence exists so a
        //    cosignature collected in era k cannot authorise a close in era k+1. Consider what this
        //    line actually does to the reachable state space: `requestClose` (+1), any number of
        //    `submitCloseIntent`s (counter untouched), then `cancelClose` (-1) leaves EVERY piece of
        //    close-lifecycle state exactly as it was before the `requestClose` — counter restored,
        //    `pendingClose` deleted, status Active, `closeRequestedAt` and the horizon zeroed. The
        //    round trip is a NO-OP on the machine. Therefore any close an attacker can mount after
        //    a cancel, they could have mounted instead of ever starting the cancelled attempt: the
        //    restore grants no capability the era fence was withholding, so no stale-close replay
        //    becomes possible that was not already in scope for the `_isNewer` challenge game.
        //
        //    Two structural facts make that argument tight rather than merely suggestive. (i) The
        //    cancel circuit's own fence `revived.close_freeze_nonce + 1 == close.close_freeze_nonce`
        //    (`cancel_close_circuit.rs:470-472`) forces the revived state into the SAME signed era
        //    as the close it cancels, so a cancel can never carry the channel across an era boundary
        //    — the counter it unwinds is provably the one its own close consumed. (ii) The cancel
        //    proof certifies a strictly NEWER signed state at that era exists
        //    (`cancel_close_circuit.rs:461-467`, re-asserted on-chain above), so the party who
        //    cancelled demonstrably holds better material than the stale close; if the griefer
        //    re-closes at the same stale version, that same material answers it again — by
        //    challenge-replacement inside the (now bounded, H-3) window, which is cheaper than a
        //    second cancel.
        //
        //    REJECTED ALTERNATIVE — a "minimum close state version" latch raised by `cancelClose`
        //    to `revivedStateVersion`. It looks safer and is strictly worse: satisfying the floor
        //    afterwards requires the COMPLETED N-of-N set over the revived state, which by
        //    construction only the canceller holds. In the C-3 attack the canceller IS the
        //    withholding coordinator, so the latch converts "channel bricked for everyone" into
        //    "channel closable only by the attacker" — a permanent lockout of every other member,
        //    with the attacker additionally free to choose the settlement state. That is a worse
        //    outcome than the bug. STILL REJECTED — and note that the A1 floor added above is a
        //    DIFFERENT object: it gates cancels, not closes, so it never has to be satisfied by an
        //    honest closer. The distinction is the whole argument; see the A1 block.
        //
        //    CORRECTION (A1, round 2): the paragraph above proves the restore grants no capability
        //    the ERA FENCE was withholding, and that is still true. It does NOT prove the restore
        //    is free, and the original text left that gap implicit: making eras cyclable also makes
        //    a cancel proof REUSABLE, which is a capability nothing else was withholding. Sentence
        //    (ii) above — "if the griefer re-closes at the same stale version, that same material
        //    answers it again" — reads as reassurance but is precisely the griefer's weapon when
        //    the griefer is the one holding the material. The A1 floor above closes that gap; the
        //    C-3 restore is sound only in conjunction with it.
        //
        //    UNDERFLOW: unreachable. `pendingClose.active` (checked above) implies a successful
        //    `submitCloseIntent`, which implies `ClosePending`, which only `requestClose()` sets —
        //    and it always bumps first. Solidity 0.8 checked arithmetic is the backstop.
        currentCloseFreezeNonce -= 1;
        emit CloseCancelled(closeIntentDigest, request.revivedChannelStateDigest, request.revivedStateVersion);
    }

    /// @notice DISABLED (P6-A / detail2 §H-3, C3). Permanently reverts.
    /// @dev SECURITY: this late-outgoing-debit correction is REDUNDANT. Its sole property — "the same
    ///      withdrawal cannot be paid more than once" — is already guaranteed by the in-circuit
    ///      nullifier used-sets enforced (check-then-set CEI) at EVERY payout path
    ///      (`IntmaxRollup.withdrawalNullifierUsed`, `usedWithdrawalNullifiers`,
    ///      `usedSharedNativeNullifiers`), and a close on a stale `state_version` is rejected by
    ///      `cancelClose` (C1). Its on-chain gate was also a forgeable `_matches` stub. The only thing
    ///      lost by disabling is an accepted, out-of-scope time-difference grief. The stub verifier
    ///      (`ChannelSettlementVerifier.verifyLateOutgoingDebit`) is left in place but unreachable.
    ///      The signature (and ABI selector) is kept so callers fail closed with a clear error.
    function submitLateOutgoingDebitCorrection(LateOutgoingDebitCorrection calldata, bytes calldata) external pure {
        revert LateOutgoingDebitDisabled();
    }

    /// @notice Finalize only the exact pending close named by the publisher's durable journal.
    /// @dev A newer valid close may replace an older pending close until its challenge deadline.
    ///      The digest check happens before any finalized state or accounting mutation, so a
    ///      preflight-to-mining replacement cannot redirect a signed finalization transaction.
    function finalizeCloseGuarded(bytes32 expectedCloseIntentDigest, uint64 expectedCloseRequestGeneration)
        external
        releaseRuntime
    {
        if (!pendingClose.active) revert CloseNotActive();
        if (
            pendingClose.closeIntentDigest != expectedCloseIntentDigest
                || closeRequestGeneration != expectedCloseRequestGeneration
        ) {
            revert CloseIntentDigestMismatch();
        }
        _finalizeClose();
    }

    function _finalizeClose() private {
        if (!pendingClose.active) revert CloseNotActive();
        // At equality a strictly-newer replacement is still admissible. Finalization must therefore
        // wait until the following timestamp; otherwise transaction order chooses which valid
        // transition wins at the boundary.
        if (block.timestamp <= pendingClose.challengeDeadline) {
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

        // Multi-token (TM-3): convert the TFD-bound (registry, amounts) vectors into per-BASE-token
        // accrual caps. `finalizeClose` runs at most once per manager lifetime (status becomes
        // Closed; a new close intent can never be submitted), so the mappings start from zero and
        // the legacy `totalWithdrawn = 0` reset is unnecessary. `+=` (not `=`) so that even in the
        // circuit-excluded duplicate-base-index case the cap degrades to the correct per-token
        // AGGREGATE rather than dropping a component (the in-circuit registry injectivity re-check
        // — TM-1 layer a — makes duplicates unreachable; the rollup's `escrowedByToken` ceiling —
        // layer b — bounds any residue independently).
        uint8 tc = pendingClose.tokenCount;
        finalizedTokenCount = tc;
        for (uint256 t = 0; t < tc; t++) {
            uint32 baseToken = pendingClose.tokenRegistry[t];
            finalizedTokenRegistry[t] = baseToken;
            finalizedChannelFundAmount[baseToken] += pendingClose.channelFundAmounts[t];
        }

        // IMCF authenticates the exact registry and amount vector of this ONE finalized state.
        finalizedTokenFundsDigest =
            verifier.tokenFundsDigest(pendingClose.tokenRegistry, tc, pendingClose.channelFundAmounts);

        // NOTE (Phase 2b review MINOR 3; corrected 2026-10-15): the Rust-side
        // `unallocated_confirmed_incoming` scalar is NOT consumed anywhere in this Manager (it is
        // not a close PI and not part of any L1 accounting variable), and neither
        // `CloseIntent::new` nor the close circuit refuses a nonzero value: a residue backed by
        // IMUI-tagged leaves in the signed accumulator is closable and is paid by
        // `submitPostCloseClaim`. A residue NOT covered by an IMUI leaf would be unpayable
        // (no ciphertext, no leaf, no late receipt); the only transition that produced one —
        // the L1 deposit fund-import leg — is no longer a signed head
        // (`wallet_core::build_l1_deposit_import`: one head per import), so no such closable
        // state exists. A per-token unallocated vector is therefore NOT required for the
        // Manager's per-token settlement soundness.
        channelStatus = ChannelLifecycleStatus.Closed;
        closeRequestedAt = 0;
        // H-3: the era's absolute challenge horizon is consumed with it.
        closeChallengeHorizon = 0;

        emit CloseFinalized(
            pendingClose.closeIntentDigest,
            pendingClose.burnTxHash,
            pendingClose.finalEpoch,
            pendingClose.channelFundAmounts[0],
            pendingClose.finalStateVersion,
            pendingClose.finalSettledTxChain
        );

        delete pendingClose;
    }

    // Partial withdrawals are not handled here. A burn is an ordinary inter-channel send to the
    // reserved BURN channel, paid by the rollup (`withdrawNative` / `withdrawERC20`) on its base
    // withdrawal proof alone, and ordered against a close by the `CloseFundingMaterializer`
    // journal: no post to a frozen channel, and a close needs backing anchored at or after the
    // channel's last posted block.

    function submitWithdrawalClaim(WithdrawalClaim calldata claim, bytes calldata compactProof)
        external
        releaseRuntime
    {
        if (channelStatus != ChannelLifecycleStatus.Closed) revert CloseNotActive();
        if (claim.closeIntentDigest != finalizedCloseIntentDigest) {
            revert CloseIntentDigestMismatch();
        }
        // B-2 (Option B): membership + recipient are PROOF-ENFORCED, not map-enforced. The
        // withdrawal-claim proof verifies the claimant's slot leaf (carrying the leaf-bound
        // `recipient`, B-1b) is included at `member_index` in the cosigner-signed
        // `finalizedBalanceStateH1` slot tree, and the nullifier is keyed on that same leaf's Regev
        // pk digest (fbcf448). This ADMITS delegates (never L1-registered under Option B) while a
        // non-member has no witness for a slot absent from the signed state, and the leaf-bound
        // recipient cannot be redirected. The former `registeredMemberIndexPlusOne` /
        // `registeredRecipientOf` gates were the pre-B1b authZ the proof now subsumes.
        // Multi-token (TM-8): the claimed slot must be ACTIVE in the finalized registry, and the
        // claim's base token must be the finalized registry's resolution of that slot. Both are
        // ALSO proof-enforced (circuit: token_slot < token_count, token_index ==
        // registry[token_slot] on the H1-committed registry; verifier: strict limbs 48/49) — this
        // re-check pins them against the TFD-bound finalized copy at the cap-lookup site too.
        if (claim.tokenSlot >= finalizedTokenCount) revert TokenSlotOutOfRange();
        if (finalizedTokenRegistry[claim.tokenSlot] != claim.tokenIndex) {
            revert TokenRegistryMismatch();
        }
        // Nullifier v2 (TM-5): [IMW2, close_intent(8), slot_regev_pk_digest(8), token_slot] —
        // derived IN-CIRCUIT from the leaf-bound Regev pk digest (never the grindable
        // member_pk_g) plus the token slot, so exactly one nullifier exists per (slot, token).
        // Consumption below is unchanged check-then-set CEI.
        if (usedWithdrawalNullifiers[claim.withdrawalNullifier]) {
            revert NullifierAlreadyUsed();
        }
        if (!verifier.verifyWithdrawalClaim(
                channelId,
                claim.closeIntentDigest,
                finalizedBalanceStateH1,
                claim.memberPkG,
                claim.recipient,
                claim.userAmountDigest,
                claim.amount,
                claim.tokenSlot,
                claim.tokenIndex,
                claim.withdrawalNullifier,
                compactProof
            )) revert InvalidWithdrawalClaimProof();

        _accrueWithdrawal(claim.tokenIndex, claim.amount, claim.recipient, claim.withdrawalNullifier);

        emit WithdrawalClaimAccepted(
            claim.closeIntentDigest,
            claim.withdrawalNullifier,
            claim.memberPkG,
            claim.recipient,
            claim.amount,
            claim.tokenIndex
        );
    }

    /// @notice Claim an imported incoming delta not applied to the final slot balance.
    /// @dev The version-2 proof opens an IMUI leaf in the signed final accumulator. Applying
    ///      the delta before close consumes that leaf. All claims share the per-token fund cap.
    function submitPostCloseClaim(PostCloseClaim calldata claim, bytes calldata compactProof)
        external releaseRuntime
    {
        if (channelStatus != ChannelLifecycleStatus.Closed) revert CloseNotActive();
        if (claim.closeIntentDigest != finalizedCloseIntentDigest) revert CloseIntentDigestMismatch();
        bool registered;
        for (uint256 i; i < finalizedTokenCount; ++i) {
            if (finalizedTokenRegistry[i] == claim.tokenIndex) registered = true;
        }
        if (!registered) revert TokenRegistryMismatch();
        bytes32 nullifier = _deriveSharedNativeNullifier(
            claim.closeIntentDigest, claim.incomingTxHash, claim.receiverPkG
        );
        if (usedSharedNativeNullifiers[nullifier] || usedWithdrawalNullifiers[nullifier]) revert NullifierAlreadyUsed();
        if (!verifier.verifyPostCloseClaim(
            channelId, claim.closeIntentDigest, claim.incomingTxHash, claim.receiverPkG,
            claim.recipient, nullifier, claim.amount, finalizedBalanceStateH1,
            finalizedSettledTxAccumulatorRoot, claim.tokenIndex, compactProof
        )) revert InvalidPostCloseClaimProof();
        usedSharedNativeNullifiers[nullifier] = true;
        _accrueWithdrawal(claim.tokenIndex, claim.amount, claim.recipient, nullifier);
        emit PostCloseClaimAccepted(claim.closeIntentDigest, nullifier, claim.receiverPkG,
            claim.recipient, claim.amount, claim.tokenIndex);
    }

    /// @notice Called atomically by the pinned materializer after a finalized receive proof and
    /// Rollup escrow credit. Preserve the original close fund digest; extend only the late cap.
    function creditLateIncoming(uint32 tokenIndex, uint64 amount, address recipient, bytes32 claimKey) external releaseRuntime {
        if (msg.sender != closeFundingMaterializer) revert InvalidPostCloseClaimProof();
        if (channelStatus != ChannelLifecycleStatus.Closed) revert CloseNotActive();
        lateIncomingFundAmount[tokenIndex] += amount;
        _accrueWithdrawal(tokenIndex, amount, recipient, claimKey);
    }

    function _accrueWithdrawal(uint32 tokenIndex, uint256 amount, address recipient, bytes32 nullifier) private {
        if (usedWithdrawalNullifiers[nullifier]) revert NullifierAlreadyUsed();
        uint256 total = totalWithdrawn[tokenIndex] + amount;
        if (total > finalizedChannelFundAmount[tokenIndex] + lateIncomingFundAmount[tokenIndex]) revert WithdrawalCapExceeded();
        totalWithdrawn[tokenIndex] = total;
        usedWithdrawalNullifiers[nullifier] = true;
        withdrawalCredits[tokenIndex][recipient] += amount;
        withdrawalPayouts[nullifier] = WithdrawalPayout({recipient: recipient, tokenIndex: tokenIndex, amount: amount});
    }

    /// @notice ABI-retained fail-closed tombstone for the old terminal-child/IPW2 close path.
    /// @dev A close is now funded only by `CloseFundingMaterializer.materializeSignedHead`, which
    ///      consumes the finalized H vector as one atomic operation. Keeping this selector makes
    ///      stale publishers fail explicitly instead of accidentally re-enabling double funding.
    function authorizeCloseFunding(uint32, bytes32) external pure returns (bytes32) {
        revert CooperativeCloseFundingDeprecated();
    }

    /// @notice Pull this CLOSED channel's remaining native backing from the bound rollup.
    /// @dev The rollup's recipient ledger is not channel-scoped, so this Manager asks it to transfer
    ///      exactly the remaining proof-bound cap. Any unrelated recipient-wide credit remains in
    ///      the Rollup ledger and cannot enter this channel's payout capacity.
    function pullChannelFunds() external returns (uint256 pulled) {
        // Share one guarded external entry point to avoid duplicating the entire native/ERC-20
        // pull core in optimized runtime bytecode. Both entry points are permissionless.
        return this.pullChannelTokenFunds(0);
    }

    /// @notice Pull this channel's funds for one base token (index 0 is native ETH) from the rollup (multitoken
    ///         §N-7): the ERC-20 mirror of `pullChannelFunds`. The channel's ERC-20 settlement
    ///         arrives as `IntmaxRollup.withdrawERC20` credits (recipient == this manager); this
    ///         moves exactly the remaining cap via the rollup's amount-scoped `withdrawToken`.
    /// @dev SECURITY: `nonReentrant` (the token is untrusted code). A fee-skimming/under-delivering
    ///      token reverts the entire Rollup pull atomically. Pre-existing credits are excluded by
    ///      exact amount selection and remain withdrawable in the Rollup ledger.
    ///      The token address resolves through the rollup's SET-ONCE registry (TM-10b) — the manager
    ///      keeps no second mutable copy.
    function pullChannelTokenFunds(uint32 tokenIndex) external releaseRuntime nonReentrant returns (uint256 pulled) {
        return _pullChannelFunds(tokenIndex);
    }

    /// @dev Shared native/ERC-20 pull core. The asset-specific balance measurement surrounds the
    ///      Rollup pull; the exact-cap reconciliation below is identical for both lanes.
    function _pullChannelFunds(uint32 tokenIndex) private returns (uint256 pulled) {
        if (channelStatus != ChannelLifecycleStatus.Closed) revert CloseNotActive();
        IERC20 token;
        if (tokenIndex != 0) {
            token = registry.tokenAddressOf(tokenIndex);
            if (address(token) == address(0)) revert TokenIndexNotRegisteredOnRollup();
        }
        uint256 received = receivedChannelFunds[tokenIndex];
        uint256 cap = finalizedChannelFundAmount[tokenIndex] + lateIncomingFundAmount[tokenIndex];
        if (received >= cap) revert ChannelFundsAlreadyReceived(tokenIndex);
        // A recipient-wide credit is not channel authority. The rollup records the exact IMCS
        // identity only after its bound materializer has validated and atomically credited every
        // active token in H. This single equality replaces token-by-token IPW2 flags.
        if (
            ICloseFundingMaterializerState(closeFundingMaterializer).materializedChannelExit(uint32(channelId))
                != finalizedCloseIntentDigest
        ) {
            revert CloseFundingProofNotMaterialized(tokenIndex);
        }
        uint256 expected = cap - received;
        if (tokenIndex == 0) {
            uint256 balBefore = address(this).balance;
            registry.withdraw(expected);
            pulled = address(this).balance - balBefore;
        } else {
            uint256 balBefore = _tokenBalanceOf(token, address(this));
            registry.withdrawToken(tokenIndex, expected);
            pulled = _tokenBalanceOf(token, address(this)) - balBefore;
        }
        if (pulled != expected) revert ChannelFundingMismatch(tokenIndex, expected, pulled);
        receivedChannelFunds[tokenIndex] = cap;
        emit ChannelFundsPulled(tokenIndex, expected, cap);
    }

    /// @notice Claim exactly the payout committed by one accepted withdrawal proof.
    /// @dev The nullifier fixes recipient, base token and amount. The aggregate credit remains an
    ///      accounting view only and cannot select or merge payouts. CEI deletes the scoped record,
    ///      subtracts the aggregate and increments the paid accumulator before value transfer.
    function claimWithdrawalCredit(bytes32 withdrawalNullifier)
        external
        releaseRuntime
        nonReentrant
        returns (uint256 amount)
    {
        WithdrawalPayout memory payout = withdrawalPayouts[withdrawalNullifier];
        amount = payout.amount;
        if (amount == 0) revert NoWithdrawalCredit();
        if (msg.sender != payout.recipient) revert WithdrawalPayoutRecipientMismatch();

        uint32 tokenIndex = payout.tokenIndex;
        uint256 available = withdrawalCredits[tokenIndex][payout.recipient];
        if (amount > available) revert InsufficientWithdrawalCredit();
        if (totalCreditedOut[tokenIndex] + amount > receivedChannelFunds[tokenIndex]) {
            revert WithdrawalCapExceeded();
        }

        IERC20 token;
        if (tokenIndex != 0) {
            token = registry.tokenAddressOf(tokenIndex);
            if (address(token) == address(0)) revert TokenIndexNotRegisteredOnRollup();
        }

        delete withdrawalPayouts[withdrawalNullifier];
        withdrawalCredits[tokenIndex][payout.recipient] = available - amount;
        totalCreditedOut[tokenIndex] += amount;
        emit WithdrawalClaimed(withdrawalNullifier, payout.recipient, tokenIndex, amount);
        if (tokenIndex == 0) {
            (bool ok,) = payout.recipient.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            uint256 balanceBefore = _tokenBalanceOf(token, payout.recipient);
            SafeERC20Lib.safeTransfer(token, payout.recipient, amount);
            if (_tokenBalanceOf(token, payout.recipient) - balanceBefore != amount) {
                revert TokenPayoutAmountMismatch();
            }
        }
    }

    /// @dev Compact strict `balanceOf` used by both ERC-20 value boundaries. A failed or malformed
    ///      token view is not a usable accounting oracle and therefore fails closed.
    function _tokenBalanceOf(IERC20 token, address account) private view returns (uint256 tokenBalance) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, shl(224, 0x70a08231))
            mstore(add(ptr, 4), account)
            if iszero(staticcall(gas(), token, ptr, 36, ptr, 32)) { revert(0, 0) }
            if lt(returndatasize(), 32) { revert(0, 0) }
            tokenBalance := mload(ptr)
        }
    }

    // RETIRED: the three aggregate `claimWithdrawalCredit` overloads are intentionally absent.
    // Only the proof/nullifier-scoped `claimWithdrawalCredit(bytes32)` payout surface exists.

    function getPendingClose() external view returns (PendingClose memory) {
        return pendingClose;
    }

    /// @dev Byte-exact mirror of Rust `close_state_id` and the close/cancel circuits:
    /// `keccak(IMCS, channelId, finalChannelStateDigest, closeFreezeNonce)`. The ABI-retained name
    /// `closeIntentDigest` now denotes this canonical state-derived identity. ABI-retained close
    /// metadata is checked for its one canonical representation by `_checkCanonicalCloseMetadata`;
    /// the verifier continues to bind the circuit-recomputed IMCL digest.
    function computeCloseIntentDigest(CloseIntent memory intent) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(bytes4(0x494d4353), channelId, intent.finalChannelStateDigest, intent.closeFreezeNonce)
        );
    }

    function _checkCloseProof(CloseIntent calldata intent, bytes calldata compactProof) internal view {
        _checkCanonicalCloseMetadata(intent);
        if (!registry.isFinalizedStateRoot(intent.channelFundIntmaxStateRoot)) {
            revert ChannelFundStateRootNotFinalized(intent.channelFundIntmaxStateRoot);
        }
        // F4/F7 SECURITY: the close proof's in-circuit `memberSetCommitment` must equal this
        // channel's registered member-set commitment, AND the close proof's `memberCount` limb must
        // equal this channel's `activeMemberCount`, so a close can only finalize with the channel's
        // registered members at the registered active/padding boundary (no non-member-key
        // substitution, no signer-set shrinking). Both are part of the close-proof public inputs
        // (103 raw limbs incl. the delegateCount and the multi-token tokenFundsDigest).
        //
        // The member/delegate boundary is frozen at settlement activation and checked exactly:
        //   * MEMBER side (limb 93 + memberSetCommitment limbs 85..92): L1-rooted. The commitment
        //     hashes `activeMemberCount` and is cross-checked against the rollup registry in the
        //     constructor (Finding E), so raising/lowering `member_count` cannot shrink the signer
        //     set. STRICT equality, unchanged.
        //   * DELEGATE side (limb 94): the constructor records the authenticated live-snapshot
        //     count after joins are frozen. The verifier requires strict equality with that
        //     immutable count and separately mirrors the in-circuit
        //     `member_count + delegate_count <= 1024` capacity bound. `delegate_count` never
        //     reaches a payout, a slot owner or a recipient — those are per-slot authenticated by
        //     the leaf-bound recipient / pk_digest / amount bindings in the claim circuits — and
        //     payouts stay hard-capped by `finalizedChannelFundAmount` / `receivedChannelFunds`.
        // A later join/membership change must therefore create a new explicitly activated
        // settlement snapshot; it cannot ride this manager's verifier binding.
        (bool verified, uint256[] memory publicInputs) = _runCloseVerify(intent, compactProof);
        if (!verified) revert InvalidCloseProof();
        // `bindCloseIntentPublicInputs` has just strict-bound PI limbs 95..102 to the verifier's
        // canonical IMTF recomputation over the complete ten-token vectors. Reusing those
        // authenticated limbs avoids ABI-encoding both fixed arrays a second time in this
        // size-constrained Manager; it does not trust an unverified caller field.
        bytes32 fundsDigest;
        for (uint256 i = 95; i < 103; ++i) {
            fundsDigest = bytes32((uint256(fundsDigest) << 32) | publicInputs[i]);
        }
        ICloseFundingMaterializerState(closeFundingMaterializer)
            .requireSignedHeadBacking(uint32(channelId), intent.finalSettledTxChain, fundsDigest);
    }

    /// @dev M-9 release invariant. Member signatures authenticate the final ChannelState, not
    /// caller-selected close telemetry. The circuit constrains the same values, while this cheap
    /// pre-check runs before verification.
    function _checkCanonicalCloseMetadata(CloseIntent calldata intent) private pure {
        if (
            intent.closeNonce != intent.closeFreezeNonce || intent.snapshotMediumBlockNumber != 0
                || intent.burnTxHash != bytes32(0)
        ) {
            revert NonCanonicalCloseMetadata();
        }
    }

    /// @dev Isolated frame for the close-field marshaling (keeps `_checkCloseProof` and
    /// `submitCloseIntent` under the via-IR stack limit once `delegateCount` is appended).
    ///
    /// The compact proof is intentionally sent straight to the constructor-pinned close adapter.
    /// Relaying the ~195 KiB blob through `ChannelSettlementVerifier` first duplicated ABI-copy and
    /// EIP-150 forwarding costs and made the real close transaction exceed a 30M block. The adapter
    /// still performs the identical immutable-VK MLE/WHIR verification. Only its authenticated,
    /// small 103-limb result crosses into the settlement verifier, whose strict binder remains the
    /// single source of truth for application semantics. Calling that stateless binder alone cannot
    /// reach this function or mutate Manager state: this path always executes the adapter call first.
    function _runCloseVerify(CloseIntent calldata intent, bytes calldata compactProof)
        internal
        view
        returns (bool verified, uint256[] memory publicInputs)
    {
        CloseProofFields memory fields = CloseProofFields({
            channelId: channelId,
            closeNonce: intent.closeNonce,
            finalEpoch: intent.finalEpoch,
            finalSmallBlockNumber: intent.finalSmallBlockNumber,
            closeFreezeNonce: intent.closeFreezeNonce,
            finalChannelStateDigest: intent.finalChannelStateDigest,
            finalBalanceStateH1: intent.finalBalanceStateH1,
            // Multi-token (TM-11): the supplied settlement vectors. The verifier RECOMPUTES the
            // tokenFundsDigest over exactly these and strict-binds it to PI limbs 95..102, so a
            // close can only be recorded with the member-signed (registry, count, amounts).
            channelFundAmounts: intent.channelFundAmounts,
            tokenRegistry: intent.tokenRegistry,
            tokenCount: intent.tokenCount,
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
            memberCount: activeMemberCount,
            // Legacy field name, exact semantics: settlement activation froze this count and the
            // verifier requires PI limb 94 to equal it (not merely to meet a floor).
            minDelegateCount: uint32(activeDelegateCount)
        });
        publicInputs = closeMleVerifier.verifyCompactPublicInputs(compactProof);
        verified = verifier.bindCloseIntentPublicInputs(fields, publicInputs);
    }

    /// @dev Challenge ordering: lexicographic strict `(finalEpoch, finalStateVersion)`.
    ///
    /// SECURITY: within one epoch the channel layer guarantees at most ONE fully-signed
    /// balance state per `state_version` (OneStatePerVersion; ChannelSafety2.lean
    /// `challenge_latest_wins2`, detail2 §H-4), so "higher version" is well-defined and the
    /// honest member's newest state always wins a challenge. The tiebreak is STRICT `>` —
    /// re-submitting an equal `(epoch, version)` pair is rejected (`CloseNotNewer`), which
    /// prevents challenge-window extension by replaying the pending state.
    function _isNewer(CloseIntent calldata intent, PendingClose memory current) internal pure returns (bool) {
        return intent.finalEpoch > current.finalEpoch
            || (intent.finalEpoch == current.finalEpoch && intent.finalStateVersion > current.finalStateVersion);
    }
}
