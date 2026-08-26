// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MleVerifier} from "@mle/MleVerifier.sol";
import {IERC20, SafeERC20Lib} from "./SafeERC20.sol";

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
    /// The 80-word segment enters the IMCI preimage, and together with `tokenRegistry` /
    /// `tokenCount` it is bound to the close PI's `tokenFundsDigest` limbs (verifier recompute).
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
    /// B-2 (doc/tasks/b2-delegate-close-threat-model.md §4d): a FLOOR on close-PI limb 94, NOT an
    /// exact expected value. The proof's own `delegateCount` limb must satisfy
    /// `limb94 >= minDelegateCount` and `memberCount + limb94 <= 1024`; the limb itself is
    /// authenticated by the N-of-N cosigner signature over the H1 it decommits, which is strictly
    /// stronger authority than L1 has for this field under Option B. Widened from the old packed
    /// `uint8` half so counts above 255 are representable at all (threat model A-10).
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
    /// Phase A: the close intent is verified by a REAL MLE/WHIR proof of the plonky2 close circuit
    /// (not a stub). The proof is the wrapped close `MleVerifier.MleProof` whose `publicInputs` are
    /// the 103 raw close limbs the verifier rebinds. `view` (reads the close VK), not `pure`.
    function verifyMemberSetUpdate(
        uint32 channelId_,
        uint64 newVersion,
        bytes32 oldCommitment,
        bytes32 newCommitment,
        uint8 oldCount,
        uint8 newCount,
        address recipient,
        MleVerifier.MleProof calldata mleProof
    ) external view returns (bool);

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
        uint8 tokenSlot,
        uint32 tokenIndex,
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
        uint32 tokenIndex,
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
        bytes32[8] memory memberPkGs,
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
    /// @notice Pull-payment ERC-20 claim (multitoken §N-7): the ERC-20 mirror of `withdraw()`.
    ///         `IntmaxRollup.withdrawERC20` credits `pendingTokenWithdrawals[t][manager]`;
    ///         `pullChannelTokenFunds(t)` calls this to move the tokens into the manager.
    function withdrawToken(uint32 tokenIndex) external;
    /// @notice The rollup's SET-ONCE `tokenIndex → ERC-20` registry (multitoken §N-7, TM-10b).
    ///         SECURITY: the manager resolves payout token addresses through THIS single registry —
    ///         it deliberately keeps NO second (potentially divergent/mutable) copy of the mapping.
    function tokenAddressOf(uint32 tokenIndex) external view returns (IERC20);
    /// @notice Authorize a partial-withdrawal auth digest on the rollup. Called by the settlement
    ///         manager after a finalized partial-withdrawal close proof (N-of-N channel consent).
    function authorizePartialWithdrawal(bytes32 authDigest) external;
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
    /// One SPHINCS+ key per member (D6 pad-to-MAX): a channel has between 2 and
    /// `MAX_MEMBER_COUNT` ACTIVE members, identified by their SPHINCS+ pubkey hash (bytes32), slot
    /// order 0..memberCount. Slots `memberCount..MAX_MEMBER_COUNT` are zero padding. Mirrors the
    /// Rust `MAX_CHANNEL_MEMBERS` constant (src/constants.rs).
    uint256 internal constant MAX_MEMBER_COUNT = 8;
    uint256 internal constant MIN_MEMBER_COUNT = 2;
    /// Fixed per-channel token capacity — the width of every `channelFundAmounts` / `tokenRegistry`
    /// array here. MUST equal Rust `MAX_CHANNEL_TOKENS` (src/constants.rs) and
    /// `ChannelSettlementVerifier.MAX_CHANNEL_TOKENS`, or the TFD recompute would disagree.
    uint256 internal constant MAX_CHANNEL_TOKENS = 10;

    error InvalidChannelId();
    error InvalidBpMemberSlot();
    error InvalidChallengePeriod();
    /// The deployer supplied a challenge period below the protocol floor on a non-local chain.
    /// `supplied` / `required` are carried so a failed deploy names the value it must be raised to.
    error ChallengePeriodTooShort(uint64 supplied, uint64 required);
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
    error PartialWithdrawalNotPending();
    error PartialWithdrawalAuxDataZero();
    error PartialWithdrawalChainMismatch();
    /// The withdrawal economics do not reproduce the N-of-N-signed IMBD burn descriptor.
    error PartialWithdrawalDescriptorMismatch();
    error PartialWithdrawalNotNewer();
    /// The claimed payout address is not a registered participant (member or delegate) of this
    /// channel (defence in depth — see `submitPartialWithdrawalIntent`).
    error PartialWithdrawalRecipientNotParticipant();
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

    event WithdrawalClaimed(address indexed recipient, uint32 indexed tokenIndex, uint256 amount);

    event PartialWithdrawalSubmitted(
        bytes32 indexed authDigest,
        bytes32 indexed chainKey,
        uint64 challengeDeadline,
        uint64 finalStateVersion
    );

    event PartialWithdrawalFinalized(bytes32 indexed authDigest, bytes32 indexed chainKey);

    event PartialWithdrawalCancelled(
        bytes32 indexed authDigest,
        bytes32 indexed revivedChannelStateDigest,
        uint64 revivedStateVersion
    );

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
        /// Multi-token (§N-6): registry-aligned per-token channel funds (Rust
        /// `ChannelFund.amounts`), ALWAYS full 10-wide (zero-padded). Slot 0 = the genesis-token
        /// burn denomination. SECURITY: bound — together with `tokenRegistry`/`tokenCount` — to
        /// the close proof's `tokenFundsDigest` PI by the verifier's on-chain recompute (TM-11),
        /// and the full 80-word vector enters the IMCI digest preimage.
        uint256[10] channelFundAmounts;
        /// Multi-token (§N-6): channel-local slot → BASE token index (Rust
        /// `BalanceState.token_registry`), zero-padded past `tokenCount`. NOT part of the IMCI
        /// preimage — bound through the `tokenFundsDigest` PI recompute (and, in-circuit, through
        /// the signed H1).
        uint32[10] tokenRegistry;
        /// Multi-token (§N-6): number of ACTIVE token slots (1..=10).
        uint8 tokenCount;
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

    struct AuthorizedWithdrawal {
        address recipient;
        uint32 tokenIndex;
        uint256 amount;
        bytes32 nullifier;
        bytes32 auxData;
        /// Regev tx leaf used as an input to IMBD. It is not independently trusted: `auxData`
        /// is pinned by the close chain and must equal the recompute over this leaf + economics.
        bytes32 txLeaf;
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
    /// §Q-4 (member-set updates): STORAGE, seeded by the constructor — a RotateKey on the bp slot
    /// advances it via `applyMemberSetUpdate` (stage Q3 slice C). The slot index itself never
    /// moves.
    bytes32 public bpPkG;
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
    /// §Q-4: STORAGE, seeded by the constructor at the genesis registration — an AddCosigner
    /// advances it via `applyMemberSetUpdate` (stage Q3 slice C; no setter exists before that
    /// entry lands, so behavior is identical to the former immutable today).
    uint8 public activeMemberCount;

    /// @notice detail2 §Q-5: the channel's member-set version — genesis registration = 0,
    /// strictly +1 per applied `MemberSetUpdate`. Mirrors `ChannelRecord.set_version`.
    uint64 public memberSetVersion;

    /// @notice The number of delegates REGISTERED AT DEPLOYMENT (delegate account). Mirrors the Rust
    /// `ChannelRecord.delegate_count` / `BalanceState.delegate_count` AT THAT MOMENT. Delegates do
    /// NOT co-sign and are NOT part of `memberBindings`/`memberPkGs`/the IMCM commitment.
    ///
    /// B-2 (doc/tasks/b2-delegate-close-threat-model.md): this is a MONOTONE FLOOR for the close
    /// path, NOT the channel's current delegate count. Under Option B, L1 registration is
    /// cosigners-only and there is no per-join L1 transaction, so a channel's true delegate count
    /// can (and normally does) exceed this value — every browser join after deployment increments it
    /// off-chain. The close proof's own `delegateCount` limb carries N-of-N cosigner authority (it
    /// decommits the signed H1); this immutable only lets L1 refuse a close whose active region is
    /// NARROWER than the delegate population registered here. See `_checkCloseProof`.
    /// SCOPE (review finding 6): a CARDINALITY bound, NOT an identity one — L1 binds no delegate to
    /// a balance-slot INDEX (`delegateBindings` is an unordered `(pkG, recipient)` set as far as the
    /// close PI is concerned), so this cannot protect a NAMED delegate from being displaced; it only
    /// stops the active region being shrunk below the registered count. The old strict equality had
    /// exactly the same property. See `ChannelSettlementVerifier.CloseDelegateCountOutOfRange`.
    /// Deployment invariant (unchanged, separate from the close bound):
    /// `activeMemberCount + activeDelegateCount <= MAX_MEMBER_COUNT` (the 16-slot on-chain binding
    /// arrays); the close path's ceiling is the wider 1024-participant capacity.
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
    /// @notice Σ accepted withdrawal/post-close claim amounts per base token (accrual bound).
    mapping(uint32 => uint256) public totalWithdrawn;

    /// @notice Real value this manager has pulled from the rollup per base token (cumulative
    ///         `pullChannelFunds` / `pullChannelTokenFunds` balance deltas; index 0 = native ETH).
    ///         SECURITY: this — NOT the intent-declared `finalizedChannelFundAmount[t]` — is the
    ///         authoritative cross-channel/cross-token solvency ceiling: `claimWithdrawalCredit`
    ///         enforces Σ token-t payouts ≤ receivedChannelFunds[t], so the manager can never pay
    ///         members more of ANY asset than the channel actually received on L1 in THAT asset
    ///         (no cross-token draw, TM-3).
    mapping(uint32 => uint256) public receivedChannelFunds;
    /// @notice Σ value actually paid out per base token via `claimWithdrawalCredit`.
    mapping(uint32 => uint256) public totalCreditedOut;

    /// @notice Accrued member credits per (base token, recipient).
    mapping(uint32 => mapping(address => uint256)) public withdrawalCredits;

    /// @notice The finalized close's token registry (channel-local slot → base token index) and
    ///         active count, stored TFD-bound at `finalizeClose`. `finalizedTokenRegistry` is
    ///         exposed via the auto-getter (per-index).
    uint32[10] public finalizedTokenRegistry;
    uint8 public finalizedTokenCount;

    mapping(bytes32 => bool) public usedWithdrawalNullifiers;
    mapping(bytes32 => bool) public usedSharedNativeNullifiers;
    mapping(bytes32 => bool) public usedLateOutgoingDebitNullifiers;

    // --- Partial withdrawal (GAP2: mid-channel burn → L1, channel stays open) ---
    bool public partialWithdrawalPending;
    bytes32 public pendingPartialWithdrawalAuthDigest;
    bytes32 public pendingPartialWithdrawalChainKey;
    bytes32 public pendingPartialWithdrawalCloseIntentDigest;
    uint64 public pendingPartialWithdrawalDeadline;
    uint64 public pendingPartialWithdrawalStateVersion;
    uint64 public pendingPartialWithdrawalEpoch;
    /// Era in which the pending intent was submitted. Any `requestClose()` increments the live
    /// nonce and thereby gives one member a unilateral veto during the challenge window.
    uint64 public pendingPartialWithdrawalCloseFreezeNonce;

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
        // SECURITY (fund mis-allocation, not liveness): a nonzero-but-tiny window voids the
        // challenge game just as completely as zero does — see CHALLENGE_PERIOD_SECS. Every deploy
        // script in this repo used to hardcode 1 second because the anvil E2Es cannot wait a day;
        // that value is now confined to the local devnet BY THE CONTRACT, so it cannot be carried
        // to a public chain by a script edit, a copied script, or bespoke deploy tooling. This is a
        // deployment-time floor only — it costs nothing at runtime and cannot be relaxed later,
        // which is deliberate: `challengePeriod` is immutable and has no setter, so a channel
        // deployed short can never be repaired.
        if (
            block.chainid != LOCAL_DEVNET_CHAIN_ID &&
            challengePeriod_ < CHALLENGE_PERIOD_SECS
        ) revert ChallengePeriodTooShort(challengePeriod_, CHALLENGE_PERIOD_SECS);

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

    event MemberSetUpdated(
        uint64 indexed newVersion,
        bytes32 oldCommitment,
        bytes32 newCommitment,
        uint8 newCount,
        address newRecipient
    );

    error MemberSetUpdateWhileNotActive();
    error MemberSetVersionNotMonotone();
    error MemberSetUpdateCountInvalid();
    error MemberSetUpdateProofInvalid();
    error MemberSetUpdateRecipientInvalid();

    /// @notice detail2 §Q-4 (stage Q3, slice C): advance the channel's registered sig-cluster —
    ///         rotate one member's signing key, or add a co-signer — under a REAL MLE-verified
    ///         `MemberSetUpdateCircuit` proof. The proof's in-circuit statement (see the Rust
    ///         module doc): the PREVIOUS set's full N-of-N (batch Falcon aggregate, recursively
    ///         verified) signed the IMMS digest committing EXACTLY the
    ///         (oldCommitment → newCommitment) transition at `newVersion`, with the §Q-3
    ///         structural delta enforced in-circuit (one slot; rotation preserves the Regev
    ///         digest; an add sits at the left-packed boundary; never a removal).
    ///
    /// @dev SECURITY:
    ///  * `oldCommitment` is COMPUTED from this contract's own storage — the proof must speak
    ///    about the set the Manager currently holds, so replay of an old update (or an update for
    ///    a different channel — channelId is a bound limb) is impossible; `newVersion` must be
    ///    strictly `memberSetVersion + 1`.
    ///  * `newPkGs` is verified against the proof's `newCommitment` limb by recomputing the IMCM
    ///    keccak over it — the stored array can only become the exact set the OLD cluster signed.
    ///  * NO disable seam: `verifyMemberSetUpdate` reverts while the msu VK is uninitialized, and
    ///    the VK latch enforces degreeBits > 0 (the audit's V3 class is structurally excluded).
    ///  * Status gate: no set change while a close is pending or done — the close family binds
    ///    against the registered set, and moving it mid-challenge would re-point the binding.
    function applyMemberSetUpdate(
        bytes32[] calldata newPkGs,
        uint8 newCount,
        address newRecipient,
        uint64 newVersion,
        MleVerifier.MleProof calldata mleProof
    ) external nonReentrant {
        if (channelStatus != ChannelLifecycleStatus.Active) {
            revert MemberSetUpdateWhileNotActive();
        }
        if (newVersion != memberSetVersion + 1) revert MemberSetVersionNotMonotone();
        if (newPkGs.length != newCount || newCount < 2 || newCount > MAX_MEMBER_COUNT) {
            revert MemberSetUpdateCountInvalid();
        }
        // The proof-side delta allows only +0 (rotate) or +1 (add).
        if (newCount != activeMemberCount && newCount != activeMemberCount + 1) {
            revert MemberSetUpdateCountInvalid();
        }
        bool isAdd = newCount == activeMemberCount + 1;
        if (isAdd) {
            // B-1b: a joiner binds a fresh, unique exit address.
            if (newRecipient == address(0) || isMemberRecipient[newRecipient]) {
                revert MemberSetUpdateRecipientInvalid();
            }
        } else if (newRecipient != address(0)) {
            // The proof zero-forces the recipient limbs for a rotation; mirror it here so the
            // calldata cannot desynchronize from the bound limbs.
            revert MemberSetUpdateRecipientInvalid();
        }

        bytes32 oldCommitment = registeredMemberSetCommitment();
        bytes32[MAX_MEMBER_COUNT] memory padded;
        for (uint256 i = 0; i < newCount; i++) {
            padded[i] = newPkGs[i];
        }
        bytes32 newCommitment = verifier.closeMemberSetCommitment(padded, newCount);

        if (
            !verifier.verifyMemberSetUpdate(
                uint32(channelId),
                newVersion,
                oldCommitment,
                newCommitment,
                activeMemberCount,
                newCount,
                newRecipient,
                mleProof
            )
        ) revert MemberSetUpdateProofInvalid();

        // ── Apply ──
        // Rotation bookkeeping for the pkG-keyed registration maps: migrate any slot whose key
        // changed (delete the old key's entries, bind the new key at the same index/recipient).
        for (uint256 i = 0; i < MAX_MEMBER_COUNT; i++) {
            bytes32 oldPk = memberPkGs[i];
            bytes32 newPk = i < newCount ? padded[i] : bytes32(0);
            if (oldPk == newPk) continue;
            if (oldPk != bytes32(0)) {
                address recip = registeredRecipientOf[oldPk];
                delete registeredMemberIndexPlusOne[oldPk];
                delete registeredRecipientOf[oldPk];
                if (newPk != bytes32(0) && !isAdd) {
                    // rotation: same slot, same recipient, new key
                    registeredMemberIndexPlusOne[newPk] = i + 1;
                    registeredRecipientOf[newPk] = recip;
                }
            }
            if (newPk != bytes32(0) && isAdd && oldPk == bytes32(0)) {
                // the joiner's slot
                registeredMemberIndexPlusOne[newPk] = i + 1;
                registeredRecipientOf[newPk] = newRecipient;
            }
            memberPkGs[i] = newPk;
        }
        if (isAdd) {
            isMemberRecipient[newRecipient] = true;
        }
        activeMemberCount = newCount;
        memberSetVersion = newVersion;
        bpPkG = memberPkGs[bpMemberSlot];

        emit MemberSetUpdated(newVersion, oldCommitment, newCommitment, newCount, newRecipient);
    }

    function isNativeSendAllowed(uint64 suppliedCloseFreezeNonce) external view returns (bool) {
        return
            channelStatus == ChannelLifecycleStatus.Active &&
            suppliedCloseFreezeNonce == currentCloseFreezeNonce;
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
        // Multi-token: cheap structural bound BEFORE the proof check (defense-in-depth; the
        // strict TFD limb bind would reject an out-of-range count anyway, since the in-circuit
        // token_count is constrained to 1..=10 and keccak is collision-resistant).
        if (intent.tokenCount == 0 || intent.tokenCount > 10) revert TokenCountOutOfRange();
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
            // Genesis-token (slot 0) fund = the burn denomination; the full vector is TFD-bound.
            intent.channelFundAmounts[0],
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
    function submitLateOutgoingDebitCorrection(LateOutgoingDebitCorrection calldata, bytes calldata)
        external
        pure
    {
        revert LateOutgoingDebitDisabled();
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

        // NOTE (Phase 2b review MINOR 3, examined for Phase 3): the Rust-side
        // `unallocated_confirmed_incoming` scalar is NOT consumed anywhere in this Manager (it is
        // not a close PI and not part of any L1 accounting variable); the close path additionally
        // requires it to be ZERO (`CloseIntent::new` fail-closes on a nonzero residue). A per-token
        // unallocated vector is therefore NOT required for the Manager's per-token settlement
        // soundness; whether the Rust channel layer wants one for mid-life P2 bookkeeping is a
        // channel-layer (Phase 4+) question, out of L1 scope.
        channelStatus = ChannelLifecycleStatus.Closed;
        closeRequestedAt = 0;

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

    // -----------------------------------------------------------------------
    // Partial withdrawal (GAP2): mid-channel burn → L1 authorization
    // -----------------------------------------------------------------------

    function submitPartialWithdrawalIntent(
        CloseIntent calldata intent,
        MleVerifier.MleProof calldata proof,
        bytes32 prevSettledTxChain,
        AuthorizedWithdrawal calldata withdrawal
    ) external {
        if (channelStatus != ChannelLifecycleStatus.Active) revert ChannelClosed();

        _checkCloseProof(intent, proof);

        // The close circuit exposes `signedState.close_freeze_nonce + 1`, not the signed state's
        // nonce itself (`close_circuit.rs`, `incremented_close_freeze_nonce`). While the manager is
        // Active, `currentCloseFreezeNonce` is the signed-state era; therefore a real mid-channel
        // close proof must carry the NEXT nonce. Comparing the PI directly with the current nonce
        // would accept the mock fixture but brick every real proof at genesis (0 versus 1).
        if (intent.closeFreezeNonce != currentCloseFreezeNonce + 1) {
            revert InvalidFreezeNonce();
        }

        if (withdrawal.auxData == bytes32(0)) revert PartialWithdrawalAuxDataZero();

        // SECURITY: verify settled_tx_chain binding — the burn's IMBD descriptor
        // (`withdrawal.auxData`) was the LAST push in the N-of-N-signed chain.
        bytes32 expectedChain = keccak256(
            abi.encodePacked(uint32(0x494d5443), prevSettledTxChain, withdrawal.auxData)
        );
        if (expectedChain != intent.finalSettledTxChain) revert PartialWithdrawalChainMismatch();

        // ── Defence in depth (2026-07-28, doc/tasks/pw-auth-threat-model.md §4) ──────────────
        //
        // SECURITY — `withdrawal.auxData` is bound to the cosigned state by the chain recompute.
        // The IMBD check below then derives recipient/token/amount from that pinned value and the
        // burn's Regev tx leaf. `nullifier` remains supplied by the base withdrawal proof path: the
        // authorization is only a second factor and never replaces `_verifyWithdrawalSet`.
        //
        // Soundness remains conjunctive: every burn payout must go through
        // `withdrawNative` / `withdrawERC20`, where the leaf is proof-verified and this
        // authorization is only a SECOND FACTOR (channel consent) that can veto, never supply, a
        // field. The proof-free `claimAuthorizedWithdrawal` was REMOVED for exactly this reason.
        // These checks would NOT make a proof-free payout safe.

        // (a) The burned token must belong to the PROOF-BOUND active registry.
        //     `_checkCloseProof` above recomputed `tokenFundsDigest(tokenRegistry, tokenCount,
        //     channelFundAmounts)` and strict-bound it to close PI limbs 95..102 (TM-11), so this
        //     registry is MEMBER-SIGNED, not caller-declared. The Verifier also rejects
        //     `tokenCount` outside 1..=10 (ChannelSettlementVerifier:342), so the slot scan below
        //     is well-formed and cannot index past the fixed 10-wide arrays.
        //
        //     IMPORTANT: `intent.channelFundAmounts[t]` is the POST-BURN fund. Comparing the burn
        //     amount to that value would subtract the same burn twice: a valid pre-burn fund F and
        //     burn X expose F-X here, so `X <= F-X` rejects every burn over half the balance and
        //     every full-balance burn. The exact amount is already bound by IMBD below, while the
        //     channel transition/base spend proof enforce debit/no-underflow. Therefore this scan
        //     is registry membership only; it must not impose a second post-state amount cap.
        //     FAIL CLOSED: a token the channel never cosigned into its registry is rejected rather
        //     than defaulting to slot 0.
        {
            bool tokenFound = false;
            uint256 activeSlots = uint256(intent.tokenCount);
            if (activeSlots > MAX_CHANNEL_TOKENS) activeSlots = MAX_CHANNEL_TOKENS;
            for (uint256 t = 0; t < activeSlots; t++) {
                if (intent.tokenRegistry[t] == withdrawal.tokenIndex) {
                    tokenFound = true;
                    break;
                }
            }
            // NOTE: the first matching slot wins. In-circuit registry injectivity makes a duplicate
            // base token impossible in a legitimate registry.
            if (!tokenFound) revert TokenRegistryMismatch();
        }

        // (b) The payout address must be a registered participant of THIS channel.
        //     `isMemberRecipient` is written ONLY in the constructor — at :715-720 for the N-of-N
        //     members and :775-778 for delegates (whose recipients are registered precisely FOR the
        //     withdrawal path, :757) — and has no setter, so it is exactly "an L1 address bound to a
        //     registered participant of this channel at construction". An honest partial withdrawal
        //     always pays the burning member's own registered L1 address, so this rejects nothing
        //     legitimate. It does NOT establish entitlement BETWEEN participants.
        if (!isMemberRecipient[withdrawal.recipient]) {
            revert PartialWithdrawalRecipientNotParticipant();
        }

        // F-AUX-1: auxData is the value pinned by the N-of-N-signed settled-tx chain. Requiring it
        // to be the IMBD recompute makes the pinned value determine recipient/token/amount. The
        // base withdrawal proof later supplies those same economics to the IMPW authorization.
        bytes32 baseRecipient = bytes32(
            (uint256(2) << 248) | uint256(uint160(withdrawal.recipient))
        );
        bytes32 expectedDescriptor = keccak256(
            abi.encodePacked(
                bytes4(0x494d4244),
                withdrawal.txLeaf,
                baseRecipient,
                withdrawal.tokenIndex,
                withdrawal.amount
            )
        );
        if (withdrawal.auxData != expectedDescriptor) {
            revert PartialWithdrawalDescriptorMismatch();
        }

        // `chainKey` is retained ONLY as an off-chain correlation id in the emitted events. It is no
        // longer a single-use token.
        //
        // SECURITY (single-use removed): the former `usedPartialWithdrawalChains[chainKey]` guard
        // marked a burn's `(channelId, finalSettledTxChain)` consumed at finalize, so any intent —
        // including a griefer's front-run carrying a wrong, IMPW-only `nullifier` — permanently
        // burned the burn's one chain slot and stranded its L1 payout. That guard was a fossil of the
        // deleted proof-free `claimAuthorizedWithdrawal` payout (42640f1): its only job was to bound
        // "at most one AUTHORIZATION per chain state", which mattered only when an authorization
        // ALONE could pay. Every payout now goes through `withdrawNative`/`withdrawERC20`, gated by
        // the proof-side single-use `withdrawalNullifierUsed` (IntmaxRollup) — one burn, one
        // nullifier, one payout — so double-payout is already prevented and this guard was redundant.
        // Removing it makes a failed/garbage submit inert (re-submittable) instead of permanently
        // fund-stranding, at no soundness cost. Do not re-add it without re-introducing a proof-free
        // payout, which must not exist.
        bytes32 chainKey = keccak256(abi.encodePacked(channelId, intent.finalSettledTxChain));

        // Challenge replacement: if a pending intent exists, allow replacement only if the new state
        // is strictly newer (higher epoch/stateVersion).
        if (partialWithdrawalPending) {
            bool newer = intent.finalEpoch > pendingPartialWithdrawalEpoch ||
                (intent.finalEpoch == pendingPartialWithdrawalEpoch &&
                 intent.finalStateVersion > pendingPartialWithdrawalStateVersion);
            if (!newer) revert PartialWithdrawalNotNewer();
        }

        bytes32 authDigest = keccak256(
            abi.encodePacked(
                bytes4(0x494d5057),
                withdrawal.nullifier,
                withdrawal.recipient,
                withdrawal.tokenIndex,
                withdrawal.amount,
                withdrawal.auxData
            )
        );

        partialWithdrawalPending = true;
        pendingPartialWithdrawalAuthDigest = authDigest;
        pendingPartialWithdrawalChainKey = chainKey;
        pendingPartialWithdrawalCloseIntentDigest = computeCloseIntentDigest(intent);
        pendingPartialWithdrawalDeadline = uint64(block.timestamp) + challengePeriod;
        pendingPartialWithdrawalStateVersion = intent.finalStateVersion;
        pendingPartialWithdrawalEpoch = intent.finalEpoch;
        // Store the manager era observed at submission, rather than the proof's +1 close nonce.
        // `requestClose()` increments this value and thereby provides the unilateral veto.
        pendingPartialWithdrawalCloseFreezeNonce = currentCloseFreezeNonce;

        emit PartialWithdrawalSubmitted(
            authDigest,
            chainKey,
            pendingPartialWithdrawalDeadline,
            intent.finalStateVersion
        );
    }

    function finalizePartialWithdrawal() external {
        if (!partialWithdrawalPending) revert PartialWithdrawalNotPending();
        if (block.timestamp <= pendingPartialWithdrawalDeadline) revert ChallengeWindowOpen();
        // P0-9 / 1-of-N veto: requestClose() advances the era. A pending PW from the previous era
        // must then fail even though the burn was already excluded from channelFund. The old 12B
        // no-status-check argument was sound only under the premise that the base payout amount
        // equalled the channel debit; IMBD now enforces that equality, while this nonce check gives
        // any one member the deliberately accepted challenge-window veto/grief trade-off.
        if (pendingPartialWithdrawalCloseFreezeNonce != currentCloseFreezeNonce) {
            revert InvalidFreezeNonce();
        }

        bytes32 authDigest = pendingPartialWithdrawalAuthDigest;
        bytes32 chainKey = pendingPartialWithdrawalChainKey;

        delete partialWithdrawalPending;
        delete pendingPartialWithdrawalAuthDigest;
        delete pendingPartialWithdrawalChainKey;
        delete pendingPartialWithdrawalCloseIntentDigest;
        delete pendingPartialWithdrawalDeadline;
        delete pendingPartialWithdrawalStateVersion;
        delete pendingPartialWithdrawalEpoch;
        delete pendingPartialWithdrawalCloseFreezeNonce;

        IChannelRegistry(address(registry)).authorizePartialWithdrawal(authDigest);

        emit PartialWithdrawalFinalized(authDigest, chainKey);
    }

    function cancelPartialWithdrawal(
        CancelCloseRequest calldata request,
        MleVerifier.MleProof calldata proof
    ) external {
        if (!partialWithdrawalPending) revert PartialWithdrawalNotPending();
        if (request.closeIntentDigest != pendingPartialWithdrawalCloseIntentDigest) {
            revert CloseIntentDigestMismatch();
        }

        // SECURITY: mirrors cancelClose — the N-of-N signed a strictly newer state, proving the
        // pending partial withdrawal's state is stale. The verifier binds memberSetCommitment to
        // the registered channel members (same as cancelClose).
        if (
            !verifier.verifyCancelClose(
                channelId,
                pendingPartialWithdrawalCloseIntentDigest,
                registeredMemberSetCommitment(),
                request.revivedStateVersion,
                request.revivedChannelStateDigest,
                proof
            )
        ) revert InvalidCancelProof();

        bytes32 authDigest = pendingPartialWithdrawalAuthDigest;

        delete partialWithdrawalPending;
        delete pendingPartialWithdrawalAuthDigest;
        delete pendingPartialWithdrawalChainKey;
        delete pendingPartialWithdrawalCloseIntentDigest;
        delete pendingPartialWithdrawalDeadline;
        delete pendingPartialWithdrawalStateVersion;
        delete pendingPartialWithdrawalEpoch;
        delete pendingPartialWithdrawalCloseFreezeNonce;

        emit PartialWithdrawalCancelled(
            authDigest,
            request.revivedChannelStateDigest,
            request.revivedStateVersion
        );
    }

    function submitWithdrawalClaim(
        WithdrawalClaim calldata claim,
        MleVerifier.MleProof calldata proof
    ) external {
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
        if (
            !verifier.verifyWithdrawalClaim(
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
                proof
            )
        ) revert InvalidWithdrawalClaimProof();

        // Per-token accrual cap (TM-3): token-t claims accrue ONLY against token-t funds.
        uint256 newTotalWithdrawn = totalWithdrawn[claim.tokenIndex] + claim.amount;
        if (newTotalWithdrawn > finalizedChannelFundAmount[claim.tokenIndex]) {
            revert WithdrawalCapExceeded();
        }
        totalWithdrawn[claim.tokenIndex] = newTotalWithdrawn;
        usedWithdrawalNullifiers[claim.withdrawalNullifier] = true;
        withdrawalCredits[claim.tokenIndex][claim.recipient] += claim.amount;

        emit WithdrawalClaimAccepted(
            claim.closeIntentDigest,
            claim.withdrawalNullifier,
            claim.memberPkG,
            claim.recipient,
            claim.amount,
            claim.tokenIndex
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
        // B-2 (Option B): membership + recipient are PROOF-ENFORCED (see submitWithdrawalClaim). The
        // post-close proof verifies the receiver's slot leaf (leaf-bound `recipient`, B-1b) is
        // included at `receiver_member_index` in the signed `finalizedBalanceStateH1`, and binds
        // `receiver_pk_g` into the settled-tx `tx_hash` accumulator inclusion — so a delegate
        // receiver is admitted while a non-member has no witness and the payout cannot be redirected.
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
        // TM-16 defense in depth (mirrors submitWithdrawalClaim's TM-8 re-check): the claimed
        // base token must be one of the TFD-bound finalized registry entries — the channel can
        // only owe tokens it cosigned into its registry. The token is ALSO proof-enforced
        // (in-circuit: PI limb 56 IS ids limb 5 of the anchored `incomingTxHash` recompute;
        // verifier: strict limb bind below), and an unregistered token would fail the accrual
        // cap anyway (`finalizedChannelFundAmount[t] == 0`); this re-check pins it against the
        // finalized copy at the cap-lookup site too, with a precise error.
        bool tokenRegistered = false;
        for (uint256 i = 0; i < finalizedTokenCount; i++) {
            if (finalizedTokenRegistry[i] == claim.tokenIndex) {
                tokenRegistered = true;
                break;
            }
        }
        if (!tokenRegistered) revert TokenRegistryMismatch();
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
                // TM-16 (§N-6): the PROOF-BOUND base token (PI limb 56) — committed by the
                // anchored accumulator leaf, replacing the former genesis-registry[0] pin.
                claim.tokenIndex,
                proof
            )
        ) revert InvalidPostCloseClaimProof();

        // Cap accrual against the (intent-declared) per-token channel fund, mirroring
        // submitWithdrawalClaim (TM-3: token-t claims accrue ONLY against token-t funds).
        // SECURITY: post-close claims share the SAME per-token accrual budget as withdrawal
        // claims — without this, post-close claims could mint unbounded credits past the channel
        // fund. An unfunded-but-registered token fails closed here for any nonzero amount
        // (`finalizedChannelFundAmount[t] == 0`). (The authoritative ceiling is still
        // `receivedChannelFunds[t]`, enforced at payout.)
        uint256 newTotalWithdrawn = totalWithdrawn[claim.tokenIndex] + claim.amount;
        if (newTotalWithdrawn > finalizedChannelFundAmount[claim.tokenIndex]) {
            revert WithdrawalCapExceeded();
        }
        totalWithdrawn[claim.tokenIndex] = newTotalWithdrawn;
        usedSharedNativeNullifiers[sharedNativeNullifier] = true;
        withdrawalCredits[claim.tokenIndex][claim.recipient] += claim.amount;
        emit PostCloseClaimAccepted(
            claim.closeIntentDigest,
            sharedNativeNullifier,
            claim.receiverPkG,
            claim.recipient,
            claim.amount,
            claim.tokenIndex
        );
    }

    /// @notice Pull this channel's native ETH from the rollup into the manager. Permissionless: it
    ///         only moves the manager's own `pendingWithdrawals[manager]` (credited when the close
    ///         paid this manager via `IntmaxRollup.withdrawNative`). The balance delta is added to
    ///         `receivedChannelFunds[0]` (ETH = base token 0) — the authoritative payout ceiling.
    /// @dev nonReentrant; measures balance before/after the external `registry.withdraw()` call.
    function pullChannelFunds() external nonReentrant returns (uint256 pulled) {
        uint256 balBefore = address(this).balance;
        registry.withdraw(); // rollup pays pendingWithdrawals[manager] to this contract (receive())
        pulled = address(this).balance - balBefore;
        receivedChannelFunds[0] += pulled;
        emit ChannelFundsPulled(0, pulled, receivedChannelFunds[0]);
    }

    /// @notice Pull this channel's ERC-20 funds for one base token from the rollup (multitoken
    ///         §N-7): the ERC-20 mirror of `pullChannelFunds`. The channel's ERC-20 settlement
    ///         arrives as `IntmaxRollup.withdrawERC20` credits (recipient == this manager); this
    ///         moves them in via the rollup's `withdrawToken` pull and records the MEASURED
    ///         balance delta as token-t payout capacity.
    /// @dev SECURITY: `nonReentrant` (the token is untrusted code); the delta measurement counts
    ///      ONLY value received during this pull — a fee-skimming token under-credits (self-harm,
    ///      fail-safe direction) and unsolicited donations are not counted (they merely sit in the
    ///      contract, exactly like SELFDESTRUCT-forced ETH on the native path). The token address
    ///      resolves through the rollup's SET-ONCE registry (TM-10b) — the manager keeps no second
    ///      mutable copy.
    function pullChannelTokenFunds(uint32 tokenIndex) external nonReentrant returns (uint256 pulled) {
        IERC20 token = registry.tokenAddressOf(tokenIndex);
        if (address(token) == address(0)) revert TokenIndexNotRegisteredOnRollup();
        uint256 balBefore = token.balanceOf(address(this));
        registry.withdrawToken(tokenIndex); // rollup pays pendingTokenWithdrawals[t][manager]
        pulled = token.balanceOf(address(this)) - balBefore;
        receivedChannelFunds[tokenIndex] += pulled;
        emit ChannelFundsPulled(tokenIndex, pulled, receivedChannelFunds[tokenIndex]);
    }

    /// @notice Claim a member's accrued native-ETH credit (pull-payment). Convenience alias for
    ///         `claimWithdrawalCredit(0)` — keeps the pre-multitoken ETH call sites unchanged.
    function claimWithdrawalCredit() external returns (uint256 amount) {
        return claimWithdrawalCredit(0);
    }

    /// @notice Claim a member's accrued credit in ONE base token as real value (pull-payment).
    ///         `tokenIndex == 0` pays native ETH; any other index pays the L1-registered ERC-20.
    /// @dev SECURITY (TM-3, per-token CapInv — the Lean `execMT_payout_ceiling` site): the
    ///      cross-channel/cross-token solvency invariant is enforced HERE, PER BASE TOKEN —
    ///      `totalCreditedOut[t] + amount <= receivedChannelFunds[t]` — so the manager can never
    ///      pay out more of ANY asset than it actually received from the rollup in THAT asset,
    ///      regardless of inflated intents or intra-channel mis-accounting (accepted intra-channel
    ///      risks). Token-t credits can NEVER draw on token-t' (or ETH) capacity. Payout dispatch:
    ///      t == 0 → ETH transfer (existing pattern); else safeTransfer of the token resolved via
    ///      the rollup's SET-ONCE registry (the SAME registry the escrow used — no second copy,
    ///      TM-10b). CEI: credit zeroed + paid-out accumulator bumped BEFORE the external
    ///      transfer; nonReentrant for defense in depth.
    function claimWithdrawalCredit(uint32 tokenIndex) public nonReentrant returns (uint256 amount) {
        amount = withdrawalCredits[tokenIndex][msg.sender];
        if (amount == 0) revert NoWithdrawalCredit();
        if (totalCreditedOut[tokenIndex] + amount > receivedChannelFunds[tokenIndex]) {
            revert WithdrawalCapExceeded();
        }
        withdrawalCredits[tokenIndex][msg.sender] = 0;
        totalCreditedOut[tokenIndex] += amount;
        emit WithdrawalClaimed(msg.sender, tokenIndex, amount);
        if (tokenIndex == 0) {
            (bool ok, ) = msg.sender.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            IERC20 token = registry.tokenAddressOf(tokenIndex);
            if (address(token) == address(0)) revert TokenIndexNotRegisteredOnRollup();
            SafeERC20Lib.safeTransfer(token, msg.sender, amount);
        }
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
    ///
    /// Multi-token (§N-6, TM-11): the former single 8-word amount segment is widened IN PLACE to
    /// the ALWAYS-full-width 80-word `channelFundAmounts[0..10]` vector, byte-identical to the
    /// Rust preimage (`abi.encodePacked(uint256[10])` = 10 x 32 BE bytes; shared vector:
    /// `close_intent_digest_matches_solidity_shared_vector`). `tokenRegistry`/`tokenCount` are NOT
    /// part of the IMCI preimage (they bind through the tokenFundsDigest PI and the signed H1).
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
                    intent.channelFundAmounts,
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
        // channel's registered member-set commitment, AND the close proof's `memberCount` limb must
        // equal this channel's `activeMemberCount`, so a close can only finalize with the channel's
        // registered members at the registered active/padding boundary (no non-member-key
        // substitution, no signer-set shrinking). Both are part of the close-proof public inputs
        // (103 raw limbs incl. the delegateCount and the multi-token tokenFundsDigest).
        //
        // B-2 SECURITY (doc/tasks/b2-delegate-close-threat-model.md §4d/§5) — the member/delegate
        // boundary has TWO halves with DIFFERENT authority roots, and L1 asserts what it actually
        // can about each:
        //   * MEMBER side (limb 93 + memberSetCommitment limbs 85..92): L1-rooted. The commitment
        //     hashes `activeMemberCount` and is cross-checked against the rollup registry in the
        //     constructor (Finding E), so raising/lowering `member_count` cannot shrink the signer
        //     set. STRICT equality, unchanged.
        //   * DELEGATE side (limb 94): COSIGNER-rooted, by the Option B decision. Registration on L1
        //     is cosigners-only, so this contract's `activeDelegateCount` is a deployer assertion
        //     cross-checked against nothing (see the TRUST note at the constructor). The limb itself
        //     decommits a field of the H1 that every cosigner's Falcon signature covers, so it
        //     carries N-of-N authority — strictly MORE than the reference it used to be compared
        //     against. L1 therefore enforces only what it can justify: MONOTONICITY (the active
        //     region is at least as WIDE as the registered delegate population — a CARDINALITY
        //     bound; L1 binds no delegate to a slot index, so it cannot name who is excluded, review
        //     finding 6) and CAPACITY (the mirror of the in-circuit
        //     `member_count + delegate_count <= 1024` bound). `delegate_count` never
        //     reaches a payout, a slot owner or a recipient — those are per-slot authenticated by
        //     the leaf-bound recipient / pk_digest / amount bindings in the claim circuits — and
        //     payouts stay hard-capped by `finalizedChannelFundAmount` / `receivedChannelFunds`.
        // RESIDUAL (accepted, DLG-2): fully-colluding cosigners can sign any delegate balance or
        // freeze out a post-deploy joiner. The former strict equality never prevented that.
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
            // B-2: the registered delegate count is a FLOOR, not an exact expected value. A channel
            // that gained delegates after this manager was deployed (the normal case — L1 has no
            // per-join registration under Option B) still closes; one whose active region is
            // NARROWER than the registered delegate count does not. Cardinality only — see the
            // `activeDelegateCount` doc comment (review finding 6).
            minDelegateCount: uint32(activeDelegateCount)
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
