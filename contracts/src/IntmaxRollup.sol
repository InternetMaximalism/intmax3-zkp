// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BlobKZGVerifierExt} from "./BlobKZGVerifier.sol";
import {IPinnedMleVerifierV2} from "./IPinnedMleVerifierV2.sol";
import {IERC20, SafeERC20Lib} from "./SafeERC20.sol";

/// @title IntmaxRollup
/// @notice INTMAX3 validity proof rollup contract.
///
///  Three-layer block architecture:
///    Off-chain — "fast blocks" (~5 seconds):
///       Pure user-tx blocks. No deposits.
///       Aggregators collect txs and build blocks off-chain.
///       Each block still has a block_number and updates the hash chain
///       inside the ZK circuit, but is NOT individually posted to L1.
///
///    Layer 1.1 — "posting rounds" (~5 minutes, on-chain calldata):
///       Aggregators call `postBlock(SubBlock[])` to commit a batch of
///       fast blocks to L1 as calldata.  The contract iterates over the
///       batch and recomputes the cumulative block_hash_chain.
///       Deposits are processed at this boundary only (applied to the
///       last sub-block in the batch).
///       `blockHashChainAt[lastBlockNumber]` is recorded for the batch.
///
///    Layer 1 — "finalization" (~6 hours, validity proof):
///       The sequencer posts each validity proof blob via `postBlockAndSubmit()`.
///       Anyone can call `finalize()` to verify the proof against the
///       on-chain block_hash_chain snapshots and accept the new state root.
///
///  Blob format (both finalize and fraudProof):
///    blob = the unique canonical `MLEWHIR3` compact byte stream
///
///  On-chain verification is MLE/WHIR-only (Groth16 removed). The validity public inputs are
///  bound to the proof through the compact proof's authenticated `publicInputs` field. Wire v3
///  constrains those raw values directly to canonical committed routed-witness cells; the wrapped
///  validity circuit additionally registers keccak256(ValidityPublicInputs) as its 8 PI limbs.
///
///  Verification checks (finalize — all must pass):
///    a) Blob commitment (KZG multi-point opening)
///    b) ValidityPublicInputs match on-chain state
///    c) Proof params binding (blob bytes == abi.encode(mleProof))
///    d) authenticated publicInputs[0..7] == keccak256(ValidityPublicInputs) as 8 BE u32 limbs
///       (SECURITY: binds the verified MLE proof to the claimed validity PIs)
///    e) MLE proof verification
///
///  Fraud proof rules:
///    1) Finalized intmax block number is recorded on-chain; each submission's
///       commitment includes the Eth block number at posting time.
///    2) Fraud proofs cannot target submissions at or before the finalized block.
///    3) Submissions not finalized within 3600 Eth blocks (~12 hours) after posting
///       are removed unconditionally (no ZKP verification needed).
///    4) Successful fraud proof deletes the target and all subsequent submissions.
///
///  Fraud proof ZKP checks (any failure = fraud):
///    a) Blob commitment + KZG binding + PI binding all PASS
///    b) Proof params binding PASSES (fake-fraud prevention)
///    c) MLE publicInputs don't bind keccak256(ValidityPublicInputs) OR MLE verification fails
contract IntmaxRollup {
    /// M-5 (audit28-08-2026): the local devnet chain id. The unpinned `postBlockAndSubmit`
    /// overload is accepted only here, so a real deployment cannot skip the pending-chain pin.
    uint256 private constant ROLLUP_LOCAL_DEVNET_CHAIN_ID = 31337;

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------
    error NoBlobAttached();
    // SECURITY (M-8: `finalize` failed silently). Every error in this group used to be DECLARED and
    // NEVER RAISED — the ABI advertised checks that produced nothing but a bare `return false`, so an
    // honest submitter whose proof the verifier could not even evaluate was told the same thing as a
    // forger. They are now each raised at exactly one site (see `finalize` and `fullVerify`), and
    // `finalize` re-emits the selector in `FinalizeRejected` so the cause survives its boolean return.
    /// @dev `finalize`: the caller's `stateRoot` is not the root this submission committed to.
    error CommitmentMismatch();
    /// @dev `finalize`: no submission with this id was ever posted.
    error SubmissionNotFound();
    error AlreadyFinalized();
    /// @dev `fullVerify` 1: the proof's final height moves `latestFinalizedBlockNumber` BACKWARDS.
    error FinalizedHeightRegression();
    /// @dev `fullVerify` 2: the proof does not start from the current finalized state root.
    error InitialStateMismatch();
    /// @dev `fullVerify` 3: `initialBlockChain` is not the on-chain chain hash at `initialBlockNumber`.
    ///      Split from the final-endpoint check below so the two are distinguishable in the event —
    ///      one shared error would have re-collapsed two causes into one indistinguishable path.
    error BlockChainMismatch();
    /// @dev `fullVerify` 4: `finalBlockChain` is not the on-chain chain hash at `finalBlockNumber`.
    error FinalBlockChainMismatch();
    /// @dev `fullVerify` 5: the proof's `finalExtCommitment` is not the `stateRoot` being finalized.
    error FinalExtCommitmentMismatch();
    /// @dev `fullVerify` 6: authenticated proof public inputs do not encode the PI preimage hash,
    ///      i.e. the claimed `validityPIs` are UNBOUND to the proof that step 7 verifies.
    error ValidityPublicInputsMismatch();
    /// @dev `fullVerify` 7: MLE/WHIR verification of the proof itself returned false.
    ///      NOTE: the former `ProofVerificationFailed()` was deleted rather than raised — on-chain
    ///      verification has been MLE/WHIR-only since Groth16 was removed, so it was an exact
    ///      synonym of this error and a second name for one cause is not diagnosability.
    error MleVerificationFailed();
    error InvalidPinnedMleVerifier(address verifier);
    error PinnedMleVerifierChainMismatch(address verifier, uint256 expected, uint256 actual);
    error DuplicatePinnedMleVerifier();
    // EIP-170 size relief: former string requires, converted to custom errors (semantics identical).
    error OnlyDeployer();
    // `EthTransferFailed` removed with `claimAuthorizedWithdrawal` (2026-07-28) — it was that
    // function's transfer-failure case and had no other use. It was the only native payout that
    // PUSHED to a caller-named third-party address; every remaining native payout is pull-payment
    // (`withdrawNative` credits `pendingWithdrawals`, the recipient then pulls via `withdraw(amount)`,
    // which sends to `msg.sender` and reverts with `WithdrawTransferFailed`).
    error EthDepositValueMismatch();
    error NonEthDepositMustNotCarryEth();
    error WithdrawTransferFailed();
    error KzgVerifierAlreadySet();
    error KzgVerifierNotAContract();
    error EmptyBatch();
    error InvalidStakeAmount();
    error NotAuthorizedBlockProducer();
    /// @dev The guarded production posting endpoint binds the transaction to the exact L1 rollup
    ///      predecessor used as the validity proof's initial block-chain state. A competing
    ///      authorized producer moving either field makes the transaction revert before stake or
    ///      batch state is written.
    error BlockHeadMoved();
    /// The producer's declared pending-chain pin is unknown or predates an already processed
    /// checkpoint. Every real pending-chain pair is retained so a proof may consume its exact
    /// historical prefix even when a later deposit/registration races publication.
    error PendingChainsMoved();
    error NotBlockProducerManager();
    error NothingToWithdraw();
    error SubmissionAlreadyFinalized();
    /// @dev SECURITY (C-1/B-4): the committed proof could not be EVALUATED (a deterministic
    ///      revert inside verification, e.g. `Plonky2GateEvaluator`'s
    ///      `unsupported gate with non-zero filter`). That is never evidence of fraud.
    error MleProofUnevaluable();
    /// @dev SECURITY (C-1/B-4): the fraud proof was gas-starved, so the verification call
    ///      could not run to completion. Never evidence of fraud — see `_mleVerdict`.
    error FraudProofGasStarved();
    error SubmissionBeforeFinalizedBlock();
    error NothingToReclaim();
    error SubmissionNotYetFinalized();
    // Size-optimized replacements for former require-strings (custom errors are ~4 bytes vs a full
    // string literal duplicated at each use site by via_ir inlining). Behavior is unchanged.
    error ReentrantCall();
    error ChannelIdZeroReserved();
    /// @notice channelId == BURN_CHANNEL_ID is reserved for the partial-withdrawal L1-exit destination
    /// (abstract2-1 §2.6) and may not host a real channel.
    error ChannelIdBurnReserved();
    error BpMemberSlotOutOfRange();
    error MemberPubkeyHashZeroReserved();
    error RegevPkDigestZeroReserved();
    error RecipientZeroReserved();
    // registerChannel validation (custom errors instead of require-strings — keeps IntmaxRollup
    // under the EIP-170 24,576-byte runtime limit after the delegate-account additions).
    error ChannelAlreadyRegistered();
    error DelegateCountExceedsActive();
    error MemberCountOrArrayLenInvalid();
    error MemberPubkeyHashesNotDistinct();
    error ReleaseRuntimeUnavailable();
    error InvalidChannelExitManager();
    error ChannelExitManagerAlreadyRegistered();
    error NotChannelExitManager();
    error NotChannelExitMaterializer();
    error ChannelExitAlreadyFrozen();
    error ChannelExitNotFrozen();
    error ChannelExitGenerationMismatch();
    error ChannelAlreadyExited();
    error ChannelExitHasUnfinalizedBlocks();
    error ChannelExitManagerNotClosed();
    error ChannelExitStatementMismatch();
    error ChannelExitTokenCountOutOfRange();
    error ChannelExitDuplicateToken();

    /// @dev Every value boundary is confined to the chain this Rollup was deployed on. The
    ///      constructor already requires both pinned MLE adapters to name `block.chainid`
    ///      (`allowedChainId()`), so `deploymentChainId` is exactly the chain the deployer opted
    ///      into when it pinned the verifiers (`MLE_VERIFIER_CHAIN_ID` in the deploy scripts; a
    ///      non-31337 deployment is an explicit opt-in). Repeating the guard at runtime covers
    ///      copied code/state that did not execute this deployment's constructor: the immutable
    ///      travels with the bytecode, so a Rollup moved to another chain fails closed.
    modifier releaseRuntime() {
        _requireReleaseRuntime();
        _;
    }

    function _requireReleaseRuntime() private view {
        if (block.chainid != deploymentChainId) revert ReleaseRuntimeUnavailable();
    }

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------
    event BlockPosted(
        uint64 indexed blockNumber, uint32 channelId, uint32[] keyIds, bytes32 txTreeRoot, bytes32 newBlockHashChain
    );

    event Deposited(
        uint64 indexed depositIndex,
        address depositor,
        bytes32 recipient,
        uint32 tokenIndex,
        uint256 amount,
        bytes32 auxData,
        bytes32 newDepositHashChain
    );

    /// @notice One SPHINCS+ key per member (F7): a channel registers exactly `CHANNEL_MEMBERS`
    /// members, each identified by their SPHINCS+ pubkey hash (bytes32). `memberPubkeysRoot` and
    /// `regevPkRoot` are the L1/keccak digest forms anchored in the registration record (mirrors
    /// the Rust `ChannelRecord`, src/common/channel.rs).
    event ChannelRegistered(
        uint64 indexed regIndex,
        uint32 indexed channelId,
        uint8 bpMemberSlot,
        bytes32[] memberPkGs,
        bytes32[] regevPkDigests,
        address[] recipients,
        bytes32 memberPubkeysRoot,
        bytes32 regevPkRoot,
        bytes32 newChannelRegHashChain
    );

    event Submitted(
        uint256 indexed id,
        address indexed submitter,
        bytes32 submissionCommitment,
        bytes32 proofHash,
        uint32 proofLength,
        bytes32 stateRoot
    );

    event Finalized(uint256 indexed id, bytes32 stateRoot);

    /// @notice SECURITY (M-8): emitted on EVERY rejecting exit of `finalize`, carrying the 4-byte
    ///         selector of the error that caused it. `finalize` keeps returning `false` instead of
    ///         reverting because its boolean IS load-bearing (`assertFalse(rollup.finalize(...))`
    ///         across the suite, and the `script/` runners branch on it), so the cause has to travel
    ///         out of band. Reason values:
    ///           - a selector from the group above  → that specific check failed;
    ///           - `0x00000000`                     → `fullVerify` aborted with NO revert data, i.e.
    ///             the verifier could not be EVALUATED (out of gas, an invalid opcode in a satellite).
    ///             That is explicitly NOT a claim that the proof is invalid — telling an honest user
    ///             "your proof is invalid" when the gate could not be evaluated is how gate-8
    ///             presented, and this code is what keeps the two apart on the validity path.
    event FinalizeRejected(uint256 indexed id, bytes4 reason);

    event FraudConfirmed(uint256 indexed id, address indexed prover);

    event WithdrawalCredited(address indexed recipient, uint256 amount);

    /// @notice Emitted per `Withdrawal` leaf paid out by `withdrawNative`.
    event PartialWithdrawalAuthorized(bytes32 indexed authDigest, address indexed manager);
    event SettlementManagerRegistered(address indexed manager);
    event BlockProducerSet(address indexed producer, bool allowed);
    event BlockProducerAdminSet(address indexed admin);

    event NativeWithdrawn(address indexed recipient, uint256 amount, bytes32 indexed nullifier, uint64 blockNumber);

    error WithdrawalExtCommitmentMismatch();
    error WithdrawalPublicInputsMismatch();
    error WithdrawalProofInvalid();
    error WithdrawalNullifierUsed();
    error WithdrawalNotEthToken();
    error WithdrawalEmptySet();
    error PartialWithdrawalNotAuthorized();
    error NotRegisteredSettlementManager();
    // --- Multi-token ERC-20 escrow (multitoken Phase 3, detail2 §N-7, TM-1/4/10) ---
    /// Token index 0 is permanently reserved for native ETH and can never map to an ERC-20.
    error TokenIndexZeroReservedForEth();
    /// The token address for an index is SET-ONCE (TM-10b: a remappable index would convert
    /// token-A escrow into token-B withdrawals; channels' H1-frozen registries reference these
    /// indices forever).
    error TokenIndexAlreadyRegistered();
    error TokenAddressZeroReserved();
    /// A registered token must be a deployed contract (a no-code address makes every token call a
    /// vacuous success, silently voiding the escrow).
    error TokenNotAContract();
    /// A nonzero tokenIndex deposit/withdrawal requires the index to be registered on L1. The old
    /// "accounting-only nonzero tokenIndex" regime is RETIRED (§N-7): unregistered-index deposits
    /// would record value in the deposit hash chain that no escrow backs.
    error TokenIndexNotRegistered();
    /// TM-4 (fee-on-transfer / rebasing / hook-skimming): the measured balanceOf delta of a
    /// deposit did not equal the stated amount. The deposit hash chain must never record
    /// unreceived value — such tokens are UNSUPPORTED and fail closed.
    error TokenDepositAmountMismatch();
    /// `withdrawERC20` pays ERC-20 leaves only; ETH leaves go through `withdrawNative`.
    error WithdrawalNotErc20Token();
    error NothingToWithdrawForToken();
    error TokenWithdrawalAmountMismatch();

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    /// @notice A single native withdrawal leaf, byte-identical to the Rust `common::Withdrawal`
    ///         (src/common/withdrawal.rs). The keccak `withdrawal_hash` chain folds these in order
    ///         (`solidity_keccak256` u32→4-byte-BE packing), and the fold is re-checked on-chain so
    ///         the amount/recipient paid is the one bound by the verified proof — never caller-declared.
    struct Withdrawal {
        address recipient; // 20 bytes  (Rust Address, 5×u32 big-endian)
        uint32 tokenIndex; // 4 bytes
        uint256 amount; // 32 bytes  (Rust U256, 8×u32 big-endian)
        bytes32 nullifier; // 32 bytes
        bytes32 auxData; // 32 bytes
    }

    struct Submission {
        // Domain-separated Proof-DA v2 commitment over both blob hashes, exact blob count,
        // keccak256(abi.encode(mleProof)), exact byte length, state root and Eth block number.
        bytes32 commitment;
        address submitter; // packed with `finalized` into one slot
        bool finalized;
        uint64 submittedAtBlock; // Eth block number when submitted
        // SECURITY (H-5): the state root THIS submission committed to. `commitment` already binds it,
        // but `finalize` receives only (submissionId, stateRoot, validityPIs, mleProof) — not the
        // blobHash/proofHash/proofLength needed to recompute `commitment` — so it had no way to tell
        // which submission a proof belonged to. Stored explicitly so `finalize` can bind the two.
        bytes32 stateRoot;
    }

    struct StakeInfo {
        address submitter;
        bool spent;
    }

    /// @notice A single fast block (~5 seconds) within a posting-round batch.
    struct SubBlock {
        uint32 channelId;
        uint64 timestamp;
        bytes32 txTreeRoot;
        uint32[] keyIds;
    }

    struct DepositRecord {
        address depositor;
        bytes32 recipient;
        uint32 tokenIndex;
        uint256 amount;
        bytes32 auxData;
    }

    struct BatchMetadata {
        uint64 startBlockNumber;
        uint64 endBlockNumber;
        bytes32 previousBlockHash;
        bytes32 previousDepositHashChain;
        uint64 postingRoundBefore;
        uint64 postingRoundAfter;
        uint64 processedDepositCountBefore;
        // G6: channel-registration chain snapshot for rollback (mirror of the deposit fields).
        bytes32 previousChannelRegHashChain;
        // SECURITY (H-1): the `pendingDepositHashChainBefore` / `pendingChannelRegHashChainBefore`
        // snapshots are RETIRED. They existed only to be restored by `_rollbackBatch`, which was
        // unsound (a batch never advances those live cumulative accumulators — see the comment in
        // `_rollbackBatch`). They had no other reader anywhere in the repo, so removing them also
        // frees a storage slot per submission.
    }

    /// @dev An immutable observation of one real pair of cumulative pending chains. A posting
    ///      proof is built against one such pair. Keeping historical prefixes makes publication
    ///      race-free: later permissionless deposits cannot force an already-proved block to use a
    ///      different chain, while the packed deposit/registration counts prevent either
    ///      accumulator from rolling back.
    struct PendingChainsCheckpoint {
        bytes32 depositHashChain;
        bytes32 channelRegHashChain;
        /// Zero is the unknown-pin sentinel. A real checkpoint stores a presence bit followed by
        /// the exact uint64 deposit count and uint64 registration count in one storage word.
        uint256 packedCounts;
    }

    /// @notice Mirrors the Rust `ValidityPublicInputs` struct.
    ///         All fields are u32-packed, matching the Rust keccak256 input layout.
    ///         initial_block_number (2 u32), initial_block_chain (8 u32),
    ///         initial_ext_commitment (8 u32), final_block_number (2 u32),
    ///         final_block_chain (8 u32), final_ext_commitment (8 u32),
    ///         prover (5 u32) = 41 u32 = 164 bytes.
    struct ValidityPublicInputs {
        uint64 initialBlockNumber;
        bytes32 initialBlockChain;
        bytes32 initialExtCommitment;
        uint64 finalBlockNumber;
        bytes32 finalBlockChain;
        bytes32 finalExtCommitment;
        address prover;
    }

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    /// @notice Per-circuit adapters. Each adapter owns one complete immutable v2 VK/configuration
    ///         and accepts only the canonical compact proof encoding.
    IPinnedMleVerifierV2 public immutable validityMleVerifier;
    IPinnedMleVerifierV2 public immutable withdrawalMleVerifier;

    /// @notice Chain on which this exact rollup deployment was constructed.
    uint256 public immutable deploymentChainId;

    /// @notice Deployment administrator for the remaining set-once operational dependencies.
    address public immutable deployer;

    /// @notice Spent withdrawal nullifiers (rollup-level, native payout path).
    /// SECURITY: each verified `Withdrawal.nullifier` (= Poseidon over the
    ///           settled transfer, recipient/amount-binding) may be paid out at
    ///           most once. Checked-then-set (CEI) before any value is credited.
    mapping(bytes32 => bool) public withdrawalNullifierUsed;

    /// @notice Authorized partial-withdrawal auth digests.
    /// SECURITY: a burn withdrawal (auxData != 0) is only paid out if the auth digest
    ///           keccak256("IPW2" || recipient || tokenIndex || amount || auxData)
    ///           was authorized by a registered settlement manager via a finalized close proof.
    mapping(bytes32 => bool) public partialWithdrawalAuthorized;

    /// @notice Registered settlement managers that may call `authorizePartialWithdrawal`.
    mapping(address => bool) public isRegisteredSettlementManager;

    /// @dev One audited close materializer per Rollup. It stores exact channel→Manager bindings
    ///      plus the freeze/reorg journal; escrow mutations remain in this contract. Set on the
    ///      first real Manager registration and immutable thereafter. Legacy authorization mocks
    ///      without `channelId()` do not initialize it.
    address private _channelExitMaterializer;

    /// @notice Whitelisted block producers that may call `postBlockAndSubmit`.
    /// SECURITY: block posting is permissioned. The set is empty at deploy (fail-closed —
    ///           nobody can post until a producer is authorized), and is managed by the deployer
    ///           OR the `blockProducerAdmin` via `setBlockProducer`. This prevents an anonymous
    ///           party from flooding the posting layer with spam/invalid submissions (the fraud
    ///           path is a recovery mechanism, not a spam-prevention gate).
    mapping(address => bool) public isBlockProducer;

    /// @notice The block-production authority. It may itself post (without being in the
    ///         whitelist) AND may designate other producers via `setBlockProducer`. This
    ///         decouples block-production governance from the deployer/admin key: block posting
    ///         is restricted to `blockProducerAdmin` or the addresses it designates.
    /// SECURITY: set/rotated only by the deployer (`setBlockProducerAdmin`); zero until set.
    address public blockProducerAdmin;

    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status = _NOT_ENTERED;

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        if (_status == _ENTERED) revert ReentrantCall();
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        _status = _NOT_ENTERED;
    }

    /// @notice On-chain block hash chain state.
    ///         Updated by `postBlock()` — iterates over a batch of sub-blocks.
    bytes32 public blockHashChain;
    mapping(uint64 => bytes32) public blockDepositHash;

    /// @notice Per-block channel-registration hash chain value folded into that block's hash (G6).
    ///         Mirrors `blockDepositHash`. Captured in `postBlock`; cleared on rollback.
    mapping(uint64 => bytes32) public blockChannelRegHash;

    /// @notice Snapshot of blockHashChain at posting-round boundaries.
    ///         Only the last block number of each batch is recorded.
    ///         finalize() references these snapshots for verification.
    mapping(uint64 => bytes32) public blockHashChainAt;

    /// @notice Current block number (incremented for every sub-block).
    uint64 public blockNumber;

    /// @notice Posting round counter (incremented once per postBlock call).
    uint64 public postingRound;

    /// @notice On-chain deposit hash chain state.
    ///         Updated by `deposit()`.
    bytes32 public depositHashChain;

    /// @notice Total deposit count.
    uint64 public depositCount;

    /// @notice Pending deposits for the next block (rolled into block's deposit_hash_chain).
    bytes32 internal _pendingDepositHashChain;

    mapping(bytes32 => PendingChainsCheckpoint) private _pendingChainsCheckpoints;

    // -----------------------------------------------------------------------
    // Identity registration (channel-as-base-user model).
    //
    // SECURITY: on-chain registration gives data availability; the validity proof
    // deterministically rebuilds the KeyTree / ChannelTree from these hash chains and
    // proves the tree contents match EXACTLY the registered set — no unregistered
    // entry, no omission (see tasks/channel-key-tree-design.md). Until the validity
    // proof consumes them (Step 4), these chains are RECORDED ONLY.
    // -----------------------------------------------------------------------

    /// @notice channel_id -> ChannelLeaf{member_pubkeys_root, ...} registration hash chain.
    bytes32 internal _pendingChannelRegHashChain;
    uint64 public channelRegCount;

    /// @notice Finding E (member-set consistency): the SINGLE SOURCE OF TRUTH for a channel's
    ///         member set + block-proposer identity, recorded at `registerChannel`. The close-path
    ///         `ChannelSettlementManager` constructor asserts its own member set + bp EQUAL these
    ///         values, so the validity-path (registration) and close-path authenticate the SAME
    ///         signer set (no divergent-signer-set attack).
    ///
    /// @dev `channelMemberSetCommitment[channelId]` is the close-form IMCM commitment computed with
    ///      the SAME fixed-8 keccak preimage as
    ///      `ChannelSettlementVerifier.closeMemberSetCommitment` — i.e.
    ///      `keccak256(bytes4(0x494d434d) || uint32(memberCount) || h_0 || .. || h_7)` with padding
    ///      slots (>= memberCount) zeroed. This is byte-identical to what the close path matches the
    ///      close proof's `member_set_commitment` PI against (asserted by
    ///      `IntmaxRollup.t.sol::test_channelMemberSetCommitmentMatchesVerifier`). A nonzero value
    ///      also acts as the per-channel one-time-registration guard.
    mapping(uint32 => bytes32) public channelMemberSetCommitment;
    /// @notice channelId -> registered block-proposer member slot (matches `channelBpPkG`).
    mapping(uint32 => uint8) public channelBpMemberSlot;
    /// @notice channelId -> registered block-proposer SPHINCS+ pubkey hash (member at `bpMemberSlot`).
    mapping(uint32 => bytes32) public channelBpPkG;

    /// @notice On-chain channel-registration hash chain accumulator (mirror of `depositHashChain`).
    ///         Advanced per posting round in `postBlock`; the resulting value is committed into the
    ///         registration block's hash (G6) and the validity proof's ext-state.
    bytes32 public channelRegHashChain;

    /// @notice Bounds on members per channel (one SPHINCS+ key per member, D6 pad-to-MAX; mirrors
    /// the Rust `MAX_CHANNEL_MEMBERS` constant in src/constants.rs). A channel registers between
    /// `MIN_CHANNEL_MEMBERS` and `MAX_CHANNEL_MEMBERS` ACTIVE members in slot order.
    uint32 internal constant MAX_CHANNEL_MEMBERS = 8;
    uint32 internal constant MIN_CHANNEL_MEMBERS = 2;

    /// @notice Reserved channel id for the partial-withdrawal burn destination (abstract2-1 §2.6;
    /// Rust `BURN_CHANNEL_ID`, src/constants.rs). No real channel may register here; a base-layer
    /// transfer routed to this id is an L1 exit (settled as a `Withdrawal`), never a channel credit.
    uint32 internal constant BURN_CHANNEL_ID = 0xFFFFFFFF;

    /// @notice IMCM domain word ("IMCM" = 0x494d434d) for the close-form member-set commitment.
    /// MUST equal `ChannelSettlementVerifier.CLOSE_MEMBER_SET_DOMAIN` so the commitment recorded by
    /// `registerChannel` is byte-identical to the one the close path matches (Finding E).
    uint32 internal constant CLOSE_MEMBER_SET_DOMAIN = 0x494d434d;

    /// @notice The token index reserved for native ETH. A deposit with this token index escrows
    ///         real ETH (msg.value must equal `amount`); any other token index is accounting-only
    ///         in v1 and must not carry ETH.
    // M-5 byte budget: made `internal` — no external consumer reads this getter (the JS side
    // defines its own local constant), so the public accessor was dead weight against EIP-170.
    uint32 internal constant ETH_TOKEN_INDEX = 0;

    /// @notice Sum of real native ETH held by this contract on behalf of queued/finalized deposits.
    /// SECURITY: `totalEscrowed` is the global ceiling for all future native payouts
    ///           (Σ payouts ≤ totalEscrowed). It is enforced later by an underflow-revert on every
    ///           decrement at payout time, so no payout path can ever release more ETH than was
    ///           escrowed here. It is intentionally kept disjoint from the `POST_BLOCK_STAKE` ETH
    ///           tracked by `stakeInfo`/`pendingWithdrawals` (fraud-stake accounting), which is NOT
    ///           part of this balance.
    /// @dev Multi-token (§N-7): ETH escrow accounting DELIBERATELY stays on `totalEscrowed` (not
    ///      `escrowedByToken[0]`) — minimal diff, and every existing ETH invariant/test keeps its
    ///      exact semantics. `escrowedByToken` is ERC-20-only (`tokenIndex != 0`); no path reads or
    ///      writes `escrowedByToken[0]`.
    uint256 public totalEscrowed;

    // -----------------------------------------------------------------------
    // Multi-token ERC-20 escrow (multitoken Phase 3, detail2 §N-7, TM-1/4/10)
    // -----------------------------------------------------------------------

    /// @notice APPEND-ONLY, SET-ONCE `tokenIndex → ERC-20 address` registry. Index 0 is native ETH
    ///         (never mapped). SECURITY (TM-10b): an index is IMMUTABLE once set — a remappable
    ///         index would turn token-A escrow into token-B withdrawals, and channels' H1-frozen
    ///         `token_registry` entries reference these base indices forever.
    mapping(uint32 => IERC20) public tokenAddressOf;

    /// @notice Per-token escrow ceiling (TM-1 layer b): Σ token-t payouts ≤ Σ token-t deposits,
    ///         enforced by Solidity-0.8 underflow-revert on every `withdrawERC20` decrement — the
    ///         per-base-token analogue of the global `totalEscrowed` ETH backstop. This holds even
    ///         if a colluding cosigner set registers duplicate base indices in a channel registry
    ///         (the in-circuit injectivity check is layer a; NEITHER layer alone suffices, TM-1).
    mapping(uint32 => uint256) public escrowedByToken;

    /// @notice Pull-payment ERC-20 credits per (token, recipient) — the ERC-20 mirror of the ETH
    ///         `pendingWithdrawals` pattern. `withdrawERC20` credits here (CEI, no token call in
    ///         the verification loop); recipients (incl. the ChannelSettlementManager) pull via
    ///         `withdrawToken`, so a reverting/hooking token transfer cannot block the payout of
    ///         other leaves and the manager's receiving path mirrors the ETH exact-amount pull.
    mapping(uint32 => mapping(address => uint256)) public pendingTokenWithdrawals;

    event TokenRegistered(uint32 indexed tokenIndex, address indexed token);
    event Erc20Withdrawn(
        address indexed recipient,
        uint32 indexed tokenIndex,
        uint256 amount,
        bytes32 indexed nullifier,
        uint64 blockNumber
    );
    event TokenWithdrawalClaimed(address indexed recipient, uint32 indexed tokenIndex, uint256 amount);

    function _requireDeployer() private view {
        if (msg.sender != deployer) revert OnlyDeployer();
    }

    /// @notice Register an ERC-20 for a base token index. Deployer-only (the contract's existing
    ///         admin pattern), APPEND-ONLY and SET-ONCE per index (TM-10b).
    /// @dev SECURITY: index 0 is reserved for native ETH; address(0) is rejected; the address must
    ///      be a deployed contract (a no-code address turns every token call into a vacuous
    ///      success, silently voiding the escrow). Once set, an index can NEVER be remapped.
    function registerToken(uint32 tokenIndex, address token) external {
        _requireDeployer();
        if (tokenIndex == ETH_TOKEN_INDEX) revert TokenIndexZeroReservedForEth();
        if (token == address(0)) revert TokenAddressZeroReserved();
        if (address(tokenAddressOf[tokenIndex]) != address(0)) revert TokenIndexAlreadyRegistered();
        if (token.code.length == 0) revert TokenNotAContract();
        tokenAddressOf[tokenIndex] = IERC20(token);
        emit TokenRegistered(tokenIndex, token);
    }

    mapping(uint256 => Submission) internal _submissions;
    uint256 public nextSubmissionId;

    /// @notice The latest finalized state root (= final_ext_commitment from the last accepted proof).
    bytes32 public latestFinalizedStateRoot;

    /// @notice Set of ALL state roots that have ever been finalized (the latest plus every prior).
    /// SECURITY: a native withdrawal proof binds to the state root it was proven against
    ///           (`ext_public_state_commitment`). Finalization advances `latestFinalizedStateRoot`
    ///           continuously, so checking equality against only the latest would lock honest
    ///           withdrawers out of an already-earned withdrawal the moment the next block finalizes.
    ///           Finalized roots are PERMANENT — `finalize` cannot re-target a finalized submission
    ///           and `fraudProof` cannot touch blocks at/before the latest finalized block — so a
    ///           root in this set can never be rolled back. Accepting any member is therefore sound
    ///           (the per-withdrawal nullifier still prevents double-spend across roots).
    mapping(bytes32 => bool) public isFinalizedStateRoot;

    /// @notice The latest finalized intmax block number.
    ///         Fraud proofs cannot target submissions at or before this block.
    ///         Updated by finalize().
    uint64 public latestFinalizedBlockNumber;

    // -----------------------------------------------------------------------
    // Fraud/Stake configuration
    // -----------------------------------------------------------------------
    uint256 private constant POST_BLOCK_STAKE = 1 ether;
    uint256 private constant FRAUD_REWARD_PERCENT = 90;
    uint256 private constant FRAUD_TREASURY_PERCENT = 10;

    /// @notice Submissions not finalized within this many Eth blocks after posting
    ///         can be removed unconditionally via fraudProof (no proof needed).
    /// @dev `_mleVerdict` outcomes — see `_mleVerdict` for why three failure modes are kept apart.
    uint8 private constant MLE_INVALID = 0; // verifier reverted InvalidMleProof (only fraud evidence)
    uint8 private constant MLE_VALID = 1; // verifier RETURNED true
    uint8 private constant MLE_UNEVALUABLE = 2; // verification reverted deterministically
    uint8 private constant MLE_STARVED = 3; // verification was gas-starved
    uint8 private constant MLE_PI_MISMATCH = 4; // fraud prover supplied the wrong PI preimage

    /// @dev SECURITY: the PoW-22 compact classifier must be remeasured below this conservative
    ///      entry floor after every verifier/profile change. A caller below the floor is
    ///      classified STARVED, never fraudulent. The parent full-transaction resource gate must
    ///      be rerun whenever the circuit envelope or verifier bytecode changes.
    uint256 private constant MIN_MLE_VERIFY_GAS = 25_000_000;

    uint256 private constant FINALIZE_DEADLINE_BLOCKS = 5 * 60 * 12;
    address public immutable fraudTreasury;

    mapping(uint256 => StakeInfo) public stakeInfo;
    mapping(address => uint256) public pendingWithdrawals;
    mapping(uint64 => DepositRecord) internal _depositRecords;
    mapping(uint256 => BatchMetadata) internal _batchMetadata;
    uint64 public processedDepositCount;

    /// @notice Mask to clear top 3 bits so a 256-bit value fits in the
    ///         BLS12-381 scalar field (used for KZG blob field elements).

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------
    constructor(
        address _fraudTreasury,
        IPinnedMleVerifierV2 _validityMleVerifier,
        IPinnedMleVerifierV2 _withdrawalMleVerifier,
        bytes32 _genesisStateRoot
    ) {
        address validityAdapter = address(_validityMleVerifier);
        address withdrawalAdapter = address(_withdrawalMleVerifier);
        if (validityAdapter == withdrawalAdapter) {
            revert DuplicatePinnedMleVerifier();
        }
        address validityCore = _requirePinnedVerifier(_validityMleVerifier);
        address withdrawalCore = _requirePinnedVerifier(_withdrawalMleVerifier);
        // A statement domain owns one adapter/core pair. Distinct adapter addresses are not
        // sufficient: two adapters can otherwise report the same core, or one statement can use
        // the other statement's adapter as its core. That defeats the deployment invariant the
        // release manifests enforce and makes a poisoned/mis-ordered deployment look initialized.
        // Same-pair adapter==core remains accepted for explicit test stubs; no identity may cross
        // the validity/withdrawal boundary.
        if (validityCore == withdrawalCore || validityCore == withdrawalAdapter || withdrawalCore == validityAdapter) {
            revert DuplicatePinnedMleVerifier();
        }
        fraudTreasury = _fraudTreasury;
        deployer = msg.sender;
        deploymentChainId = block.chainid;
        validityMleVerifier = _validityMleVerifier;
        withdrawalMleVerifier = _withdrawalMleVerifier;
        latestFinalizedStateRoot = _genesisStateRoot;
        // A non-zero genesis snapshot is already finalized by construction and must participate
        // in the same permanent membership relation as later finalized roots. Keep zero out of the
        // set: test deployments may use it as an unset sentinel, but it is never a withdrawable
        // snapshot under the strict finalized-root API.
        if (_genesisStateRoot != bytes32(0)) isFinalizedStateRoot[_genesisStateRoot] = true;
        // Genesis: block 0 has default (zero) hash chains
        blockHashChainAt[0] = bytes32(0);
        _recordPendingChainsCheckpoint();
    }

    function _requirePinnedVerifier(IPinnedMleVerifierV2 verifier) private view returns (address verifierCore) {
        address verifierAddress = address(verifier);
        if (verifierAddress.code.length == 0) revert InvalidPinnedMleVerifier(verifierAddress);

        uint256 verifierChainId;
        try verifier.allowedChainId() returns (uint256 chainId) {
            verifierChainId = chainId;
        } catch {
            revert InvalidPinnedMleVerifier(verifierAddress);
        }
        if (verifierChainId != block.chainid) {
            revert PinnedMleVerifierChainMismatch(verifierAddress, block.chainid, verifierChainId);
        }
        try verifier.core() returns (address coreAddress) {
            verifierCore = coreAddress;
        } catch {
            revert InvalidPinnedMleVerifier(verifierAddress);
        }
        if (verifierCore.code.length == 0) revert InvalidPinnedMleVerifier(verifierAddress);

        // Do not trust the adapter's reported chain on behalf of a different core. The concrete
        // pinned-v2 adapter enforces equality itself, but the parent constructor accepts an ABI
        // interface and must fail closed for substituted implementations too.
        uint256 coreChainId;
        try IPinnedMleVerifierV2(verifierCore).allowedChainId() returns (uint256 chainId) {
            coreChainId = chainId;
        } catch {
            revert InvalidPinnedMleVerifier(verifierCore);
        }
        if (coreChainId != block.chainid) {
            revert PinnedMleVerifierChainMismatch(verifierCore, block.chainid, coreChainId);
        }
    }

    /// @notice Register a settlement Manager. Legacy partial-withdrawal mocks without the immutable
    ///         `closeFundingMaterializer()` getter retain their historical authorization behavior;
    ///         a real Manager is additionally bound atomically to the set-once close satellite.
    function registerSettlementManager(address manager) external {
        _requireDeployer();
        isRegisteredSettlementManager[manager] = true;
        address materializer;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, shl(224, 0x492fbb9e)) // closeFundingMaterializer()
            // Yul evaluates call arguments right-to-left: `returndatasize()` must be read AFTER
            // the staticcall, so the call result is bound first.
            let ok := staticcall(gas(), manager, ptr, 4, ptr, 32)
            if and(ok, eq(returndatasize(), 32)) { materializer := mload(ptr) }
        }
        if (materializer != address(0)) {
            if (materializer.code.length == 0) revert InvalidChannelExitManager();
            address installed = _channelExitMaterializer;
            if (installed == address(0)) _channelExitMaterializer = materializer;
            else if (installed != materializer) revert InvalidChannelExitManager();
            assembly ("memory-safe") {
                let ptr := mload(0x40)
                mstore(ptr, shl(224, 0x3c72b923)) // bindManager(address)
                mstore(add(ptr, 4), manager)
                if iszero(call(gas(), materializer, 0, ptr, 36, 0, 0)) {
                    returndatacopy(ptr, 0, returndatasize())
                    revert(ptr, returndatasize())
                }
            }
        }
        emit SettlementManagerRegistered(manager);
    }

    /// @notice One asset write within the materializer's complete atomic H-vector transaction.
    /// @dev No token call occurs here. The only caller is the set-once audited materializer; its
    ///      outer frame validates uniqueness/completeness and any later failure reverts all writes.
    function creditChannelExit(address manager, uint32 tokenIndex, uint256 amount) external releaseRuntime {
        if (msg.sender != _channelExitMaterializer) revert InvalidChannelExitManager();
        if (tokenIndex == 0) {
            _creditNativeEscrow(manager, amount);
        } else {
            _creditTokenEscrow(tokenIndex, manager, amount);
        }
    }

    function _creditNativeEscrow(address recipient, uint256 amount) private {
        totalEscrowed -= amount;
        pendingWithdrawals[recipient] += amount;
    }

    function _creditTokenEscrow(uint32 tokenIndex, address recipient, uint256 amount) private {
        escrowedByToken[tokenIndex] -= amount;
        pendingTokenWithdrawals[tokenIndex][recipient] += amount;
    }

    /// @notice Authorize (or revoke) a block-producer address for `postBlockAndSubmit`.
    ///         Callable by the deployer OR the `blockProducerAdmin`. Rotatable: pass
    ///         `allowed = false` to revoke a compromised key.
    /// @dev SECURITY: the whitelist is empty at deploy, so `postBlockAndSubmit` is fail-closed
    ///      until a producer is authorized here. Designation is the `blockProducerAdmin`'s power
    ///      (so block posting is restricted to the admin or the addresses IT designates), with the
    ///      deployer retained as a break-glass manager. Deliberately does NOT auto-authorize the
    ///      deployer as a producer — the operational posting key stays distinct from the cold key.
    function setBlockProducer(address producer, bool allowed) external {
        if (msg.sender != deployer && msg.sender != blockProducerAdmin) {
            revert NotBlockProducerManager();
        }
        isBlockProducer[producer] = allowed;
        emit BlockProducerSet(producer, allowed);
    }

    /// @notice Set (or rotate) the block-production authority. Deployer-only.
    /// @dev SECURITY: `blockProducerAdmin` may itself post and may designate other producers via
    ///      `setBlockProducer`. Setting it to `address(0)` disables the admin role (leaving only
    ///      the explicit whitelist, deployer-managed). This is the address block posting is
    ///      restricted to (together with its designees).
    function setBlockProducerAdmin(address admin) external {
        _requireDeployer();
        blockProducerAdmin = admin;
        emit BlockProducerAdminSet(admin);
    }

    /// @notice The pinned KZG blob-binding satellite used by `fraudProof` (EIP-170 relief: the
    ///         large EIP-2537 verification bytecode lives in its own contract). Deployer-only,
    ///         set EXACTLY ONCE — behaviorally immutable.
    BlobKZGVerifierExt public kzgVerifier;

    /// @notice Pin the KZG blob-binding satellite. Deployer-only, set EXACTLY ONCE.
    /// @dev SECURITY: must be a deployed CONTRACT — a call to an address with no code succeeds
    ///      vacuously, which would turn the fraud path's KZG binding check into a no-op and allow
    ///      false fraud confirmations (rollback griefing). Until set, the KZG-binding branch of
    ///      `fraudProof` FAILS CLOSED (no fraud confirmation; the no-ZKP timeout-removal branch is
    ///      unaffected). This remaining satellite is pinned set-once after deployment.
    function setKzgVerifier(BlobKZGVerifierExt v) external {
        _requireDeployer();
        if (address(kzgVerifier) != address(0)) revert KzgVerifierAlreadySet();
        if (address(v).code.length == 0) revert KzgVerifierNotAContract();
        kzgVerifier = v;
    }

    /// @notice Authorize a partial-withdrawal auth digest. Only callable by registered settlement
    ///         managers after a close proof (proving N-of-N channel consent) has been verified and
    ///         the challenge period has elapsed.
    /// @param authDigest keccak256("IPW2" || recipient || tokenIndex || amount || auxData)
    function authorizePartialWithdrawal(bytes32 authDigest) external {
        if (!isRegisteredSettlementManager[msg.sender]) revert NotRegisteredSettlementManager();
        partialWithdrawalAuthorized[authDigest] = true;
        emit PartialWithdrawalAuthorized(authDigest, msg.sender);
    }

    // REMOVED (2026-07-28, doc/tasks/pw-auth-threat-model.md): `claimAuthorizedWithdrawal(Withdrawal)`.
    //
    // SECURITY (why it is gone, so it is never re-added): it paid native ETH out of the GLOBAL
    // `totalEscrowed` after checking ONLY `partialWithdrawalAuthorized[_withdrawalAuthDigest(w)]`.
    // It never called `_verifyWithdrawalSet`, so NOTHING proved the withdrawal's economics. The
    // historical v1 authorization bound only `withdrawal.auxData` to the cosigned close state;
    // caller-supplied economics then flowed into the digest. IPW2/IMD2 now authenticate source
    // channel, base nonce, recipient, token, and amount, but intentionally do not authenticate the
    // proof-derived nullifier. A proof-free payout would therefore still omit the base withdrawal
    // proof that establishes entitlement and single-use identity, so it must not be restored.
    //
    // The IPW2 authorization is a SECOND FACTOR (channel consent), not a payout authority. It is
    // used correctly in `withdrawNative` / `withdrawERC20`, where the economics come from the
    // VERIFIED withdrawal proof and the flag can only veto, never supply, a field. Burn payouts must
    // go through those entry points. Consequently a forged authorization is inert — exactly as it
    // already was for ERC-20, which never had a proof-free door.
    //
    // CONSEQUENCE, ACCEPTED: the proof-backed base half of partial withdrawal was never built
    // (`cmd_partial_withdraw`, doc/tasks/todo.md:90), so PW payout is NOT functional end to end
    // until it lands. A correct incomplete implementation beats an incorrect complete one.

    // postBlock()  —  post a batch of fast blocks (one posting round)
    // -----------------------------------------------------------------------

    /// @notice Post a batch of fast blocks (~5-second blocks) to L1 as one
    ///         posting round (~5 minutes).  All sub-blocks' data lives in
    ///         calldata for data availability.
    ///
    ///         Deposits are applied to the LAST sub-block in the batch only.
    ///         The deposit hash chain is CUMULATIVE: intermediate sub-blocks carry the chain as of
    ///         the previous round, and the last sub-block carries it including this round's deposits
    ///         (matches the Rust `deposit_hash_chain`; mirrors the channel-reg carry-forward).
    ///
    ///         `blockHashChainAt` is recorded only for the final block number
    ///         of the batch (the posting-round boundary).
    ///
    /// @notice Post a batch of fast blocks and submit the proof commitment in
    ///         a single transaction.
    /// @dev SECURITY: permissioned — posting is restricted to the `blockProducerAdmin` or the
    ///      producers it designates (`setBlockProducer`). Fail-closed: with no admin set and an
    ///      empty whitelist, nobody can post.
    /// @notice The live pending-chain pin a producer records when building a witness.
    /// @dev Every value returned here is retained as an immutable checkpoint. Publication consumes
    ///      the exact checkpoint named by the proof, not whatever newer pair happens to be live at
    ///      mining time. Later deposits/registrations therefore remain pending for the next block
    ///      instead of invalidating the already-built proof.
    function pendingChainsPin() public view returns (bytes32) {
        bytes32 depositChain = _pendingDepositHashChain;
        bytes32 registrationChain = _pendingChannelRegHashChain;
        bytes32 pin;
        assembly ("memory-safe") {
            mstore(0, depositChain)
            mstore(32, registrationChain)
            pin := keccak256(0, 64)
        }
        return pin;
    }

    function _recordPendingChainsCheckpoint() private {
        bytes32 depositChain = _pendingDepositHashChain;
        bytes32 registrationChain = _pendingChannelRegHashChain;
        uint256 packedCounts = 1 | (uint256(depositCount) << 1) | (uint256(channelRegCount) << 65);
        assembly ("memory-safe") {
            mstore(0, depositChain)
            mstore(32, registrationChain)
            let pin := keccak256(0, 64)
            mstore(0, pin)
            mstore(32, _pendingChainsCheckpoints.slot)
            let checkpointSlot := keccak256(0, 64)
            sstore(checkpointSlot, depositChain)
            sstore(add(checkpointSlot, 1), registrationChain)
            sstore(add(checkpointSlot, 2), packedCounts)
        }
    }

    /// @notice Local-devnet compatibility endpoint. Production publishers MUST use
    ///         `postBlockAndSubmitGuarded`, which additionally binds the proof predecessor.
    /// @dev SECURITY: accepting only the live pair created a terminal liveness trap: after local
    ///      terminal admission, one later permissionless deposit made the old proof unpostable and
    ///      using the new pin made it unverifiable. Historical checkpoints turn that race into a
    ///      prefix: this batch consumes its authenticated pair and newer records remain queued.
    ///      Unknown pins and checkpoints older than the already processed pair fail closed.
    function postBlockAndSubmit(
        SubBlock[] calldata subBlocks,
        bytes32 proofHash,
        uint32 proofLength,
        bytes32 stateRoot,
        bytes32 expectedPendingChains
    ) external payable nonReentrant {
        // Keep the legacy five-argument selector permanently local-only. `releaseRuntime` follows
        // the deployment chain, but this endpoint's preflight can be raced by another producer,
        // so a public deployment only ever publishes through `postBlockAndSubmitGuarded`.
        if (block.chainid != ROLLUP_LOCAL_DEVNET_CHAIN_ID) revert ReleaseRuntimeUnavailable();
        _postBlockAndSubmitPinned(subBlocks, proofHash, proofLength, stateRoot, expectedPendingChains);
    }

    /// @notice Post a batch using both its authenticated pending-chain checkpoint and the exact
    ///         rollup predecessor against which the validity witness was generated.
    /// @dev This is the only production publication endpoint. The predecessor guard is evaluated
    ///      before the stake is recorded or any block/submission state is mutated, closing the
    ///      preflight-to-mining race between independently authorized producers.
    function postBlockAndSubmitGuarded(
        SubBlock[] calldata subBlocks,
        bytes32 proofHash,
        uint32 proofLength,
        bytes32 stateRoot,
        bytes32 expectedPendingChains,
        uint64 expectedBlockNumber,
        bytes32 expectedBlockHashChain
    ) external payable releaseRuntime nonReentrant {
        if (blockNumber != expectedBlockNumber || blockHashChain != expectedBlockHashChain) {
            revert BlockHeadMoved();
        }
        _postBlockAndSubmitPinned(subBlocks, proofHash, proofLength, stateRoot, expectedPendingChains);
    }

    function _postBlockAndSubmitPinned(
        SubBlock[] calldata subBlocks,
        bytes32 proofHash,
        uint32 proofLength,
        bytes32 stateRoot,
        bytes32 expectedPendingChains
    ) private {
        bytes32 checkpointDepositChain;
        bytes32 checkpointRegistrationChain;
        uint256 checkpointCounts;
        bytes32 processedDepositChain = depositHashChain;
        bytes32 processedRegistrationChain = channelRegHashChain;
        uint256 processedCounts;
        assembly ("memory-safe") {
            mstore(0, expectedPendingChains)
            mstore(32, _pendingChainsCheckpoints.slot)
            let checkpointSlot := keccak256(0, 64)
            checkpointDepositChain := sload(checkpointSlot)
            checkpointRegistrationChain := sload(add(checkpointSlot, 1))
            checkpointCounts := sload(add(checkpointSlot, 2))

            mstore(0, processedDepositChain)
            mstore(32, processedRegistrationChain)
            let processedPin := keccak256(0, 64)
            mstore(0, processedPin)
            mstore(32, _pendingChainsCheckpoints.slot)
            processedCounts := sload(add(keccak256(0, 64), 2))
        }
        if (
            checkpointCounts == 0 || uint64(checkpointCounts >> 1) < uint64(processedCounts >> 1)
                || uint64(checkpointCounts >> 65) < uint64(processedCounts >> 65)
        ) {
            revert PendingChainsMoved();
        }
        _postBlockAndSubmit(
            subBlocks,
            proofHash,
            proofLength,
            stateRoot,
            checkpointDepositChain,
            checkpointRegistrationChain,
            uint64(checkpointCounts >> 1)
        );
    }

    function _postBlockAndSubmit(
        SubBlock[] calldata subBlocks,
        bytes32 proofHash,
        uint32 proofLength,
        bytes32 stateRoot,
        bytes32 checkpointDepositChain,
        bytes32 checkpointRegistrationChain,
        uint64 checkpointDepositCount
    ) private {
        if (!isBlockProducer[msg.sender] && msg.sender != blockProducerAdmin) {
            revert NotAuthorizedBlockProducer();
        }
        if (msg.value != POST_BLOCK_STAKE) revert InvalidStakeAmount();
        BatchMetadata memory meta =
            _postBlock(subBlocks, checkpointDepositChain, checkpointRegistrationChain, checkpointDepositCount);
        uint256 submissionId = _submit(proofHash, proofLength, stateRoot);

        stakeInfo[submissionId] = StakeInfo({submitter: msg.sender, spent: false});
        _batchMetadata[submissionId] = meta;
    }

    function _postBlock(
        SubBlock[] calldata subBlocks,
        bytes32 checkpointDepositChain,
        bytes32 checkpointRegistrationChain,
        uint64 checkpointDepositCount
    ) internal returns (BatchMetadata memory meta) {
        if (subBlocks.length == 0) revert EmptyBatch();

        bytes32 previousBlockHash = blockHashChain;
        bytes32 currentHash = previousBlockHash;
        uint64 currentBlockNumber = blockNumber;
        uint64 startBlockNumber = currentBlockNumber + 1;
        bytes32 previousDepositHashChain = depositHashChain;
        uint64 processedDepositsBefore = processedDepositCount;

        // --- Deposits: cumulative running chain (matches the Rust `deposit_hash_chain`) ---
        // SECURITY: `_pendingDepositHashChain` is the LIVE CUMULATIVE deposit chain — folded by
        // `deposit()`, seeded from genesis 0, and NOT reset per round. So an empty round carries it
        // forward and a deposit round folds onto the prior cumulative, byte-identical to the Rust
        // witness generator whose every block carries `self.deposit_hash_chain`
        // (block_witness_generator.rs:617,631). The previous per-round reset-to-0 diverged from Rust
        // for any block following a deposit and silently dropped deposit history across rounds —
        // this mirrors the channel-reg chain's existing carry-forward semantics below.
        bytes32 batchDepositHashChain = checkpointDepositChain;

        // --- Channel registrations: CUMULATIVE running chain (matches the Rust channel_reg chain) ---
        // SECURITY: `_pendingChannelRegHashChain` is the LIVE CUMULATIVE registration chain — folded
        // by `registerChannel`, seeded from genesis 0, and NOT reset per round. So a second
        // registration in a later round folds onto the FIRST registration's chain, byte-identical to
        // the Rust witness generator (`ChannelRegRecord::hash_with_prev_hash(self.channel_reg_hash_chain)`,
        // block_witness_generator.rs). The previous per-round reset-to-0 made a 2nd registration fold
        // onto 0 instead of the prior chain — fine for a single registration (the single-channel
        // path), but diverging from Rust for ANY channel registered in a later round than another
        // (the channel-to-channel path). Mirrors the cumulative deposit chain above.
        bytes32 previousChannelRegHashChain = channelRegHashChain;
        bytes32 batchChannelRegHashChain = checkpointRegistrationChain;

        uint64 previousPostingRound = postingRound;
        postingRound++;
        uint64 currentRound = postingRound;
        address exitMaterializer = _channelExitMaterializer;

        // --- Iterate over sub-blocks ---
        uint256 lastIdx = subBlocks.length - 1;
        for (uint256 i = 0; i < subBlocks.length; i++) {
            currentBlockNumber++;
            // The set-once close satellite rejects a post to a frozen/exited bound channel and
            // journals this exact per-channel predecessor for fraud/timeout rollback.
            if (exitMaterializer != address(0)) {
                uint32 postedChannel = subBlocks[i].channelId;
                assembly ("memory-safe") {
                    let ptr := mload(0x40)
                    mstore(ptr, shl(224, 0x194a42eb)) // recordPost(uint32,uint64)
                    mstore(add(ptr, 4), postedChannel)
                    mstore(add(ptr, 36), currentBlockNumber)
                    if iszero(call(gas(), exitMaterializer, 0, ptr, 68, 0, 0)) {
                        returndatacopy(ptr, 0, returndatasize())
                        revert(ptr, returndatasize())
                    }
                }
            }

            // Deposits: every block carries the cumulative chain. Intermediate sub-blocks carry the
            // chain as of the previous round (this round's deposits are all assigned to the last
            // sub-block); the last sub-block carries the chain including this round's deposits.
            // Mirrors the channel-reg carry-forward and the Rust generator (every block carries the
            // cumulative deposit_hash_chain).
            bytes32 depositHash = previousDepositHashChain;
            if (i == lastIdx) {
                depositHash = batchDepositHashChain;
            }

            // G6: the channel-reg chain value folded into this block's hash. Only the last sub-block
            // advances to the batch (post-registration) value; earlier sub-blocks carry the
            // unchanged prior accumulator. Mirrors the Rust witness generator (ordinary blocks carry
            // the unchanged chain; the registration block carries the post-apply chain).
            bytes32 regHash = previousChannelRegHashChain;
            if (i == lastIdx) {
                regHash = batchChannelRegHashChain;
            }

            currentHash = _computeBlockHash(
                currentHash,
                subBlocks[i].channelId,
                subBlocks[i].timestamp,
                subBlocks[i].keyIds,
                subBlocks[i].txTreeRoot,
                depositHash,
                regHash
            );
            blockDepositHash[currentBlockNumber] = depositHash;
            blockChannelRegHash[currentBlockNumber] = regHash;

            emit BlockPosted(
                currentBlockNumber, subBlocks[i].channelId, subBlocks[i].keyIds, subBlocks[i].txTreeRoot, currentHash
            );
        }

        // --- Update global state ---
        blockNumber = currentBlockNumber;
        blockHashChain = currentHash;
        blockHashChainAt[currentBlockNumber] = currentHash;
        depositHashChain = batchDepositHashChain;
        channelRegHashChain = batchChannelRegHashChain;
        processedDepositCount = checkpointDepositCount;

        meta = BatchMetadata({
            startBlockNumber: startBlockNumber,
            endBlockNumber: currentBlockNumber,
            previousBlockHash: previousBlockHash,
            previousDepositHashChain: previousDepositHashChain,
            postingRoundBefore: previousPostingRound,
            postingRoundAfter: currentRound,
            processedDepositCountBefore: processedDepositsBefore,
            previousChannelRegHashChain: previousChannelRegHashChain
        });
    }

    // -----------------------------------------------------------------------
    // deposit()  —  queue a deposit
    // -----------------------------------------------------------------------

    /// @notice Queue a deposit.  The deposit hash chain is updated immediately;
    ///         the deposit is associated with the next block.
    /// @dev Multi-token (§N-7): a nonzero `tokenIndex` now escrows REAL ERC-20 value. The former
    ///      "accounting-only nonzero tokenIndex" regime is RETIRED — an unregistered nonzero index
    ///      reverts instead of recording unbacked value in the deposit hash chain.
    function deposit(bytes32 recipient, uint32 tokenIndex, uint256 amount, bytes32 auxData)
        external
        payable
        releaseRuntime
        nonReentrant
    {
        // --- Native-ETH escrow (Phase 1) ---
        // SECURITY: For ETH deposits the caller MUST forward exactly `amount` wei; we then grow
        // `totalEscrowed`, the global ceiling for all future native payouts. CEI: this is a pure
        // effect on our own balance/storage — there is no external call on the ETH path, so there
        // is nothing to reorder. Stray ETH on a non-ETH deposit is rejected (no value sink), and
        // plain ETH transfers revert because the contract exposes no receive()/fallback().
        if (tokenIndex == ETH_TOKEN_INDEX) {
            if (msg.value != amount) revert EthDepositValueMismatch();
            totalEscrowed += amount;
        } else {
            // --- ERC-20 escrow (multitoken Phase 3, §N-7, TM-4/TM-10a) ---
            // SECURITY: the index must be L1-registered (set-once address, TM-10b) and the call
            // must not carry ETH. `safeTransferFrom` is an external call into UNTRUSTED token code
            // (ERC-777-style hooks) — `nonReentrant` (on this function) blocks reentry into every
            // guarded entry point, and the deposit hash chain / escrow effects below only run
            // AFTER the measured transfer.
            if (msg.value != 0) revert NonEthDepositMustNotCarryEth();
            IERC20 token = tokenAddressOf[tokenIndex];
            if (address(token) == address(0)) revert TokenIndexNotRegistered();
            // SECURITY (TM-4): measure the balanceOf(this) delta around the transfer and REVERT
            // unless delta == the stated amount. The deposit hash chain must NEVER record an
            // amount that was not actually received: fee-on-transfer / rebasing / hook-skimming
            // tokens are UNSUPPORTED and fail closed here rather than under-collateralizing the
            // escrow. (A hook that re-enters to inflate our balance mid-transfer can only make
            // delta LARGER, which also fails the strict equality.)
            uint256 balBefore = _tokenBalanceOf(token, address(this));
            SafeERC20Lib.safeTransferFrom(token, msg.sender, address(this), amount);
            if (_tokenBalanceOf(token, address(this)) - balBefore != amount) {
                revert TokenDepositAmountMismatch();
            }
            // Per-token escrow ceiling grows only by the VERIFIED-received amount (TM-1 layer b).
            escrowedByToken[tokenIndex] += amount;
        }

        uint64 idx = depositCount++;

        // Compute deposit hash matching Rust's Deposit::hash_with_prev_hash:
        //   keccak256(prev_hash || depositor(5×u32) || recipient(8×u32) || token_index(u32) || amount(8×u32) || aux_data(8×u32))
        //   Note: deposit_index and block_number are NOT included in the hash.
        bytes32 newHash =
            _computeDepositHash(_pendingDepositHashChain, msg.sender, recipient, tokenIndex, amount, auxData);
        _pendingDepositHashChain = newHash;
        _depositRecords[idx] = DepositRecord({
            depositor: msg.sender, recipient: recipient, tokenIndex: tokenIndex, amount: amount, auxData: auxData
        });
        _recordPendingChainsCheckpoint();

        emit Deposited(idx, msg.sender, recipient, tokenIndex, amount, auxData, newHash);
    }

    /// @notice Register a channel's member set. One SPHINCS+ key per member (D6 pad-to-MAX):
    ///         between `MIN_CHANNEL_MEMBERS` and `MAX_CHANNEL_MEMBERS` cosigners in slot
    ///         order, each described by their SPHINCS+ pubkey hash (bytes32, the member identity),
    ///         their Regev pubkey digest (bytes32), and their L1 withdrawal recipient (address).
    ///         Mirrors the Rust `ChannelRecord` (src/common/channel.rs): the registration record
    ///         carries `member_pk_gs`, the keccak `member_pubkeys_root`, the
    ///         `regev_pk_root`, and the `bp_member_slot`. The ACTIVE member pubkey hashes must be
    ///         nonzero and pairwise distinct (`ChannelRecord::validate`); the active count is the
    ///         array length.
    /// @dev R3 WORD-ALIGNED fixed-8 preimage (consumed by the validity `channel_reg_step`
    ///      circuit). The keccak chain folds a FIXED 8-slot, word-aligned stream so the circuit
    ///      can consume it with a SINGLE keccak (no byte-straddling); padding slots
    ///      (i >= activeCount) contribute zeros. Header fields are uint32 (4-byte words):
    ///        keccak256(prev || channelId(uint32) || bpMemberSlot(uint32) || memberCount(uint32) ||
    ///                  delegateCount(uint32) ||
    ///                  for i in 0..8: (pkG(32) || pkB(32) || regevPkDigest(32) || recipient(20))).
    ///      This is byte-identical to the Rust `ChannelRegRecord::hash_with_prev_hash`
    ///      (src/common/channel_registration.rs) and its in-circuit twin — asserted by
    ///      `IntmaxRollup.t.sol::test_channelRegPreimageDifferential`.
    ///      `memberPubkeysRoot` = keccak of all cosigner pubkey hashes; `regevPkRoot` = keccak of
    ///      all cosigner Regev pubkey digests.
    /// @dev Option B registration is cosigner-only. `delegateCount` remains in the ABI and fixed
    ///      registration preimage for wire compatibility, but MUST be zero. Delegates are added
    ///      later under a cosigner-signed channel state; accepting them here would create an L1
    ///      registration that the validity `channel_reg_step` circuit cannot prove.
    /// @dev P3: `pkBs[i]` is the participant's BabyBear hash-sig public key (L1/keccak digest form).
    ///      It enters the reg preimage between `pkG` and `regevPkDigest` so the in-circuit 3-field
    ///      `MemberLeaf{pk_g, pk_b, regev_pk}` is bound to the L1 keccak chain (R2 cross-binding).
    function registerChannel(
        uint32 channelId,
        uint8 bpMemberSlot,
        uint8 delegateCount,
        bytes32[] calldata memberPkGs,
        bytes32[] calldata pkBs,
        bytes32[] calldata regevPkDigests,
        address[] calldata recipients
    ) external {
        // Channel ids are one-shot protocol state. Pricing a targeted front-run does not authorize
        // it: a stranger can still pay a small fee and permanently occupy a predictable id. Keep
        // registration under the immutable deployment authority instead.
        _requireDeployer();
        if (channelId == 0) revert ChannelIdZeroReserved();
        if (channelId == BURN_CHANNEL_ID) revert ChannelIdBurnReserved();
        // The validity registration circuit constrains this retained wire field to zero. Reject
        // before deriving either accumulator or writing any per-channel state.
        if (delegateCount != 0) revert DelegateCountExceedsActive();
        // Finding E: ONE-TIME registration per channel. Matches the validity R5 one-time guard and
        // makes `channelMemberSetCommitment[channelId]` an unambiguous single source of truth that
        // the close-path manager binds to. A nonzero commitment means already registered.
        if (channelMemberSetCommitment[channelId] != bytes32(0)) revert ChannelAlreadyRegistered();
        uint256 memberCount = memberPkGs.length;
        if (
            memberCount < MIN_CHANNEL_MEMBERS || memberCount > MAX_CHANNEL_MEMBERS || pkBs.length != memberCount
                || regevPkDigests.length != memberCount || recipients.length != memberCount
        ) revert MemberCountOrArrayLenInvalid();
        // bpMemberSlot must select a co-signing MEMBER, not a delegate.
        if (uint256(bpMemberSlot) >= memberCount) revert BpMemberSlotOutOfRange();

        // Each bytes32 identity is the unique big-endian encoding of four canonical Goldilocks
        // limbs. The circuit reconstructs these bytes from four field elements; accepting a limb
        // >= p here would commit an on-chain preimage for which no registration proof exists.
        for (uint256 i = 0; i < memberCount; i++) {
            _requireValidIdentities(memberPkGs[i], pkBs[i], regevPkDigests[i], recipients[i]);
            for (uint256 j = i + 1; j < memberCount; j++) {
                if (memberPkGs[i] == memberPkGs[j]) revert MemberPubkeyHashesNotDistinct();
            }
        }

        // R3 WORD-ALIGNED fixed-8 preimage built in a helper (keeps this frame off the via-IR
        // stack-too-deep limit). The word-aligned HEADER (prev || channelId(uint32) ||
        // bpMemberSlot(uint32) || memberCount(uint32) || delegateCount(uint32)) is assembled here and
        // passed as ONE `bytes` slot; the helper folds the 8 fixed cosigner slots and hashes. This is
        // a byte-for-byte mirror of the Rust `ChannelRegRecord::hash_with_prev_hash`.
        bytes32 newHash = _channelRegHashChain(
            abi.encodePacked(
                _pendingChannelRegHashChain, channelId, uint32(bpMemberSlot), uint32(memberCount), uint32(0)
            ),
            memberCount,
            memberPkGs,
            pkBs,
            regevPkDigests,
            recipients
        );
        _pendingChannelRegHashChain = newHash;

        // Finding E: record the close-form IMCM member-set commitment (MEMBER-ONLY — delegates do
        // not co-sign) + bp identity as the SINGLE SOURCE OF TRUTH for this channel. Computed in a
        // helper to stay under the stack limit; byte-identical to
        // `ChannelSettlementVerifier.closeMemberSetCommitment(paddedHashes, memberCount)`.
        channelMemberSetCommitment[channelId] = _closeMemberSetCommitment(uint32(memberCount), memberPkGs);
        // bp identity: the member registered at `bpMemberSlot` (already range-checked above).
        channelBpMemberSlot[channelId] = bpMemberSlot;
        channelBpPkG[channelId] = memberPkGs[bpMemberSlot];

        emit ChannelRegistered(
            channelRegCount++,
            channelId,
            bpMemberSlot,
            memberPkGs,
            regevPkDigests,
            recipients,
            // L1/keccak digest forms of the member tree root and the Regev-pk root (ALL active
            // participants — members + delegates — exactly as the Rust `member_pubkeys_root_for`).
            keccak256(abi.encodePacked(memberPkGs)),
            keccak256(abi.encodePacked(regevPkDigests)),
            newHash
        );
        _recordPendingChainsCheckpoint();
    }

    /// @dev Require all three bytes32 values to encode four big-endian canonical
    ///      Goldilocks elements. A loop is intentionally used here to preserve EIP-170 headroom;
    ///      registration is deployment-time control-plane work, not a hot execution path.
    function _requireValidIdentities(bytes32 pkG, bytes32 pkB, bytes32 regev, address recipient) private pure {
        assembly ("memory-safe") {
            // One compact registration-shape error covers zero and non-canonical identities. The
            // older specific errors remain in the ABI, but separate revert branches would push the
            // deployable rollup over EIP-170.
            if or(or(iszero(pkG), iszero(regev)), iszero(recipient)) {
                mstore(0, 0xe7bf2968) // MemberCountOrArrayLenInvalid()
                revert(28, 4)
            }
            let mask := 0xffffffffffffffff
            let modulus := 0xffffffff00000001
            for { let offset := 0 } lt(offset, 256) { offset := add(offset, 64) } {
                if or(
                    or(
                        iszero(lt(and(shr(offset, pkG), mask), modulus)),
                        iszero(lt(and(shr(offset, pkB), mask), modulus))
                    ),
                    iszero(lt(and(shr(offset, regev), mask), modulus))
                ) {
                    mstore(0, 0xe7bf2968) // MemberCountOrArrayLenInvalid()
                    revert(28, 4)
                }
            }
        }
    }

    /// @dev Close-form IMCM member-set commitment (MEMBER-ONLY, pad-to-MAX D6): keccak256(
    ///      bytes4(0x494d434d) || uint32(memberCount) || h_0 || .. || h_7 ) with active hashes in
    ///      slot order and padding slots (i >= memberCount) zeroed. Delegates are EXCLUDED (they do
    ///      not co-sign). Byte-identical to `ChannelSettlementVerifier.closeMemberSetCommitment` and
    ///      the Rust `close_member_set_commitment`. Extracted to its own frame for the via-IR stack
    ///      limit.
    function _closeMemberSetCommitment(uint32 memberCount, bytes32[] calldata memberPkGs)
        internal
        pure
        returns (bytes32)
    {
        bytes32 result;
        assembly ("memory-safe") {
            // Exact 264-byte abi.encodePacked image:
            // bytes4 domain || uint32 count || bytes32[8] member hashes.
            let ptr := mload(0x40)
            mstore(ptr, shl(224, CLOSE_MEMBER_SET_DOMAIN))
            mstore(add(ptr, 4), shl(224, memberCount))
            let activeBytes := shl(5, memberCount)
            calldatacopy(add(ptr, 8), memberPkGs.offset, activeBytes)
            // CALLDATACOPY past calldata returns zero bytes, giving exact fixed-eight padding.
            calldatacopy(add(ptr, add(8, activeBytes)), calldatasize(), sub(256, activeBytes))
            result := keccak256(ptr, 264)
            mstore(0x40, add(ptr, 288))
        }
        return result;
    }

    /// @dev R3 WORD-ALIGNED fixed-8 reg-chain preimage (D6 pad-to-MAX + delegate account). The
    ///      keccak chain hashes a FIXED 8-slot, word-aligned stream so the validity
    ///      (channel_reg_step) circuit can consume it with a SINGLE keccak (no byte-straddling).
    ///      Padding slots (i >= activeCount) contribute bytes32(0) || bytes32(0) || 20 zero bytes.
    ///      Header fields are uint32 (4-byte words), matching the Rust
    ///      `ChannelRegRecord::hash_with_prev_hash` u32 stream:
    ///        prev(32) || channelId(uint32=4) || bpMemberSlot(uint32=4) || memberCount(uint32=4) ||
    ///        delegateCount(uint32=4) ||
    ///        for i in 0..8: ( pkG(32) || pkB(32) || regevDigest(32) || recipient(20) ).
    ///      SECURITY: `delegateCount` sits IMMEDIATELY AFTER `memberCount` (delegate account); active
    ///      slots are `0..memberCount+delegateCount`. recipient is appended as the 20 address bytes
    ///      (abi.encodePacked(address)), equal to the Rust Address 5-u32 big-endian encoding — NOT a
    ///      32-byte left-pad. P3: pkB(32) sits between pkG and regevDigest. Byte-identity with
    ///      Rust/circuit is asserted by test_channelRegPreimageDifferential. Extracted to its own
    ///      frame so `registerChannel` stays under the via-IR stack limit.
    function _channelRegHashChain(
        bytes memory header,
        uint256 activeCount,
        bytes32[] calldata memberPkGs,
        bytes32[] calldata pkBs,
        bytes32[] calldata regevPkDigests,
        address[] calldata recipients
    ) internal pure returns (bytes32) {
        bytes memory packed = header;
        for (uint256 i = 0; i < MAX_CHANNEL_MEMBERS; i++) {
            if (i < activeCount) {
                packed = abi.encodePacked(
                    packed,
                    memberPkGs[i], // bytes32: 32 bytes (pk_g)
                    pkBs[i], // bytes32: 32 bytes (pk_b, P3)
                    regevPkDigests[i], // bytes32: 32 bytes
                    recipients[i] // address: 20 bytes
                );
            } else {
                // Padding slot: zeroed pkG(32) || pkB(32) || regev(32) || recipient(20).
                packed = abi.encodePacked(packed, bytes32(0), bytes32(0), bytes32(0), bytes20(0));
            }
        }
        return keccak256(packed);
    }

    // -----------------------------------------------------------------------
    function _submit(bytes32 proofHash, uint32 proofLength, bytes32 stateRoot) internal returns (uint256 submissionId) {
        submissionId = nextSubmissionId++;
        uint64 ethBlock = uint64(block.number);
        bytes32 commitment = kzgVerifier.postCommitment(stateRoot, ethBlock, submissionId);

        _submissions[submissionId] = Submission({
            commitment: commitment,
            submitter: msg.sender,
            finalized: false,
            submittedAtBlock: ethBlock,
            stateRoot: stateRoot
        });

        emit Submitted(submissionId, msg.sender, commitment, proofHash, proofLength, stateRoot);
    }

    // -----------------------------------------------------------------------
    // finalize()  —  full verification + state root acceptance
    // -----------------------------------------------------------------------

    /// @notice Verify and finalize a submission.
    ///         Checks: MLE proof, public input binding to on-chain state and to the MLE proof.
    function finalize(
        uint256 submissionId,
        bytes32 stateRoot,
        ValidityPublicInputs calldata validityPIs,
        bytes calldata compactProof
    ) external nonReentrant returns (bool) {
        Submission storage sub = _submissions[submissionId];
        // SECURITY (M-8: `finalize` failed silently). Each rejecting exit below reports WHY through
        // `FinalizeRejected` before returning false. The boolean return is deliberately preserved:
        // `fullVerify` failures must stay non-reverting for the callers that assert on `false`.
        if (sub.commitment == bytes32(0)) return _rejectFinalize(submissionId, SubmissionNotFound.selector);
        if (sub.finalized) return _rejectFinalize(submissionId, AlreadyFinalized.selector);

        // SECURITY (H-5: finalize did not bind submissionId to the proof it verifies). Without this,
        // `submissionId` was used only to look up existence/finalized-ness — nothing tied the proof
        // to THAT submission. Anyone could finalize submission B with submission A's public proof:
        // B was marked finalized and its bond refunded although B's own proof was never verified,
        // and B then became permanently un-slashable (`fraudProof` reverts SubmissionAlreadyFinalized),
        // which additionally blocks the rollback of every earlier submission (`_truncateSubmissions`
        // reverts on a finalized entry). `fullVerify` below pins `validityPIs.finalExtCommitment` to
        // `stateRoot`, so pinning `stateRoot` to the submission's own committed root transitively
        // binds the verified proof to this submission.
        if (stateRoot != sub.stateRoot) return _rejectFinalize(submissionId, CommitmentMismatch.selector);

        // SECURITY (H-5/B-5: the stateRoot-only binding was insufficient). Pinning only the root
        // leaves two submissions interchangeable whenever they declare the SAME root, and nothing
        // in `_submit` constrains the declared root:
        //   (a) on a heartbeat/idle posting round the honest root does not move, so anyone can
        //       finalize submission B with submission A's byte-identical arguments — B's bond is
        //       refunded although B's own proof was never verified, B becomes permanently
        //       un-slashable (`fraudProof` reverts SubmissionAlreadyFinalized) and that in turn
        //       blocks the rollback of every earlier submission; and
        //   (b) a second whitelisted producer posts a junk batch DECLARING the honest root and
        //       front-runs the honest finalize, after which the honest submission can never be
        //       finalized at all (`latestFinalizedStateRoot` has already moved past its
        //       `initialExtCommitment`) and neither submission can ever be removed.
        // The batch's END HEIGHT is the missing discriminator: `_postBlock` strictly advances
        // `blockNumber`, so at most one LIVE submission ends at a given height, and `fullVerify`
        // already pins `finalBlockChain == blockHashChainAt[finalBlockNumber]`. Together with the
        // root pin above, the verified proof is now bound to THIS submission's own batch.
        // (Round 1 rejected this because ~20 synthetic tests built `validityPIs` before posting,
        // with `finalBlockNumber = 0`. Those harnesses were fixed instead: a test convention must
        // not dictate a soundness gap.)
        // M-8 composes with B-5: this binding now NAMES itself instead of joining the silent
        // `return false` crowd, so an operator can tell "your PIs are for another batch" from
        // "your proof is invalid" — the distinction whose absence made M-5 a silent chain halt.
        if (validityPIs.finalBlockNumber != _batchMetadata[submissionId].endBlockNumber) {
            return _rejectFinalize(submissionId, ValidityPublicInputsMismatch.selector);
        }

        // KZG work is journaled in a separate transaction. The canonical compact byte stream is
        // simultaneously the blob payload and the verifier input; no decode/re-encode bridge may
        // create a second representation at this boundary.
        if (!kzgVerifier.isProofDataAttested(
                submissionId, sub.commitment, keccak256(compactProof), compactProof.length
            )) {
            return _rejectFinalize(submissionId, CommitmentMismatch.selector);
        }

        // SECURITY (M-8): `fullVerify` now reverts with a cause-specific error instead of returning
        // false, so the catch below recovers WHICH check failed. An empty `err` (no revert data) is
        // reported as reason `0x00000000` — "could not evaluate", never "invalid". The try/catch and
        // the `return false` are both retained: swallowing the revert here is what keeps `finalize`
        // fail-CLOSED-but-non-reverting (a rejected proof can never mark `sub.finalized`).
        bool valid;
        bytes4 reason;
        try this.fullVerify(stateRoot, validityPIs, compactProof) returns (bool v) {
            valid = v;
        } catch {
            assembly ("memory-safe") {
                mstore(0, 0)
                if gt(returndatasize(), 3) { returndatacopy(0, 0, 4) }
                reason := mload(0)
            }
        }
        if (!valid) return _rejectFinalize(submissionId, reason);

        sub.finalized = true;
        latestFinalizedStateRoot = stateRoot;
        isFinalizedStateRoot[stateRoot] = true; // permanent; enables withdrawals against any finalized root
        latestFinalizedBlockNumber = validityPIs.finalBlockNumber;

        emit Finalized(submissionId, stateRoot);
        _refundStake(submissionId);
        return true;
    }

    /// @dev SECURITY (M-8): the single rejecting exit of `finalize`. Shared so every cause is
    ///      reported the same way (and so the emit is coded once — EIP-170 budget).
    function _rejectFinalize(uint256 id, bytes4 reason) private returns (bool) {
        emit FinalizeRejected(id, reason);
        return false;
    }

    // -----------------------------------------------------------------------
    // fraudProof()  —  prove a submission contains an invalid proof
    // -----------------------------------------------------------------------

    /// @notice Prove that a submission's proof is INVALID.
    ///
    /// ## Fraud proof rules
    ///
    ///   1. Finalized intmax block number is recorded on-chain; each submission's
    ///      commitment includes the Eth block number at posting time.
    ///   2. Fraud proofs CANNOT target submissions at or before the latest
    ///      finalized intmax block (reverts with SubmissionBeforeFinalizedBlock).
    ///   3. Submissions not finalized within FINALIZE_DEADLINE_BLOCKS (3600 Eth
    ///      blocks, ~12 hours) after posting are removed unconditionally — no ZKP
    ///      verification required.
    ///   4. On successful fraud proof, the target submission AND all subsequent
    ///      submissions are deleted and their blocks rolled back.
    ///
    /// ## Normal fraud verification
    ///
    ///   The fraud prover supplies the exact raw proof bytes that were committed,
    ///   plus the standard EIP-4844 sidecar evidence for that SimpleCoder blob stream.
    ///   The pinned adapter classifies those authenticated canonical compact bytes. Fraud is
    ///   confirmed only for its proof-dependent INVALID verdict; wrong PI preimages, malformed
    ///   envelopes, unavailable/configuration failures and gas starvation never convict.
    function fraudProof(
        uint256 submissionId,
        bytes32 stateRoot,
        ValidityPublicInputs calldata validityPIs,
        bytes calldata proofBytes
    ) external nonReentrant returns (bool fraudConfirmed) {
        Submission storage sub = _submissions[submissionId];
        if (sub.commitment == bytes32(0)) return false;
        if (sub.finalized) revert SubmissionAlreadyFinalized();

        // Guard: cannot fraud-proof submissions whose blocks are at or before
        // the latest finalized intmax block.
        BatchMetadata memory meta = _batchMetadata[submissionId];
        if (meta.startBlockNumber <= latestFinalizedBlockNumber) {
            revert SubmissionBeforeFinalizedBlock();
        }

        // Timeout removal: if the submission was not finalized within
        // FINALIZE_DEADLINE_BLOCKS Eth blocks, remove it unconditionally.
        if (block.number > uint256(sub.submittedAtBlock) + FINALIZE_DEADLINE_BLOCKS) {
            _truncateSubmissions(submissionId, msg.sender);
            emit FraudConfirmed(submissionId, msg.sender);
            return true;
        }

        bool confirmed = _verifyFraud(submissionId, stateRoot, validityPIs, proofBytes);
        if (!confirmed) return false;

        _truncateSubmissions(submissionId, msg.sender);
        emit FraudConfirmed(submissionId, msg.sender);
        return true;
    }

    /// @notice Permissionless first half of the split Proof-DA flow. The satellite authenticates
    /// and journals the exact raw bytes; `finalize`/`fraudProof` consume that journal separately.
    function attestProofData(uint256 submissionId, bytes calldata proofBytes, bytes calldata blobProofs)
        external
        returns (bytes32)
    {
        return kzgVerifier.attestProofData(address(this), submissionId, proofBytes, blobProofs);
    }

    // -----------------------------------------------------------------------
    // View helpers
    // -----------------------------------------------------------------------

    function getSubmission(uint256 id) external view returns (Submission memory) {
        return _submissions[id];
    }

    function getCommitment(uint256 id) external view returns (bytes32) {
        return _submissions[id].commitment;
    }

    function isFinalized(uint256 id) external view returns (bool) {
        return _submissions[id].finalized;
    }

    /// @notice Pull an exact amount from the caller's native withdrawal ledger.
    /// @dev Exact-amount withdrawal keeps unrelated recipient-wide credits out of a channel
    ///      Manager's channel-scoped backing. Credits arriving before mining remain in the Rollup
    ///      ledger instead of being swept into, and stranded inside, the Manager.
    function withdraw(uint256 amount) external releaseRuntime nonReentrant {
        uint256 pending = pendingWithdrawals[msg.sender];
        if (amount == 0 || amount > pending) revert NothingToWithdraw();
        pendingWithdrawals[msg.sender] = pending - amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert WithdrawTransferFailed();
    }

    /// @notice Reclaim a POST_BLOCK_STAKE bond once its submission's batch is part of canonical
    ///         FINALIZED history. Permissionless caller; the bond is always credited to the recorded
    ///         submitter (a helper may sweep on their behalf with no benefit to itself).
    ///
    /// ## Why this is needed
    ///   `_refundStake` (the finalize path) is otherwise the ONLY way a bond returns. But `finalize`
    ///   advances a single global `latestFinalizedStateRoot` monotonically and refunds exactly ONE
    ///   submission, so when one aggregate validity proof finalizes many posted blocks at once, every
    ///   other posting round in that range is permanently stranded: it can never be finalized (no
    ///   proof chains backwards) and `fraudProof` refuses it (`startBlockNumber <= latestFinalized`,
    ///   so it can no longer be slashed either). The bond is then dead weight with no exit. This is
    ///   the protocol's normal flow (aggregate finalization), so on mainnet it leaks a real-ETH bond
    ///   per un-finalized posting round. `reclaimStake` is the missing exit.
    ///
    /// ## Why it is sound (bond no longer at risk)
    ///   A bond exists to back the claim "my committed blob holds a valid proof for this state." Once
    ///   the batch's blocks are FINALIZED canonical history, (a) a valid proof for that state provably
    ///   exists (some finalize verified the chain past it) and (b) `fraudProof` can no longer target
    ///   it. So the bond is settled and must return.
    ///
    /// ## Eligibility (ALL required) — see tasks/reclaim-stake-threat-model.md
    ///   1. The stake exists and was neither refunded (finalize) nor slashed (fraud):
    ///      `stakeInfo.submitter != 0 && !stakeInfo.spent`. An unknown / truncated id has
    ///      `submitter == 0` and is rejected here.
    ///   2. The whole batch is finalized: `meta.endBlockNumber <= latestFinalizedBlockNumber`. Uses the
    ///      LAST block of the batch — strictly stronger than the fraud-exclusion guard's
    ///      `startBlockNumber <= latestFinalizedBlockNumber`, so a batch straddling the finalized
    ///      boundary is NOT reclaimable until its tail finalizes too.
    ///
    /// ## SECURITY: why a height comparison alone is sufficient (no per-batch hash binding needed)
    ///   An adversarial review noted `finalize` does not bind `submissionId` to the verified proof, and
    ///   worried a non-canonical batch at a finalized height could be reclaimed. That cannot happen,
    ///   from two invariants of the fraud/rollback machinery:
    ///     (a) ROLLBACK FLOOR: `fraudProof` refuses any submission with
    ///         `startBlockNumber <= latestFinalizedBlockNumber` (the guard above), and
    ///         `_truncateSubmissions`/`_rollbackBatch` only rewind from the fraud target upward — so
    ///         `blockNumber` can never be rewound below `latestFinalizedBlockNumber`. Hence
    ///         `blockHashChainAt[k]` for every finalized height `k <= latestFinalizedBlockNumber` is
    ///         IMMUTABLE, and equals the canonical chain `finalize` verified
    ///         (`finalBlockChain == blockHashChainAt[finalBlockNumber]`).
    ///     (b) UNIQUE LIVE BATCH PER HEIGHT: posting strictly advances `blockNumber`; the only way two
    ///         batches share an end height is to rewind and repost, which requires `_truncateSubmissions`
    ///         to first DELETE the prior submission there (clearing its `stakeInfo`). So at any time at
    ///         most one *live* submission ends at a given height.
    ///   Together: if a submission with `endBlockNumber = k <= latestFinalizedBlockNumber` still has a
    ///   live stake (cond 1), it is THE canonical batch finalized at height k. Releasing its bond is
    ///   therefore correct. These invariants are pinned by tests
    ///   (test_reclaim_* in ReclaimStake.t.sol): repost-after-truncate cannot reclaim, and rollback
    ///   cannot descend below the finalized height.
    function reclaimStake(uint256 submissionId) external nonReentrant {
        StakeInfo storage info = stakeInfo[submissionId];
        address submitter = info.submitter;
        if (submitter == address(0) || info.spent) revert NothingToReclaim();

        if (_batchMetadata[submissionId].endBlockNumber > latestFinalizedBlockNumber) {
            revert SubmissionNotYetFinalized();
        }

        // Effects before credit (CEI); pull-payment only — no external call here.
        info.spent = true;
        delete stakeInfo[submissionId];
        pendingWithdrawals[submitter] += POST_BLOCK_STAKE;
        emit WithdrawalCredited(submitter, POST_BLOCK_STAKE);
    }

    // -----------------------------------------------------------------------
    // withdrawNative()  —  native ETH payout for a verified withdrawal proof (Phase 2)
    // -----------------------------------------------------------------------

    /// @notice Pay out native ETH for a wrapped `WithdrawalCircuit` proof, bound to the latest
    ///         finalized state. The recipient / amount / nullifier of every leaf come from the
    ///         VERIFIED proof (re-folded keccak chain → pis_hash), never from caller declaration.
    ///
    /// @param ws               The withdrawal leaves, in chain order. Re-folded and bound to the proof.
    /// @param withdrawalProver The `withdrawal_prover` address committed in the proof's pis_hash.
    /// @param compactProof     The canonical compact WithdrawalCircuit MLE/WHIR proof bytes.
    ///
    /// SECURITY:
    ///   • MLE/WHIR verify the wrapped WithdrawalCircuit proof under the withdrawal VK (real, not a stub).
    ///   • `ext_public_state_commitment` PI (limbs 8..16) must equal `latestFinalizedStateRoot` —
    ///     the withdrawals are anchored to a state the validity proof already finalized.
    ///   • `ws` are re-folded into `withdrawal_hash` → `pis_hash` (limbs 0..8 of the proof). A
    ///     tampered amount/recipient breaks the hash and reverts. So payout == proof.
    ///   • Per leaf: single-use nullifier (CEI check-then-set) + `totalEscrowed -= amount` (the
    ///     GLOBAL solvency ceiling: Σ payouts ≤ Σ real ETH escrowed; underflow reverts the whole
    ///     call → cross-channel theft impossible) + pull-payment credit. v1 pays ETH token only.
    ///   • No external call here (pull-payment via `withdraw(amount)`); `nonReentrant` is belt-and-braces.
    function withdrawNative(Withdrawal[] calldata ws, address withdrawalProver, bytes calldata compactProof)
        external
        nonReentrant
    {
        uint64 wdBlockNumber = _verifyWithdrawalSet(ws, withdrawalProver, compactProof);

        // 4. Pay out each leaf (CEI: all checks/effects precede any value movement; pull-payment).
        for (uint256 i = 0; i < ws.length; i++) {
            Withdrawal calldata w = ws[i];
            // ETH leaves only; ERC-20 leaves go through `withdrawERC20` (multitoken §N-7). A chain
            // mixing ETH and ERC-20 leaves is not payable by either entry point (the chain binds as
            // a whole) — the withdrawal prover emits single-asset-class chains.
            if (w.tokenIndex != ETH_TOKEN_INDEX) revert WithdrawalNotEthToken();
            _consumeWithdrawalGuard(w);
            // GLOBAL solvency ceiling: Solidity 0.8 underflow reverts if Σ would exceed real escrow.
            _creditNativeEscrow(w.recipient, w.amount);
            emit NativeWithdrawn(w.recipient, w.amount, w.nullifier, wdBlockNumber);
        }
    }

    /// @notice Pay out ERC-20 leaves for a wrapped `WithdrawalCircuit` proof (multitoken Phase 3,
    ///         §N-7). MIRRORS `withdrawNative` exactly — the SAME withdrawal-set verification
    ///         (`_verifyWithdrawalSet`: real MLE/WHIR under the withdrawal VK, finalized-root
    ///         anchor, chain re-fold → pis_hash binding), the SAME per-leaf nullifier single-use,
    ///         and the SAME IPW2 partial-withdrawal authorization gate (the auth digest already
    ///         binds `tokenIndex`) — only the asset dispatch differs.
    ///
    /// SECURITY:
    ///   • Per leaf: `tokenIndex != 0` AND registered (TM-10b) — the ETH guard in `withdrawNative`
    ///     stays untouched, so no leaf is payable by both entry points.
    ///   • Per-token escrow ceiling (TM-1 layer b): `escrowedByToken[t] -= amount` underflow-reverts
    ///     the whole call if Σ token-t payouts would exceed Σ token-t verified deposits — even
    ///     across channels sharing the token, and even if a channel-local registry duplicated the
    ///     index (the in-circuit injectivity check is the other, independent layer).
    ///   • Pull-payment (CEI): credits `pendingTokenWithdrawals[t][recipient]`; NO token code runs
    ///     inside this loop. Recipients pull via `withdrawToken`, where `nonReentrant` guards the
    ///     single external token call.
    function withdrawERC20(Withdrawal[] calldata ws, address withdrawalProver, bytes calldata compactProof)
        external
        nonReentrant
    {
        uint64 wdBlockNumber = _verifyWithdrawalSet(ws, withdrawalProver, compactProof);

        for (uint256 i = 0; i < ws.length; i++) {
            Withdrawal calldata w = ws[i];
            if (w.tokenIndex == ETH_TOKEN_INDEX) revert WithdrawalNotErc20Token();
            if (address(tokenAddressOf[w.tokenIndex]) == address(0)) revert TokenIndexNotRegistered();
            _consumeWithdrawalGuard(w);
            // PER-TOKEN solvency ceiling (TM-1 layer b): underflow-revert on over-release.
            _creditTokenEscrow(w.tokenIndex, w.recipient, w.amount);
            emit Erc20Withdrawn(w.recipient, w.tokenIndex, w.amount, w.nullifier, wdBlockNumber);
        }
    }

    /// @notice Pull-payment: claim accrued ERC-20 credits for one token (the ERC-20 mirror of
    ///         `withdraw(amount)`). The ChannelSettlementManager receives its channel's ERC-20 funds
    ///         through this call (measuring its own balance delta), exactly as it pulls ETH via
    ///         `withdraw(amount)`.
    /// @dev SECURITY: CEI (credit decremented before the token call) + `nonReentrant` — the token is
    ///      untrusted code (ERC-777-style hooks) but re-entering any guarded entry point reverts;
    ///      the selected amount has already been removed even when unrelated credit remains.
    function withdrawToken(uint32 tokenIndex, uint256 amount) external releaseRuntime nonReentrant {
        IERC20 token = tokenAddressOf[tokenIndex];
        if (address(token) == address(0)) revert TokenIndexNotRegistered();
        uint256 pending = pendingTokenWithdrawals[tokenIndex][msg.sender];
        if (amount == 0 || amount > pending) revert NothingToWithdrawForToken();
        pendingTokenWithdrawals[tokenIndex][msg.sender] = pending - amount;
        emit TokenWithdrawalClaimed(msg.sender, tokenIndex, amount);
        uint256 balanceBefore = _tokenBalanceOf(token, msg.sender);
        SafeERC20Lib.safeTransfer(token, msg.sender, amount);
        if (_tokenBalanceOf(token, msg.sender) - balanceBefore != amount) {
            revert TokenWithdrawalAmountMismatch();
        }
    }

    /// @dev Compact strict `balanceOf` shared by ERC-20 deposit and withdrawal boundaries. A
    ///      failed or malformed view cannot establish exact custody/receipt and fails closed.
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

    /// @dev IPW2 partial-withdrawal auth digest over the proof-verified withdrawal economics and
    ///      IMD2 descriptor. The proof-only nullifier is deliberately excluded: the manager cannot
    ///      authenticate it, while the payout path separately enforces its single use. Shared by
    ///      the ETH and ERC-20 payout paths. The proof-free consumer of this digest
    ///      (`claimAuthorizedWithdrawal`) was removed 2026-07-28.
    function _withdrawalAuthDigest(Withdrawal calldata w) private pure returns (bytes32) {
        address recipient = w.recipient;
        uint32 tokenIndex = w.tokenIndex;
        uint256 amount = w.amount;
        bytes32 auxData = w.auxData;
        bytes32 result;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, shl(224, 0x49505732)) // "IPW2"
            mstore(add(ptr, 4), shl(96, recipient))
            mstore(add(ptr, 24), shl(224, tokenIndex))
            mstore(add(ptr, 28), amount)
            mstore(add(ptr, 60), auxData)
            result := keccak256(ptr, 92)
            mstore(0x40, add(ptr, 96))
        }
        return result;
    }

    /// @dev Shared native/ERC-20 single-use guard. IPW2 commits recipient, token, amount and aux;
    ///      the already-verified withdrawal proof supplies those economics and the independent
    ///      nullifier. The authorization is consumed before accounting, with transaction rollback
    ///      restoring both writes if a later escrow ceiling fails.
    function _consumeWithdrawalGuard(Withdrawal calldata w) private {
        if (withdrawalNullifierUsed[w.nullifier]) revert WithdrawalNullifierUsed();
        if (w.auxData != bytes32(0)) {
            bytes32 authDigest = _withdrawalAuthDigest(w);
            if (!partialWithdrawalAuthorized[authDigest]) revert PartialWithdrawalNotAuthorized();
            delete partialWithdrawalAuthorized[authDigest];
        }
        withdrawalNullifierUsed[w.nullifier] = true;
    }

    /// @dev Shared verification core of `withdrawNative` / `withdrawERC20` (steps 1–3): real
    ///      MLE/WHIR proof under the withdrawal VK, finalized-state-root anchor, and the keccak
    ///      chain re-fold binding `ws` to the proof's pis_hash. Returns the proof's block number.
    ///      SECURITY: identical checks for both asset paths — factoring shares (never weakens)
    ///      the audited `withdrawNative` pipeline.
    function _verifyWithdrawalSet(Withdrawal[] calldata ws, address withdrawalProver, bytes calldata compactProof)
        internal
        view
        returns (uint64 wdBlockNumber)
    {
        if (ws.length == 0) revert WithdrawalEmptySet();

        // 1. Verify the exact compact bytes under the constructor-pinned withdrawal circuit and
        //    only then consume the public inputs returned from that same decoded proof.
        uint256[] memory pi;
        try withdrawalMleVerifier.verifyCompactPublicInputs(compactProof) returns (
            uint256[] memory authenticatedPublicInputs
        ) {
            pi = authenticatedPublicInputs;
        } catch {
            revert WithdrawalProofInvalid();
        }

        // 2. The wrapped WithdrawalCircuit registers 17 PI limbs:
        //      [ pis_hash(8) || ext_commitment(8) || block_number(1) ]  (withdrawal_circuit.rs:206-208)
        //    NOTE: `block_number` is a u63 that fits in ONE Goldilocks field element, so its
        //    REGISTERED form is a single limb (`BlockNumberTarget::to_vec()`), even though the
        //    pis_hash keccak PREIMAGE splits it into 2 big-endian u32 words (`to_u32_vec`).
        if (pi.length != 17) revert WithdrawalPublicInputsMismatch();

        // 2a. ext_commitment PI must be a state root this rollup has finalized (anchors the
        //     withdrawal to finalized state). Any historically-finalized root is accepted, not just
        //     the latest — finalized roots are permanent, so this is sound and avoids locking honest
        //     withdrawers out when the next block finalizes (the nullifier still blocks double-spend).
        bytes32 extCommitment = _limbsToBytes32(pi, 8);
        if (!isFinalizedStateRoot[extCommitment]) revert WithdrawalExtCommitmentMismatch();

        // 2b. block_number PI (single limb 16 = the u63 value). Used in the pis_hash recomputation
        //     below (re-split into 2 big-endian u32 words there); no separate equality check is
        //     needed — the pis_hash binding (step 3) already forces it to equal the circuit's value.
        wdBlockNumber = uint64(pi[16]);

        // 3. Re-fold the keccak withdrawal chain (seed 0) → withdrawal_hash, recompute pis_hash, and
        //    require it equals the proof's pis_hash PI (limbs 0..8). Binds `ws` to the verified proof.
        bytes32 withdrawalHash = bytes32(0);
        for (uint256 i = 0; i < ws.length; i++) {
            withdrawalHash = _foldWithdrawalLeaf(withdrawalHash, ws[i]);
        }
        bytes32 pisHash = _withdrawalPisHash(withdrawalHash, withdrawalProver, extCommitment, wdBlockNumber);
        if (!_limbsMatchBytes32(pi, 0, pisHash)) revert WithdrawalPublicInputsMismatch();
    }

    /// @dev Fold one Withdrawal leaf into the keccak chain. Byte-identical to Rust
    ///      `Withdrawal::hash_with_prev_hash` (withdrawal.rs:97, via solidity_keccak256's u32→4-byte
    ///      big-endian packing):
    ///        keccak256( prev(32) || recipient(20) || tokenIndex(4) || amount(32) || nullifier(32) || auxData(32) )
    ///      = 152-byte preimage. abi.encodePacked emits address as 20 bytes, uint32 as 4, uint256 as
    ///      32 (big-endian) — matching the Rust 5/1/8 u32-limb layout exactly.
    function _foldWithdrawalLeaf(bytes32 prev, Withdrawal calldata w) private pure returns (bytes32) {
        address recipient = w.recipient;
        uint32 tokenIndex = w.tokenIndex;
        uint256 amount = w.amount;
        bytes32 nullifier = w.nullifier;
        bytes32 auxData = w.auxData;
        bytes32 result;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, prev)
            mstore(add(ptr, 32), shl(96, recipient))
            mstore(add(ptr, 52), shl(224, tokenIndex))
            mstore(add(ptr, 56), amount)
            mstore(add(ptr, 88), nullifier)
            mstore(add(ptr, 120), auxData)
            result := keccak256(ptr, 152)
            mstore(0x40, add(ptr, 160))
        }
        return result;
    }

    /// @dev pis_hash = remove_3bits( keccak256(
    ///        withdrawal_hash(32) || prover(20) || ext_commitment(32) || blockNumber(8, big-endian) ) )
    ///      mirroring `WithdrawalProofPublicInputs` (withdrawal_circuit.rs:57-68, 121-125).
    ///      remove_3bits clears the TOP 3 bits of the 256-bit value (Rust Bytes32::remove_3bits:
    ///      `limb[0] &= (1<<29)-1`, limb[0] = most-significant u32) ⇒ `value & ((1<<253)-1)`.
    ///      blockNumber as abi.encodePacked(uint64) = [high32_BE, low32_BE] = Rust to_u32_vec [high, low].
    function _withdrawalPisHash(bytes32 withdrawalHash, address prover, bytes32 extCommitment, uint64 blockNumber)
        private
        pure
        returns (bytes32)
    {
        bytes32 result;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, withdrawalHash)
            mstore(add(ptr, 32), shl(96, prover))
            mstore(add(ptr, 52), extCommitment)
            mstore(add(ptr, 84), shl(192, blockNumber))
            result := and(keccak256(ptr, 92), sub(shl(253, 1), 1))
            mstore(0x40, add(ptr, 96))
        }
        return result;
    }

    /// @dev Reconstruct a bytes32 from 8 big-endian u32 limbs starting at `off` (Bytes32::to_u32_vec
    ///      order: limb[0] = most-significant 4 bytes). Limbs are masked to u32; after a successful
    ///      the adapter-returned public inputs ARE the circuit's authenticated u32 PI wires.
    function _limbsToBytes32(uint256[] memory limbs, uint256 off) private pure returns (bytes32) {
        uint256 v = 0;
        for (uint256 i = 0; i < 8; i++) {
            v = (v << 32) | (limbs[off + i] & 0xFFFFFFFF);
        }
        return bytes32(v);
    }

    /// @dev Check 8 big-endian u32 limbs at `off` equal `value` EXACTLY (no masking — a limb with
    ///      high bits set is malformed and rejected). Mirrors `_mlePublicInputsMatch`.
    function _limbsMatchBytes32(uint256[] memory limbs, uint256 off, bytes32 value) private pure returns (bool) {
        uint256 h = uint256(value);
        for (uint256 i = 0; i < 8; i++) {
            uint256 limb = (h >> (224 - i * 32)) & 0xFFFFFFFF;
            if (limbs[off + i] != limb) return false;
        }
        return true;
    }

    // -----------------------------------------------------------------------
    // Internal — Full verification pipeline
    // -----------------------------------------------------------------------

    /// @dev Full verification pipeline for finalize() — all checks must pass. `finalize` performs
    ///      the exact compact-byte KZG-attestation lookup before entering this helper.
    /// @dev External entry point so _fullVerify runs in a fresh EVM call context.
    ///      This avoids via_ir + optimizer code generation issues with large memory structs.
    /// @return Always `true` — every failure REVERTS with a cause-specific error (M-8). Callers that
    ///         need a boolean should try/catch, as `finalize` does.
    function fullVerify(bytes32 stateRoot, ValidityPublicInputs calldata validityPIs, bytes calldata compactProof)
        external
        view
        returns (bool)
    {
        // 1. PI binding to on-chain state
        // SECURITY (defense-in-depth for INV-A / reclaimStake): finalization must only ADVANCE the
        // finalized height. The initialExtCommitment check below already forces forward chaining, but
        // asserting monotonicity on-chain removes any reliance on the validity circuit guaranteeing
        // `finalBlockNumber >= initialBlockNumber` — and `latestFinalizedBlockNumber` is the height
        // `reclaimStake` compares against, so a backward move must never be accepted.
        //
        // SECURITY (M-8): each application-state mismatch reverts with its own error. `finalize`
        // catches it and remains fail-closed/non-reverting; `_verifyFraud` uses its separate
        // non-convicting classifier path and never calls this helper.
        if (validityPIs.finalBlockNumber < latestFinalizedBlockNumber) revert FinalizedHeightRegression();
        if (validityPIs.initialExtCommitment != latestFinalizedStateRoot) revert InitialStateMismatch();
        if (validityPIs.initialBlockChain != blockHashChainAt[validityPIs.initialBlockNumber]) {
            revert BlockChainMismatch();
        }
        if (validityPIs.finalBlockChain != blockHashChainAt[validityPIs.finalBlockNumber]) {
            revert FinalBlockChainMismatch();
        }
        if (validityPIs.finalExtCommitment != stateRoot) revert FinalExtCommitmentMismatch();

        // 2. Verify the canonical compact proof and retrieve public inputs only after the pinned
        //    v2 core accepts that exact byte stream. There is no separately decoded proof object
        //    and therefore no representation that can diverge from proof DA.
        uint256[] memory publicInputs;
        try validityMleVerifier.verifyCompactPublicInputs(compactProof) returns (
            uint256[] memory authenticatedPublicInputs
        ) {
            publicInputs = authenticatedPublicInputs;
        } catch {
            revert MleVerificationFailed();
        }

        // 3. Bind those authenticated public inputs to the caller's explicit VPI preimage.
        bytes32 piHash = _computeValidityPIHash(validityPIs);
        if (!_mlePublicInputsMatch(publicInputs, piHash)) revert ValidityPublicInputsMismatch();

        return true;
    }

    /// @dev Fraud detection pipeline. Returns true if fraud is confirmed.
    ///
    ///   Pre-conditions (must pass — proves fraud prover supplied the real blob data):
    ///     1. Canonical proof bytes + standard blob KZG evidence open the submission commitment
    ///     2. PI binding to on-chain state
    ///     3. PI preimage binding: authenticated public inputs encode keccak256(ValidityPublicInputs)
    ///
    ///   Fraud confirmed if:
    ///     MLE/WHIR verification of the committed proof fails
    ///
    ///   SECURITY (C-1): 3 is a PRE-CONDITION, never a fraud trigger. See the comment at the check.
    function _verifyFraud(
        uint256 submissionId,
        bytes32 stateRoot,
        ValidityPublicInputs calldata validityPIs,
        bytes calldata proofBytes
    ) internal view returns (bool) {
        // ── Pre-conditions ────────────────────────────────────────────────

        // 1. The exact raw bytes must already have been authenticated against the submission's
        //    posted blob hashes by `attestProofData`. This keeps KZG and MLE in separate bounded-gas
        //    transactions and prevents a different proof (valid or invalid) from steering verdicts.
        if (!kzgVerifier.isProofDataAttested(
                submissionId, _submissions[submissionId].commitment, keccak256(proofBytes), proofBytes.length
            )) return false;

        // 2. PI binding to on-chain state
        if (validityPIs.initialExtCommitment != latestFinalizedStateRoot) return false;
        if (validityPIs.initialBlockChain != blockHashChainAt[validityPIs.initialBlockNumber]) return false;
        if (validityPIs.finalBlockChain != blockHashChainAt[validityPIs.finalBlockNumber]) return false;
        if (validityPIs.finalExtCommitment != stateRoot) return false;

        // 3. PI PREIMAGE binding — `validityPIs` must be THE public inputs of the committed proof.
        //    SECURITY (C-1: false-fraud conviction of an honest submission): this comparison used to
        //    live below as a fraud TRIGGER ("the proof's PIs don't encode keccak256(validityPIs) ⇒
        //    fraud"). That was unsound, because `validityPIs` is caller-supplied and NOT uniquely
        //    determined by anything the submitter committed to: `validityPIs.prover` is constrained
        //    by nothing on-chain, and it is a free witness in the validity circuit
        //    (validity/block_hash_chain/validity_circuit.rs — any address is equally provable; the
        //    production daemon takes it from the `--validity-prover` CLI flag, so it is NOT the
        //    submitter's address and cannot be pinned to `sub.submitter`). An attacker could
        //    therefore take an honest submission's REAL blob bytes and REAL PI values, flip only
        //    `prover`, and force a guaranteed hash mismatch — confirming "fraud" against a valid
        //    proof, then truncating every later submission, stealing 90% of each bond and rolling
        //    the chain back, once per posting round.
        //
        //    As a PRECONDITION it is exactly the right check: precondition 1 pins `proofBytes` to
        //    the submitted blobs. The pinned adapter decodes that canonical compact stream and
        //    compares its authenticated public inputs to `piHash` during classification.
        //    A mismatch proves only that the fraud prover supplied the wrong preimage — never that
        //    the submission is fraudulent.
        bytes32 piHash = _computeValidityPIHash(validityPIs);

        // ── Fraud detection (ONLY InvalidMleProof() = fraud) ──────────────

        // SECURITY (C-1/B-4). The round-1 comment here read:
        //     "`mleProof` is pinned to the committed blob by preconditions 1 and 4, so this
        //      verdict is a deterministic function of the submission itself — the fraud prover
        //      has no free input left with which to steer it."
        // That argument was WRONG and is corrected here, because it silently assumed the verdict
        // depends only on CALLDATA. It does not:
        //   * the transaction GAS LIMIT is a free input the fraud prover chooses, and EIP-150
        //     forwards 63/64 of it, so the prover can make the inner verification OOG while the
        //     outer frame survives to run `_truncateSubmissions`; and
        //   * the verifier can revert for reasons that are properties of the DEPLOYED EVALUATOR
        //     rather than of the proof (`Plonky2GateEvaluator`'s "unsupported gate with non-zero
        //     filter" — the gate-8 class), so an honest submission using such a gate was
        //     convictable by anyone.
        // Both routes produced a caught revert, and a caught revert used to read as fraud.
        //
        // The rule now: fraud is confirmed ONLY when the pinned verifier reaches a proof-dependent
        // check and reverts `InvalidMleProof()`. "Could not evaluate" reverts the whole
        // `fraudProof` transaction, so nothing is truncated, no bond moves, and the submission is
        // left exactly as it was.
        uint8 verdict = _encodedMleVerdict(proofBytes, piHash);
        if (verdict == MLE_PI_MISMATCH) return false;
        if (verdict == MLE_STARVED) revert FraudProofGasStarved();
        if (verdict > MLE_VALID) revert MleProofUnevaluable();
        return verdict == MLE_INVALID;
    }

    /// @dev Classify the exact compact bytes authenticated by `_verifyFraud`. Both layers retain
    /// gas so decoder/core starvation cannot masquerade as INVALID; unknown returns remain
    /// unevaluable and only the adapter's exact proof-dependent INVALID code can convict.
    function _encodedMleVerdict(bytes calldata proofBytes, bytes32 piHash) private view returns (uint8) {
        if (gasleft() < MIN_MLE_VERIFY_GAS) return MLE_STARVED;

        uint256 reserve = gasleft() / 64;
        uint256 budget = gasleft() - reserve;
        try validityMleVerifier.fraudVerdictCompact{gas: budget}(proofBytes, piHash) returns (uint8 verdict) {
            // `_verifyFraud` treats every value above VALID (except the explicit PI-mismatch and
            // starvation codes) as unevaluable, so unknown future values are already fail-safe.
            return verdict;
        } catch {
            if (gasleft() < reserve + budget / 8) return MLE_STARVED;
            return MLE_UNEVALUABLE;
        }
    }

    // -----------------------------------------------------------------------
    // Internal — Stake + rollback helpers
    // -----------------------------------------------------------------------

    function _truncateSubmissions(uint256 targetId, address reporter) internal {
        uint256 currentId = nextSubmissionId;
        while (currentId > targetId) {
            currentId--;
            Submission storage sub = _submissions[currentId];
            if (sub.finalized) revert AlreadyFinalized();

            _slashStake(currentId, reporter);
            _rollbackBatch(currentId);

            delete _submissions[currentId];
            delete _batchMetadata[currentId];
        }
        nextSubmissionId = targetId;
    }

    function _rollbackBatch(uint256 submissionId) internal {
        BatchMetadata memory meta = _batchMetadata[submissionId];
        if (meta.endBlockNumber == 0 && meta.startBlockNumber == 0) {
            return;
        }

        blockHashChain = meta.previousBlockHash;
        if (meta.startBlockNumber == 0) {
            blockNumber = 0;
        } else {
            blockNumber = meta.startBlockNumber - 1;
        }
        depositHashChain = meta.previousDepositHashChain;
        // G6: roll back the channel-registration chain accumulator (mirror of deposits).
        channelRegHashChain = meta.previousChannelRegHashChain;
        postingRound = meta.postingRoundBefore;

        if (meta.endBlockNumber >= meta.startBlockNumber && meta.endBlockNumber != 0) {
            uint64 bn = meta.endBlockNumber;
            address exitMaterializer = _channelExitMaterializer;
            while (true) {
                if (exitMaterializer != address(0)) {
                    assembly ("memory-safe") {
                        let ptr := mload(0x40)
                        mstore(ptr, shl(224, 0x2d97f88f)) // rollbackPost(uint64)
                        mstore(add(ptr, 4), bn)
                        if iszero(call(gas(), exitMaterializer, 0, ptr, 36, 0, 0)) {
                            returndatacopy(ptr, 0, returndatasize())
                            revert(ptr, returndatasize())
                        }
                    }
                }
                delete blockDepositHash[bn];
                delete blockChannelRegHash[bn];
                delete blockHashChainAt[bn];
                if (bn == meta.startBlockNumber) break;
                unchecked {
                    --bn;
                }
            }
        }

        processedDepositCount = meta.processedDepositCountBefore;

        // SECURITY (H-1: a rollback must NOT touch a chain the batch never advanced).
        // `_pendingDepositHashChain` and `_pendingChannelRegHashChain` are LIVE CUMULATIVE
        // accumulators owned exclusively by `deposit()` and `registerChannel()`. `_postBlock` only
        // READS them (see the batchDepositHashChain / batchChannelRegHashChain locals) — it never
        // writes either. So a batch never advances them, and there is nothing for a rollback to undo.
        // Restoring the pre-batch snapshots here (as this function used to) could therefore ONLY
        // erase deposits and channel registrations made AFTER the batch was posted: their ETH stays
        // in `totalEscrowed` (correctly not rolled back) while the hash chain that entitles anyone to
        // it is deleted, permanently crediting the funds to nobody. For registrations it also bricked
        // the channelId forever, because `channelMemberSetCommitment` is not rolled back either, so
        // the one-time `registerChannel` guard still fires on a retry.
        // Reachable from a genuine fraud proof and from the permissionless proof-free timeout branch.
    }

    /// @dev Credit fraud reward/treasury share to pendingWithdrawals (pull-payment).
    ///      Recipients call withdraw(amount) to claim. A reverting recipient cannot block fraudProof().
    function _slashStake(uint256 submissionId, address reporter) internal {
        StakeInfo storage info = stakeInfo[submissionId];
        if (info.submitter == address(0) || info.spent) {
            delete stakeInfo[submissionId];
            return;
        }

        info.spent = true;
        delete stakeInfo[submissionId];

        uint256 reward = (POST_BLOCK_STAKE * FRAUD_REWARD_PERCENT) / 100;
        uint256 treasuryShare = POST_BLOCK_STAKE - reward;

        pendingWithdrawals[reporter] += reward;
        pendingWithdrawals[fraudTreasury] += treasuryShare;

        emit WithdrawalCredited(reporter, reward);
        emit WithdrawalCredited(fraudTreasury, treasuryShare);
    }

    /// @dev Credit stake refund to pendingWithdrawals (pull-payment).
    ///      Submitter calls withdraw(amount) to claim. A reverting submitter cannot block finalize().
    function _refundStake(uint256 submissionId) internal {
        StakeInfo storage info = stakeInfo[submissionId];
        if (info.submitter == address(0) || info.spent) {
            delete stakeInfo[submissionId];
            return;
        }

        info.spent = true;
        address recipient = info.submitter;
        delete stakeInfo[submissionId];

        pendingWithdrawals[recipient] += POST_BLOCK_STAKE;
        emit WithdrawalCredited(recipient, POST_BLOCK_STAKE);
    }

    // -----------------------------------------------------------------------
    // Internal — Hash computation helpers
    // -----------------------------------------------------------------------

    /// @dev Compute keccak256(ValidityPublicInputs) matching the Rust layout:
    ///      initial_block_number (2×u32) || initial_block_chain (8×u32) ||
    ///      initial_ext_commitment (8×u32) || final_block_number (2×u32) ||
    ///      final_block_chain (8×u32) || final_ext_commitment (8×u32) ||
    ///      prover (5×u32) = 41 u32 words = 164 bytes.
    function _computeValidityPIHash(ValidityPublicInputs calldata pis) internal pure returns (bytes32) {
        bytes32 result;
        assembly ("memory-safe") {
            // Exact abi.encodePacked image of the seven static fields: 8+32+32+8+32+32+20.
            let ptr := mload(0x40)
            mstore(ptr, shl(192, calldataload(pis)))
            mstore(add(ptr, 8), calldataload(add(pis, 32)))
            mstore(add(ptr, 40), calldataload(add(pis, 64)))
            mstore(add(ptr, 72), shl(192, calldataload(add(pis, 96))))
            mstore(add(ptr, 80), calldataload(add(pis, 128)))
            mstore(add(ptr, 112), calldataload(add(pis, 160)))
            mstore(add(ptr, 144), shl(96, calldataload(add(pis, 192))))
            result := keccak256(ptr, 164)
            mstore(0x40, add(ptr, 192))
        }
        return result;
    }

    /// @dev SECURITY: Check that the MLE proof's public inputs encode piHash as 8 big-endian u32
    /// limbs — the soundness binding that replaces the removed Groth16 PI binding.
    ///
    /// The Plonky2 validity circuit registers keccak256(ValidityPublicInputs) as its public
    /// inputs by calling Bytes32::to_u32_vec() — 8 u32 values in big-endian byte order. The
    /// WrapperCircuit re-registers exactly those 8 limbs as its own public inputs, which become
    /// the adapter's returned public inputs after being absorbed into the WHIR Fiat-Shamir
    /// transcript. So `publicInputs` must have exactly 8 elements, each equal to the corresponding
    /// u32 limb of keccak256(ValidityPublicInputs). This ties the verified proof to the claimed
    /// validityPIs (and therefore to the accepted state root) with no separately-trusted argument.
    function _mlePublicInputsMatch(uint256[] memory publicInputs, bytes32 piHash) internal pure returns (bool) {
        if (publicInputs.length != 8) return false;
        return _limbsMatchBytes32(publicInputs, 0, piHash);
    }

    /// @dev Compute block hash matching Rust's Block::hash_with_prev_hash:
    ///      keccak256(prev_hash || channel_id || timestamp || key_ids
    ///               || tx_tree_root || deposit_hash_chain || channel_reg_hash_chain).
    ///      Integer fields and every key id are packed big-endian with their exact Rust width.
    function _computeBlockHash(
        bytes32 prevHash,
        uint32 channelId,
        uint64 blockTimestamp,
        uint32[] calldata keyIds,
        bytes32 txTreeRoot,
        bytes32 blockDepositHashChain,
        bytes32 blockChannelRegHashChain
    ) internal pure returns (bytes32) {
        bytes32 result;
        // `abi.encodePacked(uint32[])` pads each element to 32 bytes. Write the exact 4-byte words
        // directly instead; this is both cheaper and byte-identical to Rust's solidity_keccak256.
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, prevHash)
            mstore(add(ptr, 32), shl(224, channelId))
            mstore(add(ptr, 36), shl(192, blockTimestamp))
            let cursor := add(ptr, 44)
            let source := keyIds.offset
            let sourceEnd := add(source, mul(keyIds.length, 32))
            for {} lt(source, sourceEnd) { source := add(source, 32) } {
                mstore(cursor, shl(224, calldataload(source)))
                cursor := add(cursor, 4)
            }
            mstore(cursor, txTreeRoot)
            mstore(add(cursor, 32), blockDepositHashChain)
            mstore(add(cursor, 64), blockChannelRegHashChain)
            cursor := add(cursor, 96)
            result := keccak256(ptr, sub(cursor, ptr))
            mstore(0x40, and(add(cursor, 31), not(31)))
        }
        return result;
    }

    /// @dev Compute deposit hash matching Rust's Deposit::hash_with_prev_hash:
    ///      keccak256(prev_hash || depositor || recipient || token_index || amount || aux_data)
    ///      Note: deposit_index and block_number are NOT included.
    function _computeDepositHash(
        bytes32 prevHash,
        address depositor,
        bytes32 recipient,
        uint32 tokenIndex,
        uint256 amount,
        bytes32 auxData
    ) internal pure returns (bytes32) {
        bytes32 result;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, prevHash)
            mstore(add(ptr, 32), shl(96, depositor))
            mstore(add(ptr, 52), recipient)
            mstore(add(ptr, 84), shl(224, tokenIndex))
            mstore(add(ptr, 88), amount)
            mstore(add(ptr, 120), auxData)
            result := keccak256(ptr, 152)
            mstore(0x40, add(ptr, 160))
        }
        return result;
    }
}
