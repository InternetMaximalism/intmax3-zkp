// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {BlobKZGVerifier, KZGProof} from "./BlobKZGVerifier.sol";

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
///    blob = abi.encode(MleVerifier.MleProof)
///
///  On-chain verification is MLE/WHIR-only (Groth16 removed). The validity public inputs are
///  bound to the proof through the MLE proof's own `publicInputs` field: the wrapped Plonky2
///  validity circuit registers keccak256(ValidityPublicInputs) as its 8 public-input limbs, which
///  flow into `mleProof.publicInputs` and are absorbed into the WHIR Fiat-Shamir transcript.
///
///  Verification checks (finalize — all must pass):
///    a) Blob commitment (KZG multi-point opening)
///    b) ValidityPublicInputs match on-chain state
///    c) Proof params binding (blob bytes == abi.encode(mleProof))
///    d) mleProof.publicInputs[0..7] == keccak256(ValidityPublicInputs) as 8 big-endian u32 limbs
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
    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------
    error NoBlobAttached();
    error CommitmentMismatch();
    error SubmissionNotFound();
    error AlreadyFinalized();
    error ProofVerificationFailed();
    error InitialStateMismatch();
    error BlockChainMismatch();
    error MleVerificationFailed();
    error EmptyBatch();
    error InvalidStakeAmount();
    error NothingToWithdraw();
    error SubmissionAlreadyFinalized();
    error SubmissionBeforeFinalizedBlock();
    error NothingToReclaim();
    error SubmissionNotYetFinalized();
    // Size-optimized replacements for former require-strings (custom errors are ~4 bytes vs a full
    // string literal duplicated at each use site by via_ir inlining). Behavior is unchanged.
    error ReentrantCall();
    error ChannelIdZeroReserved();
    error BpMemberSlotOutOfRange();
    error MemberPubkeyHashZeroReserved();
    error RegevPkDigestZeroReserved();
    error RecipientZeroReserved();
    error WithdrawalVkDegreeBitsZero();
    // SECURITY (A-2): a validity MLE VK with degreeBits == 0 disables on-chain proof verification
    // (`_verifyMle` short-circuits to true). Reject such a VK at deploy time unless the deployer
    // explicitly opts in via `allowMleDisabled` (test-only). Mirrors the withdrawal VK guard above.
    error ValidityVkDegreeBitsZero();
    // registerChannel validation (custom errors instead of require-strings — keeps IntmaxRollup
    // under the EIP-170 24,576-byte runtime limit after the delegate-account additions).
    error ChannelAlreadyRegistered();
    error DelegateCountExceedsActive();
    error MemberCountOrArrayLenInvalid();
    error MemberPubkeyHashesNotDistinct();

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------
    event BlockPosted(
        uint64 indexed blockNumber,
        uint32 channelId,
        uint32[] keyIds,
        bytes32 txTreeRoot,
        bytes32 newBlockHashChain
    );

    event Deposited(
        uint64 indexed depositIndex,
        address depositor,
        bytes32 recipient,
        uint32  tokenIndex,
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
        uint8   bpMemberSlot,
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
        bytes32 blobVersionedHash,
        bytes32 proofHash,
        uint32  proofLength,
        bytes32 stateRoot
    );

    event Finalized(
        uint256 indexed id,
        bytes32 stateRoot
    );

    event FraudConfirmed(
        uint256 indexed id,
        address indexed prover
    );

    event WithdrawalCredited(address indexed recipient, uint256 amount);

    /// @notice Emitted once when the deployer fixes the withdrawal-circuit MLE VK.
    event WithdrawalVkInitialized(uint256 degreeBits, bytes32 preprocessedRoot);

    /// @notice Emitted per `Withdrawal` leaf paid out by `withdrawNative`.
    event NativeWithdrawn(
        address indexed recipient,
        uint256 amount,
        bytes32 indexed nullifier,
        uint64 blockNumber
    );

    error WithdrawalVkNotSet();
    error WithdrawalExtCommitmentMismatch();
    error WithdrawalPublicInputsMismatch();
    error WithdrawalProofInvalid();
    error WithdrawalNullifierUsed();
    error WithdrawalNotEthToken();
    error WithdrawalEmptySet();

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    /// @notice A single native withdrawal leaf, byte-identical to the Rust `common::Withdrawal`
    ///         (src/common/withdrawal.rs). The keccak `withdrawal_hash` chain folds these in order
    ///         (`solidity_keccak256` u32→4-byte-BE packing), and the fold is re-checked on-chain so
    ///         the amount/recipient paid is the one bound by the verified proof — never caller-declared.
    struct Withdrawal {
        address recipient;   // 20 bytes  (Rust Address, 5×u32 big-endian)
        uint32  tokenIndex;  // 4 bytes
        uint256 amount;      // 32 bytes  (Rust U256, 8×u32 big-endian)
        bytes32 nullifier;   // 32 bytes
        bytes32 auxData;     // 32 bytes
    }

    struct Submission {
        bytes32 commitment;   // keccak256(blobHash || proofHash || proofLength || stateRoot || ethBlockNumber)
        address submitter;    // packed with `finalized` into one slot
        bool    finalized;
        uint64  submittedAtBlock; // Eth block number when submitted
    }

    struct StakeInfo {
        address submitter;
        bool spent;
    }

    /// @notice A single fast block (~5 seconds) within a posting-round batch.
    struct SubBlock {
        uint32   channelId;
        uint64   timestamp;
        bytes32  txTreeRoot;
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
        bytes32 pendingDepositHashChainBefore;
        uint64 postingRoundBefore;
        uint64 postingRoundAfter;
        uint64 processedDepositCountBefore;
        // G6: channel-registration chain snapshot for rollback (mirror of the deposit fields).
        bytes32 previousChannelRegHashChain;
        bytes32 pendingChannelRegHashChainBefore;
    }

    /// @notice MLE verification key parameters — fixed per circuit, set at deploy time.
    ///         SECURITY: These bind the on-chain verifier to a specific Plonky2 circuit.
    ///         Without them, an attacker could substitute a different circuit's proof.
    /// @dev Scalar VK params only; dynamic arrays (`kIs`, `subgroupGenPowers`)
    ///      are kept in dedicated storage variables (`_mleKIs` /
    ///      `_mleSubgroupGenPowers`) because Solidity's auto-generated public
    ///      getters cannot return structs containing dynamic arrays cleanly.
    struct MleVk {
        uint256 degreeBits;                // log2 of circuit degree
        bytes32 preprocessedRoot;          // WHIR Merkle root for preprocessed polynomial (VK binding)
        uint256 numConstants;              // number of constant columns
        uint256 numRoutedWires;            // number of routed wire columns
        bytes32 gatesDigest;               // v2 R2-#1: keccak hash pinning gate metadata
    }

    /// @notice Mirrors the Rust `ValidityPublicInputs` struct.
    ///         All fields are u32-packed, matching the Rust keccak256 input layout.
    ///         initial_block_number (2 u32), initial_block_chain (8 u32),
    ///         initial_ext_commitment (8 u32), final_block_number (2 u32),
    ///         final_block_chain (8 u32), final_ext_commitment (8 u32),
    ///         prover (5 u32) = 41 u32 = 164 bytes.
    struct ValidityPublicInputs {
        uint64  initialBlockNumber;
        bytes32 initialBlockChain;
        bytes32 initialExtCommitment;
        uint64  finalBlockNumber;
        bytes32 finalBlockChain;
        bytes32 finalExtCommitment;
        address prover;
    }

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    /// @notice External MLE verifier contract.
    MleVerifier public immutable mleVerifier;

    /// @notice MLE verification key — binds the contract to a specific Plonky2 circuit.
    ///         SECURITY: When mleVk.degreeBits == 0, MLE verification is disabled. This is only
    ///         reachable when `allowMleDisabled` is true (a test-only opt-in); production deploys
    ///         pass `allowMleDisabled == false`, so the constructor rejects a zero validity VK
    ///         (`ValidityVkDegreeBitsZero`) and `_verifyMle` never short-circuits.
    MleVk public mleVk;

    /// @notice SECURITY (A-2): explicit, immutable opt-in that allows deploying with a disabled
    ///         validity MLE VK (degreeBits == 0). MUST be false in production; only Solidity tests
    ///         that exercise the PI-binding path without real proofs set it true. The constructor
    ///         enforces a non-zero validity VK whenever this is false, and `_verifyMle` only honors
    ///         the degreeBits==0 bypass when this is true — a two-layer guard against the footgun.
    bool public immutable allowMleDisabled;

    /// @notice WHIR protocol parameters — fixed per circuit, set at deploy time.
    ///         Stored in storage because WhirParams contains dynamic arrays (rounds[]).
    SpongefishWhirVerify.WhirParams internal _whirParams;

    /// @notice WHIR protocol ID (64 bytes) — domain separation for the WHIR PCS.
    bytes public whirProtocolId;

    /// @notice WHIR session ID for split-commit mode (32 bytes).
    bytes public whirSplitSessionId;

    /// @notice v2 logUp permutation k_i values (length = numRoutedWires).
    ///         VK-bound: pinned to the specific Plonky2 circuit at deploy time.
    ///         SECURITY: these determine id_col(b) = k_is[col] · subgroup[b],
    ///         which the verifier checks against h̃(r) in the linear sumcheck.
    uint256[] internal _mleKIs;

    /// @notice v2 subgroup generator powers [g, g^2, g^4, ..., g^{2^(n-1)}].
    ///         Length = mleVk.degreeBits. Together with `_mleKIs` they
    ///         determine the identity-permutation MLE evaluation that closes
    ///         the logUp h̃(r) binding gap (R2-#2).
    uint256[] internal _mleSubgroupGenPowers;

    // -----------------------------------------------------------------------
    // Withdrawal payout VK (Phase 2) — a SECOND, independent MLE verification
    // key for the on-chain native-ETH withdrawal proof. It verifies the wrapped
    // `WithdrawalCircuit` proof, which is a DIFFERENT Plonky2 circuit than the
    // validity proof, so it needs its own preprocessedRoot / gatesDigest / kIs /
    // subgroupGenPowers / WhirParams. The MleVerifier CONTRACT is shared (one
    // deploy) — only the VK parameters differ — keeping us under EIP-170.
    //
    // SECURITY: set EXACTLY ONCE by the deployer via `initializeWithdrawalVk`,
    // after which it is immutable. `withdrawNative` reverts until it is set with
    // `degreeBits > 0`, so there is no window in which the payout path runs with
    // MLE verification disabled (unlike the validity path's degreeBits==0
    // test-disable seam, which the money path deliberately does NOT inherit).
    // -----------------------------------------------------------------------

    /// @notice Deployer — the only address allowed to set the withdrawal VK (once).
    address public immutable deployer;

    /// @notice Withdrawal-circuit MLE verification key. degreeBits == 0 ⇒ unset.
    MleVk public withdrawalMleVk;

    /// @notice True once `initializeWithdrawalVk` has run. Set-once latch.
    bool public withdrawalVkInitialized;

    SpongefishWhirVerify.WhirParams internal _whirParamsW;
    bytes public whirProtocolIdW;
    bytes public whirSplitSessionIdW;
    uint256[] internal _mleKIsW;
    uint256[] internal _mleSubgroupGenPowersW;

    /// @notice Spent withdrawal nullifiers (rollup-level, native payout path).
    /// SECURITY: each verified `Withdrawal.nullifier` (= Poseidon over the
    ///           settled transfer, recipient/amount-binding) may be paid out at
    ///           most once. Checked-then-set (CEI) before any value is credited.
    mapping(bytes32 => bool) public withdrawalNullifierUsed;

    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status = _NOT_ENTERED;

    modifier nonReentrant() {
        if (_status == _ENTERED) revert ReentrantCall();
        _status = _ENTERED;
        _;
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
    ///      the SAME fixed-16 keccak preimage as
    ///      `ChannelSettlementVerifier.closeMemberSetCommitment` — i.e.
    ///      `keccak256(bytes4(0x494d434d) || uint32(memberCount) || h_0 || .. || h_15)` with padding
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
    uint32 internal constant MAX_CHANNEL_MEMBERS = 16;
    uint32 internal constant MIN_CHANNEL_MEMBERS = 2;

    /// @notice IMCM domain word ("IMCM" = 0x494d434d) for the close-form member-set commitment.
    /// MUST equal `ChannelSettlementVerifier.CLOSE_MEMBER_SET_DOMAIN` so the commitment recorded by
    /// `registerChannel` is byte-identical to the one the close path matches (Finding E).
    uint32 internal constant CLOSE_MEMBER_SET_DOMAIN = 0x494d434d;

    /// @notice The token index reserved for native ETH. A deposit with this token index escrows
    ///         real ETH (msg.value must equal `amount`); any other token index is accounting-only
    ///         in v1 and must not carry ETH.
    uint32 public constant ETH_TOKEN_INDEX = 0;

    /// @notice Sum of real native ETH held by this contract on behalf of queued/finalized deposits.
    /// SECURITY: `totalEscrowed` is the global ceiling for all future native payouts
    ///           (Σ payouts ≤ totalEscrowed). It is enforced later by an underflow-revert on every
    ///           decrement at payout time, so no payout path can ever release more ETH than was
    ///           escrowed here. It is intentionally kept disjoint from the `POST_BLOCK_STAKE` ETH
    ///           tracked by `stakeInfo`/`pendingWithdrawals` (fraud-stake accounting), which is NOT
    ///           part of this balance.
    uint256 public totalEscrowed;

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
    mapping(bytes32 => bool) internal finalizedStateRoots;

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
    uint256 private constant FINALIZE_DEADLINE_BLOCKS = 5 * 60 * 12;
    address public immutable fraudTreasury;

    mapping(uint256 => StakeInfo) public stakeInfo;
    mapping(address => uint256) public pendingWithdrawals;
    mapping(uint64 => DepositRecord) internal _depositRecords;
    mapping(uint256 => BatchMetadata) internal _batchMetadata;
    uint64 public processedDepositCount;

    /// @notice Mask to clear top 3 bits so a 256-bit value fits in the
    ///         BLS12-381 scalar field (used for KZG blob field elements).
    uint256 internal constant FIELD_MASK = type(uint256).max >> 3;

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------
    constructor(
        address _fraudTreasury,
        MleVk memory _mleVk,
        SpongefishWhirVerify.WhirParams memory whirParams_,
        bytes memory _whirProtocolId,
        bytes memory _whirSplitSessionId,
        uint256[] memory _kIs,
        uint256[] memory _subgroupGenPowers,
        MleVerifier _mleVerifier,
        bytes32 _genesisStateRoot,
        bool _allowMleDisabled
    ) {
        // SECURITY (A-2): reject a validity VK that disables MLE verification unless the deployer
        // explicitly opts in (test-only). Symmetric with `initializeWithdrawalVk`'s guard.
        if (!_allowMleDisabled && _mleVk.degreeBits == 0) revert ValidityVkDegreeBitsZero();
        allowMleDisabled = _allowMleDisabled;
        fraudTreasury = _fraudTreasury;
        deployer = msg.sender;
        mleVk = _mleVk;
        // Deep-copy WhirParams to storage (scalar fields + dynamic arrays).
        _copyWhirParams(_whirParams, whirParams_);
        whirProtocolId = _whirProtocolId;
        whirSplitSessionId = _whirSplitSessionId;
        // v2 VK-bound permutation context (R2-#2 logUp soundness fix)
        for (uint256 i = 0; i < _kIs.length; i++) {
            _mleKIs.push(_kIs[i]);
        }
        for (uint256 i = 0; i < _subgroupGenPowers.length; i++) {
            _mleSubgroupGenPowers.push(_subgroupGenPowers[i]);
        }
        mleVerifier = _mleVerifier;
        latestFinalizedStateRoot = _genesisStateRoot;
        // Genesis: block 0 has default (zero) hash chains
        blockHashChainAt[0] = bytes32(0);
    }

    /// @dev Deep-copy a WhirParams (scalar fields + dynamic arrays) from memory into a storage
    ///      slot. Used by the constructor (validity VK) and `initializeWithdrawalVk` (withdrawal
    ///      VK). The destination arrays are assumed empty (each VK slot is written exactly once).
    function _copyWhirParams(
        SpongefishWhirVerify.WhirParams storage dst,
        SpongefishWhirVerify.WhirParams memory src
    ) private {
        dst.numVariables = src.numVariables;
        dst.foldingFactor = src.foldingFactor;
        dst.numVectors = src.numVectors;
        dst.numCommitments = src.numCommitments;
        dst.outDomainSamples = src.outDomainSamples;
        dst.inDomainSamples = src.inDomainSamples;
        dst.initialSumcheckRounds = src.initialSumcheckRounds;
        dst.numRounds = src.numRounds;
        dst.finalSumcheckRounds = src.finalSumcheckRounds;
        dst.finalSize = src.finalSize;
        dst.initialCodewordLength = src.initialCodewordLength;
        dst.initialMerkleDepth = src.initialMerkleDepth;
        dst.initialDomainGenerator = src.initialDomainGenerator;
        dst.initialInterleavingDepth = src.initialInterleavingDepth;
        dst.initialNumVariables = src.initialNumVariables;
        dst.initialCosetSize = src.initialCosetSize;
        dst.initialNumCosets = src.initialNumCosets;
        for (uint256 i = 0; i < src.rounds.length; i++) {
            dst.rounds.push(src.rounds[i]);
        }
        for (uint256 i = 0; i < src.evaluationPoint.length; i++) {
            dst.evaluationPoint.push(src.evaluationPoint[i]);
        }
        for (uint256 i = 0; i < src.evaluationPoint2.length; i++) {
            dst.evaluationPoint2.push(src.evaluationPoint2[i]);
        }
    }

    /// @notice Set the withdrawal-circuit MLE verification key. Deployer-only, set EXACTLY ONCE.
    /// @dev SECURITY: the withdrawal VK governs which Plonky2 circuit `withdrawNative` accepts. It
    ///      is fixed by the deployer immediately after deploy (same trust as the constructor's
    ///      validity VK) and can never be changed (`withdrawalVkInitialized` latch). `degreeBits`
    ///      must be > 0 — the payout path never runs with verification disabled. Splitting this out
    ///      of the constructor avoids re-plumbing 9 existing deploy sites; the set-once + deployer
    ///      guard make it behaviorally immutable, and `withdrawNative` reverts until it is set.
    function initializeWithdrawalVk(
        MleVk memory _vk,
        SpongefishWhirVerify.WhirParams memory whirParams_,
        bytes memory _protocolId,
        bytes memory _sessionId,
        uint256[] memory _kIs,
        uint256[] memory _subgroupGenPowers
    ) external {
        require(msg.sender == deployer, "only deployer");
        require(!withdrawalVkInitialized, "withdrawal vk already set");
        if (_vk.degreeBits == 0) revert WithdrawalVkDegreeBitsZero();
        withdrawalVkInitialized = true;
        withdrawalMleVk = _vk;
        _copyWhirParams(_whirParamsW, whirParams_);
        whirProtocolIdW = _protocolId;
        whirSplitSessionIdW = _sessionId;
        for (uint256 i = 0; i < _kIs.length; i++) {
            _mleKIsW.push(_kIs[i]);
        }
        for (uint256 i = 0; i < _subgroupGenPowers.length; i++) {
            _mleSubgroupGenPowersW.push(_subgroupGenPowers[i]);
        }
        emit WithdrawalVkInitialized(_vk.degreeBits, _vk.preprocessedRoot);
    }

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
    // TODO: Add access control (blockProducer whitelist) before mainnet.
    function postBlockAndSubmit(
        SubBlock[] calldata subBlocks,
        bytes32 proofHash,
        uint32 proofLength,
        bytes32 stateRoot
    ) external payable nonReentrant {
        if (msg.value != POST_BLOCK_STAKE) revert InvalidStakeAmount();
        BatchMetadata memory meta = _postBlock(subBlocks);
        uint256 submissionId = _submit(proofHash, proofLength, stateRoot);

        stakeInfo[submissionId] = StakeInfo({submitter: msg.sender, spent: false});
        _batchMetadata[submissionId] = meta;
    }

    function _postBlock(SubBlock[] calldata subBlocks) internal returns (BatchMetadata memory meta) {
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
        bytes32 pendingHashBefore = _pendingDepositHashChain;
        bytes32 batchDepositHashChain = pendingHashBefore;

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
        bytes32 pendingChannelRegBefore = _pendingChannelRegHashChain;
        // CUMULATIVE: `_pendingChannelRegHashChain` is NOT reset (see comment above), so when a
        // registration has occurred it already equals the running cumulative; the ternary still
        // selects `previous` only in the never-registered case (pending == 0).
        bytes32 batchChannelRegHashChain = pendingChannelRegBefore == bytes32(0)
            ? previousChannelRegHashChain
            : pendingChannelRegBefore;

        uint64 previousPostingRound = postingRound;
        postingRound++;
        uint64 currentRound = postingRound;

        // --- Iterate over sub-blocks ---
        uint256 lastIdx = subBlocks.length - 1;
        for (uint256 i = 0; i < subBlocks.length; i++) {
            currentBlockNumber++;

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
                currentBlockNumber,
                subBlocks[i].channelId,
                subBlocks[i].keyIds,
                subBlocks[i].txTreeRoot,
                currentHash
            );
        }

        // --- Update global state ---
        blockNumber = currentBlockNumber;
        blockHashChain = currentHash;
        blockHashChainAt[currentBlockNumber] = currentHash;
        depositHashChain = batchDepositHashChain;
        channelRegHashChain = batchChannelRegHashChain;
        processedDepositCount = depositCount;

        meta = BatchMetadata({
            startBlockNumber: startBlockNumber,
            endBlockNumber: currentBlockNumber,
            previousBlockHash: previousBlockHash,
            previousDepositHashChain: previousDepositHashChain,
            pendingDepositHashChainBefore: pendingHashBefore,
            postingRoundBefore: previousPostingRound,
            postingRoundAfter: currentRound,
            processedDepositCountBefore: processedDepositsBefore,
            previousChannelRegHashChain: previousChannelRegHashChain,
            pendingChannelRegHashChainBefore: pendingChannelRegBefore
        });
    }

    // -----------------------------------------------------------------------
    // deposit()  —  queue a deposit
    // -----------------------------------------------------------------------

    /// @notice Queue a deposit.  The deposit hash chain is updated immediately;
    ///         the deposit is associated with the next block.
    function deposit(
        bytes32 recipient,
        uint32 tokenIndex,
        uint256 amount,
        bytes32 auxData
    ) external payable {
        // --- Native-ETH escrow (Phase 1) ---
        // SECURITY: For ETH deposits the caller MUST forward exactly `amount` wei; we then grow
        // `totalEscrowed`, the global ceiling for all future native payouts. CEI: this is a pure
        // effect on our own balance/storage — there is no external call here, so there is nothing
        // to reorder. Stray ETH on a non-ETH deposit is rejected (no value sink), and plain ETH
        // transfers revert because the contract exposes no receive()/fallback().
        if (tokenIndex == ETH_TOKEN_INDEX) {
            require(msg.value == amount, "ETH deposit value mismatch");
            totalEscrowed += amount;
        } else {
            // Non-ETH tokens are out of scope for v1: accounting is preserved below, but no real
            // value is custodied, so the call must not carry ETH.
            require(msg.value == 0, "non-ETH deposit must not carry ETH");
        }

        uint64 idx = depositCount++;

        // Compute deposit hash matching Rust's Deposit::hash_with_prev_hash:
        //   keccak256(prev_hash || depositor(5×u32) || recipient(8×u32) || token_index(u32) || amount(8×u32) || aux_data(8×u32))
        //   Note: deposit_index and block_number are NOT included in the hash.
        bytes32 newHash = _computeDepositHash(
            _pendingDepositHashChain,
            msg.sender,
            recipient,
            tokenIndex,
            amount,
            auxData
        );
        _pendingDepositHashChain = newHash;
        _depositRecords[idx] = DepositRecord({
            depositor: msg.sender,
            recipient: recipient,
            tokenIndex: tokenIndex,
            amount: amount,
            auxData: auxData
        });

        emit Deposited(idx, msg.sender, recipient, tokenIndex, amount, auxData, newHash);
    }

    /// @notice Register a channel's member set. One SPHINCS+ key per member (D6 pad-to-MAX):
    ///         between `MIN_CHANNEL_MEMBERS` and `MAX_CHANNEL_MEMBERS` ACTIVE members in slot
    ///         order, each described by their SPHINCS+ pubkey hash (bytes32, the member identity),
    ///         their Regev pubkey digest (bytes32), and their L1 withdrawal recipient (address).
    ///         Mirrors the Rust `ChannelRecord` (src/common/channel.rs): the registration record
    ///         carries `member_pk_gs`, the keccak `member_pubkeys_root`, the
    ///         `regev_pk_root`, and the `bp_member_slot`. The ACTIVE member pubkey hashes must be
    ///         nonzero and pairwise distinct (`ChannelRecord::validate`); the active count is the
    ///         array length.
    /// @dev R3 WORD-ALIGNED fixed-16 preimage (consumed by the validity `channel_reg_step`
    ///      circuit). The keccak chain folds a FIXED 16-slot, word-aligned stream so the circuit
    ///      can consume it with a SINGLE keccak (no byte-straddling); padding slots
    ///      (i >= activeCount) contribute zeros. Header fields are uint32 (4-byte words):
    ///        keccak256(prev || channelId(uint32) || bpMemberSlot(uint32) || memberCount(uint32) ||
    ///                  delegateCount(uint32) ||
    ///                  for i in 0..16: (pkG(32) || pkB(32) || regevPkDigest(32) || recipient(20))).
    ///      This is byte-identical to the Rust `ChannelRegRecord::hash_with_prev_hash`
    ///      (src/common/channel_registration.rs) and its in-circuit twin — asserted by
    ///      `IntmaxRollup.t.sol::test_channelRegPreimageDifferential`.
    ///      `memberPubkeysRoot` = keccak of ALL active participant pubkey hashes (members +
    ///      delegates); `regevPkRoot` = keccak of all active Regev pubkey digests.
    /// @dev Delegate account: the `memberPkGs`/`pkBs`/`regevPkDigests`/`recipients` arrays carry the
    ///      ACTIVE participants — members first (`0..memberCount`) then delegates
    ///      (`memberCount..memberCount+delegateCount`). `memberCount = arrayLength - delegateCount`.
    ///      `delegateCount` is committed into the reg preimage IMMEDIATELY AFTER `memberCount`. The
    ///      close-form IMCM member-set commitment below stays MEMBER-ONLY (`0..memberCount`):
    ///      delegates do not co-sign, so they are excluded from the N-of-N signer set.
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
        if (channelId == 0) revert ChannelIdZeroReserved();
        // Finding E: ONE-TIME registration per channel. Matches the validity R5 one-time guard and
        // makes `channelMemberSetCommitment[channelId]` an unambiguous single source of truth that
        // the close-path manager binds to. A nonzero commitment means already registered.
        if (channelMemberSetCommitment[channelId] != bytes32(0)) revert ChannelAlreadyRegistered();
        // Delegate account: the arrays carry the ACTIVE participants (members first, then
        // delegates). `activeCount = memberPkGs.length` = memberCount + delegateCount; delegates
        // occupy the contiguous region `memberCount..activeCount`. `memberCount` is derived as
        // `activeCount - delegateCount`. With delegateCount = 0 this equals the legacy
        // `memberCount = memberPkGs.length`, so the preimage is byte-identical (Phase 1).
        uint256 activeCount = memberPkGs.length;
        if (uint256(delegateCount) > activeCount) revert DelegateCountExceedsActive();
        uint256 memberCount = activeCount - uint256(delegateCount);
        if (
            memberCount < MIN_CHANNEL_MEMBERS ||
            activeCount > MAX_CHANNEL_MEMBERS ||
            pkBs.length != activeCount ||
            regevPkDigests.length != activeCount ||
            recipients.length != activeCount
        ) revert MemberCountOrArrayLenInvalid();
        // bpMemberSlot must select a co-signing MEMBER, not a delegate.
        if (uint256(bpMemberSlot) >= memberCount) revert BpMemberSlotOutOfRange();

        // One key per ACTIVE participant (members + delegates): active pubkey hashes must be nonzero
        // and pairwise distinct (mirrors ChannelRecord::validate over `0..member_count+delegate_count`).
        // Regev digests must be set; recipients must be set.
        for (uint256 i = 0; i < activeCount; i++) {
            if (memberPkGs[i] == bytes32(0)) revert MemberPubkeyHashZeroReserved();
            if (regevPkDigests[i] == bytes32(0)) revert RegevPkDigestZeroReserved();
            if (recipients[i] == address(0)) revert RecipientZeroReserved();
            for (uint256 j = i + 1; j < activeCount; j++) {
                if (memberPkGs[i] == memberPkGs[j]) revert MemberPubkeyHashesNotDistinct();
            }
        }

        // R3 WORD-ALIGNED fixed-16 preimage built in a helper (keeps this frame off the via-IR
        // stack-too-deep limit). The word-aligned HEADER (prev || channelId(uint32) ||
        // bpMemberSlot(uint32) || memberCount(uint32) || delegateCount(uint32)) is assembled here and
        // passed as ONE `bytes` slot; the helper folds the 16 fixed member slots and hashes. This is
        // a byte-for-byte mirror of the Rust `ChannelRegRecord::hash_with_prev_hash`.
        bytes32 newHash = _channelRegHashChain(
            abi.encodePacked(
                _pendingChannelRegHashChain,
                channelId,
                uint32(bpMemberSlot),
                uint32(memberCount),
                uint32(delegateCount)
            ),
            activeCount,
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
        channelMemberSetCommitment[channelId] = _closeMemberSetCommitment(
            uint32(memberCount),
            memberPkGs
        );
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
    }

    /// @dev Close-form IMCM member-set commitment (MEMBER-ONLY, pad-to-MAX D6): keccak256(
    ///      bytes4(0x494d434d) || uint32(memberCount) || h_0 || .. || h_15 ) with active hashes in
    ///      slot order and padding slots (i >= memberCount) zeroed. Delegates are EXCLUDED (they do
    ///      not co-sign). Byte-identical to `ChannelSettlementVerifier.closeMemberSetCommitment` and
    ///      the Rust `close_member_set_commitment`. Extracted to its own frame for the via-IR stack
    ///      limit.
    function _closeMemberSetCommitment(
        uint32 memberCount,
        bytes32[] calldata memberPkGs
    ) internal pure returns (bytes32) {
        bytes memory memberSetPreimage = abi.encodePacked(
            bytes4(CLOSE_MEMBER_SET_DOMAIN),
            memberCount
        );
        for (uint256 i = 0; i < MAX_CHANNEL_MEMBERS; i++) {
            bytes32 slot = i < memberCount ? memberPkGs[i] : bytes32(0);
            memberSetPreimage = abi.encodePacked(memberSetPreimage, slot);
        }
        return keccak256(memberSetPreimage);
    }

    /// @dev R3 WORD-ALIGNED fixed-16 reg-chain preimage (D6 pad-to-MAX + delegate account). The
    ///      keccak chain hashes a FIXED 16-slot, word-aligned stream so the validity
    ///      (channel_reg_step) circuit can consume it with a SINGLE keccak (no byte-straddling).
    ///      Padding slots (i >= activeCount) contribute bytes32(0) || bytes32(0) || 20 zero bytes.
    ///      Header fields are uint32 (4-byte words), matching the Rust
    ///      `ChannelRegRecord::hash_with_prev_hash` u32 stream:
    ///        prev(32) || channelId(uint32=4) || bpMemberSlot(uint32=4) || memberCount(uint32=4) ||
    ///        delegateCount(uint32=4) ||
    ///        for i in 0..16: ( pkG(32) || pkB(32) || regevDigest(32) || recipient(20) ).
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
                    memberPkGs[i],     // bytes32: 32 bytes (pk_g)
                    pkBs[i],           // bytes32: 32 bytes (pk_b, P3)
                    regevPkDigests[i], // bytes32: 32 bytes
                    recipients[i]      // address: 20 bytes
                );
            } else {
                // Padding slot: zeroed pkG(32) || pkB(32) || regev(32) || recipient(20).
                packed = abi.encodePacked(
                    packed,
                    bytes32(0),
                    bytes32(0),
                    bytes32(0),
                    bytes20(0)
                );
            }
        }
        return keccak256(packed);
    }

    // -----------------------------------------------------------------------
    function _submit(
        bytes32 proofHash,
        uint32 proofLength,
        bytes32 stateRoot
    ) internal returns (uint256 submissionId) {
        bytes32 blobHash;
        assembly {
            blobHash := blobhash(0)
        }
        if (blobHash == bytes32(0)) revert NoBlobAttached();

        submissionId = nextSubmissionId++;
        uint64 ethBlock = uint64(block.number);
        bytes32 commitment = keccak256(
            abi.encodePacked(blobHash, proofHash, proofLength, stateRoot, ethBlock)
        );

        _submissions[submissionId] = Submission({
            commitment: commitment,
            submitter: msg.sender,
            finalized: false,
            submittedAtBlock: ethBlock
        });

        emit Submitted(submissionId, msg.sender, blobHash, proofHash, proofLength, stateRoot);
    }

    // -----------------------------------------------------------------------
    // verify()  —  pure WHIR verification (no binding)
    // -----------------------------------------------------------------------

    /// @notice MLE/WHIR verification from calldata. No KZG, no blob binding.
    /// @dev v2: the WHIR ext3 evaluations previously passed as a separate
    ///      `whirEvals` parameter are now embedded inside `mleProof`, so
    ///      this surface gets one fewer argument and is safer (the prover
    ///      can no longer supply mismatched evals). Groth16 is removed: on-chain
    ///      verification is MLE/WHIR-only.
    function verify(
        MleVerifier.MleProof calldata mleProof
    ) external view returns (bool) {
        return _verifyMle(mleProof);
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
        MleVerifier.MleProof calldata mleProof
    ) external nonReentrant returns (bool) {
        Submission storage sub = _submissions[submissionId];
        if (sub.commitment == bytes32(0)) return false;
        if (sub.finalized) return false;

        bool valid;
        try this.fullVerify(stateRoot, validityPIs, mleProof) returns (bool v) {
            valid = v;
        } catch {
            valid = false;
        }
        if (!valid) return false;

        sub.finalized = true;
        latestFinalizedStateRoot = stateRoot;
        finalizedStateRoots[stateRoot] = true; // permanent; enables withdrawals against any finalized root
        latestFinalizedBlockNumber = validityPIs.finalBlockNumber;

        emit Finalized(submissionId, stateRoot);
        _refundStake(submissionId);
        return true;
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
    ///   The fraud prover supplies the exact blob bytes (the MLE proof) that
    ///   were committed, plus a KZG proof binding them to the blob.
    ///   Fraud is confirmed when binding checks pass and the proof fails.
    function fraudProof(
        uint256 submissionId,
        bytes32 blobVersionedHash,
        bytes32 stateRoot,
        bytes calldata proofBytes,
        ValidityPublicInputs calldata validityPIs,
        MleVerifier.MleProof calldata mleProof,
        KZGProof calldata kzg
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

        bool confirmed = _verifyFraud(
            submissionId, blobVersionedHash, stateRoot,
            proofBytes, validityPIs,
            mleProof, kzg
        );
        if (!confirmed) return false;

        _truncateSubmissions(submissionId, msg.sender);
        emit FraudConfirmed(submissionId, msg.sender);
        return true;
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

    /// @notice Pull-payment: claim pending withdrawals (stake refunds / fraud rewards).
    ///         Finalize and fraudProof credit amounts to pendingWithdrawals instead of
    ///         pushing ETH, so reverting recipients cannot block protocol operations.
    function withdraw() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        pendingWithdrawals[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Withdraw failed");
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
    /// @param mleProof         The wrapped WithdrawalCircuit MLE/WHIR proof.
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
    ///   • No external call here (pull-payment via `withdraw()`); `nonReentrant` is belt-and-braces.
    function withdrawNative(
        Withdrawal[] calldata ws,
        address withdrawalProver,
        MleVerifier.MleProof calldata mleProof
    ) external nonReentrant {
        if (!withdrawalVkInitialized) revert WithdrawalVkNotSet();
        if (ws.length == 0) revert WithdrawalEmptySet();

        // 1. Verify the wrapped WithdrawalCircuit proof (real MLE/WHIR under the withdrawal VK).
        if (!_verifyMleWithdrawal(mleProof)) revert WithdrawalProofInvalid();

        // 2. The wrapped WithdrawalCircuit registers 17 PI limbs:
        //      [ pis_hash(8) || ext_commitment(8) || block_number(1) ]  (withdrawal_circuit.rs:206-208)
        //    NOTE: `block_number` is a u63 that fits in ONE Goldilocks field element, so its
        //    REGISTERED form is a single limb (`BlockNumberTarget::to_vec()`), even though the
        //    pis_hash keccak PREIMAGE splits it into 2 big-endian u32 words (`to_u32_vec`).
        uint256[] memory pi = mleProof.publicInputs;
        if (pi.length != 17) revert WithdrawalPublicInputsMismatch();

        // 2a. ext_commitment PI must be a state root this rollup has finalized (anchors the
        //     withdrawal to finalized state). Any historically-finalized root is accepted, not just
        //     the latest — finalized roots are permanent, so this is sound and avoids locking honest
        //     withdrawers out when the next block finalizes (the nullifier still blocks double-spend).
        bytes32 extCommitment = _limbsToBytes32(pi, 8);
        if (!finalizedStateRoots[extCommitment]) revert WithdrawalExtCommitmentMismatch();

        // 2b. block_number PI (single limb 16 = the u63 value). Used in the pis_hash recomputation
        //     below (re-split into 2 big-endian u32 words there); no separate equality check is
        //     needed — the pis_hash binding (step 3) already forces it to equal the circuit's value.
        uint64 blockNumber = uint64(pi[16]);

        // 3. Re-fold the keccak withdrawal chain (seed 0) → withdrawal_hash, recompute pis_hash, and
        //    require it equals the proof's pis_hash PI (limbs 0..8). Binds `ws` to the verified proof.
        bytes32 withdrawalHash = bytes32(0);
        for (uint256 i = 0; i < ws.length; i++) {
            withdrawalHash = _foldWithdrawalLeaf(withdrawalHash, ws[i]);
        }
        bytes32 pisHash = _withdrawalPisHash(withdrawalHash, withdrawalProver, extCommitment, blockNumber);
        if (!_limbsMatchBytes32(pi, 0, pisHash)) revert WithdrawalPublicInputsMismatch();

        // 4. Pay out each leaf (CEI: all checks/effects precede any value movement; pull-payment).
        for (uint256 i = 0; i < ws.length; i++) {
            Withdrawal calldata w = ws[i];
            if (w.tokenIndex != ETH_TOKEN_INDEX) revert WithdrawalNotEthToken(); // v1: ETH only
            if (withdrawalNullifierUsed[w.nullifier]) revert WithdrawalNullifierUsed();
            withdrawalNullifierUsed[w.nullifier] = true;
            // GLOBAL solvency ceiling: Solidity 0.8 underflow reverts if Σ would exceed real escrow.
            totalEscrowed -= w.amount;
            pendingWithdrawals[w.recipient] += w.amount;
            emit NativeWithdrawn(w.recipient, w.amount, w.nullifier, blockNumber);
        }
    }

    /// @dev Fold one Withdrawal leaf into the keccak chain. Byte-identical to Rust
    ///      `Withdrawal::hash_with_prev_hash` (withdrawal.rs:97, via solidity_keccak256's u32→4-byte
    ///      big-endian packing):
    ///        keccak256( prev(32) || recipient(20) || tokenIndex(4) || amount(32) || nullifier(32) || auxData(32) )
    ///      = 152-byte preimage. abi.encodePacked emits address as 20 bytes, uint32 as 4, uint256 as
    ///      32 (big-endian) — matching the Rust 5/1/8 u32-limb layout exactly.
    function _foldWithdrawalLeaf(bytes32 prev, Withdrawal calldata w) private pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(prev, w.recipient, w.tokenIndex, w.amount, w.nullifier, w.auxData)
        );
    }

    /// @dev pis_hash = remove_3bits( keccak256(
    ///        withdrawal_hash(32) || prover(20) || ext_commitment(32) || blockNumber(8, big-endian) ) )
    ///      mirroring `WithdrawalProofPublicInputs` (withdrawal_circuit.rs:57-68, 121-125).
    ///      remove_3bits clears the TOP 3 bits of the 256-bit value (Rust Bytes32::remove_3bits:
    ///      `limb[0] &= (1<<29)-1`, limb[0] = most-significant u32) ⇒ `value & ((1<<253)-1)`.
    ///      blockNumber as abi.encodePacked(uint64) = [high32_BE, low32_BE] = Rust to_u32_vec [high, low].
    function _withdrawalPisHash(
        bytes32 withdrawalHash,
        address prover,
        bytes32 extCommitment,
        uint64 blockNumber
    ) private pure returns (bytes32) {
        bytes32 h = keccak256(abi.encodePacked(withdrawalHash, prover, extCommitment, blockNumber));
        return bytes32(uint256(h) & ((uint256(1) << 253) - 1));
    }

    /// @dev Reconstruct a bytes32 from 8 big-endian u32 limbs starting at `off` (Bytes32::to_u32_vec
    ///      order: limb[0] = most-significant 4 bytes). Limbs are masked to u32; after a successful
    ///      `_verifyMleWithdrawal` the proof's publicInputs ARE the circuit's registered u32 PI wires.
    function _limbsToBytes32(uint256[] memory limbs, uint256 off) private pure returns (bytes32) {
        uint256 v = 0;
        for (uint256 i = 0; i < 8; i++) {
            v = (v << 32) | (limbs[off + i] & 0xFFFFFFFF);
        }
        return bytes32(v);
    }

    /// @dev Check 8 big-endian u32 limbs at `off` equal `value` EXACTLY (no masking — a limb with
    ///      high bits set is malformed and rejected). Mirrors `_mlePublicInputsMatch`.
    function _limbsMatchBytes32(uint256[] memory limbs, uint256 off, bytes32 value)
        private pure returns (bool)
    {
        uint256 h = uint256(value);
        for (uint256 i = 0; i < 8; i++) {
            uint256 limb = (h >> (224 - i * 32)) & 0xFFFFFFFF;
            if (limbs[off + i] != limb) return false;
        }
        return true;
    }

    /// @dev Verify the wrapped WithdrawalCircuit proof under the withdrawal VK.
    ///      SECURITY: NO `degreeBits == 0` disable seam — `withdrawNative` already requires
    ///      `withdrawalVkInitialized`, and `initializeWithdrawalVk` enforces `degreeBits > 0`, so the
    ///      payout path ALWAYS runs real MLE/WHIR verification (unlike the validity test-disable path).
    function _verifyMleWithdrawal(
        MleVerifier.MleProof calldata mleProof
    ) internal view returns (bool) {
        try this._verifyMleWithVk(mleProof, true) returns (bool v) {
            return v;
        } catch {
            return false;
        }
    }

    // -----------------------------------------------------------------------
    // Internal — Full verification pipeline
    // -----------------------------------------------------------------------

    /// @dev Full verification pipeline for finalize() — all checks must pass.
    ///      No KZG/blob binding: validity proofs are verified directly from calldata.
    ///      KZG binding is only needed for fraud proofs (proving committed blob is invalid).
    /// @dev External entry point so _fullVerify runs in a fresh EVM call context.
    ///      This avoids via_ir + optimizer code generation issues with large memory structs.
    function fullVerify(
        bytes32 stateRoot,
        ValidityPublicInputs calldata validityPIs,
        MleVerifier.MleProof calldata mleProof
    ) external view returns (bool) {
        // 1. PI binding to on-chain state
        // SECURITY (defense-in-depth for INV-A / reclaimStake): finalization must only ADVANCE the
        // finalized height. The initialExtCommitment check below already forces forward chaining, but
        // asserting monotonicity on-chain removes any reliance on the validity circuit guaranteeing
        // `finalBlockNumber >= initialBlockNumber` — and `latestFinalizedBlockNumber` is the height
        // `reclaimStake` compares against, so a backward move must never be accepted.
        if (validityPIs.finalBlockNumber < latestFinalizedBlockNumber) return false;
        if (validityPIs.initialExtCommitment != latestFinalizedStateRoot) return false;
        if (validityPIs.initialBlockChain != blockHashChainAt[validityPIs.initialBlockNumber]) return false;
        if (validityPIs.finalBlockChain != blockHashChainAt[validityPIs.finalBlockNumber]) return false;
        if (validityPIs.finalExtCommitment != stateRoot) return false;

        // 2. piHash binding (SECURITY, replaces the removed Groth16 PI binding): the MLE proof's
        //    own public inputs must encode keccak256(ValidityPublicInputs) as 8 big-endian u32
        //    limbs. Without this, removing Groth16 would leave validityPIs UNBOUND to the verified
        //    proof — an attacker could finalize arbitrary validityPIs (and thus an arbitrary state
        //    root) against any valid MLE proof. `mleProof.publicInputs` is the wrapped Plonky2
        //    validity circuit's public inputs (= keccak256(ValidityPublicInputs)), absorbed into
        //    the WHIR Fiat-Shamir transcript inside `_verifyMle`, so binding them here ties the
        //    claimed validityPIs to the proof that step 3 verifies.
        bytes32 piHash = _computeValidityPIHash(validityPIs);
        if (!_mlePublicInputsMatch(mleProof.publicInputs, piHash)) return false;

        // 3. MLE proof verification
        if (!_verifyMle(mleProof)) return false;

        return true;
    }

    /// @dev Fraud detection pipeline. Returns true if fraud is confirmed.
    ///
    ///   Pre-conditions (must pass — proves fraud prover supplied the real blob data):
    ///     1. Commitment check
    ///     2. KZG blob binding
    ///     3. PI binding to on-chain state
    ///     4. Proof params binding: blob == abi.encode(mleProof)
    ///
    ///   Fraud confirmed if any of:
    ///     (a) mleProof.publicInputs don't encode keccak256(ValidityPublicInputs) — PI hash mismatch
    ///     (b) MLE/WHIR verification fails
    function _verifyFraud(
        uint256 submissionId,
        bytes32 blobVersionedHash,
        bytes32 stateRoot,
        bytes calldata proofBytes,
        ValidityPublicInputs calldata validityPIs,
        MleVerifier.MleProof calldata mleProof,
        KZGProof calldata kzg
    ) internal view returns (bool) {
        // ── Pre-conditions ────────────────────────────────────────────────

        // 1. Commitment check (includes Eth block number at submission time)
        {
            uint32 proofLength = uint32(proofBytes.length);
            bytes32 proofHash = keccak256(proofBytes);
            uint64 ethBlock = _submissions[submissionId].submittedAtBlock;
            bytes32 commitment = keccak256(
                abi.encodePacked(blobVersionedHash, proofHash, proofLength, stateRoot, ethBlock)
            );
            if (commitment != _submissions[submissionId].commitment) return false;
        }

        // 2. KZG blob binding
        try this._verifyKZG(blobVersionedHash, kzg, proofBytes) {
        } catch {
            return false;
        }

        // 3. PI binding to on-chain state
        if (validityPIs.initialExtCommitment != latestFinalizedStateRoot) return false;
        if (validityPIs.initialBlockChain != blockHashChainAt[validityPIs.initialBlockNumber]) return false;
        if (validityPIs.finalBlockChain != blockHashChainAt[validityPIs.finalBlockNumber]) return false;
        if (validityPIs.finalExtCommitment != stateRoot) return false;

        // 4. Proof params binding — ensures we verify exactly what was committed.
        //    SECURITY: v2 moves the WHIR ext3 evaluations INSIDE `mleProof`
        //    (preprocessedWhirEval / witnessWhirEval / auxWhirEval + the R2-#1
        //    and R2-#2 per-point fields), so a single keccak over `mleProof`
        //    atomically pins them together with the rest of the proof. An
        //    attacker can no longer substitute different WHIR evaluations to
        //    falsely accuse a valid proof.
        if (keccak256(abi.encode(mleProof)) != keccak256(proofBytes)) {
            return false;
        }

        // ── Fraud detection (any failure = fraud) ────────────────────────

        // (a) piHash mismatch: mleProof.publicInputs must bind keccak256(ValidityPublicInputs).
        //     SECURITY: this is the soundness anchor that replaces the removed Groth16 PI binding.
        bytes32 piHash = _computeValidityPIHash(validityPIs);
        if (!_mlePublicInputsMatch(mleProof.publicInputs, piHash)) return true;

        // (b) MLE/WHIR verification fails
        if (!_verifyMle(mleProof)) return true;

        return false;
    }

    /// @dev External helper so _fullVerify/_verifyFraud can try/catch on KZG verification.
    function _verifyKZG(
        bytes32 blobVersionedHash,
        KZGProof calldata kzg,
        bytes calldata proofBytes
    ) external view {
        BlobKZGVerifier.verify(
            blobVersionedHash,
            kzg,
            _toFieldElements(proofBytes)
        );
    }

    // -----------------------------------------------------------------------
    // Internal — MLE verification helpers
    // -----------------------------------------------------------------------

    /// @dev Verify MLE proof using the MleVerifier library.
    ///      SECURITY (A-2): the degreeBits==0 bypass is honored ONLY when `allowMleDisabled` is
    ///      true (a test-only opt-in enforced at construction). In production `allowMleDisabled` is
    ///      false and the constructor already rejects a zero validity VK, so this branch is dead and
    ///      every finalize runs real MLE/WHIR verification. The extra `allowMleDisabled` conjunct is
    ///      defense-in-depth: even if a zero VK somehow reached storage, it would NOT skip here.
    function _verifyMle(
        MleVerifier.MleProof calldata mleProof
    ) internal view returns (bool) {
        // SECURITY: Skip MLE verification only on an explicit test-only deployment.
        if (allowMleDisabled && mleVk.degreeBits == 0) return true;

        try this._verifyMleWithVk(mleProof, false) returns (bool v) {
            return v;
        } catch {
            return false;
        }
    }

    /// @dev External helper so `_verifyMle`/`_verifyMleWithdrawal` can try/catch on MLE verification.
    ///      `isWithdrawal` selects which VK storage to use: the validity VK (`mleVk`/`_whirParams`/…)
    ///      or the withdrawal VK (`withdrawalMleVk`/`_whirParamsW`/…). Shared to stay under EIP-170.
    ///      v2: the WHIR ext3 evaluations are embedded inside `mleProof` itself (Issues #3 + #7), so
    ///      an attacker cannot mix-and-match them.
    function _verifyMleWithVk(
        MleVerifier.MleProof calldata mleProof,
        bool isWithdrawal
    ) external view returns (bool) {
        MleVk storage vk = isWithdrawal ? withdrawalMleVk : mleVk;
        SpongefishWhirVerify.WhirParams memory whirParams =
            _loadWhirParamsFrom(isWithdrawal ? _whirParamsW : _whirParams);
        MleVerifier.VerifyParams memory vp = MleVerifier.VerifyParams({
            degreeBits: vk.degreeBits,
            preprocessedCommitmentRoot: vk.preprocessedRoot,
            numConstants: vk.numConstants,
            numRoutedWires: vk.numRoutedWires,
            protocolId: isWithdrawal ? whirProtocolIdW : whirProtocolId,
            sessionId: isWithdrawal ? whirSplitSessionIdW : whirSplitSessionId,
            kIs: isWithdrawal ? _mleKIsW : _mleKIs,
            subgroupGenPowers: isWithdrawal ? _mleSubgroupGenPowersW : _mleSubgroupGenPowers
        });
        return mleVerifier.verify(mleProof, vp, whirParams, vk.gatesDigest);
    }

    /// @dev Load a WhirParams from the given storage slot into memory. Shared by the validity
    ///      (`_whirParams`) and withdrawal (`_whirParamsW`) verification paths to avoid duplicating
    ///      this (bytecode-heavy) field-by-field copy twice (EIP-170 budget).
    function _loadWhirParamsFrom(SpongefishWhirVerify.WhirParams storage s)
        private view returns (SpongefishWhirVerify.WhirParams memory p)
    {
        p.numVariables = s.numVariables;
        p.foldingFactor = s.foldingFactor;
        p.numVectors = s.numVectors;
        p.numCommitments = s.numCommitments;
        p.outDomainSamples = s.outDomainSamples;
        p.inDomainSamples = s.inDomainSamples;
        p.initialSumcheckRounds = s.initialSumcheckRounds;
        p.numRounds = s.numRounds;
        p.finalSumcheckRounds = s.finalSumcheckRounds;
        p.finalSize = s.finalSize;
        p.initialCodewordLength = s.initialCodewordLength;
        p.initialMerkleDepth = s.initialMerkleDepth;
        p.initialDomainGenerator = s.initialDomainGenerator;
        p.initialInterleavingDepth = s.initialInterleavingDepth;
        p.initialNumVariables = s.initialNumVariables;
        p.initialCosetSize = s.initialCosetSize;
        p.initialNumCosets = s.initialNumCosets;
        uint256 rLen = s.rounds.length;
        p.rounds = new SpongefishWhirVerify.RoundParams[](rLen);
        for (uint256 i = 0; i < rLen; i++) {
            p.rounds[i] = s.rounds[i];
        }
        uint256 epLen = s.evaluationPoint.length;
        p.evaluationPoint = new GoldilocksExt3.Ext3[](epLen);
        for (uint256 i = 0; i < epLen; i++) {
            p.evaluationPoint[i] = s.evaluationPoint[i];
        }
        uint256 ep2Len = s.evaluationPoint2.length;
        p.evaluationPoint2 = new GoldilocksExt3.Ext3[](ep2Len);
        for (uint256 i = 0; i < ep2Len; i++) {
            p.evaluationPoint2[i] = s.evaluationPoint2[i];
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
            for (uint64 bn = meta.startBlockNumber; bn <= meta.endBlockNumber; bn++) {
                delete blockDepositHash[bn];
                delete blockChannelRegHash[bn];
                delete blockHashChainAt[bn];
                if (bn == meta.endBlockNumber) break;
            }
        }

        processedDepositCount = meta.processedDepositCountBefore;
        _pendingDepositHashChain = meta.pendingDepositHashChainBefore;
        _pendingChannelRegHashChain = meta.pendingChannelRegHashChainBefore;
    }

    /// @dev Credit fraud reward/treasury share to pendingWithdrawals (pull-payment).
    ///      Recipients call withdraw() to claim. A reverting recipient cannot block fraudProof().
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
    ///      Submitter calls withdraw() to claim. A reverting submitter cannot block finalize().
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
    function _computeValidityPIHash(
        ValidityPublicInputs calldata pis
    ) internal pure returns (bytes32) {
        // Pack into the same u32 layout as Rust's to_u32_vec():
        //   BlockNumber → [lo32, hi32] of the u64
        //   Bytes32     → 8 × u32 (big-endian byte order within each u32 matches Rust's U32LimbTrait)
        //   Address     → 5 × u32
        // All concatenated and passed through solidity keccak256.
        return keccak256(
            abi.encodePacked(
                pis.initialBlockNumber,
                pis.initialBlockChain,
                pis.initialExtCommitment,
                pis.finalBlockNumber,
                pis.finalBlockChain,
                pis.finalExtCommitment,
                pis.prover
            )
        );
    }

    /// @dev SECURITY: Check that the MLE proof's public inputs encode piHash as 8 big-endian u32
    /// limbs — the soundness binding that replaces the removed Groth16 PI binding.
    ///
    /// The Plonky2 validity circuit registers keccak256(ValidityPublicInputs) as its public
    /// inputs by calling Bytes32::to_u32_vec() — 8 u32 values in big-endian byte order. The
    /// WrapperCircuit re-registers exactly those 8 limbs as its own public inputs, which become
    /// `MleProof.publicInputs` and are absorbed into the WHIR Fiat-Shamir transcript inside
    /// `verify()`. So `publicInputs` must have exactly 8 elements, each equal to the corresponding
    /// u32 limb of keccak256(ValidityPublicInputs). This ties the verified proof to the claimed
    /// validityPIs (and therefore to the accepted state root) with no separately-trusted argument.
    function _mlePublicInputsMatch(
        uint256[] memory publicInputs,
        bytes32 piHash
    ) internal pure returns (bool) {
        if (publicInputs.length != 8) return false;
        uint256 h = uint256(piHash);
        for (uint256 i = 0; i < 8; i++) {
            // Extract the i-th big-endian u32 limb: bits [255-i*32 .. 224-i*32]
            uint256 limb = (h >> (224 - i * 32)) & 0xFFFFFFFF;
            if (publicInputs[i] != limb) return false;
        }
        return true;
    }

    /// @dev Compute block hash matching Rust's Block::hash_with_prev_hash:
    ///      keccak256(prev_hash || channel_id || timestamp || key_ids
    ///               || tx_tree_root || deposit_hash_chain)
    ///      All values packed as u32 words.
    function _computeBlockHash(
        bytes32 prevHash,
        uint32 channelId,
        uint64 timestamp,
        uint32[] calldata keyIds,
        bytes32 txTreeRoot,
        bytes32 blockDepositHashChain,
        bytes32 blockChannelRegHashChain
    ) internal pure returns (bytes32) {
        // Build the u32 array matching Rust's solidity_keccak256 layout.
        // NOTE: abi.encodePacked(uint32[]) pads each element to 32 bytes, which
        // does NOT match Rust's 4-byte-per-u32 packing. We must manually pack
        // the keyIds as raw 4-byte big-endian values.
        bytes memory packed = abi.encodePacked(
            prevHash,
            channelId,
            timestamp
        );
        // Pack keyIds as 4-byte big-endian values (matching Rust u32 layout)
        for (uint256 i = 0; i < keyIds.length; i++) {
            packed = bytes.concat(packed, bytes4(keyIds[i]));
        }
        // G6: the block-hash preimage is
        //   prev || channelId || timestamp || keyIds || txTreeRoot ||
        //   deposit_hash_chain || channel_reg_hash_chain
        // byte-identical to Rust `Block::hash_with_prev_hash` (deposit chain then reg chain, each
        // 32 bytes). This folds the registration chain into the on-chain block hash chain, so the
        // `blockHashChainAt` snapshot the validity proof must match commits the registration set.
        packed = bytes.concat(
            packed,
            txTreeRoot,
            blockDepositHashChain,
            blockChannelRegHashChain
        );
        return keccak256(packed);
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
        return keccak256(
            abi.encodePacked(
                prevHash,
                depositor,
                recipient,
                tokenIndex,
                amount,
                auxData
            )
        );
    }

    /// @dev Split raw bytes into BLS12-381 field elements (top 3 bits cleared).
    function _toFieldElements(bytes calldata data)
        internal pure returns (bytes32[] memory elems)
    {
        uint256 N = (data.length + 31) / 32;
        elems = new bytes32[](N);
        for (uint256 i = 0; i < N; i++) {
            uint256 start = i * 32;
            uint256 end = start + 32;
            bytes32 chunk;
            if (end <= data.length) {
                chunk = bytes32(data[start:end]);
            } else {
                bytes memory padded = new bytes(32);
                uint256 remaining = data.length - start;
                for (uint256 j = 0; j < remaining; j++) {
                    padded[j] = data[start + j];
                }
                assembly { chunk := mload(add(padded, 32)) }
            }
            elems[i] = bytes32(uint256(chunk) & FIELD_MASK);
        }
    }
}
