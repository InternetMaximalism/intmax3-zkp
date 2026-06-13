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
        bytes32[] memberSphincsPubkeyHashes,
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

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

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
    ///         SECURITY: When mleVk.degreeBits == 0, MLE verification is disabled.
    ///         Production deployments MUST set degreeBits > 0 with correct VK parameters.
    MleVk public mleVk;

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

    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status = _NOT_ENTERED;

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    /// @notice On-chain block hash chain state.
    ///         Updated by `postBlock()` — iterates over a batch of sub-blocks.
    bytes32 public blockHashChain;
    mapping(uint64 => bytes32) public blockDepositHash;

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

    /// @notice Bounds on members per channel (one SPHINCS+ key per member, D6 pad-to-MAX; mirrors
    /// the Rust `MAX_CHANNEL_MEMBERS` constant in src/constants.rs). A channel registers between
    /// `MIN_CHANNEL_MEMBERS` and `MAX_CHANNEL_MEMBERS` ACTIVE members in slot order.
    uint32 internal constant MAX_CHANNEL_MEMBERS = 16;
    uint32 internal constant MIN_CHANNEL_MEMBERS = 2;

    mapping(uint256 => Submission) internal _submissions;
    uint256 public nextSubmissionId;

    /// @notice The latest finalized state root (= final_ext_commitment from the last accepted proof).
    bytes32 public latestFinalizedStateRoot;

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
        bytes32 _genesisStateRoot
    ) {
        fraudTreasury = _fraudTreasury;
        mleVk = _mleVk;
        // Deep-copy WhirParams to storage (scalar fields + dynamic arrays)
        _whirParams.numVariables = whirParams_.numVariables;
        _whirParams.foldingFactor = whirParams_.foldingFactor;
        _whirParams.numVectors = whirParams_.numVectors;
        _whirParams.numCommitments = whirParams_.numCommitments;
        _whirParams.outDomainSamples = whirParams_.outDomainSamples;
        _whirParams.inDomainSamples = whirParams_.inDomainSamples;
        _whirParams.initialSumcheckRounds = whirParams_.initialSumcheckRounds;
        _whirParams.numRounds = whirParams_.numRounds;
        _whirParams.finalSumcheckRounds = whirParams_.finalSumcheckRounds;
        _whirParams.finalSize = whirParams_.finalSize;
        _whirParams.initialCodewordLength = whirParams_.initialCodewordLength;
        _whirParams.initialMerkleDepth = whirParams_.initialMerkleDepth;
        _whirParams.initialDomainGenerator = whirParams_.initialDomainGenerator;
        _whirParams.initialInterleavingDepth = whirParams_.initialInterleavingDepth;
        _whirParams.initialNumVariables = whirParams_.initialNumVariables;
        _whirParams.initialCosetSize = whirParams_.initialCosetSize;
        _whirParams.initialNumCosets = whirParams_.initialNumCosets;
        // Copy dynamic arrays
        for (uint256 i = 0; i < whirParams_.rounds.length; i++) {
            _whirParams.rounds.push(whirParams_.rounds[i]);
        }
        for (uint256 i = 0; i < whirParams_.evaluationPoint.length; i++) {
            _whirParams.evaluationPoint.push(whirParams_.evaluationPoint[i]);
        }
        for (uint256 i = 0; i < whirParams_.evaluationPoint2.length; i++) {
            _whirParams.evaluationPoint2.push(whirParams_.evaluationPoint2[i]);
        }
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

    // postBlock()  —  post a batch of fast blocks (one posting round)
    // -----------------------------------------------------------------------

    /// @notice Post a batch of fast blocks (~5-second blocks) to L1 as one
    ///         posting round (~5 minutes).  All sub-blocks' data lives in
    ///         calldata for data availability.
    ///
    ///         Deposits are applied to the LAST sub-block in the batch only.
    ///         Intermediate sub-blocks have zero deposit hash chains.
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

        // --- Prepare deposits for this posting round ---
        bytes32 pendingHashBefore = _pendingDepositHashChain;
        bytes32 batchDepositHashChain = pendingHashBefore;
        _pendingDepositHashChain = bytes32(0);

        uint64 previousPostingRound = postingRound;
        postingRound++;
        uint64 currentRound = postingRound;

        // --- Iterate over sub-blocks ---
        uint256 lastIdx = subBlocks.length - 1;
        for (uint256 i = 0; i < subBlocks.length; i++) {
            currentBlockNumber++;

            // Only the last sub-block carries deposits.
            bytes32 depositHash = bytes32(0);
            if (i == lastIdx) {
                depositHash = batchDepositHashChain;
            }

            currentHash = _computeBlockHash(
                currentHash,
                subBlocks[i].channelId,
                subBlocks[i].timestamp,
                subBlocks[i].keyIds,
                subBlocks[i].txTreeRoot,
                depositHash
            );
            blockDepositHash[currentBlockNumber] = depositHash;

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
        processedDepositCount = depositCount;

        meta = BatchMetadata({
            startBlockNumber: startBlockNumber,
            endBlockNumber: currentBlockNumber,
            previousBlockHash: previousBlockHash,
            previousDepositHashChain: previousDepositHashChain,
            pendingDepositHashChainBefore: pendingHashBefore,
            postingRoundBefore: previousPostingRound,
            postingRoundAfter: currentRound,
            processedDepositCountBefore: processedDepositsBefore
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
    ) external {
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
    ///         carries `member_sphincs_pubkey_hashes`, the keccak `member_pubkeys_root`, the
    ///         `regev_pk_root`, and the `bp_member_slot`. The ACTIVE member pubkey hashes must be
    ///         nonzero and pairwise distinct (`ChannelRecord::validate`); the active count is the
    ///         array length.
    /// @dev RECORDED ONLY: this hash chain is not yet consumed by the validity proof (see the
    ///      section header). The keccak preimage is tightly packed over the ACTIVE members, NO
    ///      array padding: keccak256(prev || channelId(4) || bpMemberSlot(1) || memberCount(1) ||
    ///               (sphincsPubkeyHash(32) || regevPkDigest(32) || recipient(20)) * memberCount).
    ///      `memberPubkeysRoot` = keccak of the active member pubkey hashes; `regevPkRoot` = keccak
    ///      of the active Regev pubkey digests (the L1/keccak digest forms anchored in the record).
    function registerChannel(
        uint32 channelId,
        uint8 bpMemberSlot,
        bytes32[] calldata memberSphincsPubkeyHashes,
        bytes32[] calldata regevPkDigests,
        address[] calldata recipients
    ) external {
        require(channelId != 0, "channel id 0 reserved");
        uint256 memberCount = memberSphincsPubkeyHashes.length;
        require(
            memberCount >= MIN_CHANNEL_MEMBERS &&
            memberCount <= MAX_CHANNEL_MEMBERS &&
            regevPkDigests.length == memberCount &&
            recipients.length == memberCount,
            "member count out of range (2..16) or array length mismatch"
        );
        require(uint256(bpMemberSlot) < memberCount, "bp member slot out of range");

        // One SPHINCS+ key per member: active pubkey hashes must be nonzero and pairwise distinct
        // (mirrors ChannelRecord::validate). Regev digests must be set; recipients must be set.
        for (uint256 i = 0; i < memberCount; i++) {
            require(memberSphincsPubkeyHashes[i] != bytes32(0), "member pubkey hash 0 reserved");
            require(regevPkDigests[i] != bytes32(0), "regev pk digest 0 reserved");
            require(recipients[i] != address(0), "recipient 0 reserved");
            for (uint256 j = i + 1; j < memberCount; j++) {
                require(
                    memberSphincsPubkeyHashes[i] != memberSphincsPubkeyHashes[j],
                    "member pubkey hashes must be distinct"
                );
            }
        }

        // L1/keccak digest forms of the member tree root and the Regev-pk root (active members).
        bytes32 memberPubkeysRoot = keccak256(abi.encodePacked(memberSphincsPubkeyHashes));
        bytes32 regevPkRoot = keccak256(abi.encodePacked(regevPkDigests));

        bytes memory packed = abi.encodePacked(
            _pendingChannelRegHashChain, channelId, bpMemberSlot, uint8(memberCount)
        );
        for (uint256 i = 0; i < memberCount; i++) {
            // Element-by-element to avoid abi.encodePacked's array-element padding.
            packed = abi.encodePacked(
                packed,
                memberSphincsPubkeyHashes[i], // bytes32: 32 bytes
                regevPkDigests[i],            // bytes32: 32 bytes
                recipients[i]                 // address: 20 bytes
            );
        }
        bytes32 newHash = keccak256(packed);
        _pendingChannelRegHashChain = newHash;
        uint64 idx = channelRegCount++;
        emit ChannelRegistered(
            idx,
            channelId,
            bpMemberSlot,
            memberSphincsPubkeyHashes,
            regevPkDigests,
            recipients,
            memberPubkeysRoot,
            regevPkRoot,
            newHash
        );
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
    ///      SECURITY: When mleVk.degreeBits == 0, MLE verification is disabled.
    ///      This is intentional only for test deployments that do not exercise the proof path.
    ///      Production deployments MUST set degreeBits > 0.
    function _verifyMle(
        MleVerifier.MleProof calldata mleProof
    ) internal view returns (bool) {
        // SECURITY: Skip MLE verification when not configured.
        // Production deployments MUST set mleVk.degreeBits > 0.
        if (mleVk.degreeBits == 0) return true;

        try this._verifyMleExternal(mleProof) returns (bool v) {
            return v;
        } catch {
            return false;
        }
    }

    /// @dev External helper so _verifyMle can try/catch on MLE verification.
    ///      Uses stored VK parameters (mleVk, _whirParams, whirProtocolId,
    ///      whirSplitSessionId, _mleKIs, _mleSubgroupGenPowers, mleVk.gatesDigest).
    ///      v2: the WHIR ext3 evaluations that were previously a separate
    ///      `whirEvals` parameter are now embedded inside `mleProof` itself
    ///      (Issues #3 + #7), so an attacker can no longer mix-and-match them.
    function _verifyMleExternal(
        MleVerifier.MleProof calldata mleProof
    ) external view returns (bool) {
        // SECURITY: Load WHIR params from storage — deep copy to memory for the library call.
        SpongefishWhirVerify.WhirParams memory whirParams = _loadWhirParams();
        MleVerifier.VerifyParams memory vp = MleVerifier.VerifyParams({
            degreeBits: mleVk.degreeBits,
            preprocessedCommitmentRoot: mleVk.preprocessedRoot,
            numConstants: mleVk.numConstants,
            numRoutedWires: mleVk.numRoutedWires,
            protocolId: whirProtocolId,
            sessionId: whirSplitSessionId,
            kIs: _mleKIs,
            subgroupGenPowers: _mleSubgroupGenPowers
        });
        return mleVerifier.verify(mleProof, vp, whirParams, mleVk.gatesDigest);
    }

    /// @dev Load WhirParams from storage into memory.
    function _loadWhirParams() private view returns (SpongefishWhirVerify.WhirParams memory p) {
        p.numVariables = _whirParams.numVariables;
        p.foldingFactor = _whirParams.foldingFactor;
        p.numVectors = _whirParams.numVectors;
        p.numCommitments = _whirParams.numCommitments;
        p.outDomainSamples = _whirParams.outDomainSamples;
        p.inDomainSamples = _whirParams.inDomainSamples;
        p.initialSumcheckRounds = _whirParams.initialSumcheckRounds;
        p.numRounds = _whirParams.numRounds;
        p.finalSumcheckRounds = _whirParams.finalSumcheckRounds;
        p.finalSize = _whirParams.finalSize;
        p.initialCodewordLength = _whirParams.initialCodewordLength;
        p.initialMerkleDepth = _whirParams.initialMerkleDepth;
        p.initialDomainGenerator = _whirParams.initialDomainGenerator;
        p.initialInterleavingDepth = _whirParams.initialInterleavingDepth;
        p.initialNumVariables = _whirParams.initialNumVariables;
        p.initialCosetSize = _whirParams.initialCosetSize;
        p.initialNumCosets = _whirParams.initialNumCosets;
        // Copy dynamic arrays from storage to memory
        uint256 rLen = _whirParams.rounds.length;
        p.rounds = new SpongefishWhirVerify.RoundParams[](rLen);
        for (uint256 i = 0; i < rLen; i++) {
            p.rounds[i] = _whirParams.rounds[i];
        }
        uint256 epLen = _whirParams.evaluationPoint.length;
        p.evaluationPoint = new GoldilocksExt3.Ext3[](epLen);
        for (uint256 i = 0; i < epLen; i++) {
            p.evaluationPoint[i] = _whirParams.evaluationPoint[i];
        }
        uint256 ep2Len = _whirParams.evaluationPoint2.length;
        p.evaluationPoint2 = new GoldilocksExt3.Ext3[](ep2Len);
        for (uint256 i = 0; i < ep2Len; i++) {
            p.evaluationPoint2[i] = _whirParams.evaluationPoint2[i];
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
        postingRound = meta.postingRoundBefore;

        if (meta.endBlockNumber >= meta.startBlockNumber && meta.endBlockNumber != 0) {
            for (uint64 bn = meta.startBlockNumber; bn <= meta.endBlockNumber; bn++) {
                delete blockDepositHash[bn];
                delete blockHashChainAt[bn];
                if (bn == meta.endBlockNumber) break;
            }
        }

        processedDepositCount = meta.processedDepositCountBefore;
        _pendingDepositHashChain = meta.pendingDepositHashChainBefore;
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
        bytes32 blockDepositHashChain
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
        packed = bytes.concat(
            packed,
            txTreeRoot,
            blockDepositHashChain
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
