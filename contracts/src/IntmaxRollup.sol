// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {BlobKZGVerifier, KZGProof} from "./BlobKZGVerifier.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";

/// @title IGnarkVerifier
/// @notice Interface for gnark-generated Groth16 verifier with commitment support.
///         The verifier has VK constants hardcoded and reverts on invalid proof.
interface IGnarkVerifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[8] calldata input
    ) external view;
}

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
///    blob = abi.encode(Groth16Params, MleVerifier.MleProof, GoldilocksExt3.Ext3[])
///
///  Verification checks (finalize — both must pass):
///    a) Blob commitment (KZG multi-point opening)
///    b) ValidityPublicInputs match on-chain state
///    c) Proof params binding (blob bytes == abi.encode(groth16, mleProof))
///    d) Groth16 pubInputs[0..7] == keccak256(ValidityPublicInputs) as 8 big-endian u32 limbs
///       (matches the Plonky2 validity circuit's public inputs as exposed by gnark)
///    e) MLE proof verification
///    f) Groth16 verification
///
///  Fraud proof rules:
///    1) Finalized intmax block number is recorded on-chain; each submission's
///       commitment includes the Eth block number at posting time.
///    2) Fraud proofs cannot target submissions at or before the finalized block.
///    3) Submissions not finalized within 3600 Eth blocks (~12 hours) after posting
///       are removed unconditionally (no ZKP verification needed).
///    4) Successful fraud proof deletes the target and all subsequent submissions.
///
///  Fraud proof ZKP checks (either failure = fraud):
///    a) Blob commitment + KZG binding + PI binding all PASS
///    b) Proof params binding PASSES (fake-fraud prevention)
///    c) WHIR fails OR Groth16 fails → fraud confirmed
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
        uint32 aggregatorId,
        uint32[] localIds,
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
        uint32   aggregatorId;
        uint64   timestamp;
        bytes32  txTreeRoot;
        uint32[] localIds;
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

    /// @notice Bundles Groth16 verification parameters to avoid stack-too-deep.
    struct Groth16Params {
        Groth16Verifier.Proof proof;
        uint256[] pubInputs;
        uint256[2] commitments;     // gnark commitment point (G1)
        uint256[2] commitmentPok;   // gnark commitment proof of knowledge (G1)
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
    Groth16Verifier.VerifyingKey internal groth16Vk;

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
    IGnarkVerifier public immutable gnarkVerifier;

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
        Groth16Verifier.VerifyingKey memory verifyingKey,
        MleVk memory _mleVk,
        SpongefishWhirVerify.WhirParams memory whirParams_,
        bytes memory _whirProtocolId,
        bytes memory _whirSplitSessionId,
        uint256[] memory _kIs,
        uint256[] memory _subgroupGenPowers,
        MleVerifier _mleVerifier,
        IGnarkVerifier _gnarkVerifier,
        bytes32 _genesisStateRoot
    ) {
        fraudTreasury = _fraudTreasury;
        _setGroth16VerifyingKey(verifyingKey);
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
        gnarkVerifier = _gnarkVerifier;
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
    // TODO: Add access control (aggregator whitelist) before mainnet.
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
                subBlocks[i].aggregatorId,
                subBlocks[i].timestamp,
                subBlocks[i].localIds,
                subBlocks[i].txTreeRoot,
                depositHash
            );
            blockDepositHash[currentBlockNumber] = depositHash;

            emit BlockPosted(
                currentBlockNumber,
                subBlocks[i].aggregatorId,
                subBlocks[i].localIds,
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

    /// @notice MLE + Groth16 verification from calldata. No KZG, no blob binding.
    ///         Both verifiers must pass for the result to be true.
    /// @dev v2: the WHIR ext3 evaluations previously passed as a separate
    ///      `whirEvals` parameter are now embedded inside `mleProof`, so
    ///      this surface gets one fewer argument and is safer (the prover
    ///      can no longer supply mismatched evals).
    function verify(
        MleVerifier.MleProof calldata mleProof,
        Groth16Params memory groth16
    ) external view returns (bool) {
        // Verify MLE proof
        if (!_verifyMle(mleProof)) return false;

        // Verify Groth16
        if (!_verifyGroth16(groth16)) return false;

        return true;
    }

    // -----------------------------------------------------------------------
    // finalize()  —  full verification + state root acceptance
    // -----------------------------------------------------------------------

    /// @notice Verify and finalize a submission.
    ///         Checks: MLE proof, Groth16 proof, public input binding to on-chain state.
    function finalize(
        uint256 submissionId,
        bytes32 stateRoot,
        ValidityPublicInputs calldata validityPIs,
        MleVerifier.MleProof calldata mleProof,
        Groth16Params memory groth16
    ) external nonReentrant returns (bool) {
        Submission storage sub = _submissions[submissionId];
        if (sub.commitment == bytes32(0)) return false;
        if (sub.finalized) return false;

        bool valid;
        try this.fullVerify(stateRoot, validityPIs, mleProof, groth16) returns (bool v) {
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
    ///   The fraud prover supplies the exact blob bytes (Groth16 + WHIR) that
    ///   were committed, plus a KZG proof binding them to the blob.
    ///   Fraud is confirmed when binding checks pass and either proof fails.
    function fraudProof(
        uint256 submissionId,
        bytes32 blobVersionedHash,
        bytes32 stateRoot,
        bytes calldata proofBytes,
        ValidityPublicInputs calldata validityPIs,
        MleVerifier.MleProof calldata mleProof,
        KZGProof calldata kzg,
        Groth16Params memory groth16
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
            mleProof, kzg, groth16
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
        MleVerifier.MleProof calldata mleProof,
        Groth16Params memory groth16
    ) external view returns (bool) {
        // 1. PI binding to on-chain state
        if (validityPIs.initialExtCommitment != latestFinalizedStateRoot) return false;
        if (validityPIs.initialBlockChain != blockHashChainAt[validityPIs.initialBlockNumber]) return false;
        if (validityPIs.finalBlockChain != blockHashChainAt[validityPIs.finalBlockNumber]) return false;
        if (validityPIs.finalExtCommitment != stateRoot) return false;

        // 2. piHash binding: Groth16 pubInputs must encode keccak256(ValidityPublicInputs)
        //    as 8 big-endian u32 limbs.
        bytes32 piHash = _computeValidityPIHash(validityPIs);
        if (!_groth16PIHashMatches(groth16.pubInputs, piHash)) return false;

        // 3. MLE proof verification
        if (!_verifyMle(mleProof)) return false;

        // 4. Groth16 verification via gnark verifier (with commitment support)
        if (!_verifyGroth16(groth16)) return false;

        return true;
    }

    /// @dev Fraud detection pipeline. Returns true if fraud is confirmed.
    ///
    ///   Pre-conditions (must pass — proves fraud prover supplied the real blob data):
    ///     1. Commitment check
    ///     2. KZG blob binding
    ///     3. PI binding to on-chain state
    ///     4. Proof params binding: blob == abi.encode(groth16, config, statement, whirProof, transcript)
    ///
    ///   Fraud confirmed if any of:
    ///     (a) Wrong WhirParams in committed blob
    ///     (b) Groth16 pubInputs don't encode keccak256(ValidityPublicInputs) — PI hash mismatch
    ///     (c) Any WHIR batch verification fails
    ///     (d) Groth16 verification fails
    function _verifyFraud(
        uint256 submissionId,
        bytes32 blobVersionedHash,
        bytes32 stateRoot,
        bytes calldata proofBytes,
        ValidityPublicInputs calldata validityPIs,
        MleVerifier.MleProof calldata mleProof,
        KZGProof calldata kzg,
        Groth16Params memory groth16
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
        //    and R2-#2 per-point fields), so a single keccak over (groth16,
        //    mleProof) atomically pins them together with the rest of the
        //    proof. An attacker can no longer substitute different WHIR
        //    evaluations to falsely accuse a valid proof.
        if (keccak256(abi.encode(groth16, mleProof)) != keccak256(proofBytes)) {
            return false;
        }

        // ── Fraud detection (any failure = fraud) ────────────────────────

        // (a) piHash mismatch: Groth16 pubInputs
        bytes32 piHash = _computeValidityPIHash(validityPIs);
        if (!_groth16PIHashMatches(groth16.pubInputs, piHash)) return true;

        // (b) MLE proof verification fails
        if (!_verifyMle(mleProof)) return true;

        // (c) Groth16 verification fails
        if (!_verifyGroth16(groth16)) return true;

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

    /// @dev Verify Groth16 proof via the gnark-generated verifier (with commitment support).
    ///      Falls back to the built-in Groth16Verifier if no gnark verifier is set.
    function _verifyGroth16(Groth16Params memory groth16) internal view returns (bool) {
        if (address(gnarkVerifier) != address(0)) {
            // Convert proof to gnark format: [a.x, a.y, b.x00, b.x01, b.x10, b.x11, c.x, c.y]
            uint256[8] memory proof = [
                groth16.proof.a[0], groth16.proof.a[1],
                groth16.proof.b[0][0], groth16.proof.b[0][1],
                groth16.proof.b[1][0], groth16.proof.b[1][1],
                groth16.proof.c[0], groth16.proof.c[1]
            ];
            // Convert pubInputs to fixed-size array
            uint256[8] memory input;
            for (uint256 i = 0; i < 8 && i < groth16.pubInputs.length; i++) {
                input[i] = groth16.pubInputs[i];
            }
            try gnarkVerifier.verifyProof(proof, groth16.commitments, groth16.commitmentPok, input) {
                return true;
            } catch {
                return false;
            }
        }
        return Groth16Verifier.verify(groth16Vk, groth16.proof, groth16.pubInputs);
    }

    // -----------------------------------------------------------------------
    // Internal — MLE verification helpers
    // -----------------------------------------------------------------------

    /// @dev Verify MLE proof using the MleVerifier library.
    ///      SECURITY: When mleVk.degreeBits == 0, MLE verification is disabled.
    ///      This is intentional for deployments that only use Groth16 verification.
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

    function _setGroth16VerifyingKey(Groth16Verifier.VerifyingKey memory vkInput) internal {
        groth16Vk.alpha = vkInput.alpha;
        groth16Vk.beta = vkInput.beta;
        groth16Vk.gamma = vkInput.gamma;
        groth16Vk.delta = vkInput.delta;

        uint256 icLength = vkInput.ic.length;
        delete groth16Vk.ic;
        groth16Vk.ic = new uint256[2][](icLength);
        for (uint256 i = 0; i < icLength; i++) {
            groth16Vk.ic[i] = vkInput.ic[i];
        }
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

    /// @dev Check that Groth16 pubInputs encode piHash as 8 big-endian u32 limbs.
    ///
    /// The Plonky2 validity circuit registers keccak256(ValidityPublicInputs) as its public
    /// inputs by calling Bytes32::to_u32_vec() — 8 u32 values in big-endian byte order.
    /// gnark's ExampleVerifierCircuit exposes each Goldilocks element as one BN254 scalar,
    /// so pubInputs must have exactly 8 elements, each equal to the corresponding u32 limb.
    function _groth16PIHashMatches(
        uint256[] memory pubInputs,
        bytes32 piHash
    ) internal pure returns (bool) {
        if (pubInputs.length != 8) return false;
        uint256 h = uint256(piHash);
        for (uint256 i = 0; i < 8; i++) {
            // Extract the i-th big-endian u32 limb: bits [255-i*32 .. 224-i*32]
            uint256 limb = (h >> (224 - i * 32)) & 0xFFFFFFFF;
            if (pubInputs[i] != limb) return false;
        }
        return true;
    }

    /// @dev Compute block hash matching Rust's Block::hash_with_prev_hash:
    ///      keccak256(prev_hash || aggregator_id || timestamp || local_ids
    ///               || tx_tree_root || deposit_hash_chain)
    ///      All values packed as u32 words.
    function _computeBlockHash(
        bytes32 prevHash,
        uint32 aggregatorId,
        uint64 timestamp,
        uint32[] calldata localIds,
        bytes32 txTreeRoot,
        bytes32 blockDepositHashChain
    ) internal pure returns (bytes32) {
        // Build the u32 array matching Rust's solidity_keccak256 layout.
        // NOTE: abi.encodePacked(uint32[]) pads each element to 32 bytes, which
        // does NOT match Rust's 4-byte-per-u32 packing. We must manually pack
        // the localIds as raw 4-byte big-endian values.
        bytes memory packed = abi.encodePacked(
            prevHash,
            aggregatorId,
            timestamp
        );
        // Pack localIds as 4-byte big-endian values (matching Rust u32 layout)
        for (uint256 i = 0; i < localIds.length; i++) {
            packed = bytes.concat(packed, bytes4(localIds[i]));
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
