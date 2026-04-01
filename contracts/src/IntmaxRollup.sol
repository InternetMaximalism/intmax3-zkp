// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SpongefishWhirVerify} from "./spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "./spongefish/GoldilocksExt3.sol";
import {BlobKZGVerifier, KZGProof} from "./BlobKZGVerifier.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";
import {Plonky2Verifier} from "./Plonky2Verifier.sol";
import {IForcedTxLogic} from "./IForcedTxLogic.sol";

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
///       Pure user-tx blocks.  No deposits, no forced txs.
///       Aggregators collect txs and build blocks off-chain.
///       Each block still has a block_number and updates the hash chain
///       inside the ZK circuit, but is NOT individually posted to L1.
///
///    Layer 1.1 — "posting rounds" (~5 minutes, on-chain calldata):
///       Aggregators call `postBlock(SubBlock[])` to commit a batch of
///       fast blocks to L1 as calldata.  The contract iterates over the
///       batch and recomputes the cumulative block_hash_chain.
///       Deposits and forced txs are processed at this boundary only
///       (applied to the last sub-block in the batch).
///       `blockHashChainAt[lastBlockNumber]` is recorded for the batch.
///
///    Layer 1 — "finalization" (~6 hours, validity proof):
///       The sequencer posts each validity proof blob via `postBlockAndSubmit()`.
///       Anyone can call `finalize()` to verify the proof against the
///       on-chain block_hash_chain snapshots and accept the new state root.
///
///  Blob format (both finalize and fraudProof):
///    blob = abi.encode(Groth16Params, WhirBatchProof[], Plonky2ConstraintData)
///
///  Verification checks (finalize — both must pass):
///    a) Blob commitment (KZG multi-point opening)
///    b) ValidityPublicInputs match on-chain state
///    c) Proof params binding (blob bytes == abi.encode(groth16, whir))
///    d) Groth16 pubInputs[0..7] == keccak256(ValidityPublicInputs) as 8 big-endian u32 limbs
///       (matches the Plonky2 validity circuit's public inputs as exposed by gnark)
///    e) WHIR proof verification
///    f) Groth16 verification
///
///  Fraud proof rules:
///    1) Finalized intmax block number is recorded on-chain; each submission's
///       commitment includes the Eth block number at posting time.
///    2) Fraud proofs cannot target submissions at or before the finalized block.
///    3) Submissions not finalized within 144 Eth blocks (~29 min) after posting
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
    error WhirPublicInputMismatch();
    error NoForcedTxLogicRegistered();
    error ForcedTxInsertFailed();
    error EmptyBatch();
    error ForcedTxLogicAlreadyRegistered();
    error ForcedTxLogicNotAccepted();
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

    event ForcedTxLogicRegistered(
        uint64 indexed userId,
        address logicContract
    );

    event ForcedTxQueued(
        uint64 indexed userId,
        bytes32 txHash,
        bytes32 newAccumulator
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

    /// @notice Bundles a single WHIR batch proof (Goldilocks Ext3 field).
    ///         The full validity proof consists of 4 WHIR batch proofs:
    ///         constants_sigmas, wires, zs_partial_products, quotient_polys.
    struct WhirBatchProof {
        bytes protocolId;
        bytes sessionId;
        bytes instance;
        bytes transcript;
        bytes hints;
        GoldilocksExt3.Ext3[] evaluations;
        SpongefishWhirVerify.WhirParams params;
    }

    /// @notice Plonky2 constraint satisfaction data.
    ///         The openings/challenges/publicInputs are proof-specific;
    ///         the params/permData/gates are circuit-constant.
    struct Plonky2ConstraintData {
        Plonky2Verifier.Openings openings;
        Plonky2Verifier.CircuitParams params;
        Plonky2Verifier.Challenges challenges;
        Plonky2Verifier.PermutationData permData;
        Plonky2Verifier.GateInfo[] gates;
        uint256[] publicInputs;
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

    /// @notice Keccak256 hash of the expected WHIR WhirParams array.
    ///         Set at deploy time. All finalize/fraudProof calls must supply
    ///         WhirBatchProof[] whose WhirParams hashes match this value.
    ///         This prevents attackers from submitting weak WHIR parameters
    ///         (e.g. low security_level, few queries) to forge proofs.
    bytes32 public whirConfigHash;

    /// @notice Keccak256 hash of the expected Plonky2 circuit-constant parameters:
    ///         (CircuitParams, PermutationData, GateInfo[]).
    ///         Prevents circuit parameter substitution attacks.
    bytes32 public plonky2CircuitHash;

    /// @notice External Plonky2 constraint verifier contract.
    Plonky2Verifier public immutable plonky2Verifier;

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
    mapping(uint64 => bytes32) public blockForcedTxHash;

    /// @notice Snapshot of blockHashChain at posting-round boundaries.
    ///         Only the last block number of each batch is recorded.
    ///         finalize() references these snapshots for verification.
    mapping(uint64 => bytes32) public blockHashChainAt;

    /// @notice Current block number (incremented for every sub-block).
    uint64 public blockNumber;

    /// @notice Posting round counter (incremented once per postBlock call).
    ///         Used for forced tx slot maturation (2-round delay).
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
    // Forced Transaction State
    // -----------------------------------------------------------------------

    /// @notice Mapping from userId to their forced tx logic contract.
    ///         Set during user registration via registerForcedTxLogic().
    mapping(uint64 => address) public forcedTxLogicContracts;

    /// @notice Running keccak hash chain of ALL queued forced txs.
    ///         Updated by queueForcedTx().
    bytes32 public forcedTxAccumulator;

    /// @notice Snapshot of forcedTxAccumulator at each posting round.
    ///         Used for slot maturation: forced txs queued before round R
    ///         become eligible for inclusion at round R+2.
    mapping(uint64 => bytes32) public forcedTxAccumulatorAtRound;

    /// @notice Total number of forced txs queued.
    uint64 public forcedTxCount;

    /// @notice Gas limit for external insertIntmaxTx() calls.
    uint256 internal constant FORCED_TX_GAS_LIMIT = 100_000;

    // -----------------------------------------------------------------------
    // Fraud/Stake configuration
    // -----------------------------------------------------------------------
    uint256 private constant POST_BLOCK_STAKE = 1 ether;
    uint256 private constant FRAUD_REWARD_PERCENT = 90;
    uint256 private constant FRAUD_TREASURY_PERCENT = 10;

    /// @notice Submissions not finalized within this many Eth blocks after posting
    ///         can be removed unconditionally via fraudProof (no proof needed).
    uint256 private constant FINALIZE_DEADLINE_BLOCKS = 12 * 12;
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
        bytes32 _whirConfigHash,
        bytes32 _plonky2CircuitHash,
        Plonky2Verifier _plonky2Verifier,
        IGnarkVerifier _gnarkVerifier,
        bytes32 _genesisStateRoot
    ) {
        fraudTreasury = _fraudTreasury;
        _setGroth16VerifyingKey(verifyingKey);
        whirConfigHash = _whirConfigHash;
        plonky2CircuitHash = _plonky2CircuitHash;
        plonky2Verifier = _plonky2Verifier;
        gnarkVerifier = _gnarkVerifier;
        latestFinalizedStateRoot = _genesisStateRoot;
        // Genesis: block 0 has default (zero) hash chains
        blockHashChainAt[0] = bytes32(0);
    }

    // -----------------------------------------------------------------------
    // registerForcedTxLogic()  —  register a forced tx logic contract for a userId
    // -----------------------------------------------------------------------

    /// @notice Register the forced tx logic contract for a userId.
    ///         Can only be set once per userId (immutable after registration).
    ///         The logic contract must accept the registration by returning the
    ///         userId when called with acceptRegistration(userId).
    /// @param userId         The Intmax user ID (aggregator_id << 32 | local_id).
    /// @param logicContract  Address of the contract implementing IForcedTxLogic.
    function registerForcedTxLogic(uint64 userId, address logicContract) external {
        if (forcedTxLogicContracts[userId] != address(0)) {
            revert ForcedTxLogicAlreadyRegistered();
        }
        // The logic contract must confirm it accepts this userId.
        // This prevents an attacker from registering a malicious contract
        // for someone else's userId — the logic contract itself must consent.
        (bool ok, bytes memory ret) = logicContract.call{gas: FORCED_TX_GAS_LIMIT}(
            abi.encodeWithSignature("acceptRegistration(uint64)", userId)
        );
        if (!ok || ret.length < 32 || abi.decode(ret, (uint64)) != userId) {
            revert ForcedTxLogicNotAccepted();
        }

        forcedTxLogicContracts[userId] = logicContract;
        emit ForcedTxLogicRegistered(userId, logicContract);
    }

    // -----------------------------------------------------------------------
    // queueForcedTx()  —  queue a forced tx (separate from postBlock)
    // -----------------------------------------------------------------------

    /// @notice Queue a forced transaction for a userId.
    ///         Calls the registered logic contract's insertIntmaxTx() with a gas
    ///         limit.  If a valid tx hash is returned, it is added to the
    ///         forced tx accumulator hash chain.
    ///         Callable by anyone — the logic contract controls whether a tx
    ///         should actually be inserted.
    /// @param userId  The Intmax user ID to insert a forced tx for.
    function queueForcedTx(uint64 userId) external {
        address logicContract = forcedTxLogicContracts[userId];
        if (logicContract == address(0)) revert NoForcedTxLogicRegistered();

        // Call with gas limit to prevent griefing
        (bool success, bytes memory returnData) = logicContract.call{gas: FORCED_TX_GAS_LIMIT}(
            abi.encodeCall(IForcedTxLogic.insertIntmaxTx, ())
        );

        if (!success || returnData.length < 32) revert ForcedTxInsertFailed();
        bytes32 txHash = abi.decode(returnData, (bytes32));

        // bytes32(0) signals "no tx to insert"
        if (txHash == bytes32(0)) revert ForcedTxInsertFailed();

        forcedTxCount++;
        forcedTxAccumulator = keccak256(
            abi.encodePacked(forcedTxAccumulator, userId, txHash)
        );

        emit ForcedTxQueued(userId, txHash, forcedTxAccumulator);
    }

    // -----------------------------------------------------------------------
    // postBlock()  —  post a batch of fast blocks (one posting round)
    // -----------------------------------------------------------------------

    /// @notice Post a batch of fast blocks (~5-second blocks) to L1 as one
    ///         posting round (~5 minutes).  All sub-blocks' data lives in
    ///         calldata for data availability.
    ///
    ///         Deposits and forced txs are applied to the LAST sub-block in
    ///         the batch only.  Intermediate sub-blocks have zero deposit and
    ///         forced tx hash chains.
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

        // --- Prepare deposits and forced txs for this posting round ---
        bytes32 pendingHashBefore = _pendingDepositHashChain;
        bytes32 batchDepositHashChain = pendingHashBefore;
        _pendingDepositHashChain = bytes32(0);

        uint64 previousPostingRound = postingRound;
        postingRound++;
        uint64 currentRound = postingRound;
        forcedTxAccumulatorAtRound[currentRound] = forcedTxAccumulator;

        bytes32 batchForcedTxHashChain = bytes32(0);
        if (currentRound >= 3) {
            batchForcedTxHashChain = forcedTxAccumulatorAtRound[currentRound - 2];
        }

        // --- Iterate over sub-blocks ---
        uint256 lastIdx = subBlocks.length - 1;
        for (uint256 i = 0; i < subBlocks.length; i++) {
            currentBlockNumber++;

            // Only the last sub-block carries deposits and forced txs
            bytes32 depositHash = bytes32(0);
            bytes32 forcedTxHash = bytes32(0);
            if (i == lastIdx) {
                depositHash = batchDepositHashChain;
                forcedTxHash = batchForcedTxHashChain;
            }

            currentHash = _computeBlockHash(
                currentHash,
                subBlocks[i].aggregatorId,
                subBlocks[i].timestamp,
                subBlocks[i].localIds,
                subBlocks[i].txTreeRoot,
                depositHash,
                forcedTxHash
            );
            blockDepositHash[currentBlockNumber] = depositHash;
            blockForcedTxHash[currentBlockNumber] = forcedTxHash;

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

    /// @notice WHIR + Plonky2 + Groth16 verification from calldata. No KZG, no blob binding.
    ///         All three verifiers must pass for the result to be true.
    function verify(
        WhirBatchProof[] memory whirBatches,
        Plonky2ConstraintData memory constraintData,
        Groth16Params memory groth16
    ) external view returns (bool) {
        // WhirConfig binding
        if (!_whirConfigMatches(whirBatches)) return false;

        // Verify all WHIR batches
        if (!_verifyAllWhirBatches(whirBatches)) return false;

        // Plonky2 constraint verification (when registered)
        if (plonky2CircuitHash != bytes32(0)) {
            if (!_plonky2CircuitMatches(constraintData)) return false;
            if (!_verifyPlonky2Constraints(constraintData)) return false;
        }

        // Verify Groth16
        if (!_verifyGroth16(groth16)) return false;

        return true;
    }

    // -----------------------------------------------------------------------
    // finalize()  —  full verification + state root acceptance
    // -----------------------------------------------------------------------

    /// @notice Verify and finalize a submission.
    ///         Checks: WHIR proof (Goldilocks Ext3), Plonky2 constraints,
    ///         Groth16 proof, public input binding to on-chain state.
    function finalize(
        uint256 submissionId,
        bytes32 stateRoot,
        ValidityPublicInputs calldata validityPIs,
        WhirBatchProof[] memory whirBatches,
        Plonky2ConstraintData memory constraintData,
        Groth16Params memory groth16
    ) external nonReentrant returns (bool) {
        Submission storage sub = _submissions[submissionId];
        if (sub.commitment == bytes32(0)) return false;
        if (sub.finalized) return false;

        bool valid;
        try this.fullVerify(stateRoot, validityPIs, whirBatches, constraintData, groth16) returns (bool v) {
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
    ///   3. Submissions not finalized within FINALIZE_DEADLINE_BLOCKS (144 Eth
    ///      blocks) after posting are removed unconditionally — no ZKP
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
        WhirBatchProof[] memory whirBatches,
        Plonky2ConstraintData memory constraintData,
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
            whirBatches, constraintData, kzg, groth16
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
        WhirBatchProof[] memory whirBatches,
        Plonky2ConstraintData memory constraintData,
        Groth16Params memory groth16
    ) external view returns (bool) {
        // 1. PI binding to on-chain state
        if (validityPIs.initialExtCommitment != latestFinalizedStateRoot) return false;
        if (validityPIs.initialBlockChain != blockHashChainAt[validityPIs.initialBlockNumber]) return false;
        if (validityPIs.finalBlockChain != blockHashChainAt[validityPIs.finalBlockNumber]) return false;
        if (validityPIs.finalExtCommitment != stateRoot) return false;

        // 2. WhirParams must match registered config
        if (!_whirConfigMatches(whirBatches)) return false;

        // 3. piHash binding: Groth16 pubInputs must encode keccak256(ValidityPublicInputs)
        //    as 8 big-endian u32 limbs.
        bytes32 piHash = _computeValidityPIHash(validityPIs);
        if (!_groth16PIHashMatches(groth16.pubInputs, piHash)) return false;

        // 4. Plonky2 constraint verification (when registered) — run before WHIR
        //    to avoid memory pressure from WHIR transcripts.
        if (plonky2CircuitHash != bytes32(0)) {
            if (!_plonky2CircuitMatches(constraintData)) return false;
            if (!_piHashMatchesU32Limbs(constraintData.publicInputs, piHash)) return false;
            if (!_verifyPlonky2Constraints(constraintData)) return false;
        }

        // 5. WHIR verification (all batches: constants_sigmas, wires, zs_partial_products, quotient_polys)
        if (!_verifyAllWhirBatches(whirBatches)) return false;

        // 6. Groth16 verification via gnark verifier (with commitment support)
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
        WhirBatchProof[] memory whirBatches,
        Plonky2ConstraintData memory constraintData,
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

        // 4. Proof params binding — ensures we verify exactly what was committed
        if (keccak256(abi.encode(groth16, whirBatches, constraintData)) != keccak256(proofBytes)) {
            return false;
        }

        // ── Fraud detection (any failure = fraud) ────────────────────────

        // (a) Wrong WhirParams
        if (!_whirConfigMatches(whirBatches)) return true;

        // (b) piHash mismatch: Groth16 pubInputs
        bytes32 piHash = _computeValidityPIHash(validityPIs);
        if (!_groth16PIHashMatches(groth16.pubInputs, piHash)) return true;

        // (c) Any WHIR batch verification fails
        if (!_verifyAllWhirBatches(whirBatches)) return true;

        // (d) Plonky2 constraint verification fails (when registered)
        if (plonky2CircuitHash != bytes32(0)) {
            if (!_plonky2CircuitMatches(constraintData)) return true;
            if (!_piHashMatchesU32Limbs(constraintData.publicInputs, piHash)) return true;
            if (!_verifyPlonky2Constraints(constraintData)) return true;
        }

        // (e) Groth16 verification fails
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
    // Internal — WHIR verification helpers
    // -----------------------------------------------------------------------

    /// @dev Check that all WhirParams in the batch match the registered config hash.
    function _whirConfigMatches(WhirBatchProof[] memory whirBatches) internal view returns (bool) {
        if (whirBatches.length == 0) return false;
        bytes memory packed;
        for (uint256 i = 0; i < whirBatches.length; i++) {
            packed = abi.encodePacked(packed, abi.encode(whirBatches[i].params));
        }
        return keccak256(packed) == whirConfigHash;
    }

    /// @dev Verify all WHIR batch proofs. Returns false if any batch fails.
    function _verifyAllWhirBatches(WhirBatchProof[] memory whirBatches) internal view returns (bool) {
        for (uint256 i = 0; i < whirBatches.length; i++) {
            bool batchValid;
            try this._verifyWhirBatch(whirBatches[i]) returns (bool v) {
                batchValid = v;
            } catch {
                batchValid = false;
            }
            if (!batchValid) return false;
        }
        return true;
    }

    /// @dev External helper so _fullVerify/_verifyFraud can try/catch on WHIR verification.
    ///      Similar pattern to _verifyKZG.
    function _verifyWhirBatch(WhirBatchProof memory batch) external pure returns (bool) {
        return SpongefishWhirVerify.verifyWhirProof(
            batch.protocolId,
            batch.sessionId,
            batch.instance,
            batch.transcript,
            batch.hints,
            batch.evaluations,
            batch.params
        );
    }

    // -----------------------------------------------------------------------
    // Internal — Plonky2 verification helpers
    // -----------------------------------------------------------------------

    /// @dev Check that circuit-constant Plonky2 parameters match the registered hash.
    function _plonky2CircuitMatches(Plonky2ConstraintData memory cd) internal view returns (bool) {
        return keccak256(abi.encode(cd.params, cd.permData, cd.gates)) == plonky2CircuitHash;
    }

    /// @dev Verify Plonky2 constraint satisfaction via external Plonky2Verifier contract.
    ///      Uses low-level staticcall + assembly decode to avoid a via_ir + optimizer
    ///      bug where abi.decode(retData, (bool)) reverts on valid return data.
    function _verifyPlonky2Constraints(Plonky2ConstraintData memory cd) internal view returns (bool) {
        bytes memory callData = abi.encodeCall(
            Plonky2Verifier.verifyConstraints,
            (cd.openings, cd.params, cd.challenges, cd.permData, cd.gates, cd.publicInputs)
        );
        (bool success, bytes memory retData) = address(plonky2Verifier).staticcall(callData);
        if (!success || retData.length < 32) return false;
        // Use assembly to decode bool — abi.decode reverts here under via_ir + optimizer
        bool result;
        assembly {
            result := mload(add(retData, 32))
        }
        return result;
    }

    /// @dev Check that publicInputs encode piHash as 8 big-endian u32 limbs.
    ///      Shared by both Groth16 and Plonky2 public input binding checks.
    function _piHashMatchesU32Limbs(
        uint256[] memory pubInputs,
        bytes32 piHash
    ) internal pure returns (bool) {
        if (pubInputs.length < 8) return false;
        uint256 h = uint256(piHash);
        for (uint256 i = 0; i < 8; i++) {
            uint256 limb = (h >> (224 - i * 32)) & 0xFFFFFFFF;
            if (pubInputs[i] != limb) return false;
        }
        return true;
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
        delete forcedTxAccumulatorAtRound[meta.postingRoundAfter];

        if (meta.endBlockNumber >= meta.startBlockNumber && meta.endBlockNumber != 0) {
            for (uint64 bn = meta.startBlockNumber; bn <= meta.endBlockNumber; bn++) {
                delete blockDepositHash[bn];
                delete blockForcedTxHash[bn];
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
    ///               || tx_tree_root || deposit_hash_chain || forced_tx_hash_chain)
    ///      All values packed as u32 words.
    function _computeBlockHash(
        bytes32 prevHash,
        uint32 aggregatorId,
        uint64 timestamp,
        uint32[] calldata localIds,
        bytes32 txTreeRoot,
        bytes32 blockDepositHashChain,
        bytes32 blockForcedTxHashChain
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
            blockDepositHashChain,
            blockForcedTxHashChain
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
