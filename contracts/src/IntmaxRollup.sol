// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Verifier} from "sol-whir/Whir.sol";
import {WhirProof, Statement, WhirConfig} from "sol-whir/WhirStructs.sol";
import {BN254} from "solidity-bn254/BN254.sol";
import {BlobKZGVerifier, KZGProof} from "./BlobKZGVerifier.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";
import {IForcedTxLogic} from "./IForcedTxLogic.sol";

/// @title WhirVerifierWrapper
/// @notice External wrapper so IntmaxRollup can try/catch on WHIR verification.
contract WhirVerifierWrapper {
    function verify(
        WhirConfig calldata config,
        Statement calldata statement,
        WhirProof calldata whirProof,
        bytes calldata transcript
    ) external pure returns (bool) {
        return Verifier.verify(config, statement, whirProof, transcript);
    }
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
///  Verification checks (finalize):
///    a) Blob commitment (KZG multi-point opening)
///    b) WHIR proof verification
///    c) WHIR statement.evaluations[0] == plonky2 public input hash
///    d) ValidityPublicInputs match on-chain state:
///       - initial_ext_commitment == latestFinalizedStateRoot
///       - initial/final block_chain match on-chain snapshots
///       - final_ext_commitment == stateRoot being accepted
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
    error RewardTransferFailed();
    error TreasuryTransferFailed();
    error StakeRefundFailed();

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

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    struct Submission {
        bytes32 commitment;   // keccak256(blobHash || proofHash || proofLength || stateRoot)
        address submitter;    // packed with `finalized` into one slot
        bool    finalized;
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
        uint64 postingRoundBefore;
        uint64 postingRoundAfter;
        uint64 processedDepositCountBefore;
    }

    /// @notice Bundles Groth16 verification parameters to avoid stack-too-deep.
    struct Groth16Params {
        Groth16Verifier.Proof proof;
        uint256[] pubInputs;
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
    WhirVerifierWrapper public immutable whirVerifier;
    Groth16Verifier.VerifyingKey internal groth16Vk;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status = _NOT_ENTERED;

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
    address public immutable fraudTreasury;

    mapping(uint256 => StakeInfo) public stakeInfo;
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
        WhirVerifierWrapper _whirVerifier,
        address _fraudTreasury,
        Groth16Verifier.VerifyingKey memory verifyingKey
    ) {
        whirVerifier = _whirVerifier;
        fraudTreasury = _fraudTreasury;
        _setGroth16VerifyingKey(verifyingKey);
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
    function postBlockAndSubmit(
        SubBlock[] calldata subBlocks,
        bytes32 proofHash,
        uint32 proofLength,
        bytes32 stateRoot
    ) external payable {
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
        bytes32 batchDepositHashChain = _pendingDepositHashChain;
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
        bytes32 commitment = keccak256(
            abi.encodePacked(blobHash, proofHash, proofLength, stateRoot)
        );

        _submissions[submissionId] = Submission({
            commitment: commitment,
            submitter: msg.sender,
            finalized: false
        });

        emit Submitted(submissionId, msg.sender, blobHash, proofHash, proofLength, stateRoot);
    }

    // -----------------------------------------------------------------------
    // verify()  —  pure WHIR verification (no binding)
    // -----------------------------------------------------------------------

    /// @notice WHIR + Groth16 verification from calldata. No KZG, no blob binding.
    ///         Both verifiers must pass for the result to be true.
    function verify(
        WhirConfig calldata config,
        Statement calldata statement,
        WhirProof calldata whirProof,
        bytes calldata transcript,
        Groth16Params memory groth16
    ) external view returns (bool) {
        bool whirValid;
        try whirVerifier.verify(config, statement, whirProof, transcript) returns (bool v) {
            whirValid = v;
        } catch {
            whirValid = false;
        }

        bool groth16Valid = Groth16Verifier.verify(groth16Vk, groth16.proof, groth16.pubInputs);

        return whirValid && groth16Valid;
    }

    // -----------------------------------------------------------------------
    // finalize()  —  full verification + state root acceptance
    // -----------------------------------------------------------------------

    /// @notice Verify and finalize a submission.
    ///         Checks: commitment, KZG blob binding, WHIR proof, public input
    ///         binding to on-chain state, WHIR↔plonky2 public input match.
    function finalize(
        uint256 submissionId,
        bytes32 blobVersionedHash,
        bytes32 stateRoot,
        bytes calldata plonky2ProofBytes,
        ValidityPublicInputs calldata validityPIs,
        WhirConfig calldata config,
        Statement calldata statement,
        WhirProof calldata whirProof,
        bytes calldata transcript,
        KZGProof calldata kzg,
        Groth16Params memory groth16
    ) external returns (bool) {
        Submission storage sub = _submissions[submissionId];
        if (sub.commitment == bytes32(0)) return false;
        if (sub.finalized) return false;

        bool valid = _fullVerify(
            submissionId, blobVersionedHash, stateRoot,
            plonky2ProofBytes, validityPIs,
            config, statement, whirProof, transcript, kzg, groth16,
            true  // expectedResult = true → finalize mode
        );
        if (!valid) return false;

        sub.finalized = true;
        latestFinalizedStateRoot = stateRoot;

        emit Finalized(submissionId, stateRoot);
        _refundStake(submissionId);
        return true;
    }

    // -----------------------------------------------------------------------
    // fraudProof()  —  prove a submission contains an invalid proof
    // -----------------------------------------------------------------------

    /// @notice Prove that a submission's proof is INVALID.
    ///
    ///   The fraud prover provides:
    ///     - The actual proof bytes from the blob (same as finalize)
    ///     - KZG proof binding the bytes to the blob commitment
    ///     - WHIR + Groth16 parameters (which will FAIL verification)
    ///
    ///   Returns true if fraud is confirmed:
    ///     1. Blob binding (KZG) PASSES — the bytes really are in the blob
    ///     2. Commitment check PASSES — the blob was submitted on-chain
    ///     3. Proof verification FAILS — WHIR or Groth16 rejects the proof
    ///
    ///   This means: "the data committed on-chain does NOT contain a valid proof."
    function fraudProof(
        uint256 submissionId,
        bytes32 blobVersionedHash,
        bytes32 stateRoot,
        bytes calldata plonky2ProofBytes,
        ValidityPublicInputs calldata validityPIs,
        WhirConfig calldata config,
        Statement calldata statement,
        WhirProof calldata whirProof,
        bytes calldata transcript,
        KZGProof calldata kzg,
        Groth16Params memory groth16
    ) external returns (bool fraudConfirmed) {
        Submission storage sub = _submissions[submissionId];
        if (sub.commitment == bytes32(0)) return false;
        if (sub.finalized) revert AlreadyFinalized();

        bool confirmed = _fullVerify(
            submissionId, blobVersionedHash, stateRoot,
            plonky2ProofBytes, validityPIs,
            config, statement, whirProof, transcript, kzg, groth16,
            false  // expectedResult = false → fraud proof mode
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

    // -----------------------------------------------------------------------
    // Internal — Full verification pipeline
    // -----------------------------------------------------------------------

    /// @dev Full verification pipeline with expected-result mode.
    ///
    ///   When `expectedResult = true` (finalize mode):
    ///     All 6 steps must pass → returns true.
    ///
    ///   When `expectedResult = false` (fraud proof mode):
    ///     Steps 1 + 2 + 4 (commitment + PI binding + KZG blob binding) MUST pass —
    ///     they prove the data really was submitted on-chain in the blob
    ///     and the supplied validityPIs match on-chain state (preventing
    ///     false fraud attacks via arbitrary validityPIs).
    ///     Steps 3/5/6 (PI hash + WHIR + Groth16) must FAIL at least once —
    ///     this proves the submitted proof is invalid.
    ///     Returns true if fraud is confirmed (binding OK but proof invalid).
    ///
    ///   Steps:
    ///     1. Commitment check (blobHash + proofHash + proofLength + stateRoot) [binding]
    ///     2. Public input binding to on-chain state [binding]
    ///     3. Plonky2 public input hash == WHIR statement.evaluations[0]
    ///     4. KZG blob binding [binding]
    ///     5. WHIR proof verification
    ///     6. Groth16 verification
    function _fullVerify(
        uint256 submissionId,
        bytes32 blobVersionedHash,
        bytes32 stateRoot,
        bytes calldata plonky2ProofBytes,
        ValidityPublicInputs calldata validityPIs,
        WhirConfig calldata config,
        Statement calldata statement,
        WhirProof calldata whirProof,
        bytes calldata transcript,
        KZGProof calldata kzg,
        Groth16Params memory groth16,
        bool expectedResult
    ) internal view returns (bool) {
        // ── Binding checks (must ALWAYS pass in both modes) ──────────────

        // 1. Commitment check — the calldata matches the on-chain submission
        {
            uint32 proofLength = uint32(plonky2ProofBytes.length);
            bytes32 proofHash = keccak256(plonky2ProofBytes);
            bytes32 commitment = keccak256(
                abi.encodePacked(blobVersionedHash, proofHash, proofLength, stateRoot)
            );
            if (commitment != _submissions[submissionId].commitment) {
                return false;  // binding failed → reject in both modes
            }
        }

        // 4. KZG blob binding — the calldata bytes match the blob content
        try this._verifyKZG(blobVersionedHash, kzg, plonky2ProofBytes) {
        } catch {
            return false;  // blob binding failed → reject in both modes
        }

        // ── Public input binding (must ALWAYS pass in both modes) ────────
        //
        // The validityPIs must match on-chain state. In fraud proof mode,
        // the fraud prover cannot supply arbitrary validityPIs to fake fraud.
        // This is a binding check, not a proof validity check.
        {
            bool pisBound = true;
            if (validityPIs.initialExtCommitment != latestFinalizedStateRoot) {
                pisBound = false;
            }
            if (pisBound && validityPIs.initialBlockChain != blockHashChainAt[validityPIs.initialBlockNumber]) {
                pisBound = false;
            }
            if (pisBound && validityPIs.finalBlockChain != blockHashChainAt[validityPIs.finalBlockNumber]) {
                pisBound = false;
            }
            if (pisBound && validityPIs.finalExtCommitment != stateRoot) {
                pisBound = false;
            }
            if (!pisBound) {
                return false;  // PI binding failed → reject in both modes
            }
        }

        // ── Proof validity checks (expected to pass for finalize, fail for fraud) ──

        bool proofValid = true;

        // 3. Plonky2 PI hash == WHIR statement.evaluations[0]
        if (proofValid) {
            bytes32 plonky2PublicInput = _computeValidityPIHash(validityPIs);
            if (statement.evaluations.length == 0 ||
                bytes32(BN254.ScalarField.unwrap(statement.evaluations[0])) != plonky2PublicInput) {
                proofValid = false;
            }
        }

        // 5. WHIR verification
        if (proofValid) {
            try whirVerifier.verify(config, statement, whirProof, transcript) returns (bool valid) {
                if (!valid) proofValid = false;
            } catch {
                proofValid = false;
            }
        }

        // 6. Groth16 verification
        //    The Groth16 circuit has ExpectedResult as a public input.
        //    Check that it matches the caller's expectedResult to prevent
        //    reusing a validity proof as a fraud proof or vice versa.
        if (proofValid) {
            // ExpectedResult is the first public input in FraudAwareVerifierCircuit
            if (groth16.pubInputs.length == 0) {
                proofValid = false;
            } else {
                uint256 groth16ExpectedResult = groth16.pubInputs[0];
                uint256 callerExpected = expectedResult ? uint256(1) : uint256(0);
                if (groth16ExpectedResult != callerExpected) {
                    proofValid = false;  // Groth16 proof was generated for different mode
                } else if (!Groth16Verifier.verify(groth16Vk, groth16.proof, groth16.pubInputs)) {
                    proofValid = false;
                }
            }
        }

        // ── Result interpretation ────────────────────────────────────────
        //
        //   expectedResult=true  (finalize): return proofValid
        //     → true  if proof is valid   (accept state transition)
        //     → false if proof is invalid (reject finalization)
        //
        //   expectedResult=false (fraud proof): return !proofValid
        //     → true  if proof is invalid (fraud confirmed!)
        //     → false if proof is valid   (no fraud — proof is actually fine)
        return proofValid == expectedResult;
    }

    /// @dev External helper so _fullVerify can try/catch on KZG verification.
    function _verifyKZG(
        bytes32 blobVersionedHash,
        KZGProof calldata kzg,
        bytes calldata plonky2ProofBytes
    ) external view {
        BlobKZGVerifier.verify(
            blobVersionedHash,
            kzg,
            _toFieldElements(plonky2ProofBytes)
        );
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
        _pendingDepositHashChain = _rebuildPendingDeposits(meta.processedDepositCountBefore);
    }

    function _rebuildPendingDeposits(uint64 startIndex) internal view returns (bytes32 hash) {
        if (startIndex >= depositCount) {
            return bytes32(0);
        }
        hash = bytes32(0);
        for (uint64 i = startIndex; i < depositCount; i++) {
            DepositRecord storage record = _depositRecords[i];
            hash = _computeDepositHash(
                hash,
                record.depositor,
                record.recipient,
                record.tokenIndex,
                record.amount,
                record.auxData
            );
        }
    }

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

        (bool rewardOk, ) = reporter.call{value: reward}("");
        require(rewardOk, "Reward transfer failed");

        (bool treasuryOk, ) = fraudTreasury.call{value: treasuryShare}("");
        require(treasuryOk, "Treasury transfer failed");
    }

    function _refundStake(uint256 submissionId) internal {
        StakeInfo storage info = stakeInfo[submissionId];
        if (info.submitter == address(0) || info.spent) {
            delete stakeInfo[submissionId];
            return;
        }

        info.spent = true;
        address recipient = info.submitter;
        delete stakeInfo[submissionId];

        (bool ok, ) = recipient.call{value: POST_BLOCK_STAKE}("");
        require(ok, "Stake refund failed");
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
        // Build the u32 array matching Rust's layout
        bytes memory packed = abi.encodePacked(
            prevHash,
            aggregatorId,
            timestamp,
            localIds,
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
