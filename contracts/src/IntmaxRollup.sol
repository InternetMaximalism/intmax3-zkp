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
///       The sequencer posts a validity proof blob via `submit()`.
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

    /// @notice A single fast block (~5 seconds) within a posting-round batch.
    struct SubBlock {
        uint32   aggregatorId;
        uint64   timestamp;
        bytes32  txTreeRoot;
        uint32[] localIds;
    }

    /// @notice Bundles Groth16 verification parameters to avoid stack-too-deep.
    struct Groth16Params {
        Groth16Verifier.VerifyingKey vk;
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

    /// @notice On-chain block hash chain state.
    ///         Updated by `postBlock()` — iterates over a batch of sub-blocks.
    bytes32 public blockHashChain;

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

    /// @notice Mask to clear top 3 bits so a 256-bit value fits in the
    ///         BLS12-381 scalar field (used for KZG blob field elements).
    uint256 internal constant FIELD_MASK = type(uint256).max >> 3;

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------
    constructor(WhirVerifierWrapper _whirVerifier) {
        whirVerifier = _whirVerifier;
        // Genesis: block 0 has default (zero) hash chains
        blockHashChainAt[0] = bytes32(0);
    }

    // -----------------------------------------------------------------------
    // registerForcedTxLogic()  —  register a forced tx logic contract for a userId
    // -----------------------------------------------------------------------

    /// @notice Register (or update) the forced tx logic contract for a userId.
    ///         Intended to be called during user ID registration.
    /// @param userId         The Intmax user ID (aggregator_id << 32 | local_id).
    /// @param logicContract  Address of the contract implementing IForcedTxLogic.
    ///                       Use address(0) to unregister.
    function registerForcedTxLogic(uint64 userId, address logicContract) external {
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
    /// @param subBlocks  Array of fast blocks to commit.
    function postBlock(SubBlock[] calldata subBlocks) external {
        if (subBlocks.length == 0) revert EmptyBatch();

        bytes32 currentHash = blockHashChain;
        uint64 currentBlockNumber = blockNumber;

        // --- Prepare deposits and forced txs for this posting round ---
        bytes32 batchDepositHashChain = _pendingDepositHashChain;
        _pendingDepositHashChain = bytes32(0);

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

        emit Deposited(idx, msg.sender, recipient, tokenIndex, amount, auxData, newHash);
    }

    // -----------------------------------------------------------------------
    // submit()  —  post validity proof blob
    // -----------------------------------------------------------------------

    /// @notice Post a validity proof in an EIP-4844 blob TX.
    ///         Stores only the commitment on-chain.
    /// @param proofHash   keccak256 of the raw Plonky2 proof bytes.
    /// @param proofLength Byte length of the Plonky2 proof in the blob.
    /// @param stateRoot   final_ext_commitment proven by the validity circuit.
    function submit(
        bytes32 proofHash,
        uint32 proofLength,
        bytes32 stateRoot
    ) external {
        bytes32 blobHash;
        assembly {
            blobHash := blobhash(0)
        }
        if (blobHash == bytes32(0)) revert NoBlobAttached();

        uint256 id = nextSubmissionId++;
        bytes32 commitment = keccak256(
            abi.encodePacked(blobHash, proofHash, proofLength, stateRoot)
        );

        _submissions[id] = Submission({
            commitment: commitment,
            submitter: msg.sender,
            finalized: false
        });

        emit Submitted(id, msg.sender, blobHash, proofHash, proofLength, stateRoot);
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

        bool groth16Valid = Groth16Verifier.verify(groth16.vk, groth16.proof, groth16.pubInputs);

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
            config, statement, whirProof, transcript, kzg, groth16
        );
        if (!valid) return false;

        sub.finalized = true;
        latestFinalizedStateRoot = stateRoot;

        emit Finalized(submissionId, stateRoot);
        return true;
    }

    // -----------------------------------------------------------------------
    // fraudProof()  —  full verification (returns bool)
    // -----------------------------------------------------------------------

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
    ) external view returns (bool) {
        return _fullVerify(
            submissionId, blobVersionedHash, stateRoot,
            plonky2ProofBytes, validityPIs,
            config, statement, whirProof, transcript, kzg, groth16
        );
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

    /// @dev Full verification:
    ///   1. Commitment check (blobHash + proofHash + proofLength + stateRoot)
    ///   2. Public input binding to on-chain state
    ///   3. Plonky2 public input hash == WHIR statement.evaluations[0]
    ///   4. KZG blob binding
    ///   5. WHIR proof verification
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
        Groth16Params memory groth16
    ) internal view returns (bool) {
        // 1. Commitment check
        {
            uint32 proofLength = uint32(plonky2ProofBytes.length);
            bytes32 proofHash = keccak256(plonky2ProofBytes);
            bytes32 commitment = keccak256(
                abi.encodePacked(blobVersionedHash, proofHash, proofLength, stateRoot)
            );
            if (commitment != _submissions[submissionId].commitment) {
                return false;
            }
        }

        // 2. Public input binding: ValidityPublicInputs ↔ on-chain state
        if (validityPIs.initialExtCommitment != latestFinalizedStateRoot) {
            return false;
        }
        if (validityPIs.initialBlockChain != blockHashChainAt[validityPIs.initialBlockNumber]) {
            return false;
        }
        if (validityPIs.finalBlockChain != blockHashChainAt[validityPIs.finalBlockNumber]) {
            return false;
        }
        if (validityPIs.finalExtCommitment != stateRoot) {
            return false;
        }

        // 3. Plonky2 public input hash must appear in WHIR statement.evaluations[0]
        bytes32 plonky2PublicInput = _computeValidityPIHash(validityPIs);
        if (statement.evaluations.length == 0 ||
            bytes32(BN254.ScalarField.unwrap(statement.evaluations[0])) != plonky2PublicInput) {
            return false;
        }

        // 4. KZG blob binding
        try this._verifyKZG(blobVersionedHash, kzg, plonky2ProofBytes) {
        } catch {
            return false;
        }

        // 5. WHIR verification
        try whirVerifier.verify(config, statement, whirProof, transcript) returns (bool valid) {
            if (!valid) return false;
        } catch {
            return false;
        }

        // 6. Groth16 verification (in parallel with WHIR — both must pass)
        if (!Groth16Verifier.verify(groth16.vk, groth16.proof, groth16.pubInputs)) {
            return false;
        }

        return true;
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
