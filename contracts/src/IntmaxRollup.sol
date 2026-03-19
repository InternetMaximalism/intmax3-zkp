// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Verifier} from "sol-whir/Whir.sol";
import {WhirProof, Statement, WhirConfig} from "sol-whir/WhirStructs.sol";
import {BN254} from "solidity-bn254/BN254.sol";
import {BlobKZGVerifier, KZGProof} from "./BlobKZGVerifier.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";

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
///  Architecture:
///    1. Aggregators call `postBlock()` to post blocks (local_ids in calldata).
///       The contract computes block_hash_chain on-chain.
///    2. Anyone calls `deposit()` to queue deposits.
///       The contract computes deposit_hash_chain on-chain.
///    3. The sequencer posts a validity proof in an EIP-4844 blob via `submit()`.
///    4. Anyone can call `finalize()` to verify and accept the proof.
///       Verification checks:
///         a) Blob commitment (KZG multi-point opening)
///         b) WHIR proof verification
///         c) WHIR statement.evaluations[0] == plonky2 public input hash
///         d) ValidityPublicInputs match on-chain state:
///            - initial_ext_commitment == latestFinalizedStateRoot
///            - initial_block_chain, final_block_chain match on-chain values
///            - final_ext_commitment == stateRoot being accepted
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

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    struct Submission {
        bytes32 commitment;   // keccak256(blobHash || proofHash || proofLength || stateRoot)
        address submitter;    // packed with `finalized` into one slot
        bool    finalized;
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
    ///         Updated by `postBlock()`.
    ///         block_hash_chain = keccak256(prev || aggregator_id || timestamp || local_ids || tx_tree_root || deposit_hash_chain)
    bytes32 public blockHashChain;

    /// @notice Snapshot of blockHashChain at each block number.
    mapping(uint64 => bytes32) public blockHashChainAt;

    /// @notice Current block number (incremented by postBlock).
    uint64 public blockNumber;

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
    // postBlock()  —  aggregator posts a block with local_ids in calldata
    // -----------------------------------------------------------------------

    /// @notice Post a new block.  The local_ids array lives in calldata,
    ///         binding the ID list to the on-chain block hash chain.
    /// @param aggregatorId  Aggregator identifier.
    /// @param localIds      Array of local user IDs (the "ID list").
    /// @param timestamp     Block timestamp.
    /// @param txTreeRoot    Root of the transaction Merkle tree.
    function postBlock(
        uint32 aggregatorId,
        uint32[] calldata localIds,
        uint64 timestamp,
        bytes32 txTreeRoot
    ) external {
        // Fold pending deposits into the deposit hash chain for this block
        bytes32 blockDepositHashChain = _pendingDepositHashChain;
        _pendingDepositHashChain = bytes32(0);

        blockNumber++;
        uint64 newBlockNumber = blockNumber;

        // Compute block hash matching Rust's Block::hash_with_prev_hash:
        //   keccak256(prev_hash || aggregator_id || timestamp(u64→2×u32) || local_ids || tx_tree_root || deposit_hash_chain)
        //   All values packed as u32 (little-endian within each u32 word).
        bytes32 newBlockHash = _computeBlockHash(
            blockHashChain,
            aggregatorId,
            timestamp,
            localIds,
            txTreeRoot,
            blockDepositHashChain
        );

        blockHashChain = newBlockHash;
        blockHashChainAt[newBlockNumber] = newBlockHash;
        depositHashChain = blockDepositHashChain;

        emit BlockPosted(newBlockNumber, aggregatorId, localIds, txTreeRoot, newBlockHash);
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
    ) external {
        Submission storage sub = _submissions[submissionId];
        if (sub.commitment == bytes32(0)) revert SubmissionNotFound();
        if (sub.finalized) revert AlreadyFinalized();

        _fullVerify(
            submissionId, blobVersionedHash, stateRoot,
            plonky2ProofBytes, validityPIs,
            config, statement, whirProof, transcript, kzg, groth16
        );

        sub.finalized = true;
        latestFinalizedStateRoot = stateRoot;

        emit Finalized(submissionId, stateRoot);
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
    ) external view returns (bool valid) {
        _fullVerify(
            submissionId, blobVersionedHash, stateRoot,
            plonky2ProofBytes, validityPIs,
            config, statement, whirProof, transcript, kzg, groth16
        );
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
    ) internal view {
        // 1. Commitment check
        {
            uint32 proofLength = uint32(plonky2ProofBytes.length);
            bytes32 proofHash = keccak256(plonky2ProofBytes);
            bytes32 commitment = keccak256(
                abi.encodePacked(blobVersionedHash, proofHash, proofLength, stateRoot)
            );
            if (commitment != _submissions[submissionId].commitment) {
                revert CommitmentMismatch();
            }
        }

        // 2. Public input binding: ValidityPublicInputs ↔ on-chain state
        //    - initial_ext_commitment must chain from the last finalized state
        //    - block hash chains must match on-chain snapshots
        //    - final_ext_commitment must equal the claimed stateRoot
        if (validityPIs.initialExtCommitment != latestFinalizedStateRoot) {
            revert InitialStateMismatch();
        }
        if (validityPIs.initialBlockChain != blockHashChainAt[validityPIs.initialBlockNumber]) {
            revert BlockChainMismatch();
        }
        if (validityPIs.finalBlockChain != blockHashChainAt[validityPIs.finalBlockNumber]) {
            revert BlockChainMismatch();
        }
        if (validityPIs.finalExtCommitment != stateRoot) {
            revert CommitmentMismatch();
        }

        // 3. Plonky2 public input hash must appear in WHIR statement.evaluations[0]
        //    The plonky2 circuit outputs keccak256(ValidityPublicInputs) as its
        //    public input.  The WHIR/Groth16 wrapper circuit takes this as its
        //    public input, which appears in statement.evaluations[0].
        bytes32 plonky2PublicInput = _computeValidityPIHash(validityPIs);
        if (statement.evaluations.length == 0 ||
            bytes32(BN254.ScalarField.unwrap(statement.evaluations[0])) != plonky2PublicInput) {
            revert WhirPublicInputMismatch();
        }

        // 4. KZG blob binding
        BlobKZGVerifier.verify(
            blobVersionedHash,
            kzg,
            _toFieldElements(plonky2ProofBytes)
        );

        // 5. WHIR verification
        try whirVerifier.verify(config, statement, whirProof, transcript) returns (bool valid) {
            if (!valid) revert ProofVerificationFailed();
        } catch {
            revert ProofVerificationFailed();
        }

        // 6. Groth16 verification (in parallel with WHIR — both must pass)
        if (!Groth16Verifier.verify(groth16.vk, groth16.proof, groth16.pubInputs)) {
            revert ProofVerificationFailed();
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
    ///      keccak256(prev_hash || aggregator_id || timestamp || local_ids || tx_tree_root || deposit_hash_chain)
    ///      All values packed as u32 words.
    function _computeBlockHash(
        bytes32 prevHash,
        uint32 aggregatorId,
        uint64 timestamp,
        uint32[] calldata localIds,
        bytes32 txTreeRoot,
        bytes32 blockDepositHashChain
    ) internal pure returns (bytes32) {
        // Build the u32 array matching Rust's layout
        bytes memory packed = abi.encodePacked(
            prevHash,
            aggregatorId,
            timestamp,
            localIds,
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
