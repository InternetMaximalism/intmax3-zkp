// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Verifier} from "sol-whir/Whir.sol";
import {WhirProof, Statement, WhirConfig} from "sol-whir/WhirStructs.sol";
import {BlobKZGVerifier, KZGProof} from "./BlobKZGVerifier.sol";

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
///  Validity proofs (Plonky2) are posted in EIP-4844 blobs. On-chain, only a
///  compact commitment is stored.  The commitment binds:
///    - the blob versioned hash (references the blob),
///    - keccak256 of the raw proof bytes,
///    - the byte-length of the proof (for deterministic KZG extraction), and
///    - the state root (final_ext_commitment from the validity circuit).
///
///  Anyone can later call `verify()` (pure WHIR check) or `fraudProof()`
///  (commitment + KZG blob binding + WHIR) to determine proof validity.
///  `finalize()` marks a submission as finalized if its proof is valid,
///  updating the on-chain state root.
///
///  State root = Poseidon(ExtendedPublicState) where ExtendedPublicState
///  contains: block_number, timestamp, account_tree_root, deposit_tree_root,
///  prev_public_state_root, block_hash_chain, deposit_hash_chain, deposit_count.
contract IntmaxRollup {
    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------
    error NoBlobAttached();
    error CommitmentMismatch();
    error SubmissionNotFound();
    error AlreadyFinalized();
    error ProofVerificationFailed();

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------
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

    /// @dev Packed into a single 256-bit storage slot:
    ///      commitment (bytes32) occupies slot N,
    ///      submitter+finalized are packed into slot N+1 (20+1 bytes).
    ///      stateRoot is NOT stored — it lives inside the commitment and is
    ///      passed as calldata when needed (finalize / fraudProof).
    struct Submission {
        bytes32 commitment;   // keccak256(blobHash || proofHash || proofLength || stateRoot)
        address submitter;    // packed with `finalized` into one slot
        bool    finalized;
    }

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------
    WhirVerifierWrapper public immutable whirVerifier;

    mapping(uint256 => Submission) internal _submissions;
    uint256 public nextId;

    /// @notice The latest finalized state root.
    bytes32 public latestFinalizedStateRoot;

    /// @notice Mask to clear top 3 bits so a 256-bit value fits in the
    ///         BLS12-381 scalar field (used for KZG blob field elements).
    uint256 internal constant FIELD_MASK = type(uint256).max >> 3;

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------
    constructor(WhirVerifierWrapper _whirVerifier) {
        whirVerifier = _whirVerifier;
    }

    // -----------------------------------------------------------------------
    // submit()
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

        uint256 id = nextId++;
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
    // verify()  —  pure WHIR verification (no blob binding)
    // -----------------------------------------------------------------------

    /// @notice Pure WHIR verification from calldata.
    ///         No KZG blob binding, no commitment check.
    ///         Useful for off-chain or quick on-chain checks.
    function verify(
        WhirConfig calldata config,
        Statement calldata statement,
        WhirProof calldata whirProof,
        bytes calldata transcript
    ) external view returns (bool) {
        try whirVerifier.verify(config, statement, whirProof, transcript) returns (bool valid) {
            return valid;
        } catch {
            return false;
        }
    }

    // -----------------------------------------------------------------------
    // fraudProof()  —  full verification (commitment + KZG + WHIR)
    // -----------------------------------------------------------------------

    /// @notice Full fraud-proof verification.
    ///         1. Checks commitment matches the stored one.
    ///         2. Verifies KZG blob binding (the blob contains the proof bytes).
    ///         3. Runs WHIR verification on the proof.
    /// @return valid True when the proof passes all checks.
    function fraudProof(
        uint256 submissionId,
        bytes32 blobVersionedHash,
        bytes32 stateRoot,
        bytes calldata plonky2ProofBytes,
        WhirConfig calldata config,
        Statement calldata statement,
        WhirProof calldata whirProof,
        bytes calldata transcript,
        KZGProof calldata kzg
    ) external view returns (bool valid) {
        return _fullVerify(
            submissionId, blobVersionedHash, stateRoot,
            plonky2ProofBytes, config, statement, whirProof, transcript, kzg
        );
    }

    // -----------------------------------------------------------------------
    // finalize()  —  mark a submission as finalized after proof verification
    // -----------------------------------------------------------------------

    /// @notice Verify and finalize a submission.
    ///         If the proof is valid, mark the submission as finalized and
    ///         update the on-chain state root.
    /// @param stateRoot Must match the stateRoot committed at submit time.
    function finalize(
        uint256 submissionId,
        bytes32 blobVersionedHash,
        bytes32 stateRoot,
        bytes calldata plonky2ProofBytes,
        WhirConfig calldata config,
        Statement calldata statement,
        WhirProof calldata whirProof,
        bytes calldata transcript,
        KZGProof calldata kzg
    ) external {
        Submission storage sub = _submissions[submissionId];
        if (sub.commitment == bytes32(0)) revert SubmissionNotFound();
        if (sub.finalized) revert AlreadyFinalized();

        bool valid = _fullVerify(
            submissionId, blobVersionedHash, stateRoot,
            plonky2ProofBytes, config, statement, whirProof, transcript, kzg
        );
        if (!valid) revert ProofVerificationFailed();

        sub.finalized = true;
        latestFinalizedStateRoot = stateRoot;

        emit Finalized(submissionId, stateRoot);
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
    // Internal
    // -----------------------------------------------------------------------

    /// @dev Shared verification: commitment → KZG → WHIR.
    function _fullVerify(
        uint256 submissionId,
        bytes32 blobVersionedHash,
        bytes32 stateRoot,
        bytes calldata plonky2ProofBytes,
        WhirConfig calldata config,
        Statement calldata statement,
        WhirProof calldata whirProof,
        bytes calldata transcript,
        KZGProof calldata kzg
    ) internal view returns (bool) {
        // 1. Commitment check
        uint32 proofLength = uint32(plonky2ProofBytes.length);
        bytes32 proofHash = keccak256(plonky2ProofBytes);
        bytes32 commitment = keccak256(
            abi.encodePacked(blobVersionedHash, proofHash, proofLength, stateRoot)
        );
        if (commitment != _submissions[submissionId].commitment) {
            revert CommitmentMismatch();
        }

        // 2. KZG blob binding: prove the blob contains these proof bytes
        BlobKZGVerifier.verify(
            blobVersionedHash,
            kzg,
            _toFieldElements(plonky2ProofBytes)
        );

        // 3. WHIR verification
        try whirVerifier.verify(config, statement, whirProof, transcript) returns (bool valid) {
            return valid;
        } catch {
            return false;
        }
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
