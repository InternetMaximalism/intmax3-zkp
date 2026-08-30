// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BlobKZGVerifierExt
/// @notice Reconstructs Alloy `SimpleCoder` blobs from the canonical proof byte stream and verifies
///         standard blob KZG proofs through EIP-4844's point-evaluation precompile (0x0a).
/// @dev No trusted-setup material is accepted from calldata. The precompile is pinned to the
///      Ethereum KZG ceremony, while this contract independently derives the Fiat-Shamir point and
///      the blob polynomial's value at that point.
contract BlobKZGVerifierExt {
    uint256 internal constant FIELD_ELEMENTS_PER_BLOB = 4096;
    uint256 internal constant BYTES_PER_FIELD_ELEMENT = 32;
    uint256 internal constant BYTES_PER_BLOB = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;
    uint256 internal constant PAYLOAD_BYTES_PER_FIELD_ELEMENT = 31;
    uint256 internal constant ONE_BLOB_CAPACITY = (FIELD_ELEMENTS_PER_BLOB - 1) * 31;
    uint256 internal constant TWO_BLOB_CAPACITY = (2 * FIELD_ELEMENTS_PER_BLOB - 1) * 31;

    uint256 internal constant BLS_MODULUS =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    uint256 internal constant BLS_MODULUS_MINUS_TWO =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfefffffffeffffffff;

    // 7^((r-1)/4096), its inverse, and 4096^-1 in Fr.
    uint256 internal constant ROOT_OF_UNITY =
        0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306;
    uint256 internal constant ROOT_OF_UNITY_INV =
        0x0391b2856c609b4784ae25ffab9dc59865046d17864183203961a252dd8543362;
    uint256 internal constant INV_FIELD_ELEMENTS_PER_BLOB =
        0x73e66878b46ae3705eb6a46a89213de7d3686828bfce5c19400fffff00100001;

    // `FSBLOBVERIFY_V1_ || uint128_be(4096)`.
    bytes32 internal constant CHALLENGE_PREFIX =
        0x4653424c4f425645524946595f56315f00000000000000000000000000001000;
    uint256 internal constant CHALLENGE_INPUT_LENGTH = 16 + 16 + BYTES_PER_BLOB + 48;
    uint256 internal constant REVERSE_NIBBLES = 0xf7b3d591e6a2c480;
    uint256 internal constant POINT_EVALUATION_GAS = 50_000;
    bytes32 internal constant PROOF_DA_DOMAIN = keccak256("INTMAX3_PROOF_DA_V3");
    bytes32 internal constant PROOF_ATTESTATION_DOMAIN = keccak256("INTMAX3_PROOF_ATTESTATION_V1");

    mapping(bytes32 => bytes32) private _attestedProofData;

    event ProofDataAttested(
        address indexed rollup,
        uint256 indexed submissionId,
        bytes32 indexed submissionCommitment,
        bytes32 proofDigest,
        bytes32 proofHash,
        uint32 proofLength
    );

    error EmptyProofPayload();
    error ProofPayloadTooLarge(uint256 proofLength);
    error BlobCountMismatch(uint256 expected, uint256 supplied);
    error MissingBlob(uint256 index);
    error ExtraBlob(uint256 index);
    error SidecarLengthMismatch(uint256 expected, uint256 supplied);
    error Sha256Failed();
    error ModexpFailed();
    error PointEvaluationFailed(uint256 index);
    error InvalidPointEvaluationResult(uint256 index);
    error InvalidRollupContext();
    error SubmissionUnavailable();
    error SubmissionCommitmentMismatch();
    error ConflictingAttestation();

    /// @notice Validate the exact number of transaction blobs required by a proof length and return
    ///         their EIP-4844 versioned hashes. `BLOBHASH(i)` is zero exactly when index i is absent.
    function blobMetadata(uint32 proofLength)
        external
        view
        returns (bytes32 blobHash0, bytes32 blobHash1, uint8 blobCount)
    {
        return _blobMetadata(proofLength);
    }

    /// @notice Build the submission commitment from the transaction's exact blob list.
    function postCommitment(
        bytes32 stateRoot,
        uint64 submittedAtBlock,
        uint256 submissionId
    ) external view returns (bytes32 commitment) {
        (bytes32 blobHash0, bytes32 blobHash1, uint8 blobCount) = _postedBlobMetadata();
        commitment = _commitment(
            blobHash0,
            blobHash1,
            blobCount,
            stateRoot,
            submittedAtBlock,
            submissionId
        );
    }

    /// @dev Posting authority comes from the transaction's blob list itself. Caller-declared proof
    ///      hashes/lengths are only telemetry: making either authoritative lets a malicious producer
    ///      commit a lie that no later exact KZG opening can match, delaying removal until timeout.
    function _postedBlobMetadata()
        internal
        view
        returns (bytes32 blobHash0, bytes32 blobHash1, uint8 blobCount)
    {
        bytes32 blobHash2;
        assembly {
            blobHash0 := blobhash(0)
            blobHash1 := blobhash(1)
            blobHash2 := blobhash(2)
        }
        if (blobHash0 == bytes32(0)) revert MissingBlob(0);
        if (blobHash1 == bytes32(0)) return (blobHash0, bytes32(0), 1);
        if (blobHash2 != bytes32(0)) revert ExtraBlob(2);
        return (blobHash0, blobHash1, 2);
    }

    function _blobMetadata(uint32 proofLength)
        internal
        view
        returns (bytes32 blobHash0, bytes32 blobHash1, uint8 blobCount)
    {
        blobCount = _blobCount(proofLength);
        bytes32 blobHash2;
        assembly {
            blobHash0 := blobhash(0)
            blobHash1 := blobhash(1)
            blobHash2 := blobhash(2)
        }
        if (blobHash0 == bytes32(0)) revert MissingBlob(0);
        if (blobCount == 1) {
            if (blobHash1 != bytes32(0)) revert ExtraBlob(1);
        } else {
            if (blobHash1 == bytes32(0)) revert MissingBlob(1);
            if (blobHash2 != bytes32(0)) revert ExtraBlob(2);
        }
    }

    /// @notice Verify that `proofBytes` is exactly the lossless stream committed by the supplied
    ///         one or two standard blob sidecars. Returns the hashes used by the rollup commitment.
    /// @param sidecars Compact concatenation in blob order:
    ///        `commitment[0](48) || proof[0](48) [|| commitment[1](48) || proof[1](48)]`.
    function verify(bytes calldata proofBytes, bytes calldata sidecars)
        external
        view
        returns (bytes32 blobHash0, bytes32 blobHash1, uint8 blobCount)
    {
        blobCount = _blobCount(proofBytes.length);
        uint256 expected = uint256(blobCount) * 96;
        if (sidecars.length != expected) revert SidecarLengthMismatch(expected, sidecars.length);

        blobHash0 = _verifyBlob(proofBytes, 0, sidecars);
        if (blobCount == 2) blobHash1 = _verifyBlob(proofBytes, 1, sidecars);
    }

    /// @notice Verify standard sidecar evidence and open the exact domain-separated commitment.
    function verifyAndCommit(
        bytes calldata proofBytes,
        bytes calldata sidecars,
        bytes32 stateRoot,
        uint64 submittedAtBlock,
        uint256 submissionId
    ) external view returns (bytes32 commitment) {
        return _verifyAndCommit(
            proofBytes,
            sidecars,
            stateRoot,
            submittedAtBlock,
            submissionId
        );
    }

    /// @notice Permissionless KZG attestation journal, namespaced by the calling rollup and exact
    /// submission commitment. Keeping the journal beside the expensive blob logic preserves the
    /// rollup's EIP-170 budget and prevents recycled submission ids from reusing old attestations.
    function attestProofData(
        address rollup,
        uint256 submissionId,
        bytes calldata proofBytes,
        bytes calldata sidecars
    ) external returns (bytes32 digest) {
        (bool ok, bytes memory context) = rollup.staticcall(
            abi.encodeWithSelector(bytes4(keccak256("getSubmission(uint256)")), submissionId)
        );
        if (!ok || context.length != 160) revert InvalidRollupContext();
        (bytes32 submissionCommitment,, bool finalized, uint64 submittedAtBlock, bytes32 stateRoot) =
            abi.decode(context, (bytes32, address, bool, uint64, bytes32));
        if (submissionCommitment == bytes32(0) || finalized) revert SubmissionUnavailable();

        bytes32 opened = _verifyAndCommit(
            proofBytes,
            sidecars,
            stateRoot,
            submittedAtBlock,
            submissionId
        );
        if (opened != submissionCommitment) revert SubmissionCommitmentMismatch();

        digest = _proofDigest(keccak256(proofBytes), proofBytes.length);
        bytes32 key = keccak256(abi.encode(rollup, submissionId, submissionCommitment));
        bytes32 prior = _attestedProofData[key];
        if (prior != bytes32(0) && prior != digest) revert ConflictingAttestation();
        _attestedProofData[key] = digest;
        emit ProofDataAttested(
            rollup,
            submissionId,
            submissionCommitment,
            digest,
            keccak256(proofBytes),
            uint32(proofBytes.length)
        );
    }

    function isProofDataAttested(
        uint256 submissionId,
        bytes32 submissionCommitment,
        bytes32 proofHash,
        uint256 proofLength
    ) external view returns (bool) {
        bytes32 key = keccak256(abi.encode(msg.sender, submissionId, submissionCommitment));
        return _attestedProofData[key] == _proofDigest(proofHash, proofLength);
    }

    function _verifyAndCommit(
        bytes calldata proofBytes,
        bytes calldata sidecars,
        bytes32 stateRoot,
        uint64 submittedAtBlock,
        uint256 submissionId
    ) private view returns (bytes32 commitment) {
        uint8 blobCount = _blobCount(proofBytes.length);
        uint256 expected = uint256(blobCount) * 96;
        if (sidecars.length != expected) revert SidecarLengthMismatch(expected, sidecars.length);
        bytes32 blobHash0 = _verifyBlob(proofBytes, 0, sidecars);
        bytes32 blobHash1;
        if (blobCount == 2) blobHash1 = _verifyBlob(proofBytes, 1, sidecars);
        commitment = _commitment(
            blobHash0,
            blobHash1,
            blobCount,
            stateRoot,
            submittedAtBlock,
            submissionId
        );
    }

    function _proofDigest(bytes32 proofHash, uint256 proofLength) private pure returns (bytes32) {
        return keccak256(abi.encode(PROOF_ATTESTATION_DOMAIN, proofHash, proofLength));
    }

    function _verifyBlob(bytes calldata proofBytes, uint256 blobIndex, bytes calldata sidecars)
        internal
        view
        returns (bytes32 versionedHash)
    {
        uint256 offset = blobIndex * 96;
        bytes calldata commitment = sidecars[offset:offset + 48];
        bytes calldata proof = sidecars[offset + 48:offset + 96];

        uint256 z;
        uint256 y;
        (versionedHash, z, y) = _blobEvaluation(proofBytes, blobIndex, commitment);
        _pointEvaluation(blobIndex, versionedHash, z, y, commitment, proof);
    }

    /// @dev Build Alloy's `SimpleCoder` stream: FE zero is a u64 big-endian total-length header;
    ///      every later FE is `0x00 || 31 bytes`, continuing across the one/two blob boundary.
    function _blobEvaluation(bytes calldata proofBytes, uint256 blobIndex, bytes calldata commitment)
        internal
        view
        returns (bytes32 versionedHash, uint256 z, uint256 y)
    {
        // Reuse this buffer as prefix || blob || commitment for the Fiat-Shamir SHA-256.
        bytes memory challengeInput = new bytes(CHALLENGE_INPUT_LENGTH);
        uint256 inputPtr;
        uint256 blobPtr;
        assembly ("memory-safe") {
            inputPtr := add(challengeInput, 0x20)
            mstore(inputPtr, CHALLENGE_PREFIX)
            blobPtr := add(inputPtr, 0x20)
        }

        _fillSimpleCoderBlob(proofBytes, blobIndex, blobPtr);
        assembly ("memory-safe") {
            calldatacopy(add(blobPtr, 0x20000), commitment.offset, 48)
        }

        bytes32 digest;
        bool shaOk;
        assembly ("memory-safe") {
            mstore(0, 0)
            shaOk := staticcall(gas(), 2, inputPtr, 0x20050, 0, 32)
            if iszero(eq(returndatasize(), 32)) { shaOk := 0 }
            digest := mload(0)
        }
        if (!shaOk) revert Sha256Failed();
        z = uint256(digest) % BLS_MODULUS;
        y = _evaluateBlob(blobPtr, z);
        versionedHash = _versionedHash(commitment);
    }

    function _fillSimpleCoderBlob(bytes calldata proofBytes, uint256 blobIndex, uint256 blobPtr)
        internal
        pure
    {
        if (blobIndex == 0) {
            // Alloy SimpleCoder's header FE is `0x00 || uint64_be(total_length) || 23 zero bytes`.
            // Shift the u64 past that 23-byte suffix; storing the unshifted integer would put it at
            // bytes 24..31 and silently disagree with `cast --blob --path`.
            assembly ("memory-safe") { mstore(blobPtr, shl(184, proofBytes.length)) }
        }

        uint256 localStart = blobIndex == 0 ? 1 : 0;
        uint256 globalBase = blobIndex * FIELD_ELEMENTS_PER_BLOB;
        for (uint256 local = localStart; local < FIELD_ELEMENTS_PER_BLOB; local++) {
            uint256 source = (globalBase + local - 1) * PAYLOAD_BYTES_PER_FIELD_ELEMENT;
            if (source >= proofBytes.length) break;
            uint256 remaining = proofBytes.length - source;
            uint256 packed;
            assembly ("memory-safe") {
                let word := calldataload(add(proofBytes.offset, source))
                switch lt(remaining, 31)
                case 0 { packed := shr(8, word) }
                default {
                    // Bytes after the declared calldata slice are not padding; retain only its tail.
                    let right := mul(sub(32, remaining), 8)
                    let left := mul(sub(31, remaining), 8)
                    packed := shl(left, shr(right, word))
                }
                mstore(add(blobPtr, mul(local, 32)), packed)
            }
        }
    }

    /// @dev Consensus-spec barycentric evaluation over 4096 bit-reversal-ordered roots. All
    ///      denominators are batch-inverted, requiring only one modexp.
    function _evaluateBlob(uint256 blobPtr, uint256 z) internal view returns (uint256 y) {
        uint256[] memory prefixes = new uint256[](FIELD_ELEMENTS_PER_BLOB);
        uint256 product = 1;
        uint256 omega = 1;

        for (uint256 i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
            if (z == omega) {
                uint256 atRoot;
                uint256 index = _bitReverse12(i);
                assembly ("memory-safe") { atRoot := mload(add(blobPtr, mul(index, 32))) }
                return atRoot;
            }
            prefixes[i] = product;
            product = mulmod(product, addmod(z, BLS_MODULUS - omega, BLS_MODULUS), BLS_MODULUS);
            omega = mulmod(omega, ROOT_OF_UNITY, BLS_MODULUS);
        }

        uint256 inverseProduct = _modexp(product, BLS_MODULUS_MINUS_TWO);
        omega = ROOT_OF_UNITY_INV; // root^4095, matching the first backwards iteration
        uint256 sum;
        for (uint256 cursor = FIELD_ELEMENTS_PER_BLOB; cursor != 0;) {
            unchecked { cursor--; }
            uint256 denominator = addmod(z, BLS_MODULUS - omega, BLS_MODULUS);
            uint256 inverseDenominator = mulmod(inverseProduct, prefixes[cursor], BLS_MODULUS);
            uint256 value;
            uint256 index = _bitReverse12(cursor);
            assembly ("memory-safe") { value := mload(add(blobPtr, mul(index, 32))) }
            sum = addmod(
                sum,
                mulmod(mulmod(value, omega, BLS_MODULUS), inverseDenominator, BLS_MODULUS),
                BLS_MODULUS
            );
            inverseProduct = mulmod(inverseProduct, denominator, BLS_MODULUS);
            omega = mulmod(omega, ROOT_OF_UNITY_INV, BLS_MODULUS);
        }

        uint256 zToWidth = z;
        for (uint256 i = 0; i < 12; i++) zToWidth = mulmod(zToWidth, zToWidth, BLS_MODULUS);
        uint256 scale = mulmod(
            addmod(zToWidth, BLS_MODULUS - 1, BLS_MODULUS),
            INV_FIELD_ELEMENTS_PER_BLOB,
            BLS_MODULUS
        );
        y = mulmod(sum, scale, BLS_MODULUS);
    }

    function _pointEvaluation(
        uint256 blobIndex,
        bytes32 versionedHash,
        uint256 z,
        uint256 y,
        bytes calldata commitment,
        bytes calldata proof
    ) private view {
        bytes memory input = new bytes(192);
        bool ok;
        uint256 outElements;
        uint256 outModulus;
        assembly ("memory-safe") {
            let ptr := add(input, 0x20)
            mstore(ptr, versionedHash)
            mstore(add(ptr, 0x20), z)
            mstore(add(ptr, 0x40), y)
            calldatacopy(add(ptr, 0x60), commitment.offset, 48)
            calldatacopy(add(ptr, 0x90), proof.offset, 48)
            // EIP-4844 prices this precompile at exactly 50,000 gas. Do not forward `gas()`:
            // invalid proof inputs consume all gas supplied to a precompile, which would prevent
            // the caller from observing a clean failed verification and enforcing atomicity.
            ok := staticcall(POINT_EVALUATION_GAS, 0x0a, ptr, 192, ptr, 64)
            if iszero(eq(returndatasize(), 64)) { ok := 0 }
            outElements := mload(ptr)
            outModulus := mload(add(ptr, 32))
        }
        if (!ok) revert PointEvaluationFailed(blobIndex);
        if (outElements != FIELD_ELEMENTS_PER_BLOB || outModulus != BLS_MODULUS) {
            revert InvalidPointEvaluationResult(blobIndex);
        }
    }

    function _versionedHash(bytes calldata commitment) private view returns (bytes32 versionedHash) {
        bytes32 digest;
        bool ok;
        assembly ("memory-safe") {
            // STATICCALL reads memory, not calldata. Copy the exact compressed commitment first.
            calldatacopy(0, commitment.offset, 48)
            ok := staticcall(gas(), 2, 0, 48, 0, 32)
            if iszero(eq(returndatasize(), 32)) { ok := 0 }
            digest := mload(0)
        }
        if (!ok) revert Sha256Failed();
        versionedHash = bytes32((uint256(digest) & (type(uint256).max >> 8)) | (uint256(1) << 248));
    }

    function _modexp(uint256 base, uint256 exponent) private view returns (uint256 result) {
        bytes memory input = new bytes(192);
        bool ok;
        assembly ("memory-safe") {
            let ptr := add(input, 32)
            mstore(ptr, 32)
            mstore(add(ptr, 32), 32)
            mstore(add(ptr, 64), 32)
            mstore(add(ptr, 96), base)
            mstore(add(ptr, 128), exponent)
            mstore(add(ptr, 160), BLS_MODULUS)
            ok := staticcall(gas(), 5, ptr, 192, ptr, 32)
            if iszero(eq(returndatasize(), 32)) { ok := 0 }
            result := mload(ptr)
        }
        if (!ok) revert ModexpFailed();
    }

    function _blobCount(uint256 proofLength) internal pure returns (uint8) {
        if (proofLength == 0) revert EmptyProofPayload();
        if (proofLength <= ONE_BLOB_CAPACITY) return 1;
        if (proofLength <= TWO_BLOB_CAPACITY) return 2;
        revert ProofPayloadTooLarge(proofLength);
    }

    function _commitment(
        bytes32 blobHash0,
        bytes32 blobHash1,
        uint8 blobCount,
        bytes32 stateRoot,
        uint64 submittedAtBlock,
        uint256 submissionId
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                PROOF_DA_DOMAIN,
                blobHash0,
                blobHash1,
                blobCount,
                stateRoot,
                submittedAtBlock,
                submissionId
            )
        );
    }

    function _bitReverse12(uint256 x) private pure returns (uint256) {
        uint256 table = REVERSE_NIBBLES;
        return (((table >> ((x & 0x0f) * 4)) & 0x0f) << 8)
            | (((table >> (((x >> 4) & 0x0f) * 4)) & 0x0f) << 4)
            | ((table >> (((x >> 8) & 0x0f) * 4)) & 0x0f);
    }
}
