// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {DuplexSponge} from "./DuplexSponge.sol";
import {SpongefishMerkle} from "./SpongefishMerkle.sol";

/// @title SpongefishWhir
/// @notice WHIR polynomial commitment verifier for WizardOfMenlo/whir (spongefish transcript).
///
///   Verifies a WHIR proof by replaying the spongefish Fiat-Shamir transcript:
///   - prover_message: read N bytes from transcript, absorb into sponge
///   - verifier_message: squeeze N bytes from sponge
///   - prover_hint: read N bytes from hints (NOT absorbed into sponge)
///
///   Field: Goldilocks 64-bit (p = 2^64 - 2^32 + 1) with cubic extension
///   Hash:  Keccak-f[1600] duplex sponge
///
///   This is a work-in-progress implementation. The full WHIR verification
///   algorithm involves sumcheck, Merkle openings, and constraint evaluation
///   in the Goldilocks cubic extension field.
library SpongefishWhir {
    using DuplexSponge for DuplexSponge.Sponge;

    uint64 constant GL_P = 0xFFFFFFFF00000001; // Goldilocks prime

    struct TranscriptState {
        DuplexSponge.Sponge sponge;
        uint256 transcriptPos;
        uint256 hintPos;
    }

    // -----------------------------------------------------------------------
    // Transcript operations (matching spongefish exactly)
    // -----------------------------------------------------------------------

    /// @dev Initialize transcript with domain separator.
    ///      Matches: spongefish::DomainSeparator::new(protocol_id).session(session_id).instance(&Empty)
    function initTranscript(
        bytes memory protocolId,
        bytes memory sessionId
    ) internal pure returns (TranscriptState memory ts) {
        ts.sponge = DuplexSponge.init();
        // public_message(&protocol_id) → absorb 64 bytes
        ts.sponge.absorb(protocolId);
        // public_message(&session_id) → absorb 32 bytes
        if (sessionId.length > 0) {
            ts.sponge.absorb(sessionId);
        }
        // public_message(&Empty) → absorb 0 bytes (no-op)
    }

    /// @dev Read N bytes from transcript and absorb into sponge.
    ///      Matches: verifier_state.prover_message::<T>()
    function proverMessage(
        TranscriptState memory ts,
        bytes calldata transcript,
        uint256 numBytes
    ) internal pure returns (bytes memory data) {
        require(ts.transcriptPos + numBytes <= transcript.length, "transcript underflow");
        data = transcript[ts.transcriptPos:ts.transcriptPos + numBytes];
        ts.transcriptPos += numBytes;
        ts.sponge.absorb(data);
    }

    /// @dev Read a 32-byte hash from transcript and absorb.
    function proverMessageHash(
        TranscriptState memory ts,
        bytes calldata transcript
    ) internal pure returns (bytes32 h) {
        bytes memory data = proverMessage(ts, transcript, 32);
        assembly { h := mload(add(data, 32)) }
    }

    /// @dev Read a Goldilocks field element (8 bytes LE) from transcript and absorb.
    function proverMessageField64(
        TranscriptState memory ts,
        bytes calldata transcript
    ) internal pure returns (uint64 val) {
        bytes memory data = proverMessage(ts, transcript, 8);
        // Little-endian decode
        for (uint256 i = 0; i < 8; i++) {
            val |= uint64(uint8(data[i])) << (i * 8);
        }
        val = val % GL_P;
    }

    /// @dev Squeeze N bytes from sponge (verifier challenge).
    ///      Matches: verifier_state.verifier_message::<T>()
    function verifierMessage(
        TranscriptState memory ts,
        uint256 numBytes
    ) internal pure returns (bytes memory) {
        return ts.sponge.squeeze(numBytes);
    }

    /// @dev Squeeze a Goldilocks field element (40 bytes → reduce mod p).
    ///      Matches Field64's Decoding impl which reads 40 bytes.
    function verifierMessageField64(
        TranscriptState memory ts
    ) internal pure returns (uint64 val) {
        bytes memory data = ts.sponge.squeeze(40);
        // Reduce 40 bytes to Field64: interpret as LE integer, mod p
        uint256 acc = 0;
        for (uint256 i = 0; i < 40; i++) {
            acc |= uint256(uint8(data[i])) << (i * 8);
        }
        // Note: 40 bytes = 320 bits. We need to reduce mod GL_P (64 bits).
        // Simple approach: take lower 128 bits and reduce
        val = uint64(acc % uint256(GL_P));
    }

    /// @dev Read N bytes from hints (NOT absorbed into sponge).
    ///      Matches: verifier_state.prover_hint::<T>()
    function proverHint(
        TranscriptState memory ts,
        bytes calldata hints,
        uint256 numBytes
    ) internal pure returns (bytes memory data) {
        require(ts.hintPos + numBytes <= hints.length, "hints underflow");
        data = hints[ts.hintPos:ts.hintPos + numBytes];
        ts.hintPos += numBytes;
    }

    /// @dev Read a 32-byte hash from hints.
    function proverHintHash(
        TranscriptState memory ts,
        bytes calldata hints
    ) internal pure returns (bytes32 h) {
        bytes memory data = proverHint(ts, hints, 32);
        assembly { h := mload(add(data, 32)) }
    }

    // -----------------------------------------------------------------------
    // Challenge generation
    // -----------------------------------------------------------------------

    /// @dev Generate challenge indices by squeezing bytes and reducing mod numLeaves.
    ///      Matches: challenge_indices(transcript, num_leaves, count, deduplicate=true)
    function challengeIndices(
        TranscriptState memory ts,
        uint256 numLeaves,
        uint256 count
    ) internal pure returns (uint256[] memory indices) {
        if (count == 0) return new uint256[](0);
        if (numLeaves == 1) {
            indices = new uint256[](1);
            indices[0] = 0;
            return indices;
        }

        // Calculate bytes needed per index
        uint256 sizeBytes = _ceilDiv(_log2(numLeaves), 8);

        // Squeeze all needed bytes
        bytes memory entropy = ts.sponge.squeeze(count * sizeBytes);

        // Convert to indices
        indices = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 val = 0;
            for (uint256 j = 0; j < sizeBytes; j++) {
                val = (val << 8) | uint256(uint8(entropy[i * sizeBytes + j]));
            }
            indices[i] = val % numLeaves;
        }

        // Sort and dedup
        _sortAndDedup(indices);
    }

    /// @dev Geometric challenge: squeeze one Field64 value, return [1, x, x^2, ..., x^(count-1)]
    ///      Matches: geometric_challenge(transcript, count)
    function geometricChallenge(
        TranscriptState memory ts,
        uint256 count
    ) internal pure returns (uint64[] memory coeffs) {
        if (count == 0) return new uint64[](0);
        if (count == 1) {
            coeffs = new uint64[](1);
            coeffs[0] = 1;
            return coeffs;
        }

        uint64 x = verifierMessageField64(ts);
        coeffs = new uint64[](count);
        coeffs[0] = 1;
        for (uint256 i = 1; i < count; i++) {
            coeffs[i] = _mulmod64(coeffs[i - 1], x);
        }
    }

    // -----------------------------------------------------------------------
    // Sumcheck verification
    // -----------------------------------------------------------------------

    /// @dev Verify a sumcheck proof.
    ///      Matches: sumcheck::Config::verify()
    ///
    ///      For each round:
    ///      1. Read c0, c2 from transcript (prover_message)
    ///      2. Compute c1 = sum - 2*c0 - c2
    ///      3. Verify PoW (if configured)
    ///      4. Squeeze folding randomness r (verifier_message)
    ///      5. Update sum = c0 + r*c1 + r^2*c2
    ///
    /// @return foldingRandomness The folding randomness values from each round
    /// @return newSum The updated sum after all rounds
    function verifySumcheck(
        TranscriptState memory ts,
        bytes calldata transcript,
        uint256 numRounds,
        uint64 sum
    ) internal pure returns (uint64[] memory foldingRandomness, uint64 newSum) {
        foldingRandomness = new uint64[](numRounds);
        newSum = sum;

        for (uint256 i = 0; i < numRounds; i++) {
            // Read c0 and c2
            uint64 c0 = proverMessageField64(ts, transcript);
            uint64 c2 = proverMessageField64(ts, transcript);

            // c1 = sum - 2*c0 - c2 (mod GL_P)
            uint64 c1 = _submod64(_submod64(newSum, _addmod64(c0, c0)), c2);

            // PoW check omitted for now (requires additional transcript operations)
            // TODO: Implement PoW verification

            // Squeeze folding randomness
            uint64 r = verifierMessageField64(ts);
            foldingRandomness[i] = r;

            // Update sum: sum = c0 + r*c1 + r^2*c2
            //            = c0 + r*(c1 + r*c2)
            newSum = _addmod64(c0, _mulmod64(r, _addmod64(c1, _mulmod64(r, c2))));
        }
    }

    // -----------------------------------------------------------------------
    // Goldilocks field arithmetic helpers
    // -----------------------------------------------------------------------

    function _addmod64(uint64 a, uint64 b) private pure returns (uint64) {
        return uint64(addmod(uint256(a), uint256(b), uint256(GL_P)));
    }

    function _submod64(uint64 a, uint64 b) private pure returns (uint64) {
        return uint64(addmod(uint256(a), uint256(GL_P) - uint256(b), uint256(GL_P)));
    }

    function _mulmod64(uint64 a, uint64 b) private pure returns (uint64) {
        return uint64(mulmod(uint256(a), uint256(b), uint256(GL_P)));
    }

    // -----------------------------------------------------------------------
    // Utility functions
    // -----------------------------------------------------------------------

    function _log2(uint256 x) private pure returns (uint256 n) {
        while (x > 1) { x >>= 1; n++; }
    }

    function _ceilDiv(uint256 a, uint256 b) private pure returns (uint256) {
        return (a + b - 1) / b;
    }

    function _sortAndDedup(uint256[] memory arr) private pure {
        uint256 n = arr.length;
        // Insertion sort
        for (uint256 i = 1; i < n; i++) {
            uint256 key = arr[i];
            uint256 j = i;
            while (j > 0 && arr[j - 1] > key) {
                arr[j] = arr[j - 1];
                j--;
            }
            arr[j] = key;
        }
        // Dedup
        if (n <= 1) return;
        uint256 write = 1;
        for (uint256 i = 1; i < n; i++) {
            if (arr[i] != arr[i - 1]) {
                arr[write++] = arr[i];
            }
        }
        assembly { mstore(arr, write) }
    }
}
