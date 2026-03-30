// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SpongefishMerkle
/// @notice Merkle tree verification matching WizardOfMenlo/whir's layered decommitment format.
///
///   Unlike OpenZeppelin multi-proof, this uses a simpler per-layer scheme:
///   - Indices are sorted and deduplicated
///   - For each layer, sibling hashes come from the "hints" buffer
///   - Neighbors (a, a^1) that are both present merge without needing a hint
///   - Hash function is Keccak256 (matching intmax3's hash_id: KECCAK)
library SpongefishMerkle {
    error MerkleVerificationFailed();

    /// @notice Verify a Merkle opening proof.
    /// @param root         Expected root hash
    /// @param numLayers    Number of tree layers (= log2(num_leaves))
    /// @param indices      Sorted, deduplicated leaf indices
    /// @param leafHashes   Leaf hashes corresponding to indices
    /// @param hints        Sibling hashes (decommitments), consumed sequentially
    /// @return hintOffset  Number of hint bytes consumed
    function verify(
        bytes32 root,
        uint256 numLayers,
        uint256[] memory indices,
        bytes32[] memory leafHashes,
        bytes calldata hints,
        uint256 hintOffset
    ) internal pure returns (uint256) {
        require(indices.length == leafHashes.length, "length mismatch");
        if (indices.length == 0) return hintOffset;

        // Working arrays — current layer
        uint256[] memory curIndices = indices;
        bytes32[] memory curHashes = leafHashes;

        for (uint256 layer = 0; layer < numLayers; layer++) {
            uint256 n = curIndices.length;
            // Allocate next layer (at most n elements)
            uint256[] memory nextIndices = new uint256[](n);
            bytes32[] memory nextHashes = new bytes32[](n);
            uint256 nextLen = 0;

            uint256 i = 0;
            while (i < n) {
                uint256 a = curIndices[i];
                // Check if next index is the sibling (a ^ 1)
                if (i + 1 < n && curIndices[i + 1] == (a ^ 1)) {
                    // Neighboring siblings — merge
                    bytes32 left = curHashes[i];
                    bytes32 right = curHashes[i + 1];
                    // Ensure left < right ordering (even index first)
                    if (a & 1 == 1) {
                        (left, right) = (right, left);
                    }
                    nextIndices[nextLen] = a >> 1;
                    nextHashes[nextLen] = keccak256(abi.encodePacked(left, right));
                    nextLen++;
                    i += 2; // Skip both
                } else {
                    // Single index — read sibling from hints
                    require(hintOffset + 32 <= hints.length, "insufficient hints");
                    bytes32 sibling = bytes32(hints[hintOffset:hintOffset + 32]);
                    hintOffset += 32;

                    bytes32 left;
                    bytes32 right;
                    if (a & 1 == 0) {
                        // a is left child
                        left = curHashes[i];
                        right = sibling;
                    } else {
                        // a is right child
                        left = sibling;
                        right = curHashes[i];
                    }
                    nextIndices[nextLen] = a >> 1;
                    nextHashes[nextLen] = keccak256(abi.encodePacked(left, right));
                    nextLen++;
                    i++;
                }
            }

            // Shrink arrays to actual size
            assembly {
                mstore(nextIndices, nextLen)
                mstore(nextHashes, nextLen)
            }
            curIndices = nextIndices;
            curHashes = nextHashes;
        }

        // Should be left with a single root
        if (curIndices.length != 1 || curIndices[0] != 0 || curHashes[0] != root) {
            revert MerkleVerificationFailed();
        }

        return hintOffset;
    }
}
