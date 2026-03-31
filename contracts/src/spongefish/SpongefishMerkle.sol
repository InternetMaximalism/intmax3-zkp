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
    /// @param hintOffset   Starting offset in hints
    /// @return newHintOffset  Number of hint bytes consumed
    function verify(
        bytes32 root,
        uint256 numLayers,
        uint256[] memory indices,
        bytes32[] memory leafHashes,
        bytes memory hints,
        uint256 hintOffset
    ) internal pure returns (uint256 newHintOffset) {
        require(indices.length == leafHashes.length, "length mismatch");
        if (indices.length == 0) return hintOffset;

        uint256[] memory curIndices = indices;
        bytes32[] memory curHashes = leafHashes;
        uint256[] memory nextIndices = new uint256[](indices.length);
        bytes32[] memory nextHashes = new bytes32[](leafHashes.length);
        newHintOffset = hintOffset;

        for (uint256 layer = 0; layer < numLayers; layer++) {
            uint256 nextLen = _processLayerInto(
                curIndices, curHashes, nextIndices, nextHashes, hints, newHintOffset
            );
            unchecked {
                uint256 curLen = curIndices.length;
                uint256 loneCount = nextLen * 2 > curLen ? (nextLen * 2) - curLen : 0;
                newHintOffset += loneCount * 32;
            }

            assembly {
                mstore(nextIndices, nextLen)
                mstore(nextHashes, nextLen)
            }

            (curIndices, nextIndices) = (nextIndices, curIndices);
            (curHashes, nextHashes) = (nextHashes, curHashes);
        }

        // Should be left with a single root
        if (curIndices.length != 1 || curIndices[0] != 0 || curHashes[0] != root) {
            revert MerkleVerificationFailed();
        }
    }

    /// @dev Process one Merkle tree layer: merge siblings, read hints for lone nodes.
    function _processLayerInto(
        uint256[] memory curIndices,
        bytes32[] memory curHashes,
        uint256[] memory nextIndices,
        bytes32[] memory nextHashes,
        bytes memory hints,
        uint256 hintOff
    ) private pure returns (uint256 nextLen) {
        uint256 n = curIndices.length;
        uint256 newHintOff = hintOff;

        uint256 i = 0;
        while (i < n) {
            uint256 a = curIndices[i];
            if (i + 1 < n && curIndices[i + 1] == (a ^ 1)) {
                // Neighboring siblings — merge
                (bytes32 left, bytes32 right) = (a & 1 == 1)
                    ? (curHashes[i + 1], curHashes[i])
                    : (curHashes[i], curHashes[i + 1]);
                nextIndices[nextLen] = a >> 1;
                bytes32 parentHash;
                assembly {
                    let scratch := mload(0x40)
                    mstore(scratch, left)
                    mstore(add(scratch, 32), right)
                    parentHash := keccak256(scratch, 64)
                }
                nextHashes[nextLen] = parentHash;
                nextLen++;
                i += 2;
            } else {
                // Single index — read sibling from hints
                require(newHintOff + 32 <= hints.length, "insufficient hints");
                bytes32 sibling;
                assembly {
                    sibling := mload(add(add(hints, 0x20), newHintOff))
                }
                newHintOff += 32;

                (bytes32 left, bytes32 right) = (a & 1 == 0)
                    ? (curHashes[i], sibling)
                    : (sibling, curHashes[i]);
                nextIndices[nextLen] = a >> 1;
                bytes32 parentHash2;
                assembly {
                    let scratch := mload(0x40)
                    mstore(scratch, left)
                    mstore(add(scratch, 32), right)
                    parentHash2 := keccak256(scratch, 64)
                }
                nextHashes[nextLen] = parentHash2;
                nextLen++;
                i++;
            }
        }

    }
}
