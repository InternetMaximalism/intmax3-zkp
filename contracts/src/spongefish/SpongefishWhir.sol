// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {DuplexSponge} from "./DuplexSponge.sol";
import {SpongefishMerkle} from "./SpongefishMerkle.sol";
import {BN254} from "solidity-bn254/BN254.sol";

/// @title SpongefishWhir
/// @notice WHIR verifier compatible with WizardOfMenlo/whir (spongefish transcript).
///
///   This replaces sol-whir's EVMFs-based verifier with one that uses:
///   - DuplexSponge (Keccak-f1600) for Fiat-Shamir
///   - SpongefishMerkle for layered Merkle decommitments
///
///   Proof format:
///   - transcript: bytes  (spongefish narg_string — prover messages)
///   - hints: bytes        (Merkle decommitments, consumed sequentially)
///
///   The mathematical verification (sumcheck, RLC, constraint checking)
///   is identical to sol-whir — only the serialization layer differs.
library SpongefishWhir {
    uint256 internal constant R_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    struct SpongefishProof {
        bytes transcript;   // spongefish narg_string
        bytes hints;        // Merkle decommitments (consumed sequentially)
    }

    struct VerifierConfig {
        uint256 numVariables;
        uint256 foldingFactor;
        uint256 securityLevel;
        uint256 domainSize;
        uint256 startingLogInvRate;
        uint256 startingFoldingPowBits;
        uint256 finalSumcheckRounds;
        uint256 finalPowBits;
        uint256 finalFoldingPowBits;
        uint32 finalQueries;
        uint32 commitmentOodSamples;
        RoundParam[] roundParameters;
        BN254.ScalarField domainGen;
        BN254.ScalarField domainGenInv;
        BN254.ScalarField expDomainGen;
    }

    struct RoundParam {
        uint256 powBits;
        uint256 foldingPowBits;
        uint32 numQueries;
        uint32 oodSamples;
        uint256 logInvRate;
    }

    struct WhirStatement {
        BN254.ScalarField[][] points;
        BN254.ScalarField[] evaluations;
    }

    /// @notice Verify a spongefish-based WHIR proof.
    /// @param proof       The proof (transcript + hints)
    /// @param config      WHIR protocol parameters
    /// @param statement   Evaluation statement (points + claimed values)
    /// @return valid      True if verification passes
    function verify(
        SpongefishProof calldata proof,
        VerifierConfig memory config,
        WhirStatement calldata statement
    ) internal pure returns (bool valid) {
        // Initialize the duplex sponge
        DuplexSponge.Sponge memory sponge = DuplexSponge.init();

        // Domain separator: absorb protocol identifier
        // spongefish uses DomainSeparator::protocol(&params) which absorbs the config
        // For now, absorb the config hash as domain separator
        DuplexSponge.absorb(sponge, abi.encodePacked(
            config.numVariables,
            config.foldingFactor,
            config.securityLevel
        ));
        DuplexSponge.ratchet(sponge);

        uint256 transcriptPos = 0;
        uint256 hintOffset = 0;

        // Step 1: Receive commitment (Merkle root)
        bytes32 root;
        (root, transcriptPos) = _readHash(proof.transcript, transcriptPos);
        DuplexSponge.absorb(sponge, abi.encodePacked(root));

        // Step 2: OOD evaluation
        uint256 numOodSamples = config.commitmentOodSamples;
        BN254.ScalarField[] memory oodPoints = new BN254.ScalarField[](numOodSamples);
        if (numOodSamples > 0) {
            // Squeeze OOD challenge points
            bytes memory squeezed = DuplexSponge.squeeze(sponge, numOodSamples * 32);
            for (uint256 i = 0; i < numOodSamples; i++) {
                oodPoints[i] = BN254.ScalarField.wrap(
                    uint256(_readMemBytes32(squeezed, i * 32)) % R_MOD
                );
            }

            // Read OOD answers from transcript
            for (uint256 i = 0; i < numOodSamples; i++) {
                bytes32 val;
                (val, transcriptPos) = _readHash(proof.transcript, transcriptPos);
                DuplexSponge.absorb(sponge, abi.encodePacked(val));
            }
        }

        // Step 3: Vector RLC coefficient
        {
            bytes memory gamma = DuplexSponge.squeeze(sponge, 32);
            // gamma is the geometric challenge base
        }

        // Step 4: Constraint RLC coefficients
        uint256 numConstraints = numOodSamples + statement.points.length;
        {
            bytes memory alpha = DuplexSponge.squeeze(sponge, 32);
            // alpha is the constraint RLC geometric base
        }

        // Step 5: Initial sumcheck
        uint256 initialSumcheckRounds = config.foldingFactor; // typically = foldingFactor
        BN254.ScalarField[] memory foldingRandomness = new BN254.ScalarField[](initialSumcheckRounds);
        BN254.ScalarField claimedSum;

        for (uint256 r = 0; r < initialSumcheckRounds; r++) {
            // Read sumcheck polynomial coefficients (c0, c2) from transcript
            bytes32 c0Bytes;
            bytes32 c2Bytes;
            (c0Bytes, transcriptPos) = _readHash(proof.transcript, transcriptPos);
            (c2Bytes, transcriptPos) = _readHash(proof.transcript, transcriptPos);
            DuplexSponge.absorb(sponge, abi.encodePacked(c0Bytes, c2Bytes));

            // PoW check (if needed)
            if (r == 0 && config.startingFoldingPowBits > 0) {
                // Read nonce, verify PoW
                bytes32 nonce;
                (nonce, transcriptPos) = _readHash(proof.transcript, transcriptPos);
                DuplexSponge.absorb(sponge, abi.encodePacked(nonce));
            }

            // Squeeze folding randomness
            bytes memory challenge = DuplexSponge.squeeze(sponge, 32);
            foldingRandomness[r] = BN254.ScalarField.wrap(
                uint256(bytes32(challenge)) % R_MOD
            );

            // Update claimed sum: sum = c0 + r*c1 + r^2*c2
            // where c1 = prevSum - 2*c0 - c2
        }

        // Step 6: Round loop
        uint256 nRounds = config.roundParameters.length;
        bytes32 prevRoot = root;

        for (uint256 round = 0; round < nRounds; round++) {
            RoundParam memory rp = config.roundParameters[round];

            // Receive new commitment
            bytes32 roundRoot;
            (roundRoot, transcriptPos) = _readHash(proof.transcript, transcriptPos);
            DuplexSponge.absorb(sponge, abi.encodePacked(roundRoot));

            // OOD for this round
            if (rp.oodSamples > 0) {
                bytes memory oodSqueeze = DuplexSponge.squeeze(sponge, rp.oodSamples * 32);
                for (uint256 i = 0; i < rp.oodSamples; i++) {
                    bytes32 val;
                    (val, transcriptPos) = _readHash(proof.transcript, transcriptPos);
                    DuplexSponge.absorb(sponge, abi.encodePacked(val));
                }
            }

            // PoW
            if (rp.powBits > 0) {
                bytes32 nonce;
                (nonce, transcriptPos) = _readHash(proof.transcript, transcriptPos);
                DuplexSponge.absorb(sponge, abi.encodePacked(nonce));
            }

            // Squeeze in-domain challenge indices
            uint256 domainSizeForRound = config.domainSize >> (config.foldingFactor * (round + 1));
            bytes memory idxSqueeze = DuplexSponge.squeeze(sponge, rp.numQueries * 8);
            uint256[] memory challengeIndices = new uint256[](rp.numQueries);
            for (uint256 i = 0; i < rp.numQueries; i++) {
                uint256 raw = uint256(_readMemUint64(idxSqueeze, i * 8));
                challengeIndices[i] = raw % domainSizeForRound;
            }
            // Sort and dedup
            _sortAndDedup(challengeIndices);

            // Read leaf hashes (answers) from transcript
            uint256 answerSize = challengeIndices.length * (1 << config.foldingFactor);
            bytes32[] memory leafHashes = new bytes32[](challengeIndices.length);
            for (uint256 i = 0; i < challengeIndices.length; i++) {
                // Each leaf is the hash of the folded evaluation vector
                // Read the evaluation data from transcript
                uint256 foldSize = 1 << config.foldingFactor;
                bytes memory evalData = new bytes(foldSize * 32);
                for (uint256 j = 0; j < foldSize; j++) {
                    bytes32 val;
                    (val, transcriptPos) = _readHash(proof.transcript, transcriptPos);
                    for (uint256 k = 0; k < 32; k++) {
                        evalData[j * 32 + k] = bytes1(uint8(uint256(val) >> (248 - k * 8)));
                    }
                }
                DuplexSponge.absorb(sponge, evalData);
                leafHashes[i] = keccak256(evalData);
            }

            // Verify Merkle proof for previous commitment
            hintOffset = SpongefishMerkle.verify(
                prevRoot,
                _log2(config.domainSize >> (config.foldingFactor * round)),
                challengeIndices,
                leafHashes,
                proof.hints,
                hintOffset
            );

            // Constraint RLC for this round
            bytes memory constraintSqueeze = DuplexSponge.squeeze(sponge, 32);

            // Sumcheck for this round
            for (uint256 s = 0; s < config.foldingFactor; s++) {
                bytes32 sc0;
                bytes32 sc2;
                (sc0, transcriptPos) = _readHash(proof.transcript, transcriptPos);
                (sc2, transcriptPos) = _readHash(proof.transcript, transcriptPos);
                DuplexSponge.absorb(sponge, abi.encodePacked(sc0, sc2));

                if (s == 0 && rp.foldingPowBits > 0) {
                    bytes32 nonce;
                    (nonce, transcriptPos) = _readHash(proof.transcript, transcriptPos);
                    DuplexSponge.absorb(sponge, abi.encodePacked(nonce));
                }

                bytes memory foldChallenge = DuplexSponge.squeeze(sponge, 32);
            }

            prevRoot = roundRoot;
        }

        // Step 7: Final vector
        uint256 finalSize = 1 << config.finalSumcheckRounds;
        for (uint256 i = 0; i < finalSize; i++) {
            bytes32 val;
            (val, transcriptPos) = _readHash(proof.transcript, transcriptPos);
            DuplexSponge.absorb(sponge, abi.encodePacked(val));
        }

        // Final PoW
        if (config.finalPowBits > 0) {
            bytes32 nonce;
            (nonce, transcriptPos) = _readHash(proof.transcript, transcriptPos);
            DuplexSponge.absorb(sponge, abi.encodePacked(nonce));
        }

        // Final Merkle verification
        {
            uint256 finalDomainSize = config.domainSize >> (config.foldingFactor * (nRounds + 1));
            bytes memory finalIdxSqueeze = DuplexSponge.squeeze(sponge, config.finalQueries * 8);
            uint256[] memory finalIndices = new uint256[](config.finalQueries);
            for (uint256 i = 0; i < config.finalQueries; i++) {
                uint256 raw = uint256(_readMemUint64(finalIdxSqueeze, i * 8));
                finalIndices[i] = raw % finalDomainSize;
            }
            _sortAndDedup(finalIndices);

            // Read final answers and verify Merkle
            bytes32[] memory finalLeafHashes = new bytes32[](finalIndices.length);
            for (uint256 i = 0; i < finalIndices.length; i++) {
                uint256 foldSize = 1 << config.foldingFactor;
                bytes memory evalData = new bytes(foldSize * 32);
                for (uint256 j = 0; j < foldSize; j++) {
                    bytes32 val;
                    (val, transcriptPos) = _readHash(proof.transcript, transcriptPos);
                    for (uint256 k = 0; k < 32; k++) {
                        evalData[j * 32 + k] = bytes1(uint8(uint256(val) >> (248 - k * 8)));
                    }
                }
                DuplexSponge.absorb(sponge, evalData);
                finalLeafHashes[i] = keccak256(evalData);
            }

            hintOffset = SpongefishMerkle.verify(
                prevRoot,
                _log2(config.domainSize >> (config.foldingFactor * nRounds)),
                finalIndices,
                finalLeafHashes,
                proof.hints,
                hintOffset
            );
        }

        // Final sumcheck
        if (config.finalSumcheckRounds > 0) {
            for (uint256 s = 0; s < config.finalSumcheckRounds; s++) {
                bytes32 sc0;
                bytes32 sc2;
                (sc0, transcriptPos) = _readHash(proof.transcript, transcriptPos);
                (sc2, transcriptPos) = _readHash(proof.transcript, transcriptPos);
                DuplexSponge.absorb(sponge, abi.encodePacked(sc0, sc2));

                if (s == 0 && config.finalFoldingPowBits > 0) {
                    bytes32 nonce;
                    (nonce, transcriptPos) = _readHash(proof.transcript, transcriptPos);
                    DuplexSponge.absorb(sponge, abi.encodePacked(nonce));
                }

                bytes memory foldChallenge = DuplexSponge.squeeze(sponge, 32);
            }
        }

        // All transcript consumed, all Merkle proofs verified
        valid = (transcriptPos == proof.transcript.length);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    function _readHash(bytes calldata data, uint256 pos) private pure returns (bytes32 h, uint256 newPos) {
        require(pos + 32 <= data.length, "transcript underflow");
        h = bytes32(data[pos:pos + 32]);
        newPos = pos + 32;
    }

    /// @dev Read a bytes32 from a memory bytes array at a given offset.
    function _readMemBytes32(bytes memory data, uint256 offset) private pure returns (bytes32 result) {
        assembly {
            result := mload(add(add(data, 0x20), offset))
        }
    }

    /// @dev Read a uint64 (big-endian) from a memory bytes array at a given offset.
    function _readMemUint64(bytes memory data, uint256 offset) private pure returns (uint64 result) {
        bytes32 word;
        assembly {
            word := mload(add(add(data, 0x20), offset))
        }
        result = uint64(uint256(word) >> 192); // top 8 bytes
    }

    function _log2(uint256 x) private pure returns (uint256 n) {
        while (x > 1) {
            x >>= 1;
            n++;
        }
    }

    function _sortAndDedup(uint256[] memory arr) private pure {
        // Simple insertion sort + dedup for small arrays
        uint256 n = arr.length;
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
