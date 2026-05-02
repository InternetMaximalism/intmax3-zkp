// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {SpongefishWhirVerify} from "../src/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "../src/spongefish/GoldilocksExt3.sol";
import {Plonky2Verifier} from "../src/Plonky2Verifier.sol";
import {GoldilocksExt2} from "../src/GoldilocksField.sol";

/// @title WhirOnchainE2ETest
/// @notice Complete E2E test: validity proof → WrapperCircuit → WHIR → on-chain verify
///         Verifies a single combined WHIR proof (all 4 polynomial batches concatenated)
///         AND Plonky2 constraint satisfaction via Plonky2Verifier.
///         All fixtures are real proofs from the Rust prover — no mocks, no dummies.
///         Inherits Plonky2Verifier to call verifyConstraints internally (avoids ABI encoding overhead).
contract WhirOnchainE2ETest is Test, Plonky2Verifier {

    // =====================================================================
    // Combined WHIR verification test (all 4 batches in 1 proof)
    // =====================================================================

    /// @notice WHIR polynomial commitment: combined (all 4 batches concatenated)
    function test_whir_wrapper_combined() public view {
        string memory json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/data/whir/wrapper_combined_verifier_data.json")
        );
        _verifyWhirCommitment(json, "combined");
    }

    // =====================================================================
    // Plonky2 constraint satisfaction test
    // =====================================================================

    /// @notice Verify WrapperCircuit constraints on-chain (13 gate types, degree 2^13).
    ///         Calls Plonky2Verifier.verifyConstraints with real openings/challenges.
    function test_plonky2_constraints_wrapper() public {
        string memory json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/data/wrapper_constraint_data.json")
        );
        _verifyPlonky2Constraints(json);
    }

    // =====================================================================
    // Combined E2E: all 4 WHIR batches + Plonky2 constraint verification
    // =====================================================================

    /// @notice Full E2E: verify combined WHIR proof + Plonky2 constraint check.
    ///         This is the complete validity proof → WHIR → smart contract verification.
    function test_full_e2e_combined_whir_and_constraints() public {
        uint256 gasBefore;

        // --- Combined WHIR verification (all 4 batches in 1 proof) ---
        {
            string memory json = vm.readFile(
                string.concat(vm.projectRoot(), "/test/data/whir/wrapper_combined_verifier_data.json")
            );
            gasBefore = gasleft();
            _verifyWhirCommitment(json, "combined");
            uint256 used = gasBefore - gasleft();
            console.log("WHIR combined (1 proof) gas:", used);
        }

        // --- Plonky2 constraint verification ---
        {
            string memory json = vm.readFile(
                string.concat(vm.projectRoot(), "/test/data/wrapper_constraint_data.json")
            );
            _verifyPlonky2Constraints(json);
        }
    }

    // =====================================================================
    // Gas measurement: pure WHIR verification (no JSON parsing overhead)
    // =====================================================================

    /// @notice Measure pure verifyWhirProof gas for the combined proof (excludes JSON parsing).
    function test_gas_pure_whir_verification() public {
        string memory json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/data/whir/wrapper_combined_verifier_data.json")
        );

        // --- Parse all data BEFORE gas measurement ---
        bytes memory protocolId = vm.parseJsonBytes(json, ".protocol_id");
        bytes memory sessionId = vm.parseJsonBytes(json, ".session_id");
        bytes memory instance = vm.parseJsonBytes(json, ".instance");
        bytes memory transcript = vm.parseJsonBytes(json, ".transcript");
        bytes memory hints = vm.parseJsonBytes(json, ".hints");

        GoldilocksExt3.Ext3[] memory evaluations = new GoldilocksExt3.Ext3[](1);
        {
            uint64 c0 = uint64(abi.decode(vm.parseJson(json, ".evaluations[0].c0"), (uint256)));
            uint64 c1 = uint64(abi.decode(vm.parseJson(json, ".evaluations[0].c1"), (uint256)));
            uint64 c2 = uint64(abi.decode(vm.parseJson(json, ".evaluations[0].c2"), (uint256)));
            evaluations[0] = GoldilocksExt3.Ext3(c0, c1, c2);
        }

        SpongefishWhirVerify.WhirParams memory params = _loadParams(json);

        // --- Measure ONLY verifyWhirProof ---
        uint256 gasBefore = gasleft();
        bool valid = SpongefishWhirVerify.verifyWhirProof(
            protocolId, sessionId, instance, transcript, hints, evaluations, params
        );
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(valid, "WHIR combined must verify");
        console.log("Pure WHIR verify [combined] gas:", gasUsed);
    }

    // =====================================================================
    // Internal: WHIR commitment verification
    // =====================================================================

    function _verifyWhirCommitment(string memory json, string memory batchName) internal pure {
        bytes memory protocolId = vm.parseJsonBytes(json, ".protocol_id");
        bytes memory sessionId = vm.parseJsonBytes(json, ".session_id");
        bytes memory instance = vm.parseJsonBytes(json, ".instance");
        bytes memory transcript = vm.parseJsonBytes(json, ".transcript");
        bytes memory hints = vm.parseJsonBytes(json, ".hints");

        // Parse evaluation (single canonical point per WHIR commitment)
        GoldilocksExt3.Ext3[] memory evaluations = new GoldilocksExt3.Ext3[](1);
        {
            uint64 c0 = uint64(abi.decode(vm.parseJson(json, ".evaluations[0].c0"), (uint256)));
            uint64 c1 = uint64(abi.decode(vm.parseJson(json, ".evaluations[0].c1"), (uint256)));
            uint64 c2 = uint64(abi.decode(vm.parseJson(json, ".evaluations[0].c2"), (uint256)));
            evaluations[0] = GoldilocksExt3.Ext3(c0, c1, c2);
        }

        // Parse WHIR params
        SpongefishWhirVerify.WhirParams memory params = _loadParams(json);

        bool valid = SpongefishWhirVerify.verifyWhirProof(
            protocolId, sessionId, instance, transcript, hints, evaluations, params
        );
        assertTrue(valid, string.concat("WHIR commitment must verify: ", batchName));
    }

    // =====================================================================
    // Internal: Plonky2 constraint verification
    // =====================================================================

    function _verifyPlonky2Constraints(string memory json) internal {
        Plonky2Verifier.CircuitParams memory params;
        params.degreeBits = abi.decode(vm.parseJson(json, ".circuitParams.degreeBits"), (uint256));
        params.numChallenges = abi.decode(vm.parseJson(json, ".circuitParams.numChallenges"), (uint256));
        params.numRoutedWires = abi.decode(vm.parseJson(json, ".circuitParams.numRoutedWires"), (uint256));
        params.quotientDegreeFactor = abi.decode(vm.parseJson(json, ".circuitParams.quotientDegreeFactor"), (uint256));
        params.numPartialProducts = abi.decode(vm.parseJson(json, ".circuitParams.numPartialProducts"), (uint256));
        params.numGateConstraints = abi.decode(vm.parseJson(json, ".circuitParams.numGateConstraints"), (uint256));
        params.numSelectors = abi.decode(vm.parseJson(json, ".circuitParams.numSelectors"), (uint256));
        params.numLookupSelectors = abi.decode(vm.parseJson(json, ".circuitParams.numLookupSelectors"), (uint256));

        uint256[] memory constFlat = abi.decode(vm.parseJson(json, ".openings.constants"), (uint256[]));
        uint256[] memory sigmaFlat = abi.decode(vm.parseJson(json, ".openings.plonkSigmas"), (uint256[]));
        uint256[] memory wiresFlat = abi.decode(vm.parseJson(json, ".openings.wires"), (uint256[]));
        uint256[] memory zsFlat = abi.decode(vm.parseJson(json, ".openings.plonkZs"), (uint256[]));
        uint256[] memory zsNextFlat = abi.decode(vm.parseJson(json, ".openings.plonkZsNext"), (uint256[]));
        uint256[] memory ppFlat = abi.decode(vm.parseJson(json, ".openings.partialProducts"), (uint256[]));
        uint256[] memory qpFlat = abi.decode(vm.parseJson(json, ".openings.quotientPolys"), (uint256[]));

        Plonky2Verifier.Openings memory openings;
        openings.constants = _flatToExt2(constFlat);
        openings.plonkSigmas = _flatToExt2(sigmaFlat);
        openings.wires = _flatToExt2(wiresFlat);
        openings.plonkZs = _flatToExt2(zsFlat);
        openings.plonkZsNext = _flatToExt2(zsNextFlat);
        openings.partialProducts = _flatToExt2(ppFlat);
        openings.quotientPolys = _flatToExt2(qpFlat);

        Plonky2Verifier.Challenges memory challenges;
        challenges.plonkBetas = abi.decode(vm.parseJson(json, ".challenges.plonkBetas"), (uint256[]));
        challenges.plonkGammas = abi.decode(vm.parseJson(json, ".challenges.plonkGammas"), (uint256[]));
        challenges.plonkAlphas = abi.decode(vm.parseJson(json, ".challenges.plonkAlphas"), (uint256[]));
        {
            uint256[] memory zetaFlat = abi.decode(vm.parseJson(json, ".challenges.plonkZeta"), (uint256[]));
            challenges.plonkZeta = GoldilocksExt2.Ext2(zetaFlat[0], zetaFlat[1]);
        }

        Plonky2Verifier.PermutationData memory permData;
        permData.kIs = abi.decode(vm.parseJson(json, ".permutation.kIs"), (uint256[]));

        uint256[] memory gateTypes = abi.decode(vm.parseJson(json, ".gates..gateType"), (uint256[]));
        Plonky2Verifier.GateInfo[] memory gates = _parseGates(json, gateTypes.length);

        uint256[] memory publicInputs = abi.decode(vm.parseJson(json, ".publicInputs"), (uint256[]));

        bool valid = verifyConstraints(openings, params, challenges, permData, gates, publicInputs);
        assertTrue(valid, "Plonky2 constraint verification must pass");
    }

    // =====================================================================
    // Internal helpers
    // =====================================================================

    function _loadParams(string memory json) internal pure returns (SpongefishWhirVerify.WhirParams memory p) {
        p.numVariables = _u(json, ".whir_params.num_variables");
        p.foldingFactor = _u(json, ".whir_params.folding_factor");
        p.numVectors = _u(json, ".whir_params.num_vectors");
        p.outDomainSamples = _u(json, ".whir_params.out_domain_samples");
        p.inDomainSamples = _u(json, ".whir_params.in_domain_samples");
        p.initialSumcheckRounds = _u(json, ".whir_params.initial_sumcheck_rounds");
        p.numRounds = _u(json, ".whir_params.num_rounds");
        p.finalSumcheckRounds = _u(json, ".whir_params.final_sumcheck_rounds");
        p.finalSize = _u(json, ".whir_params.final_size");
        p.initialCodewordLength = _u(json, ".whir_params.initial_codeword_length");
        p.initialMerkleDepth = _u(json, ".whir_params.initial_merkle_depth");
        p.initialDomainGenerator = uint64(_u(json, ".whir_params.initial_domain_generator"));
        p.initialInterleavingDepth = _u(json, ".whir_params.initial_interleaving_depth");
        p.initialNumVariables = _u(json, ".whir_params.initial_num_variables");
        p.initialCosetSize = _u(json, ".whir_params.initial_coset_size");
        p.initialNumCosets = _u(json, ".whir_params.initial_num_cosets");

        p.rounds = new SpongefishWhirVerify.RoundParams[](p.numRounds);
        for (uint256 i = 0; i < p.numRounds; i++) {
            string memory prefix = string.concat(".whir_params.rounds[", vm.toString(i), "].");
            p.rounds[i].codewordLength = _u(json, string.concat(prefix, "codeword_length"));
            p.rounds[i].merkleDepth = _u(json, string.concat(prefix, "merkle_depth"));
            p.rounds[i].domainGenerator = uint64(_u(json, string.concat(prefix, "domain_generator")));
            p.rounds[i].inDomainSamples = _u(json, string.concat(prefix, "in_domain_samples"));
            p.rounds[i].outDomainSamples = _u(json, string.concat(prefix, "out_domain_samples"));
            p.rounds[i].sumcheckRounds = _u(json, string.concat(prefix, "sumcheck_rounds"));
            p.rounds[i].interleavingDepth = _u(json, string.concat(prefix, "interleaving_depth"));
            p.rounds[i].cosetSize = _u(json, string.concat(prefix, "coset_size"));
            p.rounds[i].numCosets = _u(json, string.concat(prefix, "num_cosets"));
            p.rounds[i].numVariables = _u(json, string.concat(prefix, "num_variables"));
        }
    }

    function _u(string memory json, string memory path) internal pure returns (uint256) {
        return abi.decode(vm.parseJson(json, path), (uint256));
    }

    function _flatToExt2(uint256[] memory flat) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        uint256 len = flat.length / 2;
        GoldilocksExt2.Ext2[] memory result = new GoldilocksExt2.Ext2[](len);
        for (uint256 i = 0; i < len; i++) {
            result[i] = GoldilocksExt2.Ext2(flat[i * 2], flat[i * 2 + 1]);
        }
        return result;
    }

    function _parseGates(string memory json, uint256 numGates)
        internal pure returns (Plonky2Verifier.GateInfo[] memory)
    {
        uint256[] memory gateTypes = abi.decode(vm.parseJson(json, ".gates..gateType"), (uint256[]));
        uint256[] memory selectorIndices = abi.decode(vm.parseJson(json, ".gates..selectorIndex"), (uint256[]));
        uint256[] memory groupStarts = abi.decode(vm.parseJson(json, ".gates..groupStart"), (uint256[]));
        uint256[] memory groupEnds = abi.decode(vm.parseJson(json, ".gates..groupEnd"), (uint256[]));
        uint256[] memory rowInGroups = abi.decode(vm.parseJson(json, ".gates..rowInGroup"), (uint256[]));
        uint256[] memory numConstraintsList = abi.decode(vm.parseJson(json, ".gates..numConstraints"), (uint256[]));

        Plonky2Verifier.GateInfo[] memory gates = new Plonky2Verifier.GateInfo[](numGates);
        for (uint256 i = 0; i < numGates; i++) {
            uint256[] memory config;
            uint256 gt = gateTypes[i];
            if (gt == 1) { config = new uint256[](1); config[0] = 2; }
            else if (gt == 4) { config = new uint256[](1); config[0] = 20; }
            else if (gt == 5) { config = new uint256[](2); config[0] = 63; config[1] = 2; }
            else if (gt == 6) { config = new uint256[](4); config[0] = 4; config[1] = 4; config[2] = 2; config[3] = 16; }
            else if (gt == 7) { config = new uint256[](1); config[0] = 43; }
            else if (gt == 8) { config = new uint256[](1); config[0] = 32; }
            else if (gt == 9) { config = new uint256[](1); config[0] = 10; }
            else if (gt == 10) { config = new uint256[](1); config[0] = 13; }
            else if (gt == 12) { config = new uint256[](4); config[0] = 4; config[1] = 16; config[2] = 2; config[3] = 6; }
            else { config = new uint256[](0); }
            gates[i] = Plonky2Verifier.GateInfo(
                gateTypes[i], selectorIndices[i], groupStarts[i],
                groupEnds[i], rowInGroups[i], numConstraintsList[i],
                config
            );
        }
        return gates;
    }
}
