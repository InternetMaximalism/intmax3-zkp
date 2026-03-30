// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Plonky2Verifier.sol";
import "../src/GoldilocksField.sol";

/// @title Plonky2VerifierTest — E2E test using real Plonky2 proof data
/// @dev Loads opening values, challenges, and circuit params exported from Rust
///      and verifies that the Plonky2 constraint checker accepts a valid proof.
contract Plonky2VerifierTest is Test, Plonky2Verifier {

    /// @dev Load fixture data and call verifyConstraints
    function test_verifyConstraints_validProof() public {
        // Read fixture JSON
        string memory json = vm.readFile("../tests/fixtures/whir_constraint_data.json");

        // Parse circuit params
        Plonky2Verifier.CircuitParams memory params;
        params.degreeBits = abi.decode(vm.parseJson(json, ".circuitParams.degreeBits"), (uint256));
        params.numChallenges = abi.decode(vm.parseJson(json, ".circuitParams.numChallenges"), (uint256));
        params.numRoutedWires = abi.decode(vm.parseJson(json, ".circuitParams.numRoutedWires"), (uint256));
        params.quotientDegreeFactor = abi.decode(vm.parseJson(json, ".circuitParams.quotientDegreeFactor"), (uint256));
        params.numPartialProducts = abi.decode(vm.parseJson(json, ".circuitParams.numPartialProducts"), (uint256));
        params.numGateConstraints = abi.decode(vm.parseJson(json, ".circuitParams.numGateConstraints"), (uint256));
        params.numSelectors = abi.decode(vm.parseJson(json, ".circuitParams.numSelectors"), (uint256));
        params.numLookupSelectors = abi.decode(vm.parseJson(json, ".circuitParams.numLookupSelectors"), (uint256));

        // Parse openings (lengths from circuit structure)
        Plonky2Verifier.Openings memory openings;
        openings.constants = _parseExt2Array(json, ".openings.constants", 4);
        openings.plonkSigmas = _parseExt2Array(json, ".openings.plonkSigmas", 80);
        openings.wires = _parseExt2Array(json, ".openings.wires", 135);
        openings.plonkZs = _parseExt2Array(json, ".openings.plonkZs", 2);
        openings.plonkZsNext = _parseExt2Array(json, ".openings.plonkZsNext", 2);
        openings.partialProducts = _parseExt2Array(json, ".openings.partialProducts", 18);
        openings.quotientPolys = _parseExt2Array(json, ".openings.quotientPolys", 16);

        // Parse challenges
        Plonky2Verifier.Challenges memory challenges;
        challenges.plonkBetas = _parseU256Array(json, ".challenges.plonkBetas", 2);
        challenges.plonkGammas = _parseU256Array(json, ".challenges.plonkGammas", 2);
        challenges.plonkAlphas = _parseU256Array(json, ".challenges.plonkAlphas", 2);
        {
            uint256[] memory zetaFlat = _parseU256Array(json, ".challenges.plonkZeta", 2);
            challenges.plonkZeta = GoldilocksExt2.Ext2(zetaFlat[0], zetaFlat[1]);
        }

        // Parse permutation data
        Plonky2Verifier.PermutationData memory permData;
        permData.kIs = _parseU256Array(json, ".permutation.kIs", 80);

        // Parse gate info
        Plonky2Verifier.GateInfo[] memory gates = _parseGates(json, 4);

        // Parse public inputs
        uint256[] memory publicInputs = _parseU256Array(json, ".publicInputs", 8);

        // Debug: log array sizes
        emit log_named_uint("constants.length", openings.constants.length);
        emit log_named_uint("plonkSigmas.length", openings.plonkSigmas.length);
        emit log_named_uint("wires.length", openings.wires.length);
        emit log_named_uint("plonkZs.length", openings.plonkZs.length);
        emit log_named_uint("partialProducts.length", openings.partialProducts.length);
        emit log_named_uint("quotientPolys.length", openings.quotientPolys.length);
        emit log_named_uint("kIs.length", permData.kIs.length);
        emit log_named_uint("gates.length", gates.length);
        emit log_named_uint("numRoutedWires", params.numRoutedWires);
        emit log_named_uint("numPartialProducts", params.numPartialProducts);

        // Call verifyConstraints as internal (this contract inherits Plonky2Verifier)
        bool result = verifyConstraints(openings, params, challenges, permData, gates, publicInputs);
        assertTrue(result, "Constraint verification should pass for valid proof");
    }

    // -----------------------------------------------------------------------
    // JSON parsing helpers
    // -----------------------------------------------------------------------

    /// @dev Parse Ext2 array from flattened [c0_0, c1_0, c0_1, c1_1, ...] string array.
    function _parseExt2Array(string memory json, string memory key, uint256 len) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        // Parse flat string array: [c0_0, c1_0, c0_1, c1_1, ...]
        uint256[] memory flat = _parseU256Array(json, key, len * 2);
        GoldilocksExt2.Ext2[] memory result = new GoldilocksExt2.Ext2[](len);
        for (uint256 i = 0; i < len; i++) {
            result[i] = GoldilocksExt2.Ext2(flat[i * 2], flat[i * 2 + 1]);
        }
        return result;
    }

    function _parseU256Array(string memory json, string memory key, uint256 /* len */) internal pure returns (uint256[] memory) {
        // JSON contains numeric arrays — decode directly as uint256[]
        return abi.decode(vm.parseJson(json, key), (uint256[]));
    }

    function _parseGates(string memory json, uint256 numGates) internal pure returns (Plonky2Verifier.GateInfo[] memory) {
        uint256[] memory gateTypes = abi.decode(vm.parseJson(json, ".gates..gateType"), (uint256[]));
        uint256[] memory selectorIndices = abi.decode(vm.parseJson(json, ".gates..selectorIndex"), (uint256[]));
        uint256[] memory groupStarts = abi.decode(vm.parseJson(json, ".gates..groupStart"), (uint256[]));
        uint256[] memory groupEnds = abi.decode(vm.parseJson(json, ".gates..groupEnd"), (uint256[]));
        uint256[] memory rowInGroups = abi.decode(vm.parseJson(json, ".gates..rowInGroup"), (uint256[]));
        uint256[] memory numConstraintsList = abi.decode(vm.parseJson(json, ".gates..numConstraints"), (uint256[]));

        Plonky2Verifier.GateInfo[] memory gates = new Plonky2Verifier.GateInfo[](numGates);
        for (uint256 i = 0; i < numGates; i++) {
            // Parse gate-specific config if present, else provide defaults
            uint256[] memory config;
            uint256 gt = gateTypes[i];
            if (gt == 1) { config = new uint256[](1); config[0] = 2; }             // ConstantGate: numConsts=2
            else if (gt == 4) { config = new uint256[](1); config[0] = 20; }       // ArithmeticGate: numOps=20
            else { config = new uint256[](0); }
            gates[i] = Plonky2Verifier.GateInfo(
                gateTypes[i], selectorIndices[i], groupStarts[i],
                groupEnds[i], rowInGroups[i], numConstraintsList[i],
                config
            );
        }
        return gates;
    }

    // -----------------------------------------------------------------------
    // Negative tests — corrupted proofs must be rejected
    // -----------------------------------------------------------------------

    /// @dev Helper: load all fixture data into memory structs.
    function _loadFixture() internal returns (
        Plonky2Verifier.Openings memory openings,
        Plonky2Verifier.CircuitParams memory params,
        Plonky2Verifier.Challenges memory challenges,
        Plonky2Verifier.PermutationData memory permData,
        Plonky2Verifier.GateInfo[] memory gates,
        uint256[] memory publicInputs
    ) {
        string memory json = vm.readFile("../tests/fixtures/whir_constraint_data.json");
        params.degreeBits = abi.decode(vm.parseJson(json, ".circuitParams.degreeBits"), (uint256));
        params.numChallenges = abi.decode(vm.parseJson(json, ".circuitParams.numChallenges"), (uint256));
        params.numRoutedWires = abi.decode(vm.parseJson(json, ".circuitParams.numRoutedWires"), (uint256));
        params.quotientDegreeFactor = abi.decode(vm.parseJson(json, ".circuitParams.quotientDegreeFactor"), (uint256));
        params.numPartialProducts = abi.decode(vm.parseJson(json, ".circuitParams.numPartialProducts"), (uint256));
        params.numGateConstraints = abi.decode(vm.parseJson(json, ".circuitParams.numGateConstraints"), (uint256));
        params.numSelectors = abi.decode(vm.parseJson(json, ".circuitParams.numSelectors"), (uint256));
        params.numLookupSelectors = abi.decode(vm.parseJson(json, ".circuitParams.numLookupSelectors"), (uint256));
        openings.constants = _parseExt2Array(json, ".openings.constants", 4);
        openings.plonkSigmas = _parseExt2Array(json, ".openings.plonkSigmas", 80);
        openings.wires = _parseExt2Array(json, ".openings.wires", 135);
        openings.plonkZs = _parseExt2Array(json, ".openings.plonkZs", 2);
        openings.plonkZsNext = _parseExt2Array(json, ".openings.plonkZsNext", 2);
        openings.partialProducts = _parseExt2Array(json, ".openings.partialProducts", 18);
        openings.quotientPolys = _parseExt2Array(json, ".openings.quotientPolys", 16);
        challenges.plonkBetas = _parseU256Array(json, ".challenges.plonkBetas", 2);
        challenges.plonkGammas = _parseU256Array(json, ".challenges.plonkGammas", 2);
        challenges.plonkAlphas = _parseU256Array(json, ".challenges.plonkAlphas", 2);
        { uint256[] memory z = _parseU256Array(json, ".challenges.plonkZeta", 2); challenges.plonkZeta = GoldilocksExt2.Ext2(z[0], z[1]); }
        permData.kIs = _parseU256Array(json, ".permutation.kIs", 80);
        gates = _parseGates(json, 4);
        publicInputs = _parseU256Array(json, ".publicInputs", 8);
    }

    function test_verifyConstraints_wrongOpenings() public {
        (Openings memory o, CircuitParams memory p, Challenges memory c, PermutationData memory pd, GateInfo[] memory g, uint256[] memory pi) = _loadFixture();
        // Corrupt one wire opening
        o.wires[0].c0 = o.wires[0].c0 ^ 1;
        assertFalse(verifyConstraints(o, p, c, pd, g, pi), "Wrong openings must fail");
    }

    function test_verifyConstraints_wrongChallenges() public {
        (Openings memory o, CircuitParams memory p, Challenges memory c, PermutationData memory pd, GateInfo[] memory g, uint256[] memory pi) = _loadFixture();
        // Corrupt plonkZeta
        c.plonkZeta.c0 = c.plonkZeta.c0 ^ 1;
        assertFalse(verifyConstraints(o, p, c, pd, g, pi), "Wrong challenges must fail");
    }

    function test_verifyConstraints_wrongPublicInputs() public {
        (Openings memory o, CircuitParams memory p, Challenges memory c, PermutationData memory pd, GateInfo[] memory g, uint256[] memory pi) = _loadFixture();
        // Corrupt one public input
        pi[0] = pi[0] ^ 1;
        assertFalse(verifyConstraints(o, p, c, pd, g, pi), "Wrong public inputs must fail");
    }
}
