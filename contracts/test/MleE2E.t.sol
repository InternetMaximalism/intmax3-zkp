// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SumcheckVerifier} from "@mle/SumcheckVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";

/// @title MLE E2E test — real plonky2 validity proof → MLE+WHIR → on-chain verification
contract MleE2ETest is Test {
    MleVerifier public verifier;

    function setUp() public {
        verifier = new MleVerifier();
    }

    function _loadFixture() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/mle_fixture.json"));
    }

    /// @dev Parse a JSON value as uint256 — handles both string and number formats.
    ///      Forge's parseJson may return either ABI-encoded uint256 (32 bytes)
    ///      or ABI-encoded string (64+ bytes with offset/length).
    function _u(string memory json, string memory path) internal pure returns (uint256) {
        bytes memory raw = vm.parseJson(json, path);
        if (raw.length == 32) {
            return abi.decode(raw, (uint256));
        }
        return vm.parseUint(abi.decode(raw, (string)));
    }

    /// @dev Parse sumcheck proof round polys (array of string arrays).
    function _loadSumcheckProof(string memory json, string memory prefix, uint256 numRounds, uint256 evalsPerRound)
        internal pure returns (SumcheckVerifier.SumcheckProof memory proof)
    {
        proof.roundPolys = new SumcheckVerifier.RoundPoly[](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            proof.roundPolys[i].evals = new uint256[](evalsPerRound);
            for (uint256 j = 0; j < evalsPerRound; j++) {
                proof.roundPolys[i].evals[j] = _u(json,
                    string.concat(prefix, ".roundPolys[", vm.toString(i), "][", vm.toString(j), "]")
                );
            }
        }
    }

    /// @dev Parse array elements one by one to avoid EVM memory issues with large string arrays.
    function _parseArrayByIndex(string memory json, string memory basePath, uint256 count)
        internal pure returns (uint256[] memory result)
    {
        result = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = _u(json, string.concat(basePath, "[", vm.toString(i), "]"));
        }
    }

    /// @dev Parse evaluations from fixture.
    function _parseEvaluations(string memory json) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint64 c0 = uint64(_u(json, ".whirEval.c0"));
        uint64 c1 = uint64(_u(json, ".whirEval.c1"));
        uint64 c2 = uint64(_u(json, ".whirEval.c2"));

        GoldilocksExt3.Ext3[] memory evals = new GoldilocksExt3.Ext3[](1);
        evals[0] = GoldilocksExt3.Ext3(c0, c1, c2);
        return evals;
    }

    /// @dev Parse WhirParams from fixture.
    function _parseWhirParams(string memory json) internal pure returns (SpongefishWhirVerify.WhirParams memory params) {
        params.numVariables = _u(json, ".whirParams.numVariables");
        params.foldingFactor = _u(json, ".whirParams.foldingFactor");
        params.numVectors = _u(json, ".whirParams.numVectors");
        params.outDomainSamples = _u(json, ".whirParams.outDomainSamples");
        params.inDomainSamples = _u(json, ".whirParams.inDomainSamples");
        params.initialSumcheckRounds = _u(json, ".whirParams.initialSumcheckRounds");
        params.numRounds = _u(json, ".whirParams.numRounds");
        params.finalSumcheckRounds = _u(json, ".whirParams.finalSumcheckRounds");
        params.finalSize = _u(json, ".whirParams.finalSize");
        params.initialCodewordLength = _u(json, ".whirParams.initialCodewordLength");
        params.initialMerkleDepth = _u(json, ".whirParams.initialMerkleDepth");
        params.initialDomainGenerator = uint64(_u(json, ".whirParams.initialDomainGenerator"));
        params.initialInterleavingDepth = _u(json, ".whirParams.initialInterleavingDepth");
        params.initialNumVariables = _u(json, ".whirParams.initialNumVariables");
        params.initialCosetSize = _u(json, ".whirParams.initialCosetSize");
        params.initialNumCosets = _u(json, ".whirParams.initialNumCosets");

        uint256 numRounds = params.numRounds;
        params.rounds = new SpongefishWhirVerify.RoundParams[](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            string memory prefix = string.concat(".whirParams.rounds[", vm.toString(i), "]");
            params.rounds[i].codewordLength = _u(json, string.concat(prefix, ".codewordLength"));
            params.rounds[i].merkleDepth = _u(json, string.concat(prefix, ".merkleDepth"));
            params.rounds[i].domainGenerator = uint64(_u(json, string.concat(prefix, ".domainGenerator")));
            params.rounds[i].inDomainSamples = _u(json, string.concat(prefix, ".inDomainSamples"));
            params.rounds[i].outDomainSamples = _u(json, string.concat(prefix, ".outDomainSamples"));
            params.rounds[i].sumcheckRounds = _u(json, string.concat(prefix, ".sumcheckRounds"));
            params.rounds[i].interleavingDepth = _u(json, string.concat(prefix, ".interleavingDepth"));
            params.rounds[i].cosetSize = _u(json, string.concat(prefix, ".cosetSize"));
            params.rounds[i].numCosets = _u(json, string.concat(prefix, ".numCosets"));
            params.rounds[i].numVariables = _u(json, string.concat(prefix, ".numVariables"));
        }

        params.evaluationPoint = new GoldilocksExt3.Ext3[](0);
        params.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);
    }

    function _loadMleProof(string memory json)
        internal pure returns (MleVerifier.MleProof memory proof)
    {
        // WHIR data
        proof.whirTranscript = vm.parseJsonBytes(json, ".whirTranscript");
        proof.whirHints = vm.parseJsonBytes(json, ".whirHints");

        // Sumcheck proofs
        uint256 degreeBits = _u(json, ".degreeBits");
        proof.permProof = _loadSumcheckProof(json, ".permProof", degreeBits, 2);
        proof.permClaimedSum = _u(json, ".permClaimedSum");
        proof.constraintProof = _loadSumcheckProof(json, ".constraintProof", degreeBits, 3);

        // Scalar fields
        proof.evalValue = _u(json, ".evalValue");
        proof.batchR = _u(json, ".batchR");
        proof.numPolys = _u(json, ".numPolys");
        proof.alpha = _u(json, ".alpha");
        proof.beta = _u(json, ".beta");
        proof.gamma = _u(json, ".gamma");

        // Circuit dimensions
        proof.numWires = _u(json, ".numWires");
        proof.numRoutedWires = _u(json, ".numRoutedWires");
        proof.numConstants = _u(json, ".numConstants");

        // Oracle values
        proof.pcsConstraintEval = _u(json, ".pcsConstraintEval");
        proof.pcsPermNumeratorEval = _u(json, ".pcsPermNumeratorEval");

        // Arrays — parse element by element to avoid EVM memory issues with large string arrays
        uint256 numPub = 8; // known from fixture
        uint256 degreeBits2 = degreeBits; // already parsed above
        uint256 numIndividual = proof.numWires + proof.numConstants + proof.numRoutedWires;

        proof.publicInputs = _parseArrayByIndex(json, ".publicInputs", numPub);
        proof.individualEvals = _parseArrayByIndex(json, ".individualEvals", numIndividual);
        proof.tau = _parseArrayByIndex(json, ".tau", degreeBits2);
        proof.tauPerm = _parseArrayByIndex(json, ".tauPerm", degreeBits2);
    }

    /// @notice E2E: verify a real MLE+WHIR proof from plonky2 validity circuit.
    function test_mleVerify_realProof() public view {
        string memory json = _loadFixture();
        MleVerifier.MleProof memory proof = _loadMleProof(json);
        uint256 degreeBits = _u(json, ".degreeBits");
        SpongefishWhirVerify.WhirParams memory whirParams = _parseWhirParams(json);
        bytes memory protocolId = vm.parseJsonBytes(json, ".whirProtocolId");
        bytes memory sessionId = vm.parseJsonBytes(json, ".whirSessionId");
        GoldilocksExt3.Ext3[] memory whirEvaluations = _parseEvaluations(json);

        bool ok = verifier.verify(proof, degreeBits, whirParams, protocolId, sessionId, whirEvaluations);
        assertTrue(ok, "MLE+WHIR proof verification failed");
    }

    /// @notice Gas measurement.
    function test_mleVerify_gas() public {
        string memory json = _loadFixture();
        MleVerifier.MleProof memory proof = _loadMleProof(json);
        uint256 degreeBits = _u(json, ".degreeBits");
        SpongefishWhirVerify.WhirParams memory whirParams = _parseWhirParams(json);
        bytes memory protocolId = vm.parseJsonBytes(json, ".whirProtocolId");
        bytes memory sessionId = vm.parseJsonBytes(json, ".whirSessionId");
        GoldilocksExt3.Ext3[] memory whirEvaluations = _parseEvaluations(json);

        uint256 gasBefore = gasleft();
        bool ok = verifier.verify(proof, degreeBits, whirParams, protocolId, sessionId, whirEvaluations);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(ok, "MLE+WHIR proof verification failed");
        emit log_named_uint("MLE+WHIR verification gas", gasUsed);
    }
}
