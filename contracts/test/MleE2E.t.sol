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

    function _u(string memory json, string memory path) internal pure returns (uint256) {
        bytes memory raw = vm.parseJson(json, path);
        if (raw.length == 32) return abi.decode(raw, (uint256));
        return vm.parseUint(abi.decode(raw, (string)));
    }

    function _parseArrayByIndex(string memory json, string memory basePath, uint256 count)
        internal pure returns (uint256[] memory result)
    {
        result = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = _u(json, string.concat(basePath, "[", vm.toString(i), "]"));
        }
    }

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

    function _parseExt3(string memory json, string memory prefix) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint64 c0 = uint64(_u(json, string.concat(prefix, ".c0")));
        uint64 c1 = uint64(_u(json, string.concat(prefix, ".c1")));
        uint64 c2 = uint64(_u(json, string.concat(prefix, ".c2")));
        GoldilocksExt3.Ext3[] memory evals = new GoldilocksExt3.Ext3[](1);
        evals[0] = GoldilocksExt3.Ext3(c0, c1, c2);
        return evals;
    }

    function _parseWhirParams(string memory json) internal pure returns (SpongefishWhirVerify.WhirParams memory params) {
        params.numVariables = vm.parseJsonUint(json, ".whirParams.numVariables");
        params.foldingFactor = vm.parseJsonUint(json, ".whirParams.foldingFactor");
        params.numVectors = vm.parseJsonUint(json, ".whirParams.numVectors");
        params.numCommitments = vm.parseJsonUint(json, ".whirParams.numCommitments");
        params.outDomainSamples = vm.parseJsonUint(json, ".whirParams.outDomainSamples");
        params.inDomainSamples = vm.parseJsonUint(json, ".whirParams.inDomainSamples");
        params.initialSumcheckRounds = vm.parseJsonUint(json, ".whirParams.initialSumcheckRounds");
        params.numRounds = vm.parseJsonUint(json, ".whirParams.numRounds");
        params.finalSumcheckRounds = vm.parseJsonUint(json, ".whirParams.finalSumcheckRounds");
        params.finalSize = vm.parseJsonUint(json, ".whirParams.finalSize");
        params.initialCodewordLength = vm.parseJsonUint(json, ".whirParams.initialCodewordLength");
        params.initialMerkleDepth = vm.parseJsonUint(json, ".whirParams.initialMerkleDepth");
        params.initialDomainGenerator = uint64(_u(json, ".whirParams.initialDomainGenerator"));
        params.initialInterleavingDepth = vm.parseJsonUint(json, ".whirParams.initialInterleavingDepth");
        params.initialNumVariables = vm.parseJsonUint(json, ".whirParams.initialNumVariables");
        params.initialCosetSize = vm.parseJsonUint(json, ".whirParams.initialCosetSize");
        params.initialNumCosets = vm.parseJsonUint(json, ".whirParams.initialNumCosets");

        uint256 numRounds = params.numRounds;
        params.rounds = new SpongefishWhirVerify.RoundParams[](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            string memory p = string.concat(".whirParams.rounds[", vm.toString(i), "]");
            params.rounds[i].codewordLength = vm.parseJsonUint(json, string.concat(p, ".codewordLength"));
            params.rounds[i].merkleDepth = vm.parseJsonUint(json, string.concat(p, ".merkleDepth"));
            params.rounds[i].domainGenerator = uint64(_u(json, string.concat(p, ".domainGenerator")));
            params.rounds[i].inDomainSamples = vm.parseJsonUint(json, string.concat(p, ".inDomainSamples"));
            params.rounds[i].outDomainSamples = vm.parseJsonUint(json, string.concat(p, ".outDomainSamples"));
            params.rounds[i].sumcheckRounds = vm.parseJsonUint(json, string.concat(p, ".sumcheckRounds"));
            params.rounds[i].interleavingDepth = vm.parseJsonUint(json, string.concat(p, ".interleavingDepth"));
            params.rounds[i].cosetSize = vm.parseJsonUint(json, string.concat(p, ".cosetSize"));
            params.rounds[i].numCosets = vm.parseJsonUint(json, string.concat(p, ".numCosets"));
            params.rounds[i].numVariables = vm.parseJsonUint(json, string.concat(p, ".numVariables"));
        }
        params.evaluationPoint = new GoldilocksExt3.Ext3[](0);
        params.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);
    }

    function _loadMleProof(string memory json)
        internal pure returns (MleVerifier.MleProof memory proof)
    {
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");

        // Circuit digest
        proof.circuitDigest = _parseArrayByIndex(json, ".circuitDigest", 4);

        // Unified WHIR
        proof.whirTranscript = vm.parseJsonBytes(json, ".whirTranscript");
        proof.whirHints = vm.parseJsonBytes(json, ".whirHints");
        proof.preprocessedRoot = vm.parseJsonBytes32(json, ".preprocessedCommitmentRoot");
        proof.witnessRoot = vm.parseJsonBytes32(json, ".witnessCommitmentRoot");

        // Preprocessed batch
        proof.preprocessedEvalValue = _u(json, ".preprocessedEvalValue");
        proof.preprocessedBatchR = _u(json, ".preprocessedBatchR");

        // Witness batch
        proof.witnessEvalValue = _u(json, ".witnessEvalValue");
        proof.witnessBatchR = _u(json, ".witnessBatchR");

        // Sumcheck proofs
        proof.permProof = _loadSumcheckProof(json, ".permProof", degreeBits, 2);
        proof.permClaimedSum = _u(json, ".permClaimedSum");
        proof.constraintProof = _loadSumcheckProof(json, ".constraintProof", degreeBits, 3);

        // Challenges
        proof.alpha = _u(json, ".alpha");
        proof.beta = _u(json, ".beta");
        proof.gamma = _u(json, ".gamma");

        // Circuit dimensions
        proof.numWires = vm.parseJsonUint(json, ".numWires");
        proof.numRoutedWires = vm.parseJsonUint(json, ".numRoutedWires");
        proof.numConstants = vm.parseJsonUint(json, ".numConstants");

        // Oracle values
        proof.pcsConstraintEval = _u(json, ".pcsConstraintEval");
        proof.pcsPermNumeratorEval = _u(json, ".pcsPermNumeratorEval");

        // Arrays
        uint256 numPub = 8;
        uint256 numPreprocessed = proof.numConstants + proof.numRoutedWires;
        uint256 numWitness = proof.numWires;

        proof.publicInputs = _parseArrayByIndex(json, ".publicInputs", numPub);
        proof.preprocessedIndividualEvals = _parseArrayByIndex(json, ".preprocessedIndividualEvals", numPreprocessed);
        proof.witnessIndividualEvals = _parseArrayByIndex(json, ".witnessIndividualEvals", numWitness);
        proof.tau = _parseArrayByIndex(json, ".tau", degreeBits);
        proof.tauPerm = _parseArrayByIndex(json, ".tauPerm", degreeBits);
    }

    /// @notice E2E: verify a real MLE+WHIR proof from plonky2 validity circuit.
    function test_mleVerify_realProof() public view {
        string memory json = _loadFixture();
        MleVerifier.MleProof memory proof = _loadMleProof(json);
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        bytes32 preCommitRoot = vm.parseJsonBytes32(json, ".preprocessedCommitmentRoot");
        SpongefishWhirVerify.WhirParams memory whirParams = _parseWhirParams(json);
        bytes memory protocolId = vm.parseJsonBytes(json, ".whirProtocolId");
        bytes memory splitSessionId = vm.parseJsonBytes(json, ".whirSplitSessionId");

        // Two Ext3 evaluations: [preprocessed, witness]
        GoldilocksExt3.Ext3[] memory whirEvals = new GoldilocksExt3.Ext3[](2);
        {
            GoldilocksExt3.Ext3[] memory preEval = _parseExt3(json, ".preprocessedWhirEval");
            GoldilocksExt3.Ext3[] memory witEval = _parseExt3(json, ".witnessWhirEval");
            whirEvals[0] = preEval[0];
            whirEvals[1] = witEval[0];
        }

        bool ok = verifier.verify(
            proof, degreeBits, preCommitRoot, whirParams,
            protocolId, splitSessionId, whirEvals
        );
        assertTrue(ok, "MLE+WHIR proof verification failed");
    }

    /// @notice Gas measurement.
    function test_mleVerify_gas() public {
        string memory json = _loadFixture();
        MleVerifier.MleProof memory proof = _loadMleProof(json);
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        bytes32 preCommitRoot = vm.parseJsonBytes32(json, ".preprocessedCommitmentRoot");
        SpongefishWhirVerify.WhirParams memory whirParams = _parseWhirParams(json);
        bytes memory protocolId = vm.parseJsonBytes(json, ".whirProtocolId");
        bytes memory splitSessionId = vm.parseJsonBytes(json, ".whirSplitSessionId");

        GoldilocksExt3.Ext3[] memory whirEvals = new GoldilocksExt3.Ext3[](2);
        {
            GoldilocksExt3.Ext3[] memory preEval = _parseExt3(json, ".preprocessedWhirEval");
            GoldilocksExt3.Ext3[] memory witEval = _parseExt3(json, ".witnessWhirEval");
            whirEvals[0] = preEval[0];
            whirEvals[1] = witEval[0];
        }

        uint256 gasBefore = gasleft();
        bool ok = verifier.verify(
            proof, degreeBits, preCommitRoot, whirParams,
            protocolId, splitSessionId, whirEvals
        );
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(ok, "MLE+WHIR proof verification failed");
        emit log_named_uint("MLE+WHIR verification gas", gasUsed);
    }
}
