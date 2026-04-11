// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SumcheckVerifier} from "@mle/SumcheckVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";

/// @title MLE E2E test — real plonky2 validity proof → MLE+WHIR → on-chain verification
/// @dev Mirrors the upstream MleE2ETest pattern from polygon-plonky2/mle/contracts/test/
contract MleE2ETest is Test {
    MleVerifier public verifier;

    struct E2EData {
        MleVerifier.MleProof proof;
        uint256 degreeBits;
        SpongefishWhirVerify.WhirParams whirParams;
        bytes protocolId;
        bytes sessionId;
        GoldilocksExt3.Ext3[] whirEvals;
        bytes32 preCommitRoot;
        uint256 numConstants;
        uint256 numRoutedWires;
    }

    function setUp() public {
        verifier = new MleVerifier();
    }

    function _loadFixture() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/mle_fixture.json"));
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Tests
    // ═══════════════════════════════════════════════════════════════════

    /// @notice E2E: verify a real MLE+WHIR proof from plonky2 validity circuit.
    function test_mleVerify_realProof() public view {
        string memory json = _loadFixture();
        E2EData memory d = _parseAll(json);

        bool ok = verifier.verify(
            d.proof, d.degreeBits, d.preCommitRoot, d.numConstants, d.numRoutedWires,
            d.whirParams, d.protocolId, d.sessionId, d.whirEvals
        );
        assertTrue(ok, "MLE+WHIR proof verification failed");
    }

    /// @notice Gas measurement.
    function test_mleVerify_gas() public {
        string memory json = _loadFixture();
        E2EData memory d = _parseAll(json);

        uint256 gasBefore = gasleft();
        bool ok = verifier.verify(
            d.proof, d.degreeBits, d.preCommitRoot, d.numConstants, d.numRoutedWires,
            d.whirParams, d.protocolId, d.sessionId, d.whirEvals
        );
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(ok, "MLE+WHIR proof verification failed");
        emit log_named_uint("MLE+WHIR verification gas", gasUsed);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Fixture parsing (mirrors upstream MleE2ETest.t.sol)
    // ═══════════════════════════════════════════════════════════════════

    function _parseAll(string memory json) internal pure returns (E2EData memory d) {
        d.proof = _parseProof(json);
        d.degreeBits = vm.parseJsonUint(json, ".degreeBits");

        // Single WHIR (3 vectors: preprocessed + witness + auxiliary)
        d.whirParams = _parseWhirParams(json, ".whirParams");
        d.whirParams.numCommitments = 3; // Override for 3-vector phased commit
        d.protocolId = vm.parseJsonBytes(json, ".whirProtocolId");
        d.sessionId = vm.parseJsonBytes(json, ".whirSplitSessionId");

        // 3 Ext3 evals: [preprocessed, witness, auxiliary]
        d.whirEvals = new GoldilocksExt3.Ext3[](3);
        d.whirEvals[0] = _parseExt3(json, ".preprocessedWhirEval");
        d.whirEvals[1] = _parseExt3(json, ".witnessWhirEval");
        d.whirEvals[2] = _parseExt3(json, ".auxWhirEval");

        // Evaluation point (sumcheck output r)
        GoldilocksExt3.Ext3[] memory evalPt = _parseExt3Array(json, ".evaluationPoint");
        d.whirParams.evaluationPoint = evalPt;
        d.whirParams.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);

        // VK values
        d.preCommitRoot = vm.parseJsonBytes32(json, ".preprocessedCommitmentRoot");
        d.numConstants = vm.parseJsonUint(json, ".numConstants");
        d.numRoutedWires = vm.parseJsonUint(json, ".numRoutedWires");
    }

    function _parseProof(string memory json) internal pure returns (MleVerifier.MleProof memory proof) {
        proof.circuitDigest = _parseUintArray(json, ".circuitDigest");

        // Main WHIR PCS
        proof.whirTranscript = vm.parseJsonBytes(json, ".whirTranscript");
        proof.whirHints = vm.parseJsonBytes(json, ".whirHints");
        proof.preprocessedRoot = vm.parseJsonBytes32(json, ".preprocessedCommitmentRoot");
        proof.witnessRoot = vm.parseJsonBytes32(json, ".witnessCommitmentRoot");
        proof.auxCommitmentRoot = vm.parseJsonBytes32(json, ".auxCommitmentRoot");

        // Preprocessed batch
        proof.preprocessedEvalValue = vm.parseUint(vm.parseJsonString(json, ".preprocessedEvalValue"));
        proof.preprocessedBatchR = vm.parseUint(vm.parseJsonString(json, ".preprocessedBatchR"));

        // Witness batch
        proof.witnessEvalValue = vm.parseUint(vm.parseJsonString(json, ".witnessEvalValue"));
        proof.witnessBatchR = vm.parseUint(vm.parseJsonString(json, ".witnessBatchR"));

        // Aux polynomial
        proof.auxBatchR = vm.parseUint(vm.parseJsonString(json, ".auxBatchR"));
        proof.auxConstraintEval = vm.parseUint(vm.parseJsonString(json, ".auxConstraintEval"));
        proof.auxPermEval = vm.parseUint(vm.parseJsonString(json, ".auxPermEval"));
        proof.auxEvalValue = vm.parseUint(vm.parseJsonString(json, ".auxEvalValue"));

        // Combined sumcheck proof
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        proof.combinedProof = _parseSumcheck(json, ".combinedProof", degreeBits);

        // Challenges
        proof.alpha = vm.parseUint(vm.parseJsonString(json, ".alpha"));
        proof.beta = vm.parseUint(vm.parseJsonString(json, ".beta"));
        proof.gamma = vm.parseUint(vm.parseJsonString(json, ".gamma"));
        proof.mu = vm.parseUint(vm.parseJsonString(json, ".mu"));

        // Arrays
        proof.publicInputs = _parseUintArray(json, ".publicInputs");
        proof.preprocessedIndividualEvals = _parseUintArray(json, ".preprocessedIndividualEvals");
        proof.witnessIndividualEvals = _parseUintArray(json, ".witnessIndividualEvals");
        proof.tau = _parseUintArray(json, ".tau");
    }

    function _parseSumcheck(string memory json, string memory path, uint256 numRounds)
        internal pure returns (SumcheckVerifier.SumcheckProof memory proof)
    {
        proof.roundPolys = new SumcheckVerifier.RoundPoly[](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            string memory roundPath = string.concat(path, ".roundPolys[", vm.toString(i), "]");
            string[] memory strs = vm.parseJsonStringArray(json, roundPath);
            uint256[] memory evals = new uint256[](strs.length);
            for (uint256 j = 0; j < strs.length; j++) {
                evals[j] = vm.parseUint(strs[j]);
            }
            proof.roundPolys[i].evals = evals;
        }
    }

    function _parseWhirParams(string memory json, string memory basePath)
        internal pure returns (SpongefishWhirVerify.WhirParams memory params)
    {
        params.numVariables = vm.parseJsonUint(json, string.concat(basePath, ".numVariables"));
        params.foldingFactor = vm.parseJsonUint(json, string.concat(basePath, ".foldingFactor"));
        params.numVectors = vm.parseJsonUint(json, string.concat(basePath, ".numVectors"));
        params.numCommitments = vm.parseJsonUint(json, string.concat(basePath, ".numCommitments"));
        params.outDomainSamples = vm.parseJsonUint(json, string.concat(basePath, ".outDomainSamples"));
        params.inDomainSamples = vm.parseJsonUint(json, string.concat(basePath, ".inDomainSamples"));
        params.initialSumcheckRounds = vm.parseJsonUint(json, string.concat(basePath, ".initialSumcheckRounds"));
        params.numRounds = vm.parseJsonUint(json, string.concat(basePath, ".numRounds"));
        params.finalSumcheckRounds = vm.parseJsonUint(json, string.concat(basePath, ".finalSumcheckRounds"));
        params.finalSize = vm.parseJsonUint(json, string.concat(basePath, ".finalSize"));
        params.initialCodewordLength = vm.parseJsonUint(json, string.concat(basePath, ".initialCodewordLength"));
        params.initialMerkleDepth = vm.parseJsonUint(json, string.concat(basePath, ".initialMerkleDepth"));
        params.initialDomainGenerator = uint64(vm.parseUint(vm.parseJsonString(json, string.concat(basePath, ".initialDomainGenerator"))));
        params.initialInterleavingDepth = vm.parseJsonUint(json, string.concat(basePath, ".initialInterleavingDepth"));
        params.initialNumVariables = vm.parseJsonUint(json, string.concat(basePath, ".initialNumVariables"));
        params.initialCosetSize = vm.parseJsonUint(json, string.concat(basePath, ".initialCosetSize"));
        params.initialNumCosets = vm.parseJsonUint(json, string.concat(basePath, ".initialNumCosets"));

        uint256 nr = params.numRounds;
        params.rounds = new SpongefishWhirVerify.RoundParams[](nr);
        for (uint256 i = 0; i < nr; i++) {
            string memory rp = string.concat(basePath, ".rounds[", vm.toString(i), "]");
            params.rounds[i].codewordLength = vm.parseJsonUint(json, string.concat(rp, ".codewordLength"));
            params.rounds[i].merkleDepth = vm.parseJsonUint(json, string.concat(rp, ".merkleDepth"));
            params.rounds[i].domainGenerator = uint64(vm.parseUint(vm.parseJsonString(json, string.concat(rp, ".domainGenerator"))));
            params.rounds[i].inDomainSamples = vm.parseJsonUint(json, string.concat(rp, ".inDomainSamples"));
            params.rounds[i].outDomainSamples = vm.parseJsonUint(json, string.concat(rp, ".outDomainSamples"));
            params.rounds[i].sumcheckRounds = vm.parseJsonUint(json, string.concat(rp, ".sumcheckRounds"));
            params.rounds[i].interleavingDepth = vm.parseJsonUint(json, string.concat(rp, ".interleavingDepth"));
            params.rounds[i].cosetSize = vm.parseJsonUint(json, string.concat(rp, ".cosetSize"));
            params.rounds[i].numCosets = vm.parseJsonUint(json, string.concat(rp, ".numCosets"));
            params.rounds[i].numVariables = vm.parseJsonUint(json, string.concat(rp, ".numVariables"));
        }

        params.evaluationPoint = new GoldilocksExt3.Ext3[](0);
        params.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);
    }

    function _parseExt3(string memory json, string memory path)
        internal pure returns (GoldilocksExt3.Ext3 memory)
    {
        return GoldilocksExt3.Ext3(
            uint64(vm.parseUint(vm.parseJsonString(json, string.concat(path, ".c0")))),
            uint64(vm.parseUint(vm.parseJsonString(json, string.concat(path, ".c1")))),
            uint64(vm.parseUint(vm.parseJsonString(json, string.concat(path, ".c2"))))
        );
    }

    function _parseExt3Array(string memory json, string memory path)
        internal pure returns (GoldilocksExt3.Ext3[] memory result)
    {
        // Probe for array length by trying indices
        uint256 len = 0;
        for (uint256 i = 0; i < 20; i++) {
            try vm.parseJsonString(json, string.concat(path, "[", vm.toString(i), "].c0")) returns (string memory) {
                len = i + 1;
            } catch {
                break;
            }
        }
        result = new GoldilocksExt3.Ext3[](len);
        for (uint256 i = 0; i < len; i++) {
            string memory ep = string.concat(path, "[", vm.toString(i), "]");
            result[i] = GoldilocksExt3.Ext3(
                uint64(vm.parseUint(vm.parseJsonString(json, string.concat(ep, ".c0")))),
                uint64(vm.parseUint(vm.parseJsonString(json, string.concat(ep, ".c1")))),
                uint64(vm.parseUint(vm.parseJsonString(json, string.concat(ep, ".c2"))))
            );
        }
    }

    function _parseUintArray(string memory json, string memory path)
        internal pure returns (uint256[] memory)
    {
        string[] memory strs = vm.parseJsonStringArray(json, path);
        uint256[] memory result = new uint256[](strs.length);
        for (uint256 i = 0; i < strs.length; i++) {
            result[i] = vm.parseUint(strs[i]);
        }
        return result;
    }
}
