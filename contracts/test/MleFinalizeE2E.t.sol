// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SumcheckVerifier} from "@mle/SumcheckVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {Plonky2GateEvaluator} from "@mle/Plonky2GateEvaluator.sol";

/// @title Full real on-chain path: deploy → postBlockAndSubmit → finalize with
///        REAL MLE verification (mleVk.degreeBits > 0).
/// @notice De-risks the Sepolia smoke deploy. Today the path is only tested SPLIT
///         (MleE2E verifies the MLE proof standalone; IntmaxRollup.t.sol finalize
///         uses degreeBits=0 + dummy PIs). This test exercises, in one EVM run:
///           1. the REAL block-hash byte-equality (postBlock reconstructs the exact
///              empty block #1 the validity proof proved),
///           2. the REAL PI binding (mleProof.publicInputs == _piLimbs(keccak(VPIs))),
///           3. the REAL MLE+WHIR verification (mleVk.degreeBits > 0).
/// @dev Fixtures are produced by `cargo run --bin generate_e2e_fixture --release`:
///        - mle_fixture.json   (MLE proof + VK params)   — parsed like MleE2E.t.sol
///        - vpi_fixture.json    (ValidityPublicInputs)
///        - block_fixture.json  (exact postBlock call + finalize-binding values)
contract MleFinalizeE2ETest is Test {
    MleVerifier public verifier;
    IntmaxRollup public rollup;
    address public fraudTreasury = makeAddr("fraudTreasury");
    address public poster = makeAddr("poster");

    // Cached real MLE VK params parsed from mle_fixture.json (used at deploy time).
    struct DeployData {
        uint256 degreeBits;
        bytes32 preCommitRoot;
        uint256 numConstants;
        uint256 numRoutedWires;
        SpongefishWhirVerify.WhirParams whirParams;
        bytes protocolId;
        bytes sessionId;
        uint256[] kIs;
        uint256[] subgroupGenPowers;
    }

    function setUp() public {
        verifier = new MleVerifier();

        string memory mleJson = _loadMle();
        DeployData memory dd = _parseDeployData(mleJson);

        // gatesDigest is computed the same way MleE2E does — from the proof's gate
        // metadata. We parse the proof once here only to derive the digest for the VK.
        MleVerifier.MleProof memory proof = _parseProof(mleJson);
        bytes32 gatesDigest = verifier.computeGatesDigest(
            proof.gates,
            proof.witnessIndividualEvalsAtRGateV2.length,
            proof.numSelectors,
            proof.numGateConstraints,
            proof.quotientDegreeFactor
        );

        // REAL VK — degreeBits > 0 means MLE verification is ON.
        IntmaxRollup.MleVk memory vk = IntmaxRollup.MleVk({
            degreeBits: dd.degreeBits,
            preprocessedRoot: dd.preCommitRoot,
            numConstants: dd.numConstants,
            numRoutedWires: dd.numRoutedWires,
            gatesDigest: gatesDigest
        });

        bytes32 genesisStateRoot = vm.parseJsonBytes32(_loadBlock(), ".genesis_state_root");

        rollup = new IntmaxRollup(
            fraudTreasury,
            vk,
            dd.whirParams,
            dd.protocolId,
            dd.sessionId,
            dd.kIs,
            dd.subgroupGenPowers,
            verifier,
            genesisStateRoot,
            true // A-2: test opt-in for the degreeBits==0 bypass (this test uses a real VK anyway)
        );

        // Sanity: MLE verification really is ON.
        (uint256 db,,,, ) = rollup.mleVk();
        assertGt(db, 0, "mleVk.degreeBits must be > 0 (MLE verification ON)");
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Full path
    // ═══════════════════════════════════════════════════════════════════

    /// @dev Shared postBlockAndSubmit setup: reconstructs the exact empty block #1 and posts it.
    ///      Returns the submissionId, the final state root, the parsed VPIs and the final block
    ///      number so both the positive and the negative finalize tests reuse one posting path.
    function _postBlockForFinalize()
        internal
        returns (
            uint256 submissionId,
            bytes32 finalStateRoot,
            IntmaxRollup.ValidityPublicInputs memory vpis,
            uint64 finalBlockNumber
        )
    {
        string memory blockJson = _loadBlock();

        IntmaxRollup.SubBlock[] memory subBlocks = new IntmaxRollup.SubBlock[](1);
        {
            uint256[] memory keyIdsU = _parseUintArray(blockJson, ".key_ids");
            uint32[] memory keyIds = new uint32[](keyIdsU.length);
            for (uint256 i = 0; i < keyIdsU.length; i++) {
                keyIds[i] = uint32(keyIdsU[i]);
            }
            subBlocks[0] = IntmaxRollup.SubBlock({
                channelId: uint32(vm.parseJsonUint(blockJson, ".channel_id")),
                timestamp: uint64(vm.parseJsonUint(blockJson, ".timestamp")),
                txTreeRoot: vm.parseJsonBytes32(blockJson, ".tx_tree_root"),
                keyIds: keyIds
            });
        }

        finalStateRoot = vm.parseJsonBytes32(blockJson, ".final_state_root");
        bytes32 proofHash = vm.parseJsonBytes32(blockJson, ".proof_hash");
        uint32 proofLength = uint32(vm.parseJsonUint(blockJson, ".proof_length"));
        finalBlockNumber = uint64(vm.parseJsonUint(blockJson, ".final_block_number"));
        bytes32 expectedFinalBlockChain = vm.parseJsonBytes32(blockJson, ".final_block_chain");

        // postBlockAndSubmit reads blobhash(0); mock a non-zero blob (env setup).
        bytes32[] memory blobs = new bytes32[](1);
        blobs[0] = keccak256("smoke_blob");
        vm.blobhashes(blobs);

        vm.deal(poster, 1 ether);
        submissionId = rollup.nextSubmissionId();
        vm.prank(poster);
        rollup.postBlockAndSubmit{value: 1 ether}(
            subBlocks, proofHash, proofLength, finalStateRoot
        );

        // The on-chain recomputed block hash MUST equal the Rust-proved final block chain.
        assertEq(
            rollup.blockHashChainAt(finalBlockNumber),
            expectedFinalBlockChain,
            "on-chain block hash != proved final_block_chain (byte-layout mismatch)"
        );
        assertEq(rollup.blockNumber(), finalBlockNumber, "blockNumber advanced wrong");
        assertEq(submissionId, 0, "first submissionId must be 0");

        vpis = _parseValidityPIs();
    }

    function test_fullPath_postBlockThenFinalize() public {
        (
            uint256 expectedSubmissionId,
            bytes32 finalStateRoot,
            IntmaxRollup.ValidityPublicInputs memory vpis,
            uint64 finalBlockNumber
        ) = _postBlockForFinalize();

        // ── finalize: real ValidityPublicInputs + real MleProof + real MLE. ──
        MleVerifier.MleProof memory mleProof = _parseProof(_loadMle());

        uint256 gasBefore = gasleft();
        bool ok = rollup.finalize(
            expectedSubmissionId,
            finalStateRoot,
            vpis,
            mleProof
        );
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(ok, "finalize failed with real MLE verification ON");
        assertTrue(rollup.isFinalized(expectedSubmissionId), "submission not marked finalized");
        assertEq(rollup.latestFinalizedStateRoot(), finalStateRoot, "latestFinalizedStateRoot mismatch");
        assertEq(rollup.latestFinalizedBlockNumber(), finalBlockNumber, "latestFinalizedBlockNumber mismatch");
        emit log_named_uint("finalize gas (real MLE ON)", gasUsed);
    }

    /// @notice B-4: with MLE verification ON, finalize MUST NOT accept a tampered MLE proof. The PI
    ///         binding still matches (publicInputs untouched), so the rejection is specifically the
    ///         MLE/WHIR check failing. `finalize` returns false (it does not revert) and the
    ///         submission stays un-finalized — without this, a garbage proof could finalize any root.
    function test_finalize_rejects_tamperedMleProof() public {
        (
            uint256 submissionId,
            bytes32 finalStateRoot,
            IntmaxRollup.ValidityPublicInputs memory vpis,

        ) = _postBlockForFinalize();

        MleVerifier.MleProof memory mleProof = _parseProof(_loadMle());
        // Corrupt the WHIR transcript: real MLE verification must now fail inside fullVerify.
        mleProof.whirTranscript = hex"deadbeefdeadbeefdeadbeefdeadbeef";

        bool ok = rollup.finalize(submissionId, finalStateRoot, vpis, mleProof);
        assertFalse(ok, "finalize MUST reject a tampered MLE proof");
        assertFalse(rollup.isFinalized(submissionId), "tampered proof MUST NOT finalize the submission");
        assertTrue(
            rollup.latestFinalizedStateRoot() != finalStateRoot,
            "tampered proof MUST NOT advance latestFinalizedStateRoot to the posted root"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Fixture loading
    // ═══════════════════════════════════════════════════════════════════

    function _loadMle() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/mle_fixture.json"));
    }

    function _loadBlock() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/block_fixture.json"));
    }

    function _parseValidityPIs() internal view returns (IntmaxRollup.ValidityPublicInputs memory vpis) {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/test/data/vpi_fixture.json"));
        vpis.initialBlockNumber = uint64(vm.parseJsonUint(json, ".initial_block_number"));
        vpis.initialBlockChain = vm.parseJsonBytes32(json, ".initial_block_chain");
        vpis.initialExtCommitment = vm.parseJsonBytes32(json, ".initial_ext_commitment");
        vpis.finalBlockNumber = uint64(vm.parseJsonUint(json, ".final_block_number"));
        vpis.finalBlockChain = vm.parseJsonBytes32(json, ".final_block_chain");
        vpis.finalExtCommitment = vm.parseJsonBytes32(json, ".final_ext_commitment");
        vpis.prover = vm.parseJsonAddress(json, ".prover");
    }

    // ═══════════════════════════════════════════════════════════════════
    //  MLE fixture parsing (ported verbatim from MleE2E.t.sol so the proof
    //  fed to finalize is byte-identical to the standalone-verified proof).
    // ═══════════════════════════════════════════════════════════════════

    function _parseDeployData(string memory json) internal pure returns (DeployData memory d) {
        d.degreeBits = vm.parseJsonUint(json, ".degreeBits");
        d.whirParams = _parseWhirParams(json, ".whirParams");
        d.whirParams.numCommitments = 4;
        d.protocolId = vm.parseJsonBytes(json, ".whirProtocolId");
        d.sessionId = vm.parseJsonBytes(json, ".whirSplitSessionId");
        d.preCommitRoot = vm.parseJsonBytes32(json, ".preprocessedCommitmentRoot");
        d.numConstants = vm.parseJsonUint(json, ".numConstants");
        d.numRoutedWires = vm.parseJsonUint(json, ".numRoutedWires");
        d.kIs = _parseUintArray(json, ".kIs");
        d.subgroupGenPowers = _parseUintArray(json, ".subgroupGenPowers");
    }

    function _parseProof(string memory json) internal pure returns (MleVerifier.MleProof memory proof) {
        proof.circuitDigest = _parseUintArray(json, ".circuitDigest");
        proof.whirTranscript = vm.parseJsonBytes(json, ".whirTranscript");
        proof.whirHints = vm.parseJsonBytes(json, ".whirHints");
        proof.preprocessedRoot = vm.parseJsonBytes32(json, ".preprocessedCommitmentRoot");
        proof.witnessRoot = vm.parseJsonBytes32(json, ".witnessCommitmentRoot");
        proof.preprocessedEvalValue = vm.parseUint(vm.parseJsonString(json, ".preprocessedEvalValue"));
        proof.preprocessedBatchR = vm.parseUint(vm.parseJsonString(json, ".preprocessedBatchR"));
        proof.preprocessedIndividualEvals = _parseUintArray(json, ".preprocessedIndividualEvals");
        proof.witnessEvalValue = vm.parseUint(vm.parseJsonString(json, ".witnessEvalValue"));
        proof.witnessBatchR = vm.parseUint(vm.parseJsonString(json, ".witnessBatchR"));
        proof.witnessIndividualEvals = _parseUintArray(json, ".witnessIndividualEvals");
        proof.auxCommitmentRoot = vm.parseJsonBytes32(json, ".auxCommitmentRoot");
        proof.auxBatchR = vm.parseUint(vm.parseJsonString(json, ".auxBatchR"));
        proof.auxConstraintEval = vm.parseUint(vm.parseJsonString(json, ".auxConstraintEval"));
        proof.auxPermEval = vm.parseUint(vm.parseJsonString(json, ".auxPermEval"));
        proof.auxEvalValue = vm.parseUint(vm.parseJsonString(json, ".auxEvalValue"));

        proof.preprocessedWhirEval = _parseExt3(json, ".preprocessedWhirEval");
        proof.witnessWhirEval = _parseExt3(json, ".witnessWhirEval");
        proof.auxWhirEval = _parseExt3(json, ".auxWhirEval");

        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        proof.combinedProof = _parseSumcheckProof(json, ".combinedProof", degreeBits);

        proof.alpha = vm.parseUint(vm.parseJsonString(json, ".alpha"));
        proof.beta = vm.parseUint(vm.parseJsonString(json, ".beta"));
        proof.gamma = vm.parseUint(vm.parseJsonString(json, ".gamma"));
        proof.mu = vm.parseUint(vm.parseJsonString(json, ".mu"));

        proof.publicInputs = _parseUintArray(json, ".publicInputs");

        _parseV2LogupFields(json, proof);
        _parseGateFields(json, proof);
    }

    function _parseGateFields(string memory json, MleVerifier.MleProof memory proof) internal pure {
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        proof.extChallenge = vm.parseUint(vm.parseJsonString(json, ".extChallenge"));
        proof.gateSumcheckProof = _parseSumcheckProof(json, ".gateSumcheckProof", degreeBits);
        proof.witnessIndividualEvalsAtRGateV2 = _parseUintArray(json, ".witnessIndividualEvalsAtRGateV2");
        proof.preprocessedIndividualEvalsAtRGateV2 = _parseUintArray(json, ".preprocessedIndividualEvalsAtRGateV2");
        proof.witnessEvalValueAtRGateV2 = vm.parseUint(vm.parseJsonString(json, ".witnessEvalValueAtRGateV2"));
        proof.preprocessedEvalValueAtRGateV2 = vm.parseUint(vm.parseJsonString(json, ".preprocessedEvalValueAtRGateV2"));
        proof.preprocessedWhirEvalAtRGateV2 = _parseExt3(json, ".preprocessedWhirEvalAtRGateV2");
        proof.witnessWhirEvalAtRGateV2 = _parseExt3(json, ".witnessWhirEvalAtRGateV2");
        proof.auxWhirEvalAtRGateV2 = _parseExt3(json, ".auxWhirEvalAtRGateV2");
        proof.inverseHelpersWhirEvalAtRGateV2 = _parseExt3(json, ".inverseHelpersWhirEvalAtRGateV2");
        proof.quotientDegreeFactor = vm.parseJsonUint(json, ".quotientDegreeFactor");
        proof.numSelectors = vm.parseJsonUint(json, ".numSelectors");
        proof.numGateConstraints = vm.parseJsonUint(json, ".numGateConstraints");

        uint256 nGates = _countGates(json);
        proof.gates = new Plonky2GateEvaluator.GateInfo[](nGates);
        for (uint256 i = 0; i < nGates; i++) {
            string memory p = string.concat(".gates[", vm.toString(i), "]");
            proof.gates[i] = Plonky2GateEvaluator.GateInfo({
                gateId: uint8(vm.parseJsonUint(json, string.concat(p, ".gateId"))),
                selectorIndex: uint8(vm.parseJsonUint(json, string.concat(p, ".selectorIndex"))),
                groupStart: uint8(vm.parseJsonUint(json, string.concat(p, ".groupStart"))),
                groupEnd: uint8(vm.parseJsonUint(json, string.concat(p, ".groupEnd"))),
                gateRowIndex: uint8(vm.parseJsonUint(json, string.concat(p, ".gateRowIndex"))),
                numConstraints: uint16(vm.parseJsonUint(json, string.concat(p, ".numConstraints"))),
                numOrConsts: uint16(vm.parseJsonUint(json, string.concat(p, ".numOrConsts"))),
                param2: uint16(vm.parseJsonUint(json, string.concat(p, ".param2"))),
                param3: uint16(vm.parseJsonUint(json, string.concat(p, ".param3")))
            });
        }

        try vm.parseJsonStringArray(json, ".publicInputsHash") returns (string[] memory hs) {
            for (uint256 i = 0; i < 4 && i < hs.length; i++) {
                proof.publicInputsHash[i] = vm.parseUint(hs[i]);
            }
        } catch {
            // Older fixtures don't serialize publicInputsHash; the terminal check
            // inside MleVerifier.verify catches that.
        }
    }

    function _countGates(string memory json) internal pure returns (uint256 n) {
        for (uint256 i = 0; i < 64; i++) {
            try vm.parseJsonUint(json, string.concat(".gates[", vm.toString(i), "].gateId")) returns (uint256) {
                n = i + 1;
            } catch {
                break;
            }
        }
    }

    function _parseV2LogupFields(string memory json, MleVerifier.MleProof memory proof) internal pure {
        proof.inverseHelpersCommitmentRoot = vm.parseJsonBytes32(json, ".inverseHelpersCommitmentRoot");
        proof.inverseHelpersBatchR = vm.parseUint(vm.parseJsonString(json, ".inverseHelpersBatchR"));
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        proof.invSumcheckProof = _parseSumcheckProof(json, ".invSumcheckProof", degreeBits);
        proof.hSumcheckProof = _parseSumcheckProof(json, ".hSumcheckProof", degreeBits);
        proof.lambdaInv = vm.parseUint(vm.parseJsonString(json, ".lambdaInv"));
        proof.muInv = vm.parseUint(vm.parseJsonString(json, ".muInv"));
        proof.lambdaH = vm.parseUint(vm.parseJsonString(json, ".lambdaH"));

        proof.witnessIndividualEvalsAtRInv = _parseUintArray(json, ".witnessIndividualEvalsAtRInv");
        proof.preprocessedIndividualEvalsAtRInv = _parseUintArray(json, ".preprocessedIndividualEvalsAtRInv");
        proof.inverseHelpersEvalsAtRInv = _parseUintArray(json, ".inverseHelpersEvalsAtRInv");
        proof.inverseHelpersEvalsAtRH = _parseUintArray(json, ".inverseHelpersEvalsAtRH");
        proof.gSubEvalAtRInv = vm.parseUint(vm.parseJsonString(json, ".gSubEvalAtRInv"));
        proof.witnessEvalValueAtRInv = vm.parseUint(vm.parseJsonString(json, ".witnessEvalValueAtRInv"));
        proof.preprocessedEvalValueAtRInv = vm.parseUint(vm.parseJsonString(json, ".preprocessedEvalValueAtRInv"));

        proof.inverseHelpersWhirEvalAtRGate = _parseExt3(json, ".inverseHelpersWhirEvalAtRGate");
        proof.preprocessedWhirEvalAtRInv = _parseExt3(json, ".preprocessedWhirEvalAtRInv");
        proof.witnessWhirEvalAtRInv = _parseExt3(json, ".witnessWhirEvalAtRInv");
        proof.auxWhirEvalAtRInv = _parseExt3(json, ".auxWhirEvalAtRInv");
        proof.inverseHelpersWhirEvalAtRInv = _parseExt3(json, ".inverseHelpersWhirEvalAtRInv");
        proof.preprocessedWhirEvalAtRH = _parseExt3(json, ".preprocessedWhirEvalAtRH");
        proof.witnessWhirEvalAtRH = _parseExt3(json, ".witnessWhirEvalAtRH");
        proof.auxWhirEvalAtRH = _parseExt3(json, ".auxWhirEvalAtRH");
        proof.inverseHelpersWhirEvalAtRH = _parseExt3(json, ".inverseHelpersWhirEvalAtRH");
    }

    function _parseSumcheckProof(string memory json, string memory path, uint256 numRounds)
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
