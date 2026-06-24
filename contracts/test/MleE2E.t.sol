// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SumcheckVerifier} from "@mle/SumcheckVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {Plonky2GateEvaluator} from "@mle/Plonky2GateEvaluator.sol";

/// @title MLE E2E test — real plonky2 validity proof → MLE+WHIR → on-chain verification
/// @notice Mirrors the upstream MleE2ETest pattern (polygon-plonky2 PR #10/#11
///         vulcheck-mle-solidity + wasm-webgpu-merkle), parsing the intmax3
///         `mle_fixture.json` produced by `cargo test --test mle_onchain_e2e`.
/// @dev v2 MleProof:
///        - WHIR ext3 evaluations are embedded INSIDE the proof struct
///          (no separate `whirEvals` parameter — Issues #3 + #7).
///        - `tau` / `tauPerm` removed (re-derived from transcript — Issue #5).
///        - R2-#1 (Φ_gate gate binding) + R2-#2 (logUp inverse helpers) fields
///          added with their own sumcheck terminal points r_gate / r_inv / r_h.
contract MleE2ETest is Test {
    MleVerifier public verifier;

    struct E2EData {
        MleVerifier.MleProof proof;
        uint256 degreeBits;
        bytes32 preCommitRoot;
        uint256 numConstants;
        uint256 numRoutedWires;
        SpongefishWhirVerify.WhirParams whirParams;
        bytes protocolId;
        bytes sessionId;
        uint256[] kIs;                // Issue #2: VK-bound permutation k_is
        uint256[] subgroupGenPowers;  // Issue #2: subgroup generator powers
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

    function test_mleVerify_realProof() public view {
        string memory json = _loadFixture();
        E2EData memory d = _parseAll(json);

        bytes32 gatesDigest = verifier.computeGatesDigest(
            d.proof.gates,
            d.proof.witnessIndividualEvalsAtRGateV2.length,
            d.proof.numSelectors,
            d.proof.numGateConstraints,
            d.proof.quotientDegreeFactor
        );

        MleVerifier.VerifyParams memory vp = MleVerifier.VerifyParams({
            degreeBits: d.degreeBits,
            preprocessedCommitmentRoot: d.preCommitRoot,
            numConstants: d.numConstants,
            numRoutedWires: d.numRoutedWires,
            protocolId: d.protocolId,
            sessionId: d.sessionId,
            kIs: d.kIs,
            subgroupGenPowers: d.subgroupGenPowers
        });

        bool ok = verifier.verify(d.proof, vp, d.whirParams, gatesDigest);
        assertTrue(ok, "MLE+WHIR proof verification failed");
    }

    function test_mleVerify_gas() public {
        string memory json = _loadFixture();
        E2EData memory d = _parseAll(json);

        bytes32 gatesDigest = verifier.computeGatesDigest(
            d.proof.gates,
            d.proof.witnessIndividualEvalsAtRGateV2.length,
            d.proof.numSelectors,
            d.proof.numGateConstraints,
            d.proof.quotientDegreeFactor
        );

        MleVerifier.VerifyParams memory vp = MleVerifier.VerifyParams({
            degreeBits: d.degreeBits,
            preprocessedCommitmentRoot: d.preCommitRoot,
            numConstants: d.numConstants,
            numRoutedWires: d.numRoutedWires,
            protocolId: d.protocolId,
            sessionId: d.sessionId,
            kIs: d.kIs,
            subgroupGenPowers: d.subgroupGenPowers
        });

        uint256 gasBefore = gasleft();
        bool ok = verifier.verify(d.proof, vp, d.whirParams, gatesDigest);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(ok, "MLE+WHIR proof verification failed");
        emit log_named_uint("MLE+WHIR verification gas", gasUsed);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Negative tests (B-4) — the real MleVerifier MUST reject tampering.
    //  A silently-broken verifier that accepts a corrupted proof would let a
    //  garbage validity/close proof finalize on-chain. Each test tampers ONE
    //  axis and asserts the proof is NOT accepted (verify returns false OR
    //  reverts — both are rejections; a `true` return is the only failure).
    // ═══════════════════════════════════════════════════════════════════

    function _vp(E2EData memory d) internal pure returns (MleVerifier.VerifyParams memory vp) {
        vp = MleVerifier.VerifyParams({
            degreeBits: d.degreeBits,
            preprocessedCommitmentRoot: d.preCommitRoot,
            numConstants: d.numConstants,
            numRoutedWires: d.numRoutedWires,
            protocolId: d.protocolId,
            sessionId: d.sessionId,
            kIs: d.kIs,
            subgroupGenPowers: d.subgroupGenPowers
        });
    }

    function _gatesDigest(E2EData memory d) internal view returns (bytes32) {
        return verifier.computeGatesDigest(
            d.proof.gates,
            d.proof.witnessIndividualEvalsAtRGateV2.length,
            d.proof.numSelectors,
            d.proof.numGateConstraints,
            d.proof.quotientDegreeFactor
        );
    }

    /// @dev Asserts the verifier does NOT accept the proof: a `false` return or a revert both pass;
    ///      only a `true` return fails. Tampering can trip either an explicit check (→ false) or an
    ///      out-of-range/transcript inconsistency (→ revert), and both mean "rejected".
    function _assertRejected(
        MleVerifier.MleProof memory proof,
        MleVerifier.VerifyParams memory vp,
        SpongefishWhirVerify.WhirParams memory wp,
        bytes32 gatesDigest,
        string memory why
    ) internal {
        try verifier.verify(proof, vp, wp, gatesDigest) returns (bool ok) {
            assertFalse(ok, why);
        } catch {
            // revert == rejection: acceptable
        }
    }

    /// @notice Sanity: the UNtampered fixture is accepted (so the negatives below isolate tampering,
    ///         not a broken fixture).
    function test_mleVerify_baselineAccepts() public {
        E2EData memory d = _parseAll(_loadFixture());
        bool ok = verifier.verify(d.proof, _vp(d), d.whirParams, _gatesDigest(d));
        assertTrue(ok, "baseline real proof must verify");
    }

    function test_mleVerify_rejects_tamperedTranscript() public {
        E2EData memory d = _parseAll(_loadFixture());
        // Corrupt the WHIR Fiat-Shamir transcript: every MLE challenge is bound to it, so any
        // single-byte change must break verification.
        d.proof.whirTranscript = hex"deadbeefdeadbeefdeadbeefdeadbeef";
        _assertRejected(d.proof, _vp(d), d.whirParams, _gatesDigest(d),
            "tampered whirTranscript MUST be rejected");
    }

    function test_mleVerify_rejects_flippedWitnessEval() public {
        E2EData memory d = _parseAll(_loadFixture());
        require(d.proof.witnessIndividualEvals.length > 0, "fixture has no witness evals");
        // Flip one witness evaluation: it no longer matches the committed polynomial opened by WHIR.
        d.proof.witnessIndividualEvals[0] = d.proof.witnessIndividualEvals[0] ^ 1;
        _assertRejected(d.proof, _vp(d), d.whirParams, _gatesDigest(d),
            "flipped witness evaluation MUST be rejected");
    }

    function test_mleVerify_rejects_wrongGatesDigest() public {
        E2EData memory d = _parseAll(_loadFixture());
        // Pass a gatesDigest that does not match the proof's gates: the terminal gate-binding check
        // (R2-#1) must fail.
        bytes32 wrong = bytes32(uint256(_gatesDigest(d)) ^ 1);
        _assertRejected(d.proof, _vp(d), d.whirParams, wrong,
            "wrong gatesDigest MUST be rejected");
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Fixture parsing (ported from upstream MleE2ETest.t.sol)
    // ═══════════════════════════════════════════════════════════════════

    function _parseAll(string memory json) internal pure returns (E2EData memory d) {
        d.proof = _parseProof(json);
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
            // Older fixtures don't serialize publicInputsHash; the terminal
            // check inside MleVerifier.verify catches that.
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
