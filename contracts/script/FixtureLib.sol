// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SumcheckVerifier} from "@mle/SumcheckVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {Plonky2GateEvaluator} from "@mle/Plonky2GateEvaluator.sol";

/// @title FixtureLib
/// @notice Shared fixture-parsing helpers for the Sepolia smoke-deploy scripts.
/// @dev The parsing logic here is ported VERBATIM from
///      `contracts/test/MleFinalizeE2E.t.sol` so the constructor args, the
///      ValidityPublicInputs and the MleProof produced by these scripts are
///      byte-identical to the ones the passing Forge test feeds the contract.
///      Factored into a library to avoid duplicating ~200 lines across
///      Deploy.s.sol and Finalize.s.sol.
///
///      INTENTIONALLY SIMPLE: pure JSON parsing of trusted local fixtures
///      (produced by `cargo run --bin generate_e2e_fixture --release`). No
///      cryptographic logic lives here — the real verification happens inside
///      MleVerifier / IntmaxRollup on-chain.
library FixtureLib {
    // The canonical forge-std cheatcode address.
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @notice Resolve the immutable execution-chain pin for a new real MLE verifier.
    /// @dev Keep the known-unsafe PCS local by default. A non-31337 deployment
    ///      therefore requires an explicit `MLE_VERIFIER_CHAIN_ID` opt-in, and
    ///      the MleVerifier constructor independently requires it to equal the
    ///      chain actually executing the deployment.
    function mleVerifierChainId() internal view returns (uint256) {
        return vm.envOr("MLE_VERIFIER_CHAIN_ID", uint256(31337));
    }

    /// Maximum number of gate rows this parser accepts. The previous bounded scan silently
    /// returned 64 when a fixture carried a 65th row, so the deployed gates digest described only a
    /// prefix of the fixture. Keep the existing capacity, but reject overflow explicitly.
    uint256 internal constant MAX_GATES = 64;

    /// Goldilocks base-field modulus. Domain generators and Ext3 limbs are field elements, not
    /// arbitrary uint64 values; accepting `[P, 2^64)` creates non-canonical representations.
    uint256 internal constant GOLDILOCKS_MODULUS = 0xFFFFFFFF00000001;

    /// @notice Cached real MLE VK params parsed from mle_fixture.json.
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

    // ───────────────────────────── fixture loaders ─────────────────────────────

    function loadMle() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/mle_fixture.json"));
    }

    function loadBlock() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/block_fixture.json"));
    }

    /// @notice The WITHDRAWAL circuit's MLE/WHIR verifier data, for `initializeWithdrawalVk`.
    ///
    /// SECURITY: this is a different circuit from the validity wrapper `loadMle()` returns, and
    /// `IntmaxRollup._verifyWithdrawalSet` reverts `WithdrawalVkNotSet()` until it is installed —
    /// so a rollup deployed without this file's VK escrows deposits it can never pay out. The VK is
    /// channel- and member-INDEPENDENT (it is the circuit's verifier data), so the generic
    /// `withdrawal_mle.json` is the correct source for a rollup-only deploy; the close-lifecycle
    /// scripts use their own `*_withdrawal_mle.json`, which carries the same circuit.
    /// `vm.readFile` reverts if the fixture is absent — fail-loud, never a silent skip.
    function loadWithdrawalMle() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/withdrawal_mle.json"));
    }

    function loadVpi() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/vpi_fixture.json"));
    }

    // ───────────────────────────── high-level builders ─────────────────────────

    /// @notice Build the full constructor argument set for IntmaxRollup, with the
    ///         REAL MLE VK (degreeBits > 0). `verifier` is needed to compute the
    ///         gatesDigest exactly as MleE2E / the Forge test do.
    function buildMleVk(string memory mleJson, MleVerifier verifier)
        internal
        view
        returns (IntmaxRollup.MleVk memory vk)
    {
        DeployData memory dd = parseDeployData(mleJson);
        MleVerifier.MleProof memory proof = parseProof(mleJson);
        bytes32 gatesDigest = verifier.computeGatesDigest(
            proof.gates,
            proof.witnessIndividualEvalsAtRGateV2.length,
            proof.numSelectors,
            proof.numGateConstraints,
            proof.quotientDegreeFactor
        );
        vk = IntmaxRollup.MleVk({
            degreeBits: dd.degreeBits,
            preprocessedRoot: dd.preCommitRoot,
            numConstants: dd.numConstants,
            numRoutedWires: dd.numRoutedWires,
            gatesDigest: gatesDigest
        });
    }

    function parseValidityPIs(string memory json)
        internal
        pure
        returns (IntmaxRollup.ValidityPublicInputs memory vpis)
    {
        vpis.initialBlockNumber = _fixtureUint64(vm.parseJsonUint(json, ".initial_block_number"));
        vpis.initialBlockChain = vm.parseJsonBytes32(json, ".initial_block_chain");
        vpis.initialExtCommitment = vm.parseJsonBytes32(json, ".initial_ext_commitment");
        vpis.finalBlockNumber = _fixtureUint64(vm.parseJsonUint(json, ".final_block_number"));
        vpis.finalBlockChain = vm.parseJsonBytes32(json, ".final_block_chain");
        vpis.finalExtCommitment = vm.parseJsonBytes32(json, ".final_ext_commitment");
        vpis.prover = vm.parseJsonAddress(json, ".prover");
    }

    // ───────────────────────────── deploy-data parsing ─────────────────────────

    function parseDeployData(string memory json) internal pure returns (DeployData memory d) {
        d.degreeBits = vm.parseJsonUint(json, ".degreeBits");
        d.whirParams = parseWhirParams(json, ".whirParams");
        // SECURITY (audit M-10): the Rust exporter is the single source of truth for this field.
        // It used to write a stale `2` — correct only before v2 added the auxiliary and
        // inverse-helper commitments — which THIS line, and two other consumers, silently patched
        // back to 4. Nothing checked the field it wrote, so any submitter that trusted the export
        // (a relayer, a new deploy script, a partner integration) deployed a VK describing a
        // 2-commitment proof and rejected every honest proof. `plonky2_mle` now derives it from
        // `proof::NUM_SPLIT_COMMITMENTS`; assert rather than patch, so a stale fixture fails
        // loudly here instead of on chain.
        require(d.whirParams.numCommitments == 4, "stale fixture: whirParams.numCommitments != 4");
        d.protocolId = vm.parseJsonBytes(json, ".whirProtocolId");
        d.sessionId = vm.parseJsonBytes(json, ".whirSplitSessionId");
        d.preCommitRoot = vm.parseJsonBytes32(json, ".preprocessedCommitmentRoot");
        d.numConstants = vm.parseJsonUint(json, ".numConstants");
        d.numRoutedWires = vm.parseJsonUint(json, ".numRoutedWires");
        d.kIs = parseUintArray(json, ".kIs");
        d.subgroupGenPowers = parseUintArray(json, ".subgroupGenPowers");
    }

    // ───────────────────────────── MLE proof parsing ───────────────────────────

    function parseProof(string memory json) internal pure returns (MleVerifier.MleProof memory proof) {
        proof.circuitDigest = parseUintArray(json, ".circuitDigest");
        proof.whirTranscript = vm.parseJsonBytes(json, ".whirTranscript");
        proof.whirHints = vm.parseJsonBytes(json, ".whirHints");
        proof.preprocessedRoot = vm.parseJsonBytes32(json, ".preprocessedCommitmentRoot");
        proof.witnessRoot = vm.parseJsonBytes32(json, ".witnessCommitmentRoot");
        proof.preprocessedEvalValue = vm.parseUint(vm.parseJsonString(json, ".preprocessedEvalValue"));
        proof.preprocessedBatchR = vm.parseUint(vm.parseJsonString(json, ".preprocessedBatchR"));
        proof.preprocessedIndividualEvals = parseUintArray(json, ".preprocessedIndividualEvals");
        proof.witnessEvalValue = vm.parseUint(vm.parseJsonString(json, ".witnessEvalValue"));
        proof.witnessBatchR = vm.parseUint(vm.parseJsonString(json, ".witnessBatchR"));
        proof.witnessIndividualEvals = parseUintArray(json, ".witnessIndividualEvals");
        proof.auxCommitmentRoot = vm.parseJsonBytes32(json, ".auxCommitmentRoot");
        proof.auxBatchR = vm.parseUint(vm.parseJsonString(json, ".auxBatchR"));
        proof.auxConstraintEval = vm.parseUint(vm.parseJsonString(json, ".auxConstraintEval"));
        proof.auxPermEval = vm.parseUint(vm.parseJsonString(json, ".auxPermEval"));
        proof.auxEvalValue = vm.parseUint(vm.parseJsonString(json, ".auxEvalValue"));

        proof.preprocessedWhirEval = parseExt3(json, ".preprocessedWhirEval");
        proof.witnessWhirEval = parseExt3(json, ".witnessWhirEval");
        proof.auxWhirEval = parseExt3(json, ".auxWhirEval");

        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        proof.combinedProof = parseSumcheckProof(json, ".combinedProof", degreeBits);

        proof.alpha = vm.parseUint(vm.parseJsonString(json, ".alpha"));
        proof.beta = vm.parseUint(vm.parseJsonString(json, ".beta"));
        proof.gamma = vm.parseUint(vm.parseJsonString(json, ".gamma"));
        proof.mu = vm.parseUint(vm.parseJsonString(json, ".mu"));

        proof.publicInputs = parseUintArray(json, ".publicInputs");

        parseV2LogupFields(json, proof);
        parseGateFields(json, proof);
    }

    function parseGateFields(string memory json, MleVerifier.MleProof memory proof) internal pure {
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        proof.extChallenge = vm.parseUint(vm.parseJsonString(json, ".extChallenge"));
        proof.gateSumcheckProof = parseSumcheckProof(json, ".gateSumcheckProof", degreeBits);
        proof.witnessIndividualEvalsAtRGateV2 = parseUintArray(json, ".witnessIndividualEvalsAtRGateV2");
        proof.preprocessedIndividualEvalsAtRGateV2 = parseUintArray(json, ".preprocessedIndividualEvalsAtRGateV2");
        proof.witnessEvalValueAtRGateV2 = vm.parseUint(vm.parseJsonString(json, ".witnessEvalValueAtRGateV2"));
        proof.preprocessedEvalValueAtRGateV2 = vm.parseUint(vm.parseJsonString(json, ".preprocessedEvalValueAtRGateV2"));
        proof.preprocessedWhirEvalAtRGateV2 = parseExt3(json, ".preprocessedWhirEvalAtRGateV2");
        proof.witnessWhirEvalAtRGateV2 = parseExt3(json, ".witnessWhirEvalAtRGateV2");
        proof.auxWhirEvalAtRGateV2 = parseExt3(json, ".auxWhirEvalAtRGateV2");
        proof.inverseHelpersWhirEvalAtRGateV2 = parseExt3(json, ".inverseHelpersWhirEvalAtRGateV2");
        proof.quotientDegreeFactor = vm.parseJsonUint(json, ".quotientDegreeFactor");
        proof.numSelectors = vm.parseJsonUint(json, ".numSelectors");
        proof.numGateConstraints = vm.parseJsonUint(json, ".numGateConstraints");

        uint256 nGates = countGates(json);
        proof.gates = new Plonky2GateEvaluator.GateInfo[](nGates);
        for (uint256 i = 0; i < nGates; i++) {
            proof.gates[i] = parseGateInfo(json, i);
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

    /// Parse one gate row without permitting Solidity's explicit integer casts to truncate a
    /// malformed fixture. Every field width mirrors `Plonky2GateEvaluator.GateInfo` exactly.
    function parseGateInfo(string memory json, uint256 index)
        internal
        pure
        returns (Plonky2GateEvaluator.GateInfo memory gate)
    {
        string memory p = string.concat(".gates[", vm.toString(index), "]");
        gate = Plonky2GateEvaluator.GateInfo({
            gateId: _gateUint8(vm.parseJsonUint(json, string.concat(p, ".gateId"))),
            selectorIndex: _gateUint8(vm.parseJsonUint(json, string.concat(p, ".selectorIndex"))),
            groupStart: _gateUint8(vm.parseJsonUint(json, string.concat(p, ".groupStart"))),
            groupEnd: _gateUint8(vm.parseJsonUint(json, string.concat(p, ".groupEnd"))),
            gateRowIndex: _gateUint8(vm.parseJsonUint(json, string.concat(p, ".gateRowIndex"))),
            numConstraints: _gateUint16(vm.parseJsonUint(json, string.concat(p, ".numConstraints"))),
            numOrConsts: _gateUint16(vm.parseJsonUint(json, string.concat(p, ".numOrConsts"))),
            param2: _gateUint16(vm.parseJsonUint(json, string.concat(p, ".param2"))),
            param3: _gateUint16(vm.parseJsonUint(json, string.concat(p, ".param3")))
        });
    }

    function countGates(string memory json) internal pure returns (uint256 n) {
        // `vm.parseJson` ABI-encodes a JSON array as a top-level dynamic array. Read its encoded
        // length instead of treating a failed per-index field parse as EOF: the latter conflates
        // absent rows with malformed rows and lets a malformed row at the cap hide a valid tail.
        bytes memory encodedGates = vm.parseJson(json, ".gates");
        n = _encodedDynamicArrayLength(encodedGates);
        require(n != 0, "fixture: no gate rows");
        require(n <= MAX_GATES, "fixture: more than 64 gate rows");

        // Prove that every present array element has a uint `gateId`. `parseGateInfo` performs the
        // remaining schema and width checks when the proof is materialized.
        for (uint256 i = 0; i < n; i++) {
            vm.parseJsonUint(json, string.concat(".gates[", vm.toString(i), "].gateId"));
        }
    }

    function _encodedDynamicArrayLength(bytes memory encoded) private pure returns (uint256 length) {
        require(encoded.length >= 64, "fixture: malformed gates array encoding");
        uint256 offset;
        assembly ("memory-safe") {
            offset := mload(add(encoded, 0x20))
        }
        require(offset <= encoded.length - 32, "fixture: malformed gates array offset");
        assembly ("memory-safe") {
            length := mload(add(add(encoded, 0x20), offset))
        }
    }

    function _gateUint8(uint256 value) private pure returns (uint8) {
        require(value <= type(uint8).max, "fixture: GateInfo uint8 overflow");
        return uint8(value);
    }

    function _gateUint16(uint256 value) private pure returns (uint16) {
        require(value <= type(uint16).max, "fixture: GateInfo uint16 overflow");
        return uint16(value);
    }

    function _fixtureUint64(uint256 value) private pure returns (uint64) {
        require(value <= type(uint64).max, "fixture: uint64 overflow");
        return uint64(value);
    }

    function _goldilocksBase(uint256 value) private pure returns (uint64) {
        uint64 narrowed = _fixtureUint64(value);
        require(value < GOLDILOCKS_MODULUS, "fixture: non-canonical Goldilocks element");
        return narrowed;
    }

    function parseV2LogupFields(string memory json, MleVerifier.MleProof memory proof) internal pure {
        proof.inverseHelpersCommitmentRoot = vm.parseJsonBytes32(json, ".inverseHelpersCommitmentRoot");
        proof.inverseHelpersBatchR = vm.parseUint(vm.parseJsonString(json, ".inverseHelpersBatchR"));
        uint256 degreeBits = vm.parseJsonUint(json, ".degreeBits");
        proof.invSumcheckProof = parseSumcheckProof(json, ".invSumcheckProof", degreeBits);
        proof.hSumcheckProof = parseSumcheckProof(json, ".hSumcheckProof", degreeBits);
        proof.lambdaInv = vm.parseUint(vm.parseJsonString(json, ".lambdaInv"));
        proof.muInv = vm.parseUint(vm.parseJsonString(json, ".muInv"));
        proof.lambdaH = vm.parseUint(vm.parseJsonString(json, ".lambdaH"));

        proof.witnessIndividualEvalsAtRInv = parseUintArray(json, ".witnessIndividualEvalsAtRInv");
        proof.preprocessedIndividualEvalsAtRInv = parseUintArray(json, ".preprocessedIndividualEvalsAtRInv");
        proof.inverseHelpersEvalsAtRInv = parseUintArray(json, ".inverseHelpersEvalsAtRInv");
        proof.inverseHelpersEvalsAtRH = parseUintArray(json, ".inverseHelpersEvalsAtRH");
        proof.gSubEvalAtRInv = vm.parseUint(vm.parseJsonString(json, ".gSubEvalAtRInv"));
        proof.witnessEvalValueAtRInv = vm.parseUint(vm.parseJsonString(json, ".witnessEvalValueAtRInv"));
        proof.preprocessedEvalValueAtRInv = vm.parseUint(vm.parseJsonString(json, ".preprocessedEvalValueAtRInv"));

        proof.inverseHelpersWhirEvalAtRGate = parseExt3(json, ".inverseHelpersWhirEvalAtRGate");
        proof.preprocessedWhirEvalAtRInv = parseExt3(json, ".preprocessedWhirEvalAtRInv");
        proof.witnessWhirEvalAtRInv = parseExt3(json, ".witnessWhirEvalAtRInv");
        proof.auxWhirEvalAtRInv = parseExt3(json, ".auxWhirEvalAtRInv");
        proof.inverseHelpersWhirEvalAtRInv = parseExt3(json, ".inverseHelpersWhirEvalAtRInv");
        proof.preprocessedWhirEvalAtRH = parseExt3(json, ".preprocessedWhirEvalAtRH");
        proof.witnessWhirEvalAtRH = parseExt3(json, ".witnessWhirEvalAtRH");
        proof.auxWhirEvalAtRH = parseExt3(json, ".auxWhirEvalAtRH");
        proof.inverseHelpersWhirEvalAtRH = parseExt3(json, ".inverseHelpersWhirEvalAtRH");
    }

    function parseSumcheckProof(string memory json, string memory path, uint256 numRounds)
        internal
        pure
        returns (SumcheckVerifier.SumcheckProof memory proof)
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

    function parseWhirParams(string memory json, string memory basePath)
        internal
        pure
        returns (SpongefishWhirVerify.WhirParams memory params)
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
        params.initialDomainGenerator =
            _goldilocksBase(vm.parseUint(vm.parseJsonString(json, string.concat(basePath, ".initialDomainGenerator"))));
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
            params.rounds[i].domainGenerator =
                _goldilocksBase(vm.parseUint(vm.parseJsonString(json, string.concat(rp, ".domainGenerator"))));
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

    function parseExt3(string memory json, string memory path) internal pure returns (GoldilocksExt3.Ext3 memory) {
        return GoldilocksExt3.Ext3(
            _goldilocksBase(vm.parseUint(vm.parseJsonString(json, string.concat(path, ".c0")))),
            _goldilocksBase(vm.parseUint(vm.parseJsonString(json, string.concat(path, ".c1")))),
            _goldilocksBase(vm.parseUint(vm.parseJsonString(json, string.concat(path, ".c2"))))
        );
    }

    function parseUintArray(string memory json, string memory path) internal pure returns (uint256[] memory) {
        string[] memory strs = vm.parseJsonStringArray(json, path);
        uint256[] memory result = new uint256[](strs.length);
        for (uint256 i = 0; i < strs.length; i++) {
            result[i] = vm.parseUint(strs[i]);
        }
        return result;
    }
}
