// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {Plonky2GateEvaluator} from "@mle/Plonky2GateEvaluator.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {InvalidMleProof} from "@mle/MleProofErrors.sol";

contract AuthenticatedRejectingMleVerifier {
    function verify(
        MleVerifier.MleProof calldata,
        MleVerifier.VerifyParams memory,
        SpongefishWhirVerify.WhirParams memory,
        bytes32
    ) external pure returns (bool) {
        revert InvalidMleProof();
    }

    function fraudVerdictEncoded(
        bytes calldata,
        bytes32,
        bytes4,
        bool
    ) external pure returns (uint8) {
        return 0;
    }
}

contract ProofDaIntegrationHarness is BlobKZGVerifierExt {
    function evaluation(bytes calldata proofBytes, bytes calldata compressedCommitment)
        external
        view
        returns (bytes32 versionedHash, uint256 z, uint256 y)
    {
        return _blobEvaluation(proofBytes, 0, compressedCommitment);
    }
}

contract ProofDaRollupTest is Test {
    uint256 internal constant BLS_MODULUS =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    IntmaxRollup internal rollup;
    ProofDaIntegrationHarness internal da;
    bytes32 internal genesis = keccak256("genesis");

    function setUp() public {
        IntmaxRollup.MleVk memory vk;
        SpongefishWhirVerify.WhirParams memory whir = _emptyWhir();
        uint256[] memory empty = new uint256[](0);
        rollup = new IntmaxRollup(
            address(0xdead), vk, whir, "", "", empty, empty, new MleVerifier(), genesis, true
        );
        da = new ProofDaIntegrationHarness();
        rollup.setKzgVerifier(da);
        rollup.setBlockProducer(address(this), true);
        vm.deal(address(this), 10 ether);
    }

    function test_validDifferentProofCannotFinalizeSubmission() public {
        bytes32 root = keccak256("final root");
        IntmaxRollup.SubBlock[] memory batch = _batch();
        IntmaxRollup.ValidityPublicInputs memory pis = _previewPis(batch, root);

        MleVerifier.MleProof memory proofA = _proofFor(pis);
        MleVerifier.MleProof memory proofB = _proofFor(pis);
        proofB.whirTranscript = hex"01"; // still valid with the explicit test-only MLE bypass
        bytes memory encodedA = abi.encode(proofA);
        bytes memory encodedB = abi.encode(proofB);
        (bytes memory sidecarA, bytes32 hashA, bytes memory inputA) = _sidecar(encodedA, 0x11, 0x22);
        (bytes memory sidecarB,, bytes memory inputB) = _sidecar(encodedB, 0x33, 0x44);
        _mockPointSuccess(inputA);
        _mockPointSuccess(inputB);

        _post(batch, root, encodedA, hashA);

        vm.expectRevert(BlobKZGVerifierExt.SubmissionCommitmentMismatch.selector);
        rollup.attestProofData(0, encodedB, sidecarB);
        assertFalse(
            rollup.finalize(0, root, pis, proofB),
            "a separately valid proof must not open another submission"
        );
        assertFalse(rollup.isFinalized(0));
        assertEq(rollup.latestFinalizedStateRoot(), genesis);

        rollup.attestProofData(0, encodedA, sidecarA);
        assertTrue(rollup.finalize(0, root, pis, proofA));
        assertTrue(rollup.isFinalized(0));
        assertEq(rollup.latestFinalizedStateRoot(), root);
    }

    function test_pointEvaluationFailureLeavesFinalizeAtomicAndRetryable() public {
        bytes32 root = keccak256("atomic root");
        IntmaxRollup.SubBlock[] memory batch = _batch();
        IntmaxRollup.ValidityPublicInputs memory pis = _previewPis(batch, root);
        MleVerifier.MleProof memory proof = _proofFor(pis);
        bytes memory encoded = abi.encode(proof);
        (bytes memory sidecar, bytes32 blobHash, bytes memory pointInput) = _sidecar(encoded, 0x55, 0x66);
        _post(batch, root, encoded, blobHash);

        vm.mockCall(address(0x0a), pointInput, bytes(""));
        vm.expectRevert(abi.encodeWithSelector(BlobKZGVerifierExt.PointEvaluationFailed.selector, 0));
        rollup.attestProofData(0, encoded, sidecar);
        assertFalse(rollup.finalize(0, root, pis, proof));
        assertFalse(rollup.isFinalized(0));
        assertEq(rollup.latestFinalizedStateRoot(), genesis);

        vm.clearMockedCalls();
        _mockPointSuccess(pointInput);
        rollup.attestProofData(0, encoded, sidecar);
        assertTrue(rollup.finalize(0, root, pis, proof));
    }

    function test_preTimeoutFraudUsesSameCanonicalProofAndRejectsDifferentProof() public {
        IntmaxRollup rejecting = _deployRollup(
            MleVerifier(address(new AuthenticatedRejectingMleVerifier())), 1
        );
        rejecting.setKzgVerifier(da);
        rejecting.setBlockProducer(address(this), true);

        bytes32 root = keccak256("fraud root");
        IntmaxRollup.SubBlock[] memory batch = _batch();
        IntmaxRollup.ValidityPublicInputs memory pis = _previewPisOn(rejecting, batch, root);
        MleVerifier.MleProof memory committedProof = _proofFor(pis);
        MleVerifier.MleProof memory differentProof = _proofFor(pis);
        differentProof.whirHints = hex"01";

        bytes memory committedBytes = abi.encode(committedProof);
        bytes memory differentBytes = abi.encode(differentProof);
        (bytes memory committedSidecar, bytes32 committedHash, bytes memory committedInput) =
            _sidecar(committedBytes, 0x77, 0x88);
        (bytes memory differentSidecar,, bytes memory differentInput) =
            _sidecar(differentBytes, 0x99, 0xaa);
        _mockPointSuccess(committedInput);
        _mockPointSuccess(differentInput);
        _postOn(rejecting, batch, root, committedBytes, committedHash);

        vm.expectRevert(BlobKZGVerifierExt.SubmissionCommitmentMismatch.selector);
        rejecting.attestProofData(0, differentBytes, differentSidecar);
        rejecting.attestProofData(0, committedBytes, committedSidecar);
        assertFalse(
            rejecting.fraudProof(0, root, pis, differentBytes),
            "valid sidecar for different canonical bytes must not convict"
        );
        assertTrue(rejecting.getCommitment(0) != bytes32(0));
        assertFalse(rejecting.isFinalized(0));

        assertTrue(
            rejecting.fraudProof(0, root, pis, committedBytes),
            "the committed proof's authenticated InvalidMleProof verdict must be reachable"
        );
        assertEq(rejecting.getCommitment(0), bytes32(0));
    }

    function _post(
        IntmaxRollup.SubBlock[] memory batch,
        bytes32 root,
        bytes memory encodedProof,
        bytes32 blobHash
    ) private {
        _postOn(rollup, batch, root, encodedProof, blobHash);
    }

    function _postOn(
        IntmaxRollup target,
        IntmaxRollup.SubBlock[] memory batch,
        bytes32 root,
        bytes memory encodedProof,
        bytes32 blobHash
    ) private {
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = blobHash;
        vm.blobhashes(hashes);
        target.postBlockAndSubmit{value: 1 ether}(
            batch,
            keccak256(encodedProof),
            uint32(encodedProof.length),
            root,
            target.pendingChainsPin()
        );
    }

    function _previewPis(IntmaxRollup.SubBlock[] memory batch, bytes32 root)
        private
        returns (IntmaxRollup.ValidityPublicInputs memory pis)
    {
        return _previewPisOn(rollup, batch, root);
    }

    function _previewPisOn(
        IntmaxRollup target,
        IntmaxRollup.SubBlock[] memory batch,
        bytes32 root
    ) private returns (IntmaxRollup.ValidityPublicInputs memory pis) {
        uint256 snapshot = vm.snapshotState();
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = bytes32(uint256(1));
        vm.blobhashes(hashes);
        target.postBlockAndSubmit{value: 1 ether}(
            batch, bytes32(uint256(1)), 1, root, target.pendingChainsPin()
        );
        pis = IntmaxRollup.ValidityPublicInputs({
            initialBlockNumber: 0,
            initialBlockChain: target.blockHashChainAt(0),
            initialExtCommitment: genesis,
            finalBlockNumber: target.blockNumber(),
            finalBlockChain: target.blockHashChain(),
            finalExtCommitment: root,
            prover: address(0)
        });
        vm.revertToState(snapshot);
    }

    function _deployRollup(MleVerifier verifier, uint256 degreeBits)
        private
        returns (IntmaxRollup deployed)
    {
        IntmaxRollup.MleVk memory vk;
        vk.degreeBits = degreeBits;
        SpongefishWhirVerify.WhirParams memory whir = _emptyWhir();
        uint256[] memory empty = new uint256[](0);
        deployed = new IntmaxRollup(
            address(0xdead), vk, whir, "", "", empty, empty, verifier, genesis, true
        );
    }

    function _sidecar(bytes memory encodedProof, bytes1 commitmentByte, bytes1 proofByte)
        private
        view
        returns (bytes memory sidecar, bytes32 blobHash, bytes memory pointInput)
    {
        bytes memory commitment = new bytes(48);
        bytes memory proof = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            commitment[i] = commitmentByte;
            proof[i] = proofByte;
        }
        uint256 z;
        uint256 y;
        (blobHash, z, y) = da.evaluation(encodedProof, commitment);
        sidecar = bytes.concat(commitment, proof);
        pointInput = bytes.concat(blobHash, bytes32(z), bytes32(y), commitment, proof);
    }

    function _mockPointSuccess(bytes memory pointInput) private {
        vm.mockCall(address(0x0a), pointInput, abi.encode(uint256(4096), BLS_MODULUS));
    }

    function _proofFor(IntmaxRollup.ValidityPublicInputs memory pis)
        private
        pure
        returns (MleVerifier.MleProof memory proof)
    {
        proof.circuitDigest = new uint256[](0);
        proof.whirTranscript = "";
        proof.whirHints = "";
        proof.preprocessedIndividualEvals = new uint256[](0);
        proof.witnessIndividualEvals = new uint256[](0);
        proof.witnessIndividualEvalsAtRInv = new uint256[](0);
        proof.preprocessedIndividualEvalsAtRInv = new uint256[](0);
        proof.inverseHelpersEvalsAtRInv = new uint256[](0);
        proof.inverseHelpersEvalsAtRH = new uint256[](0);
        proof.witnessIndividualEvalsAtRGateV2 = new uint256[](0);
        proof.preprocessedIndividualEvalsAtRGateV2 = new uint256[](0);
        proof.gates = new Plonky2GateEvaluator.GateInfo[](0);

        bytes32 piHash = keccak256(
            abi.encodePacked(
                pis.initialBlockNumber,
                pis.initialBlockChain,
                pis.initialExtCommitment,
                pis.finalBlockNumber,
                pis.finalBlockChain,
                pis.finalExtCommitment,
                pis.prover
            )
        );
        proof.publicInputs = new uint256[](8);
        uint256 h = uint256(piHash);
        for (uint256 i = 0; i < 8; i++) {
            proof.publicInputs[i] = (h >> (224 - i * 32)) & 0xffffffff;
        }
    }

    function _batch() private view returns (IntmaxRollup.SubBlock[] memory batch) {
        batch = new IntmaxRollup.SubBlock[](1);
        batch[0] = IntmaxRollup.SubBlock({
            channelId: 7,
            timestamp: uint64(block.timestamp),
            txTreeRoot: keccak256("tx tree"),
            keyIds: new uint32[](0)
        });
    }

    function _emptyWhir() private pure returns (SpongefishWhirVerify.WhirParams memory whir) {
        whir.rounds = new SpongefishWhirVerify.RoundParams[](0);
        whir.evaluationPoint = new GoldilocksExt3.Ext3[](0);
        whir.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);
    }
}
