// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";

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
        rollup = new IntmaxRollup(
            address(0xdead),
            new MockPinnedMleVerifierV2(31337),
            new MockPinnedMleVerifierV2(31337),
            genesis
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

        bytes memory proofA = _proofFor(pis);
        bytes memory proofB = _differentCanonicalProof(proofA);
        bytes memory encodedA = proofA;
        bytes memory encodedB = proofB;
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
        bytes memory proof = _proofFor(pis);
        bytes memory encoded = proof;
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
        IntmaxRollup rejecting = _deployRollup(true);
        rejecting.setKzgVerifier(da);
        rejecting.setBlockProducer(address(this), true);

        bytes32 root = keccak256("fraud root");
        IntmaxRollup.SubBlock[] memory batch = _batch();
        IntmaxRollup.ValidityPublicInputs memory pis = _previewPisOn(rejecting, batch, root);
        bytes memory committedProof = _proofFor(pis);
        bytes memory differentProof = _differentCanonicalProof(committedProof);

        bytes memory committedBytes = committedProof;
        bytes memory differentBytes = differentProof;
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

    function _deployRollup(bool invalidFraudVerdict) private returns (IntmaxRollup deployed) {
        MockPinnedMleVerifierV2 validityMle = new MockPinnedMleVerifierV2(31337);
        if (invalidFraudVerdict) validityMle.setFraudVerdict(0);
        deployed = new IntmaxRollup(
            address(0xdead), validityMle, new MockPinnedMleVerifierV2(31337), genesis
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
        returns (bytes memory proof)
    {
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
        uint256[] memory publicInputs = new uint256[](8);
        uint256 h = uint256(piHash);
        for (uint256 i = 0; i < 8; i++) {
            publicInputs[i] = (h >> (224 - i * 32)) & 0xffffffff;
        }
        proof = abi.encode(publicInputs);
    }

    function _differentCanonicalProof(bytes memory proof) private pure returns (bytes memory) {
        uint256[] memory publicInputs = abi.decode(proof, (uint256[]));
        uint256[] memory different = new uint256[](publicInputs.length + 1);
        for (uint256 i = 0; i < publicInputs.length; ++i) different[i] = publicInputs[i];
        different[publicInputs.length] = 1;
        return abi.encode(different);
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

}
