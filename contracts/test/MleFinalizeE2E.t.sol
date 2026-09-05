// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";
import {TestProofDaVerifier} from "./helpers/ProofDaTestHelper.sol";
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";

/// @title Full parent path for a constructor-pinned V2 validity verifier.
/// @dev Historical V1 fixture data self-skips in this developer-facing suite. The non-skipping
///      V2FixtureCompletenessTest and CI anti-skip guard make that state a release failure.
contract MleFinalizeE2ETest is Test {
    IntmaxRollup public rollup;
    PinnedMleVerifierV2 internal validityAdapter;
    address public fraudTreasury = makeAddr("fraudTreasury");
    address public poster = makeAddr("poster");
    bool internal v2Ready;

    function setUp() public {
        string memory mleJson = _loadMle();
        IPinnedMleVerifierV2 validity;
        if (vm.keyExistsJson(mleJson, ".schemaVersion")) {
            (, validityAdapter) = FixtureLib.deployPinnedMleV2(mleJson);
            validity = IPinnedMleVerifierV2(address(validityAdapter));
            v2Ready = true;
        } else {
            validity = new MockPinnedMleVerifierV2(31337);
        }

        rollup = new IntmaxRollup(
            fraudTreasury,
            validity,
            new MockPinnedMleVerifierV2(31337),
            vm.parseJsonBytes32(_loadBlock(), ".genesis_state_root")
        );
        rollup.setKzgVerifier(BlobKZGVerifierExt(address(new TestProofDaVerifier())));
        rollup.setBlockProducer(poster, true);
    }

    function _skipUnlessV2() internal {
        if (!v2Ready) {
            vm.skip(true);
        }
    }

    function _proof() internal view returns (bytes memory) {
        return FixtureLib.parseCompactProofV2(_loadMle());
    }

    function _postBlockForFinalize()
        internal
        returns (
            uint256 submissionId,
            bytes32 finalStateRoot,
            IntmaxRollup.ValidityPublicInputs memory vpis,
            uint64 finalBlockNumber
        )
    {
        bytes memory compactProof = _proof();
        return _postBlock(keccak256(compactProof), uint32(compactProof.length), keccak256("smoke_blob"));
    }

    function _postBlock(bytes32 proofHash, uint32 proofLength, bytes32 blobHash)
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
        uint256[] memory keyIdsU = FixtureLib.parseUintArray(blockJson, ".key_ids");
        uint32[] memory keyIds = new uint32[](keyIdsU.length);
        for (uint256 i = 0; i < keyIdsU.length; ++i) {
            keyIds[i] = uint32(keyIdsU[i]);
        }
        subBlocks[0] = IntmaxRollup.SubBlock({
            channelId: uint32(vm.parseJsonUint(blockJson, ".channel_id")),
            timestamp: uint64(vm.parseJsonUint(blockJson, ".timestamp")),
            txTreeRoot: vm.parseJsonBytes32(blockJson, ".tx_tree_root"),
            keyIds: keyIds
        });

        finalStateRoot = vm.parseJsonBytes32(blockJson, ".final_state_root");
        finalBlockNumber = uint64(vm.parseJsonUint(blockJson, ".final_block_number"));
        bytes32 expectedFinalBlockChain = vm.parseJsonBytes32(blockJson, ".final_block_chain");

        bytes32[] memory blobs = new bytes32[](1);
        blobs[0] = blobHash;
        vm.blobhashes(blobs);
        vm.deal(poster, 1 ether);
        submissionId = rollup.nextSubmissionId();
        // Resolve every external read before the one-shot prank. Otherwise this staticcall
        // consumes the prank and the production post is sent by the test contract instead of
        // the authorized block producer.
        bytes32 pendingChainsPin = rollup.pendingChainsPin();
        vm.prank(poster);
        rollup.postBlockAndSubmit{value: 1 ether}(subBlocks, proofHash, proofLength, finalStateRoot, pendingChainsPin);

        assertEq(rollup.blockHashChainAt(finalBlockNumber), expectedFinalBlockChain);
        assertEq(rollup.blockNumber(), finalBlockNumber);
        vpis = _parseValidityPIs();
    }

    function test_fullPath_postBlockThenFinalize() public {
        _skipUnlessV2();
        (uint256 submissionId, bytes32 stateRoot, IntmaxRollup.ValidityPublicInputs memory vpis, uint64 height) =
            _postBlockForFinalize();

        uint256 gasBefore = gasleft();
        bool ok = rollup.finalize(submissionId, stateRoot, vpis, _proof());
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(ok, "finalize failed with pinned V2 verifier");
        assertTrue(rollup.isFinalized(submissionId));
        assertEq(rollup.latestFinalizedStateRoot(), stateRoot);
        assertEq(rollup.latestFinalizedBlockNumber(), height);
        emit log_named_uint("finalize gas (pinned V2 compact)", gasUsed);
    }

    function test_finalize_rejects_tamperedMleProof() public {
        _skipUnlessV2();
        (uint256 submissionId, bytes32 stateRoot, IntmaxRollup.ValidityPublicInputs memory vpis,) =
            _postBlockForFinalize();
        bytes memory proof = _proof();
        proof[proof.length - 1] = bytes1(uint8(proof[proof.length - 1]) ^ 1);

        assertFalse(rollup.finalize(submissionId, stateRoot, vpis, proof));
        assertFalse(rollup.isFinalized(submissionId));
    }

    function test_fraudProof_realVerifier_singleEvalMutationConvicts() public {
        _skipUnlessV2();
        bytes memory proof = _proof();
        proof[proof.length - 1] = bytes1(uint8(proof[proof.length - 1]) ^ 1);
        (uint256 submissionId, bytes32 stateRoot, IntmaxRollup.ValidityPublicInputs memory vpis,) =
            _postBlock(keccak256(proof), uint32(proof.length), keccak256("mutated_v2_blob"));

        vm.prank(makeAddr("fraudProver"));
        assertTrue(rollup.fraudProof(submissionId, stateRoot, vpis, proof));
        assertEq(rollup.nextSubmissionId(), 0);
    }

    function test_fraudProof_invalidProofCannotHideBehindPiMismatch() public {
        _skipUnlessV2();
        bytes memory proof = _proof();
        proof[8] = bytes1(uint8(proof[8]) ^ 1);
        (uint256 submissionId, bytes32 stateRoot, IntmaxRollup.ValidityPublicInputs memory vpis,) =
            _postBlock(keccak256(proof), uint32(proof.length), keccak256("invalid_pi_blob"));

        vm.prank(makeAddr("fraudProver"));
        assertTrue(rollup.fraudProof(submissionId, stateRoot, vpis, proof));
    }

    function test_fraudProof_realVerifier_validCanonicalRawDoesNotConvict() public {
        _skipUnlessV2();
        bytes memory proof = _proof();
        (uint256 submissionId, bytes32 stateRoot, IntmaxRollup.ValidityPublicInputs memory vpis,) =
            _postBlock(keccak256(proof), uint32(proof.length), keccak256("valid_compact"));

        vm.prank(makeAddr("fraudProver"));
        assertFalse(rollup.fraudProof(submissionId, stateRoot, vpis, proof));
        assertTrue(rollup.getCommitment(submissionId) != bytes32(0));
    }

    function test_fraudProof_realVerifier_undecodableAuthenticatedRawConvicts() public {
        _skipUnlessV2();
        bytes memory proof = hex"deadbeef";
        (uint256 submissionId, bytes32 stateRoot, IntmaxRollup.ValidityPublicInputs memory vpis,) =
            _postBlock(keccak256(proof), uint32(proof.length), keccak256("bad_compact"));

        vm.prank(makeAddr("fraudProver"));
        assertTrue(rollup.fraudProof(submissionId, stateRoot, vpis, proof));
        assertEq(rollup.nextSubmissionId(), 0);
    }

    function test_fraudProof_realVerifier_noncanonicalAbiRawConvicts() public {
        _skipUnlessV2();
        bytes memory proof = bytes.concat(_proof(), hex"00");
        (uint256 submissionId, bytes32 stateRoot, IntmaxRollup.ValidityPublicInputs memory vpis,) =
            _postBlock(keccak256(proof), uint32(proof.length), keccak256("trailing_compact"));

        vm.prank(makeAddr("fraudProver"));
        assertTrue(rollup.fraudProof(submissionId, stateRoot, vpis, proof));
        assertEq(rollup.nextSubmissionId(), 0);
    }

    function _loadMle() internal view returns (string memory) {
        return FixtureLib.loadMle();
    }

    function _loadBlock() internal view returns (string memory) {
        return FixtureLib.loadBlock();
    }

    function _parseValidityPIs() internal view returns (IntmaxRollup.ValidityPublicInputs memory) {
        return FixtureLib.parseValidityPIs(FixtureLib.loadVpi());
    }
}
