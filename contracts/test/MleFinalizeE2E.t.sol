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
            vm.parseJsonBytes32(_loadBlock(), ".genesis_state_root"),
            0.1 ether,
            0.001 ether
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
        uint256 gasBefore = gasleft();
        bool convicted = rollup.fraudProof(submissionId, stateRoot, vpis, proof);
        emit log_named_uint("fraudProof gas (real proof, one evaluation mutated, verdict INVALID)", gasBefore - gasleft());
        assertTrue(convicted);
        assertEq(rollup.nextSubmissionId(), 0);
    }

    /// SECURITY regression (code review 2026-10-15, finding C3): under EIP-7825 a transaction has
    /// at most 2^24 gas, so after the proof's calldata intrinsic gas roughly 14.7M remain for
    /// execution. The pinned classifier convicts this invalid proof in ~6.1M (measured in
    /// `test_fraudProof_realVerifier_singleEvalMutationConvicts`), yet `_encodedMleVerdict` used to
    /// refuse any call arriving with less than 25M gas as `FraudProofGasStarved`, which made every
    /// fraud proof impossible on a capped chain and left only the proof-free timeout removal (no
    /// forfeiture). The floor is now below the cap's execution budget; starvation is still
    /// classified by the two-layer OOG detection, never as fraud.
    function test_fraudProof_realVerifier_convictsWithinEip7825Budget() public {
        _skipUnlessV2();
        bytes memory proof = _proof();
        proof[proof.length - 1] = bytes1(uint8(proof[proof.length - 1]) ^ 1);
        (uint256 submissionId, bytes32 stateRoot, IntmaxRollup.ValidityPublicInputs memory vpis,) =
            _postBlock(keccak256(proof), uint32(proof.length), keccak256("capped_fraud_blob"));

        bytes memory callData = abi.encodeCall(IntmaxRollup.fraudProof, (submissionId, stateRoot, vpis, proof));
        uint256 intrinsic = 21_000;
        for (uint256 i = 0; i < callData.length; ++i) {
            intrinsic += callData[i] == bytes1(0) ? 4 : 16;
        }
        uint256 executionBudget = 16_777_216 - intrinsic;
        emit log_named_uint("fraudProof execution budget under EIP-7825", executionBudget);

        vm.prank(makeAddr("fraudProver"));
        (bool ok, bytes memory ret) = address(rollup).call{gas: executionBudget}(callData);
        if (!ok) {
            emit log_named_bytes32("fraudProof revert selector", bytes32(ret));
        }
        assertTrue(ok, "a fraud proof that the classifier can evaluate must not be refused under the EIP-7825 budget");
        assertTrue(abi.decode(ret, (bool)), "the invalid proof is convicted");
        assertEq(rollup.nextSubmissionId(), 0, "the fraudulent submission was truncated");
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
        uint256 gasBefore = gasleft();
        bool convicted = rollup.fraudProof(submissionId, stateRoot, vpis, proof);
        emit log_named_uint("fraudProof gas (real valid proof, verdict VALID)", gasBefore - gasleft());
        assertFalse(convicted);
        assertTrue(rollup.getCommitment(submissionId) != bytes32(0));
    }

    /// EIP-7825 (Fusaka) caps every transaction at 2^24 = 16,777,216 gas. This test records, for
    /// the checked-in wire-v3 validity fixture, the execution gas of each MLE-bound entry point and
    /// of its building blocks, next to that cap and the proof's calldata intrinsic gas. It asserts
    /// nothing about fitting: it is the executable measurement the deploy runbook cites (review
    /// 2026-10-15, finding C3). `MIN_MLE_VERIFY_GAS` is irrelevant on a capped chain unless the
    /// adapter path itself fits under the cap; see the runbook for the owner decision this leaves.
    function test_gasEnvelope_eip7825_recordValidityEntryPoints() public {
        _skipUnlessV2();
        bytes memory proof = _proof();
        uint256 cap = 16_777_216;
        uint256 intrinsic = 21_000;
        for (uint256 i = 0; i < proof.length; ++i) {
            intrinsic += proof[i] == bytes1(0) ? 4 : 16;
        }
        emit log_named_uint("EIP-7825 transaction gas cap", cap);
        emit log_named_uint("validity compact proof bytes", proof.length);
        emit log_named_uint("calldata intrinsic gas of the proof alone (+21k base)", intrinsic);

        // Adapter building blocks, called directly (view).
        uint256 g = gasleft();
        validityAdapter.verifyCompactPublicInputs(proof);
        emit log_named_uint("adapter.verifyCompactPublicInputs gas", g - gasleft());
        g = gasleft();
        validityAdapter.verifyCompact(proof);
        emit log_named_uint("adapter.verifyCompact gas", g - gasleft());

        // finalize (post first, then the real finalize).
        (uint256 submissionId, bytes32 stateRoot, IntmaxRollup.ValidityPublicInputs memory vpis,) =
            _postBlockForFinalize();
        g = gasleft();
        rollup.fullVerify(stateRoot, vpis, proof);
        emit log_named_uint("rollup.fullVerify gas (direct)", g - gasleft());
        g = gasleft();
        bool ok = rollup.finalize(submissionId, stateRoot, vpis, proof);
        emit log_named_uint("rollup.finalize gas", g - gasleft());
        assertTrue(ok);
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
