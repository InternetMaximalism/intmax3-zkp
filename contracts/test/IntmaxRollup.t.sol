// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {IntmaxRollup, WhirVerifierWrapper} from "../src/IntmaxRollup.sol";
import {KZGProof} from "../src/BlobKZGVerifier.sol";
import {WhirProof, Statement, WhirConfig} from "sol-whir/WhirStructs.sol";
import {JSONWhirProof, JSONUtils} from "sol-whir/utils/WhirJson.sol";

contract IntmaxRollupTest is Test {
    IntmaxRollup public rollup;
    WhirVerifierWrapper public verifierWrapper;

    address submitter = makeAddr("submitter");
    address prover    = makeAddr("prover");

    bytes32 constant FAKE_BLOB_HASH = bytes32(uint256(0xdeadbeef));

    bytes   internal _kzgCommitment48;
    bytes32 internal _kzgBlobHash;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    function _mockBlob() internal {
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = FAKE_BLOB_HASH;
        vm.blobhashes(hashes);
    }

    function _mockKZGBlob() internal {
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = _kzgBlobHash;
        vm.blobhashes(hashes);
    }

    function _mockBLSPrecompiles() internal {
        vm.mockCall(address(0x0b), new bytes(0), new bytes(128));
        vm.mockCall(address(0x0d), new bytes(0), new bytes(128));
        vm.mockCall(address(0x11), new bytes(0), abi.encode(uint256(1)));
    }

    function _dummyKZG(uint256 dataLen) internal view returns (KZGProof memory kzg) {
        uint256 N = (dataLen + 31) / 32;
        kzg = KZGProof({
            kzgCommitment48: _kzgCommitment48,
            kzgCommitmentG1: new bytes(128),
            openingProof:    new bytes(128),
            vanishingG2:     new bytes(256),
            lagrangeBasisG1: new bytes(N * 128)
        });
    }

    function loadProof()
        internal
        view
        returns (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        )
    {
        string memory path = string.concat(
            vm.projectRoot(),
            "/lib/sol-whir/test/data/whir/",
            "proof_16_4_1_ConjectureList_30_6_80_ProverHelps.json"
        );
        string memory json = vm.readFile(path);
        bytes memory parsed = vm.parseJson(json);
        JSONWhirProof memory jsonProof = abi.decode(parsed, (JSONWhirProof));

        config     = JSONUtils.jsonWhirConfigToWhirConfig(jsonProof.config);
        statement  = JSONUtils.jsonStatementToStatement(jsonProof.statement);
        whirProof  = JSONUtils.jsonWhirProofToWhirProof(jsonProof);
        transcript = jsonProof.arthur.transcript;
    }

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    function setUp() public {
        verifierWrapper = new WhirVerifierWrapper();
        rollup = new IntmaxRollup(verifierWrapper);

        vm.deal(submitter, 10 ether);

        _kzgCommitment48 = new bytes(48);
        (bool ok, bytes memory h) = address(0x02).staticcall(_kzgCommitment48);
        require(ok, "sha256 precompile failed in setUp");
        _kzgBlobHash = bytes32(
            (uint256(0x01) << 248) | (uint256(bytes32(h)) & (type(uint256).max >> 8))
        );
    }

    // -----------------------------------------------------------------------
    // submit() tests
    // -----------------------------------------------------------------------

    function test_submit() public {
        bytes32 proofHash   = keccak256("plonky2_proof_data");
        uint32  proofLength = 1024;
        bytes32 stateRoot   = keccak256("state_1");

        _mockBlob();
        vm.prank(submitter);
        rollup.submit(proofHash, proofLength, stateRoot);

        bytes32 expectedCommitment = keccak256(
            abi.encodePacked(FAKE_BLOB_HASH, proofHash, proofLength, stateRoot)
        );
        assertEq(rollup.getCommitment(0), expectedCommitment);
        assertEq(rollup.nextId(), 1);

        IntmaxRollup.Submission memory sub = rollup.getSubmission(0);
        assertEq(sub.submitter, submitter);
        assertFalse(sub.finalized);
    }

    function test_submit_revert_noBlob() public {
        vm.prank(submitter);
        vm.expectRevert(IntmaxRollup.NoBlobAttached.selector);
        rollup.submit(bytes32(0), uint32(0), bytes32(0));
    }

    function test_submit_multiple() public {
        _mockBlob();

        vm.prank(submitter);
        rollup.submit(keccak256("p1"), 512, keccak256("s1"));

        vm.prank(submitter);
        rollup.submit(keccak256("p2"), 768, keccak256("s2"));

        assertEq(rollup.nextId(), 2);

        IntmaxRollup.Submission memory sub0 = rollup.getSubmission(0);
        IntmaxRollup.Submission memory sub1 = rollup.getSubmission(1);
        assertTrue(sub0.commitment != bytes32(0));
        assertTrue(sub1.commitment != bytes32(0));
        assertTrue(sub0.commitment != sub1.commitment);
    }

    // -----------------------------------------------------------------------
    // verify() tests  —  pure WHIR, no KZG
    // -----------------------------------------------------------------------

    function test_verify_validProof_returnsTrue() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        bool result = rollup.verify(config, statement, whirProof, transcript);
        assertTrue(result);
    }

    function test_verify_invalidProof_returnsFalse() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        // Corrupt the transcript
        if (transcript.length > 10) {
            transcript[5] = bytes1(uint8(transcript[5]) ^ 0xFF);
            transcript[6] = bytes1(uint8(transcript[6]) ^ 0xFF);
        }

        bool result = rollup.verify(config, statement, whirProof, transcript);
        assertFalse(result);
    }

    // -----------------------------------------------------------------------
    // fraudProof() tests
    // -----------------------------------------------------------------------

    function test_fraudProof_validProof_returnsTrue() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        bytes memory plonky2Bytes = abi.encode(config, statement, whirProof, transcript);
        bytes32 proofHash   = keccak256(plonky2Bytes);
        uint32  proofLength = uint32(plonky2Bytes.length);
        bytes32 stateRoot   = keccak256("state_valid_fp");

        _mockKZGBlob();
        vm.prank(submitter);
        rollup.submit(proofHash, proofLength, stateRoot);

        _mockBLSPrecompiles();

        bool result = rollup.fraudProof(
            0, _kzgBlobHash, stateRoot,
            plonky2Bytes,
            config, statement, whirProof, transcript,
            _dummyKZG(plonky2Bytes.length)
        );
        assertTrue(result);
    }

    function test_fraudProof_invalidProof_returnsFalse() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        bytes memory corruptTranscript = transcript;
        if (corruptTranscript.length > 10) {
            corruptTranscript[5] = bytes1(uint8(corruptTranscript[5]) ^ 0xFF);
            corruptTranscript[6] = bytes1(uint8(corruptTranscript[6]) ^ 0xFF);
        }

        bytes memory plonky2Bytes = abi.encode(config, statement, whirProof, corruptTranscript);
        bytes32 proofHash   = keccak256(plonky2Bytes);
        uint32  proofLength = uint32(plonky2Bytes.length);
        bytes32 stateRoot   = keccak256("state_invalid_fp");

        _mockKZGBlob();
        vm.prank(submitter);
        rollup.submit(proofHash, proofLength, stateRoot);

        _mockBLSPrecompiles();

        bool result = rollup.fraudProof(
            0, _kzgBlobHash, stateRoot,
            plonky2Bytes,
            config, statement, whirProof, corruptTranscript,
            _dummyKZG(plonky2Bytes.length)
        );
        assertFalse(result);
    }

    function test_fraudProof_commitmentMismatch() public {
        bytes memory plonky2Bytes = "some_proof_data";
        bytes32 stateRoot = keccak256("state_mismatch");

        // Submit with different proof bytes
        _mockKZGBlob();
        vm.prank(submitter);
        rollup.submit(keccak256("different_proof"), 1024, stateRoot);

        _mockBLSPrecompiles();

        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        vm.expectRevert(IntmaxRollup.CommitmentMismatch.selector);
        rollup.fraudProof(
            0, _kzgBlobHash, stateRoot,
            plonky2Bytes,
            config, statement, whirProof, transcript,
            _dummyKZG(plonky2Bytes.length)
        );
    }

    // -----------------------------------------------------------------------
    // finalize() tests
    // -----------------------------------------------------------------------

    function test_finalize_success() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        bytes memory plonky2Bytes = abi.encode(config, statement, whirProof, transcript);
        bytes32 proofHash   = keccak256(plonky2Bytes);
        uint32  proofLength = uint32(plonky2Bytes.length);
        bytes32 stateRoot   = keccak256("finalized_state");

        _mockKZGBlob();
        vm.prank(submitter);
        rollup.submit(proofHash, proofLength, stateRoot);

        _mockBLSPrecompiles();

        rollup.finalize(
            0, _kzgBlobHash, stateRoot,
            plonky2Bytes,
            config, statement, whirProof, transcript,
            _dummyKZG(plonky2Bytes.length)
        );

        assertTrue(rollup.isFinalized(0));
        assertEq(rollup.latestFinalizedStateRoot(), stateRoot);
    }

    function test_finalize_alreadyFinalized() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        bytes memory plonky2Bytes = abi.encode(config, statement, whirProof, transcript);
        bytes32 proofHash   = keccak256(plonky2Bytes);
        uint32  proofLength = uint32(plonky2Bytes.length);
        bytes32 stateRoot   = keccak256("s");

        _mockKZGBlob();
        vm.prank(submitter);
        rollup.submit(proofHash, proofLength, stateRoot);

        _mockBLSPrecompiles();

        rollup.finalize(
            0, _kzgBlobHash, stateRoot, plonky2Bytes,
            config, statement, whirProof, transcript,
            _dummyKZG(plonky2Bytes.length)
        );

        vm.expectRevert(IntmaxRollup.AlreadyFinalized.selector);
        rollup.finalize(
            0, _kzgBlobHash, stateRoot, plonky2Bytes,
            config, statement, whirProof, transcript,
            _dummyKZG(plonky2Bytes.length)
        );
    }

    function test_finalize_invalidProofReverts() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        // Corrupt transcript
        bytes memory corruptTranscript = transcript;
        if (corruptTranscript.length > 10) {
            corruptTranscript[5] = bytes1(uint8(corruptTranscript[5]) ^ 0xFF);
        }

        bytes memory plonky2Bytes = abi.encode(config, statement, whirProof, corruptTranscript);
        bytes32 proofHash   = keccak256(plonky2Bytes);
        uint32  proofLength = uint32(plonky2Bytes.length);
        bytes32 stateRoot   = keccak256("bad_state");

        _mockKZGBlob();
        vm.prank(submitter);
        rollup.submit(proofHash, proofLength, stateRoot);

        _mockBLSPrecompiles();

        vm.expectRevert(IntmaxRollup.ProofVerificationFailed.selector);
        rollup.finalize(
            0, _kzgBlobHash, stateRoot, plonky2Bytes,
            config, statement, whirProof, corruptTranscript,
            _dummyKZG(plonky2Bytes.length)
        );

        assertFalse(rollup.isFinalized(0));
    }

    function test_finalize_notFound() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        vm.expectRevert(IntmaxRollup.SubmissionNotFound.selector);
        rollup.finalize(
            999, bytes32(0), bytes32(0), "",
            config, statement, whirProof, transcript,
            _dummyKZG(0)
        );
    }

    // -----------------------------------------------------------------------
    // Gas measurement
    // -----------------------------------------------------------------------

    function test_gas_submit() public {
        _mockBlob();
        vm.prank(submitter);
        uint256 gasBefore = gasleft();
        rollup.submit(keccak256("proof"), uint32(1024), keccak256("state"));
        uint256 gasUsed = gasBefore - gasleft();
        console.log("submit() gas:", gasUsed);
    }

    function test_gas_verify() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        uint256 gasBefore = gasleft();
        rollup.verify(config, statement, whirProof, transcript);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("verify() gas (pure WHIR):", gasUsed);
    }

    function test_gas_fraudProof() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        bytes memory plonky2Bytes = abi.encode(config, statement, whirProof, transcript);
        bytes32 proofHash   = keccak256(plonky2Bytes);
        uint32  proofLength = uint32(plonky2Bytes.length);
        bytes32 stateRoot   = keccak256("gas_test");

        _mockKZGBlob();
        vm.prank(submitter);
        rollup.submit(proofHash, proofLength, stateRoot);

        _mockBLSPrecompiles();

        uint256 gasBefore = gasleft();
        rollup.fraudProof(
            0, _kzgBlobHash, stateRoot,
            plonky2Bytes,
            config, statement, whirProof, transcript,
            _dummyKZG(plonky2Bytes.length)
        );
        uint256 gasUsed = gasBefore - gasleft();
        console.log("fraudProof() gas (KZG + WHIR):", gasUsed);
    }

    function test_gas_finalize() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        bytes memory plonky2Bytes = abi.encode(config, statement, whirProof, transcript);
        bytes32 proofHash   = keccak256(plonky2Bytes);
        uint32  proofLength = uint32(plonky2Bytes.length);
        bytes32 stateRoot   = keccak256("gas_finalize");

        _mockKZGBlob();
        vm.prank(submitter);
        rollup.submit(proofHash, proofLength, stateRoot);

        _mockBLSPrecompiles();

        uint256 gasBefore = gasleft();
        rollup.finalize(
            0, _kzgBlobHash, stateRoot, plonky2Bytes,
            config, statement, whirProof, transcript,
            _dummyKZG(plonky2Bytes.length)
        );
        uint256 gasUsed = gasBefore - gasleft();
        console.log("finalize() gas:", gasUsed);
    }
}
