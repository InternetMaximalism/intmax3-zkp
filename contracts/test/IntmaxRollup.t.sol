// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {IntmaxRollup, WhirVerifierWrapper} from "../src/IntmaxRollup.sol";
import {KZGProof} from "../src/BlobKZGVerifier.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {WhirProof, Statement, WhirConfig} from "sol-whir/WhirStructs.sol";
import {BN254} from "solidity-bn254/BN254.sol";
import {JSONWhirProof, JSONUtils} from "sol-whir/utils/WhirJson.sol";

contract IntmaxRollupTest is Test {
    IntmaxRollup public rollup;
    WhirVerifierWrapper public verifierWrapper;

    address submitter = makeAddr("submitter");
    address aggregator = makeAddr("aggregator");

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

    /// @dev Mock WhirVerifierWrapper to return true (used when we patch statement evaluations).
    function _mockWhirVerifierTrue() internal {
        vm.mockCall(
            address(verifierWrapper),
            abi.encodeWithSelector(WhirVerifierWrapper.verify.selector),
            abi.encode(true)
        );
    }

    /// @dev Mock WhirVerifierWrapper to return false.
    function _mockWhirVerifierFalse() internal {
        vm.mockCall(
            address(verifierWrapper),
            abi.encodeWithSelector(WhirVerifierWrapper.verify.selector),
            abi.encode(false)
        );
    }

    /// @dev Mock BN254 ecPairing (0x08) to return 1 (valid Groth16).
    function _mockGroth16Pairing() internal {
        vm.mockCall(address(0x08), new bytes(0), abi.encode(uint256(1)));
    }

    /// @dev Dummy Groth16 verifying key with 1 public input (2 IC points).
    function _dummyGroth16Vk() internal pure returns (Groth16Verifier.VerifyingKey memory vk) {
        vk.alpha = [uint256(1), uint256(2)];
        vk.beta  = [[uint256(1), uint256(2)], [uint256(3), uint256(4)]];
        vk.gamma = [[uint256(5), uint256(6)], [uint256(7), uint256(8)]];
        vk.delta = [[uint256(9), uint256(10)], [uint256(11), uint256(12)]];
        vk.ic = new uint256[2][](2);
        vk.ic[0] = [uint256(1), uint256(2)];
        vk.ic[1] = [uint256(1), uint256(2)];
    }

    function _dummyGroth16Proof() internal pure returns (Groth16Verifier.Proof memory proof) {
        proof.a = [uint256(1), uint256(2)];
        proof.b = [[uint256(1), uint256(2)], [uint256(3), uint256(4)]];
        proof.c = [uint256(1), uint256(2)];
    }

    function _dummyGroth16PubInputs() internal pure returns (uint256[] memory) {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = 42;
        return inputs;
    }

    function _dummyGroth16() internal pure returns (IntmaxRollup.Groth16Params memory) {
        return IntmaxRollup.Groth16Params({
            vk: _dummyGroth16Vk(),
            proof: _dummyGroth16Proof(),
            pubInputs: _dummyGroth16PubInputs()
        });
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

    /// @dev Build a dummy ValidityPublicInputs that matches on-chain state.
    function _defaultValidityPIs(bytes32 stateRoot)
        internal view returns (IntmaxRollup.ValidityPublicInputs memory pis)
    {
        pis = IntmaxRollup.ValidityPublicInputs({
            initialBlockNumber: 0,
            initialBlockChain:  rollup.blockHashChainAt(0),
            initialExtCommitment: rollup.latestFinalizedStateRoot(),
            finalBlockNumber:   rollup.blockNumber(),
            finalBlockChain:    rollup.blockHashChain(),
            finalExtCommitment: stateRoot,
            prover: address(0)
        });
    }

    /// @dev Inject the plonky2 public input hash into the WHIR statement's evaluations[0].
    function _patchStatementWithPIHash(
        Statement memory statement,
        IntmaxRollup.ValidityPublicInputs memory pis
    ) internal pure {
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
        // Ensure evaluations has at least 1 element, set [0] to piHash
        if (statement.evaluations.length == 0) {
            statement.evaluations = new BN254.ScalarField[](1);
        }
        statement.evaluations[0] = BN254.ScalarField.wrap(uint256(piHash));
    }

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    function setUp() public {
        verifierWrapper = new WhirVerifierWrapper();
        rollup = new IntmaxRollup(verifierWrapper);

        vm.deal(submitter, 10 ether);
        vm.deal(aggregator, 10 ether);

        _kzgCommitment48 = new bytes(48);
        (bool ok, bytes memory h) = address(0x02).staticcall(_kzgCommitment48);
        require(ok, "sha256 precompile failed in setUp");
        _kzgBlobHash = bytes32(
            (uint256(0x01) << 248) | (uint256(bytes32(h)) & (type(uint256).max >> 8))
        );
    }

    // -----------------------------------------------------------------------
    // postBlock() tests
    // -----------------------------------------------------------------------

    function test_postBlock() public {
        uint32[] memory localIds = new uint32[](2);
        localIds[0] = 1;
        localIds[1] = 2;

        vm.prank(aggregator);
        rollup.postBlock(5, localIds, uint64(block.timestamp), bytes32(uint256(0xabc)));

        assertEq(rollup.blockNumber(), 1);
        assertTrue(rollup.blockHashChain() != bytes32(0));
        assertEq(rollup.blockHashChainAt(1), rollup.blockHashChain());
    }

    function test_postBlock_multipleBlocks() public {
        uint32[] memory ids1 = new uint32[](1);
        ids1[0] = 1;
        uint32[] memory ids2 = new uint32[](2);
        ids2[0] = 3;
        ids2[1] = 4;

        rollup.postBlock(1, ids1, 100, bytes32(uint256(0x111)));
        rollup.postBlock(1, ids2, 200, bytes32(uint256(0x222)));

        assertEq(rollup.blockNumber(), 2);
        assertTrue(rollup.blockHashChainAt(1) != rollup.blockHashChainAt(2));
    }

    // -----------------------------------------------------------------------
    // deposit() tests
    // -----------------------------------------------------------------------

    function test_deposit() public {
        rollup.deposit(bytes32(uint256(0xdead)), 0, 100, bytes32(0));
        assertEq(rollup.depositCount(), 1);
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
        assertEq(rollup.nextSubmissionId(), 1);

        IntmaxRollup.Submission memory sub = rollup.getSubmission(0);
        assertEq(sub.submitter, submitter);
        assertFalse(sub.finalized);
    }

    function test_submit_revert_noBlob() public {
        vm.prank(submitter);
        vm.expectRevert(IntmaxRollup.NoBlobAttached.selector);
        rollup.submit(bytes32(0), uint32(0), bytes32(0));
    }

    // -----------------------------------------------------------------------
    // verify() tests  —  pure WHIR, no binding
    // -----------------------------------------------------------------------

    function test_verify_validProof_returnsTrue() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        _mockGroth16Pairing();
        bool result = rollup.verify(
            config, statement, whirProof, transcript,
            _dummyGroth16()
        );
        assertTrue(result);
    }

    function test_verify_invalidProof_returnsFalse() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        if (transcript.length > 10) {
            transcript[5] = bytes1(uint8(transcript[5]) ^ 0xFF);
            transcript[6] = bytes1(uint8(transcript[6]) ^ 0xFF);
        }

        _mockGroth16Pairing();
        bool result = rollup.verify(
            config, statement, whirProof, transcript,
            _dummyGroth16()
        );
        assertFalse(result);
    }

    // -----------------------------------------------------------------------
    // finalize() tests  —  full pipeline
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

        // Build ValidityPublicInputs matching on-chain state
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        // Patch WHIR statement.evaluations[0] = keccak256(validityPIs)
        _patchStatementWithPIHash(statement, vpis);

        _mockKZGBlob();
        vm.prank(submitter);
        rollup.submit(proofHash, proofLength, stateRoot);

        _mockBLSPrecompiles();
        _mockWhirVerifierTrue();
        _mockGroth16Pairing();

        rollup.finalize(
            0, _kzgBlobHash, stateRoot,
            plonky2Bytes,
            vpis,
            config, statement, whirProof, transcript,
            _dummyKZG(plonky2Bytes.length),
            _dummyGroth16()
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

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        _patchStatementWithPIHash(statement, vpis);

        _mockKZGBlob();
        vm.prank(submitter);
        rollup.submit(proofHash, proofLength, stateRoot);

        _mockBLSPrecompiles();
        _mockWhirVerifierTrue();
        _mockGroth16Pairing();

        rollup.finalize(
            0, _kzgBlobHash, stateRoot, plonky2Bytes, vpis,
            config, statement, whirProof, transcript,
            _dummyKZG(plonky2Bytes.length),
            _dummyGroth16()
        );

        vm.expectRevert(IntmaxRollup.AlreadyFinalized.selector);
        rollup.finalize(
            0, _kzgBlobHash, stateRoot, plonky2Bytes, vpis,
            config, statement, whirProof, transcript,
            _dummyKZG(plonky2Bytes.length),
            _dummyGroth16()
        );
    }

    function test_finalize_initialStateMismatch() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        bytes memory plonky2Bytes = abi.encode(config, statement, whirProof, transcript);
        bytes32 stateRoot = keccak256("state");

        // Build VPIs with wrong initialExtCommitment
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        vpis.initialExtCommitment = bytes32(uint256(0xbad));
        _patchStatementWithPIHash(statement, vpis);

        _mockKZGBlob();
        vm.prank(submitter);
        rollup.submit(keccak256(plonky2Bytes), uint32(plonky2Bytes.length), stateRoot);

        _mockBLSPrecompiles();

        vm.expectRevert(IntmaxRollup.InitialStateMismatch.selector);
        rollup.finalize(
            0, _kzgBlobHash, stateRoot, plonky2Bytes, vpis,
            config, statement, whirProof, transcript,
            _dummyKZG(plonky2Bytes.length),
            _dummyGroth16()
        );
    }

    function test_finalize_whirPIMismatch() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        bytes memory plonky2Bytes = abi.encode(config, statement, whirProof, transcript);
        bytes32 stateRoot = keccak256("state_mismatch");

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        // Do NOT patch statement — evaluations[0] won't match

        _mockKZGBlob();
        vm.prank(submitter);
        rollup.submit(keccak256(plonky2Bytes), uint32(plonky2Bytes.length), stateRoot);

        _mockBLSPrecompiles();

        vm.expectRevert(IntmaxRollup.WhirPublicInputMismatch.selector);
        rollup.finalize(
            0, _kzgBlobHash, stateRoot, plonky2Bytes, vpis,
            config, statement, whirProof, transcript,
            _dummyKZG(plonky2Bytes.length),
            _dummyGroth16()
        );
    }

    function test_finalize_notFound() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        IntmaxRollup.ValidityPublicInputs memory vpis;

        vm.expectRevert(IntmaxRollup.SubmissionNotFound.selector);
        rollup.finalize(
            999, bytes32(0), bytes32(0), "", vpis,
            config, statement, whirProof, transcript,
            _dummyKZG(0),
            _dummyGroth16()
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

    function test_gas_postBlock() public {
        uint32[] memory localIds = new uint32[](2);
        localIds[0] = 1;
        localIds[1] = 2;

        uint256 gasBefore = gasleft();
        rollup.postBlock(5, localIds, uint64(block.timestamp), bytes32(uint256(0xabc)));
        uint256 gasUsed = gasBefore - gasleft();
        console.log("postBlock() gas:", gasUsed);
    }

    function test_gas_verify() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        _mockGroth16Pairing();

        uint256 gasBefore = gasleft();
        rollup.verify(
            config, statement, whirProof, transcript,
            _dummyGroth16()
        );
        uint256 gasUsed = gasBefore - gasleft();
        console.log("verify() gas (WHIR + Groth16):", gasUsed);
    }

    function test_gas_finalize() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        bytes memory plonky2Bytes = abi.encode(config, statement, whirProof, transcript);
        bytes32 stateRoot = keccak256("gas_finalize");

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        _patchStatementWithPIHash(statement, vpis);

        _mockKZGBlob();
        vm.prank(submitter);
        rollup.submit(keccak256(plonky2Bytes), uint32(plonky2Bytes.length), stateRoot);

        _mockBLSPrecompiles();
        _mockWhirVerifierTrue();
        _mockGroth16Pairing();

        uint256 gasBefore = gasleft();
        rollup.finalize(
            0, _kzgBlobHash, stateRoot, plonky2Bytes, vpis,
            config, statement, whirProof, transcript,
            _dummyKZG(plonky2Bytes.length),
            _dummyGroth16()
        );
        uint256 gasUsed = gasBefore - gasleft();
        console.log("finalize() gas:", gasUsed);
    }
}
