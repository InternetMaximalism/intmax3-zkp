// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {IntmaxRollup, WhirVerifierWrapper} from "../src/IntmaxRollup.sol";
import {IForcedTxLogic} from "../src/IForcedTxLogic.sol";
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
    address fraudTreasury = makeAddr("fraudTreasury");

    bytes32 constant FAKE_BLOB_HASH = bytes32(uint256(0xdeadbeef));
    bytes32 constant DEFAULT_PROOF_HASH = keccak256("default_proof");
    uint32  constant DEFAULT_PROOF_LENGTH = 1024;
    bytes32 constant DEFAULT_STATE_ROOT = keccak256("default_state");

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    function _mockBlob() internal {
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = FAKE_BLOB_HASH;
        vm.blobhashes(hashes);
    }

    // -----------------------------------------------------------------------
    // Groth16 helpers — mathematically valid proofs using BN254 precompiles
    // -----------------------------------------------------------------------

    /// @dev BN254 field prime (for G1 y-coordinate negation).
    uint256 internal constant BN254_FIELD_P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @dev BN254 scalar field order (for scalar reduction before ecMul).
    uint256 internal constant BN254_SCALAR_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev BN254 G2 generator coordinates in the format expected by Groth16Verifier:
    ///      [[x.im, x.re], [y.im, y.re]]  (imaginary part first per gnark convention).
    function _g2Gen() internal pure returns (uint256[2][2] memory) {
        return [
            [uint256(0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed),
             uint256(0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2)],
            [uint256(0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa),
             uint256(0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b)]
        ];
    }

    /// @dev Groth16 VK using actual BN254 generators.
    ///      α = G1_gen, β = γ = δ = G2_gen, all IC[i] = G1_gen (9 points for 8 pubInputs).
    ///      This VK is consistent with _groth16ProofFor() — proofs built for this VK
    ///      satisfy the pairing equation exactly.
    function _groth16Vk() internal pure returns (Groth16Verifier.VerifyingKey memory vk) {
        vk.alpha = [uint256(1), uint256(2)];   // BN254 G1 generator
        vk.beta  = _g2Gen();
        vk.gamma = _g2Gen();
        vk.delta = _g2Gen();
        vk.ic = new uint256[2][](9);           // IC[0..8] for 8 public inputs
        for (uint256 i = 0; i < 9; i++) {
            vk.ic[i] = [uint256(1), uint256(2)];  // G1 generator
        }
    }

    /// @dev Compute a Groth16 proof whose pairing check passes for the given 8 pubInputs
    ///      under the VK produced by _groth16Vk().
    ///
    ///      Construction:
    ///        proof.a = G1_gen, proof.b = G2_gen
    ///        vkX = IC[0] + Σ(inputs[i] · IC[i+1])
    ///            = (1 + Σ inputs[i]) · G1_gen          (since all IC[j] = G1_gen)
    ///            = S · G1_gen   where S = 1 + Σ inputs[i] mod r
    ///        proof.c = −vkX = (vkX.x, p − vkX.y)
    ///
    ///      Pairing equation:
    ///        e(−A, B) · e(α, β) · e(vkX, γ) · e(C, δ)
    ///        = e(−G1,G2) · e(G1,G2) · e(S·G1,G2) · e(−S·G1,G2)
    ///        = 1 · 1 = 1  ✓
    function _groth16ProofFor(uint256[] memory inputs)
        internal view returns (Groth16Verifier.Proof memory proof)
    {
        uint256 S = 1;
        for (uint256 i = 0; i < inputs.length; i++) {
            S = addmod(S, inputs[i], BN254_SCALAR_R);
        }
        // vkX = S · G1_gen via ecMul precompile (0x07)
        uint256[3] memory mIn;
        mIn[0] = 1; mIn[1] = 2; mIn[2] = S;
        uint256[2] memory vkX;
        bool ok;
        assembly { ok := staticcall(gas(), 0x07, mIn, 0x60, vkX, 0x40) }
        require(ok, "ecMul failed in _groth16ProofFor");

        proof.a = [uint256(1), uint256(2)];
        proof.b = _g2Gen();
        proof.c = [vkX[0], BN254_FIELD_P - vkX[1]];  // −vkX
    }

    /// @dev Groth16 params with all-zero pubInputs and a valid pairing proof.
    function _groth16() internal view returns (IntmaxRollup.Groth16Params memory) {
        uint256[] memory inputs = new uint256[](8);
        return IntmaxRollup.Groth16Params({proof: _groth16ProofFor(inputs), pubInputs: inputs});
    }

    /// @dev Compute keccak256(ValidityPublicInputs) — same layout as the contract's _computeValidityPIHash.
    function _computePIHash(IntmaxRollup.ValidityPublicInputs memory pis) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            pis.initialBlockNumber,
            pis.initialBlockChain,
            pis.initialExtCommitment,
            pis.finalBlockNumber,
            pis.finalBlockChain,
            pis.finalExtCommitment,
            pis.prover
        ));
    }

    /// @dev Groth16 params with pubInputs = piHash split into 8 big-endian u32 limbs
    ///      and proof.c computed to satisfy the pairing equation for those inputs.
    function _groth16WithPIHash(bytes32 piHash) internal view returns (IntmaxRollup.Groth16Params memory) {
        uint256[] memory inputs = new uint256[](8);
        uint256 h = uint256(piHash);
        for (uint256 i = 0; i < 8; i++) {
            inputs[i] = (h >> (224 - i * 32)) & 0xFFFFFFFF;
        }
        return IntmaxRollup.Groth16Params({proof: _groth16ProofFor(inputs), pubInputs: inputs});
    }

    // -----------------------------------------------------------------------
    // KZG helpers — EIP-2537 BLS12-381 multi-point opening
    // -----------------------------------------------------------------------

    /// @dev BLS12-381 scalar field order r.
    uint256 internal constant BLS12_SCALAR_R =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    /// @dev BLS12-381 G1 generator in EIP-2537 128-byte uncompressed format.
    function _bls12G1GenBytes() internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f",
            hex"c3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            hex"0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4",
            hex"fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
        );
    }

    /// @dev BLS12-381 G2 generator in EIP-2537 256-byte format (identical to BlobKZGVerifier.G2_GENERATOR).
    function _bls12G2GenBytes() internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65",
            hex"596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
            hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051",
            hex"c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
            hex"000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a",
            hex"adfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
            hex"000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99",
            hex"cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
        );
    }

    /// @dev Compress a BLS12-381 G1 point from EIP-2537 128-byte format to 48-byte format.
    ///      EIP-2537 layout: [16 zero | 48-byte x | 16 zero | 48-byte y]
    ///      Compressed: bit 7 of byte 0 = 1 (compressed), bit 6 = sign (y > (q-1)/2).
    function _compressG1(bytes memory pt128) internal pure returns (bytes memory c48) {
        require(pt128.length == 128, "compressG1: bad length");
        bytes32 x0; bytes32 x1; bytes32 y0; bytes32 y1;
        assembly {
            let p := add(pt128, 32)
            x0 := mload(add(p, 16))
            x1 := mload(add(p, 48))
            y0 := mload(add(p, 80))
            y1 := mload(add(p, 112))
        }
        // (q-1)/2 in two parts: first 32 bytes and last 16 bytes of the 48-byte value
        bytes32 halfQ0 = 0x0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b12;
        bytes16 halfQ1 = bytes16(0x0f55ffff58a9ffffdcff7fffffffd555);
        bytes16 yEnd   = bytes16(y1);
        bool signBit = (y0 > halfQ0) || (y0 == halfQ0 && yEnd > halfQ1);

        c48 = abi.encodePacked(x0, bytes16(x1));
        c48[0] = bytes1(uint8(c48[0]) | 0x80 | (signBit ? uint8(0x20) : uint8(0)));
    }

    /// @dev Memory version of IntmaxRollup._toFieldElements — must match the contract exactly.
    ///      FIELD_MASK = type(uint256).max >> 3  (top 3 bits cleared, matching IntmaxRollup).
    function _toFieldElementsMem(bytes memory data) internal pure returns (bytes32[] memory fes) {
        uint256 FIELD_MASK = type(uint256).max >> 3;
        uint256 n = (data.length + 31) / 32;
        fes = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 word;
            uint256 off = i * 32;
            uint256 rem = data.length - off;
            if (rem >= 32) {
                assembly { word := mload(add(add(data, 32), off)) }
            } else {
                bytes memory tmp = new bytes(32);
                for (uint256 j = 0; j < rem; j++) { tmp[j] = data[off + j]; }
                assembly { word := mload(add(tmp, 32)) }
            }
            fes[i] = bytes32(uint256(word) & FIELD_MASK);
        }
    }

    /// @dev Compute a valid KZG multi-point opening proof for any proofBytes.
    ///
    ///      Construction: all Lagrange basis points = G1_gen, so I(τ) = S·G1_gen.
    ///        C = (S+1)·G1_gen, π = G1_gen, Z₂ = G2_gen.
    ///        lhs = C − I(τ) = G1_gen
    ///        e(G1_gen, G2_gen) · e(−G1_gen, G2_gen) = 1  ✓
    function _computeKZGProof(bytes memory proofBytes)
        internal view returns (KZGProof memory kzg, bytes32 blobHash)
    {
        bytes32[] memory fes = _toFieldElementsMem(proofBytes);
        uint256 N = fes.length;

        uint256 S = 0;
        for (uint256 i = 0; i < N; i++) {
            S = addmod(S, uint256(fes[i]), BLS12_SCALAR_R);
        }
        uint256 Sp1 = addmod(S, 1, BLS12_SCALAR_R);

        bytes memory g1gen = _bls12G1GenBytes();
        // G1MSM is at 0x0c in Foundry 1.5.x (spec says 0x0d)
        (bool ok1, bytes memory commitment128) = address(0x0c).staticcall(
            abi.encodePacked(g1gen, bytes32(Sp1))
        );
        require(ok1 && commitment128.length == 128, "KZGProof: G1MSM C failed");

        bytes memory commitment48 = _compressG1(commitment128);
        (bool ok2, bytes memory hb) = address(0x02).staticcall(commitment48);
        require(ok2 && hb.length >= 32, "KZGProof: sha256 failed");
        blobHash = bytes32((uint256(0x01) << 248) |
            (uint256(bytes32(hb)) & (type(uint256).max >> 8)));

        bytes memory lagrangeBasis = new bytes(N * 128);
        for (uint256 i = 0; i < N; i++) {
            assembly {
                let src := add(g1gen, 32)
                let dst := add(add(lagrangeBasis, 32), mul(i, 128))
                mstore(dst,          mload(src))
                mstore(add(dst, 32), mload(add(src, 32)))
                mstore(add(dst, 64), mload(add(src, 64)))
                mstore(add(dst, 96), mload(add(src, 96)))
            }
        }

        kzg = KZGProof({
            kzgCommitment48: commitment48,
            kzgCommitmentG1: commitment128,
            openingProof:    g1gen,
            vanishingG2:     _bls12G2GenBytes(),
            lagrangeBasisG1: lagrangeBasis
        });
    }

    /// @dev Build a valid KZG proof for proofBytes, post the batch, and return (kzg, blobHash).
    function _postWithKZG(
        IntmaxRollup.SubBlock[] memory batch,
        bytes memory proofBytes,
        bytes32 stateRoot,
        address poster
    ) internal returns (KZGProof memory kzg, bytes32 blobHash) {
        (kzg, blobHash) = _computeKZGProof(proofBytes);
        bytes32[] memory hs = new bytes32[](1);
        hs[0] = blobHash;
        vm.blobhashes(hs);
        vm.prank(poster);
        rollup.postBlockAndSubmit{value: 1 ether}(
            batch, keccak256(proofBytes), uint32(proofBytes.length), stateRoot
        );
    }

    function _loadWhirFixture(string memory filename)
        internal
        view
        returns (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        )
    {
        string memory json = vm.readFile(filename);
        bytes memory parsed = vm.parseJson(json);
        JSONWhirProof memory jsonProof = abi.decode(parsed, (JSONWhirProof));

        config     = JSONUtils.jsonWhirConfigToWhirConfig(jsonProof.config);
        statement  = JSONUtils.jsonStatementToStatement(jsonProof.statement);
        whirProof  = JSONUtils.jsonWhirProofToWhirProof(jsonProof);
        transcript = jsonProof.arthur.transcript;
    }

    /// @dev Load the sol-whir sample fixture (for tests that do NOT reach WHIR-piHash binding).
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
        return _loadWhirFixture(string.concat(
            vm.projectRoot(),
            "/lib/sol-whir/test/data/whir/",
            "proof_16_4_1_ConjectureList_30_6_80_ProverHelps.json"
        ));
    }

    /// @dev Load the INTMAX3 WHIR fixture where evaluations[0] = piHash (reduced mod BN254.R_MOD).
    ///      Used by finalize tests that require the WHIR-Groth16 piHash binding check.
    function loadIntmax3Proof()
        internal
        view
        returns (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        )
    {
        return _loadWhirFixture(string.concat(
            vm.projectRoot(),
            "/test/data/whir/intmax3_whir_fixture.json"
        ));
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

        // Load WHIR config from test data and compute its hash for the constructor.
        (WhirConfig memory whirCfg,,,) = loadProof();
        bytes32 cfgHash = keccak256(abi.encode(whirCfg));

        rollup = new IntmaxRollup(verifierWrapper, fraudTreasury, _groth16Vk(), cfgHash);

        vm.deal(submitter, 10 ether);
        vm.deal(aggregator, 10 ether);
        vm.deal(fraudTreasury, 0);

    }

    // -----------------------------------------------------------------------
    // Helper: build SubBlock arrays
    // -----------------------------------------------------------------------

    function _makeSubBlock(
        uint32 aggId, uint64 ts, bytes32 txRoot, uint32[] memory ids
    ) internal pure returns (IntmaxRollup.SubBlock memory) {
        return IntmaxRollup.SubBlock({
            aggregatorId: aggId,
            timestamp: ts,
            txTreeRoot: txRoot,
            localIds: ids
        });
    }

    function _singleBlockBatch(
        uint32 aggId, uint32[] memory ids, uint64 ts, bytes32 txRoot
    ) internal pure returns (IntmaxRollup.SubBlock[] memory batch) {
        batch = new IntmaxRollup.SubBlock[](1);
        batch[0] = _makeSubBlock(aggId, ts, txRoot, ids);
    }

    function _postAndSubmit(
        IntmaxRollup.SubBlock[] memory batch,
        bytes32 proofHash,
        uint32 proofLength,
        bytes32 stateRoot
    ) internal {
        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(batch, proofHash, proofLength, stateRoot);
    }

    function _postAndSubmitDefault(IntmaxRollup.SubBlock[] memory batch) internal {
        _postAndSubmit(batch, DEFAULT_PROOF_HASH, DEFAULT_PROOF_LENGTH, DEFAULT_STATE_ROOT);
    }

    // -----------------------------------------------------------------------
    // postBlock() tests — batched sub-blocks
    // -----------------------------------------------------------------------

    function test_postBlock_singleSubBlock() public {
        uint32[] memory localIds = new uint32[](2);
        localIds[0] = 1;
        localIds[1] = 2;

        vm.prank(aggregator);
        _postAndSubmitDefault(_singleBlockBatch(5, localIds, uint64(block.timestamp), bytes32(uint256(0xabc))));

        assertEq(rollup.blockNumber(), 1);
        assertEq(rollup.postingRound(), 1);
        assertTrue(rollup.blockHashChain() != bytes32(0));
        assertEq(rollup.blockHashChainAt(1), rollup.blockHashChain());
    }

    function test_postBlock_batchOf3() public {
        IntmaxRollup.SubBlock[] memory batch = new IntmaxRollup.SubBlock[](3);
        for (uint256 i = 0; i < 3; i++) {
            uint32[] memory ids = new uint32[](1);
            ids[0] = uint32(i + 1);
            batch[i] = _makeSubBlock(1, uint64(100 + i * 5), bytes32(uint256(0x100 + i)), ids);
        }

        _postAndSubmitDefault(batch);

        // 3 sub-blocks → blockNumber = 3
        assertEq(rollup.blockNumber(), 3);
        assertEq(rollup.postingRound(), 1);
        // Only the last block number has a snapshot
        assertEq(rollup.blockHashChainAt(3), rollup.blockHashChain());
        // Intermediate block numbers have no snapshot
        assertEq(rollup.blockHashChainAt(1), bytes32(0));
        assertEq(rollup.blockHashChainAt(2), bytes32(0));
    }

    function test_postBlock_twoRounds() public {
        // Round 1: 2 sub-blocks
        IntmaxRollup.SubBlock[] memory batch1 = new IntmaxRollup.SubBlock[](2);
        for (uint256 i = 0; i < 2; i++) {
            uint32[] memory ids = new uint32[](1);
            ids[0] = uint32(i + 1);
            batch1[i] = _makeSubBlock(1, uint64(100 + i), bytes32(uint256(0x10 + i)), ids);
        }
        _postAndSubmitDefault(batch1);
        bytes32 hashAfterRound1 = rollup.blockHashChain();

        // Round 2: 3 sub-blocks
        IntmaxRollup.SubBlock[] memory batch2 = new IntmaxRollup.SubBlock[](3);
        for (uint256 i = 0; i < 3; i++) {
            uint32[] memory ids = new uint32[](2);
            ids[0] = uint32(10 + i);
            ids[1] = uint32(20 + i);
            batch2[i] = _makeSubBlock(2, uint64(200 + i), bytes32(uint256(0x20 + i)), ids);
        }
        _postAndSubmitDefault(batch2);

        assertEq(rollup.blockNumber(), 5);
        assertEq(rollup.postingRound(), 2);
        // Round 1 snapshot at block 2, round 2 snapshot at block 5
        assertEq(rollup.blockHashChainAt(2), hashAfterRound1);
        assertEq(rollup.blockHashChainAt(5), rollup.blockHashChain());
        assertTrue(rollup.blockHashChainAt(2) != rollup.blockHashChainAt(5));
    }

    function test_postBlock_emptyBatch_reverts() public {
        IntmaxRollup.SubBlock[] memory empty = new IntmaxRollup.SubBlock[](0);
        vm.expectRevert(IntmaxRollup.EmptyBatch.selector);
        _postAndSubmitDefault(empty);
    }

    function test_postBlock_requiresStake() public {
        uint32[] memory ids = new uint32[](1);
        ids[0] = 42;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(
            5,
            ids,
            uint64(block.timestamp),
            bytes32(uint256(0x1234))
        );

        _mockBlob();
        vm.prank(aggregator);
        vm.expectRevert(IntmaxRollup.InvalidStakeAmount.selector);
        rollup.postBlockAndSubmit(batch, DEFAULT_PROOF_HASH, DEFAULT_PROOF_LENGTH, DEFAULT_STATE_ROOT);
    }

    // -----------------------------------------------------------------------
    // deposit() tests
    // -----------------------------------------------------------------------

    function test_deposit() public {
        rollup.deposit(bytes32(uint256(0xdead)), 0, 100, bytes32(0));
        assertEq(rollup.depositCount(), 1);
    }

    // -----------------------------------------------------------------------
    // postBlockAndSubmit() tests
    // -----------------------------------------------------------------------

    function test_postBlockAndSubmit() public {
        bytes32 proofHash   = keccak256("plonky2_proof_data");
        uint32  proofLength = 1024;
        bytes32 stateRoot   = keccak256("state_1");

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(
            1,
            ids,
            uint64(block.timestamp),
            bytes32(uint256(0xabc))
        );

        vm.prank(submitter);
        _postAndSubmit(batch, proofHash, proofLength, stateRoot);

        bytes32 expectedCommitment = keccak256(
            abi.encodePacked(FAKE_BLOB_HASH, proofHash, proofLength, stateRoot)
        );
        assertEq(rollup.getCommitment(0), expectedCommitment);
        assertEq(rollup.nextSubmissionId(), 1);

        IntmaxRollup.Submission memory sub = rollup.getSubmission(0);
        assertEq(sub.submitter, submitter);
        assertFalse(sub.finalized);
    }

    function test_postBlockAndSubmit_revert_noBlob() public {
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(
            1,
            ids,
            uint64(block.timestamp),
            bytes32(uint256(0xdef))
        );
        vm.prank(submitter);
        vm.expectRevert(IntmaxRollup.NoBlobAttached.selector);
        rollup.postBlockAndSubmit{value: 1 ether}(batch, bytes32(0), uint32(0), bytes32(0));
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

        bool result = rollup.verify(
            config, statement, whirProof, transcript,
            _groth16()
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

        bool result = rollup.verify(
            config, statement, whirProof, transcript,
            _groth16()
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
        ) = loadIntmax3Proof();

        bytes32 stateRoot = keccak256("finalized_state");

        // vpis computed BEFORE posting so blockHashChainAt[0]=0 and finalBlockNumber=0 always match.
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        bytes memory proofBytes = abi.encode(groth16, config, statement, whirProof, transcript);
        bytes32 proofHash   = keccak256(proofBytes);
        uint32  proofLength = uint32(proofBytes.length);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(1, ids, 100, bytes32(uint256(0xabc)));

        uint256 stakeBalanceBefore = submitter.balance;
        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);
        assertEq(submitter.balance, stakeBalanceBefore - 1 ether, "stake should lock 1 ETH");

        bool ok = rollup.finalize(
            0, blobHash, stateRoot,
            proofBytes,
            vpis,
            config, statement, whirProof, transcript,
            kzg,
            groth16
        );

        assertTrue(ok);
        assertTrue(rollup.isFinalized(0));
        assertEq(rollup.latestFinalizedStateRoot(), stateRoot);
        // Pull-payment: stake credited to pendingWithdrawals, not pushed
        assertEq(rollup.pendingWithdrawals(submitter), 1 ether, "stake should be credited");
        vm.prank(submitter);
        rollup.withdraw();
        assertEq(submitter.balance, stakeBalanceBefore, "stake should be withdrawn");
    }

    function test_finalize_alreadyFinalized() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadIntmax3Proof();

        bytes32 stateRoot = keccak256("finalized_state");

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        bytes memory proofBytes = abi.encode(groth16, config, statement, whirProof, transcript);
        bytes32 proofHash   = keccak256(proofBytes);
        uint32  proofLength = uint32(proofBytes.length);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 7;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(2, ids, 200, bytes32(uint256(0x444)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        assertTrue(rollup.finalize(
            0, blobHash, stateRoot, proofBytes, vpis,
            config, statement, whirProof, transcript,
            kzg, groth16
        ));

        // Second call returns false (already finalized)
        assertFalse(rollup.finalize(
            0, blobHash, stateRoot, proofBytes, vpis,
            config, statement, whirProof, transcript,
            kzg, groth16
        ));
    }

    function test_finalize_initialStateMismatch() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        bytes32 stateRoot = keccak256("state");

        // Build VPIs with wrong initialExtCommitment (before posting so other fields are correct)
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        vpis.initialExtCommitment = bytes32(uint256(0xbad));
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        bytes memory proofBytes = abi.encode(groth16, config, statement, whirProof, transcript);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 9;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(3, ids, 300, bytes32(uint256(0x555)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        // Returns false (initial state mismatch — initialExtCommitment = 0xbad ≠ latestFinalizedStateRoot = 0)
        assertFalse(rollup.finalize(
            0, blobHash, stateRoot, proofBytes, vpis,
            config, statement, whirProof, transcript,
            kzg,
            groth16
        ));
    }

    /// @notice finalize() returns false when groth16.pubInputs[0] != keccak256(ValidityPublicInputs).
    function test_finalize_wrongGroth16PubInputs() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        bytes32 stateRoot = keccak256("state_mismatch");

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        // pubInputs[0] = 1, which is != keccak256(vpis) → PI binding check fails
        IntmaxRollup.Groth16Params memory groth16 = _groth16(); // pubInputs[0] = 1

        bytes memory proofBytes = abi.encode(groth16, config, statement, whirProof, transcript);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 11;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(4, ids, 400, bytes32(uint256(0x777)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        // Returns false: groth16.pubInputs[0] = 1 ≠ keccak256(vpis)
        assertFalse(rollup.finalize(
            0, blobHash, stateRoot, proofBytes, vpis,
            config, statement, whirProof, transcript,
            kzg,
            groth16
        ));
    }

    function test_finalize_notFound() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        IntmaxRollup.ValidityPublicInputs memory vpis;

        // Returns false (submission not found) — KZG is never verified but must be non-dummy
        (KZGProof memory kzg, ) = _computeKZGProof(new bytes(32));
        assertFalse(rollup.finalize(
            999, bytes32(0), bytes32(0), "", vpis,
            config, statement, whirProof, transcript,
            kzg,
            _groth16()
        ));
    }

    // -----------------------------------------------------------------------
    // fraudProof() tests — prove a submission is invalid
    // -----------------------------------------------------------------------

    function test_fraudProof_invalidProof_confirmedFraud() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes memory proofBytes = abi.encode(groth16, config, statement, whirProof, transcript);
        bytes32 proofHash   = keccak256(proofBytes);
        uint32  proofLength = uint32(proofBytes.length);
        bytes32 stateRoot   = keccak256("bad_state");

        uint32[] memory ids = new uint32[](1);
        ids[0] = 21;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(5, ids, 500, bytes32(uint256(0x888)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        // groth16.pubInputs[0..7] = 0 ≠ keccak256(vpis) → fraud confirmed via condition (b)

        address reporter = makeAddr("reporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        bool fraudConfirmed = rollup.fraudProof(
            0, blobHash, stateRoot, proofBytes, vpis,
            config, statement, whirProof, transcript,
            kzg, groth16
        );
        assertTrue(fraudConfirmed, "Fraud should be confirmed for invalid proof");
    }

    function test_fraudProof_validProof_noFraud() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes memory proofBytes = abi.encode(groth16, config, statement, whirProof, transcript);
        bytes32 proofHash   = keccak256(proofBytes);
        uint32  proofLength = uint32(proofBytes.length);
        bytes32 stateRoot   = keccak256("valid_state");

        uint32[] memory ids = new uint32[](1);
        ids[0] = 31;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(6, ids, 600, bytes32(uint256(0x999)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        _patchStatementWithPIHash(statement, vpis);


        // Fraud NOT confirmed: proof params binding fails (statement was patched after creating
        // proofBytes), so _verifyFraud returns false. Valid proofs cannot be falsely accused.
        bool fraudConfirmed = rollup.fraudProof(
            0, blobHash, stateRoot, proofBytes, vpis,
            config, statement, whirProof, transcript,
            kzg, groth16
        );
        assertFalse(fraudConfirmed, "No fraud for valid proof");
    }

    function test_fraudProof_bindingFails_rejected() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes memory proofBytes = abi.encode(groth16, config, statement, whirProof, transcript);
        bytes32 stateRoot = keccak256("state");

        IntmaxRollup.ValidityPublicInputs memory vpis;

        // Submit with DIFFERENT proof hash — commitment check will fail
        uint32[] memory ids2 = new uint32[](1);
        ids2[0] = 32;
        IntmaxRollup.SubBlock[] memory batch2 = _singleBlockBatch(7, ids2, 610, bytes32(uint256(0xaaa)));
        // Compute a real KZG proof so blobHash is a valid versioned hash.
        // The commitment stored at post time uses keccak256("wrong") as proofHash, so
        // fraudProof (which recomputes from proofBytes) will fail the binding check.
        (KZGProof memory kzg, bytes32 blobHash) = _computeKZGProof(proofBytes);
        bytes32[] memory bh2 = new bytes32[](1);
        bh2[0] = blobHash;
        vm.blobhashes(bh2);
        vm.prank(submitter);
        rollup.postBlockAndSubmit{value: 1 ether}(batch2, keccak256("wrong"), uint32(999), stateRoot);

        // fraudProof returns false: commitment check failed
        // (stored commitment used keccak256("wrong")/999, but proofBytes has different hash/length)
        bool fraudConfirmed = rollup.fraudProof(
            0, blobHash, stateRoot, proofBytes, vpis,
            config, statement, whirProof, transcript,
            kzg, groth16
        );
        assertFalse(fraudConfirmed, "Can't confirm fraud if binding fails");
    }

    function test_blockDepositAndForcedHash_persistAndRollback() public {
        // Register forced tx logic and queue a tx so we have a non-zero accumulator.
        MockForcedTxLogic mockLogic = new MockForcedTxLogic(bytes32(uint256(0xabc)));
        rollup.registerForcedTxLogic(42, address(mockLogic));
        rollup.queueForcedTx(42);

        // Warm up two posting rounds so the forced tx matures on round 3.
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 100, bytes32(uint256(0x101))));
        bytes32 forcedSnapshotRound1 = rollup.forcedTxAccumulatorAtRound(1);
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 200, bytes32(uint256(0x202))));

        uint256 badSubmissionId = rollup.nextSubmissionId();

        // Queue a deposit so the target block picks it up.
        rollup.deposit(bytes32(uint256(0xdeadbeef)), 0, 100, bytes32(uint256(0xbeef)));

        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes memory proofBytes = abi.encode(groth16, config, statement, whirProof, transcript);
        bytes32 proofHash = keccak256(proofBytes);
        uint32 proofLength = uint32(proofBytes.length);
        bytes32 stateRoot = keccak256("fraud_state_with_inputs");

        uint32[] memory idsBad = new uint32[](1);
        idsBad[0] = 9;
        IntmaxRollup.SubBlock[] memory badBatch = _singleBlockBatch(3, idsBad, 300, bytes32(uint256(0x303)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(badBatch, proofBytes, stateRoot, submitter);

        uint64 targetBlock = rollup.blockNumber();
        bytes32 storedDepositHash = rollup.blockDepositHash(targetBlock);
        assertTrue(storedDepositHash != bytes32(0), "deposit hash must be recorded");
        assertEq(
            rollup.blockForcedTxHash(targetBlock),
            forcedSnapshotRound1,
            "forced tx hash should use matured snapshot"
        );

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        // groth16.pubInputs[0..7] = 0 ≠ keccak256(vpis) → fraud confirmed via condition (b)

        address reporter = makeAddr("reporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        bool fraudConfirmed = rollup.fraudProof(
            badSubmissionId,
            blobHash,
            stateRoot,
            proofBytes,
            vpis,
            config,
            statement,
            whirProof,
            transcript,
            kzg,
            groth16
        );
        assertTrue(fraudConfirmed, "fraud should be confirmed");

        assertEq(rollup.blockDepositHash(targetBlock), bytes32(0), "deposit hash cleared on rollback");
        assertEq(rollup.blockForcedTxHash(targetBlock), bytes32(0), "forced hash cleared on rollback");
    }

    function test_fraudProof_slashesCascadeAndRollsBack() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes memory proofBytes = abi.encode(groth16, config, statement, whirProof, transcript);
        bytes32 proofHash   = keccak256(proofBytes);
        uint32  proofLength = uint32(proofBytes.length);
        bytes32 badState    = keccak256("fraud_state");

        uint32[] memory idsBad = new uint32[](1);
        idsBad[0] = 77;
        IntmaxRollup.SubBlock[] memory badBatch = _singleBlockBatch(9, idsBad, 800, bytes32(uint256(0x1111)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(badBatch, proofBytes, badState, submitter);

        // Post a second batch so the fraud rollback must invalidate it too.
        uint32[] memory idsGood = new uint32[](1);
        idsGood[0] = 88;
        IntmaxRollup.SubBlock[] memory goodBatch = _singleBlockBatch(10, idsGood, 810, bytes32(uint256(0x2222)));
        vm.prank(aggregator);
        _postAndSubmitDefault(goodBatch);

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(badState);
        // groth16.pubInputs[0..7] = 0 ≠ keccak256(vpis) → fraud confirmed via condition (b)

        address reporter = makeAddr("reporter");
        vm.deal(reporter, 1 ether);
        uint256 reporterBefore = reporter.balance;
        uint256 treasuryBefore = fraudTreasury.balance;

        assertEq(address(rollup).balance, 2 ether, "two stakes should be locked");

        vm.prank(reporter);
        bool fraudConfirmed = rollup.fraudProof(
            0, blobHash, badState, proofBytes, vpis,
            config, statement, whirProof, transcript,
            kzg, groth16
        );
        assertTrue(fraudConfirmed, "Fraud should be confirmed");

        uint256 expectedReward = 2 * 0.9 ether;
        uint256 expectedTreasury = 2 * 0.1 ether;
        // Pull-payment: rewards credited to pendingWithdrawals
        assertEq(rollup.pendingWithdrawals(reporter), expectedReward, "Reporter reward mismatch");
        assertEq(rollup.pendingWithdrawals(fraudTreasury), expectedTreasury, "Treasury share mismatch");
        // Contract still holds the funds until withdraw()
        assertEq(address(rollup).balance, expectedReward + expectedTreasury, "Stakes in escrow");
        vm.prank(reporter);
        rollup.withdraw();
        assertEq(reporter.balance, reporterBefore + expectedReward, "Reporter withdrew");
        // (treasury is an EOA in this test, so it can also withdraw)
        vm.prank(fraudTreasury);
        rollup.withdraw();
        assertEq(fraudTreasury.balance, treasuryBefore + expectedTreasury, "Treasury withdrew");
        assertEq(address(rollup).balance, 0, "All funds withdrawn");
        assertEq(rollup.blockNumber(), 0, "Blocks should roll back");
        assertEq(rollup.nextSubmissionId(), 0, "Submissions truncated");
        assertEq(rollup.postingRound(), 0, "Posting round reset");
        assertEq(rollup.blockHashChain(), bytes32(0), "Hash chain reset");
    }

    /// @notice E2E fraud proof: corrupted WHIR transcript committed in the blob.
    ///         The real WhirVerifierWrapper rejects it, confirming fraud.
    ///         vpis computed BEFORE posting so finalBlockNumber=0 and
    ///         blockHashChainAt[0]=0 always match.
    function test_fraudProof_e2e_realWhir_corruptedData() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        // Corrupt the transcript — flip every byte
        bytes memory corruptedTranscript = new bytes(transcript.length);
        for (uint256 i = 0; i < transcript.length; i++) {
            corruptedTranscript[i] = bytes1(uint8(transcript[i]) ^ 0xFF);
        }

        // Compute vpis BEFORE posting (initial state: everything zero).
        // blockHashChainAt[0] stays 0 forever, so PI binding will pass.
        bytes32 stateRoot = keccak256("e2e_fraud_state");
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);

        // Use correct piHash so Groth16 pubInputs condition (b) passes.
        // statement.evaluations[0] is the sol-whir fixture value (≠ piHash), so fraud is
        // confirmed at condition (b.5): WHIR statement not bound to the same ValidityPublicInputs.
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        // Encode corrupted transcript INTO proofBytes so params binding passes
        bytes memory proofBytes = abi.encode(groth16, config, statement, whirProof, corruptedTranscript);
        bytes32 proofHash = keccak256(proofBytes);
        uint32 proofLength = uint32(proofBytes.length);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 50;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(11, ids, 900, bytes32(uint256(0xE2E)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        // NOTE: WHIR verifier is NOT mocked — it runs for real on corrupted transcript!

        address reporter = makeAddr("e2e_reporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        bool fraudConfirmed = rollup.fraudProof(
            0, blobHash, stateRoot, proofBytes, vpis,
            config, statement, whirProof, corruptedTranscript,
            kzg, groth16
        );
        assertTrue(fraudConfirmed, "Fraud: real WHIR rejects corrupted transcript");

        IntmaxRollup.Submission memory sub = rollup.getSubmission(0);
        assertEq(sub.commitment, bytes32(0), "Submission deleted after fraud");
    }

    /// @notice E2E fraud proof: corrupted WHIR proof answers + random transcript.
    ///         The real WHIR verifier rejects them, confirming fraud.
    function test_fraudProof_e2e_realWhir_randomBytes() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();

        // Corrupt WHIR proof answers
        if (whirProof.answers.length > 0 && whirProof.answers[0].length > 0) {
            whirProof.answers[0][0] = new bytes32[](1);
            whirProof.answers[0][0][0] = bytes32(uint256(0xDEADBEEFCAFEBABE));
        }
        bytes memory randomTranscript = hex"0000111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF";

        // Compute vpis BEFORE posting (initial zero state)
        bytes32 stateRoot = keccak256("random_bytes_fraud");
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);

        // Use correct piHash so Groth16 pubInputs condition (b) passes.
        // statement.evaluations[0] is the sol-whir fixture value (≠ piHash), so fraud is
        // confirmed at condition (b.5): WHIR statement not bound to the same ValidityPublicInputs.
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        // Encode corrupted proof INTO proofBytes
        bytes memory proofBytes = abi.encode(groth16, config, statement, whirProof, randomTranscript);
        bytes32 proofHash = keccak256(proofBytes);
        uint32 proofLength = uint32(proofBytes.length);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 60;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(12, ids, 950, bytes32(uint256(0xBAD)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        // Real WHIR verifier — no mock!

        address reporter = makeAddr("random_reporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        bool fraudConfirmed = rollup.fraudProof(
            0, blobHash, stateRoot, proofBytes, vpis,
            config, statement, whirProof, randomTranscript,
            kzg, groth16
        );
        assertTrue(fraudConfirmed, "Fraud: real WHIR rejects corrupted proof");

        IntmaxRollup.Submission memory sub = rollup.getSubmission(0);
        assertEq(sub.commitment, bytes32(0), "Submission deleted after fraud");
    }

    function test_fraudProof_revertsWhenFinalized() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadIntmax3Proof();

        bytes32 stateRoot = keccak256("finalized_state");

        // vpis computed BEFORE posting so proof params binding is consistent.
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        bytes memory proofBytes = abi.encode(groth16, config, statement, whirProof, transcript);
        bytes32 proofHash   = keccak256(proofBytes);
        uint32  proofLength = uint32(proofBytes.length);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 123;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(12, ids, 900, bytes32(uint256(0x3434)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        assertTrue(
            rollup.finalize(
                0, blobHash, stateRoot, proofBytes, vpis,
                config, statement, whirProof, transcript,
                kzg,
                groth16
            ),
            "finalize should succeed"
        );

        address watcher = makeAddr("watcher");
        vm.deal(watcher, 1 ether);
        vm.prank(watcher);
        vm.expectRevert(IntmaxRollup.AlreadyFinalized.selector);
        rollup.fraudProof(
            0, blobHash, stateRoot, proofBytes, vpis,
            config, statement, whirProof, transcript,
            kzg,
            groth16
        );
    }

    // -----------------------------------------------------------------------
    // Gas measurement
    // -----------------------------------------------------------------------

    function test_gas_postBlockAndSubmit_single() public {
        uint32[] memory localIds = new uint32[](2);
        localIds[0] = 1;
        localIds[1] = 2;

        uint256 gasBefore = gasleft();
        _postAndSubmitDefault(_singleBlockBatch(5, localIds, uint64(block.timestamp), bytes32(uint256(0xabc))));
        uint256 gasUsed = gasBefore - gasleft();
        console.log("postBlockAndSubmit(1 sub-block) gas:", gasUsed);
    }

    function test_gas_postBlockAndSubmit_batch60() public {
        IntmaxRollup.SubBlock[] memory batch = new IntmaxRollup.SubBlock[](60);
        for (uint256 i = 0; i < 60; i++) {
            uint32[] memory ids = new uint32[](10);
            for (uint256 j = 0; j < 10; j++) {
                ids[j] = uint32(i * 10 + j + 1);
            }
            batch[i] = _makeSubBlock(1, uint64(100 + i * 5), bytes32(uint256(0x100 + i)), ids);
        }

        uint256 gasBefore = gasleft();
        _postAndSubmitDefault(batch);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("postBlockAndSubmit(60 sub-blocks, 10 users each) gas:", gasUsed);
        assertEq(rollup.blockNumber(), 60);
    }

    function test_gas_verify() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadProof();


        uint256 gasBefore = gasleft();
        rollup.verify(
            config, statement, whirProof, transcript,
            _groth16()
        );
        uint256 gasUsed = gasBefore - gasleft();
        console.log("verify() gas (WHIR + Groth16):", gasUsed);
    }

    // -----------------------------------------------------------------------
    // Forced TX tests
    // -----------------------------------------------------------------------

    function test_registerForcedTxLogic() public {
        MockForcedTxLogic mockLogic = new MockForcedTxLogic(bytes32(uint256(0xaaa)));
        rollup.registerForcedTxLogic(42, address(mockLogic));
        assertEq(rollup.forcedTxLogicContracts(42), address(mockLogic));
    }

    function test_registerForcedTxLogic_immutable() public {
        MockForcedTxLogic mock1 = new MockForcedTxLogic(bytes32(uint256(0xaaa)));
        MockForcedTxLogic mock2 = new MockForcedTxLogic(bytes32(uint256(0xbbb)));
        rollup.registerForcedTxLogic(42, address(mock1));

        // Second registration for same userId reverts
        vm.expectRevert(IntmaxRollup.ForcedTxLogicAlreadyRegistered.selector);
        rollup.registerForcedTxLogic(42, address(mock2));
    }

    function test_registerForcedTxLogic_rejectingContract() public {
        RevertingForcedTxLogic revertLogic = new RevertingForcedTxLogic();
        vm.expectRevert(IntmaxRollup.ForcedTxLogicNotAccepted.selector);
        rollup.registerForcedTxLogic(42, address(revertLogic));
    }

    function test_queueForcedTx_noLogicRegistered() public {
        vm.expectRevert(IntmaxRollup.NoForcedTxLogicRegistered.selector);
        rollup.queueForcedTx(999);
    }

    function test_queueForcedTx_success() public {
        // Deploy a mock logic contract that returns a valid tx hash
        MockForcedTxLogic mockLogic = new MockForcedTxLogic(bytes32(uint256(0xdeadbeef)));
        rollup.registerForcedTxLogic(42, address(mockLogic));

        rollup.queueForcedTx(42);

        assertEq(rollup.forcedTxCount(), 1);
        assertTrue(rollup.forcedTxAccumulator() != bytes32(0));
    }

    function test_queueForcedTx_returnsZero_reverts() public {
        // Deploy a mock that returns bytes32(0) = no tx to insert
        MockForcedTxLogic mockLogic = new MockForcedTxLogic(bytes32(0));
        rollup.registerForcedTxLogic(42, address(mockLogic));

        vm.expectRevert(IntmaxRollup.ForcedTxInsertFailed.selector);
        rollup.queueForcedTx(42);
    }

    function test_queueForcedTx_revertingLogic() public {
        // Deploy a mock that accepts registration but reverts on insertIntmaxTx
        RevertOnInsertLogic mockLogic = new RevertOnInsertLogic();
        rollup.registerForcedTxLogic(42, address(mockLogic));

        vm.expectRevert(IntmaxRollup.ForcedTxInsertFailed.selector);
        rollup.queueForcedTx(42);
    }

    function test_forcedTx_slotMaturation() public {
        // Queue a forced tx, then post 3 rounds. The forced tx should
        // mature at round 3 (queued before round 1, snapshot at round 1,
        // mature at round 3 = accumulatorAtRound[3-2] = accumulatorAtRound[1]).
        MockForcedTxLogic mockLogic = new MockForcedTxLogic(bytes32(uint256(0xabc)));
        rollup.registerForcedTxLogic(42, address(mockLogic));

        rollup.queueForcedTx(42);
        bytes32 accumulatorAfterQueue = rollup.forcedTxAccumulator();

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;

        // Round 1: snapshot accumulator
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 100, bytes32(uint256(0x111))));
        assertEq(rollup.forcedTxAccumulatorAtRound(1), accumulatorAfterQueue);

        // Round 2
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 200, bytes32(uint256(0x222))));

        // Round 3: mature forced txs = accumulatorAtRound[3-2] = accumulatorAtRound[1]
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 300, bytes32(uint256(0x333))));

        // Verify the accumulator was snapshotted correctly
        assertEq(rollup.forcedTxAccumulatorAtRound(1), accumulatorAfterQueue);
        assertEq(rollup.postingRound(), 3);
    }

    function test_forcedTx_hashChainAccumulation() public {
        MockForcedTxLogic mock1 = new MockForcedTxLogic(bytes32(uint256(0x111)));
        MockForcedTxLogic mock2 = new MockForcedTxLogic(bytes32(uint256(0x222)));
        rollup.registerForcedTxLogic(10, address(mock1));
        rollup.registerForcedTxLogic(20, address(mock2));

        rollup.queueForcedTx(10);
        bytes32 afterFirst = rollup.forcedTxAccumulator();

        rollup.queueForcedTx(20);
        bytes32 afterSecond = rollup.forcedTxAccumulator();

        assertEq(rollup.forcedTxCount(), 2);
        assertTrue(afterFirst != bytes32(0));
        assertTrue(afterSecond != afterFirst);

        // Verify the hash chain matches expected computation
        bytes32 expected1 = keccak256(abi.encodePacked(bytes32(0), uint64(10), bytes32(uint256(0x111))));
        assertEq(afterFirst, expected1);

        bytes32 expected2 = keccak256(abi.encodePacked(expected1, uint64(20), bytes32(uint256(0x222))));
        assertEq(afterSecond, expected2);
    }

    // -----------------------------------------------------------------------
    // Gas measurement
    // -----------------------------------------------------------------------

    function test_gas_finalize() public {
        (
            WhirConfig memory config,
            Statement memory statement,
            WhirProof memory whirProof,
            bytes memory transcript
        ) = loadIntmax3Proof();

        bytes32 stateRoot = keccak256("finalized_state");

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        bytes memory proofBytes = abi.encode(groth16, config, statement, whirProof, transcript);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 99;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(8, ids, 700, bytes32(uint256(0xbbc)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        uint256 gasBefore = gasleft();
        rollup.finalize(
            0, blobHash, stateRoot, proofBytes, vpis,
            config, statement, whirProof, transcript,
            kzg,
            groth16
        );
        uint256 gasUsed = gasBefore - gasleft();
        console.log("finalize() gas:", gasUsed);
    }

    function test_gas_registerForcedTxLogic() public {
        MockForcedTxLogic mockLogic = new MockForcedTxLogic(bytes32(uint256(0xaaa)));
        uint256 gasBefore = gasleft();
        rollup.registerForcedTxLogic(42, address(mockLogic));
        uint256 gasUsed = gasBefore - gasleft();
        console.log("registerForcedTxLogic() gas:", gasUsed);
    }

    function test_gas_queueForcedTx() public {
        MockForcedTxLogic mockLogic = new MockForcedTxLogic(bytes32(uint256(0xdeadbeef)));
        rollup.registerForcedTxLogic(42, address(mockLogic));

        uint256 gasBefore = gasleft();
        rollup.queueForcedTx(42);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("queueForcedTx() gas:", gasUsed);
    }

    function test_gas_postBlock_withForcedTx() public {
        // Queue forced tx, then measure postBlock with maturation logic
        MockForcedTxLogic mockLogic = new MockForcedTxLogic(bytes32(uint256(0xabc)));
        rollup.registerForcedTxLogic(42, address(mockLogic));
        rollup.queueForcedTx(42);

        uint32[] memory ids = new uint32[](2);
        ids[0] = 1;
        ids[1] = 2;

        // Post 3 rounds so maturation kicks in on the third
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 100, bytes32(uint256(0x111))));
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 200, bytes32(uint256(0x222))));

        uint256 gasBefore = gasleft();
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 300, bytes32(uint256(0x333))));
        uint256 gasUsed = gasBefore - gasleft();
        console.log("postBlockAndSubmit() with mature forced tx gas:", gasUsed);
    }
}

/// @dev Mock forced tx logic contract that returns a fixed tx hash.
contract MockForcedTxLogic is IForcedTxLogic {
    bytes32 private _txHash;

    constructor(bytes32 txHash) {
        _txHash = txHash;
    }

    function insertIntmaxTx() external override returns (bytes32) {
        return _txHash;
    }

    function acceptRegistration(uint64 userId) external pure override returns (uint64) {
        return userId;
    }
}

/// @dev Mock forced tx logic contract that always reverts (including registration).
contract RevertingForcedTxLogic is IForcedTxLogic {
    function insertIntmaxTx() external pure override returns (bytes32) {
        revert("intentional revert");
    }

    function acceptRegistration(uint64) external pure override returns (uint64) {
        revert("intentional revert");
    }
}

/// @dev Mock that accepts registration but reverts on insertIntmaxTx.
contract RevertOnInsertLogic is IForcedTxLogic {
    function insertIntmaxTx() external pure override returns (bytes32) {
        revert("intentional revert on insert");
    }

    function acceptRegistration(uint64 userId) external pure override returns (uint64) {
        return userId;
    }
}
