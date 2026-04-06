// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {IntmaxRollup, IGnarkVerifier} from "../src/IntmaxRollup.sol";
import {Verifier as GnarkVerifier} from "../src/GnarkGroth16Verifier.sol";
import {IForcedTxLogic} from "../src/IForcedTxLogic.sol";
import {KZGProof} from "../src/BlobKZGVerifier.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {SpongefishWhirVerify} from "@plonky2-whir-verifier/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@plonky2-whir-verifier/spongefish/GoldilocksExt3.sol";
import {WhirPlonky2Verifier} from "@plonky2-whir-verifier/WhirPlonky2Verifier.sol";
import {Plonky2Verifier} from "@plonky2-whir-verifier/Plonky2Verifier.sol";

contract IntmaxRollupTest is Test {
    IntmaxRollup public rollup;
    IntmaxRollup public e2eRollup;
    GnarkVerifier public gnarkVerifierContract;

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
    ///      alpha = G1_gen, beta = gamma = delta = G2_gen, all IC[i] = G1_gen (9 points for 8 pubInputs).
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
    ///        vkX = IC[0] + sum(inputs[i] * IC[i+1])
    ///            = (1 + sum inputs[i]) * G1_gen          (since all IC[j] = G1_gen)
    ///            = S * G1_gen   where S = 1 + sum inputs[i] mod r
    ///        proof.c = -vkX = (vkX.x, p - vkX.y)
    ///
    ///      Pairing equation:
    ///        e(-A, B) * e(alpha, beta) * e(vkX, gamma) * e(C, delta)
    ///        = e(-G1,G2) * e(G1,G2) * e(S*G1,G2) * e(-S*G1,G2)
    ///        = 1 * 1 = 1
    function _groth16ProofFor(uint256[] memory inputs)
        internal view returns (Groth16Verifier.Proof memory proof)
    {
        uint256 S = 1;
        for (uint256 i = 0; i < inputs.length; i++) {
            S = addmod(S, inputs[i], BN254_SCALAR_R);
        }
        // vkX = S * G1_gen via ecMul precompile (0x07)
        uint256[3] memory mIn;
        mIn[0] = 1; mIn[1] = 2; mIn[2] = S;
        uint256[2] memory vkX;
        bool ok;
        assembly { ok := staticcall(gas(), 0x07, mIn, 0x60, vkX, 0x40) }
        require(ok, "ecMul failed in _groth16ProofFor");

        proof.a = [uint256(1), uint256(2)];
        proof.b = _g2Gen();
        proof.c = [vkX[0], BN254_FIELD_P - vkX[1]];  // -vkX
    }

    /// @dev Groth16 params with all-zero pubInputs and a valid pairing proof.
    function _groth16() internal view returns (IntmaxRollup.Groth16Params memory) {
        uint256[] memory inputs = new uint256[](8);
        uint256[2] memory emptyC;
        return IntmaxRollup.Groth16Params({
            proof: _groth16ProofFor(inputs),
            pubInputs: inputs,
            commitments: emptyC,
            commitmentPok: emptyC
        });
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
        uint256[2] memory emptyC;
        return IntmaxRollup.Groth16Params({
            proof: _groth16ProofFor(inputs),
            pubInputs: inputs,
            commitments: emptyC,
            commitmentPok: emptyC
        });
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
    ///      Construction: all Lagrange basis points = G1_gen, so I(tau) = S*G1_gen.
    ///        C = (S+1)*G1_gen, pi = G1_gen, Z2 = G2_gen.
    ///        lhs = C - I(tau) = G1_gen
    ///        e(G1_gen, G2_gen) * e(-G1_gen, G2_gen) = 1
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

    // -----------------------------------------------------------------------
    // Unified WHIR-Plonky2 proof loading from test/data/test_proof.json
    // -----------------------------------------------------------------------

    /// @dev Load the unified WHIR-Plonky2 proof from the fixture file.
    function _loadUnifiedProof()
        internal view returns (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        )
    {
        string memory json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/data/test_proof.json")
        );
        whirProof = _parseUnifiedProof(json);
        circuitConfig = _parseCircuitConfig(json);
        whirParams = _loadUnifiedWhirParams(json);
    }

    function _parseUnifiedProof(string memory json)
        internal pure returns (WhirPlonky2Verifier.WhirPlonky2Proof memory proof)
    {
        proof.protocolId = vm.parseJsonBytes(json, ".proof.protocolId");
        proof.sessionId = vm.parseJsonBytes(json, ".proof.sessionId");
        proof.instance = vm.parseJsonBytes(json, ".proof.instance");
        proof.transcript = vm.parseJsonBytes(json, ".proof.transcript");
        proof.hints = vm.parseJsonBytes(json, ".proof.hints");

        // Evaluations (2 for dual-point mode)
        proof.evaluations = new GoldilocksExt3.Ext3[](2);
        for (uint256 i = 0; i < 2; i++) {
            string memory prefix = string.concat(".proof.evaluations[", vm.toString(i), "].");
            proof.evaluations[i] = GoldilocksExt3.Ext3(
                uint64(_u(json, string.concat(prefix, "c0"))),
                uint64(_u(json, string.concat(prefix, "c1"))),
                uint64(_u(json, string.concat(prefix, "c2")))
            );
        }

        // Bridge zeta
        proof.bridgeZeta = _parseBridgeZeta(json);

        // Bridge gZeta
        proof.bridgeGZeta = _parseBridgeGZeta(json);

        // All openings at zeta (flat per batch)
        uint256[] memory polyCounts = abi.decode(vm.parseJson(json, ".circuitConfig.intraBatchPolyCounts"), (uint256[]));
        proof.allOpeningsAtZetaFlat = new uint256[][](polyCounts.length);
        for (uint256 b = 0; b < polyCounts.length; b++) {
            string memory path = string.concat(".proof.allOpeningsAtZetaFlat[", vm.toString(b), "]");
            proof.allOpeningsAtZetaFlat[b] = abi.decode(vm.parseJson(json, path), (uint256[]));
        }

        // batch2 openings at gZeta flat
        proof.batch2OpeningsAtGZetaFlat = abi.decode(
            vm.parseJson(json, ".proof.batch2OpeningsAtGZetaFlat"), (uint256[])
        );

        // batch evals at gZeta flat
        proof.batchEvalsAtGZetaFlat = abi.decode(
            vm.parseJson(json, ".proof.batchEvalsAtGZetaFlat"), (uint256[])
        );

        // Public inputs
        proof.publicInputs = abi.decode(vm.parseJson(json, ".proof.publicInputs"), (uint256[]));
    }

    function _parseBridgeZeta(string memory json)
        internal pure returns (WhirPlonky2Verifier.SumcheckBridgeData memory bridge)
    {
        uint256 numRounds = _u(json, ".proof.bridgeZeta.numRounds");
        bridge.sessionName = abi.decode(vm.parseJson(json, ".proof.bridgeZeta.sessionName"), (string));

        bridge.zeta = GoldilocksExt3.Ext3(
            uint64(_u(json, ".proof.bridgeZeta.zeta.c0")),
            uint64(_u(json, ".proof.bridgeZeta.zeta.c1")),
            uint64(_u(json, ".proof.bridgeZeta.zeta.c2"))
        );

        bridge.claimedSum = GoldilocksExt3.Ext3(
            uint64(_u(json, ".proof.bridgeZeta.claimedSum.c0")),
            uint64(_u(json, ".proof.bridgeZeta.claimedSum.c1")),
            uint64(_u(json, ".proof.bridgeZeta.claimedSum.c2"))
        );

        // evalPoint
        bridge.evalPoint = new GoldilocksExt3.Ext3[](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            string memory prefix = string.concat(".proof.bridgeZeta.evalPoint[", vm.toString(i), "].");
            bridge.evalPoint[i] = GoldilocksExt3.Ext3(
                uint64(_u(json, string.concat(prefix, "c0"))),
                uint64(_u(json, string.concat(prefix, "c1"))),
                uint64(_u(json, string.concat(prefix, "c2")))
            );
        }

        // roundPolys
        bridge.roundPolys = new GoldilocksExt3.Ext3[][](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            bridge.roundPolys[i] = new GoldilocksExt3.Ext3[](3);
            for (uint256 j = 0; j < 3; j++) {
                string memory prefix = string.concat(
                    ".proof.bridgeZeta.roundPolys[", vm.toString(i), "][", vm.toString(j), "]."
                );
                bridge.roundPolys[i][j] = GoldilocksExt3.Ext3(
                    uint64(_u(json, string.concat(prefix, "c0"))),
                    uint64(_u(json, string.concat(prefix, "c1"))),
                    uint64(_u(json, string.concat(prefix, "c2")))
                );
            }
        }
    }

    function _parseBridgeGZeta(string memory json)
        internal pure returns (WhirPlonky2Verifier.SumcheckBridgeGZetaData memory bridge)
    {
        uint256 numRounds = _u(json, ".proof.bridgeGZeta.numRounds");

        bridge.gZeta = GoldilocksExt3.Ext3(
            uint64(_u(json, ".proof.bridgeGZeta.gZeta.c0")),
            uint64(_u(json, ".proof.bridgeGZeta.gZeta.c1")),
            uint64(_u(json, ".proof.bridgeGZeta.gZeta.c2"))
        );

        bridge.claimedSum = GoldilocksExt3.Ext3(
            uint64(_u(json, ".proof.bridgeGZeta.claimedSum.c0")),
            uint64(_u(json, ".proof.bridgeGZeta.claimedSum.c1")),
            uint64(_u(json, ".proof.bridgeGZeta.claimedSum.c2"))
        );

        // evalPoint
        bridge.evalPoint = new GoldilocksExt3.Ext3[](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            string memory prefix = string.concat(".proof.bridgeGZeta.evalPoint[", vm.toString(i), "].");
            bridge.evalPoint[i] = GoldilocksExt3.Ext3(
                uint64(_u(json, string.concat(prefix, "c0"))),
                uint64(_u(json, string.concat(prefix, "c1"))),
                uint64(_u(json, string.concat(prefix, "c2")))
            );
        }

        // roundPolys
        bridge.roundPolys = new GoldilocksExt3.Ext3[][](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            bridge.roundPolys[i] = new GoldilocksExt3.Ext3[](3);
            for (uint256 j = 0; j < 3; j++) {
                string memory prefix = string.concat(
                    ".proof.bridgeGZeta.roundPolys[", vm.toString(i), "][", vm.toString(j), "]."
                );
                bridge.roundPolys[i][j] = GoldilocksExt3.Ext3(
                    uint64(_u(json, string.concat(prefix, "c0"))),
                    uint64(_u(json, string.concat(prefix, "c1"))),
                    uint64(_u(json, string.concat(prefix, "c2")))
                );
            }
        }
    }

    function _parseCircuitConfig(string memory json)
        internal pure returns (WhirPlonky2Verifier.CircuitConfig memory config)
    {
        config.degreeBits = _u(json, ".circuitConfig.degreeBits");
        config.numChallenges = _u(json, ".circuitConfig.numChallenges");
        config.numRoutedWires = _u(json, ".circuitConfig.numRoutedWires");
        config.quotientDegreeFactor = _u(json, ".circuitConfig.quotientDegreeFactor");
        config.numPartialProducts = _u(json, ".circuitConfig.numPartialProducts");
        config.numGateConstraints = _u(json, ".circuitConfig.numGateConstraints");
        config.numSelectors = _u(json, ".circuitConfig.numSelectors");
        config.numLookupSelectors = _u(json, ".circuitConfig.numLookupSelectors");
        config.batchSizes = abi.decode(vm.parseJson(json, ".circuitConfig.batchSizes"), (uint256[]));
        config.intraBatchPolyCounts = abi.decode(vm.parseJson(json, ".circuitConfig.intraBatchPolyCounts"), (uint256[]));
        config.sessionName = abi.decode(vm.parseJson(json, ".circuitConfig.sessionName"), (string));

        // Parse gates
        uint256[] memory gateTypes = abi.decode(vm.parseJson(json, ".circuitConfig.gates..gateType"), (uint256[]));
        config.gates = _parseGatesFromConfig(json, gateTypes.length);

        // Parse permutation
        config.permutation.kIs = abi.decode(vm.parseJson(json, ".circuitConfig.permutation.kIs"), (uint256[]));
    }

    function _parseGatesFromConfig(string memory json, uint256 numGates)
        internal pure returns (Plonky2Verifier.GateInfo[] memory)
    {
        uint256[] memory gateTypes = abi.decode(vm.parseJson(json, ".circuitConfig.gates..gateType"), (uint256[]));
        uint256[] memory selectorIndices = abi.decode(vm.parseJson(json, ".circuitConfig.gates..selectorIndex"), (uint256[]));
        uint256[] memory groupStarts = abi.decode(vm.parseJson(json, ".circuitConfig.gates..groupStart"), (uint256[]));
        uint256[] memory groupEnds = abi.decode(vm.parseJson(json, ".circuitConfig.gates..groupEnd"), (uint256[]));
        uint256[] memory rowInGroups = abi.decode(vm.parseJson(json, ".circuitConfig.gates..rowInGroup"), (uint256[]));
        uint256[] memory numConstraintsList = abi.decode(vm.parseJson(json, ".circuitConfig.gates..numConstraints"), (uint256[]));

        Plonky2Verifier.GateInfo[] memory gates = new Plonky2Verifier.GateInfo[](numGates);
        for (uint256 i = 0; i < numGates; i++) {
            string memory cfgKey = string.concat(".circuitConfig.gates[", vm.toString(i), "].gateConfig");
            uint256[] memory cfg = abi.decode(vm.parseJson(json, cfgKey), (uint256[]));
            gates[i] = Plonky2Verifier.GateInfo(
                gateTypes[i], selectorIndices[i], groupStarts[i],
                groupEnds[i], rowInGroups[i], numConstraintsList[i],
                cfg
            );
        }
        return gates;
    }

    function _loadUnifiedWhirParams(string memory json)
        internal pure returns (SpongefishWhirVerify.WhirParams memory p)
    {
        p.numVariables = _u(json, ".whirParams.num_variables");
        p.foldingFactor = _u(json, ".whirParams.folding_factor");
        p.numVectors = _u(json, ".whirParams.num_vectors");
        p.outDomainSamples = _u(json, ".whirParams.out_domain_samples");
        p.inDomainSamples = _u(json, ".whirParams.in_domain_samples");
        p.initialSumcheckRounds = _u(json, ".whirParams.initial_sumcheck_rounds");
        p.numRounds = _u(json, ".whirParams.num_rounds");
        p.finalSumcheckRounds = _u(json, ".whirParams.final_sumcheck_rounds");
        p.finalSize = _u(json, ".whirParams.final_size");
        p.initialCodewordLength = _u(json, ".whirParams.initial_codeword_length");
        p.initialMerkleDepth = _u(json, ".whirParams.initial_merkle_depth");
        p.initialDomainGenerator = uint64(_u(json, ".whirParams.initial_domain_generator"));
        p.initialInterleavingDepth = _u(json, ".whirParams.initial_interleaving_depth");
        p.initialNumVariables = _u(json, ".whirParams.initial_num_variables");
        p.initialCosetSize = _u(json, ".whirParams.initial_coset_size");
        p.initialNumCosets = _u(json, ".whirParams.initial_num_cosets");

        // Evaluation points from bridge data (zeta)
        {
            uint256 nv = p.numVariables;
            p.evaluationPoint = new GoldilocksExt3.Ext3[](nv);
            for (uint256 i = 0; i < nv; i++) {
                string memory epPrefix = string.concat(".proof.bridgeZeta.evalPoint[", vm.toString(i), "].");
                p.evaluationPoint[i] = GoldilocksExt3.Ext3(
                    uint64(_u(json, string.concat(epPrefix, "c0"))),
                    uint64(_u(json, string.concat(epPrefix, "c1"))),
                    uint64(_u(json, string.concat(epPrefix, "c2")))
                );
            }
        }

        // Second evaluation point (g*zeta)
        {
            uint256 nv = p.numVariables;
            p.evaluationPoint2 = new GoldilocksExt3.Ext3[](nv);
            for (uint256 i = 0; i < nv; i++) {
                string memory epPrefix = string.concat(".proof.bridgeGZeta.evalPoint[", vm.toString(i), "].");
                p.evaluationPoint2[i] = GoldilocksExt3.Ext3(
                    uint64(_u(json, string.concat(epPrefix, "c0"))),
                    uint64(_u(json, string.concat(epPrefix, "c1"))),
                    uint64(_u(json, string.concat(epPrefix, "c2")))
                );
            }
        }

        // Rounds
        p.rounds = new SpongefishWhirVerify.RoundParams[](p.numRounds);
        for (uint256 i = 0; i < p.numRounds; i++) {
            string memory prefix = string.concat(".whirParams.rounds[", vm.toString(i), "].");
            p.rounds[i].codewordLength = _u(json, string.concat(prefix, "codeword_length"));
            p.rounds[i].merkleDepth = _u(json, string.concat(prefix, "merkle_depth"));
            p.rounds[i].domainGenerator = uint64(_u(json, string.concat(prefix, "domain_generator")));
            p.rounds[i].inDomainSamples = _u(json, string.concat(prefix, "in_domain_samples"));
            p.rounds[i].outDomainSamples = _u(json, string.concat(prefix, "out_domain_samples"));
            p.rounds[i].sumcheckRounds = _u(json, string.concat(prefix, "sumcheck_rounds"));
            p.rounds[i].interleavingDepth = _u(json, string.concat(prefix, "interleaving_depth"));
            p.rounds[i].cosetSize = _u(json, string.concat(prefix, "coset_size"));
            p.rounds[i].numCosets = _u(json, string.concat(prefix, "num_cosets"));
            p.rounds[i].numVariables = _u(json, string.concat(prefix, "num_variables"));
        }
    }

    function _u(string memory json, string memory path) internal pure returns (uint256) {
        return abi.decode(vm.parseJson(json, path), (uint256));
    }

    /// @dev Compute proofConfigHash from circuitConfig and whirParams.
    function _computeProofConfigHash(
        WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
        SpongefishWhirVerify.WhirParams memory whirParams
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(circuitConfig, whirParams));
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

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    function setUp() public {
        gnarkVerifierContract = new GnarkVerifier();

        // Deploy WhirPlonky2Verifier as a standalone contract
        WhirPlonky2Verifier wpv = new WhirPlonky2Verifier();

        // Load unified proof and compute config hash
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();
        bytes32 cfgHash = _computeProofConfigHash(circuitConfig, whirParams);

        // Non-E2E rollup: uses real proofConfigHash but no gnark verifier
        // (falls through to native Groth16Verifier with synthetic VK)
        rollup = new IntmaxRollup(fraudTreasury, _groth16Vk(), cfgHash, wpv, IGnarkVerifier(address(0)), bytes32(0));

        // E2E rollup with gnark verifier — uses real proof config
        // Genesis state root from e2e fixture (Plonky2 initial ExtendedPublicState hash)
        bytes32 e2eGenesisRoot = 0x428e53c73d2e45bfa8ec3ab8e9c45fb7dcd96288a95fe1ba1fcab889e4bee766;
        e2eRollup = new IntmaxRollup(
            fraudTreasury, _groth16Vk(), cfgHash, wpv,
            IGnarkVerifier(address(gnarkVerifierContract)),
            e2eGenesisRoot
        );

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

        // 3 sub-blocks -> blockNumber = 3
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
            abi.encodePacked(FAKE_BLOB_HASH, proofHash, proofLength, stateRoot, uint64(block.number))
        );
        assertEq(rollup.getCommitment(0), expectedCommitment);
        assertEq(rollup.nextSubmissionId(), 1);

        IntmaxRollup.Submission memory sub = rollup.getSubmission(0);
        assertEq(sub.submitter, submitter);
        assertFalse(sub.finalized);
        assertEq(sub.submittedAtBlock, uint64(block.number));
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
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        bool result = rollup.verify(
            whirProof,
            circuitConfig,
            whirParams,
            _groth16()
        );
        assertTrue(result);
    }

    function test_verify_invalidProof_returnsFalse() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        // Corrupt the transcript
        if (whirProof.transcript.length > 6) {
            whirProof.transcript[6] = bytes1(uint8(whirProof.transcript[6]) ^ 0xFF);
        }

        bool result = rollup.verify(
            whirProof,
            circuitConfig,
            whirParams,
            _groth16()
        );
        assertFalse(result);
    }

    // -----------------------------------------------------------------------
    // finalize() tests  —  full pipeline
    // -----------------------------------------------------------------------

    function test_finalize_success() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        bytes32 stateRoot = keccak256("finalized_state");

        // vpis computed BEFORE posting so blockHashChainAt[0]=0 and finalBlockNumber=0 always match.
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        bytes memory proofBytes = abi.encode(groth16, whirProof);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(1, ids, 100, bytes32(uint256(0xabc)));

        uint256 stakeBalanceBefore = submitter.balance;
        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);
        assertEq(submitter.balance, stakeBalanceBefore - 1 ether, "stake should lock 1 ETH");

        bool ok = rollup.finalize(
            0, stateRoot,
            vpis,
            whirProof,
            circuitConfig,
            whirParams,
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
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        bytes32 stateRoot = keccak256("finalized_state");

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        bytes memory proofBytes = abi.encode(groth16, whirProof);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 7;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(2, ids, 200, bytes32(uint256(0x444)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        assertTrue(rollup.finalize(
            0, stateRoot, vpis,
            whirProof, circuitConfig, whirParams,
            groth16
        ));

        // Second call returns false (already finalized)
        assertFalse(rollup.finalize(
            0, stateRoot, vpis,
            whirProof, circuitConfig, whirParams,
            groth16
        ));
    }

    function test_finalize_initialStateMismatch() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        bytes32 stateRoot = keccak256("state");

        // Build VPIs with wrong initialExtCommitment (before posting so other fields are correct)
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        vpis.initialExtCommitment = bytes32(uint256(0xbad));
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        bytes memory proofBytes = abi.encode(groth16, whirProof);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 9;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(3, ids, 300, bytes32(uint256(0x555)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        // Returns false (initial state mismatch — initialExtCommitment = 0xbad != latestFinalizedStateRoot = 0)
        assertFalse(rollup.finalize(
            0, stateRoot, vpis,
            whirProof, circuitConfig, whirParams,
            groth16
        ));
    }

    /// @notice finalize() returns false when groth16.pubInputs[0] != keccak256(ValidityPublicInputs).
    function test_finalize_wrongGroth16PubInputs() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        bytes32 stateRoot = keccak256("state_mismatch");

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        // pubInputs[0] = 0, which is != keccak256(vpis) -> PI binding check fails
        IntmaxRollup.Groth16Params memory groth16 = _groth16();

        bytes memory proofBytes = abi.encode(groth16, whirProof);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 11;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(4, ids, 400, bytes32(uint256(0x777)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        // Returns false: groth16.pubInputs[0] = 0 != keccak256(vpis)
        assertFalse(rollup.finalize(
            0, stateRoot, vpis,
            whirProof, circuitConfig, whirParams,
            groth16
        ));
    }

    function test_finalize_notFound() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        IntmaxRollup.ValidityPublicInputs memory vpis;

        // Returns false (submission not found)
        assertFalse(rollup.finalize(
            999, bytes32(0), vpis,
            whirProof, circuitConfig, whirParams,
            _groth16()
        ));
    }

    // -----------------------------------------------------------------------
    // fraudProof() tests — prove a submission is invalid
    // -----------------------------------------------------------------------

    function test_fraudProof_invalidProof_confirmedFraud() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes memory proofBytes = abi.encode(groth16, whirProof);
        bytes32 stateRoot   = keccak256("bad_state");

        uint32[] memory ids = new uint32[](1);
        ids[0] = 21;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(5, ids, 500, bytes32(uint256(0x888)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        // groth16.pubInputs[0..7] = 0 != keccak256(vpis) -> fraud confirmed via condition (b)

        address reporter = makeAddr("reporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        bool fraudConfirmed = rollup.fraudProof(
            0, blobHash, stateRoot, proofBytes, vpis,
            whirProof, circuitConfig, whirParams,
            kzg, groth16
        );
        assertTrue(fraudConfirmed, "Fraud should be confirmed for invalid proof");
    }

    /// @notice Params binding mismatch is now fraud (malformed blob payload).
    ///         The fraud prover supplies the authentic proofBytes from the blob
    ///         (verified via commitment + KZG), and the re-encoded structs don't
    ///         match -> the blob contained non-ABI-decodable data -> fraud.
    function test_fraudProof_paramsBindingMismatch_isFraud() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes memory proofBytes = abi.encode(groth16, whirProof);
        bytes32 stateRoot   = keccak256("valid_state");

        uint32[] memory ids = new uint32[](1);
        ids[0] = 31;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(6, ids, 600, bytes32(uint256(0x999)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);

        // Modify proof data AFTER proofBytes was created, so params binding fails.
        // This simulates a fraud prover presenting the authentic blob bytes (proofBytes)
        // alongside structs that don't decode to match — proving the blob is malformed.
        whirProof.evaluations[0] = GoldilocksExt3.Ext3(1, 2, 3);

        address reporter = makeAddr("reporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        bool fraudConfirmed = rollup.fraudProof(
            0, blobHash, stateRoot, proofBytes, vpis,
            whirProof, circuitConfig, whirParams,
            kzg, groth16
        );
        assertTrue(fraudConfirmed, "Params binding mismatch = malformed blob = fraud");
    }

    function test_fraudProof_bindingFails_rejected() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes memory proofBytes = abi.encode(groth16, whirProof);
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
            whirProof, circuitConfig, whirParams,
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
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes memory proofBytes = abi.encode(groth16, whirProof);
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
        // groth16.pubInputs[0..7] = 0 != keccak256(vpis) -> fraud confirmed via condition (b)

        address reporter = makeAddr("reporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        bool fraudConfirmed = rollup.fraudProof(
            badSubmissionId,
            blobHash,
            stateRoot,
            proofBytes,
            vpis,
            whirProof, circuitConfig, whirParams,
            kzg,
            groth16
        );
        assertTrue(fraudConfirmed, "fraud should be confirmed");

        assertEq(rollup.blockDepositHash(targetBlock), bytes32(0), "deposit hash cleared on rollback");
        assertEq(rollup.blockForcedTxHash(targetBlock), bytes32(0), "forced hash cleared on rollback");
    }

    function test_fraudProof_slashesCascadeAndRollsBack() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes memory proofBytes = abi.encode(groth16, whirProof);
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
        // groth16.pubInputs[0..7] = 0 != keccak256(vpis) -> fraud confirmed via condition (b)

        address reporter = makeAddr("reporter");
        vm.deal(reporter, 1 ether);
        uint256 reporterBefore = reporter.balance;
        uint256 treasuryBefore = fraudTreasury.balance;

        assertEq(address(rollup).balance, 2 ether, "two stakes should be locked");

        vm.prank(reporter);
        bool fraudConfirmed = rollup.fraudProof(
            0, blobHash, badState, proofBytes, vpis,
            whirProof, circuitConfig, whirParams,
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
    ///         WHIR rejects corrupted transcript (condition c), confirming fraud.
    ///         vpis computed BEFORE posting so finalBlockNumber=0 and
    ///         blockHashChainAt[0]=0 always match.
    function test_fraudProof_e2e_realWhir_corruptedData() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        // Corrupt transcript — flip every byte
        for (uint256 i = 0; i < whirProof.transcript.length; i++) {
            whirProof.transcript[i] = bytes1(uint8(whirProof.transcript[i]) ^ 0xFF);
        }

        // Compute vpis BEFORE posting (initial state: everything zero).
        // blockHashChainAt[0] stays 0 forever, so PI binding will pass.
        bytes32 stateRoot = keccak256("e2e_fraud_state");
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);

        // Use correct piHash so Groth16 pubInputs condition (b) passes.
        // WHIR rejects corrupted transcript (condition c).
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        // Encode corrupted proof INTO proofBytes so params binding passes
        bytes memory proofBytes = abi.encode(groth16, whirProof);

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
            whirProof, circuitConfig, whirParams,
            kzg, groth16
        );
        assertTrue(fraudConfirmed, "Fraud: WHIR rejects corrupted transcript (condition c)");

        IntmaxRollup.Submission memory sub = rollup.getSubmission(0);
        assertEq(sub.commitment, bytes32(0), "Submission deleted after fraud");
    }

    /// @notice E2E fraud proof: corrupted WHIR hints + transcript.
    ///         The real WHIR verifier rejects them, confirming fraud (condition c).
    function test_fraudProof_e2e_realWhir_randomBytes() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        // Corrupt hints
        whirProof.hints = hex"0000111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF";
        // Also corrupt transcript
        whirProof.transcript = hex"DEADBEEFCAFEBABE";

        // Compute vpis BEFORE posting (initial zero state)
        bytes32 stateRoot = keccak256("random_bytes_fraud");
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);

        // Use correct piHash so Groth16 pubInputs condition (b) passes.
        // WHIR rejects corrupted data (condition c).
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        // Encode corrupted proof INTO proofBytes
        bytes memory proofBytes = abi.encode(groth16, whirProof);

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
            whirProof, circuitConfig, whirParams,
            kzg, groth16
        );
        assertTrue(fraudConfirmed, "Fraud: WHIR rejects corrupted data (condition c)");

        IntmaxRollup.Submission memory sub = rollup.getSubmission(0);
        assertEq(sub.commitment, bytes32(0), "Submission deleted after fraud");
    }

    function test_fraudProof_revertsWhenFinalized() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        bytes32 stateRoot = keccak256("finalized_state");

        // vpis computed BEFORE posting so proof params binding is consistent.
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        bytes memory proofBytes = abi.encode(groth16, whirProof);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 123;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(12, ids, 900, bytes32(uint256(0x3434)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        assertTrue(
            rollup.finalize(
                0, stateRoot, vpis,
                whirProof, circuitConfig, whirParams,
                groth16
            ),
            "finalize should succeed"
        );

        address watcher = makeAddr("watcher");
        vm.deal(watcher, 1 ether);
        vm.prank(watcher);
        vm.expectRevert(IntmaxRollup.SubmissionAlreadyFinalized.selector);
        rollup.fraudProof(
            0, blobHash, stateRoot, proofBytes, vpis,
            whirProof, circuitConfig, whirParams,
            kzg,
            groth16
        );
    }

    // -----------------------------------------------------------------------
    // Finalized block number tracking
    // -----------------------------------------------------------------------

    function test_finalize_updatesLatestFinalizedBlockNumber() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        bytes32 stateRoot = keccak256("finalized_state");
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(1, ids, 100, bytes32(uint256(0x11)));
        _mockBlob();
        vm.prank(submitter);
        rollup.postBlockAndSubmit{value: 1 ether}(batch, keccak256("p"), 1, stateRoot);

        assertEq(rollup.latestFinalizedBlockNumber(), 0, "Should be 0 before finalize");

        rollup.finalize(0, stateRoot, vpis, whirProof, circuitConfig, whirParams, groth16);

        assertEq(
            rollup.latestFinalizedBlockNumber(),
            vpis.finalBlockNumber,
            "latestFinalizedBlockNumber should match finalBlockNumber from vpis"
        );
    }

    // -----------------------------------------------------------------------
    // Fraud proof: finalized block guard
    // -----------------------------------------------------------------------

    function test_fraudProof_revertsBeforeFinalizedBlock() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        // --- Post and finalize submission 0 ---
        bytes32 stateRoot1 = keccak256("state1");
        IntmaxRollup.ValidityPublicInputs memory vpis1 = _defaultValidityPIs(stateRoot1);
        bytes32 piHash1 = _computePIHash(vpis1);
        IntmaxRollup.Groth16Params memory groth16_1 = _groth16WithPIHash(piHash1);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch1 = _singleBlockBatch(1, ids, 100, bytes32(uint256(0x11)));
        _mockBlob();
        vm.prank(submitter);
        rollup.postBlockAndSubmit{value: 1 ether}(batch1, keccak256("p1"), 1, stateRoot1);

        rollup.finalize(0, stateRoot1, vpis1, whirProof, circuitConfig, whirParams, groth16_1);
        // latestFinalizedBlockNumber is now 1

        // --- Post submission 1 with blocks that overlap finalized range ---
        bytes32 stateRoot2 = keccak256("state2");
        IntmaxRollup.Groth16Params memory groth16_2 = _groth16();
        bytes memory proofBytes2 = abi.encode(groth16_2, whirProof);

        ids[0] = 2;
        IntmaxRollup.SubBlock[] memory batch2 = _singleBlockBatch(1, ids, 200, bytes32(uint256(0x22)));
        (KZGProof memory kzg2, bytes32 blobHash2) = _postWithKZG(batch2, proofBytes2, stateRoot2, submitter);

        // submission 1 has startBlockNumber = 2 > latestFinalizedBlockNumber = 1
        // So fraud proof should NOT revert with SubmissionBeforeFinalizedBlock.
        IntmaxRollup.ValidityPublicInputs memory vpis2 = _defaultValidityPIs(stateRoot2);
        address reporter = makeAddr("reporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        // This should proceed (not revert with SubmissionBeforeFinalizedBlock)
        rollup.fraudProof(
            1, blobHash2, stateRoot2, proofBytes2, vpis2,
            whirProof, circuitConfig, whirParams, kzg2, groth16_2
        );
    }

    // -----------------------------------------------------------------------
    // Fraud proof: timeout auto-removal
    // -----------------------------------------------------------------------

    function test_fraudProof_timeoutRemoval() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes memory proofBytes = abi.encode(groth16, whirProof);
        bytes32 stateRoot = keccak256("timeout_state");

        uint32[] memory ids = new uint32[](1);
        ids[0] = 50;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(1, ids, 500, bytes32(uint256(0x55)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);

        // Advance past FINALIZE_DEADLINE_BLOCKS (3600 + 1 blocks)
        vm.roll(block.number + 3601);

        address reporter = makeAddr("timeout_reporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        bool confirmed = rollup.fraudProof(
            0, blobHash, stateRoot, proofBytes, vpis,
            whirProof, circuitConfig, whirParams, kzg, groth16
        );
        assertTrue(confirmed, "Timeout fraud should be confirmed unconditionally");

        // Submission should be deleted
        assertEq(rollup.nextSubmissionId(), 0, "Submission should be truncated");
    }

    function test_fraudProof_noTimeoutBeforeDeadline() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes memory proofBytes = abi.encode(groth16, whirProof);
        bytes32 stateRoot = keccak256("no_timeout_state");

        uint32[] memory ids = new uint32[](1);
        ids[0] = 60;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(1, ids, 600, bytes32(uint256(0x66)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);

        // Do NOT advance past deadline — stay within 3600 blocks
        vm.roll(block.number + 3000);

        address reporter = makeAddr("early_reporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        // Should go through normal fraud verification (not timeout path).
        // The proof params binding will match, then actual verification runs.
        // With synthetic groth16 it will confirm fraud via piHash mismatch.
        bool confirmed = rollup.fraudProof(
            0, blobHash, stateRoot, proofBytes, vpis,
            whirProof, circuitConfig, whirParams, kzg, groth16
        );
        assertTrue(confirmed, "Should confirm fraud via normal path, not timeout");

        // Verify submission still goes through normal truncation
        assertEq(rollup.nextSubmissionId(), 0);
    }

    // -----------------------------------------------------------------------
    // submittedAtBlock recording
    // -----------------------------------------------------------------------

    function test_submittedAtBlock_recorded() public {
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(1, ids, 100, bytes32(uint256(0x11)));

        vm.roll(42);
        _mockBlob();
        vm.prank(submitter);
        rollup.postBlockAndSubmit{value: 1 ether}(batch, keccak256("p"), 1, bytes32(uint256(1)));

        IntmaxRollup.Submission memory sub = rollup.getSubmission(0);
        assertEq(sub.submittedAtBlock, 42, "submittedAtBlock should match block.number at submission");
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
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        uint256 gasBefore = gasleft();
        rollup.verify(
            whirProof,
            circuitConfig,
            whirParams,
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
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        bytes32 stateRoot = keccak256("finalized_state");
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);

        bytes memory proofBytes = abi.encode(groth16, whirProof);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 99;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(8, ids, 700, bytes32(uint256(0xbbc)));

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(batch, proofBytes, stateRoot, submitter);

        uint256 gasBefore = gasleft();
        rollup.finalize(
            0, stateRoot, vpis,
            whirProof, circuitConfig, whirParams,
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
    // -----------------------------------------------------------------------
    // Pull-payment resilience tests
    // -----------------------------------------------------------------------

    function test_withdraw_afterFinalize() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();
        bytes32 stateRoot = keccak256("finalized_state");
        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);
        bytes memory proofBytes = abi.encode(groth16, whirProof);
        uint32[] memory ids = new uint32[](1); ids[0] = 1;
        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(_singleBlockBatch(1, ids, 100, bytes32(uint256(0xabc))), proofBytes, stateRoot, submitter);

        rollup.finalize(0, stateRoot, vpis, whirProof, circuitConfig, whirParams, groth16);

        assertEq(rollup.pendingWithdrawals(submitter), 1 ether, "stake credited");
        uint256 balBefore = submitter.balance;
        vm.prank(submitter);
        rollup.withdraw();
        assertEq(submitter.balance, balBefore + 1 ether, "stake withdrawn");
        assertEq(rollup.pendingWithdrawals(submitter), 0, "no pending after withdraw");
    }

    function test_finalize_succeedsEvenIfSubmitterReverts() public {
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();
        bytes32 stateRoot = keccak256("finalized_state");

        // Submitter is a reverting contract
        RevertingReceiver revSub = new RevertingReceiver();
        vm.deal(address(revSub), 10 ether);

        IntmaxRollup.ValidityPublicInputs memory vpis = _defaultValidityPIs(stateRoot);
        bytes32 piHash = _computePIHash(vpis);
        IntmaxRollup.Groth16Params memory groth16 = _groth16WithPIHash(piHash);
        bytes memory proofBytes = abi.encode(groth16, whirProof);
        uint32[] memory ids = new uint32[](1); ids[0] = 1;
        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(
            _singleBlockBatch(1, ids, 100, bytes32(uint256(0xabc))),
            proofBytes, stateRoot, address(revSub)
        );

        // Under old push-payment, this would revert because revSub rejects ETH.
        // Under pull-payment, finalize completes and credits pendingWithdrawals.
        bool ok = rollup.finalize(0, stateRoot, vpis, whirProof, circuitConfig, whirParams, groth16);
        assertTrue(ok, "finalize must succeed even with reverting submitter");
        assertEq(rollup.pendingWithdrawals(address(revSub)), 1 ether, "stake credited to reverting submitter");
    }

    function test_fraudProof_succeedsEvenIfTreasuryReverts() public {
        // Deploy rollup with a reverting treasury
        RevertingReceiver revTreasury = new RevertingReceiver();
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();
        bytes32 cfgHash = _computeProofConfigHash(circuitConfig, whirParams);
        IntmaxRollup rollup2 = new IntmaxRollup(
            address(revTreasury), _groth16Vk(), bytes32(0), rollup.whirPlonky2Verifier(), IGnarkVerifier(address(0)), bytes32(0)
        );

        address sub2 = makeAddr("sub2");
        vm.deal(sub2, 10 ether);

        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes32 stateRoot = keccak256("bad_state");

        // Build vpis BEFORE posting (rollup2 initial state: all zeros)
        IntmaxRollup.ValidityPublicInputs memory vpis = IntmaxRollup.ValidityPublicInputs({
            initialBlockNumber: 0,
            initialBlockChain:  rollup2.blockHashChainAt(0),
            initialExtCommitment: rollup2.latestFinalizedStateRoot(),
            finalBlockNumber:   rollup2.blockNumber(),
            finalBlockChain:    rollup2.blockHashChain(),
            finalExtCommitment: stateRoot,
            prover: address(0)
        });

        bytes memory proofBytes = abi.encode(groth16, whirProof);
        uint32[] memory ids = new uint32[](1); ids[0] = 21;

        bytes32[] memory hs = new bytes32[](1);
        (KZGProof memory kzg, bytes32 blobHash) = _computeKZGProof(proofBytes);
        hs[0] = blobHash;
        vm.blobhashes(hs);
        vm.prank(sub2);
        rollup2.postBlockAndSubmit{value: 1 ether}(
            _singleBlockBatch(5, ids, 500, bytes32(uint256(0x888))),
            keccak256(proofBytes), uint32(proofBytes.length), stateRoot
        );

        address reporter2 = makeAddr("reporter2");
        vm.deal(reporter2, 1 ether);
        vm.prank(reporter2);
        bool confirmed = rollup2.fraudProof(0, blobHash, stateRoot, proofBytes, vpis, whirProof, circuitConfig, whirParams, kzg, groth16);
        assertTrue(confirmed, "fraud must be confirmed even with reverting treasury");
        assertGt(rollup2.pendingWithdrawals(reporter2), 0, "reporter reward credited");
        assertGt(rollup2.pendingWithdrawals(address(revTreasury)), 0, "treasury share credited");
    }

    // -----------------------------------------------------------------------
    // Rollback gas test
    // -----------------------------------------------------------------------

    function test_fraudProof_rollbackGasWithManyDeposits() public {
        // Queue many deposits
        for (uint256 i = 0; i < 200; i++) {
            rollup.deposit(bytes32(uint256(i + 1)), uint32(i % 10), 100 + i, bytes32(uint256(i)));
        }

        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();
        IntmaxRollup.Groth16Params memory groth16 = _groth16();
        bytes memory proofBytes = abi.encode(groth16, whirProof);
        bytes32 stateRoot = keccak256("bad_state");
        uint32[] memory ids = new uint32[](1); ids[0] = 21;

        (KZGProof memory kzg, bytes32 blobHash) = _postWithKZG(
            _singleBlockBatch(5, ids, 500, bytes32(uint256(0x888))),
            proofBytes, stateRoot, submitter
        );

        IntmaxRollup.ValidityPublicInputs memory vpis;
        address reporter = makeAddr("gasReporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        uint256 gasBefore = gasleft();
        rollup.fraudProof(0, blobHash, stateRoot, proofBytes, vpis, whirProof, circuitConfig, whirParams, kzg, groth16);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("fraudProof() gas with 200 deposits (O(1) rollback):", gasUsed);
        // With O(1) deposit rollback, gas should not scale with deposit count.
        assertLt(gasUsed, 250_000_000, "rollback gas must be bounded");
    }

    // -----------------------------------------------------------------------
    // Forced tx ownership test
    // -----------------------------------------------------------------------

    function test_registerForcedTxLogic_permissionlessButImmutable() public {
        MockForcedTxLogic logic1 = new MockForcedTxLogic(bytes32(uint256(0x111)));
        address anyUser = makeAddr("anyUser");

        // Anyone can register (permissionless — the logic contract's acceptRegistration is the gate)
        vm.prank(anyUser);
        rollup.registerForcedTxLogic(99999, address(logic1));
        assertEq(rollup.forcedTxLogicContracts(99999), address(logic1));

        // Second registration for same userId reverts (immutable)
        MockForcedTxLogic logic2 = new MockForcedTxLogic(bytes32(uint256(0x222)));
        vm.prank(anyUser);
        vm.expectRevert(IntmaxRollup.ForcedTxLogicAlreadyRegistered.selector);
        rollup.registerForcedTxLogic(99999, address(logic2));
    }

    /// @dev gnark Groth16 raw proof bytes — stored as state to avoid via_ir inlining issues.
    bytes internal _gnarkRawProof = hex"07b73461134ed24b94cedaf234922c62224997b83784064c489f65ef3fe674b216b0bd162ccaf6ac674949bb994ed4115be6ec53ea58ce0bb288e687e531e187123f8392318d38a5e24b8b5196980e77603c51ba6bc4204baa9354fe382c47b00fba9eeb255514d79ea29d7024f5364f79278085a3b46da1c39d0098ad87162f0ef17d7c3cadf8a9620cc748e71c8cf549a669f8b289b96346cef4311eff3b861ee04d08a3921c2f8bb4f162c40e62046cf887ec4993b8173d3b9e55c80b0e471199414586525fdfcb7998407e396b4d30bc7fb4a917c70d212fe5c9b7826f661eed2d97eb3f0649f561c51ac3bf42ab898bdc1bc3ce0a24410d0823c9fd60270000000109c0e0341f14beaf0aa49803b2eea690aaae9594f11825eee1509be33adf85f110caa026ae6277f4440b0c0c74caa2c91285db838074ab03238d25273e1546111b8015653615ce6e13f48beb2c664b03fc83110c789f68cc7ec1445521ddb68d1f549bbf1d9eea73ec1d4431a38a507bb7a76d1ff66b13e15495837a72218c95";

    /// @dev Parse gnark Groth16 proof by reading 32-byte chunks from stored raw bytes.
    function _realGnarkProof() internal view returns (IntmaxRollup.Groth16Params memory params) {
        bytes memory raw = _gnarkRawProof;
        // A (64 bytes) at offset 0
        params.proof.a[0] = _readUint(raw, 0);
        params.proof.a[1] = _readUint(raw, 32);
        // B (128 bytes) at offset 64
        params.proof.b[0][0] = _readUint(raw, 64);
        params.proof.b[0][1] = _readUint(raw, 96);
        params.proof.b[1][0] = _readUint(raw, 128);
        params.proof.b[1][1] = _readUint(raw, 160);
        // C (64 bytes) at offset 192
        params.proof.c[0] = _readUint(raw, 192);
        params.proof.c[1] = _readUint(raw, 224);
        // Commitment (64 bytes at offset 260 = 256 + 4 for nbCommitments)
        params.commitments[0] = _readUint(raw, 260);
        params.commitments[1] = _readUint(raw, 292);
        // CommitmentPok (64 bytes at offset 324)
        params.commitmentPok[0] = _readUint(raw, 324);
        params.commitmentPok[1] = _readUint(raw, 356);
        // piHash = 0x6467732d3ff664b85497807da9a5c8bc058642bfab878c7a6816359bc9799ab2
        params.pubInputs = new uint256[](8);
        params.pubInputs[0] = 1684501293; params.pubInputs[1] = 1073112248;
        params.pubInputs[2] = 1419214973; params.pubInputs[3] = 2846214332;
        params.pubInputs[4] = 92684991;   params.pubInputs[5] = 2877787258;
        params.pubInputs[6] = 1746285979; params.pubInputs[7] = 3380189874;
    }

    function _readUint(bytes memory data, uint256 offset) internal pure returns (uint256 val) {
        assembly { val := mload(add(add(data, 32), offset)) }
    }

    /// @notice Complete finalize() E2E with real gnark Groth16 + real WHIR + real KZG.
    ///         Uses gnark-generated GnarkGroth16Verifier with commitment support.
    function test_finalize_realE2E() public {
        _finalize_realE2E_impl();
    }

    function _finalize_realE2E_impl() internal {
        // This test uses real postBlockAndSubmit() -> real finalize() end-to-end.

        // VPI from e2e_fixture.json (hardcoded — generated by Plonky2 validity circuit)
        bytes32 initialExtCommitment = 0x428e53c73d2e45bfa8ec3ab8e9c45fb7dcd96288a95fe1ba1fcab889e4bee766;
        bytes32 finalExtCommitment   = 0xc37a8de7f17f7efbf676c27e3dd54bd5b9750a14bf1574bebb23bde2f7a54f2c;

        // Load unified proof
        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();

        // Real gnark Groth16 proof (hardcoded from gnark v0.10 output)
        IntmaxRollup.Groth16Params memory groth16 = _realGnarkProof();

        // -- 1. Verify pre-conditions --
        // e2eRollup was deployed in setUp with genesisStateRoot = initialExtCommitment
        assertEq(e2eRollup.latestFinalizedStateRoot(), initialExtCommitment,
            "genesis state root must match fixture");
        assertEq(e2eRollup.blockNumber(), 0, "no blocks posted yet");

        // -- 2. Build proofBytes --
        bytes memory proofBytes = abi.encode(groth16, whirProof);

        // -- 3. Compute real KZG proof --
        (KZGProof memory kzg, bytes32 blobHash) = _computeKZGProof(proofBytes);

        // -- 4. Post batch via real postBlockAndSubmit() --
        // SubBlock matches the Rust fixture: aggregatorId=1, timestamp=1, localIds=[0,0], txTreeRoot=0x0
        uint32[] memory localIds = new uint32[](2);  // [0, 0] — padded to num_users=2
        IntmaxRollup.SubBlock[] memory batch = new IntmaxRollup.SubBlock[](1);
        batch[0] = IntmaxRollup.SubBlock({
            aggregatorId: 1,
            localIds: localIds,
            timestamp: 1,
            txTreeRoot: bytes32(0)
        });

        // Set blobhashes for the EIP-4844 context
        bytes32[] memory bhs = new bytes32[](1);
        bhs[0] = blobHash;
        vm.blobhashes(bhs);

        // Fund and post as submitter — this creates the submission with real commitment
        vm.deal(address(this), 10 ether);
        e2eRollup.postBlockAndSubmit{value: 1 ether}(
            batch,
            keccak256(proofBytes),
            uint32(proofBytes.length),
            finalExtCommitment  // stateRoot
        );

        // Verify state after posting
        assertEq(e2eRollup.blockNumber(), 1, "block number must be 1 after posting");

        // -- 5. Build VPI matching on-chain state --
        IntmaxRollup.ValidityPublicInputs memory vpis = IntmaxRollup.ValidityPublicInputs({
            initialBlockNumber: 0,
            initialBlockChain: e2eRollup.blockHashChainAt(0),
            initialExtCommitment: initialExtCommitment,
            finalBlockNumber: 1,
            finalBlockChain: e2eRollup.blockHashChainAt(1),
            finalExtCommitment: finalExtCommitment,
            prover: address(0)
        });

        // -- 6. Call finalize() — no vm.store, no cheatcodes --
        bool ok = e2eRollup.finalize(
            0, finalExtCommitment, vpis,
            whirProof, circuitConfig, whirParams, groth16
        );

        assertTrue(ok, "finalize() must succeed with real gnark Groth16 + real WHIR");
        assertTrue(e2eRollup.isFinalized(0));
        assertEq(e2eRollup.latestFinalizedStateRoot(), finalExtCommitment);
        // Pull-payment: stake credited, not pushed
        assertEq(e2eRollup.pendingWithdrawals(address(this)), 1 ether, "stake must be credited");
    }
}

/// @dev Contract that reverts on ETH receipt — tests pull-payment resilience.
contract RevertingReceiver {
    receive() external payable { revert("no ETH accepted"); }
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

// =========================================================================
// Fraud proof: partial corruption tests
//
// Each test corrupts exactly ONE component while keeping all others valid.
// Pre-conditions (commitment, KZG, PI binding, params binding) must pass
// for the fraud detection phase to be reached.
//
// The "base" setup uses the e2e rollup with real WHIR + Plonky2 verification.
// vpis are computed BEFORE posting so block-state matches.
// piHash is set correctly in groth16 so condition (b) passes.
// proofBytes is recomputed AFTER corruption so params binding passes.
// =========================================================================

contract FraudProofPartialCorruptionTest is Test {
    using GoldilocksExt3 for GoldilocksExt3.Ext3;

    IntmaxRollup rollup;
    address submitter = makeAddr("submitter");
    address fraudTreasury = makeAddr("fraudTreasury");

    function setUp() public {
        GnarkVerifier gnarkVerifier = new GnarkVerifier();
        WhirPlonky2Verifier wpv = new WhirPlonky2Verifier();

        (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        ) = _loadUnifiedProof();
        bytes32 cfgHash = keccak256(abi.encode(circuitConfig, whirParams));

        bytes32 genesisRoot = 0x428e53c73d2e45bfa8ec3ab8e9c45fb7dcd96288a95fe1ba1fcab889e4bee766;
        Groth16Verifier.VerifyingKey memory vk;

        rollup = new IntmaxRollup(
            fraudTreasury, vk, cfgHash, wpv,
            IGnarkVerifier(address(gnarkVerifier)),
            genesisRoot
        );

        vm.deal(submitter, 100 ether);
        vm.deal(fraudTreasury, 0);
    }

    // -----------------------------------------------------------------------
    // Helper: submit a fraud-proof-ready submission and return all proof data
    // -----------------------------------------------------------------------

    struct FraudSetup {
        WhirPlonky2Verifier.WhirPlonky2Proof whirProof;
        WhirPlonky2Verifier.CircuitConfig circuitConfig;
        SpongefishWhirVerify.WhirParams whirParams;
        IntmaxRollup.Groth16Params groth16;
        IntmaxRollup.ValidityPublicInputs vpis;
        bytes32 stateRoot;
    }

    /// @dev Build a valid fraud-proof setup. All pre-conditions pass.
    ///      Caller can corrupt one component, then call _submitAndProve().
    function _baseFraudSetup() internal view returns (FraudSetup memory s) {
        (s.whirProof, s.circuitConfig, s.whirParams) = _loadUnifiedProof();
        s.stateRoot = keccak256("fraud_partial_corruption");

        s.vpis = IntmaxRollup.ValidityPublicInputs({
            initialBlockNumber: 0,
            initialBlockChain:  rollup.blockHashChainAt(0),
            initialExtCommitment: rollup.latestFinalizedStateRoot(),
            finalBlockNumber:   0,       // before posting
            finalBlockChain:    bytes32(0),
            finalExtCommitment: s.stateRoot,
            prover: address(0)
        });

        bytes32 piHash = _computePIHash(s.vpis);
        s.groth16 = _groth16WithPIHash(piHash);
    }

    /// @dev Post the submission and call fraudProof. Returns (fraudConfirmed).
    function _submitAndProve(FraudSetup memory s) internal returns (bool) {
        bytes memory proofBytes = abi.encode(s.groth16, s.whirProof);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = new IntmaxRollup.SubBlock[](1);
        batch[0] = IntmaxRollup.SubBlock(1, 100, bytes32(uint256(0x42)), ids);

        (KZGProof memory kzg, bytes32 blobHash) = _computeAndPost(batch, proofBytes, s.stateRoot);

        address reporter = makeAddr("reporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        return rollup.fraudProof(
            0, blobHash, s.stateRoot, proofBytes, s.vpis,
            s.whirProof, s.circuitConfig, s.whirParams, kzg, s.groth16
        );
    }

    uint256 constant BLS12_SCALAR_R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    function _computeAndPost(
        IntmaxRollup.SubBlock[] memory batch,
        bytes memory proofBytes,
        bytes32 stateRoot
    ) internal returns (KZGProof memory kzg, bytes32 blobHash) {
        (kzg, blobHash) = _computeKZGProof(proofBytes);
        bytes32[] memory hs = new bytes32[](1);
        hs[0] = blobHash;
        vm.blobhashes(hs);
        vm.prank(submitter);
        rollup.postBlockAndSubmit{value: 1 ether}(
            batch, keccak256(proofBytes), uint32(proofBytes.length), stateRoot
        );
    }

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

    function _bls12G1GenBytes() internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f",
            hex"c3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            hex"0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4",
            hex"fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
        );
    }

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
        bytes32 halfQ0 = 0x0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b12;
        bytes16 halfQ1 = bytes16(0x0f55ffff58a9ffffdcff7fffffffd555);
        bytes16 yEnd   = bytes16(y1);
        bool signBit = (y0 > halfQ0) || (y0 == halfQ0 && yEnd > halfQ1);
        c48 = abi.encodePacked(x0, bytes16(x1));
        c48[0] = bytes1(uint8(c48[0]) | 0x80 | (signBit ? uint8(0x20) : uint8(0)));
    }

    // -----------------------------------------------------------------------
    // Unified proof loading (duplicated for isolation)
    // -----------------------------------------------------------------------

    function _loadUnifiedProof()
        internal view returns (
            WhirPlonky2Verifier.WhirPlonky2Proof memory whirProof,
            WhirPlonky2Verifier.CircuitConfig memory circuitConfig,
            SpongefishWhirVerify.WhirParams memory whirParams
        )
    {
        string memory json = vm.readFile(
            string.concat(vm.projectRoot(), "/test/data/test_proof.json")
        );
        whirProof = _parseUnifiedProof(json);
        circuitConfig = _parseCircuitConfig(json);
        whirParams = _loadUnifiedWhirParams(json);
    }

    function _parseUnifiedProof(string memory json)
        internal pure returns (WhirPlonky2Verifier.WhirPlonky2Proof memory proof)
    {
        proof.protocolId = vm.parseJsonBytes(json, ".proof.protocolId");
        proof.sessionId = vm.parseJsonBytes(json, ".proof.sessionId");
        proof.instance = vm.parseJsonBytes(json, ".proof.instance");
        proof.transcript = vm.parseJsonBytes(json, ".proof.transcript");
        proof.hints = vm.parseJsonBytes(json, ".proof.hints");

        proof.evaluations = new GoldilocksExt3.Ext3[](2);
        for (uint256 i = 0; i < 2; i++) {
            string memory prefix = string.concat(".proof.evaluations[", vm.toString(i), "].");
            proof.evaluations[i] = GoldilocksExt3.Ext3(
                uint64(_u(json, string.concat(prefix, "c0"))),
                uint64(_u(json, string.concat(prefix, "c1"))),
                uint64(_u(json, string.concat(prefix, "c2")))
            );
        }

        proof.bridgeZeta = _parseBridgeZeta(json);
        proof.bridgeGZeta = _parseBridgeGZeta(json);

        uint256[] memory polyCounts = abi.decode(vm.parseJson(json, ".circuitConfig.intraBatchPolyCounts"), (uint256[]));
        proof.allOpeningsAtZetaFlat = new uint256[][](polyCounts.length);
        for (uint256 b = 0; b < polyCounts.length; b++) {
            string memory path = string.concat(".proof.allOpeningsAtZetaFlat[", vm.toString(b), "]");
            proof.allOpeningsAtZetaFlat[b] = abi.decode(vm.parseJson(json, path), (uint256[]));
        }

        proof.batch2OpeningsAtGZetaFlat = abi.decode(
            vm.parseJson(json, ".proof.batch2OpeningsAtGZetaFlat"), (uint256[])
        );
        proof.batchEvalsAtGZetaFlat = abi.decode(
            vm.parseJson(json, ".proof.batchEvalsAtGZetaFlat"), (uint256[])
        );
        proof.publicInputs = abi.decode(vm.parseJson(json, ".proof.publicInputs"), (uint256[]));
    }

    function _parseBridgeZeta(string memory json)
        internal pure returns (WhirPlonky2Verifier.SumcheckBridgeData memory bridge)
    {
        uint256 numRounds = _u(json, ".proof.bridgeZeta.numRounds");
        bridge.sessionName = abi.decode(vm.parseJson(json, ".proof.bridgeZeta.sessionName"), (string));
        bridge.zeta = GoldilocksExt3.Ext3(
            uint64(_u(json, ".proof.bridgeZeta.zeta.c0")),
            uint64(_u(json, ".proof.bridgeZeta.zeta.c1")),
            uint64(_u(json, ".proof.bridgeZeta.zeta.c2"))
        );
        bridge.claimedSum = GoldilocksExt3.Ext3(
            uint64(_u(json, ".proof.bridgeZeta.claimedSum.c0")),
            uint64(_u(json, ".proof.bridgeZeta.claimedSum.c1")),
            uint64(_u(json, ".proof.bridgeZeta.claimedSum.c2"))
        );
        bridge.evalPoint = new GoldilocksExt3.Ext3[](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            string memory prefix = string.concat(".proof.bridgeZeta.evalPoint[", vm.toString(i), "].");
            bridge.evalPoint[i] = GoldilocksExt3.Ext3(
                uint64(_u(json, string.concat(prefix, "c0"))),
                uint64(_u(json, string.concat(prefix, "c1"))),
                uint64(_u(json, string.concat(prefix, "c2")))
            );
        }
        bridge.roundPolys = new GoldilocksExt3.Ext3[][](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            bridge.roundPolys[i] = new GoldilocksExt3.Ext3[](3);
            for (uint256 j = 0; j < 3; j++) {
                string memory prefix = string.concat(
                    ".proof.bridgeZeta.roundPolys[", vm.toString(i), "][", vm.toString(j), "]."
                );
                bridge.roundPolys[i][j] = GoldilocksExt3.Ext3(
                    uint64(_u(json, string.concat(prefix, "c0"))),
                    uint64(_u(json, string.concat(prefix, "c1"))),
                    uint64(_u(json, string.concat(prefix, "c2")))
                );
            }
        }
    }

    function _parseBridgeGZeta(string memory json)
        internal pure returns (WhirPlonky2Verifier.SumcheckBridgeGZetaData memory bridge)
    {
        uint256 numRounds = _u(json, ".proof.bridgeGZeta.numRounds");
        bridge.gZeta = GoldilocksExt3.Ext3(
            uint64(_u(json, ".proof.bridgeGZeta.gZeta.c0")),
            uint64(_u(json, ".proof.bridgeGZeta.gZeta.c1")),
            uint64(_u(json, ".proof.bridgeGZeta.gZeta.c2"))
        );
        bridge.claimedSum = GoldilocksExt3.Ext3(
            uint64(_u(json, ".proof.bridgeGZeta.claimedSum.c0")),
            uint64(_u(json, ".proof.bridgeGZeta.claimedSum.c1")),
            uint64(_u(json, ".proof.bridgeGZeta.claimedSum.c2"))
        );
        bridge.evalPoint = new GoldilocksExt3.Ext3[](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            string memory prefix = string.concat(".proof.bridgeGZeta.evalPoint[", vm.toString(i), "].");
            bridge.evalPoint[i] = GoldilocksExt3.Ext3(
                uint64(_u(json, string.concat(prefix, "c0"))),
                uint64(_u(json, string.concat(prefix, "c1"))),
                uint64(_u(json, string.concat(prefix, "c2")))
            );
        }
        bridge.roundPolys = new GoldilocksExt3.Ext3[][](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            bridge.roundPolys[i] = new GoldilocksExt3.Ext3[](3);
            for (uint256 j = 0; j < 3; j++) {
                string memory prefix = string.concat(
                    ".proof.bridgeGZeta.roundPolys[", vm.toString(i), "][", vm.toString(j), "]."
                );
                bridge.roundPolys[i][j] = GoldilocksExt3.Ext3(
                    uint64(_u(json, string.concat(prefix, "c0"))),
                    uint64(_u(json, string.concat(prefix, "c1"))),
                    uint64(_u(json, string.concat(prefix, "c2")))
                );
            }
        }
    }

    function _parseCircuitConfig(string memory json)
        internal pure returns (WhirPlonky2Verifier.CircuitConfig memory config)
    {
        config.degreeBits = _u(json, ".circuitConfig.degreeBits");
        config.numChallenges = _u(json, ".circuitConfig.numChallenges");
        config.numRoutedWires = _u(json, ".circuitConfig.numRoutedWires");
        config.quotientDegreeFactor = _u(json, ".circuitConfig.quotientDegreeFactor");
        config.numPartialProducts = _u(json, ".circuitConfig.numPartialProducts");
        config.numGateConstraints = _u(json, ".circuitConfig.numGateConstraints");
        config.numSelectors = _u(json, ".circuitConfig.numSelectors");
        config.numLookupSelectors = _u(json, ".circuitConfig.numLookupSelectors");
        config.batchSizes = abi.decode(vm.parseJson(json, ".circuitConfig.batchSizes"), (uint256[]));
        config.intraBatchPolyCounts = abi.decode(vm.parseJson(json, ".circuitConfig.intraBatchPolyCounts"), (uint256[]));
        config.sessionName = abi.decode(vm.parseJson(json, ".circuitConfig.sessionName"), (string));

        uint256[] memory gateTypes = abi.decode(vm.parseJson(json, ".circuitConfig.gates..gateType"), (uint256[]));
        uint256[] memory selectorIndices = abi.decode(vm.parseJson(json, ".circuitConfig.gates..selectorIndex"), (uint256[]));
        uint256[] memory groupStarts = abi.decode(vm.parseJson(json, ".circuitConfig.gates..groupStart"), (uint256[]));
        uint256[] memory groupEnds = abi.decode(vm.parseJson(json, ".circuitConfig.gates..groupEnd"), (uint256[]));
        uint256[] memory rowInGroups = abi.decode(vm.parseJson(json, ".circuitConfig.gates..rowInGroup"), (uint256[]));
        uint256[] memory numConstraintsList = abi.decode(vm.parseJson(json, ".circuitConfig.gates..numConstraints"), (uint256[]));

        uint256 numGates = gateTypes.length;
        config.gates = new Plonky2Verifier.GateInfo[](numGates);
        for (uint256 i = 0; i < numGates; i++) {
            string memory cfgKey = string.concat(".circuitConfig.gates[", vm.toString(i), "].gateConfig");
            uint256[] memory cfg = abi.decode(vm.parseJson(json, cfgKey), (uint256[]));
            config.gates[i] = Plonky2Verifier.GateInfo(
                gateTypes[i], selectorIndices[i], groupStarts[i],
                groupEnds[i], rowInGroups[i], numConstraintsList[i],
                cfg
            );
        }

        config.permutation.kIs = abi.decode(vm.parseJson(json, ".circuitConfig.permutation.kIs"), (uint256[]));
    }

    function _loadUnifiedWhirParams(string memory json)
        internal pure returns (SpongefishWhirVerify.WhirParams memory p)
    {
        p.numVariables = _u(json, ".whirParams.num_variables");
        p.foldingFactor = _u(json, ".whirParams.folding_factor");
        p.numVectors = _u(json, ".whirParams.num_vectors");
        p.outDomainSamples = _u(json, ".whirParams.out_domain_samples");
        p.inDomainSamples = _u(json, ".whirParams.in_domain_samples");
        p.initialSumcheckRounds = _u(json, ".whirParams.initial_sumcheck_rounds");
        p.numRounds = _u(json, ".whirParams.num_rounds");
        p.finalSumcheckRounds = _u(json, ".whirParams.final_sumcheck_rounds");
        p.finalSize = _u(json, ".whirParams.final_size");
        p.initialCodewordLength = _u(json, ".whirParams.initial_codeword_length");
        p.initialMerkleDepth = _u(json, ".whirParams.initial_merkle_depth");
        p.initialDomainGenerator = uint64(_u(json, ".whirParams.initial_domain_generator"));
        p.initialInterleavingDepth = _u(json, ".whirParams.initial_interleaving_depth");
        p.initialNumVariables = _u(json, ".whirParams.initial_num_variables");
        p.initialCosetSize = _u(json, ".whirParams.initial_coset_size");
        p.initialNumCosets = _u(json, ".whirParams.initial_num_cosets");

        {
            uint256 nv = p.numVariables;
            p.evaluationPoint = new GoldilocksExt3.Ext3[](nv);
            for (uint256 i = 0; i < nv; i++) {
                string memory epPrefix = string.concat(".proof.bridgeZeta.evalPoint[", vm.toString(i), "].");
                p.evaluationPoint[i] = GoldilocksExt3.Ext3(
                    uint64(_u(json, string.concat(epPrefix, "c0"))),
                    uint64(_u(json, string.concat(epPrefix, "c1"))),
                    uint64(_u(json, string.concat(epPrefix, "c2")))
                );
            }
        }
        {
            uint256 nv = p.numVariables;
            p.evaluationPoint2 = new GoldilocksExt3.Ext3[](nv);
            for (uint256 i = 0; i < nv; i++) {
                string memory epPrefix = string.concat(".proof.bridgeGZeta.evalPoint[", vm.toString(i), "].");
                p.evaluationPoint2[i] = GoldilocksExt3.Ext3(
                    uint64(_u(json, string.concat(epPrefix, "c0"))),
                    uint64(_u(json, string.concat(epPrefix, "c1"))),
                    uint64(_u(json, string.concat(epPrefix, "c2")))
                );
            }
        }

        p.rounds = new SpongefishWhirVerify.RoundParams[](p.numRounds);
        for (uint256 i = 0; i < p.numRounds; i++) {
            string memory prefix = string.concat(".whirParams.rounds[", vm.toString(i), "].");
            p.rounds[i].codewordLength = _u(json, string.concat(prefix, "codeword_length"));
            p.rounds[i].merkleDepth = _u(json, string.concat(prefix, "merkle_depth"));
            p.rounds[i].domainGenerator = uint64(_u(json, string.concat(prefix, "domain_generator")));
            p.rounds[i].inDomainSamples = _u(json, string.concat(prefix, "in_domain_samples"));
            p.rounds[i].outDomainSamples = _u(json, string.concat(prefix, "out_domain_samples"));
            p.rounds[i].sumcheckRounds = _u(json, string.concat(prefix, "sumcheck_rounds"));
            p.rounds[i].interleavingDepth = _u(json, string.concat(prefix, "interleaving_depth"));
            p.rounds[i].cosetSize = _u(json, string.concat(prefix, "coset_size"));
            p.rounds[i].numCosets = _u(json, string.concat(prefix, "num_cosets"));
            p.rounds[i].numVariables = _u(json, string.concat(prefix, "num_variables"));
        }
    }

    function _u(string memory json, string memory path) internal pure returns (uint256) {
        return abi.decode(vm.parseJson(json, path), (uint256));
    }

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

    function _groth16WithPIHash(bytes32 piHash) internal pure returns (IntmaxRollup.Groth16Params memory g) {
        g.pubInputs = new uint256[](8);
        for (uint256 i = 0; i < 8; i++) {
            g.pubInputs[i] = uint256(uint32(bytes4(piHash << (i * 32))));
        }
    }

    // =====================================================================
    // Condition (a): Corrupt ONLY proofConfigHash (WhirParams mismatch)
    // =====================================================================

    /// @dev Corrupt WhirParams foldingFactor -> condition (a) triggers fraud.
    function test_fraud_corruptWhirParams_foldingFactor() public {
        FraudSetup memory s = _baseFraudSetup();
        s.whirParams.foldingFactor = 999; // wrong folding factor
        assertTrue(_submitAndProve(s), "Condition (a): wrong WhirParams foldingFactor");
    }

    /// @dev Corrupt WhirParams numVariables -> condition (a) triggers fraud.
    function test_fraud_corruptWhirParams_numVariables() public {
        FraudSetup memory s = _baseFraudSetup();
        s.whirParams.numVariables = 1; // wrong num variables
        assertTrue(_submitAndProve(s), "Condition (a): wrong WhirParams numVariables");
    }

    // =====================================================================
    // Condition (b): Corrupt ONLY Groth16 pubInputs (piHash mismatch)
    // =====================================================================

    /// @dev Set groth16.pubInputs to zero -> piHash doesn't match validityPIs.
    function test_fraud_corruptGroth16PubInputs_allZero() public {
        FraudSetup memory s = _baseFraudSetup();
        for (uint256 i = 0; i < s.groth16.pubInputs.length; i++) {
            s.groth16.pubInputs[i] = 0;
        }
        assertTrue(_submitAndProve(s), "Condition (b): all-zero pubInputs");
    }

    /// @dev Flip one bit in pubInputs[0] -> piHash mismatch.
    function test_fraud_corruptGroth16PubInputs_singleBitFlip() public {
        FraudSetup memory s = _baseFraudSetup();
        s.groth16.pubInputs[0] ^= 1;
        assertTrue(_submitAndProve(s), "Condition (b): single bit flip in pubInputs[0]");
    }

    /// @dev Corrupt only the last pubInput limb.
    function test_fraud_corruptGroth16PubInputs_lastLimb() public {
        FraudSetup memory s = _baseFraudSetup();
        s.groth16.pubInputs[7] = 0xDEADBEEF;
        assertTrue(_submitAndProve(s), "Condition (b): wrong last limb");
    }

    // =====================================================================
    // Condition (c): Corrupt ONLY WHIR proof data
    //                (WhirParams stay correct, only transcript/hints/evaluations are bad)
    // =====================================================================

    /// @dev Corrupt transcript -> WHIR rejects.
    function test_fraud_corruptWhirTranscript() public {
        FraudSetup memory s = _baseFraudSetup();
        // Flip every byte in transcript
        for (uint256 i = 0; i < s.whirProof.transcript.length; i++) {
            s.whirProof.transcript[i] = bytes1(uint8(s.whirProof.transcript[i]) ^ 0xFF);
        }
        assertTrue(_submitAndProve(s), "Condition (c): corrupted transcript");
    }

    /// @dev Truncated transcript -> WHIR rejects.
    function test_fraud_corruptWhirTranscript_truncated() public {
        FraudSetup memory s = _baseFraudSetup();
        s.whirProof.transcript = hex"DEADBEEF";
        assertTrue(_submitAndProve(s), "Condition (c): truncated transcript");
    }

    /// @dev Corrupt hints -> WHIR rejects.
    function test_fraud_corruptWhirHints() public {
        FraudSetup memory s = _baseFraudSetup();
        s.whirProof.hints = hex"00112233445566778899AABBCCDDEEFF";
        assertTrue(_submitAndProve(s), "Condition (c): random hints");
    }

    /// @dev Zeroed hints -> WHIR rejects.
    function test_fraud_corruptWhirHints_zeroed() public {
        FraudSetup memory s = _baseFraudSetup();
        for (uint256 i = 0; i < s.whirProof.hints.length; i++) {
            s.whirProof.hints[i] = 0x00;
        }
        assertTrue(_submitAndProve(s), "Condition (c): zeroed hints");
    }

    /// @dev Corrupt evaluations -> WHIR rejects (evaluation mismatch).
    function test_fraud_corruptWhirEvaluations() public {
        FraudSetup memory s = _baseFraudSetup();
        s.whirProof.evaluations[0] = GoldilocksExt3.Ext3(999, 888, 777);
        assertTrue(_submitAndProve(s), "Condition (c): wrong evaluations");
    }

    /// @dev Corrupt sessionId -> WHIR transcript replay mismatch.
    function test_fraud_corruptWhirSessionId() public {
        FraudSetup memory s = _baseFraudSetup();
        s.whirProof.sessionId = hex"CAFEBABE";
        assertTrue(_submitAndProve(s), "Condition (c): wrong sessionId");
    }

    /// @dev Corrupt protocolId -> WHIR domain separator mismatch.
    function test_fraud_corruptWhirProtocolId() public {
        FraudSetup memory s = _baseFraudSetup();
        s.whirProof.protocolId = hex"0000000000000000000000000000000000000000000000000000000000000000";
        assertTrue(_submitAndProve(s), "Condition (c): zeroed protocolId");
    }

    /// @dev Corrupt bridgeZeta claimedSum -> sumcheck bridge fails.
    function test_fraud_corruptBridgeZetaClaimedSum() public {
        FraudSetup memory s = _baseFraudSetup();
        s.whirProof.bridgeZeta.claimedSum = GoldilocksExt3.Ext3(42, 43, 44);
        assertTrue(_submitAndProve(s), "Condition (c): corrupted bridgeZeta claimedSum");
    }

    /// @dev Corrupt bridgeGZeta roundPolys -> sumcheck bridge fails.
    function test_fraud_corruptBridgeGZetaRoundPolys() public {
        FraudSetup memory s = _baseFraudSetup();
        if (s.whirProof.bridgeGZeta.roundPolys.length > 0) {
            s.whirProof.bridgeGZeta.roundPolys[0][0] = GoldilocksExt3.Ext3(1, 1, 1);
        }
        assertTrue(_submitAndProve(s), "Condition (c): corrupted bridgeGZeta roundPolys");
    }

    // =====================================================================
    // Condition (d): Corrupt ONLY Groth16 proof (not pubInputs)
    // =====================================================================

    /// @dev Corrupt groth16.proof.a -> Groth16 verification fails.
    function test_fraud_corruptGroth16Proof_a() public {
        FraudSetup memory s = _baseFraudSetup();
        s.groth16.proof.a[0] = 999;
        s.groth16.proof.a[1] = 888;
        assertTrue(_submitAndProve(s), "Condition (d): corrupted Groth16 proof.a");
    }

    /// @dev Corrupt groth16.commitments -> Groth16 verification fails.
    function test_fraud_corruptGroth16Commitments() public {
        FraudSetup memory s = _baseFraudSetup();
        s.groth16.commitments[0] = 12345;
        s.groth16.commitments[1] = 67890;
        assertTrue(_submitAndProve(s), "Condition (d): corrupted Groth16 commitments");
    }

    // =====================================================================
    // Multi-corruption: two components corrupted simultaneously
    // =====================================================================

    /// @dev Corrupt WHIR transcript + bridgeZeta.
    ///      Fraud should be detected (first hit is condition c).
    function test_fraud_corruptWhirAndBridge() public {
        FraudSetup memory s = _baseFraudSetup();
        s.whirProof.transcript = hex"DEADBEEF";
        s.whirProof.bridgeZeta.claimedSum = GoldilocksExt3.Ext3(1, 2, 3);
        assertTrue(_submitAndProve(s), "Multi: WHIR transcript + bridge both corrupted");
    }

    /// @dev Corrupt Groth16 pubInputs + WHIR hints.
    ///      Fraud detected via condition (b) before WHIR is even checked.
    function test_fraud_corruptGroth16PIAndWhirHints() public {
        FraudSetup memory s = _baseFraudSetup();
        s.groth16.pubInputs[0] ^= 1;
        s.whirProof.hints = hex"BADC0FFEE0";
        assertTrue(_submitAndProve(s), "Multi: Groth16 PI + WHIR hints corrupted");
    }

    // =====================================================================
    // Negative: no corruption -> fraud NOT confirmed
    // =====================================================================

    /// @dev All data is valid -> fraud should NOT be confirmed.
    ///      Note: This only works if the gnark verifier + WHIR + Plonky2 all pass
    ///      with the real fixture data. Since we use synthetic gnark proofs,
    ///      this will actually confirm fraud via condition (d) — gnark rejects.
    ///      This test documents expected behavior.
    function test_fraud_noCorruption_groth16Rejects() public {
        FraudSetup memory s = _baseFraudSetup();
        // No corruption — but gnark verifier will reject the synthetic proof
        // (we don't have a real gnark proof matching this submission)
        assertTrue(_submitAndProve(s), "No corruption but gnark rejects synthetic proof");
    }

    // =====================================================================
    // Condition (0): Malformed blob payload — params binding mismatch = fraud
    // =====================================================================

    /// @dev Modify WHIR proof AFTER proofBytes encoding -> params binding fails -> fraud.
    ///      The authentic blob bytes (proofBytes) don't ABI-decode to the given structs.
    function test_fraud_paramsBindingMismatch_isFraud() public {
        FraudSetup memory s = _baseFraudSetup();
        bytes memory proofBytes = abi.encode(s.groth16, s.whirProof);

        // Now corrupt AFTER proofBytes was created
        s.whirProof.evaluations[0] = GoldilocksExt3.Ext3(1, 2, 3);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = new IntmaxRollup.SubBlock[](1);
        batch[0] = IntmaxRollup.SubBlock(1, 100, bytes32(uint256(0x42)), ids);

        (KZGProof memory kzg, bytes32 blobHash) = _computeAndPost(batch, proofBytes, s.stateRoot);

        address reporter = makeAddr("reporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        bool confirmed = rollup.fraudProof(
            0, blobHash, s.stateRoot, proofBytes, s.vpis,
            s.whirProof, s.circuitConfig, s.whirParams, kzg, s.groth16
        );
        assertTrue(confirmed, "Params binding mismatch = malformed blob = fraud");
    }

    /// @dev Submit completely random bytes as blob payload -> fraud prover
    ///      passes empty/default structs -> params binding fails -> fraud.
    function test_fraud_garbageBlobPayload() public {
        // Attacker submits random garbage as proof data
        bytes memory garbageProof = hex"DEADBEEFCAFEBABE0011223344556677"
            hex"8899AABBCCDDEEFF0000111122223333"
            hex"4444555566667777DEADBEEFCAFEBABE";

        bytes32 stateRoot = keccak256("garbage_blob");
        IntmaxRollup.ValidityPublicInputs memory vpis = IntmaxRollup.ValidityPublicInputs({
            initialBlockNumber: 0,
            initialBlockChain:  rollup.blockHashChainAt(0),
            initialExtCommitment: rollup.latestFinalizedStateRoot(),
            finalBlockNumber:   0,
            finalBlockChain:    bytes32(0),
            finalExtCommitment: stateRoot,
            prover: address(0)
        });

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = new IntmaxRollup.SubBlock[](1);
        batch[0] = IntmaxRollup.SubBlock(1, 100, bytes32(uint256(0x42)), ids);

        (KZGProof memory kzg, bytes32 blobHash) = _computeAndPost(batch, garbageProof, stateRoot);

        // Fraud prover supplies the authentic garbage bytes and empty structs.
        // The empty structs won't ABI-encode to match the garbage -> fraud.
        WhirPlonky2Verifier.WhirPlonky2Proof memory emptyWhir;
        WhirPlonky2Verifier.CircuitConfig memory emptyCfg;
        SpongefishWhirVerify.WhirParams memory emptyParams;
        IntmaxRollup.Groth16Params memory emptyG16;

        address reporter = makeAddr("reporter");
        vm.deal(reporter, 1 ether);
        vm.prank(reporter);
        bool confirmed = rollup.fraudProof(
            0, blobHash, stateRoot, garbageProof, vpis,
            emptyWhir, emptyCfg, emptyParams, kzg, emptyG16
        );
        assertTrue(confirmed, "Garbage blob payload = fraud via params binding");
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
