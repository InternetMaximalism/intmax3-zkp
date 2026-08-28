// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BlobKZGVerifier, BlobKZGVerifierExt, KZGProof} from "../src/BlobKZGVerifier.sol";

/// @title BlobKzgPairing
/// @notice Regression tests for round-2 findings B-1 and B-2, and the FIRST real exercise of
///         `BlobKZGVerifier`'s general (non-degenerate) pairing branch.
///
///  Round 1 asserted "the pairing precompile is unavailable in Foundry 1.5.x, verified
///  empirically". It had measured `address(0x11)`, which under the final EIP-2537 is
///  MAP_FP2_TO_G2 — of course it rejects a 768-byte pairing instance. The real map is
///
///    0x0b G1ADD | 0x0c G1MSM | 0x0d G2ADD | 0x0e G2MSM
///    0x0f PAIRING_CHECK | 0x10 MAP_FP_TO_G1 | 0x11 MAP_FP2_TO_G2
///
///  and PAIRING_CHECK at 0x0f works fine in this EVM. Compounding it, the shipped `G2_GENERATOR`
///  laid X out as (x_c1 || x_c0) instead of EIP-2537's (x_c0 || x_c1), so even at the right
///  address the general branch fed the precompile an invalid point.
///
///  Every test in this file FAILS on the pre-fix contracts.
contract BlobKzgPairingTest is Test {
    address constant PAIRING_CHECK = address(0x0f);
    address constant G1ADD         = address(0x0b);
    address constant G1MSM         = address(0x0c);
    address constant G2ADD         = address(0x0d);
    address constant MAP_FP2_TO_G2 = address(0x11); // what BLS12_PAIRING used to be

    uint256 internal constant BLS12_SCALAR_R =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    bytes32 internal constant NEG_ONE =
        bytes32(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000);

    // =======================================================================
    // B-1 — PAIRING_CHECK is 0x0f, and it runs
    // =======================================================================

    /// @dev The general pairing branch is now RUNNABLE, and it discriminates:
    ///        e(P,Q)·e(−P,Q) = 1  is ACCEPTED
    ///        e(P,Q)·e(P,Q)  ≠ 1  is REJECTED
    ///      Round 1 could not make this assertion at all, which is why the general branch shipped
    ///      broken for two releases.
    function test_B1_pairingCheckAt0x0fRunsAndDiscriminates() public view {
        bytes memory P = _g1Gen();
        bytes memory Q = BlobKZGVerifier.G2_GENERATOR;

        (bool ok, bytes memory ret) =
            PAIRING_CHECK.staticcall{gas: 3_000_000}(bytes.concat(P, Q, _g1Neg(P), Q));
        assertTrue(ok, "0x0f (PAIRING_CHECK) is available in this EVM");
        assertEq(ret.length, 32, "PAIRING_CHECK returns one word");
        assertEq(abi.decode(ret, (uint256)), 1, "e(P,Q)*e(-P,Q) == 1 is ACCEPTED");

        (bool ok2, bytes memory ret2) =
            PAIRING_CHECK.staticcall{gas: 3_000_000}(bytes.concat(P, Q, P, Q));
        assertTrue(ok2, "PAIRING_CHECK evaluates the false instance too");
        assertEq(abi.decode(ret2, (uint256)), 0, "e(P,Q)^2 != 1 is REJECTED");
    }

    /// @dev 0x11 is a different, present precompile (MAP_FP2_TO_G2). It returns a 256-byte G2
    ///      point for a 128-byte input and cannot evaluate a pairing instance at all — which is
    ///      exactly the observation round 1 mistook for "the pairing precompile is unavailable".
    function test_B1_theOldAddressWasMapFp2ToG2() public view {
        (bool okMap, bytes memory retMap) = MAP_FP2_TO_G2.staticcall{gas: 3_000_000}(new bytes(128));
        assertTrue(okMap, "0x11 is present");
        assertEq(retMap.length, 256, "0x11 maps Fp2 -> G2; it is not a pairing check");

        bytes memory P = _g1Gen();
        bytes memory Q = BlobKZGVerifier.G2_GENERATOR;
        (bool okBad,) = MAP_FP2_TO_G2.staticcall{gas: 3_000_000}(bytes.concat(P, Q, _g1Neg(P), Q));
        assertFalse(okBad, "0x11 cannot evaluate a 768-byte pairing instance");
    }

    // =======================================================================
    // B-2 — the shipped G2_GENERATOR is now a valid EIP-2537 encoding
    // =======================================================================

    function test_B2_shippedG2GeneratorIsAValidPoint() public view {
        bytes memory shipped = BlobKZGVerifier.G2_GENERATOR;
        assertEq(shipped.length, 256, "G2 point is 256 bytes");

        // G2ADD accepts it (it rejects the pre-fix (x_c1 || x_c0) layout outright).
        (bool okAdd, bytes memory sum) =
            G2ADD.staticcall{gas: 3_000_000}(bytes.concat(shipped, shipped));
        assertTrue(okAdd && sum.length == 256, "G2ADD accepts the shipped generator");

        // And it is byte-equal to the canonical EIP-2537 encoding.
        assertEq(keccak256(shipped), keccak256(_g2GenCanonical()), "shipped == canonical");

        // The pre-fix constant is rejected by both, pinning that this was a real defect.
        bytes memory preFix = _g2GenPreFix();
        assertTrue(keccak256(preFix) != keccak256(shipped), "the constant actually changed");
        (bool okOldAdd,) = G2ADD.staticcall{gas: 3_000_000}(bytes.concat(preFix, preFix));
        assertFalse(okOldAdd, "G2ADD rejects the pre-fix constant");
        (bool okOldPair,) = PAIRING_CHECK.staticcall{gas: 3_000_000}(
            bytes.concat(_g1Gen(), preFix, _g1Neg(_g1Gen()), preFix)
        );
        assertFalse(okOldPair, "PAIRING_CHECK rejects the pre-fix constant");
    }

    // =======================================================================
    // B-1+B-2 — the general branch of the LIBRARY, on a PRODUCTION satellite
    // =======================================================================

    /// @dev A well-formed NON-degenerate opening (Z(τ) = 2, so the degenerate guard does not fire)
    ///      is accepted by `BlobKZGVerifierExt(false)` — the configuration all six deploy scripts
    ///      use. Pre-fix this reverted `BKV_PairingCheckFailed`, which is what made
    ///      `IntmaxRollup._verifyFraud` pre-condition 2 unsatisfiable (finding B-3).
    function test_B1B2_productionSatelliteAcceptsAWellFormedGeneralOpening() public {
        BlobKZGVerifierExt prod = new BlobKZGVerifierExt(false);
        bytes memory blob = _sampleBlob();
        (KZGProof memory kzg, bytes32 blobHash) = generalOpening(blob);

        // Not the degenerate instance: the guard is not what is letting this through.
        assertTrue(
            keccak256(kzg.vanishingG2) != keccak256(BlobKZGVerifier.G2_GENERATOR),
            "the opening must exercise the GENERAL branch, not the Z(tau)=1 fast path"
        );
        prod.verify(blobHash, kzg, blob); // must not revert
    }

    /// @dev ...and the same branch still REJECTS an opening that does not match the bytes: flip
    ///      one byte of the blob and the pairing equation fails. Without this the "acceptance"
    ///      test above would be satisfied by a vacuous branch.
    function test_B1B2_productionSatelliteRejectsATamperedBlob() public {
        BlobKZGVerifierExt prod = new BlobKZGVerifierExt(false);
        bytes memory blob = _sampleBlob();
        (KZGProof memory kzg, bytes32 blobHash) = generalOpening(blob);

        bytes memory tampered = _sampleBlob();
        tampered[7] = bytes1(uint8(tampered[7]) ^ 0x01); // same length, different contents

        vm.expectRevert(BlobKZGVerifier.BKV_PairingFailed.selector);
        prod.verify(blobHash, kzg, tampered);
    }

    // =======================================================================
    // Helpers
    // =======================================================================

    /// @dev Build a mathematically valid, NON-degenerate KZG multi-point opening for `data`.
    ///
    ///      The verifier equation is  e(C − [I(τ)]₁, G2) · e(−π, [Z(τ)]₂) = 1, i.e. in scalars
    ///      C − I = z·π where z = Z(τ). Nothing on-chain constrains the trusted-setup points, so
    ///      a self-consistent instance is built by choosing them:
    ///        lagrangeBasisG1[i] = G1        ⇒ [I(τ)]₁ = (Σ fᵢ)·G1 = S·G1
    ///        z = 2                          ⇒ vanishingG2 = G2ADD(G2, G2)  (NOT the generator,
    ///                                         so the degenerate guard does not fire)
    ///        π = q·G1 with q = 7            ⇒ C = (S + 2q)·G1
    ///      Then C − I = 14·G1 = 2·π and the pairing holds.
    ///
    ///      NOTE (residual B-6): this is exactly why the trusted-setup data must not stay
    ///      caller-supplied. The instance here is honest in FORM — it proves the general branch
    ///      computes the right equation — but the same freedom is what lets an attacker forge one.
    ///      See `RedTeamFraudBreaks::test_RT4_*` and the RESIDUAL RISK note in BlobKZGVerifier.
    function generalOpening(bytes memory data)
        public view returns (KZGProof memory kzg, bytes32 blobHash)
    {
        bytes32[] memory fes = _toFieldElements(data);
        uint256 N = fes.length;

        uint256 S = 0;
        for (uint256 i = 0; i < N; i++) S = addmod(S, uint256(fes[i]), BLS12_SCALAR_R);

        bytes memory g1 = _g1Gen();
        bytes memory pi = _g1Mul(g1, bytes32(uint256(7)));            // π = 7·G1
        bytes memory C  = _g1Mul(g1, bytes32(addmod(S, 14, BLS12_SCALAR_R))); // C = (S+14)·G1

        bytes memory basis = new bytes(N * 128);
        for (uint256 i = 0; i < N; i++) {
            assembly {
                let src := add(g1, 32)
                let dst := add(add(basis, 32), mul(i, 128))
                mstore(dst,          mload(src))
                mstore(add(dst, 32), mload(add(src, 32)))
                mstore(add(dst, 64), mload(add(src, 64)))
                mstore(add(dst, 96), mload(add(src, 96)))
            }
        }

        bytes memory c48 = _compressG1(C);
        (bool okSha, bytes memory hb) = address(0x02).staticcall(c48);
        require(okSha && hb.length >= 32, "sha256 failed");
        blobHash = bytes32((uint256(0x01) << 248) | (uint256(bytes32(hb)) & (type(uint256).max >> 8)));

        kzg = KZGProof({
            kzgCommitment48: c48,
            kzgCommitmentG1: C,
            openingProof:    pi,
            vanishingG2:     _g2Times2(),
            lagrangeBasisG1: basis
        });
    }

    function _sampleBlob() internal pure returns (bytes memory) {
        return abi.encodePacked(
            keccak256("intmax3 blob word 0"),
            keccak256("intmax3 blob word 1"),
            keccak256("intmax3 blob word 2")
        );
    }

    function _g1Gen() internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f",
            hex"c3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            hex"0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4",
            hex"fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
        );
    }

    /// @dev The canonical EIP-2537 G2 generator: x_c0 || x_c1 || y_c0 || y_c1.
    function _g2GenCanonical() internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051",
            hex"c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
            hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65",
            hex"596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
            hex"000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a",
            hex"adfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
            hex"000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99",
            hex"cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
        );
    }

    /// @dev The constant `BlobKZGVerifier.G2_GENERATOR` used to hold: X as (x_c1 || x_c0).
    function _g2GenPreFix() internal pure returns (bytes memory) {
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

    function _g2Times2() internal view returns (bytes memory out) {
        bytes memory g2 = BlobKZGVerifier.G2_GENERATOR;
        bool ok;
        (ok, out) = G2ADD.staticcall(bytes.concat(g2, g2));
        require(ok && out.length == 256, "G2ADD failed");
    }

    function _g1Mul(bytes memory pt, bytes32 s) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = G1MSM.staticcall(abi.encodePacked(pt, s));
        require(ok && out.length == 128, "G1MSM failed");
    }

    function _g1Neg(bytes memory pt) internal view returns (bytes memory) {
        return _g1Mul(pt, NEG_ONE);
    }

    function _toFieldElements(bytes memory data) internal pure returns (bytes32[] memory fes) {
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
                for (uint256 j = 0; j < rem; j++) tmp[j] = data[off + j];
                assembly { word := mload(add(tmp, 32)) }
            }
            fes[i] = bytes32(uint256(word) & FIELD_MASK);
        }
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
}
