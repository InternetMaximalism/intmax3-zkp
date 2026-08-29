// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2 as console} from "forge-std/Test.sol";

/// @notice RED TEAM probe of `BlobKZGVerifier`'s EIP-2537 assumptions.
///
///  Final EIP-2537 (Prague/Pectra) precompile map:
///    0x0b G1ADD | 0x0c G1MSM | 0x0d G2ADD | 0x0e G2MSM
///    0x0f PAIRING_CHECK | 0x10 MAP_FP_TO_G1 | 0x11 MAP_FP2_TO_G2
///
///  RED TEAM CLAIM (round 2): `BlobKZGVerifier.BLS12_PAIRING` is `address(0x11)` — that is
///  MAP_FP2_TO_G2, not the pairing check. And `BlobKZGVerifier.G2_GENERATOR` orders the X
///  coordinate as (c1 || c0) while EIP-2537 requires (c0 || c1), so the constant is not a valid
///  G2 encoding at all.
///
///  DEFENCE (round 2): both claims were correct and both are FIXED — `BLS12_PAIRING` is now 0x0f
///  and `G2_GENERATOR` is now (x_c0 || x_c1). The probe is kept verbatim as the record of the
///  attack; only the two assertions that named the SHIPPED constant are re-pointed at the
///  library's current value, so the file now proves the fix rather than the defect. The
///  end-to-end consequences are pinned in `BlobKzgPairing.t.sol` and
///  `RollupFraudHardening::test_B3_*`.
contract RedTeamBlsProbeTest is Test {
    address constant PAIRING_REAL = address(0x0f);
    address constant PAIRING_USED = address(0x11); // what BlobKZGVerifier calls

    function _g1Gen() internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f",
            hex"c3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            hex"0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4",
            hex"fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
        );
    }

    /// @dev The CORRECT EIP-2537 G2 generator: x_c0 || x_c1 || y_c0 || y_c1.
    function _g2GenCorrect() internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051", // x_c0
            hex"c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
            hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65", // x_c1
            hex"596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
            hex"000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a", // y_c0
            hex"adfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
            hex"000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99", // y_c1
            hex"cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
        );
    }

    /// @dev The constant `BlobKZGVerifier.G2_GENERATOR` used to hold, before the B-2 fix:
    ///      x_c1 || x_c0 || y_c0 || y_c1. Kept so the probe still demonstrates the defect.
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

    function _g1Neg(bytes memory pt) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = address(0x0c).staticcall(abi.encodePacked(
            pt, bytes32(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000)
        ));
        require(ok && out.length == 128, "neg failed");
    }

    /// @dev RT-5a (ATTACK, now FIXED): the general (production) pairing branch called address
    ///      0x11, which is MAP_FP2_TO_G2, not PAIRING_CHECK. The real pairing check lives at 0x0f
    ///      and works fine in this very EVM — so the H-4 patch's premise ("BLS12_PAIRING at 0x11
    ///      is unavailable in Foundry 1.5.x, verified empirically") measured the wrong address.
    ///      The observations below are unchanged; `BlobKZGVerifier.BLS12_PAIRING` is now 0x0f, so
    ///      the branch that consumes them is finally the working one.
    function test_RT5a_pairingPrecompileAddressWasWrong() public view {
        bytes memory P    = _g1Gen();
        bytes memory negP = _g1Neg(P);
        bytes memory Q    = _g2GenCorrect();

        // Accepting instance: e(P,Q) * e(-P,Q) = 1.
        (bool ok, bytes memory ret) = PAIRING_REAL.staticcall{gas: 3_000_000}(
            bytes.concat(P, Q, negP, Q)
        );
        assertTrue(ok, "0x0f (real PAIRING_CHECK) IS available in this EVM");
        assertEq(ret.length, 32, "0x0f returns one word");
        assertEq(abi.decode(ret, (uint256)), 1, "0x0f accepts a true instance");

        // Rejecting instance: e(P,Q) * e(P,Q) != 1.
        (bool ok2, bytes memory ret2) = PAIRING_REAL.staticcall{gas: 3_000_000}(
            bytes.concat(P, Q, P, Q)
        );
        assertTrue(ok2, "0x0f available");
        assertEq(abi.decode(ret2, (uint256)), 0, "0x0f rejects a false instance");

        // The address the contract uses is a DIFFERENT, present precompile: MAP_FP2_TO_G2.
        (bool okMap, bytes memory retMap) = PAIRING_USED.staticcall{gas: 3_000_000}(new bytes(128));
        assertTrue(okMap, "0x11 is present");
        assertEq(retMap.length, 256, "0x11 returns a G2 point => MAP_FP2_TO_G2, not a pairing");

        // ...and it rejects the 768-byte pairing instance, which is the observation the H-4 patch
        // mistook for "the pairing precompile is unavailable".
        (bool okBad, ) = PAIRING_USED.staticcall{gas: 3_000_000}(bytes.concat(P, Q, negP, Q));
        assertFalse(okBad, "0x11 cannot evaluate a pairing instance");
    }

    /// @dev RT-5b (ATTACK, now FIXED): the shipped `G2_GENERATOR` was not a valid EIP-2537 G2
    ///      encoding — its X coordinate was (c1 || c0) instead of (c0 || c1). Fed to the real
    ///      pairing precompile it is rejected outright, so even at the correct address the general
    ///      branch could never verify anything. The pre-fix bytes are still rejected below; the
    ///      library now ships the canonical encoding instead (see `BlobKzgPairing.t.sol`).
    function test_RT5b_preFixG2GeneratorConstantWasMalformed() public view {
        bytes memory shipped = _g2GenPreFix();
        assertTrue(
            keccak256(shipped) != keccak256(_g2GenCorrect()),
            "the pre-fix constant differs from the canonical EIP-2537 G2 generator"
        );

        bytes memory P    = _g1Gen();
        bytes memory negP = _g1Neg(P);

        // With the CORRECT generator the precompile accepts.
        (bool okGood, bytes memory retGood) = PAIRING_REAL.staticcall{gas: 3_000_000}(
            bytes.concat(P, _g2GenCorrect(), negP, _g2GenCorrect())
        );
        assertTrue(okGood && abi.decode(retGood, (uint256)) == 1, "correct encoding verifies");

        // With the SHIPPED constant the precompile rejects the input as an invalid point.
        (bool okBad, ) = PAIRING_REAL.staticcall{gas: 3_000_000}(
            bytes.concat(P, shipped, negP, shipped)
        );
        assertFalse(okBad, "RT-5b: the PRE-FIX G2_GENERATOR is not a valid G2 point");

        // G2ADD (0x0d) confirms it independently: it accepts the correct encoding and rejects the
        // shipped one.
        (bool addGood, bytes memory sum) = address(0x0d).staticcall{gas: 3_000_000}(
            bytes.concat(_g2GenCorrect(), _g2GenCorrect())
        );
        assertTrue(addGood && sum.length == 256, "G2ADD accepts the correct generator");
        (bool addBad, ) = address(0x0d).staticcall{gas: 3_000_000}(
            bytes.concat(shipped, shipped)
        );
        assertFalse(addBad, "G2ADD rejects the pre-fix constant");
    }
}
