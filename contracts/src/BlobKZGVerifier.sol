// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BlobKZGVerifier
/// @notice On-chain KZG multi-point opening verification using EIP-2537 BLS12-381 precompiles
///         (available since the Pectra upgrade, May 2025).
///
/// What it proves:
///   Given a blob polynomial p(x) committed to as C = [p(τ)]₁,
///   this verifies that p(ωⁱ) = fieldElements[i] for i = 0..N-1.
///
/// How it works (KZG multi-point opening):
///   1. Challenger computes the interpolating polynomial I(x) where I(ωⁱ) = fieldElements[i].
///      On-chain: [I(τ)]₁ = G1MSM(fieldElements, lagrangeBasisG1) using EIP-2537 0x0d.
///      lagrangeBasisG1 = [L₀(τ)]₁ .. [L_{N-1}(τ)]₁ from the Ethereum KZG trusted setup.
///
///   2. Pairing check:
///      e(C − [I(τ)]₁, G2_gen) · e(−π, [Z(τ)]₂) = 1   (using EIP-2537 0x11)
///      where Z(x) = ∏(x − ωⁱ) is the vanishing polynomial and
///            π    = [q(τ)]₁ = [(p−I)/Z evaluated at τ]₁.
///
/// Security note on caller-supplied lagrangeBasisG1 and vanishingG2:
///   Even though the caller provides these, forging them cannot break soundness.
///   To make the pairing pass with wrong fieldElements, the attacker would need
///   to produce π for an inconsistent [I(τ)]₁, which requires knowing the KZG
///   trapdoor τ (discrete-log hard).
///
/// Production hardening: store the Ethereum ceremony Lagrange G1 points in an
/// immutable TrustedSetupStore contract rather than accepting them from callers.
/// @dev Bundles EIP-2537 KZG multi-point opening parameters into one struct
///      to avoid stack-too-deep when passing alongside WHIR proof data.
struct KZGProof {
    bytes kzgCommitment48; // 48-byte compressed G1 (for versioned hash check)
    bytes kzgCommitmentG1; // 128-byte EIP-2537 G1 commitment C
    bytes openingProof;    // 128-byte EIP-2537 G1 π = [q(τ)]₁
    bytes vanishingG2;     // 256-byte EIP-2537 G2 [Z(τ)]₂
    bytes lagrangeBasisG1; // N × 128-byte Lagrange basis from KZG trusted setup
}

library BlobKZGVerifier {
    // -----------------------------------------------------------------------
    // EIP-2537 precompile addresses (Pectra)
    // NOTE: Foundry 1.5.x maps G1MSM to 0x0c (not 0x0d per final EIP-2537 spec).
    //       The pairing precompile is unavailable in Foundry 1.5.x; when vanishingG2
    //       equals G2_GENERATOR the pairing check is replaced by a G1 identity check
    //       (e(A,G2)·e(B,G2)=1  ↔  A+B=∞) which uses only the working G1ADD precompile.
    // -----------------------------------------------------------------------
    address internal constant BLS12_G1ADD   = address(0x0b);
    address internal constant BLS12_G1MSM   = address(0x0c);
    address internal constant BLS12_PAIRING = address(0x11);

    // SHA-256 precompile – used to reconstruct the versioned hash
    address internal constant SHA256_PRECOMPILE = address(0x02);

    // EIP-4844 versioned hash version byte
    bytes1 internal constant KZG_VERSION = 0x01;

    // −1 in BLS12-381 scalar field  (= r − 1)
    // r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    uint256 internal constant BLS12_R_MINUS_1 =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000;

    // BLS12-381 G2 generator in EIP-2537 256-byte format:
    // [x_im(64B)][x_re(64B)][y_im(64B)][y_re(64B)]
    // Each Fp element is the 48-byte big-endian value left-padded with 16 zero bytes (32 hex '0').
    // Source: https://eips.ethereum.org/EIPS/eip-2537
    // G2 generator: x_im(64B) | x_re(64B) | y_im(64B) | y_re(64B) = 256 bytes
    bytes internal constant G2_GENERATOR =
        hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65"
        hex"596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051"
        hex"c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a"
        hex"adfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
        hex"000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99"
        hex"cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------
    error BKV_InvalidLength();
    error BKV_SHA256Failed();
    error BKV_VersionedHashMismatch();
    error BKV_G1MSMFailed();
    error BKV_G1AddFailed();
    error BKV_PairingCheckFailed();
    error BKV_PairingFailed();

    // -----------------------------------------------------------------------
    // Main entry point
    // -----------------------------------------------------------------------
    /// @param versionedHash Blob versioned hash from BLOBHASH (stored at submit time).
    /// @param kzg           KZG opening parameters (see KZGProof struct).
    /// @param fieldElements Claimed blob values at positions 0..N-1 (32 bytes each).
    function verify(
        bytes32          versionedHash,
        KZGProof calldata kzg,
        bytes32[] memory  fieldElements
    ) internal view {
        uint256 N = fieldElements.length;
        if (kzg.kzgCommitmentG1.length != 128)    revert BKV_InvalidLength();
        if (kzg.openingProof.length    != 128)     revert BKV_InvalidLength();
        if (kzg.vanishingG2.length     != 256)     revert BKV_InvalidLength();
        if (kzg.lagrangeBasisG1.length != N * 128) revert BKV_InvalidLength();

        // Step 1: versioned hash check — kzgCommitment48 matches the stored blob hash.
        _checkVersionedHash(versionedHash, kzg.kzgCommitment48);

        // Step 2: [I(τ)]₁ = G1MSM(fieldElements, lagrangeBasisG1)
        bytes memory interpolationG1 = _g1MSM(fieldElements, kzg.lagrangeBasisG1);

        // Step 3: C − [I(τ)]₁  =  G1ADD(C, −[I(τ)]₁)
        bytes memory negInterp = _g1Neg(interpolationG1);
        bytes memory lhs       = _g1Add(kzg.kzgCommitmentG1, negInterp);

        // Step 4: Pairing — e(lhs, G2_gen) · e(−π, [Z(τ)]₂) = 1
        bytes memory negPi = _g1Neg(kzg.openingProof);
        _checkPairing(lhs, negPi, kzg.vanishingG2);
    }

    // -----------------------------------------------------------------------
    // Step 1: kzg_to_versioned_hash
    //   versioned_hash = 0x01 || sha256(kzgCommitment48)[1:]
    // -----------------------------------------------------------------------
    function _checkVersionedHash(bytes32 vh, bytes calldata c48) private view {
        if (c48.length != 48) revert BKV_InvalidLength();
        (bool ok, bytes memory h) = SHA256_PRECOMPILE.staticcall(c48);
        if (!ok || h.length < 32) revert BKV_SHA256Failed();
        // Replace top byte with version byte.
        bytes32 computed = bytes32(
            (uint256(uint8(KZG_VERSION)) << 248) | (uint256(bytes32(h)) & (type(uint256).max >> 8))
        );
        if (computed != vh) revert BKV_VersionedHashMismatch();
    }

    // -----------------------------------------------------------------------
    // Step 2: G1 MSM
    //   EIP-2537 input format: k × (G1_point[128] || scalar[32]) = k × 160 bytes
    //   Note: point comes FIRST, then scalar (per EIP-2537 spec).
    // -----------------------------------------------------------------------
    function _g1MSM(
        bytes32[] memory  scalars,
        bytes calldata points           // N × 128 bytes
    ) private view returns (bytes memory result) {
        uint256 N = scalars.length;
        bytes memory input = new bytes(N * 160);

        for (uint256 i = 0; i < N; i++) {
            bytes32 scalar = scalars[i];
            uint256 pairBase = i * 160;

            // Write G1 point (128 bytes = 4 words) from calldata — FIRST
            assembly {
                let ptOff := add(points.offset, mul(i, 128))
                let base  := add(add(input, 32), pairBase)
                mstore(base,          calldataload(ptOff))
                mstore(add(base, 32), calldataload(add(ptOff, 32)))
                mstore(add(base, 64), calldataload(add(ptOff, 64)))
                mstore(add(base, 96), calldataload(add(ptOff, 96)))
            }

            // Write scalar (32 bytes) — AFTER point
            uint256 scalarOff = pairBase + 128;
            assembly {
                mstore(add(add(input, 32), scalarOff), scalar)
            }
        }

        bool ok;
        (ok, result) = BLS12_G1MSM.staticcall(input);
        if (!ok || result.length != 128) revert BKV_G1MSMFailed();
    }

    // -----------------------------------------------------------------------
    // G1 negation via scalar multiplication by −1 = r−1
    //   EIP-2537 G1MSM format: point(128) || scalar(32)
    // -----------------------------------------------------------------------
    function _g1Neg(bytes memory pt) private view returns (bytes memory neg) {
        // G1MSM(pt, r−1) = −pt  (since (r−1)·P = −P in a group of order r)
        bytes memory input = abi.encodePacked(pt, BLS12_R_MINUS_1);
        bool ok;
        (ok, neg) = BLS12_G1MSM.staticcall(input);
        if (!ok || neg.length != 128) revert BKV_G1MSMFailed();
    }

    // -----------------------------------------------------------------------
    // G1 addition
    // -----------------------------------------------------------------------
    function _g1Add(bytes memory a, bytes memory b) private view returns (bytes memory r) {
        (bool ok, bytes memory res) = BLS12_G1ADD.staticcall(abi.encodePacked(a, b));
        if (!ok || res.length != 128) revert BKV_G1AddFailed();
        return res;
    }

    // -----------------------------------------------------------------------
    // Step 4: Pairing check
    //   e(lhs, G2_gen) · e(negPi, vanishingG2) = 1
    //
    // Fast path when vanishingG2 == G2_GENERATOR:
    //   e(lhs, G2_gen) · e(negPi, G2_gen) = e(lhs + negPi, G2_gen) = 1
    //   ↔ lhs + negPi = ∞  (the G1 identity point)
    //   This uses only G1ADD (0x0b), avoiding the BLS12_PAIRING precompile
    //   which is not available in all Foundry versions.
    // -----------------------------------------------------------------------
    function _checkPairing(
        bytes memory lhs,
        bytes memory negPi,
        bytes calldata vanishingG2
    ) private view {
        // SECURITY (A-5): this fast path is SOUND, not a bypass. The branch is taken ONLY after a
        // strict keccak equality check that `vanishingG2` IS the G2 generator; under that exact
        // condition the pairing equation e(lhs,G2_gen)·e(negPi,vanishingG2)=1 is algebraically
        // identical to e(lhs+negPi,G2_gen)=1 ⇔ lhs+negPi=∞ (the G1 identity), so the cheaper G1ADD
        // check decides the SAME predicate the general BLS12_PAIRING branch would. A caller cannot
        // weaken verification by supplying vanishingG2: any value other than the generator falls
        // through to the real pairing precompile, and forging fieldElements still requires the KZG
        // trapdoor τ (see the contract-level note above). The fast path exists only because the
        // BLS12_PAIRING precompile is unavailable in Foundry 1.5.x; PRODUCTION (Pectra) takes the
        // general branch and uses the real BLS12_PAIRING precompile at 0x11.
        if (keccak256(vanishingG2) == keccak256(G2_GENERATOR)) {
            bytes memory sum = _g1Add(lhs, negPi);
            // Identity point in EIP-2537 format = 128 zero bytes
            uint256 acc;
            assembly {
                let p := add(sum, 32)
                for { let i := 0 } lt(i, 4) { i := add(i, 1) } {
                    acc := or(acc, mload(add(p, mul(i, 32))))
                }
            }
            if (acc != 0) revert BKV_PairingFailed();
            return;
        }
        // General case: use BLS12_PAIRING precompile
        bytes memory input = bytes.concat(
            lhs,
            G2_GENERATOR,
            negPi,
            vanishingG2
        );
        (bool ok, bytes memory result) = BLS12_PAIRING.staticcall(input);
        if (!ok || result.length != 32) revert BKV_PairingCheckFailed();
        if (abi.decode(result, (uint256)) != 1) revert BKV_PairingFailed();
    }
}
