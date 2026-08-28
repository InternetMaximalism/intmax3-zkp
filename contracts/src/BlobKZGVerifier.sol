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
///      On-chain: [I(τ)]₁ = G1MSM(fieldElements, lagrangeBasisG1) using EIP-2537 0x0c.
///      lagrangeBasisG1 = [L₀(τ)]₁ .. [L_{N-1}(τ)]₁ from the Ethereum KZG trusted setup.
///
///   2. Pairing check:
///      e(C − [I(τ)]₁, G2_gen) · e(−π, [Z(τ)]₂) = 1   (EIP-2537 PAIRING_CHECK, 0x0f)
///      where Z(x) = ∏(x − ωⁱ) is the vanishing polynomial and
///            π    = [q(τ)]₁ = [(p−I)/Z evaluated at τ]₁.
///
/// SECURITY (H-4) — caller-supplied lagrangeBasisG1 and vanishingG2 are NOT safe:
///   The old note here claimed forging them "cannot break soundness" because producing π for an
///   inconsistent [I(τ)]₁ needs the trapdoor τ. That is false: π is caller-supplied as well, so
///   whenever the caller knows dlog_{G2gen}(vanishingG2) = k the pairing
///   e(lhs, G2_gen)·e(−π, vanishingG2) = 1 is satisfied by simply setting π := k⁻¹·lhs — pure public
///   G1 arithmetic. k = 1 (vanishingG2 = G2_GENERATOR) is the cheapest instance and is now REJECTED
///   outside an explicit test opt-in (see `_checkPairing`). A forged `lagrangeBasisG1` making
///   [I(τ)]₁ = C (so lhs = ∞, π = ∞) is the same class of break.
///
/// RESIDUAL RISK (not closed here): rejecting k = 1 does not stop k = 2, 3, …, and lagrangeBasisG1
///   remains caller-supplied. The only complete fix is to stop trusting the caller for trusted-setup
///   data: store the Ethereum ceremony Lagrange G1 points and the domain's [Z(τ)]₂ in an immutable
///   TrustedSetupStore (SSTORE2) and read them from there. That is a redesign of this verifier and is
///   deliberately out of scope of the H-4 patch; it MUST land before this path is relied on in
///   production. Today the fraud path is the only consumer and it is additionally gated by the
///   commitment and proof-params checks in `IntmaxRollup._verifyFraud`.
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
    // EIP-2537 precompile addresses (final spec, live since Pectra):
    //   0x0b G1ADD | 0x0c G1MSM | 0x0d G2ADD | 0x0e G2MSM
    //   0x0f PAIRING_CHECK | 0x10 MAP_FP_TO_G1 | 0x11 MAP_FP2_TO_G2
    //
    // SECURITY (B-1: the pairing precompile address was wrong).
    //   `BLS12_PAIRING` used to be `address(0x11)`. Under the FINAL EIP-2537 that is
    //   MAP_FP2_TO_G2, not PAIRING_CHECK — a transcription slip (G1ADD/G1MSM next to it are
    //   correct). Consequences: (a) the general pairing branch below could never verify
    //   anything, so blob KZG binding never worked outside the degenerate fast path, and
    //   (b) the earlier "the pairing precompile is unavailable in Foundry 1.5.x, verified
    //   empirically" note in `_checkPairing` measured 0x11 — MAP_FP2_TO_G2 genuinely rejects
    //   a 768-byte pairing instance — and drew the wrong conclusion. PAIRING_CHECK at 0x0f is
    //   present and works in this very EVM; `BlobKzgPairing.t.sol` exercises it directly.
    // -----------------------------------------------------------------------
    address internal constant BLS12_G1ADD   = address(0x0b);
    address internal constant BLS12_G1MSM   = address(0x0c);
    address internal constant BLS12_PAIRING = address(0x0f);

    // SHA-256 precompile – used to reconstruct the versioned hash
    address internal constant SHA256_PRECOMPILE = address(0x02);

    // EIP-4844 versioned hash version byte
    bytes1 internal constant KZG_VERSION = 0x01;

    // −1 in BLS12-381 scalar field  (= r − 1)
    // r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    uint256 internal constant BLS12_R_MINUS_1 =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000;

    // BLS12-381 G2 generator in EIP-2537 256-byte format:
    //   x_c0(64B) || x_c1(64B) || y_c0(64B) || y_c1(64B)
    // Each Fp element is the 48-byte big-endian value left-padded with 16 zero bytes (32 hex '0').
    // Source: https://eips.ethereum.org/EIPS/eip-2537
    //
    // SECURITY (B-2: the shipped constant was not a valid G2 point).
    //   The previous constant laid the X coordinate out as (x_c1 || x_c0). EIP-2537 requires
    //   (x_c0 || x_c1) — Y was already correct, so this too was a transcription slip. Fed to
    //   PAIRING_CHECK or G2ADD the old bytes are rejected as an invalid encoding, so even at the
    //   correct precompile address the general branch could never have verified anything.
    //   `BlobKzgPairing.t.sol` pins the fixed constant against 0x0d (G2ADD) and 0x0f.
    bytes internal constant G2_GENERATOR =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051"
        hex"c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65"
        hex"596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
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
    /// @dev SECURITY (H-4): raised when the caller claims Z(τ) = 1 (`vanishingG2 == G2_GENERATOR`).
    error BKV_DegenerateVanishingG2();

    // -----------------------------------------------------------------------
    // Main entry point
    // -----------------------------------------------------------------------
    /// @param versionedHash Blob versioned hash from BLOBHASH (stored at submit time).
    /// @param kzg           KZG opening parameters (see KZGProof struct).
    /// @param fieldElements Claimed blob values at positions 0..N-1 (32 bytes each).
    /// @param allowDegenerateVanishingG2 TEST-ONLY opt-in permitting `vanishingG2 == G2_GENERATOR`
    ///        (Z(τ) = 1). MUST be false in production — see `_checkPairing`.
    function verify(
        bytes32          versionedHash,
        KZGProof calldata kzg,
        bytes32[] memory  fieldElements,
        bool             allowDegenerateVanishingG2
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
        _checkPairing(lhs, negPi, kzg.vanishingG2, allowDegenerateVanishingG2);
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
    //   Algebraically equivalent to the general branch, but it is ALSO the degenerate
    //   Z(τ) = 1 instance, which is an attacker affordance — hence the opt-in guard below.
    // -----------------------------------------------------------------------
    function _checkPairing(
        bytes memory lhs,
        bytes memory negPi,
        bytes calldata vanishingG2,
        bool allowDegenerateVanishingG2
    ) private view {
        // SECURITY (H-4: the blob binding was vacuous at the caller's option).
        //
        // The previous comment here claimed this fast path was "SOUND, not a bypass" because
        // "forging fieldElements still requires the KZG trapdoor τ". That argument is WRONG, because
        // the opening proof π is caller-supplied too. `vanishingG2 == G2_GENERATOR` asserts Z(τ) = 1,
        // which collapses the pairing equation to  lhs + negPi = ∞  ⇔  π = C − [I(τ)]₁. An attacker
        // picks ANY fieldElements, computes [I(τ)]₁ = G1MSM(fieldElements, lagrangeBasisG1) from
        // public points, and simply sets π := C − [I(τ)]₁. No trapdoor, no discrete log — the blob
        // binding degrades to an identity that always holds, so `_verifyFraud`'s data-availability
        // pre-condition becomes free and the fraud prover can "prove" the blob held anything.
        // The real [Z(τ)]₂ (Z(x) = ∏(x − ωⁱ), degree N) is never the generator, so no honest prover
        // needs this branch: it is purely an attacker affordance.
        //
        // CORRECTION (B-1/B-3): the previous version of this comment justified keeping the branch
        // with "the BLS12_PAIRING precompile at 0x11 is unavailable in Foundry 1.5.x — verified
        // empirically". That premise was FALSE: 0x11 is MAP_FP2_TO_G2, so of course it rejects a
        // 768-byte pairing instance. PAIRING_CHECK lives at 0x0f, it is present here, and with the
        // corrected `G2_GENERATOR` the general branch below now runs for real (see
        // `BlobKzgPairing.t.sol`). While that premise stood, a PRODUCTION satellite
        // (`BlobKZGVerifierExt(false)`) had NO working branch at all: the degenerate one reverted
        // and the general one called the wrong precompile with a malformed constant, which made
        // `IntmaxRollup._verifyFraud` pre-condition 2 unsatisfiable and killed the proof-based
        // fraud path outright. The branch is retained only as the (guarded) Z(τ) = 1 special case.
        // Production deploys pass `false` and it is unreachable there.
        if (keccak256(vanishingG2) == keccak256(G2_GENERATOR)) {
            if (!allowDegenerateVanishingG2) revert BKV_DegenerateVanishingG2();
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

/// @title BlobKZGVerifierExt
/// @notice Standalone EXTERNAL wrapper around the internal `BlobKZGVerifier` library, deployed as
///         its own satellite contract (mirroring the `MleVerifier` pattern) so the large EIP-2537
///         verification bytecode does not count against `IntmaxRollup`'s EIP-170 budget.
/// @dev SECURITY: this contract is stateless and `view`-only — it holds no authority. The caller
///      (`IntmaxRollup._verifyFraud`) keeps ALL state decisions (commitment checks, rollback,
///      slashing); this satellite only answers "does this KZG multi-point opening bind
///      `proofBytes` to `blobVersionedHash`?" by reverting on failure. It carries the same trust
///      class as the pinned `MleVerifier`: the deployer pins it once via
///      `IntmaxRollup.setKzgVerifier` and it can never be swapped.
contract BlobKZGVerifierExt {
    /// @dev Top-3-bits mask so each 32-byte chunk is a canonical BLS12-381 scalar field element
    ///      (moved verbatim from `IntmaxRollup.FIELD_MASK`; MUST match the Rust blob encoder).
    uint256 internal constant FIELD_MASK = type(uint256).max >> 3;

    /// @notice TEST-ONLY opt-in permitting the degenerate `vanishingG2 == G2_GENERATOR` (Z(τ) = 1)
    ///         branch. SECURITY (H-4): production MUST deploy with `false` — see `_checkPairing`.
    ///         Immutable and constructor-set, so a deployed satellite's mode can never be flipped.
    bool public immutable allowDegenerateVanishingG2;

    /// @param allowDegenerateVanishingG2_ pass `false` in production. `true` is only for tests,
    ///        which cannot build a real pairing instance (BLS12_PAIRING is absent in Foundry 1.5.x).
    constructor(bool allowDegenerateVanishingG2_) {
        allowDegenerateVanishingG2 = allowDegenerateVanishingG2_;
    }

    /// @notice Verify that `proofBytes` (split into field elements exactly as the Rust blob encoder
    ///         does) is the data committed in the blob `blobVersionedHash` via the KZG multi-point
    ///         opening `kzg`. Reverts on any failure; returns silently on success.
    function verify(
        bytes32 blobVersionedHash,
        KZGProof calldata kzg,
        bytes calldata proofBytes
    ) external view {
        BlobKZGVerifier.verify(
            blobVersionedHash, kzg, _toFieldElements(proofBytes), allowDegenerateVanishingG2
        );
    }

    /// @dev Split raw bytes into BLS12-381 field elements (top 3 bits cleared). Moved VERBATIM from
    ///      `IntmaxRollup._toFieldElements` — byte-identical chunking is what binds the fraud
    ///      prover's `proofBytes` to the blob contents.
    function _toFieldElements(bytes calldata data)
        internal pure returns (bytes32[] memory elems)
    {
        uint256 N = (data.length + 31) / 32;
        elems = new bytes32[](N);
        for (uint256 i = 0; i < N; i++) {
            uint256 start = i * 32;
            uint256 end = start + 32;
            bytes32 chunk;
            if (end <= data.length) {
                chunk = bytes32(data[start:end]);
            } else {
                bytes memory padded = new bytes(32);
                uint256 remaining = data.length - start;
                for (uint256 j = 0; j < remaining; j++) {
                    padded[j] = data[start + j];
                }
                assembly { chunk := mload(add(padded, 32)) }
            }
            elems[i] = bytes32(uint256(chunk) & FIELD_MASK);
        }
    }
}
