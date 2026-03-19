// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Groth16Verifier
/// @notice Standard Groth16 proof verification using BN254 precompiles.
///         Uses ecAdd (0x06), ecMul (0x07), ecPairing (0x08) — available since Byzantium.
///
/// Verification equation:
///   e(A, B) == e(α, β) · e(vk_x, γ) · e(C, δ)
///   where vk_x = IC[0] + Σ publicInputs[i] · IC[i+1]
///
/// Rewritten as a single pairing check (all on one side):
///   e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
library Groth16Verifier {
    uint256 internal constant BN254_P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    error Groth16_InvalidPublicInputCount();
    error Groth16_PublicInputTooLarge();
    error Groth16_ECMulFailed();
    error Groth16_ECAddFailed();
    error Groth16_PairingFailed();

    struct VerifyingKey {
        uint256[2] alpha;        // G1 point [α]₁
        uint256[2][2] beta;      // G2 point [β]₂
        uint256[2][2] gamma;     // G2 point [γ]₂
        uint256[2][2] delta;     // G2 point [δ]₂
        uint256[2][] ic;         // IC points (n+1 G1 points for n public inputs)
    }

    struct Proof {
        uint256[2] a;            // G1 point [A]₁
        uint256[2][2] b;         // G2 point [B]₂
        uint256[2] c;            // G1 point [C]₁
    }

    /// @notice Verify a Groth16 proof against a verifying key and public inputs.
    /// @return True if the proof is valid.
    function verify(
        VerifyingKey memory vk,
        Proof memory proof,
        uint256[] memory publicInputs
    ) internal view returns (bool) {
        if (publicInputs.length + 1 != vk.ic.length) revert Groth16_InvalidPublicInputCount();

        // Compute vk_x = IC[0] + Σ publicInputs[i] · IC[i+1]
        uint256[2] memory vkX = vk.ic[0];
        for (uint256 i = 0; i < publicInputs.length; i++) {
            if (publicInputs[i] >= BN254_P) revert Groth16_PublicInputTooLarge();
            uint256[2] memory term = _ecMul(vk.ic[i + 1], publicInputs[i]);
            vkX = _ecAdd(vkX, term);
        }

        // Negate A: -A = (A.x, BN254_P - A.y)
        uint256[2] memory negA;
        negA[0] = proof.a[0];
        negA[1] = (BN254_P - proof.a[1]) % BN254_P;

        // 4-pairing check: e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
        return _ecPairing4(
            negA,       proof.b,
            vk.alpha,   vk.beta,
            vkX,        vk.gamma,
            proof.c,    vk.delta
        );
    }

    // -----------------------------------------------------------------------
    // BN254 precompile wrappers
    // -----------------------------------------------------------------------

    /// @dev ecMul precompile (0x07): scalar * point
    function _ecMul(uint256[2] memory p, uint256 s)
        private view returns (uint256[2] memory result)
    {
        uint256[3] memory input;
        input[0] = p[0];
        input[1] = p[1];
        input[2] = s;

        bool ok;
        assembly {
            ok := staticcall(gas(), 0x07, input, 0x60, result, 0x40)
        }
        if (!ok) revert Groth16_ECMulFailed();
    }

    /// @dev ecAdd precompile (0x06): a + b
    function _ecAdd(uint256[2] memory a, uint256[2] memory b)
        private view returns (uint256[2] memory result)
    {
        uint256[4] memory input;
        input[0] = a[0];
        input[1] = a[1];
        input[2] = b[0];
        input[3] = b[1];

        bool ok;
        assembly {
            ok := staticcall(gas(), 0x06, input, 0x80, result, 0x40)
        }
        if (!ok) revert Groth16_ECAddFailed();
    }

    /// @dev ecPairing precompile (0x08): 4-pair check
    ///      Returns true if e(a1,b1)·e(a2,b2)·e(a3,b3)·e(a4,b4) == 1
    function _ecPairing4(
        uint256[2] memory a1, uint256[2][2] memory b1,
        uint256[2] memory a2, uint256[2][2] memory b2,
        uint256[2] memory a3, uint256[2][2] memory b3,
        uint256[2] memory a4, uint256[2][2] memory b4
    ) private view returns (bool) {
        // ecPairing input: 4 × (G1[64] + G2[128]) = 4 × 192 = 768 bytes
        uint256[24] memory input;

        // Pair 1: (-A, B)
        input[0]  = a1[0];  input[1]  = a1[1];
        input[2]  = b1[0][1]; input[3]  = b1[0][0];  // G2 x: im, re
        input[4]  = b1[1][1]; input[5]  = b1[1][0];  // G2 y: im, re

        // Pair 2: (α, β)
        input[6]  = a2[0];  input[7]  = a2[1];
        input[8]  = b2[0][1]; input[9]  = b2[0][0];
        input[10] = b2[1][1]; input[11] = b2[1][0];

        // Pair 3: (vk_x, γ)
        input[12] = a3[0];  input[13] = a3[1];
        input[14] = b3[0][1]; input[15] = b3[0][0];
        input[16] = b3[1][1]; input[17] = b3[1][0];

        // Pair 4: (C, δ)
        input[18] = a4[0];  input[19] = a4[1];
        input[20] = b4[0][1]; input[21] = b4[0][0];
        input[22] = b4[1][1]; input[23] = b4[1][0];

        uint256[1] memory result;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x08, input, 768, result, 0x20)
        }
        if (!ok) revert Groth16_PairingFailed();
        return result[0] == 1;
    }
}
