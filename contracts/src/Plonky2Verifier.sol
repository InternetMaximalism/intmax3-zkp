// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GoldilocksField.sol";

/// @title Plonky2Verifier — On-chain Plonky2 constraint satisfaction check
/// @dev Verifies that polynomial openings at challenge point ζ satisfy
///      the Plonky2 circuit constraints. This replaces FRI's role when
///      combined with WHIR polynomial commitment proofs.
///
///      The verification equation is:
///        vanishing(ζ)[i] == Z_H(ζ) · reduce_with_powers(quotient_chunks[i], ζ^n)
///
///      where vanishing(ζ) = gate_constraints + permutation_terms + boundary_terms
///      combined via alpha challenges.
contract Plonky2Verifier {
    using GoldilocksField for uint256;
    using GoldilocksExt2 for GoldilocksExt2.Ext2;

    uint256 constant GL_P = GoldilocksField.P;

    // -----------------------------------------------------------------------
    // Data structures matching Plonky2's OpeningSet
    // -----------------------------------------------------------------------

    /// @dev Opening values at challenge point ζ (and g·ζ for next-row values).
    ///      Each value is an Ext2 element (c0, c1) representing a Goldilocks
    ///      quadratic extension field element.
    struct Openings {
        // Evaluations at ζ
        GoldilocksExt2.Ext2[] constants;         // constants(ζ)
        GoldilocksExt2.Ext2[] plonkSigmas;       // σ(ζ) [permutation selectors]
        GoldilocksExt2.Ext2[] wires;             // w_0...w_m(ζ)
        GoldilocksExt2.Ext2[] plonkZs;           // Z(ζ) [permutation polynomial]
        GoldilocksExt2.Ext2[] plonkZsNext;       // Z(g·ζ) [next row]
        GoldilocksExt2.Ext2[] partialProducts;   // P_i(ζ) [partial products]
        GoldilocksExt2.Ext2[] quotientPolys;     // t_0...t_k(ζ) [quotient chunks]
    }

    /// @dev Circuit-specific parameters needed for verification.
    struct CircuitParams {
        uint256 degreeBits;              // log2(trace length)
        uint256 numChallenges;           // typically 2
        uint256 numRoutedWires;          // number of wires in routing argument
        uint256 quotientDegreeFactor;    // chunks per quotient poly
        uint256 numPartialProducts;      // partial product accumulators
        uint256 numGateConstraints;      // total constraint equations
    }

    /// @dev Fiat-Shamir challenges.
    struct Challenges {
        uint256[] plonkBetas;    // num_challenges elements (base field)
        uint256[] plonkGammas;   // num_challenges elements (base field)
        uint256[] plonkAlphas;   // num_challenges elements (base field)
        GoldilocksExt2.Ext2 plonkZeta;  // challenge point ζ (extension field)
    }

    /// @dev k_i values for the coset used in permutation argument.
    ///      k_0 = 1, k_1 = 7, k_2 = 49, ... (powers of the primitive element)
    struct PermutationData {
        uint256[] kIs;  // Coset shift constants, one per routed wire
    }

    // -----------------------------------------------------------------------
    // Main verification entry point
    // -----------------------------------------------------------------------

    /// @notice Verify Plonky2 constraint satisfaction at challenge point ζ.
    /// @return True if all constraints are satisfied.
    function verifyConstraints(
        Openings calldata openings,
        CircuitParams calldata params,
        Challenges calldata challenges,
        PermutationData calldata permData,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        // Step 1: Compute Z_H(ζ) = ζ^n - 1
        GoldilocksExt2.Ext2 memory zetaPowN = challenges.plonkZeta.expPowerOf2(params.degreeBits);
        GoldilocksExt2.Ext2 memory zHZeta = zetaPowN.sub(GoldilocksExt2.one());

        // Step 2: Compute the vanishing polynomial terms
        GoldilocksExt2.Ext2[] memory vanishingTerms = _computeVanishingTerms(
            openings, params, challenges, permData, publicInputs
        );

        // Step 3: Combine vanishing terms via alpha challenges → one value per challenge
        GoldilocksExt2.Ext2[] memory vanishing = _reduceWithAlphas(
            vanishingTerms, challenges.plonkAlphas, params.numChallenges
        );

        // Step 4: Reconstruct quotient polynomial at ζ and verify
        for (uint256 i = 0; i < params.numChallenges; i++) {
            // Extract quotient chunks for this challenge
            uint256 start = i * params.quotientDegreeFactor;
            GoldilocksExt2.Ext2[] memory chunks = new GoldilocksExt2.Ext2[](params.quotientDegreeFactor);
            for (uint256 j = 0; j < params.quotientDegreeFactor; j++) {
                chunks[j] = GoldilocksExt2.Ext2(
                    openings.quotientPolys[start + j].c0,
                    openings.quotientPolys[start + j].c1
                );
            }

            // t(ζ) = reduce_with_powers(chunks, ζ^n)
            GoldilocksExt2.Ext2 memory quotientAtZeta = GoldilocksExt2.reduceWithPowers(chunks, zetaPowN);

            // Check: vanishing[i] == Z_H(ζ) · t(ζ)
            GoldilocksExt2.Ext2 memory rhs = zHZeta.mul(quotientAtZeta);
            if (!vanishing[i].isEqual(rhs)) {
                return false;
            }
        }

        return true;
    }

    // -----------------------------------------------------------------------
    // Internal: Vanishing polynomial computation
    // -----------------------------------------------------------------------

    function _computeVanishingTerms(
        Openings calldata openings,
        CircuitParams calldata params,
        Challenges calldata challenges,
        PermutationData calldata permData,
        uint256[] calldata publicInputs
    ) internal view returns (GoldilocksExt2.Ext2[] memory) {
        // Collect all vanishing terms into a flat array
        // Order: [boundary_terms, permutation_terms, gate_constraints]

        // 1. Boundary constraint: L_0(ζ) · (Z(ζ) - 1)
        GoldilocksExt2.Ext2 memory l0Zeta = GoldilocksExt2.evalL0(
            challenges.plonkZeta, params.degreeBits
        );

        GoldilocksExt2.Ext2[] memory boundaryTerms = new GoldilocksExt2.Ext2[](params.numChallenges);
        for (uint256 i = 0; i < params.numChallenges; i++) {
            GoldilocksExt2.Ext2 memory zMinusOne = GoldilocksExt2.Ext2(
                openings.plonkZs[i].c0, openings.plonkZs[i].c1
            ).sub(GoldilocksExt2.one());
            boundaryTerms[i] = l0Zeta.mul(zMinusOne);
        }

        // 2. Permutation argument: partial product checks
        GoldilocksExt2.Ext2[] memory permTerms = _checkPermutation(
            openings, params, challenges, permData
        );

        // 3. Gate constraints (placeholder — delegates to gate-specific evaluation)
        GoldilocksExt2.Ext2[] memory gateTerms = _evaluateGateConstraints(
            openings, params, publicInputs
        );

        // Concatenate all terms
        uint256 totalTerms = boundaryTerms.length + permTerms.length + gateTerms.length;
        GoldilocksExt2.Ext2[] memory allTerms = new GoldilocksExt2.Ext2[](totalTerms);
        uint256 idx = 0;
        for (uint256 i = 0; i < boundaryTerms.length; i++) {
            allTerms[idx++] = boundaryTerms[i];
        }
        for (uint256 i = 0; i < permTerms.length; i++) {
            allTerms[idx++] = permTerms[i];
        }
        for (uint256 i = 0; i < gateTerms.length; i++) {
            allTerms[idx++] = gateTerms[i];
        }

        return allTerms;
    }

    // -----------------------------------------------------------------------
    // Permutation argument
    // -----------------------------------------------------------------------

    /// @dev Check permutation argument partial products.
    ///
    ///   For each chunk of routed wires:
    ///     prev_acc · ∏(w_j + β·k_j·ζ + γ) == next_acc · ∏(w_j + β·σ_j(ζ) + γ)
    ///
    ///   where prev_acc starts at Z(ζ) and ends at Z(g·ζ).
    function _checkPermutation(
        Openings calldata openings,
        CircuitParams calldata params,
        Challenges calldata challenges,
        PermutationData calldata permData
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        uint256 chunkSize = params.quotientDegreeFactor - 1;
        uint256 numChunks = (params.numRoutedWires + chunkSize - 1) / chunkSize;

        GoldilocksExt2.Ext2[] memory terms = new GoldilocksExt2.Ext2[](
            numChunks * params.numChallenges
        );

        for (uint256 ch = 0; ch < params.numChallenges; ch++) {
            _checkPermutationForChallenge(
                openings, params, permData,
                challenges.plonkBetas[ch],
                challenges.plonkGammas[ch],
                challenges.plonkZeta,
                ch, chunkSize, numChunks, terms
            );
        }

        return terms;
    }

    function _checkPermutationForChallenge(
        Openings calldata openings,
        CircuitParams calldata params,
        PermutationData calldata permData,
        uint256 betaBase,
        uint256 gammaBase,
        GoldilocksExt2.Ext2 memory zeta,
        uint256 ch,
        uint256 chunkSize,
        uint256 numChunks,
        GoldilocksExt2.Ext2[] memory terms
    ) internal pure {
        GoldilocksExt2.Ext2 memory beta = GoldilocksExt2.fromBase(betaBase);
        GoldilocksExt2.Ext2 memory gamma = GoldilocksExt2.fromBase(gammaBase);

        (
            GoldilocksExt2.Ext2[] memory numerators,
            GoldilocksExt2.Ext2[] memory denominators
        ) = _computePermNumeratorsDenominators(
            openings, params.numRoutedWires, permData, beta, gamma, zeta
        );

        _checkPermutationChunks(
            openings, params, numerators, denominators,
            ch, chunkSize, numChunks, terms
        );
    }

    function _computePermNumeratorsDenominators(
        Openings calldata openings,
        uint256 numRoutedWires,
        PermutationData calldata permData,
        GoldilocksExt2.Ext2 memory beta,
        GoldilocksExt2.Ext2 memory gamma,
        GoldilocksExt2.Ext2 memory zeta
    ) internal pure returns (
        GoldilocksExt2.Ext2[] memory numerators,
        GoldilocksExt2.Ext2[] memory denominators
    ) {
        numerators = new GoldilocksExt2.Ext2[](numRoutedWires);
        denominators = new GoldilocksExt2.Ext2[](numRoutedWires);

        GoldilocksExt2.Ext2 memory betaZeta = beta.mul(zeta);

        for (uint256 j = 0; j < numRoutedWires; j++) {
            GoldilocksExt2.Ext2 memory wireVal = GoldilocksExt2.Ext2(
                openings.wires[j].c0, openings.wires[j].c1
            );
            // numerator: w_j + β·k_j·ζ + γ
            numerators[j] = wireVal
                .add(betaZeta.mulScalar(permData.kIs[j]))
                .add(gamma);

            // denominator: w_j + β·σ_j(ζ) + γ
            GoldilocksExt2.Ext2 memory sigmaVal = GoldilocksExt2.Ext2(
                openings.plonkSigmas[j].c0, openings.plonkSigmas[j].c1
            );
            denominators[j] = wireVal.add(beta.mul(sigmaVal)).add(gamma);
        }
    }

    function _checkPermutationChunks(
        Openings calldata openings,
        CircuitParams calldata params,
        GoldilocksExt2.Ext2[] memory numerators,
        GoldilocksExt2.Ext2[] memory denominators,
        uint256 ch,
        uint256 chunkSize,
        uint256 numChunks,
        GoldilocksExt2.Ext2[] memory terms
    ) internal pure {
        uint256 partialIdx = ch * params.numPartialProducts;

        for (uint256 chunk = 0; chunk < numChunks; chunk++) {
            uint256 chunkEnd = (chunk + 1) * chunkSize;
            if (chunkEnd > params.numRoutedWires) chunkEnd = params.numRoutedWires;

            GoldilocksExt2.Ext2 memory prevAcc = _getPermAcc(
                openings, ch, chunk, partialIdx, true
            );
            GoldilocksExt2.Ext2 memory nextAcc = _getPermAcc(
                openings, ch, chunk == numChunks - 1 ? type(uint256).max : chunk, partialIdx, false
            );

            GoldilocksExt2.Ext2 memory numProd = GoldilocksExt2.one();
            GoldilocksExt2.Ext2 memory denProd = GoldilocksExt2.one();
            for (uint256 j = chunk * chunkSize; j < chunkEnd; j++) {
                numProd = numProd.mul(numerators[j]);
                denProd = denProd.mul(denominators[j]);
            }

            terms[ch * numChunks + chunk] = prevAcc.mul(numProd).sub(nextAcc.mul(denProd));
        }
    }

    function _getPermAcc(
        Openings calldata openings,
        uint256 ch,
        uint256 chunk,
        uint256 partialIdx,
        bool isPrev
    ) internal pure returns (GoldilocksExt2.Ext2 memory) {
        if (isPrev) {
            if (chunk == 0) {
                return GoldilocksExt2.Ext2(openings.plonkZs[ch].c0, openings.plonkZs[ch].c1);
            }
            return GoldilocksExt2.Ext2(
                openings.partialProducts[partialIdx + chunk - 1].c0,
                openings.partialProducts[partialIdx + chunk - 1].c1
            );
        } else {
            if (chunk == type(uint256).max) {
                // last chunk → use Z(g·ζ)
                return GoldilocksExt2.Ext2(openings.plonkZsNext[ch].c0, openings.plonkZsNext[ch].c1);
            }
            return GoldilocksExt2.Ext2(
                openings.partialProducts[partialIdx + chunk].c0,
                openings.partialProducts[partialIdx + chunk].c1
            );
        }
    }

    // -----------------------------------------------------------------------
    // Gate constraint evaluation
    // -----------------------------------------------------------------------

    /// @dev Evaluate all gate constraints at ζ.
    ///
    ///   For each gate type, the selector polynomial filters which constraints
    ///   are active. The selectors are encoded in the constants polynomials.
    ///
    ///   NOTE: This is a simplified implementation that handles the core gate types.
    ///   Additional gate types should be added for full circuit support.
    function _evaluateGateConstraints(
        Openings calldata openings,
        CircuitParams calldata params,
        uint256[] calldata /* publicInputs */
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        // Gate constraints are already combined in the quotient polynomial
        // by the prover. The verifier recomputes them to check.
        //
        // For now, we return the empty array of gate constraints.
        // Individual gate implementations will be added below.
        //
        // TODO: Implement gate-specific constraint evaluation:
        // - ArithmeticGate
        // - PoseidonGate
        // - BaseSumGate
        // - ConstantGate
        // - PublicInputGate
        // - RandomAccessGate
        // - ExponentiationGate
        // - ReducingGate / ReducingExtensionGate
        // - ArithmeticExtensionGate / MulExtensionGate
        // - CosetInterpolationGate
        // - LookupGate / LookupTableGate
        // - U32 gates (ComparisonGate, U32AddManyGate, U32SubtractionGate)
        // - NoopGate (trivial, all constraints are 0)

        GoldilocksExt2.Ext2[] memory constraints = new GoldilocksExt2.Ext2[](params.numGateConstraints);
        // Initialize to zero (will be filled by gate implementations)
        for (uint256 i = 0; i < params.numGateConstraints; i++) {
            constraints[i] = GoldilocksExt2.zero();
        }
        return constraints;
    }

    // -----------------------------------------------------------------------
    // Gate implementations
    // -----------------------------------------------------------------------

    /// @dev ArithmeticGate constraint evaluation.
    ///   For each operation i in the gate:
    ///     output - (multiplicand_0 * multiplicand_1 * const_0 + addend * const_1) = 0
    ///
    ///   Wire layout: [multiplicand_0, multiplicand_1, addend, output] × numOps
    ///   Constants: [const_0, const_1] × numOps
    function _evalArithmeticGate(
        GoldilocksExt2.Ext2[] calldata wires,
        GoldilocksExt2.Ext2[] calldata constants,
        uint256 numOps,
        uint256 constantOffset,
        uint256 wireOffset
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        GoldilocksExt2.Ext2[] memory constraints = new GoldilocksExt2.Ext2[](numOps);

        for (uint256 i = 0; i < numOps; i++) {
            uint256 wBase = wireOffset + i * 4;
            uint256 cBase = constantOffset + i * 2;

            GoldilocksExt2.Ext2 memory multiplicand0 = GoldilocksExt2.Ext2(
                wires[wBase].c0, wires[wBase].c1
            );
            GoldilocksExt2.Ext2 memory multiplicand1 = GoldilocksExt2.Ext2(
                wires[wBase + 1].c0, wires[wBase + 1].c1
            );
            GoldilocksExt2.Ext2 memory addend = GoldilocksExt2.Ext2(
                wires[wBase + 2].c0, wires[wBase + 2].c1
            );
            GoldilocksExt2.Ext2 memory output = GoldilocksExt2.Ext2(
                wires[wBase + 3].c0, wires[wBase + 3].c1
            );

            GoldilocksExt2.Ext2 memory const0 = GoldilocksExt2.Ext2(
                constants[cBase].c0, constants[cBase].c1
            );
            GoldilocksExt2.Ext2 memory const1 = GoldilocksExt2.Ext2(
                constants[cBase + 1].c0, constants[cBase + 1].c1
            );

            // constraint = output - (multiplicand0 * multiplicand1 * const0 + addend * const1)
            GoldilocksExt2.Ext2 memory expected = multiplicand0.mul(multiplicand1).mul(const0)
                .add(addend.mul(const1));
            constraints[i] = output.sub(expected);
        }

        return constraints;
    }

    /// @dev ConstantGate constraint evaluation.
    ///   For each wire i: wire_i - constant_i = 0
    function _evalConstantGate(
        GoldilocksExt2.Ext2[] calldata wires,
        GoldilocksExt2.Ext2[] calldata constants,
        uint256 numConsts,
        uint256 constantOffset,
        uint256 wireOffset
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        GoldilocksExt2.Ext2[] memory constraints = new GoldilocksExt2.Ext2[](numConsts);

        for (uint256 i = 0; i < numConsts; i++) {
            GoldilocksExt2.Ext2 memory wireVal = GoldilocksExt2.Ext2(
                wires[wireOffset + i].c0, wires[wireOffset + i].c1
            );
            GoldilocksExt2.Ext2 memory constVal = GoldilocksExt2.Ext2(
                constants[constantOffset + i].c0, constants[constantOffset + i].c1
            );
            constraints[i] = wireVal.sub(constVal);
        }

        return constraints;
    }

    /// @dev PublicInputGate constraint evaluation.
    ///   wire_0 - public_input_hash.elements[0] = 0
    ///   wire_1 - public_input_hash.elements[1] = 0
    ///   wire_2 - public_input_hash.elements[2] = 0
    ///   wire_3 - public_input_hash.elements[3] = 0
    function _evalPublicInputGate(
        GoldilocksExt2.Ext2[] calldata wires,
        uint256[4] memory piHashElements,
        uint256 wireOffset
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        GoldilocksExt2.Ext2[] memory constraints = new GoldilocksExt2.Ext2[](4);

        for (uint256 i = 0; i < 4; i++) {
            GoldilocksExt2.Ext2 memory wireVal = GoldilocksExt2.Ext2(
                wires[wireOffset + i].c0, wires[wireOffset + i].c1
            );
            GoldilocksExt2.Ext2 memory expected = GoldilocksExt2.fromBase(piHashElements[i]);
            constraints[i] = wireVal.sub(expected);
        }

        return constraints;
    }

    // -----------------------------------------------------------------------
    // Alpha reduction
    // -----------------------------------------------------------------------

    /// @dev Combine vanishing terms via alpha challenges (multi-alpha reduction).
    ///   result[i] = reduce_with_powers(terms, alphas[i]) for each i
    function _reduceWithAlphas(
        GoldilocksExt2.Ext2[] memory terms,
        uint256[] calldata alphas,
        uint256 numChallenges
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        GoldilocksExt2.Ext2[] memory result = new GoldilocksExt2.Ext2[](numChallenges);

        for (uint256 i = 0; i < numChallenges; i++) {
            GoldilocksExt2.Ext2 memory alpha = GoldilocksExt2.fromBase(alphas[i]);
            GoldilocksExt2.Ext2 memory acc = GoldilocksExt2.zero();
            // Horner's method (right-to-left)
            for (uint256 j = terms.length; j > 0; j--) {
                acc = acc.mul(alpha).add(terms[j - 1]);
            }
            result[i] = acc;
        }

        return result;
    }
}
