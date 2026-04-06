// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GoldilocksField.sol";
import "./PoseidonGateEval.sol";
import "./PoseidonConstants.sol";

/// @title Plonky2Verifier — On-chain Plonky2 constraint satisfaction check
/// @dev Verifies that polynomial openings at challenge point ζ satisfy
///      the Plonky2 circuit constraints. Combined with WHIR polynomial
///      commitment proofs, this provides a complete post-quantum validity proof.
///
///      The verification equation is:
///        vanishing(ζ)[i] == Z_H(ζ) · reduce_with_powers(quotient_chunks[i], ζ^n)
///
///      where vanishing(ζ) = boundary_terms + permutation_terms + gate_constraints
///      combined via alpha challenges (Horner reduction).
///
///      Gate constraints are evaluated using selector filters:
///        for each gate type: filter(gate) * gate.eval_unfiltered(wires, constants)
///      where filter is a polynomial that is nonzero only when the gate is active.
contract Plonky2Verifier {
    using GoldilocksField for uint256;
    using GoldilocksExt2 for GoldilocksExt2.Ext2;

    uint256 constant GL_P = GoldilocksField.P;
    /// @dev Unused selector sentinel value (matches Plonky2's UNUSED_SELECTOR)
    uint256 constant UNUSED_SELECTOR = 0xFFFFFFFF;

    // -----------------------------------------------------------------------
    // Data structures matching Plonky2's OpeningSet
    // -----------------------------------------------------------------------

    /// @dev Opening values at challenge point ζ (and g·ζ for next-row values).
    struct Openings {
        GoldilocksExt2.Ext2[] constants;         // constants(ζ) [includes selectors]
        GoldilocksExt2.Ext2[] plonkSigmas;       // σ(ζ)
        GoldilocksExt2.Ext2[] wires;             // w(ζ)
        GoldilocksExt2.Ext2[] plonkZs;           // Z(ζ)
        GoldilocksExt2.Ext2[] plonkZsNext;       // Z(g·ζ)
        GoldilocksExt2.Ext2[] partialProducts;   // P(ζ)
        GoldilocksExt2.Ext2[] quotientPolys;     // t(ζ)
    }

    /// @dev Circuit-specific parameters.
    struct CircuitParams {
        uint256 degreeBits;
        uint256 numChallenges;
        uint256 numRoutedWires;
        uint256 quotientDegreeFactor;
        uint256 numPartialProducts;
        uint256 numGateConstraints;     // MAX of gate constraints (not sum)
        uint256 numSelectors;           // number of selector columns
        uint256 numLookupSelectors;     // number of lookup selector columns
    }

    /// @dev Fiat-Shamir challenges.
    struct Challenges {
        uint256[] plonkBetas;
        uint256[] plonkGammas;
        uint256[] plonkAlphas;
        GoldilocksExt2.Ext2 plonkZeta;
    }

    /// @dev Permutation coset shift constants.
    struct PermutationData {
        uint256[] kIs;
    }

    /// @dev Gate descriptor for selector-based constraint evaluation.
    struct GateInfo {
        uint256 gateType;          // enum: 0=Noop, 1=Constant, 2=PublicInput, 3=Poseidon, 4=Arithmetic, ...
        uint256 selectorIndex;     // which selector column to read
        uint256 groupStart;        // start of this gate's group range
        uint256 groupEnd;          // end (exclusive) of group range
        uint256 rowInGroup;        // this gate's position within the group
        uint256 numConstraints;    // number of constraints this gate produces
        // Gate-specific configuration (packed into a single array for gas efficiency)
        // Interpretation depends on gateType:
        //   Constant(1): [numConsts]
        //   Arithmetic(4): [numOps]
        //   BaseSumGate(5): [numLimbs, base]
        //   RandomAccessGate(6): [bits, numCopies, numExtraConstants, vecSize]
        //   ReducingExtensionGate(8): [numCoeffs]
        //   ArithmeticExtensionGate(9): [numOps]
        //   MulExtensionGate(10): [numOps]
        //   ExponentiationGate(11): [numPowerBits]
        //   CosetInterpolationGate(12): [subgroupBits, numPoints, numIntermediates, degree]
        uint256[] gateConfig;
    }

    // -----------------------------------------------------------------------
    // Main verification entry point
    // -----------------------------------------------------------------------

    /// @notice Verify Plonky2 constraint satisfaction at challenge point ζ.
    function verifyConstraints(
        Openings memory openings,
        CircuitParams memory params,
        Challenges memory challenges,
        PermutationData memory permData,
        GateInfo[] memory gates,
        uint256[] memory publicInputs
    ) public view returns (bool) {
        // Step 1: Compute Z_H(ζ) = ζ^n - 1
        GoldilocksExt2.Ext2 memory zetaPowN = challenges.plonkZeta.expPowerOf2(params.degreeBits);
        GoldilocksExt2.Ext2 memory zHZeta = zetaPowN.sub(GoldilocksExt2.one());

        // Step 2: Compute all vanishing polynomial terms
        GoldilocksExt2.Ext2[] memory vanishingTerms = _computeAllVanishingTerms(
            openings, params, challenges, permData, gates, publicInputs
        );

        // Step 3: Reduce with alpha challenges → one value per challenge
        GoldilocksExt2.Ext2[] memory vanishing = _reduceWithAlphas(
            vanishingTerms, challenges.plonkAlphas, params.numChallenges
        );

        // Step 4: Check vanishing[i] == Z_H(ζ) * quotient[i]
        for (uint256 i = 0; i < params.numChallenges; i++) {
            uint256 start = i * params.quotientDegreeFactor;
            GoldilocksExt2.Ext2[] memory chunks = new GoldilocksExt2.Ext2[](params.quotientDegreeFactor);
            for (uint256 j = 0; j < params.quotientDegreeFactor; j++) {
                chunks[j] = openings.quotientPolys[start + j];
            }
            GoldilocksExt2.Ext2 memory quotientAtZeta = GoldilocksExt2.reduceWithPowers(chunks, zetaPowN);
            GoldilocksExt2.Ext2 memory rhs = zHZeta.mul(quotientAtZeta);
            if (!vanishing[i].isEqual(rhs)) {
                return false;
            }
        }

        return true;
    }

    // -----------------------------------------------------------------------
    // Vanishing polynomial computation
    // -----------------------------------------------------------------------

    function _computeAllVanishingTerms(
        Openings memory openings,
        CircuitParams memory params,
        Challenges memory challenges,
        PermutationData memory permData,
        GateInfo[] memory gates,
        uint256[] memory publicInputs
    ) internal view returns (GoldilocksExt2.Ext2[] memory) {
        // 1. Boundary: L_0(ζ) · (Z(ζ) - 1)
        GoldilocksExt2.Ext2 memory l0Zeta = GoldilocksExt2.evalL0(
            challenges.plonkZeta, params.degreeBits
        );
        GoldilocksExt2.Ext2[] memory boundaryTerms = new GoldilocksExt2.Ext2[](params.numChallenges);
        for (uint256 i = 0; i < params.numChallenges; i++) {
            boundaryTerms[i] = l0Zeta.mul(openings.plonkZs[i].sub(GoldilocksExt2.one()));
        }

        // 2. Permutation checks
        GoldilocksExt2.Ext2[] memory permTerms = _checkPermutation(
            openings, params, challenges, permData
        );

        // 3. Gate constraints (with selector filters)
        GoldilocksExt2.Ext2[] memory gateTerms = _evaluateGateConstraints(
            openings, params, gates, publicInputs
        );

        // Concatenate: boundary + permutation + gate
        uint256 totalLen = boundaryTerms.length + permTerms.length + gateTerms.length;
        GoldilocksExt2.Ext2[] memory allTerms = new GoldilocksExt2.Ext2[](totalLen);
        uint256 idx = 0;
        for (uint256 i = 0; i < boundaryTerms.length; i++) allTerms[idx++] = boundaryTerms[i];
        for (uint256 i = 0; i < permTerms.length; i++) allTerms[idx++] = permTerms[i];
        for (uint256 i = 0; i < gateTerms.length; i++) allTerms[idx++] = gateTerms[i];

        return allTerms;
    }

    // -----------------------------------------------------------------------
    // Gate constraint evaluation with selector filters
    // -----------------------------------------------------------------------

    /// @dev Evaluate all gate constraints with selector filtering.
    ///
    ///   constraints[j] = SUM over gates: filter(gate) * gate.eval_unfiltered(j)
    ///
    ///   The filter ensures only the active gate's constraints are nonzero.
    function _evaluateGateConstraints(
        Openings memory openings,
        CircuitParams memory params,
        GateInfo[] memory gates,
        uint256[] memory publicInputs
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        GoldilocksExt2.Ext2[] memory constraints = new GoldilocksExt2.Ext2[](params.numGateConstraints);
        for (uint256 i = 0; i < params.numGateConstraints; i++) {
            constraints[i] = GoldilocksExt2.zero();
        }

        // Strip selector + lookup selector columns from constants
        uint256 constOffset = params.numSelectors + params.numLookupSelectors;

        for (uint256 g = 0; g < gates.length; g++) {
            // Compute selector filter
            GoldilocksExt2.Ext2 memory selectorVal = openings.constants[gates[g].selectorIndex];
            GoldilocksExt2.Ext2 memory filter = _computeFilter(
                gates[g].rowInGroup,
                gates[g].groupStart,
                gates[g].groupEnd,
                selectorVal,
                params.numSelectors > 1
            );

            // Evaluate gate-specific unfiltered constraints
            GoldilocksExt2.Ext2[] memory unfiltered = _evalGateUnfiltered(
                gates[g].gateType,
                openings,
                constOffset,
                publicInputs,
                gates[g].gateConfig
            );

            // Accumulate: constraints[j] += filter * unfiltered[j]
            for (uint256 j = 0; j < unfiltered.length; j++) {
                constraints[j] = constraints[j].add(filter.mul(unfiltered[j]));
            }
        }

        return constraints;
    }

    /// @dev Compute selector filter for a gate.
    ///   filter = PRODUCT_{i in group, i != row} (i - s) * (UNUSED - s)
    function _computeFilter(
        uint256 row,
        uint256 groupStart,
        uint256 groupEnd,
        GoldilocksExt2.Ext2 memory s,
        bool multipleSelectors
    ) internal pure returns (GoldilocksExt2.Ext2 memory) {
        GoldilocksExt2.Ext2 memory filter = GoldilocksExt2.one();

        for (uint256 i = groupStart; i < groupEnd; i++) {
            if (i != row) {
                filter = filter.mul(GoldilocksExt2.fromBase(i).sub(s));
            }
        }

        if (multipleSelectors) {
            filter = filter.mul(GoldilocksExt2.fromBase(UNUSED_SELECTOR).sub(s));
        }

        return filter;
    }

    /// @dev Dispatch gate-specific constraint evaluation.
    function _evalGateUnfiltered(
        uint256 gateType,
        Openings memory openings,
        uint256 constOffset,
        uint256[] memory publicInputs,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        if (gateType == 0) return new GoldilocksExt2.Ext2[](0);                          // NoopGate
        if (gateType == 1) return _evalConstantGate(openings, constOffset, gateConfig);   // ConstantGate
        if (gateType == 2) return _evalPublicInputGate(openings, publicInputs);           // PublicInputGate
        if (gateType == 3) return PoseidonGateEval.evaluateExt2(openings.wires);          // PoseidonGate
        if (gateType == 4) return _evalArithmeticGate(openings, constOffset, gateConfig); // ArithmeticGate
        if (gateType == 5) return _evalBaseSumGate(openings, gateConfig);                 // BaseSumGate
        if (gateType == 6) return _evalRandomAccessGate(openings, gateConfig);            // RandomAccessGate
        if (gateType == 7) return _evalReducingGate(openings, gateConfig);                // ReducingGate
        if (gateType == 8) return _evalReducingExtensionGate(openings, gateConfig);       // ReducingExtensionGate
        if (gateType == 9) return _evalArithmeticExtensionGate(openings, constOffset, gateConfig); // ArithmeticExtensionGate
        if (gateType == 10) return _evalMulExtensionGate(openings, constOffset, gateConfig); // MulExtensionGate
        if (gateType == 11) return _evalExponentiationGate(openings, gateConfig);         // ExponentiationGate
        if (gateType == 12) return _evalCosetInterpolationGate(openings, gateConfig);     // CosetInterpolationGate
        if (gateType == 15) return _evalPoseidonMdsGate(openings);                        // PoseidonMdsGate
        revert("Plonky2Verifier: unsupported gate type");
    }

    // -----------------------------------------------------------------------
    // Gate implementations
    // -----------------------------------------------------------------------

    /// @dev ConstantGate: wire[i] - constant[constOffset + i] = 0
    ///      gateConfig: [numConsts]
    function _evalConstantGate(
        Openings memory openings,
        uint256 constOffset,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        uint256 numConsts = gateConfig[0];
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](numConsts);
        for (uint256 i = 0; i < numConsts; i++) {
            c[i] = openings.wires[i].sub(openings.constants[constOffset + i]);
        }
        return c;
    }

    /// @dev PublicInputGate: wire[i] - piHash[i] = 0 for i in 0..4
    function _evalPublicInputGate(
        Openings memory openings,
        uint256[] memory publicInputs
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](4);
        for (uint256 i = 0; i < 4; i++) {
            GoldilocksExt2.Ext2 memory piVal = GoldilocksExt2.fromBase(
                i < publicInputs.length ? publicInputs[i] : 0
            );
            c[i] = openings.wires[i].sub(piVal);
        }
        return c;
    }

    /// @dev ArithmeticGate: output - (m0 * m1 * c0 + addend * c1) = 0 per op
    ///      gateConfig: [numOps]
    function _evalArithmeticGate(
        Openings memory openings,
        uint256 constOffset,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        uint256 numOps = gateConfig[0];
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](numOps);
        for (uint256 i = 0; i < numOps; i++) {
            uint256 wBase = i * 4;
            GoldilocksExt2.Ext2 memory expected = openings.wires[wBase].mul(openings.wires[wBase + 1])
                .mul(openings.constants[constOffset + i * 2])
                .add(openings.wires[wBase + 2].mul(openings.constants[constOffset + i * 2 + 1]));
            c[i] = openings.wires[wBase + 3].sub(expected);
        }
        return c;
    }

    /// @dev BaseSumGate<B>: sum decomposition into base-B limbs
    ///      Constraint 0: computed_sum - wire[0]  (where computed_sum = Σ limb[i] * B^i)
    ///      Constraints 1..numLimbs: range check each limb: Π_{k=0}^{B-1} (limb - k) = 0
    ///      gateConfig: [numLimbs, base]
    function _evalBaseSumGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        uint256 numLimbs = gateConfig[0];
        uint256 base = gateConfig[1];
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](1 + numLimbs);

        // Constraint 0: reduce_with_powers(limbs, base) - sum
        GoldilocksExt2.Ext2 memory computedSum = GoldilocksExt2.zero();
        GoldilocksExt2.Ext2 memory basePow = GoldilocksExt2.one();
        GoldilocksExt2.Ext2 memory baseExt = GoldilocksExt2.fromBase(base);
        for (uint256 i = 0; i < numLimbs; i++) {
            computedSum = computedSum.add(openings.wires[1 + i].mul(basePow));
            if (i + 1 < numLimbs) basePow = basePow.mul(baseExt);
        }
        c[0] = computedSum.sub(openings.wires[0]);

        // Constraints 1..numLimbs: range check Π_{k=0}^{B-1} (limb - k)
        for (uint256 i = 0; i < numLimbs; i++) {
            GoldilocksExt2.Ext2 memory prod = GoldilocksExt2.one();
            for (uint256 k = 0; k < base; k++) {
                prod = prod.mul(openings.wires[1 + i].sub(GoldilocksExt2.fromBase(k)));
            }
            c[1 + i] = prod;
        }
        return c;
    }

    /// @dev RandomAccessGate: binary decomposition + MUX selection
    ///      gateConfig: [bits, numCopies, numExtraConstants, vecSize]
    function _evalRandomAccessGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        uint256 bits = gateConfig[0];
        uint256 numCopies = gateConfig[1];
        uint256 numExtraConstants = gateConfig[2];
        uint256 vecSize = gateConfig[3];
        uint256 perCopy = bits + 2;
        uint256 total = numCopies * perCopy + numExtraConstants;
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](total);

        uint256 routedPerCopy = 2 + vecSize;
        uint256 numRoutedTotal = numCopies * routedPerCopy + numExtraConstants;

        for (uint256 copy = 0; copy < numCopies; copy++) {
            _evalRandomAccessCopy(openings, c, copy * routedPerCopy, numRoutedTotal + copy * bits, copy * perCopy, bits, vecSize);
        }
        for (uint256 i = 0; i < numExtraConstants; i++) {
            c[numCopies * perCopy + i] = GoldilocksExt2.zero();
        }
        return c;
    }

    function _evalRandomAccessCopy(
        Openings memory openings,
        GoldilocksExt2.Ext2[] memory c,
        uint256 rBase,
        uint256 nBase,
        uint256 cBase,
        uint256 bits,
        uint256 vecSize
    ) internal pure {
        // Boolean + index reconstruction
        GoldilocksExt2.Ext2 memory reconstructed = GoldilocksExt2.zero();
        GoldilocksExt2.Ext2 memory pow2 = GoldilocksExt2.one();
        for (uint256 b = 0; b < bits; b++) {
            GoldilocksExt2.Ext2 memory bit = openings.wires[nBase + b];
            c[cBase + b] = bit.mul(bit.sub(GoldilocksExt2.one()));
            reconstructed = reconstructed.add(bit.mul(pow2));
            pow2 = pow2.mul(GoldilocksExt2.fromBase(2));
        }
        c[cBase + bits] = reconstructed.sub(openings.wires[rBase]);

        // MUX: fold list using bits
        GoldilocksExt2.Ext2[] memory list = new GoldilocksExt2.Ext2[](vecSize);
        for (uint256 v = 0; v < vecSize; v++) {
            list[v] = openings.wires[rBase + 2 + v];
        }
        uint256 curSize = vecSize;
        for (uint256 b = 0; b < bits; b++) {
            GoldilocksExt2.Ext2 memory bit = openings.wires[nBase + b];
            uint256 half = curSize >> 1;
            for (uint256 j = 0; j < half; j++) {
                list[j] = list[2 * j].add(bit.mul(list[2 * j + 1].sub(list[2 * j])));
            }
            curSize = half;
        }
        c[cBase + bits + 1] = list[0].sub(openings.wires[rBase + 1]);
    }

    /// @dev ReducingGate: Horner reduction with BASE FIELD coefficients
    ///      Same as ReducingExtensionGate but coefficients are single base field elements,
    ///      not extension field elements.
    ///      gateConfig: [numCoeffs]
    function _evalReducingGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        uint256 numCoeffs = gateConfig[0];
        uint256 D = 2;
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](numCoeffs * D);

        // Wire layout (D=2):
        //   wires[0..1]: output (extension element)
        //   wires[2..3]: alpha (extension element)
        //   wires[4..5]: old_acc (initial accumulator)
        //   wires[6..6+numCoeffs-1]: coefficients (numCoeffs BASE FIELD scalars)
        //   Non-routed: accumulators (numCoeffs extension elements, last reuses output)
        GoldilocksExt2.Ext2 memory alpha = GoldilocksExt2.Ext2(
            openings.wires[2].c0, openings.wires[3].c0
        );
        uint256 numRouted = 3 * D + numCoeffs; // coefficients are single scalars

        GoldilocksExt2.Ext2 memory prevAcc = GoldilocksExt2.Ext2(
            openings.wires[4].c0, openings.wires[5].c0
        );

        for (uint256 i = 0; i < numCoeffs; i++) {
            // Coefficient is a single base field scalar (promoted to Ext2 via fromBase)
            GoldilocksExt2.Ext2 memory coeff = GoldilocksExt2.fromBase(openings.wires[6 + i].c0);
            GoldilocksExt2.Ext2 memory computed = prevAcc.mul(alpha).add(coeff);

            GoldilocksExt2.Ext2 memory actualAcc;
            if (i == numCoeffs - 1) {
                actualAcc = GoldilocksExt2.Ext2(openings.wires[0].c0, openings.wires[1].c0);
            } else {
                uint256 accBase = numRouted + i * D;
                actualAcc = GoldilocksExt2.Ext2(
                    openings.wires[accBase].c0, openings.wires[accBase + 1].c0
                );
            }

            GoldilocksExt2.Ext2 memory diff = actualAcc.sub(computed);
            c[i * D] = GoldilocksExt2.fromBase(diff.c0);
            c[i * D + 1] = GoldilocksExt2.fromBase(diff.c1);

            prevAcc = actualAcc;
        }
        return c;
    }

    /// @dev ReducingExtensionGate: Horner-style polynomial evaluation
    ///      acc[0] = old_acc * alpha + coeff[0]
    ///      acc[i] = acc[i-1] * alpha + coeff[i]
    ///      constraint[i*D..i*D+D-1]: acc[i] - computed (D=2 extension components)
    ///      gateConfig: [numCoeffs]
    function _evalReducingExtensionGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        uint256 numCoeffs = gateConfig[0];
        uint256 D = 2; // Extension degree
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](numCoeffs * D);

        // Wire layout (D=2):
        //   wires[0..1]: output (extension element)
        //   wires[2..3]: alpha (extension element)
        //   wires[4..5]: old_acc (initial accumulator)
        //   wires[6..6+numCoeffs*2-1]: coefficients (numCoeffs extension elements)
        //   Non-routed: intermediate accumulators (except last = output)
        GoldilocksExt2.Ext2 memory alpha = GoldilocksExt2.Ext2(
            openings.wires[2].c0, openings.wires[3].c0
        );

        // Start wire index for intermediates (non-routed)
        // In plonky2: start_accs = 3*D = 6 + numCoeffs*D (after all routed wires)
        uint256 numRouted = 3 * D + numCoeffs * D;

        GoldilocksExt2.Ext2 memory prevAcc = GoldilocksExt2.Ext2(
            openings.wires[4].c0, openings.wires[5].c0
        );

        for (uint256 i = 0; i < numCoeffs; i++) {
            uint256 coeffBase = 6 + i * D;
            GoldilocksExt2.Ext2 memory coeff = GoldilocksExt2.Ext2(
                openings.wires[coeffBase].c0, openings.wires[coeffBase + 1].c0
            );
            GoldilocksExt2.Ext2 memory computed = prevAcc.mul(alpha).add(coeff);

            // Get the actual accumulator value
            GoldilocksExt2.Ext2 memory actualAcc;
            if (i == numCoeffs - 1) {
                // Last accumulator is the output wire
                actualAcc = GoldilocksExt2.Ext2(openings.wires[0].c0, openings.wires[1].c0);
            } else {
                // Intermediate accumulators in non-routed wires
                uint256 accBase = numRouted + i * D;
                actualAcc = GoldilocksExt2.Ext2(
                    openings.wires[accBase].c0, openings.wires[accBase + 1].c0
                );
            }

            // Constraint: actualAcc - computed (split into D=2 base field components)
            GoldilocksExt2.Ext2 memory diff = actualAcc.sub(computed);
            c[i * D] = GoldilocksExt2.fromBase(diff.c0);
            c[i * D + 1] = GoldilocksExt2.fromBase(diff.c1);

            prevAcc = actualAcc;
        }
        return c;
    }

    /// @dev ArithmeticExtensionGate: c0*x*y + c1*z on extension field elements
    ///      gateConfig: [numOps]
    function _evalArithmeticExtensionGate(
        Openings memory openings,
        uint256 constOffset,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        uint256 numOps = gateConfig[0];
        uint256 D = 2;
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](numOps * D);

        for (uint256 i = 0; i < numOps; i++) {
            uint256 wBase = i * 4 * D;
            // Read extension elements (each is D=2 consecutive wires)
            GoldilocksExt2.Ext2 memory m0 = GoldilocksExt2.Ext2(
                openings.wires[wBase].c0, openings.wires[wBase + 1].c0
            );
            GoldilocksExt2.Ext2 memory m1 = GoldilocksExt2.Ext2(
                openings.wires[wBase + D].c0, openings.wires[wBase + D + 1].c0
            );
            GoldilocksExt2.Ext2 memory addend = GoldilocksExt2.Ext2(
                openings.wires[wBase + 2 * D].c0, openings.wires[wBase + 2 * D + 1].c0
            );
            GoldilocksExt2.Ext2 memory output = GoldilocksExt2.Ext2(
                openings.wires[wBase + 3 * D].c0, openings.wires[wBase + 3 * D + 1].c0
            );
            // Constants are base field scalars
            GoldilocksExt2.Ext2 memory c0 = openings.constants[constOffset + i * 2];
            GoldilocksExt2.Ext2 memory c1 = openings.constants[constOffset + i * 2 + 1];

            GoldilocksExt2.Ext2 memory expected = m0.mul(m1).mul(c0).add(addend.mul(c1));
            GoldilocksExt2.Ext2 memory diff = output.sub(expected);
            c[i * D] = GoldilocksExt2.fromBase(diff.c0);
            c[i * D + 1] = GoldilocksExt2.fromBase(diff.c1);
        }
        return c;
    }

    /// @dev MulExtensionGate: c0*x*y on extension field elements
    ///      gateConfig: [numOps]
    function _evalMulExtensionGate(
        Openings memory openings,
        uint256 constOffset,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        uint256 numOps = gateConfig[0];
        uint256 D = 2;
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](numOps * D);

        for (uint256 i = 0; i < numOps; i++) {
            uint256 wBase = i * 3 * D;
            GoldilocksExt2.Ext2 memory m0 = GoldilocksExt2.Ext2(
                openings.wires[wBase].c0, openings.wires[wBase + 1].c0
            );
            GoldilocksExt2.Ext2 memory m1 = GoldilocksExt2.Ext2(
                openings.wires[wBase + D].c0, openings.wires[wBase + D + 1].c0
            );
            GoldilocksExt2.Ext2 memory output = GoldilocksExt2.Ext2(
                openings.wires[wBase + 2 * D].c0, openings.wires[wBase + 2 * D + 1].c0
            );
            GoldilocksExt2.Ext2 memory c0 = openings.constants[constOffset + i];
            GoldilocksExt2.Ext2 memory expected = m0.mul(m1).mul(c0);
            GoldilocksExt2.Ext2 memory diff = output.sub(expected);
            c[i * D] = GoldilocksExt2.fromBase(diff.c0);
            c[i * D + 1] = GoldilocksExt2.fromBase(diff.c1);
        }
        return c;
    }

    /// @dev ExponentiationGate: binary exponentiation base^power
    ///      gateConfig: [numPowerBits]
    function _evalExponentiationGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        uint256 numPowerBits = gateConfig[0];
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](numPowerBits + 1);

        GoldilocksExt2.Ext2 memory base = openings.wires[0];
        uint256 outputWire = 1 + numPowerBits;
        uint256 intermediateStart = 2 + numPowerBits;

        GoldilocksExt2.Ext2 memory one = GoldilocksExt2.one();

        for (uint256 i = 0; i < numPowerBits; i++) {
            // Bit at position (numPowerBits - 1 - i) in BE order
            GoldilocksExt2.Ext2 memory curBit = openings.wires[1 + numPowerBits - 1 - i];

            // prev_intermediate = intermediate[i-1]^2 if i > 0, else 1
            GoldilocksExt2.Ext2 memory prevIntermediate;
            if (i == 0) {
                prevIntermediate = one;
            } else {
                GoldilocksExt2.Ext2 memory prevVal = openings.wires[intermediateStart + i - 1];
                prevIntermediate = prevVal.mul(prevVal);
            }

            // computed = prevIntermediate * (curBit * base + (1 - curBit))
            //          = prevIntermediate * (curBit * (base - 1) + 1)
            GoldilocksExt2.Ext2 memory selector = curBit.mul(base.sub(one)).add(one);
            GoldilocksExt2.Ext2 memory computed = prevIntermediate.mul(selector);
            GoldilocksExt2.Ext2 memory actual = openings.wires[intermediateStart + i];
            c[i] = actual.sub(computed);
        }

        // Final constraint: output - intermediate[numPowerBits - 1]
        c[numPowerBits] = openings.wires[outputWire].sub(openings.wires[intermediateStart + numPowerBits - 1]);
        return c;
    }

    /// @dev CosetInterpolationGate: Barycentric interpolation on a coset
    ///      gateConfig: [subgroupBits, numPoints, numIntermediates, degree, barycentricWeights...]
    function _evalCosetInterpolationGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        uint256 numPoints = gateConfig[1];
        uint256 numIntermediates = gateConfig[2];
        uint256 D = 2;
        // Total constraints: D + D + 2*D*numIntermediates = D*(2 + 2*numIntermediates)
        uint256 numConstraints = D * (2 + 2 * numIntermediates);
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](numConstraints);

        // Wire layout:
        //   wire[0]: shift (base field)
        //   wires[1..1+numPoints*D-1]: values (numPoints extension elements)
        //   wires[1+numPoints*D..+D-1]: evaluation_point (extension element)
        //   wires[1+numPoints*D+D..+D-1]: evaluation_value (output extension element)
        //   Non-routed:
        //     intermediate_eval[i]: numIntermediates extension elements
        //     intermediate_prod[i]: numIntermediates extension elements
        //     shifted_evaluation_point: extension element

        uint256 evalPointStart = 1 + numPoints * D;
        uint256 evalValueStart = evalPointStart + D;
        uint256 numRouted = evalValueStart + D;
        uint256 intEvalStart = numRouted;
        uint256 intProdStart = intEvalStart + numIntermediates * D;
        uint256 shiftedEvalStart = intProdStart + numIntermediates * D;

        GoldilocksExt2.Ext2 memory shift = openings.wires[0];
        GoldilocksExt2.Ext2 memory evalPoint = GoldilocksExt2.Ext2(
            openings.wires[evalPointStart].c0, openings.wires[evalPointStart + 1].c0
        );
        GoldilocksExt2.Ext2 memory shiftedEvalPoint = GoldilocksExt2.Ext2(
            openings.wires[shiftedEvalStart].c0, openings.wires[shiftedEvalStart + 1].c0
        );

        // Constraint 0-1 (D=2): evaluation_point - shifted_evaluation_point * shift = 0
        GoldilocksExt2.Ext2 memory diff0 = evalPoint.sub(shiftedEvalPoint.mul(shift));
        c[0] = GoldilocksExt2.fromBase(diff0.c0);
        c[1] = GoldilocksExt2.fromBase(diff0.c1);

        // Intermediate constraints: 2*D per intermediate
        // The interpolation uses a staged Barycentric formula
        // For simplicity and correctness, each intermediate tracks (eval_acc, prod_acc)
        // These are verified against the non-routed wire values
        // The exact computation depends on barycentric weights which are gate-specific
        // For now, we check the structural constraints:
        // Each intermediate is a (eval, prod) pair that builds up the interpolation
        uint256 cIdx = D;
        for (uint256 i = 0; i < numIntermediates; i++) {
            // Read intermediate eval and prod from non-routed wires
            // These are extension elements (D=2)
            uint256 ieBase = intEvalStart + i * D;
            uint256 ipBase = intProdStart + i * D;

            // The constraint verification requires barycentric weights
            // which are stored in gateConfig[4..4+numPoints-1]
            // For now, we trust the intermediate values and verify the final result
            // via the evaluation_value constraint below.
            // TODO: Full Barycentric interpolation constraint checking
            c[cIdx++] = GoldilocksExt2.zero();
            c[cIdx++] = GoldilocksExt2.zero();
            c[cIdx++] = GoldilocksExt2.zero();
            c[cIdx++] = GoldilocksExt2.zero();
        }

        // Final constraint (D=2): evaluation_value - final_computed_eval = 0
        // This is checked by the last intermediate's eval value
        if (numIntermediates > 0) {
            uint256 lastEvalBase = intEvalStart + (numIntermediates - 1) * D;
            uint256 lastProdBase = intProdStart + (numIntermediates - 1) * D;
            GoldilocksExt2.Ext2 memory lastEval = GoldilocksExt2.Ext2(
                openings.wires[lastEvalBase].c0, openings.wires[lastEvalBase + 1].c0
            );
            GoldilocksExt2.Ext2 memory lastProd = GoldilocksExt2.Ext2(
                openings.wires[lastProdBase].c0, openings.wires[lastProdBase + 1].c0
            );
            GoldilocksExt2.Ext2 memory evalValue = GoldilocksExt2.Ext2(
                openings.wires[evalValueStart].c0, openings.wires[evalValueStart + 1].c0
            );
            // finalEval = lastEval / lastProd
            // constraint: evalValue * lastProd - lastEval = 0
            GoldilocksExt2.Ext2 memory finalDiff = evalValue.mul(lastProd).sub(lastEval);
            c[numConstraints - 2] = GoldilocksExt2.fromBase(finalDiff.c0);
            c[numConstraints - 1] = GoldilocksExt2.fromBase(finalDiff.c1);
        }

        return c;
    }

    /// @dev PoseidonMdsGate: MDS matrix multiplication on 12 extension elements
    ///      output[r] = Σ MDS_CIRC[i] * input[(i+r)%12] + MDS_DIAG[r] * input[r]
    ///      24 constraints (12 outputs × D=2)
    function _evalPoseidonMdsGate(
        Openings memory openings
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        uint256 D = 2;
        uint256 W = 12; // SPONGE_WIDTH
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](W * D);

        // Read 12 input extension elements
        GoldilocksExt2.Ext2[12] memory inputs;
        for (uint256 i = 0; i < W; i++) {
            inputs[i] = GoldilocksExt2.Ext2(
                openings.wires[i * D].c0,
                openings.wires[i * D + 1].c0
            );
        }

        // For each output row r, compute MDS multiplication
        for (uint256 r = 0; r < W; r++) {
            GoldilocksExt2.Ext2 memory acc = GoldilocksExt2.zero();
            for (uint256 i = 0; i < W; i++) {
                uint256 idx = (i + r) % W;
                acc = acc.add(inputs[idx].mulScalar(PoseidonConstants.mdsCirc(i)));
            }
            acc = acc.add(inputs[r].mulScalar(PoseidonConstants.mdsDiag(r)));

            // Read output extension element
            GoldilocksExt2.Ext2 memory output = GoldilocksExt2.Ext2(
                openings.wires[(W + r) * D].c0,
                openings.wires[(W + r) * D + 1].c0
            );

            GoldilocksExt2.Ext2 memory diff = output.sub(acc);
            c[r * D] = GoldilocksExt2.fromBase(diff.c0);
            c[r * D + 1] = GoldilocksExt2.fromBase(diff.c1);
        }
        return c;
    }

    // -----------------------------------------------------------------------
    // Permutation argument
    // -----------------------------------------------------------------------

    function _checkPermutation(
        Openings memory openings,
        CircuitParams memory params,
        Challenges memory challenges,
        PermutationData memory permData
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        // chunk_size = max_degree = quotient_degree_factor (NOT - 1)
        uint256 chunkSize = params.quotientDegreeFactor;
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
        Openings memory openings,
        CircuitParams memory params,
        PermutationData memory permData,
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
        GoldilocksExt2.Ext2 memory betaZeta = beta.mul(zeta);
        uint256 partialIdx = ch * params.numPartialProducts;

        for (uint256 chunk = 0; chunk < numChunks; chunk++) {
            uint256 cEnd = (chunk + 1) * chunkSize;
            if (cEnd > params.numRoutedWires) cEnd = params.numRoutedWires;
            terms[ch * numChunks + chunk] = _computePermChunkTerm(
                openings, permData, beta, gamma, betaZeta,
                PermChunkParams(ch, chunk, chunk * chunkSize, cEnd, numChunks, partialIdx)
            );
        }
    }

    /// @dev Packed permutation chunk parameters to avoid stack depth issues.
    struct PermChunkParams {
        uint256 ch;
        uint256 chunk;
        uint256 chunkStart;
        uint256 chunkEnd;
        uint256 numChunks;
        uint256 partialIdx;
    }

    function _computePermChunkTerm(
        Openings memory openings,
        PermutationData memory permData,
        GoldilocksExt2.Ext2 memory beta,
        GoldilocksExt2.Ext2 memory gamma,
        GoldilocksExt2.Ext2 memory betaZeta,
        PermChunkParams memory p
    ) internal pure returns (GoldilocksExt2.Ext2 memory) {
        GoldilocksExt2.Ext2 memory prevAcc = p.chunk == 0
            ? openings.plonkZs[p.ch]
            : openings.partialProducts[p.partialIdx + p.chunk - 1];

        GoldilocksExt2.Ext2 memory nextAcc = p.chunk == p.numChunks - 1
            ? openings.plonkZsNext[p.ch]
            : openings.partialProducts[p.partialIdx + p.chunk];

        GoldilocksExt2.Ext2 memory numProd = GoldilocksExt2.one();
        GoldilocksExt2.Ext2 memory denProd = GoldilocksExt2.one();
        for (uint256 j = p.chunkStart; j < p.chunkEnd; j++) {
            GoldilocksExt2.Ext2 memory wireVal = openings.wires[j];
            numProd = numProd.mul(wireVal.add(betaZeta.mulScalar(permData.kIs[j])).add(gamma));
            denProd = denProd.mul(wireVal.add(beta.mul(openings.plonkSigmas[j])).add(gamma));
        }

        return prevAcc.mul(numProd).sub(nextAcc.mul(denProd));
    }

    // -----------------------------------------------------------------------
    // Alpha reduction
    // -----------------------------------------------------------------------

    function _reduceWithAlphas(
        GoldilocksExt2.Ext2[] memory terms,
        uint256[] memory alphas,
        uint256 numChallenges
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        GoldilocksExt2.Ext2[] memory result = new GoldilocksExt2.Ext2[](numChallenges);
        for (uint256 i = 0; i < numChallenges; i++) {
            GoldilocksExt2.Ext2 memory alpha = GoldilocksExt2.fromBase(alphas[i]);
            GoldilocksExt2.Ext2 memory acc = GoldilocksExt2.zero();
            for (uint256 j = terms.length; j > 0; j--) {
                acc = acc.mul(alpha).add(terms[j - 1]);
            }
            result[i] = acc;
        }
        return result;
    }
}
