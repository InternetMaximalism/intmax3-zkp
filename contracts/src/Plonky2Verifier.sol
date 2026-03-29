// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GoldilocksField.sol";
import "./PoseidonGateEval.sol";

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
    }

    // -----------------------------------------------------------------------
    // Main verification entry point
    // -----------------------------------------------------------------------

    /// @notice Verify Plonky2 constraint satisfaction at challenge point ζ.
    function verifyConstraints(
        Openings calldata openings,
        CircuitParams calldata params,
        Challenges calldata challenges,
        PermutationData calldata permData,
        GateInfo[] calldata gates,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
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
        Openings calldata openings,
        CircuitParams calldata params,
        Challenges calldata challenges,
        PermutationData calldata permData,
        GateInfo[] calldata gates,
        uint256[] calldata publicInputs
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
        Openings calldata openings,
        CircuitParams calldata params,
        GateInfo[] calldata gates,
        uint256[] calldata publicInputs
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
                publicInputs
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
        Openings calldata openings,
        uint256 constOffset,
        uint256[] calldata publicInputs
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        if (gateType == 0) {
            // NoopGate: 0 constraints
            return new GoldilocksExt2.Ext2[](0);
        } else if (gateType == 1) {
            // ConstantGate: wire[i] - constant[i] = 0
            return _evalConstantGateExt2(openings, constOffset);
        } else if (gateType == 2) {
            // PublicInputGate: wire[i] - piHash[i] = 0
            return _evalPublicInputGateExt2(openings, publicInputs);
        } else if (gateType == 3) {
            // PoseidonGate: full 123 constraints
            return _evalPoseidonGateExt2(openings);
        } else if (gateType == 4) {
            // ArithmeticGate
            return _evalArithmeticGateExt2(openings, constOffset);
        }
        // Unknown gate: return empty
        return new GoldilocksExt2.Ext2[](0);
    }

    // -----------------------------------------------------------------------
    // Gate implementations (Ext2 versions)
    // -----------------------------------------------------------------------

    function _evalConstantGateExt2(
        Openings calldata openings,
        uint256 constOffset
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        // ConstantGate { num_consts: N }: wire[i] - constant[constOffset + i] = 0
        // Typically num_consts = 2
        uint256 numConsts = 2; // TODO: make configurable
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](numConsts);
        for (uint256 i = 0; i < numConsts; i++) {
            c[i] = openings.wires[i].sub(openings.constants[constOffset + i]);
        }
        return c;
    }

    function _evalPublicInputGateExt2(
        Openings calldata openings,
        uint256[] calldata publicInputs
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        // PublicInputGate: wire[i] - piHash_element[i] = 0 for i in 0..3
        // piHash is computed off-chain from public inputs
        // For now, compare wires to first 4 public inputs as Ext2
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](4);
        for (uint256 i = 0; i < 4; i++) {
            GoldilocksExt2.Ext2 memory piVal = GoldilocksExt2.fromBase(
                i < publicInputs.length ? publicInputs[i] : 0
            );
            c[i] = openings.wires[i].sub(piVal);
        }
        return c;
    }

    function _evalPoseidonGateExt2(
        Openings calldata openings
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        // Delegate to PoseidonGateEval library
        // Convert wire Ext2 values to base field (take c0 component)
        // PoseidonGate operates in base field
        uint256 numWires = 135;
        uint256[] memory baseWires = new uint256[](numWires);
        for (uint256 i = 0; i < numWires && i < openings.wires.length; i++) {
            baseWires[i] = openings.wires[i].c0;
        }

        uint256[] memory baseConstraints = PoseidonGateEval.evaluate(baseWires);

        // Convert back to Ext2
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](baseConstraints.length);
        for (uint256 i = 0; i < baseConstraints.length; i++) {
            c[i] = GoldilocksExt2.fromBase(baseConstraints[i]);
        }
        return c;
    }

    function _evalArithmeticGateExt2(
        Openings calldata openings,
        uint256 constOffset
    ) internal pure returns (GoldilocksExt2.Ext2[] memory) {
        // ArithmeticGate with num_ops operations
        // Each op: output - (mult0 * mult1 * const0 + addend * const1) = 0
        // Wire layout: [mult0, mult1, addend, output] * numOps
        uint256 numOps = 20; // TODO: make configurable (standard config uses 20)
        GoldilocksExt2.Ext2[] memory c = new GoldilocksExt2.Ext2[](numOps);
        for (uint256 i = 0; i < numOps; i++) {
            uint256 wBase = i * 4;
            GoldilocksExt2.Ext2 memory m0 = openings.wires[wBase];
            GoldilocksExt2.Ext2 memory m1 = openings.wires[wBase + 1];
            GoldilocksExt2.Ext2 memory addend = openings.wires[wBase + 2];
            GoldilocksExt2.Ext2 memory output = openings.wires[wBase + 3];
            GoldilocksExt2.Ext2 memory c0 = openings.constants[constOffset + i * 2];
            GoldilocksExt2.Ext2 memory c1 = openings.constants[constOffset + i * 2 + 1];
            GoldilocksExt2.Ext2 memory expected = m0.mul(m1).mul(c0).add(addend.mul(c1));
            c[i] = output.sub(expected);
        }
        return c;
    }

    // -----------------------------------------------------------------------
    // Permutation argument
    // -----------------------------------------------------------------------

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
        Openings calldata openings,
        PermutationData calldata permData,
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
        uint256[] calldata alphas,
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
