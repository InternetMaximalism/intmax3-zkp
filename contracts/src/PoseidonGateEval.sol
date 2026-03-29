// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GoldilocksField.sol";
import "./PoseidonConstants.sol";

/// @title PoseidonGateEval — Evaluate PoseidonGate constraints at challenge point ζ
/// @dev Implements the exact constraint equations from Plonky2's PoseidonGate.
///      The gate computes a Poseidon permutation over 12 Goldilocks elements.
///
///      Wire layout (135 wires total):
///        0..11:   input[0..12]
///        12..23:  output[0..12]
///        24:      swap flag (binary)
///        25..28:  delta[0..4]
///        29..64:  full_sbox_0[round 1..3][0..11]  (3 * 12 = 36)
///        65..86:  partial_sbox[0..21]              (22)
///        87..134: full_sbox_1[round 0..3][0..11]   (4 * 12 = 48)
///
///      Total constraints: 1 + 4 + 36 + 22 + 48 + 12 = 123
library PoseidonGateEval {
    using GoldilocksField for uint256;

    uint256 constant WIDTH = 12;
    uint256 constant HALF_N_FULL = 4;
    uint256 constant N_PARTIAL = 22;
    uint256 constant P = GoldilocksField.P;

    // Wire index helpers
    function wireInput(uint256 i) internal pure returns (uint256) { return i; }
    function wireOutput(uint256 i) internal pure returns (uint256) { return 12 + i; }
    function wireSwap() internal pure returns (uint256) { return 24; }
    function wireDelta(uint256 i) internal pure returns (uint256) { return 25 + i; }
    function wireFullSbox0(uint256 round, uint256 i) internal pure returns (uint256) {
        return 29 + 12 * (round - 1) + i; // round is 1-indexed (1,2,3)
    }
    function wirePartialSbox(uint256 r) internal pure returns (uint256) { return 65 + r; }
    function wireFullSbox1(uint256 round, uint256 i) internal pure returns (uint256) {
        return 87 + 12 * round + i;
    }

    /// @dev S-box: x^7 in Goldilocks field
    function sbox(uint256 x) internal pure returns (uint256) {
        uint256 x2 = x.mul(x);
        uint256 x3 = x.mul(x2);
        uint256 x4 = x2.mul(x2);
        return x3.mul(x4);
    }

    /// @dev Full MDS layer: state = MDS * state
    ///      MDS = Circulant(circ) + Diag(diag)
    function mdsLayer(uint256[12] memory state) internal pure returns (uint256[12] memory) {
        uint256[12] memory result;
        // Circulant part: result[r] = sum_{i=0..11} state[(i+r)%12] * circ[i]
        // Plus diagonal: result[r] += state[r] * diag[r]
        for (uint256 r = 0; r < 12; r++) {
            uint256 acc = 0;
            for (uint256 i = 0; i < 12; i++) {
                uint256 idx = (i + r) % 12;
                acc = acc.add(state[idx].mul(PoseidonConstants.mdsCirc(i)));
            }
            acc = acc.add(state[r].mul(PoseidonConstants.mdsDiag(r)));
            result[r] = acc;
        }
        return result;
    }

    /// @dev Partial MDS layer (fast): used in partial rounds
    function mdsPartialLayerFast(uint256[12] memory state, uint256 r)
        internal pure returns (uint256[12] memory)
    {
        uint256[12] memory result;
        // d = state[0] * (circ[0] + diag[0]) + sum_{i=1..11} state[i] * wHat[r][i-1]
        uint256 d = state[0].mul(PoseidonConstants.mdsCirc(0).add(PoseidonConstants.mdsDiag(0)));
        for (uint256 i = 1; i < 12; i++) {
            d = d.add(state[i].mul(PoseidonConstants.wHat(r, i - 1)));
        }
        result[0] = d;
        // result[i] = state[0] * vs[r][i-1] + state[i]  for i in 1..11
        for (uint256 i = 1; i < 12; i++) {
            result[i] = state[0].mul(PoseidonConstants.vs(r, i - 1)).add(state[i]);
        }
        return result;
    }

    /// @dev Initial partial round matrix multiplication
    function mdsPartialLayerInit(uint256[12] memory state)
        internal pure returns (uint256[12] memory)
    {
        uint256[12] memory result;
        result[0] = state[0];
        for (uint256 c = 1; c < 12; c++) {
            uint256 acc = 0;
            for (uint256 r = 1; r < 12; r++) {
                acc = acc.add(state[r].mul(PoseidonConstants.initialMatrix(r - 1, c - 1)));
            }
            result[c] = acc;
        }
        return result;
    }

    /// @dev Evaluate all 123 PoseidonGate constraints.
    /// @param wires Wire evaluations at ζ (base field values, will be treated as Ext2 with c1=0)
    /// @return constraints Array of 123 constraint values (should all be 0 for valid proof)
    function evaluate(uint256[] memory wires)
        internal pure returns (uint256[] memory constraints)
    {
        constraints = new uint256[](123);
        uint256 cidx = 0;

        // Load state from input wires
        uint256[12] memory state;
        for (uint256 i = 0; i < 12; i++) {
            state[i] = wires[wireInput(i)];
        }

        uint256 swap = wires[wireSwap()];

        // Constraint 0: swap * (swap - 1) == 0
        constraints[cidx++] = swap.mul(swap.sub(GoldilocksField.ONE));

        // Constraints 1-4: delta[i] = swap * (input[i+4] - input[i])
        for (uint256 i = 0; i < 4; i++) {
            uint256 expected = swap.mul(wires[wireInput(i + 4)].sub(wires[wireInput(i)]));
            constraints[cidx++] = wires[wireDelta(i)].sub(expected);
        }

        // Apply swap to state
        uint256[4] memory delta;
        for (uint256 i = 0; i < 4; i++) {
            delta[i] = wires[wireDelta(i)];
        }
        for (uint256 i = 0; i < 4; i++) {
            state[i] = state[i].add(delta[i]);
            state[i + 4] = state[i + 4].sub(delta[i]);
        }

        // ---- First half full rounds ----
        uint256 roundCtr = 0;

        // Round 0: no constraints emitted (inputs come from swap logic)
        _constantLayer(state, roundCtr);
        _sboxLayer(state);
        state = mdsLayer(state);
        roundCtr++;

        // Rounds 1, 2, 3: emit 12 constraints each (36 total)
        for (uint256 round = 1; round < HALF_N_FULL; round++) {
            _constantLayer(state, roundCtr);
            for (uint256 i = 0; i < 12; i++) {
                constraints[cidx++] = state[i].sub(wires[wireFullSbox0(round, i)]);
                state[i] = sbox(wires[wireFullSbox0(round, i)]);
            }
            state = mdsLayer(state);
            roundCtr++;
        }

        // ---- Partial rounds ----
        // Apply fast partial first round constant
        for (uint256 i = 0; i < 12; i++) {
            state[i] = state[i].add(PoseidonConstants.fastPartialFirstRoundConstant(i));
        }
        state = mdsPartialLayerInit(state);

        // 22 partial rounds
        for (uint256 r = 0; r < N_PARTIAL; r++) {
            constraints[cidx++] = state[0].sub(wires[wirePartialSbox(r)]);
            state[0] = sbox(wires[wirePartialSbox(r)]);
            if (r < N_PARTIAL - 1) {
                state[0] = state[0].add(PoseidonConstants.fastPartialRoundConstant(r));
            }
            state = mdsPartialLayerFast(state, r);
        }

        roundCtr += N_PARTIAL;

        // ---- Second half full rounds ----
        for (uint256 round = 0; round < HALF_N_FULL; round++) {
            _constantLayer(state, roundCtr);
            for (uint256 i = 0; i < 12; i++) {
                constraints[cidx++] = state[i].sub(wires[wireFullSbox1(round, i)]);
                state[i] = sbox(wires[wireFullSbox1(round, i)]);
            }
            state = mdsLayer(state);
            roundCtr++;
        }

        // ---- Output check: 12 constraints ----
        for (uint256 i = 0; i < 12; i++) {
            constraints[cidx++] = state[i].sub(wires[wireOutput(i)]);
        }

        assert(cidx == 123);
    }

    /// @dev Add round constants to state
    function _constantLayer(uint256[12] memory state, uint256 roundCtr) internal pure {
        for (uint256 i = 0; i < 12; i++) {
            state[i] = state[i].add(PoseidonConstants.roundConstant(i + 12 * roundCtr));
        }
    }

    /// @dev Apply S-box to all state elements
    function _sboxLayer(uint256[12] memory state) internal pure {
        for (uint256 i = 0; i < 12; i++) {
            state[i] = sbox(state[i]);
        }
    }
}
