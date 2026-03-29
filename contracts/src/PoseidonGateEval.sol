// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GoldilocksField.sol";
import "./PoseidonConstants.sol";

/// @title PoseidonGateEval — Evaluate PoseidonGate constraints at ζ (extension field)
/// @dev All arithmetic uses GoldilocksExt2 since the challenge point ζ is in F_p^2.
///      Wire evaluations at ζ are Ext2 elements.
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
    using GoldilocksExt2 for GoldilocksExt2.Ext2;

    uint256 constant WIDTH = 12;
    uint256 constant HALF_N_FULL = 4;
    uint256 constant N_PARTIAL = 22;

    // Wire index helpers
    function _wireInput(uint256 i) private pure returns (uint256) { return i; }
    function _wireOutput(uint256 i) private pure returns (uint256) { return 12 + i; }
    function _wireSwap() private pure returns (uint256) { return 24; }
    function _wireDelta(uint256 i) private pure returns (uint256) { return 25 + i; }
    function _wireFullSbox0(uint256 round, uint256 i) private pure returns (uint256) {
        return 29 + 12 * (round - 1) + i;
    }
    function _wirePartialSbox(uint256 r) private pure returns (uint256) { return 65 + r; }
    function _wireFullSbox1(uint256 round, uint256 i) private pure returns (uint256) {
        return 87 + 12 * round + i;
    }

    /// @dev S-box: x^7 in Ext2
    function _sbox(GoldilocksExt2.Ext2 memory x) private pure returns (GoldilocksExt2.Ext2 memory) {
        GoldilocksExt2.Ext2 memory x2 = x.mul(x);
        GoldilocksExt2.Ext2 memory x3 = x.mul(x2);
        GoldilocksExt2.Ext2 memory x4 = x2.mul(x2);
        return x3.mul(x4);
    }

    /// @dev Full MDS layer in Ext2
    function _mdsLayer(GoldilocksExt2.Ext2[12] memory state)
        private pure returns (GoldilocksExt2.Ext2[12] memory)
    {
        GoldilocksExt2.Ext2[12] memory result;
        for (uint256 r = 0; r < 12; r++) {
            GoldilocksExt2.Ext2 memory acc = GoldilocksExt2.zero();
            for (uint256 i = 0; i < 12; i++) {
                uint256 idx = (i + r) % 12;
                acc = acc.add(state[idx].mulScalar(PoseidonConstants.mdsCirc(i)));
            }
            acc = acc.add(state[r].mulScalar(PoseidonConstants.mdsDiag(r)));
            result[r] = acc;
        }
        return result;
    }

    /// @dev Partial MDS layer (fast) in Ext2
    function _mdsPartialLayerFast(GoldilocksExt2.Ext2[12] memory state, uint256 r)
        private pure returns (GoldilocksExt2.Ext2[12] memory)
    {
        GoldilocksExt2.Ext2[12] memory result;
        // d = state[0] * M_00 + sum_{i=1..11} state[i] * wHat[r][i-1]
        uint256 m00 = PoseidonConstants.mdsCirc(0) + PoseidonConstants.mdsDiag(0); // 17 + 8 = 25
        GoldilocksExt2.Ext2 memory d = state[0].mulScalar(m00);
        for (uint256 i = 1; i < 12; i++) {
            d = d.add(state[i].mulScalar(PoseidonConstants.wHat(r, i - 1)));
        }
        result[0] = d;
        for (uint256 i = 1; i < 12; i++) {
            result[i] = state[0].mulScalar(PoseidonConstants.vs(r, i - 1)).add(state[i]);
        }
        return result;
    }

    /// @dev Initial partial round matrix in Ext2
    function _mdsPartialLayerInit(GoldilocksExt2.Ext2[12] memory state)
        private pure returns (GoldilocksExt2.Ext2[12] memory)
    {
        GoldilocksExt2.Ext2[12] memory result;
        result[0] = state[0];
        for (uint256 c = 1; c < 12; c++) {
            GoldilocksExt2.Ext2 memory acc = GoldilocksExt2.zero();
            for (uint256 r = 1; r < 12; r++) {
                acc = acc.add(state[r].mulScalar(PoseidonConstants.initialMatrix(r - 1, c - 1)));
            }
            result[c] = acc;
        }
        return result;
    }

    /// @dev Add round constants to Ext2 state (constants are base field)
    function _constantLayer(GoldilocksExt2.Ext2[12] memory state, uint256 roundCtr) private pure {
        for (uint256 i = 0; i < 12; i++) {
            state[i] = state[i].add(GoldilocksExt2.fromBase(
                PoseidonConstants.roundConstant(i + 12 * roundCtr)
            ));
        }
    }

    /// @dev Apply S-box to all state elements
    function _sboxLayer(GoldilocksExt2.Ext2[12] memory state) private pure {
        for (uint256 i = 0; i < 12; i++) {
            state[i] = _sbox(state[i]);
        }
    }

    /// @dev Evaluate all 123 PoseidonGate constraints in Ext2.
    /// @param wires Wire evaluations at ζ as Ext2 elements
    /// @return constraints Array of 123 Ext2 constraint values (should all be zero)
    function evaluateExt2(GoldilocksExt2.Ext2[] memory wires)
        internal pure returns (GoldilocksExt2.Ext2[] memory constraints)
    {
        constraints = new GoldilocksExt2.Ext2[](123);
        uint256 cidx = 0;

        // Load state from input wires
        GoldilocksExt2.Ext2[12] memory state;
        for (uint256 i = 0; i < 12; i++) {
            state[i] = wires[_wireInput(i)];
        }

        GoldilocksExt2.Ext2 memory swap = wires[_wireSwap()];

        // Constraint 0: swap * (swap - 1) == 0
        constraints[cidx++] = swap.mul(swap.sub(GoldilocksExt2.one()));

        // Constraints 1-4: delta[i] = swap * (input[i+4] - input[i])
        for (uint256 i = 0; i < 4; i++) {
            GoldilocksExt2.Ext2 memory expected = swap.mul(
                wires[_wireInput(i + 4)].sub(wires[_wireInput(i)])
            );
            constraints[cidx++] = wires[_wireDelta(i)].sub(expected);
        }

        // Apply swap to state
        for (uint256 i = 0; i < 4; i++) {
            GoldilocksExt2.Ext2 memory delta = wires[_wireDelta(i)];
            state[i] = state[i].add(delta);
            state[i + 4] = state[i + 4].sub(delta);
        }

        // ---- First half full rounds ----
        uint256 roundCtr = 0;

        // Round 0: no constraints emitted
        _constantLayer(state, roundCtr);
        _sboxLayer(state);
        state = _mdsLayer(state);
        roundCtr++;

        // Rounds 1, 2, 3: emit 12 constraints each (36 total)
        for (uint256 round = 1; round < HALF_N_FULL; round++) {
            _constantLayer(state, roundCtr);
            for (uint256 i = 0; i < 12; i++) {
                constraints[cidx++] = state[i].sub(wires[_wireFullSbox0(round, i)]);
                state[i] = _sbox(wires[_wireFullSbox0(round, i)]);
            }
            state = _mdsLayer(state);
            roundCtr++;
        }

        // ---- Partial rounds ----
        for (uint256 i = 0; i < 12; i++) {
            state[i] = state[i].add(GoldilocksExt2.fromBase(
                PoseidonConstants.fastPartialFirstRoundConstant(i)
            ));
        }
        state = _mdsPartialLayerInit(state);

        for (uint256 r = 0; r < N_PARTIAL; r++) {
            constraints[cidx++] = state[0].sub(wires[_wirePartialSbox(r)]);
            state[0] = _sbox(wires[_wirePartialSbox(r)]);
            if (r < N_PARTIAL - 1) {
                state[0] = state[0].add(GoldilocksExt2.fromBase(
                    PoseidonConstants.fastPartialRoundConstant(r)
                ));
            }
            state = _mdsPartialLayerFast(state, r);
        }

        roundCtr += N_PARTIAL;

        // ---- Second half full rounds ----
        for (uint256 round = 0; round < HALF_N_FULL; round++) {
            _constantLayer(state, roundCtr);
            for (uint256 i = 0; i < 12; i++) {
                constraints[cidx++] = state[i].sub(wires[_wireFullSbox1(round, i)]);
                state[i] = _sbox(wires[_wireFullSbox1(round, i)]);
            }
            state = _mdsLayer(state);
            roundCtr++;
        }

        // ---- Output check: 12 constraints ----
        for (uint256 i = 0; i < 12; i++) {
            constraints[cidx++] = state[i].sub(wires[_wireOutput(i)]);
        }

        assert(cidx == 123);
    }
}
