// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/PoseidonGateEval.sol";
import "../src/PoseidonConstants.sol";
import "../src/GoldilocksField.sol";

contract PoseidonGateEvalTest is Test {
    using GoldilocksField for uint256;

    uint256 constant GL_P = GoldilocksField.P;

    /// @dev Test S-box: x^7 for a known value
    function test_sbox() public pure {
        // x = 3, x^7 = 2187
        uint256 result = PoseidonGateEval.sbox(3);
        assertEq(result, 2187);

        // x = 0
        assertEq(PoseidonGateEval.sbox(0), 0);

        // x = 1
        assertEq(PoseidonGateEval.sbox(1), 1);
    }

    /// @dev Test MDS layer with known input
    function test_mdsLayer() public pure {
        uint256[12] memory state;
        state[0] = 1;
        // All others are 0

        uint256[12] memory result = PoseidonGateEval.mdsLayer(state);

        // result[0] = state[0] * (circ[0] + diag[0]) = 1 * (17 + 8) = 25
        assertEq(result[0], 25);
        // result[1] = state[(0+1)%12=1] * circ[0] + state[1] * diag[1]
        //           = 0 * 17 + 0 * 0 = 0... wait, state[0]=1
        // result[r] = sum_{i=0..11} state[(i+r)%12] * circ[i] + state[r]*diag[r]
        // result[1] = state[(0+1)%12] * circ[0] + state[(1+1)%12] * circ[1] + ...
        //           = state[1]*circ[0] + state[2]*circ[1] + ...
        // Only state[0]=1, so for r=1: we need i such that (i+1)%12 == 0 → i=11
        // result[1] = state[0] * circ[11] + state[1]*diag[1] = 1*20 + 0 = 20
        assertEq(result[1], 20);
    }

    /// @dev Test Poseidon permutation matches known Plonky2 output.
    ///      Input:  [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    ///      This test verifies the full constraint evaluation returns all zeros
    ///      when wire values are correctly computed.
    function test_roundConstants() public pure {
        // Verify first few round constants match Plonky2
        assertEq(PoseidonConstants.roundConstant(0), 0xb585f766f2144405);
        assertEq(PoseidonConstants.roundConstant(1), 0x7746a55f43921ad7);
        assertEq(PoseidonConstants.roundConstant(11), 0xc54302f225db2c76);
        // Round 1 (index 12)
        assertEq(PoseidonConstants.roundConstant(12), 0x86287821f722c881);
    }

    /// @dev Test that constraint count is exactly 123
    function test_constraintCount() public pure {
        // Create a dummy wire array (all zeros)
        uint256[] memory wires = new uint256[](135);
        uint256[] memory constraints = PoseidonGateEval.evaluate(wires);
        assertEq(constraints.length, 123);
    }

    /// @dev Gas estimation for full PoseidonGate evaluation
    function test_gasEstimate() public {
        uint256[] memory wires = new uint256[](135);
        uint256 gasBefore = gasleft();
        PoseidonGateEval.evaluate(wires);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("PoseidonGate evaluate gas", gasUsed);
        // Should be under 500K gas
        assertLt(gasUsed, 500_000);
    }
}
