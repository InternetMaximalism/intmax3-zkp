// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/PoseidonGateEval.sol";
import "../src/PoseidonConstants.sol";
import "../src/GoldilocksField.sol";

contract PoseidonGateEvalTest is Test {
    /// @dev Test round constants match Plonky2
    function test_roundConstants() public pure {
        assertEq(PoseidonConstants.roundConstant(0), 0xb585f766f2144405);
        assertEq(PoseidonConstants.roundConstant(1), 0x7746a55f43921ad7);
        assertEq(PoseidonConstants.roundConstant(11), 0xc54302f225db2c76);
        assertEq(PoseidonConstants.roundConstant(12), 0x86287821f722c881);
    }

    /// @dev Test that Ext2 constraint evaluation returns exactly 123 constraints
    function test_constraintCount_ext2() public pure {
        GoldilocksExt2.Ext2[] memory wires = new GoldilocksExt2.Ext2[](135);
        for (uint256 i = 0; i < 135; i++) {
            wires[i] = GoldilocksExt2.zero();
        }
        GoldilocksExt2.Ext2[] memory constraints = PoseidonGateEval.evaluateExt2(wires);
        assertEq(constraints.length, 123);
    }

    /// @dev Gas estimation for Ext2 PoseidonGate evaluation
    function test_gasEstimate_ext2() public {
        GoldilocksExt2.Ext2[] memory wires = new GoldilocksExt2.Ext2[](135);
        for (uint256 i = 0; i < 135; i++) {
            wires[i] = GoldilocksExt2.zero();
        }
        uint256 gasBefore = gasleft();
        PoseidonGateEval.evaluateExt2(wires);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("PoseidonGate Ext2 evaluate gas", gasUsed);
        // Ext2 version should be under 500K gas
        assertLt(gasUsed, 500_000);
    }

    /// @dev Test MDS constants
    function test_mdsConstants() public pure {
        assertEq(PoseidonConstants.mdsCirc(0), 17);
        assertEq(PoseidonConstants.mdsCirc(11), 20);
        assertEq(PoseidonConstants.mdsDiag(0), 8);
        assertEq(PoseidonConstants.mdsDiag(1), 0);
    }
}
