// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/GoldilocksField.sol";

contract GoldilocksFieldTest is Test {
    using GoldilocksField for uint256;
    uint256 constant P = GoldilocksField.P;

    function test_add() public pure {
        assertEq(uint256(3).add(5), 8);
        // Wrap around
        assertEq((P - 1).add(2), 1);
        assertEq((P - 1).add(1), 0);
    }

    function test_sub() public pure {
        assertEq(uint256(5).sub(3), 2);
        // Underflow wraps
        assertEq(uint256(0).sub(1), P - 1);
        assertEq(uint256(3).sub(5), P - 2);
    }

    function test_mul() public pure {
        assertEq(uint256(3).mul(7), 21);
        assertEq((P - 1).mul(P - 1), 1); // (-1)*(-1) = 1
        assertEq(uint256(0).mul(12345), 0);
    }

    function test_neg() public pure {
        assertEq(uint256(0).neg(), 0);
        assertEq(uint256(1).neg(), P - 1);
        assertEq((P - 1).neg(), 1);
    }

    function test_inv() public view {
        uint256 a = 7;
        uint256 aInv = a.inv();
        assertEq(a.mul(aInv), 1);

        a = 12345678;
        aInv = a.inv();
        assertEq(a.mul(aInv), 1);

        a = P - 1; // -1
        aInv = a.inv();
        assertEq(a.mul(aInv), 1);
    }

    function test_modExp() public view {
        // 2^10 = 1024
        assertEq(GoldilocksField.modExp(2, 10), 1024);
        // a^(P-1) = 1 (Fermat's little theorem)
        assertEq(GoldilocksField.modExp(7, P - 1), 1);
    }

    function test_expPowerOf2() public pure {
        // x^(2^0) = x
        assertEq(GoldilocksField.expPowerOf2(3, 0), 3);
        // x^(2^1) = x^2
        assertEq(GoldilocksField.expPowerOf2(3, 1), 9);
        // x^(2^2) = x^4
        assertEq(GoldilocksField.expPowerOf2(3, 2), 81);
    }

    function test_evalL0() public view {
        // L_0(ω^0) should be 1 where ω is the subgroup generator
        // For degree_bits=2, n=4, subgroup generator ω = g^((P-1)/4)
        uint256 degreeBits = 2;
        // Test that L_0(1) would give 0/0 (special case), but for non-trivial x:
        // L_0(x) = (x^n - 1) / (n * (x - 1))
        // L_0(2) = (2^4 - 1) / (4 * (2-1)) = 15/4
        uint256 x = 2;
        uint256 result = GoldilocksField.evalL0(x, degreeBits);
        // 15/4 in field = 15 * inv(4)
        uint256 expected = uint256(15).mul(uint256(4).inv());
        assertEq(result, expected);
    }

    function test_reduceWithPowers() public pure {
        // [1, 2, 3] with alpha=10 → 1 + 2*10 + 3*100 = 321
        uint256[] memory terms = new uint256[](3);
        terms[0] = 1;
        terms[1] = 2;
        terms[2] = 3;
        uint256 result = GoldilocksField.reduceWithPowers(terms, 10);
        assertEq(result, 321);
    }
}

contract GoldilocksExt2Test is Test {
    using GoldilocksField for uint256;
    using GoldilocksExt2 for GoldilocksExt2.Ext2;
    uint256 constant P = GoldilocksField.P;

    function test_add() public pure {
        GoldilocksExt2.Ext2 memory a = GoldilocksExt2.Ext2(3, 5);
        GoldilocksExt2.Ext2 memory b = GoldilocksExt2.Ext2(7, 11);
        GoldilocksExt2.Ext2 memory c = a.add(b);
        assertEq(c.c0, 10);
        assertEq(c.c1, 16);
    }

    function test_mul() public pure {
        // (3 + 5α)(7 + 11α) = 3*7 + 7*5*7 + (3*11 + 5*7)α
        // Wait: (a0 + a1·α)(b0 + b1·α) = (a0·b0 + W·a1·b1) + (a0·b1 + a1·b0)·α
        // = (3*7 + 7*5*11) + (3*11 + 5*7)α = (21 + 385) + (33 + 35)α = 406 + 68α
        GoldilocksExt2.Ext2 memory a = GoldilocksExt2.Ext2(3, 5);
        GoldilocksExt2.Ext2 memory b = GoldilocksExt2.Ext2(7, 11);
        GoldilocksExt2.Ext2 memory c = a.mul(b);
        assertEq(c.c0, 406);
        assertEq(c.c1, 68);
    }

    function test_inv() public view {
        GoldilocksExt2.Ext2 memory a = GoldilocksExt2.Ext2(3, 5);
        GoldilocksExt2.Ext2 memory aInv = a.inv();
        GoldilocksExt2.Ext2 memory product = a.mul(aInv);
        assertEq(product.c0, 1);
        assertEq(product.c1, 0);
    }

    function test_mulScalar() public pure {
        GoldilocksExt2.Ext2 memory a = GoldilocksExt2.Ext2(3, 5);
        GoldilocksExt2.Ext2 memory b = a.mulScalar(10);
        assertEq(b.c0, 30);
        assertEq(b.c1, 50);
    }

    function test_expPowerOf2() public pure {
        GoldilocksExt2.Ext2 memory a = GoldilocksExt2.Ext2(3, 5);
        GoldilocksExt2.Ext2 memory a2 = a.expPowerOf2(1); // a^2
        GoldilocksExt2.Ext2 memory expected = a.mul(a);
        assertTrue(a2.isEqual(expected));
    }

    function test_isEqual() public pure {
        GoldilocksExt2.Ext2 memory a = GoldilocksExt2.Ext2(3, 5);
        GoldilocksExt2.Ext2 memory b = GoldilocksExt2.Ext2(3, 5);
        GoldilocksExt2.Ext2 memory c = GoldilocksExt2.Ext2(3, 6);
        assertTrue(a.isEqual(b));
        assertFalse(a.isEqual(c));
    }

    function test_reduceWithPowers() public pure {
        // [a, b] with alpha → a + b*alpha
        GoldilocksExt2.Ext2[] memory terms = new GoldilocksExt2.Ext2[](2);
        terms[0] = GoldilocksExt2.Ext2(1, 0);
        terms[1] = GoldilocksExt2.Ext2(2, 0);
        GoldilocksExt2.Ext2 memory alpha = GoldilocksExt2.Ext2(10, 0);
        GoldilocksExt2.Ext2 memory result = GoldilocksExt2.reduceWithPowers(terms, alpha);
        assertEq(result.c0, 21); // 1 + 2*10
        assertEq(result.c1, 0);
    }
}
