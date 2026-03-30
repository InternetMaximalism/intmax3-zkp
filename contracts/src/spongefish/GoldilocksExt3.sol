// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GoldilocksExt3
/// @notice Cubic extension of Goldilocks field: F_p[x] / (x^3 - 2)
///         where p = 2^64 - 2^32 + 1 (Goldilocks prime)
///
///   Elements are represented as (c0, c1, c2) where element = c0 + c1*x + c2*x^2
///   Multiplication uses x^3 = 2 (NONRESIDUE = 2)
///
///   This matches WizardOfMenlo/whir's Field64_3 = Fp3<F3Config64> with NONRESIDUE = 2.
library GoldilocksExt3 {
    uint256 internal constant P = 0xFFFFFFFF00000001; // 2^64 - 2^32 + 1

    struct Ext3 {
        uint64 c0;
        uint64 c1;
        uint64 c2;
    }

    function zero() internal pure returns (Ext3 memory) {
        return Ext3(0, 0, 0);
    }

    function one() internal pure returns (Ext3 memory) {
        return Ext3(1, 0, 0);
    }

    function fromBase(uint64 x) internal pure returns (Ext3 memory) {
        return Ext3(x, 0, 0);
    }

    function isZero(Ext3 memory a) internal pure returns (bool) {
        return a.c0 == 0 && a.c1 == 0 && a.c2 == 0;
    }

    function eq(Ext3 memory a, Ext3 memory b) internal pure returns (bool) {
        return a.c0 == b.c0 && a.c1 == b.c1 && a.c2 == b.c2;
    }

    function add(Ext3 memory a, Ext3 memory b) internal pure returns (Ext3 memory) {
        return Ext3(
            _addmod(a.c0, b.c0),
            _addmod(a.c1, b.c1),
            _addmod(a.c2, b.c2)
        );
    }

    function sub(Ext3 memory a, Ext3 memory b) internal pure returns (Ext3 memory) {
        return Ext3(
            _submod(a.c0, b.c0),
            _submod(a.c1, b.c1),
            _submod(a.c2, b.c2)
        );
    }

    function neg(Ext3 memory a) internal pure returns (Ext3 memory) {
        return Ext3(
            a.c0 == 0 ? 0 : uint64(P - uint256(a.c0)),
            a.c1 == 0 ? 0 : uint64(P - uint256(a.c1)),
            a.c2 == 0 ? 0 : uint64(P - uint256(a.c2))
        );
    }

    /// @dev Multiply in F_p[x] / (x^3 - 2)
    ///
    ///   (a0 + a1*x + a2*x^2) * (b0 + b1*x + b2*x^2)
    ///   = a0*b0 + (a0*b1 + a1*b0)*x + (a0*b2 + a1*b1 + a2*b0)*x^2
    ///     + (a1*b2 + a2*b1)*x^3 + a2*b2*x^4
    ///
    ///   Using x^3 = 2, x^4 = 2x:
    ///   c0 = a0*b0 + 2*(a1*b2 + a2*b1)
    ///   c1 = a0*b1 + a1*b0 + 2*a2*b2
    ///   c2 = a0*b2 + a1*b1 + a2*b0
    function mul(Ext3 memory a, Ext3 memory b) internal pure returns (Ext3 memory) {
        uint256 a0 = uint256(a.c0);
        uint256 a1 = uint256(a.c1);
        uint256 a2 = uint256(a.c2);
        uint256 b0 = uint256(b.c0);
        uint256 b1 = uint256(b.c1);
        uint256 b2 = uint256(b.c2);

        uint64 c0 = uint64(addmod(
            mulmod(a0, b0, P),
            mulmod(2, addmod(mulmod(a1, b2, P), mulmod(a2, b1, P), P), P),
            P
        ));
        uint64 c1 = uint64(addmod(
            addmod(mulmod(a0, b1, P), mulmod(a1, b0, P), P),
            mulmod(2, mulmod(a2, b2, P), P),
            P
        ));
        uint64 c2 = uint64(addmod(
            addmod(mulmod(a0, b2, P), mulmod(a1, b1, P), P),
            mulmod(a2, b0, P),
            P
        ));

        return Ext3(c0, c1, c2);
    }

    /// @dev Scalar multiplication: ext3 * base field element
    function mulScalar(Ext3 memory a, uint64 s) internal pure returns (Ext3 memory) {
        return Ext3(
            uint64(mulmod(uint256(a.c0), uint256(s), P)),
            uint64(mulmod(uint256(a.c1), uint256(s), P)),
            uint64(mulmod(uint256(a.c2), uint256(s), P))
        );
    }

    /// @dev Double an element
    function double_(Ext3 memory a) internal pure returns (Ext3 memory) {
        return Ext3(
            _addmod(a.c0, a.c0),
            _addmod(a.c1, a.c1),
            _addmod(a.c2, a.c2)
        );
    }

    /// @dev Square an element (optimized vs mul(a, a))
    function square(Ext3 memory a) internal pure returns (Ext3 memory) {
        return mul(a, a); // Can be optimized later
    }

    /// @dev Dot product of two arrays of Ext3 elements
    function dot(Ext3[] memory a, Ext3[] memory b) internal pure returns (Ext3 memory result) {
        result = zero();
        uint256 n = a.length < b.length ? a.length : b.length;
        for (uint256 i = 0; i < n; i++) {
            result = add(result, mul(a[i], b[i]));
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    function _addmod(uint64 a, uint64 b) private pure returns (uint64) {
        return uint64(addmod(uint256(a), uint256(b), P));
    }

    function _submod(uint64 a, uint64 b) private pure returns (uint64) {
        return uint64(addmod(uint256(a), P - uint256(b), P));
    }
}
