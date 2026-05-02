// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GoldilocksField — Goldilocks prime field arithmetic (p = 2^64 - 2^32 + 1)
/// @dev Used for on-chain Plonky2 constraint verification.
///      All operations use uint256 internally for EVM compatibility,
///      but values are always < P after reduction.
library GoldilocksField {
    /// The Goldilocks prime: p = 2^64 - 2^32 + 1
    uint256 internal constant P = 18446744069414584321;

    /// Additive identity
    uint256 internal constant ZERO = 0;

    /// Multiplicative identity
    uint256 internal constant ONE = 1;

    /// The quadratic non-residue used for extension field: W = 7, so F_p^2 = F_p[x]/(x^2 - 7)
    uint256 internal constant W = 7;

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, b, P);
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        // addmod handles underflow
        return addmod(a, P - b, P);
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, P);
    }

    function neg(uint256 a) internal pure returns (uint256) {
        if (a == 0) return 0;
        return P - a;
    }

    /// @dev Modular inverse via Fermat's little theorem: a^(p-2) mod p
    function inv(uint256 a) internal view returns (uint256) {
        require(a != 0, "GL: inv(0)");
        return modExp(a, P - 2);
    }

    /// @dev Modular exponentiation via EVM precompile (address 0x05)
    function modExp(uint256 base, uint256 e) internal view returns (uint256) {
        if (e == 0) return ONE;
        uint256 result;
        uint256 modulus = P;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 32)              // base length
            mstore(add(ptr, 32), 32)     // exponent length
            mstore(add(ptr, 64), 32)     // modulus length
            mstore(add(ptr, 96), base)
            mstore(add(ptr, 128), e)
            mstore(add(ptr, 160), modulus)
            if iszero(staticcall(gas(), 0x05, ptr, 192, ptr, 32)) {
                revert(0, 0)
            }
            result := mload(ptr)
        }
        return result;
    }

    /// @dev exp_power_of_2: base^(2^power_log)
    function expPowerOf2(uint256 base, uint256 powerLog) internal pure returns (uint256) {
        uint256 result = base;
        for (uint256 i = 0; i < powerLog; i++) {
            result = mulmod(result, result, P);
        }
        return result;
    }

    /// @dev Evaluate L_0(x) = (x^n - 1) / (n * (x - 1)) where n = 2^degree_bits
    ///      L_0 is the Lagrange basis polynomial at the first point (ω^0 = 1).
    function evalL0(uint256 x, uint256 degreeBits) internal view returns (uint256) {
        uint256 n = 1 << degreeBits;
        uint256 xn = expPowerOf2(x, degreeBits); // x^n
        uint256 numerator = sub(xn, ONE);          // x^n - 1
        uint256 denominator = mul(n % P, sub(x, ONE)); // n * (x - 1)
        return mul(numerator, inv(denominator));
    }

    /// @dev reduce_with_powers: Horner evaluation
    ///      result = terms[0] + terms[1]*alpha + terms[2]*alpha^2 + ...
    function reduceWithPowers(uint256[] memory terms, uint256 alpha) internal pure returns (uint256) {
        if (terms.length == 0) return ZERO;
        uint256 result = ZERO;
        // Horner's method (right-to-left as in Plonky2)
        for (uint256 i = terms.length; i > 0; i--) {
            result = add(mul(result, alpha), terms[i - 1]);
        }
        return result;
    }
}

/// @title GoldilocksExt2 — Quadratic extension field F_p^2 = F_p[α]/(α^2 - 7)
/// @dev Elements are represented as (c0, c1) meaning c0 + c1·α where α^2 = 7.
library GoldilocksExt2 {
    using GoldilocksField for uint256;

    uint256 internal constant P = GoldilocksField.P;
    uint256 internal constant W = GoldilocksField.W; // 7

    struct Ext2 {
        uint256 c0;
        uint256 c1;
    }

    function zero() internal pure returns (Ext2 memory) {
        return Ext2(0, 0);
    }

    function one() internal pure returns (Ext2 memory) {
        return Ext2(1, 0);
    }

    function fromBase(uint256 x) internal pure returns (Ext2 memory) {
        return Ext2(x, 0);
    }

    function add(Ext2 memory a, Ext2 memory b) internal pure returns (Ext2 memory) {
        return Ext2(a.c0.add(b.c0), a.c1.add(b.c1));
    }

    function sub(Ext2 memory a, Ext2 memory b) internal pure returns (Ext2 memory) {
        return Ext2(a.c0.sub(b.c0), a.c1.sub(b.c1));
    }

    /// @dev (a0 + a1·α)(b0 + b1·α) = (a0·b0 + W·a1·b1) + (a0·b1 + a1·b0)·α
    function mul(Ext2 memory a, Ext2 memory b) internal pure returns (Ext2 memory) {
        uint256 c0 = a.c0.mul(b.c0).add(W.mul(a.c1.mul(b.c1)));
        uint256 c1 = a.c0.mul(b.c1).add(a.c1.mul(b.c0));
        return Ext2(c0, c1);
    }

    /// @dev Scalar multiplication: (c0 + c1·α) * s = (c0·s) + (c1·s)·α
    function mulScalar(Ext2 memory a, uint256 s) internal pure returns (Ext2 memory) {
        return Ext2(a.c0.mul(s), a.c1.mul(s));
    }

    function neg(Ext2 memory a) internal pure returns (Ext2 memory) {
        return Ext2(a.c0.neg(), a.c1.neg());
    }

    /// @dev Inverse: (a0 + a1·α)^(-1) = (a0 - a1·α) / (a0^2 - W·a1^2)
    function inv(Ext2 memory a) internal view returns (Ext2 memory) {
        uint256 norm = a.c0.mul(a.c0).sub(W.mul(a.c1.mul(a.c1)));
        uint256 normInv = norm.inv();
        return Ext2(a.c0.mul(normInv), a.c1.neg().mul(normInv));
    }

    /// @dev exp_power_of_2: a^(2^power_log) — repeated squaring
    function expPowerOf2(Ext2 memory a, uint256 powerLog) internal pure returns (Ext2 memory) {
        Ext2 memory result = Ext2(a.c0, a.c1);
        for (uint256 i = 0; i < powerLog; i++) {
            result = mul(result, result);
        }
        return result;
    }

    function isEqual(Ext2 memory a, Ext2 memory b) internal pure returns (bool) {
        return a.c0 == b.c0 && a.c1 == b.c1;
    }

    /// @dev Evaluate L_0(x) for extension field element x
    function evalL0(Ext2 memory x, uint256 degreeBits) internal view returns (Ext2 memory) {
        uint256 n = 1 << degreeBits;
        Ext2 memory xn = expPowerOf2(x, degreeBits);
        Ext2 memory numerator = sub(xn, one());
        Ext2 memory denominator = mulScalar(sub(x, one()), n % P);
        return mul(numerator, inv(denominator));
    }

    /// @dev reduce_with_powers for extension field
    function reduceWithPowers(Ext2[] memory terms, Ext2 memory alpha) internal pure returns (Ext2 memory) {
        if (terms.length == 0) return zero();
        Ext2 memory result = zero();
        for (uint256 i = terms.length; i > 0; i--) {
            result = add(mul(result, alpha), terms[i - 1]);
        }
        return result;
    }
}
