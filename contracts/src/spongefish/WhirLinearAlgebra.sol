// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {GoldilocksExt3} from "./GoldilocksExt3.sol";

/// @title WhirLinearAlgebra
/// @notice Linear algebra utilities for WHIR verification.
///         All hot-path functions use inline assembly to avoid Ext3 memory allocation.
library WhirLinearAlgebra {
    using GoldilocksExt3 for GoldilocksExt3.Ext3;

    uint256 private constant P = 0xFFFFFFFF00000001;

    // =====================================================================
    // Inline assembly helpers for Ext3 arithmetic on stack
    // =====================================================================
    // All Ext3 values are kept as 3 stack variables (c0, c1, c2).
    // Ext3 mul: c0 = a0*b0 + 2*(a1*b2 + a2*b1)
    //           c1 = a0*b1 + a1*b0 + 2*a2*b2
    //           c2 = a0*b2 + a1*b1 + a2*b0

    /// @dev mleEvaluateUnivariateFrom — full assembly, zero intermediate Ext3 allocs.
    ///      Computes Π_i ((1 - r_i) + r_i * x^(2^i)) for i in [start..point.length), iterated in reverse.
    function mleEvaluateUnivariateFrom(
        GoldilocksExt3.Ext3 memory x,
        GoldilocksExt3.Ext3[] memory point,
        uint256 start
    ) internal pure returns (GoldilocksExt3.Ext3 memory result) {
        assembly {
            let p := P

            // result = 1
            let res0 := 1
            let res1 := 0
            let res2 := 0

            // x2i = x (will be squared each iteration)
            let x0 := mload(x)
            let x1 := mload(add(x, 0x20))
            let x2 := mload(add(x, 0x40))

            let pData := add(point, 0x20)
            let len := mload(point)

            for { let i := len } gt(i, start) { i := sub(i, 1) } {
                let rPtr := mload(add(pData, mul(sub(i, 1), 0x20)))
                let r0 := mload(rPtr)
                let r1 := mload(add(rPtr, 0x20))
                let r2 := mload(add(rPtr, 0x40))

                // term = (1 - r) + r * x2i
                // oneMinusR = (1-r0, -r1, -r2) mod p
                let omr0 := addmod(1, sub(p, r0), p)
                let omr1 := sub(p, r1)
                let omr2 := sub(p, r2)

                // r * x2i (Ext3 mul)
                let t1 := addmod(mulmod(r1, x2, p), mulmod(r2, x1, p), p)
                let rx0 := addmod(mulmod(r0, x0, p), mulmod(2, t1, p), p)
                let rx1 := addmod(addmod(mulmod(r0, x1, p), mulmod(r1, x0, p), p), mulmod(2, mulmod(r2, x2, p), p), p)
                let rx2 := addmod(addmod(mulmod(r0, x2, p), mulmod(r1, x1, p), p), mulmod(r2, x0, p), p)

                // term = oneMinusR + rx
                let term0 := addmod(omr0, rx0, p)
                let term1 := addmod(omr1, rx1, p)
                let term2 := addmod(omr2, rx2, p)

                // result *= term (Ext3 mul)
                let mt1 := addmod(mulmod(res1, term2, p), mulmod(res2, term1, p), p)
                let nr0 := addmod(mulmod(res0, term0, p), mulmod(2, mt1, p), p)
                let nr1 := addmod(addmod(mulmod(res0, term1, p), mulmod(res1, term0, p), p), mulmod(2, mulmod(res2, term2, p), p), p)
                let nr2 := addmod(addmod(mulmod(res0, term2, p), mulmod(res1, term1, p), p), mulmod(res2, term0, p), p)
                res0 := nr0
                res1 := nr1
                res2 := nr2

                // x2i = x2i^2 (Ext3 square = mul(x2i, x2i))
                let st1 := addmod(mulmod(x1, x2, p), mulmod(x2, x1, p), p)
                let sx0 := addmod(mulmod(x0, x0, p), mulmod(2, st1, p), p)
                let sx1 := addmod(addmod(mulmod(x0, x1, p), mulmod(x1, x0, p), p), mulmod(2, mulmod(x2, x2, p), p), p)
                let sx2 := addmod(addmod(mulmod(x0, x2, p), mulmod(x1, x1, p), p), mulmod(x2, x0, p), p)
                x0 := sx0
                x1 := sx1
                x2 := sx2
            }

            mstore(result, res0)
            mstore(add(result, 0x20), res1)
            mstore(add(result, 0x40), res2)
        }
    }

    /// @dev mleEvaluateUnivariate — same as above but start=0.
    function mleEvaluateUnivariate(
        GoldilocksExt3.Ext3 memory x,
        GoldilocksExt3.Ext3[] memory point
    ) internal pure returns (GoldilocksExt3.Ext3 memory result) {
        return mleEvaluateUnivariateFrom(x, point, 0);
    }

    /// @dev Evaluate eq((1, 2, ..., numVariables), evalPoint) — full assembly.
    ///      eq(l, r) = Π_i (l_i * r_i + (1 - l_i) * (1 - r_i))
    ///      where l_i = i+1 (base field constant).
    function mleEvaluateEqCanonical(
        uint256 numVariables,
        GoldilocksExt3.Ext3[] memory evalPoint
    ) internal pure returns (GoldilocksExt3.Ext3 memory result) {
        assembly {
            let p := P
            let res0 := 1
            let res1 := 0
            let res2 := 0

            let epLen := mload(evalPoint)
            let n := numVariables
            if lt(epLen, n) { n := epLen }
            let epData := add(evalPoint, 0x20)

            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let li := add(i, 1) // base field: l = i+1, so l0=li, l1=0, l2=0

                let rPtr := mload(add(epData, mul(i, 0x20)))
                let r0 := mload(rPtr)
                let r1 := mload(add(rPtr, 0x20))
                let r2 := mload(add(rPtr, 0x40))

                // lr = l * r = (li*r0, li*r1, li*r2) (scalar mul)
                let lr0 := mulmod(li, r0, p)
                let lr1 := mulmod(li, r1, p)
                let lr2 := mulmod(li, r2, p)

                // oneMinusL = (1 - li, 0, 0) = (p+1-li, 0, 0) mod p
                let oml := addmod(1, sub(p, li), p)

                // oneMinusR = (1-r0, -r1, -r2)
                let omr0 := addmod(1, sub(p, r0), p)
                let omr1 := sub(p, r1)
                let omr2 := sub(p, r2)

                // (1-l)*(1-r): scalar oml * (omr0, omr1, omr2)
                let pr0 := mulmod(oml, omr0, p)
                let pr1 := mulmod(oml, omr1, p)
                let pr2 := mulmod(oml, omr2, p)

                // term = lr + (1-l)*(1-r)
                let t0 := addmod(lr0, pr0, p)
                let t1 := addmod(lr1, pr1, p)
                let t2 := addmod(lr2, pr2, p)

                // result *= term
                let mt := addmod(mulmod(res1, t2, p), mulmod(res2, t1, p), p)
                let nr0 := addmod(mulmod(res0, t0, p), mulmod(2, mt, p), p)
                let nr1 := addmod(addmod(mulmod(res0, t1, p), mulmod(res1, t0, p), p), mulmod(2, mulmod(res2, t2, p), p), p)
                let nr2 := addmod(addmod(mulmod(res0, t2, p), mulmod(res1, t1, p), p), mulmod(res2, t0, p), p)
                res0 := nr0
                res1 := nr1
                res2 := nr2
            }

            mstore(result, res0)
            mstore(add(result, 0x20), res1)
            mstore(add(result, 0x40), res2)
        }
    }

    /// @dev mleEvaluateEq — full assembly version.
    function mleEvaluateEq(
        GoldilocksExt3.Ext3[] memory point,
        GoldilocksExt3.Ext3[] memory evalPoint
    ) internal pure returns (GoldilocksExt3.Ext3 memory result) {
        assembly {
            let p := P
            let res0 := 1
            let res1 := 0
            let res2 := 0

            let pLen := mload(point)
            let epLen := mload(evalPoint)
            let n := pLen
            if lt(epLen, n) { n := epLen }

            let pData := add(point, 0x20)
            let epData := add(evalPoint, 0x20)

            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let lPtr := mload(add(pData, mul(i, 0x20)))
                let l0 := mload(lPtr)
                let l1 := mload(add(lPtr, 0x20))
                let l2 := mload(add(lPtr, 0x40))

                let rPtr := mload(add(epData, mul(i, 0x20)))
                let r0 := mload(rPtr)
                let r1 := mload(add(rPtr, 0x20))
                let r2 := mload(add(rPtr, 0x40))

                // lr = l * r (Ext3 mul)
                let lrt := addmod(mulmod(l1, r2, p), mulmod(l2, r1, p), p)
                let lr0 := addmod(mulmod(l0, r0, p), mulmod(2, lrt, p), p)
                let lr1 := addmod(addmod(mulmod(l0, r1, p), mulmod(l1, r0, p), p), mulmod(2, mulmod(l2, r2, p), p), p)
                let lr2 := addmod(addmod(mulmod(l0, r2, p), mulmod(l1, r1, p), p), mulmod(l2, r0, p), p)

                // oneMinusL
                let oml0 := addmod(1, sub(p, l0), p)
                let oml1 := sub(p, l1)
                let oml2 := sub(p, l2)
                // oneMinusR
                let omr0 := addmod(1, sub(p, r0), p)
                let omr1 := sub(p, r1)
                let omr2 := sub(p, r2)

                // (1-l)*(1-r) (Ext3 mul)
                let pt := addmod(mulmod(oml1, omr2, p), mulmod(oml2, omr1, p), p)
                let pr0 := addmod(mulmod(oml0, omr0, p), mulmod(2, pt, p), p)
                let pr1 := addmod(addmod(mulmod(oml0, omr1, p), mulmod(oml1, omr0, p), p), mulmod(2, mulmod(oml2, omr2, p), p), p)
                let pr2 := addmod(addmod(mulmod(oml0, omr2, p), mulmod(oml1, omr1, p), p), mulmod(oml2, omr0, p), p)

                // term = lr + (1-l)*(1-r)
                let t0 := addmod(lr0, pr0, p)
                let t1 := addmod(lr1, pr1, p)
                let t2 := addmod(lr2, pr2, p)

                // result *= term
                let mt := addmod(mulmod(res1, t2, p), mulmod(res2, t1, p), p)
                let nr0 := addmod(mulmod(res0, t0, p), mulmod(2, mt, p), p)
                let nr1 := addmod(addmod(mulmod(res0, t1, p), mulmod(res1, t0, p), p), mulmod(2, mulmod(res2, t2, p), p), p)
                let nr2 := addmod(addmod(mulmod(res0, t2, p), mulmod(res1, t1, p), p), mulmod(res2, t0, p), p)
                res0 := nr0
                res1 := nr1
                res2 := nr2
            }

            mstore(result, res0)
            mstore(add(result, 0x20), res1)
            mstore(add(result, 0x40), res2)
        }
    }

    /// @dev Compute eq_weights from a slice of a larger array — full assembly.
    ///      Result array elements are Ext3 structs written directly.
    function eqWeightsFrom(
        GoldilocksExt3.Ext3[] memory arr,
        uint256 start,
        uint256 count
    ) internal pure returns (GoldilocksExt3.Ext3[] memory weights) {
        uint256 size = 1 << count;
        weights = new GoldilocksExt3.Ext3[](size);
        // Allocate all Ext3 structs upfront
        for (uint256 i = 0; i < size; i++) {
            weights[i] = GoldilocksExt3.zero();
        }
        // Set weights[0] = 1
        weights[0].c0 = 1;

        assembly {
            let p := P
            let wData := add(weights, 0x20)
            let aData := add(arr, 0x20)

            let half := 1
            for { let idx := 0 } lt(idx, count) { idx := add(idx, 1) } {
                let riPtr := mload(add(aData, mul(add(start, idx), 0x20)))
                let ri0 := mload(riPtr)
                let ri1 := mload(add(riPtr, 0x20))
                let ri2 := mload(add(riPtr, 0x40))
                // oneMinusRi
                let omr0 := addmod(1, sub(p, ri0), p)
                let omr1 := sub(p, ri1)
                let omr2 := sub(p, ri2)

                // Process in reverse to avoid overwriting
                for { let j := half } gt(j, 0) { j := sub(j, 1) } {
                    let srcPtr := mload(add(wData, mul(sub(j, 1), 0x20)))
                    let s0 := mload(srcPtr)
                    let s1 := mload(add(srcPtr, 0x20))
                    let s2 := mload(add(srcPtr, 0x40))

                    // weights[2*(j-1)+1] = src * ri (Ext3 mul)
                    let hiPtr := mload(add(wData, mul(add(mul(sub(j, 1), 2), 1), 0x20)))
                    let mt1 := addmod(mulmod(s1, ri2, p), mulmod(s2, ri1, p), p)
                    mstore(hiPtr, addmod(mulmod(s0, ri0, p), mulmod(2, mt1, p), p))
                    mstore(add(hiPtr, 0x20), addmod(addmod(mulmod(s0, ri1, p), mulmod(s1, ri0, p), p), mulmod(2, mulmod(s2, ri2, p), p), p))
                    mstore(add(hiPtr, 0x40), addmod(addmod(mulmod(s0, ri2, p), mulmod(s1, ri1, p), p), mulmod(s2, ri0, p), p))

                    // weights[2*(j-1)] = src * oneMinusRi (Ext3 mul)
                    let loPtr := mload(add(wData, mul(mul(sub(j, 1), 2), 0x20)))
                    let mt2 := addmod(mulmod(s1, omr2, p), mulmod(s2, omr1, p), p)
                    mstore(loPtr, addmod(mulmod(s0, omr0, p), mulmod(2, mt2, p), p))
                    mstore(add(loPtr, 0x20), addmod(addmod(mulmod(s0, omr1, p), mulmod(s1, omr0, p), p), mulmod(2, mulmod(s2, omr2, p), p), p))
                    mstore(add(loPtr, 0x40), addmod(addmod(mulmod(s0, omr2, p), mulmod(s1, omr1, p), p), mulmod(s2, omr0, p), p))
                }
                half := shl(1, half)
            }
        }
    }

    /// @dev Compute eq_weights: same as eqWeightsFrom with start=0.
    function eqWeights(
        GoldilocksExt3.Ext3[] memory point
    ) internal pure returns (GoldilocksExt3.Ext3[] memory weights) {
        // Reimplement directly to avoid extra indirection
        uint256 n = point.length;
        uint256 size = 1 << n;
        weights = new GoldilocksExt3.Ext3[](size);
        for (uint256 i = 0; i < size; i++) {
            weights[i] = GoldilocksExt3.zero();
        }
        weights[0].c0 = 1;

        assembly {
            let p := P
            let wData := add(weights, 0x20)
            let pData := add(point, 0x20)

            let half := 1
            for { let idx := 0 } lt(idx, n) { idx := add(idx, 1) } {
                let riPtr := mload(add(pData, mul(idx, 0x20)))
                let ri0 := mload(riPtr)
                let ri1 := mload(add(riPtr, 0x20))
                let ri2 := mload(add(riPtr, 0x40))
                let omr0 := addmod(1, sub(p, ri0), p)
                let omr1 := sub(p, ri1)
                let omr2 := sub(p, ri2)

                for { let j := half } gt(j, 0) { j := sub(j, 1) } {
                    let srcPtr := mload(add(wData, mul(sub(j, 1), 0x20)))
                    let s0 := mload(srcPtr)
                    let s1 := mload(add(srcPtr, 0x20))
                    let s2 := mload(add(srcPtr, 0x40))

                    let hiPtr := mload(add(wData, mul(add(mul(sub(j, 1), 2), 1), 0x20)))
                    let mt1 := addmod(mulmod(s1, ri2, p), mulmod(s2, ri1, p), p)
                    mstore(hiPtr, addmod(mulmod(s0, ri0, p), mulmod(2, mt1, p), p))
                    mstore(add(hiPtr, 0x20), addmod(addmod(mulmod(s0, ri1, p), mulmod(s1, ri0, p), p), mulmod(2, mulmod(s2, ri2, p), p), p))
                    mstore(add(hiPtr, 0x40), addmod(addmod(mulmod(s0, ri2, p), mulmod(s1, ri1, p), p), mulmod(s2, ri0, p), p))

                    let loPtr := mload(add(wData, mul(mul(sub(j, 1), 2), 0x20)))
                    let mt2 := addmod(mulmod(s1, omr2, p), mulmod(s2, omr1, p), p)
                    mstore(loPtr, addmod(mulmod(s0, omr0, p), mulmod(2, mt2, p), p))
                    mstore(add(loPtr, 0x20), addmod(addmod(mulmod(s0, omr1, p), mulmod(s1, omr0, p), p), mulmod(2, mulmod(s2, omr2, p), p), p))
                    mstore(add(loPtr, 0x40), addmod(addmod(mulmod(s0, omr2, p), mulmod(s1, omr1, p), p), mulmod(s2, omr0, p), p))
                }
                half := shl(1, half)
            }
        }
    }

    /// @dev Dot product of two Ext3 arrays — full assembly.
    function dotProduct(
        GoldilocksExt3.Ext3[] memory a,
        GoldilocksExt3.Ext3[] memory b
    ) internal pure returns (GoldilocksExt3.Ext3 memory result) {
        assembly {
            let p := P
            let aLen := mload(a)
            let bLen := mload(b)
            let n := aLen
            if lt(bLen, aLen) { n := bLen }

            let r0 := 0
            let r1 := 0
            let r2 := 0
            let aPtr := add(a, 0x20)
            let bPtr := add(b, 0x20)

            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let ae := mload(add(aPtr, mul(i, 0x20)))
                let be := mload(add(bPtr, mul(i, 0x20)))
                let a0 := mload(ae)
                let a1 := mload(add(ae, 0x20))
                let a2 := mload(add(ae, 0x40))
                let b0 := mload(be)
                let b1 := mload(add(be, 0x20))
                let b2 := mload(add(be, 0x40))

                let t := addmod(mulmod(a1, b2, p), mulmod(a2, b1, p), p)
                r0 := addmod(r0, addmod(mulmod(a0, b0, p), mulmod(2, t, p), p), p)
                r1 := addmod(r1, addmod(addmod(mulmod(a0, b1, p), mulmod(a1, b0, p), p), mulmod(2, mulmod(a2, b2, p), p), p), p)
                r2 := addmod(r2, addmod(addmod(mulmod(a0, b2, p), mulmod(a1, b1, p), p), mulmod(a2, b0, p), p), p)
            }

            mstore(result, r0)
            mstore(add(result, 0x20), r1)
            mstore(add(result, 0x40), r2)
        }
    }

    /// @dev Geometric sequence: [1, x, x^2, ..., x^(n-1)] — writes to pre-allocated array.
    function geometricSequence(
        GoldilocksExt3.Ext3 memory x,
        uint256 n
    ) internal pure returns (GoldilocksExt3.Ext3[] memory result) {
        result = new GoldilocksExt3.Ext3[](n);
        if (n == 0) return result;
        result[0] = GoldilocksExt3.one();
        for (uint256 i = 1; i < n; i++) {
            result[i] = result[i - 1].mul(x);
        }
    }

    /// @dev Tensor product of two vectors.
    function tensorProduct(
        GoldilocksExt3.Ext3[] memory a,
        GoldilocksExt3.Ext3[] memory b
    ) internal pure returns (GoldilocksExt3.Ext3[] memory result) {
        uint256 aLen = a.length;
        uint256 bLen = b.length;
        result = new GoldilocksExt3.Ext3[](aLen * bLen);
        for (uint256 i = 0; i < aLen; i++) {
            for (uint256 j = 0; j < bLen; j++) {
                result[i * bLen + j] = a[i].mul(b[j]);
            }
        }
    }
}
