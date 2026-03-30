// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {GoldilocksExt3} from "./GoldilocksExt3.sol";

/// @title WhirLinearAlgebra
/// @notice Linear algebra utilities for WHIR verification:
///   - MultilinearExtension evaluation (eq polynomial)
///   - UnivariateEvaluation (RS codeword evaluation)
///   - Tensor product
///   - eq_weights computation
///
///   Matches WizardOfMenlo/whir's algebra/linear_form/ implementations.
library WhirLinearAlgebra {
    using GoldilocksExt3 for GoldilocksExt3.Ext3;

    /// @dev Evaluate the multilinear extension of the eq indicator at a point.
    ///
    ///   eq(l, r) = Π_i (l_i * r_i + (1 - l_i) * (1 - r_i))
    ///
    ///   This is the "eq polynomial" used in sumcheck-based WHIR.
    ///   Matches: MultilinearExtension::mle_evaluate()
    function mleEvaluateEq(
        GoldilocksExt3.Ext3[] memory point,
        GoldilocksExt3.Ext3[] memory evalPoint
    ) internal pure returns (GoldilocksExt3.Ext3 memory result) {
        result = GoldilocksExt3.one();
        uint256 n = point.length < evalPoint.length ? point.length : evalPoint.length;
        for (uint256 i = 0; i < n; i++) {
            // acc *= l*r + (1-l)*(1-r)
            GoldilocksExt3.Ext3 memory l = point[i];
            GoldilocksExt3.Ext3 memory r = evalPoint[i];
            GoldilocksExt3.Ext3 memory one_ = GoldilocksExt3.one();
            GoldilocksExt3.Ext3 memory lr = l.mul(r);
            GoldilocksExt3.Ext3 memory oneMinusL = one_.sub(l);
            GoldilocksExt3.Ext3 memory oneMinusR = one_.sub(r);
            GoldilocksExt3.Ext3 memory term = lr.add(oneMinusL.mul(oneMinusR));
            result = result.mul(term);
        }
    }

    /// @dev Evaluate the multilinear extension of (1, x, x^2, ...) at a point.
    ///
    ///   MLE of univariate evaluation at x:
    ///     ⊗_i (1, x^(2^i)) evaluated at point
    ///     = Π_i ((1 - r_i) + r_i * x^(2^i))
    ///
    ///   Matches: UnivariateEvaluation::mle_evaluate()
    function mleEvaluateUnivariate(
        GoldilocksExt3.Ext3 memory x,
        GoldilocksExt3.Ext3[] memory point
    ) internal pure returns (GoldilocksExt3.Ext3 memory result) {
        result = GoldilocksExt3.one();
        GoldilocksExt3.Ext3 memory x2i = x;
        GoldilocksExt3.Ext3 memory one_ = GoldilocksExt3.one();

        // Iterate in reverse (matching Rust's `point.iter().rev()`)
        for (uint256 i = point.length; i > 0; i--) {
            GoldilocksExt3.Ext3 memory r = point[i - 1];
            // result *= (1 - r) + r * x^(2^i)
            GoldilocksExt3.Ext3 memory term = one_.sub(r).add(r.mul(x2i));
            result = result.mul(term);
            x2i = x2i.square();
        }
    }

    /// @dev Compute eq_weights: the tensor product basis for eq polynomial.
    ///
    ///   eq_weights(r) = ⊗_i (1-r_i, r_i)
    ///   Result has 2^n entries.
    ///
    ///   Matches: MultilinearPoint::eq_weights()
    function eqWeights(
        GoldilocksExt3.Ext3[] memory point
    ) internal pure returns (GoldilocksExt3.Ext3[] memory weights) {
        uint256 n = point.length;
        uint256 size = 1 << n;
        weights = new GoldilocksExt3.Ext3[](size);
        weights[0] = GoldilocksExt3.one();

        GoldilocksExt3.Ext3 memory one_ = GoldilocksExt3.one();
        uint256 half = 1;
        for (uint256 i = 0; i < n; i++) {
            GoldilocksExt3.Ext3 memory ri = point[i];
            GoldilocksExt3.Ext3 memory oneMinusRi = one_.sub(ri);
            for (uint256 j = half; j > 0; j--) {
                weights[2 * (j - 1) + 1] = weights[j - 1].mul(ri);
                weights[2 * (j - 1)] = weights[j - 1].mul(oneMinusRi);
            }
            half <<= 1;
        }
    }

    /// @dev Tensor product of two vectors.
    ///
    ///   result[i * b.length + j] = a[i] * b[j]
    ///
    ///   Matches: tensor_product()
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

    /// @dev Dot product of two Ext3 arrays.
    function dotProduct(
        GoldilocksExt3.Ext3[] memory a,
        GoldilocksExt3.Ext3[] memory b
    ) internal pure returns (GoldilocksExt3.Ext3 memory result) {
        result = GoldilocksExt3.zero();
        uint256 n = a.length < b.length ? a.length : b.length;
        for (uint256 i = 0; i < n; i++) {
            result = result.add(a[i].mul(b[i]));
        }
    }

    /// @dev Geometric sequence: [1, x, x^2, ..., x^(n-1)]
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
}
