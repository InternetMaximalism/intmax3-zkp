// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {Plonky2GateEvaluator} from "@mle/Plonky2GateEvaluator.sol";
import {ExponentiationGateVectors as V} from "./ExponentiationGateVectors.sol";

/// @dev External wrapper so `vm.expectRevert` can intercept reverts that
///      originate inside the `internal` library function (Foundry's cheatcode
///      operates on the next external call, not on inlined library code).
///      Mirrors `CosetInterpolationHarness` in the mle submodule's own suite.
contract ExponentiationHarness {
    function eval(
        uint256[] memory wires,
        uint256 numPowerBits,
        uint256 filter,
        uint256[] memory acc
    ) external pure returns (uint256[] memory) {
        Plonky2GateEvaluator._evalExponentiation(wires, numPowerBits, filter, acc);
        return acc;
    }

    function combined(
        uint256[] calldata wires,
        uint256[] calldata preprocessed,
        uint256 alpha,
        uint256 extChallenge,
        Plonky2GateEvaluator.GateInfo[] calldata gates,
        uint256 numGateConstraints
    ) external pure returns (uint256) {
        uint256[4] memory pih;
        return Plonky2GateEvaluator.evalCombinedFlat(
            wires,
            preprocessed,
            alpha,
            extChallenge,
            pih,
            gates,
            /*numSelectors=*/ 1,
            /*numConstants=*/ 0,
            numGateConstraints
        );
    }
}

/// @title ExponentiationGateTest
///
/// @notice Bit-exact equivalence test for the Solidity port of plonky2's
///         `ExponentiationGate` (`plonky2/src/gates/exponentiation.rs`).
///
/// @dev    WHY THIS TEST EXISTS (security intent, not mechanics):
///
///         `Plonky2GateEvaluator` is the on-chain re-implementation of the
///         gate constraint polynomial that the Φ_gate sumcheck terminal
///         compares against the prover's claimed evaluation. If the Solidity
///         constraint set differs from the Rust one in ANY term, the L1
///         verifier and plonky2 disagree about what a valid witness is:
///           - a MISSING or WEAKENED term ⇒ soundness break (L1 accepts a
///             witness plonky2 would reject);
///           - an EXTRA or WRONG term ⇒ completeness break (L1 rejects
///             honest proofs).
///         Neither is detectable from "the contract compiles", so every
///         `expected` array below is produced by running plonky2's own
///         `Gate::eval_unfiltered` — never by re-deriving the formula in
///         Solidity or by hand.
///
///         Coverage rationale:
///           V1/V7  happy path, small + boundary (n = 5, n = 1)
///           V4     NON-boolean power bits: proves the port does NOT add a
///                  booleanity constraint that Rust lacks (would be a
///                  completeness break — see the SECURITY note on
///                  `_evalExponentiation`)
///           V5     n = 66, the exact `num_power_bits` of the real
///                  withdrawal-claim fixture
///           V2/V3/V6 malformed prover behaviour: a wrong intermediate value
///                  and a wrong output must yield non-zero constraint values,
///                  at the exact indices Rust reports
///           filter = 0 ⇒ zero contribution (the property the dispatcher
///                  relies on when it skips a de-selected row)
///           filter = f ⇒ contribution scales linearly by f
///           accumulation ⇒ `+=` semantics of `evaluate_gate_constraints`
contract ExponentiationGateTest is Test {
    uint256 internal constant P = 0xFFFFFFFF00000001;

    ExponentiationHarness internal harness;

    function setUp() public {
        harness = new ExponentiationHarness();
    }

    // ── vector plumbing ────────────────────────────────────────────────────

    function _vec(uint256 idx)
        internal
        pure
        returns (uint256 n, uint256[] memory wires, uint256[] memory expected, string memory label)
    {
        if (idx == 0) { (n, wires, expected) = V.v1(); label = "V1 sat n=5 base=2 pow=13"; }
        else if (idx == 1) { (n, wires, expected) = V.v2(); label = "V2 UNSAT wrong intermediate[2]"; }
        else if (idx == 2) { (n, wires, expected) = V.v3(); label = "V3 UNSAT wrong output"; }
        else if (idx == 3) { (n, wires, expected) = V.v4(); label = "V4 sat non-boolean bits"; }
        else if (idx == 4) { (n, wires, expected) = V.v5(); label = "V5 sat n=66 (real fixture param)"; }
        else if (idx == 5) { (n, wires, expected) = V.v6(); label = "V6 UNSAT n=66 wrong intermediate[40]"; }
        else { (n, wires, expected) = V.v7(); label = "V7 sat n=1"; }
    }

    uint256 internal constant NUM_VECTORS = 7;

    // ── 1. bit-exact equivalence with the Rust gate ────────────────────────

    /// Every constraint slot must equal plonky2's `eval_unfiltered` output.
    function test_bitExactMatch_filterOne() public pure {
        for (uint256 v = 0; v < NUM_VECTORS; v++) {
            (uint256 n, uint256[] memory wires, uint256[] memory expected, string memory label) = _vec(v);
            assertEq(expected.length, n + 1, "vector: num_constraints must be n+1");
            assertEq(wires.length, 2 * n + 2, "vector: num_wires must be 2n+2");

            uint256[] memory acc = new uint256[](n + 1);
            Plonky2GateEvaluator._evalExponentiation(wires, n, /*filter=*/ 1, acc);
            for (uint256 k = 0; k <= n; k++) {
                assertEq(acc[k], expected[k], label);
            }
        }
    }

    // ── 2. malformed prover behaviour must be caught ───────────────────────

    /// A satisfying assignment produces an all-zero constraint vector; the
    /// three tampered assignments must NOT. (If any of these ever went to
    /// zero, the on-chain verifier would accept a witness plonky2 rejects.)
    function test_satisfyingIsZero_unsatisfyingIsNonZero() public pure {
        // (vector index, expected number of non-zero slots)
        uint256[7] memory expectedNonZero = [uint256(0), 2, 1, 0, 0, 2, 0];
        for (uint256 v = 0; v < NUM_VECTORS; v++) {
            (uint256 n, uint256[] memory wires,, string memory label) = _vec(v);
            uint256[] memory acc = new uint256[](n + 1);
            Plonky2GateEvaluator._evalExponentiation(wires, n, 1, acc);
            uint256 nz = 0;
            for (uint256 k = 0; k <= n; k++) {
                if (acc[k] != 0) nz++;
            }
            assertEq(nz, expectedNonZero[v], label);
        }
    }

    /// Wrong intermediate value at index i breaks constraint i (its own
    /// definition) AND constraint i+1 (which squares it as `prev`).
    /// Wrong output breaks only the final constraint. Pinning the exact
    /// indices guards against an off-by-one in the LE-bit / BE-accumulation
    /// index flip (`exponentiation.rs:116`).
    function test_unsatisfyingIndices() public pure {
        (uint256 n2, uint256[] memory w2,,) = _vec(1); // wrong intermediate[2]
        uint256[] memory a2 = new uint256[](n2 + 1);
        Plonky2GateEvaluator._evalExponentiation(w2, n2, 1, a2);
        assertTrue(a2[2] != 0, "constraint 2 must break");
        assertTrue(a2[3] != 0, "constraint 3 must break (prev = iv[2]^2)");
        assertEq(a2[0], 0);
        assertEq(a2[1], 0);
        assertEq(a2[4], 0);
        assertEq(a2[5], 0);

        (uint256 n3, uint256[] memory w3,,) = _vec(2); // wrong output
        uint256[] memory a3 = new uint256[](n3 + 1);
        Plonky2GateEvaluator._evalExponentiation(w3, n3, 1, a3);
        for (uint256 k = 0; k < n3; k++) {
            assertEq(a3[k], 0, "only the output constraint may break");
        }
        assertTrue(a3[n3] != 0, "output constraint must break");

        (uint256 n6, uint256[] memory w6,,) = _vec(5); // n=66, wrong intermediate[40]
        uint256[] memory a6 = new uint256[](n6 + 1);
        Plonky2GateEvaluator._evalExponentiation(w6, n6, 1, a6);
        assertTrue(a6[40] != 0, "constraint 40 must break");
        assertTrue(a6[41] != 0, "constraint 41 must break");
    }

    // ── 3. filter semantics ────────────────────────────────────────────────

    /// `filter == 0` (gate not selected on this row) must contribute nothing.
    function test_filterZero_contributesNothing() public pure {
        for (uint256 v = 0; v < NUM_VECTORS; v++) {
            (uint256 n, uint256[] memory wires,, string memory label) = _vec(v);
            uint256[] memory acc = new uint256[](n + 1);
            Plonky2GateEvaluator._evalExponentiation(wires, n, /*filter=*/ 0, acc);
            for (uint256 k = 0; k <= n; k++) {
                assertEq(acc[k], 0, label);
            }
        }
    }

    /// A non-trivial filter scales every constraint linearly.
    function test_filterScalesLinearly() public pure {
        uint256 f = 0x0123456789abcdef % P;
        for (uint256 v = 0; v < NUM_VECTORS; v++) {
            (uint256 n, uint256[] memory wires, uint256[] memory expected, string memory label) = _vec(v);
            uint256[] memory acc = new uint256[](n + 1);
            Plonky2GateEvaluator._evalExponentiation(wires, n, f, acc);
            for (uint256 k = 0; k <= n; k++) {
                assertEq(acc[k], mulmod(f, expected[k], P), label);
            }
        }
    }

    /// The gate must ADD into `acc` (`constraints[i] += c` in
    /// `evaluate_gate_constraints`), never overwrite: two different gate rows
    /// can share a constraint slot.
    function test_accumulatesRatherThanOverwrites() public pure {
        (uint256 n, uint256[] memory wires, uint256[] memory expected,) = _vec(1); // UNSAT vector
        uint256[] memory acc = new uint256[](n + 1);
        for (uint256 k = 0; k <= n; k++) {
            acc[k] = 1000 + k;
        }
        Plonky2GateEvaluator._evalExponentiation(wires, n, 1, acc);
        for (uint256 k = 0; k <= n; k++) {
            assertEq(acc[k], addmod(1000 + k, expected[k], P));
        }
    }

    // ── 4. fail-closed parameter / bounds validation ───────────────────────

    function test_revert_zeroPowerBits() public {
        uint256[] memory wires = new uint256[](8);
        uint256[] memory acc = new uint256[](8);
        vm.expectRevert(bytes("Exponentiation: num_power_bits must be >= 1"));
        harness.eval(wires, 0, 1, acc);
    }

    /// A forged `GateInfo.numOrConsts` larger than the wire array must revert
    /// rather than let raw `mload`s walk past the end of the array (Yul skips
    /// Solidity's bounds checks).
    function test_revert_wiresTooShort() public {
        (uint256 n, uint256[] memory wires,,) = _vec(0);
        uint256[] memory acc = new uint256[](n + 2);
        vm.expectRevert(bytes("Exponentiation: wires too short"));
        harness.eval(wires, n + 1, 1, acc);
    }

    function test_revert_accTooShort() public {
        (uint256 n, uint256[] memory wires,,) = _vec(0);
        uint256[] memory acc = new uint256[](n); // one slot short
        vm.expectRevert(bytes("Exponentiation: constraint slots too few"));
        harness.eval(wires, n, 1, acc);
    }

    // ── 5. non-canonical wire values (C2 defense-in-depth) ─────────────────

    /// A prover-supplied wire of the form `v + P` must evaluate identically to
    /// `v`. Without the `mod(_, p)` self-reduction, `sub(p, w)` would underflow
    /// 2^256 and inject `K = 2^256 mod P` into the constraint value — the
    /// subset-sum attack documented on `_evalConstant`.
    function test_nonCanonicalWiresReduceToSameResult() public pure {
        (uint256 n, uint256[] memory wires, uint256[] memory expected,) = _vec(0);
        uint256[] memory dirty = new uint256[](wires.length);
        for (uint256 i = 0; i < wires.length; i++) {
            dirty[i] = wires[i] + P; // still < 2^256, non-canonical
        }
        uint256[] memory acc = new uint256[](n + 1);
        Plonky2GateEvaluator._evalExponentiation(dirty, n, 1, acc);
        for (uint256 k = 0; k <= n; k++) {
            assertEq(acc[k], expected[k], "non-canonical wires must not change the result");
        }
    }

    // ── 6. dispatcher integration (the actual regression) ──────────────────

    function _expGateInfo(uint256 n)
        internal
        pure
        returns (Plonky2GateEvaluator.GateInfo[] memory gates)
    {
        gates = new Plonky2GateEvaluator.GateInfo[](1);
        gates[0] = Plonky2GateEvaluator.GateInfo({
            gateId: 8, // GATE_EXPONENTIATION
            selectorIndex: 0,
            groupStart: 0,
            groupEnd: 1, // singleton group ⇒ empty product ⇒ filter = 1
            gateRowIndex: 0,
            numConstraints: uint16(n + 1),
            numOrConsts: uint16(n), // num_power_bits
            param2: 0,
            param3: 0
        });
    }

    /// THE REGRESSION: before this port, `evalCombinedFlat` reverted with
    /// "unsupported gate with non-zero filter" for gate id 8, which made every
    /// withdrawal-claim proof unverifiable on L1. It must now evaluate, and a
    /// satisfying witness must flatten to 0.
    function test_dispatcher_satisfyingFlattensToZero() public view {
        (uint256 n, uint256[] memory wires,,) = _vec(4); // n = 66, satisfying
        uint256[] memory preprocessed = new uint256[](1); // one selector column
        uint256 flat = harness.combined(
            wires, preprocessed, /*alpha=*/ 12345, /*extChallenge=*/ 678, _expGateInfo(n), n + 1
        );
        assertEq(flat, 0, "satisfying exponentiation witness must flatten to 0");
    }

    /// ... and an unsatisfying one must not.
    function test_dispatcher_unsatisfyingFlattensNonZero() public view {
        (uint256 n, uint256[] memory wires,,) = _vec(5); // n = 66, tampered
        uint256[] memory preprocessed = new uint256[](1);
        uint256 flat = harness.combined(
            wires, preprocessed, /*alpha=*/ 12345, /*extChallenge=*/ 678, _expGateInfo(n), n + 1
        );
        assertTrue(flat != 0, "tampered exponentiation witness must not flatten to 0");
    }

    /// The fail-closed revert for genuinely unsupported gates is untouched:
    /// only gate id 8 moved out of that branch.
    function test_dispatcher_stillRevertsOnUnsupportedGate() public {
        (uint256 n, uint256[] memory wires,,) = _vec(0);
        uint256[] memory preprocessed = new uint256[](1);
        Plonky2GateEvaluator.GateInfo[] memory gates = _expGateInfo(n);
        gates[0].gateId = 255; // unsupported classifier emitted by fixture.rs
        vm.expectRevert(bytes("unsupported gate with non-zero filter"));
        harness.combined(wires, preprocessed, 12345, 678, gates, n + 1);
    }
}
