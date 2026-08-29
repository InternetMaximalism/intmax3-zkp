// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {RedTeamFraudBreaksTest, GasHungryMleVerifier} from "./RedTeamFraudBreaks.t.sol";

// ── a minimal reproduction of the PRODUCTION call topology inside `_mleVerdict` ──────────────
//   IntmaxRollup._mleVerdict            (frame 0, holds `gasBefore` and the signature check)
//     -> this._verifyMleWithVk(...)     (frame 1, external call to SELF)
//          -> mleVerifier.verify(...)   (frame 2, the immutable SATELLITE contract)
// The satellite hop is not a test artifact: `mleVerifier` is `MleVerifier public immutable`
// (IntmaxRollup.sol:333) and `_verifyMleWithVk` ends in `mleVerifier.verify(...)` (:2053).

contract Burner {
    function burn() external pure {
        uint256 acc = 1;
        for (uint256 i = 0; i < type(uint256).max; i++) {
            acc = uint256(keccak256(abi.encode(acc, i)));
        }
        require(acc != 0, "unreachable");
    }
}

contract Middle {
    Burner public immutable inner;
    constructor(Burner b) { inner = b; }
    /// Mirrors `_verifyMleWithVk`: a plain high-level call to the satellite, no try/catch.
    function hop() external view {
        inner.burn();
    }
}

contract Outer {
    Middle public immutable mid;
    constructor(Middle m) { mid = m; }

    /// Mirrors `_mleVerdict`'s catch arm and reports the two numbers the guard compares.
    /// `depth2 == false` skips the satellite hop (the topology the guard was reasoned about);
    /// `depth2 == true` is the real one.
    function probe(bool depth2) external view returns (uint256 gasBefore, uint256 retained) {
        Burner b = mid.inner();
        gasBefore = gasleft();
        if (depth2) {
            try mid.hop() { } catch { retained = gasleft(); }
        } else {
            try b.burn() { } catch { retained = gasleft(); }
        }
    }
}

/// @title RedTeamRound3Fraud
/// @notice ROUND-3 probes against the ROUND-2 B-4 guard (`MIN_MLE_VERIFY_GAS` + the
///         `gasleft() <= gasBefore/64` OOG signature). Reuses `RedTeamFraudBreaksTest`'s harness
///         by inheritance (its own tests re-run under this contract name; that is the price of not
///         duplicating a 200-line rollup fixture).
contract RedTeamRound3FraudTest is RedTeamFraudBreaksTest {
    /// The floor, mirrored (it is `private constant` in IntmaxRollup).
    uint256 internal constant MIN_MLE_VERIFY_GAS = 12_000_000;

    // ═════════════════════════════════════════════════════════════════════════
    // BREAK — B-4 part 2 (`gasleft() <= gasBefore/64`) is DEAD CODE under the
    //         production call topology.  *** FIXED (R3-4) ***
    //
    //   THE FINDING. The round-2 signature can never fire at the depth that
    //   actually ships, so the ENTIRE gas-starvation defence was the 12M floor
    //   and nothing else, and a genuine starvation was reported to the caller as
    //   `MleProofUnevaluable` -- "the deployed evaluator cannot evaluate this
    //   proof" -- which is the opposite diagnosis. SOUNDNESS was never affected:
    //   both verdicts revert, and `MLE_INVALID` (the only fraud evidence) is
    //   reachable only from the try arm RETURNING false.
    //
    //   THE FIX (round 3, R3-4). `_mleVerdict` forwards an EXPLICIT budget
    //   (`gasBefore - gasBefore/64`, i.e. exactly what EIP-150 would have kept,
    //   so the success path is unchanged) and classifies on how much of THAT
    //   BUDGET came back rather than on a depth-1 fraction of `gasBefore`. A
    //   starved subtree returns `budget * (1 - (63/64)^n)` -- 1.6% at depth 1,
    //   3.1% at depth 2 (production), 12% at depth 8 -- while a deterministic
    //   revert unwinds early and returns nearly all of it. The `budget / 8`
    //   threshold sits between the two and is depth-independent up to n = 8.
    // ═════════════════════════════════════════════════════════════════════════

    /// THE EIP-150 FACT the round-2 rule got wrong, kept as the standing justification for the R3-4
    /// threshold rather than as an attack (it is a property of the EVM, not of this repo, so it
    /// passes before and after the fix). `_verifyMleWithVk` ends in `mleVerifier.verify(...)`, an
    /// external call to the immutable satellite, so a real OOG is at DEPTH 2 -- and EIP-150's 1/64
    /// retention ACCUMULATES per frame: frame 1 keeps ~1/64 of its own budget and hands it back when
    /// it bubbles the revert, so frame 0 ends with ~2 * (gasBefore/64). Any threshold expressed as a
    /// fixed fraction of `gasBefore` at an assumed depth is therefore fragile; the shipped one is
    /// expressed against the forwarded budget instead.
    function test_R3_BREAK_B4_the6364SignatureCannotFireAtDepthTwo() public {
        Outer o = new Outer(new Middle(new Burner()));

        (uint256 gb1, uint256 r1) = o.probe{gas: 20_000_000}(false); // depth 1
        (uint256 gb2, uint256 r2) = o.probe{gas: 20_000_000}(true);  // depth 2 = production
        emit log_named_uint("depth-1 gasBefore", gb1);
        emit log_named_uint("depth-1 retained ", r1);
        emit log_named_uint("depth-1 gasBefore/64", gb1 / 64);
        emit log_named_uint("depth-2 gasBefore", gb2);
        emit log_named_uint("depth-2 retained ", r2);
        emit log_named_uint("depth-2 gasBefore/64", gb2 / 64);

        // The topology the round-2 guard was reasoned about: the old signature fires.
        assertLe(r1, gb1 / 64, "depth 1: the OOG signature holds (the round-2 reasoning's premise)");
        // The topology that actually ships: it does not. This is why the rule was rewritten.
        assertGt(
            r2,
            gb2 / 64,
            "R3: at depth 2 a full OOG leaves MORE than gasBefore/64 -- the old signature never fired"
        );
        // R3-4's rule, applied to the same measurement: the budget-relative threshold classifies
        // BOTH depths as starved, which is what makes it depth-independent.
        uint256 budget1 = gb1 - gb1 / 64;
        uint256 budget2 = gb2 - gb2 / 64;
        assertLe(r1, gb1 / 64 + budget1 / 8, "R3-4: depth 1 is classified STARVED");
        assertLe(r2, gb2 / 64 + budget2 / 8, "R3-4: depth 2 is classified STARVED");
    }

    /// BLOCKED (passes = the misclassification is gone). Body preserved VERBATIM through the sweep;
    /// only the verdict changed. A verifier heavy enough to OOG the forwarded frame, called with
    /// transaction gas limits well ABOVE the 12M floor: every one of them is a genuine gas
    /// starvation, and every one of them is now classified `FraudProofGasStarved`.
    function test_R3_BREAK_B4_starvationIsReportedAsUnevaluable() public {
        // Sized so the verifier's own cost lands above the 63/64 share of a ~19M frame.
        (IntmaxRollup r, bytes memory payload) =
            _honestSubmissionOn(address(new GasHungryMleVerifier(26_000)));

        // Control: with plenty of gas the verifier finishes and returns TRUE -> not fraud.
        uint256 gc = gasleft();
        (bool okHi, bytes memory retHi) = address(r).call{gas: 60_000_000}(payload);
        emit log_named_uint("honest (non-convicting) cost, heavy verifier", gc - gasleft());
        assertTrue(okHi, "control: a well-funded call completes");
        assertFalse(abi.decode(retHi, (bool)), "control: honest submission is not convictable");

        bool fraud;
        uint256 sawStarved;
        uint256 sawUnevaluable;
        for (uint256 g = 12_500_000; g <= 21_000_000; g += 500_000) {
            vm.prank(attacker);
            (bool ok, bytes memory ret) = address(r).call{gas: g}(payload);
            if (ok && ret.length == 32 && abi.decode(ret, (bool))) {
                fraud = true;
                emit log_named_uint("winning tx gas limit", g);
                break;
            }
            if (!ok && ret.length >= 4) {
                if (bytes4(ret) == IntmaxRollup.FraudProofGasStarved.selector) sawStarved++;
                if (bytes4(ret) == IntmaxRollup.MleProofUnevaluable.selector) sawUnevaluable++;
            }
        }
        emit log_named_uint("FraudProofGasStarved verdicts in band", sawStarved);
        emit log_named_uint("MleProofUnevaluable  verdicts in band", sawUnevaluable);

        // The defence's SOUNDNESS was never in question and is unchanged -- an OOG is never a
        // conviction, because both verdicts revert...
        assertFalse(fraud, "B-4 soundness HOLDS: no gas limit converts an OOG into fraud");
        assertEq(r.nextSubmissionId(), 1, "the honest submission survives");
        assertEq(r.pendingWithdrawals(attacker), 0, "no bond stolen");
        // ...and the CLASSIFICATION is now right for the whole band. Round 2 reported 16 of these 17
        // genuine starvations as "the deployed evaluator cannot evaluate this proof".
        assertGt(sawStarved, 0, "R3-4: genuine starvations are seen");
        assertEq(
            sawUnevaluable,
            0,
            "R3-4 BLOCKED: not one gas starvation is misreported as MleProofUnevaluable"
        );
        assertGt(
            sawStarved,
            sawUnevaluable,
            "R3-4 BLOCKED: the diagnosis the honest under-gassed prover receives is 'send more gas'"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // TEST-INTEGRITY — RT-1's sweep never reached the regime it claimed to
    //                  clear.  *** FIXED (R3-4) ***
    // ═════════════════════════════════════════════════════════════════════════

    /// RT-1 swept `g` over `[honestCost/4, honestCost + 4*step]` with `step = honestCost/200 + 1`,
    /// i.e. a band capped at ~1.02 * honestCost. With the harness's scaled-down verifier
    /// `honestCost` is ~4.89M, so EVERY `g` in the sweep was below MIN_MLE_VERIFY_GAS and every
    /// iteration was refused by the FLOOR before the try/catch was entered. "No gas limit may
    /// convict the honest submission" was therefore proven only for limits under the floor, and the
    /// 63/64 branch the test's own doc-comment names was never run.
    ///
    /// This test still MEASURES that gap -- the arithmetic of the original band is a fact -- and now
    /// also pins the repair: RT-1 carries a SECOND band, above the floor, where the call really does
    /// enter the try/catch. Deleting that band makes the last assertion here fail.
    function test_R3_TESTGAP_rt1SweepNeverReachesThe6364Branch() public {
        (IntmaxRollup r, bytes memory payload) =
            _honestSubmissionOn(address(new GasHungryMleVerifier(9_000)));

        uint256 gBefore = gasleft();
        (bool okHi, ) = address(r).call(payload);
        uint256 honestCost = gBefore - gasleft();
        assertTrue(okHi, "control call must succeed");

        uint256 step = honestCost / 200 + 1;
        uint256 sweepHi = honestCost + 4 * step;
        emit log_named_uint("RT-1 band A honestCost", honestCost);
        emit log_named_uint("RT-1 band A upper bound", sweepHi);
        emit log_named_uint("MIN_MLE_VERIFY_GAS", MIN_MLE_VERIFY_GAS);

        assertLt(
            sweepHi,
            MIN_MLE_VERIFY_GAS,
            "R3: RT-1's ORIGINAL band is entirely below the floor -- on its own it tests nothing "
            "about the 63/64 signature"
        );

        // Direct corroboration: at the top of the original band the revert is the FLOOR's selector.
        vm.prank(attacker);
        (bool ok, bytes memory ret) = address(r).call{gas: sweepHi}(payload);
        assertFalse(ok, "still refused");
        assertEq(
            bytes4(ret),
            IntmaxRollup.FraudProofGasStarved.selector,
            "R3: refused by the FLOOR, so band A alone proves nothing about the classification"
        );

        // FIXED: above the floor the call reaches the try/catch, and the R3-4 classification runs.
        // RT-1's band B covers exactly this regime; here it is exhibited directly.
        vm.prank(attacker);
        (bool ok2, bytes memory ret2) = address(r).call{gas: MIN_MLE_VERIFY_GAS + 4_000_000}(payload);
        assertTrue(
            ok2,
            "R3-4: above the floor the call is NOT refused by the floor -- it reaches the try/catch"
        );
        assertFalse(
            abi.decode(ret2, (bool)),
            "and the verifier's own verdict is returned: not fraud. Band A never got this far."
        );
    }
}
