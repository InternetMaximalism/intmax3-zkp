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
    //         production call topology. It can never fire, so the ENTIRE
    //         gas-starvation defence is the 12M floor and nothing else, and a
    //         genuine starvation is reported to the caller as
    //         `MleProofUnevaluable` -- "the deployed evaluator cannot evaluate
    //         this proof" -- which is the opposite diagnosis.
    // ═════════════════════════════════════════════════════════════════════════

    /// EXPLOIT-OF-THE-REASONING (passes = the guard does not do what its comment says). The
    /// round-2 comment reads: "an inner frame that consumed everything it was forwarded leaves the
    /// outer frame at most gasBefore/64. That is the OOG signature". True only if the OOG happens
    /// at call DEPTH 1. `_verifyMleWithVk` ends in `mleVerifier.verify(...)`, an external call to
    /// the immutable satellite, so the OOG is at DEPTH 2 -- and EIP-150's 1/64 retention
    /// ACCUMULATES per frame: frame 1 keeps ~1/64 of its own budget and hands it back when it
    /// bubbles the revert, so frame 0 ends with ~2 * (gasBefore/64).
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

        // The topology the guard was reasoned about: the signature fires.
        assertLe(r1, gb1 / 64, "depth 1: the OOG signature holds (the reasoning's premise)");
        // The topology that actually ships: it does not.
        assertGt(
            r2,
            gb2 / 64,
            "R3: at depth 2 a full OOG leaves MORE than gasBefore/64 -- the signature never fires"
        );
    }

    /// The same result observed end-to-end through `fraudProof` on a production-shaped rollup: a
    /// verifier heavy enough to OOG the forwarded frame, called with transaction gas limits well
    /// ABOVE the 12M floor. Every one of them is a genuine gas starvation, and every one of them is
    /// classified `MleProofUnevaluable`; `FraudProofGasStarved` is returned only by the FLOOR, at
    /// the bottom of the band.
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

        // The defence's SOUNDNESS holds -- an OOG is never a conviction, because both verdicts
        // revert...
        assertFalse(fraud, "B-4 soundness HOLDS: no gas limit converts an OOG into fraud");
        assertEq(r.nextSubmissionId(), 1, "the honest submission survives");
        assertEq(r.pendingWithdrawals(attacker), 0, "no bond stolen");
        // ...but the CLASSIFICATION is wrong for essentially the whole band. These are pure gas
        // starvations reported as "the deployed evaluator cannot evaluate this proof".
        assertGt(
            sawUnevaluable,
            sawStarved,
            "R3: gas starvation is reported as MleProofUnevaluable, not FraudProofGasStarved"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // TEST-INTEGRITY — RT-1's sweep never reaches the regime it claims to clear.
    // ═════════════════════════════════════════════════════════════════════════

    /// RT-1 sweeps `g` over `[honestCost/4, honestCost + 4*step]` with `step = honestCost/200 + 1`,
    /// i.e. a band capped at ~1.02 * honestCost. With the harness's scaled-down verifier
    /// `honestCost` is ~4.89M, so EVERY `g` in the sweep is below MIN_MLE_VERIFY_GAS and every
    /// iteration is refused by the FLOOR before the try/catch is entered. "No gas limit may convict
    /// the honest submission" is therefore proven only for limits under the floor, and the 63/64
    /// branch the test's own doc-comment names is never run.
    function test_R3_TESTGAP_rt1SweepNeverReachesThe6364Branch() public {
        (IntmaxRollup r, bytes memory payload) =
            _honestSubmissionOn(address(new GasHungryMleVerifier(9_000)));

        uint256 gBefore = gasleft();
        (bool okHi, ) = address(r).call(payload);
        uint256 honestCost = gBefore - gasleft();
        assertTrue(okHi, "control call must succeed");

        uint256 step = honestCost / 200 + 1;
        uint256 sweepHi = honestCost + 4 * step;
        emit log_named_uint("RT-1 honestCost", honestCost);
        emit log_named_uint("RT-1 sweep upper bound", sweepHi);
        emit log_named_uint("MIN_MLE_VERIFY_GAS", MIN_MLE_VERIFY_GAS);

        assertLt(
            sweepHi,
            MIN_MLE_VERIFY_GAS,
            "R3: RT-1's ENTIRE sweep is below the floor -- the 63/64 branch is untested"
        );

        // Direct corroboration: at the top of RT-1's sweep the revert is the FLOOR's selector.
        vm.prank(attacker);
        (bool ok, bytes memory ret) = address(r).call{gas: sweepHi}(payload);
        assertFalse(ok, "still refused");
        assertEq(
            bytes4(ret),
            IntmaxRollup.FraudProofGasStarved.selector,
            "R3: refused by the FLOOR, so the sweep proves nothing about the 63/64 signature"
        );
    }
}
