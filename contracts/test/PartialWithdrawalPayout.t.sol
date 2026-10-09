// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {WithdrawNativeE2EBase} from "./WithdrawNativeE2EBase.sol";

/// @title Partial-withdrawal payout: only the base withdrawal proof can pay, against a REAL rollup.
///
/// @notice HISTORY (doc/tasks/pw-auth-threat-model.md §7): `claimAuthorizedWithdrawal` paid native ETH
///         out of the global escrow on a manager-issued IPW2 flag alone, without any withdrawal
///         proof. It was removed on 2026-07-28, and on 2026-10-09 the IPW2 latch itself
///         (`authorizePartialWithdrawal` / `partialWithdrawalAuthorized`) and the settlement-manager
///         partial-withdrawal path were removed too: a burn is an ordinary inter-channel send to the
///         BURN channel, paid by `withdrawNative` / `withdrawERC20` on its base withdrawal proof
///         alone. Every test here runs against a REAL `IntmaxRollup` holding REAL escrowed ETH from a
///         REAL fixture deposit, and asks the question that matters: what can anything other than a
///         proof buy? Nothing.
///
/// @dev Inherits the real-fixture harness (real rollup, real withdrawal VK, real finalized state).
///      Self-skips if the heavy fixtures are absent. The proved-burn-leaf counterpart (a real proof
///      for `aux_data != 0`) is `PartialWithdrawalBurnPayout.t.sol`.
contract PartialWithdrawalPayoutTest is WithdrawNativeE2EBase {
    address internal attacker = makeAddr("pwAttacker");

    /// A burn leaf that was NEVER proved: the attacker names an arbitrary amount and recipient.
    /// This is precisely the shape that used to drain the escrow.
    function _forgedBurnLeaf(uint256 amount) internal view returns (IntmaxRollup.Withdrawal memory w) {
        w = IntmaxRollup.Withdrawal({
            recipient: attacker,
            tokenIndex: 0, // ETH
            amount: amount,
            nullifier: keccak256("forged_pw_nullifier"),
            auxData: keccak256("forged_burn_tx_leaf") // non-zero ⇒ burn leaf
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    //  (a) Nothing but a proof pays: no proof-free door, no authorization door
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// THE REGRESSION TEST. A fully-forged burn leaf naming the ENTIRE global escrow, payable to the
    /// attacker. Neither the removed proof-free door nor the removed IPW2 latch exists, and the
    /// remaining ETH path demands a proof the attacker cannot produce.
    function test_forgedBurnLeaf_cannotDrainEscrow() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();

        uint256 escrow = rollup.totalEscrowed();
        assertGt(escrow, 0, "fixture must have escrowed real ETH for this test to mean anything");

        // The attacker claims the WHOLE escrow — none of which they ever burned.
        IntmaxRollup.Withdrawal memory w = _forgedBurnLeaf(escrow);

        // 1. The proof-free door and the IPW2 latch are GONE: the selectors no longer exist, so raw
        //    calls hit the (absent) fallback and revert. Asserted at the ABI level so re-adding any
        //    function with these signatures breaks the test.
        (bool ok, ) = address(rollup).call(
            abi.encodeWithSignature(
                "claimAuthorizedWithdrawal((address,uint32,uint256,bytes32,bytes32))",
                w
            )
        );
        assertFalse(ok, "claimAuthorizedWithdrawal must no longer exist (proof-free payout removed)");
        (ok, ) = address(rollup).call(abi.encodeWithSignature("authorizePartialWithdrawal(bytes32)", bytes32(0)));
        assertFalse(ok, "authorizePartialWithdrawal must no longer exist (IPW2 latch removed)");

        // 2. The remaining ETH path demands a proof it cannot produce. The forged leaf is in no
        //    proven chain, so the pis_hash re-fold rejects it.
        IntmaxRollup.Withdrawal[] memory ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = w;
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        (, address prover) = _parsePayout();
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);

        // 3. Nothing moved.
        assertEq(rollup.totalEscrowed(), escrow, "escrow untouched");
        assertEq(rollup.pendingWithdrawals(attacker), 0, "attacker credited nothing");
        assertEq(attacker.balance, 0, "attacker received nothing");
        assertFalse(rollup.withdrawalNullifierUsed(w.nullifier), "nullifier not even consumed");
    }

    /// The same forged leaf is equally inert against the ERC-20 path.
    function test_forgedBurnLeaf_inertAgainstErc20Path() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();

        IntmaxRollup.Withdrawal memory w = _forgedBurnLeaf(1 ether);
        w.tokenIndex = 5; // some ERC-20 index

        IntmaxRollup.Withdrawal[] memory ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = w;
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        (, address prover) = _parsePayout();
        // Fails on the proof binding, exactly as the ETH path does. (Token 5 is unregistered, but
        // the proof binding is checked before any per-leaf asset dispatch.)
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawERC20(ws, prover, wproof);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    //  (b) The proof side still works, and `auxData` really is proof-bound
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// CONTROL: deleting the proof-free path did not disturb the honest proof-backed payout. The
    /// real fixture leaf (auxData == 0, a normal withdrawal) still pays real ETH.
    function test_provenNonBurnLeaf_stillPays() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        assertEq(ws[0].auxData, bytes32(0), "fixture leaf is a normal (non-burn) withdrawal");

        uint256 escrowBefore = rollup.totalEscrowed();
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        rollup.withdrawNative(ws, prover, wproof);

        assertEq(rollup.pendingWithdrawals(ws[0].recipient), ws[0].amount, "proven leaf paid");
        assertEq(rollup.totalEscrowed(), escrowBefore - ws[0].amount, "escrow debited exactly");
    }

    /// `auxData` is inside the pis_hash re-fold, so a proven normal leaf cannot be relabelled as a
    /// burn: flipping auxData to non-zero breaks the binding and reverts.
    function test_provenLeaf_cannotBeRelabelledAsBurn() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        ws[0].auxData = keccak256("pretend_this_was_a_burn");

        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    //  Nullifier: one proven leaf yields at most one payout (§3)
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// The ETH and ERC-20 paths share ONE `withdrawalNullifierUsed` set, and deleting the proof-free
    /// path only REMOVED a consumer of it. A proven leaf pays once and its nullifier is then burned
    /// for every remaining path.
    function test_provenLeaf_nullifierSingleUseAcrossRemainingPaths() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());

        rollup.withdrawNative(ws, prover, wproof);
        assertTrue(rollup.withdrawalNullifierUsed(ws[0].nullifier), "nullifier consumed");

        // Same leaf, same proof, second time: rejected on the shared nullifier.
        vm.expectRevert(IntmaxRollup.WithdrawalNullifierUsed.selector);
        rollup.withdrawNative(ws, prover, wproof);

        // And the ERC-20 entry point cannot re-pay it either (it is an ETH leaf, and the nullifier
        // is already burned regardless).
        vm.expectRevert(IntmaxRollup.WithdrawalNotErc20Token.selector);
        rollup.withdrawERC20(ws, prover, wproof);
    }
}
