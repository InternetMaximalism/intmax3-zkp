// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {WithdrawNativeE2EBase} from "./WithdrawNativeE2EBase.sol";

/// @title Full real on-chain native-ETH withdrawal payout (Phase 2).
/// @notice The honest lifecycle through `withdrawNative` -> `withdraw(amount)` pays real ETH, plus the
///         negative cases. The payout is bound to the finalized state by a REAL MLE/WHIR proof
///         (separate withdrawal VK) + the on-chain keccak re-fold of the withdrawal set.
///         Harness (setUp, lifecycle driver, fixture parsing) lives in `WithdrawNativeE2EBase`.
contract WithdrawNativeE2ETest is WithdrawNativeE2EBase {

    // ───────────────────────────────────────────────────────────────────────
    //  Happy path
    // ───────────────────────────────────────────────────────────────────────

    function test_withdrawNative_fullLifecycle() public {
        if (!fixturesReady) { vm.skip(true); return; }

        _runLifecycleThroughFinalize();

        // --- withdrawNative ---
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        address recipient = ws[0].recipient;
        uint256 amount = ws[0].amount;

        uint256 escrowBefore = rollup.totalEscrowed();
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());

        rollup.withdrawNative(ws, prover, wproof);

        assertEq(rollup.pendingWithdrawals(recipient), amount, "recipient credited exact amount");
        assertEq(rollup.totalEscrowed(), escrowBefore - amount, "escrow decreased by exactly amount");
        assertTrue(rollup.withdrawalNullifierUsed(ws[0].nullifier), "nullifier marked used");

        // --- pull payment: recipient claims real ETH ---
        uint256 balBefore = recipient.balance;
        vm.prank(recipient);
        rollup.withdraw(amount);
        assertEq(recipient.balance, balBefore + amount, "recipient received real ETH");
        assertEq(rollup.pendingWithdrawals(recipient), 0, "credit cleared after withdraw");
    }

    // ───────────────────────────────────────────────────────────────────────
    //  Negative cases
    // ───────────────────────────────────────────────────────────────────────

    /// Double-spend: paying the same withdrawal twice must revert on the nullifier.
    function test_withdrawNative_doubleSpend_reverts() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());

        rollup.withdrawNative(ws, prover, wproof); // first ok
        vm.expectRevert(IntmaxRollup.WithdrawalNullifierUsed.selector);
        rollup.withdrawNative(ws, prover, wproof); // replay rejected
    }

    /// ext_commitment mismatch: calling before finalize (latestFinalizedStateRoot == genesis)
    /// must revert — the withdrawal is not anchored to the finalized state.
    function test_withdrawNative_beforeFinalize_reverts() public {
        if (!fixturesReady) { vm.skip(true); return; }
        // Do NOT run finalize; latestFinalizedStateRoot is still the genesis root.
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        vm.expectRevert(IntmaxRollup.WithdrawalExtCommitmentMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
    }

    /// Tampered withdrawal set: mutating an amount breaks the pis_hash re-fold binding.
    function test_withdrawNative_tamperedAmount_reverts() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        ws[0].amount += 1; // tamper
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
    }

    /// The withdrawal circuit is immutable constructor state; no unset-value escrow state exists.
    function test_withdrawNative_verifierIsPinnedAtConstruction() public {
        if (!fixturesReady) { vm.skip(true); return; }
        address validity = address(rollup.validityMleVerifier());
        address withdrawal = address(rollup.withdrawalMleVerifier());
        assertTrue(validity.code.length != 0, "validity adapter code");
        assertTrue(withdrawal.code.length != 0, "withdrawal adapter code");
        assertTrue(validity != withdrawal, "circuit adapters must be distinct");
    }

    /// Constructor rejects aliasing the validity circuit as the withdrawal circuit.
    function test_constructor_rejectsDuplicateVerifierAdapters() public {
        if (!fixturesReady) { vm.skip(true); return; }
        // Resolve every getter before arming expectRevert: Foundry applies it to the very next
        // external call, which would otherwise be this harmless getter rather than the constructor.
        IPinnedMleVerifierV2 validity = rollup.validityMleVerifier();
        bytes32 genesis = vm.parseJsonBytes32(lifecycleJson, ".genesis_state_root");
        vm.expectRevert(IntmaxRollup.DuplicatePinnedMleVerifier.selector);
        new IntmaxRollup(fraudTreasury, validity, validity, genesis);
    }
}
