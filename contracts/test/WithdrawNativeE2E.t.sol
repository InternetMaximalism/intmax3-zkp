// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {WithdrawNativeE2EBase} from "./WithdrawNativeE2EBase.sol";

/// @title Full real on-chain native-ETH withdrawal payout (Phase 2).
/// @notice The honest lifecycle through `withdrawNative` -> `withdraw()` pays real ETH, plus the
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
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);

        rollup.withdrawNative(ws, prover, wproof);

        assertEq(rollup.pendingWithdrawals(recipient), amount, "recipient credited exact amount");
        assertEq(rollup.totalEscrowed(), escrowBefore - amount, "escrow decreased by exactly amount");
        assertTrue(rollup.withdrawalNullifierUsed(ws[0].nullifier), "nullifier marked used");

        // --- pull payment: recipient claims real ETH ---
        uint256 balBefore = recipient.balance;
        vm.prank(recipient);
        rollup.withdraw();
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
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);

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
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);
        vm.expectRevert(IntmaxRollup.WithdrawalExtCommitmentMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
    }

    /// Tampered withdrawal set: mutating an amount breaks the pis_hash re-fold binding.
    function test_withdrawNative_tamperedAmount_reverts() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        ws[0].amount += 1; // tamper
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
    }

    /// A fresh rollup whose withdrawal VK was never initialized must reject withdrawNative.
    function test_withdrawNative_vkNotSet_reverts() public {
        if (!fixturesReady) { vm.skip(true); return; }
        // Deploy a bare rollup (validity VK only; never initialize the withdrawal VK).
        FixtureLib.DeployData memory vdd = FixtureLib.parseDeployData(validityMleJson);
        IntmaxRollup.MleVk memory vvk = FixtureLib.buildMleVk(validityMleJson, verifier);
        bytes32 genesis = vm.parseJsonBytes32(lifecycleJson, ".genesis_state_root");
        IntmaxRollup bare = new IntmaxRollup(
            fraudTreasury, vvk, vdd.whirParams, vdd.protocolId, vdd.sessionId,
            vdd.kIs, vdd.subgroupGenPowers, verifier, genesis,
            true // A-2: test opt-in for the degreeBits==0 bypass
        );
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);
        vm.expectRevert(IntmaxRollup.WithdrawalVkNotSet.selector);
        bare.withdrawNative(ws, prover, wproof);
    }

    /// initializeWithdrawalVk is deployer-only and set-once.
    function test_initializeWithdrawalVk_access_and_setOnce() public {
        if (!fixturesReady) { vm.skip(true); return; }
        FixtureLib.DeployData memory wdd = FixtureLib.parseDeployData(withdrawalMleJson);
        IntmaxRollup.MleVk memory wvk = FixtureLib.buildMleVk(withdrawalMleJson, verifier);

        // Non-deployer rejected.
        vm.prank(makeAddr("attacker"));
        vm.expectRevert(IntmaxRollup.OnlyDeployer.selector);
        rollup.initializeWithdrawalVk(wvk, wdd.whirParams, wdd.protocolId, wdd.sessionId, wdd.kIs, wdd.subgroupGenPowers);

        // Deployer second call rejected (set-once latch; rollup VK already set in setUp).
        vm.expectRevert(IntmaxRollup.WithdrawalVkAlreadySet.selector);
        rollup.initializeWithdrawalVk(wvk, wdd.whirParams, wdd.protocolId, wdd.sessionId, wdd.kIs, wdd.subgroupGenPowers);
    }
}
