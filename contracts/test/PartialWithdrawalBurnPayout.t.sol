// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {WithdrawNativeE2EBase} from "./WithdrawNativeE2EBase.sol";

/// @title Phase 4 adversarial coverage for the partial-withdrawal (BURN) PAYOUT path, against a REAL
///        proved leaf with `aux_data != 0`.
///
/// @notice WHY THIS FILE EXISTS AND WHAT IT ADDS OVER `PartialWithdrawalPayout.t.sol`
///         (doc/tasks/partial-withdrawal-payout-design.md Phase 4):
///         `PartialWithdrawalPayout.t.sol` runs against the DEFAULT fixture, whose leaf is a normal
///         withdrawal (`aux_data == 0`). It therefore could only assert that a FORGED burn leaf
///         fails on the proof binding (`test_burnLeafWithoutAuthorization_failsClosed`) — it could
///         never carry a REAL proof for an `aux != 0` leaf THROUGH the binding and INTO the IMPW
///         authorization gate. This suite loads the `burn_` fixture set — the repo's first payout
///         artifact proved with a nonzero burn descriptor (P3 HEAVY) — so every test here exercises
///         `withdrawNative`'s burn branch with a genuinely proof-verified leaf.
///
///         Coverage map:
///           P4-1  test_burnLeaf_amountAboveBurn_rejected        (the F-AUX-1 `Y > X` shape)
///           P4-3  test_provenBurnLeaf_withoutAuthorization_...   (reaches the FLAG check, not the
///                                                                 proof binding — the new evidence)
///           P4-4  test_provenBurnLeaf_cannotBeRelabelled         (real proof, aux relabelled)
///           P4-5  testFuzz_onlyExactCosignedPair_payable         (random (amount, recipient) triples)
///           (T5)  test_provenBurnLeaf_nullifierSingleUse         (the paid leaf cannot be replayed)
///         plus the honest first-ever `aux != 0` on-chain payout as the control.
///
/// @dev Inherits the shared real-fixture lifecycle harness, overriding only the fixture prefix.
///      Self-skips if the heavy `burn_` fixtures are absent.
contract PartialWithdrawalBurnPayoutTest is WithdrawNativeE2EBase {
    address internal settlementManager = makeAddr("burnSettlementManager");

    function _fixturePrefix() internal pure override returns (string memory) {
        return "burn_";
    }

    /// The IMPW auth digest, recomputed exactly as `IntmaxRollup._withdrawalAuthDigest`.
    function _authDigest(IntmaxRollup.Withdrawal memory w) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(0x494d5057), w.nullifier, w.recipient, w.tokenIndex, w.amount, w.auxData
            )
        );
    }

    function _registerManager() internal {
        rollup.registerSettlementManager(settlementManager);
        assertTrue(rollup.isRegisteredSettlementManager(settlementManager));
    }

    /// Register the manager and authorize the EXACT proved leaf's digest — the honest second factor.
    function _authorize(IntmaxRollup.Withdrawal memory w) internal {
        _registerManager();
        vm.prank(settlementManager);
        rollup.authorizePartialWithdrawal(_authDigest(w));
        assertTrue(rollup.partialWithdrawalAuthorized(_authDigest(w)), "authorization set");
    }

    /// Sanity: the fixture really is a burn leaf. If this fails the whole suite is meaningless, so it
    /// is asserted once up front rather than assumed by every test.
    function test_fixtureLeafIsABurn() public view {
        if (!fixturesReady) return;
        (IntmaxRollup.Withdrawal[] memory ws,) = _parsePayout();
        assertEq(ws.length, 1, "single-leaf burn fixture");
        assertTrue(ws[0].auxData != bytes32(0), "burn fixture leaf must carry aux_data != 0");
    }

    // ── Control: the honest first-ever aux != 0 payout ───────────────────────────────────────────

    /// The proof-verified burn leaf, WITH a finalized authorization, pays real ETH. This is the
    /// positive half of P4-4 (a legitimate burn is payable) and the first on-chain exercise of the
    /// `withdrawNative` burn branch through a real proof.
    function test_provenBurnLeaf_paysWithAuthorization() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        _authorize(ws[0]);

        uint256 escrowBefore = rollup.totalEscrowed();
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);
        rollup.withdrawNative(ws, prover, wproof);

        assertEq(rollup.pendingWithdrawals(ws[0].recipient), ws[0].amount, "burn leaf paid");
        assertEq(rollup.totalEscrowed(), escrowBefore - ws[0].amount, "escrow debited exactly");
        assertTrue(rollup.withdrawalNullifierUsed(ws[0].nullifier), "nullifier consumed");
    }

    // ── P4-3: a real burn leaf without an authorization reverts AT the flag check ─────────────────

    /// THE NEW EVIDENCE. The leaf is proof-verified (real `aux != 0` proof), so `_verifyWithdrawalSet`
    /// PASSES; the revert is therefore `PartialWithdrawalNotAuthorized` from the IMPW gate itself —
    /// not `WithdrawalPublicInputsMismatch` from the proof binding, which is all the forged-leaf test
    /// in `PartialWithdrawalPayout.t.sol` can reach. This proves the second factor actually guards a
    /// proven leaf: the burn branch is entered, and it fails closed for want of channel consent.
    function test_provenBurnLeaf_withoutAuthorization_reverts() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        assertTrue(ws[0].auxData != bytes32(0), "precondition: burn leaf");
        assertFalse(
            rollup.partialWithdrawalAuthorized(_authDigest(ws[0])), "precondition: not authorized"
        );

        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);
        vm.expectRevert(IntmaxRollup.PartialWithdrawalNotAuthorized.selector);
        rollup.withdrawNative(ws, prover, wproof);

        assertEq(rollup.pendingWithdrawals(ws[0].recipient), 0, "nothing credited");
        assertFalse(rollup.withdrawalNullifierUsed(ws[0].nullifier), "nullifier not consumed");
    }

    /// The ERC-20 entry point is equally closed for this native burn leaf: it dies on the asset-class
    /// guard before any authorization question, confirming an ETH burn is not payable via that path.
    function test_provenBurnLeaf_notPayableViaErc20Path() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        _authorize(ws[0]); // even authorized, the wrong asset path must refuse it
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);
        vm.expectRevert(IntmaxRollup.WithdrawalNotErc20Token.selector);
        rollup.withdrawERC20(ws, prover, wproof);
    }

    // ── P4-1: the F-AUX-1 `Y > X` shape — an amount above the co-signed burn is rejected ──────────

    /// An authorization for the tampered `(Y > X)` digest still cannot pay it: the proof binding
    /// re-folds the REAL leaf, so a leaf claiming more than the proved burn amount fails the pis
    /// re-fold before the flag is ever consulted. This is exactly the regression the whole phase
    /// exists to prevent (P0-4 → P4-1).
    function test_burnLeaf_amountAboveBurn_rejected() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        _registerManager();

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        ws[0].amount = ws[0].amount + 1; // Y = X + 1

        // Authorize the tampered digest so the ONLY thing that can stop it is the proof binding.
        vm.prank(settlementManager);
        rollup.authorizePartialWithdrawal(_authDigest(ws[0]));

        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
        assertEq(rollup.totalEscrowed() > 0, true, "escrow untouched");
    }

    // ── P4-4: a proven burn leaf cannot be relabelled ────────────────────────────────────────────

    /// Flipping `aux_data` — whether to 0 (to dodge the flag) or to any other descriptor — breaks the
    /// pis re-fold. So the burn branch cannot be entered by relabelling a proven leaf, and a proven
    /// burn leaf cannot be demoted to a normal one to skip the authorization.
    function test_provenBurnLeaf_cannotBeRelabelled() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        _registerManager();
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);

        // (a) aux -> 0 (demote to normal). Even so, the binding rejects it.
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        ws[0].auxData = bytes32(0);
        vm.prank(settlementManager);
        rollup.authorizePartialWithdrawal(_authDigest(ws[0]));
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);

        // (b) aux -> a different burn descriptor.
        (ws, prover) = _parsePayout();
        ws[0].auxData = keccak256("a different burn");
        vm.prank(settlementManager);
        rollup.authorizePartialWithdrawal(_authDigest(ws[0]));
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
    }

    // ── P4-5: only the exact co-signed (amount, recipient) pair is ever payable ───────────────────

    /// Property: for random `(amount, recipient)` substitutions on the proved leaf, none is payable —
    /// the pis re-fold binds every field, so only the exact proved pair survives. The honest pair
    /// itself is covered by `test_provenBurnLeaf_paysWithAuthorization`.
    function testFuzz_onlyExactCosignedPair_payable(uint96 rawAmount, address recipient) public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        _registerManager();

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        // Keep it a genuine substitution of AT LEAST one field.
        if (recipient == ws[0].recipient && uint256(rawAmount) == ws[0].amount) {
            rawAmount = uint96(uint256(rawAmount) + 1);
        }
        ws[0].amount = rawAmount;
        ws[0].recipient = recipient;

        // Authorize whatever the attacker asks for, so only the proof binding can stop the payout.
        vm.prank(settlementManager);
        rollup.authorizePartialWithdrawal(_authDigest(ws[0]));

        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
    }

    // ── T5 (P4-2 replay half): the paid burn leaf cannot be replayed ─────────────────────────────

    /// After the honest payout consumes the nullifier, the SAME proof + leaf is dead across every
    /// remaining path. (The full P4-2 cross-lane conservation — burn lane vs close lane summing to
    /// the channel's deposits — additionally needs the close path and is asserted in the close-side
    /// suites; here we pin the burn lane's single-use guarantee, which is the replay half of T5.)
    function test_provenBurnLeaf_nullifierSingleUse() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        _authorize(ws[0]);
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);

        rollup.withdrawNative(ws, prover, wproof);
        assertTrue(rollup.withdrawalNullifierUsed(ws[0].nullifier), "nullifier consumed");

        // Second time: rejected on the shared nullifier, even with the authorization still standing.
        vm.expectRevert(IntmaxRollup.WithdrawalNullifierUsed.selector);
        rollup.withdrawNative(ws, prover, wproof);
    }
}
