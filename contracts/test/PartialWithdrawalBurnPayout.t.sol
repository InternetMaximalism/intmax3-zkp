// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {WithdrawNativeE2EBase} from "./WithdrawNativeE2EBase.sol";

/// @title The partial-withdrawal (BURN) payout path, against a REAL proved leaf with `aux_data != 0`.
///
/// @notice A partial withdrawal is an ordinary inter-channel send whose destination is the reserved
///         BURN channel with an L1 recipient. It is paid by `withdrawNative` on its base withdrawal
///         proof alone, exactly as an inter-channel transfer is consumed by a ReceiveTransfer proof:
///         channel consent is already carried by validity (every channel update binds the whole
///         registered member set's signatures over a digest including the block's tx tree root), and
///         close-vs-burn ordering is the `CloseFundingMaterializer` journal's job (covered in
///         `SignerIndependentExit.t.sol`). There is no settlement-manager step and no IPW2 latch.
///
///         This suite loads the `burn_` fixture set — a payout artifact proved with a nonzero burn
///         descriptor — so every test exercises `withdrawNative` with a genuinely proof-verified
///         burn leaf:
///           - test_provenBurnLeaf_paysOnProofAlone           (no manager, no authorization)
///           - test_provenBurnLeaf_nullifierSingleUse         (paid exactly once)
///           - test_burnLeaf_amountAboveBurn_rejected         (the F-AUX-1 `Y > X` shape)
///           - test_provenBurnLeaf_cannotBeRelabelled         (real proof, aux relabelled)
///           - testFuzz_onlyExactProvedPair_payable           (random (amount, recipient) pairs)
///           - test_provenBurnLeaf_notPayableViaErc20Path     (asset-class guard)
///
/// @dev Inherits the shared real-fixture lifecycle harness, overriding only the fixture prefix.
///      Self-skips if the heavy `burn_` fixtures are absent.
contract PartialWithdrawalBurnPayoutTest is WithdrawNativeE2EBase {
    function _fixturePrefix() internal pure override returns (string memory) {
        return "burn_";
    }

    /// Sanity: the fixture really is a burn leaf. If this fails the whole suite is meaningless, so it
    /// is asserted once up front rather than assumed by every test.
    function test_fixtureLeafIsABurn() public view {
        if (!fixturesReady) return;
        (IntmaxRollup.Withdrawal[] memory ws,) = _parsePayout();
        assertEq(ws.length, 1, "single-leaf burn fixture");
        assertTrue(ws[0].auxData != bytes32(0), "burn fixture leaf must carry aux_data != 0");
    }

    // ── 4a: a proven burn leaf is paid on its base withdrawal proof alone ────────────────────────

    /// The proof-verified burn leaf pays real ETH under a finalized root with NO settlement manager
    /// registered and NO authorization of any kind. The former IPW2 entry points do not exist.
    function test_provenBurnLeaf_paysOnProofAlone() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        assertTrue(ws[0].auxData != bytes32(0), "precondition: burn leaf");

        // No manager-side authority exists to consult: the IPW2 latch selectors are gone.
        (bool okAuthorize,) =
            address(rollup).call(abi.encodeWithSignature("authorizePartialWithdrawal(bytes32)", bytes32(uint256(1))));
        assertFalse(okAuthorize, "authorizePartialWithdrawal must no longer exist");
        (bool okLatch,) =
            address(rollup).call(abi.encodeWithSignature("partialWithdrawalAuthorized(bytes32)", bytes32(uint256(1))));
        assertFalse(okLatch, "partialWithdrawalAuthorized must no longer exist");

        uint256 escrowBefore = rollup.totalEscrowed();
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        rollup.withdrawNative(ws, prover, wproof);

        assertEq(rollup.pendingWithdrawals(ws[0].recipient), ws[0].amount, "burn leaf paid");
        assertEq(rollup.totalEscrowed(), escrowBefore - ws[0].amount, "escrow debited exactly");
        assertTrue(rollup.withdrawalNullifierUsed(ws[0].nullifier), "nullifier consumed");

        // The recipient pulls the payout.
        uint256 balanceBefore = ws[0].recipient.balance;
        vm.prank(ws[0].recipient);
        rollup.withdraw(ws[0].amount);
        assertEq(ws[0].recipient.balance - balanceBefore, ws[0].amount, "burn payout pulled");
    }

    /// Exactly once: after the payout consumes the nullifier, the SAME proof + leaf is dead on every
    /// remaining path.
    function test_provenBurnLeaf_nullifierSingleUse() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());

        rollup.withdrawNative(ws, prover, wproof);
        assertTrue(rollup.withdrawalNullifierUsed(ws[0].nullifier), "nullifier consumed");
        uint256 escrowAfterFirst = rollup.totalEscrowed();

        vm.expectRevert(IntmaxRollup.WithdrawalNullifierUsed.selector);
        rollup.withdrawNative(ws, prover, wproof);
        vm.expectRevert(IntmaxRollup.WithdrawalNotErc20Token.selector);
        rollup.withdrawERC20(ws, prover, wproof);

        assertEq(rollup.totalEscrowed(), escrowAfterFirst, "no second debit");
        assertEq(rollup.pendingWithdrawals(ws[0].recipient), ws[0].amount, "credited exactly once");
    }

    /// The ERC-20 entry point is closed for this native burn leaf: it dies on the asset-class guard.
    function test_provenBurnLeaf_notPayableViaErc20Path() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        vm.expectRevert(IntmaxRollup.WithdrawalNotErc20Token.selector);
        rollup.withdrawERC20(ws, prover, wproof);
    }

    // ── the economics are the proof's: nothing above, beside or instead of the proved leaf ──────

    /// A leaf claiming more than the proved burn amount fails the pis re-fold. With no second factor
    /// left, the proof binding is the whole guard, and it holds.
    function test_burnLeaf_amountAboveBurn_rejected() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        ws[0].amount = ws[0].amount + 1; // Y = X + 1
        uint256 escrowBefore = rollup.totalEscrowed();

        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
        assertEq(rollup.totalEscrowed(), escrowBefore, "escrow untouched");
    }

    /// Flipping `aux_data` — to 0 or to any other descriptor — breaks the pis re-fold.
    function test_provenBurnLeaf_cannotBeRelabelled() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        ws[0].auxData = bytes32(0);
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);

        (ws, prover) = _parsePayout();
        ws[0].auxData = keccak256("a different burn");
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
    }

    /// Property: for random `(amount, recipient)` substitutions on the proved leaf, none is payable.
    function testFuzz_onlyExactProvedPair_payable(uint96 rawAmount, address recipient) public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        // Keep it a genuine substitution of AT LEAST one field.
        if (recipient == ws[0].recipient && uint256(rawAmount) == ws[0].amount) {
            rawAmount = uint96(uint256(rawAmount) + 1);
        }
        ws[0].amount = rawAmount;
        ws[0].recipient = recipient;

        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
    }
}
