// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {WithdrawNativeE2EBase} from "./WithdrawNativeE2EBase.sol";

/// @title Partial-withdrawal authorization → payout, ACROSS the manager/rollup boundary.
///
/// @notice THE TEST GAP THIS FILE EXISTS TO CLOSE (doc/tasks/pw-auth-threat-model.md §7):
///         `claimAuthorizedWithdrawal` had ZERO tests, and `PartialWithdrawal.t.sol`'s manager-side
///         suite stops at `MockRollupRegistry` — it never crosses into a real `IntmaxRollup`. So no
///         test ever asked the only question that mattered: **what can an authorization actually
///         buy?** The answer, until 2026-07-28, was "the entire global ETH escrow, at an arbitrary
///         amount, to an arbitrary address". Every test here runs against a REAL `IntmaxRollup`
///         holding REAL escrowed ETH from a REAL fixture deposit.
///
///         The authorization is minted the same way the production path mints it — via a REGISTERED
///         settlement manager calling `authorizePartialWithdrawal`. This suite deliberately uses a
///         maximally-privileged authorizer (an EOA registered directly as a settlement manager, able
///         to authorize any digest at will). That is NOT a mock of a weaker thing: it is exactly the
///         capability the real `ChannelSettlementManager` hands its caller, since the Manager binds
///         only `auxData` and passes `amount`/`recipient`/`nullifier` through untouched. The point
///         is that even this maximal capability must now buy nothing.
///
/// @dev Inherits the real-fixture harness (real rollup, real withdrawal VK, real finalized state).
///      Self-skips if the heavy fixtures are absent.
contract PartialWithdrawalPayoutTest is WithdrawNativeE2EBase {
    /// Stands in for a registered `ChannelSettlementManager`. See the note above on why an EOA with
    /// full authorize rights is the correct — strictly stronger — adversary here.
    address internal settlementManager = makeAddr("settlementManager");

    address internal attacker = makeAddr("pwAttacker");

    /// The IPW2 auth digest, recomputed exactly as `IntmaxRollup._withdrawalAuthDigest`.
    function _authDigest(IntmaxRollup.Withdrawal memory w) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(0x49505732), w.recipient, w.tokenIndex, w.amount, w.auxData
            )
        );
    }

    /// Register `settlementManager` on the rollup (deployer-only; this test contract is deployer).
    function _registerManager() internal {
        rollup.registerSettlementManager(settlementManager);
        assertTrue(rollup.isRegisteredSettlementManager(settlementManager));
    }

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
    //  (a) An authorization ALONE can no longer pay anything
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// THE REGRESSION TEST. A registered settlement manager authorizes a fully-forged burn leaf
    /// naming the ENTIRE global escrow, payable to the attacker. Before the fix this succeeded and
    /// drained every channel's ETH. Now there is no entry point that will pay it.
    function test_authorizationAlone_cannotDrainEscrow() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        _registerManager();

        uint256 escrow = rollup.totalEscrowed();
        assertGt(escrow, 0, "fixture must have escrowed real ETH for this test to mean anything");

        // The attacker claims the WHOLE escrow — none of which they ever burned.
        IntmaxRollup.Withdrawal memory w = _forgedBurnLeaf(escrow);

        vm.prank(settlementManager);
        rollup.authorizePartialWithdrawal(_authDigest(w));
        assertTrue(rollup.partialWithdrawalAuthorized(_authDigest(w)), "authorization really is set");

        // 1. The proof-free door is GONE: the selector no longer exists, so a raw call hits the
        //    (absent) fallback and reverts. Asserted at the ABI level so re-adding any function with
        //    this signature breaks the test.
        (bool ok, ) = address(rollup).call(
            abi.encodeWithSignature(
                "claimAuthorizedWithdrawal((address,uint32,uint256,bytes32,bytes32))",
                w
            )
        );
        assertFalse(ok, "claimAuthorizedWithdrawal must no longer exist (proof-free payout removed)");

        // 2. The remaining ETH path demands a proof it cannot produce. The forged leaf is in no
        //    proven chain, so the pis_hash re-fold rejects it.
        IntmaxRollup.Withdrawal[] memory ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = w;
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        (, address prover) = _parsePayout();
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);

        // 3. Nothing moved. The authorization bought exactly zero.
        assertEq(rollup.totalEscrowed(), escrow, "escrow untouched");
        assertEq(rollup.pendingWithdrawals(attacker), 0, "attacker credited nothing");
        assertEq(attacker.balance, 0, "attacker received nothing");
        assertFalse(rollup.withdrawalNullifierUsed(w.nullifier), "nullifier not even consumed");
    }

    /// The same forged authorization is equally inert against the ERC-20 path — confirming the
    /// asymmetry that WAS the bug (ETH had a proof-free door; ERC-20 never did) is now gone.
    function test_authorizationAlone_inertAgainstErc20Path() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        _registerManager();

        IntmaxRollup.Withdrawal memory w = _forgedBurnLeaf(1 ether);
        w.tokenIndex = 5; // some ERC-20 index

        vm.prank(settlementManager);
        rollup.authorizePartialWithdrawal(_authDigest(w));

        IntmaxRollup.Withdrawal[] memory ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = w;
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        (, address prover) = _parsePayout();
        // Fails on the proof binding, exactly as the ETH path now does.
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawERC20(ws, prover, wproof);
    }

    /// Authorizing is still access-controlled: an unregistered address cannot mint the flag at all.
    /// (This was never the weak link — the weak link was what the flag bought — but it must hold.)
    function test_authorizePartialWithdrawal_unregisteredCallerRejected() public {
        if (!fixturesReady) { vm.skip(true); return; }
        vm.prank(attacker);
        vm.expectRevert(IntmaxRollup.NotRegisteredSettlementManager.selector);
        rollup.authorizePartialWithdrawal(keccak256("whatever"));
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

    /// `auxData` is inside the pis_hash re-fold, so the burn branch cannot be entered by relabelling
    /// a proven normal leaf: flipping auxData to non-zero breaks the binding and reverts.
    ///
    /// This is the direct positive evidence that the burn branch of `withdrawNative` is reachable
    /// ONLY via a proof that actually committed to `auxData` — i.e. that the IPW2 flag is a second
    /// factor on a proof-derived leaf, never a way to synthesize one.
    function test_provenLeaf_cannotBeRelabelledAsBurn() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        _registerManager();

        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        ws[0].auxData = keccak256("pretend_this_was_a_burn");

        // Even WITH a valid authorization for the relabelled leaf, the proof binding rejects it —
        // so the authorization cannot be used to promote a normal leaf into a burn leaf.
        vm.prank(settlementManager);
        rollup.authorizePartialWithdrawal(_authDigest(ws[0]));

        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
    }

    /// Conversely, a proven leaf that IS a burn (auxData != 0) without an authorization must be
    /// refused — the second factor is still enforced, it just can no longer act alone.
    ///
    /// HONEST LIMITATION (doc/tasks/pw-auth-threat-model.md §7.1): no fixture today produces a VALID
    /// proof for a leaf with `auxData != 0` — `withdrawal_payout.json` is a normal withdrawal, and
    /// producing a burn-leaf proof needs the base-layer path that does not exist yet
    /// (`cmd_partial_withdraw`, doc/tasks/todo.md:90). NO PROOF IS FAKED HERE. What this asserts is
    /// the reachable half: the call fails closed. It fails on the proof binding rather than on
    /// `PartialWithdrawalNotAuthorized`, which is itself the correct ordering — the proof is checked
    /// first, so an unproven leaf never reaches the authorization gate at all.
    function test_burnLeafWithoutAuthorization_failsClosed() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();

        IntmaxRollup.Withdrawal[] memory ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = _forgedBurnLeaf(1);
        bytes memory wproof = FixtureLib.parseCompactProofV2(_withdrawalMleJson());
        (, address prover) = _parsePayout();

        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
        assertEq(rollup.pendingWithdrawals(attacker), 0, "nothing credited");
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    //  Nullifier: one authorized tx_leaf still yields at most one payout (§3)
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
