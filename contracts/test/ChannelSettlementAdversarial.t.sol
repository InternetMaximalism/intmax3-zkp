// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CloseSettlementBase, MockRollupRegistry} from "./CloseSettlementBase.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";

/// @title ChannelSettlementAdversarial
/// @notice Adversarial unit + bounded-fuzz coverage for close-settlement scenarios the per-feature
///         suite does not exercise *in composition*: claim ordering (C17), intent-over-declares vs
///         actually-received (C18), the SHARED withdrawal+post-close accrual budget, the
///         received-funds payout cap across multiple members, and over-pull fund locking.
///
///         SECURITY INTENT: every test asserts a fail-CLOSED outcome — the manager must never pay a
///         member more native ETH than it actually received for the channel, and must never let the
///         accrual exceed the declared fund. A test that shows a payout where it shouldn't is a real
///         finding (per CLAUDE.md C-fund-loss rule: STOP and escalate, do not weaken the test).
contract ChannelSettlementAdversarialTest is CloseSettlementBase {
    // ── helpers ──

    function _submitWd(bytes32 d, bytes32 member, address recipient, uint64 amount)
        internal
        returns (bytes32)
    {
        ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, member, recipient, amount);
        manager.submitWithdrawalClaim(c, _withdrawalClaimProof(c));
        return c.withdrawalNullifier;
    }

    function _submitPc(bytes32 d, bytes32 tx_, bytes32 receiver, address recipient, uint64 amount) internal {
        ChannelSettlementManager.PostCloseClaim memory c = _postCloseClaim(d, tx_, receiver, recipient, amount);
        manager.submitPostCloseClaim(c, _postCloseClaimProof(c));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // C17 — claim ordering: credit only payable AFTER funds are pulled.
    // ─────────────────────────────────────────────────────────────────────────

    /// No accrued credit at all → NoWithdrawalCredit (not a silent zero-pay).
    function test_C17_claim_with_no_credit_reverts() external {
        _finalizeDefault();
        vm.prank(alice);
        vm.expectRevert(ChannelSettlementManager.NoWithdrawalCredit.selector);
        manager.claimWithdrawalCredit(bytes32(uint256(1)));
    }

    /// Credit accrued (claim accepted) but funds NOT yet pulled → payout capped at received==0 →
    /// WithdrawalCapExceeded. After pull, the same claim pays. This is the C17 ordering invariant:
    /// the manager never pays ETH it has not received, even for a fully-proven claim.
    function test_C17_claim_before_pull_reverts_then_succeeds_after() external {
        bytes32 d = _finalizeDefault();
        bytes32 nullifier = _submitWd(d, USER_A, alice, 40);

        // receivedChannelFunds == 0 → cap blocks the payout.
        vm.prank(alice);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.claimWithdrawalCredit(nullifier);

        // Pull the channel ETH, then the same credit pays out.
        _fundAndPull(registry, manager, DEFAULT_FUND_AMOUNT);
        uint256 balBefore = alice.balance;
        vm.prank(alice);
        uint256 paid = manager.claimWithdrawalCredit(nullifier);
        assertEq(paid, 40, "pays the accrued credit after pull");
        assertEq(alice.balance - balBefore, 40, "alice received real ETH");
        assertEq(manager.totalCreditedOut(0), 40, "totalCreditedOut tracks the payout");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // C18 — intent over-declares fund vs actually received: the received cap wins.
    // ─────────────────────────────────────────────────────────────────────────

    /// Intent declares 100, but only 50 ETH reaches the rollup recipient ledger. The exact pull
    /// rejects the underfunded/mixed ledger atomically: no partial payout capacity is created and
    /// the rollup credit remains recoverable for operator reconciliation.
    function test_C18_underfunded_pull_reverts_atomically() external {
        bytes32 d = _finalizeWithFund(100);
        _submitWd(d, USER_A, alice, 40);
        _submitWd(d, USER_B, bob, 40);
        assertEq(manager.totalWithdrawn(0), 80, "both claims accrue under the 100 cap");

        _materializeCloseFundingAuthorization(registry, manager, 0);
        vm.deal(address(this), address(this).balance + 50);
        registry.creditWithdrawal{value: 50}(address(manager));
        vm.expectRevert(abi.encodeWithSelector(ChannelSettlementManager.ChannelFundingMismatch.selector, 0, 100, 50));
        manager.pullChannelFunds();
        assertEq(registry.pendingWithdrawals(address(manager)), 50, "rollup pull rolled back");
        assertEq(manager.receivedChannelFunds(0), 0, "no partial channel capacity");
        assertEq(address(manager).balance, 0, "manager did not retain mismatched value");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SHARED accrual budget: withdrawal + post-close claims draw from ONE pool.
    // ─────────────────────────────────────────────────────────────────────────

    /// C-2 (audit 2026-08-28): this test's original subject was that `totalWithdrawn` is a budget
    /// SHARED by the withdrawal and post-close legs. That sharing was never a defence — it is a
    /// shared pot, so a post-close double-credit is not refused, it simply displaces whichever
    /// co-member claims last (the loss surfaces as someone else's `WithdrawalCapExceeded`). The
    /// post-close leg is disabled, so what is asserted now is that it accrues NOTHING at all, and
    /// that the surviving withdrawal leg still enforces the cap on its own.
    function test_shared_accrual_budget_withdrawal_plus_postclose() external {
        bytes32 d = _finalizeDefault(); // fund = 75
        _submitWd(d, USER_A, alice, 40); // totalWithdrawn = 40
        assertEq(manager.totalWithdrawn(0), 40);

        // Build the proof BEFORE expectRevert (proof building does view calls that would otherwise
        // consume the expectation).
        ChannelSettlementManager.PostCloseClaim memory pc =
            _postCloseClaim(d, keccak256("incoming_tx_1"), USER_B, bob, 40);
        bytes memory pcProof = _postCloseClaimProof(pc);
        vm.expectRevert(ChannelSettlementManager.PostCloseClaimDisabled.selector);
        manager.submitPostCloseClaim(pc, pcProof);
        assertEq(manager.totalWithdrawn(0), 40, "the disabled leg accrues nothing");

        // The cap still binds on the leg that remains: 40 + 36 > 75 is refused, 40 + 35 == 75 fits.
        ChannelSettlementManager.WithdrawalClaim memory over = _withdrawalClaim(d, USER_B, bob, 36);
        bytes memory overProof = _withdrawalClaimProof(over);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.submitWithdrawalClaim(over, overProof);

        _submitWd(d, USER_B, bob, 35);
        assertEq(manager.totalWithdrawn(0), 75, "budget filled exactly to the fund cap");
    }

    /// Boundary: accrual is allowed up to EXACTLY the fund and one wei more reverts.
    function test_accrual_cap_exact_boundary() external {
        bytes32 d = _finalizeDefault(); // fund = 75
        _submitWd(d, USER_A, alice, 75);
        assertEq(manager.totalWithdrawn(0), 75, "accrue exactly the fund");

        ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, USER_B, bob, 1);
        bytes memory proof = _withdrawalClaimProof(c);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.submitWithdrawalClaim(c, proof);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Payout-cap across many members (cross-channel solvency, single manager view).
    // ─────────────────────────────────────────────────────────────────────────

    /// Accrue the full 75 across A/B/C, but present only 30 ETH. Exact reconciliation refuses the
    /// partial backing before any member can race to consume it.
    function test_underfunded_credit_creates_no_first_mover_payout() external {
        bytes32 d = _finalizeDefault(); // fund = 75
        bytes32 aliceNullifier = _submitWd(d, USER_A, alice, 25);
        _submitWd(d, USER_B, bob, 25);
        _submitWd(d, USER_C, carol, 25);

        _materializeCloseFundingAuthorization(registry, manager, 0);
        vm.deal(address(this), address(this).balance + 30);
        registry.creditWithdrawal{value: 30}(address(manager));
        vm.expectRevert(abi.encodeWithSelector(ChannelSettlementManager.ChannelFundingMismatch.selector, 0, 75, 30));
        manager.pullChannelFunds();
        assertEq(manager.receivedChannelFunds(0), 0);
        vm.prank(alice);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.claimWithdrawalCredit(aliceNullifier);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Mixed/over-credit cannot permanently DoS the channel's exact cap reconciliation.
    // ─────────────────────────────────────────────────────────────────────────

    function test_exactPull_leavesUnrelatedSurplusInRollupLedger() external {
        bytes32 d = _finalizeDefault(); // fund = 75
        bytes32 aliceNullifier = _submitWd(d, USER_A, alice, 25);
        bytes32 bobNullifier = _submitWd(d, USER_B, bob, 25);
        bytes32 carolNullifier = _submitWd(d, USER_C, carol, 25); // total accrued 75 (the whole fund)

        _materializeCloseFundingAuthorization(registry, manager, 0);
        vm.deal(address(this), address(this).balance + 100);
        registry.creditWithdrawal{value: 100}(address(manager));
        assertEq(manager.pullChannelFunds(), 75, "only exact channel cap transferred");
        assertEq(registry.pendingWithdrawals(address(manager)), 25, "unrelated credit stays in rollup");
        assertEq(manager.receivedChannelFunds(0), 75, "proof-bound cap counted exactly");
        assertEq(address(manager).balance, 75, "manager receives no surplus");

        vm.prank(alice);
        manager.claimWithdrawalCredit(aliceNullifier);
        vm.prank(bob);
        manager.claimWithdrawalCredit(bobNullifier);
        vm.prank(carol);
        manager.claimWithdrawalCredit(carolNullifier);
        assertEq(manager.totalCreditedOut(0), 75, "members cannot consume surplus");
        assertEq(address(manager).balance, 0, "channel backing paid exactly");
        assertEq(registry.pendingWithdrawals(address(manager)), 25, "surplus was never swept");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Ordering: both pull and claims are gated on this manager's finalized close.
    // ─────────────────────────────────────────────────────────────────────────

    function test_pull_and_claim_are_both_gated_on_closed() external {
        vm.deal(address(this), address(this).balance + 40);
        registry.creditWithdrawal{value: 40}(address(manager));
        vm.expectRevert(ChannelSettlementManager.CloseNotActive.selector);
        manager.pullChannelFunds();
        assertEq(registry.pendingWithdrawals(address(manager)), 40, "pre-close credit stays in rollup");
        assertEq(manager.receivedChannelFunds(0), 0);

        // A withdrawal claim before any finalize → CloseNotActive (status != Closed).
        ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(bytes32(uint256(1)), USER_A, alice, 10);
        bytes memory proof = _withdrawalClaimProof(c);
        vm.expectRevert(ChannelSettlementManager.CloseNotActive.selector);
        manager.submitWithdrawalClaim(c, proof);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fuzz: any sequence of accepted withdrawal claims keeps accrual == Σ credits and ≤ fund.
    // ─────────────────────────────────────────────────────────────────────────

    /// For random (member, amount) claims with distinct (salted) nullifiers, the manager's accrual
    /// must equal the sum of accepted amounts, never exceed the declared fund, and the conservation
    /// identity totalWithdrawn == Σ withdrawalCredits must hold (no payouts in this test).
    function testFuzz_accrual_conservation(uint64 a0, uint64 a1, uint64 a2) external {
        bytes32 d = _finalizeDefault(); // fund = 75
        a0 = uint64(bound(a0, 0, 60));
        a1 = uint64(bound(a1, 0, 60));
        a2 = uint64(bound(a2, 0, 60));

        uint256 accepted = 0;
        accepted += _tryAccrue(d, USER_A, alice, a0, 0);
        accepted += _tryAccrue(d, USER_B, bob, a1, 1);
        accepted += _tryAccrue(d, USER_C, carol, a2, 2);

        assertEq(manager.totalWithdrawn(0), accepted, "accrual == sum of accepted amounts");
        assertLe(manager.totalWithdrawn(0), DEFAULT_FUND_AMOUNT, "accrual never exceeds the fund");
        // Conservation (no payouts): totalWithdrawn == Σ credits across the three recipients.
        uint256 sumCredits = manager.withdrawalCredits(0, alice) + manager.withdrawalCredits(0, bob)
            + manager.withdrawalCredits(0, carol);
        assertEq(manager.totalWithdrawn(0), sumCredits, "conservation: accrual == sum credits");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A6 — the free bond-pot mutator is GONE, and the pot stays inert.
    // `fundBpBondCredits(uint256)` was `external`, NON-payable and UNGATED: anyone could inflate
    // `bpBondCredits` for free. It has been REMOVED (capability deleted, not constrained). This
    // pins both halves: (a) the selector no longer exists, so the free-inflation path is closed at
    // the ABI level and cannot be re-added innocently; (b) the pot still feeds no payout or cap,
    // so a regression that wired it into solvency would surface here.
    // ─────────────────────────────────────────────────────────────────────────

    function test_A6_bpBondCredits_mutator_removed_and_pot_still_inert() external {
        bytes32 d = _finalizeDefault();
        bytes32 nullifier = _submitWd(d, USER_A, alice, 25);
        _fundAndPull(registry, manager, DEFAULT_FUND_AMOUNT);

        uint256 bondBefore = manager.bpBondCredits();
        uint256 managerEthBefore = address(manager).balance;

        // (a) The free mutator is gone at the ABI level: a raw call on the old selector hits no
        //     function and (with no receive/fallback for calldata) reverts.
        vm.prank(mallory);
        (bool ok,) = address(manager).call(abi.encodeWithSignature("fundBpBondCredits(uint256)", type(uint128).max));
        assertFalse(ok, "fundBpBondCredits must no longer exist");
        assertEq(manager.bpBondCredits(), bondBefore, "bond pot unchanged by the removed mutator");
        assertEq(address(manager).balance, managerEthBefore, "no ETH moved");

        // (b) The pot still feeds nothing: the legitimate claim is capped by funds RECEIVED, and
        //     the constructor-seeded bond does not raise that ceiling.
        assertEq(manager.receivedChannelFunds(0), DEFAULT_FUND_AMOUNT, "received funds unaffected by the bond pot");
        assertEq(manager.totalWithdrawn(0), 25, "accrual unaffected by the bond pot");
        vm.prank(alice);
        assertEq(manager.claimWithdrawalCredit(nullifier), 25, "payout capped by received, not by bond");
        assertLe(manager.totalCreditedOut(0), manager.receivedChannelFunds(0), "solvency holds");
    }

    /// Submit one salted withdrawal claim; return the amount if accepted, 0 if the cap rejected it.
    function _tryAccrue(bytes32 d, bytes32 member, address recipient, uint64 amount, uint256 salt)
        internal
        returns (uint256)
    {
        ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaimSalted(d, member, recipient, amount, salt);
        try manager.submitWithdrawalClaim(c, _withdrawalClaimProofFor(manager, c)) {
            return amount;
        } catch {
            return 0;
        }
    }
}
