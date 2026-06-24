// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CloseSettlementBase, MockRollupRegistry} from "./CloseSettlementBase.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";

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

    function _submitWd(bytes32 d, bytes32 member, address recipient, uint64 amount) internal {
        ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, member, recipient, amount);
        manager.submitWithdrawalClaim(c, _withdrawalClaimProof(c));
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
        manager.claimWithdrawalCredit();
    }

    /// Credit accrued (claim accepted) but funds NOT yet pulled → payout capped at received==0 →
    /// WithdrawalCapExceeded. After pull, the same claim pays. This is the C17 ordering invariant:
    /// the manager never pays ETH it has not received, even for a fully-proven claim.
    function test_C17_claim_before_pull_reverts_then_succeeds_after() external {
        bytes32 d = _finalizeDefault();
        _submitWd(d, USER_A, alice, 40);

        // receivedChannelFunds == 0 → cap blocks the payout.
        vm.prank(alice);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.claimWithdrawalCredit();

        // Pull the channel ETH, then the same credit pays out.
        _fundAndPull(registry, manager, 40);
        uint256 balBefore = alice.balance;
        vm.prank(alice);
        uint256 paid = manager.claimWithdrawalCredit();
        assertEq(paid, 40, "pays the accrued credit after pull");
        assertEq(alice.balance - balBefore, 40, "alice received real ETH");
        assertEq(manager.totalCreditedOut(), 40, "totalCreditedOut tracks the payout");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // C18 — intent over-declares fund vs actually received: the received cap wins.
    // ─────────────────────────────────────────────────────────────────────────

    /// Intent declares 100, but only 50 ETH is actually pulled. Two members accrue 40 each (80 ≤ 100
    /// accrual cap, both ACCEPTED). At payout the aggregate is capped by receivedChannelFunds (50):
    /// the first claimer is paid 40, the second can take at most 10 more — its full 40 reverts.
    /// SECURITY: aggregate ETH out (totalCreditedOut) can NEVER exceed the 50 actually received,
    /// regardless of the inflated 100 in the intent.
    function test_C18_intent_overdeclares_received_cap_wins() external {
        bytes32 d = _finalizeWithFund(100);
        _submitWd(d, USER_A, alice, 40);
        _submitWd(d, USER_B, bob, 40);
        assertEq(manager.totalWithdrawn(), 80, "both claims accrue under the 100 cap");

        _fundAndPull(registry, manager, 50); // intent said 100, reality is 50

        vm.prank(alice);
        assertEq(manager.claimWithdrawalCredit(), 40, "first claimer paid in full from the 50");

        // bob is owed 40 but only 10 remains under receivedChannelFunds=50 → revert (no partial pay).
        vm.prank(bob);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.claimWithdrawalCredit();

        assertLe(manager.totalCreditedOut(), manager.receivedChannelFunds(), "solvency: out <= received");
        assertEq(manager.totalCreditedOut(), 40, "only 40 of the 50 was claimable by the first mover");
        assertEq(address(manager).balance, 10, "10 received ETH remains, owed to bob but capped");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SHARED accrual budget: withdrawal + post-close claims draw from ONE pool.
    // ─────────────────────────────────────────────────────────────────────────

    /// A withdrawal claim (40) and a post-close claim (40) together exceed the 75 declared fund →
    /// the second accrual reverts WithdrawalCapExceeded. Confirms `totalWithdrawn` is the SHARED
    /// budget across both claim kinds (a regression that split them would let claims mint > fund).
    function test_shared_accrual_budget_withdrawal_plus_postclose() external {
        bytes32 d = _finalizeDefault(); // fund = 75
        _submitWd(d, USER_A, alice, 40); // totalWithdrawn = 40
        assertEq(manager.totalWithdrawn(), 40);

        // Post-close claim to member B for 40 → 40 + 40 = 80 > 75 → reverts. Build the proof BEFORE
        // expectRevert (proof building does view calls that would otherwise consume the expectation).
        ChannelSettlementManager.PostCloseClaim memory pc =
            _postCloseClaim(d, keccak256("incoming_tx_1"), USER_B, bob, 40);
        MleVerifier.MleProof memory pcProof = _postCloseClaimProof(pc);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.submitPostCloseClaim(pc, pcProof);

        // 35 fits (40 + 35 == 75 exactly).
        _submitPc(d, keccak256("incoming_tx_1"), USER_B, bob, 35);
        assertEq(manager.totalWithdrawn(), 75, "shared budget filled exactly to the fund cap");
    }

    /// Boundary: accrual is allowed up to EXACTLY the fund and one wei more reverts.
    function test_accrual_cap_exact_boundary() external {
        bytes32 d = _finalizeDefault(); // fund = 75
        _submitWd(d, USER_A, alice, 75);
        assertEq(manager.totalWithdrawn(), 75, "accrue exactly the fund");

        ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, USER_B, bob, 1);
        MleVerifier.MleProof memory proof = _withdrawalClaimProof(c);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.submitWithdrawalClaim(c, proof);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Payout-cap across many members (cross-channel solvency, single manager view).
    // ─────────────────────────────────────────────────────────────────────────

    /// Accrue the full 75 across A/B/C, but only 30 ETH is pulled. Members claim in order; the
    /// aggregate ETH paid out can never exceed 30. The unpaid members revert — fail-closed.
    function test_received_cap_across_members() external {
        bytes32 d = _finalizeDefault(); // fund = 75
        _submitWd(d, USER_A, alice, 25);
        _submitWd(d, USER_B, bob, 25);
        _submitWd(d, USER_C, carol, 25);

        _fundAndPull(registry, manager, 30);

        vm.prank(alice);
        assertEq(manager.claimWithdrawalCredit(), 25, "alice paid 25");
        // 25 already out; bob (25) would push to 50 > 30 → revert.
        vm.prank(bob);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.claimWithdrawalCredit();

        assertEq(manager.totalCreditedOut(), 25, "aggregate out is bounded by received (30)");
        assertLe(manager.totalCreditedOut(), manager.receivedChannelFunds(), "solvency holds");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Over-pull: received > declared fund. Surplus ETH is LOCKED (no extraction path).
    // This is a liveness/efficiency observation, NOT a theft vector — documented so a regression
    // that turned the surplus into an over-payout would be caught.
    // ─────────────────────────────────────────────────────────────────────────

    function test_overpull_surplus_is_locked_not_payable() external {
        bytes32 d = _finalizeDefault(); // fund = 75
        _submitWd(d, USER_A, alice, 25);
        _submitWd(d, USER_B, bob, 25);
        _submitWd(d, USER_C, carol, 25); // total accrued 75 (the whole fund)

        _fundAndPull(registry, manager, 100); // rollup paid MORE than the declared fund

        vm.prank(alice);
        manager.claimWithdrawalCredit();
        vm.prank(bob);
        manager.claimWithdrawalCredit();
        vm.prank(carol);
        manager.claimWithdrawalCredit();

        // All accrued credit (75) is paid; nobody can claim the surplus 25 — accrual is capped at
        // the declared fund, so the extra ETH is stranded in the manager with no extraction path.
        assertEq(manager.totalCreditedOut(), 75, "only the declared fund is ever paid out");
        assertEq(address(manager).balance, 25, "surplus 25 ETH locked in the manager (no admin path)");

        // No further credit exists, so any further claim reverts.
        vm.prank(alice);
        vm.expectRevert(ChannelSettlementManager.NoWithdrawalCredit.selector);
        manager.claimWithdrawalCredit();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Ordering: claims are gated on the manager's OWN finalizeClose (status==Closed), independent of
    // whether funds were pulled (which is permissionless and works pre-close).
    // ─────────────────────────────────────────────────────────────────────────

    function test_pull_works_before_close_but_claims_gated_on_closed() external {
        // Pull funds while still Active (permissionless, only moves pendingWithdrawals[manager]).
        _fundAndPull(registry, manager, 40);
        assertEq(manager.receivedChannelFunds(), 40, "funds pullable pre-close");

        // A withdrawal claim before any finalize → CloseNotActive (status != Closed).
        ChannelSettlementManager.WithdrawalClaim memory c =
            _withdrawalClaim(bytes32(uint256(1)), USER_A, alice, 10);
        MleVerifier.MleProof memory proof = _withdrawalClaimProof(c);
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

        assertEq(manager.totalWithdrawn(), accepted, "accrual == sum of accepted amounts");
        assertLe(manager.totalWithdrawn(), DEFAULT_FUND_AMOUNT, "accrual never exceeds the fund");
        // Conservation (no payouts): totalWithdrawn == Σ credits across the three recipients.
        uint256 sumCredits = manager.withdrawalCredits(alice)
            + manager.withdrawalCredits(bob) + manager.withdrawalCredits(carol);
        assertEq(manager.totalWithdrawn(), sumCredits, "conservation: accrual == sum credits");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A6 — fundBpBondCredits: the BP bond pot is INERT and the mutator is a footgun.
    // `fundBpBondCredits(uint256)` is named "fund", takes an amount, yet is NON-payable and
    // UNGATED — anyone can inflate `bpBondCredits` to any value for free. This pins that the value
    // (a) escrows no ETH and (b) feeds no payout/cap path, so the free inflation is harmless while
    // the special-close (C2) path is disabled. A regression that wired bpBondCredits into solvency
    // would turn this into a free over-credit — these asserts would then fail.
    // ─────────────────────────────────────────────────────────────────────────

    function test_A6_bpBondCredits_is_inert_and_freely_inflatable() external {
        bytes32 d = _finalizeDefault();
        _submitWd(d, USER_A, alice, 25);
        _fundAndPull(registry, manager, 25);

        uint256 bondBefore = manager.bpBondCredits();

        // A non-member inflates the bond pot by a huge amount for FREE (no ETH attached, no gate).
        uint256 managerEthBefore = address(manager).balance;
        vm.prank(mallory);
        manager.fundBpBondCredits(type(uint128).max);
        assertEq(
            manager.bpBondCredits(), bondBefore + type(uint128).max,
            "bpBondCredits is freely inflatable by anyone"
        );
        // ...but it moved no ETH and changed no fund-affecting accounting.
        assertEq(address(manager).balance, managerEthBefore, "fundBpBondCredits escrows no ETH");
        assertEq(manager.receivedChannelFunds(), 25, "received funds unaffected by bond inflation");
        assertEq(manager.totalWithdrawn(), 25, "accrual unaffected by bond inflation");

        // The legitimate claim path is unchanged: alice still gets exactly her 25, capped by the
        // 25 received — the inflated bond does NOT raise the payout ceiling.
        vm.prank(alice);
        assertEq(manager.claimWithdrawalCredit(), 25, "payout still capped by received, not by bond");
        assertLe(manager.totalCreditedOut(), manager.receivedChannelFunds(), "solvency holds");
    }

    /// Submit one salted withdrawal claim; return the amount if accepted, 0 if the cap rejected it.
    function _tryAccrue(bytes32 d, bytes32 member, address recipient, uint64 amount, uint256 salt)
        internal returns (uint256)
    {
        ChannelSettlementManager.WithdrawalClaim memory c =
            _withdrawalClaimSalted(d, member, recipient, amount, salt);
        try manager.submitWithdrawalClaim(c, _withdrawalClaimProofFor(manager, c)) {
            return amount;
        } catch {
            return 0;
        }
    }
}
