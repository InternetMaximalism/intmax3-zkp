// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {CloseSettlementBase, MockRollupRegistry} from "./CloseSettlementBase.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {CloseTestLib} from "./CloseTestLib.sol";

/// @title SettlementHandler
/// @notice Stateful fuzzing handler for the close-settlement payout accounting. It drives a
///         FINALIZED (Closed) channel through random sequences of: pull channel funds, submit
///         withdrawal claims, submit post-close claims, and claim accrued credit as ETH. Every
///         action is try/catch-wrapped so EXPECTED reverts (cap exceeded, nullifier reuse, …) keep
///         fuzzing instead of aborting — the point is to find a sequence that breaks an accounting
///         invariant, not one that reverts.
contract SettlementHandler {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    ChannelSettlementManager internal immutable manager;
    ChannelSettlementVerifier internal immutable verifier;
    MockRollupRegistry internal immutable registry;
    bytes4 internal immutable channelId;
    bytes32 internal immutable digest;

    bytes32[3] internal members;
    address[3] internal recipients;

    struct ScopedPayout {
        address recipient;
        bytes32 withdrawalNullifier;
        bool paid;
    }

    ScopedPayout[] internal scopedPayouts;

    // ghost counters to force distinct nullifiers across calls
    uint256 internal wdSalt;
    uint256 internal pcNonce;

    // ghost totals for cross-checking (independent of the contract's own accounting)
    uint256 public ghostPulled; // Σ pull deltas accepted as this channel's backing cap
    uint256 public ghostSurplus; // Σ physical pull delta deliberately excluded from channel backing
    uint256 public ghostPaid; // Σ ETH actually paid out to members

    // ── LIVENESS instrumentation (audit28-08-2026 M-7) ──────────────────────────────────────────
    //
    // The try/catch below is load-bearing and STAYS: the fuzzer must keep going through the many
    // legitimately-reverting sequences (cap exceeded, nullifier reuse, empty credit) or it explores
    // nothing. What it must NOT do is make a total liveness break indistinguishable from a run in
    // which the fuzzer merely happened to pick unlucky arguments. Before this, `ghostPaid` was only
    // ever compared for EQUALITY with `totalCreditedOut`, and `0 == 0` satisfies every invariant in
    // this file — so a `submitWithdrawalClaim` that reverted UNCONDITIONALLY kept the suite green.
    // That is mechanism (D) from doc/audit/why-gate8-was-missed.md, and it is what let the gate-8
    // "honest exit impossible" class ship.
    //
    // Recording attempted-vs-succeeded per action turns "nothing ever worked" into an observable,
    // which `ChannelSettlementInvariantTest.afterInvariant()` then asserts on at the END of each
    // fuzzing run (an ordinary `invariant_` function cannot: it is evaluated after the FIRST call
    // too, where zero successes is the correct state).
    uint256 public attemptedPull;
    uint256 public succeededPull;
    uint256 public attemptedWithdrawal;
    uint256 public succeededWithdrawal;
    uint256 public attemptedPostClose;
    uint256 public succeededPostClose;
    uint256 public attemptedClaim;
    uint256 public succeededClaim;

    // FEASIBLE attempts — the ones a correct contract had no legitimate reason to refuse, counted
    // from state read immediately BEFORE the call. Both accrual paths draw on the SAME I3 ceiling
    // (`finalizedChannelFundAmount`, 75), and the handler's amounts run to 99, so the ceiling is
    // typically consumed by a handful of successes and every later attempt of EITHER kind reverts
    // correctly. A bare `succeededWithdrawal > 0` floor is therefore flaky — it is a statement about
    // which selector the fuzzer drew first. Gating on feasibility turns it back into a statement
    // about the code: "an attempt that FIT under the remaining ceiling was refused anyway".
    uint256 public feasibleWithdrawal;
    uint256 public feasiblePostClose;

    constructor(
        ChannelSettlementManager manager_,
        ChannelSettlementVerifier verifier_,
        MockRollupRegistry registry_,
        bytes4 channelId_,
        bytes32 digest_,
        bytes32[3] memory members_,
        address[3] memory recipients_
    ) {
        manager = manager_;
        verifier = verifier_;
        registry = registry_;
        channelId = channelId_;
        digest = digest_;
        members = members_;
        recipients = recipients_;
    }

    receive() external payable {}

    /// Accrual headroom left under I3 for THIS token, read fresh. `amt` in `(0, remaining]` is the
    /// exact condition under which the manager owes the caller an accrual.
    function _accrualHeadroom() internal view returns (uint256) {
        uint256 fund = manager.finalizedChannelFundAmount(0);
        uint256 used = manager.totalWithdrawn(0);
        return used >= fund ? 0 : fund - used;
    }

    // ── actions (whitelisted as fuzz targets) ──

    /// Credit the manager via the rollup, then pull it in. amount bounded so the handler never runs
    /// dry and so both under- and over-funding (vs the 75 fund) are explored.
    function pull(uint96 amount) external {
        uint256 amt = uint256(amount) % 200 + 1; // [1, 200]
        if (address(this).balance < amt) return;
        registry.creditWithdrawal{value: amt}(address(manager));
        attemptedPull += 1;
        uint256 receivedBefore = manager.receivedChannelFunds(0);
        try manager.pullChannelFunds() returns (uint256 pulled) {
            succeededPull += 1;
            // The physical delta may include unrelated proof-backed surplus in the Rollup's
            // recipient-scoped ledger. Only the capped accounting delta belongs to this channel.
            uint256 accepted = manager.receivedChannelFunds(0) - receivedBefore;
            ghostPulled += accepted;
            ghostSurplus += pulled - accepted;
        } catch {}
    }

    function submitWithdrawal(uint256 memberSeed, uint64 amount) external {
        uint256 i = memberSeed % 3;
        uint64 amt = uint64(amount % 100);
        ChannelSettlementManager.WithdrawalClaim memory c = ChannelSettlementManager.WithdrawalClaim({
            closeIntentDigest: digest,
            memberPkG: members[i],
            recipient: recipients[i],
            userAmountDigest: keccak256(abi.encodePacked(members[i], amt, wdSalt)),
            amount: amt,
            tokenSlot: 0,
            tokenIndex: 0,
            withdrawalNullifier: keccak256(abi.encodePacked("wd", digest, members[i], wdSalt))
        });
        wdSalt += 1;
        uint256[] memory limbs = verifier.expectedWithdrawalClaimLimbs(
            channelId,
            c.closeIntentDigest,
            manager.finalizedBalanceStateH1(),
            c.memberPkG,
            c.recipient,
            c.userAmountDigest,
            c.amount,
            c.tokenSlot,
            c.tokenIndex,
            c.withdrawalNullifier
        );
        attemptedWithdrawal += 1;
        if (amt > 0 && amt <= _accrualHeadroom()) {
            feasibleWithdrawal += 1;
        }
        try manager.submitWithdrawalClaim(c, CloseTestLib.proofWithLimbs(limbs)) {
            succeededWithdrawal += 1;
            if (amt > 0) {
                scopedPayouts.push(ScopedPayout({
                    recipient: c.recipient,
                    withdrawalNullifier: c.withdrawalNullifier,
                    paid: false
                }));
            }
        } catch {}
    }

    function submitPostClose(uint256 memberSeed, uint64 amount) external {
        uint256 i = memberSeed % 3;
        uint64 amt = uint64(amount % 100);
        bytes32 incomingTx = keccak256(abi.encodePacked("pc", pcNonce));
        pcNonce += 1;
        bytes32 snn = keccak256(abi.encodePacked(bytes4(uint32(0x494d434b)), digest, incomingTx, members[i]));
        uint256[] memory limbs = verifier.expectedPostCloseClaimLimbs(
            channelId,
            digest,
            incomingTx,
            members[i],
            recipients[i],
            snn,
            amt,
            manager.finalizedBalanceStateH1(),
            manager.finalizedSettledTxAccumulatorRoot(),
            0
        );
        ChannelSettlementManager.PostCloseClaim memory c = ChannelSettlementManager.PostCloseClaim({
            closeIntentDigest: digest,
            incomingTxHash: incomingTx,
            receiverPkG: members[i],
            recipient: recipients[i],
            amount: amt,
            tokenIndex: 0
        });
        attemptedPostClose += 1;
        if (amt > 0 && amt <= _accrualHeadroom()) {
            feasiblePostClose += 1;
        }
        try manager.submitPostCloseClaim(c, CloseTestLib.proofWithLimbs(limbs)) {
            succeededPostClose += 1;
        } catch {}
    }

    function claim(uint256 payoutSeed) external {
        attemptedClaim += 1;
        if (scopedPayouts.length == 0) return;
        ScopedPayout storage payout = scopedPayouts[payoutSeed % scopedPayouts.length];
        if (payout.paid) return;
        address r = payout.recipient;
        uint256 balBefore = r.balance;
        vm.prank(r);
        try manager.claimWithdrawalCredit(payout.withdrawalNullifier) returns (uint256) {
            payout.paid = true;
            succeededClaim += 1;
            ghostPaid += (r.balance - balBefore);
        } catch {}
    }
}

/// @title ChannelSettlementInvariantTest
/// @notice Global accounting invariants for a closed channel under arbitrary payout sequences
///         (scenario G / invariants I1–I5). A violation of ANY of these is a fund-safety bug.
///
/// @dev The invariant budget is PINNED HERE rather than left to Foundry's defaults, because the
///      liveness floor in `afterInvariant()` is a statement about what a run of a GIVEN LENGTH must
///      achieve: a toolchain default that shortened runs would silently weaken it into something
///      that could fail by luck instead of by defect. The values are the ones this suite has been
///      running at (Foundry 1.5.1 defaults, measured: 256 runs x 500 calls = 128,000 handler calls,
///      ~32,000 per action, ~500 per RUN), so pinning them changes no coverage — it only stops the
///      floor's premise from moving underneath it. `fail-on-revert = false` is what the handler's
///      try/catch already implies, restated so the two cannot drift apart.
/// forge-config: default.invariant.runs = 256
/// forge-config: default.invariant.depth = 500
/// forge-config: default.invariant.fail-on-revert = false
contract ChannelSettlementInvariantTest is CloseSettlementBase {
    SettlementHandler internal handler;

    function setUp() public override {
        super.setUp(); // deploys verifier/manager (3 members), wires mock MLE verdict=true
        bytes32 digest = _finalizeDefault(); // drive to Closed, fund = 75
        _materializeCloseFundingAuthorization(registry, manager, 0);

        bytes32[3] memory members = [USER_A, USER_B, USER_C];
        address[3] memory recipients = [alice, bob, carol];
        handler = new SettlementHandler(manager, verifier, registry, CHANNEL_ID, digest, members, recipients);
        vm.deal(address(handler), 1_000_000 ether);

        // Restrict fuzzing to the handler's four lifecycle actions.
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = SettlementHandler.pull.selector;
        selectors[1] = SettlementHandler.submitWithdrawal.selector;
        selectors[2] = SettlementHandler.submitPostClose.selector;
        selectors[3] = SettlementHandler.claim.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    /// I1 (SOLVENCY): the manager never credits out more ETH than it received for the channel.
    function invariant_I1_solvency() external view {
        assertLe(manager.totalCreditedOut(0), manager.receivedChannelFunds(0), "I1: out > received");
    }

    /// I2 (CONSERVATION): every accrued unit is either still owed (a credit) or already paid out.
    function invariant_I2_conservation() external view {
        uint256 sumCredits = manager.withdrawalCredits(0, alice) + manager.withdrawalCredits(0, bob)
            + manager.withdrawalCredits(0, carol);
        assertEq(
            manager.totalWithdrawn(0),
            manager.totalCreditedOut(0) + sumCredits,
            "I2: totalWithdrawn != totalCreditedOut + sumCredits"
        );
    }

    /// I3 (ACCRUAL CAP): claims can never accrue past the declared channel fund.
    function invariant_I3_accrualCap() external view {
        assertLe(manager.totalWithdrawn(0), manager.finalizedChannelFundAmount(0), "I3: accrual > fund");
    }

    /// I4 (ETH BACKING): channel backing plus separately tracked mixed-ledger surplus, less actual
    /// member payouts, exactly equals the Manager's native balance. Surplus must never appear in
    /// `receivedChannelFunds`, but it still physically remains in the Manager after the atomic pull.
    function invariant_I4_ethBacking() external view {
        assertEq(
            address(manager).balance,
            manager.receivedChannelFunds(0) + handler.ghostSurplus() - manager.totalCreditedOut(0),
            "I4: balance != received + surplus - creditedOut"
        );
    }

    /// I5 (TERMINAL): a finalized channel stays Closed; no action reopens it (which would let a
    /// second close re-finalize and reset accrual under live credits).
    function invariant_I5_terminalClosed() external view {
        assertTrue(
            manager.channelStatus() == ChannelSettlementManager.ChannelLifecycleStatus.Closed, "I5: channel left Closed"
        );
    }

    /// Cross-check the handler's independent ghost totals against the contract's accounting.
    ///
    /// NOTE (M-7): this is a SAFETY check and, on its own, a vacuous one — `0 == 0` satisfies it,
    /// which is exactly why `afterInvariant()` below exists. Read the two together: this one says
    /// the accounting agrees, that one says there WAS accounting to agree about.
    function invariant_ghost_consistency() external view {
        assertEq(manager.receivedChannelFunds(0), handler.ghostPulled(), "ghost: received != sumPulled");
        assertEq(manager.totalCreditedOut(0), handler.ghostPaid(), "ghost: creditedOut != sumPaid");
    }

    // ── I6 (LIVENESS) — audit28-08-2026 M-7 ─────────────────────────────────────────────────────
    //
    // THE DEFECT THIS CLOSES. Every invariant above is a `<=`, an `==` between two zeros, or a
    // status check, and all four handler actions swallow their reverts. Stub
    // `submitWithdrawalClaim` to `revert()` unconditionally — the honest member's ONLY way to turn
    // a closed channel into money — and I1–I5 plus `invariant_ghost_consistency` ALL still hold:
    // nothing is pulled, nothing accrues, nothing is credited out, the channel stays Closed. The
    // suite that exists to protect the exit path could not see the exit path being destroyed. That
    // is the same shape as gate-8 (an evaluator that cannot evaluate the real circuits, reported to
    // the honest user as "your proof is invalid") and as audit622 A-M4 (a VK no script installs):
    // a soundness-preserving, liveness-destroying failure that every soundness-shaped check passes.
    //
    // WHY `afterInvariant` AND NOT AN `invariant_` FUNCTION. Foundry evaluates `invariant_*` after
    // EVERY call in a sequence, including the first — where "no payout has happened yet" is the
    // correct state, so a floor there would fail every run at call 1. `afterInvariant()` runs once,
    // after the last call of each run, which is the only point at which "over a whole run, at least
    // one honest exit completed" is a meaningful statement. State is reset between runs, so this is
    // a PER-RUN floor: it must hold for all 256 of them, not merely once across the campaign.
    //
    // WHY IT IS NOT ITSELF VACUOUS. It asserts on `ghostPaid`, which is the ETH DELTA OBSERVED ON
    // THE RECIPIENT'S OWN BALANCE inside `SettlementHandler.claim` — not a contract-reported number
    // — and it requires the whole chain to have completed at least once: funds pulled in, a
    // withdrawal claim accrued, and a member's own `claimWithdrawalCredit` transferring real value
    // out. The per-action attempted/succeeded pairs make the failure diagnosable: an action class
    // that was DRIVEN hundreds of times in a run and NEVER once succeeded names itself in the
    // message.
    //
    // WHY THE FLOOR IS `> 0` PER ACTION AND NOT A RATIO. A ratio would encode the fuzzer's current
    // argument distribution, and legitimate revert rates here are high and sequence-dependent (the
    // 75-unit fund cap, nullifier reuse, empty credit). "Never once, in ~125 tries in this run" is
    // the property that is actually about the code rather than about the fuzzer.
    //
    // WHY THE TWO ACCRUAL PATHS GET AN UNCONDITIONAL *OR* FLOOR PLUS A FEASIBILITY-GATED PER-PATH
    // FLOOR — and how that shape was established rather than guessed. An unconditional per-path
    // floor on `submitPostCloseClaim` was written first and OBSERVED TO FAIL on a legitimate run.
    // The reason is real: both accrual paths draw on the SAME I3 ceiling (`finalizedChannelFundAmount`
    // = 75) while the handler's amounts run to 99, so a run typically lands only a handful of
    // successful accruals in total and then correctly refuses everything else — and whether those few
    // were withdrawals or post-close claims is decided by which selector the fuzzer drew first. That
    // is a statement about the fuzzer, not the contract, and a flaky liveness test gets deleted,
    // which is precisely how this coverage would evaporate a second time.
    //
    // So the per-path floor is gated on FEASIBILITY (`SettlementHandler.feasible*`, computed from the
    // headroom read immediately before each call): an attempt whose amount FIT under the remaining
    // ceiling is one the contract had no legitimate reason to refuse. `feasible > 0 && succeeded == 0`
    // is then exactly "this entry point is broken", with no dependence on draw order — and it is the
    // assertion that catches the audit's own example, `submitWithdrawalClaim` reverting
    // unconditionally, which the OR floor alone would NOT catch (post-close claims would simply take
    // the whole ceiling and the payout floor would still be met).
    function afterInvariant() external view {
        // 1. The fuzzer really drove every action class. If a selector were dropped from the
        //    `targetSelector` list, the floors below would be trivially unreachable and this says so
        //    with the right diagnosis.
        assertGt(handler.attemptedPull(), 0, "I6: the fuzzer never called pull()");
        assertGt(handler.attemptedWithdrawal(), 0, "I6: the fuzzer never called submitWithdrawal()");
        assertGt(handler.attemptedPostClose(), 0, "I6: the fuzzer never called submitPostClose()");
        assertGt(handler.attemptedClaim(), 0, "I6: the fuzzer never called claim()");

        // 2. Each action class succeeded at least once over the run.
        assertGt(
            handler.succeededPull(),
            0,
            "I6 LIVENESS: pullChannelFunds() never once succeeded -- the manager can never be funded"
        );
        assertGt(
            handler.succeededWithdrawal() + handler.succeededPostClose(),
            0,
            "I6 LIVENESS: NEITHER submitWithdrawalClaim() NOR submitPostCloseClaim() ever succeeded "
            "-- a closed channel's members can never accrue their exit by any route"
        );
        assertGt(
            handler.succeededClaim(),
            0,
            "I6 LIVENESS: claimWithdrawalCredit() never once succeeded -- accrued credit can never be "
            "turned into value"
        );

        // 3. Per-path, gated on feasibility: an attempt that FIT under the remaining I3 ceiling was
        //    refused anyway. This is the assertion that fires on a single bricked entry point, and
        //    it is draw-order independent, so it is a claim about the contract and not the fuzzer.
        if (handler.feasibleWithdrawal() > 0) {
            assertGt(
                handler.succeededWithdrawal(),
                0,
                "I6 LIVENESS: submitWithdrawalClaim() was called with an amount that fit under the "
                "remaining accrual ceiling and STILL never once succeeded -- the members' primary "
                "exit from a closed channel is bricked"
            );
        }
        // C-2 (audit28-08-2026, CRITICAL): `submitPostCloseClaim` is DELIBERATELY disabled — in
        // every closeable state the incoming delta has already been credited into the receiver's
        // slot (a close requires `unallocated_confirmed_incoming == 0`) while its tx hash is still
        // in the settled-tx accumulator, so the path double-credited one entitlement across two
        // disjoint nullifier domains. The liveness floor this replaces asserted the OPPOSITE — that
        // the path must succeed — and would now fail by design.
        //
        // This assertion PINS THE DISABLE: it fails the moment the path starts succeeding again,
        // so re-enabling `submitPostCloseClaim` without first landing an unapplied-incoming
        // commitment in H1 (or an applied/unapplied accumulator split) trips the invariant suite
        // rather than silently restoring the double-claim.
        assertEq(
            handler.succeededPostClose(),
            0,
            "C-2: submitPostCloseClaim() SUCCEEDED -- the double-credit path is supposed to be "
            "permanently disabled; re-enabling it requires an unapplied-incoming commitment in H1"
        );

        // 4. The property the whole suite is FOR: real ETH reached a real member.
        assertGt(
            handler.ghostPaid(),
            0,
            "I6 LIVENESS: not one wei ever reached a member over the whole run -- the honest exit is "
            "impossible and every safety invariant above is satisfied by zero"
        );
    }
}
