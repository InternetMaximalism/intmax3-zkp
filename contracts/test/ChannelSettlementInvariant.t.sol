// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {CloseSettlementBase, MockRollupRegistry} from "./CloseSettlementBase.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
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

    // ghost counters to force distinct nullifiers across calls
    uint256 internal wdSalt;
    uint256 internal pcNonce;

    // ghost totals for cross-checking (independent of the contract's own accounting)
    uint256 public ghostPulled; // Σ ETH actually pulled into the manager
    uint256 public ghostPaid; // Σ ETH actually paid out to members

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

    // ── actions (whitelisted as fuzz targets) ──

    /// Credit the manager via the rollup, then pull it in. amount bounded so the handler never runs
    /// dry and so both under- and over-funding (vs the 75 fund) are explored.
    function pull(uint96 amount) external {
        uint256 amt = uint256(amount) % 200 + 1; // [1, 200]
        if (address(this).balance < amt) return;
        registry.creditWithdrawal{value: amt}(address(manager));
        try manager.pullChannelFunds() returns (uint256 pulled) {
            ghostPulled += pulled;
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
            withdrawalNullifier: keccak256(abi.encodePacked("wd", digest, members[i], wdSalt))
        });
        wdSalt += 1;
        uint256[] memory limbs = verifier.expectedWithdrawalClaimLimbs(
            channelId, c.closeIntentDigest, manager.finalizedBalanceStateH1(),
            c.memberPkG, c.recipient, c.userAmountDigest, c.amount, c.withdrawalNullifier
        );
        try manager.submitWithdrawalClaim(c, CloseTestLib.proofWithLimbs(limbs)) {} catch {}
    }

    function submitPostClose(uint256 memberSeed, uint64 amount) external {
        uint256 i = memberSeed % 3;
        uint64 amt = uint64(amount % 100);
        bytes32 incomingTx = keccak256(abi.encodePacked("pc", pcNonce));
        pcNonce += 1;
        bytes32 snn = keccak256(abi.encodePacked(bytes4(uint32(0x494d434b)), digest, incomingTx, members[i]));
        uint256[] memory limbs = verifier.expectedPostCloseClaimLimbs(
            channelId, digest, incomingTx, members[i], recipients[i], snn, amt,
            manager.finalizedBalanceStateH1(), manager.finalizedSettledTxAccumulatorRoot()
        );
        ChannelSettlementManager.PostCloseClaim memory c = ChannelSettlementManager.PostCloseClaim({
            closeIntentDigest: digest,
            incomingTxHash: incomingTx,
            receiverPkG: members[i],
            recipient: recipients[i],
            amount: amt
        });
        try manager.submitPostCloseClaim(c, CloseTestLib.proofWithLimbs(limbs)) {} catch {}
    }

    function claim(uint256 recipientSeed) external {
        address r = recipients[recipientSeed % 3];
        uint256 balBefore = r.balance;
        vm.prank(r);
        try manager.claimWithdrawalCredit() returns (uint256) {
            ghostPaid += (r.balance - balBefore);
        } catch {}
    }
}

/// @title ChannelSettlementInvariantTest
/// @notice Global accounting invariants for a closed channel under arbitrary payout sequences
///         (scenario G / invariants I1–I5). A violation of ANY of these is a fund-safety bug.
contract ChannelSettlementInvariantTest is CloseSettlementBase {
    SettlementHandler internal handler;

    function setUp() public override {
        super.setUp(); // deploys verifier/manager (3 members), wires mock MLE verdict=true
        bytes32 digest = _finalizeDefault(); // drive to Closed, fund = 75

        bytes32[3] memory members = [USER_A, USER_B, USER_C];
        address[3] memory recipients = [alice, bob, carol];
        handler = new SettlementHandler(
            manager, verifier, registry, CHANNEL_ID, digest, members, recipients
        );
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
        assertLe(manager.totalCreditedOut(), manager.receivedChannelFunds(), "I1: out > received");
    }

    /// I2 (CONSERVATION): every accrued unit is either still owed (a credit) or already paid out.
    function invariant_I2_conservation() external view {
        uint256 sumCredits = manager.withdrawalCredits(alice)
            + manager.withdrawalCredits(bob) + manager.withdrawalCredits(carol);
        assertEq(
            manager.totalWithdrawn(),
            manager.totalCreditedOut() + sumCredits,
            "I2: totalWithdrawn != totalCreditedOut + sumCredits"
        );
    }

    /// I3 (ACCRUAL CAP): claims can never accrue past the declared channel fund.
    function invariant_I3_accrualCap() external view {
        assertLe(manager.totalWithdrawn(), manager.finalizedChannelFundAmount(), "I3: accrual > fund");
    }

    /// I4 (ETH BACKING): the manager's native balance always equals received-minus-paid, so unpaid
    /// credits are always backed by held ETH up to the received ceiling.
    function invariant_I4_ethBacking() external view {
        assertEq(
            address(manager).balance,
            manager.receivedChannelFunds() - manager.totalCreditedOut(),
            "I4: balance != received - creditedOut"
        );
    }

    /// I5 (TERMINAL): a finalized channel stays Closed; no action reopens it (which would let a
    /// second close re-finalize and reset accrual under live credits).
    function invariant_I5_terminalClosed() external view {
        assertTrue(
            manager.channelStatus() == ChannelSettlementManager.ChannelLifecycleStatus.Closed,
            "I5: channel left Closed"
        );
    }

    /// Cross-check the handler's independent ghost totals against the contract's accounting.
    function invariant_ghost_consistency() external view {
        assertEq(manager.receivedChannelFunds(), handler.ghostPulled(), "ghost: received != sumPulled");
        assertEq(manager.totalCreditedOut(), handler.ghostPaid(), "ghost: creditedOut != sumPaid");
    }
}
