// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CloseFundingAuthorizationTest} from "./CloseFundingAuthorization.t.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {IERC20} from "../src/SafeERC20.sol";
import {ReentrantHookERC20} from "./tokens/TestTokens.sol";

/// Callback storage tests for the real Manager with the existing mock registry
/// and mock cryptographic verifier. No production proof-system claim is made.
contract FundingCallbackTest is CloseFundingAuthorizationTest {
    ReentrantHookERC20 internal callbackToken;
    bytes32 internal constant LATE_KEY = keccak256("funding callback late receipt");

    function _callbackFixture(uint256 rollupCredit) internal {
        callbackToken = new ReentrantHookERC20();
        registry.setToken(TOKEN_A, IERC20(address(callbackToken)));
        _finalizeTwoToken(10, 40);
        _materializeCloseFundingAuthorization(registry, manager, TOKEN_A);
        callbackToken.mint(address(registry), rollupCredit);
        registry.creditTokenWithdrawal(TOKEN_A, address(manager), rollupCredit);
    }

    function _ordinaryHook() internal returns (bytes32 key) {
        ChannelSettlementManager.WithdrawalClaim memory claim =
            _withdrawalClaimToken(manager.finalizedCloseIntentDigest(), bytes32(uint256(7)), alice, 13, 1, TOKEN_A);
        callbackToken.setHook(
            address(manager),
            abi.encodeCall(manager.submitWithdrawalClaim, (claim, _withdrawalClaimProof(claim))),
            false
        );
        return claim.withdrawalNullifier;
    }

    function test_callbackOrdinaryAccrualSurvivesFundingWrite() external {
        _callbackFixture(40);
        bytes32 key = _ordinaryHook();
        assertEq(manager.pullChannelTokenFunds(TOKEN_A), 40);
        assertFalse(callbackToken.hookReverted());
        assertTrue(manager.usedWithdrawalNullifiers(key));
        assertEq(manager.totalWithdrawn(TOKEN_A), 13);
        (address recipient, uint32 token, uint256 amount) = manager.withdrawalPayouts(key);
        assertEq(recipient, alice);
        assertEq(token, TOKEN_A);
        assertEq(amount, 13);
        assertEq(manager.receivedChannelFunds(TOKEN_A), 40);
        vm.prank(alice);
        manager.claimWithdrawalCredit(key);
        assertEq(callbackToken.balanceOf(alice), 13);
        assertEq(manager.totalCreditedOut(TOKEN_A), 13);
    }

    /// This fixture is the configured materializer. The token reaches it as a
    /// callback; the pre-funded mock ledger stands in for receipt escrow credit.
    function creditDuringTransfer() external {
        require(msg.sender == address(callbackToken), "only callback token");
        manager.creditLateIncoming(TOKEN_A, 17, alice, LATE_KEY);
    }

    function test_callbackLateCapUsesSnapshotThenRemainsPullable() external {
        _callbackFixture(57);
        callbackToken.setHook(address(this), abi.encodeCall(this.creditDuringTransfer, ()), false);
        assertEq(manager.pullChannelTokenFunds(TOKEN_A), 40);
        assertFalse(callbackToken.hookReverted());
        assertEq(manager.lateIncomingFundAmount(TOKEN_A), 17);
        assertEq(manager.totalWithdrawn(TOKEN_A), 17);
        assertEq(manager.receivedChannelFunds(TOKEN_A), 40, "write uses pre-call cap");
        assertEq(registry.pendingTokenWithdrawals(TOKEN_A, address(manager)), 17);
        assertEq(manager.pullChannelTokenFunds(TOKEN_A), 17);
        assertEq(manager.receivedChannelFunds(TOKEN_A), 57);
        vm.prank(alice);
        manager.claimWithdrawalCredit(LATE_KEY);
        assertEq(callbackToken.balanceOf(alice), 17);
    }

    function test_callbackAccrualRollsBackWhenTransferUnderDelivers() external {
        _callbackFixture(39);
        bytes32 key = _ordinaryHook();
        vm.expectRevert(
            abi.encodeWithSelector(ChannelSettlementManager.ChannelFundingMismatch.selector, TOKEN_A, 40, 39)
        );
        manager.pullChannelTokenFunds(TOKEN_A);
        assertFalse(manager.usedWithdrawalNullifiers(key));
        assertEq(manager.totalWithdrawn(TOKEN_A), 0);
        assertEq(manager.receivedChannelFunds(TOKEN_A), 0);
        (,, uint256 amount) = manager.withdrawalPayouts(key);
        assertEq(amount, 0);
        assertEq(callbackToken.balanceOf(address(manager)), 0);
        assertEq(registry.pendingTokenWithdrawals(TOKEN_A, address(manager)), 39);
    }

    function test_callbackNestedFundingRejectsWithoutDoubleReceipt() external {
        _callbackFixture(40);
        callbackToken.setHook(address(manager), abi.encodeCall(manager.pullChannelTokenFunds, (TOKEN_A)), false);
        assertEq(manager.pullChannelTokenFunds(TOKEN_A), 40);
        assertTrue(callbackToken.hookReverted());
        assertEq(manager.receivedChannelFunds(TOKEN_A), 40);
        assertEq(callbackToken.balanceOf(address(manager)), 40);
    }
}
