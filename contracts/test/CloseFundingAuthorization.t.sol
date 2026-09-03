// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CloseSettlementBase} from "./CloseSettlementBase.sol";
import {ChannelSettlementManager, IChannelRegistry} from "../src/ChannelSettlementManager.sol";
import {IERC20} from "../src/SafeERC20.sol";
import {SimpleERC20} from "./tokens/TestTokens.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";

/// @title Terminal close-funding authorization and mixed-ledger pull tests.
/// @notice Exercises only the Manager side of the existing proof-backed Rollup IPW2 lane. The
///         Rollup's withdrawal-proof binding and one-shot consumption have their own payout suites.
contract CloseFundingAuthorizationTest is CloseSettlementBase {
    event WithdrawalClaimed(
        bytes32 indexed withdrawalNullifier,
        address indexed recipient,
        uint32 indexed tokenIndex,
        uint256 amount
    );

    uint32 internal constant TOKEN_A = 55;
    SimpleERC20 internal tokenA;

    function setUp() public virtual override {
        super.setUp();
        tokenA = new SimpleERC20("TokenA");
        registry.setToken(TOKEN_A, IERC20(address(tokenA)));
    }

    function _twoTokenIntent(uint256 nativeFund, uint256 tokenFund)
        internal
        pure
        returns (ChannelSettlementManager.CloseIntent memory intent)
    {
        uint256[10] memory amounts;
        amounts[0] = nativeFund;
        amounts[1] = tokenFund;
        uint32[10] memory tokenRegistry;
        tokenRegistry[0] = 0;
        tokenRegistry[1] = TOKEN_A;
        return _intentWithTokens(1, 9, 22, 1, amounts, tokenRegistry, 2);
    }

    function _finalizeTwoToken(uint256 nativeFund, uint256 tokenFund)
        internal
        returns (ChannelSettlementManager.CloseIntent memory intent)
    {
        _requestCloseAndElapseGrace();
        intent = _twoTokenIntent(nativeFund, tokenFund);
        manager.submitCloseIntent(intent, _closeProof(intent));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
    }

    function _ipw2(uint32 tokenIndex, uint256 amount, bytes32 auxData) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(bytes4(0x49505732), address(manager), tokenIndex, amount, auxData));
    }

    function _imcf(
        uint256 chainId,
        address rollup,
        address managerAddress,
        bytes4 channelId,
        uint64 closeFreezeNonce,
        bytes32 fundsDigest
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(0x494d4346),
                chainId,
                rollup,
                managerAddress,
                channelId,
                closeFreezeNonce,
                fundsDigest
            )
        );
    }

    function _expectedAux(ChannelSettlementManager.CloseIntent memory intent) internal view returns (bytes32) {
        bytes32 fundsDigest =
            verifier.tokenFundsDigest(intent.tokenRegistry, intent.tokenCount, intent.channelFundAmounts);
        // Byte layout mirrors Rust close_funding_aux_data: 30 u32 words / 120 bytes total.
        return _imcf(block.chainid, address(registry), address(manager), CHANNEL_ID, 1, fundsDigest);
    }

    /// @dev Fixed vector produced by Rust `close_funding_aux_data` and independently checked over
    ///      the same 120-byte packed preimage. This catches integer-width/order drift across the
    ///      Rust artifact producer and Solidity authorization consumer.
    function test_imcf_matchesRustFixedGoldenVector() external pure {
        bytes32 got = keccak256(
            abi.encodePacked(
                bytes4(0x494d4346),
                uint256(1),
                address(0x1111111111111111111111111111111111111111),
                address(0x2222222222222222222222222222222222222222),
                uint32(7),
                uint64(4),
                bytes32(0x44987e3ca1c57257dfd4e9f5d6cc165f341cc4a9e5e0de7b6c06595105d27278)
            )
        );
        assertEq(got, bytes32(0x44bf64ff1965bdc482a566498e4f33854d01d3ba814e8f8a2e6b19a2823f5fc0));
    }

    function test_authorizeCloseFunding_rejectsEveryImcfBindingSubstitution() external {
        ChannelSettlementManager.CloseIntent memory intent = _finalizeTwoToken(75, 40);
        bytes32 fundsDigest =
            verifier.tokenFundsDigest(intent.tokenRegistry, intent.tokenCount, intent.channelFundAmounts);
        bytes32 expected = _expectedAux(intent);

        bytes32[6] memory substituted = [
            _imcf(block.chainid + 1, address(registry), address(manager), CHANNEL_ID, 1, fundsDigest),
            _imcf(block.chainid, address(0x1234), address(manager), CHANNEL_ID, 1, fundsDigest),
            _imcf(block.chainid, address(registry), address(0x5678), CHANNEL_ID, 1, fundsDigest),
            _imcf(block.chainid, address(registry), address(manager), bytes4(uint32(CHANNEL_ID) + 1), 1, fundsDigest),
            _imcf(block.chainid, address(registry), address(manager), CHANNEL_ID, 2, fundsDigest),
            _imcf(block.chainid, address(registry), address(manager), CHANNEL_ID, 1, bytes32(uint256(fundsDigest) ^ 1))
        ];
        for (uint256 i = 0; i < substituted.length; ++i) {
            vm.expectRevert(ChannelSettlementManager.CloseFundingAuxMismatch.selector);
            manager.authorizeCloseFunding(0, substituted[i]);
        }
        assertEq(manager.authorizeCloseFunding(0, expected), _ipw2(0, 75, expected), "all bindings preserved");
    }

    function test_authorizeCloseFunding_recomputesImcfAndExactIpw2() external {
        ChannelSettlementManager.CloseIntent memory intent = _finalizeTwoToken(75, 40);
        bytes32 expectedAux = _expectedAux(intent);
        vm.expectRevert(ChannelSettlementManager.CloseFundingAuxMismatch.selector);
        manager.authorizeCloseFunding(0, bytes32(uint256(expectedAux) ^ 1));

        bytes32 expectedNativeAuth = _ipw2(0, 75, expectedAux);
        assertEq(manager.authorizeCloseFunding(0, expectedAux), expectedNativeAuth, "exact native IPW2");
        assertTrue(registry.partialWithdrawalAuthorized(expectedNativeAuth), "Rollup flag installed");
        assertEq(registry.partialWithdrawalAuthorizationCalls(expectedNativeAuth), 1, "authorized once");

        bytes32 expectedTokenAuth = _ipw2(TOKEN_A, 40, expectedAux);
        assertEq(manager.authorizeCloseFunding(TOKEN_A, expectedAux), expectedTokenAuth, "exact token IPW2");
        assertTrue(registry.partialWithdrawalAuthorized(expectedTokenAuth), "token flag installed");

        // Any proof-side substitution derives a different IPW2 and therefore remains unauthorized.
        assertFalse(registry.partialWithdrawalAuthorized(_ipw2(0, 74, expectedAux)), "wrong amount");
        assertFalse(registry.partialWithdrawalAuthorized(_ipw2(0, 75, bytes32(uint256(expectedAux) ^ 1))), "wrong aux");
        assertFalse(registry.partialWithdrawalAuthorized(_ipw2(TOKEN_A, 75, expectedAux)), "wrong token");
    }

    function test_authorizeCloseFunding_failClosedBeforeCloseInvalidZeroAndReplay() external {
        vm.expectRevert(ChannelSettlementManager.CloseNotActive.selector);
        manager.authorizeCloseFunding(0, bytes32(0));

        ChannelSettlementManager.CloseIntent memory intent = _finalizeTwoToken(75, 0);
        bytes32 expectedAux = _expectedAux(intent);
        vm.expectRevert(abi.encodeWithSelector(ChannelSettlementManager.ChannelFundsAlreadyReceived.selector, 999));
        manager.authorizeCloseFunding(999, expectedAux);
        vm.expectRevert(abi.encodeWithSelector(ChannelSettlementManager.ChannelFundsAlreadyReceived.selector, TOKEN_A));
        manager.authorizeCloseFunding(TOKEN_A, expectedAux);

        manager.authorizeCloseFunding(0, expectedAux);
        vm.expectRevert(abi.encodeWithSelector(ChannelSettlementManager.CloseFundingAlreadyAuthorized.selector, 0));
        manager.authorizeCloseFunding(0, expectedAux);
    }

    function test_authorizeCloseFunding_rollupRevertRollsBackLifetimeLatch() external {
        _finalizeWithFund(75);
        bytes32 expectedAux = _expectedAux(_intentWithFund(1, 9, 22, 1, 75));
        bytes32 authDigest = _ipw2(0, 75, expectedAux);
        vm.mockCallRevert(
            address(registry),
            abi.encodeCall(IChannelRegistry.authorizePartialWithdrawal, (authDigest)),
            bytes("rollup authorization failed")
        );
        vm.expectRevert(bytes("rollup authorization failed"));
        manager.authorizeCloseFunding(0, expectedAux);
        vm.clearMockedCalls();
        assertEq(manager.authorizeCloseFunding(0, expectedAux), authDigest, "revert rolled bitmap back");
    }

    function test_pullNative_transfersExactCapAndLeavesSurplusOnRollup() external {
        bytes32 digest = _finalizeWithFund(75);
        ChannelSettlementManager.WithdrawalClaim memory claim = _withdrawalClaim(digest, USER_A, alice, 75);
        manager.submitWithdrawalClaim(claim, _withdrawalClaimProof(claim));

        // Five units are unrelated recipient-wide credit. The exact terminal proof authorization
        // is issued+consumed independently, then its 75-unit payout joins the same Rollup ledger.
        vm.deal(address(this), address(this).balance + 80);
        registry.creditWithdrawal{value: 5}(address(manager));
        _materializeCloseFundingAuthorization(registry, manager, 0);
        registry.creditWithdrawal{value: 75}(address(manager));
        assertEq(manager.pullChannelFunds(), 75, "exact close cap transferred");
        assertEq(manager.receivedChannelFunds(0), 75, "close cap is exact channel backing");
        assertEq(address(manager).balance, 75, "manager receives no unrelated surplus");
        assertEq(registry.pendingWithdrawals(address(manager)), 5, "surplus remains on rollup");

        vm.prank(alice);
        manager.claimWithdrawalCredit(claim.withdrawalNullifier);
        assertEq(alice.balance, 75, "member receives exact cap only");
        assertEq(address(manager).balance, 0, "only channel backing was available to members");
        assertEq(registry.pendingWithdrawals(address(manager)), 5, "third-party credit was not swept");
        assertEq(manager.totalCreditedOut(0), 75);

        bytes32 expectedAux = _expectedAux(_intentWithFund(1, 9, 22, 1, 75));
        vm.expectRevert(abi.encodeWithSelector(ChannelSettlementManager.ChannelFundsAlreadyReceived.selector, 0));
        manager.authorizeCloseFunding(0, expectedAux);
    }

    function test_pullNative_underfundRevertsRollupAndManagerAccountingAtomically() external {
        _finalizeWithFund(75);
        _materializeCloseFundingAuthorization(registry, manager, 0);
        vm.deal(address(this), address(this).balance + 74);
        registry.creditWithdrawal{value: 74}(address(manager));
        vm.expectRevert(abi.encodeWithSelector(ChannelSettlementManager.ChannelFundingMismatch.selector, 0, 75, 74));
        manager.pullChannelFunds();
        assertEq(registry.pendingWithdrawals(address(manager)), 74, "Rollup debit reverted");
        assertEq(address(manager).balance, 0, "transfer reverted");
        assertEq(manager.receivedChannelFunds(0), 0, "no partial channel credit");
    }

    function test_pullToken_transfersExactCapAndLeavesSurplusOnRollup() external {
        _finalizeTwoToken(10, 40);
        _materializeCloseFundingAuthorization(registry, manager, TOKEN_A);
        tokenA.mint(address(registry), 47);
        registry.creditTokenWithdrawal(TOKEN_A, address(manager), 47);
        assertEq(manager.pullChannelTokenFunds(TOKEN_A), 40, "exact token cap transferred");
        assertEq(manager.receivedChannelFunds(TOKEN_A), 40, "close cap is exact token backing");
        assertEq(tokenA.balanceOf(address(manager)), 40, "manager receives no token surplus");
        assertEq(
            registry.pendingTokenWithdrawals(TOKEN_A, address(manager)), 7, "token surplus remains on rollup"
        );
    }

    function test_pullToken_underfundAndInvalidTokenFailClosed() external {
        _finalizeTwoToken(10, 40);
        vm.expectRevert(ChannelSettlementManager.TokenIndexNotRegisteredOnRollup.selector);
        manager.pullChannelTokenFunds(999);
        registry.setToken(999, IERC20(address(tokenA)));
        vm.expectRevert(abi.encodeWithSelector(ChannelSettlementManager.ChannelFundsAlreadyReceived.selector, 999));
        manager.pullChannelTokenFunds(999);

        _materializeCloseFundingAuthorization(registry, manager, TOKEN_A);
        tokenA.mint(address(registry), 39);
        registry.creditTokenWithdrawal(TOKEN_A, address(manager), 39);
        vm.expectRevert(
            abi.encodeWithSelector(ChannelSettlementManager.ChannelFundingMismatch.selector, TOKEN_A, 40, 39)
        );
        manager.pullChannelTokenFunds(TOKEN_A);
        assertEq(registry.pendingTokenWithdrawals(TOKEN_A, address(manager)), 39, "Rollup token debit reverted");
        assertEq(tokenA.balanceOf(address(manager)), 0, "token transfer reverted");
        assertEq(manager.receivedChannelFunds(TOKEN_A), 0, "no partial token credit");
    }

    function test_claimNullifier_isStableAcrossSameRecipientCreditRaceAndUnscopedApisRevert() external {
        bytes32 digest = _finalizeWithFund(75);
        ChannelSettlementManager.WithdrawalClaim memory first =
            _withdrawalClaimSalted(digest, USER_A, alice, 30, 1);
        ChannelSettlementManager.WithdrawalClaim memory concurrent =
            _withdrawalClaimSalted(digest, USER_A, alice, 20, 2);
        manager.submitWithdrawalClaim(first, _withdrawalClaimProof(first));
        manager.submitWithdrawalClaim(concurrent, _withdrawalClaimProof(concurrent));
        _fundAndPull(registry, manager, 75);

        (address firstRecipient, uint32 firstToken, uint256 firstAmount) =
            manager.withdrawalPayouts(first.withdrawalNullifier);
        assertEq(firstRecipient, alice);
        assertEq(firstToken, 0);
        assertEq(firstAmount, 30);

        uint256 before = alice.balance;
        vm.expectEmit(true, true, true, true, address(manager));
        emit WithdrawalClaimed(first.withdrawalNullifier, alice, 0, 30);
        vm.prank(alice);
        assertEq(manager.claimWithdrawalCredit(first.withdrawalNullifier), 30, "proof-scoped amount paid exactly");
        assertEq(alice.balance - before, 30, "event amount equals transfer amount");
        assertEq(manager.withdrawalCredits(0, alice), 20, "concurrent credit remains claimable");
        assertEq(manager.totalCreditedOut(0), 30, "only exact amount accounted");
        (,, uint256 paidRecordAmount) = manager.withdrawalPayouts(first.withdrawalNullifier);
        assertEq(paidRecordAmount, 0, "paid payout record deleted");
        (,, uint256 concurrentAmount) = manager.withdrawalPayouts(concurrent.withdrawalNullifier);
        assertEq(concurrentAmount, 20, "other proof payout remains intact");

        vm.prank(bob);
        vm.expectRevert(ChannelSettlementManager.WithdrawalPayoutRecipientMismatch.selector);
        manager.claimWithdrawalCredit(concurrent.withdrawalNullifier);

        vm.startPrank(alice);
        (bool noArgOk, bytes memory noArgData) =
            address(manager).call(abi.encodeWithSignature("claimWithdrawalCredit()"));
        assertFalse(noArgOk, "removed aggregate claim selector unexpectedly succeeded");
        assertEq(noArgData.length, 0, "removed aggregate claim selector unexpectedly has an active decoder");
        (bool tokenOk, bytes memory tokenData) =
            address(manager).call(abi.encodeWithSignature("claimWithdrawalCredit(uint32)", uint32(0)));
        assertFalse(tokenOk, "removed token aggregate claim selector unexpectedly succeeded");
        assertEq(tokenData.length, 0, "removed token aggregate claim selector unexpectedly has an active decoder");
        (bool amountOk, bytes memory amountData) = address(manager).call(
            abi.encodeWithSignature("claimWithdrawalCredit(uint32,uint256)", uint32(0), uint256(20))
        );
        assertFalse(amountOk, "removed amount aggregate claim selector unexpectedly succeeded");
        assertEq(amountData.length, 0, "removed amount aggregate claim selector unexpectedly has an active decoder");
        vm.expectRevert(ChannelSettlementManager.NoWithdrawalCredit.selector);
        manager.claimWithdrawalCredit(first.withdrawalNullifier);
        assertEq(manager.claimWithdrawalCredit(concurrent.withdrawalNullifier), 20, "second proof pays independently");
        vm.stopPrank();
        assertEq(manager.withdrawalCredits(0, alice), 0);
        assertEq(manager.totalCreditedOut(0), 50);
    }

    function test_claimNullifier_erc20TransfersOnlyProofScopedAmounts() external {
        ChannelSettlementManager.CloseIntent memory intent = _finalizeTwoToken(10, 40);
        bytes32 digest = manager.computeCloseIntentDigest(intent);
        ChannelSettlementManager.WithdrawalClaim memory first =
            _withdrawalClaimToken(digest, USER_A, alice, 17, 1, TOKEN_A);
        ChannelSettlementManager.WithdrawalClaim memory second =
            _withdrawalClaimToken(digest, USER_B, alice, 23, 1, TOKEN_A);
        manager.submitWithdrawalClaim(first, _withdrawalClaimProof(first));
        manager.submitWithdrawalClaim(second, _withdrawalClaimProof(second));

        _materializeCloseFundingAuthorization(registry, manager, TOKEN_A);
        tokenA.mint(address(registry), 40);
        registry.creditTokenWithdrawal(TOKEN_A, address(manager), 40);
        manager.pullChannelTokenFunds(TOKEN_A);

        vm.prank(alice);
        assertEq(manager.claimWithdrawalCredit(first.withdrawalNullifier), 17, "first proof amount paid exactly");
        assertEq(tokenA.balanceOf(alice), 17, "only exact ERC-20 amount transferred");
        assertEq(manager.withdrawalCredits(TOKEN_A, alice), 23, "remaining token credit preserved");
        assertEq(manager.totalCreditedOut(TOKEN_A), 17, "only exact token amount accounted");

        vm.prank(alice);
        assertEq(manager.claimWithdrawalCredit(second.withdrawalNullifier), 23, "second proof pays independently");
        assertEq(tokenA.balanceOf(alice), 40);
        assertEq(manager.withdrawalCredits(TOKEN_A, alice), 0);
        assertEq(manager.totalCreditedOut(TOKEN_A), 40);
    }

    function test_genericManagerCreditCannotSubstituteForTerminalProofMaterialization() external {
        ChannelSettlementManager.CloseIntent memory intent = _finalizeTwoToken(75, 40);
        bytes32 auxData = _expectedAux(intent);

        vm.deal(address(this), address(this).balance + 75);
        registry.creditWithdrawal{value: 75}(address(manager));
        vm.expectRevert(
            abi.encodeWithSelector(ChannelSettlementManager.CloseFundingProofNotMaterialized.selector, 0)
        );
        manager.pullChannelFunds();

        bytes32 authDigest = manager.authorizeCloseFunding(0, auxData);
        assertTrue(registry.partialWithdrawalAuthorized(authDigest), "terminal authorization issued");
        vm.expectRevert(
            abi.encodeWithSelector(ChannelSettlementManager.CloseFundingProofNotMaterialized.selector, 0)
        );
        manager.pullChannelFunds();

        // Test-only image of the exact Rollup proof consuming IPW2. Only now may the exact cap be
        // pulled; a real execution also credits this same amount in the consumption transaction.
        registry.consumePartialWithdrawalAuthorization(authDigest);
        assertEq(manager.pullChannelFunds(), 75, "issued+consumed terminal authorization unlocks pull");
    }
}

/// @notice Regression tests for the release R3 fix: terminal authorization and proof consumption
///         are one all-or-nothing operation over a COMPLETE asset lane.
contract AtomicCloseFundingMaterializerTest is CloseFundingAuthorizationTest {
    uint32 internal constant TOKEN_B = 56;
    CloseFundingMaterializer internal materializer;

    event CloseFundingMaterialized(
        address indexed manager,
        uint8 indexed lane,
        bytes32 indexed fundingAuxData,
        bytes32 withdrawalSetDigest
    );

    function setUp() public override {
        super.setUp();
        materializer = new CloseFundingMaterializer(IntmaxRollup(payable(address(registry))));
    }

    function _activateAtomicManager() private {
        manager = _deployManagerWithMaterializer(registry, alice, bob, carol, address(materializer));
    }

    function _withdrawal(uint32 tokenIndex, uint256 amount, bytes32 nullifier, bytes32 auxData)
        private
        view
        returns (IntmaxRollup.Withdrawal memory)
    {
        return IntmaxRollup.Withdrawal({
            recipient: address(manager),
            tokenIndex: tokenIndex,
            amount: amount,
            nullifier: nullifier,
            auxData: auxData
        });
    }

    function test_atomicNative_authorizeAndConsumeHasNoExposedIntermediateState() external {
        _activateAtomicManager();
        ChannelSettlementManager.CloseIntent memory intent = _finalizeTwoToken(75, 40);
        bytes32 auxData = _expectedAux(intent);
        IntmaxRollup.Withdrawal[] memory withdrawals = new IntmaxRollup.Withdrawal[](1);
        withdrawals[0] = _withdrawal(0, 75, keccak256("competitor-nullifier"), auxData);
        bytes memory proof;

        vm.expectEmit(true, true, true, true, address(materializer));
        emit CloseFundingMaterialized(address(manager), 0, auxData, keccak256(abi.encode(withdrawals)));
        materializer.materializeNative(manager, withdrawals, address(0xBEEF), proof);

        assertFalse(registry.partialWithdrawalAuthorized(_ipw2(0, 75, auxData)), "IPW2 consumed atomically");
        assertEq(registry.pendingWithdrawals(address(manager)), 75, "complete native lane credited");
        vm.expectRevert(ChannelSettlementManager.OnlyCloseFundingMaterializer.selector);
        manager.authorizeCloseFunding(TOKEN_A, auxData);
    }

    function test_atomicErc20_rejectsPartialLaneBeforeAnyAuthorization() external {
        _activateAtomicManager();
        uint256[10] memory amounts;
        amounts[0] = 10;
        amounts[1] = 40;
        amounts[2] = 30;
        uint32[10] memory tokenRegistry;
        tokenRegistry[0] = 0;
        tokenRegistry[1] = TOKEN_A;
        tokenRegistry[2] = TOKEN_B;
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intentWithTokens(1, 9, 22, 1, amounts, tokenRegistry, 3);
        manager.submitCloseIntent(intent, _closeProof(intent));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        bytes32 auxData = _expectedAux(intent);
        bytes memory proof;

        IntmaxRollup.Withdrawal[] memory partialLane = new IntmaxRollup.Withdrawal[](1);
        partialLane[0] = _withdrawal(TOKEN_A, 40, keccak256("partial-a"), auxData);
        vm.expectRevert(
            abi.encodeWithSelector(CloseFundingMaterializer.FundingLaneLengthMismatch.selector, 2, 1)
        );
        materializer.materializeERC20(manager, partialLane, address(0xBEEF), proof);
        assertFalse(registry.partialWithdrawalAuthorized(_ipw2(TOKEN_A, 40, auxData)));
        assertFalse(registry.partialWithdrawalAuthorized(_ipw2(TOKEN_B, 30, auxData)));

        IntmaxRollup.Withdrawal[] memory complete = new IntmaxRollup.Withdrawal[](2);
        complete[0] = _withdrawal(TOKEN_A, 40, keccak256("complete-a"), auxData);
        complete[1] = _withdrawal(TOKEN_B, 30, keccak256("complete-b"), auxData);
        materializer.materializeERC20(manager, complete, address(0xBEEF), proof);
        assertEq(registry.pendingTokenWithdrawals(TOKEN_A, address(manager)), 40);
        assertEq(registry.pendingTokenWithdrawals(TOKEN_B, address(manager)), 30);
    }

    function test_atomicWithdrawalRevert_rollsBackEveryManagerLatch() external {
        _activateAtomicManager();
        ChannelSettlementManager.CloseIntent memory intent = _finalizeTwoToken(75, 40);
        bytes32 auxData = _expectedAux(intent);
        IntmaxRollup.Withdrawal[] memory withdrawals = new IntmaxRollup.Withdrawal[](1);
        withdrawals[0] = _withdrawal(0, 75, keccak256("retryable-nullifier"), auxData);
        bytes memory proof;

        registry.setRejectAtomicWithdrawal(true);
        vm.expectRevert(bytes("atomic withdrawal rejected"));
        materializer.materializeNative(manager, withdrawals, address(0xBEEF), proof);
        assertFalse(registry.partialWithdrawalAuthorized(_ipw2(0, 75, auxData)));
        assertEq(registry.pendingWithdrawals(address(manager)), 0);

        registry.setRejectAtomicWithdrawal(false);
        materializer.materializeNative(manager, withdrawals, address(0xBEEF), proof);
        assertEq(registry.pendingWithdrawals(address(manager)), 75, "same intent remains retryable");
    }
}
