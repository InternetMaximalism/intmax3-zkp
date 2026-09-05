// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CloseSettlementBase} from "./CloseSettlementBase.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {IERC20} from "../src/SafeERC20.sol";
import {SimpleERC20} from "./tokens/TestTokens.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";

/// @title Close-funding tombstones and mixed-ledger pull tests.
/// @notice The cooperative terminal-child/IPW2 route (`authorizeCloseFunding`,
///         `materializeNative`, `materializeERC20`) was retired in commit 8f70b73. Its selectors
///         are ABI-retained fail-closed tombstones that revert `CooperativeCloseFundingDeprecated`
///         before reading any argument. A close is funded only by the signer-independent exit
///         (`attestSignedHeadBacking` + `materializeSignedHead`, covered by
///         `SignerIndependentExit.t.sol`); this suite simulates that receipt through
///         `CloseSettlementBase._materializeCloseFundingAuthorization` and exercises the Manager's
///         exact-cap pull and per-nullifier claim accounting on top of it.
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

    /// @dev Historical IPW2 shape. Only used to prove the retired route installs NO rollup flag.
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

    /// @dev The aux the retired route used to require. Handed to the tombstones so they are shown
    ///      to reject even a well-formed request.
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

    // ── retired cooperative route: ABI-retained fail-closed tombstones ──

    /// The Manager's retired selector reverts `CooperativeCloseFundingDeprecated` in every lifecycle
    /// state, for every token index and aux — including the exact aux it once accepted — and the
    /// revert carries the typed error (the selector is retained, not removed).
    function test_authorizeCloseFunding_isTombstoneInEveryStateTokenAndAux() external {
        // Active: the old CloseNotActive gate is unreachable; the tombstone fires first.
        vm.expectRevert(ChannelSettlementManager.CooperativeCloseFundingDeprecated.selector);
        manager.authorizeCloseFunding(0, bytes32(0));

        ChannelSettlementManager.CloseIntent memory intent = _finalizeTwoToken(75, 40);
        bytes32 aux = _expectedAux(intent);
        uint32[4] memory tokens = [uint32(0), TOKEN_A, 999, type(uint32).max];
        bytes32[3] memory auxes = [aux, bytes32(uint256(aux) ^ 1), bytes32(0)];
        for (uint256 i = 0; i < tokens.length; ++i) {
            for (uint256 j = 0; j < auxes.length; ++j) {
                vm.expectRevert(ChannelSettlementManager.CooperativeCloseFundingDeprecated.selector);
                manager.authorizeCloseFunding(tokens[i], auxes[j]);
            }
        }

        (bool ok, bytes memory revertData) = address(manager).call(
            abi.encodeWithSelector(manager.authorizeCloseFunding.selector, uint32(0), aux)
        );
        assertFalse(ok, "retired authorizeCloseFunding unexpectedly succeeded");
        assertEq(
            revertData,
            abi.encodeWithSelector(ChannelSettlementManager.CooperativeCloseFundingDeprecated.selector),
            "retired selector must fail with the explicit typed error"
        );

        // No historical IPW2 flag was installed and the channel is not materialized.
        assertFalse(registry.partialWithdrawalAuthorized(_ipw2(0, 75, aux)), "native IPW2 not installed");
        assertFalse(registry.partialWithdrawalAuthorized(_ipw2(TOKEN_A, 40, aux)), "token IPW2 not installed");
        assertEq(registry.partialWithdrawalAuthorizationCalls(_ipw2(0, 75, aux)), 0, "rollup never called");
        assertEq(materializedChannelExit[uint32(CHANNEL_ID)], bytes32(0), "retired call did not materialize");
    }

    /// The immutable materializer's retired terminal-child entry points are tombstones that revert
    /// before validating the manager, the withdrawal vector, or the proof.
    function test_materializerTerminalChildRoutesAreTombstones() external {
        CloseFundingMaterializer materializer = new CloseFundingMaterializer(
            IntmaxRollup(payable(address(registry))),
            IPinnedMleVerifierV2(address(new MockPinnedMleVerifierV2(block.chainid)))
        );
        ChannelSettlementManager.CloseIntent memory intent = _finalizeTwoToken(75, 40);
        bytes32 aux = _expectedAux(intent);
        bytes memory proof;

        IntmaxRollup.Withdrawal[] memory native = new IntmaxRollup.Withdrawal[](1);
        native[0] = IntmaxRollup.Withdrawal({
            recipient: address(manager),
            tokenIndex: 0,
            amount: 75,
            nullifier: keccak256("retired-native-nullifier"),
            auxData: aux
        });
        IntmaxRollup.Withdrawal[] memory erc20 = new IntmaxRollup.Withdrawal[](1);
        erc20[0] = IntmaxRollup.Withdrawal({
            recipient: address(manager),
            tokenIndex: TOKEN_A,
            amount: 40,
            nullifier: keccak256("retired-erc20-nullifier"),
            auxData: aux
        });

        // Well-formed complete lanes against the finalized manager.
        vm.expectRevert(CloseFundingMaterializer.CooperativeCloseFundingDeprecated.selector);
        materializer.materializeNative(manager, native, address(0xBEEF), proof);
        vm.expectRevert(CloseFundingMaterializer.CooperativeCloseFundingDeprecated.selector);
        materializer.materializeERC20(manager, erc20, address(0xBEEF), proof);

        // Degenerate inputs: the tombstone fires ahead of NotBoundManager / lane-shape checks.
        IntmaxRollup.Withdrawal[] memory empty = new IntmaxRollup.Withdrawal[](0);
        ChannelSettlementManager unbound = ChannelSettlementManager(payable(address(0)));
        vm.expectRevert(CloseFundingMaterializer.CooperativeCloseFundingDeprecated.selector);
        materializer.materializeNative(unbound, empty, address(0), proof);
        vm.expectRevert(CloseFundingMaterializer.CooperativeCloseFundingDeprecated.selector);
        materializer.materializeERC20(unbound, empty, address(0), proof);

        (bool ok, bytes memory revertData) = address(materializer).call(
            abi.encodeWithSelector(materializer.materializeNative.selector, manager, native, address(0xBEEF), proof)
        );
        assertFalse(ok, "retired materializeNative unexpectedly succeeded");
        assertEq(
            revertData,
            abi.encodeWithSelector(CloseFundingMaterializer.CooperativeCloseFundingDeprecated.selector),
            "retired selector must fail with the explicit typed error"
        );

        assertFalse(registry.partialWithdrawalAuthorized(_ipw2(0, 75, aux)), "native IPW2 not installed");
        assertFalse(registry.partialWithdrawalAuthorized(_ipw2(TOKEN_A, 40, aux)), "token IPW2 not installed");
        assertEq(registry.pendingWithdrawals(address(manager)), 0, "no native credit");
        assertEq(registry.pendingTokenWithdrawals(TOKEN_A, address(manager)), 0, "no token credit");
        assertEq(materializer.materializedChannelExit(uint32(CHANNEL_ID)), bytes32(0), "no exit recorded");
    }

    /// Generic recipient-wide credit plus the retired route can neither move value nor make the
    /// Manager pull-ready. Only the signed-head materialization receipt unlocks the exact cap.
    function test_retiredRouteCannotMoveValueOrSubstituteForSignedHeadMaterialization() external {
        ChannelSettlementManager.CloseIntent memory intent = _finalizeTwoToken(75, 40);
        bytes32 aux = _expectedAux(intent);

        vm.deal(address(this), address(this).balance + 75);
        registry.creditWithdrawal{value: 75}(address(manager));
        tokenA.mint(address(registry), 40);
        registry.creditTokenWithdrawal(TOKEN_A, address(manager), 40);

        // Generic credit alone is not channel authority.
        vm.expectRevert(
            abi.encodeWithSelector(ChannelSettlementManager.CloseFundingProofNotMaterialized.selector, 0)
        );
        manager.pullChannelFunds();
        vm.expectRevert(
            abi.encodeWithSelector(ChannelSettlementManager.CloseFundingProofNotMaterialized.selector, TOKEN_A)
        );
        manager.pullChannelTokenFunds(TOKEN_A);

        uint256 rollupBalanceBefore = address(registry).balance;
        uint256 rollupTokenBefore = tokenA.balanceOf(address(registry));
        vm.expectRevert(ChannelSettlementManager.CooperativeCloseFundingDeprecated.selector);
        manager.authorizeCloseFunding(0, aux);
        vm.expectRevert(ChannelSettlementManager.CooperativeCloseFundingDeprecated.selector);
        manager.authorizeCloseFunding(TOKEN_A, aux);

        assertEq(registry.pendingWithdrawals(address(manager)), 75, "native ledger untouched");
        assertEq(registry.pendingTokenWithdrawals(TOKEN_A, address(manager)), 40, "token ledger untouched");
        assertEq(address(registry).balance, rollupBalanceBefore, "no ETH left the rollup");
        assertEq(tokenA.balanceOf(address(registry)), rollupTokenBefore, "no tokens left the rollup");
        assertEq(address(manager).balance, 0, "manager received no ETH");
        assertEq(tokenA.balanceOf(address(manager)), 0, "manager received no tokens");
        assertEq(manager.receivedChannelFunds(0), 0, "no native channel credit");
        assertEq(manager.receivedChannelFunds(TOKEN_A), 0, "no token channel credit");
        assertFalse(registry.partialWithdrawalAuthorized(_ipw2(0, 75, aux)), "no IPW2 issued");

        // The retired call left the pull gate closed.
        vm.expectRevert(
            abi.encodeWithSelector(ChannelSettlementManager.CloseFundingProofNotMaterialized.selector, 0)
        );
        manager.pullChannelFunds();

        // Only the live signed-head receipt unlocks the exact cap.
        _materializeCloseFundingAuthorization(registry, manager, 0);
        assertEq(manager.pullChannelFunds(), 75, "signed-head materialization unlocks native pull");
        assertEq(manager.pullChannelTokenFunds(TOKEN_A), 40, "signed-head materialization unlocks token pull");
        assertEq(manager.receivedChannelFunds(0), 75);
        assertEq(manager.receivedChannelFunds(TOKEN_A), 40);
    }

    // ── live exact-cap pull and per-nullifier claim accounting ──

    function test_pullNative_transfersExactCapAndLeavesSurplusOnRollup() external {
        bytes32 digest = _finalizeWithFund(75);
        ChannelSettlementManager.WithdrawalClaim memory claim = _withdrawalClaim(digest, USER_A, alice, 75);
        manager.submitWithdrawalClaim(claim, _withdrawalClaimProof(claim));

        // Five units are unrelated recipient-wide credit. The signed-head materialization receipt
        // is recorded independently, then its 75-unit payout joins the same Rollup ledger.
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

        // The cap is one-shot: a second pull fails closed and the surplus stays on the rollup.
        vm.expectRevert(abi.encodeWithSelector(ChannelSettlementManager.ChannelFundsAlreadyReceived.selector, 0));
        manager.pullChannelFunds();
        assertEq(registry.pendingWithdrawals(address(manager)), 5, "surplus still not swept");
        assertEq(manager.receivedChannelFunds(0), 75);

        // The retired route cannot re-open the lane either.
        bytes32 expectedAux = _expectedAux(_intentWithFund(1, 9, 22, 1, 75));
        vm.expectRevert(ChannelSettlementManager.CooperativeCloseFundingDeprecated.selector);
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
}

// `AtomicCloseFundingMaterializerTest` (release R3 IPW2 atomicity regressions) was removed with
// the terminal-child route: `materializeNative` / `materializeERC20` are tombstones, and the mock
// registry in `CloseSettlementBase` has no `bindManager` / `creditChannelExit` surface to bind a
// real materializer. Atomicity, single-use, and partial-lane rollback of the LIVE route
// (`attestSignedHeadBacking` + `materializeSignedHead`) are covered by
// `test/SignerIndependentExit.t.sol` against a bound `CloseFundingMaterializer`.
