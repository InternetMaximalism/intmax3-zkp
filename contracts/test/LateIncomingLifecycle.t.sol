// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CloseSettlementBase, MockRollupRegistry} from "./CloseSettlementBase.sol";
import {ChannelSettlementManager, IChannelSettlementVerifier} from "../src/ChannelSettlementManager.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";
import {IERC20} from "../src/SafeERC20.sol";
import {SimpleERC20} from "./tokens/TestTokens.sol";

/// Rollup ledger double. Manager and materializer below are production contracts; cryptographic
/// verification is mocked separately. The ledger really holds/transfers native and ERC-20 funds.
contract LateReceiptRollup is MockRollupRegistry {
    address public immutable deployer = msg.sender;
    uint64 public blockNumber = 10;
    uint64 public latestFinalizedBlockNumber = 10;
    CloseFundingMaterializer public materializer;
    mapping(uint32 => uint256) public escrow;
    constructor(IChannelSettlementVerifier verifier) MockRollupRegistry(verifier) {}
    function bind(CloseFundingMaterializer m, address manager) external {
        materializer = m;
        m.bindManager(manager);
    }
    function setEscrow(uint32 token, uint256 amount) external { escrow[token] = amount; }
    function creditChannelExit(address manager, uint32 token, uint256 amount) external {
        require(msg.sender == address(materializer), "only materializer");
        require(escrow[token] >= amount, "insufficient escrow");
        escrow[token] -= amount;
        if (token == 0) pendingWithdrawals[manager] += amount;
        else pendingTokenWithdrawals[token][manager] += amount;
    }
}

contract LateIncomingLifecycleTest is CloseSettlementBase {
    uint32 constant TOKEN = 55;
    bytes32 constant INITIAL = keccak256("full closing Balance commitment");
    bytes32 constant EXT = keccak256("finalized extended state");
    LateReceiptRollup rollup;
    CloseFundingMaterializer materializer;
    MockPinnedMleVerifierV2 backingVerifier;
    MockPinnedMleVerifierV2 lateVerifier;
    SimpleERC20 token;

    function setUp() public override {
        super.setUp();
        rollup = new LateReceiptRollup(IChannelSettlementVerifier(address(verifier)));
        registry = rollup;
        bytes32[] memory members = new bytes32[](3);
        members[0] = USER_A; members[1] = USER_B; members[2] = USER_C;
        registry.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, members);
        backingVerifier = new MockPinnedMleVerifierV2(block.chainid);
        lateVerifier = new MockPinnedMleVerifierV2(block.chainid);
        materializer = new CloseFundingMaterializer(IntmaxRollup(payable(address(rollup))), backingVerifier, lateVerifier);
        manager = _deployManagerWithMaterializer(registry, alice, bob, carol, address(materializer));
        rollup.bind(materializer, address(manager));
        token = new SimpleERC20("Late receipt token");
        registry.setToken(TOKEN, IERC20(address(token)));
        vm.deal(address(rollup), 1e30);
        token.mint(address(rollup), 1e30);
        rollup.setEscrow(0, 1e30); rollup.setEscrow(TOKEN, 1e30);
        uint256[10] memory funds; funds[0] = 75; funds[1] = 40;
        uint32[10] memory tokens; tokens[1] = TOKEN;
        ChannelSettlementManager.CloseIntent memory intent = _intentWithTokens(1, 9, 22, 1, funds, tokens, 2);
        uint256[] memory pi = new uint256[](34);
        pi[0] = uint32(CHANNEL_ID);
        _word(pi, 1, intent.finalSettledTxChain);
        _word(pi, 9, verifier.tokenFundsDigest(tokens, 2, funds));
        _word(pi, 17, EXT); pi[25] = 10; _word(pi, 26, INITIAL);
        bytes memory backing = abi.encode(pi);
        materializer.attestSignedHeadBacking(manager, backing);
        _requestCloseAndElapseGrace();
        manager.submitCloseIntent(intent, _closeProof(intent));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        materializer.materializeSignedHead(manager, backing);
    }

    function _word(uint256[] memory pi, uint256 offset, bytes32 value) internal pure {
        for (uint256 i; i < 8; ++i) pi[offset+i] = uint32(uint256(value) >> (224 - 32*i));
    }
    function _proof(bytes32 previous, bytes32 next, bytes32 nf, address recipient, uint32 asset, uint64 amount)
        internal view returns (bytes memory)
    {
        uint256[] memory pi = new uint256[](59);
        pi[0] = uint32(CHANNEL_ID); _word(pi, 1, manager.finalizedCloseIntentDigest());
        _word(pi, 9, manager.finalizedBalanceStateH1()); _word(pi, 17, previous);
        _word(pi, 25, next); _word(pi, 33, EXT); pi[41] = 10; _word(pi, 42, nf);
        for (uint256 i; i < 5; ++i) pi[50+i] = uint32(uint160(recipient) >> (128-32*i));
        pi[55] = asset; pi[56] = amount >> 32; pi[57] = uint32(amount); pi[58] = 1;
        return abi.encode(pi);
    }
    function _key(bytes32 nf) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(bytes4(0x494d4c43), uint32(CHANNEL_ID), manager.finalizedCloseIntentDigest(), nf));
    }
    function _receive(uint32 asset, uint64 amount, address recipient, uint256 id) internal returns (bytes32 key) {
        bytes32 previous = materializer.lateBalanceStateCommitment(uint32(CHANNEL_ID));
        bytes32 nf = keccak256(abi.encode("incoming", id));
        materializer.claimLateIncoming(manager, _proof(previous, keccak256(abi.encode(previous,id)), nf, recipient, asset, amount));
        return _key(nf);
    }
    function _assertNoLateCredit(bytes32 nf) internal view {
        assertEq(materializer.lateBalanceStateCommitment(uint32(CHANNEL_ID)), INITIAL);
        assertFalse(materializer.lateReceiveNullifierUsed(uint32(CHANNEL_ID), nf));
        assertEq(manager.lateIncomingFundAmount(0), 0);
        assertEq(manager.lateIncomingFundAmount(TOKEN), 0);
        assertEq(registry.pendingWithdrawals(address(manager)), 75);
        assertEq(registry.pendingTokenWithdrawals(TOKEN, address(manager)), 40);
    }

    function test_initialCursorIsExactBackingCommitmentNotZeroOrFinalH1() external view {
        assertEq(materializer.lateBalanceStateCommitment(uint32(CHANNEL_ID)), INITIAL);
        assertEq(materializer.lateBalanceAnchorBlock(uint32(CHANNEL_ID)), 10);
        assertTrue(INITIAL != manager.finalizedBalanceStateH1());
    }

    function test_endToEndBothAssetsAfterOriginalFundsAlreadyPaid() external {
        bytes32 close = manager.finalizedCloseIntentDigest();
        ChannelSettlementManager.WithdrawalClaim memory nativeClaim = _withdrawalClaimToken(close, USER_A, alice, 75, 0, 0);
        ChannelSettlementManager.WithdrawalClaim memory tokenClaim = _withdrawalClaimToken(close, USER_B, bob, 40, 1, TOKEN);
        manager.submitWithdrawalClaim(nativeClaim, _withdrawalClaimProof(nativeClaim));
        manager.submitWithdrawalClaim(tokenClaim, _withdrawalClaimProof(tokenClaim));
        manager.pullChannelFunds(); manager.pullChannelTokenFunds(TOKEN);
        vm.prank(alice); manager.claimWithdrawalCredit(nativeClaim.withdrawalNullifier);
        vm.prank(bob); manager.claimWithdrawalCredit(tokenClaim.withdrawalNullifier);
        bytes32 digest = manager.finalizedTokenFundsDigest();
        bytes32 nativeKey = _receive(0, 17, carol, 1);
        bytes32 tokenKey = _receive(TOKEN, 23, alice, 2);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        vm.prank(carol); manager.claimWithdrawalCredit(nativeKey);
        assertEq(manager.withdrawalCredits(0, carol), 17);
        manager.pullChannelFunds(); manager.pullChannelTokenFunds(TOKEN);
        vm.prank(alice); manager.claimWithdrawalCredit(tokenKey);
        vm.prank(carol); manager.claimWithdrawalCredit(nativeKey);
        assertEq(carol.balance, 17); assertEq(token.balanceOf(alice), 23);
        assertEq(manager.totalCreditedOut(0), 92); assertEq(manager.totalCreditedOut(TOKEN), 63);
        assertEq(manager.finalizedTokenFundsDigest(), digest);
        vm.expectRevert(ChannelSettlementManager.NoWithdrawalCredit.selector);
        vm.prank(carol); manager.claimWithdrawalCredit(nativeKey);
    }

    function test_receiptsToSameRecipientRemainIndividuallyClaimableOutOfOrder() external {
        bytes32 first = _receive(0, 5, alice, 1);
        bytes32 second = _receive(0, 7, alice, 2);
        manager.pullChannelFunds();
        vm.prank(alice); manager.claimWithdrawalCredit(second);
        assertEq(manager.withdrawalCredits(0, alice), 5);
        vm.expectRevert(ChannelSettlementManager.WithdrawalPayoutRecipientMismatch.selector);
        vm.prank(mallory); manager.claimWithdrawalCredit(first);
        vm.prank(alice); manager.claimWithdrawalCredit(first);
        assertEq(alice.balance, 12);
    }

    function test_competingBranchesRejectLoserThenAllowRebase() external {
        bytes32 a = keccak256("a"); bytes32 b = keccak256("b"); bytes32 nf = keccak256("nf");
        bytes memory loser = _proof(INITIAL, b, nf, alice, TOKEN, 7);
        materializer.claimLateIncoming(manager, _proof(INITIAL, a, keccak256("winner"), bob, 0, 3));
        vm.expectRevert(CloseFundingMaterializer.InvalidLateIncoming.selector);
        materializer.claimLateIncoming(manager, loser);
        assertFalse(materializer.lateReceiveNullifierUsed(uint32(CHANNEL_ID), nf));
        assertEq(manager.lateIncomingFundAmount(TOKEN), 0);
        materializer.claimLateIncoming(manager, _proof(a, b, nf, alice, TOKEN, 7));
        assertEq(manager.withdrawalCredits(TOKEN, alice), 7);
    }

    function test_escrowFailurePreservesCursorAndCanRetryExactProof() external {
        bytes32 nf = keccak256("retry");
        bytes memory proof = _proof(INITIAL, keccak256("next"), nf, bob, TOKEN, 8);
        rollup.setEscrow(TOKEN, 7);
        vm.expectRevert(bytes("insufficient escrow")); materializer.claimLateIncoming(manager, proof);
        _assertNoLateCredit(nf);
        rollup.setEscrow(TOKEN, 8);
        materializer.claimLateIncoming(manager, proof);
        assertEq(manager.lateIncomingFundAmount(TOKEN), 8);
        assertEq(rollup.escrow(TOKEN), 0);
    }

    function test_invalidCryptographyCannotTouchEscrowOrCheckpoint() external {
        bytes32 nf = keccak256("bad crypto");
        bytes memory proof = _proof(INITIAL, keccak256("next"), nf, alice, 0, 8);
        lateVerifier.setVerdict(false);
        vm.expectRevert(MockPinnedMleVerifierV2.MockMleVerificationRejected.selector);
        materializer.claimLateIncoming(manager, proof);
        _assertNoLateCredit(nf);
    }

    function test_lateFundsCannotExpandOrdinaryClaimBudget() external {
        bytes32 close = manager.finalizedCloseIntentDigest();
        _receive(0, 19, bob, 1);
        ChannelSettlementManager.WithdrawalClaim memory claim = _withdrawalClaimToken(close, USER_A, alice, 76, 0, 0);
        bytes memory proof = _withdrawalClaimProof(claim);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.submitWithdrawalClaim(claim, proof);
        assertEq(manager.withdrawalCredits(0, bob), 19);
        assertEq(manager.totalWithdrawn(0), 19);
    }

    function test_rollupSurplusIsNotPulledAsExtraClaimCapacity() external {
        bytes32 key = _receive(TOKEN, 9, alice, 1);
        registry.creditTokenWithdrawal(TOKEN, address(manager), 123);
        manager.pullChannelTokenFunds(TOKEN);
        assertEq(registry.pendingTokenWithdrawals(TOKEN, address(manager)), 123);
        assertEq(manager.receivedChannelFunds(TOKEN), 49);
        vm.prank(alice); manager.claimWithdrawalCredit(key);
        assertEq(token.balanceOf(alice), 9);
    }

    function testFuzz_receiptSequenceConservesEscrowCapAndPayouts(uint64 a, uint64 b, uint64 c) external {
        a = uint64(bound(a, 1, type(uint64).max));
        b = uint64(bound(b, 1, type(uint64).max));
        c = uint64(bound(c, 1, type(uint64).max));
        bytes32 first = _receive(0, a, alice, 1);
        bytes32 second = _receive(TOKEN, b, bob, 2);
        bytes32 third = _receive(0, c, carol, 3);
        assertEq(rollup.escrow(0), 1e30 - 75 - uint256(a) - c);
        assertEq(rollup.escrow(TOKEN), 1e30 - 40 - b);
        assertEq(manager.lateIncomingFundAmount(0), uint256(a) + c);
        assertEq(manager.lateIncomingFundAmount(TOKEN), b);
        manager.pullChannelFunds(); manager.pullChannelTokenFunds(TOKEN);
        vm.prank(carol); manager.claimWithdrawalCredit(third);
        vm.prank(bob); manager.claimWithdrawalCredit(second);
        vm.prank(alice); manager.claimWithdrawalCredit(first);
        assertEq(alice.balance, a); assertEq(carol.balance, c); assertEq(token.balanceOf(bob), b);
        assertEq(manager.receivedChannelFunds(0) - manager.totalCreditedOut(0), 75);
        assertEq(manager.receivedChannelFunds(TOKEN) - manager.totalCreditedOut(TOKEN), 40);
    }
}
