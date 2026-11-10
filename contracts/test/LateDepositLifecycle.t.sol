// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CloseSettlementBase, MockRollupRegistry} from "./CloseSettlementBase.sol";
import {ChannelSettlementManager, IChannelSettlementVerifier} from "../src/ChannelSettlementManager.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";
import {IERC20} from "../src/SafeERC20.sol";
import {SimpleERC20} from "./tokens/TestTokens.sol";

/// Rollup ledger double for the late-deposit lane. Like `LateReceiptRollup` it really debits
/// escrow and credits the recipient's pull-payment balance, and it additionally lets a test mark
/// one extended-state commitment as NOT finalized so an unfinalized anchor can be rejected.
contract LateDepositRollup is MockRollupRegistry {
    address public immutable deployer = msg.sender;
    uint64 public blockNumber = 10;
    uint64 public latestFinalizedBlockNumber = 10;
    CloseFundingMaterializer public materializer;
    mapping(uint32 => uint256) public escrow;
    mapping(bytes32 => bool) public unfinalizedRoot;
    constructor(IChannelSettlementVerifier verifier) MockRollupRegistry(verifier) {}
    function bind(CloseFundingMaterializer m, address manager) external {
        materializer = m;
        m.bindManager(manager);
    }
    function setEscrow(uint32 token, uint256 amount) external { escrow[token] = amount; }
    function setUnfinalized(bytes32 root) external { unfinalizedRoot[root] = true; }
    function setLatestFinalized(uint64 n) external { latestFinalizedBlockNumber = n; }
    function isFinalizedStateRoot(bytes32 root) external view override returns (bool) { return !unfinalizedRoot[root]; }
    function creditChannelExit(address recipient, uint32 token, uint256 amount) external {
        require(msg.sender == address(materializer), "only materializer");
        require(escrow[token] >= amount, "insufficient escrow");
        escrow[token] -= amount;
        if (token == 0) pendingWithdrawals[recipient] += amount;
        else pendingTokenWithdrawals[token][recipient] += amount;
    }
}

contract LateDepositLifecycleTest is CloseSettlementBase {
    uint32 constant TOKEN = 55;
    /// A token index the channel never registered: the late-deposit refund needs no registry entry.
    uint32 constant UNREGISTERED_TOKEN = 77;
    bytes32 constant INITIAL = keccak256("full closing Balance commitment");
    bytes32 constant EXT = keccak256("finalized extended state");
    LateDepositRollup rollup;
    CloseFundingMaterializer materializer;
    MockPinnedMleVerifierV2 backingVerifier;
    MockPinnedMleVerifierV2 lateVerifier;
    MockPinnedMleVerifierV2 lateDepositVerifier;
    SimpleERC20 token;
    address depositor = makeAddr("stranded depositor");

    event LateDepositClaimed(uint32 indexed channelId, bytes32 indexed nullifier, address depositor,
        uint32 tokenIndex, uint64 amount, bytes32 nextCommitment, uint64 anchorBlock);

    function setUp() public override {
        super.setUp();
        rollup = new LateDepositRollup(IChannelSettlementVerifier(address(verifier)));
        registry = rollup;
        bytes32[] memory members = new bytes32[](3);
        members[0] = USER_A; members[1] = USER_B; members[2] = USER_C;
        registry.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, members);
        backingVerifier = new MockPinnedMleVerifierV2(block.chainid);
        lateVerifier = new MockPinnedMleVerifierV2(block.chainid);
        lateDepositVerifier = new MockPinnedMleVerifierV2(block.chainid);
        materializer = new CloseFundingMaterializer(
            IntmaxRollup(payable(address(rollup))), backingVerifier, lateVerifier, lateDepositVerifier
        );
        manager = _deployManagerWithMaterializer(registry, alice, bob, carol, address(materializer));
        rollup.bind(materializer, address(manager));
        token = new SimpleERC20("Late deposit token");
        registry.setToken(TOKEN, IERC20(address(token)));
        vm.deal(address(rollup), 1e30);
        token.mint(address(rollup), 1e30);
        rollup.setEscrow(0, 1e30); rollup.setEscrow(TOKEN, 1e30); rollup.setEscrow(UNREGISTERED_TOKEN, 1e30);
        uint256[10] memory funds; funds[0] = 75; funds[1] = 40;
        uint32[10] memory tokens; tokens[1] = TOKEN;
        ChannelSettlementManager.CloseIntent memory intent = _intentWithTokens(1, 9, 22, 1, funds, tokens, 2);
        uint256[] memory pi = new uint256[](35);
        pi[0] = uint32(CHANNEL_ID);
        _word(pi, 1, intent.finalSettledTxChain);
        _word(pi, 9, verifier.tokenFundsDigest(tokens, 2, funds));
        _word(pi, 17, EXT); pi[25] = 10; pi[26] = 10; _word(pi, 27, INITIAL);
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

    /// 49-limb late-deposit statement. `high` fills amount limbs [40..46] (must be zero on chain).
    function _depositPi(bytes32 previous, bytes32 next, bytes32 ext, uint64 anchor, bytes32 nf,
        address payee, uint32 asset, uint64 amount) internal pure returns (uint256[] memory pi)
    {
        pi = new uint256[](49);
        pi[0] = uint32(CHANNEL_ID); _word(pi, 1, previous); _word(pi, 9, next); _word(pi, 17, ext);
        pi[25] = anchor; _word(pi, 26, nf);
        for (uint256 i; i < 5; ++i) pi[34+i] = uint32(uint160(payee) >> (128-32*i));
        pi[39] = asset; pi[46] = amount >> 32; pi[47] = uint32(amount); pi[48] = 1;
    }
    function _depositProof(bytes32 previous, bytes32 next, bytes32 nf, address payee, uint32 asset, uint64 amount)
        internal pure returns (bytes memory)
    {
        return abi.encode(_depositPi(previous, next, EXT, 10, nf, payee, asset, amount));
    }
    /// 59-limb late-incoming statement (the sibling lane sharing the cursor).
    function _incomingProof(bytes32 previous, bytes32 next, bytes32 nf, address recipient, uint32 asset, uint64 amount)
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
    function _cursor() internal view returns (bytes32) {
        return materializer.lateBalanceStateCommitment(uint32(CHANNEL_ID));
    }
    function _refund(uint32 asset, uint64 amount, address payee, uint256 id) internal returns (bytes32 nf) {
        bytes32 previous = _cursor();
        nf = keccak256(abi.encode("deposit", id));
        materializer.claimLateDeposit(manager, _depositProof(previous, keccak256(abi.encode(previous, id)), nf, payee, asset, amount));
    }
    function _assertUntouched(bytes32 nf) internal view {
        assertEq(_cursor(), INITIAL);
        assertEq(materializer.lateBalanceAnchorBlock(uint32(CHANNEL_ID)), 10);
        assertFalse(materializer.lateReceiveNullifierUsed(uint32(CHANNEL_ID), nf));
        assertEq(registry.pendingWithdrawals(depositor), 0);
        assertEq(registry.pendingTokenWithdrawals(TOKEN, depositor), 0);
        assertEq(rollup.escrow(0), 1e30 - 75);
        assertEq(rollup.escrow(TOKEN), 1e30 - 40);
    }
    function _expectInvalid() internal {
        vm.expectRevert(CloseFundingMaterializer.InvalidLateDeposit.selector);
    }

    function test_nativeRefundCreditsDepositorOnRollupAndAdvancesCursor() external {
        bytes32 nf = keccak256(abi.encode("deposit", uint256(1)));
        bytes32 next = keccak256(abi.encode(INITIAL, uint256(1)));
        vm.expectEmit(true, true, true, true, address(materializer));
        emit LateDepositClaimed(uint32(CHANNEL_ID), nf, depositor, 0, 17, next, 10);
        _refund(0, 17, depositor, 1);
        assertEq(registry.pendingWithdrawals(depositor), 17);
        assertEq(rollup.escrow(0), 1e30 - 75 - 17);
        assertEq(_cursor(), next);
        assertEq(materializer.lateBalanceAnchorBlock(uint32(CHANNEL_ID)), 10);
        assertTrue(materializer.lateReceiveNullifierUsed(uint32(CHANNEL_ID), nf));
        // The Manager is not involved: no late cap, no channel credit, original funds untouched.
        assertEq(manager.lateIncomingFundAmount(0), 0);
        assertEq(registry.pendingWithdrawals(address(manager)), 75);
        // The depositor pulls directly from the Rollup ledger.
        vm.prank(depositor); registry.withdraw(17);
        assertEq(depositor.balance, 17);
    }

    function test_tokenRefundNeedsNoChannelTokenRegistryEntry() external {
        _refund(TOKEN, 23, depositor, 1);
        assertEq(registry.pendingTokenWithdrawals(TOKEN, depositor), 23);
        assertEq(rollup.escrow(TOKEN), 1e30 - 40 - 23);
        _refund(UNREGISTERED_TOKEN, 5, depositor, 2);
        assertEq(registry.pendingTokenWithdrawals(UNREGISTERED_TOKEN, depositor), 5);
        assertEq(rollup.escrow(UNREGISTERED_TOKEN), 1e30 - 5);
        assertEq(manager.lateIncomingFundAmount(TOKEN), 0);
        assertEq(registry.pendingTokenWithdrawals(TOKEN, address(manager)), 40);
    }

    function test_anchorAdvancesWithTheClaimAndCannotGoBackwards() external {
        bytes32 later = keccak256("later finalized state");
        rollup.setLatestFinalized(14);
        bytes32 nf = keccak256("anchored");
        materializer.claimLateDeposit(manager, abi.encode(_depositPi(INITIAL, keccak256("n1"), later, 13, nf, depositor, 0, 1)));
        assertEq(materializer.lateBalanceAnchorBlock(uint32(CHANNEL_ID)), 13);
        _expectInvalid();
        materializer.claimLateDeposit(manager, abi.encode(_depositPi(keccak256("n1"), keccak256("n2"), EXT, 12, keccak256("back"), depositor, 0, 1)));
        _expectInvalid();
        materializer.claimLateDeposit(manager, abi.encode(_depositPi(keccak256("n1"), keccak256("n2"), later, 15, keccak256("ahead"), depositor, 0, 1)));
    }

    function test_replayedNullifierReverts() external {
        bytes32 nf = _refund(0, 9, depositor, 1);
        bytes32 previous = _cursor();
        _expectInvalid();
        materializer.claimLateDeposit(manager, _depositProof(previous, keccak256("other next"), nf, depositor, 0, 9));
        assertEq(registry.pendingWithdrawals(depositor), 9);
    }

    function test_nonzeroHighAmountLimbsRevert() external {
        for (uint256 limb = 40; limb < 46; ++limb) {
            uint256[] memory pi = _depositPi(INITIAL, keccak256("next"), EXT, 10, keccak256("high"), depositor, 0, 9);
            pi[limb] = 1;
            _expectInvalid();
            materializer.claimLateDeposit(manager, abi.encode(pi));
        }
        _assertUntouched(keccak256("high"));
    }

    function test_zeroAmountReverts() external {
        bytes32 nf = keccak256("zero");
        _expectInvalid();
        materializer.claimLateDeposit(manager, _depositProof(INITIAL, keccak256("next"), nf, depositor, 0, 0));
        _assertUntouched(nf);
    }

    function test_zeroDepositorReverts() external {
        bytes32 nf = keccak256("nobody");
        _expectInvalid();
        materializer.claimLateDeposit(manager, _depositProof(INITIAL, keccak256("next"), nf, address(0), 0, 4));
        _assertUntouched(nf);
    }

    function test_prevMismatchingCursorReverts() external {
        bytes32 nf = keccak256("stale");
        _expectInvalid();
        materializer.claimLateDeposit(manager, _depositProof(keccak256("not the cursor"), keccak256("next"), nf, depositor, 0, 4));
        _assertUntouched(nf);
    }

    function test_nextEqualToPrevReverts() external {
        bytes32 nf = keccak256("no-op");
        _expectInvalid();
        materializer.claimLateDeposit(manager, _depositProof(INITIAL, INITIAL, nf, depositor, 0, 4));
        _assertUntouched(nf);
    }

    function test_unfinalizedExtendedStateReverts() external {
        bytes32 nf = keccak256("unfinalized");
        rollup.setUnfinalized(keccak256("pending state"));
        _expectInvalid();
        materializer.claimLateDeposit(manager,
            abi.encode(_depositPi(INITIAL, keccak256("next"), keccak256("pending state"), 10, nf, depositor, 0, 4)));
        _assertUntouched(nf);
    }

    function test_wrongLengthVersionChannelAndLimbRangesRevert() external {
        uint256[] memory pi = _depositPi(INITIAL, keccak256("next"), EXT, 10, keccak256("shape"), depositor, 0, 4);
        _expectInvalid(); materializer.claimLateDeposit(manager, abi.encode(new uint256[](59)));
        pi[48] = 2; _expectInvalid(); materializer.claimLateDeposit(manager, abi.encode(pi)); pi[48] = 1;
        pi[0] = uint32(CHANNEL_ID) + 1; _expectInvalid(); materializer.claimLateDeposit(manager, abi.encode(pi)); pi[0] = uint32(CHANNEL_ID);
        pi[39] = uint256(type(uint32).max) + 1; _expectInvalid(); materializer.claimLateDeposit(manager, abi.encode(pi)); pi[39] = 0;
        pi[25] = uint256(1) << 63; _expectInvalid(); materializer.claimLateDeposit(manager, abi.encode(pi)); pi[25] = 10;
        materializer.claimLateDeposit(manager, abi.encode(pi));
        assertEq(registry.pendingWithdrawals(depositor), 4);
    }

    function test_invalidCryptographyCannotTouchEscrowOrCursor() external {
        bytes32 nf = keccak256("bad crypto");
        lateDepositVerifier.setVerdict(false);
        vm.expectRevert(MockPinnedMleVerifierV2.MockMleVerificationRejected.selector);
        materializer.claimLateDeposit(manager, _depositProof(INITIAL, keccak256("next"), nf, depositor, 0, 8));
        _assertUntouched(nf);
    }

    function test_escrowFailurePreservesCursorAndCanRetryExactProof() external {
        bytes32 nf = keccak256("retry");
        bytes memory proof = _depositProof(INITIAL, keccak256("next"), nf, depositor, TOKEN, 8);
        rollup.setEscrow(TOKEN, 7);
        vm.expectRevert(bytes("insufficient escrow")); materializer.claimLateDeposit(manager, proof);
        assertEq(_cursor(), INITIAL);
        assertFalse(materializer.lateReceiveNullifierUsed(uint32(CHANNEL_ID), nf));
        rollup.setEscrow(TOKEN, 8);
        materializer.claimLateDeposit(manager, proof);
        assertEq(registry.pendingTokenWithdrawals(TOKEN, depositor), 8);
        assertEq(rollup.escrow(TOKEN), 0);
    }

    function test_lateDepositThenLateIncomingShareOneCursor() external {
        bytes32 a = keccak256("after deposit"); bytes32 b = keccak256("after incoming");
        materializer.claimLateDeposit(manager, _depositProof(INITIAL, a, keccak256("d"), depositor, 0, 11));
        assertEq(_cursor(), a);
        // The incoming lane must build on the deposit's successor, not on INITIAL any more.
        // (`_incomingProof` reads the manager, so build it before arming the expected revert.)
        bytes memory stale = _incomingProof(INITIAL, b, keccak256("i"), alice, 0, 3);
        vm.expectRevert(CloseFundingMaterializer.InvalidLateIncoming.selector);
        materializer.claimLateIncoming(manager, stale);
        materializer.claimLateIncoming(manager, _incomingProof(a, b, keccak256("i"), alice, 0, 3));
        assertEq(_cursor(), b);
        assertEq(registry.pendingWithdrawals(depositor), 11);
        assertEq(manager.withdrawalCredits(0, alice), 3);
        assertEq(manager.lateIncomingFundAmount(0), 3);
    }

    function test_lateIncomingThenLateDepositShareOneCursor() external {
        bytes32 a = keccak256("after incoming"); bytes32 b = keccak256("after deposit");
        materializer.claimLateIncoming(manager, _incomingProof(INITIAL, a, keccak256("i"), bob, TOKEN, 3));
        assertEq(_cursor(), a);
        _expectInvalid();
        materializer.claimLateDeposit(manager, _depositProof(INITIAL, b, keccak256("d"), depositor, TOKEN, 11));
        materializer.claimLateDeposit(manager, _depositProof(a, b, keccak256("d"), depositor, TOKEN, 11));
        assertEq(_cursor(), b);
        assertEq(registry.pendingTokenWithdrawals(TOKEN, depositor), 11);
        assertEq(manager.withdrawalCredits(TOKEN, bob), 3);
        assertEq(rollup.escrow(TOKEN), 1e30 - 40 - 3 - 11);
    }

    function test_crossLaneNullifierReplayReverts() external {
        bytes32 nf = keccak256("one nullifier tree");
        // Consumed by the deposit lane first: the incoming lane must refuse it.
        materializer.claimLateDeposit(manager, _depositProof(INITIAL, keccak256("a"), nf, depositor, 0, 2));
        bytes memory replay = _incomingProof(keccak256("a"), keccak256("b"), nf, alice, 0, 2);
        vm.expectRevert(CloseFundingMaterializer.InvalidLateIncoming.selector);
        materializer.claimLateIncoming(manager, replay);
        assertEq(_cursor(), keccak256("a"));
        // And the other direction, with a fresh nullifier consumed by the incoming lane first.
        bytes32 nf2 = keccak256("another");
        materializer.claimLateIncoming(manager, _incomingProof(keccak256("a"), keccak256("b"), nf2, alice, 0, 2));
        _expectInvalid();
        materializer.claimLateDeposit(manager, _depositProof(keccak256("b"), keccak256("c"), nf2, depositor, 0, 2));
        assertEq(_cursor(), keccak256("b"));
    }

    function test_unboundOrOpenChannelRejected() external {
        ChannelSettlementManager other = _deployManagerWithMaterializer(registry, alice, bob, carol, address(materializer));
        vm.expectRevert(CloseFundingMaterializer.NotBoundManager.selector);
        materializer.claimLateDeposit(other, _depositProof(INITIAL, keccak256("next"), keccak256("x"), depositor, 0, 1));
    }

    function testFuzz_refundSequenceConservesEscrow(uint64 a, uint64 b, uint64 c) external {
        a = uint64(bound(a, 1, type(uint64).max));
        b = uint64(bound(b, 1, type(uint64).max));
        c = uint64(bound(c, 1, type(uint64).max));
        _refund(0, a, depositor, 1);
        _refund(TOKEN, b, alice, 2);
        _refund(0, c, depositor, 3);
        assertEq(rollup.escrow(0), 1e30 - 75 - uint256(a) - c);
        assertEq(rollup.escrow(TOKEN), 1e30 - 40 - b);
        assertEq(registry.pendingWithdrawals(depositor), uint256(a) + c);
        assertEq(registry.pendingTokenWithdrawals(TOKEN, alice), b);
        assertEq(manager.lateIncomingFundAmount(0), 0);
        assertEq(manager.lateIncomingFundAmount(TOKEN), 0);
    }
}
