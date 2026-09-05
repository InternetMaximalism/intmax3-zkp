// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier,
    IChannelRegistry,
    CloseProofFields
} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";
import {CloseTestLib} from "./CloseTestLib.sol";
import {IERC20} from "../src/SafeERC20.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";

/// @dev Minimal stand-in for `IntmaxRollup`'s registration + native-payout surface, byte-identical
///      to the one in `ChannelSettlementManager.t.sol`. Copied (not imported) so this base does not
///      drag in the 2122-line test contract. INTENTIONALLY SIMPLE (CLAUDE.md: helper contracts that
///      implement real interfaces with fixed behavior).
contract MockRollupRegistry is IChannelRegistry {
    IChannelSettlementVerifier internal immutable verifier;
    mapping(uint32 => bytes32) public channelMemberSetCommitment;
    mapping(uint32 => uint8) public channelBpMemberSlot;
    mapping(uint32 => bytes32) public channelBpPkG;

    constructor(IChannelSettlementVerifier verifier_) {
        verifier = verifier_;
    }

    function isFinalizedStateRoot(bytes32) external pure returns (bool) {
        return true;
    }

    function register(uint32 channelId, uint8 bpMemberSlot, bytes32[] memory activeHashes) external {
        bytes32[8] memory padded;
        for (uint256 i = 0; i < activeHashes.length; i++) {
            padded[i] = activeHashes[i];
        }
        channelMemberSetCommitment[channelId] = verifier.closeMemberSetCommitment(padded, uint8(activeHashes.length));
        channelBpMemberSlot[channelId] = bpMemberSlot;
        channelBpPkG[channelId] = activeHashes[bpMemberSlot];
    }

    // --- pull-payment stand-in for IntmaxRollup native withdrawal ---
    mapping(address => uint256) public pendingWithdrawals;

    function creditWithdrawal(address recipient) external payable {
        pendingWithdrawals[recipient] += msg.value;
    }

    function withdraw(uint256 amount) external override {
        uint256 pending = pendingWithdrawals[msg.sender];
        require(amount > 0 && pending > 0, "nothing to withdraw");
        uint256 paid = amount < pending ? amount : pending;
        pendingWithdrawals[msg.sender] = pending - paid;
        (bool ok,) = msg.sender.call{value: paid}("");
        require(ok, "withdraw failed");
    }

    mapping(bytes32 => bool) public override partialWithdrawalAuthorized;
    mapping(bytes32 => uint256) public partialWithdrawalAuthorizationCalls;
    bool public rejectAtomicWithdrawal;

    function authorizePartialWithdrawal(bytes32 authDigest) external override {
        partialWithdrawalAuthorized[authDigest] = true;
        partialWithdrawalAuthorizationCalls[authDigest] += 1;
    }

    /// Test-only image of the Rollup withdrawal proof consuming its one-shot IPW2 latch.
    function consumePartialWithdrawalAuthorization(bytes32 authDigest) external {
        require(partialWithdrawalAuthorized[authDigest], "authorization not issued");
        delete partialWithdrawalAuthorized[authDigest];
    }

    function setRejectAtomicWithdrawal(bool reject_) external {
        rejectAtomicWithdrawal = reject_;
    }

    function withdrawNative(
        IntmaxRollup.Withdrawal[] calldata withdrawals,
        address,
        bytes calldata
    ) external {
        if (rejectAtomicWithdrawal) revert("atomic withdrawal rejected");
        for (uint256 i = 0; i < withdrawals.length; ++i) {
            IntmaxRollup.Withdrawal calldata withdrawal = withdrawals[i];
            require(withdrawal.tokenIndex == 0, "not native");
            _consumeAndCredit(withdrawal);
        }
    }

    function withdrawERC20(
        IntmaxRollup.Withdrawal[] calldata withdrawals,
        address,
        bytes calldata
    ) external {
        if (rejectAtomicWithdrawal) revert("atomic withdrawal rejected");
        for (uint256 i = 0; i < withdrawals.length; ++i) {
            IntmaxRollup.Withdrawal calldata withdrawal = withdrawals[i];
            require(withdrawal.tokenIndex != 0, "not ERC-20");
            _consumeAndCredit(withdrawal);
        }
    }

    function _consumeAndCredit(IntmaxRollup.Withdrawal calldata withdrawal) private {
        bytes32 authDigest = keccak256(
            abi.encodePacked(
                bytes4(0x49505732),
                withdrawal.recipient,
                withdrawal.tokenIndex,
                withdrawal.amount,
                withdrawal.auxData
            )
        );
        require(partialWithdrawalAuthorized[authDigest], "authorization not issued");
        delete partialWithdrawalAuthorized[authDigest];
        if (withdrawal.tokenIndex == 0) {
            pendingWithdrawals[withdrawal.recipient] += withdrawal.amount;
        } else {
            pendingTokenWithdrawals[withdrawal.tokenIndex][withdrawal.recipient] += withdrawal.amount;
        }
    }

    // --- Multi-token (multitoken Phase 3): ERC-20 pull-payment + set-once registry mirror ---
    mapping(uint32 => IERC20) public tokenAddressOf;
    mapping(uint32 => mapping(address => uint256)) public pendingTokenWithdrawals;

    function setToken(uint32 tokenIndex, IERC20 token) external {
        tokenAddressOf[tokenIndex] = token;
    }

    /// Credit a recipient's ERC-20 pull balance (tests transfer/mint the tokens into this registry
    /// first), simulating a finalized `IntmaxRollup.withdrawERC20` credit.
    function creditTokenWithdrawal(uint32 tokenIndex, address recipient, uint256 amount) external {
        pendingTokenWithdrawals[tokenIndex][recipient] += amount;
    }

    function withdrawToken(uint32 tokenIndex, uint256 amount) external override {
        uint256 pending = pendingTokenWithdrawals[tokenIndex][msg.sender];
        require(amount > 0 && pending > 0, "nothing to withdraw");
        uint256 paid = amount < pending ? amount : pending;
        pendingTokenWithdrawals[tokenIndex][msg.sender] = pending - paid;
        require(tokenAddressOf[tokenIndex].transfer(msg.sender, paid), "token transfer failed");
    }
}

/// @title CloseSettlementBase
/// @notice Shared harness for the close-settlement adversarial / invariant suites. Mirrors the
///         deployment + proof-builder helpers in `ChannelSettlementManager.t.sol` (mock MLE
///         verdict=true, real 103/50/56-limb strict binding), but carries NO test functions so the
///         existing suite is not re-run when these new suites compile.
abstract contract CloseSettlementBase is Test {
    ChannelSettlementVerifier internal verifier;
    MockPinnedMleVerifierV2 internal mockMle;
    MockPinnedMleVerifierV2 internal withdrawalClaimMle;
    MockPinnedMleVerifierV2 internal postCloseClaimMle;
    MockPinnedMleVerifierV2 internal cancelCloseMle;
    MockRollupRegistry internal registry;
    ChannelSettlementManager internal manager;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    address internal mallory = makeAddr("mallory");

    bytes4 internal constant CHANNEL_ID = hex"00000009";
    uint32 internal constant PW_BASE_NONCE = 9;
    uint8 internal constant BP_MEMBER_SLOT = 0;
    bytes32 internal constant USER_A = keccak256("member_a_sphincs_pubkey_hash");
    bytes32 internal constant USER_B = keccak256("member_b_sphincs_pubkey_hash");
    bytes32 internal constant USER_C = keccak256("member_c_sphincs_pubkey_hash");
    uint64 internal constant CHALLENGE_PERIOD = 1 days;
    uint64 internal constant GRACE = 600;
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 9;
    uint256 internal constant INITIAL_BP_BOND = 25;

    /// The default intent's declared channel-fund amount (== the accrual cap once finalized).
    uint64 internal constant DEFAULT_FUND_AMOUNT = 75;

    mapping(uint32 => uint64) internal _testFrozenExitGeneration;
    mapping(uint32 => bytes32) public materializedChannelExit;
    bool internal _testBackingAvailable = true;
    bool internal _testBackingCurrent = true;

    function freezeFromManager(uint32 channelId, uint64 generation) external {
        require(_testFrozenExitGeneration[channelId] == 0, "already frozen");
        _testFrozenExitGeneration[channelId] = generation;
    }

    function unfreezeFromManager(uint32 channelId, uint64 generation) external {
        require(_testFrozenExitGeneration[channelId] == generation, "wrong generation");
        delete _testFrozenExitGeneration[channelId];
    }

    function requireSignedHeadBacking(uint32 channelId, bytes32, bytes32) external view {
        bool requireCurrent = ChannelSettlementManager(payable(msg.sender)).channelStatus()
            != ChannelSettlementManager.ChannelLifecycleStatus.Active;
        require(
            msg.sender.code.length != 0 && channelId == uint32(CHANNEL_ID) && _testBackingAvailable
                && (!requireCurrent || _testBackingCurrent),
            "backing unavailable"
        );
    }

    function setUp() public virtual {
        mockMle = new MockPinnedMleVerifierV2(block.chainid);
        withdrawalClaimMle = new MockPinnedMleVerifierV2(block.chainid);
        postCloseClaimMle = new MockPinnedMleVerifierV2(block.chainid);
        cancelCloseMle = new MockPinnedMleVerifierV2(block.chainid);
        verifier = new ChannelSettlementVerifier(mockMle, withdrawalClaimMle, postCloseClaimMle, cancelCloseMle);
        registry = new MockRollupRegistry(IChannelSettlementVerifier(address(verifier)));

        bytes32[] memory activeHashes = new bytes32[](3);
        activeHashes[0] = USER_A;
        activeHashes[1] = USER_B;
        activeHashes[2] = USER_C;
        registry.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, activeHashes);

        manager = _deployManager(registry, alice, bob, carol);
    }

    // ── deployment helpers ──

    function _deployManager(MockRollupRegistry reg, address rA, address rB, address rC)
        internal
        returns (ChannelSettlementManager m)
    {
        return _deployManagerWithMaterializer(reg, rA, rB, rC, address(this));
    }

    function _deployManagerWithMaterializer(
        MockRollupRegistry reg,
        address rA,
        address rB,
        address rC,
        address materializer
    ) internal returns (ChannelSettlementManager m) {
        ChannelSettlementManager.MemberBinding[] memory bindings = new ChannelSettlementManager.MemberBinding[](3);
        bindings[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: rA});
        bindings[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: rB});
        bindings[2] = ChannelSettlementManager.MemberBinding({pkG: USER_C, recipient: rC});
        m = new ChannelSettlementManager(
            CHANNEL_ID,
            BP_MEMBER_SLOT,
            USER_A,
            0,
            bytes32(0),
            CHALLENGE_PERIOD,
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)),
            IChannelRegistry(address(reg)),
            materializer,
            bindings
        );
    }

    // ── intent + proof builders ──

    function _intent(uint64 _closeNonce, uint64 finalEpoch, uint64 finalSmallBlockNumber, uint64 closeFreezeNonce)
        internal
        pure
        returns (ChannelSettlementManager.CloseIntent memory intent)
    {
        intent = _intentWithFund(_closeNonce, finalEpoch, finalSmallBlockNumber, closeFreezeNonce, DEFAULT_FUND_AMOUNT);
    }

    /// Single-token (genesis ETH) fund vector: amount at slot 0, zero elsewhere.
    function _singleAmounts(uint256 amount) internal pure returns (uint256[10] memory a) {
        a[0] = amount;
    }

    /// Single-token registry: base token 0 (ETH) at slot 0.
    function _singleRegistry() internal pure returns (uint32[10] memory r) {
        r[0] = 0;
    }

    /// Intent with a custom declared genesis-token channel-fund amount (single-token close — the
    /// v1-state embedding: registry=[ETH], all funds at token slot 0).
    function _intentWithFund(
        uint64 _closeNonce,
        uint64 finalEpoch,
        uint64 finalSmallBlockNumber,
        uint64 closeFreezeNonce,
        uint256 channelFundAmount
    ) internal pure returns (ChannelSettlementManager.CloseIntent memory intent) {
        intent = _intentWithTokens(
            _closeNonce,
            finalEpoch,
            finalSmallBlockNumber,
            closeFreezeNonce,
            _singleAmounts(channelFundAmount),
            _singleRegistry(),
            1
        );
    }

    /// Multi-token intent: full (amounts, registry, count) vectors (multitoken Phase 3).
    function _intentWithTokens(
        uint64 _closeNonce,
        uint64 finalEpoch,
        uint64 finalSmallBlockNumber,
        uint64 closeFreezeNonce,
        uint256[10] memory channelFundAmounts,
        uint32[10] memory tokenRegistry,
        uint8 tokenCount
    ) internal pure returns (ChannelSettlementManager.CloseIntent memory intent) {
        intent = ChannelSettlementManager.CloseIntent({
            // M-9: the ABI retains closeNonce, but its only accepted representation is the
            // circuit-derived closeFreezeNonce successor.
            closeNonce: closeFreezeNonce,
            finalEpoch: finalEpoch,
            finalSmallBlockNumber: finalSmallBlockNumber,
            closeFreezeNonce: closeFreezeNonce,
            finalChannelStateDigest: keccak256("final_state"),
            finalBalanceStateH1: keccak256("balance_state_h1"),
            channelFundAmounts: channelFundAmounts,
            tokenRegistry: tokenRegistry,
            tokenCount: tokenCount,
            channelFundIntmaxStateRoot: keccak256("intmax_root"),
            burnTxHash: bytes32(0),
            closeWithdrawalDigest: keccak256("burn_backed_close"),
            snapshotMediumBlockNumber: 0,
            finalStateVersion: 12,
            finalSettledTxChain: keccak256("settled_tx_chain"),
            finalSettledTxAccumulatorRoot: keccak256("settled_tx_accumulator_root")
        });
    }

    function _closeProof(ChannelSettlementManager.CloseIntent memory intent)
        internal
        view
        returns (bytes memory)
    {
        return this._closeProofCd(
            intent,
            manager.registeredMemberSetCommitment(),
            manager.activeMemberCount(),
            uint32(manager.activeDelegateCount())
        );
    }

    /// B-2: build a close proof whose PI limb 94 (`delegateCount`) is an EXPLICIT value rather than
    /// the manager's registered count. Used by the delegate-count range tests — the registered count
    /// is only a FLOOR now, so a proof may legitimately carry a larger one (a delegate joined after
    /// the manager was deployed), and must be REJECTED with a smaller one.
    function _closeProofWithDelegateCount(ChannelSettlementManager.CloseIntent memory intent, uint32 delegateCount)
        internal
        view
        returns (bytes memory)
    {
        return
            this._closeProofCd(
                intent, manager.registeredMemberSetCommitment(), manager.activeMemberCount(), delegateCount
            );
    }

    function _closeProofFor(ChannelSettlementManager m, ChannelSettlementManager.CloseIntent memory intent)
        internal
        view
        returns (bytes memory)
    {
        return this._closeProofCd(
            intent, m.registeredMemberSetCommitment(), m.activeMemberCount(), uint32(m.activeDelegateCount())
        );
    }

    /// External so `intent` is read from CALLDATA — builds the 17-field `CloseProofFields` from a
    /// calldata struct, staying within the via-IR stack budget (mirrors the manager harness).
    function _closeProofCd(
        ChannelSettlementManager.CloseIntent calldata intent,
        bytes32 memberSetCommitment,
        uint8 memberCount,
        uint32 delegateCount
    ) external view returns (bytes memory) {
        uint256[] memory limbs = verifier.expectedCloseLimbs(
            CloseProofFields({
                channelId: CHANNEL_ID,
                closeNonce: intent.closeNonce,
                finalEpoch: intent.finalEpoch,
                finalSmallBlockNumber: intent.finalSmallBlockNumber,
                closeFreezeNonce: intent.closeFreezeNonce,
                finalChannelStateDigest: intent.finalChannelStateDigest,
                finalBalanceStateH1: intent.finalBalanceStateH1,
                channelFundAmounts: intent.channelFundAmounts,
                tokenRegistry: intent.tokenRegistry,
                tokenCount: intent.tokenCount,
                channelFundIntmaxStateRoot: intent.channelFundIntmaxStateRoot,
                burnTxHash: intent.burnTxHash,
                closeWithdrawalDigest: intent.closeWithdrawalDigest,
                snapshotMediumBlockNumber: intent.snapshotMediumBlockNumber,
                finalStateVersion: intent.finalStateVersion,
                finalSettledTxChain: intent.finalSettledTxChain,
                finalSettledTxAccumulatorRoot: intent.finalSettledTxAccumulatorRoot,
                memberSetCommitment: memberSetCommitment,
                memberCount: memberCount,
                // B-2: `minDelegateCount` is only the FLOOR predicate input; the limb-94 VALUE laid out
                // in the vector is the explicit second argument below.
                minDelegateCount: delegateCount
            }),
            delegateCount
        );
        return CloseTestLib.proofWithLimbs(limbs);
    }

    // ── withdrawal-claim builders ──

    /// Build a withdrawal claim with the canonical per-member nullifier (one slot per member),
    /// genesis token (slot 0 / base token 0).
    function _withdrawalClaim(bytes32 closeIntentDigest, bytes32 memberPkG, address recipient, uint64 amount)
        internal
        pure
        returns (ChannelSettlementManager.WithdrawalClaim memory claim)
    {
        claim = _withdrawalClaimToken(closeIntentDigest, memberPkG, recipient, amount, 0, 0);
    }

    /// Per-(member, token) withdrawal claim (multitoken §N-6): the mock nullifier mirrors the IMW2
    /// shape's KEYING — unique per (member, token slot) — without faking the real keccak preimage.
    function _withdrawalClaimToken(
        bytes32 closeIntentDigest,
        bytes32 memberPkG,
        address recipient,
        uint64 amount,
        uint8 tokenSlot,
        uint32 tokenIndex
    ) internal pure returns (ChannelSettlementManager.WithdrawalClaim memory claim) {
        claim = ChannelSettlementManager.WithdrawalClaim({
            closeIntentDigest: closeIntentDigest,
            memberPkG: memberPkG,
            recipient: recipient,
            userAmountDigest: keccak256(abi.encodePacked(memberPkG, amount)),
            amount: amount,
            tokenSlot: tokenSlot,
            tokenIndex: tokenIndex,
            withdrawalNullifier: keccak256(abi.encodePacked("withdraw", closeIntentDigest, memberPkG, tokenSlot))
        });
    }

    /// As above, but with a salt-varied nullifier so a stress test can drive MANY distinct accepted
    /// claims. (In production each member's slot yields one proof-bound nullifier; varying it here
    /// only stresses the manager's accrual/solvency accounting, which must hold for any sequence.)
    function _withdrawalClaimSalted(
        bytes32 closeIntentDigest,
        bytes32 memberPkG,
        address recipient,
        uint64 amount,
        uint256 salt
    ) internal pure returns (ChannelSettlementManager.WithdrawalClaim memory claim) {
        claim = ChannelSettlementManager.WithdrawalClaim({
                closeIntentDigest: closeIntentDigest,
                memberPkG: memberPkG,
                recipient: recipient,
                userAmountDigest: keccak256(abi.encodePacked(memberPkG, amount, salt)),
                amount: amount,
                tokenSlot: 0,
                tokenIndex: 0,
                withdrawalNullifier: keccak256(abi.encodePacked("withdraw", closeIntentDigest, memberPkG, salt))
            });
    }

    function _withdrawalClaimProofFor(ChannelSettlementManager m, ChannelSettlementManager.WithdrawalClaim memory claim)
        internal
        view
        returns (bytes memory)
    {
        uint256[] memory limbs = verifier.expectedWithdrawalClaimLimbs(
            CHANNEL_ID,
            claim.closeIntentDigest,
            m.finalizedBalanceStateH1(),
            claim.memberPkG,
            claim.recipient,
            claim.userAmountDigest,
            claim.amount,
            claim.tokenSlot,
            claim.tokenIndex,
            claim.withdrawalNullifier
        );
        return CloseTestLib.proofWithLimbs(limbs);
    }

    function _withdrawalClaimProof(ChannelSettlementManager.WithdrawalClaim memory claim)
        internal
        view
        returns (bytes memory)
    {
        return _withdrawalClaimProofFor(manager, claim);
    }

    // ── post-close-claim builders ──

    function _expectedSharedNativeNullifier(bytes32 closeIntentDigest, bytes32 incomingTxHash, bytes32 receiverPkG)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(bytes4(uint32(0x494d434b)), closeIntentDigest, incomingTxHash, receiverPkG));
    }

    /// @dev Genesis-token (ETH, tokenIndex 0) convenience overload — the single-token test
    ///      channels' registry is [0], so 0 is the registered base token.
    function _postCloseClaim(
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverPkG,
        address recipient,
        uint64 amount
    ) internal pure returns (ChannelSettlementManager.PostCloseClaim memory claim) {
        claim = _postCloseClaim(closeIntentDigest, incomingTxHash, receiverPkG, recipient, amount, 0);
    }

    /// @dev TM-16: full form with the PROOF-bound base tokenIndex (PI limb 56).
    function _postCloseClaim(
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverPkG,
        address recipient,
        uint64 amount,
        uint32 tokenIndex
    ) internal pure returns (ChannelSettlementManager.PostCloseClaim memory claim) {
        claim = ChannelSettlementManager.PostCloseClaim({
            closeIntentDigest: closeIntentDigest,
            incomingTxHash: incomingTxHash,
            receiverPkG: receiverPkG,
            recipient: recipient,
            amount: amount,
            tokenIndex: tokenIndex
        });
    }

    function _postCloseClaimProofFor(ChannelSettlementManager m, ChannelSettlementManager.PostCloseClaim memory claim)
        internal
        view
        returns (bytes memory)
    {
        bytes32 snn = _expectedSharedNativeNullifier(claim.closeIntentDigest, claim.incomingTxHash, claim.receiverPkG);
        uint256[] memory limbs = verifier.expectedPostCloseClaimLimbs(
            CHANNEL_ID,
            claim.closeIntentDigest,
            claim.incomingTxHash,
            claim.receiverPkG,
            claim.recipient,
            snn,
            claim.amount,
            m.finalizedBalanceStateH1(),
            m.finalizedSettledTxAccumulatorRoot(),
            claim.tokenIndex
        );
        return CloseTestLib.proofWithLimbs(limbs);
    }

    function _postCloseClaimProof(ChannelSettlementManager.PostCloseClaim memory claim)
        internal
        view
        returns (bytes memory)
    {
        return _postCloseClaimProofFor(manager, claim);
    }

    // ── lifecycle drivers ──

    function _requestCloseAndElapseGrace() internal {
        uint64 freezeNonce = manager.currentCloseFreezeNonce();
        uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
        vm.prank(alice);
        manager.requestClose(freezeNonce, cancellationFloor);
        vm.warp(block.timestamp + GRACE);
    }

    function _submitClose(ChannelSettlementManager.CloseIntent memory intent) internal {
        manager.submitCloseIntent(intent, _closeProof(intent));
    }

    /// Drive the default manager to Closed with the default 75-fund intent; return the digest.
    function _finalizeDefault() internal returns (bytes32) {
        _requestCloseAndElapseGrace();
        _submitClose(_intent(1, 9, 22, 1));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        return manager.finalizedCloseIntentDigest();
    }

    /// Drive the default manager to Closed with a custom declared channel-fund amount.
    function _finalizeWithFund(uint256 channelFundAmount) internal returns (bytes32) {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intentWithFund(1, 9, 22, 1, channelFundAmount);
        manager.submitCloseIntent(intent, _closeProof(intent));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
        return manager.finalizedCloseIntentDigest();
    }

    /// Simulate the rollup paying this manager via a finalized native withdrawal, then pull it in.
    function _fundAndPull(MockRollupRegistry reg, ChannelSettlementManager m, uint256 amount) internal {
        _materializeCloseFundingAuthorization(reg, m, 0);
        vm.deal(address(this), address(this).balance + amount);
        reg.creditWithdrawal{value: amount}(address(m));
        m.pullChannelFunds();
    }

    /// Simulate the immutable materializer's exact close-digest receipt. Generic recipient credit
    /// alone must never make a Manager pull-ready.
    function _materializeCloseFundingAuthorization(
        MockRollupRegistry,
        ChannelSettlementManager m,
        uint32
    ) internal returns (bytes32 authDigest) {
        authDigest = m.finalizedCloseIntentDigest();
        materializedChannelExit[uint32(m.channelId())] = authDigest;
    }

    /// Allow this base (acting as the funder of `creditWithdrawal`) to receive ETH refunds if any.
    receive() external payable {}
}
