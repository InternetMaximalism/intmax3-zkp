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
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {MockMleVerifier, CloseTestLib} from "./CloseTestLib.sol";

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

    function register(uint32 channelId, uint8 bpMemberSlot, bytes32[] memory activeHashes) external {
        bytes32[16] memory padded;
        for (uint256 i = 0; i < activeHashes.length; i++) {
            padded[i] = activeHashes[i];
        }
        channelMemberSetCommitment[channelId] =
            verifier.closeMemberSetCommitment(padded, uint8(activeHashes.length));
        channelBpMemberSlot[channelId] = bpMemberSlot;
        channelBpPkG[channelId] = activeHashes[bpMemberSlot];
    }

    // --- pull-payment stand-in for IntmaxRollup native withdrawal ---
    mapping(address => uint256) public pendingWithdrawals;

    function creditWithdrawal(address recipient) external payable {
        pendingWithdrawals[recipient] += msg.value;
    }

    function withdraw() external override {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "nothing to withdraw");
        pendingWithdrawals[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "withdraw failed");
    }
}

/// @title CloseSettlementBase
/// @notice Shared harness for the close-settlement adversarial / invariant suites. Mirrors the
///         deployment + proof-builder helpers in `ChannelSettlementManager.t.sol` (mock MLE
///         verdict=true, real 95/48/56-limb strict binding), but carries NO test functions so the
///         existing suite is not re-run when these new suites compile.
abstract contract CloseSettlementBase is Test {
    ChannelSettlementVerifier internal verifier;
    MockMleVerifier internal mockMle;
    MockRollupRegistry internal registry;
    ChannelSettlementManager internal manager;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    address internal mallory = makeAddr("mallory");

    bytes4 internal constant CHANNEL_ID = hex"00000009";
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

    function setUp() public virtual {
        verifier = new ChannelSettlementVerifier();
        mockMle = new MockMleVerifier();
        _initCloseVk(verifier);
        _initWithdrawalClaimVk(verifier);
        _initPostCloseClaimVk(verifier);
        _initCancelCloseVk(verifier);
        registry = new MockRollupRegistry(IChannelSettlementVerifier(address(verifier)));

        bytes32[] memory activeHashes = new bytes32[](3);
        activeHashes[0] = USER_A;
        activeHashes[1] = USER_B;
        activeHashes[2] = USER_C;
        registry.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, activeHashes);

        manager = _deployManager(registry, alice, bob, carol);
    }

    // ── deployment helpers ──

    function _deployManager(
        MockRollupRegistry reg,
        address rA,
        address rB,
        address rC
    ) internal returns (ChannelSettlementManager m) {
        ChannelSettlementManager.MemberBinding[] memory bindings =
            new ChannelSettlementManager.MemberBinding[](3);
        bindings[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: rA});
        bindings[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: rB});
        bindings[2] = ChannelSettlementManager.MemberBinding({pkG: USER_C, recipient: rC});
        m = new ChannelSettlementManager(
            CHANNEL_ID,
            BP_MEMBER_SLOT,
            USER_A,
            0,
            CHALLENGE_PERIOD,
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)),
            IChannelRegistry(address(reg)),
            bindings,
            new ChannelSettlementManager.MemberBinding[](0)
        );
    }

    // ── VK init ──

    function _initCloseVk(ChannelSettlementVerifier v) internal {
        (
            ChannelSettlementVerifier.CloseVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        ) = CloseTestLib.dummyVkArgs();
        v.initializeCloseVk(
            MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers
        );
    }

    function _initWithdrawalClaimVk(ChannelSettlementVerifier v) internal {
        (
            ChannelSettlementVerifier.StatementVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        ) = CloseTestLib.dummyStatementVkArgs();
        v.initializeWithdrawalClaimVk(
            MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers
        );
    }

    function _initPostCloseClaimVk(ChannelSettlementVerifier v) internal {
        (
            ChannelSettlementVerifier.StatementVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        ) = CloseTestLib.dummyStatementVkArgs();
        v.initializePostCloseClaimVk(
            MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers
        );
    }

    function _initCancelCloseVk(ChannelSettlementVerifier v) internal {
        (
            ChannelSettlementVerifier.StatementVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        ) = CloseTestLib.dummyStatementVkArgs();
        v.initializeCancelCloseVk(
            MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers
        );
    }

    // ── intent + proof builders ──

    function _intent(
        uint64 closeNonce,
        uint64 finalEpoch,
        uint64 finalSmallBlockNumber,
        uint64 closeFreezeNonce
    ) internal pure returns (ChannelSettlementManager.CloseIntent memory intent) {
        intent = _intentWithFund(closeNonce, finalEpoch, finalSmallBlockNumber, closeFreezeNonce, DEFAULT_FUND_AMOUNT);
    }

    /// Intent with a custom declared channel-fund amount (the accrual cap once finalized).
    function _intentWithFund(
        uint64 closeNonce,
        uint64 finalEpoch,
        uint64 finalSmallBlockNumber,
        uint64 closeFreezeNonce,
        uint256 channelFundAmount
    ) internal pure returns (ChannelSettlementManager.CloseIntent memory intent) {
        intent = ChannelSettlementManager.CloseIntent({
            closeNonce: closeNonce,
            finalEpoch: finalEpoch,
            finalSmallBlockNumber: finalSmallBlockNumber,
            closeFreezeNonce: closeFreezeNonce,
            finalChannelStateDigest: keccak256("final_state"),
            finalBalanceStateH1: keccak256("balance_state_h1"),
            channelFundAmount: channelFundAmount,
            channelFundIntmaxStateRoot: keccak256("intmax_root"),
            burnTxHash: keccak256("burn_tx"),
            closeWithdrawalDigest: keccak256("burn_backed_close"),
            snapshotMediumBlockNumber: 77,
            finalStateVersion: 12,
            finalSettledTxChain: keccak256("settled_tx_chain"),
            finalSettledTxAccumulatorRoot: keccak256("settled_tx_accumulator_root")
        });
    }

    function _closeProof(ChannelSettlementManager.CloseIntent memory intent)
        internal view returns (MleVerifier.MleProof memory)
    {
        return this._closeProofCd(
            intent,
            manager.registeredMemberSetCommitment(),
            (uint16(manager.activeMemberCount()) << 8) | uint16(manager.activeDelegateCount())
        );
    }

    function _closeProofFor(ChannelSettlementManager m, ChannelSettlementManager.CloseIntent memory intent)
        internal view returns (MleVerifier.MleProof memory)
    {
        return this._closeProofCd(
            intent,
            m.registeredMemberSetCommitment(),
            (uint16(m.activeMemberCount()) << 8) | uint16(m.activeDelegateCount())
        );
    }

    /// External so `intent` is read from CALLDATA — builds the 17-field `CloseProofFields` from a
    /// calldata struct, staying within the via-IR stack budget (mirrors the manager harness).
    function _closeProofCd(
        ChannelSettlementManager.CloseIntent calldata intent,
        bytes32 memberSetCommitment,
        uint16 memberAndDelegateCount
    ) external view returns (MleVerifier.MleProof memory) {
        uint256[] memory limbs = verifier.expectedCloseLimbs(CloseProofFields({
            channelId: CHANNEL_ID,
            closeNonce: intent.closeNonce,
            finalEpoch: intent.finalEpoch,
            finalSmallBlockNumber: intent.finalSmallBlockNumber,
            closeFreezeNonce: intent.closeFreezeNonce,
            finalChannelStateDigest: intent.finalChannelStateDigest,
            finalBalanceStateH1: intent.finalBalanceStateH1,
            channelFundAmount: intent.channelFundAmount,
            channelFundIntmaxStateRoot: intent.channelFundIntmaxStateRoot,
            burnTxHash: intent.burnTxHash,
            closeWithdrawalDigest: intent.closeWithdrawalDigest,
            snapshotMediumBlockNumber: intent.snapshotMediumBlockNumber,
            finalStateVersion: intent.finalStateVersion,
            finalSettledTxChain: intent.finalSettledTxChain,
            finalSettledTxAccumulatorRoot: intent.finalSettledTxAccumulatorRoot,
            memberSetCommitment: memberSetCommitment,
            memberAndDelegateCount: memberAndDelegateCount
        }));
        return CloseTestLib.proofWithLimbs(limbs);
    }

    // ── withdrawal-claim builders ──

    /// Build a withdrawal claim with the canonical per-member nullifier (one slot per member).
    function _withdrawalClaim(
        bytes32 closeIntentDigest,
        bytes32 memberPkG,
        address recipient,
        uint64 amount
    ) internal pure returns (ChannelSettlementManager.WithdrawalClaim memory claim) {
        claim = ChannelSettlementManager.WithdrawalClaim({
            closeIntentDigest: closeIntentDigest,
            memberPkG: memberPkG,
            recipient: recipient,
            userAmountDigest: keccak256(abi.encodePacked(memberPkG, amount)),
            amount: amount,
            withdrawalNullifier: keccak256(abi.encodePacked("withdraw", closeIntentDigest, memberPkG))
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
            withdrawalNullifier: keccak256(abi.encodePacked("withdraw", closeIntentDigest, memberPkG, salt))
        });
    }

    function _withdrawalClaimProofFor(
        ChannelSettlementManager m,
        ChannelSettlementManager.WithdrawalClaim memory claim
    ) internal view returns (MleVerifier.MleProof memory) {
        uint256[] memory limbs = verifier.expectedWithdrawalClaimLimbs(
            CHANNEL_ID,
            claim.closeIntentDigest,
            m.finalizedBalanceStateH1(),
            claim.memberPkG,
            claim.recipient,
            claim.userAmountDigest,
            claim.amount,
            claim.withdrawalNullifier
        );
        return CloseTestLib.proofWithLimbs(limbs);
    }

    function _withdrawalClaimProof(ChannelSettlementManager.WithdrawalClaim memory claim)
        internal view returns (MleVerifier.MleProof memory)
    {
        return _withdrawalClaimProofFor(manager, claim);
    }

    // ── post-close-claim builders ──

    function _expectedSharedNativeNullifier(
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverPkG
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(bytes4(uint32(0x494d434b)), closeIntentDigest, incomingTxHash, receiverPkG)
        );
    }

    function _postCloseClaim(
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverPkG,
        address recipient,
        uint64 amount
    ) internal pure returns (ChannelSettlementManager.PostCloseClaim memory claim) {
        claim = ChannelSettlementManager.PostCloseClaim({
            closeIntentDigest: closeIntentDigest,
            incomingTxHash: incomingTxHash,
            receiverPkG: receiverPkG,
            recipient: recipient,
            amount: amount
        });
    }

    function _postCloseClaimProofFor(
        ChannelSettlementManager m,
        ChannelSettlementManager.PostCloseClaim memory claim
    ) internal view returns (MleVerifier.MleProof memory) {
        bytes32 snn = _expectedSharedNativeNullifier(
            claim.closeIntentDigest, claim.incomingTxHash, claim.receiverPkG
        );
        uint256[] memory limbs = verifier.expectedPostCloseClaimLimbs(
            CHANNEL_ID,
            claim.closeIntentDigest,
            claim.incomingTxHash,
            claim.receiverPkG,
            claim.recipient,
            snn,
            claim.amount,
            m.finalizedBalanceStateH1(),
            m.finalizedSettledTxAccumulatorRoot()
        );
        return CloseTestLib.proofWithLimbs(limbs);
    }

    function _postCloseClaimProof(ChannelSettlementManager.PostCloseClaim memory claim)
        internal view returns (MleVerifier.MleProof memory)
    {
        return _postCloseClaimProofFor(manager, claim);
    }

    // ── lifecycle drivers ──

    function _requestCloseAndElapseGrace() internal {
        vm.prank(alice);
        manager.requestClose();
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
        manager.finalizeClose();
        return manager.finalizedCloseIntentDigest();
    }

    /// Drive the default manager to Closed with a custom declared channel-fund amount.
    function _finalizeWithFund(uint256 channelFundAmount) internal returns (bytes32) {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent =
            _intentWithFund(1, 9, 22, 1, channelFundAmount);
        manager.submitCloseIntent(intent, _closeProof(intent));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();
        return manager.finalizedCloseIntentDigest();
    }

    /// Simulate the rollup paying this manager via a finalized native withdrawal, then pull it in.
    function _fundAndPull(MockRollupRegistry reg, ChannelSettlementManager m, uint256 amount) internal {
        vm.deal(address(this), address(this).balance + amount);
        reg.creditWithdrawal{value: amount}(address(m));
        m.pullChannelFunds();
    }

    /// Allow this base (acting as the funder of `creditWithdrawal`) to receive ETH refunds if any.
    receive() external payable {}
}
