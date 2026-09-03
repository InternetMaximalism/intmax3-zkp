// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {MockMleVerifier} from "./CloseTestLib.sol";

contract ExitRollupHarness {
    address public immutable deployer = msg.sender;
    address public materializer;
    uint64 public blockNumber;
    uint64 public latestFinalizedBlockNumber;
    mapping(uint32 => bytes32) public channelMemberSetCommitment;
    mapping(bytes32 => bool) public isFinalizedStateRoot;
    uint256 public totalEscrowed;
    mapping(uint32 => uint256) public escrowedByToken;
    mapping(address => uint256) public pendingWithdrawals;
    mapping(uint32 => mapping(address => uint256)) public pendingTokenWithdrawals;

    function setRegisteredChannel(uint32 channelId) external {
        channelMemberSetCommitment[channelId] = bytes32(uint256(1));
    }

    function setHead(uint64 head, uint64 finalized) external {
        blockNumber = head;
        latestFinalizedBlockNumber = finalized;
    }

    function setFinalizedRoot(bytes32 root) external {
        isFinalizedStateRoot[root] = true;
    }

    function bind(CloseFundingMaterializer materializer_, address manager) external {
        materializer = address(materializer_);
        materializer_.bindManager(manager);
    }

    function post(CloseFundingMaterializer materializer_, uint32 channelId, uint64 number) external {
        materializer_.recordPost(channelId, number);
        blockNumber = number;
    }

    function rollback(CloseFundingMaterializer materializer_, uint64 number, uint64 restoredHead) external {
        materializer_.rollbackPost(number);
        blockNumber = restoredHead;
    }

    function seedEscrow(uint256 nativeAmount, uint32 tokenIndex, uint256 tokenAmount) external {
        totalEscrowed = nativeAmount;
        escrowedByToken[tokenIndex] = tokenAmount;
    }

    function creditChannelExit(address manager, uint32 tokenIndex, uint256 amount) external {
        require(msg.sender == materializer, "only materializer");
        if (tokenIndex == 0) {
            totalEscrowed -= amount;
            pendingWithdrawals[manager] += amount;
        } else {
            escrowedByToken[tokenIndex] -= amount;
            pendingTokenWithdrawals[tokenIndex][manager] += amount;
        }
    }
}

contract ExitManagerHarness {
    bytes4 public immutable channelId;
    address public immutable registry;
    address public immutable closeFundingMaterializer;
    ChannelSettlementManager.ChannelLifecycleStatus public channelStatus;
    uint64 public closeRequestGeneration;
    bytes32 public finalizedCloseIntentDigest;
    bytes32 public finalizedChannelFundIntmaxStateRoot;
    bytes32 public finalizedSettledTxChain;
    bytes32 public finalizedTokenFundsDigest;
    uint8 public finalizedTokenCount;
    uint32[10] public finalizedTokenRegistry;
    mapping(uint32 => uint256) public finalizedChannelFundAmount;

    constructor(bytes4 channelId_, address registry_, address materializer_) {
        channelId = channelId_;
        registry = registry_;
        closeFundingMaterializer = materializer_;
        channelStatus = ChannelSettlementManager.ChannelLifecycleStatus.Active;
    }

    function requestClose() external {
        closeRequestGeneration++;
        channelStatus = ChannelSettlementManager.ChannelLifecycleStatus.ClosePending;
        CloseFundingMaterializer(closeFundingMaterializer).freezeFromManager(uint32(channelId), closeRequestGeneration);
    }

    function cancelClose(uint64 generation) external {
        CloseFundingMaterializer(closeFundingMaterializer).unfreezeFromManager(uint32(channelId), generation);
        channelStatus = ChannelSettlementManager.ChannelLifecycleStatus.Active;
    }

    function finishClose(
        bytes32 digest,
        bytes32 signedRoot,
        bytes32 settledChain,
        bytes32 tokenFundsDigest,
        uint32[] calldata tokens,
        uint256[] calldata amounts
    ) external {
        require(tokens.length == amounts.length && tokens.length <= 10, "shape");
        finalizedCloseIntentDigest = digest;
        finalizedChannelFundIntmaxStateRoot = signedRoot;
        finalizedSettledTxChain = settledChain;
        finalizedTokenFundsDigest = tokenFundsDigest;
        finalizedTokenCount = uint8(tokens.length);
        for (uint256 i = 0; i < tokens.length; ++i) {
            finalizedTokenRegistry[i] = tokens[i];
            finalizedChannelFundAmount[tokens[i]] = amounts[i];
        }
        channelStatus = ChannelSettlementManager.ChannelLifecycleStatus.Closed;
    }
}

contract SignerIndependentExitTest is Test {
    uint32 private constant CHANNEL = 7;
    uint32 private constant TOKEN = 5;
    bytes32 private constant SIGNED_ROOT = keccak256("signed H root");
    bytes32 private constant BACKING_ROOT = keccak256("backing ext root");
    bytes32 private constant SETTLED = keccak256("settled chain");
    bytes32 private constant TFD = keccak256("exact token funds digest");
    bytes32 private constant CLOSE_DIGEST = keccak256("close intent");

    ExitRollupHarness private rollup;
    CloseFundingMaterializer private materializer;
    ExitManagerHarness private manager;
    MockMleVerifier private verifier;

    function setUp() external {
        rollup = new ExitRollupHarness();
        materializer = new CloseFundingMaterializer(IntmaxRollup(payable(address(rollup))));
        manager = new ExitManagerHarness(bytes4(CHANNEL), address(rollup), address(materializer));
        verifier = new MockMleVerifier();
        rollup.setRegisteredChannel(CHANNEL);
        rollup.setFinalizedRoot(SIGNED_ROOT);
        rollup.setFinalizedRoot(BACKING_ROOT);
        rollup.bind(materializer, address(manager));

        CloseFundingMaterializer.MleVk memory vk = CloseFundingMaterializer.MleVk({
            degreeBits: 1,
            preprocessedRoot: bytes32(uint256(1)),
            numConstants: 1,
            numRoutedWires: 1,
            gatesDigest: bytes32(uint256(2))
        });
        SpongefishWhirVerify.WhirParams memory whir;
        uint256[] memory empty = new uint256[](0);
        materializer.initializeBackingVk(MleVerifier(address(verifier)), vk, whir, bytes(""), bytes(""), empty, empty);
    }

    function test_bindingUsesCanonicalHeadAsPrehistoryFloor() external {
        ExitRollupHarness laterRollup = new ExitRollupHarness();
        laterRollup.setHead(9, 9);
        laterRollup.setRegisteredChannel(CHANNEL);
        CloseFundingMaterializer later = new CloseFundingMaterializer(IntmaxRollup(payable(address(laterRollup))));
        ExitManagerHarness laterManager = new ExitManagerHarness(bytes4(CHANNEL), address(laterRollup), address(later));
        laterRollup.bind(later, address(laterManager));
        assertEq(later.lastPostedBlock(CHANNEL), 9);
    }

    function test_freezeRejectsPost_cancelExactGenerationRestoresPosting() external {
        manager.requestClose();
        vm.expectRevert(CloseFundingMaterializer.ChannelExitAlreadyFrozen.selector);
        rollup.post(materializer, CHANNEL, 1);

        vm.expectRevert(CloseFundingMaterializer.ChannelExitGenerationMismatch.selector);
        manager.cancelClose(2);
        manager.cancelClose(1);
        rollup.post(materializer, CHANNEL, 1);
        assertEq(materializer.lastPostedBlock(CHANNEL), 1);
    }

    function test_rollbackRestoresExactPerChannelPointer() external {
        rollup.post(materializer, CHANNEL, 1);
        rollup.post(materializer, CHANNEL, 2);
        rollup.rollback(materializer, 2, 1);
        assertEq(materializer.lastPostedBlock(CHANNEL), 1);
    }

    function test_permissionlessWholeVectorMaterializationIsAtomicAndSingleUse() external {
        MleVerifier.MleProof memory proof = _proof(0, SETTLED, TFD, BACKING_ROOT);
        address caller = makeAddr("permissionless caller");
        vm.prank(caller);
        materializer.attestSignedHeadBacking(ChannelSettlementManager(payable(address(manager))), proof);
        _closeTwoTokens(11, 29);
        rollup.seedEscrow(11, TOKEN, 29);
        vm.prank(caller);
        materializer.materializeSignedHead(ChannelSettlementManager(payable(address(manager))), proof);

        assertEq(rollup.totalEscrowed(), 0);
        assertEq(rollup.escrowedByToken(TOKEN), 0);
        assertEq(rollup.pendingWithdrawals(address(manager)), 11);
        assertEq(rollup.pendingTokenWithdrawals(TOKEN, address(manager)), 29);
        assertEq(materializer.materializedChannelExit(CHANNEL), CLOSE_DIGEST);

        vm.expectRevert(CloseFundingMaterializer.ChannelAlreadyExited.selector);
        materializer.materializeSignedHead(ChannelSettlementManager(payable(address(manager))), proof);
    }

    function test_crossedTokenFundsDigestFailsClosed() external {
        MleVerifier.MleProof memory crossed = _proof(0, SETTLED, keccak256("other vector"), BACKING_ROOT);
        materializer.attestSignedHeadBacking(ChannelSettlementManager(payable(address(manager))), crossed);
        assertTrue(
            materializer.hasSignedHeadBacking(address(manager), CHANNEL, SETTLED, keccak256("other vector"), true)
        );
        assertFalse(materializer.hasSignedHeadBacking(address(manager), CHANNEL, SETTLED, TFD, true));
        _closeTwoTokens(11, 29);
        rollup.seedEscrow(11, TOKEN, 29);
        vm.expectRevert(CloseFundingMaterializer.BackingPublicInputsMismatch.selector);
        materializer.materializeSignedHead(ChannelSettlementManager(payable(address(manager))), crossed);
        assertEq(materializer.materializedChannelExit(CHANNEL), bytes32(0));
    }

    function test_pendingPostAndUnfinalizedAnchorFailClosed() external {
        MleVerifier.MleProof memory stale = _proof(0, SETTLED, TFD, BACKING_ROOT);
        materializer.attestSignedHeadBacking(ChannelSettlementManager(payable(address(manager))), stale);
        rollup.post(materializer, CHANNEL, 1);
        assertFalse(materializer.hasSignedHeadBacking(address(manager), CHANNEL, SETTLED, TFD, true));
        assertTrue(materializer.hasSignedHeadBacking(address(manager), CHANNEL, SETTLED, TFD, false));
        manager.requestClose();
        _finishTwoTokens(11, 29);
        rollup.seedEscrow(11, TOKEN, 29);

        vm.expectRevert(CloseFundingMaterializer.ChannelExitHasUnfinalizedBlocks.selector);
        materializer.materializeSignedHead(ChannelSettlementManager(payable(address(manager))), stale);

        MleVerifier.MleProof memory future = _proof(2, SETTLED, TFD, BACKING_ROOT);
        vm.expectRevert(CloseFundingMaterializer.ChannelExitHasUnfinalizedBlocks.selector);
        materializer.attestSignedHeadBacking(ChannelSettlementManager(payable(address(manager))), future);
    }

    function test_historicalAttestationRemainsAvailableForAuthenticatedPartialWithdrawal() external {
        MleVerifier.MleProof memory historical = _proof(0, SETTLED, TFD, BACKING_ROOT);
        rollup.post(materializer, CHANNEL, 1);

        materializer.attestSignedHeadBacking(ChannelSettlementManager(payable(address(manager))), historical);

        assertTrue(materializer.hasSignedHeadBacking(address(manager), CHANNEL, SETTLED, TFD, false));
        assertFalse(materializer.hasSignedHeadBacking(address(manager), CHANNEL, SETTLED, TFD, true));
    }

    function test_rollbackMakesPreviouslyAttestedHeadCurrentAgain() external {
        MleVerifier.MleProof memory headZero = _proof(0, SETTLED, TFD, BACKING_ROOT);
        materializer.attestSignedHeadBacking(ChannelSettlementManager(payable(address(manager))), headZero);
        rollup.post(materializer, CHANNEL, 1);
        assertFalse(materializer.hasSignedHeadBacking(address(manager), CHANNEL, SETTLED, TFD, true));

        rollup.rollback(materializer, 1, 0);

        assertTrue(materializer.hasSignedHeadBacking(address(manager), CHANNEL, SETTLED, TFD, true));
    }

    function test_erc20FailureRevertsEarlierNativeCreditAndLatch() external {
        MleVerifier.MleProof memory proof = _proof(0, SETTLED, TFD, BACKING_ROOT);
        materializer.attestSignedHeadBacking(ChannelSettlementManager(payable(address(manager))), proof);
        _closeTwoTokens(11, 29);
        rollup.seedEscrow(11, TOKEN, 28);
        vm.expectRevert();
        materializer.materializeSignedHead(ChannelSettlementManager(payable(address(manager))), proof);
        assertEq(rollup.totalEscrowed(), 11);
        assertEq(rollup.pendingWithdrawals(address(manager)), 0);
        assertEq(materializer.materializedChannelExit(CHANNEL), bytes32(0));
    }

    function test_invalidBackingProofCannotMaterialize() external {
        verifier.setVerdict(false);
        vm.expectRevert(CloseFundingMaterializer.BackingProofInvalid.selector);
        materializer.attestSignedHeadBacking(
            ChannelSettlementManager(payable(address(manager))), _proof(0, SETTLED, TFD, BACKING_ROOT)
        );
    }

    function test_materializationRequiresExactPriorAttestation() external {
        _closeTwoTokens(11, 29);
        rollup.seedEscrow(11, TOKEN, 29);
        vm.expectRevert(CloseFundingMaterializer.BackingProofNotAttested.selector);
        materializer.materializeSignedHead(
            ChannelSettlementManager(payable(address(manager))), _proof(0, SETTLED, TFD, BACKING_ROOT)
        );
        assertEq(rollup.totalEscrowed(), 11);
        assertEq(materializer.materializedChannelExit(CHANNEL), bytes32(0));
    }

    function _closeTwoTokens(uint256 nativeAmount, uint256 tokenAmount) private {
        manager.requestClose();
        _finishTwoTokens(nativeAmount, tokenAmount);
    }

    function _finishTwoTokens(uint256 nativeAmount, uint256 tokenAmount) private {
        uint32[] memory tokens = new uint32[](2);
        tokens[0] = 0;
        tokens[1] = TOKEN;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = nativeAmount;
        amounts[1] = tokenAmount;
        manager.finishClose(CLOSE_DIGEST, SIGNED_ROOT, SETTLED, TFD, tokens, amounts);
    }

    function _proof(uint64 anchor, bytes32 settled, bytes32 tfd, bytes32 backingRoot)
        private
        pure
        returns (MleVerifier.MleProof memory proof)
    {
        proof.publicInputs = new uint256[](26);
        proof.publicInputs[0] = CHANNEL;
        _putBytes32(proof.publicInputs, 1, settled);
        _putBytes32(proof.publicInputs, 9, tfd);
        _putBytes32(proof.publicInputs, 17, backingRoot);
        proof.publicInputs[25] = anchor;
    }

    function _putBytes32(uint256[] memory limbs, uint256 offset, bytes32 value) private pure {
        uint256 v = uint256(value);
        for (uint256 i = 0; i < 8; ++i) {
            limbs[offset + i] = uint32(v >> (224 - 32 * i));
        }
    }
}
