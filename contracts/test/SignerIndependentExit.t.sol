// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, stdError} from "forge-std/Test.sol";
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

    // ── Attack-regression coverage ───────────────────────────────────────────────────────────
    // Each test below pins a guard an adversarial review found exercised only implicitly. They
    // document the contract as deployed; a change in the expected selector is a semantic change.

    /// Mirror of `test_crossedTokenFundsDigestFailsClosed` for the other statement limb: a valid
    /// receipt for a different settled-tx chain is not a receipt for the finalized H.
    function test_crossedSettledTxChainFailsClosed() external {
        bytes32 otherChain = keccak256("other chain");
        MleVerifier.MleProof memory crossed = _proof(0, otherChain, TFD, BACKING_ROOT);
        materializer.attestSignedHeadBacking(_m(manager), crossed);
        assertTrue(materializer.hasSignedHeadBacking(address(manager), CHANNEL, otherChain, TFD, true));
        assertFalse(materializer.hasSignedHeadBacking(address(manager), CHANNEL, SETTLED, TFD, true));
        _closeTwoTokens(11, 29);
        rollup.seedEscrow(11, TOKEN, 29);

        vm.expectRevert(CloseFundingMaterializer.BackingPublicInputsMismatch.selector);
        materializer.materializeSignedHead(_m(manager), crossed);

        assertEq(materializer.materializedChannelExit(CHANNEL), bytes32(0));
        assertEq(rollup.totalEscrowed(), 11);
        assertEq(rollup.escrowedByToken(TOKEN), 29);
    }

    /// The attestation receipt is keyed by the hash of the WHOLE proof. Moving the anchor limb to
    /// another finalized block (or touching any non-PI field) yields an unattested proof id, even
    /// though the mutated proof still passes shape validation.
    function test_mutatedAnchorAfterAttestationIsNotAttested() external {
        rollup.setHead(2, 2);
        MleVerifier.MleProof memory proof = _proof(1, SETTLED, TFD, BACKING_ROOT);
        materializer.attestSignedHeadBacking(_m(manager), proof);
        _closeTwoTokens(11, 29);
        rollup.seedEscrow(11, TOKEN, 29);

        MleVerifier.MleProof memory mutatedAnchor = _proof(1, SETTLED, TFD, BACKING_ROOT);
        mutatedAnchor.publicInputs[25] = 0;
        vm.expectRevert(CloseFundingMaterializer.BackingProofNotAttested.selector);
        materializer.materializeSignedHead(_m(manager), mutatedAnchor);

        MleVerifier.MleProof memory mutatedBody = _proof(1, SETTLED, TFD, BACKING_ROOT);
        mutatedBody.witnessRoot = keccak256("tampered witness root");
        vm.expectRevert(CloseFundingMaterializer.BackingProofNotAttested.selector);
        materializer.materializeSignedHead(_m(manager), mutatedBody);

        assertEq(materializer.materializedChannelExit(CHANNEL), bytes32(0));
        // The exact attested proof still completes the exit.
        materializer.materializeSignedHead(_m(manager), proof);
        assertEq(materializer.materializedChannelExit(CHANNEL), CLOSE_DIGEST);
    }

    /// A receipt earned for channel 7's Manager is scoped to that (manager, channel, proof). It
    /// neither transfers to a second bound Manager nor lets channel 7's proof speak for channel 8.
    function test_attestationForChannelXCannotMaterializeChannelY() external {
        uint32 otherChannel = 8;
        ExitManagerHarness manager2 = _bindExtraManager(otherChannel);

        MleVerifier.MleProof memory proof7 = _proof(0, SETTLED, TFD, BACKING_ROOT);
        materializer.attestSignedHeadBacking(_m(manager), proof7);
        assertTrue(materializer.hasSignedHeadBacking(address(manager), CHANNEL, SETTLED, TFD, true));
        assertFalse(materializer.hasSignedHeadBacking(address(manager2), otherChannel, SETTLED, TFD, true));

        // Channel 8 closes with identical economics, so only receipt scoping stands in the way.
        manager2.requestClose();
        _finishTwoTokensOn(manager2, 11, 29);
        rollup.seedEscrow(11, TOKEN, 29);

        // Channel 7's proof presented for manager2: the channel limb is checked against the
        // supplied Manager BEFORE the receipt lookup, so this fails as a public-input mismatch.
        vm.expectRevert(CloseFundingMaterializer.BackingPublicInputsMismatch.selector);
        materializer.materializeSignedHead(_m(manager2), proof7);
        // ...and the same proof cannot be attested for manager2 either.
        vm.expectRevert(CloseFundingMaterializer.BackingPublicInputsMismatch.selector);
        materializer.attestSignedHeadBacking(_m(manager2), proof7);

        // A well-formed channel-8 proof carrying the same statement limbs: manager1's attestation
        // does not carry over, because the receipt binds the Manager address and the exact proof.
        MleVerifier.MleProof memory proof8 = _proofFor(otherChannel, 0, SETTLED, TFD, BACKING_ROOT);
        vm.expectRevert(CloseFundingMaterializer.BackingProofNotAttested.selector);
        materializer.materializeSignedHead(_m(manager2), proof8);

        assertEq(materializer.materializedChannelExit(otherChannel), bytes32(0));
        assertEq(rollup.totalEscrowed(), 11);
        assertEq(rollup.escrowedByToken(TOKEN), 29);
    }

    /// A Manager that never went through `IntmaxRollup.registerSettlementManager` (and so was
    /// never bound) cannot attest, materialize, or freeze — whether it claims a fresh channel id
    /// or impersonates the channel id of the bound Manager.
    function test_unboundManagerCannotAttestOrMaterialize() external {
        uint32 strayChannel = 9;
        rollup.setRegisteredChannel(strayChannel);
        ExitManagerHarness stray = new ExitManagerHarness(bytes4(strayChannel), address(rollup), address(materializer));
        MleVerifier.MleProof memory strayProof = _proofFor(strayChannel, 0, SETTLED, TFD, BACKING_ROOT);

        vm.expectRevert(CloseFundingMaterializer.NotBoundManager.selector);
        materializer.attestSignedHeadBacking(_m(stray), strayProof);
        vm.expectRevert(CloseFundingMaterializer.NotBoundManager.selector);
        materializer.materializeSignedHead(_m(stray), strayProof);
        vm.expectRevert(CloseFundingMaterializer.NotBoundManager.selector);
        stray.requestClose();
        assertFalse(materializer.hasSignedHeadBacking(address(stray), strayChannel, SETTLED, TFD, false));

        // Impersonating the bound channel's id does not help: binding is by Manager address.
        ExitManagerHarness impostor = new ExitManagerHarness(bytes4(CHANNEL), address(rollup), address(materializer));
        MleVerifier.MleProof memory proof7 = _proof(0, SETTLED, TFD, BACKING_ROOT);
        materializer.attestSignedHeadBacking(_m(manager), proof7);
        vm.expectRevert(CloseFundingMaterializer.NotBoundManager.selector);
        materializer.attestSignedHeadBacking(_m(impostor), proof7);
        vm.expectRevert(CloseFundingMaterializer.NotBoundManager.selector);
        materializer.materializeSignedHead(_m(impostor), proof7);
        vm.expectRevert(CloseFundingMaterializer.NotBoundManager.selector);
        impostor.requestClose();
        assertFalse(materializer.hasSignedHeadBacking(address(impostor), CHANNEL, SETTLED, TFD, false));
        assertEq(materializer.frozenGeneration(CHANNEL), 0);
    }

    /// A Manager that reaches Closed without ever freezing the channel journal (no requestClose)
    /// cannot exit: posts were never fenced, so the attested anchor proves nothing about H.
    function test_materializeBeforeFreezeFailsClosed() external {
        MleVerifier.MleProof memory proof = _proof(0, SETTLED, TFD, BACKING_ROOT);
        materializer.attestSignedHeadBacking(_m(manager), proof);
        _finishTwoTokens(11, 29);
        rollup.seedEscrow(11, TOKEN, 29);
        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.Closed));
        assertEq(materializer.frozenGeneration(CHANNEL), 0);

        vm.expectRevert(CloseFundingMaterializer.ChannelExitNotFrozen.selector);
        materializer.materializeSignedHead(_m(manager), proof);

        assertEq(materializer.materializedChannelExit(CHANNEL), bytes32(0));
        assertEq(rollup.totalEscrowed(), 11);
        assertEq(rollup.pendingWithdrawals(address(manager)), 0);
    }

    /// The finalized close must point at a signed channel-fund root the Rollup has finalized (and
    /// a non-zero close digest). Both defects fail as ChannelExitStatementMismatch; once the root
    /// finalizes, the same attested proof completes the exit.
    function test_materializeRequiresFinalizedSignedRoot() external {
        bytes32 unfinalizedRoot = keccak256("unfinalized root");
        MleVerifier.MleProof memory proof = _proof(0, SETTLED, TFD, BACKING_ROOT);
        materializer.attestSignedHeadBacking(_m(manager), proof);
        manager.requestClose();
        (uint32[] memory tokens, uint256[] memory amounts) = _twoTokenVector(11, 29);
        rollup.seedEscrow(11, TOKEN, 29);

        manager.finishClose(CLOSE_DIGEST, unfinalizedRoot, SETTLED, TFD, tokens, amounts);
        assertFalse(rollup.isFinalizedStateRoot(unfinalizedRoot));
        vm.expectRevert(CloseFundingMaterializer.ChannelExitStatementMismatch.selector);
        materializer.materializeSignedHead(_m(manager), proof);

        manager.finishClose(bytes32(0), SIGNED_ROOT, SETTLED, TFD, tokens, amounts);
        vm.expectRevert(CloseFundingMaterializer.ChannelExitStatementMismatch.selector);
        materializer.materializeSignedHead(_m(manager), proof);

        assertEq(materializer.materializedChannelExit(CHANNEL), bytes32(0));
        assertEq(rollup.totalEscrowed(), 11);

        rollup.setFinalizedRoot(unfinalizedRoot);
        manager.finishClose(CLOSE_DIGEST, unfinalizedRoot, SETTLED, TFD, tokens, amounts);
        materializer.materializeSignedHead(_m(manager), proof);
        assertEq(materializer.materializedChannelExit(CHANNEL), CLOSE_DIGEST);
        assertEq(rollup.pendingWithdrawals(address(manager)), 11);
    }

    /// Descending rollback of a range that interleaves two channels restores each channel's exact
    /// pre-post pointer, block by block.
    function test_rollbackRestoresPointersAcrossInterleavedChannels() external {
        uint32 channelB = 8;
        _bindExtraManager(channelB);
        uint64 floorA = materializer.lastPostedBlock(CHANNEL);
        uint64 floorB = materializer.lastPostedBlock(channelB);

        rollup.post(materializer, CHANNEL, 1);
        rollup.post(materializer, channelB, 2);
        rollup.post(materializer, CHANNEL, 3);
        assertEq(materializer.lastPostedBlock(CHANNEL), 3);
        assertEq(materializer.lastPostedBlock(channelB), 2);

        rollup.rollback(materializer, 3, 2);
        assertEq(materializer.lastPostedBlock(CHANNEL), 1);
        assertEq(materializer.lastPostedBlock(channelB), 2);

        rollup.rollback(materializer, 2, 1);
        assertEq(materializer.lastPostedBlock(CHANNEL), 1);
        assertEq(materializer.lastPostedBlock(channelB), floorB);

        rollup.rollback(materializer, 1, 0);
        assertEq(materializer.lastPostedBlock(CHANNEL), floorA);
        assertEq(materializer.lastPostedBlock(channelB), floorB);
    }

    /// Rolling back a block that is no longer its channel's head (1 while 3 is still posted for
    /// the same channel) is refused and leaves the journal untouched; the correct descending
    /// order still works afterwards.
    function test_rollbackOutOfOrderAcrossInterleavedChannelsFailsClosed() external {
        uint32 channelB = 8;
        _bindExtraManager(channelB);
        rollup.post(materializer, CHANNEL, 1);
        rollup.post(materializer, channelB, 2);
        rollup.post(materializer, CHANNEL, 3);

        vm.expectRevert(CloseFundingMaterializer.ChannelExitStatementMismatch.selector);
        rollup.rollback(materializer, 1, 0);
        assertEq(materializer.lastPostedBlock(CHANNEL), 3);
        assertEq(materializer.lastPostedBlock(channelB), 2);

        rollup.rollback(materializer, 3, 2);
        rollup.rollback(materializer, 2, 1);
        rollup.rollback(materializer, 1, 0);
        assertEq(materializer.lastPostedBlock(CHANNEL), 0);
        assertEq(materializer.lastPostedBlock(channelB), 0);
        // The journal entries were consumed: a second rollback of the same block is a no-op.
        rollup.rollback(materializer, 1, 0);
        assertEq(materializer.lastPostedBlock(CHANNEL), 0);
    }

    /// The exit latch is written before any credit and is never cleared by the post journal: a
    /// reorg of the anchored range cannot reopen posting, unfreeze, or a second materialization.
    function test_exitLatchSurvivesRollbackAndCannotRematerialize() external {
        rollup.post(materializer, CHANNEL, 1);
        rollup.setHead(1, 1);
        MleVerifier.MleProof memory proof = _proof(1, SETTLED, TFD, BACKING_ROOT);
        materializer.attestSignedHeadBacking(_m(manager), proof);
        _closeTwoTokens(11, 29);
        rollup.seedEscrow(11, TOKEN, 29);
        materializer.materializeSignedHead(_m(manager), proof);
        assertEq(materializer.materializedChannelExit(CHANNEL), CLOSE_DIGEST);
        assertEq(rollup.pendingWithdrawals(address(manager)), 11);

        rollup.rollback(materializer, 1, 0);
        assertEq(materializer.lastPostedBlock(CHANNEL), 0);
        assertEq(materializer.materializedChannelExit(CHANNEL), CLOSE_DIGEST);

        vm.expectRevert(CloseFundingMaterializer.ChannelAlreadyExited.selector);
        rollup.post(materializer, CHANNEL, 1);
        vm.expectRevert(CloseFundingMaterializer.ChannelAlreadyExited.selector);
        manager.cancelClose(1);

        rollup.seedEscrow(11, TOKEN, 29);
        vm.expectRevert(CloseFundingMaterializer.ChannelAlreadyExited.selector);
        materializer.materializeSignedHead(_m(manager), proof);
        assertEq(rollup.totalEscrowed(), 11);
        assertEq(rollup.pendingWithdrawals(address(manager)), 11);
        assertEq(rollup.pendingTokenWithdrawals(TOKEN, address(manager)), 29);
    }

    /// Model an already-paid burn: escrow holds 4 units less than the exact H vector on one lane.
    /// The Rollup's checked debit panics, and the panic unwinds the digest latch and the earlier
    /// lane's credit — no partial exit is ever left behind. Shown for each lane.
    function test_burnAlreadyPaidMakesExactVectorExitFailClosed() external {
        MleVerifier.MleProof memory proof = _proof(0, SETTLED, TFD, BACKING_ROOT);
        materializer.attestSignedHeadBacking(_m(manager), proof);
        _closeTwoTokens(11, 29);

        rollup.seedEscrow(11, TOKEN, 25);
        vm.expectRevert(stdError.arithmeticError);
        materializer.materializeSignedHead(_m(manager), proof);
        _assertNothingMaterialized(11, 25);

        rollup.seedEscrow(7, TOKEN, 29);
        vm.expectRevert(stdError.arithmeticError);
        materializer.materializeSignedHead(_m(manager), proof);
        _assertNothingMaterialized(7, 29);

        // The channel stays frozen and exit-capable: topping escrow back up completes the exit.
        assertEq(materializer.frozenGeneration(CHANNEL), 1);
        rollup.seedEscrow(11, TOKEN, 29);
        materializer.materializeSignedHead(_m(manager), proof);
        assertEq(materializer.materializedChannelExit(CHANNEL), CLOSE_DIGEST);
    }

    function _assertNothingMaterialized(uint256 nativeEscrow, uint256 tokenEscrow) private view {
        assertEq(materializer.materializedChannelExit(CHANNEL), bytes32(0));
        assertEq(rollup.totalEscrowed(), nativeEscrow);
        assertEq(rollup.escrowedByToken(TOKEN), tokenEscrow);
        assertEq(rollup.pendingWithdrawals(address(manager)), 0);
        assertEq(rollup.pendingTokenWithdrawals(TOKEN, address(manager)), 0);
    }

    function _bindExtraManager(uint32 channelId) private returns (ExitManagerHarness extra) {
        extra = new ExitManagerHarness(bytes4(channelId), address(rollup), address(materializer));
        rollup.setRegisteredChannel(channelId);
        rollup.bind(materializer, address(extra));
        assertEq(materializer.managerOfChannel(channelId), address(extra));
    }

    function _m(ExitManagerHarness h) private pure returns (ChannelSettlementManager) {
        return ChannelSettlementManager(payable(address(h)));
    }

    function _closeTwoTokens(uint256 nativeAmount, uint256 tokenAmount) private {
        manager.requestClose();
        _finishTwoTokens(nativeAmount, tokenAmount);
    }

    function _finishTwoTokens(uint256 nativeAmount, uint256 tokenAmount) private {
        _finishTwoTokensOn(manager, nativeAmount, tokenAmount);
    }

    function _finishTwoTokensOn(ExitManagerHarness target, uint256 nativeAmount, uint256 tokenAmount) private {
        (uint32[] memory tokens, uint256[] memory amounts) = _twoTokenVector(nativeAmount, tokenAmount);
        target.finishClose(CLOSE_DIGEST, SIGNED_ROOT, SETTLED, TFD, tokens, amounts);
    }

    function _twoTokenVector(uint256 nativeAmount, uint256 tokenAmount)
        private
        pure
        returns (uint32[] memory tokens, uint256[] memory amounts)
    {
        tokens = new uint32[](2);
        tokens[0] = 0;
        tokens[1] = TOKEN;
        amounts = new uint256[](2);
        amounts[0] = nativeAmount;
        amounts[1] = tokenAmount;
    }

    function _proof(uint64 anchor, bytes32 settled, bytes32 tfd, bytes32 backingRoot)
        private
        pure
        returns (MleVerifier.MleProof memory)
    {
        return _proofFor(CHANNEL, anchor, settled, tfd, backingRoot);
    }

    function _proofFor(uint32 channelId, uint64 anchor, bytes32 settled, bytes32 tfd, bytes32 backingRoot)
        private
        pure
        returns (MleVerifier.MleProof memory proof)
    {
        proof.publicInputs = new uint256[](26);
        proof.publicInputs[0] = channelId;
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
