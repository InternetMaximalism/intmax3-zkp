// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {TestProofDaVerifier} from "./helpers/ProofDaTestHelper.sol";
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";
import {ExitManagerHarness} from "./SignerIndependentExit.t.sol";

/// @dev A real Rollup whose channel registration is seeded directly, so the materializer binding
///      (`channelMemberSetCommitment != 0`) holds without a full `registerChannel` fixture.
contract FrozenPostRollupHarness is IntmaxRollup {
    constructor(address treasury)
        IntmaxRollup(
            treasury,
            new MockPinnedMleVerifierV2(31337),
            new MockPinnedMleVerifierV2(31337),
            bytes32(0),
            0.1 ether,
            0.001 ether
        )
    {}

    function seedRegisteredChannel(uint32 channelId) external {
        channelMemberSetCommitment[channelId] = bytes32(uint256(1));
    }
}

/// @title M7 liveness gap (2): a producer batch that still carries a sub-block of a channel the
///        Manager has frozen reverts as a whole, including every other channel's sub-block.
/// @notice `IntmaxRollup._postBlock` calls `recordPost` per sub-block and bubbles its revert, so
///         once channel A freezes on L1 with an unposted sub-block in the producer's pending span,
///         no candidate containing that sub-block can ever post. Posting the other channel's
///         sub-block ALONE succeeds: the history is only stuck because the journaled span is
///         contiguous and cannot drop A's block (see `tests/block_producer_service.rs`).
contract FrozenChannelBatchPostTest is Test {
    uint32 private constant CHANNEL_A = 7;
    uint32 private constant CHANNEL_B = 9;
    uint256 private constant BOND = 0.1 ether + 0.001 ether;

    FrozenPostRollupHarness private rollup;
    CloseFundingMaterializer private materializer;
    ExitManagerHarness private managerA;
    address private producer = makeAddr("producer");

    function setUp() external {
        rollup = new FrozenPostRollupHarness(makeAddr("treasury"));
        rollup.setKzgVerifier(BlobKZGVerifierExt(address(new TestProofDaVerifier())));
        rollup.setBlockProducer(producer, true);
        MockPinnedMleVerifierV2 verifier = new MockPinnedMleVerifierV2(block.chainid);
        materializer = new CloseFundingMaterializer(rollup, verifier, verifier);
        rollup.seedRegisteredChannel(CHANNEL_A);
        rollup.seedRegisteredChannel(CHANNEL_B);
        managerA = new ExitManagerHarness(bytes4(CHANNEL_A), address(rollup), address(materializer));
        // Binds the manager at a finalized head (block 0 == finalized 0) and installs the
        // set-once materializer on the Rollup, exactly like the deploy scripts.
        rollup.registerSettlementManager(address(managerA));
        assertEq(materializer.managerOfChannel(CHANNEL_A), address(managerA), "A is bound");
        assertEq(materializer.managerOfChannel(CHANNEL_B), address(0), "B is unbound");
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = keccak256("frozen-batch-blob");
        vm.blobhashes(hashes);
        vm.deal(producer, 10 ether);
    }

    function _subBlock(uint32 channelId, uint256 salt) internal view returns (IntmaxRollup.SubBlock memory) {
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        return IntmaxRollup.SubBlock({
            channelId: channelId,
            timestamp: uint64(block.timestamp),
            txTreeRoot: keccak256(abi.encode("tx-tree", channelId, salt)),
            keyIds: ids
        });
    }

    function _post(IntmaxRollup.SubBlock[] memory batch) internal {
        bytes32 pin = rollup.pendingChainsPin();
        vm.prank(producer);
        rollup.postBlockAndSubmit{value: BOND}(batch, bytes32(0), 0, bytes32(0), pin);
    }

    function _postExpectingFrozen(IntmaxRollup.SubBlock[] memory batch) internal {
        bytes32 pin = rollup.pendingChainsPin();
        vm.prank(producer);
        vm.expectRevert(CloseFundingMaterializer.ChannelExitAlreadyFrozen.selector);
        rollup.postBlockAndSubmit{value: BOND}(batch, bytes32(0), 0, bytes32(0), pin);
    }

    /// Block 1 (channel A) posts. A freezes. The next batch [A, B] reverts as a whole; so does
    /// [B, A]: the position of A's sub-block does not matter. B alone posts fine, and after A's
    /// close is cancelled the original [A, B] batch posts again — the span was only waiting on A.
    function test_frozenChannelSubBlockRevertsTheWholeBatch() external {
        IntmaxRollup.SubBlock[] memory first = new IntmaxRollup.SubBlock[](1);
        first[0] = _subBlock(CHANNEL_A, 1);
        _post(first);
        assertEq(rollup.blockNumber(), 1);
        assertEq(materializer.lastPostedBlock(CHANNEL_A), 1, "A's first block is journaled");

        managerA.requestClose();
        assertEq(materializer.frozenGeneration(CHANNEL_A), 1, "A is frozen");

        IntmaxRollup.SubBlock[] memory mixed = new IntmaxRollup.SubBlock[](2);
        mixed[0] = _subBlock(CHANNEL_A, 2);
        mixed[1] = _subBlock(CHANNEL_B, 3);
        _postExpectingFrozen(mixed);
        assertEq(rollup.blockNumber(), 1, "nothing of the mixed batch landed");

        IntmaxRollup.SubBlock[] memory reversed = new IntmaxRollup.SubBlock[](2);
        reversed[0] = _subBlock(CHANNEL_B, 3);
        reversed[1] = _subBlock(CHANNEL_A, 2);
        _postExpectingFrozen(reversed);
        assertEq(rollup.blockNumber(), 1, "B's sub-block does not survive A's revert");

        IntmaxRollup.SubBlock[] memory onlyB = new IntmaxRollup.SubBlock[](1);
        onlyB[0] = _subBlock(CHANNEL_B, 3);
        _post(onlyB);
        assertEq(rollup.blockNumber(), 2, "a span without A's sub-block posts");
        assertEq(materializer.lastPostedBlock(CHANNEL_A), 1, "A's pointer is untouched");

        // The owner-side way out while the close is only requested: cancelling it unfreezes A and
        // the withheld sub-block can post again.
        managerA.cancelClose(1);
        _post(mixed);
        assertEq(rollup.blockNumber(), 4);
        assertEq(materializer.lastPostedBlock(CHANNEL_A), 3);
    }

    /// Pass-2 Manager B1 (2026-10-16): a sub-block with no signer slot (all-zero keyIds) cannot
    /// carry a send for its channel, so it must neither be refused by a frozen channel nor move
    /// that channel's `lastPostedBlock`. Before the fix a producer could label such an empty block
    /// with any channel id and push that channel's journal past its last real send, which made
    /// every honest backing proof fail the close ordering rule.
    function test_unsignedSubBlockNeitherFreezesNorAdvancesTheChannelJournal() external {
        IntmaxRollup.SubBlock[] memory first = new IntmaxRollup.SubBlock[](1);
        first[0] = _subBlock(CHANNEL_A, 1);
        _post(first);
        assertEq(materializer.lastPostedBlock(CHANNEL_A), 1, "A's signed block is journaled");

        // An unsigned block labelled A does not touch A's journal.
        IntmaxRollup.SubBlock[] memory empty = new IntmaxRollup.SubBlock[](1);
        empty[0] = _unsignedSubBlock(CHANNEL_A, 2);
        _post(empty);
        assertEq(rollup.blockNumber(), 2, "the unsigned block posts");
        assertEq(materializer.lastPostedBlock(CHANNEL_A), 1, "an unsigned block never advances the journal");

        // While A is frozen the unsigned block still posts; a signed one is still refused.
        managerA.requestClose();
        assertEq(materializer.frozenGeneration(CHANNEL_A), 1, "A is frozen");
        empty[0] = _unsignedSubBlock(CHANNEL_A, 3);
        _post(empty);
        assertEq(rollup.blockNumber(), 3, "an unsigned block posts past the freeze");
        assertEq(materializer.lastPostedBlock(CHANNEL_A), 1, "journal unchanged");
        IntmaxRollup.SubBlock[] memory signed = new IntmaxRollup.SubBlock[](1);
        signed[0] = _subBlock(CHANNEL_A, 4);
        _postExpectingFrozen(signed);
    }

    function _unsignedSubBlock(uint32 channelId, uint256 salt) internal view returns (IntmaxRollup.SubBlock memory) {
        uint32[] memory ids = new uint32[](1);
        ids[0] = 0;
        return IntmaxRollup.SubBlock({
            channelId: channelId,
            timestamp: uint64(block.timestamp),
            txTreeRoot: keccak256(abi.encode("tx-tree", channelId, salt)),
            keyIds: ids
        });
    }

    /// Once the close has materialized (`materializedChannelExit != 0`) there is no cancel: the
    /// sub-block is refused with `ChannelAlreadyExited` for the life of the rollup.
    function test_materializedChannelSubBlockIsRefusedForever() external {
        managerA.requestClose();
        // Simulate the exit latch exactly as the materializer records it.
        bytes32 slot = keccak256(abi.encode(CHANNEL_A, uint256(_materializedExitSlot())));
        vm.store(address(materializer), slot, keccak256("exit statement"));
        assertTrue(materializer.materializedChannelExit(CHANNEL_A) != bytes32(0), "latched");

        IntmaxRollup.SubBlock[] memory mixed = new IntmaxRollup.SubBlock[](2);
        mixed[0] = _subBlock(CHANNEL_B, 1);
        mixed[1] = _subBlock(CHANNEL_A, 2);
        bytes32 pin = rollup.pendingChainsPin();
        vm.prank(producer);
        vm.expectRevert(CloseFundingMaterializer.ChannelAlreadyExited.selector);
        rollup.postBlockAndSubmit{value: BOND}(mixed, bytes32(0), 0, bytes32(0), pin);
        assertEq(rollup.blockNumber(), 0);
    }

    /// Storage slot of `materializedChannelExit`, found by probing with `vm.record` so the test
    /// does not hard-code the contract's layout.
    function _materializedExitSlot() internal returns (uint256 slot) {
        vm.record();
        materializer.materializedChannelExit(CHANNEL_A);
        (bytes32[] memory reads,) = vm.accesses(address(materializer));
        require(reads.length == 1, "one mapping read");
        // reads[0] == keccak256(abi.encode(key, slot)); recover slot by probing the layout.
        for (uint256 candidate = 0; candidate < 64; candidate++) {
            if (keccak256(abi.encode(CHANNEL_A, candidate)) == reads[0]) return candidate;
        }
        revert("materializedChannelExit slot not found");
    }
}
