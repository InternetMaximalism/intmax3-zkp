// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {IntmaxRollup, WhirVerifierWrapper} from "../src/IntmaxRollup.sol";
import {IForcedTxLogic} from "../src/IForcedTxLogic.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";

contract IntmaxRollupTest is Test {
    IntmaxRollup public rollup;
    WhirVerifierWrapper public verifierWrapper;

    address submitter = makeAddr("submitter");
    address aggregator = makeAddr("aggregator");
    address fraudTreasury = makeAddr("fraudTreasury");

    bytes32 constant BLOB_HASH = bytes32(uint256(0xdeadbeef));
    bytes32 constant DEFAULT_PROOF_HASH = keccak256("default_proof");
    uint32  constant DEFAULT_PROOF_LENGTH = 1024;
    bytes32 constant DEFAULT_STATE_ROOT = keccak256("default_state");

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    function setUp() public {
        verifierWrapper = new WhirVerifierWrapper();

        Groth16Verifier.VerifyingKey memory vk;
        bytes32 cfgHash = bytes32(0);

        rollup = new IntmaxRollup(verifierWrapper, fraudTreasury, vk, cfgHash);

        vm.deal(submitter, 10 ether);
        vm.deal(aggregator, 10 ether);
        vm.deal(fraudTreasury, 0);
    }

    // -----------------------------------------------------------------------
    // Helper: build SubBlock arrays
    // -----------------------------------------------------------------------

    function _makeSubBlock(
        uint32 aggId, uint64 ts, bytes32 txRoot, uint32[] memory ids
    ) internal pure returns (IntmaxRollup.SubBlock memory) {
        return IntmaxRollup.SubBlock({
            aggregatorId: aggId,
            timestamp: ts,
            txTreeRoot: txRoot,
            localIds: ids
        });
    }

    function _singleBlockBatch(
        uint32 aggId, uint32[] memory ids, uint64 ts, bytes32 txRoot
    ) internal pure returns (IntmaxRollup.SubBlock[] memory batch) {
        batch = new IntmaxRollup.SubBlock[](1);
        batch[0] = _makeSubBlock(aggId, ts, txRoot, ids);
    }

    function _postAndSubmit(
        IntmaxRollup.SubBlock[] memory batch,
        bytes32 proofHash,
        uint32 proofLength,
        bytes32 stateRoot
    ) internal {
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = BLOB_HASH;
        vm.blobhashes(hashes);
        rollup.postBlockAndSubmit{value: 1 ether}(batch, proofHash, proofLength, stateRoot);
    }

    function _postAndSubmitDefault(IntmaxRollup.SubBlock[] memory batch) internal {
        _postAndSubmit(batch, DEFAULT_PROOF_HASH, DEFAULT_PROOF_LENGTH, DEFAULT_STATE_ROOT);
    }

    // -----------------------------------------------------------------------
    // postBlock() tests — batched sub-blocks
    // -----------------------------------------------------------------------

    function test_postBlock_singleSubBlock() public {
        uint32[] memory localIds = new uint32[](2);
        localIds[0] = 1;
        localIds[1] = 2;

        vm.prank(aggregator);
        _postAndSubmitDefault(_singleBlockBatch(5, localIds, uint64(block.timestamp), bytes32(uint256(0xabc))));

        assertEq(rollup.blockNumber(), 1);
        assertEq(rollup.postingRound(), 1);
        assertTrue(rollup.blockHashChain() != bytes32(0));
        assertEq(rollup.blockHashChainAt(1), rollup.blockHashChain());
    }

    function test_postBlock_batchOf3() public {
        IntmaxRollup.SubBlock[] memory batch = new IntmaxRollup.SubBlock[](3);
        for (uint256 i = 0; i < 3; i++) {
            uint32[] memory ids = new uint32[](1);
            ids[0] = uint32(i + 1);
            batch[i] = _makeSubBlock(1, uint64(100 + i * 5), bytes32(uint256(0x100 + i)), ids);
        }

        _postAndSubmitDefault(batch);

        // 3 sub-blocks → blockNumber = 3
        assertEq(rollup.blockNumber(), 3);
        assertEq(rollup.postingRound(), 1);
        // Only the last block number has a snapshot
        assertEq(rollup.blockHashChainAt(3), rollup.blockHashChain());
        // Intermediate block numbers have no snapshot
        assertEq(rollup.blockHashChainAt(1), bytes32(0));
        assertEq(rollup.blockHashChainAt(2), bytes32(0));
    }

    function test_postBlock_twoRounds() public {
        // Round 1: 2 sub-blocks
        IntmaxRollup.SubBlock[] memory batch1 = new IntmaxRollup.SubBlock[](2);
        for (uint256 i = 0; i < 2; i++) {
            uint32[] memory ids = new uint32[](1);
            ids[0] = uint32(i + 1);
            batch1[i] = _makeSubBlock(1, uint64(100 + i), bytes32(uint256(0x10 + i)), ids);
        }
        _postAndSubmitDefault(batch1);
        bytes32 hashAfterRound1 = rollup.blockHashChain();

        // Round 2: 3 sub-blocks
        IntmaxRollup.SubBlock[] memory batch2 = new IntmaxRollup.SubBlock[](3);
        for (uint256 i = 0; i < 3; i++) {
            uint32[] memory ids = new uint32[](2);
            ids[0] = uint32(10 + i);
            ids[1] = uint32(20 + i);
            batch2[i] = _makeSubBlock(2, uint64(200 + i), bytes32(uint256(0x20 + i)), ids);
        }
        _postAndSubmitDefault(batch2);

        assertEq(rollup.blockNumber(), 5);
        assertEq(rollup.postingRound(), 2);
        // Round 1 snapshot at block 2, round 2 snapshot at block 5
        assertEq(rollup.blockHashChainAt(2), hashAfterRound1);
        assertEq(rollup.blockHashChainAt(5), rollup.blockHashChain());
        assertTrue(rollup.blockHashChainAt(2) != rollup.blockHashChainAt(5));
    }

    function test_postBlock_emptyBatch_reverts() public {
        IntmaxRollup.SubBlock[] memory empty = new IntmaxRollup.SubBlock[](0);
        vm.expectRevert(IntmaxRollup.EmptyBatch.selector);
        _postAndSubmitDefault(empty);
    }

    function test_postBlock_requiresStake() public {
        uint32[] memory ids = new uint32[](1);
        ids[0] = 42;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(
            5,
            ids,
            uint64(block.timestamp),
            bytes32(uint256(0x1234))
        );

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = BLOB_HASH;
        vm.blobhashes(hashes);
        vm.prank(aggregator);
        vm.expectRevert(IntmaxRollup.InvalidStakeAmount.selector);
        rollup.postBlockAndSubmit(batch, DEFAULT_PROOF_HASH, DEFAULT_PROOF_LENGTH, DEFAULT_STATE_ROOT);
    }

    // -----------------------------------------------------------------------
    // deposit() tests
    // -----------------------------------------------------------------------

    function test_deposit() public {
        rollup.deposit(bytes32(uint256(0xdead)), 0, 100, bytes32(0));
        assertEq(rollup.depositCount(), 1);
    }

    // -----------------------------------------------------------------------
    // postBlockAndSubmit() tests
    // -----------------------------------------------------------------------

    function test_postBlockAndSubmit() public {
        bytes32 proofHash   = keccak256("plonky2_proof_data");
        uint32  proofLength = 1024;
        bytes32 stateRoot   = keccak256("state_1");

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(
            1,
            ids,
            uint64(block.timestamp),
            bytes32(uint256(0xabc))
        );

        vm.prank(submitter);
        _postAndSubmit(batch, proofHash, proofLength, stateRoot);

        bytes32 expectedCommitment = keccak256(
            abi.encodePacked(BLOB_HASH, proofHash, proofLength, stateRoot)
        );
        assertEq(rollup.getCommitment(0), expectedCommitment);
        assertEq(rollup.nextSubmissionId(), 1);

        IntmaxRollup.Submission memory sub = rollup.getSubmission(0);
        assertEq(sub.submitter, submitter);
        assertFalse(sub.finalized);
    }

    function test_postBlockAndSubmit_revert_noBlob() public {
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = _singleBlockBatch(
            1,
            ids,
            uint64(block.timestamp),
            bytes32(uint256(0xdef))
        );
        vm.prank(submitter);
        vm.expectRevert(IntmaxRollup.NoBlobAttached.selector);
        rollup.postBlockAndSubmit{value: 1 ether}(batch, bytes32(0), uint32(0), bytes32(0));
    }

    // -----------------------------------------------------------------------
    // Forced TX tests
    // -----------------------------------------------------------------------

    function test_forcedTx_slotMaturation() public {
        // Queue a forced tx, then post 3 rounds. The forced tx should
        // mature at round 3 (queued before round 1, snapshot at round 1,
        // mature at round 3 = accumulatorAtRound[3-2] = accumulatorAtRound[1]).
        FixedReturnForcedTxLogic logic = new FixedReturnForcedTxLogic(bytes32(uint256(0xabc)));
        rollup.registerForcedTxLogic(42, address(logic));

        rollup.queueForcedTx(42);
        bytes32 accumulatorAfterQueue = rollup.forcedTxAccumulator();

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;

        // Round 1: snapshot accumulator
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 100, bytes32(uint256(0x111))));
        assertEq(rollup.forcedTxAccumulatorAtRound(1), accumulatorAfterQueue);

        // Round 2
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 200, bytes32(uint256(0x222))));

        // Round 3: mature forced txs = accumulatorAtRound[3-2] = accumulatorAtRound[1]
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 300, bytes32(uint256(0x333))));

        // Verify the accumulator was snapshotted correctly
        assertEq(rollup.forcedTxAccumulatorAtRound(1), accumulatorAfterQueue);
        assertEq(rollup.postingRound(), 3);
    }

    function test_forcedTx_hashChainAccumulation() public {
        FixedReturnForcedTxLogic logic1 = new FixedReturnForcedTxLogic(bytes32(uint256(0x111)));
        FixedReturnForcedTxLogic logic2 = new FixedReturnForcedTxLogic(bytes32(uint256(0x222)));
        rollup.registerForcedTxLogic(10, address(logic1));
        rollup.registerForcedTxLogic(20, address(logic2));

        rollup.queueForcedTx(10);
        bytes32 afterFirst = rollup.forcedTxAccumulator();

        rollup.queueForcedTx(20);
        bytes32 afterSecond = rollup.forcedTxAccumulator();

        assertEq(rollup.forcedTxCount(), 2);
        assertTrue(afterFirst != bytes32(0));
        assertTrue(afterSecond != afterFirst);

        // Verify the hash chain matches expected computation
        bytes32 expected1 = keccak256(abi.encodePacked(bytes32(0), uint64(10), bytes32(uint256(0x111))));
        assertEq(afterFirst, expected1);

        bytes32 expected2 = keccak256(abi.encodePacked(expected1, uint64(20), bytes32(uint256(0x222))));
        assertEq(afterSecond, expected2);
    }

    function test_registerForcedTxLogic() public {
        FixedReturnForcedTxLogic logic = new FixedReturnForcedTxLogic(bytes32(uint256(0xaaa)));
        rollup.registerForcedTxLogic(42, address(logic));
        assertEq(rollup.forcedTxLogicContracts(42), address(logic));
    }

    function test_registerForcedTxLogic_immutable() public {
        FixedReturnForcedTxLogic logic1 = new FixedReturnForcedTxLogic(bytes32(uint256(0xaaa)));
        FixedReturnForcedTxLogic logic2 = new FixedReturnForcedTxLogic(bytes32(uint256(0xbbb)));
        rollup.registerForcedTxLogic(42, address(logic1));

        // Second registration for same userId reverts
        vm.expectRevert(IntmaxRollup.ForcedTxLogicAlreadyRegistered.selector);
        rollup.registerForcedTxLogic(42, address(logic2));
    }

    function test_registerForcedTxLogic_rejectingContract() public {
        RevertingForcedTxLogic revertLogic = new RevertingForcedTxLogic();
        vm.expectRevert(IntmaxRollup.ForcedTxLogicNotAccepted.selector);
        rollup.registerForcedTxLogic(42, address(revertLogic));
    }

    function test_queueForcedTx_noLogicRegistered() public {
        vm.expectRevert(IntmaxRollup.NoForcedTxLogicRegistered.selector);
        rollup.queueForcedTx(999);
    }

    function test_queueForcedTx_success() public {
        FixedReturnForcedTxLogic logic = new FixedReturnForcedTxLogic(bytes32(uint256(0xdeadbeef)));
        rollup.registerForcedTxLogic(42, address(logic));

        rollup.queueForcedTx(42);

        assertEq(rollup.forcedTxCount(), 1);
        assertTrue(rollup.forcedTxAccumulator() != bytes32(0));
    }

    function test_queueForcedTx_returnsZero_reverts() public {
        FixedReturnForcedTxLogic logic = new FixedReturnForcedTxLogic(bytes32(0));
        rollup.registerForcedTxLogic(42, address(logic));

        vm.expectRevert(IntmaxRollup.ForcedTxInsertFailed.selector);
        rollup.queueForcedTx(42);
    }

    function test_queueForcedTx_revertingLogic() public {
        RevertOnInsertLogic revertOnInsert = new RevertOnInsertLogic();
        rollup.registerForcedTxLogic(42, address(revertOnInsert));

        vm.expectRevert(IntmaxRollup.ForcedTxInsertFailed.selector);
        rollup.queueForcedTx(42);
    }

    // -----------------------------------------------------------------------
    // Gas measurement
    // -----------------------------------------------------------------------

    function test_gas_postBlockAndSubmit_single() public {
        uint32[] memory localIds = new uint32[](2);
        localIds[0] = 1;
        localIds[1] = 2;

        uint256 gasBefore = gasleft();
        _postAndSubmitDefault(_singleBlockBatch(5, localIds, uint64(block.timestamp), bytes32(uint256(0xabc))));
        uint256 gasUsed = gasBefore - gasleft();
        console.log("postBlockAndSubmit(1 sub-block) gas:", gasUsed);
    }

    function test_gas_postBlockAndSubmit_batch60() public {
        IntmaxRollup.SubBlock[] memory batch = new IntmaxRollup.SubBlock[](60);
        for (uint256 i = 0; i < 60; i++) {
            uint32[] memory ids = new uint32[](10);
            for (uint256 j = 0; j < 10; j++) {
                ids[j] = uint32(i * 10 + j + 1);
            }
            batch[i] = _makeSubBlock(1, uint64(100 + i * 5), bytes32(uint256(0x100 + i)), ids);
        }

        uint256 gasBefore = gasleft();
        _postAndSubmitDefault(batch);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("postBlockAndSubmit(60 sub-blocks, 10 users each) gas:", gasUsed);
        assertEq(rollup.blockNumber(), 60);
    }

    function test_gas_postBlock_withForcedTx() public {
        FixedReturnForcedTxLogic logic = new FixedReturnForcedTxLogic(bytes32(uint256(0xabc)));
        rollup.registerForcedTxLogic(42, address(logic));
        rollup.queueForcedTx(42);

        uint32[] memory ids = new uint32[](2);
        ids[0] = 1;
        ids[1] = 2;

        // Post 3 rounds so maturation kicks in on the third
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 100, bytes32(uint256(0x111))));
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 200, bytes32(uint256(0x222))));

        uint256 gasBefore = gasleft();
        _postAndSubmitDefault(_singleBlockBatch(1, ids, 300, bytes32(uint256(0x333))));
        uint256 gasUsed = gasBefore - gasleft();
        console.log("postBlockAndSubmit() with mature forced tx gas:", gasUsed);
    }

    function test_gas_queueForcedTx() public {
        FixedReturnForcedTxLogic logic = new FixedReturnForcedTxLogic(bytes32(uint256(0xdeadbeef)));
        rollup.registerForcedTxLogic(42, address(logic));

        uint256 gasBefore = gasleft();
        rollup.queueForcedTx(42);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("queueForcedTx() gas:", gasUsed);
    }

    function test_gas_registerForcedTxLogic() public {
        FixedReturnForcedTxLogic logic = new FixedReturnForcedTxLogic(bytes32(uint256(0xaaa)));
        uint256 gasBefore = gasleft();
        rollup.registerForcedTxLogic(42, address(logic));
        uint256 gasUsed = gasBefore - gasleft();
        console.log("registerForcedTxLogic() gas:", gasUsed);
    }
}

/// @dev Forced tx logic contract that returns a fixed tx hash.
contract FixedReturnForcedTxLogic is IForcedTxLogic {
    bytes32 private _txHash;

    constructor(bytes32 txHash) {
        _txHash = txHash;
    }

    function insertIntmaxTx() external override returns (bytes32) {
        return _txHash;
    }

    function acceptRegistration(uint64 userId) external pure override returns (uint64) {
        return userId;
    }
}

/// @dev Forced tx logic contract that always reverts (including registration).
contract RevertingForcedTxLogic is IForcedTxLogic {
    function insertIntmaxTx() external pure override returns (bytes32) {
        revert("intentional revert");
    }

    function acceptRegistration(uint64) external pure override returns (uint64) {
        revert("intentional revert");
    }
}

/// @dev Accepts registration but reverts on insertIntmaxTx.
contract RevertOnInsertLogic is IForcedTxLogic {
    function insertIntmaxTx() external pure override returns (bytes32) {
        revert("intentional revert on insert");
    }

    function acceptRegistration(uint64 userId) external pure override returns (uint64) {
        return userId;
    }
}
