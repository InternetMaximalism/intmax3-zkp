// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {KZGProof} from "../src/BlobKZGVerifier.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

/// @title `reclaimStake` — recover a POST_BLOCK_STAKE bond once its submission is finalized history.
/// @notice Fixes the stranded-stake fund loss: one aggregate validity proof finalizes many posted
///         blocks but refunds only ONE submission's bond; the rest were permanently locked. These
///         tests pin the working recovery AND the security invariants (see
///         tasks/reclaim-stake-threat-model.md INV-A/INV-B) that make the height-only eligibility
///         check sound. Drives the real c2c lifecycle (5 postBlocks + 1 aggregate finalize) so the
///         stranding is reproduced exactly. Self-skips if c2c fixtures are absent.
contract ReclaimStakeTest is Test {
    MleVerifier internal verifier;
    IntmaxRollup internal rollup;
    address internal fraudTreasury = makeAddr("fraudTreasury");
    address internal poster = makeAddr("poster");

    string internal lc;
    string internal validityMleJson;
    bool internal ready;

    uint256 internal constant STAKE = 1 ether; // POST_BLOCK_STAKE

    function setUp() public {
        string memory root = string.concat(vm.projectRoot(), "/test/data/");
        try vm.readFile(string.concat(root, "c2c_lifecycle.json")) returns (string memory j) {
            lc = j;
            validityMleJson = vm.readFile(string.concat(root, "c2c_lifecycle_validity_mle.json"));
            ready = true;
        } catch {
            ready = false;
            return;
        }
        verifier = new MleVerifier();
        FixtureLib.DeployData memory vdd = FixtureLib.parseDeployData(validityMleJson);
        IntmaxRollup.MleVk memory vvk = FixtureLib.buildMleVk(validityMleJson, verifier);
        bytes32 genesis = vm.parseJsonBytes32(lc, ".genesis_state_root");
        rollup = new IntmaxRollup(
            fraudTreasury, vvk, vdd.whirParams, vdd.protocolId, vdd.sessionId,
            vdd.kIs, vdd.subgroupGenPowers, verifier, genesis,
            true // A-2: test opt-in for the degreeBits==0 bypass
        );
        rollup.setBlockProducer(poster, true); // permissioned posting
    }

    // ── Main fix: every stranded postBlock bond is recoverable after the aggregate finalize. ──
    function test_reclaim_recoversAllStrandedStakes() public {
        if (!ready) { vm.skip(true); return; }
        uint256 finalSubId = _lifecycleThroughFinalize(); // = 4 (5 posting rounds, sub 0..4)

        // sub4 (the finalized submission) was refunded by finalize → not reclaimable, and its 1 STAKE
        // is already credited to the poster. Take that as the baseline.
        uint256 base = rollup.pendingWithdrawals(poster);
        assertEq(base, STAKE, "finalize refunded the finalized submission's bond");
        vm.expectRevert(IntmaxRollup.NothingToReclaim.selector);
        rollup.reclaimStake(finalSubId);

        // sub0..3 are stranded today; reclaim returns each bond to the poster, exactly once.
        uint256 credited;
        for (uint256 i = 0; i < 4; i++) {
            (address submitter, bool spent) = rollup.stakeInfo(i);
            assertEq(submitter, poster, "stranded stake owned by poster");
            assertFalse(spent, "stranded stake not yet spent");

            rollup.reclaimStake(i); // permissionless caller (this test contract)
            credited += STAKE;
            assertEq(rollup.pendingWithdrawals(poster), base + credited, "bond credited to the submitter");
            (address s2, ) = rollup.stakeInfo(i);
            assertEq(s2, address(0), "stakeInfo cleared after reclaim");
        }
        // All 5 postBlock bonds now recovered (1 via finalize-refund + 4 via reclaim).
        assertEq(rollup.pendingWithdrawals(poster), 5 * STAKE, "every postBlock bond recovered");

        // Pull-payment: the poster collects the recovered bonds as real ETH.
        uint256 balBefore = poster.balance;
        vm.prank(poster);
        rollup.withdraw();
        assertEq(poster.balance, balBefore + 5 * STAKE, "poster received all recovered bonds");
    }

    // ── Guard: a bond still at risk (block not finalized) is NOT reclaimable. ──
    function test_reclaim_beforeFinalize_reverts() public {
        if (!ready) { vm.skip(true); return; }
        _postAllRoundsNoFinalize(); // posts 5 submissions, latestFinalizedBlockNumber stays 0
        // Nothing finalized → every submission has endBlockNumber > 0 = latestFinalizedBlockNumber.
        for (uint256 i = 0; i < 5; i++) {
            vm.expectRevert(IntmaxRollup.SubmissionNotYetFinalized.selector);
            rollup.reclaimStake(i);
        }
    }

    // ── No double-recovery: reclaim is one-shot, and excludes a finalize-refunded bond. ──
    function test_reclaim_doubleReclaim_and_afterRefund_revert() public {
        if (!ready) { vm.skip(true); return; }
        uint256 finalSubId = _lifecycleThroughFinalize();

        rollup.reclaimStake(0); // ok
        vm.expectRevert(IntmaxRollup.NothingToReclaim.selector);
        rollup.reclaimStake(0); // second reclaim of same id

        vm.expectRevert(IntmaxRollup.NothingToReclaim.selector);
        rollup.reclaimStake(finalSubId); // already refunded via finalize
    }

    // ── Unknown / never-posted submission id is rejected. ──
    function test_reclaim_unknownId_reverts() public {
        if (!ready) { vm.skip(true); return; }
        _lifecycleThroughFinalize();
        vm.expectRevert(IntmaxRollup.NothingToReclaim.selector);
        rollup.reclaimStake(99);
    }

    // ── INV (truncation deletes the bond): a timed-out, truncated submission is not reclaimable. ──
    //    Uses the deadline-removal branch of fraudProof (no ZKP needed) to exercise the slash/rollback
    //    path that clears stakeInfo, then asserts reclaim reverts — pinning that truncation and
    //    reclaim cannot both pay out a bond.
    function test_reclaim_afterTimeoutTruncation_reverts() public {
        if (!ready) { vm.skip(true); return; }
        // One postBlock submission, never finalized (latestFinalizedBlockNumber stays 0).
        bytes32[] memory blobs = new bytes32[](1);
        blobs[0] = keccak256("reclaim_timeout");
        vm.blobhashes(blobs);
        vm.deal(poster, 10 ether);
        _postRound(0);
        (address before,) = rollup.stakeInfo(0);
        assertEq(before, poster, "staked");

        // Advance past FINALIZE_DEADLINE_BLOCKS (= 3600) and trigger unconditional timeout removal.
        vm.roll(block.number + 3601);
        address reporter = makeAddr("reporter");
        IntmaxRollup.ValidityPublicInputs memory emptyPis;
        MleVerifier.MleProof memory emptyProof;
        KZGProof memory emptyKzg;
        vm.prank(reporter);
        assertTrue(rollup.fraudProof(0, bytes32(0), bytes32(0), "", emptyPis, emptyProof, emptyKzg), "timeout removal");

        // Bond was slashed to the reporter, stakeInfo cleared → reclaim must revert (no double pay).
        (address afterAddr,) = rollup.stakeInfo(0);
        assertEq(afterAddr, address(0), "stakeInfo cleared by truncation");
        vm.expectRevert(IntmaxRollup.NothingToReclaim.selector);
        rollup.reclaimStake(0);
        assertGt(rollup.pendingWithdrawals(reporter), 0, "reporter got the slashed bond, not the submitter");
    }

    // ── No double-pay in the reclaim-THEN-finalize direction. ──
    function test_reclaim_thenFinalizeSameId_noDoubleCredit() public {
        if (!ready) { vm.skip(true); return; }
        _postAllRoundsNoFinalize();
        // Finalize the aggregate proof via sub4, then reclaim a stranded sibling (sub0).
        IntmaxRollup.ValidityPublicInputs memory vpis = _parseVpis();
        MleVerifier.MleProof memory vproof = FixtureLib.parseProof(validityMleJson);
        bytes32 finalRoot = vm.parseJsonBytes32(lc, ".final_state_root");
        assertTrue(rollup.finalize(4, finalRoot, vpis, vproof), "finalize");
        rollup.reclaimStake(0);
        uint256 pendingAfterReclaim = rollup.pendingWithdrawals(poster);

        // Now attempt finalize(0) with the SAME proof: must NOT pay sub0's bond again. fullVerify
        // fails (initialExtCommitment no longer == latestFinalizedStateRoot), so finalize returns
        // false and `_refundStake` never runs for the already-reclaimed id.
        assertFalse(rollup.finalize(0, finalRoot, vpis, vproof), "stale finalize must fail");
        assertEq(rollup.pendingWithdrawals(poster), pendingAfterReclaim, "no second credit for sub0's bond");
        (address s0, ) = rollup.stakeInfo(0);
        assertEq(s0, address(0), "sub0 stake stays spent");
    }

    // ── INV-B: truncating then reposting reuses the submissionId with a FRESH, independent bond. ──
    function test_reclaim_repostAfterTruncate_freshBond_notReclaimableEarly() public {
        if (!ready) { vm.skip(true); return; }
        bytes32[] memory blobs = new bytes32[](1);
        blobs[0] = keccak256("reclaim_repost");
        vm.blobhashes(blobs);
        vm.deal(poster, 10 ether);

        // Post submission id 0 (block 1), never finalize, time it out and truncate it.
        _postRound(0);
        vm.roll(block.number + 3601);
        address reporter = makeAddr("reporter");
        IntmaxRollup.ValidityPublicInputs memory emptyPis;
        MleVerifier.MleProof memory emptyProof;
        KZGProof memory emptyKzg;
        vm.prank(reporter);
        rollup.fraudProof(0, bytes32(0), bytes32(0), "", emptyPis, emptyProof, emptyKzg);
        assertEq(rollup.nextSubmissionId(), 0, "id rewound for reuse");
        assertEq(rollup.blockNumber(), 0, "blockNumber rewound (still >= latestFinalized=0)");

        // Repost: reuses submissionId 0 with a brand-new 1 ETH bond and fresh metadata.
        uint256 reposted = _postRound(0);
        assertEq(reposted, 0, "submissionId reused");
        (address submitter, bool spent) = rollup.stakeInfo(0);
        assertEq(submitter, poster, "fresh bond owned by poster");
        assertFalse(spent, "fresh bond unspent");

        // The reposted bond is NOT yet finalized → not reclaimable (the old bond was slashed to the
        // reporter; there is no stale path to reclaim it via the reused id).
        vm.expectRevert(IntmaxRollup.SubmissionNotYetFinalized.selector);
        rollup.reclaimStake(0);
        assertGt(rollup.pendingWithdrawals(reporter), 0, "the ORIGINAL bond was slashed to the reporter");
    }

    // ─── lifecycle helpers (mirror C2CFullE2E / C2CBlockHash ordering) ───

    function _lifecycleThroughFinalize() internal returns (uint256 finalSubId) {
        finalSubId = _postAllRoundsNoFinalize();
        IntmaxRollup.ValidityPublicInputs memory vpis = _parseVpis();
        MleVerifier.MleProof memory vproof = FixtureLib.parseProof(validityMleJson);
        bytes32 finalRoot = vm.parseJsonBytes32(lc, ".final_state_root");
        assertTrue(rollup.finalize(finalSubId, finalRoot, vpis, vproof), "finalize failed");
    }

    function _postAllRoundsNoFinalize() internal returns (uint256 lastSubId) {
        bytes32[] memory blobs = new bytes32[](1);
        blobs[0] = keccak256("reclaim_c2c");
        vm.blobhashes(blobs);
        vm.deal(poster, 10 ether);
        _register(".registration1");
        _postRound(0);
        _deposit();
        _postRound(1);
        _register(".registration2");
        _postRound(2);
        _postRound(3);
        lastSubId = _postRound(4);
    }

    function _register(string memory key) internal {
        rollup.registerChannel(
            uint32(vm.parseJsonUint(lc, string.concat(key, ".channel_id"))),
            uint8(vm.parseJsonUint(lc, string.concat(key, ".bp_member_slot"))),
            // Delegate account Phase 1: fixtures are member-only (delegate_count = 0).
            0,
            vm.parseJsonBytes32Array(lc, string.concat(key, ".member_pk_gs")),
            vm.parseJsonBytes32Array(lc, string.concat(key, ".member_pk_bs")),
            vm.parseJsonBytes32Array(lc, string.concat(key, ".regev_pk_digests")),
            vm.parseJsonAddressArray(lc, string.concat(key, ".recipients"))
        );
    }

    function _deposit() internal {
        address depositor = vm.parseJsonAddress(lc, ".deposit.depositor");
        uint256 amount = vm.parseUint(vm.parseJsonString(lc, ".deposit.amount"));
        vm.deal(depositor, amount);
        vm.prank(depositor);
        rollup.deposit{value: amount}(
            vm.parseJsonBytes32(lc, ".deposit.recipient"),
            uint32(vm.parseJsonUint(lc, ".deposit.token_index")),
            amount,
            vm.parseJsonBytes32(lc, ".deposit.aux_data")
        );
    }

    function _postRound(uint256 i) internal returns (uint256 subId) {
        string memory base = string.concat(".blocks[", vm.toString(i), "]");
        uint256[] memory keyIdsU = FixtureLib.parseUintArray(lc, string.concat(base, ".key_ids"));
        uint32[] memory keyIds = new uint32[](keyIdsU.length);
        for (uint256 j = 0; j < keyIdsU.length; j++) keyIds[j] = uint32(keyIdsU[j]);
        IntmaxRollup.SubBlock[] memory sb = new IntmaxRollup.SubBlock[](1);
        sb[0] = IntmaxRollup.SubBlock({
            channelId: uint32(vm.parseJsonUint(lc, string.concat(base, ".channel_id"))),
            timestamp: uint64(vm.parseJsonUint(lc, string.concat(base, ".timestamp"))),
            txTreeRoot: vm.parseJsonBytes32(lc, string.concat(base, ".tx_tree_root")),
            keyIds: keyIds
        });
        subId = rollup.nextSubmissionId();
        vm.prank(poster);
        rollup.postBlockAndSubmit{value: STAKE}(sb, bytes32(0), 0, bytes32(0));
    }

    function _parseVpis() internal view returns (IntmaxRollup.ValidityPublicInputs memory vpis) {
        vpis.initialBlockNumber = uint64(vm.parseJsonUint(lc, ".vpis.initial_block_number"));
        vpis.initialBlockChain = vm.parseJsonBytes32(lc, ".vpis.initial_block_chain");
        vpis.initialExtCommitment = vm.parseJsonBytes32(lc, ".vpis.initial_ext_commitment");
        vpis.finalBlockNumber = uint64(vm.parseJsonUint(lc, ".vpis.final_block_number"));
        vpis.finalBlockChain = vm.parseJsonBytes32(lc, ".vpis.final_block_chain");
        vpis.finalExtCommitment = vm.parseJsonBytes32(lc, ".vpis.final_ext_commitment");
        vpis.prover = vm.parseJsonAddress(lc, ".vpis.prover");
    }
}
