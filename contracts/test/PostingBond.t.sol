// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {TestProofDaVerifier} from "./helpers/ProofDaTestHelper.sol";
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";

/// @dev Exposes the truncation so the forfeiture arithmetic is tested without a fraud fixture.
contract BondHarness is IntmaxRollup {
    constructor(address treasury, uint256 base, uint256 perPost)
        IntmaxRollup(
            treasury,
            new MockPinnedMleVerifierV2(31337),
            new MockPinnedMleVerifierV2(31337),
            bytes32(0),
            base,
            perPost
        )
    {}

    function truncate(uint256 targetId, address reporter, bool forfeit) external {
        _truncateSubmissions(targetId, reporter, forfeit);
    }
}

/// @title The posting bond: a prepaid `baseStake` plus `postStake` per unfinalized post.
/// @notice A post is accepted only while the producer's bond covers the base and every one of its
///         unfinalized posts including the new one; the aggregate finalization releases all of the
///         submitter's posts up to the finalized one; with none unfinalized the whole bond is
///         withdrawable. A proven fraud forfeits the offender's base and `postStake` per truncated
///         post (capped at the bond left); a timeout removal forfeits nothing.
contract PostingBondUnitTest is Test {
    uint256 internal constant BASE = 0.1 ether;
    uint256 internal constant PER_POST = 0.001 ether;

    BondHarness internal rollup;
    address internal treasury = makeAddr("treasury");
    address internal producer = makeAddr("producer");
    address internal other = makeAddr("otherProducer");
    address internal reporter = makeAddr("reporter");

    function setUp() public {
        rollup = new BondHarness(treasury, BASE, PER_POST);
        rollup.setKzgVerifier(BlobKZGVerifierExt(address(new TestProofDaVerifier())));
        rollup.setBlockProducer(producer, true);
        rollup.setBlockProducer(other, true);
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = keccak256("bond-blob");
        vm.blobhashes(hashes);
        vm.deal(producer, 10 ether);
        vm.deal(other, 10 ether);
    }

    function _batch() internal view returns (IntmaxRollup.SubBlock[] memory batch) {
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        batch = new IntmaxRollup.SubBlock[](1);
        batch[0] = IntmaxRollup.SubBlock({
            channelId: 5, timestamp: uint64(block.timestamp), txTreeRoot: bytes32(uint256(0xabc)), keyIds: ids
        });
    }

    function _post(address who, uint256 value) internal returns (uint256 id) {
        id = rollup.nextSubmissionId();
        bytes32 pin = rollup.pendingChainsPin();
        IntmaxRollup.SubBlock[] memory batch = _batch();
        vm.prank(who);
        rollup.postBlockAndSubmit{value: value}(batch, bytes32(0), 0, bytes32(0), pin);
    }

    function _bond(address who) internal view returns (uint256 balance, uint256 posted, uint256 released) {
        (uint96 b, uint48 p, uint48 r) = rollup.bonds(who);
        return (b, p, r);
    }

    function test_bond_deploymentValues_andZeroRefused() public {
        assertEq(rollup.baseStake(), BASE);
        assertEq(rollup.postStake(), PER_POST);
        vm.expectRevert(IntmaxRollup.InvalidStakeAmount.selector);
        new BondHarness(treasury, 0, PER_POST);
        vm.expectRevert(IntmaxRollup.InvalidStakeAmount.selector);
        new BondHarness(treasury, BASE, 0);
    }

    /// No post is ever accepted without the base plus one `postStake` for each unfinalized post,
    /// this one included; `msg.value` and `depositBond` both fund it.
    function test_bond_postRequiresBasePlusEveryUnfinalizedPost() public {
        bytes32 pin = rollup.pendingChainsPin();
        IntmaxRollup.SubBlock[] memory batch = _batch();
        vm.prank(producer);
        vm.expectRevert(IntmaxRollup.InsufficientBond.selector);
        rollup.postBlockAndSubmit{value: BASE}(batch, bytes32(0), 0, bytes32(0), pin);

        _post(producer, BASE + PER_POST);
        (uint256 balance, uint256 posted, uint256 released) = _bond(producer);
        assertEq(balance, BASE + PER_POST);
        assertEq(posted, 1);
        assertEq(released, 0);

        pin = rollup.pendingChainsPin();
        vm.prank(producer);
        vm.expectRevert(IntmaxRollup.InsufficientBond.selector);
        rollup.postBlockAndSubmit(batch, bytes32(0), 0, bytes32(0), pin);

        vm.prank(producer);
        rollup.depositBond{value: PER_POST}();
        _post(producer, 0);
        (balance, posted,) = _bond(producer);
        assertEq(balance, BASE + 2 * PER_POST);
        assertEq(posted, 2);
        assertEq(address(rollup).balance, BASE + 2 * PER_POST, "the bond is held by the rollup");
        assertEq(rollup.totalEscrowed(), 0, "the bond is not deposit escrow");
    }

    function test_bond_lockedWhileUnfinalized() public {
        _post(producer, 1 ether);
        vm.startPrank(producer);
        vm.expectRevert(IntmaxRollup.NothingToWithdraw.selector);
        rollup.withdrawBond(1 ether - BASE - PER_POST + 1);
        uint256 before = producer.balance;
        rollup.withdrawBond(1 ether - BASE - PER_POST);
        assertEq(producer.balance, before + 1 ether - BASE - PER_POST, "the unlocked part is withdrawable");
        vm.expectRevert(IntmaxRollup.NothingToWithdraw.selector);
        rollup.withdrawBond(1);
        vm.stopPrank();
    }

    /// A timeout removal forfeits nothing: the removed post is uncounted and, with no post left
    /// unfinalized, the whole bond, base included, is withdrawable.
    function test_bond_timeoutRemovalForfeitsNothing() public {
        _post(producer, BASE + PER_POST);
        vm.roll(block.number + 3601);
        IntmaxRollup.ValidityPublicInputs memory none;
        vm.prank(reporter);
        assertTrue(rollup.fraudProof(0, bytes32(0), none, ""), "timeout removal");
        assertEq(rollup.pendingWithdrawals(reporter), 0, "no reward");
        assertEq(rollup.pendingWithdrawals(treasury), 0, "no treasury share");
        (uint256 balance, uint256 posted,) = _bond(producer);
        assertEq(balance, BASE + PER_POST, "nothing forfeited");
        assertEq(posted, 0, "the removed post is uncounted");
        uint256 before = producer.balance;
        vm.prank(producer);
        rollup.withdrawBond(BASE + PER_POST);
        assertEq(producer.balance, before + BASE + PER_POST, "base withdrawable with nothing unfinalized");
    }

    /// Before its deadline an unproven claim removes nothing.
    function test_bond_beforeDeadline_unprovenFraudRemovesNothing() public {
        _post(producer, BASE + PER_POST);
        IntmaxRollup.ValidityPublicInputs memory none;
        assertFalse(rollup.fraudProof(0, bytes32(0), none, ""));
        (, uint256 posted,) = _bond(producer);
        assertEq(posted, 1);
    }

    /// A proven fraud: the offender forfeits its base and `postStake` for each of its truncated
    /// posts; a later post of another producer, truncated with it, forfeits its `postStake`.
    /// The reporter receives 90% of the OFFENDER's forfeiture; the rest of it and everything
    /// forfeited by other producers goes to the treasury (review 2026-10-15, C3).
    function test_bond_fraudForfeitsBasePlusEachTruncatedPost() public {
        _post(producer, 1 ether); // id 0, kept
        _post(producer, 0); // id 1, the fraud target
        _post(other, BASE + PER_POST); // id 2, built on the fraud
        _post(producer, 0); // id 3
        rollup.truncate(1, reporter, true);

        uint256 offenderForfeited = BASE + 2 * PER_POST;
        uint256 othersForfeited = PER_POST;
        uint256 reward = offenderForfeited * 90 / 100;
        assertEq(rollup.pendingWithdrawals(reporter), reward, "reporter: 90% of the offender's forfeiture only");
        assertEq(
            rollup.pendingWithdrawals(treasury),
            offenderForfeited - reward + othersForfeited,
            "treasury: the offender's remainder plus every other producer's forfeited post stake"
        );
        (uint256 balance, uint256 posted,) = _bond(producer);
        assertEq(balance, 1 ether - BASE - 2 * PER_POST);
        assertEq(posted, 1, "the kept post is still counted");
        (balance, posted,) = _bond(other);
        assertEq(balance, BASE, "the other producer lost only its truncated post's stake");
        assertEq(posted, 0);
        assertEq(rollup.nextSubmissionId(), 1);
    }

    /// SECURITY regression (code review 2026-10-15, finding C3): `fraudProof` never checks that the
    /// reporter differs from the offender (and cannot — a second address is free), so the reporter
    /// share must never contain other producers' stakes. Before this fix an offender who reported
    /// its own fraud received 90% of EVERYTHING forfeited, including the `postStake` of every other
    /// producer whose posts were truncated with it, and turned a profit once enough foreign posts
    /// sat on top of the fraud. Now its reward is 90% of its OWN forfeiture: self-reporting always
    /// nets a loss (the treasury's 10%), and foreign stakes never reach the reporter.
    function test_bond_selfReportNeverProfitsFromOtherProducersStakes() public {
        _post(producer, 1 ether); // id 0, kept
        _post(producer, 0); // id 1, the fraud target
        _post(other, BASE + 20 * PER_POST); // ids 2..21: twenty foreign posts built on the fraud
        for (uint256 i = 1; i < 20; i++) {
            _post(other, 0);
        }
        uint256 offenderBefore = 1 ether;

        // The offender reports itself.
        rollup.truncate(1, producer, true);

        uint256 ownForfeited = BASE + PER_POST; // its base and its one truncated post (id 1)
        uint256 foreignForfeited = 20 * PER_POST;
        uint256 reward = ownForfeited * 90 / 100;
        assertEq(rollup.pendingWithdrawals(producer), reward, "self-report: 90% of its OWN forfeiture");
        assertEq(
            rollup.pendingWithdrawals(treasury),
            ownForfeited - reward + foreignForfeited,
            "treasury: the offender's 10% plus every foreign post stake"
        );
        (uint256 balance,,) = _bond(producer);
        assertLt(
            balance + rollup.pendingWithdrawals(producer),
            offenderBefore,
            "self-reporting a fraud is always a net loss for the offender"
        );
        (balance,,) = _bond(other);
        assertEq(balance, BASE, "the foreign producer lost exactly its truncated posts' stakes");
    }

    /// A bond whose base is gone yields only what it holds, and its producer posts again only
    /// after funding the full requirement again.
    function test_bond_forfeitIsCappedAtTheBond_andNoPostWithoutAFullBond() public {
        _post(producer, BASE + 2 * PER_POST); // id 0
        _post(producer, 0); // id 1
        rollup.truncate(1, reporter, true); // forfeits BASE + PER_POST; PER_POST left for id 0
        (uint256 balance, uint256 posted,) = _bond(producer);
        assertEq(balance, PER_POST);
        assertEq(posted, 1);

        rollup.truncate(0, reporter, true); // only PER_POST is left to take
        (balance, posted,) = _bond(producer);
        assertEq(balance, 0);
        assertEq(posted, 0);
        uint256 total = BASE + PER_POST + PER_POST;
        assertEq(rollup.pendingWithdrawals(reporter) + rollup.pendingWithdrawals(treasury), total);

        bytes32 pin = rollup.pendingChainsPin();
        IntmaxRollup.SubBlock[] memory batch = _batch();
        vm.prank(producer);
        vm.expectRevert(IntmaxRollup.InsufficientBond.selector);
        rollup.postBlockAndSubmit{value: BASE}(batch, bytes32(0), 0, bytes32(0), pin);
        _post(producer, BASE + PER_POST);
    }

    function test_bond_releaseBond_refusesUnfinalizedForeignAndUnknown() public {
        _post(producer, BASE + PER_POST);
        vm.expectRevert(IntmaxRollup.SubmissionNotYetFinalized.selector);
        rollup.releaseBond(producer, 0);
        vm.expectRevert(IntmaxRollup.SubmissionNotYetFinalized.selector);
        rollup.releaseBond(other, 0);
        vm.expectRevert(IntmaxRollup.SubmissionNotYetFinalized.selector);
        rollup.releaseBond(address(0), 99);
    }

    /// External readers (BlobKZGVerifier, the Rust publisher) decode exactly five words.
    function test_getSubmission_keepsItsFiveWordShape() public {
        _post(producer, BASE + PER_POST);
        (bool ok, bytes memory out) = address(rollup).staticcall(abi.encodeWithSignature("getSubmission(uint256)", 0));
        assertTrue(ok);
        assertEq(out.length, 160);
        IntmaxRollup.SubmissionView memory sub = rollup.getSubmission(0);
        assertEq(sub.submitter, producer);
        assertEq(sub.submittedAtBlock, block.number);
    }

    event BlockPosted(
        uint64 indexed blockNumber,
        uint256 indexed submissionId,
        uint32 channelId,
        uint32[] keyIds,
        bytes32 txTreeRoot,
        bytes32 newBlockHashChain
    );

    function test_blockPosted_carriesItsSubmissionId() public {
        _post(producer, BASE + PER_POST);
        vm.expectEmit(true, true, false, false, address(rollup));
        emit BlockPosted(2, 1, 0, new uint32[](0), bytes32(0), bytes32(0));
        _post(producer, PER_POST);
    }
}

/// @title The bond over the real c2c lifecycle: one aggregate validity proof finalizes five posts.
/// @notice Before the bond, that finalization refunded one post and stranded four. Drives the real
///         c2c lifecycle (5 postBlocks + 1 aggregate finalize). Self-skips if c2c fixtures are absent.
contract PostingBondLifecycleTest is Test {
    IntmaxRollup internal rollup;
    address internal fraudTreasury = makeAddr("fraudTreasury");
    address internal poster = makeAddr("poster");

    string internal lc;
    bool internal ready;

    uint256 internal constant BASE = 0.1 ether;
    uint256 internal constant PER_POST = 0.001 ether;

    function setUp() public {
        string memory root = string.concat(vm.projectRoot(), "/test/data/");
        string memory validityConfigJson;
        try vm.readFile(string.concat(root, "c2c_lifecycle.json")) returns (string memory j) {
            lc = j;
            validityConfigJson = vm.readFile(string.concat(root, "c2c_lifecycle_validity_mle_config.json"));
            if (!vm.exists(string.concat(root, "c2c_lifecycle_validity_mle.json"))) {
                ready = false;
                return;
            }
            ready = true;
        } catch {
            ready = false;
            return;
        }
        if (!vm.keyExistsJson(validityConfigJson, ".schemaVersion")) {
            ready = false;
            return;
        }
        // Deploy from the proof-free config. Keeping the ~1.3 MB proof JSON in test-contract
        // storage exhausts the setup gas cap; each proof-using test reads it transiently instead.
        (, PinnedMleVerifierV2 validityAdapter) = FixtureLib.deployPinnedMleV2(validityConfigJson);
        bytes32 genesis = vm.parseJsonBytes32(lc, ".genesis_state_root");
        rollup = new IntmaxRollup(
            fraudTreasury,
            IPinnedMleVerifierV2(address(validityAdapter)),
            new MockPinnedMleVerifierV2(31337),
            genesis,
            BASE,
            PER_POST
        );
        rollup.setKzgVerifier(BlobKZGVerifierExt(address(new TestProofDaVerifier())));
        rollup.setBlockProducer(poster, true); // permissioned posting
    }

    function _validityMleJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/c2c_lifecycle_validity_mle.json"));
    }

    function _bond() internal view returns (uint256 balance, uint256 posted, uint256 released) {
        (uint96 b, uint48 p, uint48 r) = rollup.bonds(poster);
        return (b, p, r);
    }

    /// The aggregate finalize releases all five posts at once; the whole bond is then withdrawable.
    function test_bond_aggregateFinalizeReleasesEveryPost() public {
        if (!ready) { vm.skip(true); return; }
        vm.deal(poster, 10 ether);
        vm.prank(poster);
        rollup.depositBond{value: BASE + 5 * PER_POST}();
        uint256 finalSubId = _postAllRoundsNoFinalize();
        (uint256 balance, uint256 posted, uint256 released) = _bond();
        assertEq(posted, 5);
        assertEq(released, 0);
        vm.prank(poster);
        vm.expectRevert(IntmaxRollup.NothingToWithdraw.selector);
        rollup.withdrawBond(1);

        _finalize(finalSubId);
        (balance, posted, released) = _bond();
        assertEq(released, 5, "every post released by the one finalization");
        uint256 before = poster.balance;
        vm.prank(poster);
        rollup.withdrawBond(balance);
        assertEq(poster.balance, before + BASE + 5 * PER_POST, "the whole bond returned");
        assertEq(address(rollup).balance, rollup.totalEscrowed(), "only deposit escrow remains");
    }

    /// `releaseBond` releases up to a finalized post; repeating it, or naming an earlier post,
    /// changes nothing, and a post finalized history can no longer be truncated.
    function test_bond_releaseBond_isIdempotentAndMonotone() public {
        if (!ready) { vm.skip(true); return; }
        uint256 finalSubId = _postAllRoundsNoFinalize();
        _finalize(finalSubId);
        rollup.releaseBond(poster, 2);
        rollup.releaseBond(poster, finalSubId);
        (,, uint256 released) = _bond();
        assertEq(released, 5);
        IntmaxRollup.ValidityPublicInputs memory none;
        vm.roll(block.number + 3601);
        vm.expectRevert(IntmaxRollup.SubmissionBeforeFinalizedBlock.selector);
        rollup.fraudProof(2, bytes32(0), none, "");
    }

    /// A stale finalize of an earlier submission fails and releases nothing twice.
    function test_bond_staleFinalize_releasesNothing() public {
        if (!ready) { vm.skip(true); return; }
        uint256 finalSubId = _postAllRoundsNoFinalize();
        _finalize(finalSubId);
        (uint256 balanceBefore,,) = _bond();
        IntmaxRollup.ValidityPublicInputs memory vpis = _parseVpis();
        bytes memory vproof = FixtureLib.parseCompactProofV2(_validityMleJson());
        bytes32 finalRoot = vm.parseJsonBytes32(lc, ".final_state_root");
        assertFalse(rollup.finalize(0, finalRoot, vpis, vproof), "stale finalize must fail");
        (uint256 balanceAfter,, uint256 released) = _bond();
        assertEq(balanceAfter, balanceBefore);
        assertEq(released, 5);
    }

    /// Truncating then reposting reuses the submission id with a fresh post index; the reused id
    /// is not finalized history and releases nothing.
    function test_bond_repostAfterTruncate_releasesNothingEarly() public {
        if (!ready) { vm.skip(true); return; }
        bytes32[] memory blobs = new bytes32[](1);
        blobs[0] = keccak256("bond_repost");
        vm.blobhashes(blobs);
        vm.deal(poster, 10 ether);

        _postRound(0);
        vm.roll(block.number + 3601);
        IntmaxRollup.ValidityPublicInputs memory none;
        rollup.fraudProof(0, bytes32(0), none, "");
        assertEq(rollup.nextSubmissionId(), 0, "id rewound for reuse");
        (, uint256 posted,) = _bond();
        assertEq(posted, 0);

        assertEq(_postRound(0), 0, "submissionId reused");
        (, posted,) = _bond();
        assertEq(posted, 1);
        vm.expectRevert(IntmaxRollup.SubmissionNotYetFinalized.selector);
        rollup.releaseBond(poster, 0);
    }

    // ─── lifecycle helpers (mirror C2CFullE2E / C2CBlockHash ordering) ───

    function _finalize(uint256 subId) internal {
        IntmaxRollup.ValidityPublicInputs memory vpis = _parseVpis();
        bytes memory vproof = FixtureLib.parseCompactProofV2(_validityMleJson());
        bytes32 finalRoot = vm.parseJsonBytes32(lc, ".final_state_root");
        assertTrue(rollup.finalize(subId, finalRoot, vpis, vproof), "finalize failed");
    }

    function _postAllRoundsNoFinalize() internal returns (uint256 lastSubId) {
        bytes32[] memory blobs = new bytes32[](1);
        blobs[0] = keccak256("bond_c2c");
        vm.blobhashes(blobs);
        vm.deal(poster, 10 ether);
        _register(".registration1");
        _postRound(0);
        _deposit();
        _postRound(1);
        _register(".registration2");
        _postRound(2);
        _postRound(3);
        // The aggregate validity proof finalizes via sub4, so sub4 must commit the root it proves.
        lastSubId = _postRound(4, vm.parseJsonBytes32(lc, ".final_state_root"));
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
        // Rounds that are never finalized keep the placeholder root — they only need a bond.
        return _postRound(i, bytes32(0));
    }

    /// @dev H-5: `finalize` binds the submission to the state root it was POSTED with, so a round
    ///      that will later be finalized must commit the root its proof actually proves.
    function _postRound(uint256 i, bytes32 stateRoot) internal returns (uint256 subId) {
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
        bytes32 pin = rollup.pendingChainsPin();
        // Top up whatever the bond lacks for this post.
        (uint96 balance, uint48 posted, uint48 released) = rollup.bonds(poster);
        uint256 required = BASE + (uint256(posted) + 1 - released) * PER_POST;
        uint256 value = required > balance ? required - balance : 0;
        vm.prank(poster);
        rollup.postBlockAndSubmit{value: value}(sb, bytes32(0), 0, stateRoot, pin);
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
