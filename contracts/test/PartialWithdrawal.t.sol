// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {IChannelRegistry, IChannelSettlementVerifier} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {CloseSettlementBase, MockRollupRegistry} from "./CloseSettlementBase.sol";

contract PartialWithdrawalTest is CloseSettlementBase {
    bytes32 constant TX_LEAF = keccak256("burn_tx_leaf");
    bytes32 constant PREV_CHAIN = keccak256("prev_settled_tx_chain");
    bytes32 constant NULLIFIER = keccak256("partial_withdrawal_nullifier");
    /// A NON-participant address — used only by the negative recipient test.
    address constant OUTSIDER = address(0xBEEF);
    uint32 constant TOKEN_INDEX = 0;
    /// The channel's declared genesis-token fund in `_partialIntentAtVersion` (the proof-bound cap).
    uint256 constant CHANNEL_FUND = 50;
    /// A claim strictly inside the cap. Was `5 ether` against a 50-wei fund — nonsensical, and only
    /// possible because no check ever compared the two (doc/tasks/pw-auth-threat-model.md §4.1).
    uint256 constant AMOUNT = 5;

    /// The payout address for the happy paths: `alice` is `bindings[0].recipient`, i.e. a REGISTERED
    /// participant of this channel (`isMemberRecipient[alice] == true`, set in the constructor).
    function _recipient() internal view returns (address) {
        return alice;
    }

    function _settledTxChainPush(bytes32 prev, bytes32 leaf) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint32(0x494d5443), prev, leaf));
    }

    function _baseRecipient(address recipient) internal pure returns (bytes32) {
        return bytes32((uint256(2) << 248) | uint256(uint160(recipient)));
    }

    function _burnDescriptor(address recipient, uint32 tokenIndex, uint256 amount) internal pure returns (bytes32) {
        return _burnDescriptorFor(TX_LEAF, recipient, tokenIndex, amount);
    }

    function _burnDescriptorFor(bytes32 txLeaf, address recipient, uint32 tokenIndex, uint256 amount)
        internal
        pure
        returns (bytes32)
    {
        return _burnDescriptorForNonce(txLeaf, recipient, tokenIndex, amount, PW_BASE_NONCE);
    }

    function _burnDescriptorForNonce(
        bytes32 txLeaf,
        address recipient,
        uint32 tokenIndex,
        uint256 amount,
        uint32 baseNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(0x494d4432), uint32(CHANNEL_ID), baseNonce, txLeaf, _baseRecipient(recipient), tokenIndex, amount
            )
        );
    }

    function _partialIntent() internal view returns (ChannelSettlementManager.CloseIntent memory) {
        return _partialIntentAtVersion(12, 1);
    }

    function _partialIntentAtVersion(uint64 stateVersion, uint64 epoch)
        internal
        view
        returns (ChannelSettlementManager.CloseIntent memory)
    {
        return ChannelSettlementManager.CloseIntent({
            closeNonce: 1,
            finalEpoch: epoch,
            finalSmallBlockNumber: 10,
            // A real close proof exposes signed_state.close_freeze_nonce + 1. The manager's live
            // Active-era nonce is zero in this fixture, hence the proof PI is one.
            closeFreezeNonce: 1,
            // Model a real IMCH: changing the signed state version/epoch changes the final digest.
            finalChannelStateDigest: keccak256(abi.encodePacked("partial_state", stateVersion, epoch)),
            finalBalanceStateH1: keccak256("partial_h1"),
            channelFundAmounts: _singleAmounts(CHANNEL_FUND),
            tokenRegistry: _singleRegistry(),
            tokenCount: 1,
            channelFundIntmaxStateRoot: keccak256("intmax_root"),
            burnTxHash: bytes32(0),
            closeWithdrawalDigest: keccak256("close_wd"),
            snapshotMediumBlockNumber: 0,
            finalStateVersion: stateVersion,
            finalSettledTxChain: _settledTxChainPush(PREV_CHAIN, _burnDescriptor(_recipient(), TOKEN_INDEX, AMOUNT)),
            finalSettledTxAccumulatorRoot: keccak256("acc_root")
        });
    }

    function _authorizedWithdrawal() internal view returns (ChannelSettlementManager.AuthorizedWithdrawal memory) {
        return ChannelSettlementManager.AuthorizedWithdrawal({
            recipient: _recipient(),
            tokenIndex: TOKEN_INDEX,
            amount: AMOUNT,
            baseNonce: PW_BASE_NONCE,
            nullifier: NULLIFIER,
            auxData: _burnDescriptor(_recipient(), TOKEN_INDEX, AMOUNT),
            txLeaf: TX_LEAF
        });
    }

    function _expectedAuthDigest(ChannelSettlementManager.AuthorizedWithdrawal memory w)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(bytes4(0x49505732), w.recipient, w.tokenIndex, w.amount, w.auxData));
    }

    function _expectedBurnKey(ChannelSettlementManager.AuthorizedWithdrawal memory w) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes4(0x494d424b), uint32(CHANNEL_ID), w.auxData));
    }

    // ── Happy path ──

    function test_submitPartialWithdrawalIntent_happy() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();

        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);

        assertTrue(manager.partialWithdrawalPending());
        assertEq(manager.pendingPartialWithdrawalAuthDigest(), _expectedAuthDigest(w));
        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.Active));
    }

    /// The common close-proof gate also protects the production partial-withdrawal entry point;
    /// supplying a proof whose mock PIs match the noncanonical metadata does not bypass it.
    function test_partialWithdrawal_rejects_noncanonical_close_metadata() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();

        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        intent.closeNonce = 2;
        bytes memory proof = _closeProof(intent);
        vm.expectRevert(ChannelSettlementManager.NonCanonicalCloseMetadata.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);

        intent = _partialIntent();
        intent.burnTxHash = keccak256("unproven live burn");
        proof = _closeProof(intent);
        vm.expectRevert(ChannelSettlementManager.NonCanonicalCloseMetadata.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);

        intent = _partialIntent();
        intent.snapshotMediumBlockNumber = 77;
        proof = _closeProof(intent);
        vm.expectRevert(ChannelSettlementManager.NonCanonicalCloseMetadata.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    function test_submitAndFinalize_happy() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();

        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizePartialWithdrawal();

        assertFalse(manager.partialWithdrawalPending());

        bytes32 authDigest = _expectedAuthDigest(w);
        assertTrue(registry.partialWithdrawalAuthorized(authDigest));

        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.Active));
    }

    // ── B-2: the delegate-count range bind on the PARTIAL-WITHDRAWAL lane ──
    //
    // `submitPartialWithdrawalIntent` calls the IDENTICAL `_checkCloseProof` as `submitCloseIntent`
    // (ChannelSettlementManager.sol), so the former strict limb-94 equality bricked mid-channel
    // partial withdrawals for exactly the same channels it bricked closes for. These pin that the
    // fix reaches this lane too, and that the floor still bites here (threat model §8 test 6).

    /// The same frozen-count equality applies to partial withdrawals.
    function test_partialWithdrawal_delegateCountAboveFrozenCount_reverts() public {
        assertEq(uint256(manager.activeDelegateCount()), 0, "this manager registers 0 delegates");
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProofWithDelegateCount(intent, 3);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();

        vm.expectRevert(ChannelSettlementVerifier.CloseDelegateCountOutOfRange.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    /// NEGATIVE (ceiling): `memberCount + delegateCount > 1024` is refused on this lane as well —
    /// the same mirror of the in-circuit claim bound.
    function test_b2_partialWithdrawal_delegateCountAboveCeiling_reverts() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        uint32 mc = uint32(manager.activeMemberCount());
        // Build BEFORE arming expectRevert (the builder is itself an external call).
        bytes memory overCap = _closeProofWithDelegateCount(intent, 1024 - mc + 1);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();

        vm.expectRevert(ChannelSettlementVerifier.CloseDelegateCountOutOfRange.selector);
        manager.submitPartialWithdrawalIntent(intent, overCap, PREV_CHAIN, w);
    }

    /// NEGATIVE (floor): on a manager that DID register a delegate, a partial-withdrawal proof that
    /// would exclude it from the active region is refused.
    function test_b2_partialWithdrawal_delegateCountBelowFloor_reverts() public {
        bytes32 USER_D = keccak256("pw_delegate_d");
        address dave = makeAddr("pw_dave");
        ChannelSettlementManager.MemberBinding[] memory mb = new ChannelSettlementManager.MemberBinding[](3);
        mb[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: alice});
        mb[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
        mb[2] = ChannelSettlementManager.MemberBinding({pkG: USER_C, recipient: carol});
        ChannelSettlementManager.MemberBinding[] memory db = new ChannelSettlementManager.MemberBinding[](1);
        db[0] = ChannelSettlementManager.MemberBinding({pkG: USER_D, recipient: dave});
        ChannelSettlementManager m = new ChannelSettlementManager(
            CHANNEL_ID,
            BP_MEMBER_SLOT,
            USER_A,
            1, // registered delegate_count = 1
            keccak256("pw_delegate_snapshot"),
            CHALLENGE_PERIOD,
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)),
            IChannelRegistry(address(registry)),
            address(this),
            mb
        );

        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory excludes =
            this._closeProofCd(intent, m.registeredMemberSetCommitment(), m.activeMemberCount(), 0);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();

        vm.expectRevert(ChannelSettlementVerifier.CloseDelegateCountOutOfRange.selector);
        m.submitPartialWithdrawalIntent(intent, excludes, PREV_CHAIN, w);
    }

    // ── Revert: auxData zero ──

    function test_submitPartialWithdrawal_reverts_auxDataZero() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.auxData = bytes32(0);

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalAuxDataZero.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    // ── Revert: settled_tx_chain mismatch ──

    function test_submitPartialWithdrawal_reverts_chainMismatch() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();

        bytes32 wrongPrev = keccak256("wrong_prev");

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalChainMismatch.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, wrongPrev, w);
    }

    // ── Revert: channel not Active ──

    function test_submitPartialWithdrawal_reverts_channelNotActive() public {
        uint64 freezeNonce = manager.currentCloseFreezeNonce();
        uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
        vm.prank(alice);
        manager.requestClose(freezeNonce, cancellationFloor);
        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending));

        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();

        vm.expectRevert(ChannelSettlementManager.ChannelClosed.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    // ── Revert: finalize before challenge period ──

    function test_finalizePartialWithdrawal_reverts_challengeWindowOpen() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());

        vm.expectRevert(ChannelSettlementManager.ChallengeWindowOpen.selector);
        manager.finalizePartialWithdrawal();
    }

    // ── Revert: finalize at exact deadline (strict >) ──

    function test_finalizePartialWithdrawal_reverts_atExactDeadline() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());

        vm.warp(block.timestamp + CHALLENGE_PERIOD);
        vm.expectRevert(ChannelSettlementManager.ChallengeWindowOpen.selector);
        manager.finalizePartialWithdrawal();
    }

    // ── Revert: finalize when nothing pending ──

    function test_finalizePartialWithdrawal_reverts_notPending() public {
        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalNotPending.selector);
        manager.finalizePartialWithdrawal();
    }

    // ── Logical burn single-use after atomic Manager finalization ──
    // A cancelled/unfinalized burn remains re-submittable, but once Manager finalization atomically
    // accounts the IMBK and authorizes Rollup, submitting it again has no recovery purpose. Refusing
    // it prevents an already-paid burn from monopolizing the singleton slot or re-enabling IPW2.
    function test_submitPartialWithdrawal_accountedBurnCannotBeResubmitted() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);

        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizePartialWithdrawal();
        assertFalse(manager.partialWithdrawalPending());

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalAlreadyAccounted.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());
        assertFalse(manager.partialWithdrawalPending());
    }

    /// IPW2 excludes the unverified proof-side nullifier, and IMBK — not the malleable close
    /// digest — keys the cancel floor, review window, and accounting latch.
    function test_nullifierAndCloseDigestVariationCannotBypassBurnState() public {
        uint256 t0 = block.timestamp;
        ChannelSettlementManager.CloseIntent memory firstIntent = _partialIntent();
        ChannelSettlementManager.AuthorizedWithdrawal memory first = _authorizedWithdrawal();
        manager.submitPartialWithdrawalIntent(firstIntent, _closeProof(firstIntent), PREV_CHAIN, first);

        bytes32 firstCloseDigest = manager.pendingPartialWithdrawalCloseIntentDigest();
        bytes32 burnKey = manager.pendingPartialWithdrawalBurnKey();
        bytes32 authDigest = manager.pendingPartialWithdrawalAuthDigest();
        assertEq(burnKey, _expectedBurnKey(first));

        ChannelSettlementManager.CancelCloseRequest memory cancel = ChannelSettlementManager.CancelCloseRequest({
            closeIntentDigest: firstCloseDigest,
            revivedStateVersion: 99,
            revivedChannelStateDigest: keccak256("review_state")
        });
        uint256[] memory cancelLimbs = verifier.expectedCancelCloseLimbs(
            CHANNEL_ID,
            firstCloseDigest,
            manager.registeredMemberSetCommitment(),
            manager.pendingPartialWithdrawalStateVersion(),
            cancel.revivedStateVersion,
            cancel.revivedChannelStateDigest
        );
        manager.cancelPartialWithdrawal(cancel, CloseTestLib.proofWithLimbs(cancelLimbs));

        assertEq(manager.cancelledPartialWithdrawalRevivedVersion(burnKey), 99);
        assertEq(manager.cancelledPartialWithdrawalReviewUntil(burnKey), t0 + 2 * CHALLENGE_PERIOD);

        // Same signed burn, but a different proof-side nullifier. Close metadata itself has one
        // canonical representation and cannot be varied.
        ChannelSettlementManager.AuthorizedWithdrawal memory variant = _authorizedWithdrawal();
        variant.nullifier = keccak256("another_proof_nullifier");
        assertEq(_expectedAuthDigest(variant), authDigest, "nullifier is not authorization input");

        ChannelSettlementManager.CloseIntent memory variantIntent = _partialIntent();
        manager.submitPartialWithdrawalIntent(variantIntent, _closeProof(variantIntent), PREV_CHAIN, variant);

        bytes32 variantCloseDigest = manager.pendingPartialWithdrawalCloseIntentDigest();
        assertEq(variantCloseDigest, firstCloseDigest, "M-9 metadata cannot change closeStateId");
        assertEq(manager.pendingPartialWithdrawalBurnKey(), burnKey);
        assertEq(manager.pendingPartialWithdrawalAuthDigest(), authDigest);
        assertEq(manager.pendingPartialWithdrawalDeadline(), t0 + 2 * CHALLENGE_PERIOD);

        // Even a proof rebuilt for the variant digest cannot replay the already-consumed v99
        // cancel material, because the floor follows the logical burn.
        ChannelSettlementManager.CancelCloseRequest memory replay = ChannelSettlementManager.CancelCloseRequest({
            closeIntentDigest: variantCloseDigest,
            revivedStateVersion: 99,
            revivedChannelStateDigest: keccak256("review_state")
        });
        uint256[] memory replayLimbs = verifier.expectedCancelCloseLimbs(
            CHANNEL_ID,
            variantCloseDigest,
            manager.registeredMemberSetCommitment(),
            manager.pendingPartialWithdrawalStateVersion(),
            replay.revivedStateVersion,
            replay.revivedChannelStateDigest
        );
        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalCancelReplay.selector);
        manager.cancelPartialWithdrawal(replay, CloseTestLib.proofWithLimbs(replayLimbs));

        vm.warp(uint256(manager.pendingPartialWithdrawalDeadline()) + 1);
        manager.finalizePartialWithdrawal();
        assertEq(manager.authorizedBurnAmount(TOKEN_INDEX), AMOUNT);

        // Neither the original nor a proof-side-nullifier variant can bypass the finalized IMBK
        // latch and re-enable the one-shot authorization.
        bytes memory firstProof = _closeProof(firstIntent);
        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalAlreadyAccounted.selector);
        manager.submitPartialWithdrawalIntent(firstIntent, firstProof, PREV_CHAIN, first);
        assertEq(manager.authorizedBurnAmount(TOKEN_INDEX), AMOUNT);
    }

    /// Different IMD2 descriptors are different logical burns and must each contribute once.
    function test_differentAuxDataAccruesSeparately() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory first = _authorizedWithdrawal();
        ChannelSettlementManager.CloseIntent memory firstIntent = _partialIntent();
        manager.submitPartialWithdrawalIntent(firstIntent, _closeProof(firstIntent), PREV_CHAIN, first);
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizePartialWithdrawal();

        ChannelSettlementManager.AuthorizedWithdrawal memory second = _authorizedWithdrawal();
        second.baseNonce = PW_BASE_NONCE + 1;
        second.txLeaf = keccak256("second_logical_burn");
        second.nullifier = keccak256("second_logical_burn_nullifier");
        second.auxData = _burnDescriptorForNonce(
            second.txLeaf, second.recipient, second.tokenIndex, second.amount, second.baseNonce
        );
        ChannelSettlementManager.CloseIntent memory secondIntent = _partialIntentAtVersion(13, 1);
        secondIntent.finalSettledTxChain = _settledTxChainPush(PREV_CHAIN, second.auxData);

        manager.submitPartialWithdrawalIntent(secondIntent, _closeProof(secondIntent), PREV_CHAIN, second);
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizePartialWithdrawal();

        assertTrue(_expectedBurnKey(first) != _expectedBurnKey(second));
        assertTrue(manager.accountedPartialWithdrawalBurn(_expectedBurnKey(first)));
        assertTrue(manager.accountedPartialWithdrawalBurn(_expectedBurnKey(second)));
        assertEq(manager.authorizedBurnAmount(TOKEN_INDEX), AMOUNT * 2);
    }

    // ── Challenge replacement: newer state replaces pending ──

    function test_challengeReplacement_newerStateWins() public {
        ChannelSettlementManager.CloseIntent memory intent1 = _partialIntentAtVersion(10, 1);
        bytes memory proof1 = _closeProof(intent1);
        ChannelSettlementManager.AuthorizedWithdrawal memory w1 = _authorizedWithdrawal();

        // Adjust w1.auxData and PREV_CHAIN to match intent1's finalSettledTxChain
        // intent1's chain is _settledTxChainPush(PREV_CHAIN, AUX_DATA) — same as default
        manager.submitPartialWithdrawalIntent(intent1, proof1, PREV_CHAIN, w1);

        bytes32 authDigest1 = manager.pendingPartialWithdrawalAuthDigest();
        uint64 originalDeadline = manager.pendingPartialWithdrawalDeadline();

        vm.warp(block.timestamp + CHALLENGE_PERIOD / 2);

        // Submit newer intent (higher stateVersion)
        ChannelSettlementManager.CloseIntent memory intent2 = _partialIntentAtVersion(15, 1);
        bytes memory proof2 = _closeProof(intent2);
        manager.submitPartialWithdrawalIntent(intent2, proof2, PREV_CHAIN, w1);

        // The pending digest should have changed (same withdrawal but new close intent → same authDigest)
        assertEq(manager.pendingPartialWithdrawalStateVersion(), 15);
        assertTrue(manager.partialWithdrawalPending());
        assertEq(manager.pendingPartialWithdrawalAuthDigest(), authDigest1);
        assertEq(
            manager.pendingPartialWithdrawalDeadline(),
            originalDeadline,
            "same-burn replacement must not reset the challenge window"
        );
    }

    /// A second, separately valid burn must wait for the singleton pending authorization. If it
    /// could replace the first, a subsequent close would make the first already-debited burn
    /// permanently unresubmittable and strand its payout.
    function test_challengeReplacement_unrelatedNewerBurnReverts() public {
        ChannelSettlementManager.CloseIntent memory firstIntent = _partialIntentAtVersion(10, 1);
        ChannelSettlementManager.AuthorizedWithdrawal memory first = _authorizedWithdrawal();
        manager.submitPartialWithdrawalIntent(
            firstIntent, _closeProof(firstIntent), PREV_CHAIN, first
        );

        ChannelSettlementManager.AuthorizedWithdrawal memory second = _authorizedWithdrawal();
        second.baseNonce = PW_BASE_NONCE + 1;
        second.txLeaf = keccak256("replacement_other_burn");
        second.nullifier = keccak256("replacement_other_nullifier");
        second.auxData = _burnDescriptorForNonce(
            second.txLeaf,
            second.recipient,
            second.tokenIndex,
            second.amount,
            second.baseNonce
        );
        ChannelSettlementManager.CloseIntent memory secondIntent =
            _partialIntentAtVersion(11, 1);
        secondIntent.finalSettledTxChain =
            _settledTxChainPush(firstIntent.finalSettledTxChain, second.auxData);

        bytes memory secondProof = _closeProof(secondIntent);
        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalDifferentBurnPending.selector);
        manager.submitPartialWithdrawalIntent(
            secondIntent,
            secondProof,
            firstIntent.finalSettledTxChain,
            second
        );

        assertEq(manager.pendingPartialWithdrawalBurnKey(), _expectedBurnKey(first));
        assertEq(manager.pendingPartialWithdrawalStateVersion(), 10);
    }

    // ── Challenge replacement: same or lower version reverts ──

    function test_challengeReplacement_sameVersionReverts() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntentAtVersion(10, 1);
        bytes memory proof = _closeProof(intent);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalNotNewer.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());
    }

    function test_challengeReplacement_lowerVersionReverts() public {
        ChannelSettlementManager.CloseIntent memory intent1 = _partialIntentAtVersion(15, 1);
        bytes memory proof1 = _closeProof(intent1);
        manager.submitPartialWithdrawalIntent(intent1, proof1, PREV_CHAIN, _authorizedWithdrawal());

        ChannelSettlementManager.CloseIntent memory intent2 = _partialIntentAtVersion(10, 1);
        bytes memory proof2 = _closeProof(intent2);

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalNotNewer.selector);
        manager.submitPartialWithdrawalIntent(intent2, proof2, PREV_CHAIN, _authorizedWithdrawal());
    }

    // ── Challenge replacement: higher epoch wins even if lower stateVersion ──

    function test_challengeReplacement_higherEpochWins() public {
        ChannelSettlementManager.CloseIntent memory intent1 = _partialIntentAtVersion(100, 1);
        bytes memory proof1 = _closeProof(intent1);
        manager.submitPartialWithdrawalIntent(intent1, proof1, PREV_CHAIN, _authorizedWithdrawal());

        ChannelSettlementManager.CloseIntent memory intent2 = _partialIntentAtVersion(5, 2);
        bytes memory proof2 = _closeProof(intent2);
        manager.submitPartialWithdrawalIntent(intent2, proof2, PREV_CHAIN, _authorizedWithdrawal());

        assertEq(manager.pendingPartialWithdrawalEpoch(), 2);
        assertEq(manager.pendingPartialWithdrawalStateVersion(), 5);
    }

    // ── Cancel partial withdrawal ──

    function test_cancelPartialWithdrawal_happy() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());

        assertTrue(manager.partialWithdrawalPending());

        bytes32 closeIntentDigest = manager.pendingPartialWithdrawalCloseIntentDigest();
        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager.CancelCloseRequest({
            closeIntentDigest: closeIntentDigest,
            revivedStateVersion: 99,
            revivedChannelStateDigest: keccak256("revived_state")
        });

        uint256[] memory limbs = verifier.expectedCancelCloseLimbs(
            CHANNEL_ID,
            closeIntentDigest,
            manager.registeredMemberSetCommitment(),
            manager.pendingPartialWithdrawalStateVersion(),
            request.revivedStateVersion,
            request.revivedChannelStateDigest
        );
        bytes memory cancelProof = CloseTestLib.proofWithLimbs(limbs);

        manager.cancelPartialWithdrawal(request, cancelProof);

        assertFalse(manager.partialWithdrawalPending());
        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.Active));
    }

    // ── Cancel reverts: nothing pending ──

    function test_cancelPartialWithdrawal_reverts_notPending() public {
        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager.CancelCloseRequest({
            closeIntentDigest: keccak256("x"), revivedStateVersion: 99, revivedChannelStateDigest: keccak256("revived")
        });
        bytes memory dummy;

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalNotPending.selector);
        manager.cancelPartialWithdrawal(request, dummy);
    }

    // ── Cancel reverts: wrong closeIntentDigest ──

    function test_cancelPartialWithdrawal_reverts_digestMismatch() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());

        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager.CancelCloseRequest({
            closeIntentDigest: keccak256("wrong_digest"),
            revivedStateVersion: 99,
            revivedChannelStateDigest: keccak256("revived")
        });
        bytes memory dummy;

        vm.expectRevert(ChannelSettlementManager.CloseIntentDigestMismatch.selector);
        manager.cancelPartialWithdrawal(request, dummy);
    }

    // ── P0-9: one-member requestClose vetoes an in-flight PW by advancing the era ──

    function test_finalizePartialWithdrawal_reverts_afterRequestClose() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());

        // requestClose during challenge period → status becomes ClosePending
        uint64 freezeNonce = manager.currentCloseFreezeNonce();
        uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
        vm.prank(alice);
        manager.requestClose(freezeNonce, cancellationFloor);
        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending));

        // H-6 (audit 2026-08-28): a frozen-but-unsettled close still blocks the payout, because the
        // settlement state version that decides whether the burn is already excluded from
        // `channelFundAmounts` is not yet known. The error is now the RETRYABLE
        // `PartialWithdrawalCloseInProgress` rather than `InvalidFreezeNonce` — the pending
        // withdrawal is deferred, not destroyed. (Before the fix this was a permanent strand: the
        // era could never be satisfied again, since no shipped code advances
        // `ChannelState.close_freeze_nonce`. The retryability is asserted in
        // `CloseLifecycleHardening.t.sol`.)
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalCloseInProgress.selector);
        manager.finalizePartialWithdrawal();

        bytes32 authDigest = _expectedAuthDigest(_authorizedWithdrawal());
        assertFalse(registry.partialWithdrawalAuthorized(authDigest));
        // The pending withdrawal SURVIVES the refusal — that is the difference between a deferral
        // and the old permanent veto.
        assertTrue(manager.partialWithdrawalPending(), "burn authorization not destroyed");
    }

    function test_submitPartialWithdrawal_reverts_wrongEra() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        intent.closeFreezeNonce = 2;
        intent.closeNonce = 2;
        bytes memory proof = _closeProof(intent);

        vm.expectRevert(ChannelSettlementManager.InvalidFreezeNonce.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());
    }

    function test_burnDescriptor_matchesFrozenRustVector() public pure {
        bytes32 txLeaf = bytes32(uint256(1));
        bytes32 baseRecipient = 0x02000000000000000000000000000000000000000000000000000000000000aa;
        bytes32 got = keccak256(
            abi.encodePacked(bytes4(0x494d4432), uint32(1), uint32(9), txLeaf, baseRecipient, uint32(7), uint256(20))
        );
        assertEq(got, 0xb6753ec0eaf281f39942bbc2293983db8369713fc8a3f9446f6c86c8b5c737f5);
    }

    // ── Cross-field tamper: different amount → different authDigest ──
    //
    // SECURITY SCOPE (corrected 2026-07-28, doc/tasks/pw-auth-threat-model.md §7): these two tests
    // establish ONLY that keccak over the IPW2 preimage is injective in `amount` / `recipient` —
    // i.e. REPLAY binding: one authorization cannot be re-read as a different tuple. They say
    // NOTHING about whether those fields are correct, and they must never be read as economic
    // coverage. Historically they were the closest thing to a test of the burn path's economics,
    // and they contributed to the misconception that the digest "binds" the payout. The claim's
    // legitimacy is established ONLY by the base-layer proof on the payout side
    // (`IntmaxRollup._verifyWithdrawalSet`); see `PartialWithdrawalPayout.t.sol`.

    function test_crossFieldTamper_differentAmountDifferentDigest() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory w1 = _authorizedWithdrawal();
        ChannelSettlementManager.AuthorizedWithdrawal memory w2 = _authorizedWithdrawal();
        w2.amount = AMOUNT + 1;

        assertTrue(_expectedAuthDigest(w1) != _expectedAuthDigest(w2));
    }

    // ── Cross-field tamper: different recipient → different authDigest ──

    function test_crossFieldTamper_differentRecipientDifferentDigest() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory w1 = _authorizedWithdrawal();
        ChannelSettlementManager.AuthorizedWithdrawal memory w2 = _authorizedWithdrawal();
        w2.recipient = address(0xDEAD);

        assertTrue(_expectedAuthDigest(w1) != _expectedAuthDigest(w2));
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    //  Partial-withdrawal economics and registry binding
    //
    //  IMD2 derives source-channel/base-nonce and the exact recipient/token/amount from the
    //  descriptor pinned by the N-of-N
    //  settled-tx chain. The fund vector exposed by the close proof is already POST-BURN, so it
    //  must not be used as a second cap on the same debit.
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// Regression for the double-subtraction bug: pre-burn F=50, burn X=50, post-burn fund=0.
    /// The old `X <= postFund` check rejected every honest full-balance burn.
    function test_submitPartialWithdrawal_allowsFullBalanceBurnWithZeroPostBurnFund() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.amount = CHANNEL_FUND;
        w.auxData = _burnDescriptor(w.recipient, w.tokenIndex, w.amount);
        intent.channelFundAmounts[0] = 0;
        intent.finalSettledTxChain = _settledTxChainPush(PREV_CHAIN, w.auxData);
        bytes memory proof = _closeProof(intent);

        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
        assertTrue(manager.partialWithdrawalPending());
        assertEq(manager.pendingPartialWithdrawalAuthDigest(), _expectedAuthDigest(w));
    }

    /// Regression for burns over half the pre-burn fund: F=50, X=30, post-burn fund=20.
    function test_submitPartialWithdrawal_allowsBurnGreaterThanPostBurnFund() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.amount = 30;
        w.auxData = _burnDescriptor(w.recipient, w.tokenIndex, w.amount);
        intent.channelFundAmounts[0] = 20;
        intent.finalSettledTxChain = _settledTxChainPush(PREV_CHAIN, w.auxData);
        bytes memory proof = _closeProof(intent);

        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
        assertTrue(manager.partialWithdrawalPending());
    }

    /// Two honest burns can drain the same fund in sequence. The second proof builds on the first
    /// chain and post-state, and both chain keys/auth digests remain distinct.
    function test_submitPartialWithdrawal_allowsTwoConsecutiveBurnsThroughZeroFund() public {
        bytes32 firstTxLeaf = keccak256("first_pw_tx_leaf");
        ChannelSettlementManager.AuthorizedWithdrawal memory first = _authorizedWithdrawal();
        first.txLeaf = firstTxLeaf;
        first.amount = 30;
        first.nullifier = keccak256("first_pw_nullifier");
        first.auxData = _burnDescriptorFor(firstTxLeaf, first.recipient, first.tokenIndex, first.amount);

        ChannelSettlementManager.CloseIntent memory firstIntent = _partialIntentAtVersion(12, 1);
        firstIntent.channelFundAmounts[0] = 20;
        firstIntent.finalSettledTxChain = _settledTxChainPush(PREV_CHAIN, first.auxData);
        bytes memory firstProof = _closeProof(firstIntent);

        manager.submitPartialWithdrawalIntent(firstIntent, firstProof, PREV_CHAIN, first);
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizePartialWithdrawal();

        bytes32 secondTxLeaf = keccak256("second_pw_tx_leaf");
        ChannelSettlementManager.AuthorizedWithdrawal memory second = _authorizedWithdrawal();
        second.txLeaf = secondTxLeaf;
        second.amount = 20;
        second.nullifier = keccak256("second_pw_nullifier");
        second.auxData = _burnDescriptorFor(secondTxLeaf, second.recipient, second.tokenIndex, second.amount);

        bytes32 secondPrevChain = firstIntent.finalSettledTxChain;
        ChannelSettlementManager.CloseIntent memory secondIntent = _partialIntentAtVersion(13, 2);
        secondIntent.channelFundAmounts[0] = 0;
        secondIntent.finalSettledTxChain = _settledTxChainPush(secondPrevChain, second.auxData);
        bytes memory secondProof = _closeProof(secondIntent);

        manager.submitPartialWithdrawalIntent(secondIntent, secondProof, secondPrevChain, second);
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizePartialWithdrawal();

        bytes32 firstKey = keccak256(abi.encodePacked(CHANNEL_ID, firstIntent.finalSettledTxChain));
        bytes32 secondKey = keccak256(abi.encodePacked(CHANNEL_ID, secondIntent.finalSettledTxChain));
        assertTrue(firstKey != secondKey);
        assertTrue(registry.partialWithdrawalAuthorized(_expectedAuthDigest(first)));
        assertTrue(registry.partialWithdrawalAuthorized(_expectedAuthDigest(second)));
        assertTrue(_expectedAuthDigest(first) != _expectedAuthDigest(second));
    }

    /// Property: once IMD2 and the proof-bound chain agree, the post-burn remainder is not a second
    /// cap. Base-layer no-underflow and the channel transition prove that the pre-burn debit was
    /// affordable; this Manager only consumes the resulting post-state.
    function testFuzz_submitPartialWithdrawal_exactDescriptorIgnoresPostBurnRemainder(
        uint128 rawAmount,
        uint128 rawPostFund
    ) public {
        uint256 amount = bound(uint256(rawAmount), 1, type(uint128).max);
        uint256 postFund = bound(uint256(rawPostFund), 0, type(uint128).max);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.amount = amount;
        w.auxData = _burnDescriptor(w.recipient, w.tokenIndex, amount);

        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        intent.channelFundAmounts[0] = postFund;
        intent.finalSettledTxChain = _settledTxChainPush(PREV_CHAIN, w.auxData);
        bytes memory proof = _closeProof(intent);

        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
        assertTrue(manager.partialWithdrawalPending());
    }

    /// Property: removing the stale post-state cap must not make amount caller-selectable. Any
    /// amount mutation after the chain/IMD2 descriptor was fixed still fails at the exact-binding
    /// check, even when the post-burn fund is deliberately made enormous.
    function testFuzz_submitPartialWithdrawal_amountMutationStillRejected(uint128 rawAmount) public {
        uint256 committedAmount = bound(uint256(rawAmount), 1, type(uint128).max - 1);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.amount = committedAmount;
        w.auxData = _burnDescriptor(w.recipient, w.tokenIndex, committedAmount);

        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        intent.channelFundAmounts[0] = type(uint256).max;
        intent.finalSettledTxChain = _settledTxChainPush(PREV_CHAIN, w.auxData);
        bytes memory proof = _closeProof(intent);

        w.amount = committedAmount + 1;
        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalDescriptorMismatch.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    /// Fail-closed: a base token the channel never cosigned into its registry is rejected outright
    /// rather than silently defaulting to slot 0.
    function test_submitPartialWithdrawal_reverts_tokenNotInRegistry() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.tokenIndex = 7; // registry is [0] with tokenCount 1

        vm.expectRevert(ChannelSettlementManager.TokenRegistryMismatch.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    /// A slot PAST `tokenCount` is padding, not a registration: token 0 sits at slot 0 with
    /// tokenCount 1, so a second token present only in the zero-padding must not be honoured.
    function test_submitPartialWithdrawal_reverts_tokenOnlyInPaddingSlot() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        // Slot 1 is beyond tokenCount==1 — pure padding. Give it a token index and a huge fund.
        intent.tokenRegistry[1] = 42;
        intent.channelFundAmounts[1] = type(uint256).max;
        bytes memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.tokenIndex = 42;
        w.amount = 1_000_000;

        vm.expectRevert(ChannelSettlementManager.TokenRegistryMismatch.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    // ── (b) Recipient is authenticated by the exact N-of-N burn descriptor ──
    //
    // The manager does not maintain O(1024) participant-recipient mappings. Instead, recipient,
    // token and amount are jointly committed by IMBK inside the N-of-N-signed settled chain; a
    // caller cannot redirect an already-authorized payout by changing only the ABI metadata.

    function test_submitPartialWithdrawal_reverts_outsiderRecipientTamper() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.recipient = OUTSIDER;

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalDescriptorMismatch.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    /// A funded EOA cannot replace the recipient authorized by the signed burn descriptor either.
    function test_submitPartialWithdrawal_reverts_fundedEoaRecipientTamper() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.recipient = mallory;

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalDescriptorMismatch.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    /// A burn genuinely built for another registered member remains valid when its descriptor and
    /// co-signed chain are rebuilt for that member.
    function test_submitPartialWithdrawal_allowsOtherRegisteredMembers() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.recipient = bob;
        w.auxData = _burnDescriptor(w.recipient, w.tokenIndex, w.amount);
        intent.finalSettledTxChain = _settledTxChainPush(PREV_CHAIN, w.auxData);
        bytes memory proof = _closeProof(intent);

        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
        assertTrue(manager.partialWithdrawalPending());
        assertTrue(manager.isMemberRecipient(carol));
    }

    function test_submitPartialWithdrawal_reverts_amountDescriptorMismatch() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.amount = AMOUNT + 1;

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalDescriptorMismatch.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    function test_submitPartialWithdrawal_reverts_amountMinusOneDescriptorMismatch() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.amount = AMOUNT - 1;

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalDescriptorMismatch.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    function test_submitPartialWithdrawal_reverts_recipientDescriptorMismatch() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        bytes memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.recipient = bob; // registered, but not the recipient committed by auxData

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalDescriptorMismatch.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }
}

import {CloseTestLib} from "./CloseTestLib.sol";
import {ChannelSettlementVerifier, CloseProofFields} from "../src/ChannelSettlementVerifier.sol";
