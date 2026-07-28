// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {IChannelRegistry} from "../src/ChannelSettlementManager.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {CloseSettlementBase, MockRollupRegistry} from "./CloseSettlementBase.sol";

contract PartialWithdrawalTest is CloseSettlementBase {
    bytes32 constant AUX_DATA = keccak256("burn_tx_leaf");
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

    function _partialIntent() internal pure returns (ChannelSettlementManager.CloseIntent memory) {
        return _partialIntentAtVersion(12, 1);
    }

    function _partialIntentAtVersion(uint64 stateVersion, uint64 epoch)
        internal pure returns (ChannelSettlementManager.CloseIntent memory)
    {
        return ChannelSettlementManager.CloseIntent({
            closeNonce: 1,
            finalEpoch: epoch,
            finalSmallBlockNumber: 10,
            closeFreezeNonce: 0,
            finalChannelStateDigest: keccak256("partial_state"),
            finalBalanceStateH1: keccak256("partial_h1"),
            channelFundAmounts: _singleAmounts(CHANNEL_FUND),
            tokenRegistry: _singleRegistry(),
            tokenCount: 1,
            channelFundIntmaxStateRoot: keccak256("intmax_root"),
            burnTxHash: keccak256("burn_tx"),
            closeWithdrawalDigest: keccak256("close_wd"),
            snapshotMediumBlockNumber: 77,
            finalStateVersion: stateVersion,
            finalSettledTxChain: _settledTxChainPush(PREV_CHAIN, AUX_DATA),
            finalSettledTxAccumulatorRoot: keccak256("acc_root")
        });
    }

    function _authorizedWithdrawal() internal view returns (ChannelSettlementManager.AuthorizedWithdrawal memory) {
        return ChannelSettlementManager.AuthorizedWithdrawal({
            recipient: _recipient(),
            tokenIndex: TOKEN_INDEX,
            amount: AMOUNT,
            nullifier: NULLIFIER,
            auxData: AUX_DATA
        });
    }

    function _expectedAuthDigest(ChannelSettlementManager.AuthorizedWithdrawal memory w)
        internal pure returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(bytes4(0x494d5057), w.nullifier, w.recipient, w.tokenIndex, w.amount, w.auxData)
        );
    }

    // ── Happy path ──

    function test_submitPartialWithdrawalIntent_happy() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();

        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);

        assertTrue(manager.partialWithdrawalPending());
        assertEq(manager.pendingPartialWithdrawalAuthDigest(), _expectedAuthDigest(w));
        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.Active));
    }

    function test_submitAndFinalize_happy() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();

        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizePartialWithdrawal();

        assertFalse(manager.partialWithdrawalPending());
        bytes32 chainKey = keccak256(abi.encodePacked(CHANNEL_ID, intent.finalSettledTxChain));
        assertTrue(manager.usedPartialWithdrawalChains(chainKey));

        bytes32 authDigest = _expectedAuthDigest(w);
        assertTrue(registry.partialWithdrawalAuthorized(authDigest));

        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.Active));
    }

    // ── Revert: auxData zero ──

    function test_submitPartialWithdrawal_reverts_auxDataZero() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.auxData = bytes32(0);

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalAuxDataZero.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    // ── Revert: settled_tx_chain mismatch ──

    function test_submitPartialWithdrawal_reverts_chainMismatch() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();

        bytes32 wrongPrev = keccak256("wrong_prev");

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalChainMismatch.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, wrongPrev, w);
    }

    // ── Revert: channel not Active ──

    function test_submitPartialWithdrawal_reverts_channelNotActive() public {
        vm.prank(alice);
        manager.requestClose();
        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending));

        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();

        vm.expectRevert(ChannelSettlementManager.ChannelClosed.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    // ── Revert: finalize before challenge period ──

    function test_finalizePartialWithdrawal_reverts_challengeWindowOpen() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());

        vm.expectRevert(ChannelSettlementManager.ChallengeWindowOpen.selector);
        manager.finalizePartialWithdrawal();
    }

    // ── Revert: finalize at exact deadline (strict >) ──

    function test_finalizePartialWithdrawal_reverts_atExactDeadline() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
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

    // ── Double-use blocked: same chain key can't authorize twice ──

    function test_submitPartialWithdrawal_reverts_chainUsed() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);

        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizePartialWithdrawal();

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalChainUsed.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());
    }

    // ── Challenge replacement: newer state replaces pending ──

    function test_challengeReplacement_newerStateWins() public {
        ChannelSettlementManager.CloseIntent memory intent1 = _partialIntentAtVersion(10, 1);
        MleVerifier.MleProof memory proof1 = _closeProof(intent1);
        ChannelSettlementManager.AuthorizedWithdrawal memory w1 = _authorizedWithdrawal();

        // Adjust w1.auxData and PREV_CHAIN to match intent1's finalSettledTxChain
        // intent1's chain is _settledTxChainPush(PREV_CHAIN, AUX_DATA) — same as default
        manager.submitPartialWithdrawalIntent(intent1, proof1, PREV_CHAIN, w1);

        bytes32 authDigest1 = manager.pendingPartialWithdrawalAuthDigest();

        // Submit newer intent (higher stateVersion)
        ChannelSettlementManager.CloseIntent memory intent2 = _partialIntentAtVersion(15, 1);
        MleVerifier.MleProof memory proof2 = _closeProof(intent2);
        manager.submitPartialWithdrawalIntent(intent2, proof2, PREV_CHAIN, w1);

        // The pending digest should have changed (same withdrawal but new close intent → same authDigest)
        assertEq(manager.pendingPartialWithdrawalStateVersion(), 15);
        assertTrue(manager.partialWithdrawalPending());
    }

    // ── Challenge replacement: same or lower version reverts ──

    function test_challengeReplacement_sameVersionReverts() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntentAtVersion(10, 1);
        MleVerifier.MleProof memory proof = _closeProof(intent);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalNotNewer.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());
    }

    function test_challengeReplacement_lowerVersionReverts() public {
        ChannelSettlementManager.CloseIntent memory intent1 = _partialIntentAtVersion(15, 1);
        MleVerifier.MleProof memory proof1 = _closeProof(intent1);
        manager.submitPartialWithdrawalIntent(intent1, proof1, PREV_CHAIN, _authorizedWithdrawal());

        ChannelSettlementManager.CloseIntent memory intent2 = _partialIntentAtVersion(10, 1);
        MleVerifier.MleProof memory proof2 = _closeProof(intent2);

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalNotNewer.selector);
        manager.submitPartialWithdrawalIntent(intent2, proof2, PREV_CHAIN, _authorizedWithdrawal());
    }

    // ── Challenge replacement: higher epoch wins even if lower stateVersion ──

    function test_challengeReplacement_higherEpochWins() public {
        ChannelSettlementManager.CloseIntent memory intent1 = _partialIntentAtVersion(100, 1);
        MleVerifier.MleProof memory proof1 = _closeProof(intent1);
        manager.submitPartialWithdrawalIntent(intent1, proof1, PREV_CHAIN, _authorizedWithdrawal());

        ChannelSettlementManager.CloseIntent memory intent2 = _partialIntentAtVersion(5, 2);
        MleVerifier.MleProof memory proof2 = _closeProof(intent2);
        manager.submitPartialWithdrawalIntent(intent2, proof2, PREV_CHAIN, _authorizedWithdrawal());

        assertEq(manager.pendingPartialWithdrawalEpoch(), 2);
        assertEq(manager.pendingPartialWithdrawalStateVersion(), 5);
    }

    // ── Cancel partial withdrawal ──

    function test_cancelPartialWithdrawal_happy() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());

        assertTrue(manager.partialWithdrawalPending());

        bytes32 closeIntentDigest = manager.pendingPartialWithdrawalCloseIntentDigest();
        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager
            .CancelCloseRequest({
                closeIntentDigest: closeIntentDigest,
                revivedStateVersion: 99,
                revivedChannelStateDigest: keccak256("revived_state")
            });

        uint256[] memory limbs = verifier.expectedCancelCloseLimbs(
            CHANNEL_ID,
            closeIntentDigest,
            manager.registeredMemberSetCommitment(),
            request.revivedStateVersion,
            request.revivedChannelStateDigest
        );
        MleVerifier.MleProof memory cancelProof = CloseTestLib.proofWithLimbs(limbs);

        manager.cancelPartialWithdrawal(request, cancelProof);

        assertFalse(manager.partialWithdrawalPending());
        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.Active));

        // Chain key NOT consumed — can be resubmitted
        bytes32 chainKey = keccak256(abi.encodePacked(CHANNEL_ID, intent.finalSettledTxChain));
        assertFalse(manager.usedPartialWithdrawalChains(chainKey));
    }

    // ── Cancel reverts: nothing pending ──

    function test_cancelPartialWithdrawal_reverts_notPending() public {
        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager
            .CancelCloseRequest({
                closeIntentDigest: keccak256("x"),
                revivedStateVersion: 99,
                revivedChannelStateDigest: keccak256("revived")
            });
        MleVerifier.MleProof memory dummy;

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalNotPending.selector);
        manager.cancelPartialWithdrawal(request, dummy);
    }

    // ── Cancel reverts: wrong closeIntentDigest ──

    function test_cancelPartialWithdrawal_reverts_digestMismatch() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());

        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager
            .CancelCloseRequest({
                closeIntentDigest: keccak256("wrong_digest"),
                revivedStateVersion: 99,
                revivedChannelStateDigest: keccak256("revived")
            });
        MleVerifier.MleProof memory dummy;

        vm.expectRevert(ChannelSettlementManager.CloseIntentDigestMismatch.selector);
        manager.cancelPartialWithdrawal(request, dummy);
    }

    // ── 12B fix: finalize succeeds even after requestClose ──

    function test_finalizePartialWithdrawal_succeeds_afterRequestClose() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, _authorizedWithdrawal());

        // requestClose during challenge period → status becomes ClosePending
        vm.prank(alice);
        manager.requestClose();
        assertEq(uint8(manager.channelStatus()), uint8(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending));

        // Partial withdrawal can still finalize (12B fix: no channelStatus check)
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizePartialWithdrawal();

        bytes32 authDigest = _expectedAuthDigest(_authorizedWithdrawal());
        assertTrue(registry.partialWithdrawalAuthorized(authDigest));
    }

    // ── Cross-field tamper: different amount → different authDigest ──
    //
    // SECURITY SCOPE (corrected 2026-07-28, doc/tasks/pw-auth-threat-model.md §7): these two tests
    // establish ONLY that keccak over the IMPW preimage is injective in `amount` / `recipient` —
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
    //  Defence in depth (2026-07-28) — doc/tasks/pw-auth-threat-model.md §4
    //
    //  These BOUND the claim; they do NOT derive it. Passing them does not make an authorization
    //  legitimate — it only means it is not absurd.
    // ═══════════════════════════════════════════════════════════════════════════════════════

    // ── (a) Amount cap: over-claiming the proof-bound per-token fund vector is rejected ──
    //
    // Proves: the caller-chosen `amount` can no longer exceed what the channel's own N-of-N members
    // cosigned into that token slot. `channelFundAmounts` is trustworthy because the close proof's
    // `tokenFundsDigest` (PI limbs 95..102) is recomputed and strict-bound over it.

    function test_submitPartialWithdrawal_reverts_amountExceedsChannelFund() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.amount = CHANNEL_FUND + 1;

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalAmountExceedsFund.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    /// The pre-fix drain shape, scaled down: an amount wildly beyond the channel's entire declared
    /// balance (this is what used to reach `claimAuthorizedWithdrawal` and hit the GLOBAL escrow).
    function test_submitPartialWithdrawal_reverts_absurdOverClaim() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.amount = type(uint256).max;

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalAmountExceedsFund.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    /// Boundary: claiming EXACTLY the cap is allowed (the check is `>`, not `>=`) — the cap must not
    /// be off-by-one against an honest full-balance burn.
    function test_submitPartialWithdrawal_allowsExactlyChannelFund() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.amount = CHANNEL_FUND;

        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
        assertTrue(manager.partialWithdrawalPending());
    }

    /// Fail-closed: a base token the channel never cosigned into its registry has no cap to check
    /// against, so it is rejected outright rather than silently defaulting to slot 0.
    function test_submitPartialWithdrawal_reverts_tokenNotInRegistry() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
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
        MleVerifier.MleProof memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.tokenIndex = 42;
        w.amount = 1_000_000;

        vm.expectRevert(ChannelSettlementManager.TokenRegistryMismatch.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    // ── (b) Recipient must be a registered participant of THIS channel ──
    //
    // Proves: payout can no longer be directed to an arbitrary external address. Does NOT prove
    // entitlement between participants — any member may still name any member's address.

    function test_submitPartialWithdrawal_reverts_recipientNotParticipant() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.recipient = OUTSIDER;

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalRecipientNotParticipant.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    /// `mallory` is a funded EOA in the harness but NOT a member binding — being an active address
    /// is not membership.
    function test_submitPartialWithdrawal_reverts_recipientNonMemberEoa() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.recipient = mallory;

        vm.expectRevert(ChannelSettlementManager.PartialWithdrawalRecipientNotParticipant.selector);
        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
    }

    /// Every registered member recipient is accepted (bob and carol, not just the default alice) —
    /// confirms the gate reads the constructor bindings and is not accidentally pinned to one slot.
    function test_submitPartialWithdrawal_allowsOtherRegisteredMembers() public {
        ChannelSettlementManager.CloseIntent memory intent = _partialIntent();
        MleVerifier.MleProof memory proof = _closeProof(intent);
        ChannelSettlementManager.AuthorizedWithdrawal memory w = _authorizedWithdrawal();
        w.recipient = bob;

        manager.submitPartialWithdrawalIntent(intent, proof, PREV_CHAIN, w);
        assertTrue(manager.partialWithdrawalPending());
        assertTrue(manager.isMemberRecipient(carol));
    }
}

import {CloseTestLib} from "./CloseTestLib.sol";
import {ChannelSettlementVerifier, CloseProofFields} from "../src/ChannelSettlementVerifier.sol";
