// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseSettlementBase} from "./CloseSettlementBase.sol";

/// @notice R3-5 regressions for the newest proof-bound POST-burn fund snapshot. The historical
/// filename is retained so existing CI selectors keep finding the suite; no Fenwick accounting is
/// used by settlement anymore.
contract AuthorizedBurnSnapshotTest is CloseSettlementBase {
    bytes32 internal constant PREV_CHAIN = keccak256("burn_snapshot_prev_chain");

    function _baseRecipient(address recipient) internal pure returns (bytes32) {
        return bytes32((uint256(2) << 248) | uint256(uint160(recipient)));
    }

    function _withdrawal(bytes32 txLeaf, uint32 baseNonce, uint32 tokenIndex, uint256 amount)
        internal
        view
        returns (ChannelSettlementManager.AuthorizedWithdrawal memory w)
    {
        w = ChannelSettlementManager.AuthorizedWithdrawal({
            recipient: alice,
            tokenIndex: tokenIndex,
            amount: amount,
            baseNonce: baseNonce,
            nullifier: keccak256(abi.encodePacked("snapshot_nullifier", txLeaf)),
            auxData: keccak256(
                abi.encodePacked(
                    bytes4(0x494d4432),
                    uint32(CHANNEL_ID),
                    baseNonce,
                    txLeaf,
                    _baseRecipient(alice),
                    tokenIndex,
                    amount
                )
            ),
            txLeaf: txLeaf
        });
    }

    /// The close-intent identity tracks the WHOLE state (ordering key, settled chain and fund
    /// vector), so two different states at one ordering key are distinguishable
    /// (`CloseForksAuthorizedBurn`) and the authorized burn state can be re-targeted exactly.
    function _intentAt(
        uint64 epoch,
        uint64 stateVersion,
        bytes32 settledTxChain,
        uint256 nativeFund,
        uint256 token7Fund
    ) internal pure returns (ChannelSettlementManager.CloseIntent memory intent) {
        intent = _intent(1, epoch, 22, 1);
        intent.finalStateVersion = stateVersion;
        intent.finalSettledTxChain = settledTxChain;
        intent.finalChannelStateDigest =
            keccak256(abi.encodePacked("snapshot_state", epoch, stateVersion, settledTxChain, nativeFund, token7Fund));
        intent.tokenCount = 2;
        intent.tokenRegistry[0] = 0;
        intent.tokenRegistry[1] = 7;
        intent.channelFundAmounts[0] = nativeFund;
        intent.channelFundAmounts[1] = token7Fund;
    }

    function _burnIntent(
        ChannelSettlementManager.AuthorizedWithdrawal memory w,
        uint64 epoch,
        uint64 stateVersion,
        bytes32 prevChain,
        uint256 nativePostFund,
        uint256 token7PostFund
    ) internal pure returns (ChannelSettlementManager.CloseIntent memory intent) {
        bytes32 chain = keccak256(abi.encodePacked(uint32(0x494d5443), prevChain, w.auxData));
        intent = _intentAt(epoch, stateVersion, chain, nativePostFund, token7PostFund);
    }

    function _finalizeBurn(
        ChannelSettlementManager.CloseIntent memory intent,
        bytes32 prevChain,
        ChannelSettlementManager.AuthorizedWithdrawal memory w
    ) internal {
        bytes memory proof = _closeProof(intent);
        manager.submitPartialWithdrawalIntent(intent, proof, prevChain, w);
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizePartialWithdrawal();
    }

    /// Open the close era (requestClose + grace) without installing an intent.
    function _freeze() internal {
        uint64 freezeNonce = manager.currentCloseFreezeNonce();
        uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
        vm.prank(alice);
        manager.requestClose(freezeNonce, cancellationFloor);
        vm.warp(block.timestamp + GRACE);
    }

    /// Install `intent` in the already-open era and finalize it.
    function _settlePending(ChannelSettlementManager.CloseIntent memory intent) internal {
        manager.submitCloseIntent(intent, _closeProof(intent));
        vm.warp(uint256(manager.getPendingClose().challengeDeadline) + 1);
        manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
    }

    function _settleClose(
        uint64 epoch,
        uint64 stateVersion,
        bytes32 settledTxChain,
        uint256 nativeFund,
        uint256 token7Fund
    ) internal {
        _freeze();
        _settlePending(_intentAt(epoch, stateVersion, settledTxChain, nativeFund, token7Fund));
    }

    /// A close that is not the whole authorized burn state (or strictly newer) must be refused at
    /// `submitCloseIntent` with `selector`, and the refusal must leave NOTHING behind: no intent
    /// installed, status unchanged, no settled vector, escrow untouched.
    function _expectRefused(ChannelSettlementManager.CloseIntent memory intent, bytes4 selector) internal {
        uint8 statusBefore = uint8(manager.channelStatus());
        bool closePendingBefore = manager.getPendingClose().active;
        bool burnPendingBefore = manager.partialWithdrawalPending();
        uint64 burnVersionBefore = manager.authorizedBurnStateVersion();
        uint256 balanceBefore = address(manager).balance;

        bytes memory proof = _closeProof(intent);
        vm.expectRevert(selector);
        manager.submitCloseIntent(intent, proof);

        assertEq(uint8(manager.channelStatus()), statusBefore, "status unchanged by the refusal");
        assertEq(manager.getPendingClose().active, closePendingBefore, "no close intent was installed");
        assertEq(manager.partialWithdrawalPending(), burnPendingBefore, "pending burn untouched");
        assertEq(manager.authorizedBurnStateVersion(), burnVersionBefore, "burn high-water untouched");
        assertEq(manager.finalizedChannelFundAmount(0), 0, "no native cap settled");
        assertEq(manager.finalizedChannelFundAmount(7), 0, "no token-7 cap settled");
        assertEq(manager.finalizedTokenFundsDigest(), bytes32(0), "no settled fund vector");
        assertEq(address(manager).balance, balanceBefore, "escrow untouched");
    }

    /// Stale V fund=10; then credit=10 and burn=10; newest post-burn fund is again 10. The old
    /// min-cap arithmetic on an ADMITTED stale close is gone: V is refused at admission, and the
    /// replenished value is not stranded because the burn state B itself settles at its own
    /// proof-bound post-burn fund.
    function test_staleCloseIsRefused_replenishedBurnStateSettlesAtItsOwnFund() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory burn =
            _withdrawal(keccak256("replenished_burn"), 1, 0, 10);
        ChannelSettlementManager.CloseIntent memory burnState =
            _burnIntent(burn, 9, 20, PREV_CHAIN, 10, 0);
        _finalizeBurn(burnState, PREV_CHAIN, burn);

        assertEq(manager.authorizedBurnAmount(0), 10, "gross amount remains telemetry");
        assertEq(manager.authorizedBurnPostFundAmount(0), 10, "proof-bound post-burn fund");

        _freeze();
        _expectRefused(
            _intentAt(9, 10, PREV_CHAIN, 10, 0), ChannelSettlementManager.CloseOlderThanAuthorizedBurn.selector
        );
        _settlePending(burnState);
        assertEq(manager.finalizedChannelFundAmount(0), 10, "replenished value must not be stranded");
    }

    /// A stale close declaring MORE than the later observed post-burn fund is never capped down to
    /// the snapshot any more; it is refused outright, and only the observed state (or newer) can
    /// settle. The settled cap is therefore the burn state's own vector, never a synthesized one.
    function test_staleCloseAboveTheObservedFundIsRefused_notCappedToTheSnapshot() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory burn =
            _withdrawal(keccak256("outgoing_before_burn"), 2, 0, 10);
        ChannelSettlementManager.CloseIntent memory burnState =
            _burnIntent(burn, 9, 20, PREV_CHAIN, 40, 0);
        _finalizeBurn(burnState, PREV_CHAIN, burn);

        _freeze();
        _expectRefused(
            _intentAt(9, 10, PREV_CHAIN, 100, 0), ChannelSettlementManager.CloseOlderThanAuthorizedBurn.selector
        );
        _settlePending(burnState);
        assertEq(manager.finalizedChannelFundAmount(0), 40, "cap equals the one authenticated state");
        assertEq(manager.finalizedChannelFundAmount(0), manager.authorizedBurnPostFundAmount(0), "no blend");
    }

    /// Every base token of the settled vector comes from ONE whole state. A stale multi-token close
    /// is refused as a unit; the burn state settles both denominations from its own proof.
    function test_staleMultiTokenCloseIsRefused_everyBaseTokenComesFromOneState() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory burn =
            _withdrawal(keccak256("multi_token_snapshot"), 3, 0, 10);
        ChannelSettlementManager.CloseIntent memory burnState =
            _burnIntent(burn, 9, 20, PREV_CHAIN, 90, 40);
        _finalizeBurn(burnState, PREV_CHAIN, burn);

        _freeze();
        _expectRefused(
            _intentAt(9, 10, PREV_CHAIN, 100, 100), ChannelSettlementManager.CloseOlderThanAuthorizedBurn.selector
        );
        _settlePending(burnState);
        assertEq(manager.finalizedChannelFundAmount(0), 90, "native from the burn state");
        assertEq(manager.finalizedChannelFundAmount(7), 40, "token-7 from the burn state");
    }

    /// The terminal funding identity (IMTF digest) must name exactly the vector this Manager will
    /// pull. There is no "adjusted cap vector" any more: the stale close never settles, so the
    /// digest is byte-for-byte the burn state's proof-bound vector, and the retired cooperative
    /// `authorizeCloseFunding` route cannot arm any aux — adjusted or stale.
    function test_terminalFundsDigestIsTheExactBurnStateVector_neverAnAdjustedOne() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory burn =
            _withdrawal(keccak256("close_funding_adjusted_cap"), 9, 0, 10);
        ChannelSettlementManager.CloseIntent memory burnState =
            _burnIntent(burn, 9, 20, PREV_CHAIN, 40, 0);
        _finalizeBurn(burnState, PREV_CHAIN, burn);

        _freeze();
        _expectRefused(
            _intentAt(9, 10, PREV_CHAIN, 100, 0), ChannelSettlementManager.CloseOlderThanAuthorizedBurn.selector
        );
        _settlePending(burnState);
        assertEq(manager.finalizedChannelFundAmount(0), 40, "settled cap is the burn state's own");

        uint32[10] memory tokenRegistry;
        tokenRegistry[0] = 0;
        tokenRegistry[1] = 7;
        uint256[10] memory staleAmounts;
        staleAmounts[0] = 100;
        uint256[10] memory burnStateAmounts;
        burnStateAmounts[0] = 40;

        bytes32 settledDigest = manager.finalizedTokenFundsDigest();
        assertEq(
            settledDigest,
            verifier.tokenFundsDigest(tokenRegistry, 2, burnStateAmounts),
            "terminal identity is the exact burn-state vector"
        );
        assertTrue(
            settledDigest != verifier.tokenFundsDigest(tokenRegistry, 2, staleAmounts),
            "the stale vector never becomes a terminal identity"
        );

        // The cooperative aux route is retired; neither the stale nor any adjusted aux can arm it.
        bytes32 anyAux = keccak256("any_aux");
        vm.expectRevert(ChannelSettlementManager.CooperativeCloseFundingDeprecated.selector);
        manager.authorizeCloseFunding(0, anyAux);
    }

    /// Finalization order is permissionless. An older burn finalized later must not replace the
    /// newer state's high-water (ordering key, identity, or snapshot), and a close below that
    /// high-water — including the older burn's OWN whole state — is refused.
    function test_outOfOrderOlderBurnCannotLowerHighWaterSnapshot() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory older =
            _withdrawal(keccak256("older_burn"), 4, 0, 5);
        ChannelSettlementManager.CloseIntent memory olderState =
            _burnIntent(older, 9, 10, PREV_CHAIN, 20, 20);

        ChannelSettlementManager.AuthorizedWithdrawal memory newer =
            _withdrawal(keccak256("newer_burn"), 5, 7, 7);
        ChannelSettlementManager.CloseIntent memory newerState =
            _burnIntent(newer, 9, 20, olderState.finalSettledTxChain, 80, 70);

        _finalizeBurn(newerState, olderState.finalSettledTxChain, newer);
        _finalizeBurn(olderState, PREV_CHAIN, older);
        assertEq(manager.authorizedBurnStateVersion(), 20, "high-water must not regress");
        assertEq(
            manager.authorizedBurnCloseIntentDigest(),
            manager.computeCloseIntentDigest(newerState),
            "high-water identity must not regress"
        );
        assertEq(manager.authorizedBurnPostFundAmount(0), 80);
        assertEq(manager.authorizedBurnPostFundAmount(7), 70);

        _freeze();
        _expectRefused(
            _intentAt(9, 5, PREV_CHAIN, 100, 100), ChannelSettlementManager.CloseOlderThanAuthorizedBurn.selector
        );
        // The older burn's own whole state is authenticated, but it is below the high-water.
        _expectRefused(olderState, ChannelSettlementManager.CloseOlderThanAuthorizedBurn.selector);
        _settlePending(newerState);
        assertEq(manager.finalizedChannelFundAmount(0), 80);
        assertEq(manager.finalizedChannelFundAmount(7), 70);
    }

    function test_closeAtOrAfterSnapshotNeedsNoCap() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory burn =
            _withdrawal(keccak256("equal_version"), 6, 0, 13);
        ChannelSettlementManager.CloseIntent memory burnState =
            _burnIntent(burn, 9, 20, PREV_CHAIN, 50, 0);
        _finalizeBurn(burnState, PREV_CHAIN, burn);

        _settleClose(9, 20, burnState.finalSettledTxChain, 50, 0);
        assertEq(manager.finalizedChannelFundAmount(0), 50, "equal state already excludes burn");
    }

    /// Equal `(epoch, stateVersion)` with a DIFFERENT whole-state identity is an equivocated fork
    /// of the authorized burn state, not the burn state. It is refused; the exact state is admitted.
    function test_equalPositionWithDifferentIdentityIsRefusedAsFork() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory burn =
            _withdrawal(keccak256("forked_identity"), 10, 0, 13);
        ChannelSettlementManager.CloseIntent memory burnState =
            _burnIntent(burn, 9, 20, PREV_CHAIN, 50, 0);
        _finalizeBurn(burnState, PREV_CHAIN, burn);

        _freeze();
        // Same ordering key, but a settled chain that does not carry the burn: a different state.
        _expectRefused(
            _intentAt(9, 20, PREV_CHAIN, 50, 0), ChannelSettlementManager.CloseForksAuthorizedBurn.selector
        );
        _settlePending(burnState);
        assertEq(manager.finalizedStateVersion(), 20, "the exact burn state is admitted");
    }

    /// A burn that is still inside its own challenge window is already proof-authenticated. A
    /// close below it is refused just like one below a finalized burn, so the burn cannot be
    /// stranded by a stale close that settles while its timer runs.
    function test_closeBelowAPendingBurnIsRefusedBeforeTheBurnFinalizes() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory burn =
            _withdrawal(keccak256("pending_burn"), 11, 0, 10);
        ChannelSettlementManager.CloseIntent memory burnState =
            _burnIntent(burn, 9, 20, PREV_CHAIN, 40, 0);
        manager.submitPartialWithdrawalIntent(burnState, _closeProof(burnState), PREV_CHAIN, burn);
        assertFalse(manager.authorizedBurnSnapshotActive(), "not yet finalized");

        _freeze();
        _expectRefused(
            _intentAt(9, 10, PREV_CHAIN, 100, 0), ChannelSettlementManager.CloseOlderThanAuthorizedBurn.selector
        );
        _expectRefused(
            _intentAt(9, 20, PREV_CHAIN, 40, 0), ChannelSettlementManager.CloseForksAuthorizedBurn.selector
        );
        _settlePending(burnState);
        assertEq(manager.finalizedChannelFundAmount(0), 40, "the pending burn's own state settles");
        // And the burn is still payable after that settlement (H-6 liveness half).
        manager.finalizePartialWithdrawal();
        assertTrue(manager.authorizedBurnSnapshotActive(), "burn finalized after its own state settled");
    }

    /// A burn descriptor can remain the last settled-chain push while refresh/intra-channel states
    /// advance stateVersion. The latest observed state is what the close must target: the burn's
    /// original version is below the high-water and refused, and the later state settles at its
    /// equal post-burn fund with nothing subtracted (the burn is already absent from it).
    function test_sameBurnLaterStateProof_closeTargetsTheLatestObservedState() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory burn =
            _withdrawal(keccak256("same_burn_later_state"), 8, 0, 10);
        ChannelSettlementManager.CloseIntent memory atBurn =
            _burnIntent(burn, 9, 10, PREV_CHAIN, 90, 0);
        // Construct independently: Solidity memory-struct assignment aliases the nested fixed
        // arrays and can make this test accidentally submit version 12 twice.
        ChannelSettlementManager.CloseIntent memory later =
            _burnIntent(burn, 9, 12, PREV_CHAIN, 90, 0);

        manager.submitPartialWithdrawalIntent(atBurn, _closeProof(atBurn), PREV_CHAIN, burn);
        manager.submitPartialWithdrawalIntent(later, _closeProof(later), PREV_CHAIN, burn);
        vm.warp(uint256(manager.pendingPartialWithdrawalDeadline()) + 1);
        manager.finalizePartialWithdrawal();
        assertEq(manager.authorizedBurnStateVersion(), 12, "latest observed state is retained");

        _freeze();
        _expectRefused(atBurn, ChannelSettlementManager.CloseOlderThanAuthorizedBurn.selector);
        _settlePending(later);
        assertEq(manager.finalizedChannelFundAmount(0), 90, "burn already absent is not deducted");
    }

    /// Known architectural limit, unchanged by fail-closed admission: this Manager has no
    /// proof-bound fund observation AFTER the last authorized burn. A strictly newer close carries
    /// its own vector from its own proof; a later outgoing that lowered the real fund from 90 to 40
    /// is invisible here. The assertion pins the residual so reports/tests do not overclaim that
    /// the admission gate (or the burn snapshot) closes the separate late-outgoing gap — that
    /// relies on the signed-head backing check in the materializer (always satisfied by this mock)
    /// and the close challenge/watchtower path.
    function test_knownLimitation_outgoingAfterLastBurnIsNotObservedByTheManager() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory burn =
            _withdrawal(keccak256("late_outgoing_limit"), 7, 0, 10);
        ChannelSettlementManager.CloseIntent memory burnState =
            _burnIntent(burn, 9, 20, PREV_CHAIN, 90, 0);
        _finalizeBurn(burnState, PREV_CHAIN, burn);

        _freeze();
        // Below the burn: refused, not capped to 90.
        _expectRefused(
            _intentAt(9, 10, PREV_CHAIN, 100, 0), ChannelSettlementManager.CloseOlderThanAuthorizedBurn.selector
        );
        // Strictly newer: admitted on its own proof, whatever it declares.
        _settlePending(_intentAt(9, 21, burnState.finalSettledTxChain, 100, 0));
        assertEq(
            manager.finalizedChannelFundAmount(0),
            100,
            "L1 cannot see a hypothetical outgoing after the last burn snapshot"
        );
    }
}
