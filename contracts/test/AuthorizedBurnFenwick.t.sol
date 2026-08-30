// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
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
        MleVerifier.MleProof memory proof = _closeProof(intent);
        manager.submitPartialWithdrawalIntent(intent, proof, prevChain, w);
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizePartialWithdrawal();
    }

    function _settleClose(
        uint64 epoch,
        uint64 stateVersion,
        bytes32 settledTxChain,
        uint256 nativeFund,
        uint256 token7Fund
    ) internal {
        vm.prank(alice);
        manager.requestClose();
        vm.warp(block.timestamp + GRACE);
        ChannelSettlementManager.CloseIntent memory intent =
            _intentAt(epoch, stateVersion, settledTxChain, nativeFund, token7Fund);
        manager.submitCloseIntent(intent, _closeProof(intent));
        vm.warp(uint256(manager.getPendingClose().challengeDeadline) + 1);
        manager.finalizeClose();
    }

    /// Stale V fund=10; then credit=10 and burn=10; newest post-burn fund is again 10. Gross-burn
    /// subtraction trapped the original 10. The snapshot cap preserves the fully-backed amount.
    function test_replenishmentBetweenStaleCloseAndBurnIsPreserved() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory burn =
            _withdrawal(keccak256("replenished_burn"), 1, 0, 10);
        ChannelSettlementManager.CloseIntent memory burnState =
            _burnIntent(burn, 9, 20, PREV_CHAIN, 10, 0);
        _finalizeBurn(burnState, PREV_CHAIN, burn);

        assertEq(manager.authorizedBurnAmount(0), 10, "gross amount remains telemetry");
        assertEq(manager.authorizedBurnPostFundAmount(0), 10, "proof-bound post-burn fund");
        _settleClose(9, 10, PREV_CHAIN, 10, 0);
        assertEq(manager.finalizedChannelFundAmount(0), 10, "replenished value must not be stranded");
    }

    /// Any burn and inter-channel outgoing already reflected in the observed later state lower its
    /// post-state fund. The stale close is capped at that exact remaining fund, not a gross delta.
    function test_outgoingBeforeNewestBurnLowersSnapshotCap() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory burn =
            _withdrawal(keccak256("outgoing_before_burn"), 2, 0, 10);
        ChannelSettlementManager.CloseIntent memory burnState =
            _burnIntent(burn, 9, 20, PREV_CHAIN, 40, 0);
        _finalizeBurn(burnState, PREV_CHAIN, burn);

        _settleClose(9, 10, PREV_CHAIN, 100, 0);
        assertEq(manager.finalizedChannelFundAmount(0), 40, "cap equals later observed fund");
    }

    function test_snapshotCapsEveryBaseTokenNotOnlyBurnDenomination() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory burn =
            _withdrawal(keccak256("multi_token_snapshot"), 3, 0, 10);
        ChannelSettlementManager.CloseIntent memory burnState =
            _burnIntent(burn, 9, 20, PREV_CHAIN, 90, 40);
        _finalizeBurn(burnState, PREV_CHAIN, burn);

        _settleClose(9, 10, PREV_CHAIN, 100, 100);
        assertEq(manager.finalizedChannelFundAmount(0), 90, "native snapshot cap");
        assertEq(manager.finalizedChannelFundAmount(7), 40, "token-7 snapshot cap");
    }

    /// Finalization order is permissionless. An older burn finalized later must not replace the
    /// newer state snapshot with its older vector.
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
        assertEq(manager.authorizedBurnPostFundAmount(0), 80);
        assertEq(manager.authorizedBurnPostFundAmount(7), 70);

        _settleClose(9, 5, PREV_CHAIN, 100, 100);
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

    /// A burn descriptor can remain the last settled-chain push while refresh/intra-channel states
    /// advance stateVersion. Treating that later coordinate as a gross-burn coordinate used to
    /// deduct the burn twice from a close at its real burn version. Snapshot capping compares the
    /// proof-bound funds instead, so equal post-burn funds remain equal and nothing is subtracted.
    function test_sameBurnLaterStateProofDoesNotDoubleDeductAtBurnState() public {
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

        _settleClose(9, 10, atBurn.finalSettledTxChain, 90, 0);
        assertEq(manager.finalizedChannelFundAmount(0), 90, "burn already absent is not deducted twice");
    }

    /// Known architectural limit: the Manager has no proof-bound fund observation after the last
    /// authorized burn. A later outgoing can lower the real channel fund from 90 to 40, but this
    /// contract still sees 90. The assertion intentionally pins the residual so reports/tests do
    /// not overclaim that the burn snapshot closes the separate late-outgoing gap.
    function test_knownLimitation_outgoingAfterLastBurnIsNotObserved() public {
        ChannelSettlementManager.AuthorizedWithdrawal memory burn =
            _withdrawal(keccak256("late_outgoing_limit"), 7, 0, 10);
        ChannelSettlementManager.CloseIntent memory burnState =
            _burnIntent(burn, 9, 20, PREV_CHAIN, 90, 0);
        _finalizeBurn(burnState, PREV_CHAIN, burn);

        _settleClose(9, 10, PREV_CHAIN, 100, 0);
        assertEq(
            manager.finalizedChannelFundAmount(0),
            90,
            "L1 cannot see a hypothetical outgoing after the last burn snapshot"
        );
    }
}
