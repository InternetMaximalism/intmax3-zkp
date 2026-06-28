// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title Drive the complex-calldata steps of the Sepolia close lifecycle (one fn per broadcast tx).
/// @notice Reads the sepolia_* close fixtures + deployed addresses from env (ROLLUP / MANAGER / SV).
///         Simple steps (postBlock blob txs, deposit, pullChannelFunds, requestClose, finalizeClose,
///         claimWithdrawalCredit) are done with `cast`; these four carry large struct calldata.
///         Invoke a single step with `--sig "<fn>()"`.
contract RunClose is Script {
    function _rollup() internal view returns (IntmaxRollup) { return IntmaxRollup(payable(vm.envAddress("ROLLUP"))); }
    function _manager() internal view returns (ChannelSettlementManager) { return ChannelSettlementManager(payable(vm.envAddress("MANAGER"))); }
    function _sv() internal view returns (ChannelSettlementVerifier) { return ChannelSettlementVerifier(vm.envAddress("SV")); }
    function _lc() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_lifecycle.json")); }
    function _vmle() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_lifecycle_validity_mle.json")); }
    function _wmle() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_withdrawal_mle.json")); }
    function _payout() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_withdrawal_payout.json")); }
    function _closeMle() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_close_intent_mle.json")); }
    function _closeIntent() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_close_intent.json")); }

    /// finalize the 3-block chain (submission id via SUB_ID env, default 2 = the 3rd posting round).
    function finalizeStep() external {
        string memory lc = _lc();
        IntmaxRollup.ValidityPublicInputs memory vpis;
        vpis.initialBlockNumber = uint64(vm.parseJsonUint(lc, ".vpis.initial_block_number"));
        vpis.initialBlockChain = vm.parseJsonBytes32(lc, ".vpis.initial_block_chain");
        vpis.initialExtCommitment = vm.parseJsonBytes32(lc, ".vpis.initial_ext_commitment");
        vpis.finalBlockNumber = uint64(vm.parseJsonUint(lc, ".vpis.final_block_number"));
        vpis.finalBlockChain = vm.parseJsonBytes32(lc, ".vpis.final_block_chain");
        vpis.finalExtCommitment = vm.parseJsonBytes32(lc, ".vpis.final_ext_commitment");
        vpis.prover = vm.parseJsonAddress(lc, ".vpis.prover");
        bytes32 finalRoot = vm.parseJsonBytes32(lc, ".final_state_root");
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_vmle());
        uint256 subId = vm.envOr("SUB_ID", uint256(2));

        vm.startBroadcast();
        bool ok = _rollup().finalize(subId, finalRoot, vpis, proof);
        vm.stopBroadcast();
        require(ok, "finalize returned false");
        console2.log("finalize OK; latestFinalizedStateRoot:");
        console2.logBytes32(_rollup().latestFinalizedStateRoot());
    }

    /// withdrawNative: pay the channel's native ETH to the manager (recipient baked in the proof).
    function withdrawNativeStep() external {
        string memory j = _payout();
        IntmaxRollup.Withdrawal[] memory ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = IntmaxRollup.Withdrawal({
            recipient: vm.parseJsonAddress(j, ".withdrawals[0].recipient"),
            tokenIndex: uint32(vm.parseJsonUint(j, ".withdrawals[0].token_index")),
            amount: vm.parseUint(vm.parseJsonString(j, ".withdrawals[0].amount")),
            nullifier: vm.parseJsonBytes32(j, ".withdrawals[0].nullifier"),
            auxData: vm.parseJsonBytes32(j, ".withdrawals[0].aux_data")
        });
        address prover = vm.parseJsonAddress(j, ".withdrawal_prover");
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_wmle());

        vm.startBroadcast();
        _rollup().withdrawNative(ws, prover, proof);
        vm.stopBroadcast();
        console2.log("withdrawNative OK; pendingWithdrawals[manager]:", _rollup().pendingWithdrawals(address(_manager())));
    }

    /// submitCloseIntent with the REAL wrapped-close MLE/WHIR proof (Phase A). The CloseIntent fields
    /// are read from the proved close descriptor (`sepolia_close_intent.json`), and the proof is the
    /// wrapped close `MleVerifier.MleProof` from `sepolia_close_intent_mle.json` (publicInputs = the
    /// 87 raw close limbs the manager's `_runCloseVerify` rebinds). The channel MUST be registered
    /// with the descriptor's `member_pk_gs` so `registeredMemberSetCommitment()` matches the proof.
    function closeIntentStep() external {
        ChannelSettlementManager.CloseIntent memory intent = _closeIntentFromDescriptor();
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_closeMle());
        vm.startBroadcast();
        _manager().submitCloseIntent(intent, proof);
        vm.stopBroadcast();
        console2.log("submitCloseIntent OK; challengeDeadline:", _manager().getPendingClose().challengeDeadline);
    }

    /// @dev Build the `CloseIntent` from the proved close descriptor JSON (every field is the proved
    /// close public input — see generate_close_fixture.rs `CloseIntentDescriptor`).
    function _closeIntentFromDescriptor()
        internal view returns (ChannelSettlementManager.CloseIntent memory intent)
    {
        string memory j = _closeIntent();
        intent = ChannelSettlementManager.CloseIntent({
            closeNonce: uint64(vm.parseJsonUint(j, ".close_nonce")),
            finalEpoch: uint64(vm.parseJsonUint(j, ".final_epoch")),
            finalSmallBlockNumber: uint64(vm.parseJsonUint(j, ".final_small_block_number")),
            closeFreezeNonce: uint64(vm.parseJsonUint(j, ".close_freeze_nonce")),
            finalChannelStateDigest: vm.parseJsonBytes32(j, ".final_channel_state_digest"),
            finalBalanceStateH1: vm.parseJsonBytes32(j, ".final_balance_state_h1"),
            channelFundAmount: vm.parseJsonUint(j, ".channel_fund_amount"),
            channelFundIntmaxStateRoot: vm.parseJsonBytes32(j, ".channel_fund_intmax_state_root"),
            burnTxHash: vm.parseJsonBytes32(j, ".burn_tx_hash"),
            closeWithdrawalDigest: vm.parseJsonBytes32(j, ".close_withdrawal_digest"),
            snapshotMediumBlockNumber: uint64(vm.parseJsonUint(j, ".snapshot_medium_block_number")),
            finalStateVersion: uint64(vm.parseJsonUint(j, ".final_state_version")),
            finalSettledTxChain: vm.parseJsonBytes32(j, ".final_settled_tx_chain"),
            // Stage 3: regenerate the close fixture so `.final_settled_tx_accumulator_root` exists.
            finalSettledTxAccumulatorRoot: vm.parseJsonBytes32(
                j, ".final_settled_tx_accumulator_root"
            )
        });
    }

    /// submitWithdrawalClaim demo step.
    ///
    /// Phase B-D: `verifyWithdrawalClaim` is now a REAL MLE/WHIR verification — the former
    /// stub-proof construction (`withdrawalClaimPIHash` + abi.encode(bytes32)) no longer produces an
    /// acceptable proof. Driving this step on a live deployment now requires (a) the
    /// withdrawal-claim VK initialized via `initializeWithdrawalClaimVk` and (b) a real
    /// `MleVerifier.MleProof` from `generate_withdrawal_claim_fixture`. That fixture-driven flow is
    /// exercised in `ChannelSettlementManager.t.sol`; this demo script intentionally no longer
    /// fabricates a stub proof (it would be rejected). Kept as a documented no-op so the deploy
    /// script still builds.
    function _wclaim() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_withdrawal_claim.json"));
    }

    function _wclaimMle() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_withdrawal_claim_mle.json"));
    }

    /// A-3 P4: submit a member's withdrawal claim with the REAL withdrawal-claim MLE/WHIR proof
    /// (produced by the CLI `claim` command via `WithdrawalClaimProver`). Reads the descriptor + the
    /// wrapped MLE proof staged by the CLI and calls `submitWithdrawalClaim`.
    function submitWithdrawalClaimStep() external {
        string memory j = _wclaim();
        ChannelSettlementManager.WithdrawalClaim memory claim = ChannelSettlementManager.WithdrawalClaim({
            closeIntentDigest: vm.parseJsonBytes32(j, ".close_intent_digest"),
            memberPkG: vm.parseJsonBytes32(j, ".member_pk_g"),
            recipient: vm.parseJsonAddress(j, ".recipient"),
            userAmountDigest: vm.parseJsonBytes32(j, ".user_amount_digest"),
            amount: uint64(vm.parseJsonUint(j, ".amount")),
            withdrawalNullifier: vm.parseJsonBytes32(j, ".withdrawal_nullifier")
        });
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_wclaimMle());
        vm.startBroadcast();
        _manager().submitWithdrawalClaim(claim, proof);
        vm.stopBroadcast();
        console2.log("submitWithdrawalClaim OK; recipient credit pending claimWithdrawalCredit");
    }

    function _cancelClose() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_cancel_close.json"));
    }

    function _cancelCloseMle() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_cancel_close_mle.json"));
    }

    /// A30 (H-3 C1): cancel a PENDING close with the REAL cancel-close MLE/WHIR proof (produced by
    /// the CLI `cancel-close` command via `CancelCloseProver`). The manager injects the registered
    /// member-set commitment and matches `request.closeIntentDigest` to the pending close, so the
    /// only caller fields are the close-intent digest + the revived (higher) state version/digest.
    function cancelCloseStep() external {
        string memory j = _cancelClose();
        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager
            .CancelCloseRequest({
            closeIntentDigest: vm.parseJsonBytes32(j, ".close_intent_digest"),
            revivedStateVersion: uint64(vm.parseJsonUint(j, ".revived_state_version")),
            revivedChannelStateDigest: vm.parseJsonBytes32(j, ".revived_channel_state_digest")
        });
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_cancelCloseMle());
        vm.startBroadcast();
        _manager().cancelClose(request, proof);
        vm.stopBroadcast();
        console2.log("cancelClose OK; channel status restored to Active");
    }

    function _postCloseClaim() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_post_close_claim.json"));
    }

    function _postCloseClaimMle() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_post_close_claim_mle.json"));
    }

    /// A34 (H-2 §3.5.5): claim a late inter-channel delta on a CLOSED channel with the REAL
    /// post-close-claim MLE/WHIR proof (produced by the CLI `post-close-claim` command via
    /// `PostCloseClaimProver`). The manager RECOMPUTES `sharedNativeNullifier` (HAZARD #8), so it is
    /// NOT a caller field; the claim carries only the close-intent digest, the incoming tx hash, the
    /// receiver pk_g, the recipient, and the (in-circuit decrypted) amount.
    function submitPostCloseClaimStep() external {
        string memory j = _postCloseClaim();
        ChannelSettlementManager.PostCloseClaim memory claim = ChannelSettlementManager.PostCloseClaim({
            closeIntentDigest: vm.parseJsonBytes32(j, ".close_intent_digest"),
            incomingTxHash: vm.parseJsonBytes32(j, ".incoming_tx_hash"),
            receiverPkG: vm.parseJsonBytes32(j, ".receiver_pk_g"),
            recipient: vm.parseJsonAddress(j, ".recipient"),
            amount: uint64(vm.parseJsonUint(j, ".amount"))
        });
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_postCloseClaimMle());
        vm.startBroadcast();
        _manager().submitPostCloseClaim(claim, proof);
        vm.stopBroadcast();
        console2.log("submitPostCloseClaim OK; recipient credit pending claimWithdrawalCredit");
    }
}
