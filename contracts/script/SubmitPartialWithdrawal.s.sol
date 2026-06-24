// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {CloseProofFields} from "../src/ChannelSettlementManager.sol";

/// @title Submit a partial-withdrawal intent (anvil E2E).
/// @notice Reads intent + withdrawal fields from `test/data/pw_submit.json` and drives the
///         `manager.submitPartialWithdrawalIntent` call with a mock-verified MLE proof.
contract SubmitPartialWithdrawal is Script {
    function _read(string memory f) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/", f));
    }

    function run() external {
        string memory j = _read("pw_submit.json");
        address managerAddr = vm.parseJsonAddress(j, ".manager");
        address verifierAddr = vm.parseJsonAddress(j, ".verifier");
        ChannelSettlementManager manager = ChannelSettlementManager(payable(managerAddr));
        ChannelSettlementVerifier verifier = ChannelSettlementVerifier(verifierAddr);

        // CloseIntent from JSON.
        ChannelSettlementManager.CloseIntent memory intent;
        intent.closeNonce = uint64(vm.parseJsonUint(j, ".close_nonce"));
        intent.finalEpoch = uint64(vm.parseJsonUint(j, ".final_epoch"));
        intent.finalSmallBlockNumber = uint64(vm.parseJsonUint(j, ".final_small_block_number"));
        intent.closeFreezeNonce = uint64(vm.parseJsonUint(j, ".close_freeze_nonce"));
        intent.finalChannelStateDigest = vm.parseJsonBytes32(j, ".final_channel_state_digest");
        intent.finalBalanceStateH1 = vm.parseJsonBytes32(j, ".final_balance_state_h1");
        intent.channelFundAmount = vm.parseJsonUint(j, ".channel_fund_amount");
        intent.channelFundIntmaxStateRoot = vm.parseJsonBytes32(j, ".channel_fund_intmax_state_root");
        intent.burnTxHash = vm.parseJsonBytes32(j, ".burn_tx_hash");
        intent.closeWithdrawalDigest = vm.parseJsonBytes32(j, ".close_withdrawal_digest");
        intent.snapshotMediumBlockNumber = uint64(vm.parseJsonUint(j, ".snapshot_medium_block_number"));
        intent.finalStateVersion = uint64(vm.parseJsonUint(j, ".final_state_version"));
        intent.finalSettledTxChain = vm.parseJsonBytes32(j, ".final_settled_tx_chain");
        intent.finalSettledTxAccumulatorRoot = vm.parseJsonBytes32(j, ".final_settled_tx_acc_root");

        // AuthorizedWithdrawal from JSON.
        ChannelSettlementManager.AuthorizedWithdrawal memory w;
        w.recipient = vm.parseJsonAddress(j, ".withdrawal_recipient");
        w.tokenIndex = uint32(vm.parseJsonUint(j, ".withdrawal_token_index"));
        w.amount = vm.parseJsonUint(j, ".withdrawal_amount");
        w.nullifier = vm.parseJsonBytes32(j, ".withdrawal_nullifier");
        w.auxData = vm.parseJsonBytes32(j, ".withdrawal_aux_data");

        bytes32 prevSettledTxChain = vm.parseJsonBytes32(j, ".prev_settled_tx_chain");

        // Build mock close proof: expectedCloseLimbs → proofWithLimbs.
        CloseProofFields memory fields = CloseProofFields({
            channelId: manager.channelId(),
            closeNonce: intent.closeNonce,
            finalEpoch: intent.finalEpoch,
            finalSmallBlockNumber: intent.finalSmallBlockNumber,
            closeFreezeNonce: intent.closeFreezeNonce,
            finalChannelStateDigest: intent.finalChannelStateDigest,
            finalBalanceStateH1: intent.finalBalanceStateH1,
            channelFundAmount: intent.channelFundAmount,
            channelFundIntmaxStateRoot: intent.channelFundIntmaxStateRoot,
            burnTxHash: intent.burnTxHash,
            closeWithdrawalDigest: intent.closeWithdrawalDigest,
            snapshotMediumBlockNumber: intent.snapshotMediumBlockNumber,
            finalStateVersion: intent.finalStateVersion,
            finalSettledTxChain: intent.finalSettledTxChain,
            finalSettledTxAccumulatorRoot: intent.finalSettledTxAccumulatorRoot,
            memberSetCommitment: manager.registeredMemberSetCommitment(),
            memberAndDelegateCount: (uint16(manager.activeMemberCount()) << 8) | uint16(manager.activeDelegateCount())
        });
        uint256[] memory limbs = verifier.expectedCloseLimbs(fields);
        MleVerifier.MleProof memory proof;
        proof.publicInputs = limbs;

        vm.startBroadcast();
        manager.submitPartialWithdrawalIntent(intent, proof, prevSettledTxChain, w);
        vm.stopBroadcast();

        bytes32 authDigest = manager.pendingPartialWithdrawalAuthDigest();
        console2.log("AUTH_DIGEST:");
        console2.logBytes32(authDigest);
    }
}
