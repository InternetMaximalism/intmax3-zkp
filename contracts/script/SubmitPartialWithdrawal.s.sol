// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ChannelSettlementManager, SETTLEMENT_LOCAL_DEVNET_CHAIN_ID} from "../src/ChannelSettlementManager.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title Submit a partial-withdrawal intent (anvil E2E).
/// @notice Reads intent + withdrawal fields from `test/data/pw_submit.json` and drives the
///         `manager.submitPartialWithdrawalIntent` call with the real wrapped-close MLE proof.
contract SubmitPartialWithdrawal is Script {
    error LocalDevnetOnly(uint256 actualChainId);

    function _read(string memory f) internal view virtual returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/", f));
    }

    function _parseAmounts(string memory j) internal pure returns (uint256[10] memory a) {
        string[] memory raw = vm.parseJsonStringArray(j, ".channel_fund_amounts");
        require(raw.length == 10, "channel_fund_amounts must have 10 entries");
        for (uint256 i = 0; i < 10; i++) {
            a[i] = vm.parseUint(raw[i]);
        }
    }

    function _parseRegistry(string memory j) internal pure returns (uint32[10] memory r) {
        uint256[] memory raw = vm.parseJsonUintArray(j, ".token_registry");
        require(raw.length == 10, "token_registry must have 10 entries");
        for (uint256 i = 0; i < 10; i++) {
            r[i] = uint32(raw[i]);
        }
    }

    function run() external {
        // This script stages mutable test fixtures and uses the anvil-only partial-withdrawal E2E
        // lifecycle. Refuse every other chain before reading a fixture or resolving a target.
        if (block.chainid != SETTLEMENT_LOCAL_DEVNET_CHAIN_ID) {
            revert LocalDevnetOnly(block.chainid);
        }

        string memory j = _read("pw_submit.json");
        address managerAddr = vm.parseJsonAddress(j, ".manager");
        ChannelSettlementManager manager = ChannelSettlementManager(payable(managerAddr));

        // CloseIntent from JSON.
        ChannelSettlementManager.CloseIntent memory intent;
        intent.closeNonce = uint64(vm.parseJsonUint(j, ".close_nonce"));
        intent.finalEpoch = uint64(vm.parseJsonUint(j, ".final_epoch"));
        intent.finalSmallBlockNumber = uint64(vm.parseJsonUint(j, ".final_small_block_number"));
        intent.closeFreezeNonce = uint64(vm.parseJsonUint(j, ".close_freeze_nonce"));
        intent.finalChannelStateDigest = vm.parseJsonBytes32(j, ".final_channel_state_digest");
        intent.finalBalanceStateH1 = vm.parseJsonBytes32(j, ".final_balance_state_h1");
        intent.channelFundAmounts = _parseAmounts(j);
        intent.tokenRegistry = _parseRegistry(j);
        intent.tokenCount = uint8(vm.parseJsonUint(j, ".token_count"));
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
        w.baseNonce = uint32(vm.parseJsonUint(j, ".withdrawal_base_nonce"));
        w.nullifier = vm.parseJsonBytes32(j, ".withdrawal_nullifier");
        w.auxData = vm.parseJsonBytes32(j, ".withdrawal_aux_data");
        w.txLeaf = vm.parseJsonBytes32(j, ".burn_tx_leaf");

        bytes32 prevSettledTxChain = vm.parseJsonBytes32(j, ".prev_settled_tx_chain");

        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_read("pw_close_intent_mle.json"));

        vm.startBroadcast();
        manager.submitPartialWithdrawalIntent(intent, proof, prevSettledTxChain, w);
        vm.stopBroadcast();

        bytes32 authDigest = manager.pendingPartialWithdrawalAuthDigest();
        console2.log("AUTH_DIGEST:");
        console2.logBytes32(authDigest);
    }
}
