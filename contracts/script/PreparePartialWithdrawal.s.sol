// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title Keyless ABI encoder for a proof-backed partial-withdrawal submission.
/// @dev No RPC, signing, broadcasting, shared fixtures, or devnet release override.
contract PreparePartialWithdrawal is Script {
    function _uint(string memory j, string memory key, uint256 bits) internal pure returns (uint256 value) {
        value = vm.parseJsonUint(j, key);
        require(value < (uint256(1) << bits), "integer field exceeds width");
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
            require(raw[i] <= type(uint32).max, "token registry entry exceeds u32");
            r[i] = uint32(raw[i]);
        }
    }

    function run() external {
        string memory j = vm.readFile(vm.envString("PW_INTENT_PATH"));
        address managerAddr = vm.parseJsonAddress(j, ".manager");
        require(managerAddr == vm.envAddress("PW_MANAGER"), "partial withdrawal manager mismatch");

        // CloseIntent from JSON.
        ChannelSettlementManager.CloseIntent memory intent;
        intent.closeNonce = uint64(_uint(j, ".close_nonce", 64));
        intent.finalEpoch = uint64(_uint(j, ".final_epoch", 64));
        intent.finalSmallBlockNumber = uint64(_uint(j, ".final_small_block_number", 64));
        intent.closeFreezeNonce = uint64(_uint(j, ".close_freeze_nonce", 64));
        intent.finalChannelStateDigest = vm.parseJsonBytes32(j, ".final_channel_state_digest");
        intent.finalBalanceStateH1 = vm.parseJsonBytes32(j, ".final_balance_state_h1");
        intent.channelFundAmounts = _parseAmounts(j);
        intent.tokenRegistry = _parseRegistry(j);
        intent.tokenCount = uint8(_uint(j, ".token_count", 8));
        intent.channelFundIntmaxStateRoot = vm.parseJsonBytes32(j, ".channel_fund_intmax_state_root");
        intent.burnTxHash = vm.parseJsonBytes32(j, ".burn_tx_hash");
        intent.closeWithdrawalDigest = vm.parseJsonBytes32(j, ".close_withdrawal_digest");
        intent.snapshotMediumBlockNumber = uint64(_uint(j, ".snapshot_medium_block_number", 64));
        intent.finalStateVersion = uint64(_uint(j, ".final_state_version", 64));
        intent.finalSettledTxChain = vm.parseJsonBytes32(j, ".final_settled_tx_chain");
        intent.finalSettledTxAccumulatorRoot = vm.parseJsonBytes32(j, ".final_settled_tx_acc_root");

        // AuthorizedWithdrawal from JSON.
        ChannelSettlementManager.AuthorizedWithdrawal memory w;
        w.recipient = vm.parseJsonAddress(j, ".withdrawal_recipient");
        w.tokenIndex = uint32(_uint(j, ".withdrawal_token_index", 32));
        w.amount = vm.parseJsonUint(j, ".withdrawal_amount");
        w.baseNonce = uint32(_uint(j, ".withdrawal_base_nonce", 32));
        w.nullifier = vm.parseJsonBytes32(j, ".withdrawal_nullifier");
        w.auxData = vm.parseJsonBytes32(j, ".withdrawal_aux_data");
        w.txLeaf = vm.parseJsonBytes32(j, ".burn_tx_leaf");

        bytes32 prevSettledTxChain = vm.parseJsonBytes32(j, ".prev_settled_tx_chain");

        bytes memory compactProof = FixtureLib.parseCompactProofV2(vm.readFile(vm.envString("PW_MLE_PATH")));
        bytes memory callData = abi.encodeCall(
            ChannelSettlementManager.submitPartialWithdrawalIntent,
            (intent, compactProof, prevSettledTxChain, w)
        );
        vm.writeFile(vm.envString("PW_CALLDATA_OUT"), vm.toString(callData));
    }

    function attest() external {
        address manager = vm.envAddress("PW_MANAGER");
        bytes memory proof = vm.readFileBinary(vm.envString("PW_BACKING_COMPACT_PATH"));
        vm.writeFile(vm.envString("PW_CALLDATA_OUT"), vm.toString(abi.encodeCall(
            CloseFundingMaterializer.attestSignedHeadBacking,
            (ChannelSettlementManager(payable(manager)), proof)
        )));
    }
}
