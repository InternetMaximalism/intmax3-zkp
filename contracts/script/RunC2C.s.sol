// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title Drive the channel-to-channel Sepolia lifecycle (manager-free, direct-to-EOA exit).
/// @notice One broadcast tx per --sig step. The 5 postBlock blob txs are sent with `cast` (forge
///         scripts cannot attach EIP-4844 blobs); everything carrying array/struct calldata is here.
///         CORRECT ORDER (cumulative reg+deposit chains — see C2CBlockHash.t.sol):
///           register1Step -> [cast postBlock b0] -> depositStep -> [cast postBlock b1] ->
///           register2Step -> [cast postBlock b2] -> [cast postBlock b3] -> [cast postBlock b4] ->
///           finalizeStep (SUB_ID=4) -> withdrawNativeStep -> withdrawStep
///         ROLLUP from env. SUB_ID defaults to 4 (block 5 = 5th posting round → submission id 4).
contract RunC2C is Script {
    function _rollup() internal view returns (IntmaxRollup) { return IntmaxRollup(payable(vm.envAddress("ROLLUP"))); }
    function _lc() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/c2c_lifecycle.json")); }
    function _vmle() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/c2c_lifecycle_validity_mle.json")); }
    function _wmle() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/c2c_withdrawal_mle.json")); }
    function _payout() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/c2c_withdrawal_payout.json")); }

    function _register(string memory key) internal {
        string memory lc = _lc();
        uint32 channelId = uint32(vm.parseJsonUint(lc, string.concat(key, ".channel_id")));
        uint8 bpSlot = uint8(vm.parseJsonUint(lc, string.concat(key, ".bp_member_slot")));
        bytes32[] memory sphincs = vm.parseJsonBytes32Array(lc, string.concat(key, ".member_sphincs_pubkey_hashes"));
        bytes32[] memory pkBs = vm.parseJsonBytes32Array(lc, string.concat(key, ".member_pk_bs"));
        bytes32[] memory regev = vm.parseJsonBytes32Array(lc, string.concat(key, ".regev_pk_digests"));
        address[] memory recipients = vm.parseJsonAddressArray(lc, string.concat(key, ".recipients"));
        vm.startBroadcast();
        _rollup().registerChannel(channelId, bpSlot, 0, sphincs, pkBs, regev, recipients);
        vm.stopBroadcast();
        console2.log("registerChannel OK; pendingChannelRegHashChain now folded for", key);
    }

    /// register channel 1 (BEFORE postBlock b0).
    function register1Step() external { _register(".registration1"); }

    /// register channel 2 (BEFORE postBlock b2, AFTER postBlock b1 — cumulative reg chain).
    function register2Step() external { _register(".registration2"); }

    /// deposit ch1's funds into real ETH escrow (depositor = msg.sender = baked EOA). BEFORE postBlock b1.
    function depositStep() external {
        string memory lc = _lc();
        bytes32 recipient = vm.parseJsonBytes32(lc, ".deposit.recipient");
        uint32 tokenIndex = uint32(vm.parseJsonUint(lc, ".deposit.token_index"));
        uint256 amount = vm.parseUint(vm.parseJsonString(lc, ".deposit.amount"));
        bytes32 auxData = vm.parseJsonBytes32(lc, ".deposit.aux_data");
        vm.startBroadcast();
        _rollup().deposit{value: amount}(recipient, tokenIndex, amount, auxData);
        vm.stopBroadcast();
        console2.log("deposit OK; totalEscrowed:", _rollup().totalEscrowed());
    }

    /// finalize the 5-block chain (submission id via SUB_ID env, default 4 = the 5th posting round).
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
        uint256 subId = vm.envOr("SUB_ID", uint256(4));

        vm.startBroadcast();
        bool ok = _rollup().finalize(subId, finalRoot, vpis, proof);
        vm.stopBroadcast();
        require(ok, "finalize returned false");
        console2.log("finalize OK; latestFinalizedStateRoot:");
        console2.logBytes32(_rollup().latestFinalizedStateRoot());
    }

    /// withdrawNative: ch2 pays its received native ETH DIRECTLY to the EOA (recipient baked in proof).
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
        console2.log("withdrawNative OK; pendingWithdrawals[recipient]:", _rollup().pendingWithdrawals(ws[0].recipient));
    }

    /// Local-only: ABI-encode the withdrawNative call and log its calldata byte length, so we can
    /// confirm a freshly re-rolled withdrawal proof fits under Ethereum's 128 KiB (131072-byte) tx
    /// limit BEFORE broadcasting. No RPC / no broadcast needed (run with just --sig "sizeStep()").
    function sizeStep() external view {
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
        bytes memory cd = abi.encodeCall(IntmaxRollup.withdrawNative, (ws, prover, proof));
        console2.log("withdrawNative calldata bytes:", cd.length);
        console2.log("under 130950 (raw tx < 131072)?:", cd.length <= 130950);
    }

    /// EOA pulls its pendingWithdrawals balance as real ETH (the receiver's channel-to-channel exit).
    function withdrawStep() external {
        vm.startBroadcast();
        _rollup().withdraw();
        vm.stopBroadcast();
        console2.log("withdraw OK; pendingWithdrawals[msg.sender]:", _rollup().pendingWithdrawals(msg.sender));
    }
}
