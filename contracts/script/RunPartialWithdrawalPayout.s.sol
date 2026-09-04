// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title Build the exact proof-backed partial-withdrawal payout transaction.
/// @notice The Rust payout driver first runs this script without `--broadcast`, reads the exact
///         dry-run calldata, hashes and fsyncs that calldata in its candidate journal, and only
///         then sends it with `cast send --nonce`.  Paths are per-channel and are restricted by
///         foundry.toml's read-only fs allow-list; no shared test/data filename is overwritten.
contract RunPartialWithdrawalPayout is Script {
    function _rollup() internal view returns (IntmaxRollup) {
        return IntmaxRollup(payable(vm.envAddress("ROLLUP")));
    }

    function _payout() internal view returns (string memory) {
        return vm.readFile(vm.envString("PW_PAYOUT_PATH"));
    }

    function _mle() internal view returns (string memory) {
        return vm.readFile(vm.envString("PW_MLE_PATH"));
    }

    function _withdrawal(string memory j) internal pure returns (IntmaxRollup.Withdrawal[] memory ws) {
        ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = IntmaxRollup.Withdrawal({
            recipient: vm.parseJsonAddress(j, ".withdrawals[0].recipient"),
            tokenIndex: uint32(vm.parseJsonUint(j, ".withdrawals[0].token_index")),
            amount: vm.parseUint(vm.parseJsonString(j, ".withdrawals[0].amount")),
            nullifier: vm.parseJsonBytes32(j, ".withdrawals[0].nullifier"),
            auxData: vm.parseJsonBytes32(j, ".withdrawals[0].aux_data")
        });
    }

    function withdrawNativeStep() external {
        string memory j = _payout();
        IntmaxRollup.Withdrawal[] memory ws = _withdrawal(j);
        require(ws[0].tokenIndex == 0, "partial withdrawal is not native");
        address prover = vm.parseJsonAddress(j, ".withdrawal_prover");
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_mle());

        vm.startBroadcast();
        _rollup().withdrawNative(ws, prover, proof);
        vm.stopBroadcast();
    }

    function withdrawErc20Step() external {
        string memory j = _payout();
        IntmaxRollup.Withdrawal[] memory ws = _withdrawal(j);
        require(ws[0].tokenIndex != 0, "partial withdrawal is native");
        address prover = vm.parseJsonAddress(j, ".withdrawal_prover");
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_mle());

        vm.startBroadcast();
        _rollup().withdrawERC20(ws, prover, proof);
        vm.stopBroadcast();
    }
}
