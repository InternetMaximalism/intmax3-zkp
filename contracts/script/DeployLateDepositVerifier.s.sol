// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Script, console2} from "forge-std/Script.sol";
import {FixtureLib} from "./FixtureLib.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";

/// @notice Deploy the independently pinned late-deposit adapter before the settlement stack.
/// Config comes from the Rust late-deposit MLE config export, using the production keys.
contract DeployLateDepositVerifier is Script {
    function run() external returns (PinnedMleVerifierV2 verifier) {
        string memory config = vm.readFile(vm.envString("LATE_DEPOSIT_MLE_CONFIG_PATH"));
        vm.startBroadcast();
        (, verifier) = FixtureLib.deployPinnedMleV2(config);
        vm.stopBroadcast();
        console2.log("LATE_DEPOSIT_VERIFIER", address(verifier));
    }
}
