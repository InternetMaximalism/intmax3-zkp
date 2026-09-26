// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Script, console2} from "forge-std/Script.sol";
import {FixtureLib} from "./FixtureLib.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";

/// @notice Deploy the independently pinned late-receive adapter before the settlement stack.
/// Config comes from late_incoming::export_late_incoming_mle_config, using the production keys.
contract DeployLateIncomingVerifier is Script {
    function run() external returns (PinnedMleVerifierV2 verifier) {
        string memory config = vm.readFile(vm.envString("LATE_MLE_CONFIG_PATH"));
        vm.startBroadcast();
        (, verifier) = FixtureLib.deployPinnedMleV2(config);
        vm.stopBroadcast();
        console2.log("LATE_INCOMING_VERIFIER", address(verifier));
    }
}
