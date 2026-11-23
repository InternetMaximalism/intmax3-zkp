// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Script} from "forge-std/Script.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @notice Keyless exact calldata export for the late-deposit refund lane. A wallet signs/submits
/// the output to the channel's materializer (`claimLateDeposit`).
contract PrepareLateDeposit is Script {
    function run() external {
        bytes memory proof = FixtureLib.parseCompactProofV2(vm.readFile(vm.envString("LATE_DEPOSIT_MLE_PATH")));
        ChannelSettlementManager manager = ChannelSettlementManager(payable(vm.envAddress("LATE_MANAGER")));
        vm.writeFile(vm.envString("LATE_DEPOSIT_CALLDATA_OUT"), vm.toString(
            abi.encodeCall(CloseFundingMaterializer.claimLateDeposit, (manager, proof))));
    }
}
