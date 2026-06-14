// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title Deploy the channel-to-channel demo stack to Sepolia (manager-free, direct-to-EOA exit).
/// @notice Deploys MleVerifier + IntmaxRollup and initializes the withdrawal VK — NOTHING else.
///         The two channel registrations are NOT done here: the cumulative on-chain registration
///         chain requires registerChannel(2) to be INTERLEAVED after postBlock(b2) (validated by
///         C2CBlockHash.t.sol). So registration / deposit / postBlock are driven as separate,
///         correctly-ordered transactions by RunC2C + cast. Channel 2 withdraws its received funds
///         DIRECTLY to the deployer EOA (recipient baked into c2c_withdrawal_payout.json) — no
///         ChannelSettlementManager, no close machinery (those were proven on the single-channel run).
contract DeployC2C is Script {
    function _vJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/c2c_lifecycle_validity_mle.json"));
    }
    function _wJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/c2c_withdrawal_mle.json"));
    }
    function _lcJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/c2c_lifecycle.json"));
    }

    function run() external {
        string memory vkJson = _vJson();
        string memory lcJson = _lcJson();
        bytes32 genesis = vm.parseJsonBytes32(lcJson, ".genesis_state_root");
        address fraudTreasury = vm.envOr("FRAUD_TREASURY", msg.sender);

        vm.startBroadcast();

        MleVerifier verifier = new MleVerifier();
        IntmaxRollup.MleVk memory vvk = FixtureLib.buildMleVk(vkJson, verifier);
        FixtureLib.DeployData memory vdd = FixtureLib.parseDeployData(vkJson);
        IntmaxRollup rollup = new IntmaxRollup(
            fraudTreasury, vvk, vdd.whirParams, vdd.protocolId, vdd.sessionId,
            vdd.kIs, vdd.subgroupGenPowers, verifier, genesis
        );

        {
            string memory wJson = _wJson();
            FixtureLib.DeployData memory wdd = FixtureLib.parseDeployData(wJson);
            IntmaxRollup.MleVk memory wvk = FixtureLib.buildMleVk(wJson, verifier);
            rollup.initializeWithdrawalVk(wvk, wdd.whirParams, wdd.protocolId, wdd.sessionId, wdd.kIs, wdd.subgroupGenPowers);
        }

        vm.stopBroadcast();

        console2.log("=== c2c deploy (manager-free, direct-to-EOA) ===");
        console2.log("MleVerifier :", address(verifier));
        console2.log("IntmaxRollup:", address(rollup));
        console2.log("baked withdrawal recipient (c2c_withdrawal_payout.json):");
        console2.logAddress(vm.parseJsonAddress(
            vm.readFile(string.concat(vm.projectRoot(), "/test/data/c2c_withdrawal_payout.json")),
            ".withdrawals[0].recipient"
        ));
    }
}
