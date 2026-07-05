// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title Deploy
/// @notice Sepolia (and local anvil) smoke-deploy of IntmaxRollup with the REAL
///         MLE VK (degreeBits = 13) + genesis state root parsed from the local
///         test fixtures (`contracts/test/data/*.json`).
///
///         Deployer key is read from the standard Foundry mechanism
///         (`--private-key` / `--account`) — nothing is hardcoded here.
///         `FRAUD_TREASURY` env var overrides the fraud-treasury address;
///         when unset it defaults to the broadcaster (`msg.sender`).
///
///         This mirrors, broadcast-side, the exact constructor construction in
///         `contracts/test/MleFinalizeE2E.t.sol` (the passing full-path test).
contract Deploy is Script {
    function run() external {
        string memory mleJson = FixtureLib.loadMle();
        string memory blockJson = FixtureLib.loadBlock();

        bytes32 genesisStateRoot = vm.parseJsonBytes32(blockJson, ".genesis_state_root");
        FixtureLib.DeployData memory dd = FixtureLib.parseDeployData(mleJson);

        // FRAUD_TREASURY env override; default to the broadcaster.
        address fraudTreasury = vm.envOr("FRAUD_TREASURY", msg.sender);

        vm.startBroadcast();

        MleVerifier verifier = new MleVerifier();
        IntmaxRollup.MleVk memory vk = FixtureLib.buildMleVk(mleJson, verifier);

        IntmaxRollup rollup = new IntmaxRollup(
            fraudTreasury,
            vk,
            dd.whirParams,
            dd.protocolId,
            dd.sessionId,
            dd.kIs,
            dd.subgroupGenPowers,
            verifier,
            genesisStateRoot,
            false // SECURITY (A-2): production — reject a disabled (degreeBits==0) validity VK
        );
        // Pin the KZG blob-binding satellite (EIP-170 relief; fraudProof binding is fail-closed until set).
        rollup.setKzgVerifier(new BlobKZGVerifierExt());

        vm.stopBroadcast();

        console2.log("=== IntmaxRollup smoke deploy ===");
        console2.log("MleVerifier   :", address(verifier));
        console2.log("IntmaxRollup  :", address(rollup));
        console2.log("fraudTreasury :", fraudTreasury);
        console2.log("mleVk.degreeBits:", vk.degreeBits);
        console2.log("genesisStateRoot:");
        console2.logBytes32(genesisStateRoot);
    }
}
