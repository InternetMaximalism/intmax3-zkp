// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title DeployTestnetBlockProducer
/// @notice ===================== TESTNET DEPLOY (anvil / testnet only) =====================
///         Deploys IntmaxRollup with block posting restricted to a single block-production
///         authority and the addresses it designates:
///
///             blockProducerAdmin = 0x2C0BF10558adafDd21296CbF71dd6FE88c782C80
///
///         That address (or a `BLOCK_PRODUCER_ADMIN` override) may post blocks directly AND
///         may designate additional producers via `setBlockProducer`. Everyone else is
///         rejected with `NotAuthorizedBlockProducer` (fail-closed whitelist).
///
///         ⚠️ TESTNET: this bakes a specific admin address and is intended for anvil / a public
///         testnet. For mainnet, deploy from a reviewed config (a cold deployer key, an
///         explicitly-set FRAUD_TREASURY, and a deliberate block-producer authority), and
///         regenerate/redeploy the VKs/fixtures per doc/tasks/regen-and-redeploy-runbook.md.
///
///         Deployer key comes from the standard Foundry mechanism (`--private-key`/`--account`).
///         FRAUD_TREASURY defaults to the broadcaster on anvil (chainid 31337); it is REQUIRED
///         on any other chain (see IntmaxRollup deploy guard).
contract DeployTestnetBlockProducer is Script {
    // TESTNET: the designated block-production authority. Override with BLOCK_PRODUCER_ADMIN.
    address internal constant TESTNET_BLOCK_PRODUCER_ADMIN =
        0x2C0BF10558adafDd21296CbF71dd6FE88c782C80;

    function run() external {
        string memory mleJson = FixtureLib.loadMle();
        string memory blockJson = FixtureLib.loadBlock();

        bytes32 genesisStateRoot = vm.parseJsonBytes32(blockJson, ".genesis_state_root");
        FixtureLib.DeployData memory dd = FixtureLib.parseDeployData(mleJson);

        // FRAUD_TREASURY: required on real chains; defaults to the broadcaster on anvil (31337).
        address fraudTreasury = vm.envOr("FRAUD_TREASURY", address(0));
        if (fraudTreasury == address(0)) {
            require(block.chainid == 31337, "FRAUD_TREASURY must be set for non-local deploys");
            fraudTreasury = msg.sender;
        }

        // TESTNET: the block-production authority (overridable).
        address bpAdmin = vm.envOr("BLOCK_PRODUCER_ADMIN", TESTNET_BLOCK_PRODUCER_ADMIN);

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
            false // production-shaped: reject a disabled (degreeBits==0) validity VK
        );
        // Pin the KZG blob-binding satellite (fraudProof binding is fail-closed until set).
        rollup.setKzgVerifier(new BlobKZGVerifierExt());

        // Restrict block posting to `bpAdmin` + its designees. `bpAdmin` can post directly and
        // can call setBlockProducer to designate more producers; nobody else can post.
        rollup.setBlockProducerAdmin(bpAdmin);

        vm.stopBroadcast();

        console2.log("=== IntmaxRollup TESTNET deploy (block-producer restricted) ===");
        console2.log("IntmaxRollup      :", address(rollup));
        console2.log("MleVerifier       :", address(verifier));
        console2.log("fraudTreasury     :", fraudTreasury);
        console2.log("blockProducerAdmin:", bpAdmin);
    }
}
