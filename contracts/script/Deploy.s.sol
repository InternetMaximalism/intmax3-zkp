// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title Deploy
/// @notice Sepolia (and local anvil) deploy of IntmaxRollup with the REAL
///         MLE VK (degreeBits = 13) + genesis state root parsed from the local
///         test fixtures (`contracts/test/data/*.json`), AND the withdrawal-circuit
///         VK that the payout path requires.
///
///         SCOPE: this deploys the ROLLUP only — deposits, block posting, finalize and
///         `withdrawNative`/`withdrawERC20`. It does NOT deploy a channel settlement stack
///         (`ChannelSettlementVerifier` / `ChannelSettlementManager`); use
///         `DeployCloseCli.s.sol` when the channel close/claim lifecycle is needed.
///
///         Deployer key is read from the standard Foundry mechanism
///         (`--private-key` / `--account`) — nothing is hardcoded here.
///         `FRAUD_TREASURY` env var overrides the fraud-treasury address;
///         when unset it defaults to the broadcaster (`msg.sender`).
///
///         This mirrors, broadcast-side, the exact constructor construction in
///         `contracts/test/MleFinalizeE2E.t.sol` (the passing full-path test).
contract Deploy is Script {
    /// @return rollup   the deployed IntmaxRollup (returned so tests can assert on its state)
    /// @return verifier the MleVerifier both the validity and withdrawal VKs are bound to
    function run() external returns (IntmaxRollup rollup, MleVerifier verifier) {
        string memory mleJson = FixtureLib.loadMle();
        string memory blockJson = FixtureLib.loadBlock();
        // Read the withdrawal fixture BEFORE broadcasting: if it is missing, this reverts before a
        // single transaction is sent, rather than after the rollup is already live on chain.
        string memory wJson = FixtureLib.loadWithdrawalMle();

        bytes32 genesisStateRoot = vm.parseJsonBytes32(blockJson, ".genesis_state_root");
        FixtureLib.DeployData memory dd = FixtureLib.parseDeployData(mleJson);

        // FRAUD_TREASURY env override. SECURITY (#6): require it explicitly on real chains; only
        // fall back to the broadcaster EOA on local anvil (chainid 31337), so a Sepolia/mainnet
        // deploy never silently makes the deployer the sole fraud-treasury claimant.
        address fraudTreasury = vm.envOr("FRAUD_TREASURY", address(0));
        if (fraudTreasury == address(0)) {
            require(block.chainid == 31337, "FRAUD_TREASURY must be set for non-local deploys");
            fraudTreasury = msg.sender;
        }

        vm.startBroadcast();

        verifier = new MleVerifier();
        IntmaxRollup.MleVk memory vk = FixtureLib.buildMleVk(mleJson, verifier);

        rollup = new IntmaxRollup(
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
        // Authorize the block producer (posting is permissioned; the whitelist is empty until set).
        // Defaults to the broadcaster; set BLOCK_PRODUCER when the posting key differs from the deployer.
        rollup.setBlockProducer(vm.envOr("BLOCK_PRODUCER", msg.sender), true);

        // SECURITY / LIVENESS: install the withdrawal-circuit VK. `_verifyWithdrawalSet`
        // (IntmaxRollup.sol) opens with `if (!withdrawalVkInitialized) revert WithdrawalVkNotSet();`
        // and BOTH payout entry points — `withdrawNative` and `withdrawERC20` — go through it,
        // while `deposit()` has no such gate. A rollup deployed without this call therefore accepts
        // deposits and can NEVER pay one out; there is no emergency/rescue/upgrade path in the
        // contract, and `initializeWithdrawalVk` is deployer-only and set-once, so the only repair
        // is a later manual call from the surviving deployer key. This script omitted it, and it is
        // the script the live runbook uses (doc/docs/deploy-runbook.md) — every rollup it produced
        // is money-in / no-money-out. No fail-closed check is weakened here: the revert stays, we
        // supply the VK it was correctly demanding.
        //
        // The deployer guard passes because the broadcaster that created the rollup is the same
        // sender calling this (`deployer` is set to the constructor's msg.sender).
        {
            FixtureLib.DeployData memory wdd = FixtureLib.parseDeployData(wJson);
            IntmaxRollup.MleVk memory wvk = FixtureLib.buildMleVk(wJson, verifier);
            rollup.initializeWithdrawalVk(
                wvk, wdd.whirParams, wdd.protocolId, wdd.sessionId, wdd.kIs, wdd.subgroupGenPowers
            );
        }

        vm.stopBroadcast();

        // Read the latch back rather than trusting that the call above ran. A deploy that reaches
        // this line has a payout path; one that does not, aborts loudly instead of printing an
        // address an operator would go on to fund.
        require(rollup.withdrawalVkInitialized(), "withdrawal VK not initialized: this rollup cannot pay out");

        console2.log("=== IntmaxRollup deploy ===");
        console2.log("MleVerifier   :", address(verifier));
        console2.log("IntmaxRollup  :", address(rollup));
        console2.log("fraudTreasury :", fraudTreasury);
        console2.log("mleVk.degreeBits:", vk.degreeBits);
        console2.log("withdrawalVkInitialized:", rollup.withdrawalVkInitialized());
        console2.log("genesisStateRoot:");
        console2.logBytes32(genesisStateRoot);
    }
}
