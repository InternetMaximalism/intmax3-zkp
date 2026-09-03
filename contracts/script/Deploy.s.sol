// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";
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
    /// @return validityVerifier the immutable adapter for the validity circuit
    function run() external returns (IntmaxRollup rollup, PinnedMleVerifierV2 validityVerifier) {
        string memory mleJson = FixtureLib.loadMleConfig();
        string memory blockJson = FixtureLib.loadBlock();
        // Read the withdrawal fixture BEFORE broadcasting: if it is missing, this reverts before a
        // single transaction is sent, rather than after the rollup is already live on chain.
        string memory wJson = FixtureLib.loadWithdrawalMleConfig();

        bytes32 genesisStateRoot = vm.parseJsonBytes32(blockJson, ".genesis_state_root");
        // FRAUD_TREASURY env override. SECURITY (#6): require it explicitly on real chains; only
        // fall back to the broadcaster EOA on local anvil (chainid 31337), so a Sepolia/mainnet
        // deploy never silently makes the deployer the sole fraud-treasury claimant.
        address fraudTreasury = vm.envOr("FRAUD_TREASURY", address(0));
        if (fraudTreasury == address(0)) {
            require(block.chainid == 31337, "FRAUD_TREASURY must be set for non-local deploys");
            fraudTreasury = msg.sender;
        }

        vm.startBroadcast();

        (, validityVerifier) = FixtureLib.deployPinnedMleV2(mleJson);
        (, PinnedMleVerifierV2 withdrawalVerifier) = FixtureLib.deployPinnedMleV2(wJson);

        rollup = new IntmaxRollup(
            fraudTreasury,
            IPinnedMleVerifierV2(address(validityVerifier)),
            IPinnedMleVerifierV2(address(withdrawalVerifier)),
            genesisStateRoot
        );
        // Pin the KZG blob-binding satellite (EIP-170 relief; fraudProof binding is fail-closed until set).
        rollup.setKzgVerifier(new BlobKZGVerifierExt());
        // Authorize the block producer (posting is permissioned; the whitelist is empty until set).
        // Defaults to the broadcaster; set BLOCK_PRODUCER when the posting key differs from the deployer.
        rollup.setBlockProducer(vm.envOr("BLOCK_PRODUCER", msg.sender), true);

        vm.stopBroadcast();

        // Both independent payout/validity circuits are constructor-pinned atomically. A deploy
        // cannot enter a money-in/no-money-out state while waiting for a later VK transaction.
        require(address(rollup.validityMleVerifier()) == address(validityVerifier));
        require(address(rollup.withdrawalMleVerifier()) == address(withdrawalVerifier));

        console2.log("=== IntmaxRollup deploy ===");
        console2.log("Validity MLE v2 adapter:", address(validityVerifier));
        console2.log("Withdrawal MLE v2 adapter:", address(withdrawalVerifier));
        console2.log("IntmaxRollup  :", address(rollup));
        console2.log("fraudTreasury :", fraudTreasury);
        console2.log("genesisStateRoot:");
        console2.logBytes32(genesisStateRoot);
    }
}
