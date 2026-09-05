// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier,
    IChannelRegistry,
    SETTLEMENT_LOCAL_DEVNET_CHAIN_ID
} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";
import {FixtureLib} from "./FixtureLib.sol";
import {DeployConfig} from "./DeployConfig.sol";

/// @title Deploy the close-lifecycle stack on the LOCAL DEVNET (anvil) — demo / address dry-run.
/// @notice Plain nonce-based `new` deploys (deployer = the broadcasting EOA), so:
///           - the manager's CREATE address depends only on the EOA + nonce (NOT the initcode), so a
///             dry-run (`forge script --sender <EOA>`, no broadcast, no key) prints the exact
///             address the broadcast will deploy THIS SCRIPT's manager to. Bake THAT into the close
///             withdrawal proof: WD_RECIPIENT=<manager> WD_OUT_PREFIX=close_ cargo run --release
///             --bin generate_withdrawal_fixture.
///           - all six circuit adapters are deployed and constructor-pinned before either parent
///             value boundary is created; there is no post-deploy VK initializer.
///
/// @dev Reads the sepolia_* fixtures. The 10-min GRACE_BEFORE_PROCESS_SECS is a fixed contract
///      constant and is unavoidable between requestClose and submitCloseIntent.
///
/// ⚠️ NOT A PRODUCTION DEPLOYER — and, since 2026-08-13, that is ENFORCED by the
/// `block.chainid == SETTLEMENT_LOCAL_DEVNET_CHAIN_ID` guard at the top of `run()`, not asserted by
/// this comment. Although all six v2 adapters are now pinned atomically, these demo fixture paths
/// are not a reviewed release manifest. Use `DeployCloseCli.s.sol` for an operational deployment.
contract DeployClose is Script {
    // SECURITY (challenge-period floor): was a hardcoded 1 second labelled "demo", on a script
    // whose own header aims it at Sepolia. Guarded finalization is permissionless at the deadline, so
    // a 1-second window means a stale close intent can be finalized before any honest member can
    // prove and land a replacement — permanent fund mis-allocation. The value is now devnet-only;
    // the manager's constructor enforces the same floor independently.
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 0;
    uint256 internal constant INITIAL_BP_BOND = 0;

    // Sepolia fixture set: recipient baked = the nonce-based CREATE manager address from the dry-run
    // (separate from the local CREATE2 `close_*` set used by CloseLifecycleE2E.t.sol).
    function _vJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_lifecycle_validity_mle_config.json"));
    }

    function _wJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_withdrawal_mle_config.json"));
    }

    function _lcJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_lifecycle.json"));
    }

    function _closeJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/close_intent_mle_config.json"));
    }

    function _withdrawalClaimJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/withdrawal_claim_mle_config.json"));
    }

    function _postCloseClaimJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/post_close_claim_mle_config.json"));
    }

    function _cancelCloseJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/cancel_close_mle_config.json"));
    }

    function _backingJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/close_asset_backing_mle_config.json"));
    }

    /// @return rollup  the deployed IntmaxRollup
    /// @return manager the deployed ChannelSettlementManager (returned so tests can assert on the
    ///         challenge period this script actually shipped, per chain)
    function run() external returns (IntmaxRollup rollup, ChannelSettlementManager manager) {
        // SECURITY: this remains a local-only demo because its sepolia-prefixed state fixtures are
        // not a reviewed release manifest. Unlike the legacy deploy, however, it atomically pins
        // every circuit adapter and cannot create an uninitialized settlement verifier.
        //
        // WHY THE HARD CHAIN-ID GATE REMAINS:
        //   1. This script takes validity state and genesis data from `sepolia_*` demo fixtures,
        //      not a generator-produced, reviewed deployment manifest. The strict v2 parser now
        //      rejects stale/V1 material, but successful parsing alone is not release authorization.
        //   2. Nothing legitimately needs this helper on a public chain. `DeployCloseCli.s.sol` is the
        //      real-network settlement deployer (doc/docs/deploy-runbook.md, and it is what
        //      `tests/close_lifecycle_cli_e2e.rs` / `tests/two_token_cli_e2e.rs` drive); the only
        //      recorded uses of THIS script (doc/tasks/a3-p4-withdraw-plan.md,
        //      doc/tasks/a3-p5-plus-plan.md) are anvil runs, and its Sepolia driver
        //      `RunClose.s.sol` reads `sepolia_close_intent*.json`, which do not exist in the repo.
        //   3. The nonce-based manager prediction applies only to this exact script and deployment
        //      order; it is not transferable to the production deployer's different transaction set.
        //
        // The chain id is compared against the same `SETTLEMENT_LOCAL_DEVNET_CHAIN_ID` the manager's
        // constructor uses, so "local" cannot mean two different things in this repo. This matches
        // the existing hard-gate idiom in `DeployWalletSettlement.s.sol` /
        // `DeployPartialWithdrawalE2E.s.sol` (a bare `require` at the top of `run()`), NOT the
        // `FRAUD_TREASURY` fallback check below, which only fires when the env var is unset.
        require(
            block.chainid == SETTLEMENT_LOCAL_DEVNET_CHAIN_ID,
            "local-devnet only: demo fixtures are not a release manifest -- use DeployCloseCli.s.sol"
        );
        string memory vkJson = _vJson();
        string memory withdrawalJson = _wJson();
        string memory closeJson = _closeJson();
        string memory withdrawalClaimJson = _withdrawalClaimJson();
        string memory postCloseClaimJson = _postCloseClaimJson();
        string memory cancelCloseJson = _cancelCloseJson();
        string memory backingJson = _backingJson();
        string memory lcJson = _lcJson();
        bytes32 genesis = vm.parseJsonBytes32(lcJson, ".genesis_state_root");
        // SECURITY (#6): require FRAUD_TREASURY on real chains; anvil (31337) may default it.
        address fraudTreasury = vm.envOr("FRAUD_TREASURY", address(0));
        if (fraudTreasury == address(0)) {
            require(block.chainid == 31337, "FRAUD_TREASURY must be set for non-local deploys");
            fraudTreasury = msg.sender;
        }

        vm.startBroadcast();

        (, PinnedMleVerifierV2 validityVerifier) = FixtureLib.deployPinnedMleV2(vkJson);
        (, PinnedMleVerifierV2 withdrawalVerifier) = FixtureLib.deployPinnedMleV2(withdrawalJson);
        rollup = new IntmaxRollup(
            fraudTreasury,
            IPinnedMleVerifierV2(address(validityVerifier)),
            IPinnedMleVerifierV2(address(withdrawalVerifier)),
            genesis
        );
        // Pin the KZG blob-binding satellite (EIP-170 relief; fraudProof binding is fail-closed until set).
        rollup.setKzgVerifier(new BlobKZGVerifierExt());
        // Authorize the block producer (posting is permissioned; the whitelist is empty until set).
        rollup.setBlockProducer(vm.envOr("BLOCK_PRODUCER", msg.sender), true);

        (, PinnedMleVerifierV2 closeVerifier) = FixtureLib.deployPinnedMleV2(closeJson);
        (, PinnedMleVerifierV2 withdrawalClaimVerifier) = FixtureLib.deployPinnedMleV2(withdrawalClaimJson);
        (, PinnedMleVerifierV2 postCloseClaimVerifier) = FixtureLib.deployPinnedMleV2(postCloseClaimJson);
        (, PinnedMleVerifierV2 cancelCloseVerifier) = FixtureLib.deployPinnedMleV2(cancelCloseJson);
        ChannelSettlementVerifier sv = new ChannelSettlementVerifier(
            IPinnedMleVerifierV2(address(closeVerifier)),
            IPinnedMleVerifierV2(address(withdrawalClaimVerifier)),
            IPinnedMleVerifierV2(address(postCloseClaimVerifier)),
            IPinnedMleVerifierV2(address(cancelCloseVerifier))
        );
        // The signer-independent exit's whole-vector CloseAssetBacking adapter, pinned into the
        // materializer at construction (a DIFFERENT circuit from the close-intent adapter above).
        (, PinnedMleVerifierV2 backingVerifier) = FixtureLib.deployPinnedMleV2(backingJson);
        CloseFundingMaterializer materializer =
            new CloseFundingMaterializer(rollup, IPinnedMleVerifierV2(address(backingVerifier)));

        // registerChannel BEFORE the manager deploy (Finding E).
        uint32 channelId = uint32(vm.parseJsonUint(lcJson, ".registration.channel_id"));
        uint8 bpSlot = uint8(vm.parseJsonUint(lcJson, ".registration.bp_member_slot"));
        bytes32[] memory sphincs = vm.parseJsonBytes32Array(lcJson, ".registration.member_pk_gs");
        bytes32[] memory pkBs = vm.parseJsonBytes32Array(lcJson, ".registration.member_pk_bs");
        bytes32[] memory regev = vm.parseJsonBytes32Array(lcJson, ".registration.regev_pk_digests");
        address[] memory recipients = vm.parseJsonAddressArray(lcJson, ".registration.recipients");
        rollup.registerChannel(channelId, bpSlot, 0, sphincs, pkBs, regev, recipients);

        // Manager member bindings. SECURITY/SCOPE: the close-form member-set commitment binds only
        // the SPHINCS+ pubkey hashes (not recipients), so we can route member slot 0's payout
        // recipient to the broadcasting EOA (a controlled address) so the demo can complete the final
        // `claimWithdrawalCredit` and observe real ETH arriving — the Finding-E constructor check
        // (hash-set commitment) still passes. registerChannel above used the fixture recipients
        // (baked into the validity proof's block hash); only the manager's payout target differs.
        ChannelSettlementManager.MemberBinding[] memory bindings =
            new ChannelSettlementManager.MemberBinding[](sphincs.length);
        for (uint256 i = 0; i < sphincs.length; i++) {
            address r = (i == 0) ? msg.sender : recipients[i];
            bindings[i] = ChannelSettlementManager.MemberBinding({pkG: sphincs[i], recipient: r});
        }
        manager = new ChannelSettlementManager(
            bytes4(channelId),
            bpSlot,
            sphincs[bpSlot],
            0,
            bytes32(0),
            DeployConfig.challengePeriodSecs(),
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(sv)),
            IChannelRegistry(address(rollup)),
            address(materializer),
            bindings
        );

        vm.stopBroadcast();

        console2.log("=== close-lifecycle deploy ===");
        console2.log("Validity MLE v2 adapter:", address(validityVerifier));
        console2.log("Withdrawal MLE v2 adapter:", address(withdrawalVerifier));
        console2.log("Close MLE v2 adapter:", address(closeVerifier));
        console2.log("Withdrawal-claim MLE v2 adapter:", address(withdrawalClaimVerifier));
        console2.log("Post-close-claim MLE v2 adapter:", address(postCloseClaimVerifier));
        console2.log("Cancel-close MLE v2 adapter:", address(cancelCloseVerifier));
        console2.log("IntmaxRollup:", address(rollup));
        console2.log("SettlementVerifier:", address(sv));
        console2.log("CloseFundingMaterializer:", address(materializer));
        console2.log("CLOSE_MANAGER_ADDRESS:", address(manager));
        console2.log("baked recipient (sepolia_withdrawal_payout.json):");
        console2.logAddress(
            vm.parseJsonAddress(
                vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_withdrawal_payout.json")),
                ".withdrawals[0].recipient"
            )
        );
    }
}
