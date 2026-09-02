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
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";
import {DeployConfig} from "./DeployConfig.sol";

/// @title Deploy the close-lifecycle stack on the LOCAL DEVNET (anvil) — demo / address dry-run.
/// @notice Plain nonce-based `new` deploys (deployer = the broadcasting EOA), so:
///           - the manager's CREATE address depends only on the EOA + nonce (NOT the initcode), so a
///             dry-run (`forge script --sender <EOA>`, no broadcast, no key) prints the exact
///             address the broadcast will deploy THIS SCRIPT's manager to. Bake THAT into the close
///             withdrawal proof: WD_RECIPIENT=<manager> WD_OUT_PREFIX=close_ cargo run --release
///             --bin generate_withdrawal_fixture.
///           - `rollup.deployer == EOA`, so `initializeWithdrawalVk` is called by the EOA directly
///             (no factory-deployer issue, unlike the local CREATE2 test).
///
/// @dev Reads the sepolia_* fixtures. The 10-min GRACE_BEFORE_PROCESS_SECS is a fixed contract
///      constant and is unavoidable between requestClose and submitCloseIntent.
///
/// ⚠️ NOT A PRODUCTION DEPLOYER — and, since 2026-08-13, that is ENFORCED by the
/// `block.chainid == SETTLEMENT_LOCAL_DEVNET_CHAIN_ID` guard at the top of `run()`, not asserted by
/// this comment. See the SECURITY note on that guard for the three independent reasons a deployment
/// from this script cannot work on a public chain, and why option (a) — "just key the four
/// settlement VKs here too" — could not have made it work. Use `DeployCloseCli.s.sol` for any
/// deployment that must actually settle.
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
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_lifecycle_validity_mle.json"));
    }
    function _wJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_withdrawal_mle.json"));
    }
    function _lcJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_lifecycle.json"));
    }

    /// @return rollup  the deployed IntmaxRollup
    /// @return manager the deployed ChannelSettlementManager (returned so tests can assert on the
    ///         challenge period this script actually shipped, per chain)
    function run() external returns (IntmaxRollup rollup, ChannelSettlementManager manager) {
        // SECURITY (fund freeze): this script constructs a REAL `ChannelSettlementVerifier` and a
        // REAL `ChannelSettlementManager` and keys NONE of the four settlement VKs, so a channel it
        // deploys can be FROZEN by a member's guarded close request (which flips
        // `isNativeSendAllowed = false`) and then never closed — `submitCloseIntent` reverts
        // `CloseVkNotSet()` — and never un-frozen — `cancelClose` reverts `CancelCloseVkNotSet()`.
        // `initializeCloseVk` is deployer-only-and-set-once on a verifier this script does not
        // return, and `ChannelSettlementManager.verifier` is immutable, so the channel cannot be
        // repaired after the fact. Its members' funds are stranded.
        //
        // WHY A HARD CHAIN-ID GATE AND NOT "KEY THE VKs HERE TOO" (the alternative fix):
        //   1. Keying the four settlement VKs would NOT make a real-chain deployment work. This
        //      script takes its validity VK, withdrawal VK and genesis root from the four
        //      `sepolia_*` fixtures, which are one circuit generation STALE (pre-Falcon; regenerated
        //      at 89cd044 while everything else was regenerated at 2e418f6 — see
        //      doc/tasks/falcon-sig-phase5-notes.md "STOP 1"). A rollup born with those is a rollup
        //      no current proof verifies against. Fixing that is a Rust fixture regeneration, not an
        //      edit to this file, so no change confined to `contracts/` can make this script produce
        //      a working public-chain deployment.
        //   2. Nothing legitimately needs it on a public chain. `DeployCloseCli.s.sol` is the
        //      real-network settlement deployer (doc/docs/deploy-runbook.md, and it is what
        //      `tests/close_lifecycle_cli_e2e.rs` / `tests/two_token_cli_e2e.rs` drive); the only
        //      recorded uses of THIS script (doc/tasks/a3-p4-withdraw-plan.md,
        //      doc/tasks/a3-p5-plus-plan.md) are anvil runs, and its Sepolia driver
        //      `RunClose.s.sol` reads `sepolia_close_intent*.json`, which do not exist in the repo.
        //   3. The "predict the manager address by dry-running against Sepolia" rationale in the
        //      header does not transfer to the production deployer. A nonce-based CREATE address is
        //      a function of the EOA's nonce, and `DeployCloseCli` issues 12 broadcast transactions
        //      before its manager CREATE against this script's 7 (it also keys five VKs), so the
        //      address this script predicts is not the one the production deploy uses. The
        //      prediction is only ever about THIS script's own demo manager — which is now, by this
        //      guard, a devnet object.
        //
        // The chain id is compared against the same `SETTLEMENT_LOCAL_DEVNET_CHAIN_ID` the manager's
        // constructor uses, so "local" cannot mean two different things in this repo. This matches
        // the existing hard-gate idiom in `DeployWalletSettlement.s.sol` /
        // `DeployPartialWithdrawalE2E.s.sol` (a bare `require` at the top of `run()`), NOT the
        // `FRAUD_TREASURY` fallback check below, which only fires when the env var is unset.
        require(
            block.chainid == SETTLEMENT_LOCAL_DEVNET_CHAIN_ID,
            "local-devnet only: this script keys no settlement VKs and reads stale fixtures -- use DeployCloseCli.s.sol"
        );
        string memory vkJson = _vJson();
        string memory lcJson = _lcJson();
        bytes32 genesis = vm.parseJsonBytes32(lcJson, ".genesis_state_root");
        // SECURITY (#6): require FRAUD_TREASURY on real chains; anvil (31337) may default it.
        address fraudTreasury = vm.envOr("FRAUD_TREASURY", address(0));
        if (fraudTreasury == address(0)) {
            require(block.chainid == 31337, "FRAUD_TREASURY must be set for non-local deploys");
            fraudTreasury = msg.sender;
        }

        vm.startBroadcast();

        MleVerifier verifier = new MleVerifier(FixtureLib.mleVerifierChainId());
        IntmaxRollup.MleVk memory vvk = FixtureLib.buildMleVk(vkJson, verifier);
        FixtureLib.DeployData memory vdd = FixtureLib.parseDeployData(vkJson);
        rollup = new IntmaxRollup(
            fraudTreasury, vvk, vdd.whirParams, vdd.protocolId, vdd.sessionId,
            vdd.kIs, vdd.subgroupGenPowers, verifier, genesis,
            false // SECURITY (A-2): production — reject a disabled (degreeBits==0) validity VK
        );
        // Pin the KZG blob-binding satellite (EIP-170 relief; fraudProof binding is fail-closed until set).
        rollup.setKzgVerifier(new BlobKZGVerifierExt());
        // Authorize the block producer (posting is permissioned; the whitelist is empty until set).
        rollup.setBlockProducer(vm.envOr("BLOCK_PRODUCER", msg.sender), true);

        ChannelSettlementVerifier sv = new ChannelSettlementVerifier();
        CloseFundingMaterializer materializer = new CloseFundingMaterializer(rollup);

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
            bytes4(channelId), bpSlot, sphincs[bpSlot], 0, bytes32(0), DeployConfig.challengePeriodSecs(), SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND, IChannelSettlementVerifier(address(sv)), IChannelRegistry(address(rollup)),
            address(materializer), bindings
        );

        // Withdrawal VK (deployer == EOA == msg.sender here, so the deployer-only guard passes).
        {
            string memory wJson = _wJson();
            FixtureLib.DeployData memory wdd = FixtureLib.parseDeployData(wJson);
            IntmaxRollup.MleVk memory wvk = FixtureLib.buildMleVk(wJson, verifier);
            rollup.initializeWithdrawalVk(wvk, wdd.whirParams, wdd.protocolId, wdd.sessionId, wdd.kIs, wdd.subgroupGenPowers);
        }

        vm.stopBroadcast();

        console2.log("=== close-lifecycle deploy ===");
        console2.log("MleVerifier :", address(verifier));
        console2.log("IntmaxRollup:", address(rollup));
        console2.log("SettlementVerifier:", address(sv));
        console2.log("CloseFundingMaterializer:", address(materializer));
        console2.log("CLOSE_MANAGER_ADDRESS:", address(manager));
        console2.log("baked recipient (sepolia_withdrawal_payout.json):");
        console2.logAddress(vm.parseJsonAddress(
            vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_withdrawal_payout.json")),
            ".withdrawals[0].recipient"
        ));
    }
}
