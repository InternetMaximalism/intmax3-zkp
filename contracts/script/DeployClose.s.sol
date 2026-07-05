// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {ChannelSettlementManager, IChannelSettlementVerifier, IChannelRegistry} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title Deploy the full close-lifecycle stack to Sepolia (or dry-run to learn the manager address).
/// @notice Plain nonce-based `new` deploys (deployer = the broadcasting EOA), so:
///           - the manager's CREATE address depends only on the EOA + nonce (NOT the initcode), so a
///             dry-run (`forge script --sender <EOA> --rpc-url sepolia`, no broadcast, no key) prints
///             the exact address the broadcast will deploy the manager to. Bake THAT into the close
///             withdrawal proof: WD_RECIPIENT=<manager> WD_OUT_PREFIX=close_ cargo run --release
///             --bin generate_withdrawal_fixture.
///           - `rollup.deployer == EOA`, so `initializeWithdrawalVk` is called by the EOA directly
///             (no factory-deployer issue, unlike the local CREATE2 test).
///
/// @dev Reads the close_* fixtures. CHALLENGE_PERIOD is short (Sepolia demo) so finalizeClose can
///      proceed quickly; the 10-min GRACE_BEFORE_PROCESS_SECS is a fixed contract constant and is
///      unavoidable between requestClose and submitCloseIntent.
contract DeployClose is Script {
    uint64 internal constant CHALLENGE_PERIOD = 1; // seconds (demo); challengeDeadline ~= +1 block
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
            vdd.kIs, vdd.subgroupGenPowers, verifier, genesis,
            false // SECURITY (A-2): production — reject a disabled (degreeBits==0) validity VK
        );
        // Pin the KZG blob-binding satellite (EIP-170 relief; fraudProof binding is fail-closed until set).
        rollup.setKzgVerifier(new BlobKZGVerifierExt());

        ChannelSettlementVerifier sv = new ChannelSettlementVerifier();

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
        ChannelSettlementManager manager = new ChannelSettlementManager(
            bytes4(channelId), bpSlot, sphincs[bpSlot], 0, CHALLENGE_PERIOD, SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND, IChannelSettlementVerifier(address(sv)), IChannelRegistry(address(rollup)), bindings,
            new ChannelSettlementManager.MemberBinding[](0) // no delegates
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
        console2.log("CLOSE_MANAGER_ADDRESS:", address(manager));
        console2.log("baked recipient (sepolia_withdrawal_payout.json):");
        console2.logAddress(vm.parseJsonAddress(
            vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_withdrawal_payout.json")),
            ".withdrawals[0].recipient"
        ));
    }
}
