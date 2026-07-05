// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {ChannelSettlementManager, IChannelSettlementVerifier, IChannelRegistry} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title A-3 P5-B: deploy the close-lifecycle stack registered with the CLI channel's REAL members.
/// @notice Unlike `DeployClose` (which registers the fixture members from `close_lifecycle.json`),
///         this registers the channel with the members emitted by `channel_member export-reg-record`
///         (`cli_reg_record.json`) and binds the manager to the same members — so the close proof's
///         member-set commitment AND the registration block `withdraw` posts both match this single
///         on-chain registration. The MLE/WHIR VKs are channel/member-INDEPENDENT (they are the
///         circuits' verifier data), so they are taken from the existing `close_*` fixtures and the
///         CLI's freshly-proved (channel-7) close/withdraw proofs verify under them.
/// @dev Run with the broadcasting EOA = deployer (so `initializeWithdrawalVk` / `initializeCloseVk`
///      pass their deployer-only guards). Env: none required; reads contracts/test/data/{close_*,
///      cli_reg_record.json}. Prints the deployed addresses for the driver.
contract DeployCloseCli is Script {
    uint64 internal constant CHALLENGE_PERIOD = 1; // seconds; settle after a tiny evm_increaseTime
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 0;
    uint256 internal constant INITIAL_BP_BOND = 0;

    function _read(string memory f) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/", f));
    }

    function run() external {
        string memory vkJson = _read("close_lifecycle_validity_mle.json");
        string memory lcJson = _read("close_lifecycle.json");
        string memory wJson = _read("close_withdrawal_mle.json");
        string memory cJson = _read("close_intent_mle.json");
        string memory reg = _read("cli_reg_record.json"); // staged into test/data/ by the driver
        bytes32 genesis = vm.parseJsonBytes32(lcJson, ".genesis_state_root");
        address fraudTreasury = vm.envOr("FRAUD_TREASURY", msg.sender);

        vm.startBroadcast();

        // 1. Rollup with the VALIDITY VK + genesis (production: reject a disabled VK).
        MleVerifier verifier = new MleVerifier();
        IntmaxRollup.MleVk memory vvk = FixtureLib.buildMleVk(vkJson, verifier);
        FixtureLib.DeployData memory vdd = FixtureLib.parseDeployData(vkJson);
        IntmaxRollup rollup = new IntmaxRollup(
            fraudTreasury, vvk, vdd.whirParams, vdd.protocolId, vdd.sessionId,
            vdd.kIs, vdd.subgroupGenPowers, verifier, genesis, false
        );
        // Pin the KZG blob-binding satellite (EIP-170 relief; fraudProof binding is fail-closed until set).
        rollup.setKzgVerifier(new BlobKZGVerifierExt());

        // 2. Withdrawal VK (deployer == EOA == msg.sender).
        {
            FixtureLib.DeployData memory wdd = FixtureLib.parseDeployData(wJson);
            IntmaxRollup.MleVk memory wvk = FixtureLib.buildMleVk(wJson, verifier);
            rollup.initializeWithdrawalVk(wvk, wdd.whirParams, wdd.protocolId, wdd.sessionId, wdd.kIs, wdd.subgroupGenPowers);
        }

        // 3. Settlement verifier + the REAL close VK (the close circuit's MLE/WHIR verifier data).
        ChannelSettlementVerifier sv = new ChannelSettlementVerifier();
        {
            FixtureLib.DeployData memory cdd = FixtureLib.parseDeployData(cJson);
            MleVerifier.MleProof memory cproof = FixtureLib.parseProof(cJson);
            bytes32 gatesDigest = verifier.computeGatesDigest(
                cproof.gates,
                cproof.witnessIndividualEvalsAtRGateV2.length,
                cproof.numSelectors,
                cproof.numGateConstraints,
                cproof.quotientDegreeFactor
            );
            ChannelSettlementVerifier.CloseVk memory cvk = ChannelSettlementVerifier.CloseVk({
                degreeBits: cdd.degreeBits,
                preprocessedRoot: cdd.preCommitRoot,
                numConstants: cdd.numConstants,
                numRoutedWires: cdd.numRoutedWires,
                gatesDigest: gatesDigest
            });
            sv.initializeCloseVk(verifier, cvk, cdd.whirParams, cdd.protocolId, cdd.sessionId, cdd.kIs, cdd.subgroupGenPowers);
        }

        // 3b. Withdrawal-claim VK (the claim circuit's MLE/WHIR verifier data — channel-independent,
        //     taken from the checked-in claim fixture; the CLI's fresh per-member claim proof verifies
        //     under it). Required for `claim` → `submitWithdrawalClaim` → `verifyWithdrawalClaim`.
        {
            string memory wcJson = _read("withdrawal_claim_mle.json");
            FixtureLib.DeployData memory wcdd = FixtureLib.parseDeployData(wcJson);
            MleVerifier.MleProof memory wcproof = FixtureLib.parseProof(wcJson);
            bytes32 wcGatesDigest = verifier.computeGatesDigest(
                wcproof.gates,
                wcproof.witnessIndividualEvalsAtRGateV2.length,
                wcproof.numSelectors,
                wcproof.numGateConstraints,
                wcproof.quotientDegreeFactor
            );
            ChannelSettlementVerifier.StatementVk memory wcvk = ChannelSettlementVerifier.StatementVk({
                degreeBits: wcdd.degreeBits,
                preprocessedRoot: wcdd.preCommitRoot,
                numConstants: wcdd.numConstants,
                numRoutedWires: wcdd.numRoutedWires,
                gatesDigest: wcGatesDigest
            });
            sv.initializeWithdrawalClaimVk(verifier, wcvk, wcdd.whirParams, wcdd.protocolId, wcdd.sessionId, wcdd.kIs, wcdd.subgroupGenPowers);
        }

        // 4. registerChannel with the CLI ACTIVE set (3 members + delegate). The arrays carry all
        //    `member_count + delegate_count` active participants (members first); registerChannel's
        //    close member-set commitment uses only the first `member_count` pk_gs.
        uint32 channelId = uint32(vm.parseJsonUint(reg, ".channel_id"));
        uint8 bpSlot = uint8(vm.parseJsonUint(reg, ".bp_member_slot"));
        uint8 memberCount = uint8(vm.parseJsonUint(reg, ".member_count"));
        uint8 delegateCount = uint8(vm.parseJsonUint(reg, ".delegate_count"));
        bytes32[] memory pkGs = vm.parseJsonBytes32Array(reg, ".member_pk_gs");
        bytes32[] memory pkBs = vm.parseJsonBytes32Array(reg, ".member_pk_bs");
        bytes32[] memory regev = vm.parseJsonBytes32Array(reg, ".regev_pk_digests");
        address[] memory recipients = vm.parseJsonAddressArray(reg, ".recipients");
        rollup.registerChannel(channelId, bpSlot, delegateCount, pkGs, pkBs, regev, recipients);

        // 5. Manager bound to the SAME active set: member bindings (the first `memberCount`) +
        //    delegate bindings (the remainder). The close member-set commitment + delegate_count limb
        //    then match the close proof. Route member slot 0's payout to the broadcasting EOA so a
        //    later member claim is observable.
        ChannelSettlementManager.MemberBinding[] memory mBind =
            new ChannelSettlementManager.MemberBinding[](memberCount);
        for (uint256 i = 0; i < memberCount; i++) {
            mBind[i] = ChannelSettlementManager.MemberBinding({
                pkG: pkGs[i],
                recipient: (i == 0) ? msg.sender : recipients[i]
            });
        }
        ChannelSettlementManager.MemberBinding[] memory dBind =
            new ChannelSettlementManager.MemberBinding[](delegateCount);
        for (uint256 i = 0; i < delegateCount; i++) {
            dBind[i] = ChannelSettlementManager.MemberBinding({
                pkG: pkGs[memberCount + i],
                recipient: recipients[memberCount + i]
            });
        }
        ChannelSettlementManager manager = new ChannelSettlementManager(
            bytes4(channelId), bpSlot, pkGs[bpSlot], delegateCount, CHALLENGE_PERIOD, SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND, IChannelSettlementVerifier(address(sv)), IChannelRegistry(address(rollup)), mBind,
            dBind
        );

        vm.stopBroadcast();

        console2.log("=== close-lifecycle CLI deploy ===");
        console2.log("IntmaxRollup:", address(rollup));
        console2.log("SettlementVerifier:", address(sv));
        console2.log("CLOSE_MANAGER_ADDRESS:", address(manager));
    }
}
