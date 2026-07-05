// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {ChannelSettlementManager, IChannelSettlementVerifier, IChannelRegistry} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @dev Drop-in mock for MleVerifier — always returns true. Identical to test/CloseTestLib.sol's
///      MockMleVerifier but inlined here to avoid cross-directory imports.
contract E2EMockMleVerifier {
    function verify(
        MleVerifier.MleProof calldata,
        MleVerifier.VerifyParams memory,
        SpongefishWhirVerify.WhirParams memory,
        bytes32
    ) external pure returns (bool) {
        return true;
    }
}

/// @title Deploy the full partial-withdrawal E2E stack on anvil.
/// @notice Deploys IntmaxRollup (real MLE VK for deposits) + MockMleVerifier (settlement side) +
///         ChannelSettlementVerifier + ChannelSettlementManager. Reads member registration from
///         `test/data/pw_reg.json` (written by the Rust E2E driver).
contract DeployPartialWithdrawalE2E is Script {
    uint64 internal constant CHALLENGE_PERIOD = 1;
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 0;
    uint256 internal constant INITIAL_BP_BOND = 0;

    function _read(string memory f) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/", f));
    }

    function run() external {
        string memory mleJson = _read("mle_fixture.json");
        string memory blockJson = _read("block_fixture.json");
        string memory reg = _read("pw_reg.json");
        bytes32 genesis = vm.parseJsonBytes32(blockJson, ".genesis_state_root");
        address fraudTreasury = msg.sender;

        vm.startBroadcast();

        // 1. IntmaxRollup with real validity VK (needed for deposit()).
        MleVerifier realVerifier = new MleVerifier();
        IntmaxRollup.MleVk memory vvk = FixtureLib.buildMleVk(mleJson, realVerifier);
        FixtureLib.DeployData memory vdd = FixtureLib.parseDeployData(mleJson);
        IntmaxRollup rollup = new IntmaxRollup(
            fraudTreasury, vvk, vdd.whirParams, vdd.protocolId, vdd.sessionId,
            vdd.kIs, vdd.subgroupGenPowers, realVerifier, genesis, false
        );
        // Pin the KZG blob-binding satellite (EIP-170 relief; fraudProof binding is fail-closed until set).
        rollup.setKzgVerifier(new BlobKZGVerifierExt());

        // 2. Mock MLE verifier for the settlement side (always returns true).
        E2EMockMleVerifier mockMle = new E2EMockMleVerifier();

        // 3. ChannelSettlementVerifier with dummy VKs (mock verifier ignores them).
        ChannelSettlementVerifier sv = new ChannelSettlementVerifier();
        {
            ChannelSettlementVerifier.CloseVk memory cvk = ChannelSettlementVerifier.CloseVk({
                degreeBits: 1,
                preprocessedRoot: bytes32(uint256(1)),
                numConstants: 1,
                numRoutedWires: 1,
                gatesDigest: bytes32(uint256(2))
            });
            SpongefishWhirVerify.WhirParams memory whir;
            sv.initializeCloseVk(
                MleVerifier(address(mockMle)), cvk, whir, hex"", hex"",
                new uint256[](0), new uint256[](0)
            );
        }
        {
            ChannelSettlementVerifier.StatementVk memory svk = ChannelSettlementVerifier.StatementVk({
                degreeBits: 1,
                preprocessedRoot: bytes32(uint256(1)),
                numConstants: 1,
                numRoutedWires: 1,
                gatesDigest: bytes32(uint256(2))
            });
            SpongefishWhirVerify.WhirParams memory whir;
            sv.initializeCancelCloseVk(
                MleVerifier(address(mockMle)), svk, whir, hex"", hex"",
                new uint256[](0), new uint256[](0)
            );
        }

        // 4. Register channel on rollup.
        uint32 channelId = uint32(vm.parseJsonUint(reg, ".channel_id"));
        uint8 bpSlot = uint8(vm.parseJsonUint(reg, ".bp_member_slot"));
        uint8 delegateCount = uint8(vm.parseJsonUint(reg, ".delegate_count"));
        bytes32[] memory pkGs = vm.parseJsonBytes32Array(reg, ".member_pk_gs");
        bytes32[] memory pkBs = vm.parseJsonBytes32Array(reg, ".member_pk_bs");
        bytes32[] memory regev = vm.parseJsonBytes32Array(reg, ".regev_pk_digests");
        address[] memory recipients = vm.parseJsonAddressArray(reg, ".recipients");
        rollup.registerChannel(channelId, bpSlot, delegateCount, pkGs, pkBs, regev, recipients);

        // 5. Deploy ChannelSettlementManager with member bindings.
        uint8 memberCount = uint8(vm.parseJsonUint(reg, ".member_count"));
        ChannelSettlementManager.MemberBinding[] memory mBind =
            new ChannelSettlementManager.MemberBinding[](memberCount);
        for (uint256 i = 0; i < memberCount; i++) {
            mBind[i] = ChannelSettlementManager.MemberBinding({
                pkG: pkGs[i],
                recipient: recipients[i]
            });
        }
        ChannelSettlementManager manager = new ChannelSettlementManager(
            bytes4(channelId), bpSlot, pkGs[bpSlot], delegateCount, CHALLENGE_PERIOD,
            SPECIAL_CLOSE_PENALTY, INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(sv)), IChannelRegistry(address(rollup)),
            mBind, new ChannelSettlementManager.MemberBinding[](0)
        );

        // 6. Register settlement manager on rollup (critical for authorizePartialWithdrawal).
        rollup.registerSettlementManager(address(manager));

        vm.stopBroadcast();

        console2.log("IntmaxRollup:", address(rollup));
        console2.log("SettlementVerifier:", address(sv));
        console2.log("MANAGER:", address(manager));
    }
}
