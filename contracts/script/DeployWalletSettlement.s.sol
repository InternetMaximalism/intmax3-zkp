// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {ChannelSettlementManager, IChannelSettlementVerifier, IChannelRegistry} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";

contract WalletMockMleVerifier {
    function verify(
        MleVerifier.MleProof calldata,
        MleVerifier.VerifyParams memory,
        SpongefishWhirVerify.WhirParams memory,
        bytes32
    ) external pure returns (bool) {
        return true;
    }
}

/// @title Deploy settlement infrastructure for the wallet demo (anvil).
/// @notice Reads an EXISTING IntmaxRollup from env ROLLUP, deploys MockMleVerifier +
///         ChannelSettlementVerifier + ChannelSettlementManager, registers the channel +
///         settlement manager. Member data from `test/data/pw_reg.json`.
contract DeployWalletSettlement is Script {
    uint64 internal constant CHALLENGE_PERIOD = 1;
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 0;
    uint256 internal constant INITIAL_BP_BOND = 0;

    function _read(string memory f) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/", f));
    }

    function run() external {
        string memory reg = _read("pw_reg.json");
        address rollupAddr = vm.envAddress("ROLLUP");
        IntmaxRollup rollup = IntmaxRollup(payable(rollupAddr));

        vm.startBroadcast();

        // 1. Mock MLE verifier (always returns true — local testing only).
        WalletMockMleVerifier mockMle = new WalletMockMleVerifier();

        // 2. ChannelSettlementVerifier with dummy VKs (mock verifier ignores them).
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

        // 3. Register channel on rollup.
        uint32 channelId = uint32(vm.parseJsonUint(reg, ".channel_id"));
        uint8 bpSlot = uint8(vm.parseJsonUint(reg, ".bp_member_slot"));
        uint8 delegateCount = uint8(vm.parseJsonUint(reg, ".delegate_count"));
        bytes32[] memory pkGs = vm.parseJsonBytes32Array(reg, ".member_pk_gs");
        bytes32[] memory pkBs = vm.parseJsonBytes32Array(reg, ".member_pk_bs");
        bytes32[] memory regev = vm.parseJsonBytes32Array(reg, ".regev_pk_digests");
        address[] memory recipients = vm.parseJsonAddressArray(reg, ".recipients");
        rollup.registerChannel(channelId, bpSlot, delegateCount, pkGs, pkBs, regev, recipients);

        // 4. Deploy ChannelSettlementManager with member + delegate bindings.
        uint8 memberCount = uint8(vm.parseJsonUint(reg, ".member_count"));
        ChannelSettlementManager.MemberBinding[] memory mBind =
            new ChannelSettlementManager.MemberBinding[](memberCount);
        for (uint256 i = 0; i < memberCount; i++) {
            mBind[i] = ChannelSettlementManager.MemberBinding({
                pkG: pkGs[i],
                recipient: recipients[i]
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
            bytes4(channelId), bpSlot, pkGs[bpSlot], delegateCount, CHALLENGE_PERIOD,
            SPECIAL_CLOSE_PENALTY, INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(sv)), IChannelRegistry(address(rollup)),
            mBind, dBind
        );

        // 5. Register settlement manager on rollup.
        rollup.registerSettlementManager(address(manager));

        vm.stopBroadcast();

        console2.log("VERIFIER:", address(sv));
        console2.log("MANAGER:", address(manager));
    }
}
