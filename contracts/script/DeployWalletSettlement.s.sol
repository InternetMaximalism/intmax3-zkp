// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {ChannelSettlementManager, IChannelSettlementVerifier, IChannelRegistry} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {DeployConfig} from "./DeployConfig.sol";

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
    // SECURITY (challenge-period floor): sourced from `DeployConfig` rather than hardcoded, so if
    // the `block.chainid == 31337` guard below is ever loosened, the challenge period hardens
    // automatically instead of silently shipping a 1-second window. Defence in depth only — the
    // manager's constructor rejects a sub-floor period off-devnet regardless.
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 0;
    uint256 internal constant INITIAL_BP_BOND = 0;

    function _read(string memory f) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/", f));
    }

    function run() external {
        // SECURITY: this script wires an ALWAYS-TRUE mock MLE verifier and a 1-second challenge
        // period. Anything deployed with it has a VACUOUS `_checkCloseProof`, so it must never
        // reach a public chain — and it is reachable from relay tooling pointed at Sepolia.
        // The other deploy scripts already carry a chain-id guard; this one lacked it.
        require(block.chainid == 31337, "local-devnet only: this script deploys mock verifiers");
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
            bytes4(channelId), bpSlot, pkGs[bpSlot], delegateCount, DeployConfig.challengePeriodSecs(),
            SPECIAL_CLOSE_PENALTY, INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(sv)), IChannelRegistry(address(rollup)),
            mBind, dBind
        );

        // 5. Register settlement manager on rollup.
        rollup.registerSettlementManager(address(manager));

        // 6. The remaining two settlement VK latches.
        //
        // SECURITY / LIVENESS: `ChannelSettlementVerifier` gates each statement on its OWN latch —
        // `verifyWithdrawalClaim` reverts `WithdrawalClaimVkNotSet()` and `verifyPostCloseClaim`
        // reverts `PostCloseClaimVkNotSet()`. This script keyed only close + cancelClose, so the
        // `claim` step of the wallet demo's own `full_withdrawal` ticket
        // (`{deploy, close, settle, withdraw, claim}`) could never succeed on a stack it deployed:
        // members could close the channel and then not collect. Same defect class as audit622 A-M4.
        // Deliberately placed AFTER the manager CREATE so it adds no CREATE and cannot move any
        // deployed address (the drivers read `MANAGER:` from the log and fixtures bake it).
        //
        // The values are placeholders because the verifier wired above is `WalletMockMleVerifier`,
        // which returns true unconditionally — this whole script is already hard-gated to chain id
        // 31337 for exactly that reason. No fail-closed check is weakened: the latches still gate,
        // and the SOUNDNESS of these statements on this stack rests on the devnet gate, not on the
        // VK contents.
        {
            ChannelSettlementVerifier.StatementVk memory svk = ChannelSettlementVerifier.StatementVk({
                degreeBits: 1,
                preprocessedRoot: bytes32(uint256(1)),
                numConstants: 1,
                numRoutedWires: 1,
                gatesDigest: bytes32(uint256(2))
            });
            SpongefishWhirVerify.WhirParams memory whir;
            sv.initializeWithdrawalClaimVk(
                MleVerifier(address(mockMle)), svk, whir, hex"", hex"",
                new uint256[](0), new uint256[](0)
            );
            sv.initializePostCloseClaimVk(
                MleVerifier(address(mockMle)), svk, whir, hex"", hex"",
                new uint256[](0), new uint256[](0)
            );
        }

        vm.stopBroadcast();

        console2.log("VERIFIER:", address(sv));
        console2.log("MANAGER:", address(manager));
    }
}
