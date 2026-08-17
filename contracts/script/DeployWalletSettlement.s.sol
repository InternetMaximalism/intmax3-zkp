// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {ChannelSettlementManager, IChannelSettlementVerifier, IChannelRegistry} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {DeployConfig} from "./DeployConfig.sol";
import {RegRecordLib} from "./RegRecordLib.sol";

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

    /// `virtual` so `test/DeployGuards.t.sol` can execute THIS script verbatim against a
    /// checked-in stand-in record (the live one is staged at run time by the Rust driver and is
    /// therefore untracked, and `foundry.toml` grants read-only fs access). File bytes only — no
    /// behaviour is stubbed.
    function _read(string memory f) internal view virtual returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/", f));
    }

    function run()
        external
        returns (IntmaxRollup rollup, ChannelSettlementVerifier sv, ChannelSettlementManager manager)
    {
        // SECURITY: this script wires an ALWAYS-TRUE mock MLE verifier and a 1-second challenge
        // period. Anything deployed with it has a VACUOUS `_checkCloseProof`, so it must never
        // reach a public chain — and it is reachable from relay tooling pointed at Sepolia.
        // The other deploy scripts already carry a chain-id guard; this one lacked it.
        require(block.chainid == 31337, "local-devnet only: this script deploys mock verifiers");
        RegRecordLib.Record memory r = RegRecordLib.parse(_read("pw_reg.json"));
        address rollupAddr = vm.envAddress("ROLLUP");
        rollup = IntmaxRollup(payable(rollupAddr));

        vm.startBroadcast();

        // 1. Mock MLE verifier (always returns true — local testing only).
        WalletMockMleVerifier mockMle = new WalletMockMleVerifier();

        // 2. ChannelSettlementVerifier with dummy VKs (mock verifier ignores them).
        sv = new ChannelSettlementVerifier();
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

        // 3. Register the channel on the rollup — COSIGNERS ONLY.
        //
        // SECURITY (Option B): the L1 registration record carries the `member_count` co-signing
        // members and a ZERO delegate count, EVEN WHEN the live channel this deploy serves has
        // delegates (the wallet demo's does: `wallet-live-work/chN/channel_snapshot.json` reaches
        // this script with a nonzero `active_delegate_count`). This used to pass the live count and
        // the full active arrays straight through, which produced a registration that
        //   * the validity `channel_reg_step` circuit REFUSES to fold — it constrains the
        //     `delegateCount` limb to zero — leaving the channel unprovable, and
        //   * never matched the preimage the proving side actually builds:
        //     `wallet_core::build_channel_withdrawal` has always registered the cosigner slice with
        //     `delegate_count = 0`.
        // `RegRecordLib.REGISTRATION_DELEGATE_COUNT` is a constant, so no record can reintroduce a
        // delegate here. The delegates are NOT lost — they are bound in step 4 below.
        //
        // NOTHING IS WEAKENED BY THE TRUNCATION: `channelMemberSetCommitment` is the MEMBER-ONLY
        // IMCM commitment over the first `memberCount` pk_gs, and `registerChannel` derives
        // `memberCount = arrays.length - delegateCount`. Cosigner slice + 0 and full arrays + live
        // count both yield the SAME `memberCount` and therefore the SAME commitment the manager
        // constructor binds to. What changes is only what the reg-chain preimage and the
        // `ChannelRegistered` event contain: no delegate slots, and a zero `delegateCount` limb.
        rollup.registerChannel(
            r.channelId,
            r.bpSlot,
            RegRecordLib.REGISTRATION_DELEGATE_COUNT,
            RegRecordLib.regPkGs(r),
            RegRecordLib.regPkBs(r),
            RegRecordLib.regRegevDigests(r),
            RegRecordLib.regRecipients(r)
        );

        // 4. Deploy ChannelSettlementManager with member + delegate bindings.
        //
        // SECURITY (B-2, doc/tasks/b2-delegate-close-threat-model.md): `activeDelegateCount` here is
        // the LIVE count — deliberately NOT the zero registered above. It is the FLOOR the close /
        // partial-withdrawal path checks against close PI limb 94 (`>= activeDelegateCount`), so
        // zeroing it to "match" the registration would silently retire the delegate-close
        // cardinality fence, and it sizes `dBind`, whose entries are the only place a delegate's
        // `registeredRecipientOf` / `isMemberRecipient` binding is written. The two counts mean
        // different things and are read from two different fields for exactly that reason.
        ChannelSettlementManager.MemberBinding[] memory mBind =
            new ChannelSettlementManager.MemberBinding[](r.memberCount);
        for (uint256 i = 0; i < r.memberCount; i++) {
            mBind[i] = ChannelSettlementManager.MemberBinding({
                pkG: r.pkGs[i],
                recipient: r.recipients[i]
            });
        }
        ChannelSettlementManager.MemberBinding[] memory dBind =
            new ChannelSettlementManager.MemberBinding[](r.activeDelegateCount);
        for (uint256 i = 0; i < r.activeDelegateCount; i++) {
            dBind[i] = ChannelSettlementManager.MemberBinding({
                pkG: r.pkGs[r.memberCount + i],
                recipient: r.recipients[r.memberCount + i]
            });
        }
        manager = new ChannelSettlementManager(
            bytes4(r.channelId), r.bpSlot, r.pkGs[r.bpSlot], r.activeDelegateCount,
            DeployConfig.challengePeriodSecs(),
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
