// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier,
    IChannelRegistry
} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";
import {DeployConfig} from "./DeployConfig.sol";
import {FixtureLib} from "./FixtureLib.sol";
import {RegRecordLib} from "./RegRecordLib.sol";

/// @title Deploy settlement infrastructure for the wallet demo (anvil).
/// @notice Reads an EXISTING IntmaxRollup from env ROLLUP, deploys four circuit-specific pinned
///         v2 adapters plus ChannelSettlementVerifier/Manager, and registers the channel and
///         settlement manager. Member data comes from `test/data/pw_reg.json`.
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
        // This wallet-demo deployer remains deliberately local-only. It now uses the real compact
        // v2 verification boundary, but its surrounding workflow and short challenge window are
        // still anvil-specific and are not a reviewed release manifest.
        require(block.chainid == 31337, "local-devnet only: wallet settlement demo");
        RegRecordLib.Record memory r = RegRecordLib.parse(_read("pw_reg.json"));
        string memory closeJson = _read("close_intent_mle_config.json");
        string memory withdrawalClaimJson = _read("withdrawal_claim_mle_config.json");
        string memory postCloseClaimJson = _read("post_close_claim_mle_config.json");
        string memory cancelCloseJson = _read("cancel_close_mle_config.json");
        address rollupAddr = vm.envAddress("ROLLUP");
        rollup = IntmaxRollup(payable(rollupAddr));

        vm.startBroadcast();

        // Each adapter owns one complete immutable circuit VK/configuration. All four exist before
        // the ChannelSettlementVerifier constructor runs, so there is no uninitialized interval.
        (, PinnedMleVerifierV2 closeVerifier) = FixtureLib.deployPinnedMleV2(closeJson);
        (, PinnedMleVerifierV2 withdrawalClaimVerifier) = FixtureLib.deployPinnedMleV2(withdrawalClaimJson);
        (, PinnedMleVerifierV2 postCloseClaimVerifier) = FixtureLib.deployPinnedMleV2(postCloseClaimJson);
        (, PinnedMleVerifierV2 cancelCloseVerifier) = FixtureLib.deployPinnedMleV2(cancelCloseJson);
        sv = new ChannelSettlementVerifier(
            IPinnedMleVerifierV2(address(closeVerifier)),
            IPinnedMleVerifierV2(address(withdrawalClaimVerifier)),
            IPinnedMleVerifierV2(address(postCloseClaimVerifier)),
            IPinnedMleVerifierV2(address(cancelCloseVerifier))
        );
        CloseFundingMaterializer materializer = new CloseFundingMaterializer(rollup);

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
            mBind[i] = ChannelSettlementManager.MemberBinding({pkG: r.pkGs[i], recipient: r.recipients[i]});
        }
        manager = new ChannelSettlementManager(
            bytes4(r.channelId),
            r.bpSlot,
            r.pkGs[r.bpSlot],
            r.activeDelegateCount,
            r.participantRoot,
            DeployConfig.challengePeriodSecs(),
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(sv)),
            IChannelRegistry(address(rollup)),
            address(materializer),
            mBind
        );

        // 5. Register settlement manager on rollup.
        rollup.registerSettlementManager(address(manager));

        vm.stopBroadcast();

        console2.log("CLOSE_MLE_V2_ADAPTER:", address(closeVerifier));
        console2.log("WITHDRAWAL_CLAIM_MLE_V2_ADAPTER:", address(withdrawalClaimVerifier));
        console2.log("POST_CLOSE_CLAIM_MLE_V2_ADAPTER:", address(postCloseClaimVerifier));
        console2.log("CANCEL_CLOSE_MLE_V2_ADAPTER:", address(cancelCloseVerifier));
        console2.log("VERIFIER:", address(sv));
        console2.log("CLOSE_FUNDING_MATERIALIZER:", address(materializer));
        console2.log("MANAGER:", address(manager));
    }
}
