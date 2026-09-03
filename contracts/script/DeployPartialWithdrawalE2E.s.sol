// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier,
    IChannelRegistry
} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";
import {FixtureLib} from "./FixtureLib.sol";
import {DeployConfig} from "./DeployConfig.sol";
import {RegRecordLib} from "./RegRecordLib.sol";

/// @title Deploy the full partial-withdrawal E2E stack on anvil.
/// @notice Deploys IntmaxRollup plus six circuit-specific pinned v2 adapters,
///         ChannelSettlementVerifier and ChannelSettlementManager. Reads member registration
///         from `test/data/pw_reg.json` (written by the Rust E2E driver).
contract DeployPartialWithdrawalE2E is Script {
    // SECURITY (challenge-period floor): sourced from `DeployConfig` rather than hardcoded, so if
    // the `block.chainid == 31337` guard below is ever loosened, the challenge period hardens
    // automatically instead of silently shipping a 1-second window. Defence in depth only — the
    // manager's constructor rejects a sub-floor period off-devnet regardless.
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 0;
    uint256 internal constant INITIAL_BP_BOND = 0;

    function _read(string memory f) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/", f));
    }

    /// @return rollup  the deployed IntmaxRollup
    /// @return sv      the deployed ChannelSettlementVerifier
    /// @return manager the deployed ChannelSettlementManager, registered on `rollup`
    /// @dev Returned so `test/DeployGuards.t.sol` can assert on what this script wired. Return
    ///      types are not part of the `run()` selector, so `forge script --sig run` is unaffected.
    function run()
        external
        returns (IntmaxRollup rollup, ChannelSettlementVerifier sv, ChannelSettlementManager manager)
    {
        // The surrounding E2E workflow and short challenge window remain anvil-specific even
        // though every proof boundary below now uses a real pinned compact-v2 verifier.
        require(block.chainid == 31337, "local-devnet only: partial-withdrawal E2E");
        string memory mleJson = _read("mle_fixture_config.json");
        string memory withdrawalJson = _read("withdrawal_mle_config.json");
        string memory closeJson = _read("close_intent_mle_config.json");
        string memory withdrawalClaimJson = _read("withdrawal_claim_mle_config.json");
        string memory postCloseClaimJson = _read("post_close_claim_mle_config.json");
        string memory cancelCloseJson = _read("cancel_close_mle_config.json");
        string memory blockJson = _read("block_fixture.json");
        RegRecordLib.Record memory r = RegRecordLib.parse(_read("pw_reg.json"));
        bytes32 genesis = vm.parseJsonBytes32(blockJson, ".genesis_state_root");
        address fraudTreasury = msg.sender;

        vm.startBroadcast();

        // 1. IntmaxRollup with validity and withdrawal circuits pinned atomically.
        (, PinnedMleVerifierV2 validityVerifier) = FixtureLib.deployPinnedMleV2(mleJson);
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

        // 2. Four independent channel-statement adapters, all present before the atomic verifier
        // constructor. No dummy VK, set-once latch or verification bypass remains.
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

        // 4. Register channel on rollup — COSIGNERS ONLY (Option B). See the long note in
        //    `RegRecordLib`: the registration record's delegate count is a CONSTANT zero, because
        //    the validity `channel_reg_step` circuit constrains that limb to zero and would refuse
        //    to fold anything else. This driver's record carries no delegates today
        //    (`active_delegate_count = 0`, `tests/partial_withdrawal_e2e.rs`), so this is a no-op
        //    for it — it is wired through the shared reader so it CANNOT become live-count
        //    passthrough if that driver ever grows a delegate.
        rollup.registerChannel(
            r.channelId,
            r.bpSlot,
            RegRecordLib.REGISTRATION_DELEGATE_COUNT,
            RegRecordLib.regPkGs(r),
            RegRecordLib.regPkBs(r),
            RegRecordLib.regRegevDigests(r),
            RegRecordLib.regRecipients(r)
        );

        // 5. Deploy ChannelSettlementManager with member bindings.
        //
        // SECURITY (B-2): `activeDelegateCount` is the LIVE count from the record — NOT the zero
        // registered above — because it is the close/partial-withdrawal delegate floor, and the
        // constructor requires `delegateBindings.length == activeDelegateCount`. This script binds
        // no delegates, so a record with `active_delegate_count > 0` FAILS CLOSED here
        // (`InvalidMemberCount`) rather than deploying a manager whose floor names delegates it
        // never bound.
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

        // 6. Register settlement manager on rollup (critical for authorizePartialWithdrawal).
        rollup.registerSettlementManager(address(manager));

        vm.stopBroadcast();

        console2.log("Validity MLE v2 adapter:", address(validityVerifier));
        console2.log("Withdrawal MLE v2 adapter:", address(withdrawalVerifier));
        console2.log("Close MLE v2 adapter:", address(closeVerifier));
        console2.log("Withdrawal-claim MLE v2 adapter:", address(withdrawalClaimVerifier));
        console2.log("Post-close-claim MLE v2 adapter:", address(postCloseClaimVerifier));
        console2.log("Cancel-close MLE v2 adapter:", address(cancelCloseVerifier));
        console2.log("IntmaxRollup:", address(rollup));
        console2.log("SettlementVerifier:", address(sv));
        console2.log("CloseFundingMaterializer:", address(materializer));
        console2.log("MANAGER:", address(manager));
    }
}
