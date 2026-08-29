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
import {DeployConfig} from "./DeployConfig.sol";
import {RegRecordLib} from "./RegRecordLib.sol";

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
        // SECURITY: this script wires an ALWAYS-TRUE mock MLE verifier and a 1-second challenge
        // period. Anything deployed with it has a VACUOUS `_checkCloseProof`, so it must never
        // reach a public chain — and it is reachable from relay tooling pointed at Sepolia.
        // The other deploy scripts already carry a chain-id guard; this one lacked it.
        require(block.chainid == 31337, "local-devnet only: this script deploys mock verifiers");
        string memory mleJson = _read("mle_fixture.json");
        string memory blockJson = _read("block_fixture.json");
        RegRecordLib.Record memory r = RegRecordLib.parse(_read("pw_reg.json"));
        bytes32 genesis = vm.parseJsonBytes32(blockJson, ".genesis_state_root");
        address fraudTreasury = msg.sender;

        vm.startBroadcast();

        // 1. IntmaxRollup with real validity VK (needed for deposit()).
        MleVerifier realVerifier = new MleVerifier();
        IntmaxRollup.MleVk memory vvk = FixtureLib.buildMleVk(mleJson, realVerifier);
        FixtureLib.DeployData memory vdd = FixtureLib.parseDeployData(mleJson);
        rollup = new IntmaxRollup(
            fraudTreasury, vvk, vdd.whirParams, vdd.protocolId, vdd.sessionId,
            vdd.kIs, vdd.subgroupGenPowers, realVerifier, genesis, false
        );
        // Pin the KZG blob-binding satellite (EIP-170 relief; fraudProof binding is fail-closed until set).
        rollup.setKzgVerifier(new BlobKZGVerifierExt(false));
        // Authorize the block producer (posting is permissioned; the whitelist is empty until set).
        rollup.setBlockProducer(vm.envOr("BLOCK_PRODUCER", msg.sender), true);

        // 2. Mock MLE verifier for the settlement side (always returns true).
        E2EMockMleVerifier mockMle = new E2EMockMleVerifier();

        // 3. ChannelSettlementVerifier with dummy VKs (mock verifier ignores them).
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

        // 4. Register channel on rollup — COSIGNERS ONLY (Option B). See the long note in
        //    `RegRecordLib`: the registration record's delegate count is a CONSTANT zero, because
        //    the validity `channel_reg_step` circuit constrains that limb to zero and would refuse
        //    to fold anything else. This driver's record carries no delegates today
        //    (`active_delegate_count = 0`, `tests/partial_withdrawal_e2e.rs`), so this is a no-op
        //    for it — it is wired through the shared reader so it CANNOT become live-count
        //    passthrough if that driver ever grows a delegate.
        rollup.registerChannel{value: 0.003 ether}(
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
            mBind[i] = ChannelSettlementManager.MemberBinding({
                pkG: r.pkGs[i],
                recipient: r.recipients[i]
            });
        }
        manager = new ChannelSettlementManager(
            bytes4(r.channelId), r.bpSlot, r.pkGs[r.bpSlot], r.activeDelegateCount,
            DeployConfig.challengePeriodSecs(),
            SPECIAL_CLOSE_PENALTY, INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(sv)), IChannelRegistry(address(rollup)),
            mBind, new ChannelSettlementManager.MemberBinding[](0)
        );

        // 6. Register settlement manager on rollup (critical for authorizePartialWithdrawal).
        rollup.registerSettlementManager(address(manager));

        // 7. The remaining two settlement VK latches — see the identical note in
        //    `DeployWalletSettlement.s.sol`. `verifyWithdrawalClaim` / `verifyPostCloseClaim` each
        //    gate on their own latch, so a stack keyed with only close + cancelClose can close but
        //    cannot pay out claims. Appended AFTER the manager CREATE so no deployed address moves.
        //    Placeholder values: the wired verifier is `E2EMockMleVerifier` and this script is
        //    hard-gated to chain id 31337.
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

        console2.log("IntmaxRollup:", address(rollup));
        console2.log("SettlementVerifier:", address(sv));
        console2.log("MANAGER:", address(manager));
    }
}
