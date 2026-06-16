// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {ChannelSettlementManager, IChannelSettlementVerifier, IChannelRegistry} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

/// @title Shared CREATE2 deploy + address-prediction logic for the close-lifecycle e2e.
/// @notice The channel close pays its native ETH to the `ChannelSettlementManager`, so the manager's
///         address must be baked (as the L1 withdrawal recipient) into the close withdrawal PROOF
///         before that proof is generated. To make the address knowable ahead of time, ALL four
///         contracts are deployed through the canonical CREATE2 factory with fixed salts; the
///         factory is the CREATE2 deployer, so `computeCreate2Address` is identical whether called
///         from the off-chain address-printing script (`ComputeCloseManager.s.sol`) or the on-chain
///         lifecycle test (`CloseLifecycleE2E.t.sol`). Both inherit this base so the salts and
///         initcodes — and therefore the computed addresses — cannot diverge.
///
/// SECURITY: this is test/deploy plumbing only; it does not affect on-chain verification logic.
abstract contract CloseE2EBase is Test {
    // Canonical deterministic-deployment CREATE2 factory (present on anvil / Foundry).
    address internal constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    // Fixed salts (any distinct constants; pinned so script + test agree).
    bytes32 internal constant SALT_MV = keccak256("intmax-close-e2e/MleVerifier/v1");
    bytes32 internal constant SALT_ROLLUP = keccak256("intmax-close-e2e/IntmaxRollup/v1");
    bytes32 internal constant SALT_SV = keccak256("intmax-close-e2e/SettlementVerifier/v1");
    bytes32 internal constant SALT_MANAGER = keccak256("intmax-close-e2e/SettlementManager/v1");

    // Fixed constructor constants (must match between address computation and actual deploy).
    address internal constant FRAUD_TREASURY = address(0xFEED);
    uint64 internal constant CHALLENGE_PERIOD = 1 days;
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 0;
    uint256 internal constant INITIAL_BP_BOND = 0;

    // ── Fixture file names (the close set; see generate_withdrawal_fixture WD_OUT_PREFIX=close_) ──
    function _validityJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/close_lifecycle_validity_mle.json"));
    }
    function _withdrawalJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/close_withdrawal_mle.json"));
    }
    function _lifecycleJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/close_lifecycle.json"));
    }
    function _payoutJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/close_withdrawal_payout.json"));
    }

    // ── initcodes ──

    function _mleVerifierInitcode() internal pure returns (bytes memory) {
        return type(MleVerifier).creationCode;
    }

    function _settlementVerifierInitcode() internal pure returns (bytes memory) {
        return type(ChannelSettlementVerifier).creationCode;
    }

    /// IntmaxRollup initcode. `verifierForGatesDigest` only computes the (address-independent)
    /// gatesDigest; the rollup is bound to `mleVerifierAddr` (the CREATE2 MleVerifier).
    function _rollupInitcode(
        string memory vkJson,
        bytes32 genesis,
        address mleVerifierAddr,
        MleVerifier verifierForGatesDigest
    ) internal view returns (bytes memory) {
        FixtureLib.DeployData memory dd = FixtureLib.parseDeployData(vkJson);
        IntmaxRollup.MleVk memory vk = FixtureLib.buildMleVk(vkJson, verifierForGatesDigest);
        return abi.encodePacked(
            type(IntmaxRollup).creationCode,
            abi.encode(
                FRAUD_TREASURY, vk, dd.whirParams, dd.protocolId, dd.sessionId,
                dd.kIs, dd.subgroupGenPowers, MleVerifier(mleVerifierAddr), genesis
            )
        );
    }

    /// ChannelSettlementManager initcode, with member bindings + bp read from the registration.
    function _managerInitcode(
        string memory lifecycleJson,
        address settlementVerifierAddr,
        address rollupAddr
    ) internal pure returns (bytes memory) {
        uint8 bpSlot = uint8(vm.parseJsonUint(lifecycleJson, ".registration.bp_member_slot"));
        bytes32[] memory hashes = vm.parseJsonBytes32Array(lifecycleJson, ".registration.member_pk_gs");
        address[] memory recipients = vm.parseJsonAddressArray(lifecycleJson, ".registration.recipients");
        ChannelSettlementManager.MemberBinding[] memory bindings =
            new ChannelSettlementManager.MemberBinding[](hashes.length);
        for (uint256 i = 0; i < hashes.length; i++) {
            bindings[i] = ChannelSettlementManager.MemberBinding({pkG: hashes[i], recipient: recipients[i]});
        }
        bytes4 channelId = bytes4(uint32(vm.parseJsonUint(lifecycleJson, ".registration.channel_id")));
        return abi.encodePacked(
            type(ChannelSettlementManager).creationCode,
            // Delegate account: `delegateCount_ = 0` (no delegates in this lifecycle fixture), placed
            // 4th to match the constructor (channelId, bpSlot, bpPkG, delegateCount, ...).
            abi.encode(
                channelId, bpSlot, hashes[bpSlot], uint8(0), CHALLENGE_PERIOD, SPECIAL_CLOSE_PENALTY,
                INITIAL_BP_BOND, IChannelSettlementVerifier(settlementVerifierAddr),
                IChannelRegistry(rollupAddr), bindings
            )
        );
    }

    function _predict(bytes32 salt, bytes memory initcode) internal pure returns (address) {
        return vm.computeCreate2Address(salt, keccak256(initcode), FACTORY);
    }

    /// Predict the manager address (the close withdrawal recipient) from a (validity-VK, lifecycle)
    /// fixture pair, WITHOUT deploying anything except a throwaway MleVerifier used only to derive
    /// the gatesDigest.
    /// @dev The VALIDITY VK, genesis state root and channel REGISTRATION are identical between the
    ///      plain P2 fixtures and the close fixtures (same circuit, same empty genesis, same
    ///      deterministic channel-1 member keys). So the address computed from the EXISTING P2
    ///      fixtures (before the close fixtures exist) equals the address the test derives from the
    ///      close fixtures — that's what lets us bake the manager address into the close proof.
    function predictManagerAddressFrom(string memory vkJson, string memory lcJson)
        public returns (address managerAddr)
    {
        MleVerifier tmp = new MleVerifier();
        bytes32 genesis = vm.parseJsonBytes32(lcJson, ".genesis_state_root");
        address mvAddr = _predict(SALT_MV, _mleVerifierInitcode());
        address rollupAddr = _predict(SALT_ROLLUP, _rollupInitcode(vkJson, genesis, mvAddr, tmp));
        address svAddr = _predict(SALT_SV, _settlementVerifierInitcode());
        managerAddr = _predict(SALT_MANAGER, _managerInitcode(lcJson, svAddr, rollupAddr));
    }

    // ── factory deploy ──

    function _deploy(bytes32 salt, bytes memory initcode) internal returns (address a) {
        (bool ok, bytes memory ret) = FACTORY.call(abi.encodePacked(salt, initcode));
        require(ok, "CREATE2 factory deploy failed");
        a = address(bytes20(ret));
        require(a.code.length > 0, "no code deployed");
    }

    /// Deploy MleVerifier → IntmaxRollup → ChannelSettlementVerifier → registerChannel → manager,
    /// all via the canonical CREATE2 factory with the fixed salts. SHARED by the address-printing
    /// script and the lifecycle test so they land at identical addresses (the factory is the CREATE2
    /// deployer, so the result depends only on salt + initcode, both fixed by the given fixtures).
    /// The manager address is the L1 recipient that must be baked into the close withdrawal proof.
    function _deployAll(string memory vkJson, string memory lcJson)
        internal
        returns (
            MleVerifier verifier_,
            IntmaxRollup rollup_,
            ChannelSettlementVerifier sv_,
            ChannelSettlementManager manager_
        )
    {
        bytes32 genesis = vm.parseJsonBytes32(lcJson, ".genesis_state_root");
        verifier_ = MleVerifier(_deploy(SALT_MV, _mleVerifierInitcode()));
        rollup_ = IntmaxRollup(payable(_deploy(SALT_ROLLUP, _rollupInitcode(vkJson, genesis, address(verifier_), verifier_))));
        sv_ = ChannelSettlementVerifier(_deploy(SALT_SV, _settlementVerifierInitcode()));

        // registerChannel BEFORE the manager deploy (manager constructor binds to it, Finding E).
        {
            uint32 channelId = uint32(vm.parseJsonUint(lcJson, ".registration.channel_id"));
            uint8 bpSlot = uint8(vm.parseJsonUint(lcJson, ".registration.bp_member_slot"));
            bytes32[] memory sphincs = vm.parseJsonBytes32Array(lcJson, ".registration.member_pk_gs");
            bytes32[] memory pkBs = vm.parseJsonBytes32Array(lcJson, ".registration.member_pk_bs");
            bytes32[] memory regev = vm.parseJsonBytes32Array(lcJson, ".registration.regev_pk_digests");
            address[] memory recipients = vm.parseJsonAddressArray(lcJson, ".registration.recipients");
            rollup_.registerChannel(channelId, bpSlot, 0, sphincs, pkBs, regev, recipients);
        }

        manager_ = ChannelSettlementManager(
            payable(_deploy(SALT_MANAGER, _managerInitcode(lcJson, address(sv_), address(rollup_))))
        );
    }
}
