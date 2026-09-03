// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
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
import {FixtureLib} from "../script/FixtureLib.sol";

/// @title Shared deterministic deploy + address-prediction logic for the close-lifecycle e2e.
/// @notice The channel close pays native ETH to the `ChannelSettlementManager`, so the manager's
///         address must be baked into the withdrawal proof before that proof is generated. Six
///         proof-free V2 configuration artifacts let this harness constructor-pin every circuit
///         adapter first. The four parent contracts then use fixed CREATE2 salts and initcodes.
///
/// @dev Adapter cores are ordinary CREATE deployments. The address-printer and lifecycle test live
///      in the same test contract and deploy the six adapters in the same order from a fresh test
///      state, so their adapter addresses and all dependent CREATE2 initcodes are identical. Once
///      full proof fixtures exist, the printer simply reports the manager deployed by `setUp`.
///
/// SECURITY: test/deploy plumbing only; production verification remains constructor-pinned.
abstract contract CloseE2EBase is Test {
    // Canonical deterministic-deployment CREATE2 factory (present on anvil / Foundry).
    address internal constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    bytes32 internal constant SALT_ROLLUP = keccak256("intmax-close-e2e/IntmaxRollup/v2-pinned");
    bytes32 internal constant SALT_SV = keccak256("intmax-close-e2e/SettlementVerifier/v2-pinned");
    bytes32 internal constant SALT_MATERIALIZER = keccak256("intmax-close-e2e/CloseFundingMaterializer/v2");
    bytes32 internal constant SALT_MANAGER = keccak256("intmax-close-e2e/SettlementManager/v2");

    bytes32 internal constant V2_CONFIG_SCHEMA_HASH = keccak256("plonky2-mle-v3-solidity-config");
    bytes32 internal constant V2_FULL_SCHEMA_HASH = keccak256("plonky2-mle-v3-solidity");

    address internal constant FRAUD_TREASURY = address(0xFEED);
    uint64 internal constant CHALLENGE_PERIOD = 1 days;
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 0;
    uint256 internal constant INITIAL_BP_BOND = 0;

    struct PinnedAdapters {
        IPinnedMleVerifierV2 validity;
        IPinnedMleVerifierV2 withdrawal;
        IPinnedMleVerifierV2 close;
        IPinnedMleVerifierV2 withdrawalClaim;
        IPinnedMleVerifierV2 postCloseClaim;
        IPinnedMleVerifierV2 cancelClose;
    }

    function _dataPath(string memory fileName) internal view returns (string memory) {
        return string.concat(vm.projectRoot(), "/test/data/", fileName);
    }

    function _readData(string memory fileName) internal view returns (string memory) {
        return vm.readFile(_dataPath(fileName));
    }

    function _validityJson() internal view returns (string memory) {
        return _readData("close_lifecycle_validity_mle.json");
    }

    function _withdrawalJson() internal view returns (string memory) {
        return _readData("close_withdrawal_mle.json");
    }

    function _lifecycleJson() internal view returns (string memory) {
        return _readData("close_lifecycle.json");
    }

    function _payoutJson() internal view returns (string memory) {
        return _readData("close_withdrawal_payout.json");
    }

    function _validityConfigJson() internal view returns (string memory) {
        return _readData("close_lifecycle_validity_mle_config.json");
    }

    function _withdrawalConfigJson() internal view returns (string memory) {
        return _readData("close_withdrawal_mle_config.json");
    }

    function _closeConfigJson() internal view returns (string memory) {
        return _readData("close_intent_mle_config.json");
    }

    function _withdrawalClaimConfigJson() internal view returns (string memory) {
        return _readData("withdrawal_claim_mle_config.json");
    }

    function _postCloseClaimConfigJson() internal view returns (string memory) {
        return _readData("post_close_claim_mle_config.json");
    }

    function _cancelCloseConfigJson() internal view returns (string memory) {
        return _readData("cancel_close_mle_config.json");
    }

    function _isSchemaFile(string memory fileName, bytes32 expectedSchemaHash) internal view returns (bool) {
        string memory path = _dataPath(fileName);
        if (!vm.exists(path)) return false;
        string memory json = vm.readFile(path);
        return vm.keyExistsJson(json, ".schemaVersion")
            && keccak256(bytes(vm.parseJsonString(json, ".schema"))) == expectedSchemaHash;
    }

    function _v2DeploymentConfigsReady() internal view returns (bool) {
        return _isSchemaFile("close_lifecycle_validity_mle_config.json", V2_CONFIG_SCHEMA_HASH)
            && _isSchemaFile("close_withdrawal_mle_config.json", V2_CONFIG_SCHEMA_HASH)
            && _isSchemaFile("close_intent_mle_config.json", V2_CONFIG_SCHEMA_HASH)
            && _isSchemaFile("withdrawal_claim_mle_config.json", V2_CONFIG_SCHEMA_HASH)
            && _isSchemaFile("post_close_claim_mle_config.json", V2_CONFIG_SCHEMA_HASH)
            && _isSchemaFile("cancel_close_mle_config.json", V2_CONFIG_SCHEMA_HASH);
    }

    function _deployPinnedAdapters() private returns (PinnedAdapters memory adapters) {
        (, PinnedMleVerifierV2 validity) = FixtureLib.deployPinnedMleV2(_validityConfigJson());
        (, PinnedMleVerifierV2 withdrawal) = FixtureLib.deployPinnedMleV2(_withdrawalConfigJson());
        (, PinnedMleVerifierV2 close) = FixtureLib.deployPinnedMleV2(_closeConfigJson());
        (, PinnedMleVerifierV2 withdrawalClaim) = FixtureLib.deployPinnedMleV2(_withdrawalClaimConfigJson());
        (, PinnedMleVerifierV2 postCloseClaim) = FixtureLib.deployPinnedMleV2(_postCloseClaimConfigJson());
        (, PinnedMleVerifierV2 cancelClose) = FixtureLib.deployPinnedMleV2(_cancelCloseConfigJson());

        adapters = PinnedAdapters({
            validity: IPinnedMleVerifierV2(address(validity)),
            withdrawal: IPinnedMleVerifierV2(address(withdrawal)),
            close: IPinnedMleVerifierV2(address(close)),
            withdrawalClaim: IPinnedMleVerifierV2(address(withdrawalClaim)),
            postCloseClaim: IPinnedMleVerifierV2(address(postCloseClaim)),
            cancelClose: IPinnedMleVerifierV2(address(cancelClose))
        });
    }

    function _rollupInitcode(bytes32 genesis, PinnedAdapters memory adapters) internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(IntmaxRollup).creationCode, abi.encode(FRAUD_TREASURY, adapters.validity, adapters.withdrawal, genesis)
        );
    }

    function _settlementVerifierInitcode(PinnedAdapters memory adapters) internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(ChannelSettlementVerifier).creationCode,
            abi.encode(adapters.close, adapters.withdrawalClaim, adapters.postCloseClaim, adapters.cancelClose)
        );
    }

    function _materializerInitcode(address rollupAddr) internal pure returns (bytes memory) {
        return
            abi.encodePacked(type(CloseFundingMaterializer).creationCode, abi.encode(IntmaxRollup(payable(rollupAddr))));
    }

    function _managerInitcode(
        string memory lifecycleJson,
        address settlementVerifierAddr,
        address rollupAddr,
        address materializerAddr
    ) internal pure returns (bytes memory) {
        uint8 bpSlot = uint8(vm.parseJsonUint(lifecycleJson, ".registration.bp_member_slot"));
        bytes32[] memory hashes = vm.parseJsonBytes32Array(lifecycleJson, ".registration.member_pk_gs");
        address[] memory recipients = vm.parseJsonAddressArray(lifecycleJson, ".registration.recipients");
        ChannelSettlementManager.MemberBinding[] memory bindings =
            new ChannelSettlementManager.MemberBinding[](hashes.length);
        for (uint256 i = 0; i < hashes.length; ++i) {
            bindings[i] = ChannelSettlementManager.MemberBinding({pkG: hashes[i], recipient: recipients[i]});
        }
        bytes4 channelId = bytes4(uint32(vm.parseJsonUint(lifecycleJson, ".registration.channel_id")));
        return abi.encodePacked(
            type(ChannelSettlementManager).creationCode,
            abi.encode(
                channelId,
                bpSlot,
                hashes[bpSlot],
                uint16(0),
                bytes32(0),
                CHALLENGE_PERIOD,
                SPECIAL_CLOSE_PENALTY,
                INITIAL_BP_BOND,
                IChannelSettlementVerifier(settlementVerifierAddr),
                IChannelRegistry(rollupAddr),
                materializerAddr,
                bindings
            )
        );
    }

    function _predict(bytes32 salt, bytes memory initcode) internal pure returns (address) {
        return vm.computeCreate2Address(salt, keccak256(initcode), FACTORY);
    }

    /// @notice Deploy the six proof-free adapters in canonical order and predict the manager whose
    ///         address can then be embedded in witness-specific close withdrawal data.
    function predictManagerAddressFrom(string memory lifecycleJson) public returns (address managerAddr) {
        require(_v2DeploymentConfigsReady(), "close v2 config fixtures unavailable");
        PinnedAdapters memory adapters = _deployPinnedAdapters();
        bytes32 genesis = vm.parseJsonBytes32(lifecycleJson, ".genesis_state_root");
        address rollupAddr = _predict(SALT_ROLLUP, _rollupInitcode(genesis, adapters));
        address svAddr = _predict(SALT_SV, _settlementVerifierInitcode(adapters));
        address materializerAddr = _predict(SALT_MATERIALIZER, _materializerInitcode(rollupAddr));
        managerAddr = _predict(SALT_MANAGER, _managerInitcode(lifecycleJson, svAddr, rollupAddr, materializerAddr));
    }

    function _deploy(bytes32 salt, bytes memory initcode) internal returns (address deployed) {
        (bool ok, bytes memory ret) = FACTORY.call(abi.encodePacked(salt, initcode));
        require(ok, "CREATE2 factory deploy failed");
        deployed = address(bytes20(ret));
        require(deployed.code.length > 0, "no code deployed");
    }

    /// @notice Constructor-pin all six circuit adapters, then atomically create the two parents,
    ///         materializer and manager using the same initcodes as the address printer.
    function _deployAll(string memory lifecycleJson)
        internal
        returns (
            IntmaxRollup rollup,
            ChannelSettlementVerifier settlementVerifier,
            CloseFundingMaterializer materializer,
            ChannelSettlementManager manager
        )
    {
        PinnedAdapters memory adapters = _deployPinnedAdapters();
        bytes32 genesis = vm.parseJsonBytes32(lifecycleJson, ".genesis_state_root");
        rollup = IntmaxRollup(payable(_deploy(SALT_ROLLUP, _rollupInitcode(genesis, adapters))));
        settlementVerifier = ChannelSettlementVerifier(_deploy(SALT_SV, _settlementVerifierInitcode(adapters)));
        materializer = CloseFundingMaterializer(_deploy(SALT_MATERIALIZER, _materializerInitcode(address(rollup))));

        uint32 channelId = uint32(vm.parseJsonUint(lifecycleJson, ".registration.channel_id"));
        uint8 bpSlot = uint8(vm.parseJsonUint(lifecycleJson, ".registration.bp_member_slot"));
        bytes32[] memory sphincs = vm.parseJsonBytes32Array(lifecycleJson, ".registration.member_pk_gs");
        bytes32[] memory pkBs = vm.parseJsonBytes32Array(lifecycleJson, ".registration.member_pk_bs");
        bytes32[] memory regev = vm.parseJsonBytes32Array(lifecycleJson, ".registration.regev_pk_digests");
        address[] memory recipients = vm.parseJsonAddressArray(lifecycleJson, ".registration.recipients");
        vm.prank(FACTORY);
        rollup.registerChannel(channelId, bpSlot, 0, sphincs, pkBs, regev, recipients);

        manager = ChannelSettlementManager(
            payable(_deploy(
                    SALT_MANAGER,
                    _managerInitcode(lifecycleJson, address(settlementVerifier), address(rollup), address(materializer))
                ))
        );
    }
}
