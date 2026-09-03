// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifierV2} from "@mle/MleVerifierV2.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";
import {
    COMPACT_LAYOUT_HASH_V2,
    COMPACT_MAGIC_V2,
    MLE_SCHEMA_VERSION_CURRENT,
    MLE_PROTOCOL_VERSION_CURRENT,
    MLE_PROOF_ABI_SIGNATURE_V2,
    MLE_PROOF_LAYOUT_HASH_V2,
    MAX_COMPACT_PROOF_BYTES_V2,
    WHIR_POW_BITS_V2
} from "@mle/generated/MleWhirV2.sol";

/// @title FixtureLib
/// @notice Canonical strict fixture parser shared by Forge tests and deployment scripts.
/// @dev Keeping canonical compact-V2 proof/config and public-input decoding here ensures every
///      consumer applies the same schema, width, cardinality and field-decoding rules.
///
///      Fixtures are produced by `cargo run --bin generate_e2e_fixture --release`.
///      Cryptographic verification remains inside MleVerifierV2 / IntmaxRollup on-chain.
library FixtureLib {
    // The canonical forge-std cheatcode address.
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    bytes32 private constant FULL_V2_FIXTURE_SCHEMA_HASH = keccak256("plonky2-mle-v3-solidity");
    bytes32 private constant CONFIG_V2_FIXTURE_SCHEMA_HASH = keccak256("plonky2-mle-v3-solidity-config");
    bytes32 private constant CONFIG_V2_ENCODING_HASH = keccak256("abi.encode(MleVerifierV2.VerificationConfig)");

    /// @notice Resolve the immutable execution-chain pin for a new real MLE verifier.
    /// @dev Keep release containment local by default pending independent review.
    ///      A non-31337 deployment therefore requires an explicit `MLE_VERIFIER_CHAIN_ID` opt-in, and
    ///      the MleVerifier constructor independently requires it to equal the
    ///      chain actually executing the deployment.
    function mleVerifierChainId() internal view returns (uint256) {
        // Forge runs test suites concurrently, while `vm.setEnv` mutates the process-wide
        // environment.  Never let a public-chain opt-in from another suite leak into the canonical
        // local test chain.  This does not relax containment: non-local deployments still require
        // the explicit environment pin, and MleVerifierV2 independently checks it against
        // block.chainid in its constructor.
        if (block.chainid == 31337) return 31337;
        return vm.envOr("MLE_VERIFIER_CHAIN_ID", uint256(31337));
    }

    /// Goldilocks base-field modulus. Circuit-digest limbs are field elements, not arbitrary u64s.
    uint256 internal constant GOLDILOCKS_MODULUS = 0xFFFFFFFF00000001;

    // ───────────────────────────── fixture loaders ─────────────────────────────

    function loadMle() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/mle_fixture.json"));
    }

    /// @notice Proof-free validity-circuit deployment artifact.
    /// @dev Deployment must not depend on a witness/proof whose public inputs can contain an
    ///      address created only later in the same rollout.
    function loadMleConfig() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/mle_fixture_config.json"));
    }

    function loadBlock() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/block_fixture.json"));
    }

    /// @notice Proof-free withdrawal-circuit deployment artifact.
    function loadWithdrawalMleConfig() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/withdrawal_mle_config.json"));
    }

    function loadVpi() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/vpi_fixture.json"));
    }

    // ───────────────────────────── high-level builders ─────────────────────────

    /// @notice Deploy one circuit-specific v2 core and its immutable configuration adapter.
    /// @dev The JSON may be either a full proof fixture or the proof-free deployment fixture; both
    ///      share the exact `verificationKey`, `pinnedVerifier`, and encoded-config paths. The core
    ///      constructor re-derives every circuit/WHIR digest from the decoded configuration, and the
    ///      adapter deep-copies that same object. No hand-assembled VK tuple is accepted here.
    function deployPinnedMleV2(string memory json) internal returns (MleVerifierV2 core, PinnedMleVerifierV2 adapter) {
        return deployPinnedMleV2ForChain(json, mleVerifierChainId());
    }

    /// @notice Deploy using an explicit immutable chain pin.
    /// @dev Intended for tests and deployment harnesses that deliberately exercise a non-local
    ///      chain without mutating Forge's process-global environment. MleVerifierV2 still rejects
    ///      any value that differs from the executing block.chainid.
    function deployPinnedMleV2ForChain(string memory json, uint256 allowedChainId)
        internal
        returns (MleVerifierV2 core, PinnedMleVerifierV2 adapter)
    {
        bytes32 schemaHash = keccak256(bytes(vm.parseJsonString(json, ".schema")));
        bool configOnly = schemaHash == CONFIG_V2_FIXTURE_SCHEMA_HASH;
        require(schemaHash == FULL_V2_FIXTURE_SCHEMA_HASH || configOnly, "fixture: v2 schema");
        require(vm.parseJsonUint(json, ".schemaVersion") == MLE_SCHEMA_VERSION_CURRENT, "fixture: current schema version");
        require(vm.parseJsonUint(json, ".protocolVersion") == MLE_PROTOCOL_VERSION_CURRENT, "fixture: current protocol version");
        require(
            vm.parseJsonUint(json, ".verificationKey.protocolVersion") == MLE_PROTOCOL_VERSION_CURRENT,
            "fixture: v2 VK protocol version"
        );
        require(
            keccak256(bytes(vm.parseJsonString(json, ".proofAbiSignature")))
                == keccak256(bytes(MLE_PROOF_ABI_SIGNATURE_V2)),
            "fixture: v2 proof ABI signature"
        );
        require(vm.parseJsonBytes32(json, ".proofLayoutHash") == MLE_PROOF_LAYOUT_HASH_V2, "fixture: v2 layout hash");
        if (configOnly) {
            require(
                vm.parseJsonBytes32(json, ".compactLayoutHash") == COMPACT_LAYOUT_HASH_V2,
                "fixture: v2 compact layout hash"
            );
            require(
                keccak256(bytes(vm.parseJsonString(json, ".compactProofEncoding")))
                    == keccak256(abi.encodePacked(COMPACT_MAGIC_V2)),
                "fixture: v2 compact encoding"
            );
            require(vm.parseJsonUint(json, ".whirPowBits") == WHIR_POW_BITS_V2, "fixture: v2 WHIR PoW");
        } else {
            require(
                vm.parseJsonUint(json, ".proof.protocolVersion") == MLE_PROTOCOL_VERSION_CURRENT,
                "fixture: v2 proof protocol version"
            );
        }
        require(
            keccak256(bytes(vm.parseJsonString(json, ".solidityAbiVerificationConfig.encoding")))
                == CONFIG_V2_ENCODING_HASH,
            "fixture: v2 config encoding"
        );

        bytes memory encodedConfig = vm.parseJsonBytes(json, ".solidityAbiVerificationConfig.bytes");
        require(
            encodedConfig.length == vm.parseJsonUint(json, ".solidityAbiVerificationConfig.byteLength"),
            "fixture: v2 config length"
        );
        bytes32 configHash = keccak256(encodedConfig);
        require(
            configHash == vm.parseJsonBytes32(json, ".solidityAbiVerificationConfig.keccak256"),
            "fixture: v2 config hash"
        );
        require(
            configHash == vm.parseJsonBytes32(json, ".pinnedVerifier.verificationConfigDigest"),
            "fixture: v2 pinned config hash"
        );
        MleVerifierV2.VerificationConfig memory config = abi.decode(encodedConfig, (MleVerifierV2.VerificationConfig));
        bytes memory canonicalConfig = abi.encode(config);
        require(
            canonicalConfig.length == encodedConfig.length && keccak256(canonicalConfig) == configHash,
            "fixture: non-canonical v2 config"
        );

        _requireV2PinnedFixtureViews(json, config);

        bytes memory protocolId = vm.parseJsonBytes(json, ".pinnedVerifier.whirProtocolId");
        require(protocolId.length == 64, "fixture: v2 WHIR protocol id length");
        bytes32[2] memory protocolWords;
        assembly ("memory-safe") {
            mstore(protocolWords, mload(add(protocolId, 0x20)))
            mstore(add(protocolWords, 0x20), mload(add(protocolId, 0x40)))
        }
        bytes32 sessionId = vm.parseJsonBytes32(json, ".pinnedVerifier.whirSessionId");

        string[] memory digestStrings = vm.parseJsonStringArray(json, ".pinnedVerifier.circuitDigest");
        require(digestStrings.length == 4, "fixture: v2 circuit digest length");
        uint64[4] memory circuitDigest;
        for (uint256 i = 0; i < 4; ++i) {
            uint256 limb = vm.parseUint(digestStrings[i]);
            require(limb < GOLDILOCKS_MODULUS, "fixture: v2 circuit digest limb");
            circuitDigest[i] = uint64(limb);
        }

        core = new MleVerifierV2(
            allowedChainId,
            vm.parseJsonBytes32(json, ".pinnedVerifier.preprocessedCommitmentRoot"),
            protocolWords,
            sessionId,
            circuitDigest,
            config
        );
        adapter = new PinnedMleVerifierV2(core, config);
        require(core.circuitConfigDigest() == vm.parseJsonBytes32(json, ".pinnedVerifier.circuitConfigDigest"));
        require(core.whirParametersDigest() == vm.parseJsonBytes32(json, ".pinnedVerifier.whirParametersDigest"));
        require(core.verificationConfigDigest() == configHash);
    }

    /// @notice Parse the unique proof bytes used by calldata, proof DA, attestation and fraud.
    function parseCompactProofV2(string memory json) internal pure returns (bytes memory compactProof) {
        require(
            keccak256(bytes(vm.parseJsonString(json, ".schema"))) == FULL_V2_FIXTURE_SCHEMA_HASH,
            "fixture: v2 proof schema"
        );
        require(vm.parseJsonUint(json, ".schemaVersion") == MLE_SCHEMA_VERSION_CURRENT, "fixture: current schema version");
        require(vm.parseJsonUint(json, ".protocolVersion") == MLE_PROTOCOL_VERSION_CURRENT, "fixture: current protocol version");
        require(
            vm.parseJsonUint(json, ".proof.protocolVersion") == MLE_PROTOCOL_VERSION_CURRENT,
            "fixture: v2 proof protocol version"
        );
        require(
            vm.parseJsonUint(json, ".verificationKey.protocolVersion") == MLE_PROTOCOL_VERSION_CURRENT,
            "fixture: v2 VK protocol version"
        );
        require(
            keccak256(bytes(vm.parseJsonString(json, ".proofAbiSignature")))
                == keccak256(bytes(MLE_PROOF_ABI_SIGNATURE_V2)),
            "fixture: v2 proof ABI signature"
        );
        require(vm.parseJsonBytes32(json, ".proofLayoutHash") == MLE_PROOF_LAYOUT_HASH_V2, "fixture: v2 layout hash");
        require(
            keccak256(bytes(vm.parseJsonString(json, ".compactProof.encoding")))
                == keccak256(abi.encodePacked(COMPACT_MAGIC_V2)),
            "fixture: compact encoding"
        );
        compactProof = vm.parseJsonBytes(json, ".compactProof.bytes");
        require(compactProof.length != 0 && compactProof.length <= MAX_COMPACT_PROOF_BYTES_V2, "fixture: compact cap");
        bytes8 magic;
        assembly ("memory-safe") {
            magic := mload(add(compactProof, 0x20))
        }
        require(compactProof.length >= 8 && magic == COMPACT_MAGIC_V2, "fixture: compact magic");
        require(compactProof.length == vm.parseJsonUint(json, ".compactProof.byteLength"), "fixture: compact length");
        require(
            keccak256(compactProof) == vm.parseJsonBytes32(json, ".compactProof.keccak256"), "fixture: compact hash"
        );
    }

    /// @dev Reject exporter/view drift before either CREATE. The encoded config remains the sole
    ///      constructor input, but every separately recorded VK identity must describe that same
    ///      pinned deployment artifact rather than a misleading second circuit.
    function _requireV2PinnedFixtureViews(string memory json, MleVerifierV2.VerificationConfig memory config)
        private
        pure
    {
        require(
            vm.parseJsonBytes32(json, ".verificationKey.preprocessedCommitmentRoot")
                == vm.parseJsonBytes32(json, ".pinnedVerifier.preprocessedCommitmentRoot"),
            "fixture: v2 root view mismatch"
        );
        require(
            vm.parseJsonBytes32(json, ".verificationKey.circuitConfigDigest")
                == vm.parseJsonBytes32(json, ".pinnedVerifier.circuitConfigDigest"),
            "fixture: v2 circuit view mismatch"
        );
        require(
            vm.parseJsonBytes32(json, ".verificationKey.whirSessionId")
                == vm.parseJsonBytes32(json, ".pinnedVerifier.whirSessionId"),
            "fixture: v2 session view mismatch"
        );

        bytes memory vkProtocolId = vm.parseJsonBytes(json, ".verificationKey.whirProtocolId");
        bytes memory pinnedProtocolId = vm.parseJsonBytes(json, ".pinnedVerifier.whirProtocolId");
        require(
            vkProtocolId.length == 64 && pinnedProtocolId.length == 64
                && keccak256(vkProtocolId) == keccak256(pinnedProtocolId),
            "fixture: v2 protocol view mismatch"
        );

        bytes memory vkPublicInputWireMap = vm.parseJsonBytes(json, ".verificationKey.publicInputWireMap");
        bytes memory configPublicInputWireMap = vm.parseJsonBytes(json, ".verificationConfig.publicInputWireMap");
        require(
            config.circuit.numPublicInputs <= type(uint256).max / 3
                && vkPublicInputWireMap.length == 3 * config.circuit.numPublicInputs
                && configPublicInputWireMap.length == vkPublicInputWireMap.length
                && config.publicInputWireMap.length == vkPublicInputWireMap.length
                && keccak256(configPublicInputWireMap) == keccak256(vkPublicInputWireMap)
                && keccak256(config.publicInputWireMap) == keccak256(vkPublicInputWireMap),
            "fixture: v2 public-input wire-map view mismatch"
        );

        string[] memory vkDigest = vm.parseJsonStringArray(json, ".verificationKey.circuitDigest");
        string[] memory pinnedDigest = vm.parseJsonStringArray(json, ".pinnedVerifier.circuitDigest");
        require(vkDigest.length == 4 && pinnedDigest.length == 4, "fixture: v2 circuit digest length");
        for (uint256 i = 0; i < 4; ++i) {
            require(
                keccak256(bytes(vkDigest[i])) == keccak256(bytes(pinnedDigest[i])),
                "fixture: v2 circuit digest view mismatch"
            );
        }
    }

    function parseValidityPIs(string memory json)
        internal
        pure
        returns (IntmaxRollup.ValidityPublicInputs memory vpis)
    {
        vpis.initialBlockNumber = _fixtureUint64(vm.parseJsonUint(json, ".initial_block_number"));
        vpis.initialBlockChain = vm.parseJsonBytes32(json, ".initial_block_chain");
        vpis.initialExtCommitment = vm.parseJsonBytes32(json, ".initial_ext_commitment");
        vpis.finalBlockNumber = _fixtureUint64(vm.parseJsonUint(json, ".final_block_number"));
        vpis.finalBlockChain = vm.parseJsonBytes32(json, ".final_block_chain");
        vpis.finalExtCommitment = vm.parseJsonBytes32(json, ".final_ext_commitment");
        vpis.prover = vm.parseJsonAddress(json, ".prover");
    }

    function _fixtureUint64(uint256 value) private pure returns (uint64) {
        require(value <= type(uint64).max, "fixture: uint64 overflow");
        return uint64(value);
    }

    function parseUintArray(string memory json, string memory path) internal pure returns (uint256[] memory) {
        string[] memory strs = vm.parseJsonStringArray(json, path);
        uint256[] memory result = new uint256[](strs.length);
        for (uint256 i = 0; i < strs.length; i++) {
            result[i] = vm.parseUint(strs[i]);
        }
        return result;
    }
}
