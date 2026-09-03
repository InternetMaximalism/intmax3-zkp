// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {RegRecordLib} from "../script/RegRecordLib.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifierV2} from "@mle/MleVerifierV2.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";
import {Plonky2GateEvaluatorExt3} from "@mle/Plonky2GateEvaluatorExt3.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {
    COMPACT_LAYOUT_HASH_V2,
    MLE_PROOF_ABI_SIGNATURE_V2,
    MLE_PROOF_LAYOUT_HASH_V2
} from "@mle/generated/MleWhirV2.sol";

contract FixtureParsingHarness {
    function parseValidityBlockNumbers(string calldata json) external pure returns (uint64 initial, uint64 final_) {
        IntmaxRollup.ValidityPublicInputs memory vpis = FixtureLib.parseValidityPIs(json);
        return (vpis.initialBlockNumber, vpis.finalBlockNumber);
    }

    function parseRegRecord(string calldata json) external view returns (RegRecordLib.Record memory) {
        return RegRecordLib.parse(json);
    }

    function parseCompactProofV2(string calldata json) external pure returns (bytes memory) {
        return FixtureLib.parseCompactProofV2(json);
    }

    function deployPinnedMleV2(string calldata json) external returns (address core, address adapter) {
        (MleVerifierV2 deployedCore, PinnedMleVerifierV2 deployedAdapter) = FixtureLib.deployPinnedMleV2(json);
        return (address(deployedCore), address(deployedAdapter));
    }
}

contract FixtureParsingGuardsTest is Test {
    FixtureParsingHarness internal harness;

    function setUp() public {
        harness = new FixtureParsingHarness();
    }

    function test_parseValidityPIs_rejectsEveryUint64Overflow() public {
        uint256 overflow = uint256(type(uint64).max) + 1;
        vm.expectRevert(bytes("fixture: uint64 overflow"));
        harness.parseValidityBlockNumbers(_validityJson(overflow, 1));
        vm.expectRevert(bytes("fixture: uint64 overflow"));
        harness.parseValidityBlockNumbers(_validityJson(1, overflow));
    }

    function test_parseRegRecord_rejectsChannelIdOverflow() public {
        vm.expectRevert(bytes("reg record: channel_id exceeds uint32"));
        harness.parseRegRecord(_regScalarJson(uint256(type(uint32).max) + 1, 0, 2, 0));
    }

    function test_parseRegRecord_rejectsBpSlotOverflow() public {
        vm.expectRevert(bytes("reg record: bp_member_slot exceeds uint8"));
        harness.parseRegRecord(_regScalarJson(7, uint256(type(uint8).max) + 1, 2, 0));
    }

    function test_parseRegRecord_rejectsMemberCountOverflow() public {
        vm.expectRevert(bytes("reg record: member_count exceeds uint8"));
        harness.parseRegRecord(_regScalarJson(7, 0, uint256(type(uint8).max) + 1, 0));
    }

    function test_parseRegRecord_rejectsActiveDelegateCountOverflow() public {
        vm.expectRevert(bytes("reg record: active_delegate_count exceeds uint16"));
        harness.parseRegRecord(_regScalarJson(7, 0, 2, uint256(type(uint16).max) + 1));
    }

    function test_parseRegRecord_preservesCheckedInFixture() public view {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/test/data/pw_reg_guard.json"));
        RegRecordLib.Record memory record = harness.parseRegRecord(json);
        assertEq(record.channelId, 11);
        assertEq(record.bpSlot, 0);
        assertEq(record.memberCount, 3);
        assertEq(record.activeDelegateCount, 2);
        assertEq(record.pkGs.length, 5);
    }

    function test_parseCompactProofV2_acceptsExactHeaderAndMagic() public view {
        bytes memory compact = abi.encodePacked(bytes8("MLEWHIR3"));
        assertEq(harness.parseCompactProofV2(_compactV2Json(compact, 3, 3, MLE_PROOF_ABI_SIGNATURE_V2)), compact);
    }

    function test_parseCompactProofV2_rejectsProofProtocolDrift() public {
        bytes memory compact = abi.encodePacked(bytes8("MLEWHIR3"));
        vm.expectRevert(bytes("fixture: v2 proof protocol version"));
        harness.parseCompactProofV2(_compactV2Json(compact, 2, 3, MLE_PROOF_ABI_SIGNATURE_V2));
    }

    function test_parseCompactProofV2_rejectsVkProtocolDrift() public {
        bytes memory compact = abi.encodePacked(bytes8("MLEWHIR3"));
        vm.expectRevert(bytes("fixture: v2 VK protocol version"));
        harness.parseCompactProofV2(_compactV2Json(compact, 3, 2, MLE_PROOF_ABI_SIGNATURE_V2));
    }

    function test_parseCompactProofV2_rejectsProofAbiDrift() public {
        bytes memory compact = abi.encodePacked(bytes8("MLEWHIR3"));
        vm.expectRevert(bytes("fixture: v2 proof ABI signature"));
        harness.parseCompactProofV2(_compactV2Json(compact, 3, 3, "(uint256)"));
    }

    function test_parseCompactProofV2_rejectsRelabelledWrongMagic() public {
        bytes memory compact = abi.encodePacked(bytes8("NOTWHIR3"));
        vm.expectRevert(bytes("fixture: compact magic"));
        harness.parseCompactProofV2(_compactV2Json(compact, 3, 3, MLE_PROOF_ABI_SIGNATURE_V2));
    }

    function test_deployPinnedMleV2_rejectsTrailingConfigBytesBeforeCreate() public {
        MleVerifierV2.VerificationConfig memory config;
        config.kIs = new uint256[](0);
        config.subgroupGenPowers = new uint256[](0);
        config.gates = new Plonky2GateEvaluatorExt3.GateInfoV2[](0);
        config.whir.evaluationPoint = new GoldilocksExt3.Ext3[](0);
        config.whir.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);
        config.whir.additionalEvaluationPoints = new GoldilocksExt3.Ext3[][](0);
        config.whir.rounds = new SpongefishWhirVerify.RoundParams[](0);

        // `abi.decode` accepts this valid tuple plus an ignored trailing word. All fixture length
        // and hash metadata are updated to match the malicious representation, so only the
        // decode/re-encode canonicality guard can reject it before either CREATE executes.
        bytes memory nonCanonical = abi.encodePacked(abi.encode(config), bytes32(0));
        vm.expectRevert(bytes("fixture: non-canonical v2 config"));
        harness.deployPinnedMleV2(_configV2Json(nonCanonical));
    }

    function _validityJson(uint256 initial, uint256 final_) internal view returns (string memory) {
        string memory zero = vm.toString(bytes32(0));
        return string(
            abi.encodePacked(
                '{"initial_block_number":',
                vm.toString(initial),
                ',"initial_block_chain":"',
                zero,
                '","initial_ext_commitment":"',
                zero,
                '","final_block_number":',
                vm.toString(final_),
                ',"final_block_chain":"',
                zero,
                '","final_ext_commitment":"',
                zero,
                '","prover":"',
                vm.toString(address(1)),
                '"}'
            )
        );
    }

    function _compactV2Json(bytes memory compact, uint256 proofProtocol, uint256 vkProtocol, string memory abiSig)
        internal
        view
        returns (string memory)
    {
        return string(
            abi.encodePacked(
                '{"schema":"plonky2-mle-v3-solidity","schemaVersion":3,"protocolVersion":3,',
                '"proofAbiSignature":"',
                abiSig,
                '","proofLayoutHash":"',
                vm.toString(MLE_PROOF_LAYOUT_HASH_V2),
                '","proof":{"protocolVersion":',
                vm.toString(proofProtocol),
                '},"verificationKey":{"protocolVersion":',
                vm.toString(vkProtocol),
                '},"compactProof":{"encoding":"MLEWHIR3","byteLength":',
                vm.toString(compact.length),
                ',"keccak256":"',
                vm.toString(keccak256(compact)),
                '","bytes":"',
                vm.toString(compact),
                '"}}'
            )
        );
    }

    function _configV2Json(bytes memory encodedConfig) internal view returns (string memory) {
        bytes32 configHash = keccak256(encodedConfig);
        return string(
            abi.encodePacked(
                '{"schema":"plonky2-mle-v3-solidity-config","schemaVersion":3,"protocolVersion":3,',
                '"proofAbiSignature":"',
                MLE_PROOF_ABI_SIGNATURE_V2,
                '","proofLayoutHash":"',
                vm.toString(MLE_PROOF_LAYOUT_HASH_V2),
                '","compactLayoutHash":"',
                vm.toString(COMPACT_LAYOUT_HASH_V2),
                '","compactProofEncoding":"MLEWHIR3","whirPowBits":22,',
                '"verificationKey":{"protocolVersion":3},',
                '"pinnedVerifier":{"verificationConfigDigest":"',
                vm.toString(configHash),
                '"},"solidityAbiVerificationConfig":{',
                '"encoding":"abi.encode(MleVerifierV2.VerificationConfig)","byteLength":',
                vm.toString(encodedConfig.length),
                ',"keccak256":"',
                vm.toString(configHash),
                '","bytes":"',
                vm.toString(encodedConfig),
                '"}}'
            )
        );
    }

    function _regScalarJson(uint256 channelId, uint256 bpSlot, uint256 memberCount, uint256 activeDelegateCount)
        internal
        view
        returns (string memory)
    {
        return string(
            abi.encodePacked(
                '{"channel_id":',
                vm.toString(channelId),
                ',"bp_member_slot":',
                vm.toString(bpSlot),
                ',"member_count":',
                vm.toString(memberCount),
                ',"active_delegate_count":',
                vm.toString(activeDelegateCount),
                ',"reg_delegate_count":0}'
            )
        );
    }
}
