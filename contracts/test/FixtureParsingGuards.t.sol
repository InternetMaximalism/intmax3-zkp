// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {RegRecordLib} from "../script/RegRecordLib.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {Plonky2GateEvaluator} from "@mle/Plonky2GateEvaluator.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";

contract FixtureParsingHarness {
    function countGates(string calldata json) external pure returns (uint256) {
        return FixtureLib.countGates(json);
    }

    function parseGateInfo(string calldata json, uint256 index)
        external
        pure
        returns (Plonky2GateEvaluator.GateInfo memory)
    {
        return FixtureLib.parseGateInfo(json, index);
    }

    function parseValidityBlockNumbers(string calldata json) external pure returns (uint64 initial, uint64 final_) {
        IntmaxRollup.ValidityPublicInputs memory vpis = FixtureLib.parseValidityPIs(json);
        return (vpis.initialBlockNumber, vpis.finalBlockNumber);
    }

    function parseWhirDomainGenerators(string calldata json) external pure returns (uint64 initial, uint64 round0) {
        SpongefishWhirVerify.WhirParams memory params = FixtureLib.parseWhirParams(json, ".whirParams");
        return (params.initialDomainGenerator, params.rounds[0].domainGenerator);
    }

    function parseExt3(string calldata json) external pure returns (uint64 c0, uint64 c1, uint64 c2) {
        GoldilocksExt3.Ext3 memory value = FixtureLib.parseExt3(json, ".value");
        return (value.c0, value.c1, value.c2);
    }

    function parseRegRecord(string calldata json) external view returns (RegRecordLib.Record memory) {
        return RegRecordLib.parse(json);
    }
}

contract FixtureParsingGuardsTest is Test {
    FixtureParsingHarness internal harness;

    function setUp() public {
        harness = new FixtureParsingHarness();
    }

    function test_countGates_acceptsExactly64Rows() public view {
        assertEq(harness.countGates(_gateCountJson(64)), 64);
    }

    function test_countGates_rejects65RowsInsteadOfTruncating() public {
        vm.expectRevert(bytes("fixture: more than 64 gate rows"));
        harness.countGates(_gateCountJson(65));
    }

    function test_countGates_rejectsHoleBeforeLaterRow() public {
        vm.expectRevert();
        harness.countGates(_gateCountJsonWithHole(7, 5));
    }

    function test_countGates_rejectsMalformedTerminalRow() public {
        vm.expectRevert();
        harness.countGates(_gateCountJsonWithHole(7, 6));
    }

    function test_countGates_rejectsMalformedCapRowHidingValidTail() public {
        vm.expectRevert(bytes("fixture: more than 64 gate rows"));
        harness.countGates(_gateCountJsonWithHole(66, 64));
    }

    function test_parseGateInfo_rejectsEveryUint8Overflow() public {
        for (uint256 field = 0; field < 5; field++) {
            uint256[9] memory values = _validGateValues();
            values[field] = uint256(type(uint8).max) + 1;
            vm.expectRevert(bytes("fixture: GateInfo uint8 overflow"));
            harness.parseGateInfo(_gateInfoJson(values), 0);
        }
    }

    function test_parseGateInfo_rejectsEveryUint16Overflow() public {
        for (uint256 field = 5; field < 9; field++) {
            uint256[9] memory values = _validGateValues();
            values[field] = uint256(type(uint16).max) + 1;
            vm.expectRevert(bytes("fixture: GateInfo uint16 overflow"));
            harness.parseGateInfo(_gateInfoJson(values), 0);
        }
    }

    function test_parseGateInfo_preservesValidFields() public view {
        uint256[9] memory values = _validGateValues();
        Plonky2GateEvaluator.GateInfo memory gate = harness.parseGateInfo(_gateInfoJson(values), 0);
        assertEq(gate.gateId, values[0]);
        assertEq(gate.selectorIndex, values[1]);
        assertEq(gate.groupStart, values[2]);
        assertEq(gate.groupEnd, values[3]);
        assertEq(gate.gateRowIndex, values[4]);
        assertEq(gate.numConstraints, values[5]);
        assertEq(gate.numOrConsts, values[6]);
        assertEq(gate.param2, values[7]);
        assertEq(gate.param3, values[8]);
    }

    function test_parseValidityPIs_rejectsEveryUint64Overflow() public {
        uint256 overflow = uint256(type(uint64).max) + 1;
        vm.expectRevert(bytes("fixture: uint64 overflow"));
        harness.parseValidityBlockNumbers(_validityJson(overflow, 1));
        vm.expectRevert(bytes("fixture: uint64 overflow"));
        harness.parseValidityBlockNumbers(_validityJson(1, overflow));
    }

    function test_parseWhirParams_rejectsEveryDomainGeneratorOverflow() public {
        uint256 overflow = uint256(type(uint64).max) + 1;
        vm.expectRevert(bytes("fixture: uint64 overflow"));
        harness.parseWhirDomainGenerators(_whirJson(overflow, 1));
        vm.expectRevert(bytes("fixture: uint64 overflow"));
        harness.parseWhirDomainGenerators(_whirJson(1, overflow));
    }

    function test_parseExt3_rejectsEveryUint64Overflow() public {
        for (uint256 field = 0; field < 3; field++) {
            uint256[3] memory values = [uint256(1), 2, 3];
            values[field] = uint256(type(uint64).max) + 1;
            vm.expectRevert(bytes("fixture: uint64 overflow"));
            harness.parseExt3(_ext3Json(values));
        }
    }

    function test_goldilocksParsers_rejectNonCanonicalModulus() public {
        uint256 modulus = 0xFFFFFFFF00000001;
        vm.expectRevert(bytes("fixture: non-canonical Goldilocks element"));
        harness.parseWhirDomainGenerators(_whirJson(modulus, 1));
        vm.expectRevert(bytes("fixture: non-canonical Goldilocks element"));
        harness.parseExt3(_ext3Json([modulus, uint256(2), 3]));
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

    function _validGateValues() internal pure returns (uint256[9] memory values) {
        values = [uint256(13), 2, 4, 9, 12, 123, 5, 16, 7];
    }

    function _gateCountJson(uint256 count) internal view returns (string memory) {
        bytes memory json = bytes('{"gates":[');
        for (uint256 i = 0; i < count; i++) {
            json = abi.encodePacked(json, i == 0 ? "" : ",", '{"gateId":', vm.toString(i), "}");
        }
        return string(abi.encodePacked(json, "]}"));
    }

    function _gateCountJsonWithHole(uint256 count, uint256 hole) internal view returns (string memory) {
        bytes memory json = bytes('{"gates":[');
        for (uint256 i = 0; i < count; i++) {
            bytes memory row = i == hole ? bytes("{}") : abi.encodePacked('{"gateId":', vm.toString(i), "}");
            json = abi.encodePacked(json, i == 0 ? "" : ",", row);
        }
        return string(abi.encodePacked(json, "]}"));
    }

    function _gateInfoJson(uint256[9] memory v) internal view returns (string memory) {
        return string(
            abi.encodePacked(
                '{"gates":[{"gateId":',
                vm.toString(v[0]),
                ',"selectorIndex":',
                vm.toString(v[1]),
                ',"groupStart":',
                vm.toString(v[2]),
                ',"groupEnd":',
                vm.toString(v[3]),
                ',"gateRowIndex":',
                vm.toString(v[4]),
                ',"numConstraints":',
                vm.toString(v[5]),
                ',"numOrConsts":',
                vm.toString(v[6]),
                ',"param2":',
                vm.toString(v[7]),
                ',"param3":',
                vm.toString(v[8]),
                "}]}"
            )
        );
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

    function _whirJson(uint256 initialDomain, uint256 roundDomain) internal view returns (string memory) {
        return string(
            abi.encodePacked(
                '{"whirParams":{"numVariables":1,"foldingFactor":1,"numVectors":1,',
                '"numCommitments":4,"outDomainSamples":1,"inDomainSamples":1,',
                '"initialSumcheckRounds":1,"numRounds":1,"finalSumcheckRounds":1,',
                '"finalSize":1,"initialCodewordLength":1,"initialMerkleDepth":1,',
                '"initialDomainGenerator":"',
                vm.toString(initialDomain),
                '","initialInterleavingDepth":0,"initialNumVariables":1,',
                '"initialCosetSize":1,"initialNumCosets":1,"rounds":[{',
                '"codewordLength":1,"merkleDepth":1,"domainGenerator":"',
                vm.toString(roundDomain),
                '","inDomainSamples":1,"outDomainSamples":1,"sumcheckRounds":1,',
                '"interleavingDepth":0,"cosetSize":1,"numCosets":1,"numVariables":1}]}}'
            )
        );
    }

    function _ext3Json(uint256[3] memory values) internal view returns (string memory) {
        return string(
            abi.encodePacked(
                '{"value":{"c0":"',
                vm.toString(values[0]),
                '","c1":"',
                vm.toString(values[1]),
                '","c2":"',
                vm.toString(values[2]),
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
