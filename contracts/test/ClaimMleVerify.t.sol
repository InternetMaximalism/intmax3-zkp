// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OuterLogupExt3Verifier} from "@mle/OuterLogupExt3Verifier.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";
import {Plonky2GateEvaluatorExt3} from "@mle/Plonky2GateEvaluatorExt3.sol";
import {PoseidonPublicInputsHash} from "@mle/PoseidonPublicInputsHash.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

/// @title Real constructor-pinned V2 verifier acceptance for settlement statements.
/// @dev Each statement fixture is consumed only when it carries the strict V2 schema. Historical
///      V1 ABI fixtures self-skip here rather than being reinterpreted as compact bytes; the
///      non-skipping V2FixtureCompletenessTest and CI anti-skip guard make that a release failure.
contract ClaimMleVerifyTest is Test {
    uint256 private constant MAX_PRODUCTION_VERIFY_GAS = 20_000_000;

    function _load(string memory name) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/", name));
    }

    function _loadV2OrSkip(string memory name) internal returns (string memory json) {
        json = _load(name);
        if (!vm.keyExistsJson(json, ".schemaVersion")) {
            vm.skip(true);
            return "";
        }
    }

    function _maxResourceV2() internal view returns (string memory) {
        return vm.readFile(
            string.concat(vm.projectRoot(), "/lib/polygon-plonky2/mle/contracts/test/fixtures/v2_max_resource.json")
        );
    }

    function _assertRealVerifierAccepts(string memory fixtureName) internal {
        string memory json = _loadV2OrSkip(fixtureName);
        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = FixtureLib.parseCompactProofV2(json);
        assertTrue(adapter.verifyCompact(compactProof), string.concat("real V2 verifier rejected ", fixtureName));
    }

    function _assertRejected(PinnedMleVerifierV2 adapter, bytes memory compactProof, string memory why) internal view {
        (bool success, bytes memory result) =
            address(adapter).staticcall(abi.encodeCall(PinnedMleVerifierV2.verifyCompact, (compactProof)));
        if (success) assertFalse(abi.decode(result, (bool)), why);
    }

    function test_realMleVerifier_acceptsTrackedV2ResourceProof() public {
        string memory json = _maxResourceV2();
        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = FixtureLib.parseCompactProofV2(json);
        assertTrue(adapter.verifyCompact(compactProof));
    }

    function test_realMleVerifier_acceptsWithdrawalClaimProof() public {
        _assertRealVerifierAccepts("withdrawal_claim_mle.json");
    }

    function test_realMleVerifier_acceptsPostCloseClaimProof() public {
        _assertRealVerifierAccepts("post_close_claim_mle.json");
    }

    function test_realMleVerifier_acceptsCancelCloseProof() public {
        _assertRealVerifierAccepts("cancel_close_mle.json");
    }

    function test_realMleVerifier_acceptsCloseProof() public {
        _assertRealVerifierAccepts("close_intent_mle.json");
    }

    /// @dev Measure the exact production adapter entry point with intrinsic calldata gas. The
    /// synthetic resource fixture is not a substitute: it has five gate kinds and one PI, whereas
    /// every live parent circuit has thirteen gate kinds and statement-dependent PI counts.
    function _assertPublicInputsPathFitsProductionGasEnvelope(string memory fixtureName, uint256 expectedPublicInputs)
        internal
    {
        string memory json = _loadV2OrSkip(fixtureName);
        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = FixtureLib.parseCompactProofV2(json);
        bytes memory callData = abi.encodeCall(PinnedMleVerifierV2.verifyCompactPublicInputs, (compactProof));

        // Deployment above warms the downstream accounts and every constructor-written adapter
        // slot inside this test transaction. Reset all of them, including the core's runtime-linked
        // libraries. A direct transaction's `to` account is warm by protocol, so cooling the
        // adapter too is conservative; the core, libraries and adapter storage are genuinely cold.
        address core = address(adapter.core());
        vm.cool(core);
        vm.cool(address(OuterLogupExt3Verifier));
        vm.cool(address(Plonky2GateEvaluatorExt3));
        vm.cool(address(PoseidonPublicInputsHash));
        vm.cool(address(SpongefishWhirVerify));
        // Keep this last: reading adapter.core() itself performs a STATICCALL that warms adapter.
        vm.cool(address(adapter));

        // Execute under the actual post-intrinsic 20M budget rather than measuring with unlimited
        // wrapper gas and checking only afterwards. Nested EIP-150 forwarding is therefore part of
        // the acceptance condition.
        uint256 executionBudget = MAX_PRODUCTION_VERIFY_GAS - _calldataIntrinsicGas(callData);
        uint256 gasBefore = gasleft();
        (bool success, bytes memory result) = address(adapter).staticcall{gas: executionBudget}(callData);
        uint256 executionGas = gasBefore - gasleft();
        uint256 transactionGasUpperBound = executionGas + _calldataIntrinsicGas(callData);
        assertTrue(success, string.concat(fixtureName, " PI-return call failed inside production gas cap"));
        uint256[] memory publicInputs = abi.decode(result, (uint256[]));

        emit log_named_string("production V2 gas fixture", fixtureName);
        emit log_named_uint("compact bytes", compactProof.length);
        emit log_named_uint("authenticated public inputs", publicInputs.length);
        emit log_named_uint("PI-return execution gas", executionGas);
        emit log_named_uint("PI-return transaction gas upper bound", transactionGasUpperBound);
        assertEq(publicInputs.length, expectedPublicInputs, "public-input shape drift");
        assertLt(
            transactionGasUpperBound,
            MAX_PRODUCTION_VERIFY_GAS,
            string.concat(fixtureName, " PI-return transaction exceeds production block envelope")
        );
    }

    function test_realValidityPublicInputsPathFitsProductionGasEnvelope() public {
        _assertPublicInputsPathFitsProductionGasEnvelope("mle_fixture.json", 8);
    }

    function test_realWithdrawalPublicInputsPathFitsProductionGasEnvelope() public {
        _assertPublicInputsPathFitsProductionGasEnvelope("withdrawal_mle.json", 17);
    }

    function test_realClosePublicInputsPathFitsProductionGasEnvelope() public {
        _assertPublicInputsPathFitsProductionGasEnvelope("pw_close_intent_mle.json", 103);
    }

    function test_realWithdrawalClaimPublicInputsPathFitsProductionGasEnvelope() public {
        _assertPublicInputsPathFitsProductionGasEnvelope("withdrawal_claim_mle.json", 50);
    }

    function test_realPostCloseClaimPublicInputsPathFitsProductionGasEnvelope() public {
        _assertPublicInputsPathFitsProductionGasEnvelope("post_close_claim_mle.json", 57);
    }

    function test_realCancelClosePublicInputsPathFitsProductionGasEnvelope() public {
        _assertPublicInputsPathFitsProductionGasEnvelope("cancel_close_mle.json", 29);
    }

    function _calldataIntrinsicGas(bytes memory callData) private pure returns (uint256 gasCost) {
        gasCost = 21_000;
        for (uint256 i = 0; i < callData.length; ++i) {
            gasCost += callData[i] == bytes1(0) ? 4 : 16;
        }
    }

    function test_realMleVerifier_rejectsMismatchedFinalDuplicateRow() public {
        string memory json = _loadV2OrSkip("withdrawal_claim_mle.json");
        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = FixtureLib.parseCompactProofV2(json);
        compactProof[compactProof.length - 1] = bytes1(uint8(compactProof[compactProof.length - 1]) ^ 1);
        _assertRejected(adapter, compactProof, "tampered duplicate-row payload accepted");
    }

    function test_realMleVerifier_rejectsWrongWhirVectorLengthPrefix() public {
        string memory json = _loadV2OrSkip("close_intent_mle.json");
        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = FixtureLib.parseCompactProofV2(json);
        require(compactProof.length > 8, "compact fixture too short");
        compactProof[8] = bytes1(uint8(compactProof[8]) ^ 1);
        _assertRejected(adapter, compactProof, "tampered compact length/grammar accepted");
    }

    function test_realMleVerifier_rejectsTrailingWhirHints() public {
        string memory json = _loadV2OrSkip("close_intent_mle.json");
        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = bytes.concat(FixtureLib.parseCompactProofV2(json), hex"00");
        _assertRejected(adapter, compactProof, "trailing compact byte accepted");
    }

    function test_realMleVerifier_rejectsTamperedWithdrawalClaimProof() public {
        string memory json = _loadV2OrSkip("withdrawal_claim_mle.json");
        (, PinnedMleVerifierV2 adapter) = FixtureLib.deployPinnedMleV2(json);
        bytes memory compactProof = FixtureLib.parseCompactProofV2(json);
        compactProof[compactProof.length / 2] = bytes1(uint8(compactProof[compactProof.length / 2]) ^ 1);
        _assertRejected(adapter, compactProof, "tampered withdrawal proof accepted");
    }
}
