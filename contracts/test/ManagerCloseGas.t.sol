// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier,
    IChannelRegistry
} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";
import {OuterLogupExt3Verifier} from "@mle/OuterLogupExt3Verifier.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";
import {Plonky2GateEvaluatorExt3} from "@mle/Plonky2GateEvaluatorExt3.sol";
import {PoseidonPublicInputsHash} from "@mle/PoseidonPublicInputsHash.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {RegRecordLib} from "../script/RegRecordLib.sol";
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";
import {MockRollupRegistry} from "./CloseSettlementBase.sol";

/// @notice Production-shape gas guard for the value-bearing Manager close path.
/// @dev Uses the real 103-PI partial-withdrawal close proof and real pinned adapter. Only the three
///      unrelated statement adapters and finalized-root registry response are test doubles. The
///      measured call is the exact `submitPartialWithdrawalIntent` ABI, including its state writes;
///      calldata intrinsic gas is added explicitly to the measured execution cost.
contract ManagerCloseGasTest is Test {
    uint256 private constant MAX_PRODUCTION_TRANSACTION_GAS = 30_000_000;

    ChannelSettlementManager private manager;
    ChannelSettlementVerifier private settlementVerifier;
    PinnedMleVerifierV2 private closeAdapter;
    MockRollupRegistry private rollup;
    address private closeCore;

    /// Deploy in Foundry's separate setup transaction so the measured submit begins with cold
    /// account/storage access, like a production transaction rather than a deploy-and-call bundle.
    function setUp() public {
        _deployManager(_read("pw_close_intent_mle.json"));
    }

    function _read(string memory name) private view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/", name));
    }

    function _parseAmounts(string memory json) private pure returns (uint256[10] memory amounts) {
        string[] memory raw = vm.parseJsonStringArray(json, ".channel_fund_amounts");
        require(raw.length == 10, "channel_fund_amounts length");
        for (uint256 i = 0; i < 10; ++i) {
            amounts[i] = vm.parseUint(raw[i]);
        }
    }

    function _parseRegistry(string memory json) private pure returns (uint32[10] memory registry) {
        uint256[] memory raw = vm.parseJsonUintArray(json, ".token_registry");
        require(raw.length == 10, "token_registry length");
        for (uint256 i = 0; i < 10; ++i) {
            registry[i] = uint32(raw[i]);
        }
    }

    function _parseIntent(string memory json)
        private
        pure
        returns (ChannelSettlementManager.CloseIntent memory intent)
    {
        intent = ChannelSettlementManager.CloseIntent({
            closeNonce: uint64(vm.parseJsonUint(json, ".close_nonce")),
            finalEpoch: uint64(vm.parseJsonUint(json, ".final_epoch")),
            finalSmallBlockNumber: uint64(vm.parseJsonUint(json, ".final_small_block_number")),
            closeFreezeNonce: uint64(vm.parseJsonUint(json, ".close_freeze_nonce")),
            finalChannelStateDigest: vm.parseJsonBytes32(json, ".final_channel_state_digest"),
            finalBalanceStateH1: vm.parseJsonBytes32(json, ".final_balance_state_h1"),
            channelFundAmounts: _parseAmounts(json),
            tokenRegistry: _parseRegistry(json),
            tokenCount: uint8(vm.parseJsonUint(json, ".token_count")),
            channelFundIntmaxStateRoot: vm.parseJsonBytes32(json, ".channel_fund_intmax_state_root"),
            burnTxHash: vm.parseJsonBytes32(json, ".burn_tx_hash"),
            closeWithdrawalDigest: vm.parseJsonBytes32(json, ".close_withdrawal_digest"),
            snapshotMediumBlockNumber: uint64(vm.parseJsonUint(json, ".snapshot_medium_block_number")),
            finalStateVersion: uint64(vm.parseJsonUint(json, ".final_state_version")),
            finalSettledTxChain: vm.parseJsonBytes32(json, ".final_settled_tx_chain"),
            finalSettledTxAccumulatorRoot: vm.parseJsonBytes32(json, ".final_settled_tx_acc_root")
        });
    }

    function _parseWithdrawal(string memory json)
        private
        pure
        returns (ChannelSettlementManager.AuthorizedWithdrawal memory withdrawal)
    {
        withdrawal = ChannelSettlementManager.AuthorizedWithdrawal({
            recipient: vm.parseJsonAddress(json, ".withdrawal_recipient"),
            tokenIndex: uint32(vm.parseJsonUint(json, ".withdrawal_token_index")),
            amount: vm.parseJsonUint(json, ".withdrawal_amount"),
            baseNonce: uint32(vm.parseJsonUint(json, ".withdrawal_base_nonce")),
            nullifier: vm.parseJsonBytes32(json, ".withdrawal_nullifier"),
            auxData: vm.parseJsonBytes32(json, ".withdrawal_aux_data"),
            txLeaf: vm.parseJsonBytes32(json, ".burn_tx_leaf")
        });
    }

    function _deployManager(string memory proofJson) private {
        (, closeAdapter) = FixtureLib.deployPinnedMleV2(proofJson);
        closeCore = address(closeAdapter.core());
        MockPinnedMleVerifierV2 withdrawalClaim = new MockPinnedMleVerifierV2(block.chainid);
        MockPinnedMleVerifierV2 postCloseClaim = new MockPinnedMleVerifierV2(block.chainid);
        MockPinnedMleVerifierV2 cancelClose = new MockPinnedMleVerifierV2(block.chainid);
        settlementVerifier = new ChannelSettlementVerifier(
            IPinnedMleVerifierV2(address(closeAdapter)), withdrawalClaim, postCloseClaim, cancelClose
        );

        RegRecordLib.Record memory record = RegRecordLib.parse(_read("pw_reg.json"));
        rollup = new MockRollupRegistry(IChannelSettlementVerifier(address(settlementVerifier)));
        rollup.register(record.channelId, record.bpSlot, RegRecordLib.regPkGs(record));

        ChannelSettlementManager.MemberBinding[] memory bindings =
            new ChannelSettlementManager.MemberBinding[](record.memberCount);
        for (uint256 i = 0; i < record.memberCount; ++i) {
            bindings[i] = ChannelSettlementManager.MemberBinding({pkG: record.pkGs[i], recipient: record.recipients[i]});
        }

        manager = new ChannelSettlementManager(
            bytes4(record.channelId),
            record.bpSlot,
            record.pkGs[record.bpSlot],
            record.activeDelegateCount,
            record.participantRoot,
            1,
            0,
            0,
            IChannelSettlementVerifier(address(settlementVerifier)),
            IChannelRegistry(address(rollup)),
            address(this),
            bindings
        );
        assertEq(address(manager.closeMleVerifier()), address(closeAdapter), "manager did not pin real close adapter");
    }

    function test_realPartialWithdrawalManagerSubmitFitsProductionGasEnvelope() public {
        assertEq(block.chainid, 31337, "gas fixture is local-devnet contained");
        string memory proofJson = _read("pw_close_intent_mle.json");
        string memory submitJson = _read("pw_submit.json");
        ChannelSettlementManager.CloseIntent memory intent = _parseIntent(submitJson);
        ChannelSettlementManager.AuthorizedWithdrawal memory withdrawal = _parseWithdrawal(submitJson);
        bytes32 prevSettledTxChain = vm.parseJsonBytes32(submitJson, ".prev_settled_tx_chain");
        bytes memory compactProof = FixtureLib.parseCompactProofV2(proofJson);
        bytes memory callData = abi.encodeCall(
            ChannelSettlementManager.submitPartialWithdrawalIntent,
            (intent, compactProof, prevSettledTxChain, withdrawal)
        );

        // Be explicit even though setUp and this test execute as separate calls: all parent/core
        // accounts start cold. The Manager is a transaction destination in production (therefore
        // warm by protocol), so cooling it is a small conservative overcharge in this CALL-based
        // harness; the downstream registry, adapter, core and binder really are cold in production.
        vm.cool(address(manager));
        vm.cool(address(rollup));
        vm.cool(address(closeAdapter));
        vm.cool(closeCore);
        vm.cool(address(OuterLogupExt3Verifier));
        vm.cool(address(Plonky2GateEvaluatorExt3));
        vm.cool(address(PoseidonPublicInputsHash));
        vm.cool(address(SpongefishWhirVerify));
        vm.cool(address(settlementVerifier));

        uint256 intrinsicGas = _calldataIntrinsicGas(callData);
        uint256 managerExecutionBudget = MAX_PRODUCTION_TRANSACTION_GAS - intrinsicGas;
        uint256 gasBefore = gasleft();
        (bool success,) = address(manager).call{gas: managerExecutionBudget}(callData);
        uint256 harnessCallGasSpent = gasBefore - gasleft();

        emit log_named_uint("partial-withdrawal compact bytes", compactProof.length);
        emit log_named_uint("transaction intrinsic gas", intrinsicGas);
        emit log_named_uint("Manager execution budget at 30M", managerExecutionBudget);
        emit log_named_uint("cold harness CALL gas spent", harnessCallGasSpent);
        assertTrue(success, "real Manager partial-withdrawal submit does not execute within 30M transaction budget");
        assertTrue(manager.partialWithdrawalPending(), "real partial withdrawal was not recorded");
    }

    function _calldataIntrinsicGas(bytes memory callData) private pure returns (uint256 gasCost) {
        gasCost = 21_000;
        for (uint256 i = 0; i < callData.length; ++i) {
            gasCost += callData[i] == bytes1(0) ? 4 : 16;
        }
    }
}
