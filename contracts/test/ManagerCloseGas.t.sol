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
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";
import {MockRollupRegistry} from "./CloseSettlementBase.sol";

/// @notice Production-shape gas guard for the value-bearing Manager close path.
/// @dev Uses the real 103-PI close proof of the generated close family (`close_intent_mle.json`,
///      channel 1 of `close_lifecycle.json`, intent descriptor `close_intent.json`; the former
///      `pw_` close-intent fixture lost its producer in 909658b1) and the real pinned adapter. Only the three
///      unrelated statement adapters and finalized-root registry response are test doubles. The
///      measured call is the exact `submitCloseIntent` ABI, including its state writes; calldata
///      intrinsic gas is added explicitly to the measured execution cost.
contract ManagerCloseGasTest is Test {
    uint256 private constant MAX_PRODUCTION_TRANSACTION_GAS = 20_000_000;

    ChannelSettlementManager private manager;
    ChannelSettlementVerifier private settlementVerifier;
    PinnedMleVerifierV2 private closeAdapter;
    MockRollupRegistry private rollup;
    address private closeCore;
    address private closeRequester;

    // ── close-satellite surface (this test contract is the Manager's `closeFundingMaterializer`) ──
    //
    // Signer-independent exit: `submitCloseIntent` -> `_checkCloseProof` ends with
    // `requireSignedHeadBacking` on the satellite, and `requestClose`/`cancelClose` drive its
    // freeze journal. The stub below is cost-shaped like the real `CloseFundingMaterializer`
    // check (one `channelStatus()` call back into the Manager, the statement-key hash, and cold
    // SLOADs of the binding / receipt / post-head mappings) so the measured envelope includes it.
    mapping(uint32 => address) private _boundManager;
    mapping(bytes32 => uint64) private _anchorPlusOne;
    mapping(uint32 => uint64) private _lastPostedBlock;
    mapping(uint32 => uint64) private _frozenGeneration;

    function freezeFromManager(uint32 channelId, uint64 generation) external {
        _frozenGeneration[channelId] = generation;
    }

    function unfreezeFromManager(uint32 channelId, uint64) external {
        delete _frozenGeneration[channelId];
    }

    function requireSignedHeadBacking(uint32 channelId, bytes32 settledTxChain, bytes32 tokenFundsDigest)
        external
        view
    {
        bool requireCurrent = ChannelSettlementManager(payable(msg.sender)).channelStatus()
            != ChannelSettlementManager.ChannelLifecycleStatus.Active;
        bytes32 key = keccak256(
            abi.encode(bytes4(0x494d4241), block.chainid, address(this), address(rollup), msg.sender, channelId, settledTxChain, tokenFundsDigest)
        );
        // Same slot traffic as the production satellite; the receipt itself is presumed present
        // (a real attestation is verified once, in its own earlier transaction, never here).
        require(_boundManager[channelId] == address(0) || _boundManager[channelId] == msg.sender, "bound elsewhere");
        require(!requireCurrent || _anchorPlusOne[key] >= _lastPostedBlock[channelId], "backing stale");
    }

    /// Deploy in Foundry's separate setup transaction so the measured submit begins with cold
    /// account/storage access, like a production transaction rather than a deploy-and-call bundle.
    function setUp() public {
        _deployManager(_read("close_intent_mle.json"));
        // Freeze (era 0 -> 1, the fixture's `close_freeze_nonce`) and pass the grace window here,
        // so the measured submit is the era's first close intent.
        vm.prank(closeRequester);
        manager.requestClose(0, 0);
        vm.warp(block.timestamp + manager.GRACE_BEFORE_PROCESS_SECS());
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
            finalSettledTxAccumulatorRoot: vm.parseJsonBytes32(json, ".final_settled_tx_accumulator_root")
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

        // Same registration the lifecycle E2E deploys from (CloseE2EBase._managerInitcode):
        // sig-cluster only, no delegates, zero participant root.
        string memory lifecycleJson = _read("close_lifecycle.json");
        uint32 channelId = uint32(vm.parseJsonUint(lifecycleJson, ".registration.channel_id"));
        uint8 bpSlot = uint8(vm.parseJsonUint(lifecycleJson, ".registration.bp_member_slot"));
        bytes32[] memory pkGs = vm.parseJsonBytes32Array(lifecycleJson, ".registration.member_pk_gs");
        address[] memory recipients = vm.parseJsonAddressArray(lifecycleJson, ".registration.recipients");
        rollup = new MockRollupRegistry(IChannelSettlementVerifier(address(settlementVerifier)));
        rollup.register(channelId, bpSlot, pkGs);

        ChannelSettlementManager.MemberBinding[] memory bindings =
            new ChannelSettlementManager.MemberBinding[](pkGs.length);
        for (uint256 i = 0; i < pkGs.length; ++i) {
            bindings[i] = ChannelSettlementManager.MemberBinding({pkG: pkGs[i], recipient: recipients[i]});
        }
        closeRequester = recipients[0];

        manager = new ChannelSettlementManager(
            bytes4(channelId),
            bpSlot,
            pkGs[bpSlot],
            uint16(0),
            bytes32(0),
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

    function test_realManagerCloseSubmitFitsProductionGasEnvelope() public {
        assertEq(block.chainid, 31337, "gas fixture is local-devnet contained");
        string memory proofJson = _read("close_intent_mle.json");
        string memory submitJson = _read("close_intent.json");
        ChannelSettlementManager.CloseIntent memory intent = _parseIntent(submitJson);
        bytes memory compactProof = FixtureLib.parseCompactProofV2(proofJson);
        bytes memory callData = abi.encodeCall(ChannelSettlementManager.submitCloseIntent, (intent, compactProof));

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

        emit log_named_uint("close compact bytes", compactProof.length);
        emit log_named_uint("transaction intrinsic gas", intrinsicGas);
        emit log_named_uint("Manager execution budget at 20M", managerExecutionBudget);
        emit log_named_uint("cold harness CALL gas spent", harnessCallGasSpent);
        // EIP-7825 record (review 2026-10-15, C3): the per-transaction cap this 20M envelope must be
        // compared against on Fusaka chains; execution + intrinsic must stay below it.
        emit log_named_uint("EIP-7825 transaction gas cap (2^24)", 16_777_216);
        emit log_named_uint("execution + intrinsic", harnessCallGasSpent + intrinsicGas);
        assertTrue(success, "real Manager close submit does not execute within 20M transaction budget");
        assertEq(
            manager.getPendingClose().closeIntentDigest,
            manager.computeCloseIntentDigest(intent),
            "real close intent was not recorded"
        );
    }

    function _calldataIntrinsicGas(bytes memory callData) private pure returns (uint256 gasCost) {
        gasCost = 21_000;
        for (uint256 i = 0; i < callData.length; ++i) {
            gasCost += callData[i] == bytes1(0) ? 4 : 16;
        }
    }
}
