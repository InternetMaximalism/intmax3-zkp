// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PreparePartialWithdrawal} from "../script/PreparePartialWithdrawal.s.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

contract PreparePartialWithdrawalTest is Test {
    string constant OUT = "../proof-da-output/pw-encoder-test.calldata";
    PreparePartialWithdrawal encoder;
    address manager;

    function setUp() public {
        encoder = new PreparePartialWithdrawal();
        manager = vm.parseJsonAddress(vm.readFile("test/data/pw_submit.json"), ".manager");
        vm.createDir("../proof-da-output", true);
        vm.setEnv("PW_MANAGER", vm.toString(manager));
        vm.setEnv("PW_INTENT_PATH", "test/data/pw_submit.json");
        vm.setEnv("PW_MLE_PATH", "test/data/pw_close_intent_mle.json");
        vm.setEnv("PW_CALLDATA_OUT", OUT);
    }

    function test_keylessEncodingAndManagerBinding() public {
        _encoderPreservesIntentProofAndWithdrawalWithoutCallingManager();
        _attestationPreservesExactManagerAndProof();
        _encoderRejectsDifferentManager();
        vm.setEnv("PW_MANAGER", vm.toString(manager));
        // Environment variables are process-wide: keep encoder scenarios in one test.
        _encoderRejectsScalarTruncationInsteadOfSilentlyWrapping();
        _encoderRejectsTokenRegistryTruncation();
        _encoderRejectsShortAndLongTokenVectors();
        _encoderPreservesMaximumWidthValues();
    }

    function _editableInput() internal returns (string memory input) {
        input = "../proof-da-output/pw-encoder-boundaries.json";
        vm.writeFile(input, vm.readFile("test/data/pw_submit.json"));
        vm.setEnv("PW_INTENT_PATH", input);
    }

    function _encoderRejectsScalarTruncationInsteadOfSilentlyWrapping() internal {
        string[9] memory keys = [string(".close_nonce"), ".final_epoch", ".final_small_block_number",
            ".close_freeze_nonce", ".snapshot_medium_block_number", ".final_state_version",
            ".withdrawal_token_index", ".withdrawal_base_nonce", ".token_count"];
        uint256[9] memory limits = [uint256(1) << 64, uint256(1) << 64, uint256(1) << 64,
            uint256(1) << 64, uint256(1) << 64, uint256(1) << 64,
            uint256(1) << 32, uint256(1) << 32, uint256(1) << 8];
        for (uint256 i; i < keys.length; ++i) {
            string memory input = _editableInput();
            vm.writeJson(vm.toString(limits[i]), input, keys[i]);
            vm.expectRevert(bytes("integer field exceeds width"));
            encoder.run();
        }
    }

    function _encoderRejectsTokenRegistryTruncation() internal {
        string memory input = _editableInput();
        vm.writeJson("[4294967296,0,0,0,0,0,0,0,0,0]", input, ".token_registry");
        vm.expectRevert(bytes("token registry entry exceeds u32"));
        encoder.run();
    }

    function _encoderRejectsShortAndLongTokenVectors() internal {
        string memory input = _editableInput();
        vm.writeJson("[0]", input, ".token_registry");
        vm.expectRevert(bytes("token_registry must have 10 entries")); encoder.run();
        vm.writeJson("[0,0,0,0,0,0,0,0,0,0,0]", input, ".token_registry");
        vm.expectRevert(bytes("token_registry must have 10 entries")); encoder.run();
        input = _editableInput();
        vm.writeJson('["0"]', input, ".channel_fund_amounts");
        vm.expectRevert(bytes("channel_fund_amounts must have 10 entries")); encoder.run();
    }

    function _encoderPreservesMaximumWidthValues() internal {
        string memory input = _editableInput();
        vm.writeJson(vm.toString(type(uint64).max), input, ".close_nonce");
        vm.writeJson(vm.toString(type(uint32).max), input, ".withdrawal_base_nonce");
        vm.writeJson(vm.toString(type(uint32).max), input, ".withdrawal_token_index");
        vm.writeJson(vm.toString(type(uint256).max), input, ".withdrawal_amount");
        vm.writeJson("[4294967295,0,0,0,0,0,0,0,0,0]", input, ".token_registry");
        encoder.run();
        bytes memory data = vm.parseBytes(vm.readFile(OUT));
        bytes memory args = new bytes(data.length - 4);
        for (uint256 i; i < args.length; ++i) args[i] = data[i + 4];
        (ChannelSettlementManager.CloseIntent memory intent,,, ChannelSettlementManager.AuthorizedWithdrawal memory w) =
            abi.decode(args, (ChannelSettlementManager.CloseIntent, bytes, bytes32, ChannelSettlementManager.AuthorizedWithdrawal));
        assertEq(intent.closeNonce, type(uint64).max);
        assertEq(intent.tokenRegistry[0], type(uint32).max);
        assertEq(w.baseNonce, type(uint32).max);
        assertEq(w.tokenIndex, type(uint32).max);
        assertEq(w.amount, type(uint256).max);
    }

    function _encoderPreservesIntentProofAndWithdrawalWithoutCallingManager() internal {
        // The fixture address has no deployed code: encoding must require neither RPC nor a
        // manager call, while retaining all economic fields and the exact randomized proof.
        assertEq(manager.code.length, 0);
        encoder.run();
        bytes memory data = vm.parseBytes(vm.readFile(OUT));
        assertEq(bytes4(data), ChannelSettlementManager.submitPartialWithdrawalIntent.selector);
        bytes memory args = new bytes(data.length - 4);
        for (uint256 i; i < args.length; ++i) args[i] = data[i + 4];
        (ChannelSettlementManager.CloseIntent memory intent, bytes memory proof, bytes32 previous,
            ChannelSettlementManager.AuthorizedWithdrawal memory withdrawal) = abi.decode(args,
            (ChannelSettlementManager.CloseIntent, bytes, bytes32, ChannelSettlementManager.AuthorizedWithdrawal));
        string memory j = vm.readFile("test/data/pw_submit.json");
        assertEq(intent.finalChannelStateDigest, vm.parseJsonBytes32(j, ".final_channel_state_digest"));
        assertEq(intent.finalSettledTxAccumulatorRoot, vm.parseJsonBytes32(j, ".final_settled_tx_acc_root"));
        assertEq(previous, vm.parseJsonBytes32(j, ".prev_settled_tx_chain"));
        assertEq(withdrawal.recipient, vm.parseJsonAddress(j, ".withdrawal_recipient"));
        assertEq(withdrawal.amount, vm.parseUint(vm.parseJsonString(j, ".withdrawal_amount")));
        assertEq(withdrawal.nullifier, vm.parseJsonBytes32(j, ".withdrawal_nullifier"));
        assertEq(withdrawal.txLeaf, vm.parseJsonBytes32(j, ".burn_tx_leaf"));
        assertEq(proof, FixtureLib.parseCompactProofV2(vm.readFile("test/data/pw_close_intent_mle.json")));
    }

    function _encoderRejectsDifferentManager() internal {
        vm.setEnv("PW_MANAGER", vm.toString(address(123)));
        vm.expectRevert(bytes("partial withdrawal manager mismatch"));
        encoder.run();
    }

    function _attestationPreservesExactManagerAndProof() internal {
        string memory input = "../proof-da-output/pw-encoder-test.compact";
        bytes memory proof = hex"1234567890";
        vm.writeFileBinary(input, proof);
        vm.setEnv("PW_BACKING_COMPACT_PATH", input);
        encoder.attest();
        assertEq(vm.parseBytes(vm.readFile(OUT)), abi.encodeCall(
            CloseFundingMaterializer.attestSignedHeadBacking,
            (ChannelSettlementManager(payable(manager)), proof)
        ));
    }
}
