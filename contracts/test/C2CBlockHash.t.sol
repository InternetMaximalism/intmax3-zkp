// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

/// @title Cheap on-chain validation of the c2c block-hash chain (no proofs).
/// @notice De-risks the Sepolia c2c run before spending 5x postBlock stakes: replays the exact
///         registerChannel(1) -> postBlock(b1) -> deposit -> postBlock(b2) -> registerChannel(2) ->
///         postBlock(b3) -> postBlock(b4) -> postBlock(b5) sequence and asserts blockHashChainAt[5]
///         equals the c2c fixture's proved final_block_chain. This exercises the CUMULATIVE
///         registration chain (ch2 registered in a later round than ch1) + cumulative deposit chain
///         on-chain, byte-for-byte against the Rust prover. Self-skips if c2c fixtures are absent.
contract C2CBlockHashTest is Test {
    IntmaxRollup internal rollup;
    address internal poster = makeAddr("poster");
    string internal lc;
    bool internal ready;

    function setUp() public {
        string memory root = string.concat(vm.projectRoot(), "/test/data/");
        try vm.readFile(string.concat(root, "c2c_lifecycle.json")) returns (string memory j) {
            lc = j;
            ready = true;
        } catch {
            ready = false;
            return;
        }
        string memory vkJson = vm.readFile(string.concat(root, "c2c_lifecycle_validity_mle.json"));
        MleVerifier verifier = new MleVerifier();
        FixtureLib.DeployData memory dd = FixtureLib.parseDeployData(vkJson);
        IntmaxRollup.MleVk memory vk = FixtureLib.buildMleVk(vkJson, verifier);
        bytes32 genesis = vm.parseJsonBytes32(lc, ".genesis_state_root");
        rollup = new IntmaxRollup(
            makeAddr("ft"), vk, dd.whirParams, dd.protocolId, dd.sessionId, dd.kIs, dd.subgroupGenPowers, verifier, genesis,
            true // A-2: test opt-in for the degreeBits==0 bypass
        );
    }

    function test_c2c_blockHashChain_matchesProof() public {
        if (!ready) { vm.skip(true); return; }

        bytes32[] memory blobs = new bytes32[](1);
        blobs[0] = keccak256("c2c");
        vm.blobhashes(blobs);
        vm.deal(poster, 10 ether);

        // Block 1: register ch1, then post.
        _register(".registration1");
        _post(0);
        // Block 2: deposit (ch1), then post.
        _deposit();
        _post(1);
        // Block 3: register ch2 (later round than ch1 — exercises cumulative reg chain), then post.
        _register(".registration2");
        _post(2);
        // Block 4: ch1->ch2 transfer block.
        _post(3);
        // Block 5: ch2 withdrawal block.
        _post(4);

        bytes32 expected = vm.parseJsonBytes32(lc, ".vpis.final_block_chain");
        assertEq(rollup.blockHashChainAt(5), expected, "blockHashChainAt[5] != proved final_block_chain");
        assertEq(rollup.blockNumber(), 5, "blockNumber");
    }

    function _register(string memory key) internal {
        uint32 channelId = uint32(vm.parseJsonUint(lc, string.concat(key, ".channel_id")));
        uint8 bpSlot = uint8(vm.parseJsonUint(lc, string.concat(key, ".bp_member_slot")));
        bytes32[] memory sphincs = vm.parseJsonBytes32Array(lc, string.concat(key, ".member_pk_gs"));
        bytes32[] memory pkBs = vm.parseJsonBytes32Array(lc, string.concat(key, ".member_pk_bs"));
        bytes32[] memory regev = vm.parseJsonBytes32Array(lc, string.concat(key, ".regev_pk_digests"));
        address[] memory recipients = vm.parseJsonAddressArray(lc, string.concat(key, ".recipients"));
        rollup.registerChannel(channelId, bpSlot, 0, sphincs, pkBs, regev, recipients);
    }

    function _deposit() internal {
        address depositor = vm.parseJsonAddress(lc, ".deposit.depositor");
        bytes32 recipient = vm.parseJsonBytes32(lc, ".deposit.recipient");
        uint32 tokenIndex = uint32(vm.parseJsonUint(lc, ".deposit.token_index"));
        uint256 amount = vm.parseUint(vm.parseJsonString(lc, ".deposit.amount"));
        bytes32 auxData = vm.parseJsonBytes32(lc, ".deposit.aux_data");
        vm.deal(depositor, amount);
        vm.prank(depositor);
        rollup.deposit{value: amount}(recipient, tokenIndex, amount, auxData);
    }

    function _post(uint256 i) internal {
        string memory base = string.concat(".blocks[", vm.toString(i), "]");
        uint256[] memory keyIdsU = FixtureLib.parseUintArray(lc, string.concat(base, ".key_ids"));
        uint32[] memory keyIds = new uint32[](keyIdsU.length);
        for (uint256 j = 0; j < keyIdsU.length; j++) keyIds[j] = uint32(keyIdsU[j]);
        IntmaxRollup.SubBlock[] memory sb = new IntmaxRollup.SubBlock[](1);
        sb[0] = IntmaxRollup.SubBlock({
            channelId: uint32(vm.parseJsonUint(lc, string.concat(base, ".channel_id"))),
            timestamp: uint64(vm.parseJsonUint(lc, string.concat(base, ".timestamp"))),
            txTreeRoot: vm.parseJsonBytes32(lc, string.concat(base, ".tx_tree_root")),
            keyIds: keyIds
        });
        vm.prank(poster);
        rollup.postBlockAndSubmit{value: 1 ether}(sb, bytes32(0), 0, bytes32(0));
    }
}
