// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";

contract GenesisFinalizedRootTest is Test {
    function test_nonZeroGenesisIsPermanentFinalizedRootMember() public {
        bytes32 genesis = keccak256("production genesis snapshot");
        IntmaxRollup rollup = _deploy(genesis);

        assertEq(rollup.latestFinalizedStateRoot(), genesis);
        assertTrue(rollup.isFinalizedStateRoot(genesis));
    }

    function test_zeroGenesisRemainsFailClosedSentinel() public {
        IntmaxRollup rollup = _deploy(bytes32(0));

        assertEq(rollup.latestFinalizedStateRoot(), bytes32(0));
        assertFalse(rollup.isFinalizedStateRoot(bytes32(0)));
    }

    function _deploy(bytes32 genesis) private returns (IntmaxRollup) {
        IntmaxRollup.MleVk memory vk;
        SpongefishWhirVerify.WhirParams memory whir;
        whir.rounds = new SpongefishWhirVerify.RoundParams[](0);
        whir.evaluationPoint = new GoldilocksExt3.Ext3[](0);
        whir.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);
        uint256[] memory empty = new uint256[](0);

        return new IntmaxRollup(
            address(0xdead),
            vk,
            whir,
            "",
            "",
            empty,
            empty,
            new MleVerifier(),
            genesis,
            true
        );
    }
}
