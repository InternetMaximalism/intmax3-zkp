// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";

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
        return new IntmaxRollup(
            address(0xdead),
            new MockPinnedMleVerifierV2(31337),
            new MockPinnedMleVerifierV2(31337),
            genesis
        );
    }
}
