// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Plonky2Pin} from "../script/Plonky2Pin.sol";

/// @notice Fails with the fix command when contracts/lib/polygon-plonky2 is not the pinned commit,
///         so a stale checkout shows up as ONE named failure next to whatever else it breaks.
contract Plonky2PinTest is Test {
    function test_submoduleCheckoutIsThePinnedCommit() public view {
        Plonky2Pin.requirePinned();
    }
}
