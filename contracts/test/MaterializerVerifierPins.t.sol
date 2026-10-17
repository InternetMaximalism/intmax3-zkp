// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";

contract MaterializerPinCore {
    uint8 private immutable mode;

    constructor(uint8 mode_) {
        mode = mode_;
    }

    function allowedChainId() external view returns (uint256) {
        require(mode != 5, "core chain getter failed");
        return block.chainid + (mode == 6 ? 1 : 0);
    }
}

contract MaterializerPinAdapter {
    uint8 private immutable mode;
    address private immutable linkedCore;

    constructor(uint8 mode_) {
        mode = mode_;
        linkedCore = mode_ == 4 ? address(0x1234) : address(new MaterializerPinCore(mode_));
    }

    function allowedChainId() external view returns (uint256) {
        require(mode != 1, "adapter chain getter failed");
        return block.chainid + (mode == 2 ? 1 : 0);
    }

    function core() external view returns (address) {
        require(mode != 3, "core getter failed");
        return linkedCore;
    }
}

/// Constructor validation only: these mocks do not implement proof verification.
contract MaterializerVerifierPinsTest is Test {
    function deploy(address backing, address late) private returns (CloseFundingMaterializer) {
        return new CloseFundingMaterializer(
            IntmaxRollup(payable(address(this))), IPinnedMleVerifierV2(backing), IPinnedMleVerifierV2(late)
        );
    }

    function test_distinctValidAdaptersAreBothStored() external {
        address backing = address(new MaterializerPinAdapter(0));
        address late = address(new MaterializerPinAdapter(0));
        CloseFundingMaterializer materializer = deploy(backing, late);
        assertEq(address(materializer.rollup()), address(this));
        assertEq(address(materializer.backingMleVerifier()), backing);
        assertEq(address(materializer.lateIncomingMleVerifier()), late);
    }

    function test_bothAdapterSlotsRejectEveryPinFailure() external {
        address good = address(new MaterializerPinAdapter(0));
        for (uint256 slot; slot < 2; ++slot) {
            for (uint8 mode = 1; mode <= 7; ++mode) {
                address bad = mode == 7 ? address(0x5678) : address(new MaterializerPinAdapter(mode));
                bytes memory expected;
                if (mode == 2 || mode == 6) {
                    address wrongChain = mode == 2 ? bad : MaterializerPinAdapter(bad).core();
                    expected = abi.encodeWithSelector(
                        CloseFundingMaterializer.BackingVerifierChainMismatch.selector,
                        wrongChain,
                        block.chainid,
                        block.chainid + 1
                    );
                } else {
                    address invalid = mode == 5 ? MaterializerPinAdapter(bad).core() : bad;
                    expected = abi.encodeWithSelector(CloseFundingMaterializer.InvalidBackingVerifier.selector, invalid);
                }
                vm.expectRevert(expected);
                deploy(slot == 0 ? bad : good, slot == 1 ? bad : good);
            }
        }
    }

    function test_undeployedRollupRejectedBeforeAdapterGetters() external {
        vm.expectRevert(CloseFundingMaterializer.InvalidRollup.selector);
        new CloseFundingMaterializer(
            IntmaxRollup(payable(address(0x1234))), IPinnedMleVerifierV2(address(0)), IPinnedMleVerifierV2(address(0))
        );
    }
}
