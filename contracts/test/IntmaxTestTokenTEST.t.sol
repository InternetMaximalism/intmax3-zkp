// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";
import {IntmaxTestTokenTEST} from "./tokens/IntmaxTestTokenTEST.sol";

contract IntmaxTestTokenTESTTest is Test {
    function test_RepeatableTenTokenMintAndEscrowTransfer() public {
        IntmaxTestTokenTEST token = new IntmaxTestTokenTEST();
        address alice = address(0xA11CE);
        address escrow = address(0xE5C);
        vm.startPrank(alice);
        token.mint();
        token.mint();
        assertEq(token.balanceOf(alice), 20_000_000);
        assertEq(token.totalSupply(), 20_000_000);
        token.approve(address(this), 10_000_000);
        vm.stopPrank();
        assertTrue(token.transferFrom(alice, escrow, 10_000_000));
        assertEq(token.balanceOf(escrow), 10_000_000);
        assertEq(token.balanceOf(alice), 10_000_000);
        assertEq(token.allowance(alice, address(this)), 0);
        assertEq(token.totalSupply(), 20_000_000);
        assertEq(token.symbol(), "TEST");
        assertEq(token.decimals(), 6);
    }

    function test_UncappedMintAndZeroAddressRejection() public {
        IntmaxTestTokenTEST token = new IntmaxTestTokenTEST();
        token.mint(address(this), 1_000_000_000_000_000);
        token.mint(address(this), 1_000_000_000_000_000);
        assertEq(token.totalSupply(), 2_000_000_000_000_000);
        vm.expectRevert(IntmaxTestTokenTEST.TransferToZeroAddress.selector);
        token.mint(address(0), 1);
        uint256 supply = token.totalSupply();
        vm.expectRevert(abi.encodeWithSelector(IntmaxTestTokenTEST.InsufficientBalance.selector, supply, supply + 1));
        token.transfer(address(1), supply + 1);
    }
}
