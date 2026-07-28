// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntmaxTestTokenITX} from "./tokens/IntmaxTestTokenITX.sol";

/// @title IntmaxTestTokenITX — TESTNET faucet token
///
/// @notice WHAT THESE TESTS ARE MEANT TO PROVE. The in-channel $ITX faucet's safety story is
///         "the faucet can only run dry, never inflate": its in-channel supply is one real L1
///         deposit of this token, so every dripped balance stays backed by `channel_fund`. That
///         story leans on two properties of the token itself, and both are pinned here:
///           1. THE SUPPLY IS FIXED. There is no mint entry point at all — not owner-gated, not
///              anything — so nobody (including the deployer) can inflate it after construction.
///           2. TRANSFERS ARE FAITHFUL AND CONSERVATIVE. The rollup's ERC-20 deposit path credits
///              a measured `balanceOf` delta; a fee-on-transfer or lossy token would break that
///              accounting. Balances must sum to `totalSupply` across every path.
///         The remaining tests are ordinary ERC-20 conformance so the deposit/approve leg of the
///         bootstrap cannot fail in a surprising way.
contract IntmaxTestTokenITXTest is Test {
    IntmaxTestTokenITX internal itx;

    address internal deployer = address(this);
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    /// 1,000,000,000 ITX at 6 decimals. The L1 supply is a uint256 and is unconstrained; only
    /// the slice that is deposited + imported into a channel must fit u64 (see the contract's
    /// `decimals` note).
    uint256 internal constant SUPPLY = 1_000_000_000 * 10 ** 6;

    function setUp() public {
        itx = new IntmaxTestTokenITX(SUPPLY);
    }

    /// The manifest (`node/tokens.json`) claims these, and the relay/node read `decimals()` BACK
    /// from this contract at startup and refuse to run on a mismatch — so this assertion and the
    /// shipped manifest entry are one unit.
    function test_MetadataMatchesTheManifestContract() public view {
        assertEq(itx.name(), "Intmax Test Token");
        assertEq(itx.symbol(), "ITX");
        assertEq(itx.decimals(), 6);
    }

    function test_EntireSupplyIsMintedToTheDeployerAtConstruction() public view {
        assertEq(itx.totalSupply(), SUPPLY);
        assertEq(itx.balanceOf(deployer), SUPPLY);
    }

    function test_ZeroSupplyDeploymentIsRefused() public {
        vm.expectRevert(bytes("ITX: zero supply"));
        new IntmaxTestTokenITX(0);
    }

    /// The supply is immutable by CONSTRUCTION, and this proves it over the COMPILED ABI rather
    /// than by probing guessed selectors.
    ///
    /// Probing a handful of hardcoded names (`mint(address,uint256)`, …) and asserting the call
    /// fails proves almost nothing: it misses any differently-named minter (`mintTo`, `issue`,
    /// `airdrop`), and it cannot tell "no such function" apart from "an owner-gated mint that
    /// reverted for THIS caller". So instead: walk every entry of the artifact's ABI and assert
    /// that the ONLY state-changing functions the contract exposes are the three ERC-20 movers.
    /// Everything else must be `view`/`pure`. A function that could increase `totalSupply` would
    /// have to be state-changing and would therefore have to appear in the allowlist, which is
    /// asserted exhaustively — so this fails loudly the moment any minting surface is added,
    /// whatever it is called and whoever it is gated to.
    function test_AbiExposesNoStateChangingFunctionBeyondTheThreeErc20Movers() public {
        string memory json = vm.readFile("out/IntmaxTestTokenITX.sol/IntmaxTestTokenITX.json");
        uint256 seenFunctions;
        bool sawApprove;
        bool sawTransfer;
        bool sawTransferFrom;

        // Walk by index and stop at the first absent element (same pattern as RegisterTokens.s.sol);
        // 256 bounds the loop.
        for (uint256 i = 0; i < 256; i++) {
            string memory base = string.concat(".abi[", vm.toString(i), "]");
            if (!vm.keyExistsJson(json, string.concat(base, ".type"))) break;
            if (
                keccak256(bytes(vm.parseJsonString(json, string.concat(base, ".type"))))
                    != keccak256(bytes("function"))
            ) continue;

            seenFunctions++;
            string memory fname = vm.parseJsonString(json, string.concat(base, ".name"));
            string memory mut_ = vm.parseJsonString(json, string.concat(base, ".stateMutability"));
            bytes32 m = keccak256(bytes(mut_));
            if (m == keccak256(bytes("view")) || m == keccak256(bytes("pure"))) continue;

            // State-changing: must be exactly one of the three ERC-20 movers.
            bytes32 n = keccak256(bytes(fname));
            if (n == keccak256(bytes("approve"))) sawApprove = true;
            else if (n == keccak256(bytes("transfer"))) sawTransfer = true;
            else if (n == keccak256(bytes("transferFrom"))) sawTransferFrom = true;
            else {
                emit log_named_string("unexpected state-changing function", fname);
                fail();
            }
        }

        // Guard against a vacuous pass (unreadable/empty artifact would otherwise assert nothing).
        assertGt(seenFunctions, 5, "ABI walk found almost no functions - artifact not loaded?");
        assertTrue(sawApprove && sawTransfer && sawTransferFrom, "the three ERC-20 movers must be present");
    }

    /// Complement to the ABI walk: `totalSupply` is `immutable`, so it is baked into the deployed
    /// code and no storage write can reach it.
    function test_TotalSupplyIsUnchangedByEveryMovement() public {
        itx.transfer(alice, 1_000 * 10 ** 6);
        vm.prank(alice);
        itx.transfer(bob, 400 * 10 ** 6);
        itx.approve(alice, type(uint256).max);
        vm.prank(alice);
        itx.transferFrom(deployer, bob, 700 * 10 ** 6);
        assertEq(itx.totalSupply(), SUPPLY);
        assertEq(itx.balanceOf(deployer) + itx.balanceOf(alice) + itx.balanceOf(bob), SUPPLY);
    }

    function test_TransferMovesExactlyTheAmountAndConservesSupply() public {
        itx.transfer(alice, 100 * 10 ** 6);
        assertEq(itx.balanceOf(alice), 100 * 10 ** 6, "recipient must receive the FULL amount (no fee)");
        assertEq(itx.balanceOf(deployer), SUPPLY - 100 * 10 ** 6);
        assertEq(itx.balanceOf(alice) + itx.balanceOf(deployer), itx.totalSupply());
    }

    function test_TransferFromSpendsAllowanceAndConservesSupply() public {
        itx.approve(alice, 60 * 10 ** 6);
        vm.prank(alice);
        itx.transferFrom(deployer, bob, 40 * 10 ** 6);
        assertEq(itx.allowance(deployer, alice), 20 * 10 ** 6);
        assertEq(itx.balanceOf(bob), 40 * 10 ** 6);
        assertEq(itx.balanceOf(deployer) + itx.balanceOf(bob), itx.totalSupply());
    }

    function test_InfiniteAllowanceIsNotDecremented() public {
        itx.approve(alice, type(uint256).max);
        vm.prank(alice);
        itx.transferFrom(deployer, bob, 40 * 10 ** 6);
        assertEq(itx.allowance(deployer, alice), type(uint256).max);
    }

    function test_OverspendReverts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IntmaxTestTokenITX.InsufficientBalance.selector, 0, 1));
        itx.transfer(bob, 1);

        itx.approve(alice, 1 * 10 ** 6);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IntmaxTestTokenITX.InsufficientAllowance.selector, 1 * 10 ** 6, 2 * 10 ** 6)
        );
        itx.transferFrom(deployer, bob, 2 * 10 ** 6);
    }

    /// Burning to address(0) would desynchronize `totalSupply` from the sum of balances, which the
    /// escrow's balanceOf-delta accounting relies on.
    function test_TransferToZeroAddressReverts() public {
        vm.expectRevert(IntmaxTestTokenITX.TransferToZeroAddress.selector);
        itx.transfer(address(0), 1 * 10 ** 6);
    }

    /// Property: no sequence of transfers can change the total. Randomized over amounts and
    /// recipients — the faucet bootstrap moves the whole supply through approve/transferFrom.
    function testFuzz_SupplyIsConservedAcrossArbitraryTransfers(uint128 a, uint128 b) public {
        uint256 amountA = bound(uint256(a), 0, SUPPLY);
        itx.transfer(alice, amountA);
        uint256 amountB = bound(uint256(b), 0, amountA);
        vm.prank(alice);
        itx.transfer(bob, amountB);
        assertEq(
            itx.balanceOf(deployer) + itx.balanceOf(alice) + itx.balanceOf(bob),
            itx.totalSupply(),
            "supply must be conserved"
        );
    }
}
