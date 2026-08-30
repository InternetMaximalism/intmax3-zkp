// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {MockMleVerifier} from "./CloseTestLib.sol";
import {SimpleERC20} from "./tokens/TestTokens.sol";
import {RegisterTokens} from "../script/RegisterTokens.s.sol";
import {SubmitPartialWithdrawal} from "../script/SubmitPartialWithdrawal.s.sol";

contract SubmitPartialWithdrawalNoReadHarness is SubmitPartialWithdrawal {
    error FixtureReadAttempted();

    bool internal failReads = true;

    function _read(string memory) internal view override returns (string memory) {
        if (failReads) revert FixtureReadAttempted();
        return "{}";
    }
}

contract SubmitPartialWithdrawalScriptGuardTest is Test {
    function test_run_publicChainRevertsBeforeReadingFixtures() public {
        uint256 publicChainId = 11155111;
        vm.chainId(publicChainId);

        SubmitPartialWithdrawalNoReadHarness script = new SubmitPartialWithdrawalNoReadHarness();
        vm.expectRevert(abi.encodeWithSelector(SubmitPartialWithdrawal.LocalDevnetOnly.selector, publicChainId));
        script.run();
    }

    function test_run_anvilPassesTheChainGateBeforeReadingFixture() public {
        vm.chainId(31337);

        SubmitPartialWithdrawalNoReadHarness script = new SubmitPartialWithdrawalNoReadHarness();
        vm.expectRevert(SubmitPartialWithdrawalNoReadHarness.FixtureReadAttempted.selector);
        script.run();
    }
}

/// @title RegisterTokens deploy-script logic (multitoken §N-7, TM-1/TM-10b).
/// @notice Exercises `RegisterTokens.registerAll` — the script's core logic — against a REAL
///         `IntmaxRollup`. The manifest is passed as a JSON string (the same bytes `run()` reads
///         from `TOKENS_MANIFEST`), so the JSON walk, the set-once policy and the read-back are all
///         covered without needing filesystem write permission.
///
///         WHAT THESE TESTS PROVE ABOUT SECURITY
///           * a re-run against an identical manifest is a NO-OP (idempotent redeploys are safe);
///           * a manifest that disagrees with an already-set index REVERTS instead of "updating"
///             it — set-once is what keeps token-A escrow from becoming token-B withdrawals;
///           * display metadata in the manifest can never reach the chain (only the index→address
///             pair is written), and a duplicate base index is refused (TM-1 double-drain shape);
///           * every registration is read back from `tokenAddressOf` before being reported.
///
///         The full env/broadcast path (`run()`) is additionally exercised by the two-token E2E
///         deploy path documented in doc/tasks/regen-and-redeploy-runbook.md.
contract RegisterTokensTest is Test {
    IntmaxRollup internal rollup;
    RegisterTokens internal script;
    SimpleERC20 internal tokenA;
    SimpleERC20 internal tokenB;

    address internal fraudTreasury = makeAddr("fraudTreasury");

    function _emptyWhirParams() internal pure returns (SpongefishWhirVerify.WhirParams memory p) {
        p.rounds = new SpongefishWhirVerify.RoundParams[](0);
        p.evaluationPoint = new GoldilocksExt3.Ext3[](0);
        p.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);
    }

    function setUp() public {
        script = new RegisterTokens();
        tokenA = new SimpleERC20("TokenA");
        tokenB = new SimpleERC20("TokenB");

        // NOTE: the mock is deployed BEFORE the prank — a CREATE inside the constructor argument
        // list would otherwise consume it and the rollup's `deployer` would be this test contract.
        MleVerifier mockMle = MleVerifier(address(new MockMleVerifier()));

        // `registerToken` is deployer-only, and `registerAll` is invoked externally by these tests,
        // so the script contract must BE the deployer (in production the broadcaster is).
        IntmaxRollup.MleVk memory zeroVk;
        vm.prank(address(script));
        rollup = new IntmaxRollup(
            fraudTreasury,
            zeroVk,
            _emptyWhirParams(),
            "",
            "",
            new uint256[](0),
            new uint256[](0),
            mockMle,
            bytes32(0),
            true // degreeBits == 0 validity bypass (test opt-in)
        );
        assertEq(rollup.deployer(), address(script), "the script must be the rollup deployer");
    }

    // ── manifest builders ───────────────────────────────────────────────────────────────────

    function _entry(uint32 idx, string memory symbol, address token) internal pure returns (string memory) {
        return string.concat(
            '{"tokenIndex":',
            vm.toString(uint256(idx)),
            ',"symbol":"',
            symbol,
            '","name":"Test Token","decimals":6,"address":"',
            vm.toString(token),
            '"}'
        );
    }

    function _manifest(string memory entries) internal view returns (string memory) {
        return string.concat(
            '{"chainId":',
            vm.toString(block.chainid),
            ',"rollup":"',
            vm.toString(address(rollup)),
            '","tokens":[{"tokenIndex":0,"symbol":"ETH","name":"Ether","decimals":18,"address":null,"native":true}',
            bytes(entries).length == 0 ? "" : string.concat(",", entries),
            "]}"
        );
    }

    function _manifestWithTokenCount(uint256 count) internal view returns (string memory) {
        string memory entries =
            '{"tokenIndex":0,"symbol":"ETH","name":"Ether","decimals":18,"address":null,"native":true}';
        for (uint256 i = 1; i < count; i++) {
            entries =
                string.concat(entries, ",", _entry(uint32(i), string.concat("T", vm.toString(i)), address(uint160(i))));
        }
        return string.concat(
            '{"chainId":',
            vm.toString(block.chainid),
            ',"rollup":"',
            vm.toString(address(rollup)),
            '","tokens":[',
            entries,
            "]}"
        );
    }

    // ── tests ───────────────────────────────────────────────────────────────────────────────

    function test_registerAll_registersNonNativeEntries_andReadsBack() public {
        string memory json =
            _manifest(string.concat(_entry(7, "AAA", address(tokenA)), ",", _entry(8, "BBB", address(tokenB))));
        script.registerAll(rollup, json);

        assertEq(address(rollup.tokenAddressOf(7)), address(tokenA), "index 7 bound to tokenA");
        assertEq(address(rollup.tokenAddressOf(8)), address(tokenB), "index 8 bound to tokenB");
        // The native entry is a pure skip: index 0 stays unmapped (ETH is contract-reserved).
        assertEq(address(rollup.tokenAddressOf(0)), address(0), "native index is never registered");
    }

    /// Idempotency: the same manifest applied twice must not revert and must not change anything.
    function test_registerAll_rerunIsNoOp() public {
        string memory json = _manifest(_entry(7, "AAA", address(tokenA)));
        script.registerAll(rollup, json);
        script.registerAll(rollup, json); // second run: every entry hits the "already registered" path
        assertEq(address(rollup.tokenAddressOf(7)), address(tokenA));
    }

    /// SET-ONCE (TM-10b): a manifest disagreeing with a live binding is a HARD error, not an update.
    function test_registerAll_mismatchReverts() public {
        script.registerAll(rollup, _manifest(_entry(7, "AAA", address(tokenA))));
        vm.expectRevert(
            abi.encodeWithSelector(
                RegisterTokens.AlreadyRegisteredToAnotherToken.selector, uint32(7), address(tokenA), address(tokenB)
            )
        );
        script.registerAll(rollup, _manifest(_entry(7, "BBB", address(tokenB))));
        assertEq(address(rollup.tokenAddressOf(7)), address(tokenA), "the live binding is untouched");
    }

    /// A duplicate base index is the TM-1 double-drain shape — refuse the whole run.
    function test_registerAll_duplicateIndexReverts() public {
        string memory json =
            _manifest(string.concat(_entry(7, "AAA", address(tokenA)), ",", _entry(7, "BBB", address(tokenB))));
        vm.expectRevert(abi.encodeWithSelector(RegisterTokens.DuplicateTokenIndex.selector, uint32(7)));
        script.registerAll(rollup, json);
    }

    /// A non-native entry at index 0 would put an ERC-20 label on the contract-reserved ETH index.
    function test_registerAll_indexZeroMustBeNative() public {
        string memory json = string.concat(
            '{"chainId":',
            vm.toString(block.chainid),
            ',"rollup":"',
            vm.toString(address(rollup)),
            '","tokens":[',
            _entry(0, "AAA", address(tokenA)),
            "]}"
        );
        vm.expectRevert(abi.encodeWithSelector(RegisterTokens.IndexZeroMustBeNative.selector, uint32(0)));
        script.registerAll(rollup, json);
    }

    /// A native entry at a nonzero index misdeclares which asset is ETH.
    function test_registerAll_nativeMustBeIndexZero() public {
        string memory json = string.concat(
            '{"chainId":',
            vm.toString(block.chainid),
            ',"rollup":"',
            vm.toString(address(rollup)),
            '","tokens":[{"tokenIndex":3,"symbol":"ETH","name":"Ether","decimals":18,"address":null,"native":true}]}'
        );
        vm.expectRevert(abi.encodeWithSelector(RegisterTokens.NativeMustBeIndexZero.selector, uint32(3)));
        script.registerAll(rollup, json);
    }

    /// The zero address is what `tokenAddressOf` returns for an UNREGISTERED index — never a token.
    function test_registerAll_zeroAddressReverts() public {
        vm.expectRevert(abi.encodeWithSelector(RegisterTokens.TokenAddressZero.selector, uint32(7)));
        script.registerAll(rollup, _manifest(_entry(7, "AAA", address(0))));
    }

    /// Display metadata carries no authority: two manifests differing ONLY in symbol/name/decimals
    /// produce byte-identical on-chain state, and the second run stays a no-op.
    function test_registerAll_displayMetadataHasNoOnChainEffect() public {
        script.registerAll(rollup, _manifest(_entry(7, "AAA", address(tokenA))));
        string memory relabelled = string.concat(
            '{"chainId":',
            vm.toString(block.chainid),
            ',"rollup":"',
            vm.toString(address(rollup)),
            '","tokens":[{"tokenIndex":0,"symbol":"ETH","name":"Ether","decimals":18,"address":null,"native":true},',
            '{"tokenIndex":7,"symbol":"USDC","name":"Totally Not TokenA","decimals":18,"address":"',
            vm.toString(address(tokenA)),
            '"}]}'
        );
        script.registerAll(rollup, relabelled);
        assertEq(address(rollup.tokenAddressOf(7)), address(tokenA), "a relabel cannot move the binding");
    }

    /// The bounded walker must reject, not silently ignore, the 65th manifest entry.
    function test_registerAll_moreThanMaximumEntriesRevertsBeforeRegistration() public {
        vm.expectRevert(abi.encodeWithSelector(RegisterTokens.ManifestTooManyTokens.selector, uint256(64)));
        script.registerAll(rollup, _manifestWithTokenCount(65));
        assertEq(address(rollup.tokenAddressOf(1)), address(0), "overflow manifest must write nothing");
    }

    /// A malformed element cannot masquerade as end-of-array and hide a valid tail entry.
    function test_registerAll_missingTokenIndexDoesNotHideTail() public {
        string memory json = string.concat(
            '{"chainId":',
            vm.toString(block.chainid),
            ',"rollup":"',
            vm.toString(address(rollup)),
            '","tokens":[',
            '{"tokenIndex":0,"symbol":"ETH","name":"Ether","decimals":18,"address":null,"native":true},',
            '{"symbol":"BROKEN","name":"Missing Index","decimals":6,"address":"',
            vm.toString(address(tokenA)),
            '"},',
            _entry(8, "TAIL", address(tokenB)),
            "]}"
        );

        vm.expectRevert(abi.encodeWithSelector(RegisterTokens.MissingTokenIndex.selector, uint256(1)));
        script.registerAll(rollup, json);
        assertEq(address(rollup.tokenAddressOf(8)), address(0), "tail must not be silently ignored");
    }

    function test_registerAll_emptyTokensArrayReverts() public {
        string memory json = string.concat(
            '{"chainId":', vm.toString(block.chainid), ',"rollup":"', vm.toString(address(rollup)), '","tokens":[]}'
        );
        vm.expectRevert(RegisterTokens.ManifestTokensEmpty.selector);
        script.registerAll(rollup, json);
    }
}
