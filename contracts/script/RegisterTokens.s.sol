// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";

/// @title RegisterTokens — populate the rollup's set-once base-token registry from `tokens.json`.
///
/// @notice Deploy step for the multi-token feature (detail2 §N-7, threat model TM-1/TM-10b). Reads
///         the per-deployment token manifest (`TOKENS_MANIFEST`) and calls
///         `IntmaxRollup.registerToken(tokenIndex, address)` for every NON-NATIVE entry that is not
///         already registered.
///
///         ORDERING: run AFTER the rollup deploy and BEFORE any ERC-20 deposit. `deposit()` for a
///         nonzero `tokenIndex` reverts on an unregistered index, and a channel's H1-frozen
///         `token_registry` references these base indices forever.
///
/// @dev SECURITY CONTRACT — the authority boundary this script sits on:
///      * The ONLY thing this script writes on-chain is the base `tokenIndex -> ERC-20 address`
///        mapping. That mapping IS the authoritative token identity.
///      * `symbol` / `name` / `decimals` in the manifest are DISPLAY metadata with ZERO authority.
///        This script deliberately does not read them, does not put them on-chain, and does not
///        let them influence any decision. (Mislabelling a worthless token "USDC" is a user-funds
///        attack — that risk is contained by only ever serving metadata for entries whose address
///        was read back equal from `tokenAddressOf`; see node/common/token-registry.js.)
///      * SET-ONCE (TM-10b): an index is immutable once set. A DIFFERING existing value is a hard
///        error, never an "update" — a remappable index converts token-A escrow into token-B
///        withdrawals. Re-running with the same manifest is a no-op (idempotent).
///      * Every registration is READ BACK via `tokenAddressOf` and the run reverts unless equal,
///        so a silently-failing or reordered broadcast can never be reported as success.
///
///      Env:
///        TOKENS_MANIFEST  path to tokens.json (default `../node/tokens.json`, relative to the
///                         Foundry project root; must be inside an `fs_permissions` read path).
///        ROLLUP           optional; when set it must equal the manifest's `rollup` field (the
///                         manifest pins the deployment it describes — that pin is the check).
///
///      Deployer key comes from the standard Foundry mechanism (`--private-key` / `--account`);
///      nothing is hardcoded and no key is ever printed. `registerToken` is deployer-only.
contract RegisterTokens is Script {
    /// @dev Same cap as the node-side validator (`node/common/token-registry.js`): bounds the
    ///      manifest walk so a degenerate/hostile file cannot spin the loop.
    uint256 internal constant MAX_TOKENS = 64;

    error ManifestRollupMismatch(address manifestRollup, address envRollup);
    error TokenIndexNotU32(uint256 tokenIndex);
    error ManifestChainIdMismatch(uint256 manifestChainId, uint256 actual);
    error DuplicateTokenIndex(uint32 tokenIndex);
    error NativeMustBeIndexZero(uint32 tokenIndex);
    error IndexZeroMustBeNative(uint32 tokenIndex);
    error TokenAddressZero(uint32 tokenIndex);
    /// @dev SET-ONCE violation attempt: the index is already bound to a DIFFERENT token.
    error AlreadyRegisteredToAnotherToken(uint32 tokenIndex, address onChain, address manifest);
    /// @dev The post-registration read-back disagreed — never report success on an unverified write.
    error ReadBackMismatch(uint32 tokenIndex, address onChain, address expected);

    function run() external {
        string memory manifestPath = vm.envOr("TOKENS_MANIFEST", string("../node/tokens.json"));
        string memory json = vm.readFile(manifestPath);

        address rollupAddr = vm.parseJsonAddress(json, ".rollup");
        address envRollup = vm.envOr("ROLLUP", address(0));
        // The manifest pins WHICH deployment it describes. A ROLLUP override that disagrees means
        // the operator is about to register one deployment's tokens against another — hard stop.
        if (envRollup != address(0) && envRollup != rollupAddr) {
            revert ManifestRollupMismatch(rollupAddr, envRollup);
        }
        uint256 manifestChainId = vm.parseJsonUint(json, ".chainId");
        if (manifestChainId != block.chainid) revert ManifestChainIdMismatch(manifestChainId, block.chainid);

        console2.log("=== RegisterTokens ===");
        console2.log("manifest      :", manifestPath);
        console2.log("IntmaxRollup  :", rollupAddr);
        console2.log("chainId       :", manifestChainId);

        vm.startBroadcast();
        registerAll(IntmaxRollup(rollupAddr), json);
        vm.stopBroadcast();
    }

    /// @notice The core logic, separated from env/broadcast plumbing so it is testable in-tree.
    /// @dev Called INTERNALLY from `run()` (so the calls go out as the broadcaster, which must be
    ///      the rollup's `deployer`). Prints one summary line per token: REGISTERED / already-set /
    ///      native-skip.
    function registerAll(IntmaxRollup rollup, string memory json) public {
        // Walk the array by index (a `[*]` wildcard yields multiple JSON values, which
        // `parseJsonUintArray` refuses) and stop at the first absent element. MAX_TOKENS bounds the
        // loop so a hostile/degenerate file cannot spin it.
        uint256[] memory indices = new uint256[](MAX_TOKENS);
        uint256 n = 0;

        for (uint256 i = 0; i < MAX_TOKENS; i++) {
            string memory base = string.concat(".tokens[", vm.toString(i), "]");
            if (!vm.keyExistsJson(json, string.concat(base, ".tokenIndex"))) break;

            uint256 raw = vm.parseJsonUint(json, string.concat(base, ".tokenIndex"));
            if (raw > type(uint32).max) revert TokenIndexNotU32(raw);
            uint32 idx = uint32(raw);
            // Structural check mirrored from the node-side validator (fail-closed on the operator
            // file): base indices must be unique — a duplicate index is the TM-1 double-drain shape.
            for (uint256 j = 0; j < n; j++) {
                if (uint32(indices[j]) == idx) revert DuplicateTokenIndex(idx);
            }
            indices[n++] = raw;

            bool native = vm.keyExistsJson(json, string.concat(base, ".native"))
                && vm.parseJsonBool(json, string.concat(base, ".native"));

            if (native) {
                // Index 0 is native ETH by contract construction (`registerToken` reverts
                // TokenIndexZeroReservedForEth); there is nothing to register.
                if (idx != 0) revert NativeMustBeIndexZero(idx);
                console2.log("token 0: native ETH - nothing to register");
                continue;
            }
            if (idx == 0) revert IndexZeroMustBeNative(idx);

            address token = vm.parseJsonAddress(json, string.concat(base, ".address"));
            if (token == address(0)) revert TokenAddressZero(idx);

            address onChain = address(rollup.tokenAddressOf(idx));
            if (onChain == token) {
                // Idempotent re-run: already bound to exactly this token.
                console2.log("token already registered (no-op):");
                console2.log("  tokenIndex:", idx);
                console2.log("  address   :", token);
                continue;
            }
            if (onChain != address(0)) {
                // SET-ONCE (TM-10b): a differing existing value is NEVER an update.
                revert AlreadyRegisteredToAnotherToken(idx, onChain, token);
            }

            rollup.registerToken(idx, token);

            // Read back: never report a registration we did not observe land.
            address after_ = address(rollup.tokenAddressOf(idx));
            if (after_ != token) revert ReadBackMismatch(idx, after_, token);

            console2.log("token REGISTERED:");
            console2.log("  tokenIndex:", idx);
            console2.log("  address   :", token);
        }
        console2.log("tokens processed:", n);
    }
}
