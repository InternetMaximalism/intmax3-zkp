// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @notice The validity verifier configuration a rollup deployer pins.
///
/// It must be the configuration of the producer that will publish: the rollup finalizes nothing
/// else, and every exit (withdrawal payout, close funding, late incoming claim) needs a finalized
/// validity proof, while the rollup has no refund path, so a mismatched verifier locks every deposit
/// for good. The first Sepolia rollup was pinned to the arity-[2] test fixture under a 2,4,8,16
/// producer. Off the local devnet the configuration is therefore REQUIRED: the producer's own
/// export (`channel_member export-wallet-validity-config`, see
/// hosting/wallet/verify-validity-deployment.js), pinned by its SHA-256 so the reviewed file is the
/// deployed one. The fixture stays the devnet default for the tests.
abstract contract ProducerValidityConfig is Script {
    function _validityConfigJson() internal view returns (string memory) {
        string memory path = _envString("WALLET_VALIDITY_CONFIG");
        if (block.chainid == 31337) {
            return bytes(path).length == 0 ? FixtureLib.loadMleConfig() : vm.readFile(path);
        }
        require(
            bytes(path).length != 0,
            "WALLET_VALIDITY_CONFIG (the producer's exported validity config) is required off the local devnet"
        );
        string memory json = vm.readFile(path);
        string memory pin = _envString("WALLET_VALIDITY_CONFIG_SHA256");
        require(
            bytes(pin).length != 0 && sha256(bytes(json)) == vm.parseBytes32(pin),
            "WALLET_VALIDITY_CONFIG does not match WALLET_VALIDITY_CONFIG_SHA256"
        );
        return json;
    }

    /// Environment read. Virtual so the guard tests can serve it without the process-global
    /// `vm.setEnv` (forge runs a contract's test functions in parallel).
    function _envString(string memory name) internal view virtual returns (string memory) {
        return vm.envOr(name, string(""));
    }
}
