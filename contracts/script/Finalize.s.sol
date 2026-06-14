// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title Finalize
/// @notice Smoke-finalize step: reconstructs the REAL ValidityPublicInputs
///         (vpi_fixture.json) + the REAL MleProof (mle_fixture.json, parsed
///         byte-identically to MleFinalizeE2E.t.sol) and calls
///         `finalize(0, finalStateRoot, vpis, mleProof)` under broadcast.
///
///         Reads the rollup address from env `ROLLUP_ADDR`.
///         (`postBlockAndSubmit` is a blob tx done separately via `cast send`
///          — see docs/sepolia-smoke-runbook.md — it cannot be a Forge script
///          because Forge scripts cannot attach EIP-4844 blobs.)
contract Finalize is Script {
    /// @dev submissionId 0 (the first submission). Matches block_fixture / the test.
    uint256 internal constant SUBMISSION_ID = 0;

    function run() external {
        address rollupAddr = vm.envAddress("ROLLUP_ADDR");
        IntmaxRollup rollup = IntmaxRollup(rollupAddr);

        bytes32 finalStateRoot = vm.parseJsonBytes32(FixtureLib.loadBlock(), ".final_state_root");
        IntmaxRollup.ValidityPublicInputs memory vpis = FixtureLib.parseValidityPIs(FixtureLib.loadVpi());
        MleVerifier.MleProof memory mleProof = FixtureLib.parseProof(FixtureLib.loadMle());

        console2.log("=== IntmaxRollup smoke finalize ===");
        console2.log("rollup        :", rollupAddr);
        console2.log("submissionId  :", SUBMISSION_ID);
        console2.log("finalStateRoot:");
        console2.logBytes32(finalStateRoot);

        vm.startBroadcast();
        bool ok = rollup.finalize(SUBMISSION_ID, finalStateRoot, vpis, mleProof);
        vm.stopBroadcast();

        console2.log("finalize returned:", ok);
        require(ok, "finalize returned false (MLE verification or PI binding failed)");
        console2.log("latestFinalizedStateRoot:");
        console2.logBytes32(rollup.latestFinalizedStateRoot());
    }
}
