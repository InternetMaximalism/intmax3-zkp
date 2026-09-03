// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title Finalize
/// @notice Smoke-finalize step: reconstructs the REAL ValidityPublicInputs
///         (vpi_fixture.json) plus the exact canonical compact v2 proof bytes from
///         mle_fixture.json, attests that same blob-backed byte stream, then finalizes.
///
///         Reads the rollup address from env `ROLLUP_ADDR` and the standard blob sidecar evidence
///         from `BLOB_SIDECARS` as compact hex:
///         `commitment0(48) || proof0(48) [|| commitment1(48) || proof1(48)]`.
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
        bytes memory compactProof = FixtureLib.parseCompactProofV2(FixtureLib.loadMle());
        bytes memory blobSidecars = vm.envBytes("BLOB_SIDECARS");

        console2.log("=== IntmaxRollup smoke finalize ===");
        console2.log("rollup        :", rollupAddr);
        console2.log("submissionId  :", SUBMISSION_ID);
        console2.log("finalStateRoot:");
        console2.logBytes32(finalStateRoot);

        vm.startBroadcast();
        rollup.attestProofData(SUBMISSION_ID, compactProof, blobSidecars);
        bool ok = rollup.finalize(SUBMISSION_ID, finalStateRoot, vpis, compactProof);
        vm.stopBroadcast();

        console2.log("finalize returned:", ok);
        require(ok, "finalize returned false (MLE verification or PI binding failed)");
        console2.log("latestFinalizedStateRoot:");
        console2.logBytes32(rollup.latestFinalizedStateRoot());
    }
}
