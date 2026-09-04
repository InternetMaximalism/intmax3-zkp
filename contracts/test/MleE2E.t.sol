// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {PinnedMleVerifierV2} from "@mle/PinnedMleVerifierV2.sol";
import {InvalidMleProof} from "@mle/MleProofErrors.sol";

/// @title Constructor-pinned V2 MLE/WHIR end-to-end verification.
/// @dev Consumes the production export directly: no hand-built proof tuple, VK, or WHIR params.
contract MleE2ETest is Test {
    PinnedMleVerifierV2 internal verifier;
    bytes internal compactProof;

    function setUp() public {
        string memory json = vm.readFile(
            string.concat(vm.projectRoot(), "/lib/polygon-plonky2/mle/contracts/test/fixtures/v2_max_resource.json")
        );
        (, verifier) = FixtureLib.deployPinnedMleV2(json);
        compactProof = FixtureLib.parseCompactProofV2(json);
    }

    function test_mleVerify_realCompactProof() public view {
        assertTrue(verifier.verifyCompact(compactProof), "V2 MLE+WHIR proof verification failed");
    }

    function test_mleVerify_authenticatedPublicInputs() public view {
        uint256[] memory publicInputs = verifier.verifyCompactPublicInputs(compactProof);
        assertEq(publicInputs.length, 1);
        assertEq(publicInputs[0], 0xfffffffd00000003);
    }

    function test_mleVerify_gas() public {
        uint256 gasBefore = gasleft();
        bool ok = verifier.verifyCompact(compactProof);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(ok, "V2 MLE+WHIR proof verification failed");
        emit log_named_uint("V2 compact MLE+WHIR verification gas", gasUsed);
    }

    function test_mleVerify_rejects_singleByteTamper() public {
        compactProof[compactProof.length - 1] = bytes1(uint8(compactProof[compactProof.length - 1]) ^ 1);

        vm.expectRevert(InvalidMleProof.selector);
        verifier.verifyCompact(compactProof);
    }

    function test_mleVerify_wrongChainFailsClosed() public {
        vm.chainId(1);
        vm.expectRevert();
        verifier.verifyCompact(compactProof);
        assertEq(verifier.fraudVerdictCompact(compactProof, bytes32(0)), 2);
    }

    /// A compact stream cut short must never verify: the decoder derives every vector length
    /// from the pinned circuit and requires exact EOF, so a truncated DA payload is a grammar
    /// error, not a shorter proof.
    function test_mleVerify_rejects_truncatedCompactProof() public {
        bytes memory truncated = new bytes(compactProof.length - 1);
        for (uint256 i = 0; i < truncated.length; ++i) {
            truncated[i] = compactProof[i];
        }
        vm.expectRevert();
        verifier.verifyCompact(truncated);
        uint8 verdict = verifier.fraudVerdictCompact(truncated, bytes32(0));
        assertTrue(verdict != 1 && verdict != 4, "truncated compact proof classified as verified");
    }

    /// A genuine wire-v3 proof of ANOTHER statement (the parent validity circuit) fed to this
    /// adapter must be rejected. The adapter is constructor-pinned to one circuit; a proof whose
    /// shape or digest belongs to a different circuit is not "a different valid proof".
    function test_mleVerify_rejects_crossStatementProof() public {
        string memory validityJson = vm.readFile(string.concat(vm.projectRoot(), "/test/data/mle_fixture.json"));
        bytes memory validityProof = FixtureLib.parseCompactProofV2(validityJson);
        (, PinnedMleVerifierV2 validityAdapter) = FixtureLib.deployPinnedMleV2(validityJson);
        // Sanity: the foreign proof is genuine against its own adapter.
        assertTrue(validityAdapter.verifyCompact(validityProof), "validity fixture must verify on its own adapter");

        vm.expectRevert();
        verifier.verifyCompact(validityProof);
        uint8 verdict = verifier.fraudVerdictCompact(validityProof, bytes32(0));
        assertTrue(verdict != 1 && verdict != 4, "cross-statement proof classified as verified");

        vm.expectRevert();
        validityAdapter.verifyCompact(compactProof);
    }
}
