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
}
