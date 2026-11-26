// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {PrepareProofDa} from "../script/PrepareProofDa.s.sol";

contract ProofDaCodecTest is Test {
    PrepareProofDa internal codec;

    function setUp() public {
        codec = new PrepareProofDa();
    }

    function test_blobCount_accountsForSimpleCoderLengthHeader() public {
        assertEq(codec.blobCountForLength(126_945), 1);
        assertEq(codec.blobCountForLength(126_946), 2);
        assertEq(codec.blobCountForLength(253_921), 2);
        vm.expectRevert(
            abi.encodeWithSelector(PrepareProofDa.ProofPayloadTooLarge.selector, 253_922, 3)
        );
        codec.blobCountForLength(253_922);
    }

    function test_realFixture_isCanonicalCompactV2AndFitsOneBlob() public view {
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/lib/polygon-plonky2/mle/contracts/test/fixtures/v2_max_resource.json"
            )
        );
        bytes memory proof = FixtureLib.parseCompactProofV2(json);
        bytes memory payload = codec.canonicalProofBytes(proof);

        assertEq(keccak256(payload), keccak256(proof));
        // PoW 28 (2026-11-26): the maximum-resource proof fits one blob; PoW 22's 129,284 needed two.
        assertEq(payload.length, 122_052);
        assertEq(codec.blobCountForLength(payload.length), 1);
        assertEq(codec.blobCountForLength((4096 - 1) * 31), 1);
        assertEq(codec.blobCountForLength((4096 - 1) * 31 + 1), 2);
    }

    function test_emptyPayload_rejected() public {
        vm.expectRevert(PrepareProofDa.EmptyProofPayload.selector);
        codec.blobCountForLength(0);
    }
}
