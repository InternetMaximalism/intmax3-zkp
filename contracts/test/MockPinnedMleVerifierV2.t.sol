// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";

contract MockPinnedMleVerifierV2Test is Test {
    MockPinnedMleVerifierV2 internal verifier;

    function setUp() public {
        verifier = new MockPinnedMleVerifierV2(31337);
    }

    function test_verifyCompactPublicInputs_requiresCanonicalSurrogateBytes() public view {
        uint256[] memory expected = new uint256[](2);
        expected[0] = 7;
        expected[1] = 11;
        bytes memory compactProof = abi.encode(expected);

        uint256[] memory actual = verifier.verifyCompactPublicInputs(compactProof);
        assertEq(actual, expected);
    }

    function test_verifyCompactPublicInputs_rejectsTrailingAlias() public {
        uint256[] memory publicInputs = new uint256[](1);
        publicInputs[0] = 7;
        bytes memory nonCanonical = bytes.concat(abi.encode(publicInputs), bytes32(uint256(1)));

        vm.expectRevert(MockPinnedMleVerifierV2.MockMleVerificationRejected.selector);
        verifier.verifyCompactPublicInputs(nonCanonical);
    }

    function test_verificationAndFraudVerdicts_areIndependent() public {
        verifier.setVerificationVerdict(false);
        verifier.setFraudVerdict(2);

        vm.expectRevert(MockPinnedMleVerifierV2.MockMleVerificationRejected.selector);
        verifier.verifyCompactPublicInputs(abi.encode(new uint256[](0)));
        assertEq(verifier.fraudVerdictCompact("", bytes32(0)), 2);
    }

    function test_wrongChain_isUnevaluableNeverFraud() public {
        vm.chainId(1);
        vm.expectRevert(
            abi.encodeWithSelector(MockPinnedMleVerifierV2.MockMleWrongChain.selector, 1, 31337)
        );
        verifier.verifyCompactPublicInputs(abi.encode(new uint256[](0)));
        assertEq(verifier.fraudVerdictCompact("", bytes32(0)), 2);
    }

    function test_fraudClassifier_exposesEveryProductionVerdictWithoutAliasing() public {
        for (uint8 verdict = 0; verdict <= 4; ++verdict) {
            verifier.setFraudVerdict(verdict);
            assertEq(verifier.fraudVerdictCompact("", bytes32(0)), verdict);
        }

        vm.expectRevert(bytes("mock verdict out of range"));
        verifier.setFraudVerdict(5);
    }
}
