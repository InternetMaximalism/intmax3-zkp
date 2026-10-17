// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LateIncomingLifecycleTest} from "./LateIncomingLifecycle.t.sol";
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";

/// Real Manager/materializer dispatch with independently controlled verifier mocks.
/// This tests address/byte routing; it makes no cryptographic soundness claim.
contract LateIncomingVerifierDispatchTest is LateIncomingLifecycleTest {
    function test_dispatchUsesLateAdapterAndExactProofBytes() external {
        backingVerifier.setVerificationVerdict(false);
        bytes32 nf = keccak256("dispatch accepted");
        bytes32 next = keccak256("dispatch next");
        bytes memory proof = _proof(INITIAL, next, nf, alice, TOKEN, 7);
        uint256 escrowBefore = rollup.escrow(TOKEN);
        vm.expectCall(address(lateVerifier), abi.encodeCall(IPinnedMleVerifierV2.verifyCompactPublicInputs, (proof)));
        materializer.claimLateIncoming(manager, proof);
        assertEq(materializer.lateBalanceStateCommitment(uint32(CHANNEL_ID)), next);
        assertTrue(materializer.lateReceiveNullifierUsed(uint32(CHANNEL_ID), nf));
        assertEq(rollup.escrow(TOKEN), escrowBefore - 7);
        assertEq(manager.lateIncomingFundAmount(TOKEN), 7);
    }

    function test_dispatchDoesNotFallBackToAcceptingBackingAdapter() external {
        backingVerifier.setVerificationVerdict(true);
        lateVerifier.setVerificationVerdict(false);
        bytes32 nf = keccak256("dispatch rejected");
        bytes memory proof = _proof(INITIAL, keccak256("rejected next"), nf, alice, TOKEN, 7);
        uint256 escrowBefore = rollup.escrow(TOKEN);
        vm.expectCall(address(lateVerifier), abi.encodeCall(IPinnedMleVerifierV2.verifyCompactPublicInputs, (proof)));
        vm.expectRevert(MockPinnedMleVerifierV2.MockMleVerificationRejected.selector);
        materializer.claimLateIncoming(manager, proof);
        _assertNoLateCredit(nf);
        assertEq(rollup.escrow(TOKEN), escrowBefore);
    }
}
