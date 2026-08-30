// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

/// @title Real-verifier acceptance for the three settlement claim statements.
///
/// @notice SECURITY / LIVENESS. Until this file existed, NO `.t.sol` read
///         `withdrawal_claim_mle.json`, `post_close_claim_mle.json` or `cancel_close_mle.json` —
///         only the deploy scripts did. Every settlement-verifier Foundry test wires
///         `MockMleVerifier`, which returns true unconditionally, so the one thing that was broken
///         (does the REAL `MleVerifier` accept a real proof of this statement?) was precisely the
///         thing the mock stubbed out. `ExponentiationGate` (gate id 8) entered these two claim
///         fixtures on 2026-07-31 and made `submitWithdrawalClaim` unverifiable on-chain; nothing
///         signalled it until an ignored Rust E2E reached the claim step on 2026-08-09.
///         See `doc/audit/why-gate8-was-missed.md` §6 and §8 (recommendation R2).
///
/// @dev WHAT THIS PROVES — and, deliberately, what it does not.
///      PROVES: the deployed `MleVerifier` bytecode, with the deployed `Plonky2GateEvaluator`
///      dispatcher, ACCEPTS the checked-in real proof for each claim statement. That is exactly the
///      "the on-chain verifier is capable of verifying the circuits this repo actually builds"
///      obligation that the audit corpus left unowned by treating the verifier as an oracle. It
///      covers gate-set support, `degreeBits` / VK-parameter agreement, WHIR parameter agreement and
///      `gatesDigest` binding.
///      DOES NOT PROVE: anything about the settlement contracts' use of these proofs — member-set
///      binding, H1 binding, nullifiers, payout accounting. This test is intentionally DECOUPLED
///      from the member-set / finalized-H1 co-generation problem that
///      `CloseLifecycleE2E.t.sol:244-253` correctly declines to fake; it never touches
///      `ChannelSettlementManager` or `ChannelSettlementVerifier`. "The verifier can verify this
///      statement's real proof", nothing more.
///
///      No proving is required: the fixtures are checked in, and are the same artifacts the deploy
///      scripts build the on-chain VKs from.
contract ClaimMleVerifyTest is Test {
    MleVerifier internal verifier;

    // Fixed by the checked-in close proof. This fixture deliberately carries both an initial
    // query at index zero (the old post-Merkle alias check false-rejected it) and a genuine final
    // query collision at index 869. Regeneration must update these layout sentinels explicitly.
    uint256 internal constant CLOSE_HINTS_LENGTH = 76_368;
    uint256 internal constant CLOSE_FINAL_VEC_PREFIX_OFFSET = 67_272;
    uint256 internal constant CLOSE_FINAL_DUPLICATE_ROW_OFFSET = 71_888;

    function setUp() public {
        verifier = new MleVerifier();
    }

    function _load(string memory name) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/", name));
    }

    /// @dev Verify-only: parse the fixture, recompute the `gatesDigest` the way the deploy scripts
    ///      do (`FixtureLib.buildMleVk`), and require `verify` to return true. A revert — e.g.
    ///      `"unsupported gate with non-zero filter"` from `Plonky2GateEvaluator` — fails the test
    ///      by propagating, which is the intended signal.
    function _assertRealVerifierAccepts(string memory fixtureName) internal view {
        string memory json = _load(fixtureName);
        FixtureLib.DeployData memory dd = FixtureLib.parseDeployData(json);
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(json);

        // Sanity: a fixture with no gate rows would make the gate sumcheck terminal vacuous and
        // this test meaningless.
        require(proof.gates.length > 0, "fixture has no gate rows");

        bytes32 gatesDigest = verifier.computeGatesDigest(
            proof.gates,
            proof.witnessIndividualEvalsAtRGateV2.length,
            proof.numSelectors,
            proof.numGateConstraints,
            proof.quotientDegreeFactor
        );

        MleVerifier.VerifyParams memory vp = MleVerifier.VerifyParams({
            degreeBits: dd.degreeBits,
            preprocessedCommitmentRoot: dd.preCommitRoot,
            numConstants: dd.numConstants,
            numRoutedWires: dd.numRoutedWires,
            protocolId: dd.protocolId,
            sessionId: dd.sessionId,
            kIs: dd.kIs,
            subgroupGenPowers: dd.subgroupGenPowers
        });

        bool ok = verifier.verify(proof, vp, dd.whirParams, gatesDigest);
        assertTrue(ok, string.concat("real MleVerifier rejected ", fixtureName));
    }

    /// @notice `submitWithdrawalClaim`'s statement. This is the exact fixture whose gate id 8 made
    ///         the claim path unverifiable on-chain between 2026-07-31 and 2026-08-09.
    function test_realMleVerifier_acceptsWithdrawalClaimProof() public view {
        _assertRealVerifierAccepts("withdrawal_claim_mle.json");
    }

    /// @notice `submitPostCloseClaim`'s statement.
    function test_realMleVerifier_acceptsPostCloseClaimProof() public view {
        _assertRealVerifierAccepts("post_close_claim_mle.json");
    }

    /// @notice `cancelClose`'s statement — the only on-chain remedy against a stale close.
    function test_realMleVerifier_acceptsCancelCloseProof() public view {
        _assertRealVerifierAccepts("cancel_close_mle.json");
    }

    /// @notice Regression for WHIR's final-opening binding and duplicate-query handling. The real
    ///         close proof includes an initial index-zero query and a duplicated final query, so it
    ///         exercises both paths without a synthetic verifier harness.
    function test_realMleVerifier_acceptsCloseProofWithQueryZeroAndFinalDuplicate() public view {
        _assertRealVerifierAccepts("close_intent_mle.json");
    }

    /// @notice The second serialized row for a duplicate query is consumed by Rust but discarded
    ///         by Merkle deduplication. It must equal the committed representative before dedup.
    function test_realMleVerifier_rejectsMismatchedFinalDuplicateRow() public {
        string memory json = _load("close_intent_mle.json");
        FixtureLib.DeployData memory dd = FixtureLib.parseDeployData(json);
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(json);
        require(proof.whirHints.length == CLOSE_HINTS_LENGTH, "close WHIR hints layout changed");
        require(
            uint8(proof.whirHints[CLOSE_FINAL_DUPLICATE_ROW_OFFSET]) == 0x2e,
            "close duplicate row offset changed"
        );

        bytes32 gatesDigest = verifier.computeGatesDigest(
            proof.gates,
            proof.witnessIndividualEvalsAtRGateV2.length,
            proof.numSelectors,
            proof.numGateConstraints,
            proof.quotientDegreeFactor
        );
        MleVerifier.VerifyParams memory vp = _verifyParams(dd);
        // Replace the first two Ext3 coefficients by
        //   row[0]' = row[0] + eqWeight[1], row[1]' = row[1] - eqWeight[0].
        // Their weighted dot product is therefore unchanged, so the final-opening equation still
        // holds. Merkle dedup also authenticates the untouched first occurrence. Only the explicit
        // duplicate-row equality check can reject this otherwise invisible mutation.
        bytes memory replacement =
            hex"5e0bc5163b347d1fdcac6b56b9caa4f181a240321ff3966f21ad0ca2ad0411478a864653864d4ddccf6497ecd2c6f623";
        for (uint256 i = 0; i < replacement.length; i++) {
            proof.whirHints[CLOSE_FINAL_DUPLICATE_ROW_OFFSET + i] = replacement[i];
        }

        vm.expectRevert(SpongefishWhirVerify.DuplicateLeafMismatch.selector);
        verifier.verify(proof, vp, dd.whirParams, gatesDigest);
    }

    /// @notice Arkworks' Vec prefix is part of the canonical proof encoding, not padding.
    function test_realMleVerifier_rejectsWrongWhirVectorLengthPrefix() public {
        string memory json = _load("close_intent_mle.json");
        FixtureLib.DeployData memory dd = FixtureLib.parseDeployData(json);
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(json);
        require(proof.whirHints.length == CLOSE_HINTS_LENGTH, "close WHIR hints layout changed");
        require(
            uint8(proof.whirHints[CLOSE_FINAL_VEC_PREFIX_OFFSET]) == 0,
            "close final Vec prefix offset changed"
        );

        bytes32 gatesDigest = verifier.computeGatesDigest(
            proof.gates,
            proof.witnessIndividualEvalsAtRGateV2.length,
            proof.numSelectors,
            proof.numGateConstraints,
            proof.quotientDegreeFactor
        );
        proof.whirHints[CLOSE_FINAL_VEC_PREFIX_OFFSET] = 0x01;

        vm.expectRevert(SpongefishWhirVerify.InvalidHints.selector);
        verifier.verify(proof, _verifyParams(dd), dd.whirParams, gatesDigest);
    }

    /// @notice Reject proof-extension malleability: all hint bytes must be consumed.
    function test_realMleVerifier_rejectsTrailingWhirHints() public {
        string memory json = _load("close_intent_mle.json");
        FixtureLib.DeployData memory dd = FixtureLib.parseDeployData(json);
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(json);
        bytes32 gatesDigest = verifier.computeGatesDigest(
            proof.gates,
            proof.witnessIndividualEvalsAtRGateV2.length,
            proof.numSelectors,
            proof.numGateConstraints,
            proof.quotientDegreeFactor
        );
        proof.whirHints = bytes.concat(proof.whirHints, hex"00");

        vm.expectRevert(SpongefishWhirVerify.InvalidHints.selector);
        verifier.verify(proof, _verifyParams(dd), dd.whirParams, gatesDigest);
    }

    function _verifyParams(FixtureLib.DeployData memory dd)
        internal
        pure
        returns (MleVerifier.VerifyParams memory)
    {
        return MleVerifier.VerifyParams({
            degreeBits: dd.degreeBits,
            preprocessedCommitmentRoot: dd.preCommitRoot,
            numConstants: dd.numConstants,
            numRoutedWires: dd.numRoutedWires,
            protocolId: dd.protocolId,
            sessionId: dd.sessionId,
            kIs: dd.kIs,
            subgroupGenPowers: dd.subgroupGenPowers
        });
    }

    /// @notice SECURITY: anti-vacuity. If `verify` ever degenerated into "returns true for
    ///         anything", the three acceptance tests above would pass while proving nothing. Flip a
    ///         single bit of the WHIR Fiat-Shamir transcript — every MLE challenge is bound to it —
    ///         and require the real verifier to NOT accept. A revert is a rejection; only `true` is
    ///         a failure.
    function test_realMleVerifier_rejectsTamperedWithdrawalClaimProof() public view {
        string memory json = _load("withdrawal_claim_mle.json");
        FixtureLib.DeployData memory dd = FixtureLib.parseDeployData(json);
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(json);
        bytes32 gatesDigest = verifier.computeGatesDigest(
            proof.gates,
            proof.witnessIndividualEvalsAtRGateV2.length,
            proof.numSelectors,
            proof.numGateConstraints,
            proof.quotientDegreeFactor
        );
        MleVerifier.VerifyParams memory vp = MleVerifier.VerifyParams({
            degreeBits: dd.degreeBits,
            preprocessedCommitmentRoot: dd.preCommitRoot,
            numConstants: dd.numConstants,
            numRoutedWires: dd.numRoutedWires,
            protocolId: dd.protocolId,
            sessionId: dd.sessionId,
            kIs: dd.kIs,
            subgroupGenPowers: dd.subgroupGenPowers
        });

        proof.whirTranscript = hex"deadbeefdeadbeefdeadbeefdeadbeef";
        try verifier.verify(proof, vp, dd.whirParams, gatesDigest) returns (bool ok) {
            assertFalse(ok, "tampered withdrawal-claim transcript MUST be rejected");
        } catch {
            // revert == rejection: acceptable
        }
    }
}
