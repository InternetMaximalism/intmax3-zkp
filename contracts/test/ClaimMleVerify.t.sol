// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
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
