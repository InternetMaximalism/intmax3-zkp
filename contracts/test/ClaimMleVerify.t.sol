// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {InvalidMleProof} from "@mle/MleProofErrors.sol";
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

    /// Fixtures searched, in order, for a duplicated final-round query row. WHIR's Fiat-Shamir
    /// queries are fixture-specific, so the duplicate is located from the current WHIR shape
    /// instead of pinning byte offsets that move on every regeneration.
    function _duplicateRowCandidates() internal pure returns (string[7] memory) {
        return [
            "withdrawal_claim_mle.json",
            "close_intent_mle.json",
            "post_close_claim_mle.json",
            "cancel_close_mle.json",
            "withdrawal_mle.json",
            "close_withdrawal_mle.json",
            "c2c_withdrawal_mle.json"
        ];
    }

    function setUp() public {
        verifier = new MleVerifier(block.chainid);
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
    function test_realMleVerifier_acceptsCloseProof() public view {
        _assertRealVerifierAccepts("close_intent_mle.json");
    }

    /// @notice The second serialized row for a duplicate query is consumed by Rust but discarded
    ///         by Merkle deduplication. It must equal the committed representative before dedup.
    function test_realMleVerifier_rejectsMismatchedFinalDuplicateRow() public {
        string[7] memory candidates = _duplicateRowCandidates();
        for (uint256 c = 0; c < candidates.length; c++) {
            string memory json = _load(candidates[c]);
            FixtureLib.DeployData memory dd = FixtureLib.parseDeployData(json);
            MleVerifier.MleProof memory proof = FixtureLib.parseProof(json);
            (bool found, uint256 duplicateOffset) = _findFinalDuplicateRow(proof.whirHints, dd.whirParams);
            if (!found) continue;

            bytes32 gatesDigest = verifier.computeGatesDigest(
                proof.gates,
                proof.witnessIndividualEvalsAtRGateV2.length,
                proof.numSelectors,
                proof.numGateConstraints,
                proof.quotientDegreeFactor
            );
            MleVerifier.VerifyParams memory vp = _verifyParams(dd);
            assertTrue(verifier.verify(proof, vp, dd.whirParams, gatesDigest), "unmodified fixture verifies");
            // The verifier sorts/hash-deduplicates rows before evaluating the opening. A one-byte
            // mutation in the repeated row must therefore hit the explicit duplicate-hash equality
            // check, rather than letting Merkle dedup silently authenticate only the first copy.
            proof.whirHints[duplicateOffset] = bytes1(uint8(proof.whirHints[duplicateOffset]) ^ 1);

            vm.expectRevert(InvalidMleProof.selector);
            verifier.verify(proof, vp, dd.whirParams, gatesDigest);
            emit log_named_string("duplicate final query fixture", candidates[c]);
            return;
        }
        // WHIR draws 16 final-round queries from a 2^11 domain, so a checked-in proof carries a
        // duplicated query only with ~6% probability per fixture. Regeneration is not
        // reproducible (ZK blinding), so the duplicate-row path can only be exercised against a
        // real proof when one of the fixtures happens to contain one; report that explicitly
        // instead of failing the suite on fixture luck.
        vm.skip(true, "no checked-in proof carries a duplicated final-round query; regenerate one that does");
    }

    /// Locate the second copy of a duplicated final-round query row. The final intermediate
    /// commitment is opened as an Arkworks Vec of `inDomainSamples` rows of `interleavingDepth`
    /// extension-field elements (24 bytes each); rows are serialized in transcript order, so a
    /// repeated query index yields byte-identical rows.
    function _findFinalDuplicateRow(bytes memory hints, SpongefishWhirVerify.WhirParams memory whir)
        internal pure returns (bool found, uint256 duplicateOffset)
    {
        if (whir.numRounds == 0 || whir.rounds.length != whir.numRounds) return (false, 0);
        SpongefishWhirVerify.RoundParams memory finalRound = whir.rounds[whir.numRounds - 1];
        uint256 rawQueryCount = finalRound.inDomainSamples;
        uint256 rowBytes = finalRound.interleavingDepth * 24;
        uint256 expectedElements = rawQueryCount * finalRound.interleavingDepth;
        if (expectedElements > type(uint64).max) return (false, 0);
        uint256 prefixOffset = _findUniqueFinalVecPrefix(
            hints, uint64(expectedElements), rawQueryCount, rowBytes, finalRound.merkleDepth
        );
        uint256 rowsStart = prefixOffset + 8;
        bytes32[] memory rowHashes = new bytes32[](rawQueryCount);
        for (uint256 i = 0; i < rawQueryCount; i++) {
            bytes memory row = new bytes(rowBytes);
            for (uint256 b = 0; b < rowBytes; b++) row[b] = hints[rowsStart + i * rowBytes + b];
            rowHashes[i] = keccak256(row);
            for (uint256 j = 0; j < i; j++) {
                if (rowHashes[j] == rowHashes[i]) return (true, rowsStart + i * rowBytes);
            }
        }
        return (false, 0);
    }

    /// @notice Arkworks' Vec prefix is part of the canonical proof encoding, not padding.
    function test_realMleVerifier_rejectsWrongWhirVectorLengthPrefix() public {
        string memory json = _load("close_intent_mle.json");
        FixtureLib.DeployData memory dd = FixtureLib.parseDeployData(json);
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(json);
        require(dd.whirParams.numRounds > 0, "close fixture needs an intermediate WHIR round");
        require(dd.whirParams.rounds.length == dd.whirParams.numRounds, "close WHIR round count mismatch");

        // `_phaseFinalVectorAndMerkle` opens the final intermediate commitment. Its Arkworks Vec
        // contains one row of `interleavingDepth` extension-field elements for every transcript-
        // derived in-domain query, so `_consumeVecPrefix` expects exactly this product. Locate the
        // unique little-endian u64 prefix in the serialized hints instead of hard-coding its byte
        // offset: changing the close circuit changes Fiat-Shamir queries/Merkle paths and therefore
        // moves this prefix without changing the verifier boundary being tested.
        SpongefishWhirVerify.RoundParams memory finalRound = dd.whirParams.rounds[dd.whirParams.numRounds - 1];
        uint256 rawQueryCount = finalRound.inDomainSamples;
        uint256 expectedElements = rawQueryCount * finalRound.interleavingDepth;
        require(expectedElements <= type(uint64).max, "final Vec length exceeds u64");
        uint256 finalVecPrefixOffset = _findUniqueFinalVecPrefix(
            proof.whirHints,
            uint64(expectedElements),
            rawQueryCount,
            finalRound.interleavingDepth * 24,
            finalRound.merkleDepth
        );

        bytes32 gatesDigest = verifier.computeGatesDigest(
            proof.gates,
            proof.witnessIndividualEvalsAtRGateV2.length,
            proof.numSelectors,
            proof.numGateConstraints,
            proof.quotientDegreeFactor
        );
        proof.whirHints[finalVecPrefixOffset] = bytes1(uint8(proof.whirHints[finalVecPrefixOffset]) ^ 1);

        vm.expectRevert(InvalidMleProof.selector);
        verifier.verify(proof, _verifyParams(dd), dd.whirParams, gatesDigest);
    }

    /// @dev Locate the final canonical Arkworks u64-LE prefix. Besides exact 64-bit matching, the
    ///      candidate must leave exactly the final raw rows followed only by whole Merkle hashes,
    ///      bounded by one sibling per query per tree layer. This ties the dynamic location to the
    ///      final-opening shape instead of accepting an equal 8-byte sequence in arbitrary row data.
    function _findUniqueFinalVecPrefix(
        bytes memory data,
        uint64 needle,
        uint256 rawQueryCount,
        uint256 rowBytes,
        uint256 merkleDepth
    ) internal pure returns (uint256 offset) {
        require(data.length >= 8, "WHIR hints too short for Vec prefix");
        uint256 rowsBytes = rawQueryCount * rowBytes;
        uint256 maxMerkleBytes = rawQueryCount * merkleDepth * 32;
        bool found;
        for (uint256 i = 0; i <= data.length - 8; i++) {
            if (_readU64LeAt(data, i) != needle) continue;
            uint256 rowsEnd = i + 8 + rowsBytes;
            if (rowsEnd > data.length) continue;
            uint256 merkleBytes = data.length - rowsEnd;
            if (merkleBytes % 32 != 0 || merkleBytes > maxMerkleBytes) continue;
            require(!found, "ambiguous final Vec prefix");
            found = true;
            offset = i;
        }
        require(found, "final Vec prefix not found");
    }

    function _readU64LeAt(bytes memory data, uint256 offset) internal pure returns (uint64 value) {
        assembly {
            let word := shr(192, mload(add(add(data, 0x20), offset)))
            word := or(and(shr(8, word), 0x00FF00FF00FF00FF), and(shl(8, word), 0xFF00FF00FF00FF00))
            word := or(and(shr(16, word), 0x0000FFFF0000FFFF), and(shl(16, word), 0xFFFF0000FFFF0000))
            value := and(or(shr(32, word), shl(32, word)), 0xFFFFFFFFFFFFFFFF)
        }
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

        vm.expectRevert(InvalidMleProof.selector);
        verifier.verify(proof, _verifyParams(dd), dd.whirParams, gatesDigest);
    }

    function _verifyParams(FixtureLib.DeployData memory dd) internal pure returns (MleVerifier.VerifyParams memory) {
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
