// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {KZGProof, TestProofDaVerifier} from "./helpers/ProofDaTestHelper.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {Plonky2GateEvaluator} from "@mle/Plonky2GateEvaluator.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {InvalidMleProof} from "@mle/MleProofErrors.sol";

/// @dev SECURITY (C-1/B-4): emits the production verifier's proof-dependent negative verdict.
contract RejectingMleVerifier {
    function verify(
        MleVerifier.MleProof calldata,
        MleVerifier.VerifyParams memory,
        SpongefishWhirVerify.WhirParams memory,
        bytes32
    ) external pure returns (bool) {
        revert InvalidMleProof();
    }

    function fraudVerdictEncoded(bytes calldata, bytes32, bytes4, bool) external pure returns (uint8) {
        return 0;
    }
}

/// @dev A legacy/mismatched verifier returning false did not authenticate why it rejected.
contract FalseReturningMleVerifier {
    function verify(
        MleVerifier.MleProof calldata,
        MleVerifier.VerifyParams memory,
        SpongefishWhirVerify.WhirParams memory,
        bytes32
    ) external pure returns (bool) {
        return false;
    }


    function fraudVerdictEncoded(bytes calldata, bytes32, bytes4, bool) external pure returns (uint8) {
        return 2;
    }
}

contract EmptyRevertMleVerifier {
    function verify(
        MleVerifier.MleProof calldata,
        MleVerifier.VerifyParams memory,
        SpongefishWhirVerify.WhirParams memory,
        bytes32
    ) external pure returns (bool) {
        assembly { revert(0, 0) }
    }

    function fraudVerdictEncoded(bytes calldata, bytes32, bytes4, bool) external pure returns (uint8) {
        assembly { revert(0, 0) }
    }
}

contract UnknownErrorMleVerifier {
    error InternalVerifierFailure();

    function verify(
        MleVerifier.MleProof calldata,
        MleVerifier.VerifyParams memory,
        SpongefishWhirVerify.WhirParams memory,
        bytes32
    ) external pure returns (bool) {
        revert InternalVerifierFailure();
    }

    function fraudVerdictEncoded(bytes calldata, bytes32, bytes4, bool) external pure returns (uint8) {
        revert InternalVerifierFailure();
    }
}

/// @dev SECURITY (C-1/B-4, gate-8 class): a stand-in that reverts exactly the way
///      `Plonky2GateEvaluator.sol` does on a gate the deployed evaluator cannot handle
///      (`revert("unsupported gate with non-zero filter")`). The proof is honest; the evaluator
///      simply cannot evaluate it. This must NOT be convictable.
contract UnsupportedGateMleVerifier {
    function verify(
        MleVerifier.MleProof calldata,
        MleVerifier.VerifyParams memory,
        SpongefishWhirVerify.WhirParams memory,
        bytes32
    ) external pure returns (bool) {
        revert("unsupported gate with non-zero filter");
    }

    function fraudVerdictEncoded(bytes calldata, bytes32, bytes4, bool) external pure returns (uint8) {
        revert("unsupported gate with non-zero filter");
    }
}

/// @dev SECURITY (C-1/B-4, gas starvation): ACCEPTS every proof but burns a fixed, large amount
///      of gas first - the shape of the real verifier, measured at 11,019,291 gas on the repo's
///      own fixture (`MleE2E::test_mleVerify_gas`). Used to show the transaction gas limit can no
///      longer steer the fraud verdict.
contract GasHungryMleVerifier {
    uint256 public immutable rounds;
    constructor(uint256 rounds_) { rounds = rounds_; }
    function verify(
        MleVerifier.MleProof calldata,
        MleVerifier.VerifyParams memory,
        SpongefishWhirVerify.WhirParams memory,
        bytes32
    ) external view returns (bool) {
        _burn();
        return true;
    }

    function fraudVerdictEncoded(bytes calldata, bytes32, bytes4, bool) external view returns (uint8) {
        _burn();
        return 1;
    }

    function _burn() private view {
        uint256 acc = 1;
        uint256 n = rounds;
        for (uint256 i = 0; i < n; i++) acc = uint256(keccak256(abi.encode(acc, i)));
        require(acc != 0, "unreachable");
    }
}

/// @title RollupFraudHardening
/// @notice Regression tests for the 2026-08-28 audit findings C-1, H-1, H-4 and H-5.
///         Every test in this file FAILS on the pre-fix contracts.
contract RollupFraudHardeningTest is Test {
    IntmaxRollup public rollup;

    address submitter     = makeAddr("honest_submitter");
    address attacker      = makeAddr("attacker");
    address fraudTreasury = makeAddr("fraudTreasury");

    uint256 internal constant BLS12_SCALAR_R =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    function setUp() public {
        // degreeBits = 0 → `_verifyMle` short-circuits to TRUE, i.e. every committed proof is
        // treated as VALID. That is exactly the setting the C-1 test needs: an honest submission
        // whose proof genuinely verifies must not be convictable.
        rollup = new IntmaxRollup(
            fraudTreasury,
            _emptyMleVk(),
            _emptyWhirParams(),
            "",
            "",
            _emptyMleArrays(),
            _emptyMleArrays(),
            new MleVerifier(block.chainid),
            bytes32(0),
            true
        );
        rollup.setKzgVerifier(BlobKZGVerifierExt(address(new TestProofDaVerifier())));
        rollup.setBlockProducer(address(this), true);
        rollup.setBlockProducer(submitter, true);
        vm.deal(submitter, 10 ether);
        vm.deal(attacker, 10 ether);
    }

    // =======================================================================
    // C-1 — a fraud proof must not be constructible against an honest submission
    // =======================================================================

    /// @dev C-1: the attacker replays the honest submission's REAL blob bytes and REAL PI values,
    ///      changing ONLY `validityPIs.prover` — a field constrained nowhere on-chain and a free
    ///      witness in the validity circuit. Pre-fix this forced a piHash mismatch, which the fraud
    ///      predicate treated as CONFIRMED FRAUD: the submission (and every later one) was deleted,
    ///      90% of each bond was paid to the attacker and the chain was rolled back.
    function test_C1_honestSubmissionCannotBeConvictedByFlippingProver() public {
        bytes32 stateRoot = keccak256("honest_state");

        // Honest submission: PIs match on-chain state, proof carries the matching PI limbs.
        IntmaxRollup.ValidityPublicInputs memory honestPis = _pisFor(stateRoot, address(0));
        MleVerifier.MleProof memory mleProof = _mleProofWithPI(_computePIHash(honestPis));
        bytes memory proofBytes = abi.encode(mleProof);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        (KZGProof memory kzg, bytes32 blobHash) =
            _postWithKZG(_batch(1, ids, 100, bytes32(uint256(0xabc))), proofBytes, stateRoot, submitter);

        // Sanity: the honest submission exists and its bond is locked.
        assertEq(rollup.getSubmission(0).submitter, submitter, "honest submission recorded");
        assertEq(address(rollup).balance, 1 ether, "bond locked");

        // ── The attack: identical proof bytes, identical PI values, ONLY `prover` flipped. ──
        IntmaxRollup.ValidityPublicInputs memory forgedPis = _pisFor(stateRoot, attacker);
        assertTrue(
            _computePIHash(forgedPis) != _computePIHash(honestPis),
            "flipping prover must change the PI hash (that is the whole attack)"
        );

        vm.prank(attacker);
        bool fraudConfirmed = rollup.fraudProof(0, stateRoot, forgedPis, proofBytes);

        assertFalse(fraudConfirmed, "C-1: honest submission must NOT be convictable");
        // Nothing was slashed, truncated or rolled back.
        assertEq(rollup.pendingWithdrawals(attacker), 0, "attacker must earn no fraud reward");
        assertEq(rollup.nextSubmissionId(), 1, "submission must survive");
        assertEq(rollup.getSubmission(0).submitter, submitter, "submission not deleted");
        assertEq(rollup.blockNumber(), 1, "chain must not roll back");
    }

    /// @dev C-1 must not disarm the fraud path: a submission whose committed proof genuinely fails
    ///      verification is still convictable.
    ///
    ///      B-4: this test previously reached "fraud confirmed" through a REVERT inside
    ///      `_verifyMleWithVk` (a garbage `whirTranscript` makes the real verifier revert), which
    ///      is precisely the route that also convicted honest submitters. It now runs against a
    ///      verifier that emits the authenticated proof-rejection selector.
    function test_C1_genuinelyInvalidProofIsStillConvictable() public {
        IntmaxRollup r = _mleEnabledRollupOn(address(new RejectingMleVerifier()), true);

        bytes32 stateRoot = keccak256("bad_state");
        IntmaxRollup.ValidityPublicInputs memory pis = _pisForOn(r, stateRoot, address(0));
        MleVerifier.MleProof memory mleProof = _mleProofWithPI(_computePIHash(pis));
        bytes memory proofBytes = abi.encode(mleProof);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 2;
        (KZGProof memory kzg, bytes32 blobHash) =
            _postWithKZGOn(r, _batch(1, ids, 200, bytes32(uint256(0xdef))), proofBytes, stateRoot, submitter);

        vm.prank(attacker);
        assertTrue(
            r.fraudProof(0, stateRoot, pis, proofBytes),
            "a genuinely invalid proof must still be convictable"
        );
        assertGt(r.pendingWithdrawals(attacker), 0, "honest fraud prover is still rewarded");
    }

    /// @dev Deploy an MLE-ENABLED rollup (non-zero validity VK, so the degreeBits==0 bypass is
    ///      dead) on an arbitrary verifier satellite.
    function _mleEnabledRollupOn(address verifierAddr, bool allowMleDisabled_)
        internal returns (IntmaxRollup r)
    {
        IntmaxRollup.MleVk memory enabledVk = IntmaxRollup.MleVk({
            degreeBits: 13, preprocessedRoot: bytes32(0),
            numConstants: 0, numRoutedWires: 0, gatesDigest: bytes32(0)
        });
        r = new IntmaxRollup(
            fraudTreasury, enabledVk, _emptyWhirParams(), "", "",
            _emptyMleArrays(), _emptyMleArrays(), MleVerifier(verifierAddr), bytes32(0),
            allowMleDisabled_
        );
        r.setBlockProducer(submitter, true);
        if (allowMleDisabled_) {
            r.setKzgVerifier(BlobKZGVerifierExt(address(new TestProofDaVerifier())));
        }
    }

    // =======================================================================
    // B-4 - "could not evaluate" must never read as "fraud"
    // =======================================================================

    /// @dev B-4 (a): GAS STARVATION. EIP-150 forwards 63/64 of the available gas to the inner
    ///      verification call, so the transaction gas limit is a free attacker input that never
    ///      appears in calldata. Pre-fix, an attacker scanned for the limit at which the inner
    ///      call OOGs while the outer frame survived to run `_truncateSubmissions`, and convicted
    ///      an honest submission. Post-fix, an OOG is MLE_STARVED, which reverts the whole
    ///      `fraudProof`: no truncation, no bond movement, at ANY gas limit.
    function test_B4_gasStarvationCannotConvictAnHonestSubmission() public {
        (IntmaxRollup r, bytes memory payload) =
            _honestSubmissionOn(address(new GasHungryMleVerifier(9_000)));

        // Control: fully funded, the honest submission is not convictable.
        uint256 gBefore = gasleft();
        (bool okHi, bytes memory retHi) = address(r).call(payload);
        uint256 honestCost = gBefore - gasleft();
        assertTrue(okHi, "control call must succeed");
        assertFalse(abi.decode(retHi, (bool)), "control: honest submission is not convictable");

        // Attack: sweep the gas limit. No limit may ever convict.
        uint256 step = honestCost / 40 + 1;
        for (uint256 g = honestCost / 4; g <= honestCost + 4 * step; g += step) {
            vm.prank(attacker);
            (bool ok, bytes memory ret) = address(r).call{gas: g}(payload);
            if (ok && ret.length == 32) {
                assertFalse(abi.decode(ret, (bool)), "B-4: no gas limit may convict");
            }
        }
        // Pin the diagnostic: a call that clears the whole flow but leaves less than
        // MIN_MLE_VERIFY_GAS at the verdict reverts FraudProofGasStarved, never "fraud".
        vm.prank(attacker);
        (bool okStarved, bytes memory retStarved) =
            address(r).call{gas: honestCost + 100_000}(payload);
        assertFalse(okStarved, "B-4: a starved fraudProof must revert");
        assertEq(
            bytes4(retStarved), IntmaxRollup.FraudProofGasStarved.selector,
            "B-4: fraudProof reverts FraudProofGasStarved"
        );

        assertEq(r.nextSubmissionId(), 1, "B-4: the honest submission survived every gas limit");
        assertEq(r.blockNumber(), 1, "B-4: the chain was never rolled back");
        assertEq(r.pendingWithdrawals(attacker), 0, "B-4: no bond was ever paid to the attacker");
    }

    /// @dev B-4 (b): the GATE-8 class verbatim. `Plonky2GateEvaluator` reverts by design on a gate
    ///      the deployed evaluator cannot handle. That is a property of the evaluator, not of the
    ///      proof, so it must not convict anyone. `fraudProof` now reverts `MleProofUnevaluable`.
    ///
    ///      SOUNDNESS OF THE TRADE: refusing to convict here costs only the fraud REWARD, never
    ///      safety. A submission whose proof cannot be evaluated also cannot be FINALIZED
    ///      (`finalize`'s `fullVerify` try/catch is fail-CLOSED), so it is still removed by the
    ///      `FINALIZE_DEADLINE_BLOCKS` timeout branch - the right outcome for a submission nobody
    ///      can check.
    function test_B4_unsupportedGateRevertCannotConvictAnHonestSubmission() public {
        (IntmaxRollup r, bytes memory payload) =
            _honestSubmissionOn(address(new UnsupportedGateMleVerifier()));

        vm.prank(attacker);
        (bool ok, bytes memory ret) = address(r).call(payload);
        assertFalse(ok, "B-4: an evaluator revert must not produce a fraud verdict");
        assertEq(
            bytes4(ret), IntmaxRollup.MleProofUnevaluable.selector,
            "B-4: fraudProof must revert MleProofUnevaluable"
        );

        assertEq(r.nextSubmissionId(), 1, "B-4: honest submission survives");
        assertEq(r.pendingWithdrawals(attacker), 0, "B-4: no bond stolen");

        // The timeout backstop still removes it, so liveness of removal is preserved.
        vm.roll(block.number + 3601);
        IntmaxRollup.ValidityPublicInputs memory emptyPis;
        vm.prank(attacker);
        assertTrue(
            r.fraudProof(0, bytes32(0), emptyPis, ""),
            "B-4: the 12-hour timeout branch still removes an un-evaluable submission"
        );
    }

    function test_B4_falseReturnWithoutAuthenticatedSelectorCannotConvict() public {
        _assertUnevaluableCannotConvict(address(new FalseReturningMleVerifier()));
    }

    function test_B4_emptyRevertCannotConvict() public {
        _assertUnevaluableCannotConvict(address(new EmptyRevertMleVerifier()));
    }

    function test_B4_unknownCustomErrorCannotConvict() public {
        _assertUnevaluableCannotConvict(address(new UnknownErrorMleVerifier()));
    }

    function _assertUnevaluableCannotConvict(address verifierAddr) internal {
        (IntmaxRollup r, bytes memory payload) = _honestSubmissionOn(verifierAddr);

        vm.prank(attacker);
        (bool ok, bytes memory ret) = address(r).call(payload);
        assertFalse(ok, "unauthenticated verifier outcome must not convict");
        assertEq(bytes4(ret), IntmaxRollup.MleProofUnevaluable.selector, "must be unevaluable");
        assertEq(r.nextSubmissionId(), 1, "honest submission must survive");
        assertEq(r.pendingWithdrawals(attacker), 0, "attacker must receive no bond");
    }

    // =======================================================================
    // B-3 - the PRODUCTION fraud path must actually work
    // =======================================================================

    /// @dev B-3: the pre-timeout fraud path remains reachable with a non-zero validity VK and the
    ///      degreeBits==0 bypass disabled. This suite isolates the verdict state machine with the
    ///      test Proof-DA satellite; ProofDaRollup covers the same route with canonical proof bytes.
    function test_B3_honestProverConvictsInvalidBatchOnProductionShapedDeployment() public {
        IntmaxRollup r = _mleEnabledRollupOn(address(new RejectingMleVerifier()), false);
        assertFalse(r.allowMleDisabled(), "no test bypass on a production-shaped rollup");
        r.setKzgVerifier(BlobKZGVerifierExt(address(new TestProofDaVerifier())));
        vm.deal(submitter, 10 ether);

        bytes32 stateRoot = keccak256("genuinely_bad_state");
        IntmaxRollup.ValidityPublicInputs memory pis = _pisForOn(r, stateRoot, address(0xBEEF));
        MleVerifier.MleProof memory mleProof = _mleProofWithPI(_computePIHash(pis));
        bytes memory proofBytes = abi.encode(mleProof);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        _postWithKZGOn(
            r, _batch(1, ids, 100, bytes32(uint256(0xabc))), proofBytes, stateRoot, submitter
        );

        vm.prank(attacker);
        assertTrue(
            r.fraudProof(0, stateRoot, pis, proofBytes),
            "B-3: an honest prover must be able to convict a genuinely invalid batch in production"
        );
        assertEq(r.nextSubmissionId(), 0, "B-3: the invalid batch was removed");
        assertGt(r.pendingWithdrawals(attacker), 0, "B-3: the honest fraud prover is rewarded");
    }

    /// @dev Post one honest submission and return the exact current `fraudProof(...)` calldata an
    ///      attacker would send against it. Blob/KZG behavior is isolated in ProofDaRollup.
    function _honestSubmissionOn(address verifierAddr)
        internal returns (IntmaxRollup r, bytes memory payload)
    {
        r = _mleEnabledRollupOn(verifierAddr, false);
        r.setKzgVerifier(BlobKZGVerifierExt(address(new TestProofDaVerifier())));
        vm.deal(submitter, 10 ether);
        vm.deal(attacker, 10 ether);

        bytes32 stateRoot = keccak256("honest_state");
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = _batch(1, ids, 100, bytes32(uint256(0xabc)));
        IntmaxRollup.ValidityPublicInputs memory pis =
            _pisForBatch(r, batch, stateRoot, address(0xBEEF));

        MleVerifier.MleProof memory mleProof = _mleProofWithPI(_computePIHash(pis));
        bytes memory proofBytes = abi.encode(mleProof);
        _postWithKZGOn(r, batch, proofBytes, stateRoot, submitter);

        payload = abi.encodeCall(
            IntmaxRollup.fraudProof,
            (0, stateRoot, pis, proofBytes)
        );
    }

    // =======================================================================
    // H-5 — finalize must bind submissionId to the proof it verifies
    // =======================================================================

    /// @dev H-5: submission B is finalized using submission A's proof. Pre-fix this succeeded — B
    ///      was marked finalized and its bond refunded although B's own proof was never verified,
    ///      and B became permanently un-slashable.
    function test_H5_cannotFinalizeOneSubmissionWithAnothersProof() public {
        bytes32 rootA = keccak256("state_A");

        // Submission A (id 0): a real, verifiable proof for rootA.
        IntmaxRollup.ValidityPublicInputs memory pisA = _pisFor(rootA, address(0));
        MleVerifier.MleProof memory proofA = _mleProofWithPI(_computePIHash(pisA));
        bytes memory bytesA = abi.encode(proofA);
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        _postWithKZG(_batch(1, ids, 100, bytes32(uint256(0x111))), bytesA, rootA, submitter);

        // Submission B (id 1): a DIFFERENT committed state root, posted by someone else.
        bytes32 rootB = keccak256("state_B");
        uint32[] memory ids2 = new uint32[](1);
        ids2[0] = 2;
        _postWithKZG(_batch(2, ids2, 200, bytes32(uint256(0x222))), bytesA, rootB, submitter);
        assertEq(rollup.nextSubmissionId(), 2, "two submissions posted");

        // The attack: finalize B (id 1) with A's public proof and A's PIs.
        vm.prank(attacker);
        bool ok = rollup.finalize(1, rootA, pisA, proofA);

        assertFalse(ok, "H-5: must not finalize submission B with submission A's proof");
        assertFalse(rollup.isFinalized(1), "B must not be marked finalized");
        assertFalse(rollup.isFinalizedStateRoot(rootA), "no state root may be accepted this way");
        // The bond must still be at risk (not refunded), so B stays slashable.
        assertEq(rollup.pendingWithdrawals(submitter), 0, "B's bond must not be refunded");
    }

    /// @dev H-5 must not break the honest path: finalizing a submission with ITS OWN proof works.
    function test_H5_honestFinalizeStillWorks() public {
        bytes32 root = keccak256("honest_final_state");
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = _batch(1, ids, 100, bytes32(uint256(0x333)));

        // B-5: the PIs must name the batch's own end height (see `_pisForBatch`).
        IntmaxRollup.ValidityPublicInputs memory pis = _pisForBatch(rollup, batch, root, address(0));
        MleVerifier.MleProof memory proof = _mleProofWithPI(_computePIHash(pis));

        _postWithKZG(batch, abi.encode(proof), root, submitter);

        assertTrue(rollup.finalize(0, root, pis, proof), "honest finalize must still succeed");
        assertTrue(rollup.isFinalized(0), "submission finalized");
        assertEq(rollup.pendingWithdrawals(submitter), 1 ether, "bond refunded to the submitter");
    }

    // =======================================================================
    // H-1 — a rollback must not destroy deposits / channel registrations
    // =======================================================================

    /// @dev H-1: `_pendingDepositHashChain` is advanced ONLY by `deposit()`; `_postBlock` never
    ///      writes it. Restoring the pre-batch snapshot on rollback could therefore only ERASE
    ///      deposits made AFTER the batch was posted, while their ETH stays in `totalEscrowed` —
    ///      crediting the funds to nobody. Uses the permissionless proof-free timeout branch.
    function test_H1_rollbackDoesNotEraseDepositMadeAfterThePost() public {
        // D1 lands BEFORE the batch, so it is inside the batch's pre-snapshot.
        rollup.deposit{value: 100}(bytes32(uint256(0xd1)), 0, 100, bytes32(uint256(0xa1)));

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(1, ids, 100, bytes32(uint256(0x101))), keccak256("p"), 1, keccak256("s"),
            rollup.pendingChainsPin()
        );
        bytes32 chainWithD1Only = rollup.blockDepositHash(1);
        assertTrue(chainWithD1Only != bytes32(0), "D1 folded into the posted block");

        // D2 lands AFTER the batch was posted. It belongs to nobody's batch yet.
        rollup.deposit{value: 100}(bytes32(uint256(0xd2)), 0, 100, bytes32(uint256(0xa2)));
        uint256 escrowedBefore = rollup.totalEscrowed();

        // Roll the batch back through the proof-free timeout branch.
        vm.roll(block.number + 3601);
        IntmaxRollup.ValidityPublicInputs memory emptyPis;
        vm.prank(attacker);
        assertTrue(
            rollup.fraudProof(0, bytes32(0), emptyPis, ""),
            "timeout removal"
        );
        assertEq(rollup.blockNumber(), 0, "batch rolled back");

        // The escrowed ETH is (correctly) NOT rolled back...
        assertEq(rollup.totalEscrowed(), escrowedBefore, "escrow must not roll back");

        // ...so the deposit chain that entitles anyone to it must not be rolled back either.
        // Re-post: the new block must carry a chain that still includes D2.
        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(1, ids, 300, bytes32(uint256(0x303))), keccak256("p2"), 1, keccak256("s2"),
            rollup.pendingChainsPin()
        );
        assertTrue(
            rollup.blockDepositHash(1) != chainWithD1Only,
            "H-1: rollback erased the post-batch deposit (D2) - its ETH is credited to nobody"
        );
    }

    /// @dev H-1, channel-registration leg: same defect, and worse — `channelMemberSetCommitment`
    ///      is not rolled back, so the one-time `registerChannel` guard still fires and a wiped
    ///      registration can never be replayed, bricking the channelId forever.
    function test_H1_rollbackDoesNotEraseChannelRegistrationMadeAfterThePost() public {
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(1, ids, 100, bytes32(uint256(0x101))), keccak256("p"), 1, keccak256("s"),
            rollup.pendingChainsPin()
        );
        bytes32 regChainBefore = rollup.blockChannelRegHash(1);

        // Register AFTER the batch was posted.
        _registerChannel(7);

        vm.roll(block.number + 3601);
        IntmaxRollup.ValidityPublicInputs memory emptyPis;
        vm.prank(attacker);
        assertTrue(
            rollup.fraudProof(0, bytes32(0), emptyPis, ""),
            "timeout removal"
        );

        // Re-post; the registration must still be in the chain.
        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(1, ids, 300, bytes32(uint256(0x303))), keccak256("p2"), 1, keccak256("s2"),
            rollup.pendingChainsPin()
        );
        assertTrue(
            rollup.blockChannelRegHash(1) != regChainBefore,
            "H-1: rollback erased the post-batch channel registration, bricking the channelId"
        );
    }

    // =======================================================================
    // H-4 / B-6 — caller-supplied trusted-setup API is gone
    // =======================================================================

    function test_H4_callerSuppliedTrustedSetupApiIsRemoved() public {
        BlobKZGVerifierExt prod = new BlobKZGVerifierExt();
        bytes4 legacySelector = bytes4(
            keccak256("verify(bytes32,(bytes,bytes,bytes,bytes,bytes),bytes)")
        );
        (bool ok,) = address(prod).staticcall(abi.encodeWithSelector(legacySelector));
        assertFalse(ok, "legacy caller-supplied KZG setup entry point must not exist");
    }

    function test_B6_standardVerifierRequiresCompactEip4844Sidecar() public {
        BlobKZGVerifierExt prod = new BlobKZGVerifierExt();
        vm.expectRevert(
            abi.encodeWithSelector(BlobKZGVerifierExt.SidecarLengthMismatch.selector, 96, 0)
        );
        prod.verify(hex"01", "");
    }

    // =======================================================================
    // Helpers
    // =======================================================================

    function _registerChannel(uint32 channelId) internal {
        bytes32[] memory pkGs = new bytes32[](2);
        bytes32[] memory pkBs = new bytes32[](2);
        bytes32[] memory regev = new bytes32[](2);
        address[] memory recips = new address[](2);
        for (uint256 i = 0; i < 2; i++) {
            pkGs[i]  = keccak256(abi.encodePacked("pkg", channelId, i));
            pkBs[i]  = keccak256(abi.encodePacked("pkb", channelId, i));
            regev[i] = keccak256(abi.encodePacked("rg", channelId, i));
            recips[i] = address(uint160(uint256(keccak256(abi.encodePacked("r", channelId, i)))));
        }
        rollup.registerChannel(channelId, 0, 0, pkGs, pkBs, regev, recips);
    }

    /// @dev SECURITY (H-5/B-5): `finalize` pins `validityPIs.finalBlockNumber` to the submission's
    ///      own batch `endBlockNumber`. Replay the exact batch against a state snapshot to learn
    ///      the (endBlockNumber, blockHashChain) the real post will produce, then rewind — rather
    ///      than reimplement `_postBlock`'s deposit/channel-reg fold in the harness.
    function _pisForBatch(
        IntmaxRollup target,
        IntmaxRollup.SubBlock[] memory batch,
        bytes32 stateRoot,
        address prover
    ) internal returns (IntmaxRollup.ValidityPublicInputs memory pis) {
        pis = _pisForOn(target, stateRoot, prover);
        uint256 snap = vm.snapshotState();
        _mockBlob();
        target.setBlockProducer(address(this), true);
        vm.deal(address(this), address(this).balance + 1 ether);
        target.postBlockAndSubmit{value: 1 ether}(
            batch, bytes32(uint256(1)), 1, stateRoot, target.pendingChainsPin()
        );
        pis.finalBlockNumber = target.blockNumber();
        pis.finalBlockChain = target.blockHashChain();
        vm.revertToState(snap);
    }

    function _pisFor(bytes32 stateRoot, address prover)
        internal view returns (IntmaxRollup.ValidityPublicInputs memory)
    {
        return _pisForOn(rollup, stateRoot, prover);
    }

    function _pisForOn(IntmaxRollup target, bytes32 stateRoot, address prover)
        internal view returns (IntmaxRollup.ValidityPublicInputs memory pis)
    {
        pis = IntmaxRollup.ValidityPublicInputs({
            initialBlockNumber: 0,
            initialBlockChain:  target.blockHashChainAt(0),
            initialExtCommitment: target.latestFinalizedStateRoot(),
            finalBlockNumber:   target.blockNumber(),
            finalBlockChain:    target.blockHashChain(),
            finalExtCommitment: stateRoot,
            prover: prover
        });
    }

    function _computePIHash(IntmaxRollup.ValidityPublicInputs memory pis)
        internal pure returns (bytes32)
    {
        return keccak256(abi.encodePacked(
            pis.initialBlockNumber, pis.initialBlockChain, pis.initialExtCommitment,
            pis.finalBlockNumber, pis.finalBlockChain, pis.finalExtCommitment, pis.prover
        ));
    }

    function _piLimbs(bytes32 piHash) internal pure returns (uint256[] memory limbs) {
        limbs = new uint256[](8);
        uint256 h = uint256(piHash);
        for (uint256 i = 0; i < 8; i++) {
            limbs[i] = (h >> (224 - i * 32)) & 0xFFFFFFFF;
        }
    }

    function _mleProofWithPI(bytes32 piHash) internal pure returns (MleVerifier.MleProof memory p) {
        p = _defaultMleProof();
        p.publicInputs = _piLimbs(piHash);
    }

    function _defaultMleProof() internal pure returns (MleVerifier.MleProof memory proof) {
        proof.circuitDigest = new uint256[](0);
        proof.whirTranscript = "";
        proof.whirHints = "";
        proof.preprocessedIndividualEvals = new uint256[](0);
        proof.witnessIndividualEvals = new uint256[](0);
        proof.publicInputs = new uint256[](0);
        proof.witnessIndividualEvalsAtRInv = new uint256[](0);
        proof.preprocessedIndividualEvalsAtRInv = new uint256[](0);
        proof.inverseHelpersEvalsAtRInv = new uint256[](0);
        proof.inverseHelpersEvalsAtRH = new uint256[](0);
        proof.witnessIndividualEvalsAtRGateV2 = new uint256[](0);
        proof.preprocessedIndividualEvalsAtRGateV2 = new uint256[](0);
        proof.gates = new Plonky2GateEvaluator.GateInfo[](0);
    }

    function _emptyMleVk() internal pure returns (IntmaxRollup.MleVk memory vk) {}

    function _emptyWhirParams() internal pure returns (SpongefishWhirVerify.WhirParams memory p) {
        p.rounds = new SpongefishWhirVerify.RoundParams[](0);
        p.evaluationPoint = new GoldilocksExt3.Ext3[](0);
        p.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);
    }

    function _emptyMleArrays() internal pure returns (uint256[] memory) {
        return new uint256[](0);
    }

    function _batch(uint32 aggId, uint32[] memory ids, uint64 ts, bytes32 txRoot)
        internal pure returns (IntmaxRollup.SubBlock[] memory b)
    {
        b = new IntmaxRollup.SubBlock[](1);
        b[0] = IntmaxRollup.SubBlock({
            channelId: aggId, timestamp: ts, txTreeRoot: txRoot, keyIds: ids
        });
    }

    function _mockBlob() internal {
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = bytes32(uint256(0xdeadbeef));
        vm.blobhashes(hashes);
    }

    function _postWithKZG(
        IntmaxRollup.SubBlock[] memory batch,
        bytes memory proofBytes,
        bytes32 stateRoot,
        address poster
    ) internal returns (KZGProof memory kzg, bytes32 blobHash) {
        return _postWithKZGOn(rollup, batch, proofBytes, stateRoot, poster);
    }

    function _postWithKZGOn(
        IntmaxRollup target,
        IntmaxRollup.SubBlock[] memory batch,
        bytes memory proofBytes,
        bytes32 stateRoot,
        address poster
    ) internal returns (KZGProof memory kzg, bytes32 blobHash) {
        (kzg, blobHash) = _computeKZGProof(proofBytes);
        bytes32[] memory hs = new bytes32[](1);
        hs[0] = blobHash;
        vm.blobhashes(hs);
        target.setBlockProducer(poster, true);
        bytes32 pin = target.pendingChainsPin();
        vm.prank(poster);
        target.postBlockAndSubmit{value: 1 ether}(
            batch, keccak256(proofBytes), uint32(proofBytes.length), stateRoot, pin
        );
    }

    // ── KZG construction (mirrors IntmaxRollup.t.sol's helper) ─────────────

    function _bls12G1GenBytes() internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f",
            hex"c3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            hex"0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4",
            hex"fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
        );
    }

    function _bls12G2GenBytes() internal pure returns (bytes memory) {
        return abi.encodePacked(
            // SECURITY (B-2): EIP-2537 orders X as x_c0 || x_c1. The previous layout here mirrored
            // the (malformed) constant `BlobKZGVerifier.G2_GENERATOR` used to ship; both are fixed.
            hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051",
            hex"c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
            hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65",
            hex"596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
            hex"000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a",
            hex"adfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
            hex"000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99",
            hex"cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
        );
    }

    function _compressG1(bytes memory pt128) internal pure returns (bytes memory c48) {
        require(pt128.length == 128, "compressG1: bad length");
        bytes32 x0; bytes32 x1; bytes32 y0; bytes32 y1;
        assembly {
            let p := add(pt128, 32)
            x0 := mload(add(p, 16))
            x1 := mload(add(p, 48))
            y0 := mload(add(p, 80))
            y1 := mload(add(p, 112))
        }
        bytes32 halfQ0 = 0x0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b12;
        bytes16 halfQ1 = bytes16(0x0f55ffff58a9ffffdcff7fffffffd555);
        bytes16 yEnd   = bytes16(y1);
        bool signBit = (y0 > halfQ0) || (y0 == halfQ0 && yEnd > halfQ1);
        c48 = abi.encodePacked(x0, bytes16(x1));
        c48[0] = bytes1(uint8(c48[0]) | 0x80 | (signBit ? uint8(0x20) : uint8(0)));
    }

    function _toFieldElementsMem(bytes memory data) internal pure returns (bytes32[] memory fes) {
        uint256 FIELD_MASK = type(uint256).max >> 3;
        uint256 n = (data.length + 31) / 32;
        fes = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 word;
            uint256 off = i * 32;
            uint256 rem = data.length - off;
            if (rem >= 32) {
                assembly { word := mload(add(add(data, 32), off)) }
            } else {
                bytes memory tmp = new bytes(32);
                for (uint256 j = 0; j < rem; j++) { tmp[j] = data[off + j]; }
                assembly { word := mload(add(tmp, 32)) }
            }
            fes[i] = bytes32(uint256(word) & FIELD_MASK);
        }
    }

    /// @dev Build a well-formed NON-DEGENERATE KZG multi-point opening: the GENERAL pairing
    ///      branch, which B-1 (wrong precompile address) and B-2 (malformed `G2_GENERATOR`)
    ///      together made unreachable, and whose unreachability was finding B-3.
    ///
    ///      The verifier equation is  e(C - [I(tau)]_1, G2) . e(-pi, [Z(tau)]_2) = 1, i.e. in
    ///      scalars C - I = z.pi with z = Z(tau). Nothing on-chain constrains the trusted-setup
    ///      points, so a self-consistent instance is built by choosing them:
    ///        lagrangeBasisG1[i] = G1   => [I(tau)]_1 = (sum f_i).G1 = S.G1
    ///        z = 2                     => vanishingG2 = G2ADD(G2, G2), NOT the generator, so the
    ///                                     H-4 degenerate guard does not fire
    ///        pi = 7.G1                 => C = (S + 14).G1
    ///      Then C - I = 14.G1 = 2.pi and the pairing holds.
    ///
    ///      RESIDUAL (B-6): that this instance can be BUILT by the test is the same freedom an
    ///      attacker has - the trusted-setup data is still caller-supplied. See the RESIDUAL RISK
    ///      note in BlobKZGVerifier and RedTeamFraudBreaks::test_RT4_*.
    function _computeGeneralKZGProof(bytes memory proofBytes)
        internal view returns (KZGProof memory kzg, bytes32 blobHash)
    {
        bytes32[] memory fes = _toFieldElementsMem(proofBytes);
        uint256 N = fes.length;

        uint256 S = 0;
        for (uint256 i = 0; i < N; i++) S = addmod(S, uint256(fes[i]), BLS12_SCALAR_R);

        bytes memory g1gen = _bls12G1GenBytes();
        bytes memory pi = _g1MulLocal(g1gen, bytes32(uint256(7)));
        bytes memory C  = _g1MulLocal(g1gen, bytes32(addmod(S, 14, BLS12_SCALAR_R)));

        bytes memory lagrangeBasis = new bytes(N * 128);
        for (uint256 i = 0; i < N; i++) {
            assembly {
                let src := add(g1gen, 32)
                let dst := add(add(lagrangeBasis, 32), mul(i, 128))
                mstore(dst,          mload(src))
                mstore(add(dst, 32), mload(add(src, 32)))
                mstore(add(dst, 64), mload(add(src, 64)))
                mstore(add(dst, 96), mload(add(src, 96)))
            }
        }

        bytes memory c48 = _compressG1(C);
        (bool okSha, bytes memory hb) = address(0x02).staticcall(c48);
        require(okSha && hb.length >= 32, "generalKZG: sha256 failed");
        blobHash = bytes32((uint256(0x01) << 248) |
            (uint256(bytes32(hb)) & (type(uint256).max >> 8)));

        bytes memory g2 = _bls12G2GenBytes();
        (bool okAdd, bytes memory vanishing) = address(0x0d).staticcall(bytes.concat(g2, g2));
        require(okAdd && vanishing.length == 256, "generalKZG: G2ADD failed");

        kzg = KZGProof({
            kzgCommitment48: c48,
            kzgCommitmentG1: C,
            openingProof:    pi,
            vanishingG2:     vanishing,
            lagrangeBasisG1: lagrangeBasis
        });
    }

    function _g1MulLocal(bytes memory pt, bytes32 sc) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = address(0x0c).staticcall(abi.encodePacked(pt, sc));
        require(ok && out.length == 128, "generalKZG: G1MSM failed");
    }

    function _computeKZGProof(bytes memory proofBytes)
        internal view returns (KZGProof memory kzg, bytes32 blobHash)
    {
        bytes32[] memory fes = _toFieldElementsMem(proofBytes);
        uint256 N = fes.length;

        uint256 S = 0;
        for (uint256 i = 0; i < N; i++) {
            S = addmod(S, uint256(fes[i]), BLS12_SCALAR_R);
        }
        uint256 Sp1 = addmod(S, 1, BLS12_SCALAR_R);

        bytes memory g1gen = _bls12G1GenBytes();
        (bool ok1, bytes memory commitment128) = address(0x0c).staticcall(
            abi.encodePacked(g1gen, bytes32(Sp1))
        );
        require(ok1 && commitment128.length == 128, "KZGProof: G1MSM C failed");

        bytes memory commitment48 = _compressG1(commitment128);
        (bool ok2, bytes memory hb) = address(0x02).staticcall(commitment48);
        require(ok2 && hb.length >= 32, "KZGProof: sha256 failed");
        blobHash = bytes32((uint256(0x01) << 248) |
            (uint256(bytes32(hb)) & (type(uint256).max >> 8)));

        bytes memory lagrangeBasis = new bytes(N * 128);
        for (uint256 i = 0; i < N; i++) {
            assembly {
                let src := add(g1gen, 32)
                let dst := add(add(lagrangeBasis, 32), mul(i, 128))
                mstore(dst,          mload(src))
                mstore(add(dst, 32), mload(add(src, 32)))
                mstore(add(dst, 64), mload(add(src, 64)))
                mstore(add(dst, 96), mload(add(src, 96)))
            }
        }

        kzg = KZGProof({
            kzgCommitment48: commitment48,
            kzgCommitmentG1: commitment128,
            openingProof:    g1gen,
            vanishingG2:     _bls12G2GenBytes(),
            lagrangeBasisG1: lagrangeBasis
        });
    }
}
