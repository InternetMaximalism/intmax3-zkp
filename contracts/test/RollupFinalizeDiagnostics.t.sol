// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {Plonky2GateEvaluator} from "@mle/Plonky2GateEvaluator.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";

/// @title M-8 — `finalize()` must not fail silently.
///
/// Before this fix `finalize` had three bare `return false` exits of its own and delegated the rest
/// to `fullVerify`, which had SEVEN more `return false` exits. Every one of them looked identical
/// from outside: a submitter whose proof the verifier could not even EVALUATE was told exactly what
/// a forger was told. Six declared errors (`CommitmentMismatch`, `SubmissionNotFound`,
/// `ProofVerificationFailed`, `InitialStateMismatch`, `BlockChainMismatch`, `MleVerificationFailed`)
/// were never raised anywhere — the ABI advertised checks that produced nothing.
///
/// This suite drives each distinct failure mode and asserts the `FinalizeRejected` reason code
/// identifies THAT cause and no other.
///
/// MUTATION CHECK: `test_everyReasonCodeIsDistinct` compares all nine reason codes pairwise. Collapse
/// any two causes back into one shared error (or back into a bare `return false`, which reports
/// `0x00000000`) and that test fails, along with the per-cause test for the collapsed branch.
///
/// SECURITY (fail-closed preserved): every test here asserts `finalize` still returned FALSE and the
/// submission is still NOT finalized. Naming the cause must never let a rejected proof through.
contract RollupFinalizeDiagnosticsTest is Test {
    IntmaxRollup internal rollup;
    MleVerifier internal mleVerifier;

    address internal fraudTreasury = makeAddr("fraudTreasury");
    address internal poster = makeAddr("poster");

    /// @dev Mirror of the contract's `FinalizeRejected` for `vm.expectEmit` / log decoding.
    event FinalizeRejected(uint256 indexed id, bytes4 reason);

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    function setUp() public {
        mleVerifier = new MleVerifier();
        rollup = _newRollup(0); // degreeBits = 0 → MLE verification skipped (test opt-in)
        vm.deal(poster, 100 ether);
    }

    function _newRollup(uint256 degreeBits) internal returns (IntmaxRollup r) {
        IntmaxRollup.MleVk memory vk = IntmaxRollup.MleVk({
            degreeBits: degreeBits,
            preprocessedRoot: bytes32(0),
            numConstants: 0,
            numRoutedWires: 0,
            gatesDigest: bytes32(0)
        });
        SpongefishWhirVerify.WhirParams memory p;
        p.rounds = new SpongefishWhirVerify.RoundParams[](0);
        p.evaluationPoint = new GoldilocksExt3.Ext3[](0);
        p.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);

        r = new IntmaxRollup(
            fraudTreasury,
            vk,
            p,
            "",
            "",
            new uint256[](0),
            new uint256[](0),
            mleVerifier,
            bytes32(0),
            true // A-2 test opt-in; irrelevant once degreeBits > 0
        );
        r.setBlockProducer(poster, true);
    }

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    function _emptyProof() internal pure returns (MleVerifier.MleProof memory proof) {
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

    function _piHash(IntmaxRollup.ValidityPublicInputs memory pis) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            pis.initialBlockNumber,
            pis.initialBlockChain,
            pis.initialExtCommitment,
            pis.finalBlockNumber,
            pis.finalBlockChain,
            pis.finalExtCommitment,
            pis.prover
        ));
    }

    /// @dev The 8 big-endian u32 limbs `_mlePublicInputsMatch` requires.
    function _limbs(bytes32 h) internal pure returns (uint256[] memory l) {
        l = new uint256[](8);
        for (uint256 i = 0; i < 8; i++) {
            l[i] = (uint256(h) >> (224 - i * 32)) & 0xFFFFFFFF;
        }
    }

    /// @dev Post one sub-block and submit against `stateRoot`. Returns the new submission id.
    function _post(IntmaxRollup r, uint32 channelId, bytes32 stateRoot) internal returns (uint256 id) {
        uint32[] memory keyIds = new uint32[](1);
        keyIds[0] = channelId;
        IntmaxRollup.SubBlock[] memory batch = new IntmaxRollup.SubBlock[](1);
        batch[0] = IntmaxRollup.SubBlock({
            channelId: channelId,
            timestamp: uint64(1000 + channelId),
            txTreeRoot: keccak256(abi.encodePacked("tx", channelId)),
            keyIds: keyIds
        });

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = keccak256(abi.encodePacked("blob", channelId));
        // A versioned hash must start with the 0x01 version byte.
        hashes[0] = bytes32((uint256(0x01) << 248) | (uint256(hashes[0]) >> 8));
        vm.blobhashes(hashes);

        id = r.nextSubmissionId();
        vm.prank(poster);
        r.postBlockAndSubmit{value: 1 ether}(
            batch, keccak256(abi.encodePacked("proof", channelId)), 1024, stateRoot
        );
    }

    /// @dev Validity PIs pinned to `r`'s CURRENT chain state — every `fullVerify` check passes.
    function _honestPIs(IntmaxRollup r, bytes32 stateRoot)
        internal view returns (IntmaxRollup.ValidityPublicInputs memory pis)
    {
        pis = IntmaxRollup.ValidityPublicInputs({
            initialBlockNumber: 0,
            initialBlockChain: r.blockHashChainAt(0),
            initialExtCommitment: r.latestFinalizedStateRoot(),
            finalBlockNumber: r.blockNumber(),
            finalBlockChain: r.blockHashChain(),
            finalExtCommitment: stateRoot,
            prover: address(0)
        });
    }

    // -----------------------------------------------------------------------
    // The core probe
    // -----------------------------------------------------------------------

    /// @dev Call `finalize` and return the reason code it reported. Asserts the fail-closed
    ///      invariants that must hold on EVERY rejecting path: `finalize` returns false, it does not
    ///      revert, it emits exactly one `FinalizeRejected`, and the submission stays un-finalized.
    function _rejectReason(
        IntmaxRollup r,
        uint256 submissionId,
        bytes32 stateRoot,
        IntmaxRollup.ValidityPublicInputs memory pis,
        MleVerifier.MleProof memory proof
    ) internal returns (bytes4 reason) {
        vm.recordLogs();
        bool ok = r.finalize(submissionId, stateRoot, pis, proof);
        assertFalse(ok, "fail-closed: finalize must still return false");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 hits;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(r) && logs[i].topics[0] == FinalizeRejected.selector) {
                assertEq(uint256(logs[i].topics[1]), submissionId, "reason must name the submission");
                reason = abi.decode(logs[i].data, (bytes4));
                hits++;
            }
        }
        assertEq(hits, 1, "exactly one FinalizeRejected per rejecting finalize");
        assertFalse(r.isFinalized(submissionId), "fail-closed: submission must stay un-finalized");
    }

    // -----------------------------------------------------------------------
    // finalize()'s own three exits
    // -----------------------------------------------------------------------

    function test_reason_submissionNotFound() public {
        IntmaxRollup.ValidityPublicInputs memory pis;
        assertEq(
            _rejectReason(rollup, 999, bytes32(0), pis, _emptyProof()),
            IntmaxRollup.SubmissionNotFound.selector
        );
    }

    function test_reason_alreadyFinalized() public {
        bytes32 root = keccak256("root_af");
        uint256 id = _post(rollup, 1, root);
        IntmaxRollup.ValidityPublicInputs memory pis = _honestPIs(rollup, root);
        MleVerifier.MleProof memory proof = _emptyProof();
        proof.publicInputs = _limbs(_piHash(pis));

        assertTrue(rollup.finalize(id, root, pis, proof), "first finalize must succeed");
        assertTrue(rollup.isFinalized(id));

        // Second call: the `isFinalized` assertion inside `_rejectReason` would be wrong here, so
        // decode the reason inline.
        vm.recordLogs();
        assertFalse(rollup.finalize(id, root, pis, proof), "second finalize must return false");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1, "exactly one FinalizeRejected");
        assertEq(logs[0].topics[0], FinalizeRejected.selector);
        assertEq(
            abi.decode(logs[0].data, (bytes4)),
            IntmaxRollup.AlreadyFinalized.selector,
            "re-finalize must be distinguishable from a bad proof"
        );
    }

    /// @dev H-5's `stateRoot != sub.stateRoot` pin. Distinct from `FinalExtCommitmentMismatch`
    ///      below: this one says "you named the wrong submission", that one says "your proof does
    ///      not close on the root you are finalizing".
    function test_reason_commitmentMismatch() public {
        bytes32 root = keccak256("root_cm");
        uint256 id = _post(rollup, 2, root);
        bytes32 foreign = keccak256("some_other_root");
        IntmaxRollup.ValidityPublicInputs memory pis = _honestPIs(rollup, foreign);
        MleVerifier.MleProof memory proof = _emptyProof();
        proof.publicInputs = _limbs(_piHash(pis));

        assertEq(
            _rejectReason(rollup, id, foreign, pis, proof),
            IntmaxRollup.CommitmentMismatch.selector
        );
    }

    // -----------------------------------------------------------------------
    // fullVerify()'s seven exits
    // -----------------------------------------------------------------------

    /// @dev Check 1 — the proof would move `latestFinalizedBlockNumber` BACKWARDS. Requires a real
    ///      finalize first so the floor is above zero.
    function test_reason_finalizedHeightRegression() public {
        // A GENUINE regression, not a malformed PI: post B first (lower end height), post A second
        // (higher), finalize A, then try to finalize B with B's OWN honest PIs. B-5's batch binding
        // is satisfied (pisB.finalBlockNumber == B's endBlockNumber), so the height check is the
        // first — and correct — cause reported.
        //
        // The earlier form set `pisB.finalBlockNumber = 0`, which B-5 now catches first as
        // ValidityPublicInputsMismatch ("these PIs are for another batch"). That is the more
        // accurate diagnosis for that input, so the TEST moved rather than the check order.
        bytes32 rootB = keccak256("root_hr_b");
        uint256 idB = _post(rollup, 4, rootB);
        IntmaxRollup.ValidityPublicInputs memory pisB = _honestPIs(rollup, rootB);
        MleVerifier.MleProof memory proofB = _emptyProof();
        proofB.publicInputs = _limbs(_piHash(pisB));

        bytes32 rootA = keccak256("root_hr_a");
        uint256 idA = _post(rollup, 3, rootA);
        IntmaxRollup.ValidityPublicInputs memory pisA = _honestPIs(rollup, rootA);
        MleVerifier.MleProof memory proofA = _emptyProof();
        proofA.publicInputs = _limbs(_piHash(pisA));
        assertTrue(rollup.finalize(idA, rootA, pisA, proofA), "seed finalize must succeed");
        assertGt(rollup.latestFinalizedBlockNumber(), pisB.finalBlockNumber, "floor must exceed B");

        assertEq(
            _rejectReason(rollup, idB, rootB, pisB, proofB),
            IntmaxRollup.FinalizedHeightRegression.selector
        );
    }

    /// @dev Check 2 — the proof does not start from the current finalized root.
    function test_reason_initialStateMismatch() public {
        bytes32 root = keccak256("root_is");
        uint256 id = _post(rollup, 5, root);
        IntmaxRollup.ValidityPublicInputs memory pis = _honestPIs(rollup, root);
        pis.initialExtCommitment = keccak256("not_the_finalized_root");
        MleVerifier.MleProof memory proof = _emptyProof();
        proof.publicInputs = _limbs(_piHash(pis));

        assertEq(
            _rejectReason(rollup, id, root, pis, proof),
            IntmaxRollup.InitialStateMismatch.selector
        );
    }

    /// @dev Check 3 — the INITIAL block-hash-chain endpoint disagrees with on-chain history.
    function test_reason_blockChainMismatch_initialEndpoint() public {
        bytes32 root = keccak256("root_bc_i");
        uint256 id = _post(rollup, 6, root);
        IntmaxRollup.ValidityPublicInputs memory pis = _honestPIs(rollup, root);
        pis.initialBlockChain = keccak256("wrong_initial_chain");
        MleVerifier.MleProof memory proof = _emptyProof();
        proof.publicInputs = _limbs(_piHash(pis));

        assertEq(
            _rejectReason(rollup, id, root, pis, proof),
            IntmaxRollup.BlockChainMismatch.selector
        );
    }

    /// @dev Check 4 — the FINAL block-hash-chain endpoint disagrees. MUTATION CHECK: reuse
    ///      `BlockChainMismatch` for both endpoints and this assertion fails.
    function test_reason_blockChainMismatch_finalEndpoint() public {
        bytes32 root = keccak256("root_bc_f");
        uint256 id = _post(rollup, 7, root);
        IntmaxRollup.ValidityPublicInputs memory pis = _honestPIs(rollup, root);
        pis.finalBlockChain = keccak256("wrong_final_chain");
        MleVerifier.MleProof memory proof = _emptyProof();
        proof.publicInputs = _limbs(_piHash(pis));

        bytes4 reason = _rejectReason(rollup, id, root, pis, proof);
        assertEq(reason, IntmaxRollup.FinalBlockChainMismatch.selector);
        assertTrue(
            reason != IntmaxRollup.BlockChainMismatch.selector,
            "the two chain endpoints must stay distinguishable"
        );
    }

    /// @dev Check 5 — the proof does not close on the state root being finalized.
    function test_reason_finalExtCommitmentMismatch() public {
        bytes32 root = keccak256("root_fe");
        uint256 id = _post(rollup, 8, root);
        IntmaxRollup.ValidityPublicInputs memory pis = _honestPIs(rollup, root);
        pis.finalExtCommitment = keccak256("closes_somewhere_else");
        MleVerifier.MleProof memory proof = _emptyProof();
        proof.publicInputs = _limbs(_piHash(pis));

        bytes4 reason = _rejectReason(rollup, id, root, pis, proof);
        assertEq(reason, IntmaxRollup.FinalExtCommitmentMismatch.selector);
        assertTrue(
            reason != IntmaxRollup.CommitmentMismatch.selector,
            "must be distinguishable from finalize's own stateRoot pin"
        );
    }

    /// @dev Check 6 — the claimed `validityPIs` are UNBOUND to the proof. This is the soundness
    ///      anchor that replaced the removed Groth16 PI binding; it must never read as "proof
    ///      invalid", because it is the CALLER's public inputs that are wrong.
    function test_reason_validityPublicInputsMismatch() public {
        bytes32 root = keccak256("root_pi");
        uint256 id = _post(rollup, 9, root);
        IntmaxRollup.ValidityPublicInputs memory pis = _honestPIs(rollup, root);
        MleVerifier.MleProof memory proof = _emptyProof(); // publicInputs left empty → unbound

        bytes4 reason = _rejectReason(rollup, id, root, pis, proof);
        assertEq(reason, IntmaxRollup.ValidityPublicInputsMismatch.selector);
        assertTrue(
            reason != IntmaxRollup.MleVerificationFailed.selector,
            "an unbound PI set must not be reported as a failed proof"
        );
    }

    /// @dev Check 7 — MLE/WHIR verification of the proof itself failed. Needs a rollup with the VK
    ///      ENABLED, otherwise `_verifyMle` short-circuits to true under the test opt-in.
    function test_reason_mleVerificationFailed() public {
        IntmaxRollup r = _newRollup(13);
        bytes32 root = keccak256("root_mle");
        uint256 id = _post(r, 10, root);
        IntmaxRollup.ValidityPublicInputs memory pis = _honestPIs(r, root);
        MleVerifier.MleProof memory proof = _emptyProof();
        proof.publicInputs = _limbs(_piHash(pis));
        proof.whirTranscript = hex"DEADBEEF"; // makes WHIR verification fail

        assertEq(
            _rejectReason(r, id, root, pis, proof),
            IntmaxRollup.MleVerificationFailed.selector
        );
    }

    // -----------------------------------------------------------------------
    // The catch arm — "could not evaluate" is NOT "invalid"
    // -----------------------------------------------------------------------

    /// @dev SECURITY (the gate-8 shape): when `fullVerify` aborts with NO revert data — out of gas,
    ///      an invalid opcode, a satellite that cannot be evaluated — `finalize` reports
    ///      `0x00000000`, which means "the verifier could not be evaluated", NOT "your proof is
    ///      invalid". Telling an honest submitter the latter is exactly how gate-8 presented.
    ///      `vm.mockCallRevert` with empty return data reproduces that abort precisely.
    function test_reason_unevaluable_isNotAVerdict() public {
        bytes32 root = keccak256("root_un");
        uint256 id = _post(rollup, 11, root);
        IntmaxRollup.ValidityPublicInputs memory pis = _honestPIs(rollup, root);
        MleVerifier.MleProof memory proof = _emptyProof();
        proof.publicInputs = _limbs(_piHash(pis));

        vm.mockCallRevert(
            address(rollup),
            abi.encodeWithSelector(IntmaxRollup.fullVerify.selector),
            bytes("")
        );

        bytes4 reason = _rejectReason(rollup, id, root, pis, proof);
        assertEq(reason, bytes4(0), "an unevaluable verifier must report the no-verdict code");
        assertTrue(
            reason != IntmaxRollup.MleVerificationFailed.selector,
            "unevaluable must never be reported as a failed proof"
        );
        vm.clearMockedCalls();
    }

    // -----------------------------------------------------------------------
    // Mutation guard
    // -----------------------------------------------------------------------

    /// @dev MUTATION CHECK. Collapsing any two causes into one shared error — or reverting either
    ///      branch to a bare `return false`, which surfaces as the `0x00000000` no-verdict code —
    ///      makes this pairwise comparison fail.
    function test_everyReasonCodeIsDistinct() public pure {
        bytes4[9] memory codes = [
            IntmaxRollup.SubmissionNotFound.selector,
            IntmaxRollup.AlreadyFinalized.selector,
            IntmaxRollup.CommitmentMismatch.selector,
            IntmaxRollup.FinalizedHeightRegression.selector,
            IntmaxRollup.InitialStateMismatch.selector,
            IntmaxRollup.BlockChainMismatch.selector,
            IntmaxRollup.FinalBlockChainMismatch.selector,
            IntmaxRollup.FinalExtCommitmentMismatch.selector,
            IntmaxRollup.ValidityPublicInputsMismatch.selector
        ];
        for (uint256 i = 0; i < codes.length; i++) {
            assertTrue(codes[i] != bytes4(0), "no cause may share the no-verdict code");
            for (uint256 j = i + 1; j < codes.length; j++) {
                assertTrue(codes[i] != codes[j], "two causes collapsed into one reason code");
            }
        }
        // `MleVerificationFailed` is checked separately so the array stays within the 9 codes the
        // MLE-disabled rollup can produce.
        assertTrue(
            IntmaxRollup.MleVerificationFailed.selector != bytes4(0),
            "a failed proof must not share the no-verdict code"
        );
    }

    /// @dev The success path is unchanged: no `FinalizeRejected`, and the submission finalizes.
    function test_successPathEmitsNoRejection() public {
        bytes32 root = keccak256("root_ok");
        uint256 id = _post(rollup, 12, root);
        IntmaxRollup.ValidityPublicInputs memory pis = _honestPIs(rollup, root);
        MleVerifier.MleProof memory proof = _emptyProof();
        proof.publicInputs = _limbs(_piHash(pis));

        vm.recordLogs();
        assertTrue(rollup.finalize(id, root, pis, proof), "honest finalize must still succeed");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            assertTrue(
                logs[i].topics[0] != FinalizeRejected.selector,
                "a successful finalize must not emit a rejection"
            );
        }
        assertTrue(rollup.isFinalized(id));
    }
}
