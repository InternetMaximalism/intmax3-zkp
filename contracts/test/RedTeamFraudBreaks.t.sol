// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifier, BlobKZGVerifierExt, KZGProof} from "../src/BlobKZGVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {Plonky2GateEvaluator} from "@mle/Plonky2GateEvaluator.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";

/// @dev A stand-in for `MleVerifier` with the IDENTICAL external signature. It ACCEPTS every
///      proof (returns true) but consumes a fixed, large amount of gas first — exactly the shape
///      of the real verifier, which was measured at 11,019,291 gas for the repo's own real
///      fixture (`MleE2E::test_mleVerify_gas`). The burn is scaled down here only so the test
///      runs fast; the attack does not depend on the amount.
contract GasHungryMleVerifier {
    uint256 public immutable rounds;

    constructor(uint256 rounds_) {
        rounds = rounds_;
    }

    function verify(
        MleVerifier.MleProof calldata,
        MleVerifier.VerifyParams memory,
        SpongefishWhirVerify.WhirParams memory,
        bytes32
    ) external view returns (bool) {
        uint256 acc = 1;
        uint256 n = rounds;
        for (uint256 i = 0; i < n; i++) {
            acc = uint256(keccak256(abi.encode(acc, i)));
        }
        // keep the loop live
        require(acc != 0, "unreachable");
        return true;
    }
}

/// @dev A stand-in for `MleVerifier` that REVERTS the way `Plonky2GateEvaluator` does on a gate
///      the deployed evaluator cannot handle
///      (`Plonky2GateEvaluator.sol:235  revert("unsupported gate with non-zero filter")`).
///      The proof itself is perfectly honest; the deployed evaluator simply cannot evaluate it.
contract UnsupportedGateMleVerifier {
    function verify(
        MleVerifier.MleProof calldata,
        MleVerifier.VerifyParams memory,
        SpongefishWhirVerify.WhirParams memory,
        bytes32
    ) external pure returns (bool) {
        revert("unsupported gate with non-zero filter");
    }
}

/// @dev A stand-in for `MleVerifier` that RETURNS false. After B-4 this is the only shape that
///      confirms fraud: the verifier ran to completion and the verdict was NO.
contract RejectingMleVerifier {
    function verify(
        MleVerifier.MleProof calldata,
        MleVerifier.VerifyParams memory,
        SpongefishWhirVerify.WhirParams memory,
        bytes32
    ) external pure returns (bool) {
        return false;
    }
}

/// @title RedTeamFraudBreaks
/// @notice Adversarial review of the 2026-08-28 C-1 / H-1 / H-4 / H-5 fixes. Each test here
///         demonstrated a route the round-1 fix did NOT close.
///
///         DEFENCE (round 2): the attacks are kept verbatim; every ASSERTION has been flipped to
///         the post-fix outcome, and the comment above each one records what it asserted before.
///         A test that still passes while asserting the attack succeeds would prove nothing.
///           RT-1  gas starvation      -> blocked by the MLE_STARVED verdict (B-4)
///           RT-2  gate-8 revert       -> blocked by the MLE_UNEVALUABLE verdict (B-4)
///           RT-3  shared state root   -> blocked by the endBlockNumber binding (B-5)
///           RT-3b rogue front-run     -> blocked by the endBlockNumber binding (B-5)
///           RT-4  forged setup data   -> NOT closed for k >= 2; the k = 1 hole IS closed (B-6)
///           RT-6  dead fraud path     -> the general pairing branch works now (B-1/B-2/B-3)
contract RedTeamFraudBreaksTest is Test {
    address submitter     = makeAddr("honest_submitter");
    address attacker      = makeAddr("attacker");
    address fraudTreasury = makeAddr("fraudTreasury");

    uint256 internal constant BLS12_SCALAR_R =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    // (r+1)/2 == 2^{-1} mod r
    uint256 internal constant INV2 =
        0x39f6d3a994cebea4199cec0404d0ec02a9ded2017fff2dff7fffffff80000001;

    // =======================================================================
    // FINDING RT-1 (C-1 NOT CLOSED) — gas starvation turns `!_verifyMle` into
    // a caller-steerable fraud verdict against an HONEST submission.
    //
    //   IntmaxRollup._verifyMle:
    //       try this._verifyMleWithVk(mleProof, false) returns (bool v) { return v; }
    //       catch { return false; }                      // <- OOG lands here
    //   IntmaxRollup._verifyFraud:
    //       if (!_verifyMle(mleProof)) return true;      // <- "fraud confirmed"
    //
    //   EIP-150 forwards only 63/64 of the available gas to the inner call, so the caller can
    //   pick a transaction gas limit at which the inner verification runs out of gas while the
    //   outer frame retains ~1/64 — more than enough to finish _truncateSubmissions.
    //   The defender's claimed invariant ("the fraud prover has no free input left with which to
    //   steer it") is false: the gas limit is a free input.
    // =======================================================================

    ///  POST-FIX: `_mleVerdict` returns MLE_STARVED when `gasleft()` is below
    ///  MIN_MLE_VERIFY_GAS, or when the inner frame burned the whole 63/64 it was forwarded, and
    ///  `_verifyFraud` REVERTS on that verdict. The sweep below therefore finds no winning limit;
    ///  the assertion is inverted from "expected a gas limit that convicts" to "none may".
    function test_RT1_C1_gasStarvationCannotConvictAnHonestSubmission() public {
        // ~1.1M gas of verification work (the real verifier costs 11,019,291 — see MleE2E).
        (IntmaxRollup r, bytes memory payload) = _honestSubmissionOn(
            address(new GasHungryMleVerifier(9_000))
        );

        // Control: with plenty of gas the honest submission is NOT convictable (the C-1 fix works
        // for a well-funded call).
        uint256 gBefore = gasleft();
        (bool okHi, bytes memory retHi) = address(r).call(payload);
        uint256 honestCost = gBefore - gasleft();
        assertTrue(okHi, "control call must succeed");
        assertFalse(abi.decode(retHi, (bool)), "control: honest submission is not convictable");
        assertEq(r.nextSubmissionId(), 1, "control: submission survives");
        emit log_named_uint("RT-1 honest (non-convicting) fraudProof cost", honestCost);

        // Attack: scan upward for the gas limit at which the INNER verification OOGs but the
        // OUTER frame still completes. Only a *successful* call mutates state, and we stop at the
        // first one, so no snapshot juggling is needed.
        bool fraud;
        uint256 step = honestCost / 200 + 1;
        for (uint256 g = honestCost / 4; g <= honestCost + 4 * step; g += step) {
            vm.prank(attacker);
            (bool ok, bytes memory ret) = address(r).call{gas: g}(payload);
            if (ok && ret.length == 32 && abi.decode(ret, (bool))) {
                fraud = true;
                emit log_named_uint("RT-1 winning tx gas limit", g);
                break;
            }
        }

        assertFalse(fraud, "RT-1 BLOCKED: no gas limit may convict the honest submission");

        // ...and nothing moved. (Pre-fix all three of these flipped.)
        assertEq(r.nextSubmissionId(), 1, "RT-1: the honest submission survives");
        assertEq(r.blockNumber(), 1, "RT-1: the chain was not rolled back");
        assertEq(
            r.pendingWithdrawals(attacker), 0,
            "RT-1: none of the honest submitter's bond was paid to the attacker"
        );
    }

    // =======================================================================
    // FINDING RT-2 (C-1 NOT CLOSED, gate-8 class) — any revert inside verification is read as
    // fraud. `Plonky2GateEvaluator` reverts by design on a gate it cannot evaluate; that revert
    // is caught by `_verifyMle` and converted into a fraud conviction of an honest submitter.
    // =======================================================================

    ///  POST-FIX: a deterministic revert inside verification is the MLE_UNEVALUABLE verdict, and
    ///  `_verifyFraud` reverts `MleProofUnevaluable` rather than returning "fraud confirmed".
    function test_RT2_C1_unsupportedGateRevertCannotConvictAnHonestSubmission() public {
        (IntmaxRollup r, bytes memory payload) = _honestSubmissionOn(
            address(new UnsupportedGateMleVerifier())
        );

        vm.prank(attacker);
        (bool ok, bytes memory ret) = address(r).call(payload);
        assertFalse(ok, "RT-2 BLOCKED: an evaluator revert is no longer a fraud verdict");
        assertEq(
            bytes4(ret), IntmaxRollup.MleProofUnevaluable.selector,
            "RT-2: fraudProof reverts MleProofUnevaluable"
        );

        assertEq(r.nextSubmissionId(), 1, "RT-2: honest submission survives");
        assertEq(r.pendingWithdrawals(attacker), 0, "RT-2: no bond stolen");
    }

    // =======================================================================
    // FINDING RT-3 (H-5 NOT CLOSED) — `finalize` binds only `stateRoot`, so two submissions that
    // share a committed state root remain fully interchangeable. Submission B is finalized with
    // submission A's proof, byte-for-byte, exactly as the audit described.
    //
    //   Reachable two ways:
    //     (a) permissionlessly, whenever the rollup posts a round that does not move the state
    //         root (an idle / heartbeat round) — no privileges at all; and
    //     (b) by any whitelisted block producer, who simply declares `stateRoot = R` for a batch
    //         of arbitrary blocks (nothing at `_submit` constrains the declared root).
    //   `endBlockNumber` binding — which the defender explicitly rejected — closes both.
    // =======================================================================

    function test_RT3_H5_twoSubmissionsSharingAStateRootAreNoLongerInterchangeable() public {
        bytes32 R = keccak256("idle_state_root");

        // A rollup whose genesis root is R (i.e. the state has not moved).
        IntmaxRollup r = new IntmaxRollup(
            fraudTreasury, _emptyMleVk(), _emptyWhirParams(), "", "",
            _emptyMleArrays(), _emptyMleArrays(), new MleVerifier(), R, true
        );
        r.setKzgVerifier(new BlobKZGVerifierExt(true));
        r.setBlockProducer(submitter, true);
        r.setBlockProducer(attacker, true);
        vm.deal(submitter, 10 ether);
        vm.deal(attacker, 10 ether);

        // Round A (submission 0): an idle round — the state root does not change, so the batch
        // commits `stateRoot = R`.
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        _mockBlob();
        vm.prank(submitter);
        r.postBlockAndSubmit{value: 1 ether}(
            _batch(1, ids, 100, bytes32(uint256(0x111))), keccak256("proofA"), 1, R
        );

        // A's real public inputs and its real proof.
        IntmaxRollup.ValidityPublicInputs memory pisA = IntmaxRollup.ValidityPublicInputs({
            initialBlockNumber: 0,
            initialBlockChain:  r.blockHashChainAt(0),
            initialExtCommitment: R,               // == latestFinalizedStateRoot (genesis)
            finalBlockNumber:   1,
            finalBlockChain:    r.blockHashChain(),
            finalExtCommitment: R,
            prover: address(0xBEEF)
        });
        MleVerifier.MleProof memory proofA = _mleProofWithPI(_computePIHash(pisA));

        // Round B (submission 1): a DIFFERENT batch of blocks, but the declared root is the same R.
        // Nothing in `_submit` constrains the declared root, and on an idle chain this is also
        // simply what an honest producer posts.
        uint32[] memory ids2 = new uint32[](1);
        ids2[0] = 2;
        _mockBlob();
        vm.prank(attacker);
        r.postBlockAndSubmit{value: 1 ether}(
            _batch(2, ids2, 200, bytes32(uint256(0x222))), keccak256("proofB_never_produced"), 1, R
        );

        assertEq(r.getSubmission(0).stateRoot, r.getSubmission(1).stateRoot, "roots collide");

        // Honest finalize of A.
        assertTrue(r.finalize(0, R, pisA, proofA), "A finalizes honestly");
        assertEq(r.latestFinalizedBlockNumber(), 1, "A's height is finalized");

        // ── The H-5 attack, unchanged: finalize B with A's proof, byte-for-byte. ──
        //    POST-FIX: `finalize` also pins `validityPIs.finalBlockNumber` to the submission's own
        //    batch `endBlockNumber` (B-5). A's proof names height 1, B's batch ends at height 2, so
        //    the two are no longer interchangeable even though they declare the same root.
        vm.prank(attacker);
        bool ok = r.finalize(1, R, pisA, proofA);

        assertFalse(ok, "RT-3 BLOCKED: B cannot be finalized with submission A's proof");
        assertFalse(r.isFinalized(1), "RT-3: B is NOT marked finalized");
        assertEq(
            r.pendingWithdrawals(attacker), 0,
            "RT-3: B bond not refunded; its own proof was never verified"
        );
        assertEq(r.latestFinalizedBlockNumber(), 1, "RT-3: the finalized height is still A's");

        // ...and because B was never finalized, B's bond stays at risk: the submission is still
        // removable, so it can no longer block the rollback of anything.
        IntmaxRollup.ValidityPublicInputs memory emptyPis;
        MleVerifier.MleProof memory emptyProof;
        KZGProof memory emptyKzg;
        vm.roll(block.number + 3601);
        vm.prank(submitter);
        assertTrue(
            r.fraudProof(1, bytes32(0), bytes32(0), "", emptyPis, emptyProof, emptyKzg),
            "RT-3: B remains slashable (pre-fix this reverted SubmissionAlreadyFinalized)"
        );
    }

    /// @dev RT-3b: the same break WITHOUT needing an idle chain. A second whitelisted block
    ///      producer posts a junk batch declaring the honest submission's root, then FRONT-RUNS the
    ///      honest finalize with the honest proof. The rogue submission is finalized (bond refunded,
    ///      permanently un-slashable) and the honest submission can never be finalized at all,
    ///      because `latestFinalizedStateRoot` has already moved past its `initialExtCommitment`.
    function test_RT3b_H5_rogueProducerCannotFrontRunTheHonestFinalize() public {
        bytes32 R0 = keccak256("genesis_root");
        bytes32 R1 = keccak256("honest_next_root");

        IntmaxRollup r = new IntmaxRollup(
            fraudTreasury, _emptyMleVk(), _emptyWhirParams(), "", "",
            _emptyMleArrays(), _emptyMleArrays(), new MleVerifier(), R0, true
        );
        r.setBlockProducer(submitter, true);
        r.setBlockProducer(attacker, true); // a second whitelisted producer
        vm.deal(submitter, 10 ether);
        vm.deal(attacker, 10 ether);

        // Honest round (submission 0) advancing R0 -> R1.
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        _mockBlob();
        vm.prank(submitter);
        r.postBlockAndSubmit{value: 1 ether}(
            _batch(1, ids, 100, bytes32(uint256(0x111))), keccak256("proofA"), 1, R1
        );
        IntmaxRollup.ValidityPublicInputs memory pisA = IntmaxRollup.ValidityPublicInputs({
            initialBlockNumber: 0,
            initialBlockChain:  r.blockHashChainAt(0),
            initialExtCommitment: R0,
            finalBlockNumber:   1,
            finalBlockChain:    r.blockHashChain(),
            finalExtCommitment: R1,
            prover: address(0xBEEF)
        });
        MleVerifier.MleProof memory proofA = _mleProofWithPI(_computePIHash(pisA));

        // Rogue round (submission 1): arbitrary blocks, but it DECLARES the honest root R1.
        uint32[] memory ids2 = new uint32[](1);
        ids2[0] = 99;
        _mockBlob();
        vm.prank(attacker);
        r.postBlockAndSubmit{value: 1 ether}(
            _batch(9, ids2, 999, bytes32(uint256(0x999))), keccak256("no_proof_exists"), 1, R1
        );

        // Front-run: the rogue submission is finalized with the honest submission's proof.
        //   POST-FIX (B-5): A's proof names height 1; the rogue batch ends at height 2. The junk
        //   batch can declare any root it likes, but it cannot borrow another batch's END HEIGHT.
        vm.prank(attacker);
        assertFalse(
            r.finalize(1, R1, pisA, proofA),
            "RT-3b BLOCKED: the rogue submission cannot be finalized with A's proof"
        );
        assertFalse(r.isFinalized(1), "rogue submission NOT marked finalized");
        assertEq(r.pendingWithdrawals(attacker), 0, "RT-3b: no rogue bond refunded");

        // And the honest submission finalizes normally — the front-run never moved
        // `latestFinalizedStateRoot`, so its `initialExtCommitment` (R0) still matches.
        vm.prank(submitter);
        assertTrue(r.finalize(0, R1, pisA, proofA), "RT-3b: the honest finalize still works");
        assertTrue(r.isFinalized(0), "RT-3b: the honest submission IS finalized");

        // The rogue submission stays slashable, so it blocks nothing.
        IntmaxRollup.ValidityPublicInputs memory emptyPis;
        MleVerifier.MleProof memory emptyProof;
        KZGProof memory emptyKzg;
        vm.roll(block.number + 3601);
        vm.prank(submitter);
        assertTrue(
            r.fraudProof(1, bytes32(0), bytes32(0), "", emptyPis, emptyProof, emptyKzg),
            "RT-3b: the rogue submission is removed (pre-fix it was permanently un-slashable)"
        );
    }

    // =======================================================================
    // FINDING RT-4 (H-4 NOT CLOSED) — the guard is a keccak equality against ONE encoding of the
    // G2 generator. Any `vanishingG2 = [k]G2` with k != 1 whose dlog the attacker knows walks
    // straight past it, and a `lagrangeBasisG1` of infinity points makes `[I(tau)]_1` independent
    // of the claimed blob contents. This test runs the G1/G2 arithmetic and shows the accepting
    // witness is pure public G1 arithmetic.
    //
    // POST-FIX: k = 1 is now genuinely caught (the guard compares against the CANONICAL encoding
    // after B-2). Everything else in this finding is still OPEN — see the SECURITY (H-4 / B-6)
    // block in BlobKZGVerifier.sol for the exact scope and for why the fraud path is nevertheless
    // safe (pre-conditions 1 and 4 pin proofBytes by keccak, with no BLS assumption).
    // The original note here said the pairing precompile is "absent in Foundry 1.5.x". It is not:
    // that measured 0x11 (MAP_FP2_TO_G2). PAIRING_CHECK at 0x0f works — see BlobKzgPairing.t.sol.
    // =======================================================================

    function test_RT4_H4_forgedLagrangeBasisAndKnownDlogVanishingG2() public view {
        bytes memory C = _g1Mul(_g1Gen(), bytes32(uint256(12345))); // a real blob commitment

        // (i) A lagrangeBasisG1 of N infinity points makes [I(tau)]_1 = infinity for ANY claimed
        //     field elements, so `lhs = C - [I(tau)]_1 = C` no matter what the blob "contained".
        bytes32[] memory claimA = new bytes32[](4);
        bytes32[] memory claimB = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) {
            claimA[i] = bytes32(uint256(0xAAAA + i));
            claimB[i] = bytes32(uint256(0xBBBB + i));
        }
        bytes memory basisInf = new bytes(4 * 128); // 128 zero bytes per point == infinity
        bytes memory lhsA = _g1Add(C, _g1Neg(_msm(claimA, basisInf)));
        bytes memory lhsB = _g1Add(C, _g1Neg(_msm(claimB, basisInf)));
        assertEq(keccak256(lhsA), keccak256(lhsB), "RT-4: lhs is independent of the claimed blob");
        assertEq(keccak256(lhsA), keccak256(C), "RT-4: lhs collapses to the commitment C");

        // (ii) k = 2: vanishingG2 = G2 + G2, computed on-chain from the CANONICAL EIP-2537
        //      generator encoding. It is NOT byte-equal to the constant the H-4 guard compares
        //      against, so `BKV_DegenerateVanishingG2` never fires and control reaches the general
        //      pairing branch.
        //      (Bonus: the canonical k = 1 encoding is not byte-equal to the shipped constant
        //      either, so the genuinely degenerate Z(tau) = 1 case slips past the guard too.)
        bytes memory g2gen = _g2GenCanonical();
        // POST-FIX (B-2): `G2_GENERATOR` is now the canonical encoding, so the k = 1 sub-case the
        // red team found — feeding the canonical bytes to slip past a guard that compared against
        // the malformed ones — is CLOSED. Everything below it is NOT.
        assertEq(
            keccak256(g2gen), keccak256(_g2Gen()),
            "B-2: the H-4 guard now compares against the canonical k=1 encoding"
        );
        // RESIDUAL (B-6, NOT CLOSED): k = 2 still walks straight past the keccak guard, and the
        // witness below is still pure public G1 arithmetic. The keccak guard buys nothing against
        // k >= 2; only an immutable trusted-setup store closes this. See the RESIDUAL RISK note in
        // BlobKZGVerifier.
        bytes memory vanishingK2 = _g2Add(g2gen, g2gen);
        assertTrue(
            keccak256(vanishingK2) != keccak256(g2gen),
            "RT-4 RESIDUAL: k=2 still walks past the H-4 guard"
        );

        // (iii) The accepting opening proof is pure public arithmetic: pi := 2^{-1} * lhs.
        //       Then  e(lhs, G2) * e(-pi, [2]G2) = e(lhs - 2*pi, G2) = e(inf, G2) = 1.
        bytes memory pi = _g1Mul(lhsA, bytes32(INV2));
        assertEq(
            keccak256(_g1Add(pi, pi)), keccak256(lhsA),
            "RT-4: 2*pi == lhs, so the pairing equation is satisfied with no trapdoor"
        );
        // No trapdoor, no discrete log of tau, no honest blob: the binding is vacuous for any k
        // the attacker chooses.
    }

    // =======================================================================
    // FINDING RT-6 (NEW, introduced by the H-4 fix) — on a PRODUCTION deployment
    // (`BlobKZGVerifierExt(false)`) the proof-based fraud path could never confirm anything.
    //
    //   * `_verifyFraud` pre-condition 2 requires `kzgVerifier.verify` to return without reverting.
    //   * The degenerate branch reverts `BKV_DegenerateVanishingG2`.
    //   * The general branch called address 0x11 (MAP_FP2_TO_G2, NOT the pairing check — see
    //     RedTeamBlsProbe RT-5a) and fed it a malformed `G2_GENERATOR` (RT-5b), so it could never
    //     succeed either.
    //   => Precondition 2 was unsatisfiable and `_verifyFraud` always returned false. A genuinely
    //      fraudulent batch was unprovable; the only remaining removal was the 12-hour timeout,
    //      which is indiscriminate (it removes honest submissions too).
    //
    // POST-FIX (B-1 + B-2 => B-3): the general branch runs. The test below now asserts BOTH
    // halves of the correct behaviour: a DEGENERATE opening is still refused in production (the
    // H-4 guard is intact), and a well-formed NON-degenerate opening lets an honest prover convict
    // a genuinely invalid batch. `RollupFraudHardening::test_B3_*` pins the same property.
    // =======================================================================

    function test_RT6_productionKzgConfigNowAdmitsFraudProofs() public {
        IntmaxRollup.MleVk memory vk = IntmaxRollup.MleVk({
            degreeBits: 13, preprocessedRoot: bytes32(0),
            numConstants: 0, numRoutedWires: 0, gatesDigest: bytes32(0)
        });
        // B-4: fraud is confirmed only by a RETURNED false. The real verifier REVERTS on a
        // garbage transcript, which is now "could not evaluate", so the genuinely-invalid batch is
        // modelled by a verifier that reaches a verdict and says NO.
        IntmaxRollup r = new IntmaxRollup(
            fraudTreasury, vk, _emptyWhirParams(), "", "",
            _emptyMleArrays(), _emptyMleArrays(),
            MleVerifier(address(new RejectingMleVerifier())), bytes32(0), false
        );
        // PRODUCTION configuration — exactly what all six deploy scripts pass.
        r.setKzgVerifier(new BlobKZGVerifierExt(false));
        r.setBlockProducer(submitter, true);
        vm.deal(submitter, 10 ether);

        bytes32 stateRoot = keccak256("genuinely_bad_state");
        IntmaxRollup.ValidityPublicInputs memory pis = IntmaxRollup.ValidityPublicInputs({
            initialBlockNumber: 0,
            initialBlockChain:  r.blockHashChainAt(0),
            initialExtCommitment: r.latestFinalizedStateRoot(),
            finalBlockNumber:   0,
            finalBlockChain:    r.blockHashChainAt(0),
            finalExtCommitment: stateRoot,
            prover: address(0xBEEF)
        });
        MleVerifier.MleProof memory mleProof = _mleProofWithPI(_computePIHash(pis));
        bytes memory proofBytes = abi.encode(mleProof);

        // A well-formed NON-degenerate opening: Z(tau) = 2, so the H-4 guard does not fire and the
        // GENERAL pairing branch decides. Pre-fix this branch could never succeed.
        (KZGProof memory kzg, bytes32 blobHash) = _computeGeneralKZGProof(proofBytes);
        bytes32[] memory hs = new bytes32[](1);
        hs[0] = blobHash;
        vm.blobhashes(hs);
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        vm.prank(submitter);
        r.postBlockAndSubmit{value: 1 ether}(
            _batch(1, ids, 100, bytes32(uint256(0xabc))),
            keccak256(proofBytes), uint32(proofBytes.length), stateRoot
        );

        // The honest fraud prover has the real blob bytes, the real PIs and a self-consistent KZG
        // opening — and CAN now convict a batch whose proof does not verify.
        vm.prank(attacker);
        bool confirmed = r.fraudProof(0, blobHash, stateRoot, proofBytes, pis, mleProof, kzg);
        assertTrue(confirmed, "RT-6 BLOCKED: the production fraud path works again");
        assertEq(r.nextSubmissionId(), 0, "RT-6: the invalid batch was removed");
        assertGt(r.pendingWithdrawals(attacker), 0, "RT-6: the honest fraud prover is rewarded");

        // The H-4 guard is still intact: a DEGENERATE opening remains refused in production.
        (KZGProof memory degenerate, bytes32 degenerateHash) = _computeKZGProof(proofBytes);
        BlobKZGVerifierExt prod = new BlobKZGVerifierExt(false);
        vm.expectRevert(BlobKZGVerifier.BKV_DegenerateVanishingG2.selector);
        prod.verify(degenerateHash, degenerate, proofBytes);
    }

    // =======================================================================
    // Shared harness
    // =======================================================================

    /// @dev Deploy an MLE-ENABLED rollup on `verifierAddr`, post one HONEST submission on it
    ///      (real blob bytes, real PI values, self-consistent KZG opening) and return the exact
    ///      `fraudProof(...)` calldata an attacker would send against it.
    function _honestSubmissionOn(address verifierAddr)
        internal
        returns (IntmaxRollup r, bytes memory payload)
    {
        IntmaxRollup.MleVk memory vk = IntmaxRollup.MleVk({
            degreeBits: 13, preprocessedRoot: bytes32(0),
            numConstants: 0, numRoutedWires: 0, gatesDigest: bytes32(0)
        });
        // allowMleDisabled = false: a PRODUCTION-shaped deployment. MLE verification is ON.
        r = new IntmaxRollup(
            fraudTreasury, vk, _emptyWhirParams(), "", "",
            _emptyMleArrays(), _emptyMleArrays(), MleVerifier(verifierAddr), bytes32(0), false
        );
        r.setKzgVerifier(new BlobKZGVerifierExt(true));
        r.setBlockProducer(submitter, true);
        vm.deal(submitter, 10 ether);
        vm.deal(attacker, 10 ether);

        bytes32 stateRoot = keccak256("honest_state");
        IntmaxRollup.ValidityPublicInputs memory pis = IntmaxRollup.ValidityPublicInputs({
            initialBlockNumber: 0,
            initialBlockChain:  r.blockHashChainAt(0),
            initialExtCommitment: r.latestFinalizedStateRoot(),
            finalBlockNumber:   1,
            finalBlockChain:    bytes32(0), // patched below
            finalExtCommitment: stateRoot,
            prover: address(0xBEEF)
        });

        // Post first so the PI's finalBlockChain can be the real one, then rebuild the proof.
        // (Both the commitment and the PI-preimage precondition are recomputed against the
        // finally-posted values, so the submission below is fully self-consistent.)
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = _batch(1, ids, 100, bytes32(uint256(0xabc)));
        pis.finalBlockChain = _predictChain(r, batch);

        MleVerifier.MleProof memory mleProof = _mleProofWithPI(_computePIHash(pis));
        bytes memory proofBytes = abi.encode(mleProof);

        (KZGProof memory kzg, bytes32 blobHash) = _computeKZGProof(proofBytes);
        bytes32[] memory hs = new bytes32[](1);
        hs[0] = blobHash;
        vm.blobhashes(hs);
        vm.prank(submitter);
        r.postBlockAndSubmit{value: 1 ether}(
            batch, keccak256(proofBytes), uint32(proofBytes.length), stateRoot
        );
        assertEq(r.blockHashChain(), pis.finalBlockChain, "predicted chain must match");

        payload = abi.encodeCall(
            IntmaxRollup.fraudProof,
            (0, blobHash, stateRoot, proofBytes, pis, mleProof, kzg)
        );
    }

    /// @dev Reproduce `_postBlock`'s block-hash fold for a single-sub-block batch from genesis.
    function _predictChain(IntmaxRollup r, IntmaxRollup.SubBlock[] memory batch)
        internal view returns (bytes32)
    {
        bytes memory packed = abi.encodePacked(
            r.blockHashChain(), batch[0].channelId, batch[0].timestamp
        );
        for (uint256 i = 0; i < batch[0].keyIds.length; i++) {
            packed = abi.encodePacked(packed, batch[0].keyIds[i]);
        }
        packed = abi.encodePacked(
            packed, batch[0].txTreeRoot, r.depositHashChain(), r.channelRegHashChain()
        );
        return keccak256(packed);
    }

    // ── BLS12-381 helpers (only the precompiles Foundry 1.5.x actually provides) ──

    function _g1Gen() internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f",
            hex"c3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            hex"0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4",
            hex"fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
        );
    }

    /// @dev Mirrors `BlobKZGVerifier.G2_GENERATOR`. POST-FIX (B-2) that constant is the canonical
    ///      EIP-2537 encoding (x_c0 || x_c1), so this helper is updated with it — otherwise the
    ///      degenerate openings this harness builds would no longer take the degenerate branch.
    function _g2Gen() internal pure returns (bytes memory) {
        return abi.encodePacked(
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

    /// @dev The CANONICAL EIP-2537 G2 generator: x_c0 || x_c1 || y_c0 || y_c1. NOTE that this is
    ///      NOT byte-equal to `BlobKZGVerifier.G2_GENERATOR`, which swaps x_c0/x_c1 (see
    ///      RedTeamBlsProbe.t.sol RT-5b).
    function _g2GenCanonical() internal pure returns (bytes memory) {
        return abi.encodePacked(
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

    function _g1Mul(bytes memory pt, bytes32 s) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = address(0x0c).staticcall(abi.encodePacked(pt, s));
        require(ok && out.length == 128, "G1MSM failed");
    }

    function _g1Neg(bytes memory pt) internal view returns (bytes memory) {
        return _g1Mul(
            pt,
            bytes32(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000)
        );
    }

    function _g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = address(0x0b).staticcall(abi.encodePacked(a, b));
        require(ok && out.length == 128, "G1ADD failed");
    }

    function _g2Add(bytes memory a, bytes memory b) internal view returns (bytes memory out) {
        bool ok;
        (ok, out) = address(0x0d).staticcall(abi.encodePacked(a, b));
        require(ok && out.length == 256, "G2ADD failed");
    }

    function _msm(bytes32[] memory scalars, bytes memory points)
        internal view returns (bytes memory out)
    {
        uint256 n = scalars.length;
        bytes memory input = new bytes(n * 160);
        for (uint256 i = 0; i < n; i++) {
            for (uint256 w = 0; w < 4; w++) {
                bytes32 word;
                uint256 off = i * 128 + w * 32;
                assembly { word := mload(add(add(points, 32), off)) }
                uint256 dst = i * 160 + w * 32;
                assembly { mstore(add(add(input, 32), dst), word) }
            }
            bytes32 s = scalars[i];
            uint256 sOff = i * 160 + 128;
            assembly { mstore(add(add(input, 32), sOff), s) }
        }
        bool ok;
        (ok, out) = address(0x0c).staticcall(input);
        require(ok && out.length == 128, "G1MSM(batch) failed");
    }

    // ── copies of the defender's own test helpers ──

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

    /// @dev A well-formed NON-DEGENERATE opening exercising the GENERAL pairing branch (Z(tau)=2):
    ///        lagrangeBasisG1[i] = G1  => [I(tau)]_1 = S.G1 ; pi = 7.G1 ; C = (S+14).G1
    ///      so C - I = 14.G1 = 2.pi and  e(C-I, G2).e(-pi, [2]G2) = 1.
    ///      Pre-fix this branch called MAP_FP2_TO_G2 with a malformed G2 constant and could never
    ///      succeed, which is finding RT-6 / B-3.
    function _computeGeneralKZGProof(bytes memory proofBytes)
        internal view returns (KZGProof memory kzg, bytes32 blobHash)
    {
        bytes32[] memory fes = _toFieldElementsMem(proofBytes);
        uint256 N = fes.length;
        uint256 S = 0;
        for (uint256 i = 0; i < N; i++) S = addmod(S, uint256(fes[i]), BLS12_SCALAR_R);

        bytes memory g1gen = _g1Gen();
        bytes memory pi = _g1Mul(g1gen, bytes32(uint256(7)));
        bytes memory C  = _g1Mul(g1gen, bytes32(addmod(S, 14, BLS12_SCALAR_R)));

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

        kzg = KZGProof({
            kzgCommitment48: c48,
            kzgCommitmentG1: C,
            openingProof:    pi,
            vanishingG2:     _g2Add(_g2Gen(), _g2Gen()),
            lagrangeBasisG1: lagrangeBasis
        });
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

        bytes memory g1gen = _g1Gen();
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
            vanishingG2:     _g2Gen(),
            lagrangeBasisG1: lagrangeBasis
        });
    }
}
