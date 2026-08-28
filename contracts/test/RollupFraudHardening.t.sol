// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifier, BlobKZGVerifierExt, KZGProof} from "../src/BlobKZGVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {Plonky2GateEvaluator} from "@mle/Plonky2GateEvaluator.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";

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
            new MleVerifier(),
            bytes32(0),
            true
        );
        rollup.setKzgVerifier(new BlobKZGVerifierExt(true));
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
        bool fraudConfirmed = rollup.fraudProof(
            0, blobHash, stateRoot, proofBytes, forgedPis, mleProof, kzg
        );

        assertFalse(fraudConfirmed, "C-1: honest submission must NOT be convictable");
        // Nothing was slashed, truncated or rolled back.
        assertEq(rollup.pendingWithdrawals(attacker), 0, "attacker must earn no fraud reward");
        assertEq(rollup.nextSubmissionId(), 1, "submission must survive");
        assertEq(rollup.getSubmission(0).submitter, submitter, "submission not deleted");
        assertEq(rollup.blockNumber(), 1, "chain must not roll back");
    }

    /// @dev C-1 must not disarm the fraud path: a submission whose committed proof genuinely fails
    ///      verification is still convictable, via `!_verifyMle`.
    function test_C1_genuinelyInvalidProofIsStillConvictable() public {
        IntmaxRollup.MleVk memory enabledVk = IntmaxRollup.MleVk({
            degreeBits: 13, preprocessedRoot: bytes32(0),
            numConstants: 0, numRoutedWires: 0, gatesDigest: bytes32(0)
        });
        IntmaxRollup r = new IntmaxRollup(
            fraudTreasury, enabledVk, _emptyWhirParams(), "", "",
            _emptyMleArrays(), _emptyMleArrays(), rollup.mleVerifier(), bytes32(0), true
        );
        r.setKzgVerifier(new BlobKZGVerifierExt(true));
        r.setBlockProducer(submitter, true);

        bytes32 stateRoot = keccak256("bad_state");
        IntmaxRollup.ValidityPublicInputs memory pis = _pisForOn(r, stateRoot, address(0));
        MleVerifier.MleProof memory mleProof = _mleProofWithPI(_computePIHash(pis));
        mleProof.whirTranscript = hex"DEADBEEF"; // WHIR verification fails
        bytes memory proofBytes = abi.encode(mleProof);

        uint32[] memory ids = new uint32[](1);
        ids[0] = 2;
        (KZGProof memory kzg, bytes32 blobHash) =
            _postWithKZGOn(r, _batch(1, ids, 200, bytes32(uint256(0xdef))), proofBytes, stateRoot, submitter);

        vm.prank(attacker);
        assertTrue(
            r.fraudProof(0, blobHash, stateRoot, proofBytes, pis, mleProof, kzg),
            "a genuinely invalid proof must still be convictable"
        );
        assertGt(r.pendingWithdrawals(attacker), 0, "honest fraud prover is still rewarded");
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
        IntmaxRollup.ValidityPublicInputs memory pis = _pisFor(root, address(0));
        MleVerifier.MleProof memory proof = _mleProofWithPI(_computePIHash(pis));

        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        _postWithKZG(_batch(1, ids, 100, bytes32(uint256(0x333))), abi.encode(proof), root, submitter);

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
            _batch(1, ids, 100, bytes32(uint256(0x101))), keccak256("p"), 1, keccak256("s")
        );
        bytes32 chainWithD1Only = rollup.blockDepositHash(1);
        assertTrue(chainWithD1Only != bytes32(0), "D1 folded into the posted block");

        // D2 lands AFTER the batch was posted. It belongs to nobody's batch yet.
        rollup.deposit{value: 100}(bytes32(uint256(0xd2)), 0, 100, bytes32(uint256(0xa2)));
        uint256 escrowedBefore = rollup.totalEscrowed();

        // Roll the batch back through the proof-free timeout branch.
        vm.roll(block.number + 3601);
        IntmaxRollup.ValidityPublicInputs memory emptyPis;
        MleVerifier.MleProof memory emptyProof;
        KZGProof memory emptyKzg;
        vm.prank(attacker);
        assertTrue(
            rollup.fraudProof(0, bytes32(0), bytes32(0), "", emptyPis, emptyProof, emptyKzg),
            "timeout removal"
        );
        assertEq(rollup.blockNumber(), 0, "batch rolled back");

        // The escrowed ETH is (correctly) NOT rolled back...
        assertEq(rollup.totalEscrowed(), escrowedBefore, "escrow must not roll back");

        // ...so the deposit chain that entitles anyone to it must not be rolled back either.
        // Re-post: the new block must carry a chain that still includes D2.
        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(1, ids, 300, bytes32(uint256(0x303))), keccak256("p2"), 1, keccak256("s2")
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
            _batch(1, ids, 100, bytes32(uint256(0x101))), keccak256("p"), 1, keccak256("s")
        );
        bytes32 regChainBefore = rollup.blockChannelRegHash(1);

        // Register AFTER the batch was posted.
        _registerChannel(7);

        vm.roll(block.number + 3601);
        IntmaxRollup.ValidityPublicInputs memory emptyPis;
        MleVerifier.MleProof memory emptyProof;
        KZGProof memory emptyKzg;
        vm.prank(attacker);
        assertTrue(
            rollup.fraudProof(0, bytes32(0), bytes32(0), "", emptyPis, emptyProof, emptyKzg),
            "timeout removal"
        );

        // Re-post; the registration must still be in the chain.
        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(1, ids, 300, bytes32(uint256(0x303))), keccak256("p2"), 1, keccak256("s2")
        );
        assertTrue(
            rollup.blockChannelRegHash(1) != regChainBefore,
            "H-1: rollback erased the post-batch channel registration, bricking the channelId"
        );
    }

    // =======================================================================
    // H-4 — the KZG blob binding must not be vacuous at the caller's option
    // =======================================================================

    /// @dev H-4: `vanishingG2 = G2_GENERATOR` asserts Z(tau) = 1, collapsing the pairing check to
    ///      `pi == C - I(tau)`, which anyone computes from public points with no trapdoor. A
    ///      production verifier must refuse it.
    function test_H4_productionVerifierRejectsDegenerateVanishingG2() public {
        BlobKZGVerifierExt prod = new BlobKZGVerifierExt(false); // production configuration
        assertFalse(prod.allowDegenerateVanishingG2(), "production must not allow the degenerate Z");

        bytes memory proofBytes = abi.encode(_defaultMleProof());
        (KZGProof memory kzg, bytes32 blobHash) = _computeKZGProof(proofBytes);

        // This is a fully self-consistent opening: it passes every other check and is accepted by a
        // verifier that permits the degenerate branch...
        BlobKZGVerifierExt testCfg = new BlobKZGVerifierExt(true);
        testCfg.verify(blobHash, kzg, proofBytes);

        // ...but the production verifier must reject it outright.
        vm.expectRevert(BlobKZGVerifier.BKV_DegenerateVanishingG2.selector);
        prod.verify(blobHash, kzg, proofBytes);
    }

    /// @dev H-4: the degenerate branch makes the binding VACUOUS — the same construction "proves"
    ///      the blob held completely different bytes. This is what the production reject stops.
    function test_H4_degenerateBranchBindsNothing() public {
        bytes memory realBlob  = abi.encode(_defaultMleProof());
        bytes memory otherData = hex"c0ffeec0ffeec0ffee";

        // Forge an opening for `otherData` from public points only, then note it verifies against
        // a blob hash derived from that same forged commitment: no trapdoor was ever needed.
        (KZGProof memory forged, bytes32 forgedHash) = _computeKZGProof(otherData);
        BlobKZGVerifierExt testCfg = new BlobKZGVerifierExt(true);
        testCfg.verify(forgedHash, forged, otherData);
        assertTrue(realBlob.length != otherData.length, "distinct payloads");

        // The production verifier refuses to evaluate this class of opening at all.
        BlobKZGVerifierExt prod = new BlobKZGVerifierExt(false);
        vm.expectRevert(BlobKZGVerifier.BKV_DegenerateVanishingG2.selector);
        prod.verify(forgedHash, forged, otherData);
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
        vm.prank(poster);
        target.postBlockAndSubmit{value: 1 ether}(
            batch, keccak256(proofBytes), uint32(proofBytes.length), stateRoot
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
            hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65",
            hex"596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
            hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051",
            hex"c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
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
