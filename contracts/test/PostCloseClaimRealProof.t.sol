// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

/// @title PostCloseClaimRealProof — A2/A5: REAL on-chain MLE/WHIR verification of the
///        post-close-claim statement (positive + tampered-binding negatives).
/// @notice Mirrors WithdrawalClaimRealProof for the post-close (inter-channel incoming) claim path.
///         A2: the real 56-limb post-close proof verifies on-chain against its real VK + MleVerifier.
///         A5: a real proof presented with a different finalized accumulator ROOT (the Stage-3 source-
///             tx inclusion anchor the manager injects) is REJECTED at the strict bind — plus wrong
///             H1 / receiver / nullifier / amount.
/// @dev FIXTURE-TOOLING GAP (documented finding): `generate_post_close_claim_fixture`'s descriptor
///      (`post_close_claim.json`) OMITS `final_balance_state_h1` and `final_settled_tx_accumulator_root`,
///      yet `verifyPostCloseClaim` requires both (Stage-3 anchors). They ARE in the proof's 56-limb
///      public inputs (layout src/circuits/channel/post_close_claim_pis.rs:175-198: H1 = limbs 40..48,
///      accumulator root = limbs 48..56), so this test reconstructs them from `publicInputs` rather
///      than the descriptor. A cleaner long-term fix is to add the two fields to the descriptor.
///      Self-skips if the fixture is absent.
contract PostCloseClaimRealProofTest is Test {
    ChannelSettlementVerifier internal sv;
    MleVerifier internal mle;
    bool internal ready;

    bytes4 internal pcChannelId;
    bytes32 internal pcDigest;
    bytes32 internal pcIncomingTx;
    bytes32 internal pcReceiver;
    address internal pcRecipient;
    bytes32 internal pcNullifier;
    uint64 internal pcAmount;
    bytes32 internal pcH1; // reconstructed from publicInputs[40..48]
    bytes32 internal pcRoot; // reconstructed from publicInputs[48..56]

    function _pcMleJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/post_close_claim_mle.json"));
    }
    function _pcDescJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/post_close_claim.json"));
    }

    /// Reconstruct a bytes32 from 8 big-endian u32 limbs at `publicInputs[start..start+8]`.
    function _b32FromPi(string memory j, uint256 start) internal view returns (bytes32) {
        uint256 acc = 0;
        for (uint256 i = 0; i < 8; i++) {
            uint256 limb = vm.parseJsonUint(j, string.concat(".publicInputs[", vm.toString(start + i), "]"));
            acc |= limb << (32 * (7 - i));
        }
        return bytes32(acc);
    }

    function setUp() public {
        try vm.readFile(string.concat(vm.projectRoot(), "/test/data/post_close_claim_mle.json")) {
            try vm.readFile(string.concat(vm.projectRoot(), "/test/data/post_close_claim.json")) {
                ready = true;
            } catch { ready = false; return; }
        } catch { ready = false; return; }

        mle = new MleVerifier();
        sv = new ChannelSettlementVerifier();
        _initPostCloseClaimVk();

        string memory d = _pcDescJson();
        pcChannelId = bytes4(uint32(vm.parseJsonUint(d, ".receiver_channel_id")));
        pcDigest = vm.parseJsonBytes32(d, ".close_intent_digest");
        pcIncomingTx = vm.parseJsonBytes32(d, ".incoming_tx_hash");
        pcReceiver = vm.parseJsonBytes32(d, ".receiver_pk_g");
        pcRecipient = vm.parseJsonAddress(d, ".recipient");
        pcNullifier = vm.parseJsonBytes32(d, ".shared_native_nullifier");
        pcAmount = uint64(vm.parseJsonUint(d, ".amount"));

        string memory j = _pcMleJson();
        pcH1 = _b32FromPi(j, 40);
        pcRoot = _b32FromPi(j, 48);
    }

    function _initPostCloseClaimVk() internal {
        string memory j = _pcMleJson();
        FixtureLib.DeployData memory dd = FixtureLib.parseDeployData(j);
        MleVerifier.MleProof memory p = FixtureLib.parseProof(j);
        bytes32 gatesDigest = mle.computeGatesDigest(
            p.gates,
            p.witnessIndividualEvalsAtRGateV2.length,
            p.numSelectors,
            p.numGateConstraints,
            p.quotientDegreeFactor
        );
        ChannelSettlementVerifier.StatementVk memory vk = ChannelSettlementVerifier.StatementVk({
            degreeBits: dd.degreeBits,
            preprocessedRoot: dd.preCommitRoot,
            numConstants: dd.numConstants,
            numRoutedWires: dd.numRoutedWires,
            gatesDigest: gatesDigest
        });
        sv.initializePostCloseClaimVk(
            mle, vk, dd.whirParams, dd.protocolId, dd.sessionId, dd.kIs, dd.subgroupGenPowers
        );
    }

    // ── A2: the real post-close proof verifies on-chain via the real MleVerifier ──

    function test_A2_realPostCloseClaim_verifies_onchain() external {
        if (!ready) { vm.skip(true); return; }
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_pcMleJson());
        bool ok = sv.verifyPostCloseClaim(
            pcChannelId, pcDigest, pcIncomingTx, pcReceiver, pcRecipient, pcNullifier, pcAmount, pcH1, pcRoot, proof
        );
        assertTrue(ok, "real post-close-claim proof must verify against its real VK + MleVerifier");
    }

    // ── A5: a real proof bound to a DIFFERENT expected value is rejected at the strict bind ──

    /// A5: wrong finalized settled-tx accumulator root (the source-tx inclusion anchor).
    function test_A5_wrongAccumulatorRoot_rejected() external {
        if (!ready) { vm.skip(true); return; }
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_pcMleJson());
        bytes32 wrongRoot = keccak256("not-the-finalized-accumulator-root");
        vm.expectRevert(bytes("claim limb mismatch"));
        sv.verifyPostCloseClaim(
            pcChannelId, pcDigest, pcIncomingTx, pcReceiver, pcRecipient, pcNullifier, pcAmount, pcH1, wrongRoot, proof
        );
    }

    function test_wrongFinalizedH1_rejected() external {
        if (!ready) { vm.skip(true); return; }
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_pcMleJson());
        bytes32 wrongH1 = keccak256("not-the-finalized-h1");
        vm.expectRevert(bytes("claim limb mismatch"));
        sv.verifyPostCloseClaim(
            pcChannelId, pcDigest, pcIncomingTx, pcReceiver, pcRecipient, pcNullifier, pcAmount, wrongH1, pcRoot, proof
        );
    }

    function test_wrongReceiver_rejected() external {
        if (!ready) { vm.skip(true); return; }
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_pcMleJson());
        bytes32 wrongReceiver = keccak256("another-receiver");
        vm.expectRevert(bytes("claim limb mismatch"));
        sv.verifyPostCloseClaim(
            pcChannelId, pcDigest, pcIncomingTx, wrongReceiver, pcRecipient, pcNullifier, pcAmount, pcH1, pcRoot, proof
        );
    }

    /// Forged nullifier: the shared-native nullifier the proof commits cannot be swapped out (the
    /// manager recomputes + binds it; a different value must be rejected).
    function test_wrongNullifier_rejected() external {
        if (!ready) { vm.skip(true); return; }
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_pcMleJson());
        bytes32 wrongNullifier = keccak256("forged-shared-native-nullifier");
        vm.expectRevert(bytes("claim limb mismatch"));
        sv.verifyPostCloseClaim(
            pcChannelId, pcDigest, pcIncomingTx, pcReceiver, pcRecipient, wrongNullifier, pcAmount, pcH1, pcRoot, proof
        );
    }

    function test_wrongAmount_rejected() external {
        if (!ready) { vm.skip(true); return; }
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_pcMleJson());
        uint64 wrongAmount = pcAmount + 1;
        vm.expectRevert(bytes("claim limb mismatch"));
        sv.verifyPostCloseClaim(
            pcChannelId, pcDigest, pcIncomingTx, pcReceiver, pcRecipient, pcNullifier, wrongAmount, pcH1, pcRoot, proof
        );
    }
}
