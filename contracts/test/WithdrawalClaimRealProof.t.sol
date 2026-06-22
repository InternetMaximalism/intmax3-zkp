// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

/// @title WithdrawalClaimRealProof — A1/A3/A4: REAL on-chain MLE/WHIR verification of the
///        withdrawal-claim statement (positive + tampered-binding negatives).
/// @notice Today the withdrawal-claim path is exercised on-chain ONLY with the mock MleVerifier
///         (`ChannelSettlementManager.t.sol`). The CLI E2E drives a real claim, but there is no fast
///         checked-in Solidity test that runs the REAL `MleVerifier.verify` for the claim circuit, nor
///         real-proof NEGATIVES. This drives `verifyWithdrawalClaim` DIRECTLY with the checked-in real
///         `withdrawal_claim_mle.json` proof + the real MleVerifier, so:
///           A1: the real claim proof verifies on-chain against its real VK + descriptor values.
///           A3/A4: a real proof presented with a DIFFERENT expected limb (H1 / member / recipient /
///                  amount / nullifier / channel) is REJECTED at the strict 48-limb bind — exactly the
///                  injection the manager performs (it pins the finalized H1 and registered member),
///                  proving the bind actually constrains a REAL proof (not just the mock).
/// @dev A direct verifier call supplies the expected values itself, so NO lifecycle co-generation is
///      needed — the fixture is internally consistent (proof PI == descriptor). Self-skips if the
///      fixture is absent.
///
/// SECURITY (fail-closed): every negative asserts the SPECIFIC attack — a real proof bound to the
/// wrong finalized state / wrong member / wrong amount must REVERT, never verify. A regression that
/// dropped a field from the bind would let one of these through; this suite would then fail.
contract WithdrawalClaimRealProofTest is Test {
    ChannelSettlementVerifier internal sv;
    MleVerifier internal mle;
    bool internal ready;

    // descriptor values (the proved public inputs the bind expects)
    bytes4 internal wcChannelId;
    bytes32 internal wcDigest;
    bytes32 internal wcH1;
    bytes32 internal wcMember;
    address internal wcRecipient;
    bytes32 internal wcUserAmtDigest;
    uint64 internal wcAmount;
    bytes32 internal wcNullifier;

    function _wcMleJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/withdrawal_claim_mle.json"));
    }
    function _wcDescJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/withdrawal_claim.json"));
    }

    function setUp() public {
        // Self-skip until both the real claim proof and its descriptor exist.
        try vm.readFile(string.concat(vm.projectRoot(), "/test/data/withdrawal_claim_mle.json")) {
            try vm.readFile(string.concat(vm.projectRoot(), "/test/data/withdrawal_claim.json")) {
                ready = true;
            } catch { ready = false; return; }
        } catch { ready = false; return; }

        mle = new MleVerifier();
        sv = new ChannelSettlementVerifier(); // deployer == this test contract
        _initWithdrawalClaimVk();

        string memory d = _wcDescJson();
        wcChannelId = bytes4(uint32(vm.parseJsonUint(d, ".channel_id")));
        wcDigest = vm.parseJsonBytes32(d, ".close_intent_digest");
        wcH1 = vm.parseJsonBytes32(d, ".final_balance_state_h1");
        wcMember = vm.parseJsonBytes32(d, ".member_pk_g");
        wcRecipient = vm.parseJsonAddress(d, ".recipient");
        wcUserAmtDigest = vm.parseJsonBytes32(d, ".user_amount_digest");
        wcAmount = uint64(vm.parseJsonUint(d, ".amount"));
        wcNullifier = vm.parseJsonBytes32(d, ".withdrawal_nullifier");
    }

    /// Build the withdrawal-claim VK from the proved `withdrawal_claim_mle.json` (same field layout the
    /// close VK uses) and set it on the verifier with the REAL MleVerifier.
    function _initWithdrawalClaimVk() internal {
        string memory j = _wcMleJson();
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
        sv.initializeWithdrawalClaimVk(
            mle, vk, dd.whirParams, dd.protocolId, dd.sessionId, dd.kIs, dd.subgroupGenPowers
        );
    }

    // ── A1: the real proof verifies on-chain via the real MleVerifier ──

    function test_A1_realWithdrawalClaim_verifies_onchain() external {
        if (!ready) { vm.skip(true); return; }
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_wcMleJson());
        bool ok = sv.verifyWithdrawalClaim(
            wcChannelId, wcDigest, wcH1, wcMember, wcRecipient, wcUserAmtDigest, wcAmount, wcNullifier, proof
        );
        assertTrue(ok, "real withdrawal-claim proof must verify against its real VK + MleVerifier");
    }

    // ── A3/A4: a real proof bound to a DIFFERENT expected value is rejected at the strict bind ──

    /// A3: wrong finalized balance-state H1 (the field the manager injects from finalizeClose).
    function test_A3_wrongFinalizedH1_rejected() external {
        if (!ready) { vm.skip(true); return; }
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_wcMleJson());
        bytes32 wrongH1 = keccak256("not-the-finalized-h1");
        vm.expectRevert(bytes("claim limb mismatch"));
        sv.verifyWithdrawalClaim(
            wcChannelId, wcDigest, wrongH1, wcMember, wcRecipient, wcUserAmtDigest, wcAmount, wcNullifier, proof
        );
    }

    /// A4: claim presented for a DIFFERENT member pubkey hash than the proof commits.
    function test_A4_wrongMember_rejected() external {
        if (!ready) { vm.skip(true); return; }
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_wcMleJson());
        bytes32 wrongMember = keccak256("another-member");
        vm.expectRevert(bytes("claim limb mismatch"));
        sv.verifyWithdrawalClaim(
            wcChannelId, wcDigest, wcH1, wrongMember, wcRecipient, wcUserAmtDigest, wcAmount, wcNullifier, proof
        );
    }

    /// A4: claim redirected to a DIFFERENT recipient than the proof commits.
    function test_A4_wrongRecipient_rejected() external {
        if (!ready) { vm.skip(true); return; }
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_wcMleJson());
        address wrongRecipient = address(uint160(uint256(keccak256("attacker"))));
        vm.expectRevert(bytes("claim limb mismatch"));
        sv.verifyWithdrawalClaim(
            wcChannelId, wcDigest, wcH1, wcMember, wrongRecipient, wcUserAmtDigest, wcAmount, wcNullifier, proof
        );
    }

    /// Over-claim: a larger amount than the proof commits is rejected (the amount limb is bound).
    function test_wrongAmount_rejected() external {
        if (!ready) { vm.skip(true); return; }
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_wcMleJson());
        uint64 wrongAmount = wcAmount + 1;
        vm.expectRevert(bytes("claim limb mismatch"));
        sv.verifyWithdrawalClaim(
            wcChannelId, wcDigest, wcH1, wcMember, wcRecipient, wcUserAmtDigest, wrongAmount, wcNullifier, proof
        );
    }

    /// Nullifier swap: a different withdrawal nullifier than the proof commits is rejected (so the
    /// double-spend used-set cannot be sidestepped by presenting an unrelated nullifier).
    function test_wrongNullifier_rejected() external {
        if (!ready) { vm.skip(true); return; }
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_wcMleJson());
        bytes32 wrongNullifier = keccak256("forged-nullifier");
        vm.expectRevert(bytes("claim limb mismatch"));
        sv.verifyWithdrawalClaim(
            wcChannelId, wcDigest, wcH1, wcMember, wcRecipient, wcUserAmtDigest, wcAmount, wrongNullifier, proof
        );
    }

    /// Cross-channel: a different channel id than the proof commits is rejected (limb[0] bind).
    function test_wrongChannel_rejected() external {
        if (!ready) { vm.skip(true); return; }
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_wcMleJson());
        bytes4 wrongChannel = bytes4(uint32(wcChannelId) + 1);
        vm.expectRevert(bytes("claim limb mismatch"));
        sv.verifyWithdrawalClaim(
            wrongChannel, wcDigest, wcH1, wcMember, wcRecipient, wcUserAmtDigest, wcAmount, wcNullifier, proof
        );
    }
}
