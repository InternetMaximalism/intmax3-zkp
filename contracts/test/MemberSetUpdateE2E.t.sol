// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Release fail-closed guard for member-set updates, exercised with a REAL MemberSetUpdateCircuit
// MLE proof. The proof/verifier fixture is retained for future cross-layer work, but the Manager
// must reject every update before proof verification because this statement does not establish
// inclusion/finality of the corresponding validity-tree action.
//
// The fixture (`member_set_update{,_mle}.json`, generate_member_set_update_fixture) is a REAL
// rotation of slot 1 on a 3-member cluster: proposed and IMKR-self-consented at the wallet gate,
// N-of-N signed over IMMS by the OLD set, batch-Falcon aggregated, proven by the update circuit
// (degree 2^16, 26 PIs), wrapped, and MLE/WHIR-opened. The close VK fixture initializes the
// SHARED wrapper rail; the msu VK carries this circuit's own preprocessedRoot anchor.

import {Test} from "forge-std/Test.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier,
    IChannelRegistry,
    IERC20
} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

contract MsuMockRegistry is IChannelRegistry {
    IChannelSettlementVerifier internal immutable verifier;
    mapping(uint32 => bytes32) public channelMemberSetCommitment;
    mapping(uint32 => uint8) public channelBpMemberSlot;
    mapping(uint32 => bytes32) public channelBpPkG;

    constructor(IChannelSettlementVerifier verifier_) {
        verifier = verifier_;
    }

    function register(uint32 channelId, uint8 bpMemberSlot, bytes32[] memory activeHashes) external {
        bytes32[8] memory padded;
        for (uint256 i = 0; i < activeHashes.length; i++) {
            padded[i] = activeHashes[i];
        }
        channelMemberSetCommitment[channelId] = verifier.closeMemberSetCommitment(padded, uint8(activeHashes.length));
        channelBpMemberSlot[channelId] = bpMemberSlot;
        channelBpPkG[channelId] = activeHashes[bpMemberSlot];
    }

    function withdraw() external {}
    function withdrawToken(uint32) external {}

    function tokenAddressOf(uint32) external pure returns (IERC20) {
        return IERC20(address(0));
    }
    function authorizePartialWithdrawal(bytes32) external {}
}

contract MemberSetUpdateE2ETest is Test {
    MleVerifier internal mle;
    ChannelSettlementVerifier internal settlementVerifier;
    MsuMockRegistry internal registry;
    ChannelSettlementManager internal manager;

    uint32 internal channelId;
    uint64 internal setVersion;
    uint8 internal oldCount;
    uint8 internal newCount;
    bytes32[] internal oldPkGs;
    bytes32[] internal newPkGs;

    string internal msuJson;

    function _dataPath(string memory f) internal view returns (string memory) {
        return string.concat(vm.projectRoot(), "/test/data/", f);
    }

    function setUp() external {
        msuJson = vm.readFile(_dataPath("member_set_update_mle.json"));
        string memory desc = vm.readFile(_dataPath("member_set_update.json"));
        channelId = uint32(vm.parseJsonUint(desc, ".channelId"));
        setVersion = uint64(vm.parseJsonUint(desc, ".setVersion"));
        oldCount = uint8(vm.parseJsonUint(desc, ".oldCount"));
        newCount = uint8(vm.parseJsonUint(desc, ".newCount"));
        oldPkGs = vm.parseJsonBytes32Array(desc, ".oldMemberPkGs");
        newPkGs = vm.parseJsonBytes32Array(desc, ".newMemberPkGs");

        mle = new MleVerifier();
        settlementVerifier = new ChannelSettlementVerifier();

        // The shared wrapper rail comes from the close fixture (identical wrapper shape; only the
        // per-circuit preprocessedRoot differs — asserted below with real data).
        string memory cj = vm.readFile(_dataPath("close_intent_mle.json"));
        FixtureLib.DeployData memory cdd = FixtureLib.parseDeployData(cj);
        MleVerifier.MleProof memory cproof = FixtureLib.parseProof(cj);
        bytes32 closeGates = mle.computeGatesDigest(
            cproof.gates,
            cproof.witnessIndividualEvalsAtRGateV2.length,
            cproof.numSelectors,
            cproof.numGateConstraints,
            cproof.quotientDegreeFactor
        );
        settlementVerifier.initializeCloseVk(
            mle,
            ChannelSettlementVerifier.CloseVk({
                degreeBits: cdd.degreeBits,
                preprocessedRoot: cdd.preCommitRoot,
                numConstants: cdd.numConstants,
                numRoutedWires: cdd.numRoutedWires,
                gatesDigest: closeGates
            }),
            cdd.whirParams,
            cdd.protocolId,
            cdd.sessionId,
            cdd.kIs,
            cdd.subgroupGenPowers
        );

        FixtureLib.DeployData memory mdd = FixtureLib.parseDeployData(msuJson);
        MleVerifier.MleProof memory mproof = FixtureLib.parseProof(msuJson);
        bytes32 msuGates = mle.computeGatesDigest(
            mproof.gates,
            mproof.witnessIndividualEvalsAtRGateV2.length,
            mproof.numSelectors,
            mproof.numGateConstraints,
            mproof.quotientDegreeFactor
        );
        // The rail-sharing premise, checked against the REAL fixtures rather than assumed.
        assertEq(mdd.degreeBits, cdd.degreeBits, "wrapper degree must be shared");
        assertEq(msuGates, closeGates, "wrapper gates must be shared");
        settlementVerifier.initializeMemberSetUpdateVk(
            ChannelSettlementVerifier.CloseVk({
                degreeBits: mdd.degreeBits,
                preprocessedRoot: mdd.preCommitRoot,
                numConstants: mdd.numConstants,
                numRoutedWires: mdd.numRoutedWires,
                gatesDigest: msuGates
            })
        );

        registry = new MsuMockRegistry(IChannelSettlementVerifier(address(settlementVerifier)));
        registry.register(channelId, 0, oldPkGs);

        ChannelSettlementManager.MemberBinding[] memory bindings =
            new ChannelSettlementManager.MemberBinding[](oldPkGs.length);
        for (uint256 i = 0; i < oldPkGs.length; i++) {
            bindings[i] =
                ChannelSettlementManager.MemberBinding({pkG: oldPkGs[i], recipient: address(uint160(0x1000 + i))});
        }
        manager = new ChannelSettlementManager(
            bytes4(channelId),
            0, // bp slot
            oldPkGs[0],
            0, // no delegates
            bytes32(0),
            1 days,
            0,
            0,
            IChannelSettlementVerifier(address(settlementVerifier)),
            IChannelRegistry(address(registry)),
            bindings
        );
    }

    /// Even a real, valid rotation proof under an initialized MSU VK cannot mutate the Manager.
    /// This pins every field/map the former implementation wrote, so the release guard cannot be
    /// weakened into an early-return or a verifier-dependent path that leaves partial state.
    function test_applyMemberSetUpdate_realProof_releaseDisabledAndStateUnchanged() external {
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(msuJson);
        bytes32 beforeCommitment = manager.registeredMemberSetCommitment();
        bytes32 beforeBpPkG = manager.bpPkG();
        uint8 beforeCount = manager.activeMemberCount();
        uint64 beforeVersion = manager.memberSetVersion();
        uint256 beforeMemberCount = manager.memberCount();
        ChannelSettlementManager.ChannelLifecycleStatus beforeStatus = manager.channelStatus();
        bytes32[8] memory beforeSlots;
        for (uint256 i = 0; i < beforeSlots.length; i++) {
            beforeSlots[i] = manager.memberPkGs(i);
        }

        vm.expectRevert(ChannelSettlementManager.MemberSetUpdateDisabled.selector);
        manager.applyMemberSetUpdate(newPkGs, newCount, address(0), setVersion, proof);

        assertEq(manager.registeredMemberSetCommitment(), beforeCommitment, "commitment changed");
        assertEq(manager.bpPkG(), beforeBpPkG, "BP key changed");
        assertEq(manager.activeMemberCount(), beforeCount, "active member count changed");
        assertEq(manager.memberSetVersion(), beforeVersion, "member-set version changed");
        assertEq(manager.memberCount(), beforeMemberCount, "registered member array length changed");
        assertEq(uint8(manager.channelStatus()), uint8(beforeStatus), "channel status changed");
        for (uint256 i = 0; i < beforeSlots.length; i++) {
            assertEq(manager.memberPkGs(i), beforeSlots[i], "member slot changed");
        }
        for (uint256 i = 0; i < oldPkGs.length; i++) {
            address recipient = address(uint160(0x1000 + i));
            assertEq(manager.registeredMemberPkGs(i), oldPkGs[i], "registered key array changed");
            assertEq(manager.registeredMemberIndexPlusOne(oldPkGs[i]), i + 1, "old key index changed");
            assertEq(manager.registeredRecipientOf(oldPkGs[i]), recipient, "old key recipient changed");
            assertTrue(manager.isMemberRecipient(recipient), "old recipient permission changed");
        }
        assertEq(manager.registeredMemberIndexPlusOne(newPkGs[1]), 0, "new key was registered");
        assertEq(manager.registeredRecipientOf(newPkGs[1]), address(0), "new recipient was registered");
    }

    /// Repeated submissions remain the same named release error; no first call can advance state.
    function test_applyMemberSetUpdate_repeatedValidProof_staysDisabled() external {
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(msuJson);
        vm.expectRevert(ChannelSettlementManager.MemberSetUpdateDisabled.selector);
        manager.applyMemberSetUpdate(newPkGs, newCount, address(0), setVersion, proof);
        vm.expectRevert(ChannelSettlementManager.MemberSetUpdateDisabled.selector);
        manager.applyMemberSetUpdate(newPkGs, newCount, address(0), setVersion, proof);
        assertEq(manager.memberSetVersion(), 0, "disabled calls advanced the version");
    }

    /// The former add-cosigner branch cannot install a key or grant its recipient close/withdrawal
    /// authority while the release gate is active.
    function test_applyMemberSetUpdate_addCannotGrantNewRecipient() external {
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(msuJson);
        bytes32[] memory proposed = new bytes32[](oldPkGs.length + 1);
        for (uint256 i = 0; i < oldPkGs.length; i++) {
            proposed[i] = oldPkGs[i];
        }
        bytes32 addedPkG = keccak256("disabled-add-pk-g");
        address addedRecipient = address(0xdeadbeef);
        proposed[oldPkGs.length] = addedPkG;

        vm.expectRevert(ChannelSettlementManager.MemberSetUpdateDisabled.selector);
        manager.applyMemberSetUpdate(proposed, oldCount + 1, addedRecipient, setVersion, proof);

        assertEq(manager.activeMemberCount(), oldCount, "disabled add changed count");
        assertEq(manager.memberSetVersion(), 0, "disabled add changed version");
        assertEq(manager.registeredMemberIndexPlusOne(addedPkG), 0, "disabled add installed key");
        assertEq(manager.registeredRecipientOf(addedPkG), address(0), "disabled add bound recipient");
        assertFalse(manager.isMemberRecipient(addedRecipient), "disabled add granted recipient authority");
    }

    /// Proof validation is unreachable while the release gate is active.
    function test_applyMemberSetUpdate_tamperedLimb_returnsDisabled() external {
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(msuJson);
        proof.publicInputs[3] ^= 1; // a limb of oldCommitment
        vm.expectRevert(ChannelSettlementManager.MemberSetUpdateDisabled.selector);
        manager.applyMemberSetUpdate(newPkGs, newCount, address(0), setVersion, proof);
    }

    /// Even a nonsensical version gets the single named release error.
    function test_applyMemberSetUpdate_skippedVersion_returnsDisabled() external {
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(msuJson);
        vm.expectRevert(ChannelSettlementManager.MemberSetUpdateDisabled.selector);
        manager.applyMemberSetUpdate(newPkGs, newCount, address(0), setVersion + 1, proof);
    }

    /// M-11 (audit28-08-2026) — THE RAIL-AGREEMENT CHECK, in full, on the real fixtures.
    ///
    /// `ChannelSettlementVerifier._verifyMsuMle` verifies the member-set-update proof under the
    /// CLOSE statement's rail — `_closeWhirParams`, `closeWhirProtocolId`, `closeWhirSplitSessionId`,
    /// `_closeKIs`, `_closeSubgroupGenPowers` and `closeMleVerifier` — carrying only the msu VK's
    /// own `degreeBits` / `preprocessedRoot` / `numConstants` / `numRoutedWires` / `gatesDigest`.
    /// `initializeMemberSetUpdateVk` requires `closeVkInitialized`, but NOTHING on chain checks the
    /// two rails actually agree; the whole reuse rests on the premise that every inner circuit wraps
    /// to the same shape.
    ///
    /// This asserts that premise against the checked-in fixtures rather than assuming it, field by
    /// field: the ENTIRE `WhirParams` struct (including the per-round table), the two Fiat-Shamir
    /// domain separators, both scalar tables, and the wrapper's shape constants — with
    /// `preprocessedRoot`, the one per-circuit soundness anchor, required to DIFFER, so this can
    /// never be satisfied by keying the close circuit under the msu latch.
    ///
    /// It is deliberately a top-level test rather than a `setUp` assertion: `forge-test-guard.sh`
    /// counts tests per suite, so only a named test is something CI can require. STILL OPEN — see
    /// the finding: this is a fixture-time and (via `DeployGuards`) deploy-time check. The Verifier
    /// performs no runtime agreement check, and a manually-keyed verifier can still diverge. A
    /// divergence is fail-closed (verification fails; no foreign proof is ever accepted), so the
    /// missing on-chain check is a liveness fence, not a soundness one.
    function test_msuAndCloseFixturesShareTheEntireWhirRail() external view {
        FixtureLib.DeployData memory mdd = FixtureLib.parseDeployData(msuJson);
        FixtureLib.DeployData memory cdd = FixtureLib.parseDeployData(vm.readFile(_dataPath("close_intent_mle.json")));

        // The rail the Verifier substitutes wholesale, compared in one shot so a NEW WhirParams
        // field cannot slip past this test the way a hand-listed comparison would let it.
        assertEq(
            keccak256(abi.encode(mdd.whirParams)),
            keccak256(abi.encode(cdd.whirParams)),
            "msu/close whirParams must be identical -- _verifyMsuMle substitutes the close rail"
        );
        assertEq(keccak256(mdd.protocolId), keccak256(cdd.protocolId), "whir protocolId must match");
        assertEq(keccak256(mdd.sessionId), keccak256(cdd.sessionId), "whir sessionId must match");
        assertEq(keccak256(abi.encode(mdd.kIs)), keccak256(abi.encode(cdd.kIs)), "kIs must match");
        assertEq(
            keccak256(abi.encode(mdd.subgroupGenPowers)),
            keccak256(abi.encode(cdd.subgroupGenPowers)),
            "subgroupGenPowers must match"
        );

        // The wrapper shape the msu VK carries itself must still be the wrapper's.
        assertEq(mdd.degreeBits, cdd.degreeBits, "wrapper degreeBits must be shared");
        assertEq(mdd.numConstants, cdd.numConstants, "wrapper numConstants must be shared");
        assertEq(mdd.numRoutedWires, cdd.numRoutedWires, "wrapper numRoutedWires must be shared");

        // ... and the ONE field that must NOT be shared.
        assertTrue(
            mdd.preCommitRoot != cdd.preCommitRoot,
            "msu must carry its OWN preprocessedRoot -- equal roots mean the msu latch was keyed "
            "with the close circuit"
        );
    }

    /// The same premise where it actually bites: the gates digest the Verifier hands the MLE
    /// verifier for the msu proof is the WRAPPER's, so it must equal the close circuit's.
    function test_msuAndCloseWrapperGatesDigestsAgree() external view {
        MleVerifier.MleProof memory mproof = FixtureLib.parseProof(msuJson);
        MleVerifier.MleProof memory cproof = FixtureLib.parseProof(vm.readFile(_dataPath("close_intent_mle.json")));
        assertEq(
            mle.computeGatesDigest(
                mproof.gates,
                mproof.witnessIndividualEvalsAtRGateV2.length,
                mproof.numSelectors,
                mproof.numGateConstraints,
                mproof.quotientDegreeFactor
            ),
            mle.computeGatesDigest(
                cproof.gates,
                cproof.witnessIndividualEvalsAtRGateV2.length,
                cproof.numSelectors,
                cproof.numGateConstraints,
                cproof.quotientDegreeFactor
            ),
            "wrapper gatesDigest must be shared across the two statements"
        );
    }

    /// The Manager owns the release gate: it returns the same named error without consulting an
    /// uninitialized verifier. This prevents a deploy/manual-keying difference from changing the
    /// release semantics.
    function test_applyMemberSetUpdate_withoutVk_returnsManagerDisabled() external {
        ChannelSettlementVerifier fresh = new ChannelSettlementVerifier();
        MsuMockRegistry reg2 = new MsuMockRegistry(IChannelSettlementVerifier(address(fresh)));
        reg2.register(channelId, 0, oldPkGs);
        ChannelSettlementManager.MemberBinding[] memory bindings =
            new ChannelSettlementManager.MemberBinding[](oldPkGs.length);
        for (uint256 i = 0; i < oldPkGs.length; i++) {
            bindings[i] =
                ChannelSettlementManager.MemberBinding({pkG: oldPkGs[i], recipient: address(uint160(0x2000 + i))});
        }
        ChannelSettlementManager m2 = new ChannelSettlementManager(
            bytes4(channelId),
            0,
            oldPkGs[0],
            0,
            bytes32(0),
            1 days,
            0,
            0,
            IChannelSettlementVerifier(address(fresh)),
            IChannelRegistry(address(reg2)),
            bindings
        );
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(msuJson);
        vm.expectRevert(ChannelSettlementManager.MemberSetUpdateDisabled.selector);
        m2.applyMemberSetUpdate(newPkGs, newCount, address(0), setVersion, proof);
        assertEq(m2.memberSetVersion(), 0, "disabled call advanced the version");
        assertEq(m2.registeredMemberSetCommitment(), manager.registeredMemberSetCommitment(), "set changed");
    }
}
