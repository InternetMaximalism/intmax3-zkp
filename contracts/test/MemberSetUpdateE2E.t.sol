// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// detail2 §Q-4 (stage Q3, slice C): applyMemberSetUpdate against a REAL MemberSetUpdateCircuit
// MLE proof — the R2 discipline from audit25-08-2026 (every verifier-gated entry point gets a
// real-proof on-chain test; a mock in the oracle role is the class that hid gate-8).
//
// The fixture (`member_set_update{,_mle}.json`, generate_member_set_update_fixture) is a REAL
// rotation of slot 1 on a 3-member cluster: proposed and IMKR-self-consented at the wallet gate,
// N-of-N signed over IMMS by the OLD set, batch-Falcon aggregated, proven by the update circuit
// (degree 2^16, 26 PIs), wrapped, and MLE/WHIR-opened. The close VK fixture initializes the
// SHARED wrapper rail; the msu VK carries this circuit's own preprocessedRoot anchor.

import {Test} from "forge-std/Test.sol";
import {ChannelSettlementManager, IChannelSettlementVerifier, IChannelRegistry, IERC20} from "../src/ChannelSettlementManager.sol";
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

    function register(uint32 channelId, uint8 bpMemberSlot, bytes32[] memory activeHashes)
        external
    {
        bytes32[8] memory padded;
        for (uint256 i = 0; i < activeHashes.length; i++) {
            padded[i] = activeHashes[i];
        }
        channelMemberSetCommitment[channelId] =
            verifier.closeMemberSetCommitment(padded, uint8(activeHashes.length));
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
            bindings[i] = ChannelSettlementManager.MemberBinding({
                pkG: oldPkGs[i],
                recipient: address(uint160(0x1000 + i))
            });
        }
        manager = new ChannelSettlementManager(
            bytes4(channelId),
            0, // bp slot
            oldPkGs[0],
            0, // no delegates
            1 days,
            0,
            0,
            IChannelSettlementVerifier(address(settlementVerifier)),
            IChannelRegistry(address(registry)),
            bindings,
            new ChannelSettlementManager.MemberBinding[](0)
        );
    }

    /// The REAL rotation applies: version advances, slot 1's key changes, the commitment moves to
    /// the exact set the OLD cluster signed, bpPkG (slot 0) is untouched.
    function test_applyMemberSetUpdate_realProof_rotatesSlot1() external {
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(msuJson);
        bytes32 before = manager.registeredMemberSetCommitment();

        manager.applyMemberSetUpdate(newPkGs, newCount, address(0), setVersion, proof);

        assertEq(manager.memberSetVersion(), setVersion, "version advanced");
        assertEq(manager.activeMemberCount(), newCount, "count unchanged by a rotation");
        assertEq(manager.memberPkGs(1), newPkGs[1], "slot 1 rotated");
        assertEq(manager.memberPkGs(0), oldPkGs[0], "slot 0 untouched");
        assertEq(manager.bpPkG(), oldPkGs[0], "bp key (slot 0) untouched");
        assertTrue(
            manager.registeredMemberSetCommitment() != before,
            "commitment moved"
        );
        // The pkG-keyed registration maps migrated: old key unbound, new key at the same index.
        assertEq(manager.registeredMemberIndexPlusOne(oldPkGs[1]), 0, "old key unbound");
        assertEq(manager.registeredMemberIndexPlusOne(newPkGs[1]), 2, "new key bound at slot 1");
    }

    /// Replay is dead: after the apply, the same proof speaks about a commitment the Manager no
    /// longer holds AND a version that is no longer monotone.
    function test_applyMemberSetUpdate_replay_reverts() external {
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(msuJson);
        manager.applyMemberSetUpdate(newPkGs, newCount, address(0), setVersion, proof);
        vm.expectRevert(ChannelSettlementManager.MemberSetVersionNotMonotone.selector);
        manager.applyMemberSetUpdate(newPkGs, newCount, address(0), setVersion, proof);
    }

    /// A different new set than the proof committed: the recomputed newCommitment limb mismatches.
    function test_applyMemberSetUpdate_wrongNewSet_reverts() external {
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(msuJson);
        bytes32[] memory tampered = new bytes32[](newPkGs.length);
        for (uint256 i = 0; i < newPkGs.length; i++) {
            tampered[i] = newPkGs[i];
        }
        tampered[2] = bytes32(uint256(0xdeadbeef));
        vm.expectRevert(bytes("msu limb mismatch"));
        manager.applyMemberSetUpdate(tampered, newCount, address(0), setVersion, proof);
    }

    /// A tampered proof limb dies in the strict bind before any WHIR work.
    function test_applyMemberSetUpdate_tamperedLimb_reverts() external {
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(msuJson);
        proof.publicInputs[3] ^= 1; // a limb of oldCommitment
        vm.expectRevert(bytes("msu limb mismatch"));
        manager.applyMemberSetUpdate(newPkGs, newCount, address(0), setVersion, proof);
    }

    /// The version gate is strict monotone +1.
    function test_applyMemberSetUpdate_skippedVersion_reverts() external {
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(msuJson);
        vm.expectRevert(ChannelSettlementManager.MemberSetVersionNotMonotone.selector);
        manager.applyMemberSetUpdate(newPkGs, newCount, address(0), setVersion + 1, proof);
    }

    /// Without the msu VK there is NO seam — the entry reverts (V3-class structurally excluded).
    function test_applyMemberSetUpdate_withoutVk_reverts() external {
        ChannelSettlementVerifier fresh = new ChannelSettlementVerifier();
        MsuMockRegistry reg2 = new MsuMockRegistry(IChannelSettlementVerifier(address(fresh)));
        reg2.register(channelId, 0, oldPkGs);
        ChannelSettlementManager.MemberBinding[] memory bindings =
            new ChannelSettlementManager.MemberBinding[](oldPkGs.length);
        for (uint256 i = 0; i < oldPkGs.length; i++) {
            bindings[i] = ChannelSettlementManager.MemberBinding({
                pkG: oldPkGs[i],
                recipient: address(uint160(0x2000 + i))
            });
        }
        ChannelSettlementManager m2 = new ChannelSettlementManager(
            bytes4(channelId),
            0,
            oldPkGs[0],
            0,
            1 days,
            0,
            0,
            IChannelSettlementVerifier(address(fresh)),
            IChannelRegistry(address(reg2)),
            bindings,
            new ChannelSettlementManager.MemberBinding[](0)
        );
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(msuJson);
        vm.expectRevert(ChannelSettlementVerifier.MemberSetUpdateVkNotSet.selector);
        m2.applyMemberSetUpdate(newPkGs, newCount, address(0), setVersion, proof);
    }
}
