// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier,
    IChannelRegistry,
    IERC20
} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";

contract RetiredMsuRegistry is IChannelRegistry {
    mapping(bytes32 => bool) public override partialWithdrawalAuthorized;
    mapping(uint32 => bytes32) public channelMemberSetCommitment;
    mapping(uint32 => uint8) public channelBpMemberSlot;
    mapping(uint32 => bytes32) public channelBpPkG;

    constructor(uint32 channelId, bytes32 commitment, bytes32 bpPkG) {
        channelMemberSetCommitment[channelId] = commitment;
        channelBpMemberSlot[channelId] = 0;
        channelBpPkG[channelId] = bpPkG;
    }

    function withdraw(uint256) external {}
    function isFinalizedStateRoot(bytes32) external pure returns (bool) {
        return true;
    }
    function withdrawToken(uint32, uint256) external {}
    function tokenAddressOf(uint32) external pure returns (IERC20) {
        return IERC20(address(0));
    }
    function authorizePartialWithdrawal(bytes32) external {}
}

/// The direct in-place MSU prototype is retired. Its legacy selector is absent from production;
/// the active verifier likewise has no MSU key, initializer, version storage, or mutation path.
contract MemberSetUpdateDeprecatedTest is Test {
    uint32 internal constant CHANNEL_ID = 7;
    /// Historical pre-retirement selector, fixed independently of future PCS proof-tuple changes.
    bytes4 internal constant LEGACY_APPLY_MEMBER_SET_UPDATE_SELECTOR = 0x66e3ff78;

    ChannelSettlementVerifier internal verifier;
    ChannelSettlementManager internal manager;
    bytes32[] internal memberPkGs;

    function setUp() external {
        verifier = new ChannelSettlementVerifier();
        memberPkGs = new bytes32[](2);
        memberPkGs[0] = keccak256("retired-msu-member-0");
        memberPkGs[1] = keccak256("retired-msu-member-1");

        bytes32[8] memory padded;
        padded[0] = memberPkGs[0];
        padded[1] = memberPkGs[1];
        bytes32 commitment = verifier.closeMemberSetCommitment(padded, 2);
        RetiredMsuRegistry registry = new RetiredMsuRegistry(CHANNEL_ID, commitment, memberPkGs[0]);

        ChannelSettlementManager.MemberBinding[] memory bindings =
            new ChannelSettlementManager.MemberBinding[](2);
        bindings[0] = ChannelSettlementManager.MemberBinding({pkG: memberPkGs[0], recipient: address(0x1001)});
        bindings[1] = ChannelSettlementManager.MemberBinding({pkG: memberPkGs[1], recipient: address(0x1002)});
        manager = new ChannelSettlementManager(
            bytes4(CHANNEL_ID),
            0,
            memberPkGs[0],
            0,
            bytes32(0),
            1 days,
            0,
            0,
            IChannelSettlementVerifier(address(verifier)),
            IChannelRegistry(address(registry)),
            address(this),
            bindings
        );
    }

    function test_retiredSelectorAlwaysRevertsBeforeReadingProofOrMutatingState() external {
        bytes32 beforeCommitment = manager.registeredMemberSetCommitment();
        bytes32 beforeBp = manager.bpPkG();
        uint8 beforeCount = manager.activeMemberCount();
        MleVerifier.MleProof memory noProof;

        bytes32[] memory proposed = new bytes32[](2);
        proposed[0] = memberPkGs[0];
        proposed[1] = keccak256("must-never-be-installed");
        (bool ok, bytes memory revertData) = address(manager).call(
            abi.encodeWithSelector(
                LEGACY_APPLY_MEMBER_SET_UPDATE_SELECTOR,
                proposed,
                uint8(2),
                address(0xdead),
                type(uint64).max,
                noProof
            )
        );
        assertFalse(ok, "removed MSU selector unexpectedly succeeded");
        assertEq(revertData.length, 0, "removed MSU selector unexpectedly has an active decoder");

        assertEq(manager.registeredMemberSetCommitment(), beforeCommitment);
        assertEq(manager.bpPkG(), beforeBp);
        assertEq(manager.activeMemberCount(), beforeCount);
        assertEq(manager.registeredMemberIndexPlusOne(proposed[1]), 0);
        assertEq(manager.registeredRecipientOf(proposed[1]), address(0));
    }

    function test_activeVerifierHasNoMsuKeyInitializerOrVerificationSurface() external {
        (bool initOk,) = address(verifier).call(
            abi.encodeWithSignature(
                "initializeMemberSetUpdateVk((uint256,bytes32,uint256,uint256,bytes32))",
                uint256(1),
                bytes32(uint256(1)),
                uint256(1),
                uint256(1),
                bytes32(uint256(1))
            )
        );
        assertFalse(initOk, "retired MSU initializer unexpectedly exists");

        (bool verifyOk,) = address(verifier).staticcall(
            abi.encodeWithSignature(
                "verifyMemberSetUpdate(uint32,uint64,bytes32,bytes32,uint8,uint8,address,bytes)",
                CHANNEL_ID,
                uint64(1),
                bytes32(0),
                bytes32(0),
                uint8(2),
                uint8(2),
                address(0),
                bytes("")
            )
        );
        assertFalse(verifyOk, "retired MSU verifier unexpectedly exists");
    }
}
