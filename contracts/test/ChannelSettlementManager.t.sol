// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier,
    IChannelRegistry
} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";

/// @dev Minimal stand-in for `IntmaxRollup`'s registration surface (Finding E). It records the
/// SAME close-form IMCM commitment + bp identity the real rollup stores at `registerChannel`,
/// computed via the verifier's `closeMemberSetCommitment` so the byte form is identical. Tests
/// register a channel here BEFORE deploying the manager (the real deployment order).
contract MockChannelRegistry is IChannelRegistry {
    IChannelSettlementVerifier internal immutable verifier;
    mapping(uint32 => bytes32) public channelMemberSetCommitment;
    mapping(uint32 => uint8) public channelBpMemberSlot;
    mapping(uint32 => bytes32) public channelBpPkG;

    constructor(IChannelSettlementVerifier verifier_) {
        verifier = verifier_;
    }

    /// Register a channel's member set + bp from the active hashes (slot order) — mirrors the
    /// rollup's `registerChannel` recording (one-time, but the mock is permissive for test reuse).
    function register(
        uint32 channelId,
        uint8 bpMemberSlot,
        bytes32[] memory activeHashes
    ) external {
        bytes32[16] memory padded;
        for (uint256 i = 0; i < activeHashes.length; i++) {
            padded[i] = activeHashes[i];
        }
        channelMemberSetCommitment[channelId] =
            verifier.closeMemberSetCommitment(padded, uint8(activeHashes.length));
        channelBpMemberSlot[channelId] = bpMemberSlot;
        channelBpPkG[channelId] = activeHashes[bpMemberSlot];
    }

    /// Register an EXPLICIT (possibly mismatching) commitment + bp, for negative tests.
    function registerRaw(
        uint32 channelId,
        bytes32 commitment,
        uint8 bpMemberSlot,
        bytes32 bpHash
    ) external {
        channelMemberSetCommitment[channelId] = commitment;
        channelBpMemberSlot[channelId] = bpMemberSlot;
        channelBpPkG[channelId] = bpHash;
    }

    // --- Native-payout stand-in for IntmaxRollup.withdraw() (P3 close→payout tests) ---
    // Models the rollup's pull-payment: the close pays the manager via withdrawNative, crediting
    // pendingWithdrawals[manager]; the manager later calls withdraw() to pull that ETH.
    mapping(address => uint256) public pendingWithdrawals;

    /// Fund + credit a recipient's pull balance (simulates a finalized native withdrawal payout).
    function creditWithdrawal(address recipient) external payable {
        pendingWithdrawals[recipient] += msg.value;
    }

    function withdraw() external override {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "nothing to withdraw");
        pendingWithdrawals[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "withdraw failed");
    }
}

contract ChannelSettlementManagerTest is Test {
    // Redeclared for vm.expectEmit.
    event CloseRequested(
        address indexed requester,
        uint64 closeRequestedAt,
        uint64 closeFreezeNonce
    );

    ChannelSettlementVerifier internal verifier;
    MockChannelRegistry internal registry;
    ChannelSettlementManager internal manager;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    address internal mallory = makeAddr("mallory");

    bytes4 internal constant CHANNEL_ID = hex"00000009";
    // F7: members are identified by their SPHINCS+ pubkey hash (bytes32). The block-proposer is
    // member slot 0 (USER_A).
    uint8 internal constant BP_MEMBER_SLOT = 0;
    bytes32 internal constant USER_A = keccak256("member_a_sphincs_pubkey_hash");
    bytes32 internal constant USER_B = keccak256("member_b_sphincs_pubkey_hash");
    bytes32 internal constant USER_C = keccak256("member_c_sphincs_pubkey_hash");
    uint64 internal constant CHALLENGE_PERIOD = 1 days;
    uint64 internal constant GRACE = 600;
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 9;
    uint256 internal constant INITIAL_BP_BOND = 25;

    // Shared Rust<->Solidity CloseIntent digest test vector. The same fully-populated intent is
    // hashed by `CloseIntent::signing_digest()` in src/common/channel.rs
    // (close_intent_digest_matches_solidity_shared_vector) and MUST produce this constant.
    bytes32 internal constant SHARED_VECTOR_DIGEST =
        0xa2679bf7c2d9c08c45b6fdd39202456707cbdcf3e1667a45fb493a717b37d264;

    function setUp() external {
        verifier = new ChannelSettlementVerifier();
        registry = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));

        ChannelSettlementManager.MemberBinding[] memory bindings =
            new ChannelSettlementManager.MemberBinding[](3);
        bindings[0] =
            ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: alice});
        bindings[1] =
            ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
        bindings[2] =
            ChannelSettlementManager.MemberBinding({pkG: USER_C, recipient: carol});

        // Finding E DEPLOYMENT ORDER: register the channel on the (mock) rollup FIRST, then deploy
        // the manager so its member set + bp can be bound to the on-chain registration.
        bytes32[] memory activeHashes = new bytes32[](3);
        activeHashes[0] = USER_A;
        activeHashes[1] = USER_B;
        activeHashes[2] = USER_C;
        registry.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, activeHashes);

        manager = new ChannelSettlementManager(
            CHANNEL_ID,
            BP_MEMBER_SLOT,
            USER_A, // block-proposer pubkey hash = member at BP_MEMBER_SLOT
            CHALLENGE_PERIOD,
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)),
            IChannelRegistry(address(registry)),
            bindings
        );
    }

    function _proofFor(bytes32 piHash) internal pure returns (bytes memory) {
        return abi.encode(piHash);
    }

    function _intent(
        uint64 closeNonce,
        uint64 finalEpoch,
        uint64 finalSmallBlockNumber,
        uint64 closeFreezeNonce
    ) internal pure returns (ChannelSettlementManager.CloseIntent memory intent) {
        intent = _intentWithVersion(
            closeNonce,
            finalEpoch,
            finalSmallBlockNumber,
            closeFreezeNonce,
            12
        );
    }

    function _intentWithVersion(
        uint64 closeNonce,
        uint64 finalEpoch,
        uint64 finalSmallBlockNumber,
        uint64 closeFreezeNonce,
        uint64 finalStateVersion
    ) internal pure returns (ChannelSettlementManager.CloseIntent memory intent) {
        intent = ChannelSettlementManager.CloseIntent({
            closeNonce: closeNonce,
            finalEpoch: finalEpoch,
            finalSmallBlockNumber: finalSmallBlockNumber,
            closeFreezeNonce: closeFreezeNonce,
            finalChannelStateDigest: keccak256("final_state"),
            finalBalanceStateH1: keccak256("balance_state_h1"),
            channelFundAmount: 75,
            channelFundIntmaxStateRoot: keccak256("intmax_root"),
            burnTxHash: keccak256("burn_tx"),
            closeWithdrawalDigest: keccak256("burn_backed_close"),
            snapshotMediumBlockNumber: 77,
            finalStateVersion: finalStateVersion,
            finalSettledTxChain: keccak256("settled_tx_chain")
        });
    }

    function _closeProof(
        ChannelSettlementManager.CloseIntent memory intent
    ) internal view returns (bytes memory) {
        // F4/F7: the close proof binds the channel's registered member-set commitment (limbs
        // 77..85) AND the active member count (limb 85, appended at the END → 86 limbs).
        return _proofFor(
            verifier.closePIHash(
                CHANNEL_ID,
                intent.closeNonce,
                intent.finalEpoch,
                intent.finalSmallBlockNumber,
                intent.closeFreezeNonce,
                intent.finalChannelStateDigest,
                intent.finalBalanceStateH1,
                intent.channelFundAmount,
                intent.channelFundIntmaxStateRoot,
                intent.burnTxHash,
                intent.closeWithdrawalDigest,
                intent.snapshotMediumBlockNumber,
                intent.finalStateVersion,
                intent.finalSettledTxChain,
                manager.registeredMemberSetCommitment(),
                manager.activeMemberCount()
            )
        );
    }

    function _submitClose(ChannelSettlementManager.CloseIntent memory intent) internal {
        manager.submitCloseIntent(intent, _closeProof(intent));
    }

    /// Two-step close preamble: a member freezes the channel and the grace window elapses.
    function _requestCloseAndElapseGrace() internal {
        vm.prank(alice);
        manager.requestClose();
        vm.warp(block.timestamp + GRACE);
    }

    function _withdrawalClaim(
        bytes32 closeIntentDigest,
        bytes32 memberPkG,
        address recipient,
        uint64 amount
    ) internal pure returns (ChannelSettlementManager.WithdrawalClaim memory claim) {
        claim = ChannelSettlementManager.WithdrawalClaim({
            closeIntentDigest: closeIntentDigest,
            memberPkG: memberPkG,
            recipient: recipient,
            userAmountDigest: keccak256(abi.encodePacked(memberPkG, amount)),
            amount: amount,
            withdrawalNullifier: keccak256(
                abi.encodePacked("withdraw", closeIntentDigest, memberPkG)
            )
        });
    }

    function test_hash_helpers_are_stable() external view {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        bytes32 closePiHash = verifier.closePIHash(
            CHANNEL_ID,
            intent.closeNonce,
            intent.finalEpoch,
            intent.finalSmallBlockNumber,
            intent.closeFreezeNonce,
            intent.finalChannelStateDigest,
            intent.finalBalanceStateH1,
            intent.channelFundAmount,
            intent.channelFundIntmaxStateRoot,
            intent.burnTxHash,
            intent.closeWithdrawalDigest,
            intent.snapshotMediumBlockNumber,
            intent.finalStateVersion,
            intent.finalSettledTxChain,
            manager.registeredMemberSetCommitment(),
            manager.activeMemberCount()
        );
        assertTrue(closePiHash != bytes32(0));

        assertTrue(
            verifier.specialClosePIHash(
                CHANNEL_ID,
                BP_MEMBER_SLOT,
                USER_A,
                keccak256("root"),
                33,
                10,
                15
            ) != bytes32(0)
        );

        assertTrue(
            verifier.withdrawalClaimPIHash(
                CHANNEL_ID,
                keccak256("close"),
                keccak256("root"),
                USER_A,
                alice,
                keccak256("amount"),
                9,
                keccak256("nullifier")
            ) != bytes32(0)
        );

        assertTrue(
            verifier.cancelPIHash(
                CHANNEL_ID,
                keccak256("close"),
                keccak256("small_block"),
                keccak256("revived"),
                keccak256("tx_hash"),
                keccak256("seal")
            ) != bytes32(0)
        );

        assertTrue(
            verifier.postCloseClaimPIHash(
                CHANNEL_ID,
                keccak256("close"),
                keccak256("incoming"),
                USER_B,
                bob,
                keccak256("shared_nullifier"),
                9
            ) != bytes32(0)
        );
    }

    /// Shared Rust<->Solidity test vector: `computeCloseIntentDigest` must be byte-identical to
    /// Rust `CloseIntent::signing_digest()` (IMCI). The Rust side asserts the same constant in
    /// src/common/channel.rs::close_intent_digest_matches_solidity_shared_vector. The intent's
    /// channel id slots (header + channel_fund_snapshot) are this manager's CHANNEL_ID (9).
    function test_close_intent_digest_matches_rust_shared_vector() external view {
        ChannelSettlementManager.CloseIntent memory intent = ChannelSettlementManager.CloseIntent({
            closeNonce: 0x1111111122222222,
            finalEpoch: 0x3333333344444444,
            finalSmallBlockNumber: 0x5555555566666666,
            closeFreezeNonce: 0x7777777788888888,
            finalChannelStateDigest: 0x0000000100000002000000030000000400000005000000060000000700000008,
            finalBalanceStateH1: 0x000000090000000a0000000b0000000c0000000d0000000e0000000f00000010,
            channelFundAmount: 0x0000001100000012000000130000001400000015000000160000001700000018,
            channelFundIntmaxStateRoot: 0x000000190000001a0000001b0000001c0000001d0000001e0000001f00000020,
            burnTxHash: 0x0000002100000022000000230000002400000025000000260000002700000028,
            closeWithdrawalDigest: 0x000000290000002a0000002b0000002c0000002d0000002e0000002f00000030,
            snapshotMediumBlockNumber: 0x99999999aaaaaaaa,
            finalStateVersion: 0xbbbbbbbbcccccccc,
            finalSettledTxChain: 0x0000003100000032000000330000003400000035000000360000003700000038
        });
        assertEq(manager.computeCloseIntentDigest(intent), SHARED_VECTOR_DIGEST);
    }

    // Shared Rust<->Solidity test vector for the F4/D6 close-circuit member-set commitment (FIXED
    // 16-slot form, pad-to-MAX): keccak([IMCM, memberCount, h0..h15]) over the member SPHINCS+
    // pubkey hashes in slot order (130 u32 words; padding slots zeroed). The Rust side asserts the
    // same constant in src/common/channel.rs::close_member_set_commitment_matches_solidity_shared_vector.
    // Each active bytes32 is the byte form of 8 consecutive big-endian u32 limbs (h0 = 1..8,
    // h1 = 9..16, h2 = 17..24), with memberCount = 3 and slots 3..15 zero.
    bytes32 internal constant MEMBER_SET_VECTOR_H0 =
        0x0000000100000002000000030000000400000005000000060000000700000008;
    bytes32 internal constant MEMBER_SET_VECTOR_H1 =
        0x000000090000000a0000000b0000000c0000000d0000000e0000000f00000010;
    bytes32 internal constant MEMBER_SET_VECTOR_H2 =
        0x0000001100000012000000130000001400000015000000160000001700000018;
    bytes32 internal constant MEMBER_SET_COMMITMENT_VECTOR =
        0x12450612c5f67b7ff613b705f6e5efccf4bdd43e647570fcb207076f447236cc;

    function test_member_set_commitment_matches_rust_shared_vector() external view {
        // The shape is locked to this constant via the Rust counterpart; we recompute it here over
        // the FIXED 16-slot array (3 active hashes + 13 zero padding slots) and memberCount = 3.
        bytes32[16] memory hashes;
        hashes[0] = MEMBER_SET_VECTOR_H0;
        hashes[1] = MEMBER_SET_VECTOR_H1;
        hashes[2] = MEMBER_SET_VECTOR_H2;
        bytes32 commitment = verifier.closeMemberSetCommitment(hashes, 3);
        assertEq(commitment, MEMBER_SET_COMMITMENT_VECTOR);

        // Padding slots (>= memberCount) are zeroed INTERNALLY (mirrors Rust + the in-circuit
        // gadget), so a nonzero padding slot in the input array does NOT change the commitment —
        // the value depends only on memberCount and the active hashes (injective on the active set).
        bytes32[16] memory tampered = hashes;
        tampered[3] = bytes32(uint256(1));
        assertEq(verifier.closeMemberSetCommitment(tampered, 3), MEMBER_SET_COMMITMENT_VECTOR);

        // memberCount is part of the preimage: a different count changes the value.
        assertTrue(verifier.closeMemberSetCommitment(hashes, 4) != MEMBER_SET_COMMITMENT_VECTOR);
    }

    // -----------------------------------------------------------------------
    // F4/D6: variable active member count (2..16, pad-to-MAX)
    // -----------------------------------------------------------------------

    function _bindings(uint256 n) internal returns (ChannelSettlementManager.MemberBinding[] memory b) {
        b = new ChannelSettlementManager.MemberBinding[](n);
        for (uint256 i = 0; i < n; i++) {
            b[i] = ChannelSettlementManager.MemberBinding({
                pkG: keccak256(abi.encodePacked("member", i)),
                recipient: makeAddr(string.concat("rcpt", vm.toString(i)))
            });
        }
    }

    function _newManager(uint256 n, uint8 bpSlot)
        internal
        returns (ChannelSettlementManager m)
    {
        m = _newManagerFrom(_bindings(n), bpSlot);
    }

    /// @dev Construct a manager from pre-built bindings. Kept separate so `vm.expectRevert` can
    /// immediately precede ONLY the constructor call (no intervening cheatcode-tripping helpers).
    function _newManagerFrom(
        ChannelSettlementManager.MemberBinding[] memory b,
        uint8 bpSlot
    ) internal returns (ChannelSettlementManager m) {
        bytes32 bpHash = bpSlot < b.length ? b[bpSlot].pkG : bytes32(uint256(1));
        // Finding E: when the bindings are in-range (so the manager reaches the registry-consistency
        // check), register a MATCHING member set on the shared mock registry first so the
        // constructor binding succeeds. Out-of-range cases revert in the manager BEFORE the registry
        // check (and BEFORE the registry check matters). We reuse the shared `registry` (deployed in
        // setUp) rather than deploying a new contract here, so the ONLY call after a caller's
        // `vm.expectRevert` is the manager constructor itself (Foundry requires the reverting call
        // immediately after the cheatcode).
        if (b.length >= 2 && b.length <= 16 && bpSlot < b.length) {
            bytes32[] memory activeHashes = new bytes32[](b.length);
            for (uint256 i = 0; i < b.length; i++) {
                activeHashes[i] = b[i].pkG;
            }
            registry.register(uint32(CHANNEL_ID), bpSlot, activeHashes);
        }
        m = new ChannelSettlementManager(
            CHANNEL_ID,
            bpSlot,
            bpHash,
            CHALLENGE_PERIOD,
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)),
            IChannelRegistry(address(registry)),
            b
        );
    }

    function test_variable_member_count_2_and_16() external {
        ChannelSettlementManager m2 = _newManager(2, 0);
        assertEq(uint256(m2.activeMemberCount()), 2);
        assertEq(m2.memberCount(), 2);
        // registeredMemberSetCommitment uses the FIXED 16-slot form with the active count.
        bytes32[16] memory h2;
        h2[0] = keccak256(abi.encodePacked("member", uint256(0)));
        h2[1] = keccak256(abi.encodePacked("member", uint256(1)));
        assertEq(m2.registeredMemberSetCommitment(), verifier.closeMemberSetCommitment(h2, 2));

        ChannelSettlementManager m16 = _newManager(16, 5);
        assertEq(uint256(m16.activeMemberCount()), 16);
        assertEq(uint256(m16.bpMemberSlot()), 5);
        bytes32[16] memory h16;
        for (uint256 i = 0; i < 16; i++) {
            h16[i] = keccak256(abi.encodePacked("member", i));
        }
        assertEq(m16.registeredMemberSetCommitment(), verifier.closeMemberSetCommitment(h16, 16));
    }

    function test_member_count_out_of_range_reverts() external {
        // Build bindings BEFORE expectRevert so the cheatcode immediately precedes only the
        // constructor call (Foundry requires the reverting call at the same depth).
        ChannelSettlementManager.MemberBinding[] memory one = _bindings(1);
        vm.expectRevert(ChannelSettlementManager.InvalidMemberCount.selector);
        _newManagerFrom(one, 0);

        ChannelSettlementManager.MemberBinding[] memory seventeen = _bindings(17);
        vm.expectRevert(ChannelSettlementManager.InvalidMemberCount.selector);
        _newManagerFrom(seventeen, 0);

        // bpMemberSlot >= activeMemberCount reverts.
        ChannelSettlementManager.MemberBinding[] memory three = _bindings(3);
        vm.expectRevert(ChannelSettlementManager.InvalidBpMemberSlot.selector);
        _newManagerFrom(three, 3);
    }

    // -----------------------------------------------------------------------
    // Finding E: manager member set + bp MUST equal the rollup registration
    // -----------------------------------------------------------------------

    /// @dev Deploy a manager bound to `reg`, from 3 bindings (USER_A/B/C, bp slot 0).
    function _newManagerWithRegistry(IChannelRegistry reg)
        internal
        returns (ChannelSettlementManager)
    {
        ChannelSettlementManager.MemberBinding[] memory b =
            new ChannelSettlementManager.MemberBinding[](3);
        b[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: alice});
        b[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
        b[2] = ChannelSettlementManager.MemberBinding({pkG: USER_C, recipient: carol});
        return new ChannelSettlementManager(
            CHANNEL_ID,
            BP_MEMBER_SLOT,
            USER_A,
            CHALLENGE_PERIOD,
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)),
            reg,
            b
        );
    }

    /// (a) Manager constructor SUCCEEDS when its member set + bp match the rollup registration, and
    /// the manager's `registeredMemberSetCommitment()` equals the registry's recorded commitment.
    function test_findingE_constructorSucceeds_whenMemberSetMatches() external {
        MockChannelRegistry reg =
            new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
        bytes32[] memory active = new bytes32[](3);
        active[0] = USER_A;
        active[1] = USER_B;
        active[2] = USER_C;
        reg.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, active);

        ChannelSettlementManager m = _newManagerWithRegistry(IChannelRegistry(address(reg)));
        assertEq(
            m.registeredMemberSetCommitment(),
            reg.channelMemberSetCommitment(uint32(CHANNEL_ID)),
            "manager commitment != registry commitment"
        );
        assertEq(address(m.registry()), address(reg));
    }

    /// (b1) REVERTS when an active member differs from the registration.
    function test_findingE_constructorReverts_whenMemberDiffers() external {
        MockChannelRegistry reg =
            new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
        bytes32[] memory active = new bytes32[](3);
        active[0] = USER_A;
        active[1] = USER_B;
        active[2] = keccak256("a_DIFFERENT_member_c"); // registration has a different member C
        reg.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, active);

        vm.expectRevert(ChannelSettlementManager.MemberSetMismatch.selector);
        _newManagerWithRegistry(IChannelRegistry(address(reg)));
    }

    /// (b2) REVERTS when the registration has a different member_count (extra member).
    function test_findingE_constructorReverts_whenMemberCountDiffers() external {
        MockChannelRegistry reg =
            new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
        bytes32[] memory active = new bytes32[](4); // registration has 4 members, manager has 3
        active[0] = USER_A;
        active[1] = USER_B;
        active[2] = USER_C;
        active[3] = keccak256("extra_member_d");
        reg.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, active);

        vm.expectRevert(ChannelSettlementManager.MemberSetMismatch.selector);
        _newManagerWithRegistry(IChannelRegistry(address(reg)));
    }

    /// (b3) REVERTS when the registered bp differs (commitment matches but bp slot/hash differs).
    function test_findingE_constructorReverts_whenBpDiffers() external {
        MockChannelRegistry reg =
            new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
        bytes32[] memory active = new bytes32[](3);
        active[0] = USER_A;
        active[1] = USER_B;
        active[2] = USER_C;
        // Same member-set commitment, but bp registered at slot 1 (USER_B) instead of slot 0.
        reg.register(uint32(CHANNEL_ID), 1, active);

        vm.expectRevert(ChannelSettlementManager.BpMismatch.selector);
        _newManagerWithRegistry(IChannelRegistry(address(reg)));
    }

    /// (b4) REVERTS when the channel was never registered (commitment is bytes32(0)) — enforces the
    /// register-then-deploy order.
    function test_findingE_constructorReverts_whenUnregistered() external {
        MockChannelRegistry reg =
            new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
        // No register() call: registry returns bytes32(0).
        vm.expectRevert(ChannelSettlementManager.MemberSetMismatch.selector);
        _newManagerWithRegistry(IChannelRegistry(address(reg)));
    }

    function test_request_close_freezes_channel_and_emits() external {
        assertTrue(manager.isNativeSendAllowed(0));

        vm.expectEmit(true, false, false, true);
        emit CloseRequested(alice, uint64(block.timestamp), 1);
        vm.prank(alice);
        manager.requestClose();

        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
        );
        assertEq(manager.closeRequestedAt(), uint64(block.timestamp));
        assertEq(manager.currentCloseFreezeNonce(), 1);
        // The freeze halts native sends for every nonce.
        assertFalse(manager.isNativeSendAllowed(0));
        assertFalse(manager.isNativeSendAllowed(1));
    }

    function test_request_close_reverts_for_non_member() external {
        vm.prank(mallory);
        vm.expectRevert(ChannelSettlementManager.NotChannelMember.selector);
        manager.requestClose();
    }

    function test_request_close_reverts_when_already_pending() external {
        vm.prank(alice);
        manager.requestClose();

        vm.prank(bob);
        vm.expectRevert(ChannelSettlementManager.ChannelAlreadyFrozen.selector);
        manager.requestClose();
    }

    function test_request_close_reverts_when_closed() external {
        _requestCloseAndElapseGrace();
        _submitClose(_intent(1, 9, 22, 1));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();

        vm.prank(alice);
        vm.expectRevert(ChannelSettlementManager.ChannelClosed.selector);
        manager.requestClose();
    }

    function test_submit_close_intent_reverts_from_active_without_request() external {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        bytes memory proof = _closeProof(intent);
        vm.expectRevert(ChannelSettlementManager.CloseNotRequested.selector);
        manager.submitCloseIntent(intent, proof);
    }

    function test_submit_close_intent_grace_period_boundary() external {
        vm.prank(alice);
        manager.requestClose();
        uint256 requestedAt = block.timestamp;

        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        bytes memory proof = _closeProof(intent);

        // At +599s the grace window has not elapsed.
        vm.warp(requestedAt + GRACE - 1);
        vm.expectRevert(ChannelSettlementManager.GracePeriodNotElapsed.selector);
        manager.submitCloseIntent(intent, proof);

        // At exactly +600s it has.
        vm.warp(requestedAt + GRACE);
        manager.submitCloseIntent(intent, proof);
        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
        );
    }

    function test_challenge_replacement_uses_epoch_then_state_version() external {
        _requestCloseAndElapseGrace();
        _submitClose(_intentWithVersion(1, 9, 22, 1, 5));

        // Challenge path needs no fresh grace: the replacement lands in the same block as the
        // first intent.
        _submitClose(_intentWithVersion(2, 9, 23, 1, 6));
        ChannelSettlementManager.PendingClose memory pending = manager.getPendingClose();
        assertEq(pending.finalStateVersion, 6);

        // Same epoch, lower version: rejected.
        ChannelSettlementManager.CloseIntent memory lower = _intentWithVersion(3, 9, 24, 1, 5);
        bytes memory lowerProof = _closeProof(lower);
        vm.expectRevert(ChannelSettlementManager.CloseNotNewer.selector);
        manager.submitCloseIntent(lower, lowerProof);

        // Same epoch, equal version: rejected (strict tiebreak).
        ChannelSettlementManager.CloseIntent memory equalVersion =
            _intentWithVersion(3, 9, 24, 1, 6);
        bytes memory equalProof = _closeProof(equalVersion);
        vm.expectRevert(ChannelSettlementManager.CloseNotNewer.selector);
        manager.submitCloseIntent(equalVersion, equalProof);

        // Higher epoch wins even with a lower state version.
        _submitClose(_intentWithVersion(4, 10, 25, 1, 2));
        pending = manager.getPendingClose();
        assertEq(pending.finalEpoch, 10);
        assertEq(pending.finalStateVersion, 2);
    }

    function test_tampered_version_or_chain_fails_close_proof() external {
        _requestCloseAndElapseGrace();

        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        bytes memory proof = _closeProof(intent);
        bytes32 originalChain = intent.finalSettledTxChain;
        uint64 originalVersion = intent.finalStateVersion;

        // Tampering with finalSettledTxChain after the proof was computed must fail.
        intent.finalSettledTxChain = keccak256("forged_chain");
        vm.expectRevert(ChannelSettlementManager.InvalidCloseProof.selector);
        manager.submitCloseIntent(intent, proof);
        intent.finalSettledTxChain = originalChain;

        // Tampering with finalStateVersion must fail too.
        intent.finalStateVersion = originalVersion + 1;
        vm.expectRevert(ChannelSettlementManager.InvalidCloseProof.selector);
        manager.submitCloseIntent(intent, proof);
        intent.finalStateVersion = originalVersion;

        // The untampered intent still goes through.
        manager.submitCloseIntent(intent, proof);
    }

    function test_finalize_records_version_chain_and_h1() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intentWithVersion(1, 9, 22, 1, 41);
        _submitClose(intent);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();

        assertEq(manager.finalizedStateVersion(), 41);
        assertEq(manager.finalizedSettledTxChain(), intent.finalSettledTxChain);
        assertEq(manager.finalizedBalanceStateH1(), intent.finalBalanceStateH1);
        assertEq(manager.closeRequestedAt(), 0);
    }

    function test_cancel_then_reclose_requires_fresh_request_and_grace() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        _submitClose(intent);

        bytes32 closeIntentDigest = manager.computeCloseIntentDigest(intent);
        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager
            .CancelCloseRequest({
                closeIntentDigest: closeIntentDigest,
                revivedSmallBlockRoot: keccak256("small_block"),
                revivedInterChannelTxDigest: keccak256("revived_tx"),
                revivedTxHash: keccak256("tx_hash"),
                revivedSeal: keccak256("seal")
            });
        manager.cancelClose(
            request,
            _proofFor(
                verifier.cancelPIHash(
                    CHANNEL_ID,
                    closeIntentDigest,
                    request.revivedSmallBlockRoot,
                    request.revivedInterChannelTxDigest,
                    request.revivedTxHash,
                    request.revivedSeal
                )
            )
        );
        assertEq(manager.closeRequestedAt(), 0);

        // Re-closing straight away is barred: the channel is Active again.
        ChannelSettlementManager.CloseIntent memory reclose = _intent(2, 10, 30, 2);
        bytes memory recloseProof = _closeProof(reclose);
        vm.expectRevert(ChannelSettlementManager.CloseNotRequested.selector);
        manager.submitCloseIntent(reclose, recloseProof);

        // A fresh requestClose starts a fresh grace window.
        vm.prank(bob);
        manager.requestClose();
        assertEq(manager.currentCloseFreezeNonce(), 2);
        vm.expectRevert(ChannelSettlementManager.GracePeriodNotElapsed.selector);
        manager.submitCloseIntent(reclose, recloseProof);

        vm.warp(block.timestamp + GRACE);
        manager.submitCloseIntent(reclose, recloseProof);
        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
        );
    }

    function test_submit_finalize_withdraw_and_post_close_claim() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        _submitClose(intent);

        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
        );
        assertFalse(manager.isNativeSendAllowed(0));

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();

        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.Closed)
        );
        bytes32 closeIntentDigest = manager.finalizedCloseIntentDigest();

        ChannelSettlementManager.WithdrawalClaim memory aliceClaim = _withdrawalClaim(
            closeIntentDigest,
            USER_A,
            alice,
            30
        );
        manager.submitWithdrawalClaim(
            aliceClaim,
            _proofFor(
                verifier.withdrawalClaimPIHash(
                    CHANNEL_ID,
                    closeIntentDigest,
                    manager.finalizedBalanceStateH1(),
                    USER_A,
                    alice,
                    aliceClaim.userAmountDigest,
                    aliceClaim.amount,
                    aliceClaim.withdrawalNullifier
                )
            )
        );

        ChannelSettlementManager.PostCloseClaim memory postCloseClaim = ChannelSettlementManager
            .PostCloseClaim({
                closeIntentDigest: closeIntentDigest,
                incomingTxHash: keccak256("incoming_tx"),
                receiverPkG: USER_B,
                recipient: bob,
                sharedNativeNullifier: keccak256("shared_nullifier"),
                amount: 5
            });
        manager.submitPostCloseClaim(
            postCloseClaim,
            _proofFor(
                verifier.postCloseClaimPIHash(
                    CHANNEL_ID,
                    closeIntentDigest,
                    postCloseClaim.incomingTxHash,
                    USER_B,
                    bob,
                    postCloseClaim.sharedNativeNullifier,
                    postCloseClaim.amount
                )
            )
        );

        assertEq(manager.withdrawalCredits(alice), 30);
        assertEq(manager.withdrawalCredits(bob), 5);
    }

    function test_special_close_slashes_bp_and_freezes_channel() external {
        ChannelSettlementManager.SpecialClose memory specialClose = ChannelSettlementManager
            .SpecialClose({
                offendingBpMemberSlot: BP_MEMBER_SLOT,
                offendingBpPkG: USER_A,
                fullySignedSmallBlockRoot: keccak256("small_block_root"),
                smallBlockNumber: 33,
                signedMediumBlockNumber: 10,
                latestFinalizedMediumBlockNumber: 15
            });

        manager.submitSpecialClose(
            specialClose,
            _proofFor(
                verifier.specialClosePIHash(
                    CHANNEL_ID,
                    specialClose.offendingBpMemberSlot,
                    specialClose.offendingBpPkG,
                    specialClose.fullySignedSmallBlockRoot,
                    specialClose.smallBlockNumber,
                    specialClose.signedMediumBlockNumber,
                    specialClose.latestFinalizedMediumBlockNumber
                )
            )
        );

        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
        );
        assertEq(manager.currentCloseFreezeNonce(), 1);
        assertEq(manager.closeRequestedAt(), uint64(block.timestamp));
        assertEq(manager.bpBondCredits(), INITIAL_BP_BOND - SPECIAL_CLOSE_PENALTY);
        assertEq(manager.withdrawalCredits(address(this)), SPECIAL_CLOSE_PENALTY);
    }

    function test_cancel_close_restores_active_channel() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        _submitClose(intent);

        bytes32 closeIntentDigest = manager.computeCloseIntentDigest(intent);
        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager
            .CancelCloseRequest({
                closeIntentDigest: closeIntentDigest,
                revivedSmallBlockRoot: keccak256("small_block"),
                revivedInterChannelTxDigest: keccak256("revived_tx"),
                revivedTxHash: keccak256("tx_hash"),
                revivedSeal: keccak256("seal")
            });

        manager.cancelClose(
            request,
            _proofFor(
                verifier.cancelPIHash(
                    CHANNEL_ID,
                    closeIntentDigest,
                    request.revivedSmallBlockRoot,
                    request.revivedInterChannelTxDigest,
                    request.revivedTxHash,
                    request.revivedSeal
                )
            )
        );

        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.Active)
        );
        assertEq(manager.currentCloseFreezeNonce(), 1);
        assertEq(manager.closeRequestedAt(), 0);
        assertTrue(manager.isNativeSendAllowed(1));
    }

    function test_late_outgoing_debit_correction_invalidates_pending_close() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        _submitClose(intent);

        bytes32 closeIntentDigest = manager.computeCloseIntentDigest(intent);
        ChannelSettlementManager.LateOutgoingDebitCorrection memory correction =
            ChannelSettlementManager.LateOutgoingDebitCorrection({
                closeIntentDigest: closeIntentDigest,
                sourceTxHash: keccak256("source_tx"),
                senderPkG: USER_C,
                senderAmountDigest: keccak256("sender_amount"),
                debitNullifier: keccak256("debit_nullifier"),
                amount: 7
            });

        manager.submitLateOutgoingDebitCorrection(
            correction,
            _proofFor(
                verifier.lateOutgoingDebitPIHash(
                    CHANNEL_ID,
                    closeIntentDigest,
                    correction.sourceTxHash,
                    USER_C,
                    correction.senderAmountDigest,
                    correction.debitNullifier,
                    correction.amount
                )
            )
        );

        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.Active)
        );
        assertEq(manager.currentCloseFreezeNonce(), 1);
        assertEq(manager.closeRequestedAt(), 0);
    }

    function test_special_close_then_submit_and_finalize_normal_close() external {
        ChannelSettlementManager.SpecialClose memory specialClose = ChannelSettlementManager
            .SpecialClose({
                offendingBpMemberSlot: BP_MEMBER_SLOT,
                offendingBpPkG: USER_A,
                fullySignedSmallBlockRoot: keccak256("small_block_root"),
                smallBlockNumber: 33,
                signedMediumBlockNumber: 10,
                latestFinalizedMediumBlockNumber: 15
            });
        manager.submitSpecialClose(
            specialClose,
            _proofFor(
                verifier.specialClosePIHash(
                    CHANNEL_ID,
                    specialClose.offendingBpMemberSlot,
                    specialClose.offendingBpPkG,
                    specialClose.fullySignedSmallBlockRoot,
                    specialClose.smallBlockNumber,
                    specialClose.signedMediumBlockNumber,
                    specialClose.latestFinalizedMediumBlockNumber
                )
            )
        );

        ChannelSettlementManager.CloseIntent memory intent = _intent(2, 10, 40, 1);
        bytes memory proof = _closeProof(intent);

        // A special close is a freeze request: the first intent obeys the same grace window.
        vm.expectRevert(ChannelSettlementManager.GracePeriodNotElapsed.selector);
        manager.submitCloseIntent(intent, proof);

        vm.warp(block.timestamp + GRACE);
        manager.submitCloseIntent(intent, proof);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();
        assertEq(manager.finalizedEpoch(), 10);
        assertEq(manager.finalizedSmallBlockNumber(), 40);
        assertEq(manager.finalizedBurnTxHash(), intent.burnTxHash);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  P3: real native-ETH payout (close → manager pulls funds → member split)
    // ═══════════════════════════════════════════════════════════════════════

    /// Drive the default manager to Closed and return the finalized close-intent digest.
    function _finalizeDefault() internal returns (bytes32) {
        _requestCloseAndElapseGrace();
        _submitClose(_intent(1, 9, 22, 1)); // channelFundAmount = 75
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();
        return manager.finalizedCloseIntentDigest();
    }

    function _submitWd(bytes32 d, bytes32 memberHash, address recipient, uint64 amount) internal {
        ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, memberHash, recipient, amount);
        manager.submitWithdrawalClaim(
            c,
            _proofFor(
                verifier.withdrawalClaimPIHash(
                    CHANNEL_ID, d, manager.finalizedBalanceStateH1(), memberHash, recipient,
                    c.userAmountDigest, c.amount, c.withdrawalNullifier
                )
            )
        );
    }

    /// Simulate the rollup paying this manager via a finalized native withdrawal, then pull it in.
    function _fundAndPull(MockChannelRegistry reg, ChannelSettlementManager m, uint256 amount) internal {
        vm.deal(address(this), address(this).balance + amount);
        reg.creditWithdrawal{value: amount}(address(m));
        m.pullChannelFunds();
    }

    function _closeProofFor(ChannelSettlementManager m, ChannelSettlementManager.CloseIntent memory intent)
        internal view returns (bytes memory)
    {
        return _proofFor(
            verifier.closePIHash(
                CHANNEL_ID, intent.closeNonce, intent.finalEpoch, intent.finalSmallBlockNumber,
                intent.closeFreezeNonce, intent.finalChannelStateDigest, intent.finalBalanceStateH1,
                intent.channelFundAmount, intent.channelFundIntmaxStateRoot, intent.burnTxHash,
                intent.closeWithdrawalDigest, intent.snapshotMediumBlockNumber, intent.finalStateVersion,
                intent.finalSettledTxChain, m.registeredMemberSetCommitment(), m.activeMemberCount()
            )
        );
    }

    /// Deploy a manager whose member-slot-0 recipient is `r0` (USER_A/B/C hashes unchanged, so the
    /// Finding-E member-set commitment still matches). Used for the reentrancy test.
    function _managerWithRecipient0(address r0)
        internal returns (ChannelSettlementManager m, MockChannelRegistry reg)
    {
        reg = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
        bytes32[] memory activeHashes = new bytes32[](3);
        activeHashes[0] = USER_A; activeHashes[1] = USER_B; activeHashes[2] = USER_C;
        reg.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, activeHashes);
        ChannelSettlementManager.MemberBinding[] memory b = new ChannelSettlementManager.MemberBinding[](3);
        b[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: r0});
        b[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
        b[2] = ChannelSettlementManager.MemberBinding({pkG: USER_C, recipient: carol});
        m = new ChannelSettlementManager(
            CHANNEL_ID, BP_MEMBER_SLOT, USER_A, CHALLENGE_PERIOD, SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND, IChannelSettlementVerifier(address(verifier)), IChannelRegistry(address(reg)), b
        );
    }

    /// Stray ETH from a non-rollup sender must be rejected (receive() restricted to the registry).
    function test_p3_receive_rejectsNonRollup() external {
        vm.deal(mallory, 1 ether);
        vm.prank(mallory);
        (bool ok, ) = address(manager).call{value: 1}("");
        assertFalse(ok, "non-rollup ETH must be rejected");
        assertEq(address(manager).balance, 0, "no stray ETH held");
    }

    /// pullChannelFunds moves the manager's rollup credit into the manager and records it.
    function test_p3_pullChannelFunds_recordsReceived() external {
        _fundAndPull(registry, manager, 60);
        assertEq(manager.receivedChannelFunds(), 60, "receivedChannelFunds == pulled");
        assertEq(address(manager).balance, 60, "manager holds the pulled ETH");
    }

    /// Happy path: members claim their accrued credit as real native ETH.
    function test_p3_claimWithdrawalCredit_paysRealEth() external {
        bytes32 d = _finalizeDefault();
        _submitWd(d, USER_A, alice, 30);
        _submitWd(d, USER_B, bob, 20); // distinct nullifier (keyed by member hash)
        _fundAndPull(registry, manager, 75);

        uint256 aliceBefore = alice.balance;
        vm.prank(alice);
        uint256 got = manager.claimWithdrawalCredit();
        assertEq(got, 30, "alice claims her credit");
        assertEq(alice.balance, aliceBefore + 30, "alice received real ETH");
        assertEq(manager.withdrawalCredits(alice), 0, "credit cleared");
        assertEq(manager.totalCreditedOut(), 30, "paid-out accumulator");

        vm.prank(bob);
        manager.claimWithdrawalCredit();
        assertEq(bob.balance, 20, "bob received real ETH");
        assertEq(manager.totalCreditedOut(), 50, "total paid out");
    }

    /// CROSS-CHANNEL ISOLATION (non-negotiable): the manager cannot pay out more ETH than it
    /// actually received from the rollup, even if intra-channel credits say otherwise.
    function test_p3_claimWithdrawalCredit_cappedByReceivedFunds() external {
        bytes32 d = _finalizeDefault();
        _submitWd(d, USER_A, alice, 30);   // credit = 30
        _fundAndPull(registry, manager, 10); // but only 10 ETH actually received
        vm.prank(alice);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.claimWithdrawalCredit();
        assertEq(alice.balance, 0, "no over-cap payout");
    }

    /// submitPostCloseClaim now shares the channel-fund accrual budget (previously uncapped).
    function test_p3_submitPostCloseClaim_capEnforced() external {
        bytes32 d = _finalizeDefault();
        _submitWd(d, USER_A, alice, 70); // totalWithdrawn = 70 (≤ 75)
        ChannelSettlementManager.PostCloseClaim memory pc = ChannelSettlementManager.PostCloseClaim({
            closeIntentDigest: d,
            incomingTxHash: keccak256("itx"),
            receiverPkG: USER_B,
            recipient: bob,
            sharedNativeNullifier: keccak256("snn"),
            amount: 10 // 70 + 10 = 80 > 75 -> must revert
        });
        // Precompute the proof BEFORE expectRevert: vm.expectRevert applies to the next external
        // call, which would otherwise be the argument-side postCloseClaimPIHash() rather than
        // submitPostCloseClaim().
        bytes memory proof = _proofFor(
            verifier.postCloseClaimPIHash(
                CHANNEL_ID, d, pc.incomingTxHash, USER_B, bob, pc.sharedNativeNullifier, pc.amount
            )
        );
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.submitPostCloseClaim(pc, proof);
    }

    /// A reentering recipient cannot double-withdraw: nonReentrant + CEI make the reentrant call
    /// revert, which bubbles up and reverts the whole claim (credit preserved, no ETH drained).
    function test_p3_claimWithdrawalCredit_reentrancyBlocked() external {
        ReentrantClaimer attacker = new ReentrantClaimer();
        (ChannelSettlementManager m, MockChannelRegistry reg) = _managerWithRecipient0(address(attacker));
        attacker.setManager(m);

        vm.prank(bob);
        m.requestClose();
        vm.warp(block.timestamp + GRACE);
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        m.submitCloseIntent(intent, _closeProofFor(m, intent));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        m.finalizeClose();
        bytes32 d = m.finalizedCloseIntentDigest();

        ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, USER_A, address(attacker), 30);
        m.submitWithdrawalClaim(
            c,
            _proofFor(
                verifier.withdrawalClaimPIHash(
                    CHANNEL_ID, d, m.finalizedBalanceStateH1(), USER_A, address(attacker),
                    c.userAmountDigest, c.amount, c.withdrawalNullifier
                )
            )
        );

        vm.deal(address(this), address(this).balance + 75);
        reg.creditWithdrawal{value: 75}(address(m));
        m.pullChannelFunds();

        // attacker re-enters during the payout → inner call reverts (Reentrant) → outer reverts.
        vm.expectRevert();
        attacker.claim();

        assertEq(m.withdrawalCredits(address(attacker)), 30, "credit preserved (no double-pay)");
        assertEq(m.totalCreditedOut(), 0, "nothing paid out");
        assertEq(address(attacker).balance, 0, "no ETH drained");
    }
}

/// @dev Attacker that re-enters claimWithdrawalCredit on receiving ETH (reentrancy test).
contract ReentrantClaimer {
    ChannelSettlementManager public mgr;
    uint256 public reenterCount;

    function setManager(ChannelSettlementManager m) external {
        mgr = m;
    }

    function claim() external returns (uint256) {
        return mgr.claimWithdrawalCredit();
    }

    receive() external payable {
        if (reenterCount == 0) {
            reenterCount = 1;
            mgr.claimWithdrawalCredit(); // reentrant attempt; reverts under nonReentrant
        }
    }
}
