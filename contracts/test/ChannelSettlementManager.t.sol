// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier,
    IChannelRegistry,
    CloseProofFields
} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {MockMleVerifier, CloseTestLib} from "./CloseTestLib.sol";
import {IERC20} from "../src/SafeERC20.sol";

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

    mapping(bytes32 => bool) public partialWithdrawalAuthorized;

    function authorizePartialWithdrawal(bytes32 authDigest) external override {
        partialWithdrawalAuthorized[authDigest] = true;
    }

    // --- Multi-token (multitoken Phase 3): ERC-20 pull-payment + set-once registry mirror ---
    mapping(uint32 => IERC20) public tokenAddressOf;
    mapping(uint32 => mapping(address => uint256)) public pendingTokenWithdrawals;

    function setToken(uint32 tokenIndex, IERC20 token) external {
        tokenAddressOf[tokenIndex] = token;
    }

    function creditTokenWithdrawal(uint32 tokenIndex, address recipient, uint256 amount) external {
        pendingTokenWithdrawals[tokenIndex][recipient] += amount;
    }

    function withdrawToken(uint32 tokenIndex) external override {
        uint256 amount = pendingTokenWithdrawals[tokenIndex][msg.sender];
        require(amount > 0, "nothing to withdraw");
        pendingTokenWithdrawals[tokenIndex][msg.sender] = 0;
        require(tokenAddressOf[tokenIndex].transfer(msg.sender, amount), "token transfer failed");
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
    MockMleVerifier internal mockMle;
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
    // Multitoken Phase 3 re-pin (2026-07-27): regenerated FROM THE RUST SIDE after the IMCI
    // preimage widened to the 80-word amounts[0..10] vector (§N-6, TM-11).
    bytes32 internal constant SHARED_VECTOR_DIGEST =
        0x9fc3ced58e9f82428e4b8a20f6e7755e1c0145facd2824f57d112cef86be42fb;

    function setUp() external {
        verifier = new ChannelSettlementVerifier();
        // Phase A close path: a real `verifyCloseIntent` rebinds the 103-limb close public inputs and
        // then calls `MleVerifier.verify`. The lifecycle tests exercise the manager + the REAL limb
        // binding, not the WHIR cryptography, so we wire a controllable mock verifier (verdict=true)
        // as the close MLE verifier and set the close VK once (set-once). `dummyVkArgs()` carries a
        // degreeBits=1 VK the mock ignores. (This test deploys ONE verifier — the shared `verifier`.)
        mockMle = new MockMleVerifier();
        _initCloseVk(verifier);
        // Phase B-D: the withdrawal-claim / post-close-claim paths are now REAL MLE verifications
        // too. Wire the same controllable mock verifier + set each statement's VK once.
        _initWithdrawalClaimVk(verifier);
        _initPostCloseClaimVk(verifier);
        // Phase C1: the cancelClose path is now a REAL MLE verification too. Wire the same mock MLE
        // verifier + set the cancel VK once.
        _initCancelCloseVk(verifier);
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
            0, // delegate_count (Phase 1: member-only)
            CHALLENGE_PERIOD,
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)),
            IChannelRegistry(address(registry)),
            bindings,
            new ChannelSettlementManager.MemberBinding[](0) // no delegates
        );
    }

    function _proofFor(bytes32 piHash) internal pure returns (bytes memory) {
        return abi.encode(piHash);
    }

    /// @dev Initialize a verifier's close VK with the shared mock MLE verifier (set-once). Mirrors
    /// the production `initializeCloseVk(verifier, vk, whir, protocolId, sessionId, kIs, subgroup)`.
    function _initCloseVk(ChannelSettlementVerifier v) internal {
        (
            ChannelSettlementVerifier.CloseVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        ) = CloseTestLib.dummyVkArgs();
        v.initializeCloseVk(
            MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers
        );
    }

    /// @dev Phase B-D: initialize the withdrawal-claim VK with the shared mock MLE verifier.
    function _initWithdrawalClaimVk(ChannelSettlementVerifier v) internal {
        (
            ChannelSettlementVerifier.StatementVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        ) = CloseTestLib.dummyStatementVkArgs();
        v.initializeWithdrawalClaimVk(
            MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers
        );
    }

    /// @dev Phase B-D: initialize the post-close-claim VK with the shared mock MLE verifier.
    function _initPostCloseClaimVk(ChannelSettlementVerifier v) internal {
        (
            ChannelSettlementVerifier.StatementVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        ) = CloseTestLib.dummyStatementVkArgs();
        v.initializePostCloseClaimVk(
            MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers
        );
    }

    /// @dev Phase C1: initialize the cancel-close VK with the shared mock MLE verifier.
    function _initCancelCloseVk(ChannelSettlementVerifier v) internal {
        (
            ChannelSettlementVerifier.StatementVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        ) = CloseTestLib.dummyStatementVkArgs();
        v.initializeCancelCloseVk(
            MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers
        );
    }

    /// @dev Build a cancel-close `MleProof` whose `publicInputs` equal the verifier's expected
    ///      27-limb vector for `request`. The `memberSetCommitment` limbs use the channel's
    ///      REGISTERED member-set commitment (what `cancelClose` injects — Finding D), so the strict
    ///      bind passes only when the proof claims the registered set.
    function _cancelCloseProof(ChannelSettlementManager.CancelCloseRequest memory request)
        internal view returns (MleVerifier.MleProof memory)
    {
        uint256[] memory limbs = verifier.expectedCancelCloseLimbs(
            CHANNEL_ID,
            request.closeIntentDigest,
            manager.registeredMemberSetCommitment(),
            request.revivedStateVersion,
            request.revivedChannelStateDigest
        );
        return CloseTestLib.proofWithLimbs(limbs);
    }

    /// @dev Build a withdrawal-claim `MleProof` whose `publicInputs` equal the verifier's expected
    ///      50-limb vector for `claim` — exactly what `_bindLimbsStrict` requires. Uses the channel's
    ///      finalized H1 (the manager passes it through to the verifier).
    function _withdrawalClaimProof(ChannelSettlementManager.WithdrawalClaim memory claim)
        internal view returns (MleVerifier.MleProof memory)
    {
        uint256[] memory limbs = verifier.expectedWithdrawalClaimLimbs(
            CHANNEL_ID,
            claim.closeIntentDigest,
            manager.finalizedBalanceStateH1(),
            claim.memberPkG,
            claim.recipient,
            claim.userAmountDigest,
            claim.amount,
            claim.tokenSlot,
            claim.tokenIndex,
            claim.withdrawalNullifier
        );
        return CloseTestLib.proofWithLimbs(limbs);
    }

    /// @dev As `_withdrawalClaimProof` but against an explicit manager instance (multi-manager
    ///      tests) and its finalized H1.
    function _withdrawalClaimProofFor(
        ChannelSettlementManager m,
        ChannelSettlementManager.WithdrawalClaim memory claim
    ) internal view returns (MleVerifier.MleProof memory) {
        uint256[] memory limbs = verifier.expectedWithdrawalClaimLimbs(
            CHANNEL_ID,
            claim.closeIntentDigest,
            m.finalizedBalanceStateH1(),
            claim.memberPkG,
            claim.recipient,
            claim.userAmountDigest,
            claim.amount,
            claim.tokenSlot,
            claim.tokenIndex,
            claim.withdrawalNullifier
        );
        return CloseTestLib.proofWithLimbs(limbs);
    }

    /// @dev Build a post-close-claim `MleProof` whose `publicInputs` equal the verifier's expected
    ///      40-limb vector. The `sharedNativeNullifier` is the RECOMPUTED value (hazard #8) —
    ///      mirroring the manager's `_deriveSharedNativeNullifier`.
    function _postCloseClaimProof(ChannelSettlementManager.PostCloseClaim memory claim)
        internal view returns (MleVerifier.MleProof memory)
    {
        bytes32 snn = _expectedSharedNativeNullifier(
            claim.closeIntentDigest, claim.incomingTxHash, claim.receiverPkG
        );
        // Stage 3: the proof's H1 + accumulator-root limbs must equal the FINALIZED values
        // `submitPostCloseClaim` passes to the verifier (else the strict limb bind rejects).
        uint256[] memory limbs = verifier.expectedPostCloseClaimLimbs(
            CHANNEL_ID,
            claim.closeIntentDigest,
            claim.incomingTxHash,
            claim.receiverPkG,
            claim.recipient,
            snn,
            claim.amount,
            manager.finalizedBalanceStateH1(),
            manager.finalizedSettledTxAccumulatorRoot(),
            claim.tokenIndex
        );
        return CloseTestLib.proofWithLimbs(limbs);
    }

    /// @dev Mirror of the manager's / circuit's IMCK shared-native nullifier derivation.
    function _expectedSharedNativeNullifier(
        bytes32 closeIntentDigest,
        bytes32 incomingTxHash,
        bytes32 receiverPkG
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes4(uint32(0x494d434b)), closeIntentDigest, incomingTxHash, receiverPkG
            )
        );
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

    /// Single-token (genesis ETH) helpers: amount at slot 0, base token 0 at registry slot 0.
    function _singleAmounts(uint256 amount) internal pure returns (uint256[10] memory a) {
        a[0] = amount;
    }

    function _singleRegistry() internal pure returns (uint32[10] memory r) {
        r[0] = 0;
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
            channelFundAmounts: _singleAmounts(75),
            tokenRegistry: _singleRegistry(),
            tokenCount: 1,
            channelFundIntmaxStateRoot: keccak256("intmax_root"),
            burnTxHash: keccak256("burn_tx"),
            closeWithdrawalDigest: keccak256("burn_backed_close"),
            snapshotMediumBlockNumber: 77,
            finalStateVersion: finalStateVersion,
            finalSettledTxChain: keccak256("settled_tx_chain"),
            finalSettledTxAccumulatorRoot: keccak256("settled_tx_accumulator_root")
        });
    }

    /// @dev Build a close `MleVerifier.MleProof` for the default manager whose `publicInputs` equal
    /// the EXACT 87 expected close limbs the manager's `_runCloseVerify` rebinds (channelId =
    /// CHANNEL_ID, the channel's registered member-set commitment, and the packed member/delegate
    /// counts). With the mock MLE verifier returning `true`, this is an ACCEPTING close proof.
    function _closeProof(
        ChannelSettlementManager.CloseIntent memory intent
    ) internal view returns (MleVerifier.MleProof memory) {
        // F4/F7 + delegate account: the close proof binds the channel's registered member-set
        // commitment (limbs 85..92) AND the packed member/delegate counts (limbs 93,94; 103 limbs
        // total incl. the multi-token tokenFundsDigest at 95..102).
        return this._closeProofCd(
            intent,
            manager.registeredMemberSetCommitment(),
            manager.activeMemberCount(),
            uint32(manager.activeDelegateCount())
        );
    }

    /// B-2 (doc/tasks/b2-delegate-close-threat-model.md §4d): build a close proof whose PI limb 94
    /// (`delegateCount`) is an EXPLICIT value instead of the manager's registered count. The
    /// registered count is only a FLOOR now: a proof carrying a LARGER count is legitimate (a
    /// delegate joined after the manager was deployed — the normal case under Option B), a SMALLER
    /// one must be rejected.
    function _closeProofWithDelegateCount(
        ChannelSettlementManager.CloseIntent memory intent,
        uint32 delegateCount
    ) internal view returns (MleVerifier.MleProof memory) {
        return this._closeProofCd(
            intent,
            manager.registeredMemberSetCommitment(),
            manager.activeMemberCount(),
            delegateCount
        );
    }

    /// @dev Build the close proof. External so `intent` is read from CALLDATA — building the
    /// 16-field `CloseProofFields` from a calldata struct (not a memory one) keeps the construction
    /// within the via-IR stack budget, mirroring the manager's `_runCloseVerify`. `channelId` is the
    /// fixed `CHANNEL_ID`; the member-set commitment and packed member/delegate count vary per
    /// channel, so they are passed in. The proof's `publicInputs` are the verifier's own
    /// `expectedCloseLimbs(fields)` — exactly what `_bindCloseLimbsStrict` requires.
    function _closeProofCd(
        ChannelSettlementManager.CloseIntent calldata intent,
        bytes32 memberSetCommitment,
        uint8 memberCount,
        uint32 delegateCount
    ) external view returns (MleVerifier.MleProof memory) {
        uint256[] memory limbs = verifier.expectedCloseLimbs(CloseProofFields({
            channelId: CHANNEL_ID,
            closeNonce: intent.closeNonce,
            finalEpoch: intent.finalEpoch,
            finalSmallBlockNumber: intent.finalSmallBlockNumber,
            closeFreezeNonce: intent.closeFreezeNonce,
            finalChannelStateDigest: intent.finalChannelStateDigest,
            finalBalanceStateH1: intent.finalBalanceStateH1,
            channelFundAmounts: intent.channelFundAmounts,
            tokenRegistry: intent.tokenRegistry,
            tokenCount: intent.tokenCount,
            channelFundIntmaxStateRoot: intent.channelFundIntmaxStateRoot,
            burnTxHash: intent.burnTxHash,
            closeWithdrawalDigest: intent.closeWithdrawalDigest,
            snapshotMediumBlockNumber: intent.snapshotMediumBlockNumber,
            finalStateVersion: intent.finalStateVersion,
            finalSettledTxChain: intent.finalSettledTxChain,
            finalSettledTxAccumulatorRoot: intent.finalSettledTxAccumulatorRoot,
            memberSetCommitment: memberSetCommitment,
            memberCount: memberCount,
            // B-2: `minDelegateCount` feeds only the FLOOR predicate; the limb-94 VALUE written into
            // the vector is the explicit second argument.
            minDelegateCount: delegateCount
        }), delegateCount);
        return CloseTestLib.proofWithLimbs(limbs);
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
            tokenSlot: 0,
            tokenIndex: 0,
            withdrawalNullifier: keccak256(
                abi.encodePacked("withdraw", closeIntentDigest, memberPkG)
            )
        });
    }

    function test_hash_helpers_are_stable() external view {
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        // The close proof now carries the 103 raw close limbs as its MLE publicInputs (not a keccak).
        MleVerifier.MleProof memory closeProof = _closeProof(intent);
        assertEq(
            closeProof.publicInputs.length,
            103,
            "close proof carries 103 raw limbs (Stage 3 + multi-token TFD)"
        );
        assertEq(closeProof.publicInputs[0], uint256(uint32(CHANNEL_ID)), "limb[0] == channelId");

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

        // Phase B-D: the withdrawal-claim / post-close-claim PIs are now RAW limb vectors (48 / 40),
        // not keccak hashes. Assert the introspection builders produce the right lengths.
        assertEq(
            verifier.expectedWithdrawalClaimLimbs(
                CHANNEL_ID,
                keccak256("close"),
                keccak256("root"),
                USER_A,
                alice,
                keccak256("amount"),
                9,
                0, // tokenSlot
                0, // tokenIndex
                keccak256("nullifier")
            ).length,
            50,
            "withdrawal-claim PI is 50 raw limbs (multi-token)"
        );

        assertEq(
            verifier.expectedCancelCloseLimbs(
                CHANNEL_ID,
                keccak256("close"),
                keccak256("member_set"),
                9,
                keccak256("revived_state")
            ).length,
            27,
            "cancel-close PI is 27 raw limbs"
        );

        assertEq(
            verifier.expectedPostCloseClaimLimbs(
                CHANNEL_ID,
                keccak256("close"),
                keccak256("incoming"),
                USER_B,
                bob,
                keccak256("shared_nullifier"),
                9,
                keccak256("final_balance_state_h1"),
                keccak256("settled_tx_accumulator_root"),
                0
            ).length,
            57,
            "post-close-claim PI is 57 raw limbs (Stage 3 + TM-16 tokenIndex)"
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
            // Multi-token: the shared-vector amounts sit at slot 0 (single-token embedding, exactly
            // the Rust `ChannelFund::single_token_amounts`); slots 1..9 hash as zero words.
            channelFundAmounts: _singleAmounts(
                0x0000001100000012000000130000001400000015000000160000001700000018
            ),
            tokenRegistry: _singleRegistry(),
            tokenCount: 1,
            channelFundIntmaxStateRoot: 0x000000190000001a0000001b0000001c0000001d0000001e0000001f00000020,
            burnTxHash: 0x0000002100000022000000230000002400000025000000260000002700000028,
            closeWithdrawalDigest: 0x000000290000002a0000002b0000002c0000002d0000002e0000002f00000030,
            snapshotMediumBlockNumber: 0x99999999aaaaaaaa,
            finalStateVersion: 0xbbbbbbbbcccccccc,
            finalSettledTxChain: 0x0000003100000032000000330000003400000035000000360000003700000038,
            // Stage 3: the accumulator root is NOT part of the IMCI close-intent digest preimage
            // (the digest predates Stage 3), so its value here does not affect the shared vector.
            finalSettledTxAccumulatorRoot: keccak256("settled_tx_accumulator_root")
        });
        assertEq(manager.computeCloseIntentDigest(intent), SHARED_VECTOR_DIGEST);
    }

    /// @dev sentinel bytes32 = the 8 consecutive big-endian u32 words [tag, tag+1, …, tag+7], the
    /// SAME `b32(tag)` helper the Rust golden test uses.
    function _sentinelB32(uint32 tag) internal pure returns (bytes32 r) {
        for (uint256 i = 0; i < 8; i++) {
            r = bytes32((uint256(r) << 32) | uint256(tag + uint32(i)));
        }
    }

    /// GOLDEN VECTOR (Phase A, close-verifier-a1-plan §R2 / §S2): pin the EXACT limb LAYOUT of
    /// `ChannelSettlementVerifier._expectedCloseLimbs` against the Rust
    /// `ChannelClosePublicInputs::to_u64_vec()` order. The Rust mirror
    /// (`src/circuits/channel/close_pis.rs::close_public_inputs_match_solidity_shared_vector`) uses
    /// the IDENTICAL per-field sentinels, so any drift in either builder fails one of the two tests.
    ///
    /// The `closeIntentDigest` (limbs 57..64) is NOT a `CloseProofFields` member — Solidity
    /// RECOMPUTES it, so this test asserts those 8 limbs equal the split of the recomputed digest
    /// (the value is pinned cross-language by `test_close_intent_digest_matches_rust_shared_vector`),
    /// while every OTHER field is asserted against the shared sentinel.
    function test_expectedCloseLimbs_goldenVector() external view {
        // Multi-token: TWO active tokens so the TFD recompute is exercised beyond the genesis
        // embedding. amounts[0] carries the legacy 0x3000 sentinel (limbs 25..32 must equal it).
        uint256[10] memory amounts;
        amounts[0] = uint256(_sentinelB32(0x3000));
        amounts[1] = uint256(_sentinelB32(0xa000));
        uint32[10] memory tokenRegistry;
        tokenRegistry[0] = 0;
        tokenRegistry[1] = 55;
        CloseProofFields memory fields = CloseProofFields({
            channelId: bytes4(uint32(0x0a0b0c0d)),
            closeNonce: 0x0000001100000022,
            finalEpoch: 0x0000003300000044,
            finalSmallBlockNumber: 0x0000005500000066,
            closeFreezeNonce: 0x0000007700000088,
            finalChannelStateDigest: _sentinelB32(0x1000),
            finalBalanceStateH1: _sentinelB32(0x2000),
            channelFundAmounts: amounts,
            tokenRegistry: tokenRegistry,
            tokenCount: 2,
            channelFundIntmaxStateRoot: _sentinelB32(0x4000),
            burnTxHash: _sentinelB32(0x5000),
            closeWithdrawalDigest: _sentinelB32(0x6000),
            // (0x99 hi, 0xaa lo) — matches the Rust sentinel 0x0000_0099_0000_00aa.
            snapshotMediumBlockNumber: (uint64(0x99) << 32) | uint64(0xaa),
            // (0xbb hi, 0xcc lo).
            finalStateVersion: (uint64(0xbb) << 32) | uint64(0xcc),
            finalSettledTxChain: _sentinelB32(0x8000),
            finalSettledTxAccumulatorRoot: _sentinelB32(0x8800),
            memberSetCommitment: _sentinelB32(0x9000),
            memberCount: 3,
            // B-2: the FLOOR. The laid-out limb-94 value is the explicit argument to
            // `_expectedCloseLimbsExt` below (here 1, matching the Rust shared vector's
            // `delegate_count = 1` so the cross-language layout pin is unchanged).
            minDelegateCount: 1
        });

        uint256[] memory v = this._expectedCloseLimbsExt(fields, 1);
        assertEq(v.length, 103, "103 limbs (Stage 3 accumulator root + multi-token TFD)");
        // channelId — limb 0.
        assertEq(v[0], 0x0a0b0c0d);
        // close_nonce — 1..2.
        assertEq(v[1], 0x11); assertEq(v[2], 0x22);
        // final_epoch — 3..4.
        assertEq(v[3], 0x33); assertEq(v[4], 0x44);
        // final_small_block_number — 5..6.
        assertEq(v[5], 0x55); assertEq(v[6], 0x66);
        // close_freeze_nonce — 7..8.
        assertEq(v[7], 0x77); assertEq(v[8], 0x88);
        _assertSentinelRange(v, 9, 0x1000);  // final_channel_state_digest 9..16
        _assertSentinelRange(v, 17, 0x2000); // final_balance_state_h1 17..24
        _assertSentinelRange(v, 25, 0x3000); // channel_fund_amount 25..32
        _assertSentinelRange(v, 33, 0x4000); // channel_fund_intmax_state_root 33..40
        _assertSentinelRange(v, 41, 0x5000); // burn_tx_hash 41..48
        _assertSentinelRange(v, 49, 0x6000); // close_withdrawal_digest 49..56
        // close_intent_digest 57..64 — RECOMPUTED; assert == split of the IMCI digest. We recompute
        // the SAME inner keccak the verifier's `_closeIntentDigest` uses (IMCI domain 0x494d4349 +
        // the close-intent fields incl. the second channelId from the fund snapshot and the
        // finalStateVersion / finalSettledTxChain tail).
        bytes32 digest = keccak256(
            abi.encodePacked(
                abi.encodePacked(
                    bytes4(uint32(0x494d4349)),
                    fields.channelId,
                    fields.closeNonce,
                    fields.finalEpoch,
                    fields.finalSmallBlockNumber,
                    fields.closeFreezeNonce,
                    fields.finalChannelStateDigest,
                    fields.finalBalanceStateH1,
                    fields.channelId
                ),
                // Multi-token: the FULL 80-word amounts vector (10 x 32 BE bytes) in the IMCI
                // preimage — an independent second encoding of the widened segment.
                abi.encodePacked(fields.channelFundAmounts),
                abi.encodePacked(
                    fields.channelFundIntmaxStateRoot,
                    fields.burnTxHash,
                    fields.closeWithdrawalDigest,
                    fields.snapshotMediumBlockNumber,
                    fields.finalStateVersion,
                    fields.finalSettledTxChain
                )
            )
        );
        for (uint256 i = 0; i < 8; i++) {
            assertEq(v[57 + i], (uint256(digest) >> (32 * (7 - i))) & 0xffffffff, "imci limb");
        }
        // snapshot_medium_block_number — 65..66.
        assertEq(v[65], 0x99); assertEq(v[66], 0xaa);
        // final_state_version — 67..68.
        assertEq(v[67], 0xbb); assertEq(v[68], 0xcc);
        _assertSentinelRange(v, 69, 0x8000); // final_settled_tx_chain 69..76
        // Stage 3: final_settled_tx_accumulator_root 77..84 (inserted), shifting the rest +8.
        _assertSentinelRange(v, 77, 0x8800);
        _assertSentinelRange(v, 85, 0x9000); // member_set_commitment 85..92
        // member_count — 93; delegate_count — 94.
        // B-2: limb 93 is still laid out from `fields.memberCount` (STRICT-bound to the channel's
        // registered `activeMemberCount` — never relaxed, A-6). Limb 94 is now laid out from the
        // EXPLICIT `delegateCount` argument (the value `verifyCloseIntent` takes from the proof
        // AFTER the floor/ceiling predicate), not from `fields.minDelegateCount`. The values here
        // (3, 1) still match the Rust shared vector, so the cross-language layout pin is intact.
        assertEq(v[93], 3); assertEq(v[94], 1);
        // Multi-token (§N-6, TM-11): tokenFundsDigest 95..102 — RECOMPUTED over the supplied
        // (registry, count, amounts); assert the limbs equal the split of the public recompute.
        bytes32 tfd = verifier.tokenFundsDigest(
            fields.tokenRegistry, fields.tokenCount, fields.channelFundAmounts
        );
        for (uint256 i = 0; i < 8; i++) {
            assertEq(v[95 + i], (uint256(tfd) >> (32 * (7 - i))) & 0xffffffff, "tfd limb");
        }
    }

    /// @dev external passthroughs so `fields` is read from calldata (the verifier's
    /// `_expectedCloseLimbs` / `_closeIntentDigest` take `calldata`).
    function _expectedCloseLimbsExt(CloseProofFields calldata fields, uint32 delegateCount)
        external view returns (uint256[] memory)
    {
        return verifier.expectedCloseLimbs(fields, delegateCount);
    }

    /// B-2 LAYOUT REGRESSION GUARD: limb 94 must follow the EXPLICIT (validated) delegate-count
    /// argument, and limb 93 must NOT — limb 93 stays sourced from `fields.memberCount`, the
    /// L1-rooted half of the member/delegate boundary (A-6). Asserted with a `delegateCount`
    /// deliberately different from `fields.minDelegateCount` so a regression that re-derived limb 94
    /// from the struct field (i.e. silently restored the old strict equality) fails here.
    function test_expectedCloseLimbs_limb94FollowsValidatedArgument() external view {
        uint256[10] memory amounts;
        amounts[0] = 1 ether;
        uint32[10] memory tokenRegistry;
        CloseProofFields memory fields = CloseProofFields({
            channelId: CHANNEL_ID,
            closeNonce: 1,
            finalEpoch: 2,
            finalSmallBlockNumber: 3,
            closeFreezeNonce: 4,
            finalChannelStateDigest: keccak256("d"),
            finalBalanceStateH1: keccak256("h1"),
            channelFundAmounts: amounts,
            tokenRegistry: tokenRegistry,
            tokenCount: 1,
            channelFundIntmaxStateRoot: keccak256("r"),
            burnTxHash: keccak256("b"),
            closeWithdrawalDigest: keccak256("w"),
            snapshotMediumBlockNumber: 5,
            finalStateVersion: 6,
            finalSettledTxChain: keccak256("c"),
            finalSettledTxAccumulatorRoot: keccak256("a"),
            memberSetCommitment: keccak256("m"),
            memberCount: 3,
            minDelegateCount: 1
        });
        uint256[] memory v = this._expectedCloseLimbsExt(fields, 7);
        assertEq(v[93], 3, "limb 93 = fields.memberCount (STRICT, A-6)");
        assertEq(v[94], 7, "limb 94 = the validated argument, NOT fields.minDelegateCount");
        // And a count far above the old uint8 packing width is representable at all (A-10).
        uint256[] memory v2 = this._expectedCloseLimbsExt(fields, 1000);
        assertEq(v2[94], 1000, "delegate counts > 255 are representable");
    }

    function _assertSentinelRange(uint256[] memory v, uint256 start, uint32 tag) internal pure {
        for (uint256 i = 0; i < 8; i++) {
            assertEq(v[start + i], uint256(tag + uint32(i)), "sentinel limb");
        }
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
            0, // delegate_count (Phase 1: member-only)
            CHALLENGE_PERIOD,
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)),
            IChannelRegistry(address(registry)),
            b,
            new ChannelSettlementManager.MemberBinding[](0) // no delegates
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
            0, // delegate_count (Phase 1: member-only)
            CHALLENGE_PERIOD,
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)),
            reg,
            b,
            new ChannelSettlementManager.MemberBinding[](0) // no delegates
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
        MleVerifier.MleProof memory proof = _closeProof(intent);
        vm.expectRevert(ChannelSettlementManager.CloseNotRequested.selector);
        manager.submitCloseIntent(intent, proof);
    }

    function test_submit_close_intent_grace_period_boundary() external {
        vm.prank(alice);
        manager.requestClose();
        uint256 requestedAt = block.timestamp;

        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        MleVerifier.MleProof memory proof = _closeProof(intent);

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
        MleVerifier.MleProof memory lowerProof = _closeProof(lower);
        vm.expectRevert(ChannelSettlementManager.CloseNotNewer.selector);
        manager.submitCloseIntent(lower, lowerProof);

        // Same epoch, equal version: rejected (strict tiebreak).
        ChannelSettlementManager.CloseIntent memory equalVersion =
            _intentWithVersion(3, 9, 24, 1, 6);
        MleVerifier.MleProof memory equalProof = _closeProof(equalVersion);
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
        // Build a VALID proof for the REAL intent (publicInputs == expected limbs for `intent`).
        MleVerifier.MleProof memory proof = _closeProof(intent);
        bytes32 originalChain = intent.finalSettledTxChain;
        uint64 originalVersion = intent.finalStateVersion;

        // SECURITY (Phase A behavior): submitting a TAMPERED intent with the proof built for the
        // ORIGINAL intent changes the expected limb vector the manager rebuilds in `_runCloseVerify`,
        // so the proof's `publicInputs` no longer match. The verifier's `_bindCloseLimbsStrict`
        // REVERTS with "close limb mismatch". That revert happens INSIDE `verifyCloseIntent`, so it
        // propagates RAW — it is NOT caught and re-wrapped as `InvalidCloseProof` (the manager only
        // wraps a `false` RETURN, not a revert). We assert the exact propagated string.
        intent.finalSettledTxChain = keccak256("forged_chain");
        vm.expectRevert(bytes("close limb mismatch"));
        manager.submitCloseIntent(intent, proof);
        intent.finalSettledTxChain = originalChain;

        // Tampering with finalStateVersion must fail too (same raw revert).
        intent.finalStateVersion = originalVersion + 1;
        vm.expectRevert(bytes("close limb mismatch"));
        manager.submitCloseIntent(intent, proof);
        intent.finalStateVersion = originalVersion;

        // The untampered intent still goes through.
        manager.submitCloseIntent(intent, proof);
    }

    /// @notice B-3: these lifecycle tests wire a CONTROLLABLE mock MLE verifier (verdict=true) so
    ///         they exercise the manager's member/version/limb binding, not the WHIR cryptography.
    ///         This negative flips the mock to REJECT and asserts the manager actually GATES on the
    ///         MLE verdict: a close whose proof does not verify is wrapped as `InvalidCloseProof`
    ///         and cannot be committed. Without this, the whole suite could pass even if the manager
    ///         never consulted the verifier. (Real proof-soundness lives in `CloseLifecycleE2E`.)
    function test_close_rejected_when_mle_verdict_false() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        MleVerifier.MleProof memory proof = _closeProof(intent);

        // MLE verifier says the proof is INVALID → the manager must refuse the close.
        mockMle.setVerdict(false);
        vm.expectRevert(ChannelSettlementManager.InvalidCloseProof.selector);
        manager.submitCloseIntent(intent, proof);

        // Restore the accepting verdict: the SAME intent+proof now goes through, proving the
        // rejection above was the MLE verdict and not some other gate (no channel state changed).
        mockMle.setVerdict(true);
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
        // Revived state version (13) > the close's finalStateVersion (12, from `_intent`). The mock
        // MLE verifier returns true; the manager-side binding (closeIntentDigest match + the
        // verifier's strict limb bind to the registered member-set commitment) is what is exercised.
        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager
            .CancelCloseRequest({
                closeIntentDigest: closeIntentDigest,
                revivedStateVersion: 13,
                revivedChannelStateDigest: keccak256("revived_state")
            });
        manager.cancelClose(request, _cancelCloseProof(request));
        assertEq(manager.closeRequestedAt(), 0);

        // Re-closing straight away is barred: the channel is Active again.
        ChannelSettlementManager.CloseIntent memory reclose = _intent(2, 10, 30, 2);
        MleVerifier.MleProof memory recloseProof = _closeProof(reclose);
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
        manager.submitWithdrawalClaim(aliceClaim, _withdrawalClaimProof(aliceClaim));

        ChannelSettlementManager.PostCloseClaim memory postCloseClaim = ChannelSettlementManager
            .PostCloseClaim({
                closeIntentDigest: closeIntentDigest,
                incomingTxHash: keccak256("incoming_tx"),
                receiverPkG: USER_B,
                recipient: bob,
                amount: 5,
                tokenIndex: 0
            });
        manager.submitPostCloseClaim(postCloseClaim, _postCloseClaimProof(postCloseClaim));

        assertEq(manager.withdrawalCredits(0, alice), 30);
        assertEq(manager.withdrawalCredits(0, bob), 5);
    }

    /// Delegate account (Phase 4 / DA4): a DELEGATE is registered for the WITHDRAWAL path (its
    /// pk_g -> recipient binding + presence + payout authorization) but is EXCLUDED from the IMCM
    /// member-set commitment (member-only). After close+finalize the delegate withdraws its
    /// member-attested balance via the SAME WithdrawalClaim a member uses; a stranger pk_g is
    /// rejected. mc=2 (USER_A/B), dc=1 (USER_D -> dave).
    function test_delegate_registered_and_withdraws_after_close() external {
        bytes32 USER_D = keccak256("member_d_pubkey_hash");
        address dave = makeAddr("dave");

        // Fresh registry: register the 2 MEMBERS only (IMCM is member-only).
        MockChannelRegistry reg = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
        bytes32[] memory members = new bytes32[](2);
        members[0] = USER_A;
        members[1] = USER_B;
        reg.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, members);

        ChannelSettlementManager.MemberBinding[] memory mb =
            new ChannelSettlementManager.MemberBinding[](2);
        mb[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: alice});
        mb[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
        ChannelSettlementManager.MemberBinding[] memory db =
            new ChannelSettlementManager.MemberBinding[](1);
        db[0] = ChannelSettlementManager.MemberBinding({pkG: USER_D, recipient: dave});

        ChannelSettlementManager m = new ChannelSettlementManager(
            CHANNEL_ID, BP_MEMBER_SLOT, USER_A, 1, // delegate_count = 1
            CHALLENGE_PERIOD, SPECIAL_CLOSE_PENALTY, INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)), IChannelRegistry(address(reg)), mb, db
        );

        // The delegate is in the withdrawal lookup + payout authorization, NOT in the member set.
        assertEq(uint256(m.activeMemberCount()), 2);
        assertEq(uint256(m.activeDelegateCount()), 1);
        assertEq(m.memberCount(), 2, "registeredMemberPkGs is member-only (delegate excluded)");
        assertTrue(m.registeredMemberIndexPlusOne(USER_D) != 0, "delegate present");
        assertEq(m.registeredRecipientOf(USER_D), dave, "delegate recipient bound");
        assertTrue(m.isMemberRecipient(dave), "delegate recipient can transact");
        // IMCM commits ONLY the 2 members (delegate excluded) — matches the registry.
        assertEq(m.registeredMemberSetCommitment(), reg.channelMemberSetCommitment(uint32(CHANNEL_ID)));

        // Drive the close to Closed.
        vm.prank(alice);
        m.requestClose();
        vm.warp(block.timestamp + GRACE);
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        m.submitCloseIntent(intent, _closeProofFor(m, intent));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        m.finalizeClose();
        bytes32 cid = m.finalizedCloseIntentDigest();

        // The DELEGATE withdraws its member-attested balance (40) — accepted.
        ChannelSettlementManager.WithdrawalClaim memory dClaim =
            _withdrawalClaim(cid, USER_D, dave, 40);
        m.submitWithdrawalClaim(dClaim, _withdrawalClaimProofFor(m, dClaim));
        assertEq(m.withdrawalCredits(0, dave), 40, "delegate withdrawal credited");

        // B-2 (Option B): membership is now PROOF-ENFORCED, not gate-enforced. There is NO on-chain
        // delegate registry to gate a claim against — a claimant's membership is established SOLELY
        // by the withdrawal proof's slot-inclusion against the signed `finalizedBalanceStateH1`. A
        // stranger not in the signed state cannot produce a verifying proof; that ZK slot-inclusion
        // rejection is covered by the Rust circuit tests (`withdrawal_claim` rejects a non-included
        // slot / fake pk). On-chain it surfaces as `InvalidWithdrawalClaimProof`: a claim whose
        // public inputs the verifier does not accept is rejected. Model the stranger with a claim
        // whose proof binds a DIFFERENT (the delegate's) claim — its limbs cannot match, standing in
        // for "no valid slot-inclusion witness exists". Build proof args BEFORE `expectRevert` so the
        // cheatcode targets ONLY the `submitWithdrawalClaim` call.
        bytes32 STRANGER = keccak256("not_in_channel");
        ChannelSettlementManager.WithdrawalClaim memory sClaim =
            _withdrawalClaim(cid, STRANGER, mallory, 1);
        // The stranger's limbs are self-consistent, but a stranger cannot produce a cryptographically
        // valid slot-inclusion proof against the signed state — simulate the ZK verdict = false. The
        // manager rejects with `InvalidWithdrawalClaimProof`. (Reset the verdict afterwards.)
        MleVerifier.MleProof memory sProof = _withdrawalClaimProofFor(m, sClaim);
        mockMle.setVerdict(false);
        vm.expectRevert(ChannelSettlementManager.InvalidWithdrawalClaimProof.selector);
        m.submitWithdrawalClaim(sClaim, sProof);
        mockMle.setVerdict(true);
    }

    /// Delegate account: a delegate pk_g that collides with a MEMBER pk_g is rejected at
    /// construction (no shared-key claim across the active set).
    function test_delegate_pkg_collision_with_member_reverts() external {
        MockChannelRegistry reg = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
        bytes32[] memory members = new bytes32[](2);
        members[0] = USER_A;
        members[1] = USER_B;
        reg.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, members);

        ChannelSettlementManager.MemberBinding[] memory mb =
            new ChannelSettlementManager.MemberBinding[](2);
        mb[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: alice});
        mb[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
        ChannelSettlementManager.MemberBinding[] memory db =
            new ChannelSettlementManager.MemberBinding[](1);
        db[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: makeAddr("dave")}); // collides with member 0

        vm.expectRevert(ChannelSettlementManager.DuplicateRegisteredMember.selector);
        new ChannelSettlementManager(
            CHANNEL_ID, BP_MEMBER_SLOT, USER_A, 1,
            CHALLENGE_PERIOD, SPECIAL_CLOSE_PENALTY, INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)), IChannelRegistry(address(reg)), mb, db
        );
    }

    /// P6-A / detail2 §H-3 (C2): `submitSpecialClose` is permanently DISABLED — any call reverts and
    /// the channel is left untouched (no freeze, no BP slash). It was gated only by a forgeable
    /// `_matches` stub, which let anyone freeze the channel and slash an honest BP (freeze-grief).
    /// SECURITY: this asserts the intended behavior change, not a workaround — the disposition is to
    /// disable the entry point until a sound cross-layer non-inclusion commitment exists.
    function test_special_close_disabled_reverts() external {
        ChannelSettlementManager.SpecialClose memory specialClose = ChannelSettlementManager
            .SpecialClose({
                offendingBpMemberSlot: BP_MEMBER_SLOT,
                offendingBpPkG: USER_A,
                fullySignedSmallBlockRoot: keccak256("small_block_root"),
                smallBlockNumber: 33,
                signedMediumBlockNumber: 10,
                latestFinalizedMediumBlockNumber: 15
            });

        // Even with a "valid" stub proof, the entry point is disabled and reverts.
        vm.expectRevert(ChannelSettlementManager.SpecialCloseDisabled.selector);
        manager.submitSpecialClose(specialClose, hex"");

        // The channel is untouched: still Active, no freeze, no BP slash, no caller credit.
        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.Active)
        );
        assertEq(manager.currentCloseFreezeNonce(), 0);
        assertEq(manager.bpBondCredits(), INITIAL_BP_BOND);
        assertEq(manager.withdrawalCredits(0, address(this)), 0);
    }

    function test_cancel_close_restores_active_channel() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        _submitClose(intent);

        bytes32 closeIntentDigest = manager.computeCloseIntentDigest(intent);
        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager
            .CancelCloseRequest({
                closeIntentDigest: closeIntentDigest,
                revivedStateVersion: 13,
                revivedChannelStateDigest: keccak256("revived_state")
            });

        manager.cancelClose(request, _cancelCloseProof(request));

        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.Active)
        );
        assertEq(manager.currentCloseFreezeNonce(), 1);
        assertEq(manager.closeRequestedAt(), 0);
        assertTrue(manager.isNativeSendAllowed(1));
    }

    /// Finding D (member binding): a cancel proof whose `memberSetCommitment` limbs do NOT equal the
    /// channel's REGISTERED member set is rejected. The manager injects
    /// `registeredMemberSetCommitment()`; a proof built over a different commitment fails the
    /// verifier's strict limb bind (revert inside `verifyCancelClose`), so the close survives.
    function test_cancel_close_rejects_non_registered_member_set() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        _submitClose(intent);

        bytes32 closeIntentDigest = manager.computeCloseIntentDigest(intent);
        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager
            .CancelCloseRequest({
                closeIntentDigest: closeIntentDigest,
                revivedStateVersion: 13,
                revivedChannelStateDigest: keccak256("revived_state")
            });
        // Build a proof over an ATTACKER member-set commitment (not the registered one). The manager
        // injects the registered commitment into the expected vector, so the strict limb bind sees a
        // mismatch at the memberSetCommitment limbs and reverts.
        uint256[] memory forgedLimbs = verifier.expectedCancelCloseLimbs(
            CHANNEL_ID,
            closeIntentDigest,
            keccak256("attacker_member_set"),
            request.revivedStateVersion,
            request.revivedChannelStateDigest
        );
        MleVerifier.MleProof memory forged = CloseTestLib.proofWithLimbs(forgedLimbs);
        vm.expectRevert(bytes("claim limb mismatch"));
        manager.cancelClose(request, forged);

        // The pending close is untouched.
        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
        );
    }

    /// A cancel whose proof claims a different close intent digest than the pending close is rejected
    /// (manager guard), and a crypto-invalid proof (mock verdict=false) reverts InvalidCancelProof.
    function test_cancel_close_rejects_wrong_close_and_invalid_proof() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
        _submitClose(intent);

        bytes32 closeIntentDigest = manager.computeCloseIntentDigest(intent);
        ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager
            .CancelCloseRequest({
                closeIntentDigest: closeIntentDigest,
                revivedStateVersion: 13,
                revivedChannelStateDigest: keccak256("revived_state")
            });

        // Precompute the proof so the expectRevert arms on the cancelClose call itself (not on the
        // external view calls inside `_cancelCloseProof`).
        MleVerifier.MleProof memory validProof = _cancelCloseProof(request);

        // Wrong close intent digest → manager guard. (Fresh struct: `= request` would ALIAS the
        // memory reference and mutate `request`.)
        ChannelSettlementManager.CancelCloseRequest memory wrong = ChannelSettlementManager
            .CancelCloseRequest({
                closeIntentDigest: keccak256("not_the_pending_close"),
                revivedStateVersion: request.revivedStateVersion,
                revivedChannelStateDigest: request.revivedChannelStateDigest
            });
        vm.expectRevert(ChannelSettlementManager.CloseIntentDigestMismatch.selector);
        manager.cancelClose(wrong, validProof);

        // Crypto-invalid proof (limbs correct, but MLE verdict=false) → InvalidCancelProof.
        mockMle.setVerdict(false);
        vm.expectRevert(ChannelSettlementManager.InvalidCancelProof.selector);
        manager.cancelClose(request, validProof);
        mockMle.setVerdict(true);
    }

    /// P6-A / detail2 §H-3 (C3): `submitLateOutgoingDebitCorrection` is permanently DISABLED
    /// (redundant — double-pay is prevented by the in-circuit nullifier used-sets, stale closes by
    /// cancelClose). A call reverts and the pending close is left untouched (still ClosePending).
    function test_late_outgoing_debit_correction_disabled_reverts() external {
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

        vm.expectRevert(ChannelSettlementManager.LateOutgoingDebitDisabled.selector);
        manager.submitLateOutgoingDebitCorrection(correction, hex"");

        // The pending close is untouched — it survives the (disabled) correction attempt.
        assertEq(
            uint256(manager.channelStatus()),
            uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
        );
        assertEq(manager.currentCloseFreezeNonce(), 1);
    }

    /// P6-A: disabling special close does not break the normal member-driven close path.
    function test_normal_close_still_finalizes_after_special_close_disabled() external {
        ChannelSettlementManager.SpecialClose memory specialClose = ChannelSettlementManager
            .SpecialClose({
                offendingBpMemberSlot: BP_MEMBER_SLOT,
                offendingBpPkG: USER_A,
                fullySignedSmallBlockRoot: keccak256("small_block_root"),
                smallBlockNumber: 33,
                signedMediumBlockNumber: 10,
                latestFinalizedMediumBlockNumber: 15
            });
        vm.expectRevert(ChannelSettlementManager.SpecialCloseDisabled.selector);
        manager.submitSpecialClose(specialClose, hex"");

        // The honest close lifecycle (request → grace → submit → finalize) still works.
        _requestCloseAndElapseGrace(); // bumps currentCloseFreezeNonce to 1
        ChannelSettlementManager.CloseIntent memory intent = _intent(2, 10, 40, 1);
        _submitClose(intent);

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
        manager.submitWithdrawalClaim(c, _withdrawalClaimProof(c));
    }

    /// Simulate the rollup paying this manager via a finalized native withdrawal, then pull it in.
    function _fundAndPull(MockChannelRegistry reg, ChannelSettlementManager m, uint256 amount) internal {
        vm.deal(address(this), address(this).balance + amount);
        reg.creditWithdrawal{value: amount}(address(m));
        m.pullChannelFunds();
    }

    function _closeProofFor(ChannelSettlementManager m, ChannelSettlementManager.CloseIntent memory intent)
        internal view returns (MleVerifier.MleProof memory)
    {
        // Same calldata-reentry as `_closeProof` (via-IR stack budget): `_closeProofCd` reads the
        // intent from calldata and uses CHANNEL_ID; the per-channel commitment + packed counts come
        // from the supplied manager `m`. All these managers are bound to the shared `verifier`, so
        // `expectedCloseLimbs` (called inside `_closeProofCd`) uses CHANNEL_ID — the same channelId
        // every manager in this suite uses.
        return this._closeProofCd(
            intent,
            m.registeredMemberSetCommitment(),
            m.activeMemberCount(),
            uint32(m.activeDelegateCount())
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
            CHANNEL_ID, BP_MEMBER_SLOT, USER_A, 0, CHALLENGE_PERIOD, SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND, IChannelSettlementVerifier(address(verifier)), IChannelRegistry(address(reg)), b,
            new ChannelSettlementManager.MemberBinding[](0) // no delegates
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
        assertEq(manager.receivedChannelFunds(0), 60, "receivedChannelFunds == pulled");
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
        assertEq(manager.withdrawalCredits(0, alice), 0, "credit cleared");
        assertEq(manager.totalCreditedOut(0), 30, "paid-out accumulator");

        vm.prank(bob);
        manager.claimWithdrawalCredit();
        assertEq(bob.balance, 20, "bob received real ETH");
        assertEq(manager.totalCreditedOut(0), 50, "total paid out");
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
            amount: 10, // 70 + 10 = 80 > 75 -> must revert
            tokenIndex: 0
        });
        // Precompute the proof BEFORE expectRevert: vm.expectRevert applies to the next external
        // call, which would otherwise be the view calls that assemble the proof.
        MleVerifier.MleProof memory proof = _postCloseClaimProof(pc);
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
        m.submitWithdrawalClaim(c, _withdrawalClaimProofFor(m, c));

        vm.deal(address(this), address(this).balance + 75);
        reg.creditWithdrawal{value: 75}(address(m));
        m.pullChannelFunds();

        // attacker re-enters during the payout → inner call reverts (Reentrant) → outer reverts.
        vm.expectRevert();
        attacker.claim();

        assertEq(m.withdrawalCredits(0, address(attacker)), 30, "credit preserved (no double-pay)");
        assertEq(m.totalCreditedOut(0), 0, "nothing paid out");
        assertEq(address(attacker).balance, 0, "no ETH drained");
    }

    // -----------------------------------------------------------------------
    // Phase A — direct verifier negative tests (close-verifier-a1-plan §T2)
    //
    // These call `verifier.verifyCloseIntent(fields, proof)` directly (the verifier is mock-MLE-
    // backed in this suite, so a VALID 103-limb proof passes the crypto step) to isolate the binding
    // and VK-management failure modes. The cross-circuit-replay negative (a validity/withdrawal MLE
    // proof rejected by the REAL MleVerifier on circuitDigest / gatesDigest) lives in the real-MLE
    // CloseLifecycleE2E suite, where the genuine verifier runs.
    // -----------------------------------------------------------------------

    /// @dev Canonical CloseProofFields for the registered channel (channelId / commitment / counts
    /// match `manager`), with arbitrary-but-fixed close-intent values. `calldata` external so the
    /// 16-field struct is built once and reused.
    function _validCloseFields() external view returns (CloseProofFields memory f) {
        f = CloseProofFields({
            channelId: CHANNEL_ID,
            closeNonce: 1,
            finalEpoch: 9,
            finalSmallBlockNumber: 22,
            closeFreezeNonce: 1,
            finalChannelStateDigest: keccak256("fcsd"),
            finalBalanceStateH1: keccak256("h1"),
            channelFundAmounts: _singleAmounts(123),
            tokenRegistry: _singleRegistry(),
            tokenCount: 1,
            channelFundIntmaxStateRoot: keccak256("isr"),
            burnTxHash: keccak256("burn"),
            closeWithdrawalDigest: keccak256("cwd"),
            snapshotMediumBlockNumber: 77,
            finalStateVersion: 12,
            finalSettledTxChain: keccak256("chain"),
            finalSettledTxAccumulatorRoot: keccak256("settled_tx_accumulator_root"),
            memberSetCommitment: manager.registeredMemberSetCommitment(),
            memberCount: manager.activeMemberCount(),
            minDelegateCount: uint32(manager.activeDelegateCount())
        });
    }

    /// Build a proof whose limb 94 sits exactly AT the floor (`f.minDelegateCount`) — the baseline
    /// for the direct-verifier negatives below.
    function _proofForFields(CloseProofFields memory f)
        internal view returns (MleVerifier.MleProof memory)
    {
        return CloseTestLib.proofWithLimbs(this._expectedCloseLimbsExt(f, f.minDelegateCount));
    }

    /// B-2: same, with an EXPLICIT limb-94 value (may be above or below the floor).
    function _proofForFieldsWithDc(CloseProofFields memory f, uint32 dc)
        internal view returns (MleVerifier.MleProof memory)
    {
        return CloseTestLib.proofWithLimbs(this._expectedCloseLimbsExt(f, dc));
    }

    /// Positive control: a valid 103-limb proof for valid fields passes (mock verdict = true).
    function test_verifyClose_validProof_passes() external {
        CloseProofFields memory f = this._validCloseFields();
        assertTrue(verifier.verifyCloseIntent(f, _proofForFields(f)));
    }

    /// Forged memberSetCommitment (e.g. non-member keys) ⇒ limbs 85..92 differ ⇒ reverts.
    function test_verifyClose_forgedMemberSetCommitment_reverts() external {
        CloseProofFields memory f = this._validCloseFields();
        MleVerifier.MleProof memory proof = _proofForFields(f); // proof for the REAL commitment
        f.memberSetCommitment = keccak256("non-member keys"); // now expected limbs 77..84 change
        vm.expectRevert(bytes("close limb mismatch"));
        verifier.verifyCloseIntent(f, proof);
    }

    /// Wrong channelId ⇒ limb 0 differs ⇒ reverts.
    function test_verifyClose_wrongChannelId_reverts() external {
        CloseProofFields memory f = this._validCloseFields();
        MleVerifier.MleProof memory proof = _proofForFields(f);
        f.channelId = hex"deadbeef";
        vm.expectRevert(bytes("close limb mismatch"));
        verifier.verifyCloseIntent(f, proof);
    }

    /// publicInputs.length != 103 ⇒ reverts on the length guard.
    function test_verifyClose_wrongLength_reverts() external {
        CloseProofFields memory f = this._validCloseFields();
        uint256[] memory shortPis = new uint256[](102);
        MleVerifier.MleProof memory proof = CloseTestLib.proofWithLimbs(shortPis);
        vm.expectRevert(bytes("close pi len"));
        verifier.verifyCloseIntent(f, proof);
    }

    /// A limb >= 2**32 ⇒ reverts on the canonical-range guard (even if it would "match" mod nothing).
    function test_verifyClose_nonCanonicalLimb_reverts() external {
        CloseProofFields memory f = this._validCloseFields();
        uint256[] memory pis = this._expectedCloseLimbsExt(f, f.minDelegateCount);
        pis[0] = uint256(1) << 32; // 2**32, the smallest non-canonical u32
        MleVerifier.MleProof memory proof = CloseTestLib.proofWithLimbs(pis);
        vm.expectRevert(bytes("close limb range"));
        verifier.verifyCloseIntent(f, proof);
    }

    // =====================================================================
    // B-2 — the delegate-count RANGE bind on close PI limb 94
    // (doc/tasks/b2-delegate-close-threat-model.md §4d, test list §8)
    //
    // What these prove about security, test by test:
    //   * the FLOOR still refuses to exclude an L1-registered delegate from the active region;
    //   * the CEILING still refuses states the claim circuits could not serve (`active > 1024`);
    //   * limb 93 (`memberCount`) was NOT collaterally loosened — the signer-set bind is intact;
    //   * the length + canonicality guards run BEFORE limb 94 is read/used, so the pre-loop read is
    //     never out-of-bounds and never a raw arithmetic panic (A-4 / A-5).
    // =====================================================================

    /// §8.1 POSITIVE (the live case the old strict equality bricked): a close proof whose
    /// `delegateCount` limb is ABOVE the manager's registered count is ACCEPTED. Under Option B, L1
    /// registration is cosigners-only and there is no per-join transaction, so any delegate that
    /// joined after deployment makes the proof's count exceed the registered one.
    function test_verifyClose_delegateCountAboveFloor_accepted() external {
        CloseProofFields memory f = this._validCloseFields();
        assertEq(uint256(f.minDelegateCount), 0, "default manager registers 0 delegates");
        // 1 and 5 post-deploy joiners: both accepted, no upper bound short of the capacity.
        assertTrue(verifier.verifyCloseIntent(f, _proofForFieldsWithDc(f, 1)));
        assertTrue(verifier.verifyCloseIntent(f, _proofForFieldsWithDc(f, 5)));
    }

    /// §8.2 NEGATIVE (floor): `delegateCount < minDelegateCount` ⇒ `CloseDelegateCountOutOfRange`.
    /// SECURITY: this is the one directional property L1 can still assert — `join_delegate` only
    /// ever increments and there is no leave path, so a count BELOW the registered one would push a
    /// registered delegate's slot outside `[0, member_count + delegate_count)` and make its
    /// withdrawal claim unprovable (a targeted freeze-out).
    function test_verifyClose_delegateCountBelowFloor_reverts() external {
        CloseProofFields memory f = this._validCloseFields();
        f.minDelegateCount = 2; // pretend the manager registered 2 delegates
        // NOTE: the proof builders make an external call, so they MUST be evaluated before
        // `vm.expectRevert` is armed — otherwise the expectation binds to the builder call.
        MleVerifier.MleProof memory below = _proofForFieldsWithDc(f, 1);
        MleVerifier.MleProof memory atFloor = _proofForFieldsWithDc(f, 2);
        vm.expectRevert(ChannelSettlementVerifier.CloseDelegateCountOutOfRange.selector);
        verifier.verifyCloseIntent(f, below);
        // Exactly AT the floor is fine (boundary, inclusive).
        assertTrue(verifier.verifyCloseIntent(f, atFloor));
    }

    /// §8.3 NEGATIVE (ceiling): `memberCount + delegateCount > MAX_CHANNEL_PARTICIPANTS (1024)` ⇒
    /// `CloseDelegateCountOutOfRange`. SECURITY: mirrors the in-circuit `active <= 1024` bound the
    /// withdrawal-claim / post-close-claim circuits enforce, so L1 never records a close whose
    /// participant count the claim lane could not serve. Both sides of the boundary are pinned.
    function test_verifyClose_delegateCountAboveCeiling_reverts() external {
        CloseProofFields memory f = this._validCloseFields();
        uint32 mc = uint32(f.memberCount);
        // Builders first (they are external calls; see the note in the floor test).
        MleVerifier.MleProof memory atCap = _proofForFieldsWithDc(f, 1024 - mc);
        MleVerifier.MleProof memory overCap = _proofForFieldsWithDc(f, 1024 - mc + 1);
        MleVerifier.MleProof memory huge = _proofForFieldsWithDc(f, type(uint32).max);
        // active == 1024 exactly: accepted.
        assertTrue(verifier.verifyCloseIntent(f, atCap));
        // active == 1025: rejected.
        vm.expectRevert(ChannelSettlementVerifier.CloseDelegateCountOutOfRange.selector);
        verifier.verifyCloseIntent(f, overCap);
        // A huge-but-CANONICAL limb (2**32 - 1) is rejected by the ceiling, not by an overflow
        // panic — the explicit error is the failure mode (A-5).
        vm.expectRevert(ChannelSettlementVerifier.CloseDelegateCountOutOfRange.selector);
        verifier.verifyCloseIntent(f, huge);
    }

    /// §8.4 NEGATIVE (A-6, the invariant that must NEVER relax): tampering limb 93 (`memberCount`)
    /// still fails with the generic strict-bind error. This proves the member half of the boundary
    /// was not collaterally loosened when the delegate half became a range. If limb 93 ever became
    /// pass-through, a state with a smaller `member_count` could close under fewer than N
    /// signatures (the close circuit gates its signature loop on `i < member_count`).
    function test_verifyClose_tamperedMemberCountLimb_stillStrict() external {
        CloseProofFields memory f = this._validCloseFields();
        MleVerifier.MleProof memory proof = _proofForFields(f); // built for the REAL memberCount
        f.memberCount = f.memberCount + 1; // expected limb 93 moves; the proof's does not
        vm.expectRevert(bytes("close limb mismatch"));
        verifier.verifyCloseIntent(f, proof);

        // …and the symmetric direction: a proof carrying a DIFFERENT limb 93 against the real
        // registered count. Built by hand so only limb 93 moves.
        CloseProofFields memory g = this._validCloseFields();
        uint256[] memory pis = this._expectedCloseLimbsExt(g, g.minDelegateCount);
        pis[93] = pis[93] - 1; // one fewer "member" ⇒ one fewer required signature in-circuit
        vm.expectRevert(bytes("close limb mismatch"));
        verifier.verifyCloseIntent(g, CloseTestLib.proofWithLimbs(pis));
    }

    /// §8.5 ORDERING REGRESSION GUARD (A-4/A-5): the length and canonicality checks MUST run before
    /// limb 94 is read and used. A short vector must revert with the length guard (NOT an
    /// out-of-bounds calldata read), and a non-canonical limb 94 must revert with the range guard
    /// (NOT an arithmetic panic inside the ceiling sum).
    function test_verifyClose_limb94_lengthAndCanonicalityCheckedFirst() external {
        CloseProofFields memory f = this._validCloseFields();

        // (a) 94 limbs — long enough that a naive `pi[94]` read would be out of bounds.
        uint256[] memory shortPis = new uint256[](94);
        vm.expectRevert(bytes("close pi len"));
        verifier.verifyCloseIntent(f, CloseTestLib.proofWithLimbs(shortPis));

        // (b) empty vector — the degenerate case.
        vm.expectRevert(bytes("close pi len"));
        verifier.verifyCloseIntent(f, CloseTestLib.proofWithLimbs(new uint256[](0)));

        // (c) limb 94 == 2**32 (smallest non-canonical) ⇒ the range guard, not the delegate error.
        uint256[] memory pis = this._expectedCloseLimbsExt(f, f.minDelegateCount);
        pis[94] = uint256(1) << 32;
        vm.expectRevert(bytes("close limb range"));
        verifier.verifyCloseIntent(f, CloseTestLib.proofWithLimbs(pis));

        // (d) limb 94 == 2**256-1 ⇒ still the range guard. Without the hoisted canonicality check
        // the ceiling's `memberCount + delegateCount` would be a 0.8 overflow Panic(0x11) here.
        pis[94] = type(uint256).max;
        vm.expectRevert(bytes("close limb range"));
        verifier.verifyCloseIntent(f, CloseTestLib.proofWithLimbs(pis));
    }

    /// §8.1/§8.7 MANAGER-LEVEL POSITIVE + §8.2 MANAGER-LEVEL NEGATIVE, and the full post-deploy-join
    /// lane end to end: a manager deployed with ONE registered delegate accepts a close whose proof
    /// carries TWO delegates (a second browser joined after deployment), finalizes, and the
    /// POST-DEPLOY (unregistered) delegate then collects its member-attested balance. This is
    /// exactly the scenario the former strict equality bricked. A close carrying ZERO delegates
    /// (which would exclude the registered one) is refused.
    function test_b2_postDeployDelegateJoin_closesAndClaims() external {
        bytes32 USER_D = keccak256("delegate_d_pubkey_hash");  // registered at deployment
        bytes32 USER_E = keccak256("delegate_e_pubkey_hash");  // joined AFTER deployment
        address dave = makeAddr("b2_dave");
        address erin = makeAddr("b2_erin");

        MockChannelRegistry reg = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
        bytes32[] memory members = new bytes32[](2);
        members[0] = USER_A;
        members[1] = USER_B;
        reg.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, members);

        ChannelSettlementManager.MemberBinding[] memory mb =
            new ChannelSettlementManager.MemberBinding[](2);
        mb[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: alice});
        mb[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
        ChannelSettlementManager.MemberBinding[] memory db =
            new ChannelSettlementManager.MemberBinding[](1);
        db[0] = ChannelSettlementManager.MemberBinding({pkG: USER_D, recipient: dave});

        ChannelSettlementManager m = new ChannelSettlementManager(
            CHANNEL_ID, BP_MEMBER_SLOT, USER_A, 1, // registered delegate_count = 1 (the FLOOR)
            CHALLENGE_PERIOD, SPECIAL_CLOSE_PENALTY, INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)), IChannelRegistry(address(reg)), mb, db
        );

        vm.prank(alice);
        m.requestClose();
        vm.warp(block.timestamp + GRACE);
        ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);

        // Builders first (external calls; `vm.expectRevert` binds to the NEXT call).
        MleVerifier.MleProof memory excludesDelegate = this._closeProofCd(
            intent, m.registeredMemberSetCommitment(), m.activeMemberCount(), 0
        );
        MleVerifier.MleProof memory withJoiner = this._closeProofCd(
            intent, m.registeredMemberSetCommitment(), m.activeMemberCount(), 2
        );

        // A close carrying delegate_count = 0 would EXCLUDE the registered delegate ⇒ refused.
        // The floor error propagates as a revert out of the manager's `_checkCloseProof`.
        vm.expectRevert(ChannelSettlementVerifier.CloseDelegateCountOutOfRange.selector);
        m.submitCloseIntent(intent, excludesDelegate);

        // delegate_count = 2 (one post-deploy joiner) ⇒ ACCEPTED.
        m.submitCloseIntent(intent, withJoiner);
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        m.finalizeClose();
        bytes32 cid = m.finalizedCloseIntentDigest();

        // Both delegates collect. The POST-DEPLOY one has no constructor binding at all — its
        // authorization is entirely the proof-bound `recipient` claim PI (the claim-side B-2, commit
        // 6d2b9d8, removed the `registeredRecipientOf` gate), which is hashed into the slot leaf
        // in-circuit and so provably equals the cosigner-signed exit address.
        assertTrue(m.registeredMemberIndexPlusOne(USER_E) == 0, "post-deploy joiner is unregistered");
        ChannelSettlementManager.WithdrawalClaim memory dClaim =
            _withdrawalClaim(cid, USER_D, dave, 30);
        m.submitWithdrawalClaim(dClaim, _withdrawalClaimProofFor(m, dClaim));
        ChannelSettlementManager.WithdrawalClaim memory eClaim =
            _withdrawalClaim(cid, USER_E, erin, 20);
        m.submitWithdrawalClaim(eClaim, _withdrawalClaimProofFor(m, eClaim));
        assertEq(m.withdrawalCredits(0, dave), 30, "registered delegate credited");
        assertEq(m.withdrawalCredits(0, erin), 20, "POST-DEPLOY delegate credited (B-2 unblocks)");
    }

    /// The mock verifier returning `false` (crypto-invalid proof) ⇒ verifyCloseIntent returns false
    /// ⇒ the manager wraps it as `InvalidCloseProof`.
    function test_verifyClose_cryptoInvalid_returnsFalse() external {
        CloseProofFields memory f = this._validCloseFields();
        MleVerifier.MleProof memory proof = _proofForFields(f);
        mockMle.setVerdict(false);
        assertTrue(!verifier.verifyCloseIntent(f, proof), "crypto-invalid returns false");
        mockMle.setVerdict(true);
    }

    /// verifyCloseIntent reverts (CloseVkNotSet) on a verifier whose close VK is unset.
    function test_verifyClose_unsetVk_reverts() external {
        ChannelSettlementVerifier fresh = new ChannelSettlementVerifier();
        CloseProofFields memory f = this._validCloseFields();
        MleVerifier.MleProof memory proof = _proofForFields(f);
        vm.expectRevert(ChannelSettlementVerifier.CloseVkNotSet.selector);
        fresh.verifyCloseIntent(f, proof);
    }

    /// initializeCloseVk is deployer-only and set-once, and rejects degreeBits == 0.
    function test_initializeCloseVk_access_setOnce_and_degreeBitsZero() external {
        ChannelSettlementVerifier fresh = new ChannelSettlementVerifier(); // deployer = this test
        (
            ChannelSettlementVerifier.CloseVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        ) = CloseTestLib.dummyVkArgs();

        // degreeBits == 0 is rejected. Build an INDEPENDENT zero-degreeBits VK (no aliasing of `vk`).
        ChannelSettlementVerifier.CloseVk memory zeroVk = ChannelSettlementVerifier.CloseVk({
            degreeBits: 0,
            preprocessedRoot: vk.preprocessedRoot,
            numConstants: vk.numConstants,
            numRoutedWires: vk.numRoutedWires,
            gatesDigest: vk.gatesDigest
        });
        vm.expectRevert(ChannelSettlementVerifier.CloseVkDegreeBitsZero.selector);
        fresh.initializeCloseVk(MleVerifier(address(mockMle)), zeroVk, whir, protocolId, sessionId, kIs, subgroupGenPowers);

        // Non-deployer cannot set.
        vm.prank(address(0xBEEF));
        vm.expectRevert(bytes("only deployer"));
        fresh.initializeCloseVk(MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers);

        // Deployer sets once…
        fresh.initializeCloseVk(MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers);
        assertTrue(fresh.closeVkInitialized());
        // …and cannot set again.
        vm.expectRevert(bytes("close vk already set"));
        fresh.initializeCloseVk(MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers);
    }

    // =====================================================================
    // Phase C1 — cancel-close REAL verification (verifier-level)
    // =====================================================================

    /// @dev Build the 27-limb cancel vector + an accepting MleProof for the given args (member-set
    ///      commitment = the channel's registered set).
    function _cancelLimbs(
        bytes32 closeIntentDigest,
        uint64 revivedStateVersion,
        bytes32 revivedChannelStateDigest
    ) internal view returns (uint256[] memory) {
        return verifier.expectedCancelCloseLimbs(
            CHANNEL_ID,
            closeIntentDigest,
            manager.registeredMemberSetCommitment(),
            revivedStateVersion,
            revivedChannelStateDigest
        );
    }

    /// GOLDEN- vector length + accepting proof: a proof whose publicInputs == expected 27 limbs
    /// passes verifyCancelClose (mock verdict=true).
    function test_verifyCancelClose_validProof_passes() external view {
        uint256[] memory pis = _cancelLimbs(keccak256("close"), 13, keccak256("revived"));
        assertEq(pis.length, 27, "cancel PI is 27 raw limbs");
        MleVerifier.MleProof memory proof = CloseTestLib.proofWithLimbs(pis);
        assertTrue(
            verifier.verifyCancelClose(
                CHANNEL_ID,
                keccak256("close"),
                manager.registeredMemberSetCommitment(),
                13,
                keccak256("revived"),
                proof
            )
        );
    }

    /// A tampered limb (wrong revivedChannelStateDigest in the proof vs the expected) ⇒ reverts.
    function test_verifyCancelClose_tamperedLimb_reverts() external {
        bytes32 msc = manager.registeredMemberSetCommitment();
        uint256[] memory pis = _cancelLimbs(keccak256("close"), 13, keccak256("revived"));
        MleVerifier.MleProof memory proof = CloseTestLib.proofWithLimbs(pis);
        // Expected vector uses a DIFFERENT revived digest than the proof's limbs.
        vm.expectRevert(bytes("claim limb mismatch"));
        verifier.verifyCancelClose(
            CHANNEL_ID, keccak256("close"), msc, 13, keccak256("OTHER_revived"), proof
        );
    }

    /// publicInputs.length != 27 ⇒ reverts on the length guard.
    function test_verifyCancelClose_wrongLength_reverts() external {
        bytes32 msc = manager.registeredMemberSetCommitment();
        uint256[] memory shortPis = new uint256[](26);
        MleVerifier.MleProof memory proof = CloseTestLib.proofWithLimbs(shortPis);
        vm.expectRevert(bytes("claim pi len"));
        verifier.verifyCancelClose(
            CHANNEL_ID, keccak256("close"), msc, 13, keccak256("revived"), proof
        );
    }

    /// A limb >= 2**32 ⇒ reverts on the canonical-range guard.
    function test_verifyCancelClose_nonCanonicalLimb_reverts() external {
        bytes32 msc = manager.registeredMemberSetCommitment();
        uint256[] memory pis = _cancelLimbs(keccak256("close"), 13, keccak256("revived"));
        pis[0] = uint256(1) << 32; // 2**32, smallest non-canonical u32
        MleVerifier.MleProof memory proof = CloseTestLib.proofWithLimbs(pis);
        vm.expectRevert(bytes("claim limb range"));
        verifier.verifyCancelClose(
            CHANNEL_ID, keccak256("close"), msc, 13, keccak256("revived"), proof
        );
    }

    /// The mock verifier returning `false` (crypto-invalid) ⇒ verifyCancelClose returns false.
    function test_verifyCancelClose_cryptoInvalid_returnsFalse() external {
        uint256[] memory pis = _cancelLimbs(keccak256("close"), 13, keccak256("revived"));
        MleVerifier.MleProof memory proof = CloseTestLib.proofWithLimbs(pis);
        mockMle.setVerdict(false);
        assertTrue(
            !verifier.verifyCancelClose(
                CHANNEL_ID,
                keccak256("close"),
                manager.registeredMemberSetCommitment(),
                13,
                keccak256("revived"),
                proof
            ),
            "crypto-invalid returns false"
        );
        mockMle.setVerdict(true);
    }

    /// verifyCancelClose reverts (CancelCloseVkNotSet) on a verifier whose cancel VK is unset.
    function test_verifyCancelClose_unsetVk_reverts() external {
        ChannelSettlementVerifier fresh = new ChannelSettlementVerifier();
        bytes32 msc = manager.registeredMemberSetCommitment();
        uint256[] memory pis = _cancelLimbs(keccak256("close"), 13, keccak256("revived"));
        MleVerifier.MleProof memory proof = CloseTestLib.proofWithLimbs(pis);
        vm.expectRevert(ChannelSettlementVerifier.CancelCloseVkNotSet.selector);
        fresh.verifyCancelClose(
            CHANNEL_ID, keccak256("close"), msc, 13, keccak256("revived"), proof
        );
    }

    /// initializeCancelCloseVk is deployer-only, set-once, rejects degreeBits == 0.
    function test_initializeCancelCloseVk_access_setOnce_and_degreeBitsZero() external {
        ChannelSettlementVerifier fresh = new ChannelSettlementVerifier(); // deployer = this test
        (
            ChannelSettlementVerifier.StatementVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        ) = CloseTestLib.dummyStatementVkArgs();

        ChannelSettlementVerifier.StatementVk memory zeroVk = ChannelSettlementVerifier.StatementVk({
            degreeBits: 0,
            preprocessedRoot: vk.preprocessedRoot,
            numConstants: vk.numConstants,
            numRoutedWires: vk.numRoutedWires,
            gatesDigest: vk.gatesDigest
        });
        vm.expectRevert(ChannelSettlementVerifier.StatementVkDegreeBitsZero.selector);
        fresh.initializeCancelCloseVk(MleVerifier(address(mockMle)), zeroVk, whir, protocolId, sessionId, kIs, subgroupGenPowers);

        vm.prank(address(0xBEEF));
        vm.expectRevert(bytes("only deployer"));
        fresh.initializeCancelCloseVk(MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers);

        fresh.initializeCancelCloseVk(MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers);
        assertTrue(fresh.cancelCloseVkInitialized());
        vm.expectRevert(bytes("cancel close vk already set"));
        fresh.initializeCancelCloseVk(MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers);
    }

    // =====================================================================
    // Phase B-D — withdrawal-claim / post-close-claim REAL verification negatives
    // =====================================================================

    /// GOLDEN VECTOR mirror: the Solidity `_expectedWithdrawalClaimLimbs` must produce the SAME
    /// 50-limb vector as the Rust `WithdrawalClaimPublicInputs::to_u64_vec()` layout
    /// (src/circuits/channel/withdrawal_claim_pis.rs; multi-token §N-6: + tokenSlot at 48,
    /// resolved base tokenIndex at 49). Same sentinels.
    function test_expectedWithdrawalClaimLimbs_goldenVector() external view {
        bytes32 cid = _b32(0x1000);
        bytes32 h1 = _b32(0x2000);
        bytes32 pkg = _b32(0x3000);
        address rcp = address(uint160((uint256(0x4000) << 128) | (uint256(0x4001) << 96)
            | (uint256(0x4002) << 64) | (uint256(0x4003) << 32) | uint256(0x4004)));
        bytes32 uad = _b32(0x5000);
        bytes32 nul = _b32(0x6000);
        uint64 amount = 0x0000001100000022;
        uint256[] memory v = verifier.expectedWithdrawalClaimLimbs(
            hex"0a0b0c0d", cid, h1, pkg, rcp, uad, amount, 7, 0xdeadbeef, nul
        );
        assertEq(v.length, 50);
        _assertB32(v, 0, 0x1000);          // close_intent_digest
        assertEq(v[8], 0x0a0b0c0d);        // channel_id
        _assertB32(v, 9, 0x2000);          // final_balance_state_h1
        _assertB32(v, 17, 0x3000);         // member_pk_g
        assertEq(v[25], 0x4000); assertEq(v[26], 0x4001); assertEq(v[27], 0x4002);
        assertEq(v[28], 0x4003); assertEq(v[29], 0x4004); // recipient
        _assertB32(v, 30, 0x5000);         // user_amount_digest
        _assertB32(v, 38, 0x6000);         // withdrawal_nullifier
        assertEq(v[46], 0x11); assertEq(v[47], 0x22); // amount (hi, lo)
        assertEq(v[48], 7);                // token_slot (multi-token §N-6)
        assertEq(v[49], 0xdeadbeef);       // token_index (resolved base token)
    }

    /// GOLDEN VECTOR mirror for post-close-claim (57 limbs; Stage 3: + finalBalanceStateH1 +
    /// finalSettledTxAccumulatorRoot appended; TM-16: + tokenIndex at limb 56).
    function test_expectedPostCloseClaimLimbs_goldenVector() external view {
        address rcp = address(uint160((uint256(0x4000) << 128) | (uint256(0x4001) << 96)
            | (uint256(0x4002) << 64) | (uint256(0x4003) << 32) | uint256(0x4004)));
        uint256[] memory v = verifier.expectedPostCloseClaimLimbs(
            hex"0a0b0c0d", _b32(0x1000), _b32(0x2000), _b32(0x3000), rcp, _b32(0x5000),
            0x0000001100000022, _b32(0x7000), _b32(0x8000), 0xdeadbeef
        );
        assertEq(v.length, 57);
        _assertB32(v, 0, 0x1000);          // close_intent_digest
        assertEq(v[8], 0x0a0b0c0d);        // receiver_channel_id
        _assertB32(v, 9, 0x2000);          // incoming_tx_hash
        _assertB32(v, 17, 0x3000);         // receiver_pk_g
        assertEq(v[25], 0x4000); assertEq(v[29], 0x4004); // recipient ends
        _assertB32(v, 30, 0x5000);         // shared_native_nullifier
        assertEq(v[38], 0x11); assertEq(v[39], 0x22); // amount
        _assertB32(v, 40, 0x7000);         // final_balance_state_h1 (Stage 3)
        _assertB32(v, 48, 0x8000);         // final_settled_tx_accumulator_root (Stage 3)
        assertEq(v[56], 0xdeadbeef);       // token_index (TM-16, anchored base token)
    }

    /// GOLDEN VECTOR mirror for cancel-close (27 limbs). The Rust side asserts the SAME constant in
    /// src/circuits/channel/cancel_close_pis.rs
    /// (`cancel_close_public_inputs_match_solidity_shared_vector`). Same sentinels.
    /// Layout: channelId(1) | closeIntentDigest(8) | memberSetCommitment(8) |
    /// revivedStateVersion(2 hi,lo) | revivedChannelStateDigest(8).
    function test_expectedCancelCloseLimbs_goldenVector() external view {
        uint256[] memory v = verifier.expectedCancelCloseLimbs(
            hex"0a0b0c0d",
            _b32(0x1000), // closeIntentDigest
            _b32(0x2000), // memberSetCommitment
            0x0000001100000022, // revivedStateVersion (hi=0x11, lo=0x22)
            _b32(0x3000) // revivedChannelStateDigest
        );
        assertEq(v.length, 27);
        assertEq(v[0], 0x0a0b0c0d); // channel_id
        _assertB32(v, 1, 0x1000); // close_intent_digest
        _assertB32(v, 9, 0x2000); // member_set_commitment
        assertEq(v[17], 0x11); // revived_state_version hi
        assertEq(v[18], 0x22); // revived_state_version lo
        _assertB32(v, 19, 0x3000); // revived_channel_state_digest
    }

    function _b32(uint32 tag) internal pure returns (bytes32) {
        uint256 v;
        for (uint256 i = 0; i < 8; i++) {
            v = (v << 32) | uint256(tag + uint32(i));
        }
        return bytes32(v);
    }

    function _assertB32(uint256[] memory v, uint256 off, uint32 tag) internal pure {
        for (uint256 i = 0; i < 8; i++) {
            assertEq(v[off + i], uint256(tag + uint32(i)));
        }
    }

    /// Negative — tampered amount limb: an MleProof whose amount PI disagrees with the claim's
    /// declared amount is rejected by the strict limb bind.
    function test_wclaim_tamperedAmount_reverts() external {
        bytes32 d = _finalizeDefault();
        ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, USER_A, alice, 30);
        // Build a proof for a DIFFERENT amount (31) than the claim (30) → limb mismatch. NOTE: a
        // fresh struct (not aliasing `c`, which a `memory` assignment would do).
        ChannelSettlementManager.WithdrawalClaim memory tampered = _withdrawalClaim(d, USER_A, alice, 30);
        tampered.amount = 31;
        MleVerifier.MleProof memory proof = _withdrawalClaimProof(tampered);
        vm.expectRevert(bytes("claim limb mismatch"));
        manager.submitWithdrawalClaim(c, proof);
    }

    /// Negative — wrong user_amount_digest: a proof bound to a different digest than the claim is
    /// rejected.
    function test_wclaim_wrongUserAmountDigest_reverts() external {
        bytes32 d = _finalizeDefault();
        ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, USER_A, alice, 30);
        ChannelSettlementManager.WithdrawalClaim memory tampered = _withdrawalClaim(d, USER_A, alice, 30);
        tampered.userAmountDigest = keccak256("other");
        MleVerifier.MleProof memory proof = _withdrawalClaimProof(tampered);
        vm.expectRevert(bytes("claim limb mismatch"));
        manager.submitWithdrawalClaim(c, proof);
    }

    /// Negative — non-canonical limb (>= 2**32) is rejected before the crypto check.
    function test_wclaim_nonCanonicalLimb_reverts() external {
        bytes32 d = _finalizeDefault();
        ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, USER_A, alice, 30);
        MleVerifier.MleProof memory proof = _withdrawalClaimProof(c);
        proof.publicInputs[0] = uint256(1) << 32; // 2**32, out of u32 range
        vm.expectRevert(bytes("claim limb range"));
        manager.submitWithdrawalClaim(c, proof);
    }

    /// Negative — wrong length publicInputs is rejected.
    function test_wclaim_wrongLength_reverts() external {
        bytes32 d = _finalizeDefault();
        ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, USER_A, alice, 30);
        MleVerifier.MleProof memory proof;
        proof.publicInputs = new uint256[](48); // != 50 (the pre-multitoken length)
        vm.expectRevert(bytes("claim pi len"));
        manager.submitWithdrawalClaim(c, proof);
    }

    /// Negative — crypto-invalid (mock verdict false) is rejected even with correct limbs.
    function test_wclaim_cryptoInvalid_reverts() external {
        bytes32 d = _finalizeDefault();
        ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, USER_A, alice, 30);
        MleVerifier.MleProof memory proof = _withdrawalClaimProof(c);
        mockMle.setVerdict(false);
        vm.expectRevert(ChannelSettlementManager.InvalidWithdrawalClaimProof.selector);
        manager.submitWithdrawalClaim(c, proof);
        mockMle.setVerdict(true);
    }

    /// Negative — unset withdrawal-claim VK reverts. Fresh verifier with ONLY the close VK set.
    function test_wclaim_unsetVk_reverts() external {
        ChannelSettlementVerifier fresh = new ChannelSettlementVerifier();
        _initCloseVk(fresh);
        // withdrawal-claim VK deliberately NOT set.
        MleVerifier.MleProof memory proof;
        proof.publicInputs = new uint256[](50);
        vm.expectRevert(ChannelSettlementVerifier.WithdrawalClaimVkNotSet.selector);
        fresh.verifyWithdrawalClaim(
            CHANNEL_ID, bytes32(0), bytes32(0), USER_A, alice, bytes32(0), 0, 0, 0, bytes32(0), proof
        );
    }

    /// Negative — withdrawal-claim VK guards: deployer-only, set-once, degreeBits>0.
    function test_wclaim_vkGuards() external {
        ChannelSettlementVerifier fresh = new ChannelSettlementVerifier();
        (
            ChannelSettlementVerifier.StatementVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        ) = CloseTestLib.dummyStatementVkArgs();

        // degreeBits == 0 rejected. Build a FRESH zero VK (a `memory` assignment would alias `vk`).
        (ChannelSettlementVerifier.StatementVk memory zeroVk,,,,,) = CloseTestLib.dummyStatementVkArgs();
        zeroVk.degreeBits = 0;
        vm.expectRevert(ChannelSettlementVerifier.StatementVkDegreeBitsZero.selector);
        fresh.initializeWithdrawalClaimVk(MleVerifier(address(mockMle)), zeroVk, whir, protocolId, sessionId, kIs, subgroupGenPowers);

        // non-deployer rejected.
        vm.prank(address(0xBEEF));
        vm.expectRevert(bytes("only deployer"));
        fresh.initializeWithdrawalClaimVk(MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers);

        // set once…
        fresh.initializeWithdrawalClaimVk(MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers);
        assertTrue(fresh.withdrawalClaimVkInitialized());
        // …and not again.
        vm.expectRevert(bytes("withdrawal claim vk already set"));
        fresh.initializeWithdrawalClaimVk(MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers);
    }

    /// Negative — post-close-claim unset VK reverts.
    function test_pcclaim_unsetVk_reverts() external {
        ChannelSettlementVerifier fresh = new ChannelSettlementVerifier();
        _initCloseVk(fresh);
        MleVerifier.MleProof memory proof;
        proof.publicInputs = new uint256[](57);
        vm.expectRevert(ChannelSettlementVerifier.PostCloseClaimVkNotSet.selector);
        fresh.verifyPostCloseClaim(
            CHANNEL_ID, bytes32(0), bytes32(0), USER_B, bob, bytes32(0), 0,
            bytes32(0), bytes32(0), 0, proof
        );
    }

    /// Negative — post-close-claim VK guards: set-once + already-set message.
    function test_pcclaim_vkSetOnce() external {
        ChannelSettlementVerifier fresh = new ChannelSettlementVerifier();
        (
            ChannelSettlementVerifier.StatementVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        ) = CloseTestLib.dummyStatementVkArgs();
        fresh.initializePostCloseClaimVk(MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers);
        vm.expectRevert(bytes("post close claim vk already set"));
        fresh.initializePostCloseClaimVk(MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers);
    }

    /// Negative (#8) — double-claim: the SAME derived shared_native_nullifier cannot be used twice.
    /// The nullifier is RECOMPUTED by the manager from (closeIntentDigest, incomingTxHash,
    /// receiverPkG), so re-submitting the same (digest, tx, receiver) reverts NullifierAlreadyUsed —
    /// even though the caller no longer supplies the nullifier.
    function test_pcclaim_doubleClaim_reverts() external {
        bytes32 d = _finalizeDefault();
        ChannelSettlementManager.PostCloseClaim memory pc = ChannelSettlementManager.PostCloseClaim({
            closeIntentDigest: d,
            incomingTxHash: keccak256("itx"),
            receiverPkG: USER_B,
            recipient: bob,
            amount: 5,
            tokenIndex: 0
        });
        manager.submitPostCloseClaim(pc, _postCloseClaimProof(pc));
        assertEq(manager.withdrawalCredits(0, bob), 5);

        // Same claim → same recomputed nullifier → rejected.
        MleVerifier.MleProof memory proof2 = _postCloseClaimProof(pc);
        vm.expectRevert(ChannelSettlementManager.NullifierAlreadyUsed.selector);
        manager.submitPostCloseClaim(pc, proof2);
    }

    /// Negative (#8) — manager passes the RECOMPUTED nullifier to the verifier: a proof bound to a
    /// DIFFERENT (attacker-picked) shared_native_nullifier than the recomputed one is rejected by
    /// the strict limb bind. Confirms the manager cannot be made to bind an opaque nullifier.
    function test_pcclaim_forgedNullifier_reverts() external {
        bytes32 d = _finalizeDefault();
        ChannelSettlementManager.PostCloseClaim memory pc = ChannelSettlementManager.PostCloseClaim({
            closeIntentDigest: d,
            incomingTxHash: keccak256("itx"),
            receiverPkG: USER_B,
            recipient: bob,
            amount: 5,
            tokenIndex: 0
        });
        // Build a proof whose shared_native_nullifier limb is a FORGED value (not the IMCK derive).
        // The Stage-3 H1 + accumulator-root limbs are the finalized ones (so the ONLY mismatch is
        // the nullifier limb the manager strict-binds).
        uint256[] memory limbs = verifier.expectedPostCloseClaimLimbs(
            CHANNEL_ID, d, pc.incomingTxHash, USER_B, bob, keccak256("forged"), pc.amount,
            manager.finalizedBalanceStateH1(), manager.finalizedSettledTxAccumulatorRoot(), 0
        );
        MleVerifier.MleProof memory proof = CloseTestLib.proofWithLimbs(limbs);
        vm.expectRevert(bytes("claim limb mismatch"));
        manager.submitPostCloseClaim(pc, proof);
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
