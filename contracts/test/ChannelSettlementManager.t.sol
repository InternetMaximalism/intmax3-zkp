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
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";
import {MockPinnedMleVerifierV2, MockPinnedMleVerifierV2WithCore} from "./helpers/MockPinnedMleVerifierV2.sol";
import {CloseTestLib} from "./CloseTestLib.sol";
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

    function isFinalizedStateRoot(bytes32) external pure returns (bool) {
        return true;
    }

    /// Register a channel's member set + bp from the active hashes (slot order) — mirrors the
    /// rollup's `registerChannel` recording (one-time, but the mock is permissive for test reuse).
    function register(uint32 channelId, uint8 bpMemberSlot, bytes32[] memory activeHashes) external {
        bytes32[8] memory padded;
        for (uint256 i = 0; i < activeHashes.length; i++) {
            padded[i] = activeHashes[i];
        }
        channelMemberSetCommitment[channelId] = verifier.closeMemberSetCommitment(padded, uint8(activeHashes.length));
        channelBpMemberSlot[channelId] = bpMemberSlot;
        channelBpPkG[channelId] = activeHashes[bpMemberSlot];
    }

    /// Register an EXPLICIT (possibly mismatching) commitment + bp, for negative tests.
    function registerRaw(uint32 channelId, bytes32 commitment, uint8 bpMemberSlot, bytes32 bpHash) external {
        channelMemberSetCommitment[channelId] = commitment;
        channelBpMemberSlot[channelId] = bpMemberSlot;
        channelBpPkG[channelId] = bpHash;
    }

    // --- Native-payout stand-in for IntmaxRollup.withdraw(amount) (P3 close→payout tests) ---
    // Models the rollup's pull-payment: the close pays the manager via withdrawNative, crediting
    // pendingWithdrawals[manager]; the manager later calls withdraw(amount) to pull that ETH.
    mapping(address => uint256) public pendingWithdrawals;

    /// Fund + credit a recipient's pull balance (simulates a finalized native withdrawal payout).
    function creditWithdrawal(address recipient) external payable {
        pendingWithdrawals[recipient] += msg.value;
    }

    function withdraw(uint256 amount) external override {
        uint256 pending = pendingWithdrawals[msg.sender];
        require(amount > 0 && pending > 0, "nothing to withdraw");
        uint256 paid = amount < pending ? amount : pending;
        pendingWithdrawals[msg.sender] = pending - paid;
        (bool ok,) = msg.sender.call{value: paid}("");
        require(ok, "withdraw failed");
    }

    mapping(bytes32 => bool) public override partialWithdrawalAuthorized;

    function authorizePartialWithdrawal(bytes32 authDigest) external override {
        partialWithdrawalAuthorized[authDigest] = true;
    }

    function consumePartialWithdrawalAuthorization(bytes32 authDigest) external {
        require(partialWithdrawalAuthorized[authDigest], "authorization not issued");
        delete partialWithdrawalAuthorized[authDigest];
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

    function withdrawToken(uint32 tokenIndex, uint256 amount) external override {
        uint256 pending = pendingTokenWithdrawals[tokenIndex][msg.sender];
        require(amount > 0 && pending > 0, "nothing to withdraw");
        uint256 paid = amount < pending ? amount : pending;
        pendingTokenWithdrawals[tokenIndex][msg.sender] = pending - paid;
        require(tokenAddressOf[tokenIndex].transfer(msg.sender, paid), "token transfer failed");
    }
}

    /// @dev Adversarial settlement-verifier facade whose close-adapter getter can change or revert
    ///      after Manager construction. Every other selector delegates to a real immutable verifier.
    ///      This proves the Manager does not re-read an attacker-controlled getter on the value path.
    contract MutableCloseAdapterSettlementVerifier {
        ChannelSettlementVerifier internal immutable implementation;
        IPinnedMleVerifierV2 internal currentCloseAdapter;
        bool internal getterReverts;

        constructor(ChannelSettlementVerifier implementation_, IPinnedMleVerifierV2 initialCloseAdapter_) {
            implementation = implementation_;
            currentCloseAdapter = initialCloseAdapter_;
        }

        function closeMleVerifier() external view returns (IPinnedMleVerifierV2) {
            require(!getterReverts, "adversarial getter revert");
            return currentCloseAdapter;
        }

        function setCloseMleVerifier(IPinnedMleVerifierV2 adapter) external {
            currentCloseAdapter = adapter;
        }

        function setGetterReverts(bool value) external {
            getterReverts = value;
        }

        fallback() external {
            address target = address(implementation);
            assembly ("memory-safe") {
                calldatacopy(0, 0, calldatasize())
                let ok := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
                returndatacopy(0, 0, returndatasize())
                if iszero(ok) { revert(0, returndatasize()) }
                return(0, returndatasize())
            }
        }
    }

    contract ChannelSettlementManagerTest is Test {
        // Redeclared for vm.expectEmit.
        event CloseRequested(address indexed requester, uint64 closeRequestedAt, uint64 closeFreezeNonce);

        ChannelSettlementVerifier internal verifier;
        MockPinnedMleVerifierV2 internal mockMle;
        MockPinnedMleVerifierV2 internal withdrawalClaimMle;
        MockPinnedMleVerifierV2 internal postCloseClaimMle;
        MockPinnedMleVerifierV2 internal cancelCloseMle;
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
        uint256 internal constant TEST_CHAIN_ID = 31337;

        // Shared Rust<->circuit<->Solidity canonical closeStateId vector. The legacy ABI method name
        // remains `computeCloseIntentDigest`, but the value is IMCS(channelId, final IMCH, freeze).
        bytes32 internal constant SHARED_VECTOR_DIGEST =
            0x02dd6084b2c3921fb635639fab58406994068a7cdfca286992eac9e57c373778;

        // ── Signer-independent exit: this test contract is the Manager's `closeFundingMaterializer`
        // and stands in for the close satellite's freeze journal, whole-vector backing receipt and
        // exact close-digest exit latch (`materializedChannelExit`). ──
        mapping(uint32 => uint64) internal _testFrozenExitGeneration;
        mapping(uint32 => bytes32) public materializedChannelExit;
        bool internal _testBackingAvailable = true;
        bool internal _testBackingCurrent = true;

        function freezeFromManager(uint32 channelId, uint64 generation) external {
            require(_testFrozenExitGeneration[channelId] == 0, "already frozen");
            _testFrozenExitGeneration[channelId] = generation;
        }

        function unfreezeFromManager(uint32 channelId, uint64 generation) external {
            require(_testFrozenExitGeneration[channelId] == generation, "wrong generation");
            delete _testFrozenExitGeneration[channelId];
        }

        function requireSignedHeadBacking(uint32 channelId, bytes32, bytes32) external view {
            bool requireCurrent = ChannelSettlementManager(payable(msg.sender)).channelStatus()
                != ChannelSettlementManager.ChannelLifecycleStatus.Active;
            require(
                msg.sender.code.length != 0 && channelId == uint32(CHANNEL_ID) && _testBackingAvailable
                    && (!requireCurrent || _testBackingCurrent),
                "backing unavailable"
            );
        }

        function setUp() external {
            assertEq(block.chainid, TEST_CHAIN_ID, "unit-test chain containment");
            mockMle = new MockPinnedMleVerifierV2(TEST_CHAIN_ID);
            withdrawalClaimMle = new MockPinnedMleVerifierV2(TEST_CHAIN_ID);
            postCloseClaimMle = new MockPinnedMleVerifierV2(TEST_CHAIN_ID);
            cancelCloseMle = new MockPinnedMleVerifierV2(TEST_CHAIN_ID);
            verifier = new ChannelSettlementVerifier(mockMle, withdrawalClaimMle, postCloseClaimMle, cancelCloseMle);
            registry = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));

            ChannelSettlementManager.MemberBinding[] memory bindings = new ChannelSettlementManager.MemberBinding[](3);
            bindings[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: alice});
            bindings[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
            bindings[2] = ChannelSettlementManager.MemberBinding({pkG: USER_C, recipient: carol});

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
                bytes32(0),
                CHALLENGE_PERIOD,
                SPECIAL_CLOSE_PENALTY,
                INITIAL_BP_BOND,
                IChannelSettlementVerifier(address(verifier)),
                IChannelRegistry(address(registry)),
                address(this),
                bindings
            );
        }

        function _proofFor(bytes32 piHash) internal pure returns (bytes memory) {
            return abi.encode(piHash);
        }

        function _participantTree(bytes32[] memory pkGs, address[] memory recipients, uint16 targetSlot)
            internal
            pure
            returns (bytes32 root, bytes32[10] memory siblings)
        {
            bytes32[1024] memory nodes;
            for (uint256 i = 0; i < pkGs.length; i++) {
                nodes[i] = keccak256(abi.encodePacked(bytes4(0x494d5052), uint16(i), pkGs[i], recipients[i]));
            }
            uint256 width = 1024;
            uint256 target = uint256(targetSlot);
            uint256 level = 0;
            while (width > 1) {
                siblings[level] = nodes[target ^ 1];
                for (uint256 i = 0; i < width; i += 2) {
                    nodes[i >> 1] = keccak256(abi.encodePacked(bytes4(0x494d504e), nodes[i], nodes[i + 1]));
                }
                width >>= 1;
                target >>= 1;
                level++;
            }
            root = nodes[0];
        }

        /// @dev Build a cancel-close `MleProof` whose `publicInputs` equal the verifier's expected
        ///      29-limb vector for `request`. The `memberSetCommitment` limbs use the channel's
        ///      REGISTERED member-set commitment (what `cancelClose` injects — Finding D), so the strict
        ///      bind passes only when the proof claims the registered set.
        function _cancelCloseProof(ChannelSettlementManager.CancelCloseRequest memory request)
            internal
            view
            returns (bytes memory)
        {
            ChannelSettlementManager.PendingClose memory pending = manager.getPendingClose();
            uint256[] memory limbs = verifier.expectedCancelCloseLimbs(
                CHANNEL_ID,
                request.closeIntentDigest,
                manager.registeredMemberSetCommitment(),
                pending.finalStateVersion,
                request.revivedStateVersion,
                request.revivedChannelStateDigest
            );
            return CloseTestLib.proofWithLimbs(limbs);
        }

        function _cancelCloseProofFor(
            ChannelSettlementManager m,
            ChannelSettlementManager.CancelCloseRequest memory request
        ) internal view returns (bytes memory) {
            ChannelSettlementManager.PendingClose memory pending = m.getPendingClose();
            uint256[] memory limbs = verifier.expectedCancelCloseLimbs(
                CHANNEL_ID,
                request.closeIntentDigest,
                m.registeredMemberSetCommitment(),
                pending.finalStateVersion,
                request.revivedStateVersion,
                request.revivedChannelStateDigest
            );
            return CloseTestLib.proofWithLimbs(limbs);
        }

        /// @dev Build a withdrawal-claim `MleProof` whose `publicInputs` equal the verifier's expected
        ///      50-limb vector for `claim` — exactly what `_bindLimbsStrict` requires. Uses the channel's
        ///      finalized H1 (the manager passes it through to the verifier).
        function _withdrawalClaimProof(ChannelSettlementManager.WithdrawalClaim memory claim)
            internal
            view
            returns (bytes memory)
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
        ) internal view returns (bytes memory) {
            uint256[] memory limbs =
                verifier.expectedWithdrawalClaimLimbs(
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
            internal
            view
            returns (bytes memory)
        {
            bytes32 snn =
                _expectedSharedNativeNullifier(claim.closeIntentDigest, claim.incomingTxHash, claim.receiverPkG);
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
        function _expectedSharedNativeNullifier(bytes32 closeIntentDigest, bytes32 incomingTxHash, bytes32 receiverPkG)
            internal
            pure
            returns (bytes32)
        {
            return
                keccak256(abi.encodePacked(bytes4(uint32(0x494d434b)), closeIntentDigest, incomingTxHash, receiverPkG));
        }

        function _intent(uint64 _closeNonce, uint64 finalEpoch, uint64 finalSmallBlockNumber, uint64 closeFreezeNonce)
            internal
            pure
            returns (ChannelSettlementManager.CloseIntent memory intent)
        {
            intent = _intentWithVersion(_closeNonce, finalEpoch, finalSmallBlockNumber, closeFreezeNonce, 12);
        }

        /// Single-token (genesis ETH) helpers: amount at slot 0, base token 0 at registry slot 0.
        function _singleAmounts(uint256 amount) internal pure returns (uint256[10] memory a) {
            a[0] = amount;
        }

        function _singleRegistry() internal pure returns (uint32[10] memory r) {
            r[0] = 0;
        }

        function _intentWithVersion(
            uint64 _closeNonce,
            uint64 finalEpoch,
            uint64 finalSmallBlockNumber,
            uint64 closeFreezeNonce,
            uint64 finalStateVersion
        ) internal pure returns (ChannelSettlementManager.CloseIntent memory intent) {
            intent = ChannelSettlementManager.CloseIntent({
                    closeNonce: closeFreezeNonce,
                    finalEpoch: finalEpoch,
                    finalSmallBlockNumber: finalSmallBlockNumber,
                    closeFreezeNonce: closeFreezeNonce,
                    finalChannelStateDigest: keccak256("final_state"),
                    finalBalanceStateH1: keccak256("balance_state_h1"),
                    channelFundAmounts: _singleAmounts(75),
                    tokenRegistry: _singleRegistry(),
                    tokenCount: 1,
                    channelFundIntmaxStateRoot: keccak256("intmax_root"),
                    burnTxHash: bytes32(0),
                    closeWithdrawalDigest: keccak256("burn_backed_close"),
                    snapshotMediumBlockNumber: 0,
                    finalStateVersion: finalStateVersion,
                    finalSettledTxChain: keccak256("settled_tx_chain"),
                    finalSettledTxAccumulatorRoot: keccak256("settled_tx_accumulator_root")
                });
        }

        /// @dev Build a close compact-proof surrogate for the default manager whose `publicInputs` equal
        /// the EXACT 87 expected close limbs the manager's `_runCloseVerify` rebinds (channelId =
        /// CHANNEL_ID, the channel's registered member-set commitment, and the packed member/delegate
        /// counts). With the mock MLE verifier returning `true`, this is an ACCEPTING close proof.
        function _closeProof(ChannelSettlementManager.CloseIntent memory intent) internal view returns (bytes memory) {
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
        function _closeProofWithDelegateCount(ChannelSettlementManager.CloseIntent memory intent, uint32 delegateCount)
            internal
            view
            returns (bytes memory)
        {
            return this._closeProofCd(
                intent, manager.registeredMemberSetCommitment(), manager.activeMemberCount(), delegateCount
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
        ) external view returns (bytes memory) {
            uint256[] memory limbs = verifier.expectedCloseLimbs(
                CloseProofFields({
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
                }),
                delegateCount
            );
            return CloseTestLib.proofWithLimbs(limbs);
        }

        function _submitClose(ChannelSettlementManager.CloseIntent memory intent) internal {
            manager.submitCloseIntent(intent, _closeProof(intent));
        }

        /// Two-step close preamble: a member freezes the channel and the grace window elapses.
        function _requestCloseAndElapseGrace() internal {
            uint64 freezeNonce = manager.currentCloseFreezeNonce();
            uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
            vm.prank(alice);
            manager.requestClose(freezeNonce, cancellationFloor);
            vm.warp(block.timestamp + GRACE);
        }

        function _withdrawalClaim(bytes32 closeIntentDigest, bytes32 memberPkG, address recipient, uint64 amount)
            internal
            pure
            returns (ChannelSettlementManager.WithdrawalClaim memory claim)
        {
            claim = ChannelSettlementManager.WithdrawalClaim({
                closeIntentDigest: closeIntentDigest,
                memberPkG: memberPkG,
                recipient: recipient,
                userAmountDigest: keccak256(abi.encodePacked(memberPkG, amount)),
                amount: amount,
                tokenSlot: 0,
                tokenIndex: 0,
                withdrawalNullifier: keccak256(abi.encodePacked("withdraw", closeIntentDigest, memberPkG))
            });
        }

        function test_hash_helpers_are_stable() external view {
            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
            // The close proof now carries the 103 raw close limbs as its MLE publicInputs (not a keccak).
            bytes memory closeProof = _closeProof(intent);
            uint256[] memory closePublicInputs = abi.decode(closeProof, (uint256[]));
            assertEq(closePublicInputs.length, 103, "close proof carries 103 raw limbs (Stage 3 + multi-token TFD)");
            assertEq(closePublicInputs[0], uint256(uint32(CHANNEL_ID)), "limb[0] == channelId");

            assertTrue(
                verifier.specialClosePIHash(CHANNEL_ID, BP_MEMBER_SLOT, USER_A, keccak256("root"), 33, 10, 15)
                    != bytes32(0)
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
                    CHANNEL_ID, keccak256("close"), keccak256("member_set"), 7, 9, keccak256("revived_state")
                )
                .length,
                29,
                "cancel-close PI is 29 raw limbs"
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
                )
                .length,
                57,
                "post-close-claim PI is 57 raw limbs (Stage 3 + TM-16 tokenIndex)"
            );
        }

        /// M-9: even a mock-verifier proof rebuilt to match caller-selected metadata cannot enter the
        /// close lifecycle. The production circuit enforces the same three equalities.
        function test_close_rejects_noncanonical_close_metadata_before_verification() external {
            _requestCloseAndElapseGrace();

            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
            intent.closeNonce = 2;
            bytes memory proof = _closeProof(intent);
            vm.expectRevert(ChannelSettlementManager.NonCanonicalCloseMetadata.selector);
            manager.submitCloseIntent(intent, proof);

            intent = _intent(1, 9, 22, 1);
            intent.burnTxHash = keccak256("unproven live burn");
            proof = _closeProof(intent);
            vm.expectRevert(ChannelSettlementManager.NonCanonicalCloseMetadata.selector);
            manager.submitCloseIntent(intent, proof);

            intent = _intent(1, 9, 22, 1);
            intent.snapshotMediumBlockNumber = 77;
            proof = _closeProof(intent);
            vm.expectRevert(ChannelSettlementManager.NonCanonicalCloseMetadata.selector);
            manager.submitCloseIntent(intent, proof);
        }

        function test_close_requires_available_current_whole_vector_backing() external {
            _requestCloseAndElapseGrace();
            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
            bytes memory proof = _closeProof(intent);

            _testBackingAvailable = false;
            vm.expectRevert(bytes("backing unavailable"));
            manager.submitCloseIntent(intent, proof);

            _testBackingAvailable = true;
            _testBackingCurrent = false;
            vm.expectRevert(bytes("backing unavailable"));
            manager.submitCloseIntent(intent, proof);

            _testBackingCurrent = true;
            manager.submitCloseIntent(intent, proof);
            assertTrue(manager.getPendingClose().active);
        }

        /// Shared Rust<->Solidity test vector: `computeCloseIntentDigest` must be byte-identical to
        /// Rust `CloseIntent::signing_digest()` (canonical IMCS). The Rust side asserts the same constant in
        /// src/common/channel.rs::close_intent_digest_matches_solidity_shared_vector. The intent's
        /// channel id is this manager's CHANNEL_ID (9).
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
                channelFundAmounts: _singleAmounts(0x0000001100000012000000130000001400000015000000160000001700000018),
                tokenRegistry: _singleRegistry(),
                tokenCount: 1,
                channelFundIntmaxStateRoot: 0x000000190000001a0000001b0000001c0000001d0000001e0000001f00000020,
                burnTxHash: 0x0000002100000022000000230000002400000025000000260000002700000028,
                closeWithdrawalDigest: 0x000000290000002a0000002b0000002c0000002d0000002e0000002f00000030,
                snapshotMediumBlockNumber: 0x99999999aaaaaaaa,
                finalStateVersion: 0xbbbbbbbbcccccccc,
                finalSettledTxChain: 0x0000003100000032000000330000003400000035000000360000003700000038,
                // Free transport metadata is intentionally outside the canonical IMCS state identity,
                // so its value here does not affect the shared vector.
                finalSettledTxAccumulatorRoot: keccak256("settled_tx_accumulator_root")
            });
            assertEq(manager.computeCloseIntentDigest(intent), SHARED_VECTOR_DIGEST);

            ChannelSettlementManager.CloseIntent memory metadataVariant = intent;
            metadataVariant.closeNonce += 1;
            metadataVariant.burnTxHash = keccak256("different burn transport metadata");
            metadataVariant.closeWithdrawalDigest = keccak256("different IMCL metadata");
            metadataVariant.snapshotMediumBlockNumber += 1;
            assertEq(
                manager.computeCloseIntentDigest(metadataVariant),
                SHARED_VECTOR_DIGEST,
                "free metadata must not mint a new closeStateId"
            );

            // Solidity memory structs alias on assignment, so mutate and restore one copy explicitly.
            metadataVariant.finalChannelStateDigest = keccak256("different member-signed state");
            assertTrue(manager.computeCloseIntentDigest(metadataVariant) != SHARED_VECTOR_DIGEST);
            metadataVariant.finalChannelStateDigest = 0x0000000100000002000000030000000400000005000000060000000700000008;
            metadataVariant.closeFreezeNonce += 1;
            assertTrue(manager.computeCloseIntentDigest(metadataVariant) != SHARED_VECTOR_DIGEST);
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
            assertEq(v[1], 0x11);
            assertEq(v[2], 0x22);
            // final_epoch — 3..4.
            assertEq(v[3], 0x33);
            assertEq(v[4], 0x44);
            // final_small_block_number — 5..6.
            assertEq(v[5], 0x55);
            assertEq(v[6], 0x66);
            // close_freeze_nonce — 7..8.
            assertEq(v[7], 0x77);
            assertEq(v[8], 0x88);
            _assertSentinelRange(v, 9, 0x1000); // final_channel_state_digest 9..16
            _assertSentinelRange(v, 17, 0x2000); // final_balance_state_h1 17..24
            _assertSentinelRange(v, 25, 0x3000); // channel_fund_amount 25..32
            _assertSentinelRange(v, 33, 0x4000); // channel_fund_intmax_state_root 33..40
            _assertSentinelRange(v, 41, 0x5000); // burn_tx_hash 41..48
            _assertSentinelRange(v, 49, 0x6000); // close_withdrawal_digest 49..56
            // close_intent_digest 57..64 — RECOMPUTED canonical IMCS closeStateId.
            bytes32 digest = keccak256(
                abi.encodePacked(
                    bytes4(uint32(0x494d4353)),
                    fields.channelId,
                    fields.finalChannelStateDigest,
                    fields.closeFreezeNonce
                )
            );
            for (uint256 i = 0; i < 8; i++) {
                assertEq(v[57 + i], (uint256(digest) >> (32 * (7 - i))) & 0xffffffff, "imci limb");
            }
            // snapshot_medium_block_number — 65..66.
            assertEq(v[65], 0x99);
            assertEq(v[66], 0xaa);
            // final_state_version — 67..68.
            assertEq(v[67], 0xbb);
            assertEq(v[68], 0xcc);
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
            assertEq(v[93], 3);
            assertEq(v[94], 1);
            // Multi-token (§N-6, TM-11): tokenFundsDigest 95..102 — RECOMPUTED over the supplied
            // (registry, count, amounts); assert the limbs equal the split of the public recompute.
            bytes32 tfd = verifier.tokenFundsDigest(fields.tokenRegistry, fields.tokenCount, fields.channelFundAmounts);
            for (uint256 i = 0; i < 8; i++) {
                assertEq(v[95 + i], (uint256(tfd) >> (32 * (7 - i))) & 0xffffffff, "tfd limb");
            }
        }

        /// @dev external passthroughs so `fields` is read from calldata (the verifier's
        /// `_expectedCloseLimbs` / `_closeIntentDigest` take `calldata`).
        function _expectedCloseLimbsExt(CloseProofFields calldata fields, uint32 delegateCount)
            external
            view
            returns (uint256[] memory)
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
            0x826fa6c83e36ef8f4537ce2bdd5873faa8e861dd7a4d3b072b77990cbfd7b886;

        function test_member_set_commitment_matches_rust_shared_vector() external view {
            // The shape is locked to this constant via the Rust counterpart; we recompute it here over
            // the FIXED 16-slot array (3 active hashes + 13 zero padding slots) and memberCount = 3.
            bytes32[8] memory hashes;
            hashes[0] = MEMBER_SET_VECTOR_H0;
            hashes[1] = MEMBER_SET_VECTOR_H1;
            hashes[2] = MEMBER_SET_VECTOR_H2;
            bytes32 commitment = verifier.closeMemberSetCommitment(hashes, 3);
            assertEq(commitment, MEMBER_SET_COMMITMENT_VECTOR);

            // Padding slots (>= memberCount) are zeroed INTERNALLY (mirrors Rust + the in-circuit
            // gadget), so a nonzero padding slot in the input array does NOT change the commitment —
            // the value depends only on memberCount and the active hashes (injective on the active set).
            bytes32[8] memory tampered = hashes;
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

        function _newManager(uint256 n, uint8 bpSlot) internal returns (ChannelSettlementManager m) {
            m = _newManagerFrom(_bindings(n), bpSlot);
        }

        /// @dev Construct a manager from pre-built bindings. Kept separate so `vm.expectRevert` can
        /// immediately precede ONLY the constructor call (no intervening cheatcode-tripping helpers).
        function _newManagerFrom(ChannelSettlementManager.MemberBinding[] memory b, uint8 bpSlot)
            internal
            returns (ChannelSettlementManager m)
        {
            bytes32 bpHash = bpSlot < b.length ? b[bpSlot].pkG : bytes32(uint256(1));
            // Finding E: when the bindings are in-range (so the manager reaches the registry-consistency
            // check), register a MATCHING member set on the shared mock registry first so the
            // constructor binding succeeds. Out-of-range cases revert in the manager BEFORE the registry
            // check (and BEFORE the registry check matters). We reuse the shared `registry` (deployed in
            // setUp) rather than deploying a new contract here, so the ONLY call after a caller's
            // `vm.expectRevert` is the manager constructor itself (Foundry requires the reverting call
            // immediately after the cheatcode).
            if (b.length >= 2 && b.length <= 8 && bpSlot < b.length) {
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
                bytes32(0),
                CHALLENGE_PERIOD,
                SPECIAL_CLOSE_PENALTY,
                INITIAL_BP_BOND,
                IChannelSettlementVerifier(address(verifier)),
                IChannelRegistry(address(registry)),
                address(this),
                b
            );
        }

        function test_variable_member_count_2_and_8() external {
            ChannelSettlementManager m2 = _newManager(2, 0);
            assertEq(uint256(m2.activeMemberCount()), 2);
            assertEq(m2.memberCount(), 2);
            // registeredMemberSetCommitment uses the FIXED 8-slot (MAX_MEMBER_COUNT) form with the
            // active count.
            bytes32[8] memory h2;
            h2[0] = keccak256(abi.encodePacked("member", uint256(0)));
            h2[1] = keccak256(abi.encodePacked("member", uint256(1)));
            assertEq(m2.registeredMemberSetCommitment(), verifier.closeMemberSetCommitment(h2, 2));

            ChannelSettlementManager m8 = _newManager(8, 5);
            assertEq(uint256(m8.activeMemberCount()), 8);
            assertEq(uint256(m8.bpMemberSlot()), 5);
            bytes32[8] memory h8;
            for (uint256 i = 0; i < 8; i++) {
                h8[i] = keccak256(abi.encodePacked("member", i));
            }
            assertEq(m8.registeredMemberSetCommitment(), verifier.closeMemberSetCommitment(h8, 8));
        }

        /// A capacity-sized snapshot costs one root/count immutable, not 1016 delegate SSTOREs.  The
        /// bound leaves ample headroom below a 30M mainnet block even including the manager's large
        /// runtime-code deposit.
        function test_1024ParticipantDeploymentGas_isBoundedAndStoresOnlyCosigners() external {
            ChannelSettlementManager.MemberBinding[] memory b = new ChannelSettlementManager.MemberBinding[](8);
            bytes32[] memory hashes = new bytes32[](8);
            for (uint256 i = 0; i < 8; i++) {
                hashes[i] = keccak256(abi.encodePacked("capacity-cosigner", i));
                b[i] = ChannelSettlementManager.MemberBinding({pkG: hashes[i], recipient: address(uint160(0xCA00 + i))});
            }
            registry.register(uint32(CHANNEL_ID), 0, hashes);
            uint256 gasBefore = gasleft();
            ChannelSettlementManager maxed = new ChannelSettlementManager(
                CHANNEL_ID,
                0,
                hashes[0],
                1016,
                keccak256("authenticated-1024-participant-root"),
                CHALLENGE_PERIOD,
                SPECIAL_CLOSE_PENALTY,
                INITIAL_BP_BOND,
                IChannelSettlementVerifier(address(verifier)),
                IChannelRegistry(address(registry)),
                address(this),
                b
            );
            uint256 used = gasBefore - gasleft();
            assertLt(used, 10_000_000, "1024-participant manager must fit comfortably in one block");
            assertEq(uint256(maxed.activeParticipantCount()), 1024);
            assertEq(uint256(maxed.activeDelegateCount()), 1016);
            assertEq(maxed.memberCount(), 8, "only cosigners may be materialized");
            assertEq(maxed.registeredMemberIndexPlusOne(keccak256("delegate-not-stored")), 0);
        }

        function test_member_count_out_of_range_reverts() external {
            // Build bindings BEFORE expectRevert so the cheatcode immediately precedes only the
            // constructor call (Foundry requires the reverting call at the same depth).
            ChannelSettlementManager.MemberBinding[] memory one = _bindings(1);
            vm.expectRevert(ChannelSettlementManager.InvalidMemberCount.selector);
            _newManagerFrom(one, 0);

            // One past the sig-cluster cap (MAX_MEMBER_COUNT = 8).
            ChannelSettlementManager.MemberBinding[] memory nine = _bindings(9);
            vm.expectRevert(ChannelSettlementManager.InvalidMemberCount.selector);
            _newManagerFrom(nine, 0);

            // bpMemberSlot >= activeMemberCount reverts.
            ChannelSettlementManager.MemberBinding[] memory three = _bindings(3);
            vm.expectRevert(ChannelSettlementManager.InvalidBpMemberSlot.selector);
            _newManagerFrom(three, 3);
        }

        // -----------------------------------------------------------------------
        // Finding E: manager member set + bp MUST equal the rollup registration
        // -----------------------------------------------------------------------

        /// @dev Deploy a manager bound to `reg`, from 3 bindings (USER_A/B/C, bp slot 0).
        function _newManagerWithRegistry(IChannelRegistry reg) internal returns (ChannelSettlementManager) {
            return _newManagerWithVerifierAndRegistry(IChannelSettlementVerifier(address(verifier)), reg);
        }

        function _newManagerWithVerifierAndRegistry(IChannelSettlementVerifier settlementVerifier, IChannelRegistry reg)
            internal
            returns (ChannelSettlementManager)
        {
            ChannelSettlementManager.MemberBinding[] memory b = new ChannelSettlementManager.MemberBinding[](3);
            b[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: alice});
            b[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
            b[2] = ChannelSettlementManager.MemberBinding({pkG: USER_C, recipient: carol});
            return new ChannelSettlementManager(
                CHANNEL_ID,
                BP_MEMBER_SLOT,
                USER_A,
                0, // delegate_count (Phase 1: member-only)
                bytes32(0),
                CHALLENGE_PERIOD,
                SPECIAL_CLOSE_PENALTY,
                INITIAL_BP_BOND,
                settlementVerifier,
                reg,
                address(this),
                b
            );
        }

        /// (a) Manager constructor SUCCEEDS when its member set + bp match the rollup registration, and
        /// the manager's `registeredMemberSetCommitment()` equals the registry's recorded commitment.
        function test_findingE_constructorSucceeds_whenMemberSetMatches() external {
            MockChannelRegistry reg = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
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
            MockChannelRegistry reg = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
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
            MockChannelRegistry reg = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
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
            MockChannelRegistry reg = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
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
            MockChannelRegistry reg = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
            // No register() call: registry returns bytes32(0).
            vm.expectRevert(ChannelSettlementManager.MemberSetMismatch.selector);
            _newManagerWithRegistry(IChannelRegistry(address(reg)));
        }

        function test_request_close_freezes_channel_and_emits() external {
            assertTrue(manager.isNativeSendAllowed(0));

            uint64 freezeNonce = manager.currentCloseFreezeNonce();
            uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();

            vm.expectEmit(true, false, false, true);
            emit CloseRequested(alice, uint64(block.timestamp), 1);
            vm.prank(alice);
            manager.requestClose(freezeNonce, cancellationFloor);

            assertEq(
                uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
            );
            assertEq(manager.closeRequestedAt(), uint64(block.timestamp));
            assertEq(manager.currentCloseFreezeNonce(), 1);
            // The freeze halts native sends for every nonce.
            assertFalse(manager.isNativeSendAllowed(0));
            assertFalse(manager.isNativeSendAllowed(1));
        }

        function test_request_close_reverts_for_non_member() external {
            uint64 freezeNonce = manager.currentCloseFreezeNonce();
            uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
            vm.prank(mallory);
            vm.expectRevert(ChannelSettlementManager.NotChannelMember.selector);
            manager.requestClose(freezeNonce, cancellationFloor);
        }

        function test_request_close_reverts_when_already_pending() external {
            uint64 freezeNonce = manager.currentCloseFreezeNonce();
            uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
            vm.prank(alice);
            manager.requestClose(freezeNonce, cancellationFloor);

            freezeNonce = manager.currentCloseFreezeNonce();
            cancellationFloor = manager.highestCancelledRevivedStateVersion();
            vm.prank(bob);
            vm.expectRevert(ChannelSettlementManager.ChannelAlreadyFrozen.selector);
            manager.requestClose(freezeNonce, cancellationFloor);
        }

        function test_request_close_reverts_when_closed() external {
            _requestCloseAndElapseGrace();
            _submitClose(_intent(1, 9, 22, 1));
            vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
            manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());

            uint64 freezeNonce = manager.currentCloseFreezeNonce();
            uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
            vm.prank(alice);
            vm.expectRevert(ChannelSettlementManager.ChannelClosed.selector);
            manager.requestClose(freezeNonce, cancellationFloor);
        }

        function test_submit_close_intent_reverts_from_active_without_request() external {
            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
            bytes memory proof = _closeProof(intent);
            vm.expectRevert(ChannelSettlementManager.CloseNotRequested.selector);
            manager.submitCloseIntent(intent, proof);
        }

        function test_submit_close_intent_grace_period_boundary() external {
            uint64 freezeNonce = manager.currentCloseFreezeNonce();
            uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
            vm.prank(alice);
            manager.requestClose(freezeNonce, cancellationFloor);
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
                uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
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
            ChannelSettlementManager.CloseIntent memory equalVersion = _intentWithVersion(3, 9, 24, 1, 6);
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
            // Build a VALID proof for the REAL intent (publicInputs == expected limbs for `intent`).
            bytes memory proof = _closeProof(intent);
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
            bytes memory proof = _closeProof(intent);

            // The pinned adapter rejects the proof → the manager must refuse the close.
            mockMle.setVerdict(false);
            vm.expectRevert(MockPinnedMleVerifierV2.MockMleVerificationRejected.selector);
            manager.submitCloseIntent(intent, proof);

            // Restore the accepting verdict: the SAME intent+proof now goes through, proving the
            // rejection above was the MLE verdict and not some other gate (no channel state changed).
            mockMle.setVerdict(true);
            manager.submitCloseIntent(intent, proof);
        }

        /// The large-proof fast path is fixed to the settlement verifier's close adapter at
        /// Manager construction. No caller-supplied adapter or later getter read can redirect it.
        function test_managerPinsSettlementVerifiersCloseAdapter() external view {
            assertEq(address(manager.closeMleVerifier()), address(mockMle), "manager close adapter mismatch");
            assertEq(
                address(manager.closeMleVerifier()),
                address(verifier.closeMleVerifier()),
                "manager did not derive adapter from verifier"
            );
        }

        /// Even a malicious verifier facade whose getter changes from A to B cannot redirect an
        /// already-deployed Manager: the constructor-derived adapter A remains authoritative.
        function test_managerDoesNotRereadMutableCloseAdapterGetter() external {
            MutableCloseAdapterSettlementVerifier facade = new MutableCloseAdapterSettlementVerifier(verifier, mockMle);
            IChannelSettlementVerifier facadeInterface = IChannelSettlementVerifier(address(facade));
            MockChannelRegistry facadeRegistry = new MockChannelRegistry(facadeInterface);
            bytes32[] memory active = new bytes32[](3);
            active[0] = USER_A;
            active[1] = USER_B;
            active[2] = USER_C;
            facadeRegistry.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, active);
            ChannelSettlementManager pinnedManager =
                _newManagerWithVerifierAndRegistry(facadeInterface, IChannelRegistry(address(facadeRegistry)));
            assertEq(address(pinnedManager.closeMleVerifier()), address(mockMle), "adapter A was not pinned");

            // B accepts while pinned A rejects. A runtime getter read would incorrectly authorize.
            facade.setCloseMleVerifier(withdrawalClaimMle);
            assertEq(address(facade.closeMleVerifier()), address(withdrawalClaimMle), "facade did not switch to B");
            assertEq(address(pinnedManager.closeMleVerifier()), address(mockMle), "manager followed mutable getter");

            uint64 freezeNonce = pinnedManager.currentCloseFreezeNonce();
            uint64 cancellationFloor = pinnedManager.highestCancelledRevivedStateVersion();
            vm.prank(alice);
            pinnedManager.requestClose(freezeNonce, cancellationFloor);
            vm.warp(block.timestamp + GRACE);
            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
            bytes memory proof = _closeProofFor(pinnedManager, intent);
            mockMle.setVerdict(false);
            withdrawalClaimMle.setVerdict(true);
            vm.expectRevert(MockPinnedMleVerifierV2.MockMleVerificationRejected.selector);
            pinnedManager.submitCloseIntent(intent, proof);
            assertFalse(pinnedManager.getPendingClose().active, "mutable getter bypass changed close state");
        }

        /// Missing or unreadable adapter getters fail at Manager construction, before protocol
        /// state exists. This excludes zero, EOA and reverting adapter sources.
        function test_managerConstructorRejectsInvalidCloseAdapterGetter() external {
            MutableCloseAdapterSettlementVerifier zeroFacade =
                new MutableCloseAdapterSettlementVerifier(verifier, IPinnedMleVerifierV2(address(0)));
            vm.expectRevert(ChannelSettlementManager.InvalidSettlementVerifier.selector);
            _newManagerWithVerifierAndRegistry(IChannelSettlementVerifier(address(zeroFacade)), registry);

            MutableCloseAdapterSettlementVerifier eoaFacade =
                new MutableCloseAdapterSettlementVerifier(verifier, IPinnedMleVerifierV2(address(0xBEEF)));
            vm.expectRevert(ChannelSettlementManager.InvalidSettlementVerifier.selector);
            _newManagerWithVerifierAndRegistry(IChannelSettlementVerifier(address(eoaFacade)), registry);

            MutableCloseAdapterSettlementVerifier revertingFacade =
                new MutableCloseAdapterSettlementVerifier(verifier, mockMle);
            revertingFacade.setGetterReverts(true);
            vm.expectRevert(ChannelSettlementManager.InvalidSettlementVerifier.selector);
            _newManagerWithVerifierAndRegistry(IChannelSettlementVerifier(address(revertingFacade)), registry);
        }

        /// The public bind-only helper is intentionally non-authoritative: even when an arbitrary
        /// caller presents a matching 103-limb vector to it, Manager state stays unchanged and a
        /// subsequent close still MUST pass the immutable adapter's cryptographic verdict.
        function test_bindOnlySuccessCannotBypassManagerAdapterVerification() external {
            CloseProofFields memory fields = this._validCloseFields();
            uint256[] memory publicInputs = this._expectedCloseLimbsExt(fields, fields.minDelegateCount);

            vm.prank(mallory);
            assertTrue(verifier.bindCloseIntentPublicInputs(fields, publicInputs), "matching limbs must bind");
            assertFalse(manager.getPendingClose().active, "stateless binder mutated manager");

            _requestCloseAndElapseGrace();
            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
            bytes memory proof = _closeProof(intent);
            mockMle.setVerdict(false);
            vm.expectRevert(MockPinnedMleVerifierV2.MockMleVerificationRejected.selector);
            manager.submitCloseIntent(intent, proof);
            assertFalse(manager.getPendingClose().active, "adapter rejection changed close state");
        }

        function test_finalize_records_version_chain_and_h1() external {
            _requestCloseAndElapseGrace();
            ChannelSettlementManager.CloseIntent memory intent = _intentWithVersion(1, 9, 22, 1, 41);
            _submitClose(intent);

            vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
            manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());

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
            ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager.CancelCloseRequest({
                closeIntentDigest: closeIntentDigest,
                revivedStateVersion: 13,
                revivedChannelStateDigest: keccak256("revived_state")
            });
            manager.cancelClose(request, _cancelCloseProof(request));
            assertEq(manager.closeRequestedAt(), 0);

            // Re-closing straight away is barred: the channel is Active again.
            //
            // C-3 (audit 2026-08-28): the re-close intent now carries era 1, not era 2. That is the
            // whole point of the fix — era 1 is the ONLY era a real close proof can ever carry, because
            // the close PI is `signedState.close_freeze_nonce + 1` and no shipped code advances a
            // `ChannelState.close_freeze_nonce` past 0. This test previously built an era-2 intent,
            // which only a `#[cfg(test)]` helper can produce, and so hid the deadlock it was walking
            // straight through.
            ChannelSettlementManager.CloseIntent memory reclose = _intent(2, 10, 30, 1);
            bytes memory recloseProof = _closeProof(reclose);
            vm.expectRevert(ChannelSettlementManager.CloseNotRequested.selector);
            manager.submitCloseIntent(reclose, recloseProof);

            // A fresh requestClose starts a fresh grace window.
            uint64 freezeNonce = manager.currentCloseFreezeNonce();
            uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
            vm.prank(bob);
            manager.requestClose(freezeNonce, cancellationFloor);
            assertEq(manager.currentCloseFreezeNonce(), 1);
            vm.expectRevert(ChannelSettlementManager.GracePeriodNotElapsed.selector);
            manager.submitCloseIntent(reclose, recloseProof);

            vm.warp(block.timestamp + GRACE);
            manager.submitCloseIntent(reclose, recloseProof);
            assertEq(
                uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
            );
        }

        /// C-2 (audit 2026-08-28): the withdrawal leg is unchanged and still credits; the post-close leg
        /// is now a permanently reverting stub, because in EVERY closeable state the incoming delta has
        /// already been applied into the receiver's slot while its tx hash remains in the accumulator,
        /// so the two legs would credit ONE entitlement twice across two disjoint nullifier maps.
        function test_submit_finalize_withdraw_and_post_close_claim() external {
            _requestCloseAndElapseGrace();
            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
            _submitClose(intent);

            assertEq(
                uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
            );
            assertFalse(manager.isNativeSendAllowed(0));

            vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
            manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());

            assertEq(uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.Closed));
            bytes32 closeIntentDigest = manager.finalizedCloseIntentDigest();

            ChannelSettlementManager.WithdrawalClaim memory aliceClaim =
                _withdrawalClaim(closeIntentDigest, USER_A, alice, 30);
            manager.submitWithdrawalClaim(aliceClaim, _withdrawalClaimProof(aliceClaim));

            ChannelSettlementManager.PostCloseClaim memory postCloseClaim = ChannelSettlementManager.PostCloseClaim({
                closeIntentDigest: closeIntentDigest,
                incomingTxHash: keccak256("incoming_tx"),
                receiverPkG: USER_B,
                recipient: bob,
                amount: 5,
                tokenIndex: 0
            });
            // Precompute the proof BEFORE expectRevert: the builder makes external view calls that
            // would otherwise consume the expectation.
            bytes memory pcProof = _postCloseClaimProof(postCloseClaim);
            vm.expectRevert(ChannelSettlementManager.PostCloseClaimDisabled.selector);
            manager.submitPostCloseClaim(postCloseClaim, pcProof);

            assertEq(manager.withdrawalCredits(0, alice), 30);
            assertEq(manager.withdrawalCredits(0, bob), 0, "the double-credit path is disabled");
        }

        function test_participantCloseGuardedRawCannotReplayAfterCancelRestoresFreezeNonce() external {
            bytes32 USER_D = keccak256("guarded_delegate_pubkey_hash");
            address dave = makeAddr("guarded-dave");
            MockChannelRegistry reg = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
            bytes32[] memory members = new bytes32[](2);
            members[0] = USER_A;
            members[1] = USER_B;
            reg.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, members);

            ChannelSettlementManager.MemberBinding[] memory bindings = new ChannelSettlementManager.MemberBinding[](2);
            bindings[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: alice});
            bindings[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
            bytes32[] memory participantPkGs = new bytes32[](3);
            participantPkGs[0] = USER_A;
            participantPkGs[1] = USER_B;
            participantPkGs[2] = USER_D;
            address[] memory participantRecipients = new address[](3);
            participantRecipients[0] = alice;
            participantRecipients[1] = bob;
            participantRecipients[2] = dave;
            (bytes32 root, bytes32[10] memory daveProof) = _participantTree(participantPkGs, participantRecipients, 2);

            ChannelSettlementManager m = new ChannelSettlementManager(
                CHANNEL_ID,
                BP_MEMBER_SLOT,
                USER_A,
                1,
                root,
                CHALLENGE_PERIOD,
                SPECIAL_CLOSE_PENALTY,
                INITIAL_BP_BOND,
                IChannelSettlementVerifier(address(verifier)),
                IChannelRegistry(address(reg)),
                address(this),
                bindings
            );

            vm.prank(dave);
            m.requestCloseAsParticipant(2, USER_D, daveProof, 0, 0);
            vm.warp(block.timestamp + GRACE);
            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
            m.submitCloseIntent(intent, _closeProofFor(m, intent));
            bytes32 digest = m.computeCloseIntentDigest(intent);
            ChannelSettlementManager.CancelCloseRequest memory cancel = ChannelSettlementManager.CancelCloseRequest({
                closeIntentDigest: digest,
                revivedStateVersion: 13,
                revivedChannelStateDigest: keccak256("guarded-revived-state")
            });
            m.cancelClose(cancel, _cancelCloseProofFor(m, cancel));

            assertEq(m.currentCloseFreezeNonce(), 0, "cancel deliberately restores the freeze nonce");
            assertEq(m.highestCancelledRevivedStateVersion(), 13, "cancel floor advances monotonically");
            vm.prank(dave);
            vm.expectRevert(ChannelSettlementManager.InvalidFreezeNonce.selector);
            m.requestCloseAsParticipant(2, USER_D, daveProof, 0, 0);

            vm.prank(dave);
            m.requestCloseAsParticipant(2, USER_D, daveProof, 0, 13);
            assertEq(
                uint256(m.channelStatus()),
                uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending),
                "a freshly guarded request remains live"
            );
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

            ChannelSettlementManager.MemberBinding[] memory mb = new ChannelSettlementManager.MemberBinding[](2);
            mb[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: alice});
            mb[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
            bytes32[] memory participantPkGs = new bytes32[](3);
            participantPkGs[0] = USER_A;
            participantPkGs[1] = USER_B;
            participantPkGs[2] = USER_D;
            address[] memory participantRecipients = new address[](3);
            participantRecipients[0] = alice;
            participantRecipients[1] = bob;
            participantRecipients[2] = dave;
            (bytes32 participantRoot, bytes32[10] memory daveProof) =
                _participantTree(participantPkGs, participantRecipients, 2);

            ChannelSettlementManager m = new ChannelSettlementManager(
                CHANNEL_ID,
                BP_MEMBER_SLOT,
                USER_A,
                1,
                participantRoot,
                CHALLENGE_PERIOD,
                SPECIAL_CLOSE_PENALTY,
                INITIAL_BP_BOND,
                IChannelSettlementVerifier(address(verifier)),
                IChannelRegistry(address(reg)),
                address(this),
                mb
            );

            // Only the two cosigners are materialized. The delegate identity remains available through
            // the immutable root/proof without any per-delegate constructor SSTORE.
            assertEq(uint256(m.activeMemberCount()), 2);
            assertEq(uint256(m.activeDelegateCount()), 1);
            assertEq(uint256(m.activeParticipantCount()), 3);
            assertEq(m.participantRoot(), participantRoot);
            assertEq(m.memberCount(), 2, "registeredMemberPkGs is member-only (delegate excluded)");
            assertEq(m.registeredMemberIndexPlusOne(USER_D), 0, "delegate must not consume mapping storage");
            assertEq(m.registeredRecipientOf(USER_D), address(0), "delegate must not consume recipient storage");
            assertFalse(m.isMemberRecipient(dave), "delegate close authorization is proof-based");
            // IMCM commits ONLY the 2 members (delegate excluded) — matches the registry.
            assertEq(m.registeredMemberSetCommitment(), reg.channelMemberSetCommitment(uint32(CHANNEL_ID)));

            // A wrong recipient cannot reuse Dave's path, while Dave retains unilateral close.
            vm.prank(mallory);
            vm.expectRevert(ChannelSettlementManager.InvalidParticipantProof.selector);
            m.requestCloseAsParticipant(2, USER_D, daveProof, 0, 0);
            vm.prank(dave);
            m.requestCloseAsParticipant(2, USER_D, daveProof, 0, 0);
            vm.warp(block.timestamp + GRACE);
            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
            m.submitCloseIntent(intent, _closeProofFor(m, intent));
            vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
            m.finalizeCloseGuarded(m.getPendingClose().closeIntentDigest, m.closeRequestGeneration());
            bytes32 cid = m.finalizedCloseIntentDigest();

            // The DELEGATE withdraws its member-attested balance (40) — accepted.
            ChannelSettlementManager.WithdrawalClaim memory dClaim = _withdrawalClaim(cid, USER_D, dave, 40);
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
            ChannelSettlementManager.WithdrawalClaim memory sClaim = _withdrawalClaim(cid, STRANGER, mallory, 1);
            // The stranger's limbs are self-consistent, but a stranger cannot produce a cryptographically
            // valid slot-inclusion proof against the signed state — simulate the ZK verdict = false. The
            // manager rejects with `InvalidWithdrawalClaimProof`. (Reset the verdict afterwards.)
            bytes memory sProof = _withdrawalClaimProofFor(m, sClaim);
            withdrawalClaimMle.setVerdict(false);
            vm.expectRevert(MockPinnedMleVerifierV2.MockMleVerificationRejected.selector);
            m.submitWithdrawalClaim(sClaim, sProof);
            withdrawalClaimMle.setVerdict(true);
        }

        /// A delegate-bearing manager cannot silently fall back to a member-only derived root.
        function test_delegate_count_without_authenticated_root_reverts() external {
            MockChannelRegistry reg = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
            bytes32[] memory members = new bytes32[](2);
            members[0] = USER_A;
            members[1] = USER_B;
            reg.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, members);

            ChannelSettlementManager.MemberBinding[] memory mb = new ChannelSettlementManager.MemberBinding[](2);
            mb[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: alice});
            mb[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
            vm.expectRevert(ChannelSettlementManager.InvalidParticipantRoot.selector);
            new ChannelSettlementManager(
                CHANNEL_ID,
                BP_MEMBER_SLOT,
                USER_A,
                1,
                bytes32(0),
                CHALLENGE_PERIOD,
                SPECIAL_CLOSE_PENALTY,
                INITIAL_BP_BOND,
                IChannelSettlementVerifier(address(verifier)),
                IChannelRegistry(address(reg)),
                address(this),
                mb
            );
        }

        /// P6-A / detail2 §H-3 (C2): `submitSpecialClose` is permanently DISABLED — any call reverts and
        /// the channel is left untouched (no freeze, no BP slash). It was gated only by a forgeable
        /// `_matches` stub, which let anyone freeze the channel and slash an honest BP (freeze-grief).
        /// SECURITY: this asserts the intended behavior change, not a workaround — the disposition is to
        /// disable the entry point until a sound cross-layer non-inclusion commitment exists.
        function test_special_close_disabled_reverts() external {
            ChannelSettlementManager.SpecialClose memory specialClose = ChannelSettlementManager.SpecialClose({
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
            assertEq(uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.Active));
            assertEq(manager.currentCloseFreezeNonce(), 0);
            assertEq(manager.bpBondCredits(), INITIAL_BP_BOND);
            assertEq(manager.withdrawalCredits(0, address(this)), 0);
        }

        function test_cancel_close_restores_active_channel() external {
            _requestCloseAndElapseGrace();
            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
            _submitClose(intent);

            bytes32 closeIntentDigest = manager.computeCloseIntentDigest(intent);
            ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager.CancelCloseRequest({
                closeIntentDigest: closeIntentDigest,
                revivedStateVersion: 13,
                revivedChannelStateDigest: keccak256("revived_state")
            });

            manager.cancelClose(request, _cancelCloseProof(request));

            assertEq(uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.Active));
            // C-3 (audit 2026-08-28): the cancel UNWINDS `requestClose`'s era bump. Before the fix this
            // asserted 1 — i.e. it pinned the deadlock: the counter stayed one era ahead of every
            // producible signed state, so no later close intent could ever satisfy the strict equality.
            assertEq(manager.currentCloseFreezeNonce(), 0, "cancel restores the pre-freeze era");
            assertEq(manager.closeRequestedAt(), 0);
            assertEq(manager.closeChallengeHorizon(), 0, "H-3 horizon is cleared with the era");
            // A shipped wallet state carries era 0 (nothing in the tree ever advances
            // `ChannelState.close_freeze_nonce`), so native sends must be live again at 0, not at 1.
            assertTrue(manager.isNativeSendAllowed(0));
            assertFalse(manager.isNativeSendAllowed(1));
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
            ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager.CancelCloseRequest({
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
                intent.finalStateVersion,
                request.revivedStateVersion,
                request.revivedChannelStateDigest
            );
            bytes memory forged = CloseTestLib.proofWithLimbs(forgedLimbs);
            vm.expectRevert(bytes("claim limb mismatch"));
            manager.cancelClose(request, forged);

            // The pending close is untouched.
            assertEq(
                uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
            );
        }

        /// A cancel whose proof claims a different close intent digest than the pending close is rejected
        /// (manager guard), and a crypto-invalid proof (mock verdict=false) reverts InvalidCancelProof.
        function test_cancel_close_rejects_wrong_close_and_invalid_proof() external {
            _requestCloseAndElapseGrace();
            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
            _submitClose(intent);

            bytes32 closeIntentDigest = manager.computeCloseIntentDigest(intent);
            ChannelSettlementManager.CancelCloseRequest memory request = ChannelSettlementManager.CancelCloseRequest({
                closeIntentDigest: closeIntentDigest,
                revivedStateVersion: 13,
                revivedChannelStateDigest: keccak256("revived_state")
            });

            // Precompute the proof so the expectRevert arms on the cancelClose call itself (not on the
            // external view calls inside `_cancelCloseProof`).
            bytes memory validProof = _cancelCloseProof(request);

            // Wrong close intent digest → manager guard. (Fresh struct: `= request` would ALIAS the
            // memory reference and mutate `request`.)
            ChannelSettlementManager.CancelCloseRequest memory wrong = ChannelSettlementManager.CancelCloseRequest({
                closeIntentDigest: keccak256("not_the_pending_close"),
                revivedStateVersion: request.revivedStateVersion,
                revivedChannelStateDigest: request.revivedChannelStateDigest
            });
            vm.expectRevert(ChannelSettlementManager.CloseIntentDigestMismatch.selector);
            manager.cancelClose(wrong, validProof);

            // Crypto-invalid proof (limbs correct, but MLE verdict=false) → InvalidCancelProof.
            cancelCloseMle.setVerdict(false);
            vm.expectRevert(MockPinnedMleVerifierV2.MockMleVerificationRejected.selector);
            manager.cancelClose(request, validProof);
            cancelCloseMle.setVerdict(true);
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
                uint256(manager.channelStatus()), uint256(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending)
            );
            assertEq(manager.currentCloseFreezeNonce(), 1);
        }

        /// P6-A: disabling special close does not break the normal member-driven close path.
        function test_normal_close_still_finalizes_after_special_close_disabled() external {
            ChannelSettlementManager.SpecialClose memory specialClose = ChannelSettlementManager.SpecialClose({
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
            manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
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
            manager.finalizeCloseGuarded(manager.getPendingClose().closeIntentDigest, manager.closeRequestGeneration());
            return manager.finalizedCloseIntentDigest();
        }

        function _submitWd(bytes32 d, bytes32 memberHash, address recipient, uint64 amount) internal returns (bytes32) {
            ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, memberHash, recipient, amount);
            manager.submitWithdrawalClaim(c, _withdrawalClaimProof(c));
            return c.withdrawalNullifier;
        }

        /// Simulate the rollup paying this manager via a finalized native withdrawal, then pull it in.
        function _fundAndPull(MockChannelRegistry reg, ChannelSettlementManager m, uint256 amount) internal {
            _materializeCloseFundingAuthorization(reg, m, 0);
            vm.deal(address(this), address(this).balance + amount);
            reg.creditWithdrawal{value: amount}(address(m));
            m.pullChannelFunds();
        }

        /// Simulate the immutable materializer's exact close-digest receipt. Generic recipient credit
        /// alone must never make a Manager pull-ready.
        function _materializeCloseFundingAuthorization(
            MockChannelRegistry,
            ChannelSettlementManager m,
            uint32
        ) internal returns (bytes32 authDigest) {
            authDigest = m.finalizedCloseIntentDigest();
            materializedChannelExit[uint32(m.channelId())] = authDigest;
        }

        function _closeProofFor(ChannelSettlementManager m, ChannelSettlementManager.CloseIntent memory intent)
            internal
            view
            returns (bytes memory)
        {
            // Same calldata-reentry as `_closeProof` (via-IR stack budget): `_closeProofCd` reads the
            // intent from calldata and uses CHANNEL_ID; the per-channel commitment + packed counts come
            // from the supplied manager `m`. All these managers are bound to the shared `verifier`, so
            // `expectedCloseLimbs` (called inside `_closeProofCd`) uses CHANNEL_ID — the same channelId
            // every manager in this suite uses.
            return this._closeProofCd(
                intent, m.registeredMemberSetCommitment(), m.activeMemberCount(), uint32(m.activeDelegateCount())
            );
        }

        /// Deploy a manager whose member-slot-0 recipient is `r0` (USER_A/B/C hashes unchanged, so the
        /// Finding-E member-set commitment still matches). Used for the reentrancy test.
        function _managerWithRecipient0(address r0)
            internal
            returns (ChannelSettlementManager m, MockChannelRegistry reg)
        {
            reg = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
            bytes32[] memory activeHashes = new bytes32[](3);
            activeHashes[0] = USER_A;
            activeHashes[1] = USER_B;
            activeHashes[2] = USER_C;
            reg.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, activeHashes);
            ChannelSettlementManager.MemberBinding[] memory b = new ChannelSettlementManager.MemberBinding[](3);
            b[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: r0});
            b[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
            b[2] = ChannelSettlementManager.MemberBinding({pkG: USER_C, recipient: carol});
            m = new ChannelSettlementManager(
                CHANNEL_ID,
                BP_MEMBER_SLOT,
                USER_A,
                0,
                bytes32(0),
                CHALLENGE_PERIOD,
                SPECIAL_CLOSE_PENALTY,
                INITIAL_BP_BOND,
                IChannelSettlementVerifier(address(verifier)),
                IChannelRegistry(address(reg)),
                address(this),
                b
            );
        }

        /// Stray ETH from a non-rollup sender must be rejected (receive() restricted to the registry).
        function test_p3_receive_rejectsNonRollup() external {
            vm.deal(mallory, 1 ether);
            vm.prank(mallory);
            (bool ok,) = address(manager).call{value: 1}("");
            assertFalse(ok, "non-rollup ETH must be rejected");
            assertEq(address(manager).balance, 0, "no stray ETH held");
        }

        /// pullChannelFunds moves the exact finalized channel cap into the manager and records it.
        function test_p3_pullChannelFunds_recordsReceived() external {
            _finalizeDefault();
            _fundAndPull(registry, manager, 75);
            assertEq(manager.receivedChannelFunds(0), 75, "receivedChannelFunds == finalized cap");
            assertEq(address(manager).balance, 75, "manager holds the exact backing");

            vm.expectRevert(abi.encodeWithSelector(ChannelSettlementManager.ChannelFundsAlreadyReceived.selector, 0));
            manager.pullChannelFunds();
        }

        /// A close may use only a channel-fund root finalized by this manager's immutable Rollup.
        /// A proof valid against another deployment/history must not become local backing authority.
        function test_close_rejectsStateRootNotFinalizedByBoundRollup() external {
            uint64 freezeNonce = manager.currentCloseFreezeNonce();
            uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
            vm.prank(alice);
            manager.requestClose(freezeNonce, cancellationFloor);
            vm.warp(block.timestamp + GRACE);
            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
            bytes memory proof = _closeProof(intent);
            vm.mockCall(
                address(registry),
                abi.encodeCall(IChannelRegistry.isFinalizedStateRoot, (intent.channelFundIntmaxStateRoot)),
                abi.encode(false)
            );
            vm.expectRevert(
                abi.encodeWithSelector(
                    ChannelSettlementManager.ChannelFundStateRootNotFinalized.selector,
                    intent.channelFundIntmaxStateRoot
                )
            );
            manager.submitCloseIntent(intent, proof);
        }

        /// Happy path: members claim their accrued credit as real native ETH.
        function test_p3_claimWithdrawalCredit_paysRealEth() external {
            bytes32 d = _finalizeDefault();
            bytes32 aliceNullifier = _submitWd(d, USER_A, alice, 30);
            bytes32 bobNullifier = _submitWd(d, USER_B, bob, 20); // distinct nullifier (keyed by member hash)
            _fundAndPull(registry, manager, 75);

            uint256 aliceBefore = alice.balance;
            vm.prank(alice);
            uint256 got = manager.claimWithdrawalCredit(aliceNullifier);
            assertEq(got, 30, "alice claims her credit");
            assertEq(alice.balance, aliceBefore + 30, "alice received real ETH");
            assertEq(manager.withdrawalCredits(0, alice), 0, "credit cleared");
            assertEq(manager.totalCreditedOut(0), 30, "paid-out accumulator");

            vm.prank(bob);
            manager.claimWithdrawalCredit(bobNullifier);
            assertEq(bob.balance, 20, "bob received real ETH");
            assertEq(manager.totalCreditedOut(0), 50, "total paid out");
        }

        /// CROSS-CHANNEL ISOLATION: underfunded recipient credit is rejected atomically and creates no
        /// payout capacity, even if intra-channel claims have already accrued.
        function test_p3_underfundedPull_createsNoPayoutCapacity() external {
            bytes32 d = _finalizeDefault();
            bytes32 nullifier = _submitWd(d, USER_A, alice, 30); // credit = 30
            _materializeCloseFundingAuthorization(registry, manager, 0);
            vm.deal(address(this), address(this).balance + 10);
            registry.creditWithdrawal{value: 10}(address(manager));
            vm.expectRevert(abi.encodeWithSelector(ChannelSettlementManager.ChannelFundingMismatch.selector, 0, 75, 10));
            manager.pullChannelFunds();
            vm.prank(alice);
            vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
            manager.claimWithdrawalCredit(nullifier);
            assertEq(alice.balance, 0, "no over-cap payout");
        }

        /// C-2 (audit 2026-08-28): `submitPostCloseClaim` used to share the channel-fund accrual budget
        /// (this test's original subject). The shared budget was never a DEFENCE against the
        /// double-credit — it is a shared pot, so the second credit simply displaced whichever co-member
        /// claimed last — and the entry point is now disabled outright. The refusal is asserted at the
        /// same over-cap input, so the test still fails if the stub is ever removed without a fix.
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
            bytes memory proof = _postCloseClaimProof(pc);
            vm.expectRevert(ChannelSettlementManager.PostCloseClaimDisabled.selector);
            manager.submitPostCloseClaim(pc, proof);
            assertEq(manager.totalWithdrawn(0), 70, "no accrual on the disabled path");
        }

        /// A reentering recipient cannot double-withdraw: nonReentrant + CEI make the reentrant call
        /// revert, which bubbles up and reverts the whole claim (credit preserved, no ETH drained).
        function test_p3_claimWithdrawalCredit_reentrancyBlocked() external {
            ReentrantClaimer attacker = new ReentrantClaimer();
            (ChannelSettlementManager m, MockChannelRegistry reg) = _managerWithRecipient0(address(attacker));
            uint64 freezeNonce = m.currentCloseFreezeNonce();
            uint64 cancellationFloor = m.highestCancelledRevivedStateVersion();
            vm.prank(bob);
            m.requestClose(freezeNonce, cancellationFloor);
            vm.warp(block.timestamp + GRACE);
            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);
            m.submitCloseIntent(intent, _closeProofFor(m, intent));
            vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
            m.finalizeCloseGuarded(m.getPendingClose().closeIntentDigest, m.closeRequestGeneration());
            bytes32 d = m.finalizedCloseIntentDigest();

            ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, USER_A, address(attacker), 30);
            m.submitWithdrawalClaim(c, _withdrawalClaimProofFor(m, c));
            attacker.setManager(m, c.withdrawalNullifier);

            _materializeCloseFundingAuthorization(reg, m, 0);
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
        function _proofForFields(CloseProofFields memory f) internal view returns (bytes memory) {
            return CloseTestLib.proofWithLimbs(this._expectedCloseLimbsExt(f, f.minDelegateCount));
        }

        /// B-2: same, with an EXPLICIT limb-94 value (may be above or below the floor).
        function _proofForFieldsWithDc(CloseProofFields memory f, uint32 dc) internal view returns (bytes memory) {
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
            bytes memory proof = _proofForFields(f); // proof for the REAL commitment
            f.memberSetCommitment = keccak256("non-member keys"); // now expected limbs 77..84 change
            vm.expectRevert(bytes("close limb mismatch"));
            verifier.verifyCloseIntent(f, proof);
        }

        /// Wrong channelId ⇒ limb 0 differs ⇒ reverts.
        function test_verifyClose_wrongChannelId_reverts() external {
            CloseProofFields memory f = this._validCloseFields();
            bytes memory proof = _proofForFields(f);
            f.channelId = hex"deadbeef";
            vm.expectRevert(bytes("close limb mismatch"));
            verifier.verifyCloseIntent(f, proof);
        }

        /// publicInputs.length != 103 ⇒ reverts on the length guard.
        function test_verifyClose_wrongLength_reverts() external {
            CloseProofFields memory f = this._validCloseFields();
            uint256[] memory shortPis = new uint256[](102);
            bytes memory proof = CloseTestLib.proofWithLimbs(shortPis);
            vm.expectRevert(bytes("close pi len"));
            verifier.verifyCloseIntent(f, proof);
        }

        /// A limb >= 2**32 ⇒ reverts on the canonical-range guard (even if it would "match" mod nothing).
        function test_verifyClose_nonCanonicalLimb_reverts() external {
            CloseProofFields memory f = this._validCloseFields();
            uint256[] memory pis = this._expectedCloseLimbsExt(f, f.minDelegateCount);
            pis[0] = uint256(1) << 32; // 2**32, the smallest non-canonical u32
            bytes memory proof = CloseTestLib.proofWithLimbs(pis);
            vm.expectRevert(bytes("close limb range"));
            verifier.verifyCloseIntent(f, proof);
        }

        /// Property-style regression: every one of the 103 close limbs is mandatory. This covers
        /// the complete loop, including memberCount (93), delegateCount (94), and all eight
        /// tokenFundsDigest limbs (95..102), on the new bind-only boundary.
        function test_bindClosePublicInputs_rejectsMutationAtEveryIndex() external view {
            CloseProofFields memory fields = this._validCloseFields();
            uint256[] memory publicInputs = this._expectedCloseLimbsExt(fields, fields.minDelegateCount);
            for (uint256 i = 0; i < publicInputs.length; ++i) {
                uint256 original = publicInputs[i];
                publicInputs[i] = original ^ 1;
                (bool accepted,) = address(verifier)
                    .staticcall(
                        abi.encodeCall(ChannelSettlementVerifier.bindCloseIntentPublicInputs, (fields, publicInputs))
                    );
                assertFalse(accepted, "mutated close limb accepted");
                publicInputs[i] = original;
            }
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

        /// Settlement freezes joins, so a proof cannot widen the active region beyond the immutable
        /// participant root/count.
        function test_verifyClose_delegateCountAboveFrozenCount_reverts() external {
            CloseProofFields memory f = this._validCloseFields();
            bytes memory one = _proofForFieldsWithDc(f, 1);
            bytes memory five = _proofForFieldsWithDc(f, 5);
            vm.expectRevert(ChannelSettlementVerifier.CloseDelegateCountOutOfRange.selector);
            verifier.verifyCloseIntent(f, one);
            vm.expectRevert(ChannelSettlementVerifier.CloseDelegateCountOutOfRange.selector);
            verifier.verifyCloseIntent(f, five);
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
            bytes memory below = _proofForFieldsWithDc(f, 1);
            bytes memory atFloor = _proofForFieldsWithDc(f, 2);
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
            bytes memory atCap = _proofForFieldsWithDc(f, 1024 - mc);
            bytes memory overCap = _proofForFieldsWithDc(f, 1024 - mc + 1);
            bytes memory huge = _proofForFieldsWithDc(f, type(uint32).max);
            // The frozen count must match each direct-verifier case. This isolates the structural
            // ceiling from the earlier exact-snapshot-count check.
            f.minDelegateCount = 1024 - mc;
            // active == 1024 exactly: accepted.
            assertTrue(verifier.verifyCloseIntent(f, atCap));
            // active == 1025: rejected.
            f.minDelegateCount = 1024 - mc + 1;
            vm.expectRevert(ChannelSettlementVerifier.CloseDelegateCountOutOfRange.selector);
            verifier.verifyCloseIntent(f, overCap);
            // A huge-but-CANONICAL limb (2**32 - 1) is rejected by the ceiling, not by an overflow
            // panic — the explicit error is the failure mode (A-5).
            f.minDelegateCount = type(uint32).max;
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
            bytes memory proof = _proofForFields(f); // built for the REAL memberCount
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

        /// Both shrinking and widening the delegate region are refused after the live identity root is
        /// frozen. The exact count closes and the frozen delegate can still claim.
        function test_frozenDelegateCount_requiresExactCloseAndClaims() external {
            bytes32 USER_D = keccak256("delegate_d_pubkey_hash"); // registered at deployment
            bytes32 USER_E = keccak256("delegate_e_pubkey_hash"); // joined AFTER deployment
            address dave = makeAddr("b2_dave");
            address erin = makeAddr("b2_erin");

            MockChannelRegistry reg = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
            bytes32[] memory members = new bytes32[](2);
            members[0] = USER_A;
            members[1] = USER_B;
            reg.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, members);

            ChannelSettlementManager.MemberBinding[] memory mb = new ChannelSettlementManager.MemberBinding[](2);
            mb[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: alice});
            mb[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
            ChannelSettlementManager.MemberBinding[] memory db = new ChannelSettlementManager.MemberBinding[](1);
            db[0] = ChannelSettlementManager.MemberBinding({pkG: USER_D, recipient: dave});

            ChannelSettlementManager m = new ChannelSettlementManager(
                CHANNEL_ID,
                BP_MEMBER_SLOT,
                USER_A,
                1,
                keccak256("b2_delegate_snapshot"),
                CHALLENGE_PERIOD,
                SPECIAL_CLOSE_PENALTY,
                INITIAL_BP_BOND,
                IChannelSettlementVerifier(address(verifier)),
                IChannelRegistry(address(reg)),
                address(this),
                mb
            );

            uint64 freezeNonce = m.currentCloseFreezeNonce();
            uint64 cancellationFloor = m.highestCancelledRevivedStateVersion();
            vm.prank(alice);
            m.requestClose(freezeNonce, cancellationFloor);
            vm.warp(block.timestamp + GRACE);
            ChannelSettlementManager.CloseIntent memory intent = _intent(1, 9, 22, 1);

            // Builders first (external calls; `vm.expectRevert` binds to the NEXT call).
            bytes memory excludesDelegate =
                this._closeProofCd(intent, m.registeredMemberSetCommitment(), m.activeMemberCount(), 0);
            bytes memory withJoiner =
                this._closeProofCd(intent, m.registeredMemberSetCommitment(), m.activeMemberCount(), 2);
            bytes memory exact = this._closeProofCd(intent, m.registeredMemberSetCommitment(), m.activeMemberCount(), 1);

            // A close carrying delegate_count = 0 would EXCLUDE the registered delegate ⇒ refused.
            // The floor error propagates as a revert out of the manager's `_checkCloseProof`.
            vm.expectRevert(ChannelSettlementVerifier.CloseDelegateCountOutOfRange.selector);
            m.submitCloseIntent(intent, excludesDelegate);

            vm.expectRevert(ChannelSettlementVerifier.CloseDelegateCountOutOfRange.selector);
            m.submitCloseIntent(intent, withJoiner);

            m.submitCloseIntent(intent, exact);
            vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
            m.finalizeCloseGuarded(m.getPendingClose().closeIntentDigest, m.closeRequestGeneration());
            bytes32 cid = m.finalizedCloseIntentDigest();

            ChannelSettlementManager.WithdrawalClaim memory dClaim = _withdrawalClaim(cid, USER_D, dave, 30);
            m.submitWithdrawalClaim(dClaim, _withdrawalClaimProofFor(m, dClaim));
            assertEq(m.withdrawalCredits(0, dave), 30, "frozen delegate credited");
        }

        /// The pinned adapter rejects a crypto-invalid proof before any application state can change.
        function test_verifyClose_cryptoInvalid_reverts() external {
            CloseProofFields memory f = this._validCloseFields();
            bytes memory proof = _proofForFields(f);
            mockMle.setVerdict(false);
            vm.expectRevert(MockPinnedMleVerifierV2.MockMleVerificationRejected.selector);
            verifier.verifyCloseIntent(f, proof);
            mockMle.setVerdict(true);
        }

        /// Every statement adapter is pinned atomically; duplicate statement domains are rejected.
        function test_constructor_rejects_duplicate_statement_adapters() external {
            vm.expectRevert(ChannelSettlementVerifier.DuplicatePinnedMleVerifier.selector);
            new ChannelSettlementVerifier(mockMle, withdrawalClaimMle, postCloseClaimMle, postCloseClaimMle);
        }

        /// Distinct adapter addresses must not disguise one shared statement core.
        function test_constructor_rejects_cross_statement_core_reuse() external {
            MockPinnedMleVerifierV2 sharedCore = new MockPinnedMleVerifierV2(TEST_CHAIN_ID);
            MockPinnedMleVerifierV2WithCore close = new MockPinnedMleVerifierV2WithCore(
                TEST_CHAIN_ID, address(sharedCore)
            );
            MockPinnedMleVerifierV2WithCore claim = new MockPinnedMleVerifierV2WithCore(
                TEST_CHAIN_ID, address(sharedCore)
            );

            vm.expectRevert(ChannelSettlementVerifier.DuplicatePinnedMleVerifier.selector);
            new ChannelSettlementVerifier(close, claim, postCloseClaimMle, cancelCloseMle);
        }

        /// No statement core may alias another statement's adapter address.
        function test_constructor_rejects_cross_statement_adapter_core_alias() external {
            MockPinnedMleVerifierV2 claimCore = new MockPinnedMleVerifierV2(TEST_CHAIN_ID);
            MockPinnedMleVerifierV2WithCore claim = new MockPinnedMleVerifierV2WithCore(
                TEST_CHAIN_ID, address(claimCore)
            );
            MockPinnedMleVerifierV2WithCore close = new MockPinnedMleVerifierV2WithCore(TEST_CHAIN_ID, address(claim));

            vm.expectRevert(ChannelSettlementVerifier.DuplicatePinnedMleVerifier.selector);
            new ChannelSettlementVerifier(close, claim, postCloseClaimMle, cancelCloseMle);
        }

        /// The adapter and the core it reports must both pin the executing chain.
        function test_constructor_rejects_core_chain_mismatch() external {
            MockPinnedMleVerifierV2 wrongChainCore = new MockPinnedMleVerifierV2(TEST_CHAIN_ID + 1);
            MockPinnedMleVerifierV2WithCore close =
                new MockPinnedMleVerifierV2WithCore(TEST_CHAIN_ID, address(wrongChainCore));

            vm.expectRevert(
                abi.encodeWithSelector(
                    ChannelSettlementVerifier.PinnedMleVerifierChainMismatch.selector,
                    address(wrongChainCore),
                    TEST_CHAIN_ID,
                    TEST_CHAIN_ID + 1
                )
            );
            new ChannelSettlementVerifier(close, withdrawalClaimMle, postCloseClaimMle, cancelCloseMle);
        }

        /// A constructor-pinned adapter cannot silently target a different chain.
        function test_constructor_rejects_wrong_chain_adapter() external {
            MockPinnedMleVerifierV2 wrongChain = new MockPinnedMleVerifierV2(TEST_CHAIN_ID + 1);
            vm.expectRevert(
                abi.encodeWithSelector(
                    ChannelSettlementVerifier.PinnedMleVerifierChainMismatch.selector,
                    address(wrongChain),
                    TEST_CHAIN_ID,
                    TEST_CHAIN_ID + 1
                )
            );
            new ChannelSettlementVerifier(wrongChain, withdrawalClaimMle, postCloseClaimMle, cancelCloseMle);
        }

        // =====================================================================
        // Phase C1 — cancel-close REAL verification (verifier-level)
        // =====================================================================

        /// @dev Build the 29-limb cancel vector + an accepting MleProof for the given args (member-set
        ///      commitment = the channel's registered set).
        function _cancelLimbs(bytes32 closeIntentDigest, uint64 revivedStateVersion, bytes32 revivedChannelStateDigest)
            internal
            view
            returns (uint256[] memory)
        {
            return verifier.expectedCancelCloseLimbs(
                CHANNEL_ID,
                closeIntentDigest,
                manager.registeredMemberSetCommitment(),
                12,
                revivedStateVersion,
                revivedChannelStateDigest
            );
        }

        /// GOLDEN- vector length + accepting proof: a proof whose publicInputs == expected 29 limbs
        /// passes verifyCancelClose (mock verdict=true).
        function test_verifyCancelClose_validProof_passes() external view {
            uint256[] memory pis = _cancelLimbs(keccak256("close"), 13, keccak256("revived"));
            assertEq(pis.length, 29, "cancel PI is 29 raw limbs");
            bytes memory proof = CloseTestLib.proofWithLimbs(pis);
            assertTrue(
                verifier.verifyCancelClose(
                    CHANNEL_ID,
                    keccak256("close"),
                    manager.registeredMemberSetCommitment(),
                    12,
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
            bytes memory proof = CloseTestLib.proofWithLimbs(pis);
            // Expected vector uses a DIFFERENT revived digest than the proof's limbs.
            vm.expectRevert(bytes("claim limb mismatch"));
            verifier.verifyCancelClose(CHANNEL_ID, keccak256("close"), msc, 12, 13, keccak256("OTHER_revived"), proof);
        }

        /// The closing-version operand is L1-injected and strict-bound; a prover cannot lower it to
        /// make an otherwise stale revived state satisfy the circuit comparison.
        function test_verifyCancelClose_tamperedCloseFinalVersion_reverts() external {
            bytes32 msc = manager.registeredMemberSetCommitment();
            uint256[] memory pis = _cancelLimbs(keccak256("close"), 13, keccak256("revived"));
            bytes memory proof = CloseTestLib.proofWithLimbs(pis);
            vm.expectRevert(bytes("claim limb mismatch"));
            verifier.verifyCancelClose(CHANNEL_ID, keccak256("close"), msc, 11, 13, keccak256("revived"), proof);
        }

        /// publicInputs.length != 29 ⇒ reverts on the length guard.
        function test_verifyCancelClose_wrongLength_reverts() external {
            bytes32 msc = manager.registeredMemberSetCommitment();
            uint256[] memory shortPis = new uint256[](28);
            bytes memory proof = CloseTestLib.proofWithLimbs(shortPis);
            vm.expectRevert(bytes("claim pi len"));
            verifier.verifyCancelClose(CHANNEL_ID, keccak256("close"), msc, 12, 13, keccak256("revived"), proof);
        }

        /// A limb >= 2**32 ⇒ reverts on the canonical-range guard.
        function test_verifyCancelClose_nonCanonicalLimb_reverts() external {
            bytes32 msc = manager.registeredMemberSetCommitment();
            uint256[] memory pis = _cancelLimbs(keccak256("close"), 13, keccak256("revived"));
            pis[0] = uint256(1) << 32; // 2**32, smallest non-canonical u32
            bytes memory proof = CloseTestLib.proofWithLimbs(pis);
            vm.expectRevert(bytes("claim limb range"));
            verifier.verifyCancelClose(CHANNEL_ID, keccak256("close"), msc, 12, 13, keccak256("revived"), proof);
        }

        /// The cancel adapter independently rejects a crypto-invalid proof.
        function test_verifyCancelClose_cryptoInvalid_reverts() external {
            uint256[] memory pis = _cancelLimbs(keccak256("close"), 13, keccak256("revived"));
            bytes memory proof = CloseTestLib.proofWithLimbs(pis);
            bytes32 memberSetCommitment = manager.registeredMemberSetCommitment();
            cancelCloseMle.setVerdict(false);
            vm.expectRevert(MockPinnedMleVerifierV2.MockMleVerificationRejected.selector);
            verifier.verifyCancelClose(
                CHANNEL_ID, keccak256("close"), memberSetCommitment, 12, 13, keccak256("revived"), proof
            );
            cancelCloseMle.setVerdict(true);
        }

        /// The constructor preserves the statement-to-adapter mapping without any mutable init seam.
        function test_constructor_pins_four_statement_adapters() external view {
            assertEq(address(verifier.closeMleVerifier()), address(mockMle));
            assertEq(address(verifier.withdrawalClaimMleVerifier()), address(withdrawalClaimMle));
            assertEq(address(verifier.postCloseClaimMleVerifier()), address(postCloseClaimMle));
            assertEq(address(verifier.cancelCloseMleVerifier()), address(cancelCloseMle));
            assertGt(address(mockMle).code.length, 0);
            assertGt(mockMle.core().code.length, 0);
            assertEq(mockMle.allowedChainId(), TEST_CHAIN_ID);
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
            address rcp = address(
                uint160(
                    (uint256(0x4000) << 128) | (uint256(0x4001) << 96) | (uint256(0x4002) << 64)
                        | (uint256(0x4003) << 32) | uint256(0x4004)
                )
            );
            bytes32 uad = _b32(0x5000);
            bytes32 nul = _b32(0x6000);
            uint64 amount = 0x0000001100000022;
            uint256[] memory v =
                verifier.expectedWithdrawalClaimLimbs(hex"0a0b0c0d", cid, h1, pkg, rcp, uad, amount, 7, 0xdeadbeef, nul);
            assertEq(v.length, 50);
            _assertB32(v, 0, 0x1000); // close_intent_digest
            assertEq(v[8], 0x0a0b0c0d); // channel_id
            _assertB32(v, 9, 0x2000); // final_balance_state_h1
            _assertB32(v, 17, 0x3000); // member_pk_g
            assertEq(v[25], 0x4000);
            assertEq(v[26], 0x4001);
            assertEq(v[27], 0x4002);
            assertEq(v[28], 0x4003); // recipient
            assertEq(v[29], 0x4004);
            _assertB32(v, 30, 0x5000); // user_amount_digest
            _assertB32(v, 38, 0x6000); // withdrawal_nullifier
            assertEq(v[46], 0x11); // amount (hi, lo)
            assertEq(v[47], 0x22);
            assertEq(v[48], 7); // token_slot (multi-token §N-6)
            assertEq(v[49], 0xdeadbeef); // token_index (resolved base token)
        }

        /// GOLDEN VECTOR mirror for post-close-claim (57 limbs; Stage 3: + finalBalanceStateH1 +
        /// finalSettledTxAccumulatorRoot appended; TM-16: + tokenIndex at limb 56).
        function test_expectedPostCloseClaimLimbs_goldenVector() external view {
            address rcp = address(
                uint160(
                    (uint256(0x4000) << 128) | (uint256(0x4001) << 96) | (uint256(0x4002) << 64)
                        | (uint256(0x4003) << 32) | uint256(0x4004)
                )
            );
            uint256[] memory v = verifier.expectedPostCloseClaimLimbs(
                hex"0a0b0c0d",
                _b32(0x1000),
                _b32(0x2000),
                _b32(0x3000),
                rcp,
                _b32(0x5000),
                0x0000001100000022,
                _b32(0x7000),
                _b32(0x8000),
                0xdeadbeef
            );
            assertEq(v.length, 57);
            _assertB32(v, 0, 0x1000); // close_intent_digest
            assertEq(v[8], 0x0a0b0c0d); // receiver_channel_id
            _assertB32(v, 9, 0x2000); // incoming_tx_hash
            _assertB32(v, 17, 0x3000); // receiver_pk_g
            assertEq(v[25], 0x4000); // recipient ends
            assertEq(v[29], 0x4004);
            _assertB32(v, 30, 0x5000); // shared_native_nullifier
            assertEq(v[38], 0x11); // amount
            assertEq(v[39], 0x22);
            _assertB32(v, 40, 0x7000); // final_balance_state_h1 (Stage 3)
            _assertB32(v, 48, 0x8000); // final_settled_tx_accumulator_root (Stage 3)
            assertEq(v[56], 0xdeadbeef); // token_index (TM-16, anchored base token)
        }

        /// GOLDEN VECTOR mirror for cancel-close (29 limbs). The Rust side asserts the SAME constant in
        /// src/circuits/channel/cancel_close_pis.rs
        /// (`cancel_close_public_inputs_match_solidity_shared_vector`). Same sentinels.
        /// Layout: channelId(1) | closeIntentDigest(8) | memberSetCommitment(8) |
        /// closeFinalStateVersion(2 hi,lo) | revivedStateVersion(2 hi,lo) |
        /// revivedChannelStateDigest(8).
        function test_expectedCancelCloseLimbs_goldenVector() external view {
            uint256[] memory v = verifier.expectedCancelCloseLimbs(
                hex"0a0b0c0d",
                _b32(0x1000), // closeIntentDigest
                _b32(0x2000), // memberSetCommitment
                0x0000003300000044, // closeFinalStateVersion (hi=0x33, lo=0x44)
                0x0000001100000022, // revivedStateVersion (hi=0x11, lo=0x22)
                _b32(0x3000) // revivedChannelStateDigest
            );
            assertEq(v.length, 29);
            assertEq(v[0], 0x0a0b0c0d); // channel_id
            _assertB32(v, 1, 0x1000); // close_intent_digest
            _assertB32(v, 9, 0x2000); // member_set_commitment
            assertEq(v[17], 0x33); // close_final_state_version hi
            assertEq(v[18], 0x44); // close_final_state_version lo
            assertEq(v[19], 0x11); // revived_state_version hi
            assertEq(v[20], 0x22); // revived_state_version lo
            _assertB32(v, 21, 0x3000); // revived_channel_state_digest
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
            bytes memory proof = _withdrawalClaimProof(tampered);
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
            bytes memory proof = _withdrawalClaimProof(tampered);
            vm.expectRevert(bytes("claim limb mismatch"));
            manager.submitWithdrawalClaim(c, proof);
        }

        /// Negative — non-canonical limb (>= 2**32) is rejected before the crypto check.
        function test_wclaim_nonCanonicalLimb_reverts() external {
            bytes32 d = _finalizeDefault();
            ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, USER_A, alice, 30);
            bytes memory proof = _withdrawalClaimProof(c);
            uint256[] memory publicInputs = abi.decode(proof, (uint256[]));
            publicInputs[0] = uint256(1) << 32; // 2**32, out of u32 range
            proof = CloseTestLib.proofWithLimbs(publicInputs);
            vm.expectRevert(bytes("claim limb range"));
            manager.submitWithdrawalClaim(c, proof);
        }

        /// Negative — wrong length publicInputs is rejected.
        function test_wclaim_wrongLength_reverts() external {
            bytes32 d = _finalizeDefault();
            ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, USER_A, alice, 30);
            bytes memory proof = CloseTestLib.proofWithLimbs(
                new uint256[](48) // != 50 (the pre-multitoken length)
            );
            vm.expectRevert(bytes("claim pi len"));
            manager.submitWithdrawalClaim(c, proof);
        }

        /// Negative — crypto-invalid (mock verdict false) is rejected even with correct limbs.
        function test_wclaim_cryptoInvalid_reverts() external {
            bytes32 d = _finalizeDefault();
            ChannelSettlementManager.WithdrawalClaim memory c = _withdrawalClaim(d, USER_A, alice, 30);
            bytes memory proof = _withdrawalClaimProof(c);
            withdrawalClaimMle.setVerdict(false);
            vm.expectRevert(MockPinnedMleVerifierV2.MockMleVerificationRejected.selector);
            manager.submitWithdrawalClaim(c, proof);
            withdrawalClaimMle.setVerdict(true);
        }

        /// C-2 (audit 2026-08-28) — supersedes the former "#8 double-claim within the post-close map"
        /// test. The `usedSharedNativeNullifiers` replay guard it exercised was never the binding
        /// constraint: the theft did not need to reuse a post-close nullifier at all, because the FIRST
        /// post-close claim already credits a delta the withdrawal claim credited under a DIFFERENT
        /// nullifier map (IMW2 vs IMCK). The entry point is disabled, so even the first call reverts.
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
            bytes memory proof1 = _postCloseClaimProof(pc);
            vm.expectRevert(ChannelSettlementManager.PostCloseClaimDisabled.selector);
            manager.submitPostCloseClaim(pc, proof1);
            assertEq(manager.withdrawalCredits(0, bob), 0, "not even the FIRST post-close credit lands");

            // And the second call is refused identically — the disable is unconditional, not a
            // once-per-nullifier guard.
            bytes memory proof2 = _postCloseClaimProof(pc);
            vm.expectRevert(ChannelSettlementManager.PostCloseClaimDisabled.selector);
            manager.submitPostCloseClaim(pc, proof2);
        }

        /// Negative (#8) — the manager must never bind an attacker-picked shared_native_nullifier. C-2
        /// (audit 2026-08-28): the entry point is disabled, so the refusal now happens BEFORE the strict
        /// limb bind is reached. Kept as a regression fence: if the stub is removed, this reverts with
        /// "claim limb mismatch" again rather than passing, and the mismatch is visible in the diff.
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
                CHANNEL_ID,
                d,
                pc.incomingTxHash,
                USER_B,
                bob,
                keccak256("forged"),
                pc.amount,
                manager.finalizedBalanceStateH1(),
                manager.finalizedSettledTxAccumulatorRoot(),
                0
            );
            bytes memory proof = CloseTestLib.proofWithLimbs(limbs);
            vm.expectRevert(ChannelSettlementManager.PostCloseClaimDisabled.selector);
            manager.submitPostCloseClaim(pc, proof);
        }
    }

    /// @dev Attacker that re-enters claimWithdrawalCredit on receiving ETH (reentrancy test).
    contract ReentrantClaimer {
        ChannelSettlementManager public mgr;
        bytes32 public withdrawalNullifier;
        uint256 public reenterCount;

        function setManager(ChannelSettlementManager m, bytes32 nullifier) external {
            mgr = m;
            withdrawalNullifier = nullifier;
        }

        function claim() external returns (uint256) {
            return mgr.claimWithdrawalCredit(withdrawalNullifier);
        }

        receive() external payable {
            if (reenterCount == 0) {
                reenterCount = 1;
                mgr.claimWithdrawalCredit(withdrawalNullifier); // reentrant attempt; reverts under nonReentrant
            }
        }
    }
