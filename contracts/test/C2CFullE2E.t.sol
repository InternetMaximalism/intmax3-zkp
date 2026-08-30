// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

/// @title Full real on-chain channel-to-channel lifecycle (manager-free, direct-to-EOA exit).
/// @notice Exercises, in one EVM run, the complete cross-channel flow the Sepolia run will perform:
///           register(ch1) -> postBlock(b0) -> deposit{value} -> postBlock(b1) -> register(ch2) ->
///           postBlock(b2) -> postBlock(b3, ch1->ch2 transfer) -> postBlock(b4, ch2 withdrawal) ->
///           finalize(validity proof, sub 4) -> withdrawNative(ch2's withdrawal proof, recipient=EOA)
///           -> withdraw() pays real ETH to the EOA.
///         This is the strongest local de-risk before spending real Sepolia ETH + 5x1ETH stakes:
///         it verifies BOTH real MLE/WHIR proofs (validity + ch2 withdrawal) against the cumulative
///         registration + deposit chains, with ch2's received funds exiting to L1 as native ETH.
/// @dev Fixtures from `cargo run --release --bin generate_c2c_fixture`. Self-skips if absent.
contract C2CFullE2ETest is Test {
    MleVerifier public verifier;
    IntmaxRollup public rollup;
    address public fraudTreasury = makeAddr("fraudTreasury");
    address public poster = makeAddr("poster");

    string internal lc;
    string internal validityMleJson;
    string internal withdrawalMleJson;
    string internal payoutJson;
    bool internal ready;

    uint256 internal constant STAKE = 1 ether; // POST_BLOCK_STAKE

    function setUp() public {
        string memory root = string.concat(vm.projectRoot(), "/test/data/");
        try vm.readFile(string.concat(root, "c2c_withdrawal_payout.json")) returns (string memory p) {
            payoutJson = p;
            lc = vm.readFile(string.concat(root, "c2c_lifecycle.json"));
            validityMleJson = vm.readFile(string.concat(root, "c2c_lifecycle_validity_mle.json"));
            withdrawalMleJson = vm.readFile(string.concat(root, "c2c_withdrawal_mle.json"));
            ready = true;
        } catch {
            ready = false;
            return;
        }

        verifier = new MleVerifier();
        FixtureLib.DeployData memory vdd = FixtureLib.parseDeployData(validityMleJson);
        IntmaxRollup.MleVk memory vvk = FixtureLib.buildMleVk(validityMleJson, verifier);
        bytes32 genesis = vm.parseJsonBytes32(lc, ".genesis_state_root");
        rollup = new IntmaxRollup(
            fraudTreasury, vvk, vdd.whirParams, vdd.protocolId, vdd.sessionId,
            vdd.kIs, vdd.subgroupGenPowers, verifier, genesis,
            true // A-2: test opt-in for the degreeBits==0 bypass
        );
        rollup.setBlockProducer(poster, true); // permissioned posting
        FixtureLib.DeployData memory wdd = FixtureLib.parseDeployData(withdrawalMleJson);
        IntmaxRollup.MleVk memory wvk = FixtureLib.buildMleVk(withdrawalMleJson, verifier);
        rollup.initializeWithdrawalVk(wvk, wdd.whirParams, wdd.protocolId, wdd.sessionId, wdd.kIs, wdd.subgroupGenPowers);
    }

    function test_c2c_fullLifecycle_receiverExitsToL1() public {
        if (!ready) { vm.skip(true); return; }

        bytes32[] memory blobs = new bytes32[](1);
        blobs[0] = keccak256("c2c_full");
        vm.blobhashes(blobs);
        vm.deal(poster, 10 ether);

        bytes32 finalStateRoot = vm.parseJsonBytes32(lc, ".final_state_root");
        bytes32 proofHash = vm.parseJsonBytes32(lc, ".proof_hash");
        uint32 proofLength = uint32(vm.parseJsonUint(lc, ".proof_length"));

        // --- cumulative reg+deposit chain ordering (matches C2CBlockHash.t.sol + Sepolia driver) ---
        _register(".registration1");
        _postRound(0, proofHash, proofLength, finalStateRoot);
        _deposit();
        _postRound(1, proofHash, proofLength, finalStateRoot);
        _register(".registration2");
        _postRound(2, proofHash, proofLength, finalStateRoot);
        _postRound(3, proofHash, proofLength, finalStateRoot); // ch1->ch2 transfer block
        uint256 finalSubId = _postRound(4, proofHash, proofLength, finalStateRoot); // ch2 withdrawal block

        assertEq(rollup.totalEscrowed(), 10, "escrow holds the ch1 deposit");

        // --- finalize the 5-block chain with the REAL validity MLE proof ---
        IntmaxRollup.ValidityPublicInputs memory vpis = _parseVpis();
        MleVerifier.MleProof memory vproof = FixtureLib.parseProof(validityMleJson);
        assertTrue(rollup.finalize(finalSubId, finalStateRoot, vpis, vproof), "finalize failed (real validity MLE)");
        assertEq(rollup.latestFinalizedStateRoot(), finalStateRoot, "finalized state root mismatch");
        assertEq(rollup.blockHashChainAt(5), vpis.finalBlockChain, "blockHashChainAt[5] != proved final_block_chain");

        // --- ch2 exits its received funds to L1 via the REAL withdrawal MLE proof, recipient = EOA ---
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        address recipient = ws[0].recipient; // baked EOA
        uint256 amount = ws[0].amount;
        assertEq(amount, 3, "ch2 received 3 wei across the channel-to-channel transfer");

        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);
        rollup.withdrawNative(ws, prover, wproof);
        assertEq(rollup.pendingWithdrawals(recipient), amount, "EOA credited the cross-channel amount");
        assertEq(rollup.totalEscrowed(), 10 - amount, "escrow decreased by exactly the withdrawn amount");

        // --- pull payment: the receiver (EOA) collects real ETH ---
        uint256 balBefore = recipient.balance;
        vm.prank(recipient);
        rollup.withdraw();
        assertEq(recipient.balance, balBefore + amount, "receiver got real ETH from the channel-to-channel exit");
        assertEq(rollup.pendingWithdrawals(recipient), 0, "credit cleared");
    }

    /// POST_BLOCK_STAKE recovery, and the stranded-stake lesson from the 2026-06-14 Sepolia run.
    /// @notice Every `postBlockAndSubmit` locks exactly 1 ETH (POST_BLOCK_STAKE), refunded ONLY by
    ///         `finalize()`-ing THAT submission (`_refundStake`, the sole refund path — there is no
    ///         standalone reclaim). `finalize` requires `initialExtCommitment == latestFinalizedStateRoot`
    ///         and advances it monotonically, so ONE aggregate genesis->blockN proof finalizes ONE
    ///         submission and refunds ONE stake; the other postBlock submissions stay locked.
    ///         To recover EVERY stake you must finalize EACH submission incrementally (a proof per
    ///         [latest -> that submission's block boundary]) OR post fewer submissions by batching
    ///         multiple SubBlocks into a single postBlockAndSubmit call (one stake per call, not per
    ///         block). This test pins both the working refund->withdraw path AND the stranding so a
    ///         future run never silently burns stakes again.
    function test_c2c_postBlockStakes_recovery_and_strandedLesson() public {
        if (!ready) { vm.skip(true); return; }

        bytes32[] memory blobs = new bytes32[](1);
        blobs[0] = keccak256("c2c_stake");
        vm.blobhashes(blobs);
        vm.deal(poster, 10 ether);

        bytes32 finalStateRoot = vm.parseJsonBytes32(lc, ".final_state_root");
        bytes32 proofHash = vm.parseJsonBytes32(lc, ".proof_hash");
        uint32 proofLength = uint32(vm.parseJsonUint(lc, ".proof_length"));

        _register(".registration1");
        _postRound(0, proofHash, proofLength, finalStateRoot);
        _deposit();
        _postRound(1, proofHash, proofLength, finalStateRoot);
        _register(".registration2");
        _postRound(2, proofHash, proofLength, finalStateRoot);
        _postRound(3, proofHash, proofLength, finalStateRoot);
        uint256 finalSubId = _postRound(4, proofHash, proofLength, finalStateRoot);

        // Poster locked 5 stakes (one per postBlockAndSubmit call).
        assertEq(poster.balance, 10 ether - 5 * STAKE, "poster locked 5 x POST_BLOCK_STAKE");
        for (uint256 i = 0; i <= 4; i++) {
            (address submitter, bool spent) = rollup.stakeInfo(i);
            assertEq(submitter, poster, "submission staked by poster");
            assertFalse(spent, "stake not yet spent/refunded");
        }

        // Finalize the aggregate genesis->block5 proof: refunds EXACTLY the finalized submission's stake.
        IntmaxRollup.ValidityPublicInputs memory vpis = _parseVpis();
        MleVerifier.MleProof memory vproof = FixtureLib.parseProof(validityMleJson);
        assertTrue(rollup.finalize(finalSubId, finalStateRoot, vpis, vproof), "finalize failed");

        // --- WORKING RECOVERY PATH: finalized submission's stake is credited to the poster, then pulled. ---
        assertEq(rollup.pendingWithdrawals(poster), STAKE, "finalized submission's stake refunded to poster");
        uint256 balBefore = poster.balance;
        vm.prank(poster);
        rollup.withdraw();
        assertEq(poster.balance, balBefore + STAKE, "poster pulled the refunded stake as real ETH");
        (address s4, bool spent4) = rollup.stakeInfo(finalSubId);
        assertEq(s4, address(0), "finalized submission's stakeInfo cleared");
        assertFalse(spent4, "stakeInfo deleted on refund");

        // --- STRANDED LESSON: the other four postBlock stakes stay locked. ---
        // The same aggregate proof CANNOT refund them: finalize now requires initialExtCommitment ==
        // latestFinalizedStateRoot (advanced to block5), but the proof's initial commitment is genesis.
        for (uint256 i = 0; i < 4; i++) {
            (address submitter, bool spent) = rollup.stakeInfo(i);
            assertEq(submitter, poster, "un-finalized submission stake still locked");
            assertFalse(spent, "un-finalized stake not refunded");
        }
        assertFalse(
            rollup.finalize(0, finalStateRoot, vpis, vproof),
            "re-finalizing with the same genesis->block5 proof must fail: latestFinalizedStateRoot already advanced"
        );
        assertEq(rollup.pendingWithdrawals(poster), 0, "no further stake recoverable with this proof");
    }

    // ─── helpers ───────────────────────────────────────────────────────────

    function _register(string memory key) internal {
        uint32 channelId = uint32(vm.parseJsonUint(lc, string.concat(key, ".channel_id")));
        uint8 bpSlot = uint8(vm.parseJsonUint(lc, string.concat(key, ".bp_member_slot")));
        bytes32[] memory sphincs = vm.parseJsonBytes32Array(lc, string.concat(key, ".member_pk_gs"));
        bytes32[] memory pkBs = vm.parseJsonBytes32Array(lc, string.concat(key, ".member_pk_bs"));
        bytes32[] memory regev = vm.parseJsonBytes32Array(lc, string.concat(key, ".regev_pk_digests"));
        address[] memory recipients = vm.parseJsonAddressArray(lc, string.concat(key, ".recipients"));
        rollup.registerChannel(channelId, bpSlot, 0, sphincs, pkBs, regev, recipients);
    }

    function _deposit() internal {
        address depositor = vm.parseJsonAddress(lc, ".deposit.depositor");
        bytes32 recipient = vm.parseJsonBytes32(lc, ".deposit.recipient");
        uint32 tokenIndex = uint32(vm.parseJsonUint(lc, ".deposit.token_index"));
        uint256 amount = vm.parseUint(vm.parseJsonString(lc, ".deposit.amount"));
        bytes32 auxData = vm.parseJsonBytes32(lc, ".deposit.aux_data");
        vm.deal(depositor, amount);
        vm.prank(depositor);
        rollup.deposit{value: amount}(recipient, tokenIndex, amount, auxData);
    }

    function _postRound(uint256 i, bytes32 proofHash, uint32 proofLength, bytes32 stateRoot)
        internal
        returns (uint256 subId)
    {
        string memory base = string.concat(".blocks[", vm.toString(i), "]");
        uint256[] memory keyIdsU = FixtureLib.parseUintArray(lc, string.concat(base, ".key_ids"));
        uint32[] memory keyIds = new uint32[](keyIdsU.length);
        for (uint256 j = 0; j < keyIdsU.length; j++) keyIds[j] = uint32(keyIdsU[j]);
        IntmaxRollup.SubBlock[] memory sb = new IntmaxRollup.SubBlock[](1);
        sb[0] = IntmaxRollup.SubBlock({
            channelId: uint32(vm.parseJsonUint(lc, string.concat(base, ".channel_id"))),
            timestamp: uint64(vm.parseJsonUint(lc, string.concat(base, ".timestamp"))),
            txTreeRoot: vm.parseJsonBytes32(lc, string.concat(base, ".tx_tree_root")),
            keyIds: keyIds
        });
        subId = rollup.nextSubmissionId();
        vm.prank(poster);
        rollup.postBlockAndSubmit{value: STAKE}(sb, proofHash, proofLength, stateRoot);
    }

    function _parseVpis() internal view returns (IntmaxRollup.ValidityPublicInputs memory vpis) {
        vpis.initialBlockNumber = uint64(vm.parseJsonUint(lc, ".vpis.initial_block_number"));
        vpis.initialBlockChain = vm.parseJsonBytes32(lc, ".vpis.initial_block_chain");
        vpis.initialExtCommitment = vm.parseJsonBytes32(lc, ".vpis.initial_ext_commitment");
        vpis.finalBlockNumber = uint64(vm.parseJsonUint(lc, ".vpis.final_block_number"));
        vpis.finalBlockChain = vm.parseJsonBytes32(lc, ".vpis.final_block_chain");
        vpis.finalExtCommitment = vm.parseJsonBytes32(lc, ".vpis.final_ext_commitment");
        vpis.prover = vm.parseJsonAddress(lc, ".vpis.prover");
    }

    function _parsePayout() internal view returns (IntmaxRollup.Withdrawal[] memory ws, address prover) {
        prover = vm.parseJsonAddress(payoutJson, ".withdrawal_prover");
        ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = IntmaxRollup.Withdrawal({
            recipient: vm.parseJsonAddress(payoutJson, ".withdrawals[0].recipient"),
            tokenIndex: uint32(vm.parseJsonUint(payoutJson, ".withdrawals[0].token_index")),
            amount: vm.parseUint(vm.parseJsonString(payoutJson, ".withdrawals[0].amount")),
            nullifier: vm.parseJsonBytes32(payoutJson, ".withdrawals[0].nullifier"),
            auxData: vm.parseJsonBytes32(payoutJson, ".withdrawals[0].aux_data")
        });
    }
}
