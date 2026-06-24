// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

/// @title Full real on-chain native-ETH withdrawal payout (Phase 2).
/// @notice Exercises, in one EVM run, the complete honest lifecycle:
///           registerChannel -> deposit{value} -> postBlock x3 -> finalize(validity proof)
///           -> withdrawNative(withdrawal proof) -> withdraw() pays real ETH.
///         The withdrawal payout is bound to the finalized state by a REAL MLE/WHIR proof
///         (separate withdrawal VK) + the on-chain keccak re-fold of the withdrawal set.
/// @dev Fixtures produced by `cargo run --bin generate_withdrawal_fixture --release`:
///        - lifecycle.json               (registration / deposit / blocks / vpis)
///        - lifecycle_validity_mle.json  (validity MLE proof + VK, for finalize)
///        - withdrawal_mle.json          (withdrawal MLE proof + VK, for withdrawNative)
///        - withdrawal_payout.json       (the committed Withdrawal[] + prover)
///      If the fixtures are absent (heavy proving not yet run), every test self-skips.
contract WithdrawNativeE2ETest is Test {
    MleVerifier public verifier;
    IntmaxRollup public rollup;
    address public fraudTreasury = makeAddr("fraudTreasury");
    address public poster = makeAddr("poster");

    string internal lifecycleJson;
    string internal validityMleJson;
    string internal withdrawalMleJson;
    string internal payoutJson;
    bool internal fixturesReady;

    uint256 internal constant STAKE = 1 ether; // POST_BLOCK_STAKE

    function setUp() public {
        // Load fixtures; if any is missing the heavy proving step hasn't run yet — self-skip.
        string memory root = string.concat(vm.projectRoot(), "/test/data/");
        try vm.readFile(string.concat(root, "withdrawal_payout.json")) returns (string memory p) {
            payoutJson = p;
            lifecycleJson = vm.readFile(string.concat(root, "lifecycle.json"));
            validityMleJson = vm.readFile(string.concat(root, "lifecycle_validity_mle.json"));
            withdrawalMleJson = vm.readFile(string.concat(root, "withdrawal_mle.json"));
            fixturesReady = true;
        } catch {
            fixturesReady = false;
            return;
        }

        verifier = new MleVerifier();

        // Deploy with the VALIDITY VK (degreeBits > 0) + genesis state root.
        FixtureLib.DeployData memory vdd = FixtureLib.parseDeployData(validityMleJson);
        IntmaxRollup.MleVk memory vvk = FixtureLib.buildMleVk(validityMleJson, verifier);
        bytes32 genesis = vm.parseJsonBytes32(lifecycleJson, ".genesis_state_root");
        // msg.sender at construction (this test contract) becomes `deployer`.
        rollup = new IntmaxRollup(
            fraudTreasury, vvk, vdd.whirParams, vdd.protocolId, vdd.sessionId,
            vdd.kIs, vdd.subgroupGenPowers, verifier, genesis,
            true // A-2: test opt-in for the degreeBits==0 bypass
        );

        // Set the WITHDRAWAL VK (deployer-only, set-once). deployer == this test contract.
        FixtureLib.DeployData memory wdd = FixtureLib.parseDeployData(withdrawalMleJson);
        IntmaxRollup.MleVk memory wvk = FixtureLib.buildMleVk(withdrawalMleJson, verifier);
        rollup.initializeWithdrawalVk(wvk, wdd.whirParams, wdd.protocolId, wdd.sessionId, wdd.kIs, wdd.subgroupGenPowers);
    }

    // ───────────────────────────────────────────────────────────────────────
    //  Happy path
    // ───────────────────────────────────────────────────────────────────────

    function test_withdrawNative_fullLifecycle() public {
        if (!fixturesReady) { vm.skip(true); return; }

        _runLifecycleThroughFinalize();

        // --- withdrawNative ---
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        address recipient = ws[0].recipient;
        uint256 amount = ws[0].amount;

        uint256 escrowBefore = rollup.totalEscrowed();
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);

        rollup.withdrawNative(ws, prover, wproof);

        assertEq(rollup.pendingWithdrawals(recipient), amount, "recipient credited exact amount");
        assertEq(rollup.totalEscrowed(), escrowBefore - amount, "escrow decreased by exactly amount");
        assertTrue(rollup.withdrawalNullifierUsed(ws[0].nullifier), "nullifier marked used");

        // --- pull payment: recipient claims real ETH ---
        uint256 balBefore = recipient.balance;
        vm.prank(recipient);
        rollup.withdraw();
        assertEq(recipient.balance, balBefore + amount, "recipient received real ETH");
        assertEq(rollup.pendingWithdrawals(recipient), 0, "credit cleared after withdraw");
    }

    // ───────────────────────────────────────────────────────────────────────
    //  Negative cases
    // ───────────────────────────────────────────────────────────────────────

    /// Double-spend: paying the same withdrawal twice must revert on the nullifier.
    function test_withdrawNative_doubleSpend_reverts() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);

        rollup.withdrawNative(ws, prover, wproof); // first ok
        vm.expectRevert(IntmaxRollup.WithdrawalNullifierUsed.selector);
        rollup.withdrawNative(ws, prover, wproof); // replay rejected
    }

    /// ext_commitment mismatch: calling before finalize (latestFinalizedStateRoot == genesis)
    /// must revert — the withdrawal is not anchored to the finalized state.
    function test_withdrawNative_beforeFinalize_reverts() public {
        if (!fixturesReady) { vm.skip(true); return; }
        // Do NOT run finalize; latestFinalizedStateRoot is still the genesis root.
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);
        vm.expectRevert(IntmaxRollup.WithdrawalExtCommitmentMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
    }

    /// Tampered withdrawal set: mutating an amount breaks the pis_hash re-fold binding.
    function test_withdrawNative_tamperedAmount_reverts() public {
        if (!fixturesReady) { vm.skip(true); return; }
        _runLifecycleThroughFinalize();
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        ws[0].amount += 1; // tamper
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);
        vm.expectRevert(IntmaxRollup.WithdrawalPublicInputsMismatch.selector);
        rollup.withdrawNative(ws, prover, wproof);
    }

    /// A fresh rollup whose withdrawal VK was never initialized must reject withdrawNative.
    function test_withdrawNative_vkNotSet_reverts() public {
        if (!fixturesReady) { vm.skip(true); return; }
        // Deploy a bare rollup (validity VK only; never initialize the withdrawal VK).
        FixtureLib.DeployData memory vdd = FixtureLib.parseDeployData(validityMleJson);
        IntmaxRollup.MleVk memory vvk = FixtureLib.buildMleVk(validityMleJson, verifier);
        bytes32 genesis = vm.parseJsonBytes32(lifecycleJson, ".genesis_state_root");
        IntmaxRollup bare = new IntmaxRollup(
            fraudTreasury, vvk, vdd.whirParams, vdd.protocolId, vdd.sessionId,
            vdd.kIs, vdd.subgroupGenPowers, verifier, genesis,
            true // A-2: test opt-in for the degreeBits==0 bypass
        );
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(withdrawalMleJson);
        vm.expectRevert(IntmaxRollup.WithdrawalVkNotSet.selector);
        bare.withdrawNative(ws, prover, wproof);
    }

    /// initializeWithdrawalVk is deployer-only and set-once.
    function test_initializeWithdrawalVk_access_and_setOnce() public {
        if (!fixturesReady) { vm.skip(true); return; }
        FixtureLib.DeployData memory wdd = FixtureLib.parseDeployData(withdrawalMleJson);
        IntmaxRollup.MleVk memory wvk = FixtureLib.buildMleVk(withdrawalMleJson, verifier);

        // Non-deployer rejected.
        vm.prank(makeAddr("attacker"));
        vm.expectRevert(bytes("only deployer"));
        rollup.initializeWithdrawalVk(wvk, wdd.whirParams, wdd.protocolId, wdd.sessionId, wdd.kIs, wdd.subgroupGenPowers);

        // Deployer second call rejected (set-once latch; rollup VK already set in setUp).
        vm.expectRevert(bytes("withdrawal vk already set"));
        rollup.initializeWithdrawalVk(wvk, wdd.whirParams, wdd.protocolId, wdd.sessionId, wdd.kIs, wdd.subgroupGenPowers);
    }

    // ───────────────────────────────────────────────────────────────────────
    //  Lifecycle driver
    // ───────────────────────────────────────────────────────────────────────

    /// Reproduce on-chain exactly the registration -> deposit -> 3 blocks -> finalize sequence the
    /// Rust prover proved, leaving `latestFinalizedStateRoot == lifecycle.final_state_root`.
    function _runLifecycleThroughFinalize() internal {
        // Mock a non-zero blob for every postBlockAndSubmit (reads blobhash(0)).
        bytes32[] memory blobs = new bytes32[](1);
        blobs[0] = keccak256("withdraw_native_blob");
        vm.blobhashes(blobs);
        vm.deal(poster, 10 ether);

        bytes32 finalStateRoot = vm.parseJsonBytes32(lifecycleJson, ".final_state_root");
        bytes32 proofHash = vm.parseJsonBytes32(lifecycleJson, ".proof_hash");
        uint32 proofLength = uint32(vm.parseJsonUint(lifecycleJson, ".proof_length"));

        // 1. Registration (must precede block 1 so its reg chain is folded in).
        _registerChannel();
        _postRound(0, proofHash, proofLength, finalStateRoot);

        // 2. Deposit (must precede block 2; pranked as the proved depositor so the deposit hash
        //    — which folds msg.sender — matches the proved chain). Escrows real ETH.
        _depositFromFixture();
        _postRound(1, proofHash, proofLength, finalStateRoot);

        // 3. Withdrawal block. The submission for the LAST block is the one we finalize.
        uint256 finalSubId = _postRound(2, proofHash, proofLength, finalStateRoot);

        // 4. Finalize the full 3-block chain with the real validity MLE proof.
        IntmaxRollup.ValidityPublicInputs memory vpis = _parseVpis();
        MleVerifier.MleProof memory vproof = FixtureLib.parseProof(validityMleJson);
        bool ok = rollup.finalize(finalSubId, finalStateRoot, vpis, vproof);
        assertTrue(ok, "finalize failed (real validity MLE)");
        assertEq(rollup.latestFinalizedStateRoot(), finalStateRoot, "finalized state root mismatch");
    }

    function _registerChannel() internal {
        uint32 channelId = uint32(vm.parseJsonUint(lifecycleJson, ".registration.channel_id"));
        uint8 bpSlot = uint8(vm.parseJsonUint(lifecycleJson, ".registration.bp_member_slot"));
        bytes32[] memory sphincs = vm.parseJsonBytes32Array(lifecycleJson, ".registration.member_pk_gs");
        bytes32[] memory pkBs = vm.parseJsonBytes32Array(lifecycleJson, ".registration.member_pk_bs");
        bytes32[] memory regev = vm.parseJsonBytes32Array(lifecycleJson, ".registration.regev_pk_digests");
        address[] memory recipients = vm.parseJsonAddressArray(lifecycleJson, ".registration.recipients");
        rollup.registerChannel(channelId, bpSlot, 0, sphincs, pkBs, regev, recipients);
    }

    function _depositFromFixture() internal {
        address depositor = vm.parseJsonAddress(lifecycleJson, ".deposit.depositor");
        bytes32 recipient = vm.parseJsonBytes32(lifecycleJson, ".deposit.recipient");
        uint32 tokenIndex = uint32(vm.parseJsonUint(lifecycleJson, ".deposit.token_index"));
        uint256 amount = vm.parseUint(vm.parseJsonString(lifecycleJson, ".deposit.amount"));
        bytes32 auxData = vm.parseJsonBytes32(lifecycleJson, ".deposit.aux_data");
        vm.deal(depositor, amount);
        vm.prank(depositor);
        rollup.deposit{value: amount}(recipient, tokenIndex, amount, auxData);
    }

    /// Post block index `i` (0-based into lifecycle.blocks) as its own posting round; return the
    /// submission id.
    function _postRound(uint256 i, bytes32 proofHash, uint32 proofLength, bytes32 stateRoot)
        internal
        returns (uint256 subId)
    {
        IntmaxRollup.SubBlock[] memory subBlocks = new IntmaxRollup.SubBlock[](1);
        subBlocks[0] = _subBlock(i);
        subId = rollup.nextSubmissionId();
        vm.prank(poster);
        rollup.postBlockAndSubmit{value: STAKE}(subBlocks, proofHash, proofLength, stateRoot);
    }

    function _subBlock(uint256 i) internal view returns (IntmaxRollup.SubBlock memory sb) {
        string memory base = string.concat(".blocks[", vm.toString(i), "]");
        uint256[] memory keyIdsU = FixtureLib.parseUintArray(lifecycleJson, string.concat(base, ".key_ids"));
        uint32[] memory keyIds = new uint32[](keyIdsU.length);
        for (uint256 j = 0; j < keyIdsU.length; j++) {
            keyIds[j] = uint32(keyIdsU[j]);
        }
        sb = IntmaxRollup.SubBlock({
            channelId: uint32(vm.parseJsonUint(lifecycleJson, string.concat(base, ".channel_id"))),
            timestamp: uint64(vm.parseJsonUint(lifecycleJson, string.concat(base, ".timestamp"))),
            txTreeRoot: vm.parseJsonBytes32(lifecycleJson, string.concat(base, ".tx_tree_root")),
            keyIds: keyIds
        });
    }

    function _parseVpis() internal view returns (IntmaxRollup.ValidityPublicInputs memory vpis) {
        vpis.initialBlockNumber = uint64(vm.parseJsonUint(lifecycleJson, ".vpis.initial_block_number"));
        vpis.initialBlockChain = vm.parseJsonBytes32(lifecycleJson, ".vpis.initial_block_chain");
        vpis.initialExtCommitment = vm.parseJsonBytes32(lifecycleJson, ".vpis.initial_ext_commitment");
        vpis.finalBlockNumber = uint64(vm.parseJsonUint(lifecycleJson, ".vpis.final_block_number"));
        vpis.finalBlockChain = vm.parseJsonBytes32(lifecycleJson, ".vpis.final_block_chain");
        vpis.finalExtCommitment = vm.parseJsonBytes32(lifecycleJson, ".vpis.final_ext_commitment");
        vpis.prover = vm.parseJsonAddress(lifecycleJson, ".vpis.prover");
    }

    function _parsePayout()
        internal
        view
        returns (IntmaxRollup.Withdrawal[] memory ws, address prover)
    {
        prover = vm.parseJsonAddress(payoutJson, ".withdrawal_prover");
        // Count entries.
        uint256 n = 0;
        while (true) {
            string memory p = string.concat(".withdrawals[", vm.toString(n), "].recipient");
            try vm.parseJsonAddress(payoutJson, p) returns (address) {
                n++;
            } catch {
                break;
            }
        }
        ws = new IntmaxRollup.Withdrawal[](n);
        for (uint256 i = 0; i < n; i++) {
            string memory b = string.concat(".withdrawals[", vm.toString(i), "]");
            ws[i] = IntmaxRollup.Withdrawal({
                recipient: vm.parseJsonAddress(payoutJson, string.concat(b, ".recipient")),
                tokenIndex: uint32(vm.parseJsonUint(payoutJson, string.concat(b, ".token_index"))),
                amount: vm.parseUint(vm.parseJsonString(payoutJson, string.concat(b, ".amount"))),
                nullifier: vm.parseJsonBytes32(payoutJson, string.concat(b, ".nullifier")),
                auxData: vm.parseJsonBytes32(payoutJson, string.concat(b, ".aux_data"))
            });
        }
    }
}
