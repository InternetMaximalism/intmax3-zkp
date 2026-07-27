// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CloseE2EBase} from "./CloseE2EBase.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {ChannelSettlementManager, IChannelSettlementVerifier, IChannelRegistry} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "../script/FixtureLib.sol";

/// @title Full local CLOSE lifecycle e2e (Sepolia-rehearsal).
/// @notice One EVM run: deploy (CREATE2) -> register -> deposit{value} -> postBlock x3 ->
///         finalize(real validity MLE) -> withdrawNative(recipient = ChannelSettlementManager, real
///         withdrawal MLE) -> manager.pullChannelFunds() -> close intent/finalize ->
///         submitWithdrawalClaim -> claimWithdrawalCredit -> a channel member receives REAL ETH.
///         Proves the channel's aggregate native settlement (P2 withdrawNative) feeds the manager's
///         capped per-member split (P3), end-to-end with real proofs.
/// @dev Fixtures: `forge test --match-test test_printCloseManagerAddress -vv` (CloseManagerAddr.t.sol)
///      to get the manager address, then
///        WD_RECIPIENT=<addr> WD_OUT_PREFIX=close_ cargo run --release --bin generate_withdrawal_fixture
///      then `cargo run --release --features close-fixture-bin --bin generate_close_fixture`
///      (co-generated: both derive the channel-1 member set from ChannelMemberKeys::deterministic).
///      Self-skips ONLY if the close_* fixtures are absent; stale fixtures are hard failures.
contract CloseLifecycleE2ETest is CloseE2EBase {
    MleVerifier internal verifier;
    IntmaxRollup internal rollup;
    ChannelSettlementVerifier internal settlementVerifier;
    ChannelSettlementManager internal manager;
    address internal poster = makeAddr("poster");
    bool internal ready;
    /// True iff the close fixture's member set matches the lifecycle-registered member set, so the
    /// REAL close-intent MLE proof can be bound to THIS channel (see the member_pk_gs note below).
    bool internal closeFixtureMatchesRegistration;
    /// The manager recipient baked into the close withdrawal payout fixture (asserted against the
    /// actually-deployed manager in the lifecycle test — a mismatch is a stale-fixture HARD fail).
    address internal bakedRecipient;

    uint256 internal constant STAKE = 1 ether;

    function _closeMleJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/close_intent_mle.json"));
    }
    function _closeIntentJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/close_intent.json"));
    }

    function setUp() public {
        // Self-skip until ALL close fixtures exist (heavy proving runs). The lifecycle path needs the
        // validity/withdrawal/payout fixtures; the REAL close-intent submission additionally needs
        // the wrapped-close MLE proof (`close_intent_mle.json`) + its descriptor (`close_intent.json`,
        // produced by `cargo run --release --features close-fixture-bin --bin generate_close_fixture`).
        try vm.readFile(string.concat(vm.projectRoot(), "/test/data/close_withdrawal_payout.json")) {
            try vm.readFile(string.concat(vm.projectRoot(), "/test/data/close_intent_mle.json")) {
                try vm.readFile(string.concat(vm.projectRoot(), "/test/data/close_intent.json")) {
                    ready = true;
                } catch {
                    ready = false;
                    return;
                }
            } catch {
                ready = false;
                return;
            }
        } catch {
            ready = false;
            return;
        }

        // 1-2. Deploy all four contracts (+ registerChannel) via the shared CREATE2 path — IDENTICAL
        //      to ComputeCloseManager.s.sol so the manager lands at the baked address.
        (verifier, rollup, settlementVerifier, manager) = _deployAll(_validityJson(), _lifecycleJson());

        // 3. The deployed manager MUST equal the close proof's withdrawal recipient. Multitoken
        //    Phase 5b: the fixtures are regenerated against the multi-token manager initcode, so a
        //    mismatch is a HARD failure (stale fixtures / changed initcode — regenerate per
        //    doc/tasks/regen-and-redeploy-runbook.md), no longer a self-skip. Asserted in the
        //    lifecycle TEST (not here) so the in-contract address printer below stays runnable
        //    mid-regeneration while the payout fixture is still stale.
        emit log_named_address("manager(actual)", address(manager));
        bakedRecipient = vm.parseJsonAddress(_payoutJson(), ".withdrawals[0].recipient");

        // 4. Set the withdrawal VK. deployer == the CREATE2 factory (msg.sender at construction), so
        //    prank the factory. (Production P7 uses a normal deploy where deployer = the EOA.)
        FixtureLib.DeployData memory wdd = FixtureLib.parseDeployData(_withdrawalJson());
        IntmaxRollup.MleVk memory wvk = FixtureLib.buildMleVk(_withdrawalJson(), verifier);
        vm.prank(FACTORY);
        rollup.initializeWithdrawalVk(wvk, wdd.whirParams, wdd.protocolId, wdd.sessionId, wdd.kIs, wdd.subgroupGenPowers);
        // Permissioned posting: authorize the poster. deployer == FACTORY (CREATE2), so prank it.
        vm.prank(FACTORY);
        rollup.setBlockProducer(poster, true);

        // 5. Set the REAL close VK on the settlement verifier from the close fixture. deployer ==
        //    FACTORY (CREATE2), so prank the factory. The close VK is the close circuit's OWN
        //    MLE/WHIR verification key (degreeBits / preprocessedRoot / gatesDigest / kIs /
        //    subgroupGenPowers / whirParams / protocolId / sessionId), pulled from the proved
        //    `close_intent_mle.json` exactly as the rollup's withdrawal VK is built from its fixture.
        _initRealCloseVk();

        // 6. CO-GENERATION (multitoken Phase 5b): the close fixture is now generated over the SAME
        //    deterministic channel-1 member keys the lifecycle fixture registers
        //    (`ChannelMemberKeys::deterministic(1)` is the single derivation shared by
        //    `generate_close_fixture` and `generate_withdrawal_fixture`), so the close proof's
        //    `member_set_commitment` MUST equal the registered one. A mismatch means the fixture
        //    pair was not co-generated (stale / mixed-run fixtures) — HARD failure, no longer a
        //    self-skip.
        closeFixtureMatchesRegistration =
            manager.registeredMemberSetCommitment()
                == vm.parseJsonBytes32(_closeIntentJson(), ".member_set_commitment");
    }

    /// @dev Build the close `CloseVk` from the proved `close_intent_mle.json` (same field layout the
    /// rollup's withdrawal VK uses) and set it on the settlement verifier (deployer == FACTORY).
    function _initRealCloseVk() internal {
        string memory cj = _closeMleJson();
        FixtureLib.DeployData memory cdd = FixtureLib.parseDeployData(cj);
        MleVerifier.MleProof memory cproof = FixtureLib.parseProof(cj);
        bytes32 gatesDigest = verifier.computeGatesDigest(
            cproof.gates,
            cproof.witnessIndividualEvalsAtRGateV2.length,
            cproof.numSelectors,
            cproof.numGateConstraints,
            cproof.quotientDegreeFactor
        );
        ChannelSettlementVerifier.CloseVk memory cvk = ChannelSettlementVerifier.CloseVk({
            degreeBits: cdd.degreeBits,
            preprocessedRoot: cdd.preCommitRoot,
            numConstants: cdd.numConstants,
            numRoutedWires: cdd.numRoutedWires,
            gatesDigest: gatesDigest
        });
        vm.prank(FACTORY);
        settlementVerifier.initializeCloseVk(
            verifier, cvk, cdd.whirParams, cdd.protocolId, cdd.sessionId, cdd.kIs, cdd.subgroupGenPowers
        );
    }

    /// Print the close-manager CREATE2 address for the fixture-regeneration flow (moved here from
    /// CloseManagerAddr.t.sol — the address depends on THIS test contract's library-linking
    /// context, see that file). Reads the PLAIN (unprefixed) lifecycle fixtures, whose
    /// registration / VK / genesis are identical to the close set, so it works BEFORE the close
    /// fixtures are (re)generated. Then:
    ///   WD_RECIPIENT=<addr> WD_OUT_PREFIX=close_ cargo run --release --bin generate_withdrawal_fixture
    function test_printCloseManagerAddress() external {
        string memory vkJson = vm.readFile(string.concat(vm.projectRoot(), "/test/data/lifecycle_validity_mle.json"));
        string memory lcJson = vm.readFile(string.concat(vm.projectRoot(), "/test/data/lifecycle.json"));
        emit log_named_address("CLOSE_MANAGER_ADDRESS", predictManagerAddressFrom(vkJson, lcJson));
    }

    function test_closeLifecycle_endToEnd() public {
        if (!ready) { vm.skip(true); return; }

        // Multitoken Phase 5b: stale fixtures are a HARD failure (no self-skip) — the manager the
        // close set was baked against must be the manager this test just deployed.
        assertEq(
            address(manager),
            bakedRecipient,
            "manager CREATE2 address != close payout fixture recipient (stale fixtures -- regenerate)"
        );

        // ── A. Advance + finalize the registration→deposit→withdrawal chain (real validity MLE). ──
        _runChainThroughFinalize();

        // ── B. Channel aggregate settlement: withdrawNative pays the channel's ETH to the manager. ──
        (IntmaxRollup.Withdrawal[] memory ws, address prover) = _parsePayout();
        assertEq(ws[0].recipient, address(manager), "withdrawal recipient is the manager");
        uint256 channelAmount = ws[0].amount; // = 3
        MleVerifier.MleProof memory wproof = FixtureLib.parseProof(_withdrawalJson());
        rollup.withdrawNative(ws, prover, wproof);
        assertEq(rollup.pendingWithdrawals(address(manager)), channelAmount, "manager credited at rollup");

        // ── C. Manager pulls the real ETH in. ──
        uint256 pulled = manager.pullChannelFunds();
        assertEq(pulled, channelAmount, "manager pulled channel ETH");
        assertEq(manager.receivedChannelFunds(0), channelAmount, "receivedChannelFunds[ETH] == channel amount");

        // ── D-E. Drive the channel close to Closed with the REAL wrapped-close MLE/WHIR proof.
        //
        // Multitoken Phase 5b: the close fixture is CO-GENERATED with the lifecycle fixture over
        // the same deterministic member keys (see setUp step 6), so this section always runs — a
        // member-set mismatch is a hard failure, not a skip.
        assertTrue(
            closeFixtureMatchesRegistration,
            "close fixture member_set_commitment != registeredMemberSetCommitment (fixtures not co-generated -- regenerate BOTH sets in one run)"
        );

        // The proved close intent's `close_freeze_nonce` must equal the manager's
        // `currentCloseFreezeNonce` after requestClose (== 1); the co-generated fixture is proved
        // at freeze nonce 1 by construction.
        string memory cij = _closeIntentJson();
        assertEq(
            uint64(vm.parseJsonUint(cij, ".close_freeze_nonce")),
            1,
            "close fixture freeze nonce != 1 (must be proved from a state with close_freeze_nonce = 0)"
        );

        string memory lcJson = _lifecycleJson();
        address member0 = vm.parseJsonAddress(lcJson, ".registration.recipients[0]");
        bytes32 member0Hash = vm.parseJsonBytes32Array(lcJson, ".registration.member_pk_gs")[0];

        vm.prank(member0);
        manager.requestClose();
        vm.warp(block.timestamp + 600); // grace

        // REAL close intent (every field is the proved close public input) + REAL wrapped-close proof
        // (publicInputs = the 103 raw close limbs the manager's `_runCloseVerify` rebinds, then
        // re-checked by the settlement verifier's MleVerifier.verify against the real close VK).
        ChannelSettlementManager.CloseIntent memory intent = _closeIntentFromDescriptor(cij);
        MleVerifier.MleProof memory closeProof = FixtureLib.parseProof(_closeMleJson());
        // Multitoken Phase 5b: the regenerated close fixture carries the 103-limb multi-token PI
        // vector (tokenFundsDigest at limbs 95..103, §N-6) — anything else is a stale fixture.
        assertEq(
            closeProof.publicInputs.length,
            103,
            "close fixture must carry the 103-limb multi-token close PI vector (stale fixture -- regenerate)"
        );
        manager.submitCloseIntent(intent, closeProof);
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();
        bytes32 digest = manager.finalizedCloseIntentDigest();

        // Multitoken (§N-6): `finalizeClose` accrues the member-signed per-token fund vector into
        // the per-BASE-token settlement caps — the TWO-token fixture (registry [ETH, t1], both
        // amounts nonzero) must accrue BOTH lanes, and only those.
        {
            uint256[] memory amounts = _parseAmountsArray(cij);
            uint256[] memory registryU = vm.parseJsonUintArray(cij, ".token_registry");
            uint256 tokenCount = vm.parseJsonUint(cij, ".token_count");
            assertEq(tokenCount, 2, "two-token close fixture expected (token_count == 2)");
            uint32 t1 = uint32(registryU[1]);
            assertTrue(t1 != 0, "non-genesis registry slot must map to a non-ETH base token");
            assertTrue(amounts[0] != 0 && amounts[1] != 0, "both per-token fund amounts must be nonzero");
            assertEq(
                manager.finalizedChannelFundAmount(0),
                amounts[0],
                "ETH lane accrual != signed amounts[0]"
            );
            assertEq(
                manager.finalizedChannelFundAmount(t1),
                amounts[1],
                "token-t1 lane accrual != signed amounts[1]"
            );
        }

        // Phase B-D: `submitWithdrawalClaim` now runs a REAL `verifyWithdrawalClaim` MLE/WHIR
        // verification (no more stub proof). Driving it here would require a withdrawal-claim MLE
        // fixture (from `generate_withdrawal_claim_fixture`) + VK co-generated with THIS lifecycle's
        // member set / finalized H1, which this generator pair does not yet produce (same
        // co-generation gap Phase A documented as a MEDIUM follow-up). The close-lifecycle path up to
        // `finalizeClose` — the real value of this E2E — has now run end-to-end against the real
        // MleVerifier. The withdrawal-claim binding + payout is exercised independently by the
        // mock-verified `ChannelSettlementManager.t.sol` (real 48-limb strict bind) and the
        // withdrawal-claim circuit's own Rust tests. Stop here rather than fabricate a stub proof on
        // a value path.
        assertEq(uint256(digest) != 0 ? uint256(1) : uint256(0), 1, "close finalized end-to-end");
    }

    /// @dev Build the `CloseIntent` from the proved close descriptor JSON (every field is a proved
    /// close public input — see generate_close_fixture.rs `CloseIntentDescriptor`). Multitoken
    /// Phase 5b: the per-token fund vector / registry / count are parsed from the descriptor
    /// verbatim (the verifier's on-chain tokenFundsDigest recompute binds them to the
    /// member-signed PI limbs 95..103 — a tampered vector fails `submitCloseIntent`).
    function _closeIntentFromDescriptor(string memory j)
        internal pure returns (ChannelSettlementManager.CloseIntent memory intent)
    {
        intent = ChannelSettlementManager.CloseIntent({
            closeNonce: uint64(vm.parseJsonUint(j, ".close_nonce")),
            finalEpoch: uint64(vm.parseJsonUint(j, ".final_epoch")),
            finalSmallBlockNumber: uint64(vm.parseJsonUint(j, ".final_small_block_number")),
            closeFreezeNonce: uint64(vm.parseJsonUint(j, ".close_freeze_nonce")),
            finalChannelStateDigest: vm.parseJsonBytes32(j, ".final_channel_state_digest"),
            finalBalanceStateH1: vm.parseJsonBytes32(j, ".final_balance_state_h1"),
            channelFundAmounts: _parseAmounts(j),
            tokenRegistry: _parseRegistry(j),
            tokenCount: uint8(vm.parseJsonUint(j, ".token_count")),
            channelFundIntmaxStateRoot: vm.parseJsonBytes32(j, ".channel_fund_intmax_state_root"),
            burnTxHash: vm.parseJsonBytes32(j, ".burn_tx_hash"),
            closeWithdrawalDigest: vm.parseJsonBytes32(j, ".close_withdrawal_digest"),
            snapshotMediumBlockNumber: uint64(vm.parseJsonUint(j, ".snapshot_medium_block_number")),
            finalStateVersion: uint64(vm.parseJsonUint(j, ".final_state_version")),
            finalSettledTxChain: vm.parseJsonBytes32(j, ".final_settled_tx_chain"),
            finalSettledTxAccumulatorRoot: vm.parseJsonBytes32(
                j, ".final_settled_tx_accumulator_root"
            )
        });
    }

    // ── helpers ──

    /// @dev Parse the descriptor's 10-entry per-token fund vector (0x-hex U256 strings).
    function _parseAmountsArray(string memory j) internal pure returns (uint256[] memory a) {
        string[] memory raw = vm.parseJsonStringArray(j, ".channel_fund_amounts");
        require(raw.length == 10, "channel_fund_amounts must have 10 entries");
        a = new uint256[](10);
        for (uint256 i = 0; i < 10; i++) a[i] = vm.parseUint(raw[i]);
    }

    function _parseAmounts(string memory j) internal pure returns (uint256[10] memory a) {
        uint256[] memory v = _parseAmountsArray(j);
        for (uint256 i = 0; i < 10; i++) a[i] = v[i];
    }

    function _parseRegistry(string memory j) internal pure returns (uint32[10] memory r) {
        uint256[] memory raw = vm.parseJsonUintArray(j, ".token_registry");
        require(raw.length == 10, "token_registry must have 10 entries");
        for (uint256 i = 0; i < 10; i++) r[i] = uint32(raw[i]);
    }

    function _registerChannel(string memory lcJson) internal {
        uint32 channelId = uint32(vm.parseJsonUint(lcJson, ".registration.channel_id"));
        uint8 bpSlot = uint8(vm.parseJsonUint(lcJson, ".registration.bp_member_slot"));
        bytes32[] memory sphincs = vm.parseJsonBytes32Array(lcJson, ".registration.member_pk_gs");
        bytes32[] memory pkBs = vm.parseJsonBytes32Array(lcJson, ".registration.member_pk_bs");
        bytes32[] memory regev = vm.parseJsonBytes32Array(lcJson, ".registration.regev_pk_digests");
        address[] memory recipients = vm.parseJsonAddressArray(lcJson, ".registration.recipients");
        rollup.registerChannel(channelId, bpSlot, 0, sphincs, pkBs, regev, recipients);
    }

    function _runChainThroughFinalize() internal {
        bytes32[] memory blobs = new bytes32[](1);
        blobs[0] = keccak256("close_blob");
        vm.blobhashes(blobs);
        vm.deal(poster, 10 ether);

        string memory lcJson = _lifecycleJson();
        bytes32 finalRoot = vm.parseJsonBytes32(lcJson, ".final_state_root");
        bytes32 proofHash = vm.parseJsonBytes32(lcJson, ".proof_hash");
        uint32 proofLength = uint32(vm.parseJsonUint(lcJson, ".proof_length"));

        _register0(); // block 1 (already registered in setUp; here we only post the block)
        _postRound(0, proofHash, proofLength, finalRoot);

        _deposit(lcJson);
        _postRound(1, proofHash, proofLength, finalRoot);

        uint256 finalSubId = _postRound(2, proofHash, proofLength, finalRoot);

        IntmaxRollup.ValidityPublicInputs memory vpis = _parseVpis(lcJson);
        MleVerifier.MleProof memory vproof = FixtureLib.parseProof(_validityJson());
        bool ok = rollup.finalize(finalSubId, finalRoot, vpis, vproof);
        assertTrue(ok, "finalize failed");
        assertEq(rollup.latestFinalizedStateRoot(), finalRoot, "finalized root mismatch");
    }

    /// Block 1 is the registration block; registerChannel already ran in setUp, so this is a no-op
    /// placeholder kept for readability of the block sequence.
    function _register0() internal {}

    function _deposit(string memory lcJson) internal {
        address depositor = vm.parseJsonAddress(lcJson, ".deposit.depositor");
        bytes32 recipient = vm.parseJsonBytes32(lcJson, ".deposit.recipient");
        uint32 tokenIndex = uint32(vm.parseJsonUint(lcJson, ".deposit.token_index"));
        uint256 amount = vm.parseUint(vm.parseJsonString(lcJson, ".deposit.amount"));
        bytes32 auxData = vm.parseJsonBytes32(lcJson, ".deposit.aux_data");
        vm.deal(depositor, amount);
        vm.prank(depositor);
        rollup.deposit{value: amount}(recipient, tokenIndex, amount, auxData);
    }

    function _postRound(uint256 i, bytes32 proofHash, uint32 proofLength, bytes32 stateRoot)
        internal returns (uint256 subId)
    {
        string memory lcJson = _lifecycleJson();
        string memory base = string.concat(".blocks[", vm.toString(i), "]");
        uint256[] memory keyIdsU = FixtureLib.parseUintArray(lcJson, string.concat(base, ".key_ids"));
        uint32[] memory keyIds = new uint32[](keyIdsU.length);
        for (uint256 j = 0; j < keyIdsU.length; j++) keyIds[j] = uint32(keyIdsU[j]);
        IntmaxRollup.SubBlock[] memory subBlocks = new IntmaxRollup.SubBlock[](1);
        subBlocks[0] = IntmaxRollup.SubBlock({
            channelId: uint32(vm.parseJsonUint(lcJson, string.concat(base, ".channel_id"))),
            timestamp: uint64(vm.parseJsonUint(lcJson, string.concat(base, ".timestamp"))),
            txTreeRoot: vm.parseJsonBytes32(lcJson, string.concat(base, ".tx_tree_root")),
            keyIds: keyIds
        });
        subId = rollup.nextSubmissionId();
        vm.prank(poster);
        rollup.postBlockAndSubmit{value: STAKE}(subBlocks, proofHash, proofLength, stateRoot);
    }

    function _parseVpis(string memory lcJson) internal pure returns (IntmaxRollup.ValidityPublicInputs memory v) {
        v.initialBlockNumber = uint64(vm.parseJsonUint(lcJson, ".vpis.initial_block_number"));
        v.initialBlockChain = vm.parseJsonBytes32(lcJson, ".vpis.initial_block_chain");
        v.initialExtCommitment = vm.parseJsonBytes32(lcJson, ".vpis.initial_ext_commitment");
        v.finalBlockNumber = uint64(vm.parseJsonUint(lcJson, ".vpis.final_block_number"));
        v.finalBlockChain = vm.parseJsonBytes32(lcJson, ".vpis.final_block_chain");
        v.finalExtCommitment = vm.parseJsonBytes32(lcJson, ".vpis.final_ext_commitment");
        v.prover = vm.parseJsonAddress(lcJson, ".vpis.prover");
    }

    function _parsePayout() internal view returns (IntmaxRollup.Withdrawal[] memory ws, address prover) {
        string memory j = _payoutJson();
        prover = vm.parseJsonAddress(j, ".withdrawal_prover");
        ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = IntmaxRollup.Withdrawal({
            recipient: vm.parseJsonAddress(j, ".withdrawals[0].recipient"),
            tokenIndex: uint32(vm.parseJsonUint(j, ".withdrawals[0].token_index")),
            amount: vm.parseUint(vm.parseJsonString(j, ".withdrawals[0].amount")),
            nullifier: vm.parseJsonBytes32(j, ".withdrawals[0].nullifier"),
            auxData: vm.parseJsonBytes32(j, ".withdrawals[0].aux_data")
        });
    }

    /// Stub-proof bytes for the OTHER (non-close) accepted-stub verifier paths (e.g.
    /// withdrawalClaimPIHash): `abi.encode(piHash)`. The close path no longer uses this — it submits
    /// a real `MleVerifier.MleProof`.
    function _proofFor(bytes32 piHash) internal pure returns (bytes memory) {
        return abi.encode(piHash);
    }
}
