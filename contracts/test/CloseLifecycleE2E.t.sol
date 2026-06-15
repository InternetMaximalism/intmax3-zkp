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
/// @dev Fixtures: `forge script script/ComputeCloseManager.s.sol` to get the manager address, then
///        WD_RECIPIENT=<addr> WD_OUT_PREFIX=close_ cargo run --release --bin generate_withdrawal_fixture
///      Self-skips if the close_* fixtures are absent.
contract CloseLifecycleE2ETest is CloseE2EBase {
    MleVerifier internal verifier;
    IntmaxRollup internal rollup;
    ChannelSettlementVerifier internal settlementVerifier;
    ChannelSettlementManager internal manager;
    address internal poster = makeAddr("poster");
    bool internal ready;

    uint256 internal constant STAKE = 1 ether;

    function setUp() public {
        // Self-skip until the close fixtures exist (heavy proving run).
        try vm.readFile(string.concat(vm.projectRoot(), "/test/data/close_withdrawal_payout.json")) {
            ready = true;
        } catch {
            ready = false;
            return;
        }

        // 1-2. Deploy all four contracts (+ registerChannel) via the shared CREATE2 path — IDENTICAL
        //      to ComputeCloseManager.s.sol so the manager lands at the baked address.
        (verifier, rollup, settlementVerifier, manager) = _deployAll(_validityJson(), _lifecycleJson());

        // 3. The deployed manager MUST equal the close proof's withdrawal recipient.
        emit log_named_address("manager(actual)", address(manager));
        address bakedRecipient = vm.parseJsonAddress(_payoutJson(), ".withdrawals[0].recipient");
        assertEq(address(manager), bakedRecipient, "manager address != close proof recipient");

        // 4. Set the withdrawal VK. deployer == the CREATE2 factory (msg.sender at construction), so
        //    prank the factory. (Production P7 uses a normal deploy where deployer = the EOA.)
        FixtureLib.DeployData memory wdd = FixtureLib.parseDeployData(_withdrawalJson());
        IntmaxRollup.MleVk memory wvk = FixtureLib.buildMleVk(_withdrawalJson(), verifier);
        vm.prank(FACTORY);
        rollup.initializeWithdrawalVk(wvk, wdd.whirParams, wdd.protocolId, wdd.sessionId, wdd.kIs, wdd.subgroupGenPowers);
    }

    function test_closeLifecycle_endToEnd() public {
        if (!ready) { vm.skip(true); return; }

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
        assertEq(manager.receivedChannelFunds(), channelAmount, "receivedChannelFunds == channel amount");

        // ── D. Drive the channel close to Closed (stub intra-channel consensus). ──
        string memory lcJson = _lifecycleJson();
        address member0 = vm.parseJsonAddress(lcJson, ".registration.recipients[0]");
        bytes32 member0Hash = vm.parseJsonBytes32Array(lcJson, ".registration.member_pk_gs")[0];

        vm.prank(member0);
        manager.requestClose();
        vm.warp(block.timestamp + 600); // grace

        ChannelSettlementManager.CloseIntent memory intent = _defaultIntent(uint256(channelAmount));
        manager.submitCloseIntent(intent, _closeStubProof(intent));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();
        bytes32 digest = manager.finalizedCloseIntentDigest();

        // ── E. A member claims their split (≤ receivedChannelFunds) and pulls REAL ETH. ──
        ChannelSettlementManager.WithdrawalClaim memory claim = ChannelSettlementManager.WithdrawalClaim({
            closeIntentDigest: digest,
            memberPkG: member0Hash,
            recipient: member0,
            userAmountDigest: keccak256(abi.encodePacked(member0Hash, uint64(channelAmount))),
            amount: uint64(channelAmount),
            withdrawalNullifier: keccak256(abi.encodePacked("wd", digest, member0Hash))
        });
        bytes memory claimProof = _proofFor(
            settlementVerifier.withdrawalClaimPIHash(
                bytes4(uint32(vm.parseJsonUint(lcJson, ".registration.channel_id"))),
                digest, manager.finalizedBalanceStateH1(), member0Hash, member0,
                claim.userAmountDigest, claim.amount, claim.withdrawalNullifier
            )
        );
        manager.submitWithdrawalClaim(claim, claimProof);
        assertEq(manager.withdrawalCredits(member0), channelAmount, "member credited");

        uint256 balBefore = member0.balance;
        vm.prank(member0);
        manager.claimWithdrawalCredit();
        assertEq(member0.balance, balBefore + channelAmount, "member received REAL ETH");
        assertEq(manager.totalCreditedOut(), channelAmount, "paid out == channel amount");
    }

    // ── helpers ──

    function _registerChannel(string memory lcJson) internal {
        uint32 channelId = uint32(vm.parseJsonUint(lcJson, ".registration.channel_id"));
        uint8 bpSlot = uint8(vm.parseJsonUint(lcJson, ".registration.bp_member_slot"));
        bytes32[] memory sphincs = vm.parseJsonBytes32Array(lcJson, ".registration.member_pk_gs");
        bytes32[] memory regev = vm.parseJsonBytes32Array(lcJson, ".registration.regev_pk_digests");
        address[] memory recipients = vm.parseJsonAddressArray(lcJson, ".registration.recipients");
        rollup.registerChannel(channelId, bpSlot, sphincs, regev, recipients);
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

    function _proofFor(bytes32 piHash) internal pure returns (bytes memory) {
        return abi.encode(piHash);
    }

    /// A stub close intent (the verifier is an accepted-stub; channelFundAmount must cover the split).
    function _defaultIntent(uint256 channelFundAmount)
        internal pure returns (ChannelSettlementManager.CloseIntent memory intent)
    {
        intent = ChannelSettlementManager.CloseIntent({
            closeNonce: 1,
            finalEpoch: 9,
            finalSmallBlockNumber: 22,
            closeFreezeNonce: 1,
            finalChannelStateDigest: keccak256("final_state"),
            finalBalanceStateH1: keccak256("balance_state_h1"),
            channelFundAmount: channelFundAmount,
            channelFundIntmaxStateRoot: keccak256("intmax_root"),
            burnTxHash: keccak256("burn_tx"),
            closeWithdrawalDigest: keccak256("burn_backed_close"),
            snapshotMediumBlockNumber: 77,
            finalStateVersion: 12,
            finalSettledTxChain: keccak256("settled_tx_chain")
        });
    }

    function _closeStubProof(ChannelSettlementManager.CloseIntent memory intent)
        internal view returns (bytes memory)
    {
        return _proofFor(
            settlementVerifier.closePIHash(
                manager.channelId(), intent.closeNonce, intent.finalEpoch, intent.finalSmallBlockNumber,
                intent.closeFreezeNonce, intent.finalChannelStateDigest, intent.finalBalanceStateH1,
                intent.channelFundAmount, intent.channelFundIntmaxStateRoot, intent.burnTxHash,
                intent.closeWithdrawalDigest, intent.snapshotMediumBlockNumber, intent.finalStateVersion,
                intent.finalSettledTxChain, manager.registeredMemberSetCommitment(), manager.activeMemberCount()
            )
        );
    }
}
