// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {FixtureLib} from "./FixtureLib.sol";

/// @title Drive the complex-calldata steps of the Sepolia close lifecycle (one fn per broadcast tx).
/// @notice Reads the sepolia_* close fixtures + deployed addresses from env (ROLLUP / MANAGER / SV).
///         Simple steps (postBlock blob txs, deposit, pullChannelFunds, requestClose, finalizeClose,
///         claimWithdrawalCredit) are done with `cast`; these four carry large struct calldata.
///         Invoke a single step with `--sig "<fn>()"`.
contract RunClose is Script {
    function _rollup() internal view returns (IntmaxRollup) { return IntmaxRollup(payable(vm.envAddress("ROLLUP"))); }
    function _manager() internal view returns (ChannelSettlementManager) { return ChannelSettlementManager(payable(vm.envAddress("MANAGER"))); }
    function _sv() internal view returns (ChannelSettlementVerifier) { return ChannelSettlementVerifier(vm.envAddress("SV")); }
    function _lc() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_lifecycle.json")); }
    function _vmle() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_lifecycle_validity_mle.json")); }
    function _wmle() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_withdrawal_mle.json")); }
    function _payout() internal view returns (string memory) { return vm.readFile(string.concat(vm.projectRoot(), "/test/data/sepolia_withdrawal_payout.json")); }

    /// finalize the 3-block chain (submission id via SUB_ID env, default 2 = the 3rd posting round).
    function finalizeStep() external {
        string memory lc = _lc();
        IntmaxRollup.ValidityPublicInputs memory vpis;
        vpis.initialBlockNumber = uint64(vm.parseJsonUint(lc, ".vpis.initial_block_number"));
        vpis.initialBlockChain = vm.parseJsonBytes32(lc, ".vpis.initial_block_chain");
        vpis.initialExtCommitment = vm.parseJsonBytes32(lc, ".vpis.initial_ext_commitment");
        vpis.finalBlockNumber = uint64(vm.parseJsonUint(lc, ".vpis.final_block_number"));
        vpis.finalBlockChain = vm.parseJsonBytes32(lc, ".vpis.final_block_chain");
        vpis.finalExtCommitment = vm.parseJsonBytes32(lc, ".vpis.final_ext_commitment");
        vpis.prover = vm.parseJsonAddress(lc, ".vpis.prover");
        bytes32 finalRoot = vm.parseJsonBytes32(lc, ".final_state_root");
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_vmle());
        uint256 subId = vm.envOr("SUB_ID", uint256(2));

        vm.startBroadcast();
        bool ok = _rollup().finalize(subId, finalRoot, vpis, proof);
        vm.stopBroadcast();
        require(ok, "finalize returned false");
        console2.log("finalize OK; latestFinalizedStateRoot:");
        console2.logBytes32(_rollup().latestFinalizedStateRoot());
    }

    /// withdrawNative: pay the channel's native ETH to the manager (recipient baked in the proof).
    function withdrawNativeStep() external {
        string memory j = _payout();
        IntmaxRollup.Withdrawal[] memory ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = IntmaxRollup.Withdrawal({
            recipient: vm.parseJsonAddress(j, ".withdrawals[0].recipient"),
            tokenIndex: uint32(vm.parseJsonUint(j, ".withdrawals[0].token_index")),
            amount: vm.parseUint(vm.parseJsonString(j, ".withdrawals[0].amount")),
            nullifier: vm.parseJsonBytes32(j, ".withdrawals[0].nullifier"),
            auxData: vm.parseJsonBytes32(j, ".withdrawals[0].aux_data")
        });
        address prover = vm.parseJsonAddress(j, ".withdrawal_prover");
        MleVerifier.MleProof memory proof = FixtureLib.parseProof(_wmle());

        vm.startBroadcast();
        _rollup().withdrawNative(ws, prover, proof);
        vm.stopBroadcast();
        console2.log("withdrawNative OK; pendingWithdrawals[manager]:", _rollup().pendingWithdrawals(address(_manager())));
    }

    /// submitCloseIntent (stub intra-channel consensus; channelFundAmount covers the member split).
    function closeIntentStep() external {
        ChannelSettlementManager.CloseIntent memory intent = ChannelSettlementManager.CloseIntent({
            closeNonce: 1, finalEpoch: 9, finalSmallBlockNumber: 22, closeFreezeNonce: 1,
            finalChannelStateDigest: keccak256("final_state"),
            finalBalanceStateH1: keccak256("balance_state_h1"),
            channelFundAmount: vm.envOr("FUND", uint256(3)),
            channelFundIntmaxStateRoot: keccak256("intmax_root"),
            burnTxHash: keccak256("burn_tx"),
            closeWithdrawalDigest: keccak256("burn_backed_close"),
            snapshotMediumBlockNumber: 77, finalStateVersion: 12,
            finalSettledTxChain: keccak256("settled_tx_chain")
        });
        bytes memory proof = abi.encode(
            _sv().closePIHash(
                _manager().channelId(), intent.closeNonce, intent.finalEpoch, intent.finalSmallBlockNumber,
                intent.closeFreezeNonce, intent.finalChannelStateDigest, intent.finalBalanceStateH1,
                intent.channelFundAmount, intent.channelFundIntmaxStateRoot, intent.burnTxHash,
                intent.closeWithdrawalDigest, intent.snapshotMediumBlockNumber, intent.finalStateVersion,
                intent.finalSettledTxChain, _manager().registeredMemberSetCommitment(), _manager().activeMemberCount()
            )
        );
        vm.startBroadcast();
        _manager().submitCloseIntent(intent, proof);
        vm.stopBroadcast();
        console2.log("submitCloseIntent OK; challengeDeadline:", _manager().getPendingClose().challengeDeadline);
    }

    /// submitWithdrawalClaim for member slot 0 (recipient = the EOA, per the manager binding).
    function withdrawalClaimStep() external {
        string memory lc = _lc();
        bytes32 memberHash = vm.parseJsonBytes32Array(lc, ".registration.member_sphincs_pubkey_hashes")[0];
        address recipient = msg.sender; // member0 recipient was set to the deployer EOA at deploy
        uint64 amount = uint64(vm.envOr("CLAIM", uint256(3)));
        bytes32 digest = _manager().finalizedCloseIntentDigest();
        ChannelSettlementManager.WithdrawalClaim memory claim = ChannelSettlementManager.WithdrawalClaim({
            closeIntentDigest: digest,
            memberSphincsPubkeyHash: memberHash,
            recipient: recipient,
            userAmountDigest: keccak256(abi.encodePacked(memberHash, amount)),
            amount: amount,
            withdrawalNullifier: keccak256(abi.encodePacked("wd", digest, memberHash))
        });
        bytes memory proof = abi.encode(
            _sv().withdrawalClaimPIHash(
                _manager().channelId(), digest, _manager().finalizedBalanceStateH1(), memberHash, recipient,
                claim.userAmountDigest, claim.amount, claim.withdrawalNullifier
            )
        );
        vm.startBroadcast();
        _manager().submitWithdrawalClaim(claim, proof);
        vm.stopBroadcast();
        console2.log("submitWithdrawalClaim OK; withdrawalCredits[recipient]:", _manager().withdrawalCredits(recipient));
    }
}
