// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseSettlementBase} from "./CloseSettlementBase.sol";

/// Stranded L1 deposit (2026-10-15 review).
///
/// The Rust L1 deposit import used to sign TWO N-of-N heads: a fund-import head (fund vector +
/// settle chain advanced, `unallocated_confirmed_incoming += amount`, ciphertexts untouched) and a
/// bundle-apply head (depositor ciphertext credited, fund vector and chain unchanged). Both share
/// the CloseAssetBacking statement key `(channelId, settledTxChain, tokenFundsDigest)`, so the one
/// attested backing proof closes either. This test MODELS a close finalized on the fund-import
/// head and pins the L1 consequence: the Manager offers no payout lane for the deposit.
///
///   * withdrawal lane — claims open the final slot ciphertexts, which do not contain the deposit
///     (modelled here as the members' pre-deposit balances);
///   * post-close residual lane — needs an IMUI-tagged leaf `keccak(IMUI || tx_hash)` in the
///     final accumulator; the fund-import head pushed the RAW deposit nullifier, so no such
///     opening exists (modelled: no claim is submitted because none can be proved);
///   * late-incoming lane — `creditLateIncoming` is materializer-only and ReceiveTransfer-only.
///
/// The Manager cannot distinguish the two heads (same key, same H1-bound balance proof), so the
/// fix is off-chain: the import is now ONE signed head and the fund leg is never N-of-N signed
/// (`wallet_core::build_l1_deposit_import`, `channel_member` signing primitive). This test stays
/// as the pinned L1 model of what a signed fund-import head would cost.
contract L1DepositFundImportHeadStrandingTest is CloseSettlementBase {
    uint256 internal constant PRE_DEPOSIT_BALANCE_A = 30;
    uint256 internal constant PRE_DEPOSIT_BALANCE_B = 25;
    uint256 internal constant PRE_DEPOSIT_BALANCE_C = 20;
    uint256 internal constant DEPOSIT_AMOUNT = 7_777;

    function test_closeOnFundImportHead_leavesTheDepositUnclaimable() external {
        uint256 preDepositFund = PRE_DEPOSIT_BALANCE_A + PRE_DEPOSIT_BALANCE_B + PRE_DEPOSIT_BALANCE_C;
        // The fund-import head's declared fund vector already contains the deposit.
        bytes32 closeIntentDigest = _finalizeWithFund(preDepositFund + DEPOSIT_AMOUNT);
        assertEq(manager.finalizedChannelFundAmount(0), preDepositFund + DEPOSIT_AMOUNT);

        // Withdrawal lane: every member's claim decrypts the PRE-deposit ciphertext.
        ChannelSettlementManager.WithdrawalClaim memory a =
            _withdrawalClaim(closeIntentDigest, USER_A, alice, uint64(PRE_DEPOSIT_BALANCE_A));
        manager.submitWithdrawalClaim(a, _withdrawalClaimProof(a));
        ChannelSettlementManager.WithdrawalClaim memory b =
            _withdrawalClaim(closeIntentDigest, USER_B, bob, uint64(PRE_DEPOSIT_BALANCE_B));
        manager.submitWithdrawalClaim(b, _withdrawalClaimProof(b));
        ChannelSettlementManager.WithdrawalClaim memory c =
            _withdrawalClaim(closeIntentDigest, USER_C, carol, uint64(PRE_DEPOSIT_BALANCE_C));
        manager.submitWithdrawalClaim(c, _withdrawalClaimProof(c));

        // Late-incoming lane: not reachable from outside the materializer (the base deploys this
        // test contract AS the materializer, so call from a member instead).
        vm.prank(alice);
        vm.expectRevert(ChannelSettlementManager.InvalidPostCloseClaimProof.selector);
        manager.creditLateIncoming(0, uint64(DEPOSIT_AMOUNT), alice, keccak256("late"));

        uint256 claimable = manager.totalWithdrawn(0);
        uint256 stranded = manager.finalizedChannelFundAmount(0) - claimable;
        // PINNED MODEL: a close on a signed fund-import head strands exactly the deposit. The
        // red run of this file (2026-10-15) also asserted `stranded == 0` and failed with
        // `7777 != 0`; nothing in the Manager can satisfy that, because the two heads are
        // indistinguishable on L1 (same statement key, same H1-bound balance proof). The
        // guarantee lives off-chain: the fund-import leg is never an N-of-N signed head
        // (`wallet_core::build_l1_deposit_import`, `channel_member` signing primitive). Whether
        // the Manager/materializer should ALSO gain a distinguishing signal is an owner decision.
        assertEq(stranded, DEPOSIT_AMOUNT, "every lane together leaves exactly the deposit unpaid");
        assertEq(manager.withdrawalCredits(0, alice), PRE_DEPOSIT_BALANCE_A);
        assertEq(manager.withdrawalCredits(0, bob), PRE_DEPOSIT_BALANCE_B);
        assertEq(manager.withdrawalCredits(0, carol), PRE_DEPOSIT_BALANCE_C);
    }
}
