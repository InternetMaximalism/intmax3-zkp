// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CloseSettlementBase, MockRollupRegistry} from "./CloseSettlementBase.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {IERC20} from "../src/SafeERC20.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {CloseTestLib} from "./CloseTestLib.sol";
import {SimpleERC20, ReentrantHookERC20} from "./tokens/TestTokens.sol";

/// @title Multi-token settlement adversarial suite (multitoken Phase 3, detail2 §N-6, TM-3/TM-11).
/// @notice Per-base-token Manager accounting: the TFD binding chain (close PI → finalization →
///         per-token caps), the no-cross-token frame at accrual AND payout, per-token cap
///         exhaustion, the token registry re-checks (TM-8), the proof-bound post-close claim
///         token (TM-16), the Rust↔Solidity token_funds_digest shared vector, and ERC-20 payout
///         reentrancy.
/// @dev Mock-MLE-verified (verdict=true) like the main manager suite: these tests exercise the
///      REAL 103/50-limb strict binding + the manager's per-token accounting, not the WHIR crypto.
contract MultiTokenSettlementTest is CloseSettlementBase {
    SimpleERC20 internal tokenA; // base token index 55
    uint32 internal constant TOKEN_A = 55;

    function setUp() public override {
        super.setUp();
        tokenA = new SimpleERC20("TokenA");
        registry.setToken(TOKEN_A, IERC20(address(tokenA)));
    }

    // ── builders ──

    /// Two-token close: ETH (slot 0) + TOKEN_A (slot 1).
    function _twoTokenIntent(uint256 ethFund, uint256 tokenFund)
        internal pure returns (ChannelSettlementManager.CloseIntent memory intent)
    {
        uint256[10] memory amounts;
        amounts[0] = ethFund;
        amounts[1] = tokenFund;
        uint32[10] memory reg;
        reg[0] = 0;
        reg[1] = TOKEN_A;
        intent = _intentWithTokens(1, 9, 22, 1, amounts, reg, 2);
    }

    /// Drive the default manager to Closed with a two-token close; return the finalized digest.
    function _finalizeTwoToken(uint256 ethFund, uint256 tokenFund) internal returns (bytes32) {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _twoTokenIntent(ethFund, tokenFund);
        manager.submitCloseIntent(intent, _closeProof(intent));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();
        return manager.finalizedCloseIntentDigest();
    }

    /// Fund the manager's TOKEN_A capacity: mint to the mock registry, credit, pull.
    function _fundAndPullToken(uint256 amount) internal {
        tokenA.mint(address(registry), amount);
        registry.creditTokenWithdrawal(TOKEN_A, address(manager), amount);
        manager.pullChannelTokenFunds(TOKEN_A);
    }

    function _submitTokenClaim(
        bytes32 digest,
        bytes32 memberPkG,
        address recipient,
        uint64 amount,
        uint8 tokenSlot,
        uint32 tokenIndex
    ) internal {
        ChannelSettlementManager.WithdrawalClaim memory c =
            _withdrawalClaimToken(digest, memberPkG, recipient, amount, tokenSlot, tokenIndex);
        manager.submitWithdrawalClaim(c, _withdrawalClaimProof(c));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TM-11: Rust↔Solidity token_funds_digest shared vector
    // ═══════════════════════════════════════════════════════════════════════

    /// Shared Rust<->Solidity test vector: `ChannelSettlementVerifier.tokenFundsDigest` must be
    /// byte-identical to the Rust `token_funds_digest` (src/common/channel.rs). The SAME
    /// (registry, count, amounts) are hashed by the Rust golden
    /// `token_funds_digest_golden_vector` and pin the SAME constant — generated FROM THE RUST
    /// side. If the two sides disagree, fix Solidity, not the digest.
    function test_tokenFundsDigest_matchesRustSharedVector() external view {
        uint32[10] memory reg;
        uint256[10] memory amounts;
        for (uint256 t = 0; t < 10; t++) {
            reg[t] = uint32(100 + t);
            amounts[t] = 1000 + t;
        }
        bytes32 digest = verifier.tokenFundsDigest(reg, 4, amounts);
        assertEq(
            digest,
            bytes32(0x44987e3ca1c57257dfd4e9f5d6cc165f341cc4a9e5e0de7b6c06595105d27278),
            "TFD must match the Rust-generated shared vector"
        );

        // Full-width binding (TM-11): positions beyond token_count are STILL hashed.
        uint32[10] memory regTail = reg;
        regTail[7] = 9999;
        assertTrue(verifier.tokenFundsDigest(regTail, 4, amounts) != digest, "registry tail bound");
        uint256[10] memory amtTail = amounts;
        amtTail[9] = 1;
        assertTrue(verifier.tokenFundsDigest(reg, 4, amtTail) != digest, "amounts tail bound");
        assertTrue(verifier.tokenFundsDigest(reg, 5, amounts) != digest, "token_count bound");
    }

    /// Review MINOR 2 (TM-8 defense-in-depth): the VERIFIER's own `tokenFundsDigest` rejects a
    /// token count outside 1..=10 — self-contained, independent of the Manager's structural check.
    /// Since `_expectedCloseLimbs` recomputes the TFD, every close bind inherits the bound too.
    function test_tokenFundsDigest_tokenCountBounds_reverts() external {
        uint32[10] memory reg;
        uint256[10] memory amounts;
        vm.expectRevert(ChannelSettlementVerifier.TokenCountOutOfRange.selector);
        verifier.tokenFundsDigest(reg, 0, amounts);
        vm.expectRevert(ChannelSettlementVerifier.TokenCountOutOfRange.selector);
        verifier.tokenFundsDigest(reg, 11, amounts);
        // Boundary values are accepted (the valid range is exactly 1..=10).
        verifier.tokenFundsDigest(reg, 1, amounts);
        verifier.tokenFundsDigest(reg, 10, amounts);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TM-11: the TFD binding chain at close submission
    // ═══════════════════════════════════════════════════════════════════════

    /// A close whose supplied (registry, count, amounts) do NOT hash to the proof's TFD limbs is
    /// rejected by the strict bind — the Manager can only store proof-bound settlement vectors.
    function test_close_tamperedTokenVectors_rejected() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _twoTokenIntent(75, 40);
        MleVerifier.MleProof memory proof = _closeProof(intent); // proof for the REAL vectors

        // Inflate the token-A fund after the proof is built → TFD recompute changes → limb mismatch.
        intent.channelFundAmounts[1] = 40_000;
        vm.expectRevert(bytes("close limb mismatch"));
        manager.submitCloseIntent(intent, proof);

        // Remap the registry (token-A → token 66) → limb mismatch.
        intent.channelFundAmounts[1] = 40;
        intent.tokenRegistry[1] = 66;
        vm.expectRevert(bytes("close limb mismatch"));
        manager.submitCloseIntent(intent, proof);

        // Shrink the active boundary (2 → 1) → limb mismatch (count is TFD-bound).
        intent.tokenRegistry[1] = TOKEN_A;
        intent.tokenCount = 1;
        vm.expectRevert(bytes("close limb mismatch"));
        manager.submitCloseIntent(intent, proof);

        // The untampered intent still goes through.
        intent.tokenCount = 2;
        manager.submitCloseIntent(intent, proof);
    }

    /// tokenCount outside 1..=10 is rejected before any proof work.
    function test_close_tokenCountOutOfRange_rejected() external {
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory intent = _twoTokenIntent(75, 40);
        MleVerifier.MleProof memory proof = _closeProof(intent);

        intent.tokenCount = 0;
        vm.expectRevert(ChannelSettlementManager.TokenCountOutOfRange.selector);
        manager.submitCloseIntent(intent, proof);

        intent.tokenCount = 11;
        vm.expectRevert(ChannelSettlementManager.TokenCountOutOfRange.selector);
        manager.submitCloseIntent(intent, proof);
    }

    /// finalizeClose converts the TFD-bound vectors into per-base-token caps + registry copy.
    function test_finalize_recordsPerTokenFunds() external {
        _finalizeTwoToken(75, 40);
        assertEq(manager.finalizedChannelFundAmount(0), 75, "ETH fund keyed by base token 0");
        assertEq(manager.finalizedChannelFundAmount(TOKEN_A), 40, "token-A fund keyed by base index");
        assertEq(manager.finalizedTokenCount(), 2);
        assertEq(manager.finalizedTokenRegistry(0), 0);
        assertEq(manager.finalizedTokenRegistry(1), TOKEN_A);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TM-3/TM-8: per-token claims — accrual caps, slot/registry re-checks
    // ═══════════════════════════════════════════════════════════════════════

    /// Happy path: per-(member, token) claims accrue into per-token credits; the same member can
    /// claim BOTH tokens (distinct per-(slot, token) nullifiers — the TM-5 completeness
    /// direction).
    function test_claims_perTokenAccrual() external {
        bytes32 d = _finalizeTwoToken(75, 40);
        _submitTokenClaim(d, USER_A, alice, 30, 0, 0);       // ETH claim
        _submitTokenClaim(d, USER_A, alice, 25, 1, TOKEN_A); // token-A claim, SAME member
        assertEq(manager.withdrawalCredits(0, alice), 30, "ETH credit");
        assertEq(manager.withdrawalCredits(TOKEN_A, alice), 25, "token-A credit");
        assertEq(manager.totalWithdrawn(0), 30);
        assertEq(manager.totalWithdrawn(TOKEN_A), 25);
    }

    /// Cross-token claim where finalized fund[t] = 0: the per-token accrual cap rejects it even
    /// though OTHER tokens hold plenty of funds (the no-cross-token frame at the accrual site).
    function test_claim_zeroFundToken_rejected() external {
        bytes32 d = _finalizeTwoToken(75, 0); // token-A fund = 0
        ChannelSettlementManager.WithdrawalClaim memory c =
            _withdrawalClaimToken(d, USER_A, alice, 1, 1, TOKEN_A);
        MleVerifier.MleProof memory proof = _withdrawalClaimProof(c);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.submitWithdrawalClaim(c, proof);
    }

    /// Per-token cap exhaustion: token-A claims up to fund[A] succeed, the next rejects; claims in
    /// the OTHER token are unaffected (the no-cross-token frame end-to-end).
    function test_claim_perTokenCapExhaustion_frame() external {
        bytes32 d = _finalizeTwoToken(75, 40);
        _submitTokenClaim(d, USER_A, alice, 40, 1, TOKEN_A); // fills the token-A budget exactly
        assertEq(manager.totalWithdrawn(TOKEN_A), 40);

        // Next token-A claim (1 wei-equivalent) exceeds the exhausted budget.
        ChannelSettlementManager.WithdrawalClaim memory over =
            _withdrawalClaimToken(d, USER_B, bob, 1, 1, TOKEN_A);
        MleVerifier.MleProof memory overProof = _withdrawalClaimProof(over);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.submitWithdrawalClaim(over, overProof);

        // The ETH budget is untouched: a 75 ETH-side claim still accrues in full.
        _submitTokenClaim(d, USER_B, bob, 75, 0, 0);
        assertEq(manager.totalWithdrawn(0), 75, "ETH budget independent of token-A exhaustion");
    }

    /// TM-8: a claim on an inactive token slot (>= finalizedTokenCount) is rejected at the Manager
    /// (defense-in-depth on top of the circuit + verifier bounds).
    function test_claim_inactiveSlot_rejected() external {
        bytes32 d = _finalizeTwoToken(75, 40);
        ChannelSettlementManager.WithdrawalClaim memory c =
            _withdrawalClaimToken(d, USER_A, alice, 1, 2, TOKEN_A); // slot 2 >= count 2
        MleVerifier.MleProof memory proof = _withdrawalClaimProof(c);
        vm.expectRevert(ChannelSettlementManager.TokenSlotOutOfRange.selector);
        manager.submitWithdrawalClaim(c, proof);
    }

    /// TM-8/m8: a claim whose base tokenIndex disagrees with the finalized registry at its slot is
    /// rejected (the caller cannot re-denominate a slot into a different asset).
    function test_claim_registryMismatch_rejected() external {
        bytes32 d = _finalizeTwoToken(75, 40);
        ChannelSettlementManager.WithdrawalClaim memory c =
            _withdrawalClaimToken(d, USER_A, alice, 5, 1, 66); // slot 1 resolves to 55, not 66
        MleVerifier.MleProof memory proof = _withdrawalClaimProof(c);
        vm.expectRevert(ChannelSettlementManager.TokenRegistryMismatch.selector);
        manager.submitWithdrawalClaim(c, proof);
    }

    /// A withdrawal-claim proof bound to one (tokenSlot, tokenIndex) cannot be replayed for a
    /// claim declaring another pair — the strict limbs 48/49 bind (verifier-level TM-2 seam).
    function test_claim_tokenLimbTamper_rejected() external {
        bytes32 d = _finalizeTwoToken(75, 40);
        ChannelSettlementManager.WithdrawalClaim memory ethClaim =
            _withdrawalClaimToken(d, USER_A, alice, 5, 0, 0);

        // (a) Proof whose limbs are IDENTICAL to the ETH claim's EXCEPT tokenIndex (limb 49) = 55:
        //     the ONLY differing limb is the token limb, so the rejection is attributable to it.
        uint256[] memory limbs = verifier.expectedWithdrawalClaimLimbs(
            CHANNEL_ID,
            ethClaim.closeIntentDigest,
            manager.finalizedBalanceStateH1(),
            ethClaim.memberPkG,
            ethClaim.recipient,
            ethClaim.userAmountDigest,
            ethClaim.amount,
            0, // tokenSlot as claimed
            TOKEN_A, // tokenIndex 55 != the claim's 0 — ONLY limb 49 differs
            ethClaim.withdrawalNullifier
        );
        MleVerifier.MleProof memory forged = CloseTestLib.proofWithLimbs(limbs);
        vm.expectRevert(bytes("claim limb mismatch"));
        manager.submitWithdrawalClaim(ethClaim, forged);

        // (b) Full cross-token replay: a proof built for the TOKEN-A variant of the same claim
        //     (limbs 38..46 nullifier AND 48/49 token pair differ) is also rejected.
        ChannelSettlementManager.WithdrawalClaim memory tokClaim =
            _withdrawalClaimToken(d, USER_A, alice, 5, 1, TOKEN_A);
        MleVerifier.MleProof memory tokProof = _withdrawalClaimProof(tokClaim);
        vm.expectRevert(bytes("claim limb mismatch"));
        manager.submitWithdrawalClaim(ethClaim, tokProof);
    }

    /// TM-16 (§N-6, Phase 5a): the post-close claim's credited token is the PROOF-BOUND base
    /// tokenIndex (PI limb 56, committed by the anchored incoming tx_hash) — the genesis pin is
    /// retired. A TOKEN_A claim credits and accrues in TOKEN_A only; the ETH lane is untouched
    /// (cross-token isolation frame, TM-3).
    function test_postCloseClaim_proofBoundToken() external {
        bytes32 d = _finalizeTwoToken(75, 40);
        ChannelSettlementManager.PostCloseClaim memory pc =
            _postCloseClaim(d, keccak256("itx"), USER_B, bob, 10, TOKEN_A);
        manager.submitPostCloseClaim(pc, _postCloseClaimProof(pc));
        assertEq(manager.withdrawalCredits(TOKEN_A, bob), 10, "credited in the PROVED token");
        assertEq(manager.totalWithdrawn(TOKEN_A), 10, "accrued against the token-A budget");
        assertEq(manager.withdrawalCredits(0, bob), 0, "ETH lane untouched");
        assertEq(manager.totalWithdrawn(0), 0, "ETH budget untouched");
    }

    /// TM-16 negative: a tampered token limb — the claim states TOKEN_A but the proof's PI
    /// limb 56 carries 0 (genesis) — fails the strict limb bind. Only limb 56 differs.
    function test_postCloseClaim_tamperedTokenLimb_reverts() external {
        bytes32 d = _finalizeTwoToken(75, 40);
        ChannelSettlementManager.PostCloseClaim memory genesisVariant =
            _postCloseClaim(d, keccak256("itx"), USER_B, bob, 10, 0);
        // Proof limbs built for tokenIndex 0; the submitted claim says TOKEN_A.
        MleVerifier.MleProof memory proofToken0 = _postCloseClaimProof(genesisVariant);
        ChannelSettlementManager.PostCloseClaim memory claimTokenA =
            _postCloseClaim(d, keccak256("itx"), USER_B, bob, 10, TOKEN_A);
        vm.expectRevert(bytes("claim limb mismatch"));
        manager.submitPostCloseClaim(claimTokenA, proofToken0);
    }

    /// TM-16 defense-in-depth: a token the channel never cosigned into its registry is refused
    /// BEFORE proof verification (the channel can only owe registered tokens) — and would fail
    /// the zero accrual cap anyway.
    function test_postCloseClaim_unregisteredToken_reverts() external {
        bytes32 d = _finalizeTwoToken(75, 40);
        ChannelSettlementManager.PostCloseClaim memory pc =
            _postCloseClaim(d, keccak256("itx"), USER_B, bob, 10, 999);
        MleVerifier.MleProof memory proof = _postCloseClaimProof(pc);
        vm.expectRevert(ChannelSettlementManager.TokenRegistryMismatch.selector);
        manager.submitPostCloseClaim(pc, proof);
    }

    /// TM-16 cross-token isolation at the accrual cap: a TOKEN_A post-close claim above the
    /// TOKEN_A fund (40) reverts even though the ETH fund (75) has plenty of headroom — token-t
    /// claims accrue ONLY against token-t funds (TM-3), and the payout ceiling stays per token.
    function test_postCloseClaim_perTokenCap_noCrossTokenDraw() external {
        bytes32 d = _finalizeTwoToken(75, 40);
        ChannelSettlementManager.PostCloseClaim memory over =
            _postCloseClaim(d, keccak256("itx"), USER_B, bob, 41, TOKEN_A);
        MleVerifier.MleProof memory overProof = _postCloseClaimProof(over);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.submitPostCloseClaim(over, overProof);

        // Exactly the token fund fits; the payout is then paid in REAL tokens only.
        ChannelSettlementManager.PostCloseClaim memory pc =
            _postCloseClaim(d, keccak256("itx"), USER_B, bob, 40, TOKEN_A);
        manager.submitPostCloseClaim(pc, _postCloseClaimProof(pc));
        _fundAndPullToken(40);
        vm.prank(bob);
        assertEq(manager.claimWithdrawalCredit(TOKEN_A), 40);
        assertEq(tokenA.balanceOf(bob), 40, "bob received real tokens");
        assertEq(manager.totalCreditedOut(0), 0, "no ETH left the manager");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TM-3: per-token payout ceiling (the Lean execMT_payout_ceiling site)
    // ═══════════════════════════════════════════════════════════════════════

    /// Token credits are paid in REAL tokens, capped by the token's OWN received funds; ETH
    /// capacity can never satisfy a token claim (and vice versa).
    function test_payout_perTokenCeiling_noCrossTokenDraw() external {
        bytes32 d = _finalizeTwoToken(75, 40);
        _submitTokenClaim(d, USER_A, alice, 40, 1, TOKEN_A);

        // Fund ONLY the ETH side generously; token-A received = 0.
        _fundAndPull(registry, manager, 75);
        assertEq(manager.receivedChannelFunds(0), 75);
        assertEq(manager.receivedChannelFunds(TOKEN_A), 0);

        // Token-A payout must revert: totalCreditedOut[A] + 40 > receivedChannelFunds[A] = 0.
        vm.prank(alice);
        vm.expectRevert(ChannelSettlementManager.WithdrawalCapExceeded.selector);
        manager.claimWithdrawalCredit(TOKEN_A);

        // Now fund token-A for real: the payout succeeds and pays REAL tokens.
        _fundAndPullToken(40);
        assertEq(manager.receivedChannelFunds(TOKEN_A), 40, "measured token delta recorded");
        vm.prank(alice);
        uint256 got = manager.claimWithdrawalCredit(TOKEN_A);
        assertEq(got, 40);
        assertEq(tokenA.balanceOf(alice), 40, "alice received real tokens");
        assertEq(manager.totalCreditedOut(TOKEN_A), 40);
        assertEq(manager.withdrawalCredits(TOKEN_A, alice), 0, "credit cleared");

        // Solvency invariant per token.
        assertLe(manager.totalCreditedOut(TOKEN_A), manager.receivedChannelFunds(TOKEN_A));
        assertEq(manager.totalCreditedOut(0), 0, "no ETH left the manager");
    }

    /// ERC-777-style reentrancy on the manager's TOKEN payout: the hook's nested
    /// claimWithdrawalCredit reverts (credit zeroed + nonReentrant); paid exactly once.
    function test_payout_reentrantHookToken_blocked() external {
        // Use the hook token as base token 77 for a fresh close.
        ReentrantHookERC20 hookToken = new ReentrantHookERC20();
        uint32 hookIndex = 77;
        registry.setToken(hookIndex, IERC20(address(hookToken)));

        _requestCloseAndElapseGrace();
        uint256[10] memory amounts;
        amounts[0] = 10;
        amounts[1] = 200;
        uint32[10] memory reg;
        reg[1] = hookIndex;
        ChannelSettlementManager.CloseIntent memory intent =
            _intentWithTokens(1, 9, 22, 1, amounts, reg, 2);
        manager.submitCloseIntent(intent, _closeProof(intent));
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        manager.finalizeClose();
        bytes32 d = manager.finalizedCloseIntentDigest();

        _submitTokenClaim(d, USER_A, alice, 200, 1, hookIndex);
        hookToken.mint(address(registry), 200);
        registry.creditTokenWithdrawal(hookIndex, address(manager), 200);
        manager.pullChannelTokenFunds(hookIndex);

        // Hook fires on `transfer` (the manager's payout) and re-enters the payout entry point.
        hookToken.setHook(
            address(manager),
            abi.encodeWithSignature("claimWithdrawalCredit(uint32)", hookIndex),
            false
        );
        vm.prank(alice);
        manager.claimWithdrawalCredit(hookIndex);

        assertTrue(hookToken.hookReverted(), "reentrant payout must have reverted");
        assertEq(hookToken.balanceOf(alice), 200, "paid exactly once");
        assertEq(manager.totalCreditedOut(hookIndex), 200, "single payout recorded");
    }

    /// Unsolicited token donations to the manager do NOT create payout capacity (only measured
    /// pull deltas count — the ERC-20 analogue of the SELFDESTRUCT-forced-ETH note).
    function test_pullTokenFunds_ignoresDonations() external {
        tokenA.mint(address(manager), 1_000_000); // stray donation
        assertEq(manager.receivedChannelFunds(TOKEN_A), 0, "donations never counted");
        _fundAndPullToken(5);
        assertEq(manager.receivedChannelFunds(TOKEN_A), 5, "only the measured pull delta counts");
    }

    /// pullChannelTokenFunds refuses an index with no L1-registered token address.
    function test_pullTokenFunds_unregisteredIndex_reverts() external {
        vm.expectRevert(ChannelSettlementManager.TokenIndexNotRegisteredOnRollup.selector);
        manager.pullChannelTokenFunds(999);
    }

    /// ETH regression: the single-token (genesis) close path behaves exactly as before through the
    /// per-token machinery — same caps, same payout, keyed at base token 0.
    function test_singleTokenClose_ethRegression() external {
        bytes32 d = _finalizeDefault(); // 75 at slot 0, registry [ETH], count 1
        assertEq(manager.finalizedChannelFundAmount(0), 75);
        _submitTokenClaim(d, USER_A, alice, 30, 0, 0);
        _fundAndPull(registry, manager, 75);
        vm.prank(alice);
        assertEq(manager.claimWithdrawalCredit(), 30, "zero-arg ETH alias still works");
        assertEq(alice.balance, 30, "real ETH paid");
        assertEq(manager.totalCreditedOut(0), 30);
    }
}
