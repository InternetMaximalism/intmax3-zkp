// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {IERC20, SafeERC20Lib} from "../src/SafeERC20.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "@mle/spongefish/GoldilocksExt3.sol";
import {Plonky2GateEvaluator} from "@mle/Plonky2GateEvaluator.sol";
import {MockMleVerifier} from "./CloseTestLib.sol";
import {
    SimpleERC20,
    FeeOnTransferERC20,
    FalseReturnERC20,
    ShortReturnERC20,
    ReentrantHookERC20
} from "./tokens/TestTokens.sol";

/// @title Multi-token L1 escrow adversarial suite (multitoken Phase 3, detail2 §N-7).
/// @notice Covers the TM-1/TM-4/TM-10 obligations on `IntmaxRollup`: set-once token registry,
///         measured-delta ERC-20 deposits (fee-on-transfer fail-closed), reentrancy on deposit and
///         payout, the per-token `escrowedByToken` underflow ceiling (duplicate-index /
///         cross-channel drain bound), and the ETH-path frame.
/// @dev The rollup is deployed with a CONTROLLABLE MockMleVerifier (verdict=true) as its
///      `mleVerifier`, so `withdrawERC20`/`withdrawNative` run the REAL chain-refold + pis_hash +
///      finalized-root binding while the WHIR cryptography itself is mocked (INTENTIONALLY SIMPLE
///      per CLAUDE.md; the real MLE path is covered by the fixture E2Es). The validity VK is the
///      degreeBits=0 test bypass (allowMleDisabled=true) purely to mint a finalized state root.
contract MultiTokenEscrowTest is Test {
    IntmaxRollup internal rollup;
    MockMleVerifier internal mockMle;
    address internal fraudTreasury = makeAddr("fraudTreasury");
    address internal recipient1 = makeAddr("recipient1");
    address internal recipient2 = makeAddr("recipient2");
    address internal wdProver = makeAddr("wdProver");

    SimpleERC20 internal tokenA; // registered at index 7
    SimpleERC20 internal tokenB; // registered at index 8
    uint32 internal constant TOKEN_A = 7;
    uint32 internal constant TOKEN_B = 8;

    bytes32 internal finalizedRoot;

    // ── deploy + finalize plumbing (mirrors IntmaxRollup.t.sol's helpers) ──

    function _emptyWhirParams() internal pure returns (SpongefishWhirVerify.WhirParams memory p) {
        p.rounds = new SpongefishWhirVerify.RoundParams[](0);
        p.evaluationPoint = new GoldilocksExt3.Ext3[](0);
        p.evaluationPoint2 = new GoldilocksExt3.Ext3[](0);
    }

    function _defaultMleProof() internal pure returns (MleVerifier.MleProof memory proof) {
        proof.circuitDigest = new uint256[](0);
        proof.whirTranscript = "";
        proof.whirHints = "";
        proof.preprocessedIndividualEvals = new uint256[](0);
        proof.witnessIndividualEvals = new uint256[](0);
        proof.publicInputs = new uint256[](0);
        proof.witnessIndividualEvalsAtRInv = new uint256[](0);
        proof.preprocessedIndividualEvalsAtRInv = new uint256[](0);
        proof.inverseHelpersEvalsAtRInv = new uint256[](0);
        proof.inverseHelpersEvalsAtRH = new uint256[](0);
        proof.witnessIndividualEvalsAtRGateV2 = new uint256[](0);
        proof.preprocessedIndividualEvalsAtRGateV2 = new uint256[](0);
        proof.gates = new Plonky2GateEvaluator.GateInfo[](0);
    }

    function _piLimbs(bytes32 piHash) internal pure returns (uint256[] memory limbs) {
        limbs = new uint256[](8);
        uint256 h = uint256(piHash);
        for (uint256 i = 0; i < 8; i++) {
            limbs[i] = (h >> (224 - i * 32)) & 0xFFFFFFFF;
        }
    }

    function setUp() public {
        mockMle = new MockMleVerifier();
        IntmaxRollup.MleVk memory zeroVk; // degreeBits = 0 → validity MLE bypass (test opt-in)
        rollup = new IntmaxRollup(
            fraudTreasury,
            zeroVk,
            _emptyWhirParams(),
            "",
            "",
            new uint256[](0),
            new uint256[](0),
            MleVerifier(address(mockMle)),
            bytes32(0),
            true // A-2 test opt-in for the degreeBits==0 validity bypass
        );
        // Withdrawal VK: degreeBits = 1 (never disabled) — the mock verifier supplies the verdict.
        IntmaxRollup.MleVk memory wVk;
        wVk.degreeBits = 1;
        rollup.initializeWithdrawalVk(
            wVk, _emptyWhirParams(), "", "", new uint256[](0), new uint256[](0)
        );

        tokenA = new SimpleERC20("TokenA");
        tokenB = new SimpleERC20("TokenB");
        rollup.registerToken(TOKEN_A, address(tokenA));
        rollup.registerToken(TOKEN_B, address(tokenB));

        _finalizeARoot();
    }

    /// Mint a finalized state root so `_verifyWithdrawalSet`'s ext-commitment anchor is satisfied
    /// (same flow as IntmaxRollup.t.sol::test_finalize_success).
    function _finalizeARoot() internal {
        rollup.setBlockProducerAdmin(address(this));

        MleVerifier.MleProof memory mleProof = _defaultMleProof();
        finalizedRoot = keccak256("mt_finalized_state");
        // vpis computed BEFORE posting so blockHashChainAt[0]=0 and finalBlockNumber=0 match.
        IntmaxRollup.ValidityPublicInputs memory vpis = IntmaxRollup.ValidityPublicInputs({
            initialBlockNumber: 0,
            initialBlockChain: rollup.blockHashChainAt(0),
            initialExtCommitment: rollup.latestFinalizedStateRoot(),
            finalBlockNumber: rollup.blockNumber(),
            finalBlockChain: rollup.blockHashChain(),
            finalExtCommitment: finalizedRoot,
            prover: address(0)
        });
        bytes32 piHash = keccak256(
            abi.encodePacked(
                vpis.initialBlockNumber,
                vpis.initialBlockChain,
                vpis.initialExtCommitment,
                vpis.finalBlockNumber,
                vpis.finalBlockChain,
                vpis.finalExtCommitment,
                vpis.prover
            )
        );
        mleProof.publicInputs = _piLimbs(piHash);

        bytes32[] memory blobs = new bytes32[](1);
        blobs[0] = keccak256("mt_blob");
        vm.blobhashes(blobs);
        uint32[] memory ids = new uint32[](1);
        ids[0] = 1;
        IntmaxRollup.SubBlock[] memory batch = new IntmaxRollup.SubBlock[](1);
        batch[0] = IntmaxRollup.SubBlock({
            channelId: 1,
            timestamp: 100,
            txTreeRoot: bytes32(uint256(0xabc)),
            keyIds: ids
        });
        vm.deal(address(this), 10 ether);
        rollup.postBlockAndSubmit{value: 1 ether}(
            batch, keccak256("proof"), 1, finalizedRoot
        );
        assertTrue(rollup.finalize(0, finalizedRoot, vpis, mleProof), "finalize must succeed");
    }

    // ── withdrawal-proof builders (byte mirrors of the contract's fold/pis_hash) ──

    function _foldLeaf(bytes32 prev, IntmaxRollup.Withdrawal memory w)
        internal pure returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(prev, w.recipient, w.tokenIndex, w.amount, w.nullifier, w.auxData)
        );
    }

    /// Build a 17-limb withdrawal MLE proof binding `ws` to `finalizedRoot` (blockNumber = 5).
    function _withdrawalProof(IntmaxRollup.Withdrawal[] memory ws)
        internal view returns (MleVerifier.MleProof memory proof)
    {
        uint64 blockNumber = 5;
        bytes32 wdHash = bytes32(0);
        for (uint256 i = 0; i < ws.length; i++) {
            wdHash = _foldLeaf(wdHash, ws[i]);
        }
        bytes32 pisHash = keccak256(
            abi.encodePacked(wdHash, wdProver, finalizedRoot, blockNumber)
        );
        pisHash = bytes32(uint256(pisHash) & ((uint256(1) << 253) - 1));

        proof = _defaultMleProof();
        uint256[] memory pi = new uint256[](17);
        uint256 h = uint256(pisHash);
        for (uint256 i = 0; i < 8; i++) {
            pi[i] = (h >> (224 - i * 32)) & 0xFFFFFFFF;
        }
        uint256 e = uint256(finalizedRoot);
        for (uint256 i = 0; i < 8; i++) {
            pi[8 + i] = (e >> (224 - i * 32)) & 0xFFFFFFFF;
        }
        pi[16] = blockNumber;
        proof.publicInputs = pi;
    }

    function _leaf(address recipient, uint32 tokenIndex, uint256 amount, bytes32 nullifier)
        internal pure returns (IntmaxRollup.Withdrawal memory w)
    {
        w = IntmaxRollup.Withdrawal({
            recipient: recipient,
            tokenIndex: tokenIndex,
            amount: amount,
            nullifier: nullifier,
            auxData: bytes32(0)
        });
    }

    function _depositToken(SimpleERC20 token, uint32 tokenIndex, address from, uint256 amount)
        internal
    {
        token.mint(from, amount);
        vm.startPrank(from);
        token.approve(address(rollup), amount);
        rollup.deposit(bytes32(uint256(0xCAFE)), tokenIndex, amount, bytes32(0));
        vm.stopPrank();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // registerToken (TM-10b: set-once, append-only)
    // ═══════════════════════════════════════════════════════════════════════

    function test_registerToken_setOnce_guards() public {
        // index 0 is reserved for native ETH.
        vm.expectRevert(IntmaxRollup.TokenIndexZeroReservedForEth.selector);
        rollup.registerToken(0, address(tokenA));

        // address(0) rejected.
        vm.expectRevert(IntmaxRollup.TokenAddressZeroReserved.selector);
        rollup.registerToken(9, address(0));

        // non-contract rejected (a no-code address makes token calls vacuous successes).
        vm.expectRevert(IntmaxRollup.TokenNotAContract.selector);
        rollup.registerToken(9, makeAddr("not_a_contract"));

        // non-deployer rejected.
        vm.prank(makeAddr("mallory"));
        vm.expectRevert(IntmaxRollup.OnlyDeployer.selector);
        rollup.registerToken(9, address(tokenA));

        // TM-10b: RE-registration of a set index is rejected — even by the deployer, even to the
        // same address. A remappable index would convert token-A escrow into token-B withdrawals.
        vm.expectRevert(IntmaxRollup.TokenIndexAlreadyRegistered.selector);
        rollup.registerToken(TOKEN_A, address(tokenB));
        vm.expectRevert(IntmaxRollup.TokenIndexAlreadyRegistered.selector);
        rollup.registerToken(TOKEN_A, address(tokenA));

        // A fresh index still registers (append-only, not frozen).
        SimpleERC20 tokenC = new SimpleERC20("TokenC");
        rollup.registerToken(9, address(tokenC));
        assertEq(address(rollup.tokenAddressOf(9)), address(tokenC));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // deposit (TM-4: measured delta; TM-10a: reentrancy; regime retirement)
    // ═══════════════════════════════════════════════════════════════════════

    function test_deposit_erc20_escrowsMeasuredValue() public {
        address depositor = makeAddr("erc20Depositor");
        _depositToken(tokenA, TOKEN_A, depositor, 1000);

        assertEq(tokenA.balanceOf(address(rollup)), 1000, "tokens custodied");
        assertEq(rollup.escrowedByToken(TOKEN_A), 1000, "per-token escrow grew");
        assertEq(rollup.totalEscrowed(), 0, "ETH escrow untouched by ERC-20 deposits");
        assertEq(rollup.depositCount(), 1, "deposit recorded");
    }

    /// TM-4: fee-on-transfer tokens under-deliver — the measured delta != stated amount, so the
    /// deposit REVERTS (fail closed) and the hash chain never records unreceived value.
    function test_deposit_feeOnTransfer_reverts() public {
        FeeOnTransferERC20 feeToken = new FeeOnTransferERC20(100); // 1% fee
        rollup.registerToken(20, address(feeToken));
        address depositor = makeAddr("feeDepositor");
        feeToken.mint(depositor, 1000);
        vm.startPrank(depositor);
        feeToken.approve(address(rollup), 1000);
        vm.expectRevert(IntmaxRollup.TokenDepositAmountMismatch.selector);
        rollup.deposit(bytes32(uint256(1)), 20, 1000, bytes32(0));
        vm.stopPrank();
        assertEq(rollup.depositCount(), 0, "no deposit recorded");
        assertEq(rollup.escrowedByToken(20), 0, "no escrow recorded");
    }

    /// Review MINOR 1 (OZ-exact semantics): a token returning a MALFORMED 1-byte value (moves the
    /// balances, but the return data is undecodable as bool) is treated as FAILURE — never as
    /// success — so the deposit reverts and records nothing.
    function test_deposit_shortReturnToken_reverts() public {
        ShortReturnERC20 shortToken = new ShortReturnERC20();
        rollup.registerToken(24, address(shortToken));
        address depositor = makeAddr("shortDepositor");
        shortToken.mint(depositor, 100);
        vm.startPrank(depositor);
        shortToken.approve(address(rollup), 100);
        vm.expectRevert(SafeERC20Lib.TokenCallFailed.selector);
        rollup.deposit(bytes32(uint256(1)), 24, 100, bytes32(0));
        vm.stopPrank();
        assertEq(rollup.depositCount(), 0, "no deposit recorded");
        assertEq(rollup.escrowedByToken(24), 0, "no escrow recorded");
    }

    /// A token returning `false` (no revert) is treated as failure by SafeERC20Lib.
    function test_deposit_falseReturnToken_reverts() public {
        FalseReturnERC20 badToken = new FalseReturnERC20();
        rollup.registerToken(21, address(badToken));
        address depositor = makeAddr("falseDepositor");
        badToken.mint(depositor, 100);
        vm.startPrank(depositor);
        badToken.approve(address(rollup), 100);
        vm.expectRevert(SafeERC20Lib.TokenCallFailed.selector);
        rollup.deposit(bytes32(uint256(1)), 21, 100, bytes32(0));
        vm.stopPrank();
    }

    /// TM-10a: an ERC-777-style hook re-entering `deposit` during `safeTransferFrom` is blocked by
    /// `nonReentrant`; the outer deposit completes with exactly ONE escrow credit.
    function test_deposit_reentrantHook_blocked() public {
        ReentrantHookERC20 hookToken = new ReentrantHookERC20();
        rollup.registerToken(22, address(hookToken));
        address depositor = makeAddr("hookDepositor");
        hookToken.mint(depositor, 500);

        // The hook attempts a nested ETH deposit (any deposit re-entry must be rejected).
        hookToken.setHook(
            address(rollup),
            abi.encodeCall(IntmaxRollup.deposit, (bytes32(uint256(2)), 0, 0, bytes32(0))),
            true // fire on transferFrom (the deposit path)
        );

        vm.startPrank(depositor);
        hookToken.approve(address(rollup), 500);
        rollup.deposit(bytes32(uint256(1)), 22, 500, bytes32(0));
        vm.stopPrank();

        assertTrue(hookToken.hookReverted(), "reentrant deposit call must have reverted");
        assertEq(rollup.depositCount(), 1, "exactly one deposit recorded");
        assertEq(rollup.escrowedByToken(22), 500, "exactly one escrow credit");
    }

    /// ERC-20 deposits must not carry ETH (checked before registration, regression).
    function test_deposit_erc20_withEth_reverts() public {
        vm.deal(address(this), 1 ether);
        vm.expectRevert(IntmaxRollup.NonEthDepositMustNotCarryEth.selector);
        rollup.deposit{value: 1}(bytes32(uint256(1)), TOKEN_A, 100, bytes32(0));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // withdrawERC20 + withdrawToken (TM-1 layer b: per-token ceiling; asset frame)
    // ═══════════════════════════════════════════════════════════════════════

    function test_withdrawERC20_happyPath_pullPayment() public {
        _depositToken(tokenA, TOKEN_A, makeAddr("d1"), 1000);

        IntmaxRollup.Withdrawal[] memory ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = _leaf(recipient1, TOKEN_A, 400, keccak256("nA1"));
        rollup.withdrawERC20(ws, wdProver, _withdrawalProof(ws));

        assertEq(rollup.escrowedByToken(TOKEN_A), 600, "escrow ceiling decremented");
        assertEq(
            rollup.pendingTokenWithdrawals(TOKEN_A, recipient1), 400, "pull credit recorded"
        );
        assertTrue(rollup.withdrawalNullifierUsed(keccak256("nA1")), "nullifier consumed");

        // Pull the tokens.
        vm.prank(recipient1);
        rollup.withdrawToken(TOKEN_A);
        assertEq(tokenA.balanceOf(recipient1), 400, "recipient received real tokens");
        assertEq(rollup.pendingTokenWithdrawals(TOKEN_A, recipient1), 0, "credit cleared");

        // Double-pay via the same nullifier is rejected.
        MleVerifier.MleProof memory proof = _withdrawalProof(ws);
        vm.expectRevert(IntmaxRollup.WithdrawalNullifierUsed.selector);
        rollup.withdrawERC20(ws, wdProver, proof);
    }

    /// Asset frame: `withdrawNative` refuses ERC-20 leaves; `withdrawERC20` refuses ETH leaves and
    /// unregistered indices.
    function test_withdraw_assetFrame() public {
        _depositToken(tokenA, TOKEN_A, makeAddr("d2"), 100);

        IntmaxRollup.Withdrawal[] memory erc20Ws = new IntmaxRollup.Withdrawal[](1);
        erc20Ws[0] = _leaf(recipient1, TOKEN_A, 50, keccak256("nF1"));
        MleVerifier.MleProof memory erc20Proof = _withdrawalProof(erc20Ws);
        vm.expectRevert(IntmaxRollup.WithdrawalNotEthToken.selector);
        rollup.withdrawNative(erc20Ws, wdProver, erc20Proof);

        IntmaxRollup.Withdrawal[] memory ethWs = new IntmaxRollup.Withdrawal[](1);
        ethWs[0] = _leaf(recipient1, 0, 50, keccak256("nF2"));
        MleVerifier.MleProof memory ethProof = _withdrawalProof(ethWs);
        vm.expectRevert(IntmaxRollup.WithdrawalNotErc20Token.selector);
        rollup.withdrawERC20(ethWs, wdProver, ethProof);

        IntmaxRollup.Withdrawal[] memory unregWs = new IntmaxRollup.Withdrawal[](1);
        unregWs[0] = _leaf(recipient1, 999, 50, keccak256("nF3"));
        MleVerifier.MleProof memory unregProof = _withdrawalProof(unregWs);
        vm.expectRevert(IntmaxRollup.TokenIndexNotRegistered.selector);
        rollup.withdrawERC20(unregWs, wdProver, unregProof);
    }

    /// TM-1 (duplicate-index drain / cross-channel bound): two "channels" (two proofs, distinct
    /// nullifiers — e.g. one channel registering token A at two local slots, or two channels
    /// sharing the token) can NEVER extract more of token A than its REAL total escrow. The
    /// per-token `escrowedByToken` underflow ceiling reverts the excess withdrawal regardless of
    /// what any channel-local registry claimed.
    function test_perToken_escrowCeiling_boundsCombinedDrain() public {
        _depositToken(tokenA, TOKEN_A, makeAddr("chan1"), 60);
        _depositToken(tokenA, TOKEN_A, makeAddr("chan2"), 40);
        assertEq(rollup.escrowedByToken(TOKEN_A), 100);

        // First drain attempt: 60 (fits).
        IntmaxRollup.Withdrawal[] memory ws1 = new IntmaxRollup.Withdrawal[](1);
        ws1[0] = _leaf(recipient1, TOKEN_A, 60, keccak256("nD1"));
        rollup.withdrawERC20(ws1, wdProver, _withdrawalProof(ws1));

        // Second: 50 > remaining 40 → the whole call reverts (underflow ceiling).
        IntmaxRollup.Withdrawal[] memory ws2 = new IntmaxRollup.Withdrawal[](1);
        ws2[0] = _leaf(recipient2, TOKEN_A, 50, keccak256("nD2"));
        MleVerifier.MleProof memory p2 = _withdrawalProof(ws2);
        vm.expectRevert(); // arithmetic underflow (Solidity 0.8 checked math)
        rollup.withdrawERC20(ws2, wdProver, p2);

        // Exactly the remaining 40 still succeeds.
        IntmaxRollup.Withdrawal[] memory ws3 = new IntmaxRollup.Withdrawal[](1);
        ws3[0] = _leaf(recipient2, TOKEN_A, 40, keccak256("nD3"));
        rollup.withdrawERC20(ws3, wdProver, _withdrawalProof(ws3));
        assertEq(rollup.escrowedByToken(TOKEN_A), 0, "ceiling exactly exhausted");
    }

    /// Cross-token frame: token-B escrow can NEVER be released by token-A withdrawals — the
    /// per-token ceiling is keyed by base token index, not by a global sum.
    function test_perToken_escrowCeiling_noCrossTokenDraw() public {
        _depositToken(tokenA, TOKEN_A, makeAddr("d3"), 30);
        _depositToken(tokenB, TOKEN_B, makeAddr("d4"), 100);

        // 50 token-A against 30 token-A escrow reverts even though 130 total escrow exists.
        IntmaxRollup.Withdrawal[] memory ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = _leaf(recipient1, TOKEN_A, 50, keccak256("nX1"));
        MleVerifier.MleProof memory p = _withdrawalProof(ws);
        vm.expectRevert();
        rollup.withdrawERC20(ws, wdProver, p);
        assertEq(rollup.escrowedByToken(TOKEN_B), 100, "token-B escrow untouched");
    }

    /// TM-10a: a hook token re-entering `withdrawToken` during the payout transfer is blocked
    /// (credit already zeroed + nonReentrant); the recipient is paid exactly once.
    function test_withdrawToken_reentrantHook_blocked() public {
        ReentrantHookERC20 hookToken = new ReentrantHookERC20();
        rollup.registerToken(23, address(hookToken));
        address depositor = makeAddr("hookDepositor2");
        hookToken.mint(depositor, 500);
        vm.startPrank(depositor);
        hookToken.approve(address(rollup), 500);
        rollup.deposit(bytes32(uint256(1)), 23, 500, bytes32(0));
        vm.stopPrank();

        IntmaxRollup.Withdrawal[] memory ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = _leaf(recipient1, 23, 200, keccak256("nR1"));
        rollup.withdrawERC20(ws, wdProver, _withdrawalProof(ws));

        // The hook (fires on `transfer`, i.e. the payout path) attempts a nested withdrawToken.
        hookToken.setHook(
            address(rollup), abi.encodeCall(IntmaxRollup.withdrawToken, (uint32(23))), false
        );
        vm.prank(recipient1);
        rollup.withdrawToken(23);

        assertTrue(hookToken.hookReverted(), "reentrant withdrawToken must have reverted");
        assertEq(hookToken.balanceOf(recipient1), 200, "paid exactly once");
        assertEq(rollup.pendingTokenWithdrawals(23, recipient1), 0, "credit cleared once");
    }

    /// ETH regression frame: the ETH path's global `totalEscrowed` semantics are untouched by the
    /// ERC-20 machinery (escrowedByToken[0] is never written).
    function test_ethPath_unchangedByErc20Machinery() public {
        vm.deal(address(this), 10 ether);
        rollup.deposit{value: 3 ether}(bytes32(uint256(0xE)), 0, 3 ether, bytes32(0));
        assertEq(rollup.totalEscrowed(), 3 ether, "ETH stays on totalEscrowed");
        assertEq(rollup.escrowedByToken(0), 0, "escrowedByToken[0] never used");

        IntmaxRollup.Withdrawal[] memory ws = new IntmaxRollup.Withdrawal[](1);
        ws[0] = _leaf(recipient1, 0, 1 ether, keccak256("nE1"));
        rollup.withdrawNative(ws, wdProver, _withdrawalProof(ws));
        assertEq(rollup.totalEscrowed(), 2 ether, "ETH ceiling decremented");
        assertEq(rollup.pendingWithdrawals(recipient1), 1 ether, "ETH pull credit");
    }

    receive() external payable {}
}
