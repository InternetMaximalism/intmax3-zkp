// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {TestProofDaVerifier} from "./helpers/ProofDaTestHelper.sol";


/// @title Shared real-fixture harness for the native-ETH withdrawal E2E suites.
/// @notice Extracted from `WithdrawNativeE2E.t.sol` (2026-07-28) so the partial-withdrawal payout
///         suite can reuse the SAME real rollup, real withdrawal VK and real lifecycle rather than
///         copy-pasting them. Carries setUp + helpers only, NO test functions, so inheriting it does
///         not re-run the withdrawal suite (same pattern as `CloseE2EBase` / `CloseSettlementBase`).
///
/// Exercises the complete honest lifecycle:
///   registerChannel -> deposit{value} -> postBlock x3 -> finalize(validity proof)
/// leaving `latestFinalizedStateRoot == lifecycle.final_state_root`, so a real withdrawal proof
/// verifies against it.
///
/// @dev Fixtures produced by `cargo run --bin generate_withdrawal_fixture --release`:
///        - lifecycle.json               (registration / deposit / blocks / vpis)
///        - lifecycle_validity_mle.json  (validity MLE proof + VK, for finalize)
///        - withdrawal_mle.json          (withdrawal MLE proof + VK, for withdrawNative)
///        - withdrawal_payout.json       (the committed Withdrawal[] + prover)
///      If the fixtures are absent (heavy proving not yet run), `fixturesReady` is false and every
///      inheriting test self-skips.
abstract contract WithdrawNativeE2EBase is Test {
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

    /// Which fixture set to load. "" = the default normal-withdrawal set; a subclass overrides it to
    /// load a variant set (e.g. "burn_" for the partial-withdrawal payout suite, whose leaf carries
    /// `aux_data != 0`). Keeping the whole lifecycle harness shared means the burn suite runs against
    /// byte-identical rollup wiring — only the proved leaf differs.
    function _fixturePrefix() internal pure virtual returns (string memory) {
        return "";
    }

    function setUp() public virtual {
        // Load fixtures; if any is missing the heavy proving step hasn't run yet — self-skip.
        string memory root = string.concat(vm.projectRoot(), "/test/data/", _fixturePrefix());
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
        rollup.setKzgVerifier(BlobKZGVerifierExt(address(new TestProofDaVerifier())));
        rollup.setBlockProducer(poster, true); // permissioned posting

        // Set the WITHDRAWAL VK (deployer-only, set-once). deployer == this test contract.
        FixtureLib.DeployData memory wdd = FixtureLib.parseDeployData(withdrawalMleJson);
        IntmaxRollup.MleVk memory wvk = FixtureLib.buildMleVk(withdrawalMleJson, verifier);
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
        bytes32 pin = rollup.pendingChainsPin();
        vm.prank(poster);
        rollup.postBlockAndSubmit{value: STAKE}(subBlocks, proofHash, proofLength, stateRoot, pin);
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
