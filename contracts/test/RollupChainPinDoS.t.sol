// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// M-5 (audit28-08-2026): the permissionless-writer DoS on block posting, and the pin that stops it.
//
// `_pendingDepositHashChain` and `_pendingChannelRegHashChain` are LIVE CUMULATIVE and are folded
// into the last sub-block at POSTING time. A producer generates its witness against the values it
// reads, so a 1 wei permissionless `deposit()` or a deployer-authorized `registerChannel()` landing
// in between makes `_postBlock` commit a different chain than the proof was built over.
// `finalize` then fails SILENTLY (it returns false), `finalizedStateRoots` never advances, and EVERY
// withdrawal is blocked until the ~12 h `FINALIZE_DEADLINE_BLOCKS` timeout lets someone truncate the
// stuck submission. One cheap transaction per window bought a 12-hour chain halt, repeatable.
//
// The release fix retains every real pending-chain pair as a monotone checkpoint. An already-built
// proof consumes its exact historical prefix even if a later record lands; that later record stays
// pending for the next proof. Unknown or regressive pins still fail closed.

import {Test} from "forge-std/Test.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {BlobKZGVerifierExt} from "../src/BlobKZGVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {TestProofDaVerifier} from "./helpers/ProofDaTestHelper.sol";

contract RollupChainPinDoSTest is Test {
    IntmaxRollup internal rollup;
    address internal constant GRIEFER = address(0xBEEF);

    function setUp() public {
        MleVerifier mle = new MleVerifier(block.chainid);
        IntmaxRollup.MleVk memory emptyVk;
        rollup = new IntmaxRollup(
            address(this),                 // fraudTreasury
            emptyVk,                       // mleVk (zero => verification disabled, allowed below)
            _emptyWhir(), "", "",
            new uint256[](0), new uint256[](0),
            mle,
            bytes32(0),                    // genesisStateRoot
            true                           // allowMleDisabled (this test never verifies a proof)
        );
        rollup.setKzgVerifier(BlobKZGVerifierExt(address(new TestProofDaVerifier())));
        rollup.setBlockProducer(address(this), true);
        vm.deal(address(this), 100 ether);
        vm.deal(GRIEFER, 10 ether);
    }

    function _emptyWhir() internal pure returns (SpongefishWhirVerify.WhirParams memory p) {
        return p;
    }

    function _batch() internal pure returns (IntmaxRollup.SubBlock[] memory b) {
        b = new IntmaxRollup.SubBlock[](1);
        b[0] = IntmaxRollup.SubBlock({
            channelId: 1, timestamp: 1, txTreeRoot: bytes32(uint256(7)), keyIds: new uint32[](0)
        });
    }

    function _mockBlob() internal {
        bytes32[] memory h = new bytes32[](1);
        h[0] = bytes32(uint256(0x01 << 248) | uint256(1));
        vm.blobhashes(h);
    }

    function _register(uint32 channelId, uint256 seed) internal {
        bytes32[] memory pk = new bytes32[](2);
        pk[0] = bytes32(seed + 11); pk[1] = bytes32(seed + 12);
        bytes32[] memory pkb = new bytes32[](2);
        pkb[0] = bytes32(seed + 21); pkb[1] = bytes32(seed + 22);
        bytes32[] memory rg = new bytes32[](2);
        rg[0] = bytes32(seed + 31); rg[1] = bytes32(seed + 32);
        address[] memory rc = new address[](2);
        rc[0] = address(uint160(seed + 0x1001)); rc[1] = address(uint160(seed + 0x1002));
        rollup.registerChannel(channelId, 0, 0, pk, pkb, rg, rc);
    }

    /// The griefer's 1 wei deposit cannot invalidate the already-built prefix. Block 1 consumes
    /// the zero-chain checkpoint and block 2 later consumes the deposit, with no proof substitution.
    function test_M5_griefersDepositRemainsPendingAfterHistoricalPrefixPosts() public {
        bytes32 pin = rollup.pendingChainsPin();

        vm.prank(GRIEFER);
        rollup.deposit{value: 1}(bytes32(uint256(0xAA)), 0, 1, bytes32(0));
        bytes32 depositPin = rollup.pendingChainsPin();

        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(_batch(), bytes32(uint256(1)), 1, bytes32(uint256(9)), pin);
        assertEq(rollup.blockDepositHash(1), bytes32(0), "proved historical prefix is preserved");
        assertEq(rollup.processedDepositCount(), 0, "racing deposit remains pending");

        // The next witness can consume the still-pending deposit checkpoint.
        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(2)), 1, bytes32(uint256(10)), depositPin
        );
        assertEq(rollup.blockDepositHash(2), rollup.depositHashChain(), "next block consumes deposit");
        assertEq(rollup.processedDepositCount(), 1, "deposit consumed exactly once");
        assertEq(rollup.nextSubmissionId(), 2, "both sound prefixes posted");
    }

    /// The same prefix behavior applies to an authorized registration racing publication.
    function test_M5_authorizedRegistrationRemainsPendingAfterHistoricalPrefixPosts() public {
        bytes32 pin = rollup.pendingChainsPin();

        _register(4242, 0);
        bytes32 registrationPin = rollup.pendingChainsPin();

        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(_batch(), bytes32(uint256(1)), 1, bytes32(uint256(9)), pin);
        assertEq(rollup.blockChannelRegHash(1), bytes32(0), "proved registration prefix is preserved");

        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(2)), 1, bytes32(uint256(10)), registrationPin
        );
        assertEq(rollup.blockChannelRegHash(2), rollup.channelRegHashChain(), "next block consumes registration");
    }

    /// Deposit count alone is not an ordering relation: two registration-only checkpoints have
    /// the same deposit count. Once the newer registration prefix is consumed, an older pin must
    /// not be able to rewind the channel-registration accumulator.
    function test_M5_registrationOnlyCheckpointCannotRegress() public {
        _register(4242, 0);
        bytes32 firstRegistrationPin = rollup.pendingChainsPin();
        _register(4243, 100);
        bytes32 secondRegistrationPin = rollup.pendingChainsPin();

        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(1)), 1, bytes32(uint256(9)), secondRegistrationPin
        );

        _mockBlob();
        vm.expectRevert(IntmaxRollup.PendingChainsMoved.selector);
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(2)), 1, bytes32(uint256(10)), firstRegistrationPin
        );
    }

    /// With no new pending record, the exact current pair is still a valid carry-forward prefix.
    function test_M5_currentCheckpointMayCarryForwardAcrossEmptyRounds() public {
        bytes32 pin = rollup.pendingChainsPin();
        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(_batch(), bytes32(uint256(1)), 1, bytes32(uint256(9)), pin);
        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(_batch(), bytes32(uint256(2)), 1, bytes32(uint256(10)), pin);
        assertEq(rollup.nextSubmissionId(), 2);
    }

    function test_M5_unknownAndRegressivePinsFailClosed() public {
        bytes32 genesisPin = rollup.pendingChainsPin();
        vm.prank(GRIEFER);
        rollup.deposit{value: 1}(bytes32(uint256(0xAA)), 0, 1, bytes32(0));
        bytes32 latestPin = rollup.pendingChainsPin();

        _mockBlob();
        vm.expectRevert(IntmaxRollup.PendingChainsMoved.selector);
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(1)), 1, bytes32(uint256(9)), bytes32(uint256(123456))
        );

        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(2)), 1, bytes32(uint256(10)), latestPin
        );
        _mockBlob();
        vm.expectRevert(IntmaxRollup.PendingChainsMoved.selector);
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(3)), 1, bytes32(uint256(11)), genesisPin
        );
    }

    /// A fraud/timeout rollback rewinds only the processed prefix. The immutable pending
    /// checkpoint remains available, so the exact sound prefix can be reposted without erasing the
    /// deposit record or silently switching to a newer accumulator.
    function test_M5_checkpointSurvivesRollbackAndCanBeReposted() public {
        vm.prank(GRIEFER);
        rollup.deposit{value: 1}(bytes32(uint256(0xAA)), 0, 1, bytes32(0));
        bytes32 depositPin = rollup.pendingChainsPin();

        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(1)), 1, bytes32(uint256(9)), depositPin
        );
        assertEq(rollup.processedDepositCount(), 1);

        vm.roll(block.number + 3601);
        IntmaxRollup.ValidityPublicInputs memory emptyPis;
        assertTrue(rollup.fraudProof(0, bytes32(0), emptyPis, bytes("")), "timeout removes batch");
        assertEq(rollup.processedDepositCount(), 0, "rollback restores processed prefix count");
        assertEq(rollup.blockNumber(), 0, "rollback restores block height");

        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(2)), 1, bytes32(uint256(10)), depositPin
        );
        assertEq(rollup.processedDepositCount(), 1, "same real checkpoint remains postable");
        assertEq(rollup.blockDepositHash(1), rollup.depositHashChain());
    }

    /// An unraced post succeeds — the pin is not a new honest-path revert (gate-8 class check).
    function test_M5_unracedPostSucceeds() public {
        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(1)), 1, bytes32(uint256(9)), rollup.pendingChainsPin()
        );
        assertEq(rollup.nextSubmissionId(), 1, "honest post landed");
    }

    /// A candidate is built over predecessor (0, 0). If another authorized producer advances the
    /// rollup before the candidate is mined, the guarded transaction must lose no stake and leave
    /// no orphan submission. A publisher-side preflight alone cannot provide this property.
    function test_guardedPost_competingProducerMoveRevertsBeforeMutation() public {
        bytes32 candidatePin = rollup.pendingChainsPin();
        uint64 candidateBlockNumber = rollup.blockNumber();
        bytes32 candidateBlockHashChain = rollup.blockHashChain();

        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(100)), 1, bytes32(uint256(200)), candidatePin
        );

        uint256 submissionsAfterCompetitor = rollup.nextSubmissionId();
        uint64 blockNumberAfterCompetitor = rollup.blockNumber();
        bytes32 blockHashAfterCompetitor = rollup.blockHashChain();
        uint256 balanceAfterCompetitor = address(rollup).balance;

        _mockBlob();
        vm.expectRevert(IntmaxRollup.BlockHeadMoved.selector);
        rollup.postBlockAndSubmitGuarded{value: 1 ether}(
            _batch(),
            bytes32(uint256(101)),
            1,
            bytes32(uint256(201)),
            candidatePin,
            candidateBlockNumber,
            candidateBlockHashChain
        );

        assertEq(rollup.nextSubmissionId(), submissionsAfterCompetitor, "no orphan submission");
        assertEq(rollup.blockNumber(), blockNumberAfterCompetitor, "no orphan block");
        assertEq(rollup.blockHashChain(), blockHashAfterCompetitor, "head remains competitor head");
        assertEq(address(rollup).balance, balanceAfterCompetitor, "guarded candidate stake refunded");
    }

    function test_guardedPost_exactPredecessorSucceeds() public {
        _mockBlob();
        rollup.postBlockAndSubmitGuarded{value: 1 ether}(
            _batch(),
            bytes32(uint256(1)),
            1,
            bytes32(uint256(9)),
            rollup.pendingChainsPin(),
            rollup.blockNumber(),
            rollup.blockHashChain()
        );
        assertEq(rollup.nextSubmissionId(), 1, "exact predecessor candidate landed");
    }

    /// The compatibility selector cannot become a production bypass when the PCS release gate is
    /// later opened for an explicitly configured chain.
    function test_legacyPostSelector_isPermanentlyLocalDevnetOnly() public {
        bytes32 pin = rollup.pendingChainsPin();
        vm.chainId(1);
        _mockBlob();
        vm.expectRevert(IntmaxRollup.ReleaseRuntimeUnavailable.selector);
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(1)), 1, bytes32(uint256(9)), pin
        );
        assertEq(rollup.nextSubmissionId(), 0);
    }

    /// M-5 (squatting half): a targeted front-run is an authorization problem, not a pricing
    /// problem. A stranger cannot occupy the one-shot id, even if it sends the retired fee amount.
    function test_M5_channelSquattingIsDeployerOnlyEvenWithLegacyFee() public {
        bytes32[] memory pk = new bytes32[](2);
        pk[0] = bytes32(uint256(11)); pk[1] = bytes32(uint256(12));
        bytes32[] memory pkb = new bytes32[](2);
        pkb[0] = bytes32(uint256(21)); pkb[1] = bytes32(uint256(22));
        bytes32[] memory rg = new bytes32[](2);
        rg[0] = bytes32(uint256(31)); rg[1] = bytes32(uint256(32));
        address[] memory rc = new address[](2);
        rc[0] = address(0x1001); rc[1] = address(0x1002);

        // The function-level authorization produces the explicit reason on an ordinary call.
        vm.prank(GRIEFER);
        vm.expectRevert(IntmaxRollup.OnlyDeployer.selector);
        rollup.registerChannel(4242, 0, 0, pk, pkb, rg, rc);

        // A legacy caller trying to attach the former 0.003 ETH fee is rejected by the nonpayable
        // ABI before it can occupy the id.
        bytes memory callData = abi.encodeWithSelector(
            rollup.registerChannel.selector, 4242, 0, 0, pk, pkb, rg, rc
        );
        vm.prank(GRIEFER);
        (bool ok, ) = address(rollup).call{value: 0.003 ether}(callData);
        assertFalse(ok, "legacy fee must not bypass deployer authorization");
        assertEq(rollup.channelMemberSetCommitment(4242), bytes32(0), "target id remains free");

        // The immutable deployer can still perform the intended one-shot registration.
        rollup.registerChannel(4242, 0, 0, pk, pkb, rg, rc);
        assertTrue(rollup.channelMemberSetCommitment(4242) != bytes32(0));
    }

    /// The unpinned overload is absent, so no deployment can skip the pin.
    function test_M5_unpinnedOverloadIsRemoved() public {
        _mockBlob();
        bytes memory legacyCall = abi.encodeWithSignature(
            "postBlockAndSubmit((uint32,uint64,bytes32,uint32[])[],bytes32,uint32,bytes32)",
            _batch(),
            bytes32(uint256(1)),
            uint32(1),
            bytes32(uint256(9))
        );
        (bool ok,) = address(rollup).call{value: 1 ether}(legacyCall);
        assertFalse(ok, "retired unpinned selector must not be callable");
        assertEq(rollup.nextSubmissionId(), 0, "retired selector must not mutate state");
    }
}
