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
// The fix makes the producer declare the pin it proved against, so the race is a CLEAN REVERT and
// the producer simply re-reads and retries.

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

    /// THE ATTACK, blocked: the griefer's 1 wei deposit lands between the producer reading the pin
    /// and posting. The post now REVERTS cleanly instead of committing an unfinalizable batch.
    function test_M5_griefersDepositMakesThePostRevertCleanly() public {
        bytes32 pin = rollup.pendingChainsPin();

        vm.prank(GRIEFER);
        rollup.deposit{value: 1}(bytes32(uint256(0xAA)), 0, 1, bytes32(0));

        _mockBlob();
        vm.expectRevert(IntmaxRollup.PendingChainsMoved.selector);
        rollup.postBlockAndSubmit{value: 1 ether}(_batch(), bytes32(uint256(1)), 1, bytes32(uint256(9)), pin);

        // And the producer simply retries with a fresh pin — no halt, no stuck submission.
        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(1)), 1, bytes32(uint256(9)), rollup.pendingChainsPin()
        );
        assertEq(rollup.nextSubmissionId(), 1, "the retry posted");
    }

    /// The same clean retry behavior for an authorized registration racing the producer's pin.
    function test_M5_authorizedRegistrationMakesThePostRevertCleanly() public {
        bytes32 pin = rollup.pendingChainsPin();

        bytes32[] memory pk = new bytes32[](2);
        pk[0] = bytes32(uint256(11)); pk[1] = bytes32(uint256(12));
        bytes32[] memory pkb = new bytes32[](2);
        pkb[0] = bytes32(uint256(21)); pkb[1] = bytes32(uint256(22));
        bytes32[] memory rg = new bytes32[](2);
        rg[0] = bytes32(uint256(31)); rg[1] = bytes32(uint256(32));
        address[] memory rc = new address[](2);
        rc[0] = address(0x1001); rc[1] = address(0x1002);

        rollup.registerChannel(4242, 0, 0, pk, pkb, rg, rc);

        _mockBlob();
        vm.expectRevert(IntmaxRollup.PendingChainsMoved.selector);
        rollup.postBlockAndSubmit{value: 1 ether}(_batch(), bytes32(uint256(1)), 1, bytes32(uint256(9)), pin);
    }

    /// An unraced post succeeds — the pin is not a new honest-path revert (gate-8 class check).
    function test_M5_unracedPostSucceeds() public {
        _mockBlob();
        rollup.postBlockAndSubmit{value: 1 ether}(
            _batch(), bytes32(uint256(1)), 1, bytes32(uint256(9)), rollup.pendingChainsPin()
        );
        assertEq(rollup.nextSubmissionId(), 1, "honest post landed");
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
