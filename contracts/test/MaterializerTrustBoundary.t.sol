// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseFundingMaterializer} from "../src/CloseFundingMaterializer.sol";
import {IPinnedMleVerifierV2} from "../src/IPinnedMleVerifierV2.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {MockPinnedMleVerifierV2} from "./helpers/MockPinnedMleVerifierV2.sol";

/// @dev A satellite that answers `bindManager` and then uses the Rollup's exit-credit gate for
///      itself. Whatever `registerSettlementManager` installs as the exit materializer may call
///      `creditChannelExit`; nothing else in the Rollup binds the credited amounts to a proof.
contract FakeExitMaterializer {
    function bindManager(address) external {}

    function drain(IntmaxRollup rollup, address manager, uint32 tokenIndex, uint256 amount) external {
        rollup.creditChannelExit(manager, tokenIndex, amount);
    }

    function pull(IntmaxRollup rollup, uint256 amount) external {
        rollup.withdraw(amount);
    }

    receive() external payable {}
}

/// @dev The only thing `registerSettlementManager` reads from a Manager is this getter.
contract FakeManagerAdvertisingSatellite {
    address public immutable closeFundingMaterializer;

    constructor(address satellite) {
        closeFundingMaterializer = satellite;
    }
}

/// @dev A Manager that answers every getter the real materializer reads on the signed-head exit
///      path, with amounts of its own choosing. It is bound through the deployer-only
///      `registerSettlementManager` exactly like a real Manager; `bindManager` checks ABI answers
///      only.
contract LyingManager {
    bytes4 public channelId;
    IntmaxRollup public registry;
    address public closeFundingMaterializer;
    ChannelSettlementManager.ChannelLifecycleStatus public channelStatus;
    uint64 public closeRequestGeneration = 1;
    bytes32 public finalizedCloseIntentDigest = bytes32(uint256(1));
    bytes32 public finalizedChannelFundIntmaxStateRoot;
    uint8 public finalizedTokenCount = 1;
    bytes32 public finalizedSettledTxChain;
    bytes32 public finalizedTokenFundsDigest;
    mapping(uint256 => uint32) private _registry;
    mapping(uint32 => uint256) private _amount;

    constructor(uint32 channelId_, IntmaxRollup rollup, address materializer, bytes32 fundRoot) {
        channelId = bytes4(channelId_);
        registry = rollup;
        closeFundingMaterializer = materializer;
        finalizedChannelFundIntmaxStateRoot = fundRoot;
    }

    function finalizedTokenRegistry(uint256 i) external view returns (uint32) {
        return _registry[i];
    }

    function finalizedChannelFundAmount(uint32 tokenIndex) external view returns (uint256) {
        return _amount[tokenIndex];
    }

    function setFinalized(bytes32 chain, bytes32 tokenFundsDigest, uint32 tokenIndex, uint256 amount) external {
        finalizedSettledTxChain = chain;
        finalizedTokenFundsDigest = tokenFundsDigest;
        _registry[0] = tokenIndex;
        _amount[tokenIndex] = amount;
    }

    function setStatus(ChannelSettlementManager.ChannelLifecycleStatus status) external {
        channelStatus = status;
    }

    function freeze(CloseFundingMaterializer materializer, uint32 channelId_, uint64 generation) external {
        materializer.freezeFromManager(channelId_, generation);
    }

    function pull(IntmaxRollup rollup, uint256 amount) external {
        rollup.withdraw(amount);
    }

    receive() external payable {}
}

/// Pass-3 H2 (2026-10-16): the deployer-only settlement registration must not be able to move
/// escrow without a proof. Two variants were reachable on 5957f094:
///   A. with the exit-materializer slot still empty, install a satellite that calls
///      `creditChannelExit` directly;
///   B. with the real materializer installed, bind a Manager that echoes a real backing proof's
///      settled chain / token-funds digest but reports inflated `finalizedChannelFundAmount`.
contract MaterializerTrustBoundaryTest is Test {
    uint32 internal constant CHANNEL_ID = 7;
    bytes32 internal constant GENESIS_ROOT = bytes32(uint256(0x1234));
    uint32 internal constant TOKEN_FUNDS_DIGEST_DOMAIN = 0x494d5446;

    IntmaxRollup internal rollup;
    CloseFundingMaterializer internal materializer;
    address internal user = makeAddr("depositor");

    function setUp() public {
        rollup = new IntmaxRollup(
            makeAddr("treasury"),
            IPinnedMleVerifierV2(address(new MockPinnedMleVerifierV2(block.chainid))),
            IPinnedMleVerifierV2(address(new MockPinnedMleVerifierV2(block.chainid))),
            GENESIS_ROOT,
            0.1 ether,
            0.001 ether
        );
        materializer = new CloseFundingMaterializer(
            rollup,
            IPinnedMleVerifierV2(address(new MockPinnedMleVerifierV2(block.chainid))),
            IPinnedMleVerifierV2(address(new MockPinnedMleVerifierV2(block.chainid)))
        );
        vm.deal(user, 100 ether);
    }

    function _deposit(uint256 amount) internal {
        vm.prank(user);
        rollup.deposit{value: amount}(bytes32(uint256(0xABCD)), 0, amount, bytes32(0));
    }

    function _registerChannel() internal {
        bytes32[] memory pkGs = new bytes32[](2);
        bytes32[] memory pkBs = new bytes32[](2);
        bytes32[] memory regev = new bytes32[](2);
        address[] memory recipients = new address[](2);
        for (uint256 i = 0; i < 2; ++i) {
            pkGs[i] = bytes32(uint256(11 + i));
            pkBs[i] = bytes32(uint256(21 + i));
            regev[i] = bytes32(uint256(31 + i));
            recipients[i] = address(uint160(41 + i));
        }
        rollup.registerChannel(CHANNEL_ID, 0, 0, pkGs, pkBs, regev, recipients);
    }

    /// Byte-exact copy of `ChannelSettlementVerifier.tokenFundsDigest` (the Rust IMTF digest).
    function _tokenFundsDigest(uint32[10] memory tokenRegistry, uint8 tokenCount, uint256[10] memory amounts)
        internal
        pure
        returns (bytes32)
    {
        bytes memory pre = abi.encodePacked(bytes4(TOKEN_FUNDS_DIGEST_DOMAIN));
        for (uint256 t = 0; t < 10; t++) {
            pre = abi.encodePacked(pre, tokenRegistry[t]);
        }
        pre = abi.encodePacked(pre, uint32(tokenCount));
        for (uint256 t = 0; t < 10; t++) {
            pre = abi.encodePacked(pre, amounts[t]);
        }
        return keccak256(pre);
    }

    function _putLimbs(uint256[] memory pi, uint256 offset, bytes32 value) internal pure {
        uint256 v = uint256(value);
        for (uint256 i = 0; i < 8; ++i) {
            pi[offset + i] = (v >> (32 * (7 - i))) & 0xffffffff;
        }
    }

    /// The 35-limb CloseAssetBacking statement the mock adapter "verifies".
    function _backingProof(bytes32 chain, bytes32 tokenFundsDigest) internal pure returns (bytes memory) {
        uint256[] memory pi = new uint256[](35);
        pi[0] = CHANNEL_ID;
        _putLimbs(pi, 1, chain);
        _putLimbs(pi, 9, tokenFundsDigest);
        _putLimbs(pi, 17, GENESIS_ROOT);
        pi[25] = 0;
        pi[26] = 0;
        return abi.encode(pi);
    }

    /// Bind a lying Manager for a registered channel while the escrow is still empty (the
    /// legitimate deployment order), then let a user deposit.
    function _bindLyingManager(bytes32 chain, bytes32 tokenFundsDigest, uint256 reportedAmount)
        internal
        returns (LyingManager lying)
    {
        _registerChannel();
        lying = new LyingManager(CHANNEL_ID, rollup, address(materializer), GENESIS_ROOT);
        lying.setFinalized(chain, tokenFundsDigest, 0, reportedAmount);
        rollup.registerSettlementManager(address(lying));
        assertEq(materializer.managerOfChannel(CHANNEL_ID), address(lying));
        _deposit(5 ether);
        lying.setStatus(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending);
        lying.freeze(materializer, CHANNEL_ID, 1);
        lying.setStatus(ChannelSettlementManager.ChannelLifecycleStatus.Closed);
    }

    /// Variant A. A satellite advertised by a Manager with no other ABI is installed into the exit
    /// slot and drains the escrow with two calls. The fix refuses to install a materializer while
    /// escrow already exists: the satellite must be in place before anyone deposits, where every
    /// depositor can inspect it first.
    function test_installingAnExitMaterializerAfterDepositsIsRefused() public {
        _deposit(1 ether);
        FakeExitMaterializer fake = new FakeExitMaterializer();
        FakeManagerAdvertisingSatellite manager = new FakeManagerAdvertisingSatellite(address(fake));

        vm.expectRevert(IntmaxRollup.InvalidChannelExitManager.selector);
        rollup.registerSettlementManager(address(manager));

        // The slot stayed empty, so the satellite cannot reach the escrow.
        vm.expectRevert(IntmaxRollup.InvalidChannelExitManager.selector);
        fake.drain(rollup, address(fake), 0, 1 ether);
        assertEq(rollup.totalEscrowed(), 1 ether);
    }

    /// Variant A, the measured attack shape on the unfixed tree (kept as documentation of the
    /// drain; it must now stop at registration).
    function test_fakeSatelliteCannotDrainEscrow() public {
        _deposit(1 ether);
        FakeExitMaterializer fake = new FakeExitMaterializer();
        FakeManagerAdvertisingSatellite manager = new FakeManagerAdvertisingSatellite(address(fake));
        try rollup.registerSettlementManager(address(manager)) {} catch {}
        try fake.drain(rollup, address(fake), 0, 1 ether) {} catch {}
        try fake.pull(rollup, 1 ether) {} catch {}
        assertEq(address(fake).balance, 0, "a deployer-installed satellite drained the escrow");
        assertEq(rollup.totalEscrowed(), 1 ether);
    }

    /// Variant B. The lying Manager echoes the proof's chain and token-funds digest but reports the
    /// whole escrow as its channel fund. The fix recomputes the digest from the amounts it is about
    /// to credit and refuses the mismatch.
    function test_materializeRefusesAmountsTheBackingProofDoesNotAttest() public {
        uint32[10] memory registry;
        uint256[10] memory amounts;
        amounts[0] = 1 wei;
        bytes32 chain = keccak256("settled chain");
        bytes32 tfd = _tokenFundsDigest(registry, 1, amounts);
        LyingManager lying = _bindLyingManager(chain, tfd, 5 ether);
        bytes memory proof = _backingProof(chain, tfd);
        ChannelSettlementManager m = ChannelSettlementManager(payable(address(lying)));

        materializer.attestSignedHeadBacking(m, proof);
        vm.expectRevert(CloseFundingMaterializer.ChannelExitTokenFundsDigestMismatch.selector);
        materializer.materializeSignedHead(m, proof);

        // Nothing moved.
        try lying.pull(rollup, 5 ether) {} catch {}
        assertEq(address(lying).balance, 0, "a lying Manager materialized amounts no proof attests");
        assertEq(rollup.totalEscrowed(), 5 ether);
    }

    /// Positive: a Manager whose amounts match the proof-bound digest still materializes.
    function test_materializeCreditsExactlyTheProofBoundAmounts() public {
        uint32[10] memory registry;
        uint256[10] memory amounts;
        amounts[0] = 1 wei;
        bytes32 chain = keccak256("settled chain");
        bytes32 tfd = _tokenFundsDigest(registry, 1, amounts);
        LyingManager honest = _bindLyingManager(chain, tfd, 1 wei);
        bytes memory proof = _backingProof(chain, tfd);
        ChannelSettlementManager m = ChannelSettlementManager(payable(address(honest)));

        materializer.attestSignedHeadBacking(m, proof);
        uint256 gasBefore = gasleft();
        materializer.materializeSignedHead(m, proof);
        emit log_named_uint("materializeSignedHead gas (1 token, mock adapter)", gasBefore - gasleft());
        assertEq(rollup.pendingWithdrawals(address(honest)), 1 wei);
        assertEq(rollup.totalEscrowed(), 5 ether - 1 wei);
    }

    /// The exit materializer may still be installed on an empty Rollup, and only then.
    function test_installBeforeAnyEscrowIsAccepted() public {
        _registerChannel();
        LyingManager lying = new LyingManager(CHANNEL_ID, rollup, address(materializer), GENESIS_ROOT);
        rollup.registerSettlementManager(address(lying));
        assertEq(rollup.channelExitMaterializer(), address(materializer));
    }

    /// ERC-20 escrow is reachable only through a registered token; a registered token therefore
    /// also closes the install window.
    function test_installAfterATokenIsRegisteredIsRefused() public {
        rollup.registerToken(1, address(materializer));
        _registerChannel();
        LyingManager lying = new LyingManager(CHANNEL_ID, rollup, address(materializer), GENESIS_ROOT);
        vm.expectRevert(IntmaxRollup.InvalidChannelExitManager.selector);
        rollup.registerSettlementManager(address(lying));
    }
}
