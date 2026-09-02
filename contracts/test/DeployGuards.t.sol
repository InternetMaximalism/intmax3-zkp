// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {IntmaxRollup} from "../src/IntmaxRollup.sol";
import {
    ChannelSettlementManager,
    IChannelSettlementVerifier,
    IChannelRegistry,
    CHALLENGE_PERIOD_SECS_FLOOR,
    SETTLEMENT_LOCAL_DEVNET_CHAIN_ID
} from "../src/ChannelSettlementManager.sol";
import {ChannelSettlementVerifier} from "../src/ChannelSettlementVerifier.sol";
import {MleVerifier} from "@mle/MleVerifier.sol";
import {InvalidMleVerifierChainId, MleProofEngineUnavailable} from "@mle/MleProofErrors.sol";
import {SpongefishWhirVerify} from "@mle/spongefish/SpongefishWhirVerify.sol";
import {MockMleVerifier, CloseTestLib} from "./CloseTestLib.sol";
import {MockChannelRegistry} from "./ChannelSettlementManager.t.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {DeployTestnetBlockProducer} from "../script/DeployTestnetBlockProducer.s.sol";
import {DeployClose} from "../script/DeployClose.s.sol";
import {DeployCloseCli} from "../script/DeployCloseCli.s.sol";
import {DeployPartialWithdrawalE2E, E2EMockMleVerifier} from "../script/DeployPartialWithdrawalE2E.s.sol";
import {DeployWalletSettlement, WalletMockMleVerifier} from "../script/DeployWalletSettlement.s.sol";
import {FixtureLib} from "../script/FixtureLib.sol";
import {DeployConfig} from "../script/DeployConfig.sol";

/// @notice `DeployCloseCli` with its ONE run-time-staged input redirected to a checked-in copy.
///
/// @dev WHY THIS EXISTS. `DeployCloseCli.s.sol` is the production settlement deployer, so the
///      guards below must execute IT, not a paraphrase of it. Its inputs are all checked in except
///      `cli_reg_record.json`, which `channel_member export-reg-record` writes and the Rust drivers
///      copy into `test/data/` before each `forge script` run. `foundry.toml` grants Foundry
///      READ-ONLY filesystem access (deliberately — the repo root holds gitignored secrets), so a
///      test cannot stage that file itself.
///
///      The override therefore swaps FILE BYTES ONLY, and only for that one name: the `run()` under
///      test is `DeployCloseCli.run()` verbatim, including every call whose absence is the defect
///      these tests exist to catch. Substituting a registration record is exactly what the drivers
///      do; nothing about the script's behaviour is stubbed.
contract DeployCloseCliHarness is DeployCloseCli {
    function _read(string memory f) internal view override returns (string memory) {
        if (keccak256(bytes(f)) == keccak256(bytes("cli_reg_record.json"))) {
            return super._read("cli_reg_record_guard.json");
        }
        return super._read(f);
    }
}

/// @notice `DeployWalletSettlement` with its ONE run-time-staged input redirected to a checked-in
///         DELEGATE-BEARING record.
///
/// @dev Same override discipline as `DeployCloseCliHarness` above: FILE BYTES ONLY, for one name.
///      The live `pw_reg.json` is written by `channel_member deploy-settlement` from the wallet's
///      channel snapshot and is a stale by-product in git; the committed copy carries NO delegates,
///      so it cannot tell a fixed script from the conflated one. `pw_reg_guard.json` is the shape
///      that matters — `member_count = 3` cosigners plus `active_delegate_count = 2` live delegates,
///      which is what `wallet-live-work/ch7` actually has.
contract DeployWalletSettlementHarness is DeployWalletSettlement {
    function _read(string memory f) internal view override returns (string memory) {
        if (keccak256(bytes(f)) == keccak256(bytes("pw_reg.json"))) {
            return super._read("pw_reg_guard.json");
        }
        return super._read(f);
    }
}

/// @title Deployment-time guards on the two fund-impacting exit defects.
///
/// @notice WHAT THESE TESTS PROVE ABOUT SECURITY — both defects were "the deploy script forgot
///         something", and both were invisible to a green suite because nothing in `forge test`
///         ever ran a deploy script or inspected a deployed parameter.
///
///         (1) CHALLENGE PERIOD — `finalizeClose()` is permissionless the instant
///             `pendingClose.challengeDeadline` lapses, and the only two remedies against a stale
///             close intent (`submitCloseIntent` with a newer state, `cancelClose`) each need a
///             freshly generated MLE/WHIR proof — minutes — plus a transaction that lands before
///             the deadline. Every deploy script hardcoded a 1-SECOND window, so a member holding
///             an old N-of-N-signed state could freeze, submit it, and finalize it one block later;
///             the difference between that state and an honest member's true balance is
///             permanently mis-allocated. `challengePeriod` is immutable with no setter, so a
///             channel deployed short can never be repaired. These tests assert the floor is
///             enforced by the CONSTRUCTOR (not by script discipline), that a real-chain deploy
///             script now ships the spec value, and that the local devnet keeps the short window
///             the anvil E2Es require.
///
///         (2) WITHDRAWAL VK — `IntmaxRollup._verifyWithdrawalSet` opens with
///             `if (!withdrawalVkInitialized) revert WithdrawalVkNotSet();` and gates BOTH
///             `withdrawNative` and `withdrawERC20`, while `deposit()` has no matching gate. A
///             rollup deployed without `initializeWithdrawalVk` therefore takes money it can never
///             return, and there is no rescue/upgrade path in the contract. `Deploy.s.sol` — the
///             script the live runbook uses — never called it. These tests run the real scripts on
///             a NON-anvil chain id and assert the latch is set.
///
/// @dev The scripts are executed, not grepped: `run()` performs the same CREATEs and calls it
///      performs under `forge script`, so deleting either fix makes these tests fail rather than
///      merely go stale.
contract DeployGuardsTest is Test {
    /// Historical pre-retirement selector, fixed independently of future PCS proof-tuple changes.
    bytes4 internal constant LEGACY_APPLY_MEMBER_SET_UPDATE_SELECTOR = 0x66e3ff78;

    /// A public chain id, so `block.chainid != SETTLEMENT_LOCAL_DEVNET_CHAIN_ID` on every path
    /// under test. Sepolia is the network the live runbook targets.
    uint256 internal constant REAL_CHAIN_ID = 11155111;

    bytes4 internal constant CHANNEL_ID = hex"00000009";
    uint8 internal constant BP_MEMBER_SLOT = 0;
    bytes32 internal constant USER_A = keccak256("guards_member_a");
    bytes32 internal constant USER_B = keccak256("guards_member_b");
    bytes32 internal constant USER_C = keccak256("guards_member_c");
    uint256 internal constant SPECIAL_CLOSE_PENALTY = 0;
    uint256 internal constant INITIAL_BP_BOND = 0;

    ChannelSettlementVerifier internal verifier;
    MockMleVerifier internal mockMle;
    MockChannelRegistry internal registry;

    address internal alice = makeAddr("guards_alice");
    address internal bob = makeAddr("guards_bob");
    address internal carol = makeAddr("guards_carol");
    address internal fraudTreasury = makeAddr("guards_fraudTreasury");

    function setUp() public {
        vm.setEnv("MLE_VERIFIER_CHAIN_ID", vm.toString(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID));
        verifier = new ChannelSettlementVerifier();
        mockMle = new MockMleVerifier();
        (
            ChannelSettlementVerifier.CloseVk memory vk,
            SpongefishWhirVerify.WhirParams memory whir,
            bytes memory protocolId,
            bytes memory sessionId,
            uint256[] memory kIs,
            uint256[] memory subgroupGenPowers
        ) = CloseTestLib.dummyVkArgs();
        verifier.initializeCloseVk(
            MleVerifier(address(mockMle)), vk, whir, protocolId, sessionId, kIs, subgroupGenPowers
        );

        registry = new MockChannelRegistry(IChannelSettlementVerifier(address(verifier)));
        bytes32[] memory active = new bytes32[](3);
        active[0] = USER_A;
        active[1] = USER_B;
        active[2] = USER_C;
        registry.register(uint32(CHANNEL_ID), BP_MEMBER_SLOT, active);
    }

    // ── (1) challenge period: the constructor floor ────────────────────────────────────────────

    function _newManager(uint64 challengePeriod) internal returns (ChannelSettlementManager) {
        ChannelSettlementManager.MemberBinding[] memory b = new ChannelSettlementManager.MemberBinding[](3);
        b[0] = ChannelSettlementManager.MemberBinding({pkG: USER_A, recipient: alice});
        b[1] = ChannelSettlementManager.MemberBinding({pkG: USER_B, recipient: bob});
        b[2] = ChannelSettlementManager.MemberBinding({pkG: USER_C, recipient: carol});
        return new ChannelSettlementManager(
            CHANNEL_ID,
            BP_MEMBER_SLOT,
            USER_A,
            0,
            bytes32(0),
            challengePeriod,
            SPECIAL_CLOSE_PENALTY,
            INITIAL_BP_BOND,
            IChannelSettlementVerifier(address(verifier)),
            IChannelRegistry(address(registry)),
            address(this),
            b
        );
    }

    /// THE defect, at the only layer that cannot be bypassed: the 1-second window every deploy
    /// script used to hardcode is refused outright on a public chain. This fires for ANY deployment
    /// tooling — a script edit, a copied script, a factory, a hand-rolled transaction.
    function test_manager_realChain_rejectsOneSecondChallengePeriod() public {
        vm.chainId(REAL_CHAIN_ID);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChannelSettlementManager.ChallengePeriodTooShort.selector, uint64(1), CHALLENGE_PERIOD_SECS_FLOOR
            )
        );
        _newManager(1);
    }

    /// The floor is a floor, not a "not obviously tiny" heuristic: one second below spec is refused.
    /// A boundary test, because an off-by-one here is exactly the shape that survives review.
    function test_manager_realChain_rejectsJustBelowFloor() public {
        vm.chainId(REAL_CHAIN_ID);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChannelSettlementManager.ChallengePeriodTooShort.selector,
                CHALLENGE_PERIOD_SECS_FLOOR - 1,
                CHALLENGE_PERIOD_SECS_FLOOR
            )
        );
        _newManager(CHALLENGE_PERIOD_SECS_FLOOR - 1);
    }

    /// The spec value itself is accepted (the floor is inclusive), and longer windows stay legal —
    /// the guard must not brick a deployer who wants MORE challenge time.
    function test_manager_realChain_acceptsFloorAndAbove() public {
        vm.chainId(REAL_CHAIN_ID);
        ChannelSettlementManager m = _newManager(CHALLENGE_PERIOD_SECS_FLOOR);
        assertEq(m.challengePeriod(), CHALLENGE_PERIOD_SECS_FLOOR, "spec value must be accepted");
        assertEq(
            m.challengePeriod(),
            m.CHALLENGE_PERIOD_SECS(),
            "the deployed period must equal the documented protocol constant"
        );
        ChannelSettlementManager longer = _newManager(CHALLENGE_PERIOD_SECS_FLOOR * 7);
        assertEq(longer.challengePeriod(), CHALLENGE_PERIOD_SECS_FLOOR * 7, "longer must stay legal");
    }

    /// The escape hatch the fix depends on: the anvil E2Es drive a REAL node through
    /// close → challenge-window → finalizeClose and cannot wait a day, so the short window must
    /// remain reachable on chain id 31337 — and only there.
    function test_manager_localDevnet_allowsShortChallengePeriod() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        ChannelSettlementManager m = _newManager(1);
        assertEq(m.challengePeriod(), 1, "the devnet E2E value must still deploy on 31337");
    }

    /// A short-window dev manager must freeze if its code/state is moved to a
    /// public chain. Guard the state transition plus every value-bearing sink,
    /// including already-pending/credited state that needs no verifier call.
    function test_manager_devnetShortWindow_runtimeSinksRefuseAfterChainIdChange() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        ChannelSettlementManager m = _newManager(1);
        assertTrue(m.isNativeSendAllowed(0), "local manager should initially be active");

        vm.chainId(REAL_CHAIN_ID);
        bytes memory expected = abi.encodeWithSelector(
            ChannelSettlementManager.ChallengePeriodTooShort.selector, uint64(1), CHALLENGE_PERIOD_SECS_FLOOR
        );
        assertFalse(m.isNativeSendAllowed(0), "migrated dev manager must not authorize sends");

        uint64 freezeNonce = m.currentCloseFreezeNonce();
        uint64 cancellationFloor = m.highestCancelledRevivedStateVersion();
        bytes32 closeIntentDigest = m.getPendingClose().closeIntentDigest;
        uint64 generation = m.closeRequestGeneration();
        vm.expectRevert(expected);
        m.requestClose(freezeNonce, cancellationFloor);
        vm.expectRevert(expected);
        m.finalizeCloseGuarded(closeIntentDigest, generation);
        vm.expectRevert(expected);
        m.finalizePartialWithdrawal();
        vm.expectRevert(expected);
        m.pullChannelFunds();
        vm.expectRevert(expected);
        m.pullChannelTokenFunds(7);
        vm.expectRevert(expected);
        m.claimWithdrawalCredit(bytes32(uint256(1)));
    }

    /// Zero stays rejected on every chain, including the devnet — a same-block finalize voids the
    /// challenge game even in tests, and `InvalidChallengePeriod` must not be masked by the floor.
    function test_manager_zeroRejectedOnLocalDevnet() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        vm.expectRevert(ChannelSettlementManager.InvalidChallengePeriod.selector);
        _newManager(0);
    }

    function test_manager_zeroRejectedOnRealChain() public {
        vm.chainId(REAL_CHAIN_ID);
        // Zero is caught by the nonzero check first — assert the specific selector so a future
        // reorder that swallows `InvalidChallengePeriod` into the floor error is visible.
        vm.expectRevert(ChannelSettlementManager.InvalidChallengePeriod.selector);
        _newManager(0);
    }

    // ── (1) challenge period: what the deploy scripts ask for ──────────────────────────────────

    /// `DeployConfig` is the single source the settlement deploy scripts read. It must resolve to
    /// the protocol constant off-devnet and to the short E2E value on 31337.
    ///
    /// NOTE (why these are three functions, not one): `challengePeriodSecs()` is an `internal view`
    /// library function, so it inlines into the caller's frame, and solc treats `CHAINID` as
    /// constant within a frame — a single test calling it after successive `vm.chainId()` switches
    /// reads the FIRST chain id every time. One chain id per test function keeps each assertion
    /// honest.
    function test_deployConfig_sepoliaGetsSpecChallengePeriod() public {
        vm.chainId(REAL_CHAIN_ID);
        assertEq(
            DeployConfig.challengePeriodSecs(),
            CHALLENGE_PERIOD_SECS_FLOOR,
            "a real chain must get the spec challenge period"
        );
    }

    function test_deployConfig_mainnetGetsSpecChallengePeriod() public {
        vm.chainId(1);
        assertEq(
            DeployConfig.challengePeriodSecs(),
            CHALLENGE_PERIOD_SECS_FLOOR,
            "mainnet must get the spec challenge period"
        );
    }

    function test_deployConfig_localDevnetGetsShortChallengePeriod() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        assertEq(
            DeployConfig.challengePeriodSecs(),
            DeployConfig.LOCAL_DEVNET_CHALLENGE_PERIOD_SECS,
            "the devnet keeps the short E2E window"
        );
        assertEq(
            DeployConfig.LOCAL_DEVNET_CHAIN_ID,
            SETTLEMENT_LOCAL_DEVNET_CHAIN_ID,
            "script and contract must agree on which chain is local"
        );
    }

    /// END-TO-END for the script layer: run the real settlement deploy script against a public
    /// chain id and read the challenge period off the manager it produced. This fires if the
    /// script reintroduces a literal (the constructor floor reverts the whole deploy) AND if the
    /// floor is removed while a literal is reintroduced (the assertion fails).
    ///
    /// This targets `DeployCloseCli.s.sol` — the production settlement deployer — via the harness
    /// above. It used to target `DeployClose.s.sol`, which is now hard-gated to the devnet (see the
    /// HOLE-2 tests below), so this is strictly better coverage: the script under test is the one a
    /// real deployment actually uses.
    function test_deployCloseCliScript_realChain_refusesUnreleasedMleEngine() public {
        vm.chainId(REAL_CHAIN_ID);
        vm.setEnv("MLE_VERIFIER_CHAIN_ID", vm.toString(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID));
        vm.setEnv("FRAUD_TREASURY", vm.toString(fraudTreasury));
        DeployCloseCliHarness script = new DeployCloseCliHarness();
        vm.expectRevert(
            abi.encodeWithSelector(InvalidMleVerifierChainId.selector, SETTLEMENT_LOCAL_DEVNET_CHAIN_ID, REAL_CHAIN_ID)
        );
        script.run();
    }

    function test_mleVerifierChainId_explicitConfiguredChainDeploysPinnedVerifier() public {
        vm.chainId(REAL_CHAIN_ID);
        vm.setEnv("MLE_VERIFIER_CHAIN_ID", vm.toString(REAL_CHAIN_ID));
        MleVerifier configured = new MleVerifier(FixtureLib.mleVerifierChainId());
        assertEq(configured.allowedChainId(), REAL_CHAIN_ID, "constructor must persist the explicit chain pin");
        vm.setEnv("MLE_VERIFIER_CHAIN_ID", vm.toString(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID));
    }

    /// `DeployClose.s.sol` on the devnet keeps the short window, so the local lifecycle E2Es that
    /// depend on finalizing quickly are not collateral damage.
    function test_deployCloseScript_localDevnet_shipsShortChallengePeriod() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        DeployClose script = new DeployClose();
        (, ChannelSettlementManager manager) = script.run();
        assertEq(
            manager.challengePeriod(),
            DeployConfig.LOCAL_DEVNET_CHALLENGE_PERIOD_SECS,
            "the devnet deploy must keep the short window"
        );
    }

    // ── (2) withdrawal VK on the production-shaped rollup deployers ────────────────────────────

    /// `Deploy.s.sol` is the script `doc/docs/deploy-runbook.md` uses for the live network. A
    /// rollup it produces MUST be able to pay out: without `initializeWithdrawalVk`, `deposit()`
    /// still works and both withdrawal entry points revert `WithdrawalVkNotSet()` forever.
    function test_deployScript_realChain_refusesUnreleasedMleEngine() public {
        vm.chainId(REAL_CHAIN_ID);
        vm.setEnv("MLE_VERIFIER_CHAIN_ID", vm.toString(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID));
        vm.setEnv("FRAUD_TREASURY", vm.toString(fraudTreasury));
        Deploy script = new Deploy();
        vm.expectRevert(
            abi.encodeWithSelector(InvalidMleVerifierChainId.selector, SETTLEMENT_LOCAL_DEVNET_CHAIN_ID, REAL_CHAIN_ID)
        );
        script.run();
    }

    /// Same requirement for the other production-shaped deployer. It was missing the call too, and
    /// its own docstring positions it for a public testnet.
    function test_deployTestnetBlockProducerScript_realChain_refusesUnreleasedMleEngine() public {
        vm.chainId(REAL_CHAIN_ID);
        vm.setEnv("MLE_VERIFIER_CHAIN_ID", vm.toString(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID));
        vm.setEnv("FRAUD_TREASURY", vm.toString(fraudTreasury));
        DeployTestnetBlockProducer script = new DeployTestnetBlockProducer();
        vm.expectRevert(
            abi.encodeWithSelector(InvalidMleVerifierChainId.selector, SETTLEMENT_LOCAL_DEVNET_CHAIN_ID, REAL_CHAIN_ID)
        );
        script.run();
    }

    /// The withdrawal VK must be bound to the SAME `MleVerifier` the script deployed and must be
    /// set exactly once — a second call is refused, so a later "top-up" cannot silently swap the
    /// circuit a payout is checked against.
    function test_deployScript_localDevnet_withdrawalVkIsSetOnce() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        vm.setEnv("FRAUD_TREASURY", vm.toString(fraudTreasury));
        Deploy script = new Deploy();
        (IntmaxRollup rollup,) = script.run();
        IntmaxRollup.MleVk memory zeroVk;
        SpongefishWhirVerify.WhirParams memory whir;
        vm.prank(rollup.deployer());
        vm.expectRevert(IntmaxRollup.WithdrawalVkAlreadySet.selector);
        rollup.initializeWithdrawalVk(zeroVk, whir, hex"", hex"", new uint256[](0), new uint256[](0));
    }

    // ── (3) HOLE 1 — the settlement manager must be REGISTERED on the rollup ───────────────────
    //
    // WHAT THESE PROVE ABOUT SECURITY. `ChannelSettlementManager.finalizePartialWithdrawal()` ends
    // by calling `IntmaxRollup.authorizePartialWithdrawal`, which is gated on
    // `isRegisteredSettlementManager[msg.sender]`. `registerSettlementManager` is deployer-only, so
    // only the deploying EOA can ever grant it. Until this fix its only callers were the two
    // `chainid == 31337` mock scripts, so on every REAL deployment a member's partial withdrawal
    // reverted `NotRegisteredSettlementManager` at FINALIZE — after they had submitted the intent
    // and waited out the entire challenge period. That path is live: `pw-submit` / `pw-finalize`
    // (`src/bin/channel_member.rs`) are implemented and driven by `api/routes/partial-withdrawal.js`.

    /// THE guard for HOLE 1: deploy the production settlement stack at a PUBLIC chain id and assert
    /// the rollup knows about the manager the very same script deployed. Deleting the
    /// `registerSettlementManager` call fails this assertion (and trips the script's own read-back
    /// `require` first).
    function test_deployCloseCliScript_localDevnet_registersSettlementManager() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        vm.setEnv("FRAUD_TREASURY", vm.toString(fraudTreasury));
        (IntmaxRollup rollup,, ChannelSettlementManager manager) = new DeployCloseCliHarness().run();
        assertTrue(
            rollup.isRegisteredSettlementManager(address(manager)),
            "a real-chain settlement deploy must register its own manager, or partial withdrawal cannot finalize"
        );
    }

    /// The property that actually matters, exercised rather than inferred: the deployed manager can
    /// perform the ONE rollup call `finalizePartialWithdrawal` makes. Asserting the mapping alone
    /// would pass even if the gate later moved to a different predicate.
    function test_deployCloseCliScript_localDevnet_managerCanAuthorizePartialWithdrawal() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        vm.setEnv("FRAUD_TREASURY", vm.toString(fraudTreasury));
        (IntmaxRollup rollup,, ChannelSettlementManager manager) = new DeployCloseCliHarness().run();
        bytes32 authDigest = keccak256("guards_auth_digest");
        vm.prank(address(manager));
        rollup.authorizePartialWithdrawal(authDigest);
        assertTrue(
            rollup.partialWithdrawalAuthorized(authDigest),
            "the deployed manager must be able to authorize a partial withdrawal"
        );
    }

    /// NOTHING IS WEAKENED: the fail-closed check still fires for everyone else. Registration is a
    /// per-address grant to the manager this deploy created, not a hole in the gate. If a future
    /// edit made `authorizePartialWithdrawal` permissive (or registered a wildcard), this fails.
    function test_deployCloseCliScript_localDevnet_strangerStillRefusedAuthorization() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        vm.setEnv("FRAUD_TREASURY", vm.toString(fraudTreasury));
        (IntmaxRollup rollup,,) = new DeployCloseCliHarness().run();
        assertFalse(rollup.isRegisteredSettlementManager(alice), "registration must be per-address, not blanket");
        vm.prank(alice);
        vm.expectRevert(IntmaxRollup.NotRegisteredSettlementManager.selector);
        rollup.authorizePartialWithdrawal(keccak256("stranger_digest"));
    }

    /// ... and it is still deployer-only, so an unregistered party cannot register itself.
    function test_deployCloseCliScript_localDevnet_registrationIsDeployerOnly() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        vm.setEnv("FRAUD_TREASURY", vm.toString(fraudTreasury));
        (IntmaxRollup rollup,,) = new DeployCloseCliHarness().run();
        vm.prank(alice);
        vm.expectRevert(IntmaxRollup.OnlyDeployer.selector);
        rollup.registerSettlementManager(alice);
    }

    /// A real settlement deployment keys every live statement VK. Direct member-set updates are
    /// retired, so the active verifier has no MSU key or initialization surface at all.
    function test_deployCloseCliScript_localDevnet_keysOnlyLiveVks() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        vm.setEnv("FRAUD_TREASURY", vm.toString(fraudTreasury));
        (IntmaxRollup rollup, ChannelSettlementVerifier sv,) = new DeployCloseCliHarness().run();
        assertTrue(rollup.withdrawalVkInitialized(), "withdrawal VK: the rollup could never pay out");
        (uint256 degreeBits,,,,) = rollup.withdrawalMleVk();
        assertGt(degreeBits, 0, "the installed withdrawal VK must have verification enabled");
        assertTrue(sv.closeVkInitialized(), "close VK: the channel could be frozen and never closed");
        assertTrue(sv.cancelCloseVkInitialized(), "cancelClose VK: no remedy against a stale close");
        assertTrue(sv.withdrawalClaimVkInitialized(), "withdrawalClaim VK: members could not collect");
        assertTrue(sv.postCloseClaimVkInitialized(), "postCloseClaim VK: `post-close-claim` bricked");
        assertTrue(address(rollup.kzgVerifier()).code.length > 0, "KZG satellite must be pinned");
    }

    /// The production-deployed Manager has no direct-MSU selector; legacy raw calldata must fail
    /// before it can change the signer set or block-proposer identity.
    function test_deployCloseCliScript_localDevnet_removedMsuSelectorCannotMutate() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        vm.setEnv("FRAUD_TREASURY", vm.toString(fraudTreasury));
        (, , ChannelSettlementManager manager) = new DeployCloseCliHarness().run();

        uint8 beforeCount = manager.activeMemberCount();
        bytes32 beforeBp = manager.bpPkG();
        bytes32 beforeCommitment = manager.registeredMemberSetCommitment();
        bytes32[] memory proposed = new bytes32[](beforeCount);
        for (uint256 i = 0; i < beforeCount; i++) {
            proposed[i] = manager.memberPkGs(i);
        }
        proposed[beforeCount - 1] = keccak256("must-not-be-installed");
        MleVerifier.MleProof memory noProof;

        (bool ok, bytes memory revertData) = address(manager).call(
            abi.encodeWithSelector(
                LEGACY_APPLY_MEMBER_SET_UPDATE_SELECTOR,
                proposed,
                beforeCount,
                address(0),
                uint64(1),
                noProof
            )
        );
        assertFalse(ok, "removed MSU selector unexpectedly succeeded");
        assertEq(revertData.length, 0, "removed MSU selector unexpectedly has an active decoder");

        assertEq(manager.activeMemberCount(), beforeCount, "member count mutated");
        assertEq(manager.bpPkG(), beforeBp, "BP key mutated");
        assertEq(manager.registeredMemberSetCommitment(), beforeCommitment, "member commitment mutated");
        for (uint256 i = 0; i < beforeCount; i++) {
            assertTrue(manager.memberPkGs(i) != proposed[beforeCount - 1], "proposed key was installed");
        }
    }

    // ── (4) HOLE 2 — the VK-less settlement deployer must not reach a public chain ─────────────
    //
    // WHAT THIS PROVES ABOUT SECURITY. `DeployClose.s.sol` deploys a REAL `ChannelSettlementVerifier`
    // and a REAL `ChannelSettlementManager` and keys NONE of the four settlement VKs. A channel it
    // deploys accepts the permissionless `requestClose()` — which sets `isNativeSendAllowed = false`
    // and freezes it — and then reverts `CloseVkNotSet()` on every `submitCloseIntent` and
    // `CancelCloseVkNotSet()` on every `cancelClose`. `initializeCloseVk` is set-once on a verifier
    // the script does not return and `ChannelSettlementManager.verifier` is immutable, so the
    // channel can never be repaired: member funds are stranded. Before this fix the only protection
    // was a "DEMO / DRY-RUN ONLY" line in a docstring, which no `forge script` invocation reads.

    /// THE guard for HOLE 2: the script REFUSES to run on a public chain id. Deleting the
    /// `require` makes this test fail — it is the whole fix, expressed as a test.
    function test_deployCloseScript_realChain_refusesToDeploy() public {
        vm.chainId(REAL_CHAIN_ID);
        vm.setEnv("FRAUD_TREASURY", vm.toString(fraudTreasury));
        DeployClose script = new DeployClose();
        vm.expectRevert(
            bytes(
                "local-devnet only: this script keys no settlement VKs and reads stale fixtures -- use DeployCloseCli.s.sol"
            )
        );
        script.run();
    }

    /// Not just Sepolia: mainnet too. The guard is an allowlist of one chain, not a denylist — an
    /// operator pointing this at any public network is stopped.
    function test_deployCloseScript_mainnet_refusesToDeploy() public {
        vm.chainId(1);
        vm.setEnv("FRAUD_TREASURY", vm.toString(fraudTreasury));
        DeployClose script = new DeployClose();
        vm.expectRevert(
            bytes(
                "local-devnet only: this script keys no settlement VKs and reads stale fixtures -- use DeployCloseCli.s.sol"
            )
        );
        script.run();
    }

    /// The reason the guard is needed, stated as an executable fact rather than a comment: the
    /// manager this script produces on the devnet is bound to a settlement verifier with NO close
    /// VK and NO cancel-close VK. If a future edit keys them here, this test fails loudly and the
    /// devnet-only gate can be revisited on purpose — it will not drift silently.
    function test_deployCloseScript_devnetStackHasNoSettlementVks() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        DeployClose script = new DeployClose();
        (, ChannelSettlementManager manager) = script.run();
        ChannelSettlementVerifier sv = ChannelSettlementVerifier(address(manager.verifier()));
        assertFalse(sv.closeVkInitialized(), "unexpected close VK: revisit the devnet-only gate");
        assertFalse(sv.cancelCloseVkInitialized(), "unexpected cancelClose VK: revisit the gate");
        assertFalse(sv.withdrawalClaimVkInitialized(), "unexpected withdrawalClaim VK: revisit the gate");
        assertFalse(sv.postCloseClaimVkInitialized(), "unexpected postCloseClaim VK: revisit the gate");
    }

    // ── (5) the anvil-gated mock deployers: complete stacks, still fail-closed off-devnet ──────

    /// `DeployPartialWithdrawalE2E` and `DeployWalletSettlement` keyed only close + cancelClose, so
    /// `verifyWithdrawalClaim` / `verifyPostCloseClaim` reverted their own `*VkNotSet()` — the
    /// wallet demo's `full_withdrawal` ticket ends in a `claim` step that could not succeed. Same
    /// defect class, devnet blast radius. Asserted on the script whose inputs are all checked in.
    function test_deployPartialWithdrawalE2EScript_devnet_keysAllFourSettlementVks() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        (IntmaxRollup rollup, ChannelSettlementVerifier sv, ChannelSettlementManager manager) =
            new DeployPartialWithdrawalE2E().run();
        assertTrue(sv.closeVkInitialized(), "close VK");
        assertTrue(sv.cancelCloseVkInitialized(), "cancelClose VK");
        assertTrue(sv.withdrawalClaimVkInitialized(), "withdrawalClaim VK");
        assertTrue(sv.postCloseClaimVkInitialized(), "postCloseClaim VK");
        assertTrue(rollup.isRegisteredSettlementManager(address(manager)), "the manager must be registered here too");
    }

    /// The mock-verifier scripts must stay unreachable from a public chain — they wire an
    /// always-true MLE verifier, so a stack they deploy has a VACUOUS close-proof check. This is
    /// the pre-existing gate; it is asserted here so the HOLE-2 gate and this one are covered by
    /// the same suite and cannot be removed unnoticed.
    function test_deployPartialWithdrawalE2EScript_realChain_refusesToDeploy() public {
        vm.chainId(REAL_CHAIN_ID);
        DeployPartialWithdrawalE2E script = new DeployPartialWithdrawalE2E();
        vm.expectRevert(bytes("local-devnet only: this script deploys mock verifiers"));
        script.run();
    }

    /// Script-entry guards do not protect already-deployed dev bytecode after
    /// a chain-id change or state migration. Each always-true mock therefore
    /// enforces the local chain again at proof-verification time.
    function test_devSettlementMocks_runtimeGuardAfterChainIdChange() public {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        WalletMockMleVerifier walletMock = new WalletMockMleVerifier();
        E2EMockMleVerifier e2eMock = new E2EMockMleVerifier();
        MleVerifier.MleProof memory proof;
        MleVerifier.VerifyParams memory params;
        SpongefishWhirVerify.WhirParams memory whir;

        assertTrue(walletMock.verify(proof, params, whir, bytes32(0)), "wallet mock must work locally");
        assertTrue(e2eMock.verify(proof, params, whir, bytes32(0)), "E2E mock must work locally");

        vm.chainId(REAL_CHAIN_ID);
        vm.expectRevert(abi.encodeWithSelector(MleProofEngineUnavailable.selector, REAL_CHAIN_ID));
        walletMock.verify(proof, params, whir, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(MleProofEngineUnavailable.selector, REAL_CHAIN_ID));
        e2eMock.verify(proof, params, whir, bytes32(0));
    }

    // ── (6) the REGISTRATION delegate count and the MANAGER's are different things ─────────────
    //
    // WHAT THESE PROVE ABOUT SECURITY. `DeployWalletSettlement.s.sol` read ONE `delegate_count`
    // field out of the registration record and fed it to THREE consumers: `registerChannel`, the
    // manager's `activeDelegateCount`, and the delegate `MemberBinding[]`. The live wallet channel
    // it serves has delegates, so both directions of that conflation are live defects:
    //
    //   * REGISTRATION — the L1 registration record is cosigners-only under Option B, and
    //     `ChannelRegStepCircuit` now CONSTRAINS its `delegateCount` limb to zero
    //     (`src/circuits/validity/channel_reg_hash_chain/channel_reg_step.rs`). A registration made
    //     with the live count is therefore UNPROVABLE — no reg-chain step can fold it, so the
    //     channel is stuck in the validity chain. (It also never matched the preimage the proving
    //     side builds: `wallet_core::build_channel_withdrawal` registers the cosigner slice.)
    //   * MANAGER — "fixing" that by passing zero to the manager would zero the B-2 delegate-close
    //     FLOOR (close PI limb 94 must be `>= activeDelegateCount`) and drop every delegate's
    //     recipient binding. That is a WEAKENED CHECK, and it is the tempting one-line fix.
    //
    // One test per direction, because a single "the two agree" assertion would pass for either
    // broken value. Both run the REAL script (via a harness that only swaps the record's bytes) on
    // a record with 3 cosigners and 2 live delegates — the wallet demo's own shape.

    uint32 internal constant GUARD_REG_CHANNEL_ID = 11;
    uint8 internal constant GUARD_MEMBER_COUNT = 3;
    uint8 internal constant GUARD_ACTIVE_DELEGATES = 2;

    /// Deploy a rollup and then run the wallet settlement script against it, exactly as the devnet
    /// wallet flow does (`setup-backing` then `deploy-settlement`). Both scripts broadcast as the
    /// same default sender, so the rollup's `deployer` is the script's caller — which is what
    /// `registerSettlementManager` requires.
    function _runWalletSettlement()
        internal
        returns (IntmaxRollup rollup, ChannelSettlementManager manager, Vm.Log[] memory logs)
    {
        vm.chainId(SETTLEMENT_LOCAL_DEVNET_CHAIN_ID);
        vm.setEnv("FRAUD_TREASURY", vm.toString(fraudTreasury));
        (rollup,) = new Deploy().run();
        vm.setEnv("ROLLUP", vm.toString(address(rollup)));
        vm.recordLogs();
        (,, manager) = new DeployWalletSettlementHarness().run();
        logs = vm.getRecordedLogs();
    }

    function _guardRecord() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/data/pw_reg_guard.json"));
    }

    /// DIRECTION 1: what the script actually registered on L1 carries NO delegate.
    ///
    /// The `ChannelRegistered` event is decoded rather than inferred, and the reg-chain hash is
    /// recomputed here from the record with a `delegateCount` limb of ZERO and the delegate slots
    /// left as padding. That last assertion is the decisive one: it fails if the limb carries the
    /// live count, and it fails if the delegates are folded into the active slots — the two halves
    /// of what the conflated script did.
    function test_deployWalletSettlementScript_registersCosignersOnly() public {
        (IntmaxRollup rollup,, Vm.Log[] memory logs) = _runWalletSettlement();

        (bytes32[] memory eventPkGs, bytes32 memberPubkeysRoot, bytes32 newChainHash) = _decodeChannelRegistered(logs);

        string memory json = _guardRecord();
        bytes32[] memory allPkGs = vm.parseJsonBytes32Array(json, ".member_pk_gs");
        assertEq(
            allPkGs.length,
            uint256(GUARD_MEMBER_COUNT) + uint256(GUARD_ACTIVE_DELEGATES),
            "the fixture must actually carry delegates, or this test proves nothing"
        );

        assertEq(
            eventPkGs.length, GUARD_MEMBER_COUNT, "the L1 registration record must carry the co-signing members ONLY"
        );
        for (uint256 i = 0; i < GUARD_MEMBER_COUNT; i++) {
            assertEq(eventPkGs[i], allPkGs[i], "registered key order must be the cosigner prefix");
        }

        bytes32[] memory cosigners = new bytes32[](GUARD_MEMBER_COUNT);
        for (uint256 i = 0; i < GUARD_MEMBER_COUNT; i++) {
            cosigners[i] = allPkGs[i];
        }
        assertEq(
            memberPubkeysRoot,
            keccak256(abi.encodePacked(cosigners)),
            "the registered member-pubkey root must span the cosigners only"
        );

        assertEq(
            newChainHash,
            _expectedCosignerOnlyRegHash(json),
            "the reg-chain preimage must have a ZERO delegateCount limb and padding in the delegate slots -- anything else is unprovable by channel_reg_step"
        );

        // The truncation must not have moved the close-path binding: `registerChannel` derives
        // `memberCount = arrays.length - delegateCount`, so cosigner-slice + 0 and full-set + live
        // count yield the SAME member-only IMCM commitment. Asserted, not assumed — the manager
        // constructor binds to it.
        assertEq(
            rollup.channelMemberSetCommitment(GUARD_REG_CHANNEL_ID),
            _closeMemberSetCommitment(cosigners),
            "cosigner-only registration must record the same member-set commitment as before"
        );
    }

    /// DIRECTION 2: the manager keeps the LIVE delegate count and authenticated participant root.
    ///
    /// This is the test that fails if someone achieves the Option B invariant by zeroing the
    /// manager side instead of decoupling the two.
    function test_deployWalletSettlementScript_managerKeepsLiveDelegateCount() public {
        (IntmaxRollup rollup, ChannelSettlementManager manager,) = _runWalletSettlement();

        assertEq(
            manager.activeDelegateCount(),
            GUARD_ACTIVE_DELEGATES,
            "the manager's delegate count is the B-2 close floor: it must stay the LIVE count, never the registration's zero"
        );
        assertEq(manager.activeMemberCount(), GUARD_MEMBER_COUNT, "the co-signing set is unchanged by the decoupling");

        // Counted is not enough: the immutable root must bind the full live pkG/recipient array.
        // Delegates are deliberately NOT expanded into mappings (1024 SSTOREs would make the
        // deployment unmineable); they open their fixed-depth leaf when requesting a close.
        string memory json = _guardRecord();
        bytes32[] memory pkGs = vm.parseJsonBytes32Array(json, ".member_pk_gs");
        address[] memory recipients = vm.parseJsonAddressArray(json, ".recipients");
        bytes32 expectedRoot = _participantRoot(pkGs, recipients);
        assertEq(manager.participantRoot(), expectedRoot, "manager lost the signed live participant root");
        assertEq(
            manager.activeParticipantCount(),
            uint256(GUARD_MEMBER_COUNT) + uint256(GUARD_ACTIVE_DELEGATES),
            "manager lost the signed live participant count"
        );
        for (uint256 i = GUARD_MEMBER_COUNT; i < pkGs.length; i++) {
            assertEq(
                manager.participantLeaf(uint16(i), pkGs[i], recipients[i]),
                keccak256(abi.encodePacked(bytes4("IMPR"), uint16(i), pkGs[i], recipients[i])),
                "delegate leaf encoding drifted"
            );
            assertEq(
                manager.registeredRecipientOf(pkGs[i]), address(0), "delegate unexpectedly consumed mapping SSTORE"
            );
            assertFalse(manager.isMemberRecipient(recipients[i]), "delegate unexpectedly consumed recipient SSTORE");
        }

        // And the manager is still bound to the (now cosigner-only) registration: the decoupling
        // must not have broken the Finding-E single-source-of-truth check.
        assertEq(
            manager.registeredMemberSetCommitment(),
            rollup.channelMemberSetCommitment(GUARD_REG_CHANNEL_ID),
            "manager and rollup must still agree on the member set"
        );
    }

    function _participantRoot(bytes32[] memory pkGs, address[] memory recipients) internal pure returns (bytes32) {
        assert(pkGs.length == recipients.length && pkGs.length <= 1024);
        bytes32[] memory nodes = new bytes32[](1024);
        for (uint256 slot = 0; slot < pkGs.length; slot++) {
            nodes[slot] = keccak256(abi.encodePacked(bytes4("IMPR"), uint16(slot), pkGs[slot], recipients[slot]));
        }
        for (uint256 width = 1024; width > 1; width >>= 1) {
            for (uint256 i = 0; i < width; i += 2) {
                nodes[i >> 1] = keccak256(abi.encodePacked(bytes4("IMPN"), nodes[i], nodes[i + 1]));
            }
        }
        return nodes[0];
    }

    /// @dev Decode the one `ChannelRegistered` event out of a recorded log set.
    function _decodeChannelRegistered(Vm.Log[] memory logs)
        internal
        pure
        returns (bytes32[] memory pkGs, bytes32 memberPubkeysRoot, bytes32 newChainHash)
    {
        bytes32 topic0 = keccak256(
            "ChannelRegistered(uint64,uint32,uint8,bytes32[],bytes32[],address[],bytes32,bytes32,bytes32)"
        );
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == topic0) {
                (, pkGs,,, memberPubkeysRoot,, newChainHash) =
                    abi.decode(logs[i].data, (uint8, bytes32[], bytes32[], address[], bytes32, bytes32, bytes32));
                return (pkGs, memberPubkeysRoot, newChainHash);
            }
        }
        revert("ChannelRegistered event not found");
    }

    /// @dev The reg-chain hash a COSIGNER-ONLY registration of this record must produce, built here
    ///      from the documented preimage (`IntmaxRollup._channelRegHashChain`, byte-identical to the
    ///      Rust `ChannelRegRecord::hash_with_prev_hash` and its in-circuit twin) rather than by
    ///      calling the contract — so this is an independent expectation, not a restatement of
    ///      whatever the script did. `prev` is `bytes32(0)`: the rollup is freshly deployed and no
    ///      other channel has been registered on it.
    function _expectedCosignerOnlyRegHash(string memory json) internal view returns (bytes32) {
        bytes32[] memory pkGs = vm.parseJsonBytes32Array(json, ".member_pk_gs");
        bytes32[] memory pkBs = vm.parseJsonBytes32Array(json, ".member_pk_bs");
        bytes32[] memory regev = vm.parseJsonBytes32Array(json, ".regev_pk_digests");
        address[] memory recipients = vm.parseJsonAddressArray(json, ".recipients");
        bytes memory packed = abi.encodePacked(
            bytes32(0),
            GUARD_REG_CHANNEL_ID,
            uint32(0), // bp_member_slot
            uint32(GUARD_MEMBER_COUNT),
            uint32(0) // SECURITY: the delegateCount limb the circuit constrains to zero
        );
        for (uint256 i = 0; i < 8; i++) {
            if (i < GUARD_MEMBER_COUNT) {
                packed = abi.encodePacked(packed, pkGs[i], pkBs[i], regev[i], recipients[i]);
            } else {
                // Padding — INCLUDING the delegate slots, which a cosigner-only record does not
                // register.
                packed = abi.encodePacked(packed, bytes32(0), bytes32(0), bytes32(0), bytes20(0));
            }
        }
        return keccak256(packed);
    }

    /// @dev The member-only IMCM close commitment (`IntmaxRollup._closeMemberSetCommitment`),
    ///      recomputed independently over the cosigner prefix.
    function _closeMemberSetCommitment(bytes32[] memory cosigners) internal pure returns (bytes32) {
        bytes memory preimage = abi.encodePacked(bytes4(0x494d434d), uint32(cosigners.length));
        for (uint256 i = 0; i < 8; i++) {
            preimage = abi.encodePacked(preimage, i < cosigners.length ? cosigners[i] : bytes32(0));
        }
        return keccak256(preimage);
    }
}
