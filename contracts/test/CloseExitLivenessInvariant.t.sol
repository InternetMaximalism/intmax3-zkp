// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Vm} from "forge-std/Vm.sol";
import {CloseSettlementBase} from "./CloseSettlementBase.sol";
import {ChannelSettlementManager} from "../src/ChannelSettlementManager.sol";
import {CloseTestLib} from "./CloseTestLib.sol";

/// @dev The proof/intent builders the handler needs. They live on the test contract (which extends
///      `CloseSettlementBase`) so nothing is duplicated; the handler reaches them through this
///      interface as ordinary external calls.
interface ICloseExitOracle {
    function oBuildIntent(uint64 stateVersion, uint64 freezeNonce)
        external pure returns (ChannelSettlementManager.CloseIntent memory);
    function oCloseProof(ChannelSettlementManager.CloseIntent calldata intent)
        external view returns (bytes memory);
    function oCancelProof(bytes32 closeIntentDigest, uint64 revivedStateVersion)
        external view returns (bytes memory);
    function oMember() external view returns (address);
}

/// @title CloseExitHandler
/// @notice Stateful-fuzzing driver for the CLOSE LIFECYCLE (not the payout accounting — that is
///         `ChannelSettlementInvariant.t.sol`). It walks the manager through arbitrary interleavings
///         of freeze / submit / replace / cancel / finalize / wait.
///
/// SUPPLY MODEL. Every piece of material any actor uses is bounded by `supplyTop` — the newest
/// N-of-N-signed state that EXISTS in the world. It starts at a finite value and only ever grows
/// through `growSupply()`, which models the members co-signing one more state. No action may
/// reference a version above it, so the invariant's "an exit is satisfiable by a party holding
/// material the world can produce" is a claim about material that provably exists, not about a
/// version an oracle conjured. This is the exact modelling error that made round 2's A3 argument
/// ("the material they need provably exists") wrong: it did exist, and A1 had already spent it.
/// (The partial-withdrawal actions — burn submit/finalize/cancel and the A3/A4 marks — were removed
/// on 2026-10-09 with the Manager's partial-withdrawal path.)
contract CloseExitHandler {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    ChannelSettlementManager internal immutable manager;
    ICloseExitOracle internal immutable oracle;

    /// The newest signed state in existence. Monotone, and the ceiling on every action's material.
    uint64 public supplyTop = 30;

    // Coverage counters: an action class that was never once driven, or never once succeeded, makes
    // the invariant vacuous in that direction. `afterInvariant` reports on them.
    uint256 public succeededRequest;
    uint256 public succeededSubmit;
    uint256 public succeededCancel;
    uint256 public succeededFinalize;
    /// How many times the fuzzer left the machine in `ClosePending` past its challenge deadline —
    /// the state in which the R3-1 lock was terminal, and the one the invariant is really about.
    uint256 public sawPendingPastDeadline;

    constructor(ChannelSettlementManager manager_, ICloseExitOracle oracle_) {
        manager = manager_;
        oracle = oracle_;
    }

    /// A version the world can produce: anything at or below the supply top.
    function _version(uint256 seed) internal view returns (uint64) {
        return uint64(1 + (seed % uint256(supplyTop)));
    }

    /// The close intent the world can produce at `version`: an ordinary signed state.
    function closeIntentAt(uint64 version)
        public view returns (ChannelSettlementManager.CloseIntent memory)
    {
        return oracle.oBuildIntent(version, manager.currentCloseFreezeNonce());
    }

    function noteState() external {
        if (
            manager.channelStatus() == ChannelSettlementManager.ChannelLifecycleStatus.ClosePending &&
            manager.getPendingClose().active &&
            block.timestamp > manager.getPendingClose().challengeDeadline
        ) {
            sawPendingPastDeadline += 1;
        }
    }

    /// The members co-sign one more state. This is the ONLY way new material enters the world.
    function growSupply(uint256 seed) external {
        supplyTop += uint64(1 + (seed % 3));
        this.noteState();
    }

    function advanceTime(uint256 seed) external {
        // Bounded jumps, biased to land on both sides of the deadlines that matter.
        uint256 step = seed % 4;
        uint256 dt = step == 0 ? 1 : step == 1 ? 601 : step == 2 ? 43_200 : 90_000;
        vm.warp(block.timestamp + dt);
        this.noteState();
    }

    function requestClose() external {
        uint64 freezeNonce = manager.currentCloseFreezeNonce();
        uint64 cancellationFloor = manager.highestCancelledRevivedStateVersion();
        vm.prank(oracle.oMember());
        try manager.requestClose(freezeNonce, cancellationFloor) {
            succeededRequest += 1;
        } catch {}
        this.noteState();
    }

    function submitClose(uint256 seed) external {
        ChannelSettlementManager.CloseIntent memory intent = closeIntentAt(_version(seed));
        try manager.submitCloseIntent(intent, oracle.oCloseProof(intent)) {
            succeededSubmit += 1;
        } catch {}
        this.noteState();
    }

    function cancelTheClose(uint256 seed) external {
        if (!manager.getPendingClose().active) return;
        bytes32 d = manager.getPendingClose().closeIntentDigest;
        uint64 revived = _version(seed);
        try manager.cancelClose(
            ChannelSettlementManager.CancelCloseRequest({
                closeIntentDigest: d,
                revivedStateVersion: revived,
                revivedChannelStateDigest: keccak256(abi.encodePacked("revived", revived))
            }),
            oracle.oCancelProof(d, revived)
        ) {
            succeededCancel += 1;
        } catch {}
        this.noteState();
    }

    function finalizeTheClose() external {
        ChannelSettlementManager.PendingClose memory pending = manager.getPendingClose();
        try manager.finalizeCloseGuarded(pending.closeIntentDigest, manager.closeRequestGeneration()) {
            succeededFinalize += 1;
        } catch {}
        this.noteState();
    }
}

/// @title CloseExitLivenessInvariant
/// @notice THE MISSING INVARIANT (round 3). Independent monotone latches — A1's global
///         `highestCancelledRevivedStateVersion` and H-3's absolute horizon (and, until 2026-10-09,
///         the partial-withdrawal A3/A4 marks) — gate a state machine whose only exits are
///         `finalizeClose` and `cancelClose`, and until round 3 NOTHING enforced that at least one
///         exit stayed satisfiable. Round 1 fixed a fund lock (C-3); round 2's fixes reintroduced
///         the class; round 3 found it reachable a THIRD way. This suite is the machine-checked
///         statement that the class is closed, so a later round that adds a new latch trips it
///         instead of shipping.
///
/// THE PROPERTY. From any reachable `ClosePending` state, at least one of `finalizeClose` /
/// `cancelClose` / `submitCloseIntent` is satisfiable by a party holding material the world can
/// produce (a state version at or below the handler's `supplyTop`). Waiting is allowed — the check
/// may advance the clock to the pending challenge deadline, because time passes without anyone's
/// cooperation — but nothing else is: no version above the supply top, no member-only privilege
/// beyond `requestClose`'s own gate, and no proof that does not verify.
contract CloseExitLivenessInvariantTest is CloseSettlementBase, ICloseExitOracle {
    CloseExitHandler internal handler;

    function setUp() public override {
        super.setUp();
        handler = new CloseExitHandler(manager, ICloseExitOracle(address(this)));

        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = CloseExitHandler.requestClose.selector;
        selectors[1] = CloseExitHandler.submitClose.selector;
        selectors[2] = CloseExitHandler.cancelTheClose.selector;
        selectors[3] = CloseExitHandler.finalizeTheClose.selector;
        selectors[4] = CloseExitHandler.advanceTime.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    // ── ICloseExitOracle ─────────────────────────────────────────────────────────────────────

    function oMember() external view returns (address) {
        return alice;
    }

    function oBuildIntent(uint64 stateVersion, uint64 freezeNonce)
        external pure returns (ChannelSettlementManager.CloseIntent memory intent)
    {
        intent = _intent(1, 9, 22, freezeNonce);
        intent.finalStateVersion = stateVersion;
        intent.finalChannelStateDigest = keccak256(abi.encodePacked("final_state", stateVersion, freezeNonce));
    }

    function oCloseProof(ChannelSettlementManager.CloseIntent calldata intent)
        external view returns (bytes memory)
    {
        return this._closeProofCd(
            intent,
            manager.registeredMemberSetCommitment(),
            manager.activeMemberCount(),
            uint32(manager.activeDelegateCount())
        );
    }

    function oCancelProof(bytes32 closeIntentDigest, uint64 revivedStateVersion)
        external view returns (bytes memory)
    {
        return _cancelProofFor(closeIntentDigest, revivedStateVersion);
    }

    function _cancelProofFor(bytes32 closeIntentDigest, uint64 revivedStateVersion)
        internal view returns (bytes memory)
    {
        ChannelSettlementManager.PendingClose memory pending = manager.getPendingClose();
        return CloseTestLib.proofWithLimbs(
            verifier.expectedCancelCloseLimbs(
                CHANNEL_ID,
                closeIntentDigest,
                manager.registeredMemberSetCommitment(),
                pending.finalStateVersion,
                revivedStateVersion,
                keccak256(abi.encodePacked("revived", revivedStateVersion))
            )
        );
    }

    // ── THE CHECK ────────────────────────────────────────────────────────────────────────────

    /// Try every exit from the current state under a state snapshot, using ONLY material at or below
    /// `supplyTop`, and revert everything the probe did. Returns which exits were satisfiable.
    ///
    /// The probe is destructive by construction (it settles or cancels the close, and it may warp),
    /// so it runs inside `vm.snapshotState()` / `vm.revertToState()` and restores the clock
    /// explicitly afterwards — `revertToState` is not relied on to roll back `block.timestamp`.
    function _probeExits()
        internal
        returns (bool viaFinalize, bool viaCancel, bool viaReplace)
    {
        uint256 clock = block.timestamp;

        // (a) guarded finalize — permissionless, but names the exact request generation and digest.
        uint256 snap = vm.snapshotState();
        uint64 deadline = manager.getPendingClose().challengeDeadline;
        if (block.timestamp <= deadline) vm.warp(uint256(deadline) + 1);
        ChannelSettlementManager.PendingClose memory pending = manager.getPendingClose();
        try manager.finalizeCloseGuarded(pending.closeIntentDigest, manager.closeRequestGeneration()) {
            viaFinalize = true;
        } catch {}
        vm.revertToState(snap);
        vm.warp(clock);

        // (b) `cancelClose` with the newest state that EXISTS. No window bound, but it must clear
        //     A1's manager-lifetime floor and the pending close's own version.
        snap = vm.snapshotState();
        uint64 top = handler.supplyTop();
        bytes32 d = manager.getPendingClose().closeIntentDigest;
        try manager.cancelClose(
            ChannelSettlementManager.CancelCloseRequest({
                closeIntentDigest: d,
                revivedStateVersion: top,
                revivedChannelStateDigest: keccak256(abi.encodePacked("revived", top))
            }),
            _cancelProofFor(d, top)
        ) {
            viaCancel = true;
        } catch {}
        vm.revertToState(snap);
        vm.warp(clock);

        // (c) challenge-replacement with the newest state that EXISTS.
        snap = vm.snapshotState();
        ChannelSettlementManager.CloseIntent memory head = handler.closeIntentAt(top);
        try manager.submitCloseIntent(head, this.oCloseProof(head)) {
            viaReplace = true;
        } catch {}
        vm.revertToState(snap);
        vm.warp(clock);
    }

    /// THE INVARIANT. Whenever the machine is in `ClosePending`, at least one exit is satisfiable.
    ///
    /// NOT VACUOUS, and the proof is not an argument but a run: adding any version-dependent
    /// refusal to `finalizeClose` makes `test_exitInvariant_isNotVacuous_twoExitsShutFinalizeCarries`
    /// below fail with all three exits false — the round-3 lock, detected. That test parks the
    /// machine where the other two exits are genuinely shut, so the property is pinned
    /// deterministically as well as fuzzed. `finalizeClose` keeps no version-dependent revert.
    function invariant_closePendingAlwaysHasAReachableExit() external {
        if (manager.channelStatus() != ChannelSettlementManager.ChannelLifecycleStatus.ClosePending) {
            return;
        }
        if (!manager.getPendingClose().active) {
            // Frozen with no intent yet: `submitCloseIntent` is the entry, and it is reachable by
            // anyone once the grace window elapses. Nothing to probe.
            return;
        }
        (bool f, bool c, bool r) = _probeExits();
        assertTrue(
            f || c || r,
            "EXIT LIVENESS: the channel is in ClosePending and NONE of finalizeClose / cancelClose / "
            "submitCloseIntent is satisfiable with material the world can produce -- ClosePending is "
            "terminal and every channel fund is locked (the C-3 / R3-1 class)"
        );
    }

    /// Coverage floor. If the fuzzer never once parked the machine in `ClosePending` past its
    /// challenge deadline, the invariant above was never asked the question that matters, and a
    /// green run means nothing. This is the `afterInvariant` shape established by
    /// `ChannelSettlementInvariant.t.sol` (audit28-08-2026 M-7).
    function afterInvariant() external view {
        assertGt(handler.succeededRequest(), 0, "COVERAGE: no era was ever opened");
        assertGt(handler.succeededSubmit(), 0, "COVERAGE: no close intent was ever admitted");
        assertGt(
            handler.sawPendingPastDeadline(),
            0,
            "COVERAGE: the fuzzer never once left the machine in ClosePending past its challenge "
            "deadline -- the state the exit invariant exists for was never reached, so a green run "
            "proves nothing"
        );
    }

    // ── DETERMINISTIC NON-VACUITY PIN ────────────────────────────────────────────────────────

    /// The R3-1 shape without a burn, handed to the SAME `_probeExits` machinery the invariant uses:
    /// A1's floor spends the supply top, a stale close is installed and parked past the fixed
    /// response-tail end. `cancelClose` is then genuinely shut (`CancelCloseReplay`: the newest
    /// existing state was already consumed) and `submitCloseIntent` is genuinely shut
    /// (`ChallengeWindowClosed`), so `finalizeClose` is the only exit — and it must stay reachable.
    /// A version-dependent refusal in `finalizeClose` makes all three probes false here.
    function test_exitInvariant_isNotVacuous_twoExitsShutFinalizeCarries() external {
        // 1. A1's floor spends the supply top: a stale close at v28 is cancelled by the honest
        //    holder of the head v30.
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory stale1 =
            this.oBuildIntent(28, manager.currentCloseFreezeNonce());
        manager.submitCloseIntent(stale1, this.oCloseProof(stale1));
        bytes32 d1 = manager.computeCloseIntentDigest(stale1);
        manager.cancelClose(
            ChannelSettlementManager.CancelCloseRequest({
                closeIntentDigest: d1,
                revivedStateVersion: 30,
                revivedChannelStateDigest: keccak256(abi.encodePacked("revived", uint64(30)))
            }),
            _cancelProofFor(d1, 30)
        );
        assertEq(manager.highestCancelledRevivedStateVersion(), 30, "A1 floor at the supply top");

        // 2. the same stale close again, parked past the fixed response-tail end.
        _requestCloseAndElapseGrace();
        ChannelSettlementManager.CloseIntent memory stale2 =
            this.oBuildIntent(28, manager.currentCloseFreezeNonce());
        manager.submitCloseIntent(stale2, this.oCloseProof(stale2));
        vm.warp(
            uint256(manager.closeChallengeHorizon())
                + manager.MIN_CLOSE_RESPONSE_SECS()
                + 1
        );
        assertEq(
            uint8(manager.channelStatus()),
            uint8(ChannelSettlementManager.ChannelLifecycleStatus.ClosePending),
            "the machine is parked in ClosePending, past the fixed response-tail end"
        );

        // THE CHECK, with the supply top pinned at 30 — no party can manufacture v31.
        assertEq(handler.supplyTop(), 30, "supply model: v30 is the newest state that exists");
        (bool f, bool c, bool r) = _probeExits();

        assertTrue(f || c || r, "EXIT LIVENESS: every exit from ClosePending is closed -- total permanent fund lock");
        assertTrue(f, "finalizeClose is the exit that stays reachable");
        assertFalse(c, "the spent A1 floor really refuses the newest existing state's cancel");
        assertFalse(r, "H-3/R3-4's fixed absolute end really does refuse the replacement");
    }
}
