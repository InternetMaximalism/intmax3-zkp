// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {VmSafe} from "forge-std/Vm.sol";

/// @title The ONE reader for a channel registration record JSON.
///
/// @notice WHY THIS EXISTS. Three deploy scripts (`DeployWalletSettlement`,
///         `DeployPartialWithdrawalE2E`, `DeployCloseCli`) each read a registration record written
///         by `src/bin/channel_member.rs` and use it for TWO structurally different things:
///
///           1. `IntmaxRollup.registerChannel(...)` — the L1 REGISTRATION RECORD. Under Option B
///              this is COSIGNERS-ONLY: it carries exactly `member_count` participants and its
///              `delegateCount` limb is ZERO. It is the preimage the validity `channel_reg_step`
///              circuit must reproduce.
///           2. `new ChannelSettlementManager(..., delegateCount, ..., mBind, dBind)` — the
///              SETTLEMENT BINDING. Its `activeDelegateCount` is the LIVE channel's delegate count:
///              it is the B-2 floor for close/partial-withdrawal (close PI limb 94 must be
///              `>= activeDelegateCount`) and it sizes the delegate `MemberBinding[]` that writes
///              `registeredRecipientOf` / `isMemberRecipient`.
///
///         Every script read ONE `delegate_count` field and fed it to both. That conflation is a
///         defect in each direction:
///
///           * Feeding the LIVE count to `registerChannel` produces an L1 registration with a
///             nonzero `delegateCount` limb. `ChannelRegStepCircuit` now CONSTRAINS that limb to
///             zero (`src/circuits/validity/channel_reg_hash_chain/channel_reg_step.rs`), so such a
///             registration is UNPROVABLE — the reg-chain step can never fold it and the channel is
///             stuck in the validity chain. Independently, the proving path that reproduces this
///             preimage (`wallet_core::build_channel_withdrawal`) has always built the record
///             cosigner-only, so a delegate-bearing registration never matched it in the first
///             place.
///           * Feeding ZERO to the manager would silently drop the B-2 delegate-close floor to
///             `0` (any close, however few delegates it claims, would pass the cardinality fence)
///             AND drop every delegate's recipient binding. That is a WEAKENED CHECK and is
///             exactly what this library refuses to let a "make the registration zero" edit do by
///             accident.
///
///         So the two are read from two DIFFERENT fields and can never be conflated again:
///         `reg_delegate_count` (must be 0, asserted here) and `active_delegate_count` (the live
///         count, passed through untouched).
///
/// @dev The record's `member_pk_gs` / `member_pk_bs` / `regev_pk_digests` / `recipients` arrays
///      carry the ACTIVE participants, MEMBERS FIRST (`0..member_count`) then delegates
///      (`member_count..member_count + active_delegate_count`) — the layout
///      `ChannelSettlementManager` and `channel_member.rs` already use. Registration consumes the
///      leading cosigner slice ONLY; the manager consumes the whole thing.
library RegRecordLib {
    /// forge-std's `VM_ADDRESS`, restated because a library cannot inherit `CommonBase`.
    VmSafe private constant vm =
        VmSafe(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// SECURITY (Option B, cosigner-only L1 registration): the ONLY delegate count that may reach
    /// `registerChannel`. A CONSTANT, not a field read — there is no JSON a producer can write that
    /// makes a script register a delegate. Mirrors the in-circuit `assert_zero(delegate_count)` in
    /// `ChannelRegStepTarget::new`, so a registration made with this library is always foldable by
    /// the reg-chain step.
    uint8 internal constant REGISTRATION_DELEGATE_COUNT = 0;

    /// Minimum co-signing members, mirroring `IntmaxRollup.MIN_CHANNEL_MEMBERS`. Checked here too
    /// so a malformed record fails on a readable message before it costs a broadcast.
    uint8 internal constant MIN_MEMBERS = 2;

    /// A parsed registration record. `pkGs`/`pkBs`/`regevDigests`/`recipients` are the ACTIVE set
    /// (`memberCount + activeDelegateCount` entries, members first).
    struct Record {
        uint32 channelId;
        uint8 bpSlot;
        uint8 memberCount;
        /// The LIVE delegate count — for the SETTLEMENT MANAGER only. Never for `registerChannel`.
        uint8 activeDelegateCount;
        bytes32[] pkGs;
        bytes32[] pkBs;
        bytes32[] regevDigests;
        address[] recipients;
    }

    /// Parse and VALIDATE a registration record.
    ///
    /// SECURITY: the `reg_delegate_count` check below is a tripwire, not the enforcement — the
    /// enforcement is `REGISTRATION_DELEGATE_COUNT`. Its job is to make a producer that starts
    /// emitting a nonzero registration delegate count fail LOUDLY at deploy time (where it is a
    /// one-line fix) instead of having the value silently ignored here and the two sides drift.
    function parse(string memory json) internal view returns (Record memory r) {
        r.channelId = uint32(vm.parseJsonUint(json, ".channel_id"));
        r.bpSlot = uint8(vm.parseJsonUint(json, ".bp_member_slot"));
        r.memberCount = uint8(vm.parseJsonUint(json, ".member_count"));
        r.activeDelegateCount = uint8(vm.parseJsonUint(json, ".active_delegate_count"));
        require(
            vm.parseJsonUint(json, ".reg_delegate_count") == 0,
            "reg record: reg_delegate_count must be 0 (Option B: L1 registration is cosigner-only; a nonzero registration is unprovable by channel_reg_step)"
        );

        r.pkGs = vm.parseJsonBytes32Array(json, ".member_pk_gs");
        r.pkBs = vm.parseJsonBytes32Array(json, ".member_pk_bs");
        r.regevDigests = vm.parseJsonBytes32Array(json, ".regev_pk_digests");
        r.recipients = vm.parseJsonAddressArray(json, ".recipients");

        require(r.memberCount >= MIN_MEMBERS, "reg record: member_count < MIN_CHANNEL_MEMBERS");
        require(r.bpSlot < r.memberCount, "reg record: bp_member_slot must be a co-signing member");
        uint256 active = uint256(r.memberCount) + uint256(r.activeDelegateCount);
        require(
            r.pkGs.length == active &&
                r.pkBs.length == active &&
                r.regevDigests.length == active &&
                r.recipients.length == active,
            "reg record: arrays must hold member_count + active_delegate_count entries (members first)"
        );
    }

    // ── the REGISTRATION view: the leading cosigner slice, nothing else ────────────────────────

    function regPkGs(Record memory r) internal pure returns (bytes32[] memory) {
        return _sliceB32(r.pkGs, r.memberCount);
    }

    function regPkBs(Record memory r) internal pure returns (bytes32[] memory) {
        return _sliceB32(r.pkBs, r.memberCount);
    }

    function regRegevDigests(Record memory r) internal pure returns (bytes32[] memory) {
        return _sliceB32(r.regevDigests, r.memberCount);
    }

    function regRecipients(Record memory r) internal pure returns (address[] memory out) {
        out = new address[](r.memberCount);
        for (uint256 i = 0; i < r.memberCount; i++) {
            out[i] = r.recipients[i];
        }
    }

    function _sliceB32(bytes32[] memory a, uint256 n) private pure returns (bytes32[] memory out) {
        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = a[i];
        }
    }
}
