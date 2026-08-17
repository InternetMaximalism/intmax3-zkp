// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    CHALLENGE_PERIOD_SECS_FLOOR,
    SETTLEMENT_LOCAL_DEVNET_CHAIN_ID
} from "../src/ChannelSettlementManager.sol";

/// @title DeployConfig
/// @notice The one place where a deploy script decides "real network" vs "local devnet".
///
/// INTENTIONALLY SIMPLE: no state, no cryptography, one branch on `block.chainid`. The value it
/// returns is consumed by `ChannelSettlementManager`'s constructor, which independently enforces
/// the same floor — this library exists so the scripts ask for the right value, not so the scripts
/// are trusted to.
library DeployConfig {
    /// @notice Chain id of the local development network (anvil's default). Imported from
    /// `ChannelSettlementManager.sol` rather than restated, so the script's notion of "local" and
    /// the constructor's can never diverge.
    uint256 internal constant LOCAL_DEVNET_CHAIN_ID = SETTLEMENT_LOCAL_DEVNET_CHAIN_ID;

    /// @notice The challenge period used on the local devnet.
    ///
    /// SECURITY: 1 second is a value the challenge game cannot survive (see
    /// `ChannelSettlementManager.CHALLENGE_PERIOD_SECS`). It exists ONLY because the anvil E2Es
    /// drive a real node through close → challenge-window → `finalizeClose` and cannot wait a day
    /// of wall-clock. It is confined to chain id 31337 here AND rejected by the manager's
    /// constructor on every other chain, so this constant cannot reach a public network.
    uint64 internal constant LOCAL_DEVNET_CHALLENGE_PERIOD_SECS = 1;

    /// @notice The challenge period a deploy script must pass to `ChannelSettlementManager`.
    /// @return The protocol constant `CHALLENGE_PERIOD_SECS` (1 day) on every chain except the
    ///         local devnet, where the short E2E value is returned.
    ///
    /// SECURITY: this reads the CONTRACT's constant rather than restating 86_400, so the deployed
    /// value and the documented value cannot drift apart — which is exactly how the 1-second window
    /// survived: `CHALLENGE_PERIOD_SECS` was declared with a spec reference and read by nothing.
    function challengePeriodSecs() internal view returns (uint64) {
        if (block.chainid == LOCAL_DEVNET_CHAIN_ID) {
            return LOCAL_DEVNET_CHALLENGE_PERIOD_SECS;
        }
        return CHALLENGE_PERIOD_SECS_FLOOR;
    }
}
