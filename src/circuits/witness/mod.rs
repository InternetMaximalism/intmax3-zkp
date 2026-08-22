//! Witness state machines for block production and balance proving.
//!
//! Promoted out of `test_utils` (checkpoint handoff item: "production live witness code must stop
//! importing test_utils"): `block_producer.rs` and `live_balance_service.rs` — the durable
//! production services — are built on these state machines, so they are production code and live
//! in a production namespace. `circuits::test_utils` re-exports both modules unchanged, so every
//! test and fixture-generator path keeps compiling.
//!
//! BOUNDARY THAT REMAINS: the modules still CONTAIN harness-only material — the deterministic
//! per-channel key derivation (`deterministic_member_falcon_keys`, `ChannelMemberKeys::
//! deterministic`, `TEST_ACTIVE_MEMBERS`, `test_recipient_for`) and the keyed local-signing
//! registration paths (`add_channel_registration`, `register_channel`) that hold every member's
//! Falcon key. They cannot be `cfg(test)`-gated today because the fixture-generator binaries build
//! them without features. The production services use ONLY the keyless surface
//! (`add_channel_registration_public`, `next_channel_cosign`, `holds_local_signing_keys` as the
//! guard); extracting the harness material into its own module is the remaining cut.
pub mod balance_witness_generator;
pub mod block_witness_generator;
