//! Explicitly non-production protocol prototypes.
//!
//! Nothing in this module is compiled unless its matching `deprecated-*` Cargo feature is
//! selected. Release binaries must never enable those features.

pub mod member_set_update;
