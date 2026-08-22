//! Test/fixture-facing re-exports of the witness state machines.
//!
//! The modules themselves moved to [`crate::circuits::witness`] (production namespace — the
//! durable services are built on them). These re-exports keep every existing
//! `circuits::test_utils::*` path in tests and fixture generators compiling unchanged.
pub use crate::circuits::witness::balance_witness_generator;
pub use crate::circuits::witness::block_witness_generator;
