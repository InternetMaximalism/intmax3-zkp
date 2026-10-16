//! Thin vendored fork of `p3-batch-stark`'s prover/verifier entry points.
//!
//! Upstream hardcodes `LogUpGadget`; we swap in the polynomial-evaluation
//! gadget ([`crate::gadget::EvalGadget`]) and a single shared evaluation
//! challenge. All heavy machinery (PCS, FRI, quotient computation, symbolic
//! constraint analysis) is used directly from the published crates.

#[cfg(debug_assertions)]
pub(crate) mod check_constraints;
pub mod prover;
pub mod verifier;

pub use prover::prove_batch;
pub use verifier::verify_batch;
