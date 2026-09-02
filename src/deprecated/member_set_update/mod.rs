//! Retired direct, in-place member-set-update prototype.
//!
//! The prototype could authenticate an old signer set's requested mutation, but it never proved
//! an atomic transition of every settlement and validity-layer authority. It is preserved only
//! for audit archaeology and historical fixture reproduction. It must not be linked into a
//! release binary or deployed verifier.

pub mod circuit;
