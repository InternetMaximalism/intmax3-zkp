//! Retired Goldilocks Poseidon-preimage signature scheme — **format remnants only**.
//!
//! # RETIREMENT STATUS (falcon-sig migration) — COMPLETE
//!
//! The Goldilocks proof-as-signature primitive that this module used to host
//! (`GoldilocksSecretKey` + `circuit::SingleSigCircuit`, the "the proof IS the signature" scheme)
//! was replaced by Falcon-512/Poseidon ([`crate::falcon_sig`]) across close/cancel-close
//! (Phase 2), the validity list step (Phase 3) and the wallet/CLI/wasm co-sign (Phase 4). Both
//! types are DELETED: no key, no circuit, no verifier for that scheme exists anywhere in the tree.
//!
//! What survives here, and why:
//!
//! - [`list`] — the IMLL `(m, pk)` hash-CHAIN FORMAT (native reference + the shared in-circuit
//!   gadgets `leaf_target` / `chain_step_target`). The migration keeps it bit-for-bit; its producer
//!   lives in [`crate::falcon_sig::list`] and `update_channel_tree` consumes exactly these gadgets.
//!   This is the "shared chain gadgets" the module reduces to.
//! - [`DOMAIN_PK_G`] / [`DOMAIN_SIG_G`] — RETIRED domain constants, kept RESERVED so the repo-wide
//!   pairwise-distinctness registry (`crate::constants`) and the Falcon domain non-collision test
//!   keep proving that no live domain ever collides with a value this system once hashed under.
//!   They are not used to derive anything.
//!
//! A legacy `SingleSigCircuit` proof blob captured before the deletion lives at
//! `src/falcon_sig/testdata/legacy_single_sig_proof.bin`; the O-9 downgrade test verifies the
//! Falcon cosign parser rejects it on the version gate.

pub mod list;

/// RETIRED (falcon-sig Phase 4), kept RESERVED: the domain the deleted Goldilocks scheme hashed
/// public keys under, `pk = H(DOMAIN_PK_G ‖ sk)`. ASCII "IMPG". Nothing derives from it any more;
/// it stays registered so the pairwise-distinctness registry and
/// `falcon_sig::tests::falcon_domains_do_not_collide` keep proving no LIVE domain collides with
/// it. Do not reuse this value for a new purpose.
pub const DOMAIN_PK_G: u32 = 0x494d_5047;

/// RETIRED (falcon-sig Phase 4), kept RESERVED — see [`DOMAIN_PK_G`]. The domain the deleted
/// scheme hashed message signatures under, `sig = H(DOMAIN_SIG_G ‖ sk ‖ m)`. ASCII "IMSG".
pub const DOMAIN_SIG_G: u32 = 0x494d_5347;
