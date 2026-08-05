//! Vendored Falcon-512 DSA core from `0xMiden/crypto` (`miden-crypto/src/dsa/falcon512_poseidon2`).
//!
//! See `vendor/README.md` for provenance (upstream commit hash), the license (MIT), and the
//! exact list of modified files. The Gaussian sampler (`math/ffsampling.rs`, `math/samplerz.rs`),
//! FFT (`math/fft.rs`), field (`math/field.rs`) and NTRU keygen (`math/mod.rs`) are vendored with
//! import-only edits; the ONLY intentional functional change in this vendor tree is
//! `hash_to_point.rs` (plonky2 Poseidon instead of Miden Poseidon2, per the threat model
//! `doc/tasks/falcon-sig-threat-model.md` TM-C1 / O-1).
//!
//! VENDOR EDITS in this file (see README for the full list):
//! - Miden `Felt`/serialization imports are mapped through `falcon_sig::compat`.
//! - The deterministic-signing machinery (`Nonce::deterministic`, the fixed `PREVERSIONED_NONCE`,
//!   the nonce version byte, and the `Nonce` `Serializable`/`Deserializable` impls that reconstruct
//!   the fixed nonce) is REMOVED. SECURITY: our salt policy is a randomized 40-byte CSPRNG salt per
//!   signature (TM-C2 / DD-3); a `deterministic()` constructor for the salt is exactly the
//!   fixed-salt footgun the threat model bans, and the upstream `Deserializable` impl silently
//!   fabricates salt bytes.
//! - The upstream `tests/` directory is not vendored; upstream's own tests were run against the
//!   pristine copy instead (O-4, see README).
//!
//! What follows below is otherwise upstream text/code.
//!
//! ---
//!
//! Upstream module documentation (describing the deterministic variant we do NOT use; kept for
//! provenance): a deterministic Falcon512 Poseidon2 signature over a message, differing from the
//! reference implementation in its use of the Poseidon2 algebraic hash function in its
//! hash-to-point algorithm and in the determinism of the signing process (algorand
//! `falcon-det.pdf`). This vendor copy removes the determinism and keeps the reference-style
//! randomized salt, while the sampler keeps relying solely on the builtin `f64` type with no
//! platform-specific optimizations.

// Vendored code retains upstream API surface; parts unused by the host crate are kept to
// minimize the diff against upstream (provenance / auditability outweighs dead-code pruning).
#![allow(dead_code)]

use crate::falcon_sig::compat::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Felt, Serializable, ZERO,
};
// VENDOR EDIT: `plonky2::field::types::Field` provides `from_canonical_u64` used in
// `Nonce::to_elements` (upstream: `Felt::new_unchecked`).
use plonky2::field::types::Field as _;

mod hash_to_point;
mod keys;
mod math;
mod signature;

// VENDOR EDIT: the re-export list is trimmed to what the host `falcon_sig` module consumes
// (`PublicKey` / `SignatureHeader` / `Signature` remain reachable through their defining
// submodules for later phases).
pub use self::{
    hash_to_point::hash_to_point_poseidon,
    keys::SecretKey,
    math::{FalconFelt, FastFft, Polynomial},
    signature::{Signature, SignaturePoly},
};

// CONSTANTS
// ================================================================================================

// The Falcon modulus p.
// VENDOR EDIT: visibility raised to pub(crate) so the host `falcon_sig` module can reference the
// canonical parameter set (values unchanged).
pub(crate) const MODULUS: i16 = 12289;

// Number of bits needed to encode an element in the Falcon field.
pub(crate) const FALCON_ENCODING_BITS: u32 = 14;

// The Falcon parameters for Falcon-512. This is the degree of the polynomial `phi := x^N + 1`
// defining the ring `Z_p[x]/(phi)`.
pub(crate) const N: usize = 512;
const LOG_N: u8 = 9;

/// Length of nonce used for signature generation.
pub(crate) const SIG_NONCE_LEN: usize = 40;

/// Number of field elements used to encode a nonce.
const NONCE_ELEMENTS: usize = 8;

/// Public key length as a u8 vector.
pub const PK_LEN: usize = 897;

/// Secret key length as a u8 vector.
pub const SK_LEN: usize = 1281;

/// Signature length as a u8 vector.
pub(crate) const SIG_POLY_BYTE_LEN: usize = 625;

/// Bound on the squared-norm of the signature.
pub(crate) const SIG_L2_BOUND: u64 = 34034726;

/// Standard deviation of the Gaussian over the lattice.
const SIGMA: f64 = 165.7366171829776;

// TYPE ALIASES
// ================================================================================================

type ShortLatticeBasis = [Polynomial<i16>; 4];

// NONCE
// ================================================================================================

/// Nonce of the Falcon signature.
///
/// VENDOR EDIT / SECURITY: unlike upstream, a `Nonce` here is always a caller-supplied 40-byte
/// value. The host `falcon_sig::FalconKeys::sign` samples it from the OS CSPRNG once per
/// signature (TM-C2 / DD-3); there is deliberately no `deterministic()` constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; SIG_NONCE_LEN]);

impl Nonce {
    /// Returns the underlying concatenated bytes of this nonce.
    pub fn as_bytes(&self) -> [u8; SIG_NONCE_LEN] {
        self.0
    }

    /// Returns a `Nonce` given an array of bytes.
    pub fn from_bytes(nonce_bytes: [u8; SIG_NONCE_LEN]) -> Self {
        Self(nonce_bytes)
    }

    /// Converts byte representation of the nonce into field element representation.
    ///
    /// Nonce bytes are converted to field elements by taking consecutive 5 byte chunks
    /// of the nonce and interpreting them as field elements.
    pub fn to_elements(&self) -> [Felt; NONCE_ELEMENTS] {
        let mut buffer = [0_u8; 8];
        let mut result = [ZERO; 8];
        for (i, bytes) in self.as_bytes().chunks(5).enumerate() {
            buffer[..5].copy_from_slice(bytes);
            // we can safely (without overflow) create a new Felt from u64 value here since this
            // value contains at most 5 bytes
            // VENDOR EDIT: upstream `Felt::new_unchecked`; plonky2's `from_canonical_u64` is the
            // same operation here because the value is < 2^40 < p (canonical by construction).
            result[i] = Felt::from_canonical_u64(u64::from_le_bytes(buffer));
        }

        result
    }
}
