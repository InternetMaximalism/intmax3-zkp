//! Type-adaptation layer between the vendored Miden `falcon512_poseidon2` code
//! (`src/falcon_sig/vendor/`) and this crate.
//!
//! Upstream code is written against `miden-crypto`'s own types: `Felt` (Miden Goldilocks),
//! `Word` (4-element digest), the `miden-serde-utils` byte-serialization traits, and a
//! `zeroize` re-export. This module maps each of those onto the host crate's equivalents so the
//! vendored math can stay byte-identical up to import lines (threat model TM-C3 / O-4):
//!
//! - `Felt` -> `plonky2::field::goldilocks_field::GoldilocksField` (the same Goldilocks prime `p =
//!   2^64 - 2^32 + 1`, so all canonical-value semantics carry over unchanged);
//! - `Word` -> `Bytes32` (the crate-wide 32-byte digest type; Falcon messages here are always
//!   32-byte keccak digests, per the threat model);
//! - serialization traits -> minimal re-implementations with the exact upstream method surface
//!   (`write_u8`/`write_bytes`/`write`, `read_u8`/`read_array`/`read`, `to_bytes`/
//!   `read_from_bytes`). INTENTIONALLY SIMPLE: plain byte plumbing, no framing or logic beyond what
//!   the vendored call sites use — this is serialization glue, not cryptography;
//! - `zeroize` -> re-export of the audited `zeroize` crate (same crate upstream re-exports).
//!
//! Everything here is deliberately free of cryptographic logic: conversions are kept in this one
//! file so the vendored math files carry only mechanical import edits (listed in
//! `vendor/README.md`).

use alloc::{string::String, vec::Vec};

use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

use crate::ethereum_types::bytes32::Bytes32;

/// Re-export of the audited `zeroize` crate under the path shape the vendored code imports
/// (`crate::falcon_sig::compat::zeroize::...`, mirroring upstream `crate::utils::zeroize::...`).
pub mod zeroize {
    pub use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
}

/// Miden `Felt` -> plonky2 Goldilocks. Same prime field; canonical-value semantics unchanged.
pub type Felt = GoldilocksField;

/// Miden `ZERO` constant.
pub const ZERO: Felt = GoldilocksField::ZERO;

/// Miden `Word` (the signed message digest) -> the crate-wide 32-byte digest type.
///
/// SECURITY: every message signed by the Falcon key in this system is a 32-byte keccak digest
/// whose preimage opens with a distinct domain constant (IMCH / IMSB), exactly as for the key it
/// replaces (threat model TM-C6). The signing API deliberately accepts only this digest type.
pub type Word = Bytes32;

// SERIALIZATION TRAITS (upstream `miden-serde-utils` surface)
// ================================================================================================

/// Deserialization error, matching the upstream variants used by the vendored code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeserializationError {
    /// The input was malformed.
    InvalidValue(String),
    /// The input ended before the requested number of bytes could be read.
    UnexpectedEof,
}

impl core::fmt::Display for DeserializationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidValue(msg) => write!(f, "invalid value: {msg}"),
            Self::UnexpectedEof => write!(f, "unexpected end of input"),
        }
    }
}

impl core::error::Error for DeserializationError {}

/// Byte-sink trait with the upstream method surface.
pub trait ByteWriter: Sized {
    fn write_u8(&mut self, value: u8);
    fn write_bytes(&mut self, values: &[u8]);
    fn write<S: Serializable>(&mut self, value: S) {
        value.write_into(self)
    }
}

impl ByteWriter for Vec<u8> {
    fn write_u8(&mut self, value: u8) {
        self.push(value);
    }
    fn write_bytes(&mut self, values: &[u8]) {
        self.extend_from_slice(values);
    }
}

/// Byte-source trait with the upstream method surface.
pub trait ByteReader {
    fn read_u8(&mut self) -> Result<u8, DeserializationError>;
    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError>;

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        let slice = self.read_slice(N)?;
        Ok(slice
            .try_into()
            .expect("read_slice returned exactly N bytes"))
    }

    fn read<D: Deserializable>(&mut self) -> Result<D, DeserializationError>
    where
        Self: Sized,
    {
        D::read_from(self)
    }
}

/// A `ByteReader` over a byte slice.
pub struct SliceReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Number of bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
}

impl ByteReader for SliceReader<'_> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        let value = *self
            .data
            .get(self.pos)
            .ok_or(DeserializationError::UnexpectedEof)?;
        self.pos += 1;
        Ok(value)
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        if self.remaining() < len {
            return Err(DeserializationError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }
}

/// Types that can serialize themselves into a `ByteWriter`.
pub trait Serializable {
    fn write_into<W: ByteWriter>(&self, target: &mut W);

    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        self.write_into(&mut result);
        result
    }
}

impl<const N: usize> Serializable for [u8; N] {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(self)
    }
}

/// Types that can deserialize themselves from a `ByteReader`.
pub trait Deserializable: Sized {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError>;

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        Self::read_from(&mut SliceReader::new(bytes))
    }
}

impl Deserializable for u8 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u8()
    }
}

/// Reads `N` bytes into a zeroize-on-drop buffer (upstream `read_sensitive_array`).
///
/// SECURITY: used for secret-key bytes during deserialization; the buffer is wiped on drop so
/// transient secret material does not linger on the heap/stack after parsing.
pub fn read_sensitive_array<const N: usize, R: ByteReader>(
    source: &mut R,
) -> Result<zeroize::Zeroizing<[u8; N]>, DeserializationError> {
    let mut buffer = zeroize::Zeroizing::new([0u8; N]);
    let slice = source.read_slice(N)?;
    buffer.copy_from_slice(slice);
    Ok(buffer)
}

/// Hex formatter used by the vendored `Display` impls (upstream `utils::write_hex`).
pub fn write_hex(f: &mut core::fmt::Formatter<'_>, bytes: &[u8]) -> core::fmt::Result {
    f.write_str("0x")?;
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

/// Deterministic pseudo-random byte expansion for vendored in-file tests (upstream
/// `crate::rand::test_utils::prng_array`).
///
/// INTENTIONALLY SIMPLE: test-only helper; the vendored test that consumes it asserts an
/// input-independent algebraic identity, so any deterministic expansion is adequate.
#[cfg(test)]
pub fn prng_array<const N: usize>(seed: [u8; 32]) -> [u8; N] {
    use rand010::{Rng as _, SeedableRng as _};
    let mut rng = rand_chacha010::ChaCha20Rng::from_seed(seed);
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}
