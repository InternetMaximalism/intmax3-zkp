//! Falcon-512 signatures with a plonky2-Poseidon hash-to-point — the post-quantum member
//! signing key that replaces the Goldilocks `poseidon_sig` proof-as-signature scheme
//! (Phases 1-4). As of Phase 4 this is the ONE member signing key: it signs both the channel
//! state co-sign (IMCH) and the bp's small-block root (IMSB), with isolation resting on the
//! message digests' distinct domain constants (TM-C6).
//!
//! Scheme (threat model: `doc/tasks/falcon-sig-threat-model.md`, plan:
//! `doc/tasks/falcon-sig-todo.md`):
//!
//! - Falcon-512 (`n = 512`, `q = 12289`, GPV trapdoor sampling over NTRU lattices), vendored from
//!   `0xMiden/crypto` under `vendor/` (provenance + modified-file list in `vendor/README.md`). The
//!   sampler / FFT / NTRU keygen math is upstream code; the ONLY intentional functional change is
//!   the hash-to-point (TM-C1 / O-1).
//! - Hash-to-point: in-tree plonky2 Poseidon (Goldilocks, width 12, rate 8), capacity
//!   domain-separated with `IMFH`; one full field element per coefficient reduced mod q (see
//!   `vendor/hash_to_point.rs` for the exact sponge layout and the bias argument).
//! - Member identity: `pk_g = Poseidon(IMFK || encode(h))` where `encode(h)` packs the 512
//!   canonical (`< q`) coefficients of the public polynomial `h` 4-per-field-element in 14-bit
//!   lanes (see [`falcon_pk_digest`]) — a 32-byte digest, drop-in for the current `pk_g` slot.
//! - Signature wire format (DD-4 / O-9): `FALCON_SIG_V1 (1 byte) || salt (40 bytes) || compressed
//!   s2 (625 bytes, Falcon-standard Golomb-Rice, zero-padded)` — 666 bytes total, fixed length.
//! - Verification: recompute `c = H2P(salt, message_digest)`, `s1 = c - s2 * h` (NTT mod q, exact),
//!   accept iff `||(s1, s2)||^2 <= 34_034_726` over centered coefficient values.
//!
//! SECURITY: signing randomness policy (TM-C2 / DD-3) — the 40-byte salt is drawn from the OS
//! CSPRNG once per signature (outside the encodability retry loop) and the ffSampling trapdoor
//! sampler also draws from the OS CSPRNG. Deterministic signing is deliberately not
//! implemented (CARDIS-2023 fault attack on det-Falcon; sampler multi-runtime consistency).

pub mod agg;
pub mod agg_list;
pub mod batch;
pub mod compat;
pub mod gadget;
pub mod list;
pub(crate) mod vendor;

use alloc::vec::Vec;

use rand_chacha010::ChaCha20Rng;
use rand010::{Rng as _, SeedableRng as _};
use zeroize::Zeroize as _;

use crate::{ethereum_types::bytes32::Bytes32, utils::poseidon_hash_out::PoseidonHashOut};
use compat::{Deserializable as _, Serializable as _};
use vendor::{
    FalconFelt, FastFft as _, MODULUS, N, Polynomial, SIG_L2_BOUND, SIG_NONCE_LEN,
    SIG_POLY_BYTE_LEN, SecretKey, SignaturePoly,
};
pub use vendor::{Nonce, hash_to_point_poseidon};

// DOMAIN CONSTANTS
// ================================================================================================
// New IMxx domain constants for the Falcon scheme (threat model TM-C1 / TM-C7 / TM-C10). Each is
// the big-endian u32 of its ASCII tag, following the repo-wide convention (see the registry in
// `src/constants.rs::all_domain_constants_pairwise_distinct`; the `falcon_domains_do_not_collide`
// test below pins non-collision against every registered constant until these are merged into
// that registry in Phase 2).

/// "IMFH" — capacity domain separator of the Falcon hash-to-point sponge (TM-C1 / O-1).
pub const DOMAIN_FALCON_H2P: u32 = 0x494d_4648;

/// "IMFK" — domain of the member-identity digest `pk_g = Poseidon(IMFK || encode(h))` (TM-C7).
pub const DOMAIN_FALCON_PK: u32 = 0x494d_464b;

/// "IMFG" — domain separating the keygen-RNG seed derivation from every other use of the
/// 32-byte member seed (TM-C10 / O-11).
pub const DOMAIN_FALCON_KEYGEN: u32 = 0x494d_4647;

/// "IMFB" — capacity domain separator of the BATCH-aggregation Fiat-Shamir transcript sponge
/// (`batch::FalconBatchAggCircuit`): the in-circuit Poseidon transcript that commits every
/// slot's `(h, s2, pi)` polynomials before the product-check challenge `tau` is squeezed.
pub const DOMAIN_FALCON_BATCH: u32 = 0x494d_4642;

// WIRE-FORMAT CONSTANTS
// ================================================================================================

/// Version byte of the v1 Falcon signature wire format (O-9). Any other leading byte — in
/// particular the first byte of a legacy ~76 KB `SingleSigCircuit` proof blob — is rejected by
/// [`FalconSignature::from_bytes`] before any further parsing.
pub const FALCON_SIG_V1: u8 = 0x01;

/// Fixed total wire length of a v1 Falcon signature:
/// `1 (version) + 40 (salt) + 625 (compressed s2)` bytes.
///
/// 625 bytes is the Falcon-512 padded compressed-signature-polynomial length from the Falcon
/// specification (`sbytelen = 666` for the full salted signature; the s2 field alone is
/// `666 - 40 - 1 = 625`). Signing re-samples (same salt) in the negligible-probability event
/// that a sampled `s2` does not fit the padded encoding, so every emitted signature is exactly
/// this long, and the structural checks of later phases can enforce the exact length (TM-C8).
pub const FALCON_SIG_BYTES: usize = 1 + SIG_NONCE_LEN + SIG_POLY_BYTE_LEN;

/// Falcon-512 ring degree (number of polynomial coefficients).
pub const FALCON_N: usize = N;

/// Wire length of the public polynomial `h` inside a COSIGN blob: 512 coefficients, 2 bytes
/// each, little-endian, canonical (`< q`). See [`encode_cosign_blob`].
pub const FALCON_PK_H_BYTES: usize = 2 * FALCON_N;

/// Fixed total length of the wallet COSIGN transport blob (Phase 4):
/// `v1 signature (666) || h (1024)` = 1690 bytes. See [`encode_cosign_blob`] for why `h`
/// travels and why carrying it does not weaken the identity binding.
pub const FALCON_COSIGN_BLOB_BYTES: usize = FALCON_SIG_BYTES + FALCON_PK_H_BYTES;

/// Falcon-512 modulus `q`.
pub const FALCON_Q: u16 = MODULUS as u16;

/// Squared-norm acceptance bound `beta^2` for `(s1, s2)` (Falcon-512 spec value; threat model
/// §1: accept iff `||(s1, s2)||^2 <= beta^2`).
pub const FALCON_SIG_L2_BOUND: u64 = SIG_L2_BOUND;

// ERRORS
// ================================================================================================

/// Errors returned by [`FalconSignature::from_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FalconSigError {
    /// The input is empty (no version byte).
    #[error("empty falcon signature blob")]
    Empty,
    /// The leading version byte is not [`FALCON_SIG_V1`]. Distinct from the other variants so
    /// downgrade/replay attempts (TM-C8 / O-9) are observably rejected on the version gate.
    #[error("unsupported falcon signature version byte {0:#04x} (expected 0x01)")]
    UnsupportedVersion(u8),
    /// The input length is wrong: `(actual, expected)`. SECURITY (Phase-4 review MINOR-1): the
    /// expected length is carried in the error rather than hard-coded, because this ONE variant
    /// now serves two gates — the 666-byte bare signature and the 1690-byte cosign blob (which
    /// additionally carries `h`). The message previously always said "expected 666", so a
    /// rejected COSIGNATURE printed a length it was never checked against, misdirecting anyone
    /// reading the log. Tests match on the variant, so this was invisible to them.
    #[error("invalid falcon signature length {0} (expected {1})")]
    InvalidLength(usize, usize),
    /// The compressed `s2` field is not a canonical Falcon-512 compressed polynomial.
    #[error("malformed falcon s2 encoding: {0}")]
    MalformedS2(alloc::string::String),
    /// A COSIGN blob carried a public-polynomial coefficient `>= q`. Non-canonical encodings are
    /// rejected so `encode(h)` stays injective on the accepted domain (one `h` per `pk_g`) and so
    /// the blob encoding stays a bijection (signature BYTES feed keccak digests downstream).
    #[error("non-canonical falcon public key coefficient at index {0}")]
    NonCanonicalPublicKey(usize),
    /// The blob parsed but the signature did not verify against the authenticated `pk_g` — either
    /// `Poseidon(IMFK || encode(h)) != pk_g` (wrong signer / substituted public key) or the norm
    /// bound failed (wrong message / forgery attempt).
    #[error("falcon signature verification failed")]
    VerificationFailed,
}

// KEYS
// ================================================================================================

/// A member's Falcon-512 signing keypair.
///
/// SECURITY: this type derives neither `Serialize` nor `Deserialize` (a default secret-bearing
/// serialization is a leak-by-default footgun); `Debug` is redacted by the inner `SecretKey`.
/// Key material is zeroized on drop by the vendored `SecretKey`.
pub struct FalconKeys {
    sk: SecretKey,
}

impl FalconKeys {
    /// Deterministically derives the Falcon keypair from a 32-byte member seed (TM-C10 / O-11).
    ///
    /// SECURITY (domain separation): the NTRU-keygen RNG is `ChaCha20Rng` seeded with
    /// `keccak256("IMFG" || seed)` — NOT with the raw seed — so this use of the member seed can
    /// never collide with any other subkey derivation from the same seed (the repo's existing
    /// discipline draws independent sub-seeds per key; hashing under a dedicated domain gives
    /// the same independence for a deterministic derivation). Same seed => identical `h` and
    /// `pk_g` (restore-from-seed cannot fork identities); keygen runs at join/restore only,
    /// never per signature.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut preimage = [0u8; 36];
        preimage[..4].copy_from_slice(&DOMAIN_FALCON_KEYGEN.to_be_bytes());
        preimage[4..].copy_from_slice(&seed);
        let mut digest = keccak_hash::keccak(preimage).0;
        preimage.zeroize();
        let mut rng = ChaCha20Rng::from_seed(digest);
        digest.zeroize();
        let sk = SecretKey::with_rng(&mut rng);
        Self { sk }
    }

    /// The canonical coefficients of the public polynomial `h` (each `< q = 12289`).
    pub fn pk_coefficients(&self) -> [u16; FALCON_N] {
        let pk = self.sk.public_key();
        let mut out = [0u16; FALCON_N];
        for (o, c) in out.iter_mut().zip(pk.coefficients.iter()) {
            // `FalconFelt::value()` is the canonical representative in [0, q).
            *o = c.value() as u16;
        }
        out
    }

    /// The member-identity digest `pk_g = Poseidon(IMFK || encode(h))` (see
    /// [`falcon_pk_digest`]). Drop-in for the `Bytes32` `pk_g` slot of the current scheme.
    pub fn pk_g(&self) -> Bytes32 {
        falcon_pk_digest(&self.pk_coefficients())
    }

    /// Signs a 32-byte message digest, returning a wire-encodable signature.
    ///
    /// The digest MUST be a domain-separated digest (IMCH / IMSB) computed by the caller's
    /// context — never a raw caller-supplied message (TM-C6).
    pub fn sign(&self, message_digest: Bytes32) -> FalconSignature {
        // SECURITY (TM-C2 / DD-3 / O-3): the 40-byte salt is drawn from the OS CSPRNG
        // (`SysRng`, getrandom-backed) and sampled exactly ONCE, outside the retry loop below —
        // retries reuse the same salt (FN-DSA draft behavior), and two calls for the same
        // message get independent salts. A constant salt here is the `cmd_send` constant-seed
        // bug class (77594be); the `salt_freshness_*` test fails loudly on it.
        let mut rng = rand010::rand_core::UnwrapErr(rand010::rngs::SysRng);
        let mut salt = [0u8; SIG_NONCE_LEN];
        rng.fill_bytes(&mut salt);
        let nonce = Nonce::from_bytes(salt);

        loop {
            // SECURITY (TM-C2): the ffSampling trapdoor sampler draws from the same OS CSPRNG.
            // Deterministic (derandomized) sampling is deliberately not offered — see the
            // module-level policy note.
            let sig = self
                .sk
                .sign_with_rng(message_digest, nonce.clone(), &mut rng);
            let s2 = sig.sig_poly();
            // Falcon padded-format rule: in the negligible-probability event the sampled s2
            // exceeds the fixed 625-byte compressed encoding, re-sample s2 (same salt, same c).
            if s2_fits_padded_encoding(s2) {
                let out = FalconSignature {
                    salt,
                    s2: SignaturePoly::from(s2.clone()),
                };
                // SECURITY (review F-3): self-verify before returning. The vendored signer's
                // internal norm test runs on PRE-rounding float FFT values while `verify` norms
                // the exact post-rounding integers, so in principle the signer can emit a
                // signature its own verifier rejects; re-sampling closes that gap for ~64us
                // against a ~5.4ms signing cost. It also blunts the TM-C4 fault-attack residual
                // (a faulted signature is discarded here instead of shipped).
                if verify(&self.pk_coefficients(), message_digest, &out) {
                    return out;
                }
            }
        }
    }
}

/// The member-identity digest `pk_g = Poseidon(IMFK || encode(h))` over the canonical public
/// polynomial (TM-C7 / DD-2).
///
/// `encode(h)` — the canonical, circuit-friendly packing (mirrored in-circuit in Phase 1):
/// the 512 coefficients (each canonical, `< q = 12289 < 2^14`) are packed 4 per Goldilocks
/// element in 14-bit lanes, little-lane-first:
/// `e_j = h[4j] + h[4j+1] * 2^14 + h[4j+2] * 2^28 + h[4j+3] * 2^42` for `j = 0..128`.
/// Each packed element is `< 2^56 < p`, hence canonical; with every lane range-checked to
/// 14 bits (the in-circuit obligation, TM-C5 item 5) the packing is injective, so the digest
/// binds `h` uniquely. The hash is the same fixed-arity
/// `PoseidonHashOut::hash_inputs_u64([domain, ...])` construction as the current
/// `pk_g = Poseidon(IMPG || sk)` (129 elements here, domain first), and the output is the same
/// canonical `Bytes32` — a drop-in for every `pk_g` slot in Phase 4.
///
/// # Panics
/// Panics if any coefficient is `>= q`: callers derive `h` from `FalconKeys` (canonical by
/// construction); accepting a non-canonical encoding here would let one `h` open under two
/// digests. Untrusted encodings enter only through [`verify`], which rejects them gracefully.
pub fn falcon_pk_digest(pk_h: &[u16; FALCON_N]) -> Bytes32 {
    assert!(
        pk_h.iter().all(|&c| c < FALCON_Q),
        "falcon_pk_digest: non-canonical coefficient (>= q)"
    );
    let mut inputs = Vec::with_capacity(1 + FALCON_N / 4);
    inputs.push(DOMAIN_FALCON_PK as u64);
    for chunk in pk_h.chunks_exact(4) {
        let mut packed = 0u64;
        for (lane, &coeff) in chunk.iter().enumerate() {
            packed |= (coeff as u64) << (14 * lane);
        }
        inputs.push(packed);
    }
    PoseidonHashOut::hash_inputs_u64(&inputs).into()
}

/// The fixed PADDING-slot identity digest `Poseidon(IMFK || encode(0))` — the `pk_g` value the
/// conditional in-circuit gadget forces onto an INACTIVE (padding) slot, whose witness is the
/// all-zero polynomial (`gadget::FalconSigGadgetWitness::padding`).
///
/// SECURITY (TM-C7 padding argument, Phase-2 site): this digest is PUBLIC (anyone can compute
/// it) and MUST NOT be admitted as a member identity anywhere: the close / cancel-close
/// circuits zero padding slots out of the member-set commitment (so the committed padding value
/// stays `0x0…0`, exactly as before — forging a REAL member at a padding slot still requires a
/// Poseidon preimage of the ZERO digest under IMFK) and skip padding slots in the A5
/// distinctness chain. Registration-side, `h = 0` is not a valid NTRU public key, so no honest
/// member can ever collide with it; a MALICIOUS registrant registering this digest as their
/// pk_g gains nothing (they would merely be claiming a key whose only "signatures" are
/// norm-check failures — the padding slot never has a live norm bound, but a padding slot is
/// gated OFF by `member_count`, which is bound into the signed H1).
pub fn falcon_padding_pk_g() -> Bytes32 {
    falcon_pk_digest(&[0u16; FALCON_N])
}

// SIGNATURE
// ================================================================================================

/// A Falcon-512 signature: 40-byte salt + the `s2` polynomial.
///
/// Fields are private: instances exist only via [`FalconKeys::sign`] (canonical `s2` by
/// construction) or [`FalconSignature::from_bytes`] (canonicity enforced by the decoder), so
/// [`verify`] never sees an s2 outside the canonical coefficient range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FalconSignature {
    salt: [u8; SIG_NONCE_LEN],
    s2: SignaturePoly,
}

impl FalconSignature {
    /// The signature salt (public wire data).
    pub fn salt(&self) -> [u8; SIG_NONCE_LEN] {
        self.salt
    }

    /// The balanced (centered) `s2` coefficients, each in `[-2047, 2047]` by decoder
    /// canonicity. Phase-1 accessor: the in-circuit gadget witnesses `s2` (as canonical
    /// residues) and this is the only sanctioned way to read it out of a signature
    /// (`gadget::FalconSigGadgetWitness::for_signature`).
    pub fn s2_coefficients(&self) -> [i16; FALCON_N] {
        let mut out = [0i16; FALCON_N];
        for (o, c) in out.iter_mut().zip(self.s2.coefficients.iter()) {
            *o = c.balanced_value();
        }
        out
    }

    /// Serializes to the fixed 666-byte v1 wire format (DD-4):
    /// `FALCON_SIG_V1 || salt(40) || compressed s2 (625, zero-padded)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FALCON_SIG_BYTES);
        out.push(FALCON_SIG_V1);
        out.extend_from_slice(&self.salt);
        (&self.s2).write_into(&mut out);
        debug_assert_eq!(out.len(), FALCON_SIG_BYTES);
        out
    }

    /// Parses the v1 wire format.
    ///
    /// SECURITY (O-9 / TM-C8): the version byte is checked FIRST, before any length or
    /// structure parsing, and any version other than [`FALCON_SIG_V1`] gets the distinct
    /// [`FalconSigError::UnsupportedVersion`] error — so a legacy `SingleSigCircuit` proof blob
    /// (~76 KB) is rejected by policy at the first byte, not merely by failing to parse.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FalconSigError> {
        let &version = bytes.first().ok_or(FalconSigError::Empty)?;
        if version != FALCON_SIG_V1 {
            return Err(FalconSigError::UnsupportedVersion(version));
        }
        if bytes.len() != FALCON_SIG_BYTES {
            return Err(FalconSigError::InvalidLength(bytes.len(), FALCON_SIG_BYTES));
        }
        let salt: [u8; SIG_NONCE_LEN] = bytes[1..1 + SIG_NONCE_LEN]
            .try_into()
            .expect("length checked above");
        // The vendored decoder enforces s2 coefficient canonicity: coefficients in
        // [-2047, 2047], no `-0` encoding, no over-long unary runs, and zero unused bits in the
        // last CONSUMED byte.
        let s2_wire = &bytes[1 + SIG_NONCE_LEN..];
        let s2 = SignaturePoly::read_from_bytes(s2_wire)
            .map_err(|e| FalconSigError::MalformedS2(alloc::format!("{e}")))?;
        // SECURITY (encoding canonicality / malleability): the vendored decoder does NOT check
        // the zero-padding bytes after the consumed compressed prefix, so without this check two
        // distinct 666-byte strings could decode to the same signature (found by the
        // `tamper_suite_rejects` test; the Falcon reference implementation requires all
        // remaining padding bytes to be zero). Signature BYTES feed keccak digests downstream
        // (`SignedSmallBlock::signing_digest`), so the wire encoding must be a bijection:
        // re-encode and require byte equality, making exactly one byte string decode to any
        // given (salt, s2).
        let mut reencoded = Vec::with_capacity(SIG_POLY_BYTE_LEN);
        (&s2).write_into(&mut reencoded);
        if reencoded != s2_wire {
            return Err(FalconSigError::MalformedS2(alloc::string::String::from(
                "non-canonical s2 encoding (padding or re-encoding mismatch)",
            )));
        }
        Ok(Self { salt, s2 })
    }
}

// COSIGN TRANSPORT BLOB (Phase 4)
// ================================================================================================

/// Encodes the wallet COSIGN transport blob: `v1 signature (666) || h (1024, u16-LE canonical)`.
///
/// # Why `h` travels
///
/// A verifier of a channel-state co-signature holds the signer's AUTHENTICATED identity
/// `pk_g = Poseidon(IMFK || encode(h))` (it is `ChannelRecord.member_pk_gs[slot]`, anchored by the
/// on-chain registration), but `pk_g` is a hash: `h` cannot be recovered from it, and the Falcon
/// verification equation `s1 = c - s2*h` needs `h` itself. The alternatives were to widen
/// `MemberInfo`/`MemberLeaf` with a 1 KB public key (a wire-schema change on every consumer, and
/// still unauthenticated — `MemberLeaf` commits `pk_g`, not `h`) or to carry `h` inside the
/// already-opaque `MemberSignature.signature: Vec<u8>`. This does the latter: no wire schema
/// anywhere changes.
///
/// SECURITY (identity binding is NOT weakened): `h` arrives from the network and is therefore
/// UNTRUSTED. Every consumer must verify through [`verify_with_pk_g`], which recomputes
/// `falcon_pk_digest(h)` and requires it to equal the AUTHENTICATED `pk_g` before checking the
/// signature — exactly the check the in-circuit gadget performs (TM-C5 item 5). A blob carrying an
/// attacker's `h` therefore fails on the digest comparison; forging one that passes needs a
/// Poseidon collision/preimage under IMFK (assumption A-F4, unchanged). The transported `h` is a
/// convenience for the verifier, never a source of identity.
///
/// SECURITY (bijectivity): the decoder rejects any coefficient `>= q`, so exactly one 1690-byte
/// string decodes to any given `(salt, s2, h)` (the 666-byte prefix is already bijective — see
/// [`FalconSignature::from_bytes`]). Signature bytes feed keccak digests downstream
/// (`SignedSmallBlock::signing_digest`), so a malleable encoding would be a real defect.
///
/// # Panics
/// Panics if any coefficient is `>= q`. Callers encode `h` from their OWN [`FalconKeys`]
/// (canonical by construction); untrusted encodings enter only through [`decode_cosign_blob`],
/// which rejects them gracefully.
pub fn encode_cosign_blob(sig: &FalconSignature, pk_h: &[u16; FALCON_N]) -> Vec<u8> {
    assert!(
        pk_h.iter().all(|&c| c < FALCON_Q),
        "encode_cosign_blob: non-canonical coefficient (>= q)"
    );
    let mut out = sig.to_bytes();
    out.reserve_exact(FALCON_PK_H_BYTES);
    for &c in pk_h.iter() {
        out.extend_from_slice(&c.to_le_bytes());
    }
    debug_assert_eq!(out.len(), FALCON_COSIGN_BLOB_BYTES);
    out
}

/// Parses a COSIGN transport blob produced by [`encode_cosign_blob`].
///
/// SECURITY (O-9 / TM-C8, downgrade rejection): the VERSION byte is checked FIRST — before the
/// length and before any structural parsing — so a legacy ~76 KB `SingleSigCircuit` proof blob is
/// rejected by POLICY on the version gate rather than by an incidental parse failure. The blob
/// then has to be exactly [`FALCON_COSIGN_BLOB_BYTES`] long, which is the "fixed Falcon encoding
/// length" the threat model asks structural checks to enforce in place of "non-empty".
pub fn decode_cosign_blob(
    bytes: &[u8],
) -> Result<(FalconSignature, [u16; FALCON_N]), FalconSigError> {
    // Version gate FIRST (O-9): policy rejection, not a parse accident.
    let &version = bytes.first().ok_or(FalconSigError::Empty)?;
    if version != FALCON_SIG_V1 {
        return Err(FalconSigError::UnsupportedVersion(version));
    }
    if bytes.len() != FALCON_COSIGN_BLOB_BYTES {
        return Err(FalconSigError::InvalidLength(
            bytes.len(),
            FALCON_COSIGN_BLOB_BYTES,
        ));
    }
    let sig = FalconSignature::from_bytes(&bytes[..FALCON_SIG_BYTES])?;
    let mut pk_h = [0u16; FALCON_N];
    for (i, (slot, chunk)) in pk_h
        .iter_mut()
        .zip(bytes[FALCON_SIG_BYTES..].chunks_exact(2))
        .enumerate()
    {
        let c = u16::from_le_bytes([chunk[0], chunk[1]]);
        if c >= FALCON_Q {
            return Err(FalconSigError::NonCanonicalPublicKey(i));
        }
        *slot = c;
    }
    Ok((sig, pk_h))
}

/// Full COSIGN verification: parse the blob, then verify through [`verify_with_pk_g`] so the
/// transported `h` is bound to the AUTHENTICATED `pk_g` INSIDE the call.
///
/// SECURITY: this is the only sanctioned entry point for verifying a `MemberSignature.signature`.
/// Using [`verify`] on a decoded blob would drop the `falcon_pk_digest(h) == pk_g` check and
/// accept signatures under an attacker-chosen key (review F-2).
pub fn verify_cosign_blob(
    pk_g: Bytes32,
    message_digest: Bytes32,
    blob: &[u8],
) -> Result<(), FalconSigError> {
    let (sig, pk_h) = decode_cosign_blob(blob)?;
    if !verify_with_pk_g(pk_g, &pk_h, message_digest, &sig) {
        return Err(FalconSigError::VerificationFailed);
    }
    Ok(())
}

// VERIFICATION
// ================================================================================================

/// Verifies a Falcon signature over `message_digest` against the public polynomial `pk_h`.
///
/// This is the single canonical native verifier (the vendored upstream verifier is removed —
/// see `vendor/signature.rs`). Checks, in order:
///
/// 1. `pk_h` canonicity: every coefficient `< q`. SECURITY (encode(h) canonicity): a
///    mod-q-equivalent but non-canonical encoding (e.g. `h[i] + q`) would pass the algebraic check
///    below with the SAME norm while hashing to a DIFFERENT `pk_g` digest — this gate is what makes
///    `encode(h)` injective on the accepted domain, so one digest binds one `h`. (Chosen mitigation
///    per the plan: "rejected by verify"; key generation additionally never produces non-canonical
///    coefficients.)
/// 2. `c = H2P(salt, message_digest)` — recomputed here, never caller-supplied (TM-C6).
/// 3. `s1 = c - s2 * h` via the exact NTT mod q (vendored `FastFft` over `FalconFelt`).
/// 4. `||(s1, s2)||^2 <= beta^2 = 34_034_726` over CENTERED (balanced) coefficient values.
///    SECURITY: `<=` per the threat model §1 and the Falcon reference implementation (upstream
///    miden used a strict `<`, which wrongly rejects the boundary — see
///    `doc/tasks/falcon-sig-phase0-notes.md`). No overflow: the sum is at most `1024 * (q/2)^2 <
///    2^36`, far below `u64::MAX`.
pub fn verify(pk_h: &[u16; FALCON_N], message_digest: Bytes32, sig: &FalconSignature) -> bool {
    if pk_h.iter().any(|&c| c >= FALCON_Q) {
        return false;
    }
    let h = Polynomial::new(pk_h.iter().map(|&c| FalconFelt::new(c as i16)).collect());
    let c = hash_to_point_poseidon(message_digest, &Nonce::from_bytes(sig.salt));
    norm_within_bound(recomputed_norm_squared(&c, &sig.s2, &h))
}

/// Verify with the member-identity binding checked INSIDE the call (review F-2).
///
/// SECURITY: `verify` alone takes a raw `h` and does NOT tie it to any registered identity — a
/// consumer that forgets `falcon_pk_digest(h) == pk_g` accepts signatures under an
/// attacker-chosen key. Phases 2/4 consumers MUST use this entry point (or replicate the digest
/// check in-circuit); `verify` stays public only for the gadget-mirror tests.
pub fn verify_with_pk_g(
    pk_g: Bytes32,
    pk_h: &[u16; FALCON_N],
    message_digest: Bytes32,
    sig: &FalconSignature,
) -> bool {
    if pk_h.iter().any(|&c| c >= FALCON_Q) {
        return false;
    }
    if falcon_pk_digest(pk_h) != pk_g {
        return false;
    }
    verify(pk_h, message_digest, sig)
}

/// The acceptance predicate on the recomputed squared norm (factored out so the boundary tests
/// exercise the exact predicate [`verify`] uses).
pub(crate) fn norm_within_bound(norm_squared: u64) -> bool {
    norm_squared <= SIG_L2_BOUND
}

/// Computes `||(s1, s2)||^2` with `s1 = c - s2 * h`, all products exact (NTT mod q), norms over
/// centered (balanced) coefficient values.
pub(crate) fn recomputed_norm_squared(
    c: &Polynomial<FalconFelt>,
    s2: &Polynomial<FalconFelt>,
    h: &Polynomial<FalconFelt>,
) -> u64 {
    let s1 = (c.fft() - s2.fft().hadamard_mul(&h.fft())).ifft();
    s1.norm_squared() + s2.norm_squared()
}

/// Whether `s2` fits the fixed 625-byte padded compressed encoding (per-coefficient cost:
/// 1 sign bit + 7 low bits + unary high bits + terminator = `9 + (|c| >> 7)` bits).
fn s2_fits_padded_encoding(s2: &Polynomial<FalconFelt>) -> bool {
    let bits: usize = s2
        .coefficients
        .iter()
        .map(|c| 9 + (c.balanced_value().unsigned_abs() as usize >> 7))
        .sum();
    bits <= SIG_POLY_BYTE_LEN * 8
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;

    use super::*;
    use crate::ethereum_types::u32limb_trait::U32LimbTrait as _;

    /// One shared deterministic keypair for the suite (NTRU keygen is the slow step; sharing it
    /// keeps the suite fast without weakening any test — determinism is separately proven by
    /// `keygen_from_seed_is_deterministic_and_seed_separated`).
    static KEYS: Lazy<FalconKeys> = Lazy::new(|| FalconKeys::from_seed([7u8; 32]));
    static KEYS_H: Lazy<[u16; FALCON_N]> = Lazy::new(|| KEYS.pk_coefficients());

    fn sample_digest(tag: u8) -> Bytes32 {
        // Stand-in for a domain-separated IMCH/IMSB keccak digest.
        Bytes32::from_u32_slice(&[0x494d_0000 | tag as u32, 1, 2, 3, 4, 5, 6, 7]).unwrap()
    }

    /// SECURITY: pins the new IMFH/IMFK/IMFG domain constants to their documented ASCII tags and
    /// proves they collide with NO existing domain constant in the codebase (cross-protocol
    /// domain confusion is the attack this rules out, TM-C1; the pinned list mirrors
    /// `constants.rs::all_domain_constants_pairwise_distinct` and will be merged there in
    /// Phase 2).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn falcon_domains_do_not_collide() {
        assert_eq!(DOMAIN_FALCON_H2P, u32::from_be_bytes(*b"IMFH"));
        assert_eq!(DOMAIN_FALCON_PK, u32::from_be_bytes(*b"IMFK"));
        assert_eq!(DOMAIN_FALCON_KEYGEN, u32::from_be_bytes(*b"IMFG"));
        assert_eq!(DOMAIN_FALCON_BATCH, u32::from_be_bytes(*b"IMFB"));

        // Every domain constant registered in constants.rs (pinned there as literals/consts),
        // plus the poseidon_sig pub constants referenced directly.
        let existing: &[u32] = &[
            0x494d_4348,                       // IMCH
            0x494d_5041,                       // IMPA (retired)
            0x494d_5342,                       // IMSB
            0x494d_5353,                       // IMSS
            0x494d_4954,                       // IMIT (retired)
            0x494d_434c,                       // IMCL
            0x494d_4349,                       // IMCI (retired)
            0x494d_4353,                       // IMCS
            0x494d_5343,                       // IMSC
            0x494d_434e,                       // IMCN
            0x494d_4350,                       // IMCP
            0x494d_434b,                       // IMCK
            0x494d_4357,                       // IMCW
            0x494d_5546,                       // IMUF
            0x494d_4352,                       // IMCR
            0x494d_434d,                       // IMCM
            0x494d_4c44,                       // IMLD (retired)
            0x494d_4253,                       // IMBS (retired)
            0x494d_534c,                       // IMSL (retired)
            0x494d_4248,                       // IMBH
            0x494d_544c,                       // IMTL
            0x494d_4244,                       // IMBD (retired)
            0x494d_4432,                       // IMD2
            0x494d_5443,                       // IMTC
            0x494d_5243,                       // IMRC
            0x494d_524b,                       // IMRK
            0x494d_5252,                       // IMRR
            0x494d_5250,                       // IMRP
            0x494d_435a,                       // IMCZ
            0x494d_555a,                       // IMUZ (retired)
            0x494d_575a,                       // IMWZ
            0x494d_5246,                       // IMRF
            0x494d_4c4c,                       // IMLL
            crate::poseidon_sig::DOMAIN_PK_G,  // IMPG
            crate::poseidon_sig::DOMAIN_SIG_G, // IMSG
            0x494d_5057,                       // IMPW (retired)
            0x4950_5732,                       // IPW2
            0x4d42_4c46,                       // MBLF
            0x4348_4c46,                       // CHLF
            0x5549_4400,                       // UID\0
            crate::regev::hash_sig::DOMAIN_PK_B,
            crate::regev::hash_sig::DOMAIN_SIG_B,
            crate::common::channel_message::CHANNEL_MESSAGE_MAGIC,
            crate::constants::BALANCE_STATE_DOMAIN_V2,
            crate::constants::BALANCE_SLOT_LEAF_DOMAIN_V2,
            crate::constants::PAY_DOMAIN_V2,
            crate::constants::L1_DEPOSIT_IMPORT_DOMAIN_V2,
            crate::constants::WITHDRAWAL_CLAIM_DOMAIN_V2,
            crate::constants::CHANNEL_UPDATE_ZKP_DOMAIN_V2,
            crate::constants::INTER_CHANNEL_TX_DOMAIN_V2,
            crate::constants::INTER_CHANNEL_TX_DOMAIN_V3,
            crate::constants::INTER_CHANNEL_TX_DOMAIN_V4,
            crate::constants::TOKEN_FUNDS_DIGEST_DOMAIN,
        ];
        let new = [
            DOMAIN_FALCON_H2P,
            DOMAIN_FALCON_PK,
            DOMAIN_FALCON_KEYGEN,
            DOMAIN_FALCON_BATCH,
        ];
        for (i, a) in new.iter().enumerate() {
            for b in new.iter().skip(i + 1) {
                assert_ne!(a, b, "new falcon domains collide with each other");
            }
            for b in existing {
                assert_ne!(
                    a, b,
                    "falcon domain {a:#010x} collides with existing {b:#010x}"
                );
            }
        }
    }

    /// Happy path over multiple messages. SECURITY: completeness — an honestly generated
    /// signature verifies for its message and public key, including after a wire round trip
    /// (so the 666-byte wire format loses no verification-relevant information), and the wire
    /// length is exactly the fixed constant (the size premise later structural checks rely on,
    /// TM-C8/O-10).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn round_trip_sign_verify() {
        for tag in [0x01u8, 0x7f, 0xee] {
            let digest = sample_digest(tag);
            let sig = KEYS.sign(digest);
            assert!(
                verify(&KEYS_H, digest, &sig),
                "fresh signature must verify (tag {tag})"
            );

            let wire = sig.to_bytes();
            assert_eq!(wire.len(), FALCON_SIG_BYTES, "wire length must be fixed");
            assert_eq!(wire[0], FALCON_SIG_V1);
            let decoded = FalconSignature::from_bytes(&wire).expect("wire round trip");
            assert_eq!(decoded, sig, "decode(encode(sig)) must be identity");
            assert!(verify(&KEYS_H, digest, &decoded));
        }
    }

    // ---- COSIGN TRANSPORT BLOB (Phase 4) --------------------------------------------------

    /// A REAL legacy `SingleSigCircuit` proof blob (77,872 bytes) captured from the tree at
    /// `79f11ad`, immediately before that circuit was deleted — see `testdata/README.md`.
    const LEGACY_SINGLE_SIG_BLOB: &[u8] = include_bytes!("testdata/legacy_single_sig_proof.bin");

    /// SECURITY (TM-C8 / O-9, DOWNGRADE REJECTION — the obligation, with a real artifact).
    ///
    /// A valid OLD-scheme cosignature (the proof-as-signature wire object every co-signer used
    /// to ship) must be rejected by the new verifier **by policy on the version gate**, not
    /// merely by failing to parse. The blob here is genuine, not a random byte string of the
    /// right size: a random blob could not distinguish "rejected because the format is
    /// unsupported" from "rejected because the bytes are noise".
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn legacy_single_sig_proof_blob_rejected_on_version_gate() {
        // The artifact really is the old thing: ~76 KB, not 666/1690 bytes.
        assert_eq!(LEGACY_SINGLE_SIG_BLOB.len(), 77_872);
        assert!(LEGACY_SINGLE_SIG_BLOB.len() > FALCON_COSIGN_BLOB_BYTES);
        assert_ne!(LEGACY_SINGLE_SIG_BLOB[0], FALCON_SIG_V1);

        // The COSIGN entry point (what `wallet_core::verify_state_sig` calls) rejects it on the
        // VERSION byte — the first thing it looks at, before length or structure.
        assert_eq!(
            decode_cosign_blob(LEGACY_SINGLE_SIG_BLOB),
            Err(FalconSigError::UnsupportedVersion(
                LEGACY_SINGLE_SIG_BLOB[0]
            )),
            "a legacy proof blob must be rejected by POLICY on the version gate"
        );
        // ... and so does the bare 666-byte signature parser.
        assert_eq!(
            FalconSignature::from_bytes(LEGACY_SINGLE_SIG_BLOB),
            Err(FalconSigError::UnsupportedVersion(
                LEGACY_SINGLE_SIG_BLOB[0]
            )),
        );
        // Full verification (with a real authenticated pk_g) rejects it too — the version gate
        // fires before any key or norm arithmetic happens.
        assert_eq!(
            verify_cosign_blob(KEYS.pk_g(), sample_digest(0x11), LEGACY_SINGLE_SIG_BLOB),
            Err(FalconSigError::UnsupportedVersion(
                LEGACY_SINGLE_SIG_BLOB[0]
            )),
        );
    }

    /// Completeness + wire fixity of the COSIGN blob: a freshly signed blob has the fixed 1690
    /// byte length, round-trips exactly, and verifies against the signer's `pk_g` alone (the
    /// verifier never needs `h` from anywhere else).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn cosign_blob_round_trip_and_verify() {
        let digest = sample_digest(0x21);
        let sig = KEYS.sign(digest);
        let blob = encode_cosign_blob(&sig, &KEYS_H);
        assert_eq!(blob.len(), FALCON_COSIGN_BLOB_BYTES);
        assert_eq!(blob[0], FALCON_SIG_V1);
        let (sig2, h2) = decode_cosign_blob(&blob).expect("round trip");
        assert_eq!(sig2, sig);
        assert_eq!(h2, *KEYS_H);
        assert_eq!(verify_cosign_blob(KEYS.pk_g(), digest, &blob), Ok(()));
        // Re-encoding the decoded pair reproduces the exact bytes (encoding is a bijection —
        // signature BYTES feed keccak digests downstream, so malleability would be a defect).
        assert_eq!(encode_cosign_blob(&sig2, &h2), blob);
    }

    /// SECURITY (the identity binding the transported `h` must NOT weaken, review F-2).
    ///
    /// `h` travels inside the blob and is therefore attacker-controlled. Each case below is a
    /// distinct way to try to exploit that; all must fail.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn cosign_blob_rejects_substituted_or_malformed_public_keys() {
        let digest = sample_digest(0x22);
        let blob = encode_cosign_blob(&KEYS.sign(digest), &KEYS_H);
        let pk_g = KEYS.pk_g();

        // (1) SUBSTITUTED KEY — the attacker signs with a key of their own and ships the matching
        // `h`. Internally consistent (it verifies under its OWN pk_g), but it is not the
        // registered member's identity, so the `Poseidon(IMFK||encode(h)) == pk_g` check rejects.
        // This is THE case that would break member authentication if `h` were trusted.
        let other = FalconKeys::from_seed([0xd1u8; 32]);
        let other_blob = encode_cosign_blob(&other.sign(digest), &other.pk_coefficients());
        assert_eq!(
            verify_cosign_blob(other.pk_g(), digest, &other_blob),
            Ok(())
        );
        assert_eq!(
            verify_cosign_blob(pk_g, digest, &other_blob),
            Err(FalconSigError::VerificationFailed),
            "a signature under an attacker key must not verify against a member's pk_g"
        );

        // (2) TAMPERED h with the honest signature — flipping any coefficient changes the digest.
        let mut tampered = blob.clone();
        tampered[FALCON_SIG_BYTES] ^= 0x01;
        assert_eq!(
            verify_cosign_blob(pk_g, digest, &tampered),
            Err(FalconSigError::VerificationFailed)
        );

        // (3) NON-CANONICAL h (`c >= q`): rejected by the decoder, never reaching
        // `falcon_pk_digest` (which panics on non-canonical input). A mod-q-equivalent encoding
        // would satisfy the algebraic check while hashing to a different digest, so this gate is
        // what keeps `encode(h)` injective on the accepted domain.
        let mut noncanon = blob.clone();
        noncanon[FALCON_SIG_BYTES..FALCON_SIG_BYTES + 2].copy_from_slice(&FALCON_Q.to_le_bytes());
        assert_eq!(
            verify_cosign_blob(pk_g, digest, &noncanon),
            Err(FalconSigError::NonCanonicalPublicKey(0))
        );

        // (4) WRONG MESSAGE — the norm bound fails once c is recomputed from another digest.
        assert_eq!(
            verify_cosign_blob(pk_g, sample_digest(0x23), &blob),
            Err(FalconSigError::VerificationFailed)
        );

        // (5) LENGTH GATE — truncation and extension are both rejected (the fixed-length
        // structural check TM-C8 asks for, replacing "non-empty").
        assert_eq!(
            verify_cosign_blob(pk_g, digest, &blob[..blob.len() - 1]),
            Err(FalconSigError::InvalidLength(
                FALCON_COSIGN_BLOB_BYTES - 1,
                FALCON_COSIGN_BLOB_BYTES
            ))
        );
        let mut extended = blob.clone();
        extended.push(0);
        assert_eq!(
            verify_cosign_blob(pk_g, digest, &extended),
            Err(FalconSigError::InvalidLength(
                FALCON_COSIGN_BLOB_BYTES + 1,
                FALCON_COSIGN_BLOB_BYTES
            ))
        );
        // (6) A bare 666-byte signature (no h) is NOT a cosign blob.
        assert_eq!(
            verify_cosign_blob(pk_g, digest, &blob[..FALCON_SIG_BYTES]),
            Err(FalconSigError::InvalidLength(
                FALCON_SIG_BYTES,
                FALCON_COSIGN_BLOB_BYTES
            ))
        );
        // (7) Empty input hits the version gate's `Empty`, not a panic.
        assert_eq!(
            verify_cosign_blob(pk_g, digest, &[]),
            Err(FalconSigError::Empty)
        );
    }

    /// SECURITY (TM-C2 / O-3): salts are fresh per signature. Signing the SAME message twice
    /// must produce different 40-byte salts (this test FAILS LOUDLY if the salt source ever
    /// degrades to a constant — the `cmd_send` constant-seed bug class, 77594be) while both
    /// signatures still verify (randomization does not break completeness).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn salt_freshness_two_signatures_differ_and_both_verify() {
        let digest = sample_digest(0xaa);
        let sig1 = KEYS.sign(digest);
        let sig2 = KEYS.sign(digest);
        assert_ne!(
            sig1.salt(),
            sig2.salt(),
            "two signatures of the same message must have distinct salts \
             (constant salt = deterministic signing, banned by TM-C2)"
        );
        assert!(verify(&KEYS_H, digest, &sig1));
        assert!(verify(&KEYS_H, digest, &sig2));
    }

    /// SECURITY (TM-C10 / O-11): restore-from-seed cannot fork identities — two fresh
    /// derivations from the same 32-byte seed yield the identical public polynomial h and the
    /// identical pk_g digest; a different seed yields a different key.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn keygen_from_seed_is_deterministic_and_seed_separated() {
        let a1 = FalconKeys::from_seed([42u8; 32]);
        let a2 = FalconKeys::from_seed([42u8; 32]);
        assert_eq!(
            a1.pk_coefficients(),
            a2.pk_coefficients(),
            "same seed => same h"
        );
        assert_eq!(a1.pk_g(), a2.pk_g(), "same seed => same pk_g");

        let b = FalconKeys::from_seed([43u8; 32]);
        assert_ne!(
            a1.pk_coefficients(),
            b.pk_coefficients(),
            "different seed => different h"
        );
        assert_ne!(a1.pk_g(), b.pk_g(), "different seed => different pk_g");
    }

    /// SECURITY (unforgeability surface): any single tampered component — salt byte, s2 byte,
    /// message digest, or public key — must make verification fail. Each case would be a direct
    /// forgery vector if accepted (a tampered salt/s2 accepted means the verification equation
    /// does not bind c and s2; a wrong-pk acceptance means signatures transfer between
    /// identities, breaking the pk_g binding of TM-C7).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn tamper_suite_rejects() {
        let digest = sample_digest(0x33);
        let sig = KEYS.sign(digest);
        let wire = sig.to_bytes();

        // flipped salt byte (inside salt region [1, 41))
        let mut w = wire.clone();
        w[17] ^= 0x01;
        let tampered = FalconSignature::from_bytes(&w).expect("salt bytes are opaque");
        assert!(
            !verify(&KEYS_H, digest, &tampered),
            "flipped salt byte must reject"
        );

        // flipped s2 byte (region [41, 666)): either the canonical decoder rejects the
        // encoding, or the decoded s2 differs and the verification equation rejects. NOTE: a
        // flip in the zero-padding tail (e.g. byte 665) decodes to the SAME s2 under the
        // vendored decoder — the re-encoding canonicality check in `from_bytes` is what rejects
        // it (wire malleability finding; see the SECURITY comment there). This test FAILED
        // before that check existed and guards it now.
        for pos in [41usize, 300, 665] {
            let mut w = wire.clone();
            w[pos] ^= 0x40;
            match FalconSignature::from_bytes(&w) {
                Err(_) => {}
                Ok(t) => {
                    assert!(
                        !verify(&KEYS_H, digest, &t),
                        "flipped s2 byte at {pos} must reject"
                    )
                }
            }
        }

        // wrong message digest
        assert!(
            !verify(&KEYS_H, sample_digest(0x34), &sig),
            "wrong digest must reject"
        );

        // wrong public key (a different member's h)
        let other = FalconKeys::from_seed([99u8; 32]);
        assert!(
            !verify(&other.pk_coefficients(), digest, &sig),
            "valid signature must not verify under another member's pk"
        );
    }

    /// SECURITY (TM-C8 / O-9 downgrade protection): the version gate rejects any non-v1 leading
    /// byte with the DISTINCT `UnsupportedVersion` error before parsing anything else, and a
    /// legacy-proof-sized random blob (~76 KB stand-in for an old `SingleSigCircuit` proof)
    /// is rejected without panicking. Also: a correct version byte with a wrong length is
    /// rejected by the exact-length check (no trailing-garbage acceptance).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn version_gate_rejects_non_v1_and_legacy_blobs() {
        let digest = sample_digest(0x55);
        let sig = KEYS.sign(digest);
        let wire = sig.to_bytes();

        for bad_version in [0x00u8, 0x02] {
            let mut w = wire.clone();
            w[0] = bad_version;
            assert_eq!(
                FalconSignature::from_bytes(&w),
                Err(FalconSigError::UnsupportedVersion(bad_version)),
                "version {bad_version:#04x} must hit the version gate, not a parse error"
            );
        }

        // ~76 KB deterministic pseudo-random blob (old proof stand-in). First byte forced
        // non-v1: the version gate must fire without reading further (no panic on huge input).
        let mut blob: Vec<u8> = compat::prng_array::<{ 76 * 1024 }>([0xabu8; 32]).to_vec();
        blob[0] = 0x9c;
        assert_eq!(
            FalconSignature::from_bytes(&blob),
            Err(FalconSigError::UnsupportedVersion(0x9c)),
        );

        // Same blob with a forged v1 version byte: exact-length check rejects.
        blob[0] = FALCON_SIG_V1;
        assert_eq!(
            FalconSignature::from_bytes(&blob),
            Err(FalconSigError::InvalidLength(76 * 1024, FALCON_SIG_BYTES)),
        );

        // Empty input: distinct error, no panic.
        assert_eq!(FalconSignature::from_bytes(&[]), Err(FalconSigError::Empty));
    }

    /// SECURITY (TM-C5 item 3 analog, native side): the acceptance predicate is exactly
    /// `norm^2 <= beta^2` — a norm of exactly beta^2 ACCEPTS and beta^2 + 1 REJECTS.
    ///
    /// Approach (documented per the plan): a real signature with norm exactly beta^2 is not
    /// constructible by search, so this drives the verify path's own components
    /// (`recomputed_norm_squared` + `norm_within_bound`, the exact composition `verify` uses)
    /// with crafted witnesses: h = 0 and s2 = 0 make s1 = c, and c is chosen with centered
    /// coefficients {5833, 104, 4, 2, 1} whose squares sum to exactly 34_034_726 = beta^2
    /// (5833^2 + 104^2 + 4^2 + 2^2 + 1^2). Appending one more coefficient of 1 gives
    /// beta^2 + 1. This proves the boundary of the predicate itself; end-to-end
    /// norm-exceeding rejection is covered by `tamper_suite_rejects`.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn norm_boundary_beta_squared_accepts_and_plus_one_rejects() {
        fn crafted_c(extra_one: bool) -> Polynomial<FalconFelt> {
            let mut vals = vec![0i16; FALCON_N];
            vals[0] = 5833;
            vals[1] = 104;
            vals[2] = 4;
            vals[3] = 2;
            vals[4] = 1;
            if extra_one {
                vals[5] = 1;
            }
            Polynomial::new(vals.into_iter().map(FalconFelt::new).collect())
        }
        let zero = Polynomial::new(vec![FalconFelt::new(0); FALCON_N]);

        let at_bound = recomputed_norm_squared(&crafted_c(false), &zero, &zero);
        assert_eq!(
            at_bound, FALCON_SIG_L2_BOUND,
            "crafted norm must hit beta^2 exactly"
        );
        assert!(
            norm_within_bound(at_bound),
            "norm == beta^2 must ACCEPT (threat model §1)"
        );

        let above = recomputed_norm_squared(&crafted_c(true), &zero, &zero);
        assert_eq!(above, FALCON_SIG_L2_BOUND + 1);
        assert!(!norm_within_bound(above), "norm == beta^2 + 1 must REJECT");
    }

    /// SECURITY (TM-C1 / A-F3): hash-to-point is a deterministic function of (salt, message) —
    /// same inputs give the same c, and either input changing changes c (so the salt binds the
    /// signature to one c and the digest binds it to one message). The histogram check is a
    /// crude uniformity smoke test: over 100 salts (51_200 coefficients), all 16 value buckets
    /// of [0, q) are populated within a generous band — catching gross squeeze bugs (stuck
    /// state, reused output, truncated range) rather than proving uniformity (the 2^-50 bias
    /// bound is an analytical argument, documented in `vendor/hash_to_point.rs`).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn h2p_deterministic_and_distribution_sane() {
        let digest = sample_digest(0x66);
        let salt = [5u8; 40];
        let c1 = hash_to_point_poseidon(digest, &Nonce::from_bytes(salt));
        let c2 = hash_to_point_poseidon(digest, &Nonce::from_bytes(salt));
        assert_eq!(
            c1.coefficients, c2.coefficients,
            "H2P must be deterministic"
        );

        let mut other_salt = salt;
        other_salt[39] ^= 1;
        let c3 = hash_to_point_poseidon(digest, &Nonce::from_bytes(other_salt));
        assert_ne!(
            c1.coefficients, c3.coefficients,
            "salt change must change c"
        );
        let c4 = hash_to_point_poseidon(sample_digest(0x67), &Nonce::from_bytes(salt));
        assert_ne!(
            c1.coefficients, c4.coefficients,
            "message change must change c"
        );

        let mut buckets = [0u32; 16];
        let mut samples = 0u32;
        for i in 0..100u32 {
            let mut s = [0u8; 40];
            s[..4].copy_from_slice(&i.to_le_bytes());
            let c = hash_to_point_poseidon(digest, &Nonce::from_bytes(s));
            assert_eq!(c.coefficients.len(), FALCON_N);
            for coeff in &c.coefficients {
                let v = coeff.value() as u32;
                assert!(
                    v < FALCON_Q as u32,
                    "H2P coefficient must be canonical (< q)"
                );
                buckets[(v * 16 / FALCON_Q as u32) as usize] += 1;
                samples += 1;
            }
        }
        let expected = samples / 16; // = 3200
        for (i, &count) in buckets.iter().enumerate() {
            assert!(
                count > expected / 2 && count < expected * 2,
                "H2P bucket {i} degenerate: {count} of {samples} (expected ~{expected})"
            );
        }
    }

    /// SECURITY (encode(h) canonicity, TM-C1/TM-C7): a forged pk encoding with any
    /// coefficient at or above q is REJECTED BY VERIFY (the chosen mitigation; keygen
    /// additionally never emits one). The sharp case is `h[i] + q`: it is mod-q EQUIVALENT to
    /// the honest key, so the algebraic check and norm would pass identically — only the
    /// canonicity gate stops an attacker from opening the same h under a second, different
    /// pk_g digest.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn pk_encoding_canonicity_rejected_by_verify() {
        let digest = sample_digest(0x77);
        let sig = KEYS.sign(digest);
        assert!(verify(&KEYS_H, digest, &sig), "sanity: honest pk verifies");

        // mod-q-equivalent non-canonical encoding of the SAME key
        let mut forged = *KEYS_H;
        forged[0] += FALCON_Q; // h[0] + q ≡ h[0] (mod q), but a different byte encoding
        assert!(
            !verify(&forged, digest, &sig),
            "mod-q-equivalent non-canonical pk encoding must be rejected by the canonicity gate"
        );

        // plain out-of-range coefficient (= q)
        let mut forged2 = *KEYS_H;
        forged2[100] = FALCON_Q;
        assert!(
            !verify(&forged2, digest, &sig),
            "coefficient == q must be rejected"
        );
    }

    /// Phase-0 bench (plan item): keygen / sign / verify wall-clock, printed with --nocapture.
    /// Not a security test; numbers feed the Phase-1 sizing decision.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn bench_keygen_sign_verify() {
        use std::time::Instant;

        // NTRU keygen has high retry variance; report a few seeds individually.
        let mut keygen_ms_all = Vec::new();
        for seed_byte in [1u8, 2, 3] {
            let t = Instant::now();
            let _k = FalconKeys::from_seed([seed_byte; 32]);
            keygen_ms_all.push(t.elapsed().as_secs_f64() * 1e3);
        }
        let t0 = Instant::now();
        let keys = FalconKeys::from_seed([1u8; 32]);
        let keygen_ms = t0.elapsed().as_secs_f64() * 1e3;

        let h = keys.pk_coefficients();
        let digest = sample_digest(0x88);

        const SIGN_ITERS: usize = 20;
        let t1 = Instant::now();
        let sigs: Vec<FalconSignature> = (0..SIGN_ITERS).map(|_| keys.sign(digest)).collect();
        let sign_ms = t1.elapsed().as_secs_f64() * 1e3 / SIGN_ITERS as f64;

        let t2 = Instant::now();
        for sig in &sigs {
            assert!(verify(&h, digest, sig));
        }
        let verify_ms = t2.elapsed().as_secs_f64() * 1e3 / SIGN_ITERS as f64;

        println!(
            "falcon_sig bench (native, release): keygen {keygen_ms:.1} ms \
             (per-seed samples {keygen_ms_all:.1?} ms), \
             sign {sign_ms:.3} ms/op, verify {verify_ms:.3} ms/op ({SIGN_ITERS} iters)"
        );
    }
}

#[cfg(test)]
mod review_hardening_tests {
    use super::*;
    use crate::ethereum_types::u32limb_trait::U32LimbTrait as _;

    /// SECURITY (review F-1): a malformed wire blob must be an ERROR, never a panic. Under this
    /// repo's `panic = "abort"` an out-of-bounds index in the s2 decoder is a remote
    /// process-kill (wasm: wallet trap) reachable with valid version + valid length + junk s2 —
    /// the review reproduced an abort on ~10% of RANDOM 666-byte v1 blobs. This test drives the
    /// exact reproduction (long unary runs exhausting the 625-byte buffer) plus a deterministic
    /// fuzz sweep through the SHIPPED `from_bytes` entry point.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn malformed_wire_blobs_error_instead_of_panicking() {
        // Exact reproduction shape: version + salt, then s2 bytes that are all-zero — every
        // coefficient burns unary continuation bits with no terminating 1, exhausting the buffer.
        let mut blob = vec![0u8; FALCON_SIG_BYTES];
        blob[0] = FALCON_SIG_V1;
        assert!(FalconSignature::from_bytes(&blob).is_err());

        // Deterministic fuzz: xorshift-filled s2 fields. Before the F-1 bounds fix this aborted
        // within the first ~10 iterations; now every outcome must be Ok or Err, never a panic.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut step = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut accepted = 0u32;
        for _ in 0..2000 {
            let mut b = vec![0u8; FALCON_SIG_BYTES];
            b[0] = FALCON_SIG_V1;
            for chunk in b[1..].chunks_mut(8) {
                let v = step().to_le_bytes();
                let n = chunk.len();
                chunk.copy_from_slice(&v[..n]);
            }
            if FalconSignature::from_bytes(&b).is_ok() {
                accepted += 1;
            }
        }
        // Random blobs may legitimately decode (and then fail verification); what matters here
        // is that no input aborts the process. The counter just keeps the loop un-optimizable.
        assert!(accepted <= 2000);
    }

    /// SECURITY (review §4): the all-zero s2 polynomial is a well-formed encoding but must never
    /// verify — `s1 = c` alone has norm far above beta^2 for any real c. Guards against a future
    /// "skip the multiplication when s2 == 0" shortcut.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn zero_s2_never_verifies() {
        let keys = FalconKeys::from_seed([7u8; 32]);
        let msg = Bytes32::from_u32_slice(&[9u32; 8]).unwrap();
        let real = keys.sign(msg);
        // Canonical encoding of the zero polynomial: for each coefficient, sign=0, low7=0, one
        // terminating 1-bit — i.e. bytes 0x00 0x80 repeated? Build via wire: decode path is the
        // only constructor, so craft the minimal unary form: each coefficient contributes
        // 8 zero-sign+low bits then a '1'. Simpler and robust: take the real signature and zero
        // its decoded s2 through the public wire round-trip is impossible by design (bijective
        // encoding), so instead check the verifier's algebra directly through `verify` with a
        // signature whose s2 encodes zero, constructed byte-wise.
        let mut z = vec![0u8; FALCON_SIG_BYTES];
        z[0] = FALCON_SIG_V1;
        z[1..1 + SIG_NONCE_LEN].copy_from_slice(&real.salt());
        // Each zero coefficient encodes as: 1 sign bit (0) + 7 low bits (0) + terminator '1'
        // => 9 bits per coefficient, 512 coefficients = 4608 bits = 576 bytes, padded to 625.
        {
            let s2_field = &mut z[1 + SIG_NONCE_LEN..];
            let mut bitpos = 0usize;
            for _ in 0..FALCON_N {
                bitpos += 8; // sign + low7 all zero
                s2_field[bitpos / 8] |= 0x80 >> (bitpos % 8); // terminating 1
                bitpos += 1;
            }
        }
        let zero_sig = FalconSignature::from_bytes(&z).expect("canonical zero s2 must decode");
        assert!(
            !verify(&keys.pk_coefficients(), msg, &zero_sig),
            "s2 = 0 must never satisfy the norm bound"
        );
    }

    /// SECURITY (review F-2): the pk_g-binding entry point rejects a VALID signature under a key
    /// whose digest does not match the claimed identity — the exact mistake a consumer could
    /// make with bare `verify`.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn verify_with_pk_g_binds_identity() {
        let a = FalconKeys::from_seed([1u8; 32]);
        let b = FalconKeys::from_seed([2u8; 32]);
        let msg = Bytes32::from_u32_slice(&[3u32; 8]).unwrap();
        let sig = a.sign(msg);
        assert!(verify_with_pk_g(a.pk_g(), &a.pk_coefficients(), msg, &sig));
        // Right signature, right h, WRONG claimed identity.
        assert!(!verify_with_pk_g(b.pk_g(), &a.pk_coefficients(), msg, &sig));
        // Attacker supplies their own h alongside the victim's pk_g.
        assert!(!verify_with_pk_g(a.pk_g(), &b.pk_coefficients(), msg, &sig));
    }

    /// SECURITY (review §9c): pinned KATs for the two constructions the Phase-1 circuit must
    /// mirror (O-2). A refactor that silently changes the sponge layout, the salt packing, the
    /// limb order, or the encode(h) packing breaks these fixed anchors instead of drifting
    /// unnoticed into a native/circuit mismatch.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn h2p_and_pk_digest_pinned_vectors() {
        let salt = {
            let mut s = [0u8; SIG_NONCE_LEN];
            for (i, b) in s.iter_mut().enumerate() {
                *b = i as u8;
            }
            s
        };
        let msg = Bytes32::from_u32_slice(&[0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
        let c = hash_to_point_poseidon(msg, &Nonce::from_bytes(salt));
        let coeffs: Vec<u16> = c.coefficients.iter().map(|f| f.value() as u16).collect();
        assert_eq!(coeffs.len(), 512);
        assert!(coeffs.iter().all(|&v| v < FALCON_Q));
        // Pinned from the reviewed Phase-0 implementation (2026-08-05). If any of these move,
        // the sponge layout / salt packing / limb order / reduction changed — which breaks the
        // native<->circuit mirror contract (O-2) and every already-issued pk_g. That is never a
        // refactor; it is a new scheme version.
        assert_eq!(
            &coeffs[..8],
            &[12069, 12087, 3183, 532, 2490, 10450, 11601, 9973]
        );
        assert_eq!(&coeffs[508..], &[2920, 9587, 9507, 7323]);
        let fold = coeffs
            .iter()
            .fold(0u64, |a, &v| a.wrapping_mul(31).wrapping_add(v as u64));
        assert_eq!(fold, 0x696f_2d35_6e5f_bbeb);
        let keys = FalconKeys::from_seed([42u8; 32]);
        assert_eq!(
            format!("{}", keys.pk_g()),
            "0x90eed9636e2a86f4043c297a284a6cc24666678312c6bd8a62fc56dc241decf0"
        );
    }
}
