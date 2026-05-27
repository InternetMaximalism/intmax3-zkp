//! SPHINCS+ signature witness data types for the validity proof circuit.
//!
//! Each active user in a block must provide a SPHINCS+ signature over:
//!   M_i = [block_number, aggregator_id, local_id_i, tx_tree_root_u32_0..7]
//! (11 Goldilocks field elements = 88 bytes)
//!
//! The signature proves the user authorised their inclusion in this block with
//! the given tx_tree_root.  The corresponding public key is authenticated
//! against the `pk_set_root` field stored in the `AccountLeaf`.

use plonky2::iop::target::Target;

/// SPHINCS+ parameters (matches sphincsplus-params crate, SPX-128s Poseidon variant).
/// SPX_N = 16 bytes → SPX_N_WORDS = 2 Goldilocks (GL) field elements.
pub const SPX_N_WORDS: usize = 2;
/// SPX_FORS_TREES = 14
pub const SPX_FORS_TREES: usize = 14;
/// SPX_FORS_HEIGHT = 12
pub const SPX_FORS_HEIGHT: usize = 12;
/// SPX_D = 7 hypertree layers
pub const SPX_D: usize = 7;
/// SPX_WOTS_LEN = 35 (32 message digits + 3 checksum digits at base-16)
pub const SPX_WOTS_LEN: usize = 35;
/// SPX_TREE_HEIGHT = 9  (full height 63 / D 7 = 9)
pub const SPX_TREE_HEIGHT: usize = 9;

/// Number of GL elements in the FORS signature portion.
/// Each FORS tree contributes: 1 leaf hash (SPX_N_WORDS) + SPX_FORS_HEIGHT auth nodes.
pub const SPX_FORS_SIG_GL_LEN: usize = SPX_FORS_TREES * SPX_N_WORDS * (SPX_FORS_HEIGHT + 1);

/// Number of GL elements in one layer's WOTS+ signature.
pub const SPX_WOTS_SIG_GL_LEN: usize = SPX_WOTS_LEN * SPX_N_WORDS;

/// Number of GL elements in one layer's Merkle authentication path.
pub const SPX_AUTH_GL_LEN: usize = SPX_TREE_HEIGHT * SPX_N_WORDS;

/// Number of GL elements for the signing message.
/// [block_number (1), aggregator_id (1), local_id (1), tx_tree_root u32×8 (8)] = 11
pub const SPX_MSG_GL_LEN: usize = 11;

// ── Witness value types ────────────────────────────────────────────────────

/// SPHINCS+ signature witness for a single user slot.
///
/// All values are stored as Goldilocks field element words (u64, little-endian
/// byte order within each word).  A "word" is 8 bytes → SPX_N = 16 bytes = 2
/// words.
///
/// Provide [`SpxSigWitness::dummy`] for inactive (zero `local_id`) slots; the
/// circuit constraints are gated by `should_update` so the dummy values are
/// never checked.
#[derive(Clone, Debug)]
pub struct SpxSigWitness {
    /// Public key as GL words: `[pub_seed[0], pub_seed[1], root[0], root[1]]`.
    pub pk_gl: [u64; 4],
    /// Signature randomiser R: 2 GL words.
    pub r_gl: [u64; 2],
    /// FORS signature: `SPX_FORS_SIG_GL_LEN` GL words.
    pub fors_sig_gl: Vec<u64>,
    /// Hypertree WOTS+ signatures: `SPX_D` layers, each `SPX_WOTS_SIG_GL_LEN` words.
    pub ht_sig_gl: Vec<Vec<u64>>,
    /// Hypertree Merkle authentication paths: `SPX_D` layers, each `SPX_AUTH_GL_LEN` words.
    pub ht_auth_gl: Vec<Vec<u64>>,
}

impl SpxSigWitness {
    /// All-zero dummy witness for inactive user slots.
    pub fn dummy() -> Self {
        Self {
            pk_gl: [0u64; 4],
            r_gl: [0u64; 2],
            fors_sig_gl: vec![0u64; SPX_FORS_SIG_GL_LEN],
            ht_sig_gl: vec![vec![0u64; SPX_WOTS_SIG_GL_LEN]; SPX_D],
            ht_auth_gl: vec![vec![0u64; SPX_AUTH_GL_LEN]; SPX_D],
        }
    }

    /// Construct from raw `SpxPublicKey` and `SpxSignature` byte arrays
    /// (as defined in the `sphincsplus-params` crate).
    ///
    /// `pk_bytes`  – 32-byte public key: `pub_seed (16 bytes) || root (16 bytes)`.
    /// `sig_bytes` – 7856-byte SPHINCS+ signature.
    pub fn from_bytes(pk_bytes: &[u8; 32], sig_bytes: &[u8; 7856]) -> Self {
        let pack = |b: &[u8]| -> Vec<u64> {
            b.chunks(8)
                .map(|c| u64::from_le_bytes(c.try_into().expect("chunk is 8 bytes")))
                .collect()
        };

        let pk_words = pack(pk_bytes);
        let pk_gl: [u64; 4] = pk_words.try_into().expect("PK is exactly 4 words");

        // R: first 16 bytes of signature
        let r_words = pack(&sig_bytes[0..16]);
        let r_gl: [u64; 2] = r_words.try_into().expect("R is exactly 2 words");

        // FORS signature: next SPX_FORS_TREES * SPX_N * (SPX_FORS_HEIGHT+1) bytes
        let fors_bytes_len = SPX_FORS_TREES * 16 * (SPX_FORS_HEIGHT + 1);
        let fors_sig_gl = pack(&sig_bytes[16..16 + fors_bytes_len]);

        // Hypertree: SPX_D layers, each with WOTS sig + auth path
        let wots_bytes = SPX_WOTS_LEN * 16; // per layer WOTS sig bytes
        let auth_bytes = SPX_TREE_HEIGHT * 16; // per layer auth path bytes
        let layer_bytes = wots_bytes + auth_bytes;

        let mut offset = 16 + fors_bytes_len;
        let mut ht_sig_gl = Vec::with_capacity(SPX_D);
        let mut ht_auth_gl = Vec::with_capacity(SPX_D);
        for _ in 0..SPX_D {
            ht_sig_gl.push(pack(&sig_bytes[offset..offset + wots_bytes]));
            offset += wots_bytes;
            ht_auth_gl.push(pack(&sig_bytes[offset..offset + auth_bytes]));
            offset += auth_bytes;
        }
        assert_eq!(offset, 16 + fors_bytes_len + SPX_D * layer_bytes);

        Self {
            pk_gl,
            r_gl,
            fors_sig_gl,
            ht_sig_gl,
            ht_auth_gl,
        }
    }
}

// ── Circuit target types ───────────────────────────────────────────────────

/// Plonky2 virtual targets holding a single user's SPHINCS+ signature data.
///
/// Created by `UpdateAccountTreeTarget::new` for every user slot.  The
/// witness values are filled in via `set_witness`.
#[derive(Clone, Debug)]
pub struct SpxSigTargets {
    /// SPHINCS+ public key targets: `[pub_seed[0], pub_seed[1], root[0], root[1]]`.
    pub pub_seed_gl: [Target; 2],
    pub pub_root_gl: [Target; 2],
    /// Signature randomiser R targets.
    pub r_gl: [Target; 2],
    /// FORS signature targets.
    pub fors_sig_gl: Vec<Target>,
    /// Hypertree WOTS+ signature targets (SPX_D layers).
    pub ht_sig_gls: Vec<Vec<Target>>,
    /// Hypertree auth path targets (SPX_D layers).
    pub ht_auth_gls: Vec<Vec<Target>>,
}

impl SpxSigTargets {
    /// Set all virtual targets from a [`SpxSigWitness`].
    pub fn set_witness<F, W>(&self, witness: &mut W, value: &SpxSigWitness)
    where
        F: plonky2::field::types::Field,
        W: plonky2::iop::witness::WitnessWrite<F>,
    {
        let set = |w: &mut W, t: Target, v: u64| {
            w.set_target(t, F::from_canonical_u64(v));
        };

        set(witness, self.pub_seed_gl[0], value.pk_gl[0]);
        set(witness, self.pub_seed_gl[1], value.pk_gl[1]);
        set(witness, self.pub_root_gl[0], value.pk_gl[2]);
        set(witness, self.pub_root_gl[1], value.pk_gl[3]);

        set(witness, self.r_gl[0], value.r_gl[0]);
        set(witness, self.r_gl[1], value.r_gl[1]);

        for (t, v) in self.fors_sig_gl.iter().zip(value.fors_sig_gl.iter()) {
            set(witness, *t, *v);
        }
        for (layer_t, layer_v) in self.ht_sig_gls.iter().zip(value.ht_sig_gl.iter()) {
            for (t, v) in layer_t.iter().zip(layer_v.iter()) {
                set(witness, *t, *v);
            }
        }
        for (layer_t, layer_v) in self.ht_auth_gls.iter().zip(value.ht_auth_gl.iter()) {
            for (t, v) in layer_t.iter().zip(layer_v.iter()) {
                set(witness, *t, *v);
            }
        }
    }
}
