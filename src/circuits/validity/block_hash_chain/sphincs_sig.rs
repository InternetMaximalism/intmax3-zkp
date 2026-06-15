//! SPHINCS+ signature witness data types for the validity proof circuit.
//!
//! Each active channel member in a block must provide a SPHINCS+ signature over the v2
//! IMSB digest (abstract2 §3.3.5 / detail2 §F-2):
//!   M = SmallBlockRootMessage::signing_digest()
//!     = keccak256(IMSB || channel_id || bp_key_id || small_block_number ||
//!                 prev_small_block_root || tx_tree_root || state_commitment_root ||
//!                 medium_epoch_hint || close_freeze_nonce)
//! consumed in-circuit as 8 Goldilocks elements, one u32 digest limb each (64 message
//! bytes for the native signer: each limb serialised as an 8-byte little-endian word).
//!
//! SECURITY: the digest is recomputed IN-CIRCUIT from witnessed message fields with the
//! `tx_tree_root` component connected to the block's actual tx_tree_root targets, so a
//! signature can never be verified over a different root than the one applied.
//! Additionally `tx_tree_root != 0` is enforced whenever a member signature is applied
//! (detail2 §C-2: H2 = 0 is reserved for in-channel updates).

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::builder::BuilderKeccak256 as _;

use crate::{
    common::channel::{SMALL_BLOCK_DOMAIN, hash_words, split_u64},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
};

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
/// The 8 u32 limbs of the IMSB `SmallBlockRootMessage::signing_digest()` (detail2 §F-2).
pub const SPX_MSG_GL_LEN: usize = 8;

// ── IMSB small-block signing message fields ────────────────────────────────

/// Witnessed per-block components of the v2 `SmallBlockRootMessage` preimage
/// (detail2 §F-2) EXCLUDING `channel_id` and `tx_tree_root`, which are supplied
/// by the enclosing circuit from its block-level targets so the digest stays
/// structurally bound to the root actually applied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmallBlockMessageFields {
    /// Block-producer member slot (1 u32 limb in the preimage).
    pub bp_member_slot: u32,
    /// Block-producer SPHINCS+ pubkey hash (8 u32 limbs in the preimage).
    pub bp_pk_g: Bytes32,
    pub small_block_number: u64,
    pub prev_small_block_root: Bytes32,
    /// H1' of the channel's BalanceState. The off-circuit equality check
    /// `state_commitment_root == balance_state.h1()` lives in
    /// `circuits::channel::state_update_verifier`.
    pub state_commitment_root: Bytes32,
    pub medium_epoch_hint: u64,
    pub close_freeze_nonce: u64,
}

impl SmallBlockMessageFields {
    /// Native mirror of `SmallBlockRootMessage::signing_digest()` (src/common/channel.rs).
    /// Limb order: [IMSB domain (1), channel_id (1), bp_member_slot (1),
    /// bp_pk_g (8), small_block_number (2), prev_small_block_root (8),
    /// tx_tree_root (8), state_commitment_root (8), medium_epoch_hint (2),
    /// close_freeze_nonce (2)] = 41 limbs.
    pub fn signing_digest(&self, channel_id: u32, tx_tree_root: Bytes32) -> Bytes32 {
        hash_words(
            &[
                vec![SMALL_BLOCK_DOMAIN, channel_id, self.bp_member_slot],
                self.bp_pk_g.to_u32_vec(),
                split_u64(self.small_block_number),
                self.prev_small_block_root.to_u32_vec(),
                tx_tree_root.to_u32_vec(),
                self.state_commitment_root.to_u32_vec(),
                split_u64(self.medium_epoch_hint),
                split_u64(self.close_freeze_nonce),
            ]
            .concat(),
        )
    }
}

/// Circuit targets for [`SmallBlockMessageFields`]. All scalar limbs are
/// range-checked to 32 bits at allocation (required by the keccak gadget).
#[derive(Clone, Debug)]
pub struct SmallBlockMessageFieldsTarget {
    pub bp_member_slot: Target,
    pub bp_pk_g: Bytes32Target,
    /// `split_u64(small_block_number)` limbs `[hi, lo]`.
    pub small_block_number: [Target; 2],
    pub prev_small_block_root: Bytes32Target,
    pub state_commitment_root: Bytes32Target,
    /// `split_u64(medium_epoch_hint)` limbs `[hi, lo]`.
    pub medium_epoch_hint: [Target; 2],
    /// `split_u64(close_freeze_nonce)` limbs `[hi, lo]`.
    pub close_freeze_nonce: [Target; 2],
}

impl SmallBlockMessageFieldsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let u32_limb = |builder: &mut CircuitBuilder<F, D>| {
            let t = builder.add_virtual_target();
            builder.range_check(t, 32);
            t
        };
        let bp_member_slot = u32_limb(builder);
        let bp_pk_g = Bytes32Target::new(builder, true);
        let small_block_number = [u32_limb(builder), u32_limb(builder)];
        let medium_epoch_hint = [u32_limb(builder), u32_limb(builder)];
        let close_freeze_nonce = [u32_limb(builder), u32_limb(builder)];
        let prev_small_block_root = Bytes32Target::new(builder, true);
        let state_commitment_root = Bytes32Target::new(builder, true);
        Self {
            bp_member_slot,
            bp_pk_g,
            small_block_number,
            prev_small_block_root,
            state_commitment_root,
            medium_epoch_hint,
            close_freeze_nonce,
        }
    }

    /// Recompute `SmallBlockRootMessage::signing_digest()` in-circuit.
    ///
    /// SECURITY: `channel_id` and `tx_tree_root` MUST be the enclosing circuit's
    /// block-level targets (already range-checked to u32 limbs) — this is what binds
    /// the signed digest to the tx root actually applied by the block.
    pub fn compute_signing_digest<F, C, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        channel_id: Target,
        tx_tree_root: &Bytes32Target,
    ) -> Bytes32Target
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let domain = builder.constant(F::from_canonical_u32(SMALL_BLOCK_DOMAIN));
        // Preimage limb order matches `SmallBlockRootMessage::signing_digest()` exactly.
        let inputs: Vec<Target> = [
            vec![domain, channel_id, self.bp_member_slot],
            self.bp_pk_g.to_vec(),
            self.small_block_number.to_vec(),
            self.prev_small_block_root.to_vec(),
            tx_tree_root.to_vec(),
            self.state_commitment_root.to_vec(),
            self.medium_epoch_hint.to_vec(),
            self.close_freeze_nonce.to_vec(),
        ]
        .concat();
        Bytes32Target::from_slice(&builder.keccak256::<C>(&inputs))
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &SmallBlockMessageFields,
    ) {
        witness.set_target(
            self.bp_member_slot,
            F::from_canonical_u32(value.bp_member_slot),
        );
        self.bp_pk_g
            .set_witness(witness, value.bp_pk_g);
        for (targets, native) in [
            (&self.small_block_number, value.small_block_number),
            (&self.medium_epoch_hint, value.medium_epoch_hint),
            (&self.close_freeze_nonce, value.close_freeze_nonce),
        ] {
            let limbs = split_u64(native);
            witness.set_target(targets[0], F::from_canonical_u32(limbs[0]));
            witness.set_target(targets[1], F::from_canonical_u32(limbs[1]));
        }
        self.prev_small_block_root
            .set_witness(witness, value.prev_small_block_root);
        self.state_commitment_root
            .set_witness(witness, value.state_commitment_root);
    }
}

// ── Witness value types ────────────────────────────────────────────────────

/// SPHINCS+ signature witness for a single user slot.
///
/// All values are stored as Goldilocks field element words (u64, little-endian
/// byte order within each word).  A "word" is 8 bytes → SPX_N = 16 bytes = 2
/// words.
///
/// Provide [`SpxSigWitness::dummy`] for inactive (zero `key_id`) slots; the
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
/// Created by `UpdateUserTreeTarget::new` for every user slot.  The
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::channel::{ChannelId, SmallBlockRootMessage};

    /// SECURITY: guards against drift between the circuit-side IMSB preimage
    /// (`SmallBlockMessageFields::signing_digest`, mirrored limb-for-limb by
    /// `SmallBlockMessageFieldsTarget::compute_signing_digest`) and the canonical
    /// `SmallBlockRootMessage::signing_digest()` that channel members actually sign.
    #[test]
    fn small_block_message_fields_digest_matches_canonical_message() {
        let channel_id = ChannelId::new(5).unwrap();
        let bp_pk_g =
            Bytes32::from_u32_slice(&[101, 102, 103, 104, 105, 106, 107, 108]).unwrap();
        let prev_small_block_root = Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let tx_tree_root =
            Bytes32::from_u32_slice(&[9, 10, 11, 12, 13, 14, 15, 0xffff_ffff]).unwrap();
        let state_commitment_root =
            Bytes32::from_u32_slice(&[21, 22, 23, 24, 25, 26, 27, 28]).unwrap();

        let canonical = SmallBlockRootMessage {
            channel_id,
            bp_member_slot: 2,
            bp_pk_g,
            small_block_number: 0x1_2345_6789,
            prev_small_block_root,
            tx_tree_root,
            state_commitment_root,
            medium_epoch_hint: 42,
            close_freeze_nonce: 0xdead_beef_0000_0001,
        }
        .signing_digest();

        let fields = SmallBlockMessageFields {
            bp_member_slot: 2,
            bp_pk_g,
            small_block_number: 0x1_2345_6789,
            prev_small_block_root,
            state_commitment_root,
            medium_epoch_hint: 42,
            close_freeze_nonce: 0xdead_beef_0000_0001,
        };
        assert_eq!(fields.signing_digest(5, tx_tree_root), canonical);
        assert_ne!(fields.signing_digest(5, tx_tree_root), Bytes32::default());
    }
}
