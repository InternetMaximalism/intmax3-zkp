//! IMSB small-block signing-message fields for the validity proof circuit.
//!
//! Each signing block carries the block-producer's signature over the v2 IMSB digest (abstract2
//! §3.3.5 / detail2 §F-2):
//!   M = SmallBlockRootMessage::signing_digest()
//!     = keccak256(IMSB || channel_id || bp_member_slot || small_block_number ||
//!                 prev_small_block_root || tx_tree_root || state_commitment_root ||
//!                 medium_epoch_hint || close_freeze_nonce)
//! consumed in-circuit as 8 Goldilocks elements, one u32 digest limb each.
//!
//! SECURITY: the digest is recomputed IN-CIRCUIT from witnessed message fields with the
//! `tx_tree_root` component connected to the block's actual tx_tree_root targets, so a signature
//! can never be verified over a different root than the one applied. Additionally `tx_tree_root !=
//! 0` is enforced whenever a member signature is applied (detail2 §C-2: H2 = 0 is reserved for
//! in-channel updates).
//!
//! P4-3: these types were extracted from the deleted `sphincs_sig` module (the SPHINCS+ witness /
//! target residue was removed once the validity/close signature check moved to the Goldilocks
//! Poseidon-preimage single-sig + recursive list proof). The IMSB preimage layout is UNCHANGED.

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

// ── IMSB small-block signing message fields ────────────────────────────────

/// Witnessed per-block components of the v2 `SmallBlockRootMessage` preimage
/// (detail2 §F-2) EXCLUDING `channel_id` and `tx_tree_root`, which are supplied
/// by the enclosing circuit from its block-level targets so the digest stays
/// structurally bound to the root actually applied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmallBlockMessageFields {
    /// Block-producer member slot (1 u32 limb in the preimage).
    pub bp_member_slot: u32,
    /// Block-producer Goldilocks pubkey hash `pk_g` (8 u32 limbs in the preimage).
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
        self.bp_pk_g.set_witness(witness, value.bp_pk_g);
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
        let bp_pk_g = Bytes32::from_u32_slice(&[101, 102, 103, 104, 105, 106, 107, 108]).unwrap();
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
