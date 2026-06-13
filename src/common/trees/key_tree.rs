//! Two new identity trees for the channel-as-base-user model:
//!
//! * `KeyTree` maps a `key_id` to a `KeyLeaf { pk_set_root, threshold, num_keys }` — i.e. the
//!   registered M-of-N SPHINCS+ key set for that keyID. Indexed by `key_id`.
//! * `MemberKeyTree` commits the ordered, unique set of member `key_id`s belonging to a single
//!   channel; its root is stored in `ChannelLeaf.member_key_ids_root`.
//!
//! SECURITY: both leaves are domain-separated (distinct leading tags) so a leaf of one tree can
//! never be reinterpreted as a leaf of another tree (cross-tree confusion). Both trees are
//! populated only from on-chain registrations and proven consistent in-circuit (see
//! tasks/channel-key-tree-design.md).

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    constants::{KEY_ID_BITS, KEY_SET_TREE_HEIGHT, KEY_TREE_HEIGHT, MEMBER_KEY_TREE_HEIGHT},
    utils::{
        leafable::{Leafable, LeafableTarget},
        leafable_hasher::PoseidonLeafableHasher,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::{
            incremental_merkle_tree::{
                IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
            },
            sparse_merkle_tree::{SparseMerkleProof, SparseMerkleProofTarget, SparseMerkleTree},
        },
    },
};

/// Domain-separation tags (leading field of each leaf's Poseidon preimage). ASCII mnemonics.
const KEY_LEAF_DOMAIN: u64 = 0x4b594c46; // "KYLF"
const MEMBER_KEY_LEAF_DOMAIN: u64 = 0x4d4b4c46; // "MKLF"

// ---------------------------------------------------------------------------
// KeyTree: key_id -> KeyLeaf { pk_set_root, threshold, num_keys }
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyLeaf {
    pub pk_set_root: PoseidonHashOut, // root of this keyID's KeySetTree (its SPHINCS+ pubkey set)
    pub threshold: u32,               // M: minimum valid signatures for this keyID
    pub num_keys: u32,                // N: registered key count (threshold <= num_keys <= 2^H)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyLeafTarget {
    pub pk_set_root: PoseidonHashOutTarget,
    pub threshold: Target,
    pub num_keys: Target,
}

impl Default for KeyLeaf {
    fn default() -> Self {
        // Empty/unregistered keyID: zero pk_set_root marks "no key set yet".
        Self {
            pk_set_root: PoseidonHashOut::default(),
            threshold: 0,
            num_keys: 0,
        }
    }
}

impl KeyLeaf {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            vec![KEY_LEAF_DOMAIN],
            self.pk_set_root.to_u64_vec(),
            vec![self.threshold as u64, self.num_keys as u64],
        ]
        .concat()
    }
}

impl Leafable for KeyLeaf {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(self.to_u64_vec().as_slice())
    }
}

impl KeyLeafTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let pk_set_root = PoseidonHashOutTarget::new(builder);
        let threshold = builder.add_virtual_target();
        let num_keys = builder.add_virtual_target();
        if is_checked {
            // threshold and num_keys fit in KEY_SET_TREE_HEIGHT + 1 bits (max
            // 2^KEY_SET_TREE_HEIGHT).
            builder.range_check(threshold, KEY_SET_TREE_HEIGHT + 1);
            builder.range_check(num_keys, KEY_SET_TREE_HEIGHT + 1);
        }
        Self {
            pk_set_root,
            threshold,
            num_keys,
        }
    }

    /// Field targets WITHOUT the domain tag. The domain tag is prepended inside
    /// `LeafableTarget::hash` (which has a builder to allocate the constant), matching the native
    /// `KeyLeaf::to_u64_vec` preimage.
    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.pk_set_root.to_vec(),
            vec![self.threshold, self.num_keys],
        ]
        .concat()
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: KeyLeaf,
    ) -> Self {
        Self {
            pk_set_root: PoseidonHashOutTarget::constant(builder, value.pk_set_root),
            threshold: builder.constant(F::from_canonical_u64(value.threshold.into())),
            num_keys: builder.constant(F::from_canonical_u64(value.num_keys.into())),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &KeyLeaf) {
        self.pk_set_root.set_witness(witness, value.pk_set_root);
        witness.set_target(
            self.threshold,
            F::from_canonical_u64(value.threshold.into()),
        );
        witness.set_target(self.num_keys, F::from_canonical_u64(value.num_keys.into()));
    }
}

impl LeafableTarget for KeyLeafTarget {
    type Leaf = KeyLeaf;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        KeyLeafTarget::constant(builder, <KeyLeaf as Leafable>::empty_leaf())
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let domain = builder.constant(F::from_canonical_u64(KEY_LEAF_DOMAIN));
        let inputs = [
            vec![domain],
            self.pk_set_root.to_vec(),
            vec![self.threshold, self.num_keys],
        ]
        .concat();
        PoseidonHashOutTarget::hash_inputs(builder, &inputs)
    }
}

pub type KeyTree = SparseMerkleTree<KeyLeaf>;
pub type KeyMerkleProof = SparseMerkleProof<KeyLeaf>;
pub type KeyMerkleProofTarget = SparseMerkleProofTarget<KeyLeafTarget>;

impl KeyTree {
    pub fn init() -> Self {
        Self::new(KEY_TREE_HEIGHT)
    }
}

// ---------------------------------------------------------------------------
// MemberKeyTree: ordered, unique member key_ids for one channel.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct MemberKeyLeaf {
    pub key_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberKeyLeafTarget {
    pub key_id: Target,
}

impl MemberKeyLeaf {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        vec![MEMBER_KEY_LEAF_DOMAIN, self.key_id as u64]
    }
}

impl Leafable for MemberKeyLeaf {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(self.to_u64_vec().as_slice())
    }
}

impl MemberKeyLeafTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let key_id = builder.add_virtual_target();
        if is_checked {
            builder.range_check(key_id, KEY_ID_BITS);
        }
        Self { key_id }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        vec![self.key_id]
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: MemberKeyLeaf,
    ) -> Self {
        Self {
            key_id: builder.constant(F::from_canonical_u64(value.key_id.into())),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &MemberKeyLeaf,
    ) {
        witness.set_target(self.key_id, F::from_canonical_u64(value.key_id.into()));
    }
}

impl LeafableTarget for MemberKeyLeafTarget {
    type Leaf = MemberKeyLeaf;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        MemberKeyLeafTarget::constant(builder, <MemberKeyLeaf as Leafable>::empty_leaf())
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let domain = builder.constant(F::from_canonical_u64(MEMBER_KEY_LEAF_DOMAIN));
        let inputs = vec![domain, self.key_id];
        PoseidonHashOutTarget::hash_inputs(builder, &inputs)
    }
}

pub type MemberKeyTree = IncrementalMerkleTree<MemberKeyLeaf>;
pub type MemberKeyMerkleProof = IncrementalMerkleProof<MemberKeyLeaf>;
pub type MemberKeyMerkleProofTarget = IncrementalMerkleProofTarget<MemberKeyLeafTarget>;

impl MemberKeyTree {
    pub fn init() -> Self {
        Self::new(MEMBER_KEY_TREE_HEIGHT)
    }
}
