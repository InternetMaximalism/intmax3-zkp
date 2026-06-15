//! Per-channel member identity tree (one Goldilocks signing key per member; no multisig / threshold).
//!
//! `MemberTree` commits the ordered member set of a single channel. Each leaf binds a member's
//! Goldilocks public key `pk_g` (the Poseidon-preimage signature public key,
//! `poseidon_sig::GoldilocksSecretKey::public_key()`), the member's BabyBear hash-signature public
//! key `pk_b` (P3, channel-tx sender authorization — A11 two-key binding), to that member's Regev
//! public-key digest at the slot
//! (0..MAX_CHANNEL_MEMBERS). Active members occupy slots `0..member_count`; slots
//! `member_count..MAX_CHANNEL_MEMBERS` are empty leaves (pad-to-MAX D6). Its root is stored in
//! `ChannelLeaf.member_pubkeys_root` and is the trusted on-chain-bound root against which the
//! validity circuit proves slot inclusion of the signing pubkey (see
//! `circuits::validity::block_hash_chain::update_channel_tree`).
//!
//! SECURITY: the leaf is domain-separated (leading `MEMBER_LEAF_DOMAIN` tag) so a leaf of this
//! tree can never be reinterpreted as a leaf of another tree (cross-tree confusion). The tree is
//! populated only from on-chain registrations.

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::witness::WitnessWrite,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    constants::MEMBER_TREE_HEIGHT,
    utils::{
        leafable::{Leafable, LeafableTarget},
        leafable_hasher::PoseidonLeafableHasher,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::incremental_merkle_tree::{
            IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
        },
    },
};

/// Domain-separation tag (leading field of the leaf's Poseidon preimage). ASCII "MBLF".
const MEMBER_LEAF_DOMAIN: u64 = 0x4d424c46;

// ---------------------------------------------------------------------------
// MemberTree: slot -> MemberLeaf { pk_g, regev_pk_digest }
// ---------------------------------------------------------------------------

/// One channel member's identity leaf.
///
/// * `pk_g` — the member's Goldilocks public key `Poseidon([DOMAIN_PK_G] || sk_g)` (the member's
///   canonical signing identity, supplied at registration from `GoldilocksSecretKey::public_key()`).
/// * `pk_b` — the member's BabyBear hash-signature public key (the canonical reduction of the
///   `pk_b` digest exposed by the channel-tx sender hash-sig STARK; P3, threat-model D1(b)/A11).
///   Bound here so the off-chain channel-tx verifier can confirm that `pk_b`, `pk_g` and the Regev
///   key all belong to the SAME registered member (inseparable two-key binding).
/// * `regev_pk_digest` = the Poseidon reduction of the member's Regev public-key digest.
///
/// SECURITY (A11): all three components live in ONE leaf, so the channel's `member_pubkeys_root`
/// commits the `(pk_g, pk_b, regev_pk)` triple jointly. An adversary cannot pair member X's `pk_g`
/// with member Y's `pk_b` — that triple is not a registered leaf, so the membership check fails.
#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct MemberLeaf {
    pub pk_g: PoseidonHashOut,
    pub pk_b: PoseidonHashOut,
    pub regev_pk_digest: PoseidonHashOut,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberLeafTarget {
    pub pk_g: PoseidonHashOutTarget,
    pub pk_b: PoseidonHashOutTarget,
    pub regev_pk_digest: PoseidonHashOutTarget,
}

impl MemberLeaf {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            vec![MEMBER_LEAF_DOMAIN],
            self.pk_g.to_u64_vec(),
            self.pk_b.to_u64_vec(),
            self.regev_pk_digest.to_u64_vec(),
        ]
        .concat()
    }
}

impl Leafable for MemberLeaf {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(self.to_u64_vec().as_slice())
    }
}

impl MemberLeafTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            pk_g: PoseidonHashOutTarget::new(builder),
            pk_b: PoseidonHashOutTarget::new(builder),
            regev_pk_digest: PoseidonHashOutTarget::new(builder),
        }
    }

    /// Field targets WITHOUT the domain tag (prepended inside `LeafableTarget::hash`).
    pub fn to_vec(&self) -> Vec<plonky2::iop::target::Target> {
        [
            self.pk_g.to_vec(),
            self.pk_b.to_vec(),
            self.regev_pk_digest.to_vec(),
        ]
        .concat()
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: MemberLeaf,
    ) -> Self {
        Self {
            pk_g: PoseidonHashOutTarget::constant(builder, value.pk_g),
            pk_b: PoseidonHashOutTarget::constant(builder, value.pk_b),
            regev_pk_digest: PoseidonHashOutTarget::constant(builder, value.regev_pk_digest),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &MemberLeaf) {
        self.pk_g
            .set_witness(witness, value.pk_g);
        self.pk_b
            .set_witness(witness, value.pk_b);
        self.regev_pk_digest
            .set_witness(witness, value.regev_pk_digest);
    }
}

impl LeafableTarget for MemberLeafTarget {
    type Leaf = MemberLeaf;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        MemberLeafTarget::constant(builder, <MemberLeaf as Leafable>::empty_leaf())
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // Prepend the domain tag in-circuit to match `MemberLeaf::to_u64_vec` (cross-tree safety).
        let domain = builder.constant(F::from_canonical_u64(MEMBER_LEAF_DOMAIN));
        let inputs = [vec![domain], self.to_vec()].concat();
        PoseidonHashOutTarget::hash_inputs(builder, &inputs)
    }
}

pub type MemberTree = IncrementalMerkleTree<MemberLeaf>;
pub type MemberMerkleProof = IncrementalMerkleProof<MemberLeaf>;
pub type MemberMerkleProofTarget = IncrementalMerkleProofTarget<MemberLeafTarget>;

impl MemberTree {
    pub fn init() -> Self {
        Self::new(MEMBER_TREE_HEIGHT)
    }
}
