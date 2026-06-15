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
    common::u63::{BlockNumber, BlockNumberTarget},
    constants::{CHANNEL_TREE_HEIGHT, SEND_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
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

/// SendTree is a Merkle tree where contains SendLeaf as leaves.
/// SendLeaf is added when user sends a transaction.
pub type SendTree = IncrementalMerkleTree<SendLeaf>;
pub type SendMerkleProof = IncrementalMerkleProof<SendLeaf>;
pub type SendMerkleProofTarget = IncrementalMerkleProofTarget<SendLeafTarget>;

impl SendTree {
    pub fn init() -> Self {
        Self::new(SEND_TREE_HEIGHT)
    }
}

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct SendLeaf {
    pub prev: BlockNumber,
    pub cur: BlockNumber,
    pub tx_tree_root: Bytes32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendLeafTarget {
    pub prev: BlockNumberTarget,
    pub cur: BlockNumberTarget,
    pub tx_tree_root: Bytes32Target,
}

impl Leafable for SendLeaf {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(self.to_u64_vec().as_slice())
    }
}

impl LeafableTarget for SendLeafTarget {
    type Leaf = SendLeaf;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = <SendLeaf as Leafable>::empty_leaf();
        SendLeafTarget::constant(builder, empty_leaf)
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }
}

/// Domain-separation tag for ChannelLeaf Poseidon preimage (see key_tree.rs for the others).
const CHANNEL_LEAF_DOMAIN: u64 = 0x43484c46; // "CHLF"

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChannelLeaf {
    pub index: u32,                      // the next index of send leaf
    pub prev: BlockNumber,               // the previous block number
    pub send_tree_root: PoseidonHashOut, // the root of send tree
    // Root of this channel's MemberTree: the ordered member leaves
    // `MemberLeaf { pk_g, regev_pk_digest }`, slot 0..MAX_CHANNEL_MEMBERS (active
    // members first, padding slots empty; pad-to-MAX D6). One SPHINCS+ key
    // per member (no multisig / threshold). This root is the trusted anchor the validity circuit
    // proves slot inclusion against to bind a signing pubkey to the channel's members.
    pub member_pubkeys_root: PoseidonHashOut,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelLeafTarget {
    pub index: Target,                              // the next index of send leaf
    pub prev: BlockNumberTarget,                    // the previous block number
    pub send_tree_root: PoseidonHashOutTarget,      // the root of send tree
    pub member_pubkeys_root: PoseidonHashOutTarget, // root of this channel's MemberTree
}

impl Leafable for ChannelLeaf {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(self.to_u64_vec().as_slice())
    }
}

impl LeafableTarget for ChannelLeafTarget {
    type Leaf = ChannelLeaf;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = <ChannelLeaf as Leafable>::empty_leaf();
        ChannelLeafTarget::constant(builder, empty_leaf)
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // Prepend the domain tag in-circuit to match ChannelLeaf::to_u64_vec (cross-tree safety).
        let domain = builder.constant(F::from_canonical_u64(CHANNEL_LEAF_DOMAIN));
        let inputs = [vec![domain], self.to_vec()].concat();
        PoseidonHashOutTarget::hash_inputs(builder, &inputs)
    }
}

/// ChannelTree is a Merkle tree where each leaf is an ChannelLeaf.
/// The position of each leaf is determined by the global user id (concatenation of proof_submitter
/// id and user id).
pub type ChannelTree = SparseMerkleTree<ChannelLeaf>;
pub type ChannelMerkleProof = SparseMerkleProof<ChannelLeaf>;
pub type ChannelMerkleProofTarget = SparseMerkleProofTarget<ChannelLeafTarget>;

impl ChannelTree {
    pub fn init() -> Self {
        Self::new(CHANNEL_TREE_HEIGHT)
    }
}

impl SendLeaf {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.prev.to_u64_vec(),
            self.cur.to_u64_vec(),
            self.tx_tree_root.to_u64_vec(),
        ]
        .concat()
    }
}

impl SendLeafTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let prev = BlockNumberTarget::new(builder, is_checked);
        let cur = BlockNumberTarget::new(builder, is_checked);
        let tx_tree_root = Bytes32Target::new(builder, is_checked);
        Self {
            prev,
            cur,
            tx_tree_root,
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.prev.to_vec(),
            self.cur.to_vec(),
            self.tx_tree_root.to_vec(),
        ]
        .concat()
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: SendLeaf,
    ) -> Self {
        Self {
            prev: BlockNumberTarget::constant(builder, value.prev),
            cur: BlockNumberTarget::constant(builder, value.cur),
            tx_tree_root: Bytes32Target::constant(builder, value.tx_tree_root),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &SendLeaf) {
        self.prev.set_witness(witness, value.prev);
        self.cur.set_witness(witness, value.cur);
        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
    }
}

impl Default for ChannelLeaf {
    fn default() -> Self {
        Self {
            index: 0,
            prev: BlockNumber::default(),
            send_tree_root: SendTree::init().get_root(),
            // Unregistered channel: empty MemberTree root (no members yet).
            member_pubkeys_root: crate::common::trees::key_tree::MemberTree::init().get_root(),
        }
    }
}

impl ChannelLeaf {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            vec![CHANNEL_LEAF_DOMAIN, self.index as u64],
            self.prev.to_u64_vec(),
            self.send_tree_root.to_u64_vec(),
            self.member_pubkeys_root.to_u64_vec(),
        ]
        .concat()
    }
}

impl ChannelLeafTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let index = builder.add_virtual_target();
        if is_checked {
            builder.range_check(index, SEND_TREE_HEIGHT);
        }
        let prev = BlockNumberTarget::new(builder, is_checked);
        let send_tree_root = PoseidonHashOutTarget::new(builder);
        let member_pubkeys_root = PoseidonHashOutTarget::new(builder);
        Self {
            index,
            prev,
            send_tree_root,
            member_pubkeys_root,
        }
    }

    /// Field targets WITHOUT the domain tag (prepended inside `LeafableTarget::hash`).
    pub fn to_vec(&self) -> Vec<Target> {
        [
            vec![self.index],
            self.prev.to_vec(),
            self.send_tree_root.to_vec(),
            self.member_pubkeys_root.to_vec(),
        ]
        .concat()
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: ChannelLeaf,
    ) -> Self {
        Self {
            index: builder.constant(F::from_canonical_u64(value.index.into())),
            prev: BlockNumberTarget::constant(builder, value.prev),
            send_tree_root: PoseidonHashOutTarget::constant(builder, value.send_tree_root),
            member_pubkeys_root: PoseidonHashOutTarget::constant(
                builder,
                value.member_pubkeys_root,
            ),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &ChannelLeaf) {
        witness.set_target(self.index, F::from_canonical_u64(value.index.into()));
        self.prev.set_witness(witness, value.prev);
        self.send_tree_root
            .set_witness(witness, value.send_tree_root);
        self.member_pubkeys_root
            .set_witness(witness, value.member_pubkeys_root);
    }
}
