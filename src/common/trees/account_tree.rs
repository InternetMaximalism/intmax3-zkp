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
    common::block_number::{BlockNumber, BlockNumberTarget},
    constants::SEND_TREE_HEIGHT,
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountLeaf {
    pub index: u32,                      // the next index of send leaf
    pub prev: BlockNumber,               // the previous block number
    pub send_tree_root: PoseidonHashOut, // the root of send tree
}

#[derive(Clone, Debug)]
pub struct AccountLeafTarget {
    pub index: Target,                         // the next index of send leaf
    pub prev: BlockNumberTarget,               // the previous block number
    pub send_tree_root: PoseidonHashOutTarget, // the root of send tree
}

impl Leafable for AccountLeaf {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(self.to_u64_vec().as_slice())
    }
}

impl LeafableTarget for AccountLeafTarget {
    type Leaf = AccountLeaf;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = <AccountLeaf as Leafable>::empty_leaf();
        AccountLeafTarget::constant(builder, empty_leaf)
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

/// AccountTree is a Merkle tree where each leaf is an AccountLeaf.
/// The position of each leaf is determined by the global user id (concatenation of aggregator id
/// and account id).
pub type AccountTree = SparseMerkleTree<AccountLeaf>;
pub type AccountMerkleProof = SparseMerkleProof<AccountLeaf>;
pub type AccountMerkleProofTarget = SparseMerkleProofTarget<AccountLeafTarget>;

impl AccountTree {
    pub fn init() -> Self {
        Self::new(SEND_TREE_HEIGHT)
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

impl Default for AccountLeaf {
    fn default() -> Self {
        Self {
            index: 0,
            prev: BlockNumber(0),
            send_tree_root: SendTree::init().get_root(),
        }
    }
}

impl AccountLeaf {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            vec![self.index as u64],
            self.prev.to_u64_vec(),
            self.send_tree_root.to_u64_vec(),
        ]
        .concat()
    }
}

impl AccountLeafTarget {
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
        Self {
            index,
            prev,
            send_tree_root,
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            vec![self.index],
            self.prev.to_vec(),
            self.send_tree_root.to_vec(),
        ]
        .concat()
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: AccountLeaf,
    ) -> Self {
        Self {
            index: builder.constant(F::from_canonical_u64(value.index.into())),
            prev: BlockNumberTarget::constant(builder, value.prev),
            send_tree_root: PoseidonHashOutTarget::constant(builder, value.send_tree_root),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &AccountLeaf) {
        witness.set_target(self.index, F::from_canonical_u64(value.index.into()));
        self.prev.set_witness(witness, value.prev);
        self.send_tree_root
            .set_witness(witness, value.send_tree_root);
    }
}
