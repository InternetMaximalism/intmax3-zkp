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
    constants::KEY_SET_TREE_HEIGHT,
    utils::{
        leafable::{Leafable, LeafableTarget},
        leafable_hasher::PoseidonLeafableHasher,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::sparse_merkle_tree::{SparseMerkleProof, SparseMerkleProofTarget, SparseMerkleTree},
    },
};

/// A leaf in the key set tree, wrapping a single public key hash.
///
/// `pk_hash = Poseidon(pub_seed || pub_root)` for a SPHINCS+ key.
#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct PkLeaf {
    pub pk_hash: PoseidonHashOut,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PkLeafTarget {
    pub pk_hash: PoseidonHashOutTarget,
}

impl Leafable for PkLeaf {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.pk_hash.to_u64_vec())
    }
}

impl LeafableTarget for PkLeafTarget {
    type Leaf = PkLeaf;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = <PkLeaf as Leafable>::empty_leaf();
        PkLeafTarget::constant(builder, empty_leaf)
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

impl PkLeaf {
    pub fn new(pk_hash: PoseidonHashOut) -> Self {
        Self { pk_hash }
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        self.pk_hash.to_u64_vec()
    }
}

impl PkLeafTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            pk_hash: PoseidonHashOutTarget::new(builder),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        self.pk_hash.to_vec()
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: PkLeaf,
    ) -> Self {
        Self {
            pk_hash: PoseidonHashOutTarget::constant(builder, value.pk_hash),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &PkLeaf) {
        self.pk_hash.set_witness(witness, value.pk_hash);
    }
}

/// Key set tree: a sparse Merkle tree of public key hashes.
/// Height = KEY_SET_TREE_HEIGHT (max 2^KEY_SET_TREE_HEIGHT keys per ID).
pub type KeySetTree = SparseMerkleTree<PkLeaf>;
pub type KeySetMerkleProof = SparseMerkleProof<PkLeaf>;
pub type KeySetMerkleProofTarget = SparseMerkleProofTarget<PkLeafTarget>;

impl KeySetTree {
    pub fn init() -> Self {
        Self::new(KEY_SET_TREE_HEIGHT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_key_set_tree_basic() {
        let mut tree = KeySetTree::init();
        assert_eq!(tree.height(), KEY_SET_TREE_HEIGHT);

        let pk1 = PkLeaf::new(PoseidonHashOut::hash_inputs_u64(&[1, 2, 3, 4]));
        let pk2 = PkLeaf::new(PoseidonHashOut::hash_inputs_u64(&[5, 6, 7, 8]));

        tree.update(0, pk1.clone());
        tree.update(1, pk2.clone());

        let proof0 = tree.prove(0);
        let proof1 = tree.prove(1);

        proof0.verify(&pk1, 0, tree.get_root()).unwrap();
        proof1.verify(&pk2, 1, tree.get_root()).unwrap();
    }

    #[test]
    fn test_key_set_tree_circuit() {
        let mut tree = KeySetTree::init();
        let pk = PkLeaf::new(PoseidonHashOut::hash_inputs_u64(&[10, 20, 30, 40]));
        tree.update(0, pk.clone());

        let proof = tree.prove(0);
        let root = tree.get_root();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = KeySetMerkleProofTarget::new(&mut builder, KEY_SET_TREE_HEIGHT);
        let leaf_t = PkLeafTarget::new(&mut builder);
        let root_t = PoseidonHashOutTarget::new(&mut builder);
        let index_t = builder.add_virtual_target();

        proof_t.verify::<F, C, D>(&mut builder, &leaf_t, index_t, root_t);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::<F>::new();
        leaf_t.set_witness(&mut pw, &pk);
        root_t.set_witness(&mut pw, root);
        pw.set_target(index_t, F::from_canonical_u64(0));
        proof_t.set_witness(&mut pw, &proof);

        data.prove(pw).unwrap();
    }

    #[test]
    fn test_single_key_compat() {
        // Single-sig: only one key at index 0, threshold = 1
        let mut tree = KeySetTree::init();
        let pk = PkLeaf::new(PoseidonHashOut::hash_inputs_u64(&[1, 2, 3, 4]));
        tree.update(0, pk.clone());

        let root = tree.get_root();
        let proof = tree.prove(0);
        proof.verify(&pk, 0, root).unwrap();

        // Empty slots are default
        let empty = tree.get_leaf(1);
        assert_eq!(empty, PkLeaf::default());
    }
}
