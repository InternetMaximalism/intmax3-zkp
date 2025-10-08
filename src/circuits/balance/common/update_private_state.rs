use crate::{
    common::{
        private_state::{PrivateState, PrivateStateTarget},
        trees::{
            asset_tree::{AssetMerkleProof, AssetMerkleProofTarget},
            nullifier_tree::{NullifierInsertionProof, NullifierInsertionProofTarget},
        },
    },
    constants::{ASSET_TREE_HEIGHT, TOKEN_INDEX_BITS},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait as _,
        u256::{U256, U256Target},
    },
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

#[derive(Debug, thiserror::Error, Clone)]
pub enum UpdatePrivateStateError {
    #[error("Merkle proof error: {0}")]
    MerkleProofError(String),
}

#[derive(Debug, Clone)]
pub struct UpdatePrivateState {
    pub token_index: u32,                 // token index of incoming transfer/deposit
    pub amount: U256,                     // token amount of incoming transfer/deposit
    pub nullifier: Bytes32,               // nullifier of corresponding transfer/deposit
    pub prev_private_state: PrivateState, // previous private state
    pub nullifier_proof: NullifierInsertionProof, // merkle proof to update nullifier tree
    pub prev_balance: U256,
    pub asset_merkle_proof: AssetMerkleProof, // merkle proof to update asset tree
    pub new_private_state: PrivateState,      // new private state
}

impl UpdatePrivateState {
    pub fn new(
        token_index: u32,
        amount: U256,
        nullifier: Bytes32,
        prev_private_state: &PrivateState,
        nullifier_proof: &NullifierInsertionProof,
        prev_balance: U256,
        asset_merkle_proof: &AssetMerkleProof,
    ) -> Result<Self, UpdatePrivateStateError> {
        let prev_private_commitment = prev_private_state.commitment();
        let new_nullifier_tree_root = nullifier_proof
            .get_new_root(prev_private_state.nullifier_tree_root, nullifier)
            .map_err(|e| {
                UpdatePrivateStateError::MerkleProofError(format!(
                    "Invalid nullifier merkle proof: {}",
                    e
                ))
            })?;
        asset_merkle_proof
            .verify(
                &prev_balance,
                token_index as u64,
                prev_private_state.asset_tree_root,
            )
            .map_err(|e| {
                UpdatePrivateStateError::MerkleProofError(format!(
                    "Invalid asset merkle proof: {}",
                    e
                ))
            })?;
        let new_asset_leaf = prev_balance + amount;
        let new_asset_tree_root = asset_merkle_proof.get_root(&new_asset_leaf, token_index as u64);
        let new_private_state = PrivateState {
            asset_tree_root: new_asset_tree_root,
            nullifier_tree_root: new_nullifier_tree_root,
            prev_private_commitment,
            ..prev_private_state.clone()
        };

        Ok(Self {
            token_index,
            amount,
            nullifier,
            prev_private_state: prev_private_state.clone(),
            nullifier_proof: nullifier_proof.clone(),
            prev_balance,
            asset_merkle_proof: asset_merkle_proof.clone(),
            new_private_state,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UpdatePrivateStateTarget {
    pub token_index: Target,
    pub amount: U256Target,
    pub nullifier: Bytes32Target,
    pub prev_private_state: PrivateStateTarget,
    pub nullifier_proof: NullifierInsertionProofTarget,
    pub prev_balance: U256Target,
    pub asset_merkle_proof: AssetMerkleProofTarget,
    pub new_private_state: PrivateStateTarget,
}

impl UpdatePrivateStateTarget {
    /// Creates a new PrivateStateTransitionTarget with circuit constraints that enforce
    /// the private state transition rules.
    ///
    /// The circuit enforces:
    /// 1. Valid nullifier insertion into the nullifier tree
    /// 2. Valid asset merkle proof for the token being updated
    /// 3. Correct computation of the new asset leaf by adding the amount
    /// 4. Proper construction of the new private state with updated roots
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let token_index = builder.add_virtual_target();
        if is_checked {
            builder.range_check(token_index, TOKEN_INDEX_BITS);
        }
        let amount = U256Target::new(builder, is_checked);
        let nullifier = Bytes32Target::new(builder, is_checked);
        let prev_private_state = PrivateStateTarget::new(builder);
        let nullifier_proof = NullifierInsertionProofTarget::new(builder, is_checked);
        let prev_balance = U256Target::new(builder, is_checked);
        let asset_merkle_proof = AssetMerkleProofTarget::new(builder, ASSET_TREE_HEIGHT);
        let new_private_state = PrivateStateTarget::new(builder);

        let prev_private_commitment = prev_private_state.commitment(builder);
        let new_nullifier_tree_root = nullifier_proof.get_new_root::<F, C, D>(
            builder,
            prev_private_state.nullifier_tree_root.clone(),
            nullifier,
        );

        asset_merkle_proof.verify::<F, C, D>(
            builder,
            &prev_balance,
            token_index,
            prev_private_state.asset_tree_root.clone(),
        );

        let new_asset_leaf = prev_balance.add(builder, &amount);
        let new_asset_tree_root =
            asset_merkle_proof.get_root::<F, C, D>(builder, &new_asset_leaf, token_index);

        new_private_state
            .asset_tree_root
            .connect(builder, new_asset_tree_root);
        new_private_state
            .nullifier_tree_root
            .connect(builder, new_nullifier_tree_root);
        new_private_state
            .prev_private_commitment
            .connect(builder, prev_private_commitment);
        builder.connect(new_private_state.nonce, prev_private_state.nonce);
        new_private_state
            .salt
            .connect(builder, prev_private_state.salt);

        Self {
            token_index,
            amount,
            nullifier,
            prev_private_state,
            nullifier_proof,
            prev_balance,
            asset_merkle_proof,
            new_private_state,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &UpdatePrivateState,
    ) {
        witness.set_target(self.token_index, F::from_canonical_u32(value.token_index));
        self.amount.set_witness(witness, value.amount);
        self.nullifier.set_witness(witness, value.nullifier);
        self.prev_private_state
            .set_witness(witness, &value.prev_private_state);
        self.nullifier_proof
            .set_witness(witness, &value.nullifier_proof);
        self.prev_balance.set_witness(witness, value.prev_balance);
        self.asset_merkle_proof
            .set_witness(witness, &value.asset_merkle_proof);
        self.new_private_state
            .set_witness(witness, &value.new_private_state);
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use rand::Rng;

    use crate::{
        common::{
            private_state::PrivateState,
            salt::Salt,
            transfer::Transfer,
            trees::{asset_tree::AssetTree, nullifier_tree::NullifierTree},
        },
        constants::ASSET_TREE_HEIGHT,
        ethereum_types::bytes32::Bytes32,
        utils::poseidon_hash_out::PoseidonHashOut,
    };

    use super::{UpdatePrivateState, UpdatePrivateStateTarget};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_update_private_state_circuit() {
        let mut rng = rand::thread_rng();
        let transfer = Transfer::rand(&mut rng);
        let mut asset_tree = AssetTree::new(ASSET_TREE_HEIGHT);
        let mut nullifier_tree = NullifierTree::init();
        let prev_private_state = PrivateState {
            asset_tree_root: asset_tree.get_root(),
            nullifier_tree_root: nullifier_tree.get_root(),
            prev_private_commitment: PoseidonHashOut::default(),
            nonce: rng.r#gen(),
            salt: Salt::rand(&mut rng),
        };
        let prev_private_commitment = prev_private_state.commitment();

        let prev_asset_leaf = asset_tree.get_leaf(transfer.token_index as u64);
        let asset_merkle_proof = asset_tree.prove(transfer.token_index as u64);
        let new_asset_leaf = prev_asset_leaf + transfer.amount;
        asset_tree.update(transfer.token_index as u64, new_asset_leaf);

        let nullifier: Bytes32 = transfer.poseidon_hash().into();
        let nullifier_proof = nullifier_tree.prove_and_insert(nullifier).unwrap();

        let value = UpdatePrivateState::new(
            transfer.token_index,
            transfer.amount,
            nullifier,
            &prev_private_state,
            &nullifier_proof,
            prev_asset_leaf,
            &asset_merkle_proof,
        )
        .unwrap();

        let expected_new_private_state = PrivateState {
            asset_tree_root: asset_tree.get_root(),
            nullifier_tree_root: nullifier_tree.get_root(),
            prev_private_commitment,
            ..prev_private_state.clone()
        };
        assert_eq!(value.new_private_state, expected_new_private_state);

        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        let target = UpdatePrivateStateTarget::new::<F, C, D>(&mut builder, true);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::<F>::new();
        target.set_witness(&mut pw, &value);
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
}
