use crate::{
    common::{
        block::{Block, BlockError, BlockTarget},
        trees::account_tree::{
            AccountLeaf, AccountLeafTarget, AccountMerkleProof, AccountMerkleProofTarget, SendLeaf,
            SendLeafTarget, SendMerkleProof, SendMerkleProofTarget,
        },
        u63::{BlockNumber, BlockNumberTarget},
        user_id::{UserId, UserIdError, UserIdTarget},
    },
    constants::{ACCOUNT_TREE_HEIGHT, SEND_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::{
        leafable::Leafable as _,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

#[derive(thiserror::Error, Debug)]
pub enum UpdateAccountTreeError {
    #[error("Invalid length: {0}")]
    InvalidLength(String),

    #[error("Block error: {0}")]
    BlockError(#[from] BlockError),

    #[error("User ID error: {0}")]
    UserIdError(#[from] UserIdError),

    #[error("Merkle proof error: {0}")]
    MerkleProofError(String),
}

#[derive(Clone, Debug)]
pub struct UpdateAccountPublicInputs {
    pub block_number: BlockNumber,
    pub prev_block_hash_chain: Bytes32,
    pub prev_account_tree_root: PoseidonHashOut,
    pub new_block_hash_chain: Bytes32,
    pub new_account_tree_root: PoseidonHashOut,
}

#[derive(Clone, Debug)]
pub struct UpdateAccountTree {
    pub prev_block_hash_chain: Bytes32,
    pub prev_account_tree_root: PoseidonHashOut,

    // block number that is being processed
    pub block_number: BlockNumber,

    // contains num_users, which is circuit constant
    pub block: Block,

    // account/send merkle proofs corresponding to local_ids in the block
    pub prev_account_leaves: Vec<AccountLeaf>,
    pub account_merkle_proofs: Vec<AccountMerkleProof>,
    pub send_merkle_proofs: Vec<SendMerkleProof>,
}

impl UpdateAccountTree {
    pub fn to_public_inputs(&self) -> Result<UpdateAccountPublicInputs, UpdateAccountTreeError> {
        if self.prev_account_leaves.len() != self.block.num_users as usize
            || self.account_merkle_proofs.len() != self.block.num_users as usize
            || self.send_merkle_proofs.len() != self.block.num_users as usize
        {
            return Err(UpdateAccountTreeError::InvalidLength(format!(
                "prev_account_leaves length is {}, account_merkle_proofs length is {}, send_merkle_proofs length is {}, but block.num_users is {}",
                self.prev_account_leaves.len(),
                self.account_merkle_proofs.len(),
                self.send_merkle_proofs.len(),
                self.block.num_users,
            )));
        }
        // update hash chain
        let new_block_hash_chain = self.block.hash_with_prev_hash(self.prev_block_hash_chain)?;

        // update account tree
        let mut account_tree_root = self.prev_account_tree_root;
        let aggregator_id = self.block.aggregator_id;
        for (i, &local_id) in self.block.local_ids.iter().enumerate() {
            if local_id == 0 {
                // ignore zero local_id (padding or dummy)
                continue;
            }
            let user_id = UserId::new(aggregator_id, local_id)?;

            let prev_account_leaf = &self.prev_account_leaves[i];
            let account_merkle_proof = &self.account_merkle_proofs[i];
            let send_merkle_proof = &self.send_merkle_proofs[i];

            // verify the inclusion of prev_account_leaf in the account tree
            account_merkle_proof
                .verify(&prev_account_leaf, user_id.as_u64(), account_tree_root)
                .map_err(|e| {
                    UpdateAccountTreeError::MerkleProofError(format!(
                        "failed to verify account merkle proof for i {}: {}",
                        i, e
                    ))
                })?;

            if prev_account_leaf.prev == self.block_number {
                // already updated in this block
                continue;
            }

            // verify the inclusion of empty leaf in the send tree
            send_merkle_proof
                .verify(
                    &SendLeaf::empty_leaf(),
                    prev_account_leaf.index.into(),
                    prev_account_leaf.send_tree_root,
                )
                .map_err(|e| {
                    UpdateAccountTreeError::MerkleProofError(format!(
                        "failed to verify send merkle proof for i {}: {}",
                        i, e
                    ))
                })?;

            // create new send leaf and compute new send tree root
            let new_send_leaf = SendLeaf {
                prev: prev_account_leaf.prev,
                cur: self.block_number,
                tx_tree_root: self.block.tx_tree_root,
            };
            let new_send_tree_root =
                send_merkle_proof.get_root(&new_send_leaf, prev_account_leaf.index.into());

            // create new account leaf and compute new account tree root
            let new_account_leaf = AccountLeaf {
                index: prev_account_leaf.index + 1,
                prev: self.block_number,
                send_tree_root: new_send_tree_root,
            };
            account_tree_root = account_merkle_proof.get_root(&new_account_leaf, user_id.as_u64());
        }

        Ok(UpdateAccountPublicInputs {
            block_number: self.block_number,
            prev_block_hash_chain: self.prev_block_hash_chain,
            prev_account_tree_root: self.prev_account_tree_root,
            new_block_hash_chain,
            new_account_tree_root: account_tree_root,
        })
    }
}

impl UpdateAccountPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let mut result = vec![self.block_number.0];
        result.extend(self.prev_block_hash_chain.to_u64_vec());
        result.extend(self.prev_account_tree_root.to_u64_vec());
        result.extend(self.new_block_hash_chain.to_u64_vec());
        result.extend(self.new_account_tree_root.to_u64_vec());
        result
    }
}

#[derive(Clone, Debug)]
pub struct UpdateAccountPublicInputsTarget {
    pub block_number: BlockNumberTarget,
    pub prev_block_hash_chain: Bytes32Target,
    pub prev_account_tree_root: PoseidonHashOutTarget,
    pub new_block_hash_chain: Bytes32Target,
    pub new_account_tree_root: PoseidonHashOutTarget,
}

impl UpdateAccountPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.block_number.to_vec(),
            self.prev_block_hash_chain.to_vec(),
            self.prev_account_tree_root.to_vec(),
            self.new_block_hash_chain.to_vec(),
            self.new_account_tree_root.to_vec(),
        ]
        .concat()
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &UpdateAccountPublicInputs,
    ) {
        self.block_number.set_witness(witness, value.block_number);
        self.prev_block_hash_chain
            .set_witness(witness, value.prev_block_hash_chain);
        self.prev_account_tree_root
            .set_witness(witness, value.prev_account_tree_root);
        self.new_block_hash_chain
            .set_witness(witness, value.new_block_hash_chain);
        self.new_account_tree_root
            .set_witness(witness, value.new_account_tree_root);
    }
}

#[derive(Clone, Debug)]
pub struct UpdateAccountTreeTarget {
    pub block_number: BlockNumberTarget,
    pub prev_block_hash_chain: Bytes32Target,
    pub prev_account_tree_root: PoseidonHashOutTarget,
    pub block: BlockTarget,
    pub prev_account_leaves: Vec<AccountLeafTarget>,
    pub account_merkle_proofs: Vec<AccountMerkleProofTarget>,
    pub send_merkle_proofs: Vec<SendMerkleProofTarget>,
    pub public_inputs: UpdateAccountPublicInputsTarget,
}

impl UpdateAccountTreeTarget {
    pub fn new<F, C, const D: usize>(builder: &mut CircuitBuilder<F, D>, num_users: u32) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let block_number = BlockNumberTarget::new(builder, true);
        let prev_block_hash_chain = Bytes32Target::new(builder, true);
        let prev_account_tree_root = PoseidonHashOutTarget::new(builder);

        let block = BlockTarget::new(builder, num_users, true);

        let prev_account_leaves = (0..num_users)
            .map(|_| AccountLeafTarget::new(builder, true))
            .collect::<Vec<_>>();
        let account_merkle_proofs = (0..num_users)
            .map(|_| AccountMerkleProofTarget::new(builder, ACCOUNT_TREE_HEIGHT))
            .collect::<Vec<_>>();
        let send_merkle_proofs = (0..num_users)
            .map(|_| SendMerkleProofTarget::new(builder, SEND_TREE_HEIGHT))
            .collect::<Vec<_>>();

        let new_block_hash_chain =
            block.hash_with_prev_hash::<F, C, D>(builder, prev_block_hash_chain.clone());

        let empty_send_leaf = SendLeafTarget::constant(builder, SendLeaf::empty_leaf());
        let mut account_tree_root = prev_account_tree_root.clone();

        for i in 0..(num_users as usize) {
            let local_id = block.local_ids[i];
            let prev_account_leaf = &prev_account_leaves[i];
            let account_merkle_proof = &account_merkle_proofs[i];
            let send_merkle_proof = &send_merkle_proofs[i];
            let user_id =
                UserIdTarget::from_parts(builder, block.aggregator_id, local_id, true).value;

            let zero = builder.zero();
            let is_dummy = builder.is_equal(local_id, zero);
            let should_check_account = builder.not(is_dummy);

            let current_root = account_tree_root.clone();
            let prev_root =
                account_merkle_proof.get_root::<F, C, D>(builder, prev_account_leaf, user_id);
            current_root.conditional_assert_eq(builder, prev_root, should_check_account);

            let prev_matches_block = prev_account_leaf.prev.is_equal(builder, &block_number);
            let prev_differs = builder.not(prev_matches_block);
            let should_update = builder.and(should_check_account, prev_differs);

            send_merkle_proof.conditional_verify::<F, C, D>(
                builder,
                should_update,
                &empty_send_leaf,
                prev_account_leaf.index,
                prev_account_leaf.send_tree_root.clone(),
            );

            let new_send_leaf = SendLeafTarget {
                prev: prev_account_leaf.prev.clone(),
                cur: block_number.clone(),
                tx_tree_root: block.tx_tree_root.clone(),
            };
            let new_send_tree_root = send_merkle_proof.get_root::<F, C, D>(
                builder,
                &new_send_leaf,
                prev_account_leaf.index,
            );

            let next_index = builder.add_const(prev_account_leaf.index, F::ONE);
            let new_account_leaf = AccountLeafTarget {
                index: next_index,
                prev: block_number.clone(),
                send_tree_root: new_send_tree_root.clone(),
            };

            let updated_root =
                account_merkle_proof.get_root::<F, C, D>(builder, &new_account_leaf, user_id);

            account_tree_root =
                PoseidonHashOutTarget::select(builder, should_update, updated_root, current_root);
        }

        let public_inputs = UpdateAccountPublicInputsTarget {
            block_number: block_number.clone(),
            prev_block_hash_chain: prev_block_hash_chain.clone(),
            prev_account_tree_root: prev_account_tree_root.clone(),
            new_block_hash_chain,
            new_account_tree_root: account_tree_root.clone(),
        };

        Self {
            block_number,
            prev_block_hash_chain,
            prev_account_tree_root,
            block,
            prev_account_leaves,
            account_merkle_proofs,
            send_merkle_proofs,
            public_inputs,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &UpdateAccountTree,
    ) {
        self.block_number.set_witness(witness, value.block_number);
        self.prev_block_hash_chain
            .set_witness(witness, value.prev_block_hash_chain);
        self.prev_account_tree_root
            .set_witness(witness, value.prev_account_tree_root);
        self.block.set_witness(witness, &value.block);

        for (target, leaf) in self
            .prev_account_leaves
            .iter()
            .zip(value.prev_account_leaves.iter())
        {
            target.set_witness(witness, leaf);
        }
        for (target, proof) in self
            .account_merkle_proofs
            .iter()
            .zip(value.account_merkle_proofs.iter())
        {
            target.set_witness(witness, proof);
        }
        for (target, proof) in self
            .send_merkle_proofs
            .iter()
            .zip(value.send_merkle_proofs.iter())
        {
            target.set_witness(witness, proof);
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum UpdateAccountCircuitError {
    #[error("Update account tree error: {0}")]
    TreeError(#[from] UpdateAccountTreeError),
    #[error("Failed to prove: {0}")]
    FailedToProve(String),
}

pub struct UpdateAccountCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: UpdateAccountTreeTarget,
    pub public_inputs: UpdateAccountPublicInputsTarget,
}

impl<F, C, const D: usize> UpdateAccountCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(num_users: u32) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = UpdateAccountTreeTarget::new::<F, C, D>(&mut builder, num_users);
        let public_inputs = target.public_inputs.clone();
        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build();

        Self {
            data,
            target,
            public_inputs,
        }
    }

    pub fn prove(
        &self,
        witness: &UpdateAccountTree,
    ) -> Result<ProofWithPublicInputs<F, C, D>, UpdateAccountCircuitError> {
        let public_inputs = witness.to_public_inputs()?;
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, witness);
        self.public_inputs.set_witness(&mut pw, &public_inputs);
        self.data
            .prove(pw)
            .map_err(|e| UpdateAccountCircuitError::FailedToProve(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{
            block::Block,
            trees::account_tree::{AccountLeaf, AccountTree, SendLeaf, SendTree},
            u63::BlockNumber,
            user_id::UserId,
        },
        ethereum_types::bytes32::Bytes32,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{SeedableRng, rngs::StdRng};

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_update_account_tree_circuit() {
        let block_number = BlockNumber::new(20).unwrap();
        let aggregator_id = 5u32;
        let num_users = 2;

        let mut rng = StdRng::seed_from_u64(42);

        let prev_block_hash_chain = Bytes32::rand(&mut rng);
        let tx_tree_root = Bytes32::rand(&mut rng);
        let deposit_hash_chain = Bytes32::rand(&mut rng);

        let user1 = UserId::new(aggregator_id, 1).unwrap();
        let mut send_tree_user1 = SendTree::init();
        let send_leaf_user1_prev = SendLeaf {
            prev: BlockNumber::default(),
            cur: BlockNumber::new(10).unwrap(),
            tx_tree_root: Bytes32::rand(&mut rng),
        };
        send_tree_user1.push(send_leaf_user1_prev.clone());
        let prev_account_leaf_user1 = AccountLeaf {
            index: send_tree_user1.len() as u32,
            prev: send_leaf_user1_prev.cur,
            send_tree_root: send_tree_user1.get_root(),
        };

        let user2 = UserId::new(aggregator_id, 2).unwrap();
        let mut send_tree_user2 = SendTree::init();
        let send_leaf_user2_prev = SendLeaf {
            prev: BlockNumber::new(7).unwrap(),
            cur: block_number,
            tx_tree_root: Bytes32::rand(&mut rng),
        };
        send_tree_user2.push(send_leaf_user2_prev.clone());
        let prev_account_leaf_user2 = AccountLeaf {
            index: send_tree_user2.len() as u32,
            prev: block_number,
            send_tree_root: send_tree_user2.get_root(),
        };

        let mut account_tree = AccountTree::new(ACCOUNT_TREE_HEIGHT);
        account_tree.update(user1.as_u64(), prev_account_leaf_user1.clone());
        account_tree.update(user2.as_u64(), prev_account_leaf_user2.clone());

        let prev_account_tree_root = account_tree.get_root();
        assert_eq!(
            account_tree.get_leaf(user1.as_u64()),
            prev_account_leaf_user1
        );
        assert_eq!(
            account_tree.get_leaf(user2.as_u64()),
            prev_account_leaf_user2
        );

        let block = Block::new(
            num_users,
            aggregator_id,
            &[1, 2],
            tx_tree_root,
            deposit_hash_chain,
        )
        .unwrap();

        let send_proof_user1 = send_tree_user1.prove(prev_account_leaf_user1.index.into());
        let send_proof_user2 = send_tree_user2.prove(prev_account_leaf_user2.index.into());
        let dummy_account_leaf = AccountLeaf::default();
        let dummy_account_merkle_proof = AccountMerkleProof::dummy(ACCOUNT_TREE_HEIGHT);
        let dummy_send_proof = SendMerkleProof::dummy(SEND_TREE_HEIGHT);

        let mut prev_account_leaves = vec![
            prev_account_leaf_user1.clone(),
            prev_account_leaf_user2.clone(),
        ];
        prev_account_leaves.resize(num_users as usize, dummy_account_leaf);

        let mut send_merkle_proofs = vec![send_proof_user1.clone(), send_proof_user2.clone()];
        send_merkle_proofs.resize(num_users as usize, dummy_send_proof);

        let mut account_tree_for_proofs = account_tree.clone();
        let mut account_merkle_proofs = Vec::with_capacity(num_users as usize);
        for (i, &local_id) in block.local_ids.iter().enumerate() {
            if local_id == 0 {
                account_merkle_proofs.push(dummy_account_merkle_proof.clone());
                continue;
            }
            let user_id = UserId::new(aggregator_id, local_id).unwrap();
            let proof = account_tree_for_proofs.prove(user_id.as_u64());
            account_merkle_proofs.push(proof);

            let prev_leaf = &prev_account_leaves[i];
            if prev_leaf.prev != block_number {
                let send_proof = &send_merkle_proofs[i];
                let new_send_leaf = SendLeaf {
                    prev: prev_leaf.prev,
                    cur: block_number,
                    tx_tree_root,
                };
                let new_send_root = send_proof.get_root(&new_send_leaf, prev_leaf.index.into());
                let new_account_leaf = AccountLeaf {
                    index: prev_leaf.index + 1,
                    prev: block_number,
                    send_tree_root: new_send_root,
                };
                account_tree_for_proofs.update(user_id.as_u64(), new_account_leaf);
            }
        }

        let update_account_tree = UpdateAccountTree {
            prev_block_hash_chain,
            prev_account_tree_root,
            block_number,
            block: block.clone(),
            prev_account_leaves: prev_account_leaves.clone(),
            account_merkle_proofs: account_merkle_proofs.clone(),
            send_merkle_proofs: send_merkle_proofs.clone(),
        };

        let public_inputs = update_account_tree.to_public_inputs().unwrap();

        let mut expected_tree = account_tree.clone();
        let new_send_leaf_user1 = SendLeaf {
            prev: prev_account_leaf_user1.prev,
            cur: block_number,
            tx_tree_root,
        };
        let new_send_root_user1 =
            send_proof_user1.get_root(&new_send_leaf_user1, prev_account_leaf_user1.index.into());
        let new_account_leaf_user1 = AccountLeaf {
            index: prev_account_leaf_user1.index + 1,
            prev: block_number,
            send_tree_root: new_send_root_user1,
        };
        expected_tree.update(user1.as_u64(), new_account_leaf_user1);

        assert_eq!(public_inputs.prev_account_tree_root, prev_account_tree_root);
        assert_eq!(
            public_inputs.new_account_tree_root,
            expected_tree.get_root()
        );
        assert_eq!(
            public_inputs.new_block_hash_chain,
            block.hash_with_prev_hash(prev_block_hash_chain).unwrap()
        );

        let circuit = UpdateAccountCircuit::<F, C, D>::new(num_users);
        let proof = circuit.prove(&update_account_tree).unwrap();
        circuit.data.verify(proof.clone()).unwrap();

        let expected_public_inputs: Vec<F> = public_inputs
            .to_u64_vec()
            .into_iter()
            .map(F::from_canonical_u64)
            .collect();
        assert_eq!(proof.public_inputs, expected_public_inputs);
    }
}
