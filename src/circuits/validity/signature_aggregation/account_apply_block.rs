use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::validity::signature_aggregation::account_apply_block_pis::{
        AccountApplyBlockPublicInputs, AccountApplyBlockPublicInputsError,
        AccountApplyBlockPublicInputsTarget,
    },
    common::{
        trees::account_tree::{
            AccountLeaf, AccountLeafTarget, AccountMerkleProof, AccountMerkleProofTarget,
            SendLeaf, SendLeafTarget, SendMerkleProof, SendMerkleProofTarget,
        },
        u63::{BlockNumber, BlockNumberTarget},
        user_id::{UserId, UserIdTarget},
    },
    constants::{ACCOUNT_TREE_HEIGHT, SEND_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait as _,
    },
    utils::{
        leafable::Leafable as _,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};

/// Maximum number of users processed per flat block proof.
pub const ACCOUNT_APPLY_BLOCK_SIZE: usize = 20;

#[derive(Debug, thiserror::Error)]
pub enum AccountApplyBlockError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Failed to prove: {0}")]
    FailedToProve(String),
    #[error("Public inputs error: {0}")]
    PublicInputsError(#[from] AccountApplyBlockPublicInputsError),
}

/// Per-user witness data for account tree update.
pub struct AccountApplyUserWitness {
    pub is_active: bool,
    pub user_local_id: u32,
    pub prev_account_leaf: AccountLeaf,
    pub account_merkle_proof: AccountMerkleProof,
    pub send_merkle_proof: SendMerkleProof,
}

/// Witness for the entire block.
pub struct AccountApplyBlockWitness {
    pub initial_account_tree_root: PoseidonHashOut,
    pub block_number: BlockNumber,
    pub aggregator_id: u32,
    pub tx_tree_root: Bytes32,
    /// Exactly ACCOUNT_APPLY_BLOCK_SIZE entries. Inactive entries are padded with dummies.
    pub users: Vec<AccountApplyUserWitness>,
}

impl AccountApplyBlockWitness {
    pub fn to_public_inputs(
        &self,
    ) -> Result<AccountApplyBlockPublicInputs, AccountApplyBlockError> {
        if self.users.len() != ACCOUNT_APPLY_BLOCK_SIZE {
            return Err(AccountApplyBlockError::InvalidInput(format!(
                "Expected {} users, got {}",
                ACCOUNT_APPLY_BLOCK_SIZE,
                self.users.len()
            )));
        }

        let mut current_root = self.initial_account_tree_root;
        let mut current_hash = PoseidonHashOut::default();
        let mut user_count: u32 = 0;
        let mut first_user_id: u64 = 0;
        let mut last_user_id: u64 = 0;

        for user in &self.users {
            if !user.is_active {
                continue;
            }

            let user_id = UserId::new(self.aggregator_id, user.user_local_id)
                .map_err(|e| AccountApplyBlockError::InvalidInput(e.to_string()))?;

            // Verify old leaf membership
            let old_root = user
                .account_merkle_proof
                .get_root(&user.prev_account_leaf, user_id.as_u64());
            if old_root != current_root {
                return Err(AccountApplyBlockError::InvalidInput(format!(
                    "Account merkle proof mismatch for user {}",
                    user_id.as_u64()
                )));
            }

            // Verify empty send leaf at index
            let empty_send_root = user.send_merkle_proof.get_root(
                &SendLeaf::empty_leaf(),
                user.prev_account_leaf.index as u64,
            );
            if empty_send_root != user.prev_account_leaf.send_tree_root {
                return Err(AccountApplyBlockError::InvalidInput(format!(
                    "Send merkle proof mismatch for user {}",
                    user_id.as_u64()
                )));
            }

            // Create new send leaf
            let new_send_leaf = SendLeaf {
                prev: user.prev_account_leaf.prev,
                cur: self.block_number,
                tx_tree_root: self.tx_tree_root,
            };

            // Compute new send tree root
            let new_send_tree_root = user.send_merkle_proof.get_root(
                &new_send_leaf,
                user.prev_account_leaf.index as u64,
            );

            // Create new account leaf
            let new_account_leaf = AccountLeaf {
                index: user.prev_account_leaf.index + 1,
                prev: self.block_number,
                send_tree_root: new_send_tree_root,
                pk_set_root: user.prev_account_leaf.pk_set_root,
                threshold: user.prev_account_leaf.threshold,
            };

            // Update current root
            current_root = user
                .account_merkle_proof
                .get_root(&new_account_leaf, user_id.as_u64());

            // Chain hash: H(prev_hash || user_id)
            current_hash = PoseidonHashOut::hash_inputs_u64(
                &[current_hash.to_u64_vec(), vec![user_id.as_u64()]].concat(),
            );

            // Track first/last user_id and count
            user_count += 1;
            if user_count == 1 {
                first_user_id = user_id.as_u64();
            }
            last_user_id = user_id.as_u64();
        }

        Ok(AccountApplyBlockPublicInputs {
            initial_account_tree_root: self.initial_account_tree_root,
            final_account_tree_root: current_root,
            block_number: self.block_number,
            aggregator_id: self.aggregator_id,
            tx_tree_root: self.tx_tree_root,
            users_hash: current_hash,
            user_count,
            first_user_id,
            last_user_id,
        })
    }
}

struct AccountApplyBlockUserTarget {
    is_active: BoolTarget,
    user_local_id: Target,
    prev_account_leaf: AccountLeafTarget,
    account_merkle_proof: AccountMerkleProofTarget,
    send_merkle_proof: SendMerkleProofTarget,
}

pub struct AccountApplyBlockTarget {
    initial_account_tree_root: PoseidonHashOutTarget,
    block_number: BlockNumberTarget,
    aggregator_id: Target,
    tx_tree_root: Bytes32Target,
    users: Vec<AccountApplyBlockUserTarget>,
    pub new_pis: AccountApplyBlockPublicInputsTarget,
}

impl AccountApplyBlockTarget {
    pub fn new<F, C, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let initial_account_tree_root = PoseidonHashOutTarget::new(builder);
        let block_number = BlockNumberTarget::new(builder, true);
        let aggregator_id = builder.add_virtual_target();
        let tx_tree_root = Bytes32Target::new::<F, D>(builder, true);
        let zero = builder.zero();
        let zero_hash = PoseidonHashOutTarget::constant(builder, PoseidonHashOut::default());
        let empty_send_leaf = SendLeafTarget::constant(builder, SendLeaf::empty_leaf());

        let mut current_root = initial_account_tree_root.clone();
        let mut current_hash = zero_hash.clone();
        let mut current_count = zero;
        let mut current_first_user_id = zero;
        let mut current_last_user_id = zero;
        let mut users = Vec::new();

        for _ in 0..ACCOUNT_APPLY_BLOCK_SIZE {
            let is_active = builder.add_virtual_bool_target_safe();
            let user_local_id = builder.add_virtual_target();
            let prev_account_leaf = AccountLeafTarget::new::<F, D>(builder, true);
            let account_merkle_proof =
                AccountMerkleProofTarget::new::<F, D>(builder, ACCOUNT_TREE_HEIGHT);
            let send_merkle_proof =
                SendMerkleProofTarget::new::<F, D>(builder, SEND_TREE_HEIGHT);

            // Compute user_id
            let user_id =
                UserIdTarget::from_parts(builder, aggregator_id, user_local_id, true).value;

            // Verify old leaf membership against current_root
            let old_root = account_merkle_proof.get_root::<F, C, D>(
                builder,
                &prev_account_leaf,
                user_id,
            );
            current_root.conditional_assert_eq(builder, old_root, is_active);

            // Verify empty send leaf at index in prev send tree
            send_merkle_proof.conditional_verify::<F, C, D>(
                builder,
                is_active,
                &empty_send_leaf,
                prev_account_leaf.index,
                prev_account_leaf.send_tree_root.clone(),
            );

            // Create new send leaf
            let new_send_leaf = SendLeafTarget {
                prev: prev_account_leaf.prev.clone(),
                cur: block_number.clone(),
                tx_tree_root: tx_tree_root.clone(),
            };
            let new_send_root = send_merkle_proof.get_root::<F, C, D>(
                builder,
                &new_send_leaf,
                prev_account_leaf.index,
            );

            // Create new account leaf
            let one = builder.one();
            let next_index = builder.add(prev_account_leaf.index, one);
            let new_account_leaf = AccountLeafTarget {
                index: next_index,
                prev: block_number.clone(),
                send_tree_root: new_send_root,
                pk_set_root: prev_account_leaf.pk_set_root.clone(),
                threshold: prev_account_leaf.threshold,
            };
            let updated_root = account_merkle_proof.get_root::<F, C, D>(
                builder,
                &new_account_leaf,
                user_id,
            );

            // Conditionally update root
            current_root =
                PoseidonHashOutTarget::select(builder, is_active, updated_root, current_root);

            // Chain user hash: H(prev_hash || user_id)
            let hash_inputs: Vec<_> = current_hash
                .to_vec()
                .into_iter()
                .chain(std::iter::once(user_id))
                .collect();
            let new_hash = PoseidonHashOutTarget::hash_inputs(builder, &hash_inputs);
            current_hash =
                PoseidonHashOutTarget::select(builder, is_active, new_hash, current_hash);

            // Update count
            let new_count = builder.add(current_count, one);
            current_count = builder.select(is_active, new_count, current_count);

            // Update first_user_id (only on first active user, when count was still 0)
            let is_first = builder.is_equal(current_first_user_id, zero);
            let is_first_active = builder.and(is_active, is_first);
            current_first_user_id =
                builder.select(is_first_active, user_id, current_first_user_id);

            // Update last_user_id (always update on active)
            current_last_user_id = builder.select(is_active, user_id, current_last_user_id);

            users.push(AccountApplyBlockUserTarget {
                is_active,
                user_local_id,
                prev_account_leaf,
                account_merkle_proof,
                send_merkle_proof,
            });
        }

        let new_pis = AccountApplyBlockPublicInputsTarget {
            initial_account_tree_root: initial_account_tree_root.clone(),
            final_account_tree_root: current_root,
            block_number: block_number.clone(),
            aggregator_id,
            tx_tree_root: tx_tree_root.clone(),
            users_hash: current_hash,
            user_count: current_count,
            first_user_id: current_first_user_id,
            last_user_id: current_last_user_id,
        };

        Self {
            initial_account_tree_root,
            block_number,
            aggregator_id,
            tx_tree_root,
            users,
            new_pis,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        witness: &AccountApplyBlockWitness,
        new_pis: &AccountApplyBlockPublicInputs,
    ) {
        self.initial_account_tree_root
            .set_witness(pw, witness.initial_account_tree_root);
        self.block_number.set_witness(pw, witness.block_number);
        pw.set_target(
            self.aggregator_id,
            F::from_canonical_u64(witness.aggregator_id as u64),
        );
        self.tx_tree_root.set_witness(pw, witness.tx_tree_root);

        for (i, user_target) in self.users.iter().enumerate() {
            let user_witness = &witness.users[i];
            pw.set_bool_target(user_target.is_active, user_witness.is_active);
            pw.set_target(
                user_target.user_local_id,
                F::from_canonical_u64(user_witness.user_local_id as u64),
            );
            user_target
                .prev_account_leaf
                .set_witness(pw, &user_witness.prev_account_leaf);
            user_target
                .account_merkle_proof
                .set_witness(pw, &user_witness.account_merkle_proof);
            user_target
                .send_merkle_proof
                .set_witness(pw, &user_witness.send_merkle_proof);
        }

        self.new_pis.set_witness::<F, D, _>(pw, new_pis);
    }
}

pub struct AccountApplyBlockCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: AccountApplyBlockTarget,
}

impl<F, C, const D: usize> AccountApplyBlockCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = AccountApplyBlockTarget::new::<F, C, D>(&mut builder);
        builder.register_public_inputs(&target.new_pis.to_vec());
        let data = builder.build::<C>();
        Self { data, target }
    }

    pub fn prove(
        &self,
        witness: &AccountApplyBlockWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, AccountApplyBlockError> {
        let new_pis = witness.to_public_inputs()?;
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, witness, &new_pis);
        self.data
            .prove(pw)
            .map_err(|e| AccountApplyBlockError::FailedToProve(e.to_string()))
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), AccountApplyBlockError> {
        self.data.verify(proof.clone()).map_err(|e| {
            AccountApplyBlockError::FailedToProve(format!("Verification failed: {}", e))
        })
    }
}
