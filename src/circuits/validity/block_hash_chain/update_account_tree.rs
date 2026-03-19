use crate::{
    circuits::validity::block_hash_chain::sphincs_sig::{
        SpxSigTargets, SpxSigWitness, SPX_AUTH_GL_LEN, SPX_D, SPX_FORS_SIG_GL_LEN,
        SPX_WOTS_SIG_GL_LEN,
    },
    common::{
        block::{Block, BlockError, BlockTarget},
        trees::account_tree::{
            AccountLeaf, AccountLeafTarget, AccountMerkleProof, AccountMerkleProofTarget, SendLeaf,
            SendLeafTarget, SendMerkleProof, SendMerkleProofTarget,
        },
        u63::{BlockNumber, BlockNumberTarget, U63Target},
        user_id::{UserId, UserIdError, UserIdTarget},
    },
    constants::{ACCOUNT_TREE_HEIGHT, SEND_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
        u64::{U64, U64_LEN, U64Target},
    },
    utils::{
        cyclic::add_const_gate,
        leafable::Leafable as _,
        poseidon_hash_out::{POSEIDON_HASH_OUT_LEN, PoseidonHashOut, PoseidonHashOutTarget},
    },
};
use sphincsplus_circuits::verification::{SpxVerifyWitness, verify_circuit};
use plonky2::{
    field::{extension::Extendable, types::Field},
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
    pub block_timestamp: u64,
    pub prev_block_hash_chain: Bytes32,
    pub prev_account_tree_root: PoseidonHashOut,
    pub new_block_hash_chain: Bytes32,
    pub new_account_tree_root: PoseidonHashOut,
    pub deposit_hash_chain: Bytes32,
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

    // SPHINCS+ signature witnesses for each user slot (index matches local_ids).
    // Use SpxSigWitness::dummy() for inactive (zero local_id) slots.
    pub sig_witnesses: Vec<SpxSigWitness>,
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
            // pk_hash is preserved from the previous leaf across state transitions
            let new_account_leaf = AccountLeaf {
                index: prev_account_leaf.index + 1,
                prev: self.block_number,
                send_tree_root: new_send_tree_root,
                pk_hash: prev_account_leaf.pk_hash,
            };
            account_tree_root = account_merkle_proof.get_root(&new_account_leaf, user_id.as_u64());
        }

        Ok(UpdateAccountPublicInputs {
            block_number: self.block_number,
            block_timestamp: self.block.timestamp,
            prev_block_hash_chain: self.prev_block_hash_chain,
            prev_account_tree_root: self.prev_account_tree_root,
            new_block_hash_chain,
            new_account_tree_root: account_tree_root,
            deposit_hash_chain: self.block.deposit_hash_chain,
        })
    }
}

const UPDATE_ACCOUNT_PUBLIC_INPUTS_LEN: usize =
    1 + U64_LEN + 3 * BYTES32_LEN + 2 * POSEIDON_HASH_OUT_LEN;

impl UpdateAccountPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let mut result = vec![self.block_number.as_u64()];
        result.extend(U64::from(self.block_timestamp).to_u64_vec());
        result.extend(self.prev_block_hash_chain.to_u64_vec());
        result.extend(self.prev_account_tree_root.to_u64_vec());
        result.extend(self.new_block_hash_chain.to_u64_vec());
        result.extend(self.new_account_tree_root.to_u64_vec());
        result.extend(self.deposit_hash_chain.to_u64_vec());
        result
    }

    pub fn commitment(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, UpdateAccountTreeError> {
        if values.len() != UPDATE_ACCOUNT_PUBLIC_INPUTS_LEN {
            return Err(UpdateAccountTreeError::InvalidLength(format!(
                "invalid update-account public inputs length: expected {UPDATE_ACCOUNT_PUBLIC_INPUTS_LEN}, got {}",
                values.len()
            )));
        }

        let mut cursor = 0;

        let block_number = BlockNumber::new(values[cursor]).map_err(|e| {
            UpdateAccountTreeError::InvalidLength(format!("invalid block number: {e}"))
        })?;
        cursor += 1;

        let block_timestamp = U64::from_u64_slice(&values[cursor..cursor + U64_LEN])
            .map_err(|e| UpdateAccountTreeError::InvalidLength(e.to_string()))?;
        cursor += U64_LEN;

        let prev_block_hash_chain = Bytes32::from_u64_slice(&values[cursor..cursor + BYTES32_LEN])
            .map_err(|e| UpdateAccountTreeError::InvalidLength(e.to_string()))?;
        cursor += BYTES32_LEN;

        let prev_account_tree_root =
            PoseidonHashOut::from_u64_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| UpdateAccountTreeError::MerkleProofError(e.to_string()))?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let new_block_hash_chain =
            Bytes32::from_u64_slice(&values[cursor..cursor + BYTES32_LEN])
                .map_err(|e| UpdateAccountTreeError::InvalidLength(e.to_string()))?;
        cursor += BYTES32_LEN;

        let new_account_tree_root =
            PoseidonHashOut::from_u64_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| UpdateAccountTreeError::MerkleProofError(e.to_string()))?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let deposit_hash_chain = Bytes32::from_u64_slice(&values[cursor..cursor + BYTES32_LEN])
            .map_err(|e| UpdateAccountTreeError::InvalidLength(e.to_string()))?;

        Ok(Self {
            block_number,
            block_timestamp: u64::from(block_timestamp),
            prev_block_hash_chain,
            prev_account_tree_root,
            new_block_hash_chain,
            new_account_tree_root,
            deposit_hash_chain,
        })
    }
}

#[derive(Clone, Debug)]
pub struct UpdateAccountPublicInputsTarget {
    pub block_number: BlockNumberTarget,
    pub block_timestamp: U64Target,
    pub prev_block_hash_chain: Bytes32Target,
    pub prev_account_tree_root: PoseidonHashOutTarget,
    pub new_block_hash_chain: Bytes32Target,
    pub new_account_tree_root: PoseidonHashOutTarget,
    pub deposit_hash_chain: Bytes32Target,
}

impl UpdateAccountPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let block_number = BlockNumberTarget::new(builder, is_checked);
        let block_timestamp = U64Target::new(builder, is_checked);
        let prev_block_hash_chain = Bytes32Target::new(builder, is_checked);
        let prev_account_tree_root = PoseidonHashOutTarget::new(builder);
        let new_block_hash_chain = Bytes32Target::new(builder, is_checked);
        let new_account_tree_root = PoseidonHashOutTarget::new(builder);
        let deposit_hash_chain = Bytes32Target::new(builder, is_checked);
        Self {
            block_number,
            block_timestamp,
            prev_block_hash_chain,
            prev_account_tree_root,
            new_block_hash_chain,
            new_account_tree_root,
            deposit_hash_chain,
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.block_number.to_vec(),
            self.block_timestamp.to_vec(),
            self.prev_block_hash_chain.to_vec(),
            self.prev_account_tree_root.to_vec(),
            self.new_block_hash_chain.to_vec(),
            self.new_account_tree_root.to_vec(),
            self.deposit_hash_chain.to_vec(),
        ]
        .concat()
    }

    pub fn commitment<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        let inputs = self.to_vec();
        PoseidonHashOutTarget::hash_inputs(builder, &inputs)
    }

    pub fn from_slice(values: &[Target]) -> Self {
        assert_eq!(
            values.len(),
            UPDATE_ACCOUNT_PUBLIC_INPUTS_LEN,
            "UpdateAccountPublicInputsTarget::from_slice length mismatch",
        );

        let mut cursor = 0;

        let block_number = BlockNumberTarget::from_slice(&values[cursor..cursor + 1]);
        cursor += 1;

        let block_timestamp = U64Target::from_slice(&values[cursor..cursor + U64_LEN]);
        cursor += U64_LEN;

        let prev_block_hash_chain =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;

        let prev_account_tree_root =
            PoseidonHashOutTarget::from_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let new_block_hash_chain = Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;

        let new_account_tree_root =
            PoseidonHashOutTarget::from_slice(&values[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let deposit_hash_chain = Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);

        Self {
            block_number,
            block_timestamp,
            prev_block_hash_chain,
            prev_account_tree_root,
            new_block_hash_chain,
            new_account_tree_root,
            deposit_hash_chain,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &UpdateAccountPublicInputs,
    ) {
        self.block_number.set_witness(witness, value.block_number);
        self.block_timestamp
            .set_witness(witness, U64::from(value.block_timestamp));
        self.prev_block_hash_chain
            .set_witness(witness, value.prev_block_hash_chain);
        self.prev_account_tree_root
            .set_witness(witness, value.prev_account_tree_root);
        self.new_block_hash_chain
            .set_witness(witness, value.new_block_hash_chain);
        self.new_account_tree_root
            .set_witness(witness, value.new_account_tree_root);
        self.deposit_hash_chain
            .set_witness(witness, value.deposit_hash_chain);
    }

    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        when_true: &Self,
        when_false: &Self,
    ) -> Self {
        Self {
            block_number: U63Target::select(
                builder,
                condition,
                &when_true.block_number,
                &when_false.block_number,
            ),
            block_timestamp: U64Target::select(
                builder,
                condition,
                when_true.block_timestamp,
                when_false.block_timestamp,
            ),
            prev_block_hash_chain: Bytes32Target::select(
                builder,
                condition,
                when_true.prev_block_hash_chain.clone(),
                when_false.prev_block_hash_chain.clone(),
            ),
            prev_account_tree_root: PoseidonHashOutTarget::select(
                builder,
                condition,
                when_true.prev_account_tree_root.clone(),
                when_false.prev_account_tree_root.clone(),
            ),
            new_block_hash_chain: Bytes32Target::select(
                builder,
                condition,
                when_true.new_block_hash_chain.clone(),
                when_false.new_block_hash_chain.clone(),
            ),
            new_account_tree_root: PoseidonHashOutTarget::select(
                builder,
                condition,
                when_true.new_account_tree_root.clone(),
                when_false.new_account_tree_root.clone(),
            ),
            deposit_hash_chain: Bytes32Target::select(
                builder,
                condition,
                when_true.deposit_hash_chain.clone(),
                when_false.deposit_hash_chain.clone(),
            ),
        }
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
    /// SPHINCS+ signature witness targets for each user slot.
    pub spx_sig_targets: Vec<SpxSigTargets>,
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

        let mut spx_sig_targets: Vec<SpxSigTargets> = Vec::with_capacity(num_users as usize);

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
                // pk_hash is preserved unchanged across state transitions
                pk_hash: prev_account_leaf.pk_hash.clone(),
            };

            let updated_root =
                account_merkle_proof.get_root::<F, C, D>(builder, &new_account_leaf, user_id);

            account_tree_root =
                PoseidonHashOutTarget::select(builder, should_update, updated_root, current_root);

            // ── SPHINCS+ signature verification ────────────────────────────
            //
            // For each active user whose pk_hash is non-zero (has_pk_hash) we
            // verify that:
            //   1. Poseidon(pub_seed || root) == prev_account_leaf.pk_hash
            //   2. The SPHINCS+ signature is valid over the message
            //      M_i = [block_number, aggregator_id, local_id, tx_tree_root×8]
            //
            // When pk_hash == 0 (user has no registered key yet) the signature
            // constraints are skipped — dummy witnesses are accepted.
            // For padding slots (should_update=false) constraints are also skipped.

            // -- Compute should_verify_sig = should_update AND has_pk_hash --
            // Only enforce SPHINCS+ when the user has a registered key (pk_hash != 0).
            let should_verify_sig = {
                let zero = builder.zero();
                let e = &prev_account_leaf.pk_hash.elements;
                let z0 = builder.is_equal(e[0], zero);
                let z1 = builder.is_equal(e[1], zero);
                let z2 = builder.is_equal(e[2], zero);
                let z3 = builder.is_equal(e[3], zero);
                let all_zero_01 = builder.and(z0, z1);
                let all_zero_012 = builder.and(all_zero_01, z2);
                let all_zero = builder.and(all_zero_012, z3);
                let has_pk_hash = builder.not(all_zero);
                builder.and(should_update, has_pk_hash)
            };

            // -- Allocate virtual targets for PK and signature components --
            let pub_seed_gl: [_; 2] =
                std::array::from_fn(|_| builder.add_virtual_target());
            let pub_root_gl: [_; 2] =
                std::array::from_fn(|_| builder.add_virtual_target());
            let r_gl: [_; 2] =
                std::array::from_fn(|_| builder.add_virtual_target());
            let fors_sig_gl = builder.add_virtual_targets(SPX_FORS_SIG_GL_LEN);
            let ht_sig_gls: Vec<Vec<_>> = (0..SPX_D)
                .map(|_| builder.add_virtual_targets(SPX_WOTS_SIG_GL_LEN))
                .collect();
            let ht_auth_gls: Vec<Vec<_>> = (0..SPX_D)
                .map(|_| builder.add_virtual_targets(SPX_AUTH_GL_LEN))
                .collect();

            // -- Verify pk_hash stored in account leaf matches the provided PK --
            let pk_inputs: Vec<_> = [pub_seed_gl.as_slice(), pub_root_gl.as_slice()].concat();
            let computed_pk_hash =
                PoseidonHashOutTarget::hash_inputs(builder, &pk_inputs);
            prev_account_leaf
                .pk_hash
                .conditional_assert_eq(builder, computed_pk_hash, should_verify_sig);

            // -- Build message: [block_number, aggregator_id, local_id, tx_root×8] --
            let msg_gl: Vec<_> = std::iter::once(block_number.value)
                .chain(std::iter::once(block.aggregator_id))
                .chain(std::iter::once(local_id))
                .chain(block.tx_tree_root.to_vec())
                .collect();

            // pk_gl = pub_seed_gl || pub_root_gl (used in hash_message inside verify_circuit)
            let pk_gl: Vec<_> = [pub_seed_gl.as_slice(), pub_root_gl.as_slice()].concat();

            // -- Call verify_circuit from sphincsplus-circuits --
            let spx_witness = SpxVerifyWitness {
                pub_seed_gl,
                pub_root_gl,
                r_gl,
                pk_gl,
                msg_gl,
                fors_sig_gl: fors_sig_gl.clone(),
                ht_sig_gl: ht_sig_gls.clone(),
                ht_auth_gl: ht_auth_gls.clone(),
            };
            let computed_root = verify_circuit(builder, &spx_witness);

            // -- Conditionally assert computed_root == pub_root_gl --
            // (only enforced when should_verify_sig is true)
            builder.conditional_assert_eq(
                should_verify_sig.target,
                computed_root[0],
                pub_root_gl[0],
            );
            builder.conditional_assert_eq(
                should_verify_sig.target,
                computed_root[1],
                pub_root_gl[1],
            );

            spx_sig_targets.push(SpxSigTargets {
                pub_seed_gl,
                pub_root_gl,
                r_gl,
                fors_sig_gl,
                ht_sig_gls,
                ht_auth_gls,
            });
        }

        let public_inputs = UpdateAccountPublicInputsTarget {
            block_number: block_number.clone(),
            block_timestamp: block.timestamp.clone(),
            prev_block_hash_chain: prev_block_hash_chain.clone(),
            prev_account_tree_root: prev_account_tree_root.clone(),
            new_block_hash_chain,
            new_account_tree_root: account_tree_root.clone(),
            deposit_hash_chain: block.deposit_hash_chain.clone(),
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
            spx_sig_targets,
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

        // Set SPHINCS+ signature witnesses
        for (target, sig) in self
            .spx_sig_targets
            .iter()
            .zip(value.sig_witnesses.iter())
        {
            target.set_witness(witness, sig);
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
    pub num_users: u32,
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

        // add constant gates to enable conditional verification
        add_const_gate(&mut builder);

        let data = builder.build();

        Self {
            num_users,
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
        circuits::validity::block_hash_chain::sphincs_sig::SpxSigWitness,
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
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
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
        // Set cur = block_number so that prev_account_leaf_user1.prev == block_number.
        // This makes should_update = false → SPHINCS+ signature check is skipped.
        // A full signature test requires a SPHINCS+ signer (not yet implemented).
        let send_leaf_user1_prev = SendLeaf {
            prev: BlockNumber::default(),
            cur: block_number, // already-at-current-block: no update triggered
            tx_tree_root: Bytes32::rand(&mut rng),
        };
        send_tree_user1.push(send_leaf_user1_prev.clone());
        let prev_account_leaf_user1 = AccountLeaf {
            index: send_tree_user1.len() as u32,
            prev: send_leaf_user1_prev.cur,
            send_tree_root: send_tree_user1.get_root(),
            pk_hash: PoseidonHashOut::default(),
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
            pk_hash: PoseidonHashOut::default(),
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

        let timestamp = rng.next_u64();
        let block = Block::new(
            num_users,
            aggregator_id,
            &[1, 2],
            timestamp,
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
                    pk_hash: prev_leaf.pk_hash,
                };
                account_tree_for_proofs.update(user_id.as_u64(), new_account_leaf);
            }
        }

        // Dummy signature witnesses for the test (no real SPHINCS+ keys needed)
        let sig_witnesses = vec![SpxSigWitness::dummy(); num_users as usize];

        let update_account_tree = UpdateAccountTree {
            prev_block_hash_chain,
            prev_account_tree_root,
            block_number,
            block: block.clone(),
            prev_account_leaves: prev_account_leaves.clone(),
            account_merkle_proofs: account_merkle_proofs.clone(),
            send_merkle_proofs: send_merkle_proofs.clone(),
            sig_witnesses,
        };

        let public_inputs = update_account_tree.to_public_inputs().unwrap();

        // user1 has prev == block_number → should_update = false → tree unchanged.
        // user2 also has prev == block_number → should_update = false → tree unchanged.
        let expected_tree = account_tree.clone();

        assert_eq!(public_inputs.prev_account_tree_root, prev_account_tree_root);
        assert_eq!(
            public_inputs.new_account_tree_root,
            expected_tree.get_root()
        );
        assert_eq!(
            public_inputs.new_block_hash_chain,
            block.hash_with_prev_hash(prev_block_hash_chain).unwrap()
        );
        assert_eq!(public_inputs.deposit_hash_chain, block.deposit_hash_chain);

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
