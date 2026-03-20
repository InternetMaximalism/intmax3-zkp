use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::validity::forced_tx_hash_chain::forced_tx_chain_pis::{
        ForcedTxChainPublicInputs, ForcedTxChainPublicInputsError, ForcedTxChainPublicInputsTarget,
    },
    common::{
        forced_tx::{ForcedTx, ForcedTxTarget},
        trees::account_tree::{
            AccountLeaf, AccountLeafTarget, AccountMerkleProof, AccountMerkleProofTarget,
            SendLeaf, SendLeafTarget, SendMerkleProof, SendMerkleProofTarget,
        },
        u63::{BlockNumber, BlockNumberTarget, U63, U63Target},
    },
    constants::{ACCOUNT_TREE_HEIGHT, SEND_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait as _,
    },
    utils::{
        conversion::ToU64,
        cyclic::conditionally_connect_vd,
        dummy::{DummyProof, conditionally_verify_proof},
        leafable::Leafable as _,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};

#[derive(Debug, thiserror::Error)]
pub enum ForcedTxStepError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Failed to prove: {0}")]
    FailedToProve(String),

    #[error("Merkle proof error: {0}")]
    MerkleProofError(String),

    #[error("Forced tx chain public inputs error: {0}")]
    ForcedTxChainPublicInputsError(#[from] ForcedTxChainPublicInputsError),
}

/// Witness for a single forced tx step.
/// Processes one forced tx: updates account tree (adds SendLeaf) without
/// SPHINCS+ signature verification.
pub struct ForcedTxStepWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    /// Initial values if this is the first step (hash_chain, account_tree_root, count).
    pub initial_value: Option<(Bytes32, PoseidonHashOut, U63)>,

    /// Previous forced tx chain proof if not the first step.
    pub prev_forced_tx_chain_proof: Option<ProofWithPublicInputs<F, C, D>>,

    /// The forced tx to process.
    pub forced_tx: ForcedTx,

    /// Block number this forced tx belongs to.
    pub block_number: BlockNumber,

    /// Account tree merkle proof for the user.
    pub prev_account_leaf: AccountLeaf,
    pub account_merkle_proof: AccountMerkleProof,

    /// Send tree merkle proof for the empty slot.
    pub send_merkle_proof: SendMerkleProof,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ForcedTxStepWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        forced_tx_chain_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<ForcedTxChainPublicInputs<F, C, D>, ForcedTxStepError> {
        let total_inputs = self.initial_value.is_some() as usize
            + self.prev_forced_tx_chain_proof.is_some() as usize;
        if total_inputs != 1 {
            return Err(ForcedTxStepError::InvalidInput(
                "Exactly one of initial_value or prev_forced_tx_chain_proof must be provided"
                    .to_string(),
            ));
        }

        let prev_pis = if let Some((
            initial_forced_tx_hash_chain,
            initial_account_tree_root,
            initial_forced_tx_count,
        )) = &self.initial_value
        {
            ForcedTxChainPublicInputs {
                initial_forced_tx_hash_chain: *initial_forced_tx_hash_chain,
                initial_account_tree_root: *initial_account_tree_root,
                initial_forced_tx_count: *initial_forced_tx_count,
                forced_tx_hash_chain: *initial_forced_tx_hash_chain,
                account_tree_root: *initial_account_tree_root,
                forced_tx_count: *initial_forced_tx_count,
                block_number: self.block_number,
                vd: forced_tx_chain_vd.verifier_only.clone(),
            }
        } else {
            let prev_proof = self
                .prev_forced_tx_chain_proof
                .clone()
                .expect("Checked above");
            let prev_pis = ForcedTxChainPublicInputs::<F, C, D>::from_u64_slice(
                &prev_proof.public_inputs.to_u64_vec(),
                &forced_tx_chain_vd.common.config,
            )?;
            if prev_pis.block_number != self.block_number {
                return Err(ForcedTxStepError::InvalidInput(format!(
                    "Block number mismatch: prev {}, current {}",
                    prev_pis.block_number.as_u64(),
                    self.block_number.as_u64()
                )));
            }
            prev_pis
        };

        let user_id = self.forced_tx.user_id;

        // Verify account leaf membership
        self.account_merkle_proof
            .verify(
                &self.prev_account_leaf,
                user_id.as_u64(),
                prev_pis.account_tree_root,
            )
            .map_err(|e| {
                ForcedTxStepError::MerkleProofError(format!(
                    "Failed to verify account merkle proof: {e}"
                ))
            })?;

        // Verify empty send leaf exists at the index
        self.send_merkle_proof
            .verify(
                &SendLeaf::empty_leaf(),
                self.prev_account_leaf.index.into(),
                self.prev_account_leaf.send_tree_root,
            )
            .map_err(|e| {
                ForcedTxStepError::MerkleProofError(format!(
                    "Failed to verify empty send leaf: {e}"
                ))
            })?;

        // Create new send leaf with forced tx hash as tx_tree_root
        let new_send_leaf = SendLeaf {
            prev: self.prev_account_leaf.prev,
            cur: self.block_number,
            tx_tree_root: self.forced_tx.tx_hash,
        };
        let new_send_tree_root = self
            .send_merkle_proof
            .get_root(&new_send_leaf, self.prev_account_leaf.index.into());

        // Create new account leaf
        let new_account_leaf = AccountLeaf {
            index: self.prev_account_leaf.index + 1,
            prev: self.block_number,
            send_tree_root: new_send_tree_root,
            pk_hash: self.prev_account_leaf.pk_hash,
        };
        let new_account_tree_root = self
            .account_merkle_proof
            .get_root(&new_account_leaf, user_id.as_u64());

        // Compute new forced tx hash chain
        let new_forced_tx_hash_chain = self
            .forced_tx
            .hash_with_prev_hash(prev_pis.forced_tx_hash_chain);

        // Increment count
        let new_forced_tx_count = prev_pis.forced_tx_count.add(1).map_err(|e| {
            ForcedTxStepError::InvalidInput(format!("Forced tx count overflow: {e}"))
        })?;

        Ok(ForcedTxChainPublicInputs {
            initial_forced_tx_hash_chain: prev_pis.initial_forced_tx_hash_chain,
            initial_account_tree_root: prev_pis.initial_account_tree_root,
            initial_forced_tx_count: prev_pis.initial_forced_tx_count,
            forced_tx_hash_chain: new_forced_tx_hash_chain,
            account_tree_root: new_account_tree_root,
            forced_tx_count: new_forced_tx_count,
            block_number: self.block_number,
            vd: prev_pis.vd,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ForcedTxStepTarget<const D: usize> {
    pub is_initial: BoolTarget,
    pub initial_forced_tx_hash_chain: Bytes32Target,
    pub initial_account_tree_root: PoseidonHashOutTarget,
    pub initial_forced_tx_count: U63Target,
    pub prev_forced_tx_chain_proof: ProofWithPublicInputsTarget<D>,
    pub forced_tx: ForcedTxTarget,
    pub block_number: BlockNumberTarget,
    pub prev_account_leaf: AccountLeafTarget,
    pub account_merkle_proof: AccountMerkleProofTarget,
    pub send_merkle_proof: SendMerkleProofTarget,

    pub new_pis: ForcedTxChainPublicInputsTarget,
}

impl<const D: usize> ForcedTxStepTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        forced_tx_chain_cd: &CommonCircuitData<F, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let is_initial = builder.add_virtual_bool_target_safe();
        let not_initial = builder.not(is_initial);

        let initial_forced_tx_hash_chain = Bytes32Target::new::<F, D>(builder, true);
        let initial_account_tree_root = PoseidonHashOutTarget::new(builder);
        let initial_forced_tx_count = U63Target::new(builder, true);
        let forced_tx = ForcedTxTarget::new(builder, true);
        let block_number = BlockNumberTarget::new(builder, true);
        let prev_account_leaf = AccountLeafTarget::new(builder, true);
        let account_merkle_proof = AccountMerkleProofTarget::new(builder, ACCOUNT_TREE_HEIGHT);
        let send_merkle_proof = SendMerkleProofTarget::new(builder, SEND_TREE_HEIGHT);

        // Add prev forced tx chain proof and conditionally verify
        let prev_forced_tx_chain_proof =
            builder.add_virtual_proof_with_pis(forced_tx_chain_cd);
        let prev_chain_pis = ForcedTxChainPublicInputsTarget::from_pis(
            &prev_forced_tx_chain_proof.public_inputs,
            &forced_tx_chain_cd.config,
        );
        conditionally_verify_proof::<F, C, D>(
            builder,
            not_initial,
            &prev_forced_tx_chain_proof,
            &prev_chain_pis.vd,
            forced_tx_chain_cd,
        );
        let forced_tx_chain_vd =
            builder.add_virtual_verifier_data(forced_tx_chain_cd.config.fri_config.cap_height);
        conditionally_connect_vd(
            builder,
            not_initial,
            &prev_chain_pis.vd,
            &forced_tx_chain_vd,
        );

        // Select previous state
        let prev_forced_tx_hash_chain = Bytes32Target::select(
            builder,
            is_initial,
            initial_forced_tx_hash_chain.clone(),
            prev_chain_pis.forced_tx_hash_chain.clone(),
        );
        let prev_account_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            initial_account_tree_root.clone(),
            prev_chain_pis.account_tree_root.clone(),
        );
        let prev_forced_tx_count = U63Target::select(
            builder,
            is_initial,
            &initial_forced_tx_count,
            &prev_chain_pis.forced_tx_count,
        );

        // Connect block number for prev proof
        builder.conditional_assert_eq(
            not_initial.target,
            prev_chain_pis.block_number.value,
            block_number.value,
        );

        // Select initial state
        let selected_initial_hash_chain = Bytes32Target::select(
            builder,
            is_initial,
            initial_forced_tx_hash_chain.clone(),
            prev_chain_pis.initial_forced_tx_hash_chain.clone(),
        );
        let selected_initial_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            initial_account_tree_root.clone(),
            prev_chain_pis.initial_account_tree_root.clone(),
        );
        let selected_initial_count = U63Target::select(
            builder,
            is_initial,
            &initial_forced_tx_count,
            &prev_chain_pis.initial_forced_tx_count,
        );

        // --- Account tree update (single user, no signature) ---
        let user_id = forced_tx.user_id.clone();

        // Verify account leaf membership in account tree
        let current_root = prev_account_tree_root.clone();
        let leaf_root = account_merkle_proof.get_root::<F, C, D>(
            builder,
            &prev_account_leaf,
            user_id.value,
        );
        current_root.connect(builder, leaf_root);

        // Verify empty send leaf at prev_account_leaf.index
        let empty_send_leaf = SendLeafTarget::constant(builder, SendLeaf::empty_leaf());
        send_merkle_proof.verify::<F, C, D>(
            builder,
            &empty_send_leaf,
            prev_account_leaf.index,
            prev_account_leaf.send_tree_root.clone(),
        );

        // Create new send leaf with forced tx hash as tx_tree_root
        let new_send_leaf = SendLeafTarget {
            prev: prev_account_leaf.prev.clone(),
            cur: block_number.clone(),
            tx_tree_root: forced_tx.tx_hash.clone(),
        };
        let new_send_tree_root = send_merkle_proof.get_root::<F, C, D>(
            builder,
            &new_send_leaf,
            prev_account_leaf.index,
        );

        // Create new account leaf
        let next_index = builder.add_const(prev_account_leaf.index, F::ONE);
        let new_account_leaf = AccountLeafTarget {
            index: next_index,
            prev: block_number.clone(),
            send_tree_root: new_send_tree_root,
            pk_hash: prev_account_leaf.pk_hash.clone(),
        };
        let new_account_tree_root = account_merkle_proof.get_root::<F, C, D>(
            builder,
            &new_account_leaf,
            user_id.value,
        );

        // NO SPHINCS+ signature verification — this is the forced tx bypass

        // Compute new forced tx hash chain
        let new_forced_tx_hash_chain =
            forced_tx.hash_with_prev_hash::<F, C, D>(builder, prev_forced_tx_hash_chain);

        // Increment count
        let incremented_count = builder.add_const(prev_forced_tx_count.value, F::ONE);
        builder.range_check(incremented_count, 63);
        let new_forced_tx_count = U63Target {
            value: incremented_count,
        };

        let new_pis = ForcedTxChainPublicInputsTarget {
            initial_forced_tx_hash_chain: selected_initial_hash_chain,
            initial_account_tree_root: selected_initial_tree_root,
            initial_forced_tx_count: selected_initial_count,
            forced_tx_hash_chain: new_forced_tx_hash_chain,
            account_tree_root: new_account_tree_root,
            forced_tx_count: new_forced_tx_count,
            block_number: block_number.clone(),
            vd: forced_tx_chain_vd,
        };

        Self {
            is_initial,
            initial_forced_tx_hash_chain,
            initial_account_tree_root,
            initial_forced_tx_count,
            prev_forced_tx_chain_proof,
            forced_tx,
            block_number,
            prev_account_leaf,
            account_merkle_proof,
            send_merkle_proof,
            new_pis,
        }
    }

    pub fn set_witness<F, C, W>(
        &self,
        witness: &mut W,
        value: &ForcedTxStepWitness<F, C, D>,
        new_pis: &ForcedTxChainPublicInputs<F, C, D>,
        dummy_proof: &ProofWithPublicInputs<F, C, D>,
    ) where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
        W: WitnessWrite<F>,
    {
        let is_initial = value.initial_value.is_some();
        witness.set_bool_target(self.is_initial, is_initial);

        if let Some((hash_chain, tree_root, count)) = value.initial_value {
            self.initial_forced_tx_hash_chain
                .set_witness(witness, hash_chain);
            self.initial_account_tree_root
                .set_witness(witness, tree_root);
            self.initial_forced_tx_count.set_witness(witness, count);
        } else {
            self.initial_forced_tx_hash_chain
                .set_witness(witness, Bytes32::default());
            self.initial_account_tree_root
                .set_witness(witness, PoseidonHashOut::default());
            self.initial_forced_tx_count
                .set_witness(witness, U63::default());
        }

        if let Some(proof) = &value.prev_forced_tx_chain_proof {
            witness.set_proof_with_pis_target(&self.prev_forced_tx_chain_proof, proof);
        } else {
            witness.set_proof_with_pis_target(&self.prev_forced_tx_chain_proof, dummy_proof);
        }

        self.new_pis.set_witness::<F, C, D, _>(witness, new_pis);
        self.forced_tx.set_witness(witness, &value.forced_tx);
        self.block_number.set_witness(witness, value.block_number);
        self.prev_account_leaf
            .set_witness(witness, &value.prev_account_leaf);
        self.account_merkle_proof
            .set_witness(witness, &value.account_merkle_proof);
        self.send_merkle_proof
            .set_witness(witness, &value.send_merkle_proof);
    }
}

pub struct ForcedTxStepCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: ForcedTxStepTarget<D>,
    pub public_inputs: ForcedTxChainPublicInputsTarget,
    pub dummy_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F, C, const D: usize> ForcedTxStepCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(forced_tx_chain_cd: &CommonCircuitData<F, D>) -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target =
            ForcedTxStepTarget::new::<F, C>(&mut builder, forced_tx_chain_cd);
        let public_inputs = target.new_pis.clone();
        builder.register_public_inputs(&public_inputs.to_vec(&forced_tx_chain_cd.config));
        let data = builder.build::<C>();
        let dummy_proof = DummyProof::new(forced_tx_chain_cd);
        Self {
            data,
            target,
            public_inputs,
            dummy_proof: dummy_proof.proof,
        }
    }

    pub fn prove(
        &self,
        forced_tx_chain_vd: &VerifierCircuitData<F, C, D>,
        witness: &ForcedTxStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ForcedTxStepError> {
        let new_pis = witness.to_public_inputs(forced_tx_chain_vd)?;
        let mut pw = PartialWitness::<F>::new();
        self.target
            .set_witness(&mut pw, witness, &new_pis, &self.dummy_proof);
        self.public_inputs
            .set_witness::<F, C, D, _>(&mut pw, &new_pis);
        self.data
            .prove(pw)
            .map_err(|e| ForcedTxStepError::FailedToProve(e.to_string()))
    }

    pub fn verify(
        &self,
        proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), ForcedTxStepError> {
        self.data
            .verify(proof)
            .map_err(|e| ForcedTxStepError::InvalidProof(e.to_string()))
    }
}
