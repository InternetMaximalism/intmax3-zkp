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
    circuits::validity::deposit_hash_chain::deposit_chain_pis::{
        DepositChainPublicInputs, DepositChainPublicInputsError, DepositChainPublicInputsTarget,
    },
    common::{
        deposit::{Deposit, DepositTarget},
        trees::deposit_tree::{DepositMerkleProof, DepositMerkleProofTarget},
        u63::{U63, U63Target},
    },
    constants::DEPOSIT_TREE_HEIGHT,
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
pub enum UpdateDepositTreeError {
    #[error("Invalid input: {0}")]
    InvaldInput(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Failed to prove: {0}")]
    FailedToProve(String),

    #[error("Merkle proof error: {0}")]
    MerkleProofError(String),

    #[error("Deposit chain public inputs error: {0}")]
    DepositChainPublicInputsError(#[from] DepositChainPublicInputsError),
}

pub struct DepositStepWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub initial_value: Option<(Bytes32, PoseidonHashOut, U63)>,
    pub prev_deposit_chain_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub deposit: Deposit,
    pub deposit_merkle_proof: DepositMerkleProof,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    DepositStepWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        deposit_chain_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<DepositChainPublicInputs<F, C, D>, UpdateDepositTreeError> {
        let total_inputs = self.initial_value.is_some() as usize
            + self.prev_deposit_chain_proof.is_some() as usize;
        if total_inputs != 1 {
            return Err(UpdateDepositTreeError::InvaldInput(
                "Exactly one of initial_value or prev_deposit_chain_proof must be provided"
                    .to_string(),
            ));
        }

        // initial value case
        let prev_pis = if let Some((
            initial_deposit_hash_chain,
            initial_deposit_tree_root,
            initial_deposit_count,
        )) = &self.initial_value
        {
            DepositChainPublicInputs {
                initial_deposit_hash_chain: *initial_deposit_hash_chain,
                initial_deposit_tree_root: *initial_deposit_tree_root,
                initial_deposit_count: *initial_deposit_count,
                deposit_hash_chain: *initial_deposit_hash_chain,
                deposit_tree_root: *initial_deposit_tree_root,
                deposit_count: *initial_deposit_count,
                vd: deposit_chain_vd.verifier_only.clone(),
            }
        } else {
            let prev_proof = self
                .prev_deposit_chain_proof
                .clone()
                .expect("Checked above");
            DepositChainPublicInputs::<F, C, D>::from_u64_slice(
                &prev_proof.public_inputs.to_u64_vec(),
                &deposit_chain_vd.common.config,
            )?
        };

        // Validate empty deposit merkle proof
        let empty_deposit = Deposit::empty_leaf();
        self.deposit_merkle_proof
            .verify(
                &empty_deposit,
                prev_pis.deposit_count.as_u64(),
                prev_pis.deposit_tree_root,
            )
            .map_err(|e| {
                UpdateDepositTreeError::MerkleProofError(format!(
                    "Failed to verify empty deposit merkle proof: {e}",
                ))
            })?;
        // Compute new deposit tree root
        let new_deposit_tree_root = self
            .deposit_merkle_proof
            .get_root(&self.deposit, prev_pis.deposit_count.as_u64());

        // Increment deposit count
        let new_deposit_count = prev_pis.deposit_count.add(1).map_err(|e| {
            UpdateDepositTreeError::InvaldInput(format!("Deposit count overflow: {e}"))
        })?;

        // Compute new deposit hash chain
        let new_deposit_hash_chain = self
            .deposit
            .hash_with_prev_hash(prev_pis.deposit_hash_chain);

        Ok(DepositChainPublicInputs {
            initial_deposit_hash_chain: prev_pis.initial_deposit_hash_chain,
            initial_deposit_tree_root: prev_pis.initial_deposit_tree_root,
            initial_deposit_count: prev_pis.initial_deposit_count,
            deposit_hash_chain: new_deposit_hash_chain,
            deposit_tree_root: new_deposit_tree_root,
            deposit_count: new_deposit_count,
            vd: prev_pis.vd,
        })
    }
}

#[derive(Clone, Debug)]
pub struct DepositStepTarget<const D: usize> {
    pub is_initial: BoolTarget,
    pub initial_deposit_hash_chain: Bytes32Target,
    pub initial_deposit_tree_root: PoseidonHashOutTarget,
    pub initial_deposit_count: U63Target,
    pub prev_deposit_chain_proof: ProofWithPublicInputsTarget<D>,
    pub deposit: DepositTarget,
    pub deposit_merkle_proof: DepositMerkleProofTarget,

    pub new_pis: DepositChainPublicInputsTarget,
}

impl<const D: usize> DepositStepTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        deposit_chain_cd: &CommonCircuitData<F, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let is_initial = builder.add_virtual_bool_target_safe();
        let not_initial = builder.not(is_initial);

        let initial_deposit_hash_chain = Bytes32Target::new::<F, D>(builder, true);
        let initial_deposit_tree_root = PoseidonHashOutTarget::new(builder);
        let initial_deposit_count = U63Target::new(builder, true);
        let deposit = DepositTarget::new(builder, true);
        let deposit_merkle_proof = DepositMerkleProofTarget::new(builder, DEPOSIT_TREE_HEIGHT);

        // add prev deposit chain proof and conditionally verify
        let prev_deposit_chain_proof = builder.add_virtual_proof_with_pis(&deposit_chain_cd);
        let prev_deposit_chain_pis = DepositChainPublicInputsTarget::from_pis(
            &prev_deposit_chain_proof.public_inputs,
            &deposit_chain_cd.config,
        );
        conditionally_verify_proof::<F, C, D>(
            builder,
            not_initial,
            &prev_deposit_chain_proof,
            &prev_deposit_chain_pis.vd,
            &deposit_chain_cd,
        );
        let deposit_chain_vd =
            builder.add_virtual_verifier_data(deposit_chain_cd.config.fri_config.cap_height);
        conditionally_connect_vd(
            builder,
            not_initial,
            &prev_deposit_chain_pis.vd,
            &deposit_chain_vd,
        );

        // Select previous state depending on whether this is the initial step.
        let prev_deposit_hash_chain = Bytes32Target::select(
            builder,
            is_initial,
            initial_deposit_hash_chain.clone(),
            prev_deposit_chain_pis.deposit_hash_chain.clone(),
        );
        let prev_deposit_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            initial_deposit_tree_root.clone(),
            prev_deposit_chain_pis.deposit_tree_root.clone(),
        );
        let prev_deposit_count = U63Target::select(
            builder,
            is_initial,
            &initial_deposit_count,
            &prev_deposit_chain_pis.deposit_count,
        );

        // Select initial state depending on whether this is the initial step.
        let selected_initial_hash_chain = Bytes32Target::select(
            builder,
            is_initial,
            initial_deposit_hash_chain.clone(),
            prev_deposit_chain_pis.initial_deposit_hash_chain.clone(),
        );
        let selected_initial_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_initial,
            initial_deposit_tree_root.clone(),
            prev_deposit_chain_pis.initial_deposit_tree_root.clone(),
        );
        let selected_initial_count = U63Target::select(
            builder,
            is_initial,
            &initial_deposit_count,
            &prev_deposit_chain_pis.initial_deposit_count,
        );

        // Verify the Merkle proof for the empty leaf and compute the updated root.
        let empty_deposit_target = DepositTarget::constant(builder, &Deposit::default());
        deposit_merkle_proof.verify::<F, C, D>(
            builder,
            &empty_deposit_target,
            prev_deposit_count.value,
            prev_deposit_tree_root.clone(),
        );
        let new_deposit_tree_root =
            deposit_merkle_proof.get_root::<F, C, D>(builder, &deposit, prev_deposit_count.value);

        // Enforce deposit count increment.
        let incremented_count = builder.add_const(prev_deposit_count.value, F::ONE);
        builder.range_check(incremented_count, 63);
        let new_deposit_count = U63Target {
            value: incremented_count,
        };

        // Compute the new deposit hash chain.
        let new_deposit_hash_chain =
            deposit.hash_with_prev_hash::<F, C, D>(builder, prev_deposit_hash_chain.clone());

        let new_pis = DepositChainPublicInputsTarget {
            initial_deposit_hash_chain: selected_initial_hash_chain,
            initial_deposit_tree_root: selected_initial_tree_root,
            initial_deposit_count: selected_initial_count,
            deposit_hash_chain: new_deposit_hash_chain,
            deposit_tree_root: new_deposit_tree_root,
            deposit_count: new_deposit_count,
            vd: deposit_chain_vd,
        };

        Self {
            is_initial,
            initial_deposit_hash_chain,
            initial_deposit_tree_root,
            initial_deposit_count,
            prev_deposit_chain_proof,
            deposit,
            deposit_merkle_proof,
            new_pis,
        }
    }

    pub fn set_witness<F, C, W>(
        &self,
        witness: &mut W,
        value: &DepositStepWitness<F, C, D>,
        new_pis: &DepositChainPublicInputs<F, C, D>,
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
            self.initial_deposit_hash_chain
                .set_witness(witness, hash_chain);
            self.initial_deposit_tree_root
                .set_witness(witness, tree_root);
            self.initial_deposit_count.set_witness(witness, count);
        } else {
            self.initial_deposit_hash_chain
                .set_witness(witness, Bytes32::default());
            self.initial_deposit_tree_root
                .set_witness(witness, PoseidonHashOut::default());
            self.initial_deposit_count
                .set_witness(witness, U63::default());
        }
        if let Some(proof) = &value.prev_deposit_chain_proof {
            witness.set_proof_with_pis_target(&self.prev_deposit_chain_proof, proof);
        } else {
            witness.set_proof_with_pis_target(&self.prev_deposit_chain_proof, &dummy_proof);
        }
        self.new_pis.set_witness::<F, C, D, _>(witness, new_pis);
        self.deposit.set_witness(witness, &value.deposit);
        self.deposit_merkle_proof
            .set_witness(witness, &value.deposit_merkle_proof);
    }
}

#[derive(Debug)]
pub struct DepositStepCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: DepositStepTarget<D>,
    pub public_inputs: DepositChainPublicInputsTarget,

    pub dummy_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F, C, const D: usize> DepositStepCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(deposit_chain_cd: &CommonCircuitData<F, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = DepositStepTarget::new::<F, C>(&mut builder, deposit_chain_cd);
        let public_inputs = target.new_pis.clone();
        builder.register_public_inputs(&public_inputs.to_vec(&deposit_chain_cd.config));
        let data = builder.build::<C>();
        let dummy_proof = DummyProof::new(deposit_chain_cd);
        Self {
            data,
            target,
            public_inputs,
            dummy_proof: dummy_proof.proof,
        }
    }

    pub fn prove(
        &self,
        deposit_chain_vd: &VerifierCircuitData<F, C, D>,
        witness: &DepositStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, UpdateDepositTreeError> {
        let new_pis = witness.to_public_inputs(deposit_chain_vd)?;
        let mut pw = PartialWitness::<F>::new();
        self.target
            .set_witness(&mut pw, witness, &new_pis, &self.dummy_proof);
        self.public_inputs
            .set_witness::<F, C, D, _>(&mut pw, &new_pis);
        self.data
            .prove(pw)
            .map_err(|e| UpdateDepositTreeError::FailedToProve(e.to_string()))
    }

    pub fn verify(
        &self,
        proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), UpdateDepositTreeError> {
        self.data
            .verify(proof)
            .map_err(|e| UpdateDepositTreeError::InvalidProof(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::validity::deposit_hash_chain::deposit_chain_pis::DEPOSIT_CHAIN_PUBLIC_INPUTS_LEN,
        common::{deposit::Deposit, trees::deposit_tree::DepositTree, u63::U63},
        ethereum_types::{address::Address, bytes32::Bytes32, u256::U256},
        utils::{conversion::ToField as _, cyclic::TestCyclicCircuit},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_deposit_step_circuit() {
        // build dummy circuits
        let deposit_chain_config = CircuitConfig::standard_recursion_config();
        let pis_len = DEPOSIT_CHAIN_PUBLIC_INPUTS_LEN;
        let deposit_chain_cd = TestCyclicCircuit::<F, C, D>::generate_cd(pis_len);
        let deposit_chain_circuit =
            TestCyclicCircuit::<F, C, D>::new(deposit_chain_config, pis_len, &deposit_chain_cd);
        let deposit_chain_vd = deposit_chain_circuit.data.verifier_data();

        // Initial deposit chain state.
        let initial_deposit_hash_chain = Bytes32::default();
        let deposit_tree = DepositTree::init();
        let initial_deposit_tree_root = deposit_tree.get_root();
        let initial_deposit_count = U63::default();
        let deposit_index = 0u64;
        let deposit_merkle_proof = deposit_tree.prove(deposit_index);

        // Deposit to be appended.
        let deposit = Deposit {
            depositor: Address::default(),
            recipient: Bytes32::default(),
            token_index: 0,
            amount: U256::from(5u32),
            block_number: U63::default(),
            aux_data: Bytes32::default(),
        };

        // Expected new state after the deposit.
        let mut deposit_tree_after_first = deposit_tree.clone();
        deposit_tree_after_first.push(deposit.clone());
        let expected_deposit_tree_root = deposit_tree_after_first.get_root();
        let expected_deposit_hash_chain = deposit.hash_with_prev_hash(initial_deposit_hash_chain);

        let witness = DepositStepWitness::<F, C, D> {
            initial_value: Some((
                initial_deposit_hash_chain,
                initial_deposit_tree_root,
                initial_deposit_count,
            )),
            prev_deposit_chain_proof: None,
            deposit: deposit.clone(),
            deposit_merkle_proof: deposit_merkle_proof.clone(),
        };

        let expected_public_inputs = witness
            .to_public_inputs(&deposit_chain_vd)
            .expect("public inputs");
        assert_eq!(expected_public_inputs.deposit_count.as_u64(), 1);
        assert_eq!(
            expected_public_inputs.deposit_tree_root,
            expected_deposit_tree_root
        );
        assert_eq!(
            expected_public_inputs.deposit_hash_chain,
            expected_deposit_hash_chain
        );

        let circuit = DepositStepCircuit::<F, C, D>::new(&deposit_chain_cd);
        let first_step_proof = circuit
            .prove(&deposit_chain_vd, &witness)
            .expect("deposit step proof should succeed");
        circuit
            .verify(first_step_proof.clone())
            .expect("first proof verifies");

        let first_public_inputs_fields = expected_public_inputs
            .to_u64_vec(&deposit_chain_cd.config)
            .to_field_vec::<F>();
        let first_deposit_chain_proof = deposit_chain_circuit
            .prove(Some(first_public_inputs_fields.as_slice()), None)
            .expect("first deposit chain proof");

        // Second deposit step using the proof from the first step.
        let second_deposit = Deposit {
            depositor: Address::default(),
            recipient: Bytes32::default(),
            token_index: 1,
            amount: U256::from(7u32),
            block_number: U63::new(1).expect("valid block number"),
            aux_data: Bytes32::default(),
        };
        let second_deposit_index = 1u64;
        let second_deposit_merkle_proof = deposit_tree_after_first.prove(second_deposit_index);

        let expected_deposit_hash_chain_second =
            second_deposit.hash_with_prev_hash(expected_deposit_hash_chain);
        let mut deposit_tree_after_second = deposit_tree_after_first.clone();
        deposit_tree_after_second.push(second_deposit.clone());
        let expected_deposit_tree_root_second = deposit_tree_after_second.get_root();

        let second_witness = DepositStepWitness::<F, C, D> {
            initial_value: None,
            prev_deposit_chain_proof: Some(first_deposit_chain_proof.clone()),
            deposit: second_deposit.clone(),
            deposit_merkle_proof: second_deposit_merkle_proof,
        };

        let second_expected_public_inputs = second_witness
            .to_public_inputs(&deposit_chain_vd)
            .expect("second public inputs");
        assert_eq!(second_expected_public_inputs.deposit_count.as_u64(), 2);
        assert_eq!(
            second_expected_public_inputs.deposit_tree_root,
            expected_deposit_tree_root_second
        );
        assert_eq!(
            second_expected_public_inputs.deposit_hash_chain,
            expected_deposit_hash_chain_second
        );

        let second_proof = circuit
            .prove(&deposit_chain_vd, &second_witness)
            .expect("second deposit step proof should succeed");
        circuit.verify(second_proof).expect("second proof verifies");
    }
}
