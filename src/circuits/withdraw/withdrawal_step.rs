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
use thiserror::Error;

use crate::{
    circuits::{
        balance::common::update_public_state::{
            UpdatePublicState, UpdatePublicStateError, UpdatePublicStateTarget,
        },
        withdraw::single_withdrawal_circuit::{
            SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN, SingleWithdawalPublicInputs,
            SingleWithdawalPublicInputsTarget,
        },
    },
    common::public_state::{PUBLIC_STATE_U64_LEN, PublicState, PublicStateTarget},
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::{
        conversion::{ToField, ToU64},
        cyclic::{
            conditionally_connect_vd, vd_from_pis_slice, vd_from_pis_slice_target, vd_to_vec,
            vd_to_vec_target, vd_vec_len,
        },
        dummy::{DummyProof, conditionally_verify_proof},
        recursively_verifiable::add_proof_target_and_verify,
    },
};

pub const WITHDRAWAL_STEP_PUBLIC_INPUTS_LEN: usize = BYTES32_LEN + PUBLIC_STATE_U64_LEN;

#[derive(Debug, Error)]
pub enum WithdrawalStepPublicInputsError {
    #[error("Invalid public inputs length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Failed to parse withdrawal hash: {0}")]
    WithdrawalHash(String),

    #[error("Failed to parse verifier data: {0}")]
    VerifierData(String),

    #[error("Failed to parse public state: {0}")]
    PublicState(String),
}

pub struct WithdrawalStepPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub withdrawal_hash_chain: Bytes32,
    pub public_state: PublicState,
    pub vd: plonky2::plonk::circuit_data::VerifierOnlyCircuitData<C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    WithdrawalStepPublicInputs<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_u64_vec(&self, config: &CircuitConfig) -> Vec<u64> {
        [
            self.withdrawal_hash_chain.to_u64_vec(),
            self.public_state.to_u64_vec(),
            vd_to_vec(config, &self.vd).to_u64_vec(),
        ]
        .concat()
    }

    pub fn from_u64_slice(
        inputs: &[u64],
        config: &CircuitConfig,
    ) -> Result<Self, WithdrawalStepPublicInputsError> {
        let vd_len = vd_vec_len(config);
        let expected = WITHDRAWAL_STEP_PUBLIC_INPUTS_LEN + vd_len;
        if inputs.len() != expected {
            return Err(WithdrawalStepPublicInputsError::InvalidLength {
                expected,
                actual: inputs.len(),
            });
        }

        let mut cursor = 0;

        let withdrawal_hash_chain = Bytes32::from_u64_slice(&inputs[cursor..cursor + BYTES32_LEN])
            .map_err(|e| WithdrawalStepPublicInputsError::WithdrawalHash(e.to_string()))?;
        cursor += BYTES32_LEN;

        let public_state =
            PublicState::from_u64_slice(&inputs[cursor..cursor + PUBLIC_STATE_U64_LEN])
                .map_err(|e| WithdrawalStepPublicInputsError::PublicState(e.to_string()))?;
        cursor += PUBLIC_STATE_U64_LEN;

        let vd_slice = &inputs[cursor..cursor + vd_len];
        let vd = vd_from_pis_slice::<F, C, D>(&vd_slice.to_field_vec(), config)
            .map_err(|e| WithdrawalStepPublicInputsError::VerifierData(e.to_string()))?;

        Ok(Self {
            withdrawal_hash_chain,
            public_state,
            vd,
        })
    }
}

#[derive(Clone, Debug)]
pub struct WithdrawalStepPublicInputsTarget {
    pub withdrawal_hash_chain: Bytes32Target,
    pub public_state: PublicStateTarget,
    pub vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,
}

impl WithdrawalStepPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        config: &CircuitConfig,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        Self {
            withdrawal_hash_chain: Bytes32Target::new(builder, true),
            public_state: PublicStateTarget::new(builder, false),
            vd: builder.add_virtual_verifier_data(config.fri_config.cap_height),
        }
    }

    pub fn to_vec(&self, config: &CircuitConfig) -> Vec<plonky2::iop::target::Target> {
        [
            self.withdrawal_hash_chain.to_vec(),
            self.public_state.to_vec(),
            vd_to_vec_target(config, &self.vd),
        ]
        .concat()
    }

    pub fn from_pis(pis: &[plonky2::iop::target::Target], config: &CircuitConfig) -> Self {
        let vd_len = vd_vec_len(config);
        assert!(
            pis.len() >= WITHDRAWAL_STEP_PUBLIC_INPUTS_LEN + vd_len,
            "WithdrawalStepPublicInputsTarget::from_pis length mismatch"
        );

        let mut cursor = 0;
        let withdrawal_hash_chain = Bytes32Target::from_slice(&pis[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;

        let public_state =
            PublicStateTarget::from_slice(&pis[cursor..cursor + PUBLIC_STATE_U64_LEN]);
        cursor += PUBLIC_STATE_U64_LEN;

        let vd_slice = &pis[cursor..cursor + vd_len];
        let vd = vd_from_pis_slice_target(vd_slice, config)
            .expect("vd_from_pis_slice_target should not fail");

        Self {
            withdrawal_hash_chain,
            public_state,
            vd,
        }
    }

    pub fn set_witness<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
        W: WitnessWrite<F>,
    >(
        &self,
        witness: &mut W,
        value: &WithdrawalStepPublicInputs<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.withdrawal_hash_chain
            .set_witness(witness, value.withdrawal_hash_chain);
        self.public_state.set_witness(witness, &value.public_state);
        witness.set_verifier_data_target(&self.vd, &value.vd);
    }
}

#[derive(Debug, Error)]
pub enum WithdrawalStepError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Failed to prove: {0}")]
    FailedToProve(String),

    #[error("Update public state error: {0}")]
    UpdatePublicState(#[from] UpdatePublicStateError),

    #[error("Withdrawal step public inputs error: {0}")]
    PublicInputs(#[from] WithdrawalStepPublicInputsError),

    #[error("Single withdrawal public inputs error: {0}")]
    SingleWithdrawalPublicInputs(String),
}

pub struct WithdrawalStepWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub prev_withdrawal_chain_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub single_withdrawal_proof: ProofWithPublicInputs<F, C, D>,
    pub update_public_state: UpdatePublicState,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    WithdrawalStepWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        withdrawal_chain_vd: &VerifierCircuitData<F, C, D>,
        single_withdrawal_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<WithdrawalStepPublicInputs<F, C, D>, WithdrawalStepError> {
        self.update_public_state.verify()?;

        let mut prev_hash = Bytes32::default();
        let vd = withdrawal_chain_vd.verifier_only.clone();

        single_withdrawal_vd
            .verify(self.single_withdrawal_proof.clone())
            .map_err(|e| {
                WithdrawalStepError::InvalidProof(format!("single withdrawal proof invalid: {e}"))
            })?;

        let single_withdrawal_inputs = SingleWithdawalPublicInputs::from_u64_slice(
            &self.single_withdrawal_proof.public_inputs[..SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN]
                .to_u64_vec(),
        )
        .map_err(|e| WithdrawalStepError::SingleWithdrawalPublicInputs(e.to_string()))?;

        if single_withdrawal_inputs.public_state != self.update_public_state.old {
            return Err(WithdrawalStepError::InvalidInput(
                "update_public_state.old must match single withdrawal public state".to_string(),
            ));
        }

        if let Some(prev_proof) = &self.prev_withdrawal_chain_proof {
            withdrawal_chain_vd
                .verify(prev_proof.clone())
                .map_err(|e| WithdrawalStepError::InvalidProof(e.to_string()))?;

            let prev_inputs = WithdrawalStepPublicInputs::<F, C, D>::from_u64_slice(
                &prev_proof.public_inputs.to_u64_vec(),
                &withdrawal_chain_vd.common.config,
            )?;

            // SECURITY (WDR-CRIT-001): every step in the chain must output the
            // SAME public_state (the canonical target state the whole batch is
            // anchored to). Enforce it here so that each step's
            // `update_public_state` is a valid Merkle transition from that
            // step's single_withdrawal.public_state to the canonical target.
            if prev_inputs.public_state != self.update_public_state.new {
                return Err(WithdrawalStepError::InvalidInput(format!(
                    "update_public_state.new must equal prev chain public_state; \
                     prev.public_state = {:?}, update_public_state.new = {:?}",
                    prev_inputs.public_state, self.update_public_state.new,
                )));
            }

            prev_hash = prev_inputs.withdrawal_hash_chain;
        }

        let withdrawal_hash_chain = single_withdrawal_inputs
            .withdrawal
            .hash_with_prev_hash(prev_hash);

        Ok(WithdrawalStepPublicInputs {
            withdrawal_hash_chain,
            // SECURITY (WDR-CRIT-001): output the chain-wide canonical state
            // `update_public_state.new`, not `.old`. The chain wrapper then
            // anchors this to the canonical validity-proof state on L1, which
            // cascades back through every step's Merkle proof to force every
            // single_withdrawal's public_state to be on real on-chain history.
            public_state: self.update_public_state.new.clone(),
            vd,
        })
    }
}

#[derive(Clone, Debug)]
pub struct WithdrawalStepTarget<const D: usize> {
    pub is_initial: BoolTarget,
    pub prev_withdrawal_chain_proof: ProofWithPublicInputsTarget<D>,
    pub single_withdrawal_proof: ProofWithPublicInputsTarget<D>,
    pub single_withdrawal_public_inputs: SingleWithdawalPublicInputsTarget,
    pub update_public_state: UpdatePublicStateTarget,
    pub new_pis: WithdrawalStepPublicInputsTarget,
}

impl<const D: usize> WithdrawalStepTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        withdrawal_chain_cd: &CommonCircuitData<F, D>,
        single_withdrawal_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let is_initial = builder.add_virtual_bool_target_safe();
        let not_initial = builder.not(is_initial);

        let update_public_state = UpdatePublicStateTarget::new::<F, C, D>(builder);

        let prev_withdrawal_chain_proof = builder.add_virtual_proof_with_pis(withdrawal_chain_cd);
        let prev_withdrawal_chain_pis = WithdrawalStepPublicInputsTarget::from_pis(
            &prev_withdrawal_chain_proof.public_inputs,
            &withdrawal_chain_cd.config,
        );
        conditionally_verify_proof::<F, C, D>(
            builder,
            not_initial,
            &prev_withdrawal_chain_proof,
            &prev_withdrawal_chain_pis.vd,
            withdrawal_chain_cd,
        );
        let withdrawal_chain_vd =
            builder.add_virtual_verifier_data(withdrawal_chain_cd.config.fri_config.cap_height);
        conditionally_connect_vd(
            builder,
            not_initial,
            &prev_withdrawal_chain_pis.vd,
            &withdrawal_chain_vd,
        );

        let single_withdrawal_proof = add_proof_target_and_verify(&single_withdrawal_vd, builder);
        let single_withdrawal_pis = SingleWithdawalPublicInputsTarget::from_vec(
            &single_withdrawal_proof.public_inputs[..SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN],
        );

        update_public_state
            .old
            .connect(builder, &single_withdrawal_pis.public_state);

        // SECURITY (WDR-CRIT-001): force every non-initial step's
        // `update_public_state.new` to equal the chain's running `public_state`.
        // Combined with the output below (`public_state = update_public_state.new`),
        // this means the chain carries a single fixed public_state across all
        // steps; the L1 anchor on the final state cascades back through every
        // step's Merkle proof of `old -> new`, forcing every
        // single_withdrawal.public_state to be a real on-chain historical state.
        update_public_state.new.conditional_assert_eq(
            builder,
            &prev_withdrawal_chain_pis.public_state,
            not_initial,
        );

        let zero_hash = Bytes32Target::constant::<F, D, Bytes32>(builder, Bytes32::default());
        let prev_withdrawal_hash_chain = Bytes32Target::select(
            builder,
            is_initial,
            zero_hash,
            prev_withdrawal_chain_pis.withdrawal_hash_chain.clone(),
        );

        let withdrawal_hash_chain = single_withdrawal_pis
            .withdrawal
            .hash_with_prev_hash::<F, C, D>(builder, prev_withdrawal_hash_chain);

        let new_pis = WithdrawalStepPublicInputsTarget {
            withdrawal_hash_chain,
            // SECURITY (WDR-CRIT-001): output `update_public_state.new`, not
            // `.old`. See the companion witness-side change above and the
            // `conditional_assert_eq` that ties consecutive steps' `.new`
            // together.
            public_state: update_public_state.new.clone(),
            vd: withdrawal_chain_vd,
        };

        Self {
            is_initial,
            prev_withdrawal_chain_proof,
            single_withdrawal_proof,
            single_withdrawal_public_inputs: single_withdrawal_pis,
            update_public_state,
            new_pis,
        }
    }

    pub fn set_witness<F, C, W>(
        &self,
        witness: &mut W,
        value: &WithdrawalStepWitness<F, C, D>,
        new_pis: &WithdrawalStepPublicInputs<F, C, D>,
        dummy_proof: &ProofWithPublicInputs<F, C, D>,
    ) where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
        W: WitnessWrite<F>,
    {
        let is_initial = value.prev_withdrawal_chain_proof.is_none();
        witness.set_bool_target(self.is_initial, is_initial);

        if let Some(proof) = &value.prev_withdrawal_chain_proof {
            witness.set_proof_with_pis_target(&self.prev_withdrawal_chain_proof, proof);
        } else {
            witness.set_proof_with_pis_target(&self.prev_withdrawal_chain_proof, dummy_proof);
        }

        witness.set_proof_with_pis_target(
            &self.single_withdrawal_proof,
            &value.single_withdrawal_proof,
        );
        let single_withdrawal_public_inputs = SingleWithdawalPublicInputs::from_u64_slice(
            &value.single_withdrawal_proof.public_inputs[..SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN]
                .to_u64_vec(),
        )
        .expect("single withdrawal public inputs should parse");
        self.single_withdrawal_public_inputs
            .set_witness(witness, &single_withdrawal_public_inputs);
        self.update_public_state
            .set_witness(witness, &value.update_public_state);
        self.new_pis.set_witness::<F, C, D, _>(witness, new_pis);
    }
}

pub struct WithdrawalStepCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: WithdrawalStepTarget<D>,
    pub public_inputs: WithdrawalStepPublicInputsTarget,
    pub dummy_proof: ProofWithPublicInputs<F, C, D>,
    pub single_withdrawal_vd: VerifierCircuitData<F, C, D>,
}

impl<F, C, const D: usize> WithdrawalStepCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn setup_builder(
        withdrawal_chain_cd: &CommonCircuitData<F, D>,
        single_withdrawal_vd: &VerifierCircuitData<F, C, D>,
    ) -> (
        CircuitBuilder<F, D>,
        WithdrawalStepTarget<D>,
        WithdrawalStepPublicInputsTarget,
    ) {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = WithdrawalStepTarget::new::<F, C>(
            &mut builder,
            withdrawal_chain_cd,
            single_withdrawal_vd,
        );
        let public_inputs = target.new_pis.clone();
        builder.register_public_inputs(&public_inputs.to_vec(&withdrawal_chain_cd.config));
        (builder, target, public_inputs)
    }

    fn from_parts(
        data: CircuitData<F, C, D>,
        target: WithdrawalStepTarget<D>,
        public_inputs: WithdrawalStepPublicInputsTarget,
        dummy_proof: ProofWithPublicInputs<F, C, D>,
        single_withdrawal_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        Self {
            data,
            target,
            public_inputs,
            dummy_proof,
            single_withdrawal_vd: single_withdrawal_vd.clone(),
        }
    }

    pub fn new(
        withdrawal_chain_cd: &CommonCircuitData<F, D>,
        single_withdrawal_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let (builder, target, public_inputs) =
            Self::setup_builder(withdrawal_chain_cd, single_withdrawal_vd);
        let data = builder.build::<C>();
        let dummy_proof = DummyProof::new(withdrawal_chain_cd);
        Self::from_parts(data, target, public_inputs, dummy_proof.proof, single_withdrawal_vd)
    }

    pub async fn new_async(
        withdrawal_chain_cd: &CommonCircuitData<F, D>,
        single_withdrawal_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let (builder, target, public_inputs) =
            Self::setup_builder(withdrawal_chain_cd, single_withdrawal_vd);
        let data = builder.build_async::<C>().await;
        let dummy_proof = DummyProof::new_async(withdrawal_chain_cd).await;
        Self::from_parts(data, target, public_inputs, dummy_proof.proof, single_withdrawal_vd)
    }

    fn prepare_witness(
        &self,
        withdrawal_chain_vd: &VerifierCircuitData<F, C, D>,
        witness: &WithdrawalStepWitness<F, C, D>,
    ) -> Result<PartialWitness<F>, WithdrawalStepError> {
        let new_pis = witness.to_public_inputs(withdrawal_chain_vd, &self.single_withdrawal_vd)?;
        let mut pw = PartialWitness::<F>::new();
        self.target
            .set_witness(&mut pw, witness, &new_pis, &self.dummy_proof);
        self.public_inputs
            .set_witness::<F, C, D, _>(&mut pw, &new_pis);
        Ok(pw)
    }

    pub fn prove(
        &self,
        withdrawal_chain_vd: &VerifierCircuitData<F, C, D>,
        witness: &WithdrawalStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, WithdrawalStepError> {
        let pw = self.prepare_witness(withdrawal_chain_vd, witness)?;
        self.data
            .prove(pw)
            .map_err(|e| WithdrawalStepError::FailedToProve(e.to_string()))
    }

    pub async fn prove_async(
        &self,
        withdrawal_chain_vd: &VerifierCircuitData<F, C, D>,
        witness: &WithdrawalStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, WithdrawalStepError> {
        let pw = self.prepare_witness(withdrawal_chain_vd, witness)?;
        self.data
            .prove_async(pw)
            .await
            .map_err(|e| WithdrawalStepError::FailedToProve(e.to_string()))
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> Result<(), WithdrawalStepError> {
        self.data
            .verify(proof)
            .map_err(|e| WithdrawalStepError::InvalidProof(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::{
            balance::common::update_public_state::UpdatePublicState,
            withdraw::single_withdrawal_circuit::{
                SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN, SingleWithdawalPublicInputs,
            },
        },
        common::{public_state::PublicState, withdrawal::Withdrawal},
        ethereum_types::{address::Address, bytes32::Bytes32, u256::U256},
        utils::cyclic::TestCyclicCircuit,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_withdrawal_step_circuit() {
        let withdrawal_chain_config = CircuitConfig::standard_recursion_config();
        let pis_len = WITHDRAWAL_STEP_PUBLIC_INPUTS_LEN;
        let withdrawal_chain_cd = TestCyclicCircuit::<F, C, D>::generate_cd(pis_len);
        let withdrawal_chain_circuit = TestCyclicCircuit::<F, C, D>::new(
            withdrawal_chain_config,
            pis_len,
            &withdrawal_chain_cd,
        );
        let withdrawal_chain_vd = withdrawal_chain_circuit.data.verifier_data();

        let single_withdrawal_config = CircuitConfig::standard_recursion_config();
        let single_pis_len = SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN;
        let single_withdrawal_cd = TestCyclicCircuit::<F, C, D>::generate_cd(single_pis_len);
        let single_withdrawal_circuit = TestCyclicCircuit::<F, C, D>::new(
            single_withdrawal_config,
            single_pis_len,
            &single_withdrawal_cd,
        );
        let single_withdrawal_vd = single_withdrawal_circuit.data.verifier_data();

        let public_state = PublicState::default();
        let update_public_state =
            UpdatePublicState::new(public_state.clone(), public_state.clone(), None)
                .expect("update public state");

        let withdrawal = Withdrawal {
            recipient: Address::default(),
            token_index: 0,
            amount: U256::from(10u32),
            nullifier: Bytes32::default(),
            aux_data: Bytes32::default(),
        };

        let single_inputs = SingleWithdawalPublicInputs {
            public_state: update_public_state.old.clone(),
            withdrawal: withdrawal.clone(),
        };
        let single_inputs_fields = single_inputs.to_u64_vec().to_field_vec::<F>();
        let single_withdrawal_proof = single_withdrawal_circuit
            .prove(Some(single_inputs_fields.as_slice()), None)
            .expect("single withdrawal proof");

        let circuit =
            WithdrawalStepCircuit::<F, C, D>::new(&withdrawal_chain_cd, &single_withdrawal_vd);
        let witness = WithdrawalStepWitness::<F, C, D> {
            prev_withdrawal_chain_proof: None,
            single_withdrawal_proof: single_withdrawal_proof.clone(),
            update_public_state: update_public_state.clone(),
        };

        let expected_public_inputs = witness
            .to_public_inputs(&withdrawal_chain_vd, &circuit.single_withdrawal_vd)
            .expect("public inputs");
        assert_eq!(
            expected_public_inputs.withdrawal_hash_chain,
            withdrawal.hash_with_prev_hash(Bytes32::default())
        );
        assert_eq!(expected_public_inputs.public_state, update_public_state.old);

        let first_step_proof = circuit
            .prove(&withdrawal_chain_vd, &witness)
            .expect("withdrawal step proof should succeed");
        circuit
            .verify(first_step_proof.clone())
            .expect("first proof should verify");

        let first_public_inputs_fields = expected_public_inputs
            .to_u64_vec(&withdrawal_chain_cd.config)
            .to_field_vec::<F>();
        let first_withdrawal_chain_proof = withdrawal_chain_circuit
            .prove(Some(first_public_inputs_fields.as_slice()), None)
            .expect("withdrawal chain proof should succeed");

        let second_withdrawal = Withdrawal {
            recipient: Address::default(),
            token_index: 1,
            amount: U256::from(5u32),
            nullifier: Bytes32::default(),
            aux_data: Bytes32::default(),
        };

        let second_single_inputs = SingleWithdawalPublicInputs {
            public_state: update_public_state.old.clone(),
            withdrawal: second_withdrawal.clone(),
        };
        let second_inputs_fields = second_single_inputs.to_u64_vec().to_field_vec::<F>();
        let second_single_withdrawal_proof = single_withdrawal_circuit
            .prove(Some(second_inputs_fields.as_slice()), None)
            .expect("second single withdrawal proof");

        let second_witness = WithdrawalStepWitness::<F, C, D> {
            prev_withdrawal_chain_proof: Some(first_withdrawal_chain_proof.clone()),
            single_withdrawal_proof: second_single_withdrawal_proof.clone(),
            update_public_state: update_public_state.clone(),
        };

        let second_expected_inputs = second_witness
            .to_public_inputs(&withdrawal_chain_vd, &circuit.single_withdrawal_vd)
            .expect("public inputs");
        assert_eq!(
            second_expected_inputs.withdrawal_hash_chain,
            second_withdrawal.hash_with_prev_hash(expected_public_inputs.withdrawal_hash_chain)
        );
        assert_eq!(second_expected_inputs.public_state, update_public_state.old);

        let second_step_proof = circuit
            .prove(&withdrawal_chain_vd, &second_witness)
            .expect("second withdrawal step proof should succeed");
        circuit
            .verify(second_step_proof)
            .expect("second proof should verify");
    }
}
