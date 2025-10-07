use std::collections::HashMap;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::balance::balance_pis::{
        BalanceFullPublicInputs, BalanceFullPublicInputsTarget, BalancePublicInputs,
        BalancePublicInputsError, BalancePublicInputsTarget,
    },
    common::{
        block_number::BlockNumberTarget,
        private_state::{PrivateState, PrivateStateTarget},
        public_state::PublicStateTarget,
        salt::{Salt, SaltTarget},
        user_id::{UserId, UserIdTarget},
    },
    utils::{
        conversion::ToU64, dummy::DummyProof, poseidon_hash_out::PoseidonHashOutTarget,
        recursively_verifiable::add_proof_target_and_conditionally_verify,
    },
};

#[derive(thiserror::Error, Debug)]
pub enum BalanceSwitchBoardError {
    #[error("Invalid balance proof: {0}")]
    InvalidBalanceProof(String),

    #[error("Invalid balance verifier data: {0}")]
    InvalidBalanceVd(String),

    #[error("Balance public inputs error: {0}")]
    BalancePublicInputsError(#[from] BalancePublicInputsError),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Dummy proof not provided for index {0}")]
    DummyProofNotProvided(usize),

    #[error("Failed to prove: {0}")]
    FailedToProve(String),
}

pub struct BalanceSwichBoard<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub initial_value: Option<(UserId, Salt)>,
    pub receive_transfer_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub receive_deposit_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub send_tx_proof: Option<ProofWithPublicInputs<F, C, D>>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    BalanceSwichBoard<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        balance_vd: &VerifierCircuitData<F, C, D>,
        receive_transfer_vd: &VerifierCircuitData<F, C, D>,
        receive_deposit_vd: &VerifierCircuitData<F, C, D>,
        send_tx_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<BalanceFullPublicInputs<F, C, D>, BalanceSwitchBoardError> {
        // number of initial value or proofs must be exactly one
        let total = self.initial_value.is_some() as u8
            + self.receive_transfer_proof.is_some() as u8
            + self.receive_deposit_proof.is_some() as u8
            + self.send_tx_proof.is_some() as u8;
        if total != 1 {
            return Err(BalanceSwitchBoardError::InvalidInput(
                "exactly one of initial value or proofs must be provided".to_string(),
            ));
        }

        if self.initial_value.is_some() {
            let (user_id, salt) = self.initial_value.unwrap();
            let pis = BalancePublicInputs::new(user_id, salt);
            return Ok(BalanceFullPublicInputs {
                pis,
                vd: balance_vd.verifier_only.clone(),
            });
        }

        if self.receive_transfer_proof.is_some() {
            let proof = self.receive_transfer_proof.as_ref().unwrap();
            receive_transfer_vd.verify(proof.clone()).map_err(|e| {
                BalanceSwitchBoardError::InvalidBalanceProof(format!(
                    "receive transfer proof is invalid: {}",
                    e
                ))
            })?;
            let pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
                &proof.public_inputs.to_u64_vec(),
                &balance_vd.common.config,
            )?;
            return Ok(pis);
        }

        if self.receive_deposit_proof.is_some() {
            let proof = self.receive_deposit_proof.as_ref().unwrap();
            receive_deposit_vd.verify(proof.clone()).map_err(|e| {
                BalanceSwitchBoardError::InvalidBalanceProof(format!(
                    "receive deposit proof is invalid: {}",
                    e
                ))
            })?;
            let pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
                &proof.public_inputs.to_u64_vec(),
                &balance_vd.common.config,
            )?;
            return Ok(pis);
        }

        if self.send_tx_proof.is_some() {
            let proof = self.send_tx_proof.as_ref().unwrap();
            send_tx_vd.verify(proof.clone()).map_err(|e| {
                BalanceSwitchBoardError::InvalidBalanceProof(format!(
                    "send tx proof is invalid: {}",
                    e
                ))
            })?;
            let pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
                &proof.public_inputs.to_u64_vec(),
                &balance_vd.common.config,
            )?;
            return Ok(pis);
        }

        unreachable!()
    }
}

pub struct BalanceSwichBoardTarget<const D: usize> {
    pub one_hot: [BoolTarget; 4], // initial_value, receive_transfer, receive_deposit, send_tx

    pub initial_value: (UserIdTarget, SaltTarget),
    pub receive_transfer_proof: ProofWithPublicInputsTarget<D>,
    pub receive_deposit_proof: ProofWithPublicInputsTarget<D>,
    pub send_tx_proof: ProofWithPublicInputsTarget<D>,
    pub balance_vd: VerifierCircuitTarget,

    pub new_pis: BalanceFullPublicInputsTarget,
}

impl<const D: usize> BalanceSwichBoardTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        balance_config: &CircuitConfig,
        receive_transfer_vd: &VerifierCircuitData<F, C, D>,
        receive_deposit_vd: &VerifierCircuitData<F, C, D>,
        send_tx_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // prepare balance vd
        let balance_vd = builder.add_virtual_verifier_data(balance_config.fri_config.cap_height);

        // create one-hot selector
        let one_hot: [BoolTarget; 4] = [
            builder.add_virtual_bool_target_safe(),
            builder.add_virtual_bool_target_safe(),
            builder.add_virtual_bool_target_safe(),
            builder.add_virtual_bool_target_safe(),
        ];
        // enforce one-hot
        let sum = one_hot
            .iter()
            .fold(builder.zero(), |acc, b| builder.add(acc, b.target));
        builder.assert_one(sum);

        let position = one_hot
            .iter()
            .enumerate()
            .fold(builder.zero(), |acc, (i, b)| {
                let i_const = builder.constant(F::from_canonical_u32(i as u32));
                let term = builder.mul(b.target, i_const);
                builder.add(acc, term)
            });

        // Case0: initial value
        let initial_user_id = UserIdTarget::new(builder, true);
        let initial_salt = SaltTarget::new(builder);
        let default_private_state = PrivateState::new(Salt::default());
        let initial_private_state = PrivateStateTarget {
            asset_tree_root: PoseidonHashOutTarget::constant(
                builder,
                default_private_state.asset_tree_root,
            ),
            nullifier_tree_root: PoseidonHashOutTarget::constant(
                builder,
                default_private_state.nullifier_tree_root,
            ),
            prev_private_commitment: PoseidonHashOutTarget::constant(
                builder,
                default_private_state.prev_private_commitment,
            ),
            nonce: builder.constant(F::from_canonical_u32(default_private_state.nonce)),
            salt: initial_salt,
        };
        let initial_private_commitment = initial_private_state.commitment(builder);
        let default_pis = BalancePublicInputs::new(UserId(0), Salt::default());
        let initial_pis = BalancePublicInputsTarget {
            user_id: initial_user_id.clone(),
            public_state: PublicStateTarget::constant(builder, &default_pis.public_state),
            block_r: BlockNumberTarget::constant(builder, default_pis.block_r),
            private_commitment: initial_private_commitment,
        };
        let new_pis0 = BalanceFullPublicInputsTarget {
            pis: initial_pis,
            vd: balance_vd.clone(),
        };

        // Case1: receive transfer proof
        let receive_transfer_proof =
            add_proof_target_and_conditionally_verify(receive_transfer_vd, builder, one_hot[1]);
        let new_pis1 = BalanceFullPublicInputsTarget::from_pis(
            &receive_transfer_proof.public_inputs,
            balance_config,
        );

        // Case2: receive deposit proof
        let receive_deposit_proof =
            add_proof_target_and_conditionally_verify(receive_deposit_vd, builder, one_hot[2]);
        let new_pis2 = BalanceFullPublicInputsTarget::from_pis(
            &receive_deposit_proof.public_inputs,
            balance_config,
        );

        // Case3: send tx proof
        let send_tx_proof =
            add_proof_target_and_conditionally_verify(send_tx_vd, builder, one_hot[3]);
        let new_pis3 =
            BalanceFullPublicInputsTarget::from_pis(&send_tx_proof.public_inputs, balance_config);

        // Selection
        let candidates = vec![
            new_pis0.clone(),
            new_pis1.clone(),
            new_pis2.clone(),
            new_pis3.clone(),
        ];

        let candidate_commitments = candidates
            .iter()
            .map(|pis| pis.commitment(builder, balance_config))
            .collect::<Vec<_>>();

        let candidate_hash_targets = candidate_commitments
            .iter()
            .map(|hash| HashOutTarget {
                elements: hash.elements,
            })
            .collect::<Vec<_>>();

        let selected_commitment = PoseidonHashOutTarget {
            elements: builder
                .random_access_hash(position, candidate_hash_targets)
                .elements,
        };
        let new_pis = BalanceFullPublicInputsTarget::new(builder, balance_config);
        let new_pis_commitment = new_pis.commitment(builder, balance_config);

        // enforce equality
        new_pis_commitment.connect(builder, selected_commitment);

        Self {
            one_hot,
            initial_value: (initial_user_id, initial_salt),
            receive_transfer_proof,
            receive_deposit_proof,
            send_tx_proof,
            balance_vd,
            new_pis,
        }
    }

    pub fn set_witness<F, C, W>(
        &self,
        witness: &mut W,
        value: &BalanceSwichBoard<F, C, D>,
        balance_vd: &VerifierCircuitData<F, C, D>,
        new_full_pis: &BalanceFullPublicInputs<F, C, D>,
        dummy_proofs: &HashMap<usize, ProofWithPublicInputs<F, C, D>>,
    ) -> Result<(), BalanceSwitchBoardError>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
        W: WitnessWrite<F>,
    {
        let flags = [
            value.initial_value.is_some(),
            value.receive_transfer_proof.is_some(),
            value.receive_deposit_proof.is_some(),
            value.send_tx_proof.is_some(),
        ];
        let total = flags.iter().filter(|f| **f).count();
        if total != 1 {
            return Err(BalanceSwitchBoardError::InvalidInput(
                "exactly one of initial value or proofs must be provided".to_string(),
            ));
        }

        for (flag, target) in flags.iter().zip(self.one_hot.iter()) {
            witness.set_bool_target(*target, *flag);
        }

        if let Some((user_id, salt)) = value.initial_value {
            self.initial_value.0.set_witness(witness, user_id);
            self.initial_value.1.set_witness(witness, salt);
        } else {
            self.initial_value.0.set_witness(witness, UserId(0));
            self.initial_value.1.set_witness(witness, Salt::default());
        }

        fn get_dummy_proof<F, C, const D: usize>(
            dummy_proofs: &HashMap<usize, ProofWithPublicInputs<F, C, D>>,
            index: usize,
        ) -> Result<&ProofWithPublicInputs<F, C, D>, BalanceSwitchBoardError>
        where
            F: RichField + Extendable<D>,
            C: GenericConfig<D, F = F>,
            <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
        {
            dummy_proofs
                .get(&index)
                .ok_or_else(|| BalanceSwitchBoardError::DummyProofNotProvided(index))
        }

        if let Some(proof) = &value.receive_transfer_proof {
            witness.set_proof_with_pis_target(&self.receive_transfer_proof, proof);
        } else {
            witness.set_proof_with_pis_target(
                &self.receive_transfer_proof,
                get_dummy_proof(dummy_proofs, 1)?,
            );
        }
        if let Some(proof) = &value.receive_deposit_proof {
            witness.set_proof_with_pis_target(&self.receive_deposit_proof, proof);
        } else {
            witness.set_proof_with_pis_target(
                &self.receive_deposit_proof,
                get_dummy_proof(dummy_proofs, 2)?,
            );
        }
        if let Some(proof) = &value.send_tx_proof {
            witness.set_proof_with_pis_target(&self.send_tx_proof, proof);
        } else {
            witness
                .set_proof_with_pis_target(&self.send_tx_proof, get_dummy_proof(dummy_proofs, 3)?);
        }

        witness.set_verifier_data_target(&self.balance_vd, &balance_vd.verifier_only);
        self.new_pis.set_witness(witness, new_full_pis);

        Ok(())
    }
}

pub struct BalanceSwichBoardCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub receive_transfer_vd: VerifierCircuitData<F, C, D>,
    pub receive_deposit_vd: VerifierCircuitData<F, C, D>,
    pub send_tx_vd: VerifierCircuitData<F, C, D>,
    pub dummy_proofs: HashMap<usize, ProofWithPublicInputs<F, C, D>>,
    pub target: BalanceSwichBoardTarget<D>,
    pub public_inputs: BalanceFullPublicInputsTarget,
}

impl<F, C, const D: usize> BalanceSwichBoardCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        balance_config: &CircuitConfig,
        receive_transfer_vd: &VerifierCircuitData<F, C, D>,
        receive_deposit_vd: &VerifierCircuitData<F, C, D>,
        send_tx_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let target = BalanceSwichBoardTarget::new::<F, C>(
            &mut builder,
            &balance_config,
            receive_transfer_vd,
            receive_deposit_vd,
            send_tx_vd,
        );
        let public_inputs = target.new_pis.clone();
        builder.register_public_inputs(&public_inputs.to_vec(&balance_config));
        let data = builder.build::<C>();

        // prepare dummy proofs
        let mut dummy_proofs = HashMap::new();
        for (i, vd) in [
            None,
            Some(receive_transfer_vd),
            Some(receive_deposit_vd),
            Some(send_tx_vd),
        ]
        .iter()
        .enumerate()
        {
            if let Some(vd) = vd {
                let dummy_proof = DummyProof::new(&vd.common);
                dummy_proofs.insert(i, dummy_proof.proof);
            }
        }

        Self {
            data,
            receive_transfer_vd: receive_transfer_vd.clone(),
            receive_deposit_vd: receive_deposit_vd.clone(),
            send_tx_vd: send_tx_vd.clone(),
            dummy_proofs,
            target,
            public_inputs,
        }
    }

    pub fn prove(
        &self,
        balance_vd: &VerifierCircuitData<F, C, D>,
        witness: &BalanceSwichBoard<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceSwitchBoardError> {
        let new_full_pis = witness.to_public_inputs(
            balance_vd,
            &self.receive_transfer_vd,
            &self.receive_deposit_vd,
            &self.send_tx_vd,
        )?;

        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(
            &mut pw,
            witness,
            balance_vd,
            &new_full_pis,
            &self.dummy_proofs,
        )?;
        self.public_inputs.set_witness(&mut pw, &new_full_pis);

        self.data
            .prove(pw)
            .map_err(|e| BalanceSwitchBoardError::FailedToProve(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::balance::balance_pis::BalanceFullPublicInputs,
        common::{
            block_number::BlockNumber, public_state::PublicState, salt::Salt, user_id::UserId,
        },
        utils::{conversion::ToField, cyclic::add_noop_gates, poseidon_hash_out::PoseidonHashOut},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_data::{CircuitConfig, CircuitData},
            config::PoseidonGoldilocksConfig,
        },
    };
    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    fn build_balance_circuit() -> (
        CircuitData<F, C, D>,
        BalanceFullPublicInputsTarget,
        CircuitConfig,
    ) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target = BalanceFullPublicInputsTarget::new(&mut builder, &config);
        builder.register_public_inputs(&target.to_vec(&config));
        add_noop_gates(&mut builder, 1 << 10);
        let data = builder.build::<C>();
        (data, target, config)
    }

    fn prove_balance(
        data: &CircuitData<F, C, D>,
        target: &BalanceFullPublicInputsTarget,
        pis: &BalanceFullPublicInputs<F, C, D>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let mut pw = PartialWitness::<F>::new();
        target.set_witness::<F, C, D, _>(&mut pw, pis);
        data.prove(pw).unwrap()
    }

    fn make_public_state(block: u64) -> PublicState {
        let root =
            PoseidonHashOut::from_u64_slice(&[block + 1, block + 2, block + 3, block + 4]).unwrap();
        PublicState {
            block_number: BlockNumber::new(block).unwrap(),
            account_tree_root: root,
            deposit_tree_root: root,
            prev_public_state_root: root,
        }
    }

    fn make_balance_full_inputs(
        user_id: UserId,
        block_r: u64,
        commitment_seed: u64,
        balance_vd: &VerifierCircuitData<F, C, D>,
    ) -> BalanceFullPublicInputs<F, C, D> {
        let public_state = make_public_state(block_r + 10);
        let private_commitment = PoseidonHashOut::from_u64_slice(&[
            commitment_seed,
            commitment_seed + 1,
            commitment_seed + 2,
            commitment_seed + 3,
        ])
        .unwrap();
        let pis = BalancePublicInputs {
            user_id,
            public_state,
            block_r: BlockNumber::new(block_r).unwrap(),
            private_commitment,
        };
        BalanceFullPublicInputs {
            pis,
            vd: balance_vd.verifier_only.clone(),
        }
    }

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_balance_switch_board_circuit() {
        let (balance_data, balance_target, balance_config) = build_balance_circuit();
        let balance_vd = balance_data.verifier_data();
        let balance_cd = balance_data.common.clone();

        let initial_user = UserId::new(0, 1).unwrap();
        let initial_salt = Salt::default();

        let transfer_pis = make_balance_full_inputs(UserId::new(0, 2).unwrap(), 5, 10, &balance_vd);
        let deposit_pis = make_balance_full_inputs(UserId::new(0, 3).unwrap(), 6, 20, &balance_vd);
        let send_pis = make_balance_full_inputs(UserId::new(0, 4).unwrap(), 7, 30, &balance_vd);

        let transfer_proof = prove_balance(&balance_data, &balance_target, &transfer_pis);
        let deposit_proof = prove_balance(&balance_data, &balance_target, &deposit_pis);
        let send_proof = prove_balance(&balance_data, &balance_target, &send_pis);

        let receive_transfer_vd = balance_vd.clone();
        let receive_deposit_vd = balance_vd.clone();
        let send_tx_vd = balance_vd.clone();

        let circuit = BalanceSwichBoardCircuit::new(
            &balance_cd.config,
            &receive_transfer_vd,
            &receive_deposit_vd,
            &send_tx_vd,
        );

        // Initial value scenario
        let witness_initial = BalanceSwichBoard {
            initial_value: Some((initial_user, initial_salt)),
            receive_transfer_proof: None,
            receive_deposit_proof: None,
            send_tx_proof: None,
        };

        let proof_initial = circuit.prove(&balance_vd, &witness_initial).unwrap();
        circuit.data.verify(proof_initial.clone()).unwrap();
        let expected_initial = witness_initial
            .to_public_inputs(
                &balance_vd,
                &receive_transfer_vd,
                &receive_deposit_vd,
                &send_tx_vd,
            )
            .unwrap();
        let expected_initial_fields = expected_initial
            .to_u64_vec(&balance_config)
            .to_field_vec::<F>();
        assert_eq!(proof_initial.public_inputs, expected_initial_fields);

        // Receive transfer scenario
        let witness_receive_transfer = BalanceSwichBoard {
            initial_value: None,
            receive_transfer_proof: Some(transfer_proof.clone()),
            receive_deposit_proof: None,
            send_tx_proof: None,
        };
        let proof_receive_transfer = circuit
            .prove(&balance_vd, &witness_receive_transfer)
            .unwrap();
        circuit.data.verify(proof_receive_transfer.clone()).unwrap();
        let expected_receive_transfer = witness_receive_transfer
            .to_public_inputs(
                &balance_vd,
                &receive_transfer_vd,
                &receive_deposit_vd,
                &send_tx_vd,
            )
            .unwrap();
        let expected_receive_transfer_fields = expected_receive_transfer
            .to_u64_vec(&balance_config)
            .to_field_vec::<F>();
        assert_eq!(
            proof_receive_transfer.public_inputs,
            expected_receive_transfer_fields
        );

        // Receive deposit scenario
        let witness_receive_deposit = BalanceSwichBoard {
            initial_value: None,
            receive_transfer_proof: None,
            receive_deposit_proof: Some(deposit_proof.clone()),
            send_tx_proof: None,
        };
        let proof_receive_deposit = circuit
            .prove(&balance_vd, &witness_receive_deposit)
            .unwrap();
        circuit.data.verify(proof_receive_deposit.clone()).unwrap();
        let expected_receive_deposit = witness_receive_deposit
            .to_public_inputs(
                &balance_vd,
                &receive_transfer_vd,
                &receive_deposit_vd,
                &send_tx_vd,
            )
            .unwrap();
        let expected_receive_deposit_fields = expected_receive_deposit
            .to_u64_vec(&balance_config)
            .to_field_vec::<F>();
        assert_eq!(
            proof_receive_deposit.public_inputs,
            expected_receive_deposit_fields
        );

        // Send tx scenario
        let witness_send_tx = BalanceSwichBoard {
            initial_value: None,
            receive_transfer_proof: None,
            receive_deposit_proof: None,
            send_tx_proof: Some(send_proof.clone()),
        };
        let proof_send_tx = circuit.prove(&balance_vd, &witness_send_tx).unwrap();
        circuit.data.verify(proof_send_tx.clone()).unwrap();
        let expected_send_tx = witness_send_tx
            .to_public_inputs(
                &balance_vd,
                &receive_transfer_vd,
                &receive_deposit_vd,
                &send_tx_vd,
            )
            .unwrap();
        let expected_send_tx_fields = expected_send_tx
            .to_u64_vec(&balance_config)
            .to_field_vec::<F>();
        assert_eq!(proof_send_tx.public_inputs, expected_send_tx_fields);
    }
}
