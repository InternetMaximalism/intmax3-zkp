use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::BoolTarget,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget},
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
        conversion::ToU64, poseidon_hash_out::PoseidonHashOutTarget,
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
            .map(|pis| HashOutTarget {
                elements: pis.commitment(builder, balance_config).elements,
            })
            .collect::<Vec<_>>();

        let selected_commitment = PoseidonHashOutTarget {
            elements: builder
                .random_access_hash(position, candidate_commitments)
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
}
