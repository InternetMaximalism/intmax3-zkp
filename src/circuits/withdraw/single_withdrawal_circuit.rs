use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
    recursion::cyclic_recursion::check_cyclic_proof_verifier_data,
};
use thiserror::Error;

use crate::{
    circuits::balance::common::transfer_witness::TransferWitness,
    common::{
        private_state::PrivateState,
        public_state::{PUBLIC_STATE_U64_LEN, PublicState, PublicStateError, PublicStateTarget},
        trees::sent_tx_tree::SentTxMerkleProof,
        tx::Tx,
        withdrawal::{WITHDRAWAL_LEN, Withdrawal, WithdrawalTarget},
    },
};

pub const SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN: usize = PUBLIC_STATE_U64_LEN + WITHDRAWAL_LEN;

pub struct SingleWithdawalPublicInputs {
    pub public_state: PublicState,
    pub withdraw: Withdrawal,
}

#[derive(Debug, Error)]
pub enum SingleWithdawalPublicInputsError {
    #[error("Invalid public inputs length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Failed to parse public state: {0}")]
    PublicState(#[from] PublicStateError),

    #[error("Failed to parse withdrawal: {0}")]
    Withdrawal(String),
}

impl SingleWithdawalPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let mut limbs = self.public_state.to_u64_vec();
        limbs.extend(self.withdraw.to_u32_vec().into_iter().map(|x| x as u64));
        limbs
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, SingleWithdawalPublicInputsError> {
        if values.len() != SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN {
            return Err(SingleWithdawalPublicInputsError::InvalidLength {
                expected: SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN,
                actual: values.len(),
            });
        }

        let mut cursor = 0;

        let public_state =
            PublicState::from_u64_slice(&values[cursor..cursor + PUBLIC_STATE_U64_LEN])?;
        cursor += PUBLIC_STATE_U64_LEN;

        let withdraw_slice = &values[cursor..cursor + WITHDRAWAL_LEN];
        let withdraw = Withdrawal::from_u64_slice(withdraw_slice)
            .map_err(|e| SingleWithdawalPublicInputsError::Withdrawal(e.to_string()))?;

        Ok(Self {
            public_state,
            withdraw,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SingleWithdawalPublicInputsTarget {
    pub public_state: PublicStateTarget,
    pub withdraw: WithdrawalTarget,
}

impl SingleWithdawalPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        [self.public_state.to_vec(), self.withdraw.to_vec()].concat()
    }

    pub fn from_vec(values: &[Target]) -> Self {
        assert_eq!(
            values.len(),
            SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN,
            "SingleWithdawalPublicInputsTarget::from_vec length mismatch",
        );

        let mut cursor = 0;

        let public_state =
            PublicStateTarget::from_slice(&values[cursor..cursor + PUBLIC_STATE_U64_LEN]);
        cursor += PUBLIC_STATE_U64_LEN;

        let withdraw = WithdrawalTarget::from_slice(&values[cursor..cursor + WITHDRAWAL_LEN]);

        Self {
            public_state,
            withdraw,
        }
    }
}

#[derive(Debug, Error)]
pub enum SingleWithdawalWitnessError {}

pub struct SingleWithdawalWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // the balance proof of the user performing the withdrawal
    // it must contain the withdrawal in its sent tx tree
    pub balance_proof: ProofWithPublicInputs<F, C, D>,

    // the private state of the balance proof
    pub private_state: PrivateState,

    // the tx that contains the withdrawal
    pub tx: Tx,

    // the sent tx merkle proof of the tx
    pub sent_tx_merkle_proof: SentTxMerkleProof,

    // the transfer witness of the withdrawal
    pub transfer_witness: TransferWitness,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SingleWithdawalWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        balance_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<SingleWithdawalPublicInputs, SingleWithdawalWitnessError> {
        // verify the balance proof

        // check the commmitment of the private state

        // verify the sent tx merkle proof

        // verify the transfer witness

        // convert transfer to withdrawal

        todo!()
    }
}
