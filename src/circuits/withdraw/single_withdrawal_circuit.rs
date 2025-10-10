use plonky2::iop::target::Target;
use thiserror::Error;

use crate::common::{
    public_state::{PublicState, PublicStateError, PublicStateTarget, PUBLIC_STATE_U64_LEN},
    withdrawal::{Withdrawal, WithdrawalTarget, WITHDRAWAL_LEN},
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

        let public_state = PublicState::from_u64_slice(&values[cursor..cursor + PUBLIC_STATE_U64_LEN])?;
        cursor += PUBLIC_STATE_U64_LEN;

        let withdraw_slice = &values[cursor..cursor + WITHDRAWAL_LEN];
        let withdraw = Withdrawal::from_u64_slice(withdraw_slice).map_err(|e| {
            SingleWithdawalPublicInputsError::Withdrawal(e.to_string())
        })?;

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

        let public_state = PublicStateTarget::from_slice(&values[cursor..cursor + PUBLIC_STATE_U64_LEN]);
        cursor += PUBLIC_STATE_U64_LEN;

        let withdraw = WithdrawalTarget::from_slice(&values[cursor..cursor + WITHDRAWAL_LEN]);

        Self {
            public_state,
            withdraw,
        }
    }
}
