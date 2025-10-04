use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256, utils::solidity_keccak256};
use serde::{Deserialize, Serialize};

use crate::ethereum_types::{
    address::{ADDRESS_LEN, Address, AddressTarget},
    bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
    u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    u256::{U256, U256_LEN, U256Target},
};

pub const WITHDRAWAL_LEN: usize = ADDRESS_LEN + 1 + U256_LEN + 2 * BYTES32_LEN;

/// A withdrawal that is processed in the withdrawal contract.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    pub recipient: Address, // The recipient of the withdrawal
    pub token_index: u32,   // The index of the token
    pub amount: U256,       // The amount of the token
    pub nullifier: Bytes32, // The nullifier which is used to prevent double withdrawal
    pub aux_data: Bytes32,  // Auxiliary data for the withdrawal, e.g. cross-chain withdrawal
}

#[derive(Debug, Clone)]
pub struct WithdrawalTarget {
    pub recipient: AddressTarget,
    pub token_index: Target,
    pub amount: U256Target,
    pub nullifier: Bytes32Target,
    pub aux_data: Bytes32Target,
}

impl Withdrawal {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let result = [
            self.recipient.to_u32_vec(),
            vec![self.token_index],
            self.amount.to_u32_vec(),
            self.nullifier.to_u32_vec(),
            self.aux_data.to_u32_vec(),
        ]
        .concat();
        assert_eq!(result.len(), WITHDRAWAL_LEN);
        result
    }

    pub fn from_u32_slice(slice: &[u32]) -> Result<Self, crate::common::error::CommonError> {
        if slice.len() != WITHDRAWAL_LEN {
            return Err(crate::common::error::CommonError::InvalidData(format!(
                "Invalid input length for Withdrawal: expected {}, got {}",
                WITHDRAWAL_LEN,
                slice.len()
            )));
        }
        let recipient = Address::from_u32_slice(&slice[0..ADDRESS_LEN]).unwrap();
        let token_index = slice[ADDRESS_LEN];
        let amount =
            U256::from_u32_slice(&slice[ADDRESS_LEN + 1..ADDRESS_LEN + 1 + U256_LEN]).unwrap();
        let nullifier = Bytes32::from_u32_slice(
            &slice[ADDRESS_LEN + 1 + U256_LEN..ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN],
        )
        .unwrap();
        let aux_data = Bytes32::from_u32_slice(
            &slice[ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN
                ..ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN + BYTES32_LEN],
        )
        .unwrap();
        Ok(Self {
            recipient,
            token_index,
            amount,
            nullifier,
            aux_data,
        })
    }

    pub fn from_u64_slice(slice: &[u64]) -> Result<Withdrawal, super::error::CommonError> {
        let u32_slice: Vec<u32> = slice
            .iter()
            .map(|&x| {
                assert!(x <= u32::MAX as u64);
                x as u32
            })
            .collect();
        Self::from_u32_slice(&u32_slice)
    }

    pub fn hash_with_prev_hash(&self, prev_withdrawal_hash: Bytes32) -> Bytes32 {
        let input = [prev_withdrawal_hash.to_u32_vec(), self.to_u32_vec()].concat();
        Bytes32::from_u32_slice(&solidity_keccak256(&input)).unwrap()
    }

    pub fn rand<R: rand::Rng>(rng: &mut R) -> Self {
        Self {
            recipient: Address::rand(rng),
            token_index: rng.r#gen(),
            amount: U256::rand_small(rng),
            nullifier: Bytes32::rand(rng),
            aux_data: Bytes32::rand(rng),
        }
    }
}

impl WithdrawalTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let result = [
            self.recipient.to_vec(),
            vec![self.token_index],
            self.amount.to_vec(),
            self.nullifier.to_vec(),
            self.aux_data.to_vec(),
        ]
        .concat();
        assert_eq!(result.len(), WITHDRAWAL_LEN);
        result
    }

    pub fn from_slice(slice: &[Target]) -> Self {
        assert_eq!(slice.len(), WITHDRAWAL_LEN);
        let recipient = AddressTarget::from_slice(&slice[0..ADDRESS_LEN]);
        let token_index = slice[ADDRESS_LEN];
        let amount = U256Target::from_slice(&slice[ADDRESS_LEN + 1..ADDRESS_LEN + 1 + U256_LEN]);
        let nullifier = Bytes32Target::from_slice(
            &slice[ADDRESS_LEN + 1 + U256_LEN..ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN],
        );
        let aux_data = Bytes32Target::from_slice(
            &slice[ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN
                ..ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN + BYTES32_LEN],
        );
        Self {
            recipient,
            token_index,
            amount,
            nullifier,
            aux_data,
        }
    }

    pub fn hash_with_prev_hash<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        prev_withdrawal_hash: Bytes32Target,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let input = [prev_withdrawal_hash.to_vec(), self.to_vec()].concat();
        Bytes32Target::from_slice(&builder.keccak256::<C>(&input))
    }
}
