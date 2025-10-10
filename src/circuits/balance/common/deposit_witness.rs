use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::witness::WitnessWrite,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::{
    circuits::balance::common::recipient::{
        calculate_recipient_from_user_id, calculate_recipient_from_user_id_circuit,
    },
    common::{
        deposit::{Deposit, DepositTarget},
        salt::{Salt, SaltTarget},
        trees::deposit_tree::{DepositMerkleProof, DepositMerkleProofTarget},
        user_id::{UserId, UserIdTarget},
    },
    constants::DEPOSIT_TREE_HEIGHT,
    ethereum_types::u32limb_trait::U32LimbTargetTrait as _,
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

#[derive(Debug, thiserror::Error)]
pub enum DepositWitnessError {
    #[error("Invalid deposit index: {0}")]
    InvalidDepositIndex(String),

    #[error("Invalid deposit merkle proof: {0}")]
    InvalidDepositMerkleProof(String),

    #[error("Invalid recipient in deposit")]
    InvalidRecipient(String),
}

#[derive(Clone, Debug)]
pub struct DepositWitness {
    pub user_id: UserId,
    pub deposit_tree_root: PoseidonHashOut,
    pub deposit_salt: Salt,
    pub deposit: Deposit,
    pub deposit_merkle_proof: DepositMerkleProof,
}

#[derive(Clone, Debug)]
pub struct DepositWitnessTarget {
    pub user_id: UserIdTarget,
    pub deposit_tree_root: PoseidonHashOutTarget,
    pub deposit_salt: SaltTarget,
    pub deposit: DepositTarget,
    pub deposit_merkle_proof: DepositMerkleProofTarget,
}

impl DepositWitness {
    pub fn new(
        user_id: UserId,
        deposit_tree_root: PoseidonHashOut,
        deposit_salt: Salt,
        deposit: Deposit,
        deposit_merkle_proof: DepositMerkleProof,
    ) -> Result<Self, DepositWitnessError> {
        let witness = Self {
            user_id,
            deposit_tree_root,
            deposit_salt,
            deposit,
            deposit_merkle_proof,
        };
        witness.verify()?;
        Ok(witness)
    }

    pub fn verify(&self) -> Result<(), DepositWitnessError> {
        let deposit_index = self.deposit.deposit_index.as_u64();
        if deposit_index >= (1 << crate::constants::DEPOSIT_TREE_HEIGHT) {
            return Err(DepositWitnessError::InvalidDepositIndex(format!(
                "index {} is out of range",
                deposit_index
            )));
        }

        // verify the Merkle proof.
        self.deposit_merkle_proof
            .verify(&self.deposit, deposit_index, self.deposit_tree_root)
            .map_err(|e| DepositWitnessError::InvalidDepositMerkleProof(e.to_string()))?;

        // verify the deposit's user_id and salt.
        let expected_recpient = calculate_recipient_from_user_id(self.user_id, self.deposit_salt);
        if self.deposit.recipient != expected_recpient {
            return Err(DepositWitnessError::InvalidRecipient(format!(
                "expected {}, got {}",
                expected_recpient, self.deposit.recipient
            )));
        }
        Ok(())
    }
}

impl DepositWitnessTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let user_id = UserIdTarget::new(builder, is_checked);
        let deposit_tree_root = PoseidonHashOutTarget::new(builder);
        let deposit_salt = SaltTarget::new(builder);
        let deposit = DepositTarget::new(builder, is_checked);
        let deposit_merkle_proof = DepositMerkleProofTarget::new(builder, DEPOSIT_TREE_HEIGHT);

        deposit_merkle_proof.verify::<F, C, D>(
            builder,
            &deposit,
            deposit.deposit_index.value,
            deposit_tree_root,
        );

        let expected_recipient =
            calculate_recipient_from_user_id_circuit(builder, &user_id, &deposit_salt);
        deposit.recipient.connect(builder, expected_recipient);

        Self {
            user_id,
            deposit_tree_root,
            deposit_salt,
            deposit,
            deposit_merkle_proof,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &DepositWitness,
    ) {
        self.user_id.set_witness(witness, value.user_id);
        self.deposit_tree_root
            .set_witness(witness, value.deposit_tree_root);
        self.deposit_salt.set_witness(witness, value.deposit_salt);
        self.deposit.set_witness(witness, &value.deposit);
        self.deposit_merkle_proof
            .set_witness(witness, &value.deposit_merkle_proof);
    }
}
