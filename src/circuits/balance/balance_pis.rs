use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};
use thiserror::Error;

use crate::{
    common::{
        block_number::{BlockNumber, BlockNumberTarget},
        public_state::{PUBLIC_STATE_U64_LEN, PublicState, PublicStateTarget},
        user_id::{UserId, UserIdTarget},
    },
    utils::poseidon_hash_out::{POSEIDON_HASH_OUT_LEN, PoseidonHashOut, PoseidonHashOutTarget},
};

pub const BALANCE_PUBLIC_INPUTS_LEN: usize = 1 + PUBLIC_STATE_U64_LEN + 1 + POSEIDON_HASH_OUT_LEN;

#[derive(Debug, Error)]
pub enum BalancePublicInputsError {
    #[error("Invalid public inputs length: got {0}")]
    InvalidLength(usize),
    #[error("Failed to parse {field}: {message}")]
    ParseError {
        field: &'static str,
        message: String,
    },
}

#[derive(Clone, Debug)]
pub struct BalancePublicInputs {
    // User ID of the balance owner.
    pub user_id: UserId,

    // Onchain state reference. Usually the latest state.
    pub public_state: PublicState,

    /*
     * Block number when the balance is guaranteed to be
     * sufficient. block_r <= public_state.block_number must
     * hold.
     */
    pub block_r: BlockNumber,

    // Commitment of private state.
    pub private_commitment: PoseidonHashOut,
}

impl BalancePublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            vec![self.user_id.0],
            self.public_state.to_u64_vec(),
            self.block_r.to_u64_vec(),
            self.private_commitment.to_u64_vec(),
        ]
        .concat()
    }

    pub fn from_pis_u64(pis: &[u64]) -> Result<Self, BalancePublicInputsError> {
        if pis.len() <= BALANCE_PUBLIC_INPUTS_LEN {
            return Err(BalancePublicInputsError::InvalidLength(pis.len()));
        }

        let mut cursor = 0;

        let user_id = UserId(pis[cursor]);
        cursor += 1;

        let ps_block_number_u64 = pis[cursor];
        let ps_block_number = BlockNumber::new(ps_block_number_u64).map_err(|e| {
            BalancePublicInputsError::ParseError {
                field: "public_state.block_number",
                message: e.to_string(),
            }
        })?;
        cursor += 1;

        let account_tree_root =
            PoseidonHashOut::from_u64_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .expect("public_state.account_tree_root must deserialize");
        cursor += POSEIDON_HASH_OUT_LEN;
        let deposit_tree_root =
            PoseidonHashOut::from_u64_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .expect("public_state.deposit_tree_root must deserialize");
        cursor += POSEIDON_HASH_OUT_LEN;
        let prev_public_state_root =
            PoseidonHashOut::from_u64_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .expect("public_state.prev_public_state_root must deserialize");
        cursor += POSEIDON_HASH_OUT_LEN;

        let public_state = PublicState {
            block_number: ps_block_number,
            account_tree_root,
            deposit_tree_root,
            prev_public_state_root,
        };

        let block_r_u64 = pis[cursor];
        let block_r =
            BlockNumber::new(block_r_u64).map_err(|e| BalancePublicInputsError::ParseError {
                field: "block_r",
                message: e.to_string(),
            })?;
        cursor += 1;

        let private_commitment =
            PoseidonHashOut::from_u64_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .expect("private_commitment must deserialize");

        Ok(Self {
            user_id,
            public_state,
            block_r,
            private_commitment,
        })
    }
}

#[derive(Clone, Debug)]
pub struct BalancePublicInputsTarget {
    pub user_id: UserIdTarget,
    pub public_state: PublicStateTarget,
    pub block_r: BlockNumberTarget,
    pub private_commitment: PoseidonHashOutTarget,
}

impl BalancePublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        [
            vec![self.user_id.value],
            self.public_state.to_vec(),
            vec![self.block_r.value],
            self.private_commitment.to_vec(),
        ]
        .concat()
    }

    pub fn from_pis(pis: &[Target]) -> Self {
        assert!(pis.len() >= BALANCE_PUBLIC_INPUTS_LEN);
        let mut cursor = 0;

        let user_id = UserIdTarget { value: pis[cursor] };
        cursor += 1;

        let ps_block_number = BlockNumberTarget { value: pis[cursor] };
        cursor += 1;

        let account_tree_root =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;
        let deposit_tree_root =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;
        let prev_public_state_root =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let public_state = PublicStateTarget {
            block_number: ps_block_number,
            account_tree_root,
            deposit_tree_root,
            prev_public_state_root,
        };

        let block_r = BlockNumberTarget { value: pis[cursor] };
        cursor += 1;

        let private_commitment =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);

        Self {
            user_id,
            public_state,
            block_r,
            private_commitment,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &BalancePublicInputs,
    ) {
        self.user_id.set_witness(witness, value.user_id);
        self.public_state.set_witness(witness, &value.public_state);
        self.block_r.set_witness(witness, value.block_r);
        self.private_commitment
            .set_witness(witness, value.private_commitment);
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        builder.connect(self.user_id.value, other.user_id.value);
        builder.connect(
            self.public_state.block_number.value,
            other.public_state.block_number.value,
        );
        self.public_state
            .account_tree_root
            .connect(builder, other.public_state.account_tree_root);
        self.public_state
            .deposit_tree_root
            .connect(builder, other.public_state.deposit_tree_root);
        self.public_state
            .prev_public_state_root
            .connect(builder, other.public_state.prev_public_state_root);
        builder.connect(self.block_r.value, other.block_r.value);
        self.private_commitment
            .connect(builder, other.private_commitment);
    }
}
