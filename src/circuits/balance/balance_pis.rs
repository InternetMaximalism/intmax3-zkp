use std::fmt::Debug;

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
    },
};
use thiserror::Error;

use crate::{
    common::{
        block_number::{BlockNumber, BlockNumberTarget},
        public_state::{PUBLIC_STATE_U64_LEN, PublicState, PublicStateTarget},
        user_id::{UserId, UserIdTarget},
    },
    utils::{
        conversion::{ToField as _, ToU64},
        cyclic::{
            vd_from_pis_slice, vd_from_pis_slice_target, vd_to_vec, vd_to_vec_target, vd_vec_len,
        },
        poseidon_hash_out::{POSEIDON_HASH_OUT_LEN, PoseidonHashOut, PoseidonHashOutTarget},
    },
};

pub const BALANCE_PUBLIC_INPUTS_LEN: usize = 1 + PUBLIC_STATE_U64_LEN + 1 + POSEIDON_HASH_OUT_LEN;

#[derive(Debug, Error)]
pub enum BalancePublicInputsError {
    #[error("Invalid public inputs length: {0}")]
    InvalidLength(String),
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

    pub fn from_u64(pis: &[u64]) -> Result<Self, BalancePublicInputsError> {
        if pis.len() != BALANCE_PUBLIC_INPUTS_LEN {
            return Err(BalancePublicInputsError::InvalidLength(format!(
                "Expected {}, got {}",
                BALANCE_PUBLIC_INPUTS_LEN,
                pis.len()
            )));
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
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            user_id: UserIdTarget::new(builder, is_checked),
            public_state: PublicStateTarget::new(builder, is_checked),
            block_r: BlockNumberTarget::new(builder, is_checked),
            private_commitment: PoseidonHashOutTarget::new(builder),
        }
    }

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
        assert!(pis.len() != BALANCE_PUBLIC_INPUTS_LEN);
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
        self.public_state.connect(builder, &other.public_state);
        builder.connect(self.block_r.value, other.block_r.value);
        self.private_commitment
            .connect(builder, other.private_commitment);
    }
}

// #[derive(Clone, Debug)]
// pub struct BalancePisBeforeAfter {
//     pub before: BalancePublicInputs,
//     pub after: BalancePublicInputs,
// }

// impl BalancePisBeforeAfter {
//     pub fn to_u64_vec(&self) -> Vec<u64> {
//         [self.before.to_u64_vec(), self.after.to_u64_vec()].concat()
//     }

//     pub fn from_u64(pis: &[u64]) -> Result<Self, BalancePublicInputsError> {
//         if pis.len() <= 2 * BALANCE_PUBLIC_INPUTS_LEN {
//             return Err(BalancePublicInputsError::InvalidLength(pis.len()));
//         }
//         let before = BalancePublicInputs::from_u64(&pis[0..BALANCE_PUBLIC_INPUTS_LEN])?;
//         let after = BalancePublicInputs::from_u64(
//             &pis[BALANCE_PUBLIC_INPUTS_LEN..2 * BALANCE_PUBLIC_INPUTS_LEN],
//         )?;
//         Ok(Self { before, after })
//     }
// }

// #[derive(Clone, Debug)]
// pub struct BalancePisBeforeAfterTarget {
//     pub before: BalancePublicInputsTarget,
//     pub after: BalancePublicInputsTarget,
// }

// impl BalancePisBeforeAfterTarget {
//     pub fn to_vec(&self) -> Vec<Target> {
//         [self.before.to_vec(), self.after.to_vec()].concat()
//     }

//     pub fn from_pis(pis: &[Target]) -> Self {
//         assert!(pis.len() >= 2 * BALANCE_PUBLIC_INPUTS_LEN);
//         let before = BalancePublicInputsTarget::from_pis(&pis[0..BALANCE_PUBLIC_INPUTS_LEN]);
//         let after = BalancePublicInputsTarget::from_pis(
//             &pis[BALANCE_PUBLIC_INPUTS_LEN..2 * BALANCE_PUBLIC_INPUTS_LEN],
//         );
//         Self { before, after }
//     }

//     pub fn connect<F: RichField + Extendable<D>, const D: usize>(
//         &self,
//         builder: &mut CircuitBuilder<F, D>,
//         other: &Self,
//     ) {
//         self.before.connect(builder, &other.before);
//         self.after.connect(builder, &other.after);
//     }
// }

#[derive(Clone, Debug)]
pub struct BalanceFullPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub pis: BalancePublicInputs,
    pub vd: VerifierOnlyCircuitData<C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    BalanceFullPublicInputs<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_u64_vec(&self, config: &CircuitConfig) -> Vec<u64> {
        [
            self.pis.to_u64_vec(),
            vd_to_vec(config, &self.vd).to_u64_vec(),
        ]
        .concat()
    }

    pub fn from_u64_slice(
        inputs: &[u64],
        config: &CircuitConfig,
    ) -> Result<Self, BalancePublicInputsError> {
        let vd_len = vd_vec_len(config);
        if inputs.len() != BALANCE_PUBLIC_INPUTS_LEN + vd_len {
            return Err(BalancePublicInputsError::InvalidLength(format!(
                "Expected {}, got {}",
                BALANCE_PUBLIC_INPUTS_LEN + vd_len,
                inputs.len()
            )));
        }
        let vd_slice = &inputs[BALANCE_PUBLIC_INPUTS_LEN..BALANCE_PUBLIC_INPUTS_LEN + vd_len];
        let pis = BalancePublicInputs::from_u64(&inputs[0..BALANCE_PUBLIC_INPUTS_LEN])?;
        let vd = vd_from_pis_slice(&vd_slice.to_field_vec(), config).map_err(|e| {
            BalancePublicInputsError::ParseError {
                field: "verifier data",
                message: e.to_string(),
            }
        })?;
        Ok(Self { pis, vd })
    }
}

#[derive(Clone, Debug)]
pub struct BalanceFullPublicInputsTarget {
    pub pis: BalancePublicInputsTarget,
    pub vd: VerifierCircuitTarget,
}

impl BalanceFullPublicInputsTarget {
    pub fn to_vec(&self, config: &CircuitConfig) -> Vec<Target> {
        [self.pis.to_vec(), vd_to_vec_target(config, &self.vd)].concat()
    }

    pub fn from_pis(pis: &[Target], config: &CircuitConfig) -> Self {
        let vd_len = vd_vec_len(config);
        assert!(pis.len() >= BALANCE_PUBLIC_INPUTS_LEN + vd_len);
        let vd_slice = &pis[BALANCE_PUBLIC_INPUTS_LEN..BALANCE_PUBLIC_INPUTS_LEN + vd_len];
        let pis = BalancePublicInputsTarget::from_pis(&pis[0..BALANCE_PUBLIC_INPUTS_LEN]);
        let vd = vd_from_pis_slice_target(vd_slice, config)
            .expect("vd_from_pis_slice_target should not fail");
        Self { pis, vd }
    }

    pub fn set_witness<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
        W: WitnessWrite<F>,
    >(
        &self,
        witness: &mut W,
        value: &BalanceFullPublicInputs<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.pis.set_witness(witness, &value.pis);
        witness.set_verifier_data_target(&self.vd, &value.vd);
    }
}
