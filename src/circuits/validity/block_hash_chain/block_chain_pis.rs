use plonky2::{
    field::extension::Extendable,
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
    common::public_state::{
        PUBLIC_STATE_U64_LEN, PublicState, PublicStateError, PublicStateTarget,
    },
    utils::{
        conversion::{ToField as _, ToU64},
        cyclic::{
            vd_from_pis_slice, vd_from_pis_slice_target, vd_to_vec, vd_to_vec_target, vd_vec_len,
        },
    },
};

pub const BLOCK_CHAIN_PUBLIC_INPUTS_LEN: usize = 2 * PUBLIC_STATE_U64_LEN;

#[derive(Debug, Error)]
pub enum BlockChainPublicInputsError {
    #[error("Invalid public inputs length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Failed to parse {field}: {message}")]
    ParseError {
        field: &'static str,
        message: String,
    },
}

pub struct BlockChainPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub initial_public_state: PublicState,
    pub public_state: PublicState,
    pub vd: VerifierOnlyCircuitData<C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    BlockChainPublicInputs<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_u64_vec(&self, config: &CircuitConfig) -> Vec<u64> {
        [
            self.initial_public_state.to_u64_vec(),
            self.public_state.to_u64_vec(),
            vd_to_vec(config, &self.vd).to_u64_vec(),
        ]
        .concat()
    }

    pub fn from_u64_slice(
        inputs: &[u64],
        config: &CircuitConfig,
    ) -> Result<Self, BlockChainPublicInputsError> {
        let vd_len = vd_vec_len(config);
        let expected = BLOCK_CHAIN_PUBLIC_INPUTS_LEN + vd_len;
        if inputs.len() != expected {
            return Err(BlockChainPublicInputsError::InvalidLength {
                expected,
                actual: inputs.len(),
            });
        }

        let mut cursor = 0;

        let initial_public_state =
            PublicState::from_u64_slice(&inputs[cursor..cursor + PUBLIC_STATE_U64_LEN]).map_err(
                |e: PublicStateError| BlockChainPublicInputsError::ParseError {
                    field: "initial_public_state",
                    message: e.to_string(),
                },
            )?;
        cursor += PUBLIC_STATE_U64_LEN;

        let public_state =
            PublicState::from_u64_slice(&inputs[cursor..cursor + PUBLIC_STATE_U64_LEN]).map_err(
                |e: PublicStateError| BlockChainPublicInputsError::ParseError {
                    field: "public_state",
                    message: e.to_string(),
                },
            )?;
        cursor += PUBLIC_STATE_U64_LEN;

        let vd_slice = &inputs[cursor..cursor + vd_len];
        let vd = vd_from_pis_slice::<F, C, D>(&vd_slice.to_field_vec(), config).map_err(|e| {
            BlockChainPublicInputsError::ParseError {
                field: "verifier data",
                message: e.to_string(),
            }
        })?;

        Ok(Self {
            initial_public_state,
            public_state,
            vd,
        })
    }
}

#[derive(Clone, Debug)]
pub struct BlockChainPublicInputsTarget {
    pub initial_public_state: PublicStateTarget,
    pub public_state: PublicStateTarget,
    pub vd: VerifierCircuitTarget,
}

impl BlockChainPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        config: &CircuitConfig,
    ) -> Self {
        Self {
            initial_public_state: PublicStateTarget::new(builder, true),
            public_state: PublicStateTarget::new(builder, true),
            vd: builder.add_virtual_verifier_data(config.fri_config.cap_height),
        }
    }

    pub fn to_vec(&self, config: &CircuitConfig) -> Vec<Target> {
        [
            self.initial_public_state.to_vec(),
            self.public_state.to_vec(),
            vd_to_vec_target(config, &self.vd),
        ]
        .concat()
    }

    pub fn from_pis(pis: &[Target], config: &CircuitConfig) -> Self {
        let vd_len = vd_vec_len(config);
        assert!(pis.len() >= BLOCK_CHAIN_PUBLIC_INPUTS_LEN + vd_len);

        let mut cursor = 0;

        let initial_public_state =
            PublicStateTarget::from_slice(&pis[cursor..cursor + PUBLIC_STATE_U64_LEN]);
        cursor += PUBLIC_STATE_U64_LEN;

        let public_state =
            PublicStateTarget::from_slice(&pis[cursor..cursor + PUBLIC_STATE_U64_LEN]);
        cursor += PUBLIC_STATE_U64_LEN;

        let vd_slice = &pis[cursor..cursor + vd_len];
        let vd = vd_from_pis_slice_target(vd_slice, config)
            .expect("vd_from_pis_slice_target should not fail");

        Self {
            initial_public_state,
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
        value: &BlockChainPublicInputs<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.initial_public_state
            .set_witness(witness, &value.initial_public_state);
        self.public_state.set_witness(witness, &value.public_state);
        witness.set_verifier_data_target(&self.vd, &value.vd);
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        self.initial_public_state
            .connect(builder, &other.initial_public_state);
        self.public_state.connect(builder, &other.public_state);
        builder.connect_verifier_data(&self.vd, &other.vd);
    }
}
