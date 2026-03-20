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
    common::u63::{BlockNumber, BlockNumberTarget, U63, U63Target},
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::{
        conversion::{ToField as _, ToU64},
        cyclic::{
            vd_from_pis_slice, vd_from_pis_slice_target, vd_to_vec, vd_to_vec_target, vd_vec_len,
        },
        poseidon_hash_out::{POSEIDON_HASH_OUT_LEN, PoseidonHashOut, PoseidonHashOutTarget},
    },
};

/// Public inputs for the forced tx hash chain circuit.
///
/// Unlike the deposit chain (which tracks deposit_tree_root), the forced tx chain
/// tracks account_tree_root because forced txs update the account tree directly
/// (adding SendLeaf entries without signature verification).
///
/// Length: 2*BYTES32 + 2*POSEIDON_HASH_OUT + 3 scalar fields (two counts + block_number)
pub const FORCED_TX_CHAIN_PUBLIC_INPUTS_LEN: usize =
    2 * BYTES32_LEN + 2 * POSEIDON_HASH_OUT_LEN + 3;

#[derive(Debug, Error)]
pub enum ForcedTxChainPublicInputsError {
    #[error("Invalid public inputs length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("Failed to parse {field}: {message}")]
    ParseError {
        field: &'static str,
        message: String,
    },
}

pub struct ForcedTxChainPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub initial_forced_tx_hash_chain: Bytes32,
    pub initial_account_tree_root: PoseidonHashOut,
    pub initial_forced_tx_count: U63,
    pub forced_tx_hash_chain: Bytes32,
    pub account_tree_root: PoseidonHashOut,
    pub forced_tx_count: U63,
    pub block_number: BlockNumber,
    pub vd: VerifierOnlyCircuitData<C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ForcedTxChainPublicInputs<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_u64_vec(&self, config: &CircuitConfig) -> Vec<u64> {
        [
            self.initial_forced_tx_hash_chain.to_u64_vec(),
            self.initial_account_tree_root.to_u64_vec(),
            self.initial_forced_tx_count.to_u64_vec(),
            self.forced_tx_hash_chain.to_u64_vec(),
            self.account_tree_root.to_u64_vec(),
            self.forced_tx_count.to_u64_vec(),
            self.block_number.to_u64_vec(),
            vd_to_vec(config, &self.vd).to_u64_vec(),
        ]
        .concat()
    }

    pub fn from_u64_slice(
        inputs: &[u64],
        config: &CircuitConfig,
    ) -> Result<Self, ForcedTxChainPublicInputsError> {
        let vd_len = vd_vec_len(config);
        let expected = FORCED_TX_CHAIN_PUBLIC_INPUTS_LEN + vd_len;
        if inputs.len() != expected {
            return Err(ForcedTxChainPublicInputsError::InvalidLength {
                expected,
                actual: inputs.len(),
            });
        }

        let mut cursor = 0;

        let initial_forced_tx_hash_chain =
            Bytes32::from_u64_slice(&inputs[cursor..cursor + BYTES32_LEN]).map_err(|e| {
                ForcedTxChainPublicInputsError::ParseError {
                    field: "initial_forced_tx_hash_chain",
                    message: e.to_string(),
                }
            })?;
        cursor += BYTES32_LEN;

        let initial_account_tree_root =
            PoseidonHashOut::from_u64_slice(&inputs[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| ForcedTxChainPublicInputsError::ParseError {
                    field: "initial_account_tree_root",
                    message: e.to_string(),
                })?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let initial_forced_tx_count =
            U63::new(inputs[cursor]).map_err(|e| ForcedTxChainPublicInputsError::ParseError {
                field: "initial_forced_tx_count",
                message: e.to_string(),
            })?;
        cursor += 1;

        let forced_tx_hash_chain =
            Bytes32::from_u64_slice(&inputs[cursor..cursor + BYTES32_LEN]).map_err(|e| {
                ForcedTxChainPublicInputsError::ParseError {
                    field: "forced_tx_hash_chain",
                    message: e.to_string(),
                }
            })?;
        cursor += BYTES32_LEN;

        let account_tree_root =
            PoseidonHashOut::from_u64_slice(&inputs[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| ForcedTxChainPublicInputsError::ParseError {
                    field: "account_tree_root",
                    message: e.to_string(),
                })?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let forced_tx_count =
            U63::new(inputs[cursor]).map_err(|e| ForcedTxChainPublicInputsError::ParseError {
                field: "forced_tx_count",
                message: e.to_string(),
            })?;
        cursor += 1;

        let block_number = BlockNumber::new(inputs[cursor]).map_err(|e| {
            ForcedTxChainPublicInputsError::ParseError {
                field: "block_number",
                message: e.to_string(),
            }
        })?;
        cursor += 1;

        let vd_slice = &inputs[cursor..cursor + vd_len];
        let vd = vd_from_pis_slice::<F, C, D>(&vd_slice.to_field_vec(), config).map_err(|e| {
            ForcedTxChainPublicInputsError::ParseError {
                field: "verifier data",
                message: e.to_string(),
            }
        })?;

        Ok(Self {
            initial_forced_tx_hash_chain,
            initial_account_tree_root,
            initial_forced_tx_count,
            forced_tx_hash_chain,
            account_tree_root,
            forced_tx_count,
            block_number,
            vd,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ForcedTxChainPublicInputsTarget {
    pub initial_forced_tx_hash_chain: Bytes32Target,
    pub initial_account_tree_root: PoseidonHashOutTarget,
    pub initial_forced_tx_count: U63Target,
    pub forced_tx_hash_chain: Bytes32Target,
    pub account_tree_root: PoseidonHashOutTarget,
    pub forced_tx_count: U63Target,
    pub block_number: BlockNumberTarget,
    pub vd: VerifierCircuitTarget,
}

impl ForcedTxChainPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        config: &CircuitConfig,
    ) -> Self {
        Self {
            initial_forced_tx_hash_chain: Bytes32Target::new(builder, true),
            initial_account_tree_root: PoseidonHashOutTarget::new(builder),
            initial_forced_tx_count: U63Target::new(builder, true),
            forced_tx_hash_chain: Bytes32Target::new(builder, true),
            account_tree_root: PoseidonHashOutTarget::new(builder),
            forced_tx_count: U63Target::new(builder, true),
            block_number: BlockNumberTarget::new(builder, true),
            vd: builder.add_virtual_verifier_data(config.fri_config.cap_height),
        }
    }

    pub fn to_vec(&self, config: &CircuitConfig) -> Vec<Target> {
        [
            self.initial_forced_tx_hash_chain.to_vec(),
            self.initial_account_tree_root.to_vec(),
            self.initial_forced_tx_count.to_vec(),
            self.forced_tx_hash_chain.to_vec(),
            self.account_tree_root.to_vec(),
            self.forced_tx_count.to_vec(),
            self.block_number.to_vec(),
            vd_to_vec_target(config, &self.vd),
        ]
        .concat()
    }

    pub fn from_pis(pis: &[Target], config: &CircuitConfig) -> Self {
        let vd_len = vd_vec_len(config);
        assert!(pis.len() >= FORCED_TX_CHAIN_PUBLIC_INPUTS_LEN + vd_len);

        let mut cursor = 0;
        let initial_forced_tx_hash_chain =
            Bytes32Target::from_slice(&pis[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;

        let initial_account_tree_root =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let initial_forced_tx_count = U63Target::from_slice(&pis[cursor..cursor + 1]);
        cursor += 1;

        let forced_tx_hash_chain = Bytes32Target::from_slice(&pis[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;

        let account_tree_root =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let forced_tx_count = U63Target::from_slice(&pis[cursor..cursor + 1]);
        cursor += 1;

        let block_number = BlockNumberTarget::from_slice(&pis[cursor..cursor + 1]);
        cursor += 1;

        let vd_slice = &pis[cursor..cursor + vd_len];
        let vd = vd_from_pis_slice_target(vd_slice, config)
            .expect("vd_from_pis_slice_target should not fail");

        Self {
            initial_forced_tx_hash_chain,
            initial_account_tree_root,
            initial_forced_tx_count,
            forced_tx_hash_chain,
            account_tree_root,
            forced_tx_count,
            block_number,
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
        value: &ForcedTxChainPublicInputs<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.initial_forced_tx_hash_chain
            .set_witness(witness, value.initial_forced_tx_hash_chain);
        self.initial_account_tree_root
            .set_witness(witness, value.initial_account_tree_root);
        self.initial_forced_tx_count
            .set_witness(witness, value.initial_forced_tx_count);
        self.forced_tx_hash_chain
            .set_witness(witness, value.forced_tx_hash_chain);
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        self.forced_tx_count
            .set_witness(witness, value.forced_tx_count);
        self.block_number.set_witness(witness, value.block_number);
        witness.set_verifier_data_target(&self.vd, &value.vd);
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        self.initial_forced_tx_hash_chain
            .connect(builder, other.initial_forced_tx_hash_chain);
        self.initial_account_tree_root
            .connect(builder, other.initial_account_tree_root);
        self.initial_forced_tx_count
            .connect(builder, &other.initial_forced_tx_count);
        self.forced_tx_hash_chain
            .connect(builder, other.forced_tx_hash_chain);
        self.account_tree_root
            .connect(builder, other.account_tree_root);
        self.forced_tx_count
            .connect(builder, &other.forced_tx_count);
        self.block_number.connect(builder, &other.block_number);
        builder.connect_verifier_data(&self.vd, &other.vd);
    }
}
