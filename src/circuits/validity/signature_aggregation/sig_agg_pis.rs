use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_data::{CircuitConfig, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
    },
};
use thiserror::Error;

use crate::{
    common::u63::{BlockNumber, BlockNumberTarget},
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

/// Public inputs length (excluding verifier data).
///
/// Fields:
///   initial_account_tree_root: POSEIDON_HASH_OUT_LEN (4)
///   account_tree_root:         POSEIDON_HASH_OUT_LEN (4)
///   block_number:              1
///   channel_id:             1
///   tx_tree_root:              BYTES32_LEN (8)
///   signed_digest:             BYTES32_LEN (8)
///   current_user_key_id:     1
///   current_user_pk_set_root:  POSEIDON_HASH_OUT_LEN (4)
///   current_user_threshold:    1
///   current_user_sigs_verified:1
///   current_user_last_pk_index:1
///   processed_count:           1
///   processed_users_hash:      POSEIDON_HASH_OUT_LEN (4)
///   Total: 39
pub const SIG_AGG_PUBLIC_INPUTS_LEN: usize = 4 * POSEIDON_HASH_OUT_LEN + 2 * BYTES32_LEN + 7;

#[derive(Debug, Error)]
pub enum SigAggPublicInputsError {
    #[error("Invalid public inputs length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("Failed to parse {field}: {message}")]
    ParseError {
        field: &'static str,
        message: String,
    },
}

pub struct SigAggPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub initial_account_tree_root: PoseidonHashOut,
    pub account_tree_root: PoseidonHashOut,
    pub block_number: BlockNumber,
    pub channel_id: u32,
    pub tx_tree_root: Bytes32,
    /// IMSB `SmallBlockRootMessage::signing_digest()` every member signature in this chain is
    /// verified over (detail2 §F-2). Recomputed+connected from the block context at the
    /// block-level circuit; carried through the per-signature steps as a PI.
    pub signed_digest: Bytes32,
    pub current_user_key_id: u32,
    pub current_user_pk_set_root: PoseidonHashOut,
    pub current_user_threshold: u32,
    pub current_user_sigs_verified: u32,
    pub current_user_last_pk_index: u32,
    pub processed_count: u32,
    pub processed_users_hash: PoseidonHashOut,
    pub vd: VerifierOnlyCircuitData<C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SigAggPublicInputs<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_u64_vec(&self, config: &CircuitConfig) -> Vec<u64> {
        [
            self.initial_account_tree_root.to_u64_vec(),
            self.account_tree_root.to_u64_vec(),
            self.block_number.to_u64_vec(),
            vec![self.channel_id as u64],
            self.tx_tree_root.to_u64_vec(),
            self.signed_digest.to_u64_vec(),
            vec![self.current_user_key_id as u64],
            self.current_user_pk_set_root.to_u64_vec(),
            vec![self.current_user_threshold as u64],
            vec![self.current_user_sigs_verified as u64],
            vec![self.current_user_last_pk_index as u64],
            vec![self.processed_count as u64],
            self.processed_users_hash.to_u64_vec(),
            vd_to_vec(config, &self.vd).to_u64_vec(),
        ]
        .concat()
    }

    pub fn from_u64_slice(
        inputs: &[u64],
        config: &CircuitConfig,
    ) -> Result<Self, SigAggPublicInputsError> {
        let vd_len = vd_vec_len(config);
        let expected = SIG_AGG_PUBLIC_INPUTS_LEN + vd_len;
        if inputs.len() != expected {
            return Err(SigAggPublicInputsError::InvalidLength {
                expected,
                actual: inputs.len(),
            });
        }

        let mut cursor = 0;

        let initial_account_tree_root =
            PoseidonHashOut::from_u64_slice(&inputs[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| SigAggPublicInputsError::ParseError {
                    field: "initial_account_tree_root",
                    message: e.to_string(),
                })?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let account_tree_root =
            PoseidonHashOut::from_u64_slice(&inputs[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| SigAggPublicInputsError::ParseError {
                    field: "account_tree_root",
                    message: e.to_string(),
                })?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let block_number =
            BlockNumber::new(inputs[cursor]).map_err(|e| SigAggPublicInputsError::ParseError {
                field: "block_number",
                message: e.to_string(),
            })?;
        cursor += 1;

        let channel_id = inputs[cursor] as u32;
        cursor += 1;

        let tx_tree_root =
            Bytes32::from_u64_slice(&inputs[cursor..cursor + BYTES32_LEN]).map_err(|e| {
                SigAggPublicInputsError::ParseError {
                    field: "tx_tree_root",
                    message: e.to_string(),
                }
            })?;
        cursor += BYTES32_LEN;

        let signed_digest = Bytes32::from_u64_slice(&inputs[cursor..cursor + BYTES32_LEN])
            .map_err(|e| SigAggPublicInputsError::ParseError {
                field: "signed_digest",
                message: e.to_string(),
            })?;
        cursor += BYTES32_LEN;

        let current_user_key_id = inputs[cursor] as u32;
        cursor += 1;

        let current_user_pk_set_root =
            PoseidonHashOut::from_u64_slice(&inputs[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| SigAggPublicInputsError::ParseError {
                    field: "current_user_pk_set_root",
                    message: e.to_string(),
                })?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let current_user_threshold = inputs[cursor] as u32;
        cursor += 1;

        let current_user_sigs_verified = inputs[cursor] as u32;
        cursor += 1;

        let current_user_last_pk_index = inputs[cursor] as u32;
        cursor += 1;

        let processed_count = inputs[cursor] as u32;
        cursor += 1;

        let processed_users_hash =
            PoseidonHashOut::from_u64_slice(&inputs[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| SigAggPublicInputsError::ParseError {
                    field: "processed_users_hash",
                    message: e.to_string(),
                })?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let vd_slice = &inputs[cursor..cursor + vd_len];
        let vd = vd_from_pis_slice::<F, C, D>(&vd_slice.to_field_vec(), config).map_err(|e| {
            SigAggPublicInputsError::ParseError {
                field: "verifier data",
                message: e.to_string(),
            }
        })?;

        Ok(Self {
            initial_account_tree_root,
            account_tree_root,
            block_number,
            channel_id,
            tx_tree_root,
            signed_digest,
            current_user_key_id,
            current_user_pk_set_root,
            current_user_threshold,
            current_user_sigs_verified,
            current_user_last_pk_index,
            processed_count,
            processed_users_hash,
            vd,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SigAggPublicInputsTarget {
    pub initial_account_tree_root: PoseidonHashOutTarget,
    pub account_tree_root: PoseidonHashOutTarget,
    pub block_number: BlockNumberTarget,
    pub channel_id: Target,
    pub tx_tree_root: Bytes32Target,
    pub signed_digest: Bytes32Target,
    pub current_user_key_id: Target,
    pub current_user_pk_set_root: PoseidonHashOutTarget,
    pub current_user_threshold: Target,
    pub current_user_sigs_verified: Target,
    pub current_user_last_pk_index: Target,
    pub processed_count: Target,
    pub processed_users_hash: PoseidonHashOutTarget,
    pub vd: VerifierCircuitTarget,
}

impl SigAggPublicInputsTarget {
    pub fn to_vec(&self, config: &CircuitConfig) -> Vec<Target> {
        [
            self.initial_account_tree_root.to_vec(),
            self.account_tree_root.to_vec(),
            self.block_number.to_vec(),
            vec![self.channel_id],
            self.tx_tree_root.to_vec(),
            self.signed_digest.to_vec(),
            vec![self.current_user_key_id],
            self.current_user_pk_set_root.to_vec(),
            vec![self.current_user_threshold],
            vec![self.current_user_sigs_verified],
            vec![self.current_user_last_pk_index],
            vec![self.processed_count],
            self.processed_users_hash.to_vec(),
            vd_to_vec_target(config, &self.vd),
        ]
        .concat()
    }

    pub fn from_pis(pis: &[Target], config: &CircuitConfig) -> Self {
        let vd_len = vd_vec_len(config);
        assert!(pis.len() >= SIG_AGG_PUBLIC_INPUTS_LEN + vd_len);

        let mut cursor = 0;

        let initial_account_tree_root =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let account_tree_root =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let block_number = BlockNumberTarget::from_slice(&pis[cursor..cursor + 1]);
        cursor += 1;

        let channel_id = pis[cursor];
        cursor += 1;

        let tx_tree_root = Bytes32Target::from_slice(&pis[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;

        let signed_digest = Bytes32Target::from_slice(&pis[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;

        let current_user_key_id = pis[cursor];
        cursor += 1;

        let current_user_pk_set_root =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let current_user_threshold = pis[cursor];
        cursor += 1;

        let current_user_sigs_verified = pis[cursor];
        cursor += 1;

        let current_user_last_pk_index = pis[cursor];
        cursor += 1;

        let processed_count = pis[cursor];
        cursor += 1;

        let processed_users_hash =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let vd_slice = &pis[cursor..cursor + vd_len];
        let vd = vd_from_pis_slice_target(vd_slice, config)
            .expect("vd_from_pis_slice_target should not fail");

        Self {
            initial_account_tree_root,
            account_tree_root,
            block_number,
            channel_id,
            tx_tree_root,
            signed_digest,
            current_user_key_id,
            current_user_pk_set_root,
            current_user_threshold,
            current_user_sigs_verified,
            current_user_last_pk_index,
            processed_count,
            processed_users_hash,
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
        value: &SigAggPublicInputs<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.initial_account_tree_root
            .set_witness(witness, value.initial_account_tree_root);
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        self.block_number.set_witness(witness, value.block_number);
        witness.set_target(
            self.channel_id,
            F::from_canonical_u64(value.channel_id as u64),
        );
        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
        self.signed_digest.set_witness(witness, value.signed_digest);
        witness.set_target(
            self.current_user_key_id,
            F::from_canonical_u64(value.current_user_key_id as u64),
        );
        self.current_user_pk_set_root
            .set_witness(witness, value.current_user_pk_set_root);
        witness.set_target(
            self.current_user_threshold,
            F::from_canonical_u64(value.current_user_threshold as u64),
        );
        witness.set_target(
            self.current_user_sigs_verified,
            F::from_canonical_u64(value.current_user_sigs_verified as u64),
        );
        witness.set_target(
            self.current_user_last_pk_index,
            F::from_canonical_u64(value.current_user_last_pk_index as u64),
        );
        witness.set_target(
            self.processed_count,
            F::from_canonical_u64(value.processed_count as u64),
        );
        self.processed_users_hash
            .set_witness(witness, value.processed_users_hash);
        witness.set_verifier_data_target(&self.vd, &value.vd);
    }
}
