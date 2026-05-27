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

/// Public inputs for the parallelizable signature batch verification circuit.
///
/// Unlike the sequential SigAgg circuit, this circuit does NOT update the account tree.
/// `account_tree_root` is read-only — used only to verify account leaf membership.
/// This enables independent parallel batches sharing the same snapshot.
///
/// Fields:
///   account_tree_root:           POSEIDON_HASH_OUT_LEN (4)
///   block_number:                1
///   aggregator_id:               1
///   tx_tree_root:                BYTES32_LEN (8)
///   current_user_local_id:       1
///   current_user_pk_set_root:    POSEIDON_HASH_OUT_LEN (4)
///   current_user_threshold:      1
///   current_user_sigs_verified:  1
///   current_user_last_pk_index:  1
///   verified_users_hash:         POSEIDON_HASH_OUT_LEN (4)
///   verified_count:              1
///   first_user_id:               1
///   last_user_id:                1
///   Total: 29
pub const SIG_BATCH_PUBLIC_INPUTS_LEN: usize = 3 * POSEIDON_HASH_OUT_LEN + BYTES32_LEN + 9;

#[derive(Debug, Error)]
pub enum SigBatchPublicInputsError {
    #[error("Invalid public inputs length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("Failed to parse {field}: {message}")]
    ParseError {
        field: &'static str,
        message: String,
    },
}

pub struct SigBatchPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    /// Read-only account tree root (snapshot at block start).
    pub account_tree_root: PoseidonHashOut,
    pub block_number: BlockNumber,
    pub aggregator_id: u32,
    pub tx_tree_root: Bytes32,

    /// In-progress user state (cleared when user is finalized).
    pub current_user_local_id: u32,
    pub current_user_pk_set_root: PoseidonHashOut,
    pub current_user_threshold: u32,
    pub current_user_sigs_verified: u32,
    pub current_user_last_pk_index: u32,

    /// Cumulative hash of verified users: Poseidon(prev || user_id).
    pub verified_users_hash: PoseidonHashOut,
    pub verified_count: u32,
    /// First finalized user_id in this batch (0 if empty).
    pub first_user_id: u64,
    /// Last finalized user_id in this batch (0 if empty).
    pub last_user_id: u64,

    pub vd: VerifierOnlyCircuitData<C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SigBatchPublicInputs<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn hub_id(&self) -> u32 {
        self.aggregator_id
    }

    pub fn to_u64_vec(&self, config: &CircuitConfig) -> Vec<u64> {
        [
            self.account_tree_root.to_u64_vec(),
            self.block_number.to_u64_vec(),
            vec![self.aggregator_id as u64],
            self.tx_tree_root.to_u64_vec(),
            vec![self.current_user_local_id as u64],
            self.current_user_pk_set_root.to_u64_vec(),
            vec![self.current_user_threshold as u64],
            vec![self.current_user_sigs_verified as u64],
            vec![self.current_user_last_pk_index as u64],
            self.verified_users_hash.to_u64_vec(),
            vec![self.verified_count as u64],
            vec![self.first_user_id],
            vec![self.last_user_id],
            vd_to_vec(config, &self.vd).to_u64_vec(),
        ]
        .concat()
    }

    pub fn from_u64_slice(
        inputs: &[u64],
        config: &CircuitConfig,
    ) -> Result<Self, SigBatchPublicInputsError> {
        let vd_len = vd_vec_len(config);
        let expected = SIG_BATCH_PUBLIC_INPUTS_LEN + vd_len;
        if inputs.len() != expected {
            return Err(SigBatchPublicInputsError::InvalidLength {
                expected,
                actual: inputs.len(),
            });
        }

        let mut cursor = 0;

        let account_tree_root =
            PoseidonHashOut::from_u64_slice(&inputs[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| SigBatchPublicInputsError::ParseError {
                    field: "account_tree_root",
                    message: e.to_string(),
                })?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let block_number = BlockNumber::new(inputs[cursor]).map_err(|e| {
            SigBatchPublicInputsError::ParseError {
                field: "block_number",
                message: e.to_string(),
            }
        })?;
        cursor += 1;

        let aggregator_id = inputs[cursor] as u32;
        cursor += 1;

        let tx_tree_root =
            Bytes32::from_u64_slice(&inputs[cursor..cursor + BYTES32_LEN]).map_err(|e| {
                SigBatchPublicInputsError::ParseError {
                    field: "tx_tree_root",
                    message: e.to_string(),
                }
            })?;
        cursor += BYTES32_LEN;

        let current_user_local_id = inputs[cursor] as u32;
        cursor += 1;

        let current_user_pk_set_root =
            PoseidonHashOut::from_u64_slice(&inputs[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| SigBatchPublicInputsError::ParseError {
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

        let verified_users_hash =
            PoseidonHashOut::from_u64_slice(&inputs[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| SigBatchPublicInputsError::ParseError {
                    field: "verified_users_hash",
                    message: e.to_string(),
                })?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let verified_count = inputs[cursor] as u32;
        cursor += 1;
        let first_user_id = inputs[cursor];
        cursor += 1;
        let last_user_id = inputs[cursor];
        cursor += 1;

        let vd_slice = &inputs[cursor..cursor + vd_len];
        let vd = vd_from_pis_slice::<F, C, D>(&vd_slice.to_field_vec(), config).map_err(|e| {
            SigBatchPublicInputsError::ParseError {
                field: "verifier data",
                message: e.to_string(),
            }
        })?;

        Ok(Self {
            account_tree_root,
            block_number,
            aggregator_id,
            tx_tree_root,
            current_user_local_id,
            current_user_pk_set_root,
            current_user_threshold,
            current_user_sigs_verified,
            current_user_last_pk_index,
            verified_users_hash,
            verified_count,
            first_user_id,
            last_user_id,
            vd,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SigBatchPublicInputsTarget {
    pub account_tree_root: PoseidonHashOutTarget,
    pub block_number: BlockNumberTarget,
    pub aggregator_id: Target,
    pub tx_tree_root: Bytes32Target,
    pub current_user_local_id: Target,
    pub current_user_pk_set_root: PoseidonHashOutTarget,
    pub current_user_threshold: Target,
    pub current_user_sigs_verified: Target,
    pub current_user_last_pk_index: Target,
    pub verified_users_hash: PoseidonHashOutTarget,
    pub verified_count: Target,
    pub first_user_id: Target,
    pub last_user_id: Target,
    pub vd: VerifierCircuitTarget,
}

impl SigBatchPublicInputsTarget {
    pub fn hub_id(&self) -> Target {
        self.aggregator_id
    }

    pub fn to_vec(&self, config: &CircuitConfig) -> Vec<Target> {
        [
            self.account_tree_root.to_vec(),
            self.block_number.to_vec(),
            vec![self.aggregator_id],
            self.tx_tree_root.to_vec(),
            vec![self.current_user_local_id],
            self.current_user_pk_set_root.to_vec(),
            vec![self.current_user_threshold],
            vec![self.current_user_sigs_verified],
            vec![self.current_user_last_pk_index],
            self.verified_users_hash.to_vec(),
            vec![self.verified_count],
            vec![self.first_user_id],
            vec![self.last_user_id],
            vd_to_vec_target(config, &self.vd),
        ]
        .concat()
    }

    pub fn from_pis(pis: &[Target], config: &CircuitConfig) -> Self {
        let vd_len = vd_vec_len(config);
        assert!(pis.len() >= SIG_BATCH_PUBLIC_INPUTS_LEN + vd_len);

        let mut cursor = 0;

        let account_tree_root =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let block_number = BlockNumberTarget::from_slice(&pis[cursor..cursor + 1]);
        cursor += 1;

        let aggregator_id = pis[cursor];
        cursor += 1;

        let tx_tree_root = Bytes32Target::from_slice(&pis[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;

        let current_user_local_id = pis[cursor];
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

        let verified_users_hash =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let verified_count = pis[cursor];
        cursor += 1;
        let first_user_id = pis[cursor];
        cursor += 1;
        let last_user_id = pis[cursor];
        cursor += 1;

        let vd_slice = &pis[cursor..cursor + vd_len];
        let vd = vd_from_pis_slice_target(vd_slice, config)
            .expect("vd_from_pis_slice_target should not fail");

        Self {
            account_tree_root,
            block_number,
            aggregator_id,
            tx_tree_root,
            current_user_local_id,
            current_user_pk_set_root,
            current_user_threshold,
            current_user_sigs_verified,
            current_user_last_pk_index,
            verified_users_hash,
            verified_count,
            first_user_id,
            last_user_id,
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
        value: &SigBatchPublicInputs<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        self.block_number.set_witness(witness, value.block_number);
        witness.set_target(
            self.aggregator_id,
            F::from_canonical_u64(value.aggregator_id as u64),
        );
        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
        witness.set_target(
            self.current_user_local_id,
            F::from_canonical_u64(value.current_user_local_id as u64),
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
        self.verified_users_hash
            .set_witness(witness, value.verified_users_hash);
        witness.set_target(
            self.verified_count,
            F::from_canonical_u64(value.verified_count as u64),
        );
        witness.set_target(
            self.first_user_id,
            F::from_canonical_u64(value.first_user_id),
        );
        witness.set_target(self.last_user_id, F::from_canonical_u64(value.last_user_id));
        witness.set_verifier_data_target(&self.vd, &value.vd);
    }
}
