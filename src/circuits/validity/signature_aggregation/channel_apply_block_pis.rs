use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
};
use thiserror::Error;

use crate::{
    common::u63::{BlockNumber, BlockNumberTarget},
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::poseidon_hash_out::{POSEIDON_HASH_OUT_LEN, PoseidonHashOut, PoseidonHashOutTarget},
};

/// Public inputs for an ChannelApplyBlock (flat) circuit.
///
/// This circuit processes a block of users, updating the user tree.
/// It is NOT cyclic — no verifier data in the public inputs.
///
/// Fields:
///   initial_account_tree_root:  POSEIDON_HASH_OUT_LEN (4)
///   final_account_tree_root:    POSEIDON_HASH_OUT_LEN (4)
///   block_number:               1
///   channel_id:                     1
///   tx_tree_root:               BYTES32_LEN (8)
///   signed_digest:              BYTES32_LEN (8)
///   channels_hash:                 POSEIDON_HASH_OUT_LEN (4)
///   user_count:                 1
///   first_user_id:              1
///   last_user_id:               1
///   Total: 33
pub const ACCOUNT_APPLY_BLOCK_PUBLIC_INPUTS_LEN: usize =
    3 * POSEIDON_HASH_OUT_LEN + 2 * BYTES32_LEN + 5;

#[derive(Debug, Error)]
pub enum ChannelApplyBlockPublicInputsError {
    #[error("Invalid public inputs length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("Failed to parse {field}: {message}")]
    ParseError {
        field: &'static str,
        message: String,
    },
}

pub struct ChannelApplyBlockPublicInputs {
    pub initial_account_tree_root: PoseidonHashOut,
    pub final_account_tree_root: PoseidonHashOut,
    pub block_number: BlockNumber,
    pub channel_id: u32,
    pub tx_tree_root: Bytes32,
    /// IMSB `SmallBlockRootMessage::signing_digest()` recomputed IN-CIRCUIT by this block
    /// circuit from witnessed message fields with the `channel_id`/`tx_tree_root` preimage
    /// components connected to this circuit's own block targets (detail2 §F-2).
    pub signed_digest: Bytes32,
    pub channels_hash: PoseidonHashOut,
    pub user_count: u32,
    pub first_user_id: u64,
    pub last_user_id: u64,
}

impl ChannelApplyBlockPublicInputs {
    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.initial_account_tree_root.to_u64_vec(),
            self.final_account_tree_root.to_u64_vec(),
            self.block_number.to_u64_vec(),
            vec![self.channel_id as u64],
            self.tx_tree_root.to_u64_vec(),
            self.signed_digest.to_u64_vec(),
            self.channels_hash.to_u64_vec(),
            vec![self.user_count as u64],
            vec![self.first_user_id],
            vec![self.last_user_id],
        ]
        .concat()
    }

    pub fn from_u64_slice(inputs: &[u64]) -> Result<Self, ChannelApplyBlockPublicInputsError> {
        let expected = ACCOUNT_APPLY_BLOCK_PUBLIC_INPUTS_LEN;
        if inputs.len() != expected {
            return Err(ChannelApplyBlockPublicInputsError::InvalidLength {
                expected,
                actual: inputs.len(),
            });
        }

        let mut cursor = 0;

        let initial_account_tree_root =
            PoseidonHashOut::from_u64_slice(&inputs[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| ChannelApplyBlockPublicInputsError::ParseError {
                    field: "initial_account_tree_root",
                    message: e.to_string(),
                })?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let final_account_tree_root =
            PoseidonHashOut::from_u64_slice(&inputs[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| ChannelApplyBlockPublicInputsError::ParseError {
                    field: "final_account_tree_root",
                    message: e.to_string(),
                })?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let block_number = BlockNumber::new(inputs[cursor]).map_err(|e| {
            ChannelApplyBlockPublicInputsError::ParseError {
                field: "block_number",
                message: e.to_string(),
            }
        })?;
        cursor += 1;

        let channel_id = inputs[cursor] as u32;
        cursor += 1;

        let tx_tree_root =
            Bytes32::from_u64_slice(&inputs[cursor..cursor + BYTES32_LEN]).map_err(|e| {
                ChannelApplyBlockPublicInputsError::ParseError {
                    field: "tx_tree_root",
                    message: e.to_string(),
                }
            })?;
        cursor += BYTES32_LEN;

        let signed_digest = Bytes32::from_u64_slice(&inputs[cursor..cursor + BYTES32_LEN])
            .map_err(|e| ChannelApplyBlockPublicInputsError::ParseError {
                field: "signed_digest",
                message: e.to_string(),
            })?;
        cursor += BYTES32_LEN;

        let channels_hash =
            PoseidonHashOut::from_u64_slice(&inputs[cursor..cursor + POSEIDON_HASH_OUT_LEN])
                .map_err(|e| ChannelApplyBlockPublicInputsError::ParseError {
                    field: "channels_hash",
                    message: e.to_string(),
                })?;
        cursor += POSEIDON_HASH_OUT_LEN;

        let user_count = inputs[cursor] as u32;
        cursor += 1;
        let first_user_id = inputs[cursor];
        cursor += 1;
        let last_user_id = inputs[cursor];

        Ok(Self {
            initial_account_tree_root,
            final_account_tree_root,
            block_number,
            channel_id,
            tx_tree_root,
            signed_digest,
            channels_hash,
            user_count,
            first_user_id,
            last_user_id,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ChannelApplyBlockPublicInputsTarget {
    pub initial_account_tree_root: PoseidonHashOutTarget,
    pub final_account_tree_root: PoseidonHashOutTarget,
    pub block_number: BlockNumberTarget,
    pub channel_id: Target,
    pub tx_tree_root: Bytes32Target,
    pub signed_digest: Bytes32Target,
    pub channels_hash: PoseidonHashOutTarget,
    pub user_count: Target,
    pub first_user_id: Target,
    pub last_user_id: Target,
}

impl ChannelApplyBlockPublicInputsTarget {
    pub fn channel_id(&self) -> Target {
        self.channel_id
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.initial_account_tree_root.to_vec(),
            self.final_account_tree_root.to_vec(),
            self.block_number.to_vec(),
            vec![self.channel_id],
            self.tx_tree_root.to_vec(),
            self.signed_digest.to_vec(),
            self.channels_hash.to_vec(),
            vec![self.user_count],
            vec![self.first_user_id],
            vec![self.last_user_id],
        ]
        .concat()
    }

    pub fn from_pis(pis: &[Target]) -> Self {
        assert!(pis.len() >= ACCOUNT_APPLY_BLOCK_PUBLIC_INPUTS_LEN);

        let mut cursor = 0;

        let initial_account_tree_root =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let final_account_tree_root =
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

        let channels_hash =
            PoseidonHashOutTarget::from_slice(&pis[cursor..cursor + POSEIDON_HASH_OUT_LEN]);
        cursor += POSEIDON_HASH_OUT_LEN;

        let user_count = pis[cursor];
        cursor += 1;
        let first_user_id = pis[cursor];
        cursor += 1;
        let last_user_id = pis[cursor];

        Self {
            initial_account_tree_root,
            final_account_tree_root,
            block_number,
            channel_id,
            tx_tree_root,
            signed_digest,
            channels_hash,
            user_count,
            first_user_id,
            last_user_id,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, const D: usize, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &ChannelApplyBlockPublicInputs,
    ) {
        self.initial_account_tree_root
            .set_witness(witness, value.initial_account_tree_root);
        self.final_account_tree_root
            .set_witness(witness, value.final_account_tree_root);
        self.block_number.set_witness(witness, value.block_number);
        witness.set_target(
            self.channel_id,
            F::from_canonical_u64(value.channel_id as u64),
        );
        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
        self.signed_digest.set_witness(witness, value.signed_digest);
        self.channels_hash.set_witness(witness, value.channels_hash);
        witness.set_target(
            self.user_count,
            F::from_canonical_u64(value.user_count as u64),
        );
        witness.set_target(
            self.first_user_id,
            F::from_canonical_u64(value.first_user_id),
        );
        witness.set_target(self.last_user_id, F::from_canonical_u64(value.last_user_id));
    }
}
