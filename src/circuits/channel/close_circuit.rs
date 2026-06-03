use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use plonky2_keccak::builder::BuilderKeccak256 as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    circuits::channel::close_pis::{
        CHANNEL_CLOSE_PUBLIC_INPUTS_LEN, ChannelClosePublicInputs, ChannelCloseWitness,
        ChannelCloseWitnessError,
    },
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32Target},
        u64::{U64, U64Target},
        u32limb_trait::U32LimbTargetTrait,
        u256::{U256_LEN, U256Target},
    },
};

const CHANNEL_STATE_DOMAIN: u32 = 0x494d4348;
const CLOSE_TX_DOMAIN: u32 = 0x494d434c;
const CLOSE_INTENT_DOMAIN: u32 = 0x494d4349;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelClosePublicInputsTarget {
    pub channel_id: [Target; 2],
    pub close_nonce: U64Target,
    pub final_epoch: U64Target,
    pub final_small_block_number: U64Target,
    pub close_freeze_nonce: U64Target,
    pub final_channel_state_digest: Bytes32Target,
    pub final_channel_balance_root: Bytes32Target,
    pub channel_fund_amount: U256Target,
    pub channel_fund_intmax_state_root: Bytes32Target,
    pub burn_tx_hash: Bytes32Target,
    pub close_withdrawal_digest: Bytes32Target,
    pub close_intent_digest: Bytes32Target,
    pub snapshot_medium_block_number: U64Target,
}

impl ChannelClosePublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            channel_id: [builder.add_virtual_target(), builder.add_virtual_target()],
            close_nonce: U64Target::from_slice(&builder.add_virtual_targets(2)),
            final_epoch: U64Target::from_slice(&builder.add_virtual_targets(2)),
            final_small_block_number: U64Target::from_slice(&builder.add_virtual_targets(2)),
            close_freeze_nonce: U64Target::from_slice(&builder.add_virtual_targets(2)),
            final_channel_state_digest: Bytes32Target::from_slice(
                &builder.add_virtual_targets(BYTES32_LEN),
            ),
            final_channel_balance_root: Bytes32Target::from_slice(
                &builder.add_virtual_targets(BYTES32_LEN),
            ),
            channel_fund_amount: U256Target::from_slice(&builder.add_virtual_targets(U256_LEN)),
            channel_fund_intmax_state_root: Bytes32Target::from_slice(
                &builder.add_virtual_targets(BYTES32_LEN),
            ),
            burn_tx_hash: Bytes32Target::from_slice(&builder.add_virtual_targets(BYTES32_LEN)),
            close_withdrawal_digest: Bytes32Target::from_slice(
                &builder.add_virtual_targets(BYTES32_LEN),
            ),
            close_intent_digest: Bytes32Target::from_slice(
                &builder.add_virtual_targets(BYTES32_LEN),
            ),
            snapshot_medium_block_number: U64Target::from_slice(&builder.add_virtual_targets(2)),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.channel_id.to_vec(),
            self.close_nonce.to_vec(),
            self.final_epoch.to_vec(),
            self.final_small_block_number.to_vec(),
            self.close_freeze_nonce.to_vec(),
            self.final_channel_state_digest.to_vec(),
            self.final_channel_balance_root.to_vec(),
            self.channel_fund_amount.to_vec(),
            self.channel_fund_intmax_state_root.to_vec(),
            self.burn_tx_hash.to_vec(),
            self.close_withdrawal_digest.to_vec(),
            self.close_intent_digest.to_vec(),
            self.snapshot_medium_block_number.to_vec(),
        ]
        .concat()
    }

    pub fn from_slice(values: &[Target]) -> Self {
        assert_eq!(values.len(), CHANNEL_CLOSE_PUBLIC_INPUTS_LEN);
        let mut cursor = 0;
        let channel_id = [values[cursor], values[cursor + 1]];
        cursor += 2;
        let close_nonce = U64Target::from_slice(&values[cursor..cursor + 2]);
        cursor += 2;
        let final_epoch = U64Target::from_slice(&values[cursor..cursor + 2]);
        cursor += 2;
        let final_small_block_number = U64Target::from_slice(&values[cursor..cursor + 2]);
        cursor += 2;
        let close_freeze_nonce = U64Target::from_slice(&values[cursor..cursor + 2]);
        cursor += 2;
        let final_channel_state_digest =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let final_channel_balance_root =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let channel_fund_amount = U256Target::from_slice(&values[cursor..cursor + U256_LEN]);
        cursor += U256_LEN;
        let channel_fund_intmax_state_root =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let burn_tx_hash = Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let close_withdrawal_digest =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let close_intent_digest = Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let snapshot_medium_block_number = U64Target::from_slice(&values[cursor..cursor + 2]);
        Self {
            channel_id,
            close_nonce,
            final_epoch,
            final_small_block_number,
            close_freeze_nonce,
            final_channel_state_digest,
            final_channel_balance_root,
            channel_fund_amount,
            channel_fund_intmax_state_root,
            burn_tx_hash,
            close_withdrawal_digest,
            close_intent_digest,
            snapshot_medium_block_number,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &ChannelClosePublicInputs,
    ) {
        witness
            .set_target(self.channel_id[0], F::from_canonical_u64(value.channel_id.to_u64_vec()[0]))
            .unwrap();
        witness
            .set_target(self.channel_id[1], F::from_canonical_u64(value.channel_id.to_u64_vec()[1]))
            .unwrap();
        self.close_nonce
            .set_witness(witness, U64::from(value.close_nonce));
        self.final_epoch
            .set_witness(witness, U64::from(value.final_epoch));
        self.final_small_block_number
            .set_witness(witness, U64::from(value.final_small_block_number));
        self.close_freeze_nonce
            .set_witness(witness, U64::from(value.close_freeze_nonce));
        self.final_channel_state_digest
            .set_witness(witness, value.final_channel_state_digest);
        self.final_channel_balance_root
            .set_witness(witness, value.final_channel_balance_root);
        self.channel_fund_amount
            .set_witness(witness, value.channel_fund_amount);
        self.channel_fund_intmax_state_root
            .set_witness(witness, value.channel_fund_intmax_state_root);
        self.burn_tx_hash.set_witness(witness, value.burn_tx_hash);
        self.close_withdrawal_digest
            .set_witness(witness, value.close_withdrawal_digest);
        self.close_intent_digest
            .set_witness(witness, value.close_intent_digest);
        self.snapshot_medium_block_number
            .set_witness(witness, U64::from(value.snapshot_medium_block_number));
    }
}

#[derive(Debug, Error)]
pub enum ChannelCloseCircuitError {
    #[error("witness error: {0}")]
    Witness(#[from] ChannelCloseWitnessError),
    #[error("failed to prove: {0}")]
    FailedToProve(String),
}

pub struct ChannelCloseCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub public_inputs: ChannelClosePublicInputsTarget,
    final_state_close_freeze_nonce: U64Target,
    final_state_shared_native_nullifier_root: Bytes32Target,
    final_state_unallocated_confirmed_incoming: U256Target,
    final_state_prev_digest: Bytes32Target,
}

impl<F, C, const D: usize> ChannelCloseCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let public_inputs = ChannelClosePublicInputsTarget::new(&mut builder);
        let final_state_close_freeze_nonce = U64Target::from_slice(&builder.add_virtual_targets(2));
        let final_state_shared_native_nullifier_root =
            Bytes32Target::from_slice(&builder.add_virtual_targets(BYTES32_LEN));
        let final_state_unallocated_confirmed_incoming =
            U256Target::from_slice(&builder.add_virtual_targets(U256_LEN));
        let final_state_prev_digest =
            Bytes32Target::from_slice(&builder.add_virtual_targets(BYTES32_LEN));
        let one = U64Target::constant(&mut builder, U64::from(1u64));
        let incremented_close_freeze_nonce =
            final_state_close_freeze_nonce.add(&mut builder, &one);
        incremented_close_freeze_nonce.connect(&mut builder, public_inputs.close_freeze_nonce);

        let zero = builder.zero();
        for limb in final_state_unallocated_confirmed_incoming.to_vec() {
            builder.connect(limb, zero);
        }

        let channel_state_domain = builder.constant(F::from_canonical_u32(CHANNEL_STATE_DOMAIN));
        let close_tx_domain = builder.constant(F::from_canonical_u32(CLOSE_TX_DOMAIN));
        let close_intent_domain = builder.constant(F::from_canonical_u32(CLOSE_INTENT_DOMAIN));

        let state_digest_inputs = [
            vec![channel_state_domain],
            public_inputs.channel_id.to_vec(),
            public_inputs.final_epoch.to_vec(),
            public_inputs.final_small_block_number.to_vec(),
            final_state_close_freeze_nonce.to_vec(),
            public_inputs.channel_id.to_vec(),
            public_inputs.channel_fund_amount.to_vec(),
            public_inputs.channel_fund_intmax_state_root.to_vec(),
            public_inputs.final_channel_balance_root.to_vec(),
            final_state_shared_native_nullifier_root.to_vec(),
            final_state_unallocated_confirmed_incoming.to_vec(),
            final_state_prev_digest.to_vec(),
        ]
        .concat();
        let state_digest = Bytes32Target::from_slice(&builder.keccak256::<C>(&state_digest_inputs));
        state_digest.connect(&mut builder, public_inputs.final_channel_state_digest);

        let close_withdrawal_inputs = [
            vec![close_tx_domain],
            public_inputs.channel_id.to_vec(),
            public_inputs.final_channel_state_digest.to_vec(),
            public_inputs.final_channel_balance_root.to_vec(),
            public_inputs.channel_fund_intmax_state_root.to_vec(),
            public_inputs.burn_tx_hash.to_vec(),
            public_inputs.channel_fund_amount.to_vec(),
        ]
        .concat();
        let close_withdrawal_digest =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&close_withdrawal_inputs));
        close_withdrawal_digest.connect(&mut builder, public_inputs.close_withdrawal_digest);

        let close_intent_inputs = [
            vec![close_intent_domain],
            public_inputs.channel_id.to_vec(),
            public_inputs.close_nonce.to_vec(),
            public_inputs.final_epoch.to_vec(),
            public_inputs.final_small_block_number.to_vec(),
            public_inputs.close_freeze_nonce.to_vec(),
            public_inputs.final_channel_state_digest.to_vec(),
            public_inputs.final_channel_balance_root.to_vec(),
            public_inputs.channel_id.to_vec(),
            public_inputs.channel_fund_amount.to_vec(),
            public_inputs.channel_fund_intmax_state_root.to_vec(),
            public_inputs.burn_tx_hash.to_vec(),
            public_inputs.close_withdrawal_digest.to_vec(),
            public_inputs.snapshot_medium_block_number.to_vec(),
        ]
        .concat();
        let close_intent_digest =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&close_intent_inputs));
        close_intent_digest.connect(&mut builder, public_inputs.close_intent_digest);

        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build::<C>();
        Self {
            data,
            public_inputs,
            final_state_close_freeze_nonce,
            final_state_shared_native_nullifier_root,
            final_state_unallocated_confirmed_incoming,
            final_state_prev_digest,
        }
    }

    pub fn prove(
        &self,
        witness_value: &ChannelCloseWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ChannelCloseCircuitError> {
        let public_inputs = witness_value.to_public_inputs()?;
        let mut witness = PartialWitness::<F>::new();
        self.public_inputs.set_witness(&mut witness, &public_inputs);
        self.final_state_close_freeze_nonce
            .set_witness(&mut witness, U64::from(witness_value.final_channel_state.close_freeze_nonce));
        self.final_state_shared_native_nullifier_root
            .set_witness(
                &mut witness,
                witness_value.final_channel_state.shared_native_nullifier_root,
            );
        self.final_state_unallocated_confirmed_incoming
            .set_witness(
                &mut witness,
                witness_value.final_channel_state.unallocated_confirmed_incoming,
            );
        self.final_state_prev_digest
            .set_witness(&mut witness, witness_value.final_channel_state.prev_digest);
        self.data
            .prove(witness)
            .map_err(|e| ChannelCloseCircuitError::FailedToProve(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::channel::{ChannelFund, ChannelId, ChannelState, CloseIntent, CloseWithdrawal, KeyId, MemberSignature, UserId},
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256},
    };
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::PrimeField64},
        plonk::config::PoseidonGoldilocksConfig,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn channel_close_circuit_proves_close_intent_public_inputs() {
        let final_channel_state = ChannelState {
            channel_id: ChannelId::new(5).unwrap(),
            epoch: 3,
            small_block_number: 7,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id: ChannelId::new(5).unwrap(),
                amount: U256::from(77u32),
                intmax_state_root: Bytes32::from_u32_slice(&[1, 2, 3, 4, 0, 0, 0, 0]).unwrap(),
            },
            channel_balance_root: Bytes32::from_u32_slice(&[2, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            shared_native_nullifier_root: Bytes32::from_u32_slice(&[3, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::from_u32_slice(&[4, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            digest: Bytes32::default(),
            member_signatures: vec![MemberSignature {
                key_id: KeyId::new(10).unwrap(),
                user_id: UserId::from_parts(ChannelId::new(5).unwrap(), KeyId::new(10).unwrap()),
                signature: vec![1],
                key_condition_proof: vec![2],
            }],
        }
        .with_computed_digest();
        let close_tx = CloseWithdrawal {
            channel_id: final_channel_state.channel_id,
            final_channel_state_digest: final_channel_state.digest,
            final_channel_balance_root: final_channel_state.channel_balance_root,
            intmax_state_root: final_channel_state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[9, 8, 7, 6, 0, 0, 0, 0]).unwrap(),
            burn_amount: final_channel_state.channel_fund.amount,
            zkp: vec![1, 2, 3],
        };
        let close_intent = CloseIntent::new(5, &final_channel_state, &close_tx, 123).unwrap();
        let close_witness = ChannelCloseWitness {
            final_channel_state,
            close_tx,
            close_intent,
        };
        let circuit = ChannelCloseCircuit::<F, C, D>::new();
        let proof = circuit.prove(&close_witness).unwrap();
        let expected = close_witness.to_public_inputs().unwrap().to_u64_vec();
        let actual = proof.public_inputs.iter().map(|field| field.to_canonical_u64()).collect::<Vec<_>>();
        assert_eq!(expected, actual);
    }
}
