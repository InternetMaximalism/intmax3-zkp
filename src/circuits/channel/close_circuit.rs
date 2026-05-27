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
        config::GenericConfig,
        proof::ProofWithPublicInputs,
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    circuits::channel::close_pis::{
        CHANNEL_CLOSE_PUBLIC_INPUTS_LEN, ChannelClosePublicInputs, ChannelCloseWitness,
        ChannelCloseWitnessError,
    },
    common::user_id::AccountIdTarget,
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait,
        u64::{U64, U64Target},
        u256::{U256_LEN, U256Target},
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelClosePublicInputsTarget {
    pub channel_id: AccountIdTarget,
    pub close_nonce: U64Target,
    pub final_channel_state_digest: Bytes32Target,
    pub channel_fund_amount: U256Target,
    pub channel_fund_intmax_state_root: Bytes32Target,
    pub settlement_digest: Bytes32Target,
    pub close_intent_digest: Bytes32Target,
    pub snapshot_block_number: U64Target,
}

impl ChannelClosePublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            channel_id: AccountIdTarget::new(builder, true),
            close_nonce: U64Target::from_slice(&builder.add_virtual_targets(2)),
            final_channel_state_digest: Bytes32Target::from_slice(
                &builder.add_virtual_targets(BYTES32_LEN),
            ),
            channel_fund_amount: U256Target::from_slice(&builder.add_virtual_targets(U256_LEN)),
            channel_fund_intmax_state_root: Bytes32Target::from_slice(
                &builder.add_virtual_targets(BYTES32_LEN),
            ),
            settlement_digest: Bytes32Target::from_slice(&builder.add_virtual_targets(BYTES32_LEN)),
            close_intent_digest: Bytes32Target::from_slice(
                &builder.add_virtual_targets(BYTES32_LEN),
            ),
            snapshot_block_number: U64Target::from_slice(&builder.add_virtual_targets(2)),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.channel_id.to_vec(),
            self.close_nonce.to_vec(),
            self.final_channel_state_digest.to_vec(),
            self.channel_fund_amount.to_vec(),
            self.channel_fund_intmax_state_root.to_vec(),
            self.settlement_digest.to_vec(),
            self.close_intent_digest.to_vec(),
            self.snapshot_block_number.to_vec(),
        ]
        .concat()
    }

    pub fn from_slice(values: &[Target]) -> Self {
        assert_eq!(
            values.len(),
            CHANNEL_CLOSE_PUBLIC_INPUTS_LEN,
            "ChannelClosePublicInputsTarget::from_slice length mismatch",
        );
        let mut cursor = 0;

        let channel_id = AccountIdTarget::from_slice(&values[cursor..cursor + 1]);
        cursor += 1;
        let close_nonce = U64Target::from_slice(&values[cursor..cursor + 2]);
        cursor += 2;
        let final_channel_state_digest =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let channel_fund_amount = U256Target::from_slice(&values[cursor..cursor + U256_LEN]);
        cursor += U256_LEN;
        let channel_fund_intmax_state_root =
            Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let settlement_digest = Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let close_intent_digest = Bytes32Target::from_slice(&values[cursor..cursor + BYTES32_LEN]);
        cursor += BYTES32_LEN;
        let snapshot_block_number = U64Target::from_slice(&values[cursor..cursor + 2]);

        Self {
            channel_id,
            close_nonce,
            final_channel_state_digest,
            channel_fund_amount,
            channel_fund_intmax_state_root,
            settlement_digest,
            close_intent_digest,
            snapshot_block_number,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &ChannelClosePublicInputs,
    ) {
        self.channel_id.set_witness(witness, value.channel_id);
        self.close_nonce
            .set_witness(witness, U64::from(value.close_nonce));
        self.final_channel_state_digest
            .set_witness(witness, value.final_channel_state_digest);
        self.channel_fund_amount
            .set_witness(witness, value.channel_fund_amount);
        self.channel_fund_intmax_state_root
            .set_witness(witness, value.channel_fund_intmax_state_root);
        self.settlement_digest
            .set_witness(witness, value.settlement_digest);
        self.close_intent_digest
            .set_witness(witness, value.close_intent_digest);
        self.snapshot_block_number
            .set_witness(witness, U64::from(value.snapshot_block_number));
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
}

impl<F, C, const D: usize> ChannelCloseCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
{
    pub fn new() -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let public_inputs = ChannelClosePublicInputsTarget::new(&mut builder);
        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build::<C>();

        Self {
            data,
            public_inputs,
        }
    }

    pub fn prove(
        &self,
        witness: &ChannelCloseWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ChannelCloseCircuitError> {
        let public_inputs = witness.to_public_inputs()?;
        let mut pw = PartialWitness::<F>::new();
        self.public_inputs.set_witness(&mut pw, &public_inputs);
        self.data
            .prove(pw)
            .map_err(|e| ChannelCloseCircuitError::FailedToProve(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{
            channel::{
                ChannelFund, ChannelState, CloseIntent, CloseTransfer, CloseWithdrawal,
                LatticeCommitment, MemberSignature,
            },
            user_id::AccountId,
        },
        ethereum_types::{
            address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256,
        },
    };
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::PrimeField64},
        plonk::config::PoseidonGoldilocksConfig,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    fn sample_witness() -> ChannelCloseWitness {
        let state = ChannelState {
            channel_id: AccountId::new(3, 9).unwrap(),
            epoch: 8,
            channel_fund: ChannelFund {
                channel_id: AccountId::new(3, 9).unwrap(),
                amount: U256::from(77u32),
                intmax_state_root: Bytes32::default(),
            },
            user_fund_root: Bytes32::default(),
            channel_nullifier_root: Bytes32::default(),
            personal_nullifier_root: Bytes32::default(),
            incoming_root: Bytes32::default(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![MemberSignature {
                signer: AccountId::new(3, 10).unwrap(),
                signature: vec![1, 2, 3],
            }],
        }
        .with_computed_digest();

        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            intmax_state_root: state.channel_fund.intmax_state_root,
            transfers: vec![CloseTransfer {
                member_id: AccountId::new(3, 10).unwrap(),
                l1_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
                user_amount: LatticeCommitment {
                    commitment: vec![7; 48],
                },
            }],
            zkp: vec![9, 9, 9],
        };
        let close_intent = CloseIntent::new(5, &state, &close_tx, 123).unwrap();

        ChannelCloseWitness {
            final_channel_state: state,
            close_tx,
            close_intent,
        }
    }

    #[test]
    fn channel_close_circuit_proves_close_intent_public_inputs() {
        let circuit = ChannelCloseCircuit::<F, C, D>::new();
        let witness = sample_witness();
        let expected_public_inputs = witness.to_public_inputs().unwrap();

        let proof = circuit.prove(&witness).unwrap();
        circuit.data.verify(proof.clone()).unwrap();

        let proof_public_inputs = ChannelClosePublicInputs::from_u64_slice(
            &proof
                .public_inputs
                .iter()
                .map(|x| x.to_canonical_u64())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(proof_public_inputs, expected_public_inputs);
    }
}
