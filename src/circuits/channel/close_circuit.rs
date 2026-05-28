use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
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
    common::{
        channel::MAX_CLOSE_TRANSFERS,
        user_id::{AccountId, AccountIdTarget},
    },
    ethereum_types::{
        address::{Address, AddressTarget},
        bytes32::{BYTES32_LEN, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait,
        u64::{U64, U64Target},
        u256::{U256_LEN, U256Target},
    },
};

const CHANNEL_STATE_DOMAIN: u32 = 0x494d4348;
const CLOSE_TX_DOMAIN: u32 = 0x494d434c;
const CLOSE_INTENT_DOMAIN: u32 = 0x494d4349;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelClosePublicInputsTarget {
    pub channel_id: AccountIdTarget,
    pub close_nonce: U64Target,
    pub final_epoch: U64Target,
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
            final_epoch: U64Target::from_slice(&builder.add_virtual_targets(2)),
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
            self.final_epoch.to_vec(),
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
        let final_epoch = U64Target::from_slice(&values[cursor..cursor + 2]);
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
            final_epoch,
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
        self.final_epoch
            .set_witness(witness, U64::from(value.final_epoch));
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
    final_state_user_fund_root: Bytes32Target,
    final_state_channel_nullifier_root: Bytes32Target,
    final_state_personal_nullifier_root: Bytes32Target,
    final_state_incoming_root: Bytes32Target,
    final_state_prev_digest: Bytes32Target,
    transfer_amounts: Vec<U64Target>,
    transfer_is_active: Vec<BoolTarget>,
    transfer_member_ids: Vec<AccountIdTarget>,
    transfer_recipients: Vec<AddressTarget>,
    transfer_commitment_digests: Vec<Bytes32Target>,
}

impl<F, C, const D: usize> ChannelCloseCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let public_inputs = ChannelClosePublicInputsTarget::new(&mut builder);
        let zero = builder.zero();

        for limb in &public_inputs.channel_fund_amount.to_vec()[0..6] {
            builder.connect(*limb, zero);
        }

        let final_state_user_fund_root =
            Bytes32Target::from_slice(&builder.add_virtual_targets(BYTES32_LEN));
        let final_state_channel_nullifier_root =
            Bytes32Target::from_slice(&builder.add_virtual_targets(BYTES32_LEN));
        let final_state_personal_nullifier_root =
            Bytes32Target::from_slice(&builder.add_virtual_targets(BYTES32_LEN));
        let final_state_incoming_root =
            Bytes32Target::from_slice(&builder.add_virtual_targets(BYTES32_LEN));
        let final_state_prev_digest =
            Bytes32Target::from_slice(&builder.add_virtual_targets(BYTES32_LEN));

        let channel_id_u32 = public_inputs.channel_id.to_u32_vec(&mut builder);
        let channel_fund_channel_id_u32 = public_inputs.channel_id.to_u32_vec(&mut builder);
        let state_digest_inputs = [
            vec![constant_u32(&mut builder, CHANNEL_STATE_DOMAIN)],
            channel_id_u32,
            public_inputs.final_epoch.to_vec(),
            channel_fund_channel_id_u32,
            public_inputs.channel_fund_amount.to_vec(),
            public_inputs.channel_fund_intmax_state_root.to_vec(),
            final_state_user_fund_root.to_vec(),
            final_state_channel_nullifier_root.to_vec(),
            final_state_personal_nullifier_root.to_vec(),
            final_state_incoming_root.to_vec(),
            final_state_prev_digest.to_vec(),
        ]
        .concat();
        let recomputed_state_digest =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&state_digest_inputs));
        recomputed_state_digest.connect(&mut builder, public_inputs.final_channel_state_digest);

        let mut transfer_amounts = Vec::with_capacity(MAX_CLOSE_TRANSFERS);
        let mut transfer_is_active = Vec::with_capacity(MAX_CLOSE_TRANSFERS);
        let mut transfer_member_ids = Vec::with_capacity(MAX_CLOSE_TRANSFERS);
        let mut transfer_recipients = Vec::with_capacity(MAX_CLOSE_TRANSFERS);
        let mut transfer_commitment_digests = Vec::with_capacity(MAX_CLOSE_TRANSFERS);

        let mut running_total = U64Target::constant(&mut builder, U64::from(0u64));
        let mut active_transfer_count = zero;
        let mut settlement_transfer_inputs = Vec::new();

        for idx in 0..MAX_CLOSE_TRANSFERS {
            let is_active = builder.add_virtual_bool_target_safe();
            if idx > 0 {
                let prev_active = transfer_is_active[idx - 1];
                let prev_inactive = builder.not(prev_active);
                let invalid_activation = builder.and(prev_inactive, is_active);
                builder.assert_zero(invalid_activation.target);
            }
            let not_active = builder.not(is_active);

            let member_id = AccountIdTarget::new(&mut builder, true);
            let recipient = AddressTarget::new(&mut builder, true);
            let commitment_digest =
                Bytes32Target::from_slice(&builder.add_virtual_targets(BYTES32_LEN));
            let amount = U64Target::from_slice(&builder.add_virtual_targets(2));
            active_transfer_count = builder.add(active_transfer_count, is_active.target);

            for limb in member_id.to_u32_vec(&mut builder) {
                builder.conditional_assert_eq(not_active.target, limb, zero);
            }
            for limb in recipient.to_vec() {
                builder.conditional_assert_eq(not_active.target, limb, zero);
            }
            for limb in commitment_digest.to_vec() {
                builder.conditional_assert_eq(not_active.target, limb, zero);
            }
            for limb in amount.to_vec() {
                builder.conditional_assert_eq(not_active.target, limb, zero);
            }

            settlement_transfer_inputs.push(is_active.target);
            settlement_transfer_inputs.extend(member_id.to_u32_vec(&mut builder));
            settlement_transfer_inputs.extend(recipient.to_vec());
            settlement_transfer_inputs.extend(commitment_digest.to_vec());
            settlement_transfer_inputs.extend(amount.to_vec());

            running_total = running_total.add(&mut builder, &amount);
            transfer_amounts.push(amount);
            transfer_is_active.push(is_active);
            transfer_member_ids.push(member_id);
            transfer_recipients.push(recipient);
            transfer_commitment_digests.push(commitment_digest);
        }

        for (lhs, rhs) in running_total
            .to_vec()
            .iter()
            .zip(public_inputs.channel_fund_amount.to_vec()[6..8].iter())
        {
            builder.connect(*lhs, *rhs);
        }

        let settlement_channel_id = public_inputs.channel_id.to_u32_vec(&mut builder);
        let settlement_inputs = [
            vec![constant_u32(&mut builder, CLOSE_TX_DOMAIN)],
            settlement_channel_id,
            public_inputs.final_channel_state_digest.to_vec(),
            public_inputs.channel_fund_intmax_state_root.to_vec(),
            vec![active_transfer_count],
            settlement_transfer_inputs,
        ]
        .concat();
        let recomputed_settlement_digest =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&settlement_inputs));
        recomputed_settlement_digest.connect(&mut builder, public_inputs.settlement_digest);

        let close_intent_channel_id = public_inputs.channel_id.to_u32_vec(&mut builder);
        let close_intent_fund_channel_id = public_inputs.channel_id.to_u32_vec(&mut builder);
        let close_intent_inputs = [
            vec![constant_u32(&mut builder, CLOSE_INTENT_DOMAIN)],
            close_intent_channel_id,
            public_inputs.close_nonce.to_vec(),
            public_inputs.final_epoch.to_vec(),
            public_inputs.final_channel_state_digest.to_vec(),
            close_intent_fund_channel_id,
            public_inputs.channel_fund_amount.to_vec(),
            public_inputs.channel_fund_intmax_state_root.to_vec(),
            public_inputs.settlement_digest.to_vec(),
            public_inputs.snapshot_block_number.to_vec(),
        ]
        .concat();
        let recomputed_close_intent_digest =
            Bytes32Target::from_slice(&builder.keccak256::<C>(&close_intent_inputs));
        recomputed_close_intent_digest.connect(&mut builder, public_inputs.close_intent_digest);

        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build::<C>();

        Self {
            data,
            public_inputs,
            final_state_user_fund_root,
            final_state_channel_nullifier_root,
            final_state_personal_nullifier_root,
            final_state_incoming_root,
            final_state_prev_digest,
            transfer_amounts,
            transfer_is_active,
            transfer_member_ids,
            transfer_recipients,
            transfer_commitment_digests,
        }
    }

    pub fn prove(
        &self,
        witness: &ChannelCloseWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ChannelCloseCircuitError> {
        let public_inputs = witness.to_public_inputs()?;
        let mut pw = PartialWitness::<F>::new();
        self.public_inputs.set_witness(&mut pw, &public_inputs);
        self.final_state_user_fund_root
            .set_witness(&mut pw, witness.final_channel_state.user_fund_root);
        self.final_state_channel_nullifier_root
            .set_witness(&mut pw, witness.final_channel_state.channel_nullifier_root);
        self.final_state_personal_nullifier_root
            .set_witness(&mut pw, witness.final_channel_state.personal_nullifier_root);
        self.final_state_incoming_root
            .set_witness(&mut pw, witness.final_channel_state.incoming_root);
        self.final_state_prev_digest
            .set_witness(&mut pw, witness.final_channel_state.prev_digest);

        for idx in 0..MAX_CLOSE_TRANSFERS {
            let is_active = idx < witness.close_tx.transfers.len();
            pw.set_bool_target(self.transfer_is_active[idx], is_active)
                .map_err(|e| ChannelCloseCircuitError::FailedToProve(e.to_string()))?;

            if is_active {
                let transfer = &witness.close_tx.transfers[idx];
                let opening = &witness.transfer_openings[idx];
                self.transfer_member_ids[idx].set_witness(&mut pw, transfer.member_id);
                self.transfer_recipients[idx].set_witness(&mut pw, transfer.l1_recipient);
                self.transfer_commitment_digests[idx]
                    .set_witness(&mut pw, transfer.user_amount.digest());
                self.transfer_amounts[idx].set_witness(&mut pw, U64::from(opening.amount));
            } else {
                self.transfer_member_ids[idx].set_witness(&mut pw, AccountId::dummy());
                self.transfer_recipients[idx].set_witness(&mut pw, Address::default());
                self.transfer_commitment_digests[idx]
                    .set_witness(&mut pw, crate::ethereum_types::bytes32::Bytes32::default());
                self.transfer_amounts[idx].set_witness(&mut pw, U64::from(0u64));
            }
        }

        self.data
            .prove(pw)
            .map_err(|e| ChannelCloseCircuitError::FailedToProve(e.to_string()))
    }
}

fn constant_u32<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: u32,
) -> Target {
    builder.constant(F::from_canonical_u32(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{
            channel::{
                ChannelFund, ChannelMember, ChannelState, CloseIntent, CloseTransfer,
                CloseWithdrawal, LatticeCommitment, LatticeOpening, MemberSignature,
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
        let transfer_openings = vec![LatticeOpening {
            amount: 77,
            randomness: vec![],
        }];
        let close_intent =
            CloseIntent::new(5, &state, &close_tx, &transfer_openings, 123).unwrap();

        ChannelCloseWitness {
            final_channel_state: state,
            registered_members: vec![ChannelMember {
                member_id: AccountId::new(3, 10).unwrap(),
                signing_pubkey: vec![1, 2, 3],
                l1_withdrawal_recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
            }],
            close_tx,
            close_intent,
            transfer_openings,
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
