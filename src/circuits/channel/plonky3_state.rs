use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues};
use p3_challenger::DuplexChallenger;
use p3_commit::testing::TrivialPcs;
use p3_dft::Radix2DitParallel;
use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Proof, StarkConfig, prove, verify};
use rand09::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::circuits::channel::state_update_verifier::{
    ChannelProofEnvelope, ChannelProofVerifier, ChannelStateUpdateError, ChannelStateUpdatePublicInputs,
};
use crate::common::channel::{ProofBackend, ReceiverBalanceDelta, TransitionProofRole};
use crate::ethereum_types::u32limb_trait::U32LimbTrait;

type Val = Goldilocks;
type Challenge = BinomialExtensionField<Val, 2>;
type Perm = Poseidon2Goldilocks<8>;
type Challenger = DuplexChallenger<Val, Perm, 8, 4>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TrivialPcs<Val, Dft>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;
type StarkProof = Proof<Config>;

const SINGLE_PUBLIC_VALUES: usize = 8;
const BUNDLE_PUBLIC_VALUES: usize = 5;
const SINGLE_TRACE_WIDTH: usize = 8;
const BUNDLE_TRACE_WIDTH: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SingleTransitionWitness {
    pub is_in_channel: bool,
    pub amount: u64,
    pub sender_before: u64,
    pub sender_after: u64,
    pub receiver_before: u64,
    pub receiver_after: u64,
    pub channel_fund_before: u64,
    pub channel_fund_after: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiverBundleRowWitness {
    pub receiver_before: u64,
    pub delta_amount: u64,
    pub receiver_after: u64,
    pub is_dummy: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiverBundleWitness {
    pub amount: u64,
    pub channel_fund_before: u64,
    pub channel_fund_after: u64,
    pub rows: Vec<ReceiverBundleRowWitness>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Plonky3ChannelStateProof {
    Single {
        witness: SingleTransitionWitness,
        proof: Vec<u8>,
    },
    ReceiverBundle {
        witness: ReceiverBundleWitness,
        proof: Vec<u8>,
    },
}

#[derive(Debug, Error)]
pub enum Plonky3ChannelProofError {
    #[error("invalid single-transition witness: {0}")]
    InvalidSingleWitness(String),

    #[error("invalid receiver-bundle witness: {0}")]
    InvalidBundleWitness(String),

    #[error("serialization failed: {0}")]
    Serialization(String),

    #[error("proof verification failed: {0}")]
    Verification(String),

    #[error("public input mismatch: {0}")]
    PublicInputMismatch(String),
}

#[derive(Clone, Copy)]
struct SingleTransitionAir;

#[derive(Clone, Copy)]
struct ReceiverBundleAir;

#[derive(Clone, Copy)]
struct SingleTransitionRow<F> {
    amount: F,
    sender_before: F,
    sender_after: F,
    receiver_before: F,
    receiver_after: F,
    channel_fund_before: F,
    channel_fund_after: F,
    is_in_channel: F,
}

#[derive(Clone, Copy)]
struct ReceiverBundleRow<F> {
    receiver_before: F,
    delta_amount: F,
    receiver_after: F,
    is_dummy: F,
    is_active: F,
    running_sum: F,
    running_dummy_count: F,
    running_active_count: F,
}

impl<F> Borrow<SingleTransitionRow<F>> for [F] {
    fn borrow(&self) -> &SingleTransitionRow<F> {
        debug_assert_eq!(self.len(), SINGLE_TRACE_WIDTH);
        let (prefix, rows, suffix) = unsafe { self.align_to::<SingleTransitionRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(rows.len(), 1);
        &rows[0]
    }
}

impl<F> Borrow<ReceiverBundleRow<F>> for [F] {
    fn borrow(&self) -> &ReceiverBundleRow<F> {
        debug_assert_eq!(self.len(), BUNDLE_TRACE_WIDTH);
        let (prefix, rows, suffix) = unsafe { self.align_to::<ReceiverBundleRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(rows.len(), 1);
        &rows[0]
    }
}

impl<F> BaseAir<F> for SingleTransitionAir {
    fn width(&self) -> usize {
        SINGLE_TRACE_WIDTH
    }
}

impl<F> BaseAirWithPublicValues<F> for SingleTransitionAir {
    fn num_public_values(&self) -> usize {
        SINGLE_PUBLIC_VALUES
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for SingleTransitionAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0).expect("single transition trace must have one row");
        let row: &SingleTransitionRow<AB::Var> = (*row).borrow();
        let pi_amount = builder.public_values()[0].clone();
        let pi_sender_before = builder.public_values()[1].clone();
        let pi_sender_after = builder.public_values()[2].clone();
        let pi_receiver_before = builder.public_values()[3].clone();
        let pi_receiver_after = builder.public_values()[4].clone();
        let pi_channel_fund_before = builder.public_values()[5].clone();
        let pi_channel_fund_after = builder.public_values()[6].clone();
        let pi_is_in_channel = builder.public_values()[7].clone();

        builder
            .when_first_row()
            .assert_eq(row.amount.clone(), pi_amount);
        builder
            .when_first_row()
            .assert_eq(row.sender_before.clone(), pi_sender_before);
        builder
            .when_first_row()
            .assert_eq(row.sender_after.clone(), pi_sender_after);
        builder
            .when_first_row()
            .assert_eq(row.receiver_before.clone(), pi_receiver_before);
        builder
            .when_first_row()
            .assert_eq(row.receiver_after.clone(), pi_receiver_after);
        builder
            .when_first_row()
            .assert_eq(row.channel_fund_before.clone(), pi_channel_fund_before);
        builder
            .when_first_row()
            .assert_eq(row.channel_fund_after.clone(), pi_channel_fund_after);
        builder
            .when_first_row()
            .assert_eq(row.is_in_channel.clone(), pi_is_in_channel);

        builder.assert_zero(
            row.is_in_channel.clone() * (row.is_in_channel.clone() - AB::Expr::ONE),
        );
        builder.assert_eq(
            row.sender_before.clone(),
            row.sender_after.clone() + row.amount.clone(),
        );

        let receiver_delta = row.receiver_after.clone() - row.receiver_before.clone();
        builder
            .when(row.is_in_channel.clone())
            .assert_eq(receiver_delta.clone(), row.amount.clone());
        builder
            .when(row.is_in_channel.clone())
            .assert_eq(row.channel_fund_before.clone(), row.channel_fund_after.clone());
        builder
            .when(AB::Expr::ONE - row.is_in_channel.clone())
            .assert_zero(receiver_delta);
        builder
            .when(AB::Expr::ONE - row.is_in_channel.clone())
            .assert_eq(
                row.channel_fund_before.clone(),
                row.channel_fund_after.clone() + row.amount.clone(),
            );
    }
}

impl<F> BaseAir<F> for ReceiverBundleAir {
    fn width(&self) -> usize {
        BUNDLE_TRACE_WIDTH
    }
}

impl<F> BaseAirWithPublicValues<F> for ReceiverBundleAir {
    fn num_public_values(&self) -> usize {
        BUNDLE_PUBLIC_VALUES
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for ReceiverBundleAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = main.row_slice(0).expect("receiver bundle trace missing current row");
        let next_row = main.row_slice(1).expect("receiver bundle trace missing next row");
        let local: &ReceiverBundleRow<AB::Var> = (*local_row).borrow();
        let next: &ReceiverBundleRow<AB::Var> = (*next_row).borrow();
        let amount = builder.public_values()[0].clone();
        let fund_before = builder.public_values()[1].clone();
        let fund_after = builder.public_values()[2].clone();
        let entry_count = builder.public_values()[3].clone();
        let dummy_count = builder.public_values()[4].clone();

        builder.assert_zero(local.is_active.clone() * (local.is_active.clone() - AB::Expr::ONE));
        builder.assert_zero(local.is_dummy.clone() * (local.is_dummy.clone() - AB::Expr::ONE));
        builder.assert_zero((AB::Expr::ONE - local.is_active.clone()) * local.is_dummy.clone());

        builder
            .when(local.is_active.clone())
            .assert_eq(
                local.receiver_after.clone(),
                local.receiver_before.clone() + local.delta_amount.clone(),
            );
        builder
            .when(AB::Expr::ONE - local.is_active.clone())
            .assert_zero(local.receiver_before.clone());
        builder
            .when(AB::Expr::ONE - local.is_active.clone())
            .assert_zero(local.receiver_after.clone());
        builder
            .when(AB::Expr::ONE - local.is_active.clone())
            .assert_zero(local.delta_amount.clone());

        builder
            .when(local.is_dummy.clone())
            .assert_zero(local.delta_amount.clone() * (local.delta_amount.clone() - AB::Expr::ONE));

        builder
            .when_first_row()
            .assert_eq(
                local.running_sum.clone(),
                local.is_active.clone() * local.delta_amount.clone(),
            );
        builder
            .when_first_row()
            .assert_eq(local.running_dummy_count.clone(), local.is_dummy.clone());
        builder
            .when_first_row()
            .assert_eq(local.running_active_count.clone(), local.is_active.clone());

        builder.when_transition().assert_eq(
            next.running_sum.clone(),
            local.running_sum.clone() + next.is_active.clone() * next.delta_amount.clone(),
        );
        builder.when_transition().assert_eq(
            next.running_dummy_count.clone(),
            local.running_dummy_count.clone() + next.is_dummy.clone(),
        );
        builder.when_transition().assert_eq(
            next.running_active_count.clone(),
            local.running_active_count.clone() + next.is_active.clone(),
        );
        builder
            .when_transition()
            .assert_zero((AB::Expr::ONE - local.is_active.clone()) * next.is_active.clone());

        builder
            .when_last_row()
            .assert_eq(local.running_sum.clone(), amount);
        builder
            .when_last_row()
            .assert_eq(local.running_dummy_count.clone(), dummy_count);
        builder
            .when_last_row()
            .assert_eq(local.running_active_count.clone(), entry_count);
        builder.assert_zero(fund_before.into() + amount.into() - fund_after.into());
    }
}

fn single_public_values(witness: &SingleTransitionWitness) -> [Val; SINGLE_PUBLIC_VALUES] {
    [
        Val::from_u64(witness.amount),
        Val::from_u64(witness.sender_before),
        Val::from_u64(witness.sender_after),
        Val::from_u64(witness.receiver_before),
        Val::from_u64(witness.receiver_after),
        Val::from_u64(witness.channel_fund_before),
        Val::from_u64(witness.channel_fund_after),
        if witness.is_in_channel {
            Val::ONE
        } else {
            Val::ZERO
        },
    ]
}

fn bundle_public_values(witness: &ReceiverBundleWitness) -> [Val; BUNDLE_PUBLIC_VALUES] {
    [
        Val::from_u64(witness.amount),
        Val::from_u64(witness.channel_fund_before),
        Val::from_u64(witness.channel_fund_after),
        Val::from_u64(witness.rows.len() as u64),
        Val::from_u64(witness.rows.iter().filter(|row| row.is_dummy).count() as u64),
    ]
}

fn make_config(log_n: usize) -> Config {
    let mut rng = StdRng::seed_from_u64(1);
    let perm = Perm::new_from_rng_128(&mut rng);
    let pcs = Pcs {
        dft: Dft::default(),
        log_n,
        _phantom: core::marker::PhantomData,
    };
    let challenger = Challenger::new(perm);
    Config::new(pcs, challenger)
}

fn single_trace(witness: &SingleTransitionWitness) -> RowMajorMatrix<Val> {
    RowMajorMatrix::new(
        vec![
            Val::from_u64(witness.amount),
            Val::from_u64(witness.sender_before),
            Val::from_u64(witness.sender_after),
            Val::from_u64(witness.receiver_before),
            Val::from_u64(witness.receiver_after),
            Val::from_u64(witness.channel_fund_before),
            Val::from_u64(witness.channel_fund_after),
            if witness.is_in_channel {
                Val::ONE
            } else {
                Val::ZERO
            },
        ],
        SINGLE_TRACE_WIDTH,
    )
}

fn bundle_trace(witness: &ReceiverBundleWitness) -> RowMajorMatrix<Val> {
    let mut rows = witness.rows.len().max(1).next_power_of_two();
    if rows == 0 {
        rows = 1;
    }

    let mut values = Val::zero_vec(rows * BUNDLE_TRACE_WIDTH);
    let (prefix, aligned_rows, suffix) = unsafe { values.align_to_mut::<ReceiverBundleRow<Val>>() };
    assert!(prefix.is_empty());
    assert!(suffix.is_empty());

    let mut running_sum = 0u64;
    let mut running_dummy = 0u64;
    for (idx, row) in aligned_rows.iter_mut().enumerate() {
        if let Some(w) = witness.rows.get(idx) {
            running_sum += w.delta_amount;
            running_dummy += u64::from(w.is_dummy);
            *row = ReceiverBundleRow {
                receiver_before: Val::from_u64(w.receiver_before),
                delta_amount: Val::from_u64(w.delta_amount),
                receiver_after: Val::from_u64(w.receiver_after),
                is_dummy: if w.is_dummy { Val::ONE } else { Val::ZERO },
                is_active: Val::ONE,
                running_sum: Val::from_u64(running_sum),
                running_dummy_count: Val::from_u64(running_dummy),
                running_active_count: Val::from_u64((idx + 1) as u64),
            };
        } else {
            *row = ReceiverBundleRow {
                receiver_before: Val::ZERO,
                delta_amount: Val::ZERO,
                receiver_after: Val::ZERO,
                is_dummy: Val::ZERO,
                is_active: Val::ZERO,
                running_sum: Val::from_u64(running_sum),
                running_dummy_count: Val::from_u64(running_dummy),
                running_active_count: Val::from_u64(witness.rows.len() as u64),
            };
        }
    }

    RowMajorMatrix::new(values, BUNDLE_TRACE_WIDTH)
}

fn validate_single_witness(witness: &SingleTransitionWitness) -> Result<(), Plonky3ChannelProofError> {
    if witness.sender_before != witness.sender_after + witness.amount {
        return Err(Plonky3ChannelProofError::InvalidSingleWitness(
            "sender_before must equal sender_after + amount".to_string(),
        ));
    }
    if witness.is_in_channel {
        if witness.receiver_after != witness.receiver_before + witness.amount {
            return Err(Plonky3ChannelProofError::InvalidSingleWitness(
                "receiver_after must equal receiver_before + amount".to_string(),
            ));
        }
        if witness.channel_fund_before != witness.channel_fund_after {
            return Err(Plonky3ChannelProofError::InvalidSingleWitness(
                "channel fund must stay unchanged for in-channel transfers".to_string(),
            ));
        }
    } else {
        if witness.receiver_before != 0 || witness.receiver_after != 0 {
            return Err(Plonky3ChannelProofError::InvalidSingleWitness(
                "receiver balances must be zeroed in inter-channel send local proof".to_string(),
            ));
        }
        if witness.channel_fund_before != witness.channel_fund_after + witness.amount {
            return Err(Plonky3ChannelProofError::InvalidSingleWitness(
                "channel fund must decrease by amount for inter-channel send".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_bundle_witness(witness: &ReceiverBundleWitness) -> Result<(), Plonky3ChannelProofError> {
    if witness.rows.is_empty() {
        return Err(Plonky3ChannelProofError::InvalidBundleWitness(
            "receiver bundle must contain at least one row".to_string(),
        ));
    }
    let total = witness.rows.iter().try_fold(0u64, |acc, row| {
        if row.receiver_after != row.receiver_before + row.delta_amount {
            return Err(Plonky3ChannelProofError::InvalidBundleWitness(
                "receiver_after must equal receiver_before + delta_amount".to_string(),
            ));
        }
        if row.is_dummy && row.delta_amount > 1 {
            return Err(Plonky3ChannelProofError::InvalidBundleWitness(
                "dummy rows must have delta_amount 0 or 1".to_string(),
            ));
        }
        acc.checked_add(row.delta_amount).ok_or_else(|| {
            Plonky3ChannelProofError::InvalidBundleWitness(
                "receiver delta total overflow".to_string(),
            )
        })
    })?;
    if total != witness.amount {
        return Err(Plonky3ChannelProofError::InvalidBundleWitness(
            "receiver delta total must equal amount".to_string(),
        ));
    }
    if witness.channel_fund_after != witness.channel_fund_before + witness.amount {
        return Err(Plonky3ChannelProofError::InvalidBundleWitness(
            "channel fund must increase by amount on import".to_string(),
        ));
    }
    Ok(())
}

pub fn prove_single_transition(
    witness: SingleTransitionWitness,
) -> Result<Plonky3ChannelStateProof, Plonky3ChannelProofError> {
    validate_single_witness(&witness)?;
    let config = make_config(0);
    let proof = prove(&config, &SingleTransitionAir, single_trace(&witness), &single_public_values(&witness))
        ;
    let bytes = postcard::to_allocvec(&proof)
        .map_err(|e| Plonky3ChannelProofError::Serialization(e.to_string()))?;
    Ok(Plonky3ChannelStateProof::Single { witness, proof: bytes })
}

pub fn single_transition_envelope(
    witness: SingleTransitionWitness,
) -> Result<ChannelProofEnvelope, Plonky3ChannelProofError> {
    let state_proof = prove_single_transition(witness)?;
    let proof = postcard::to_allocvec(&state_proof)
        .map_err(|e| Plonky3ChannelProofError::Serialization(e.to_string()))?;
    Ok(ChannelProofEnvelope {
        role: TransitionProofRole::ChannelStateUpdate,
        backend: ProofBackend::Plonky3,
        proof,
    })
}

pub fn prove_receiver_bundle(
    witness: ReceiverBundleWitness,
) -> Result<Plonky3ChannelStateProof, Plonky3ChannelProofError> {
    validate_bundle_witness(&witness)?;
    let config = make_config(witness.rows.len().max(1).next_power_of_two().ilog2() as usize);
    let proof = prove(&config, &ReceiverBundleAir, bundle_trace(&witness), &bundle_public_values(&witness));
    let bytes = postcard::to_allocvec(&proof)
        .map_err(|e| Plonky3ChannelProofError::Serialization(e.to_string()))?;
    Ok(Plonky3ChannelStateProof::ReceiverBundle { witness, proof: bytes })
}

pub fn receiver_bundle_envelope(
    witness: ReceiverBundleWitness,
) -> Result<ChannelProofEnvelope, Plonky3ChannelProofError> {
    let state_proof = prove_receiver_bundle(witness)?;
    let proof = postcard::to_allocvec(&state_proof)
        .map_err(|e| Plonky3ChannelProofError::Serialization(e.to_string()))?;
    Ok(ChannelProofEnvelope {
        role: TransitionProofRole::ChannelStateUpdate,
        backend: ProofBackend::Plonky3,
        proof,
    })
}

pub fn verify_state_proof(
    proof: &Plonky3ChannelStateProof,
) -> Result<(), Plonky3ChannelProofError> {
    match proof {
        Plonky3ChannelStateProof::Single { witness, proof } => {
            validate_single_witness(witness)?;
            let config = make_config(0);
            let stark_proof: StarkProof = postcard::from_bytes(proof)
                .map_err(|e| Plonky3ChannelProofError::Serialization(e.to_string()))?;
            verify(&config, &SingleTransitionAir, &stark_proof, &single_public_values(witness))
                .map_err(|e| Plonky3ChannelProofError::Verification(format!("{e:?}")))
        }
        Plonky3ChannelStateProof::ReceiverBundle { witness, proof } => {
            validate_bundle_witness(witness)?;
            let config =
                make_config(witness.rows.len().max(1).next_power_of_two().ilog2() as usize);
            let stark_proof: StarkProof = postcard::from_bytes(proof)
                .map_err(|e| Plonky3ChannelProofError::Serialization(e.to_string()))?;
            verify(&config, &ReceiverBundleAir, &stark_proof, &bundle_public_values(witness))
                .map_err(|e| Plonky3ChannelProofError::Verification(format!("{e:?}")))
        }
    }
}

pub struct RealPlonky3ChannelProofVerifier;

impl ChannelProofVerifier for RealPlonky3ChannelProofVerifier {
    fn verify(
        &self,
        proof: &ChannelProofEnvelope,
        public_inputs: &ChannelStateUpdatePublicInputs,
    ) -> Result<(), ChannelStateUpdateError> {
        if proof.role != TransitionProofRole::ChannelStateUpdate
            || proof.backend != ProofBackend::Plonky3
        {
            return Err(ChannelStateUpdateError::ProofVerification(
                "unexpected proof role/backend for Plonky3 verifier".to_string(),
            ));
        }

        let state_proof: Plonky3ChannelStateProof = postcard::from_bytes(&proof.proof)
            .map_err(|e| ChannelStateUpdateError::ProofVerification(e.to_string()))?;
        verify_state_proof(&state_proof)
            .map_err(|e| ChannelStateUpdateError::ProofVerification(e.to_string()))?;

        match state_proof {
            Plonky3ChannelStateProof::Single { witness, .. } => {
                let expected_in_channel = public_inputs.kind
                    == crate::common::channel::ChannelTransitionKind::InChannelTransfer;
                if witness.is_in_channel != expected_in_channel {
                    return Err(ChannelStateUpdateError::ProofVerification(
                        "single-transition proof kind mismatch".to_string(),
                    ));
                }
                if witness.amount != public_inputs.amount
                    || witness.sender_before != public_inputs.sender_balance_before
                    || witness.sender_after != public_inputs.sender_balance_after
                    || witness.receiver_before != public_inputs.receiver_balance_before
                    || witness.receiver_after != public_inputs.receiver_balance_after
                    || witness.channel_fund_before != public_inputs.channel_fund_before.low_u64()
                    || witness.channel_fund_after != public_inputs.channel_fund_after.low_u64()
                {
                    return Err(ChannelStateUpdateError::PublicInputMismatch(
                        "single-transition proof does not match channel public inputs".to_string(),
                    ));
                }
            }
            Plonky3ChannelStateProof::ReceiverBundle { witness, .. } => {
                if public_inputs.kind
                    != crate::common::channel::ChannelTransitionKind::InterChannelImport
                {
                    return Err(ChannelStateUpdateError::ProofVerification(
                        "receiver-bundle proof kind mismatch".to_string(),
                    ));
                }
                let dummy_count = witness.rows.iter().filter(|row| row.is_dummy).count() as u64;
                if witness.amount != public_inputs.amount
                    || witness.channel_fund_before != public_inputs.channel_fund_before.low_u64()
                    || witness.channel_fund_after != public_inputs.channel_fund_after.low_u64()
                    || witness.rows.len() as u64 != public_inputs.receiver_entry_count
                    || dummy_count != public_inputs.receiver_dummy_count
                {
                    return Err(ChannelStateUpdateError::PublicInputMismatch(
                        "receiver-bundle proof does not match channel public inputs".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

trait LowU64 {
    fn low_u64(&self) -> u64;
}

impl LowU64 for crate::ethereum_types::u256::U256 {
    fn low_u64(&self) -> u64 {
        let limbs = self.to_u32_vec();
        ((limbs[6] as u64) << 32) | limbs[7] as u64
    }
}

pub fn dummy_count_from_deltas(deltas: &[ReceiverBalanceDelta], amounts: &[u64]) -> u64 {
    deltas
        .iter()
        .zip(amounts)
        .filter(|(_, amount)| **amount <= 1)
        .count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_transition_proof_roundtrip() {
        let proof = prove_single_transition(SingleTransitionWitness {
            is_in_channel: true,
            amount: 7,
            sender_before: 50,
            sender_after: 43,
            receiver_before: 10,
            receiver_after: 17,
            channel_fund_before: 100,
            channel_fund_after: 100,
        })
        .unwrap();
        verify_state_proof(&proof).unwrap();
    }

    #[test]
    fn receiver_bundle_proof_roundtrip() {
        let proof = prove_receiver_bundle(ReceiverBundleWitness {
            amount: 7,
            channel_fund_before: 100,
            channel_fund_after: 107,
            rows: vec![
                ReceiverBundleRowWitness {
                    receiver_before: 10,
                    delta_amount: 5,
                    receiver_after: 15,
                    is_dummy: false,
                },
                ReceiverBundleRowWitness {
                    receiver_before: 20,
                    delta_amount: 1,
                    receiver_after: 21,
                    is_dummy: true,
                },
                ReceiverBundleRowWitness {
                    receiver_before: 30,
                    delta_amount: 1,
                    receiver_after: 31,
                    is_dummy: true,
                },
            ],
        })
        .unwrap();
        verify_state_proof(&proof).unwrap();
    }
}
