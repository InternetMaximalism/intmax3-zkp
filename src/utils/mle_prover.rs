//! MLE-based Plonky2 prover — uses plonky2_mle for multilinear PCS.
//!
//! Replaces the previous WHIR pipeline with the plonky2_mle crate which
//! provides sumcheck + multilinear polynomial commitment based proving.

use std::time::{Duration, Instant};

use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::CircuitData,
        config::{GenericConfig, Hasher},
    },
    util::timing::TimingTree,
};
use plonky2_mle::{
    proof::{MleProof, MleVerificationKey},
    prover::{mle_prove, mle_setup},
    verifier::mle_verify,
};

/// Result of MLE proving, including timing information.
pub struct MleProveResult<F: plonky2::field::types::Field> {
    pub proof: MleProof<F>,
    pub prove_time: Duration,
}

/// Compute the MLE verification key for a circuit.
/// This must be done once during setup (deterministic).
pub fn setup_mle_vk<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    circuit_data: &CircuitData<F, C, D>,
) -> MleVerificationKey<F>
where
    C::Hasher: Hasher<F>,
{
    mle_setup::<F, C, D>(&circuit_data.prover_only, &circuit_data.common)
}

/// Generate an MLE proof for a Plonky2 circuit.
pub fn prove_with_mle<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    circuit_data: &CircuitData<F, C, D>,
    inputs: PartialWitness<F>,
) -> Result<MleProveResult<F>>
where
    C::Hasher: Hasher<F>,
    C::InnerHasher: Hasher<F>,
{
    let start = Instant::now();
    let mut timing = TimingTree::new("mle_prove", log::Level::Debug);

    let proof = mle_prove::<F, C, D>(
        &circuit_data.prover_only,
        &circuit_data.common,
        inputs,
        &mut timing,
    )?;

    let prove_time = start.elapsed();
    Ok(MleProveResult { proof, prove_time })
}

/// Verify an MLE proof against the circuit's common data and verification key.
pub fn verify_mle_proof<F: RichField + Extendable<D>, const D: usize>(
    circuit_data: &CircuitData<F, impl GenericConfig<D, F = F>, D>,
    vk: &MleVerificationKey<F>,
    proof: &MleProof<F>,
) -> Result<()> {
    mle_verify::<F, D>(&circuit_data.common, vk, proof)
}

/// Export MLE proof data as JSON for on-chain verification via MleVerifier.sol.
pub fn export_mle_json<F: RichField + Extendable<D>, const D: usize>(
    proof: &MleProof<F>,
    common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
) -> String {
    plonky2_mle::fixture::proof_to_json(proof, common_data, common_data.degree_bits())
}
