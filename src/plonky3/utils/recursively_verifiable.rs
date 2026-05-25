use anyhow::{anyhow, Result};
use p3_circuit::ops::Poseidon2Config;
use p3_circuit_prover::{BatchStarkProver, ConstraintProfile, TablePacking};
use p3_recursion::{
    build_and_prove_aggregation_layer, AggregationPrepCache, BatchOnly, ProveNextLayerParams,
    RecursionOutput,
};

use crate::plonky3::config::{koala_recursion_backend, KoalaRecursionConfig};

pub type KoalaRecursionProof = RecursionOutput<KoalaRecursionConfig>;

pub fn verify_recursion_output(
    proof: &KoalaRecursionProof,
    table_packing: TablePacking,
) -> Result<()> {
    let config = KoalaRecursionConfig::new();
    let mut prover = BatchStarkProver::new(config).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W16);
    prover.register_recompose_table::<4>(false);
    prover
        .verify_all_tables(&proof.0)
        .map_err(|e| anyhow!("failed to verify KoalaBear recursive proof: {e}"))
}

pub fn aggregation_params(level: usize) -> ProveNextLayerParams {
    let table_packing = if level == 1 {
        TablePacking::new(2, 2)
    } else {
        TablePacking::new(2, 3)
    };
    ProveNextLayerParams {
        table_packing: table_packing.with_fri_params(0, 1),
        constraint_profile: ConstraintProfile::Standard,
    }
}

pub fn aggregate_recursion_outputs(
    left: &KoalaRecursionProof,
    right: &KoalaRecursionProof,
    level: usize,
    prep_cache: Option<&mut Option<AggregationPrepCache<KoalaRecursionConfig>>>,
) -> Result<KoalaRecursionProof> {
    let config = KoalaRecursionConfig::new();
    let backend = koala_recursion_backend();
    let params = aggregation_params(level);
    let left_input = left.into_recursion_input::<BatchOnly>();
    let right_input = right.into_recursion_input::<BatchOnly>();
    build_and_prove_aggregation_layer::<KoalaRecursionConfig, _, _, _, 4>(
        &left_input,
        &right_input,
        &config,
        &backend,
        &params,
        prep_cache,
    )
    .map_err(|e| anyhow!("failed to aggregate KoalaBear recursive proofs: {e:?}"))
}

pub fn aggregate_recursion_outputs_and_verify(
    left: &KoalaRecursionProof,
    right: &KoalaRecursionProof,
    level: usize,
    prep_cache: Option<&mut Option<AggregationPrepCache<KoalaRecursionConfig>>>,
) -> Result<KoalaRecursionProof> {
    let aggregated = aggregate_recursion_outputs(left, right, level, prep_cache)?;
    verify_recursion_output(&aggregated, aggregation_params(level).table_packing)?;
    Ok(aggregated)
}
