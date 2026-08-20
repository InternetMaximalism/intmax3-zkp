//! Decision benchmark for 2/4/8/16-slot Falcon aggregate circuits.
//!
//! Run: `cargo test --release --test falcon_arity_bench -- --nocapture`
#![cfg(not(debug_assertions))]

use std::time::Instant;

use intmax3_zkp::{
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _},
    falcon_sig::{
        FALCON_N, FalconKeys, FalconSignature, agg::FalconAggWitness, batch::FalconBatchAggCircuit,
    },
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

fn run<const SLOTS: usize>() {
    let message = Bytes32::from_u32_slice(&[0x494d_4348, SLOTS as u32, 2, 3, 4, 5, 6, 7]).unwrap();
    let mut hs: Vec<[u16; FALCON_N]> = Vec::with_capacity(SLOTS);
    let mut sigs: Vec<FalconSignature> = Vec::with_capacity(SLOTS);
    for i in 0..SLOTS {
        let keys = FalconKeys::from_seed([0x40 + i as u8; 32]);
        hs.push(keys.pk_coefficients());
        sigs.push(keys.sign(message));
    }
    let refs: Vec<(&[u16; FALCON_N], &FalconSignature)> = hs.iter().zip(&sigs).collect();
    let witness = FalconAggWitness::for_signatures(message, &refs);

    let t = Instant::now();
    let circuit = FalconBatchAggCircuit::<F, C, D, SLOTS>::new();
    let build = t.elapsed();
    let t = Instant::now();
    let proof = circuit.prove(&witness).expect("prove");
    let prove = t.elapsed();
    let size = proof.to_bytes().len();
    let t = Instant::now();
    circuit.data.verify(proof).expect("verify");
    let verify = t.elapsed();

    println!(
        "falcon slots={SLOTS:>2}: gates={} degree=2^{} build={build:?} prove={prove:?} verify={verify:?} proof={size} B",
        circuit.num_gates_before_padding,
        circuit.data.common.degree_bits(),
    );
}

#[test]
fn falcon_aggregate_arity_matrix() {
    run::<2>();
    run::<4>();
    run::<8>();
    run::<16>();
}
