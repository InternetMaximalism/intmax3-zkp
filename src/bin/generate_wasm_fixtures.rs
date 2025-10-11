use anyhow::Result;
use intmax3_zkp::circuits::{
    balance::{balance_processor::BalanceProcessor, spend_circuit::SpendCircuit},
    withdraw::single_withdrawal_circuit::SingleWithdawalCircuit,
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use std::{fs, path::PathBuf};

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

const SPEND_FIXTURE: &str = "spend_circuit.bin";
const BALANCE_FIXTURE: &str = "balance_processor.bin";
const SINGLE_WITHDRAWAL_FIXTURE: &str = "single_withdrawal_circuit.bin";

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn main() -> Result<()> {
    let dir = fixtures_dir();
    fs::create_dir_all(&dir)?;

    let spend_circuit = SpendCircuit::<F, C, D>::new();
    let spend_bytes = spend_circuit.to_bytes()?;
    fs::write(dir.join(SPEND_FIXTURE), spend_bytes)?;

    let balance_processor = BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
    let balance_bytes = balance_processor.to_bytes()?;
    fs::write(dir.join(BALANCE_FIXTURE), balance_bytes)?;

    let single_withdrawal_circuit =
        SingleWithdawalCircuit::<F, C, D>::new(&balance_processor.balance_vd());
    let single_bytes = single_withdrawal_circuit.to_bytes()?;
    fs::write(dir.join(SINGLE_WITHDRAWAL_FIXTURE), single_bytes)?;

    println!("Fixtures written to {}", dir.display());
    Ok(())
}
