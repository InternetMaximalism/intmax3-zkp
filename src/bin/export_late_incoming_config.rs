//! Proof-free deployment config for the post-close receive statement.
//! cargo run --release --features authenticated-tail-receive --bin export_late_incoming_config --
//! balance_vd.bin output.json
use anyhow::{Result, ensure};
use intmax3_zkp::{
    circuits::{
        balance::{balance_processor::BalanceProcessor, spend_circuit::SpendCircuit},
        channel::late_incoming_circuit::LateIncomingCircuit,
    },
    late_incoming::export_late_incoming_mle_config,
    utils::serialize::deserialize_verifier_data,
    wallet_core::PostCloseClaimProver,
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
fn main() -> Result<()> {
    ensure!(
        cfg!(feature = "authenticated-tail-receive"),
        "requires authenticated-tail-receive"
    );
    let args: Vec<_> = std::env::args_os().collect();
    ensure!(
        args.len() == 3,
        "usage: export_late_incoming_config BALANCE_VD_BIN OUTPUT_JSON"
    );
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    let balance_vd = deserialize_verifier_data::<F, C, D>(&std::fs::read(&args[1])?)?;
    let spend = SpendCircuit::<F, C, D>::new();
    let balance = BalanceProcessor::<F, C, D>::new(&spend.data.verifier_data());
    ensure!(
        balance_vd == balance.balance_vd(),
        "Balance verifier data does not match this production protocol build"
    );
    let binding = PostCloseClaimProver::new_late_binding();
    let late = LateIncomingCircuit::new(&balance_vd, &spend.data.verifier_data(), &binding.vd());
    let config = export_late_incoming_mle_config(&late)?;
    use std::io::Write;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])?;
    output.write_all(config.as_bytes())?;
    output.sync_all()?;
    Ok(())
}
