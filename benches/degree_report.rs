use intmax3_zkp::circuits::{
    balance::{
        balance_circuit::BalanceCircuit, receive_deposit_circuit::ReceiveDepositCircuit,
        receive_transfer_circuit::ReceiveTransferCircuit, send_tx_circuit::SendTxCircuit,
        spend_circuit::SpendCircuit, switch_board::BalanceSwichBoardCircuit,
    },
    validity::{
        block_hash_chain::{
            block_hash_chain_circuit::BlockHashChainCircuit, block_step::BlockStepCircuit,
            update_channel_tree::UpdateUserCircuit, validity_circuit::ValidityCircuit,
        },
        deposit_hash_chain::{
            deposit_hash_chain_circuit::DepositHashChainCircuit, deposit_step::DepositStepCircuit,
        },
        signature_aggregation::{sig_agg_circuit::SigAggCircuit, sig_agg_step::SigAggStepCircuit},
    },
    withdraw::{
        single_withdrawal_circuit::SingleWithdawalCircuit,
        withdrawal_chain_circuit::WithdrawalChainCircuit, withdrawal_circuit::WithdrawalCircuit,
        withdrawal_step::WithdrawalStepCircuit,
    },
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{circuit_data::CommonCircuitData, config::PoseidonGoldilocksConfig},
};

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

fn main() {
    let supported_user_counts = vec![2];

    let mut rows: Vec<(String, usize)> = Vec::new();

    // Spend circuit
    let spend_circuit = SpendCircuit::<F, C, D>::new();
    rows.push((
        "balance::SpendCircuit".to_string(),
        spend_circuit.data.common.degree_bits(),
    ));

    let spend_vd = spend_circuit.data.verifier_data();
    let balance_cd: CommonCircuitData<F, D> = BalanceCircuit::<F, C, D>::generate_cd();

    // Balance-related circuits
    let receive_transfer = ReceiveTransferCircuit::<F, C, D>::new(&balance_cd, &spend_vd);
    rows.push((
        "balance::ReceiveTransferCircuit".to_string(),
        receive_transfer.data.common.degree_bits(),
    ));

    let receive_deposit = ReceiveDepositCircuit::<F, C, D>::new(&balance_cd);
    rows.push((
        "balance::ReceiveDepositCircuit".to_string(),
        receive_deposit.data.common.degree_bits(),
    ));

    let send_tx = SendTxCircuit::<F, C, D>::new(&balance_cd, &spend_vd);
    rows.push((
        "balance::SendTxCircuit".to_string(),
        send_tx.data.common.degree_bits(),
    ));

    let switch_board = BalanceSwichBoardCircuit::<F, C, D>::new(
        &balance_cd.config,
        &receive_transfer.data.verifier_data(),
        &receive_deposit.data.verifier_data(),
        &send_tx.data.verifier_data(),
    );
    rows.push((
        "balance::BalanceSwichBoardCircuit".to_string(),
        switch_board.data.common.degree_bits(),
    ));

    let balance_circuit =
        BalanceCircuit::<F, C, D>::new(&balance_cd, &switch_board.data.verifier_data());
    rows.push((
        "balance::BalanceCircuit".to_string(),
        balance_circuit.data.common.degree_bits(),
    ));

    // Deposit hash chain circuits
    let deposit_chain_cd = DepositHashChainCircuit::<F, C, D>::generate_cd();
    let deposit_step = DepositStepCircuit::<F, C, D>::new(&deposit_chain_cd);
    rows.push((
        "validity::DepositStepCircuit".to_string(),
        deposit_step.data.common.degree_bits(),
    ));

    let deposit_hash_chain = DepositHashChainCircuit::<F, C, D>::new(
        &deposit_chain_cd,
        &deposit_step.data.verifier_data(),
    );
    rows.push((
        "validity::DepositHashChainCircuit".to_string(),
        deposit_hash_chain.data.common.degree_bits(),
    ));

    // Signature aggregation circuits
    let sig_agg_cd = SigAggCircuit::<F, C, D>::generate_cd();
    let sig_agg_step = SigAggStepCircuit::<F, C, D>::new(&sig_agg_cd);
    rows.push((
        "validity::SigAggStepCircuit".to_string(),
        sig_agg_step.data.common.degree_bits(),
    ));

    let sig_agg_circuit =
        SigAggCircuit::<F, C, D>::new(&sig_agg_cd, &sig_agg_step.data.verifier_data());
    rows.push((
        "validity::SigAggCircuit".to_string(),
        sig_agg_circuit.data.common.degree_bits(),
    ));

    // Block hash chain circuits
    let block_chain_cd = BlockHashChainCircuit::<F, C, D>::generate_cd();
    let update_user_circuits: Vec<UpdateUserCircuit<F, C, D>> = supported_user_counts
        .iter()
        .map(|&n| UpdateUserCircuit::<F, C, D>::new(n))
        .collect();
    for circuit in &update_user_circuits {
        rows.push((
            format!(
                "validity::UpdateUserCircuit(num_users={})",
                circuit.num_users
            ),
            circuit.data.common.degree_bits(),
        ));
    }
    let update_account_vds = update_user_circuits
        .iter()
        .map(|c| (c.num_users, c.data.verifier_data()))
        .collect::<Vec<_>>();

    let block_step = BlockStepCircuit::<F, C, D>::new(
        &block_chain_cd,
        &update_account_vds,
        &deposit_hash_chain.data.verifier_data(),
    );
    rows.push((
        "validity::BlockStepCircuit".to_string(),
        block_step.data.common.degree_bits(),
    ));

    let block_hash_chain =
        BlockHashChainCircuit::<F, C, D>::new(&block_chain_cd, &block_step.data.verifier_data());
    rows.push((
        "validity::BlockHashChainCircuit".to_string(),
        block_hash_chain.data.common.degree_bits(),
    ));

    let validity_circuit = ValidityCircuit::<F, C, D>::new(&block_hash_chain.data.verifier_data());
    rows.push((
        "validity::ValidityCircuit".to_string(),
        validity_circuit.data.common.degree_bits(),
    ));

    // Withdrawal circuits
    let single_withdrawal =
        SingleWithdawalCircuit::<F, C, D>::new(&balance_circuit.data.verifier_data());
    rows.push((
        "withdraw::SingleWithdawalCircuit".to_string(),
        single_withdrawal.data.common.degree_bits(),
    ));

    let withdrawal_chain_cd = WithdrawalChainCircuit::<F, C, D>::generate_cd();
    let withdrawal_step = WithdrawalStepCircuit::<F, C, D>::new(
        &withdrawal_chain_cd,
        &single_withdrawal.data.verifier_data(),
    );
    rows.push((
        "withdraw::WithdrawalStepCircuit".to_string(),
        withdrawal_step.data.common.degree_bits(),
    ));

    let withdrawal_chain = WithdrawalChainCircuit::<F, C, D>::new(
        &withdrawal_chain_cd,
        &withdrawal_step.data.verifier_data(),
    );
    rows.push((
        "withdraw::WithdrawalChainCircuit".to_string(),
        withdrawal_chain.data.common.degree_bits(),
    ));

    let withdrawal_circuit =
        WithdrawalCircuit::<F, C, D>::new(&withdrawal_chain.data.verifier_data());
    rows.push((
        "withdraw::WithdrawalCircuit".to_string(),
        withdrawal_circuit.data.common.degree_bits(),
    ));

    println!("{:<45}{}", "Circuit", "degree_bits");
    println!("{:-<60}", "");
    for (name, degree) in rows {
        println!("{:<45}{}", name, degree);
    }
}
