use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite as _},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData,
            VerifierCircuitTarget,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::cyclic_recursion::check_cyclic_proof_verifier_data,
};
use thiserror::Error;

use crate::{
    circuits::withdraw::withdrawal_step::{
        WITHDRAWAL_STEP_PUBLIC_INPUTS_LEN, WithdrawalStepPublicInputsTarget,
    },
    utils::{
        cyclic::{add_noop_gates, simple_recursion_circuit_data, vd_vec_len},
        recursively_verifiable::add_proof_target_and_verify,
    },
};

#[derive(Debug, Error)]
pub enum WithdrawalChainCircuitError {
    #[error("Failed to prove: {0}")]
    FailedToProve(String),

    #[error("Failed to verify: {0}")]
    ProofVerificationError(String),
}

pub struct WithdrawalChainCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub withdrawal_step_proof: ProofWithPublicInputsTarget<D>,
}

impl<F, C, const D: usize> WithdrawalChainCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        withdrawal_chain_cd: &CommonCircuitData<F, D>,
        withdrawal_step_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(withdrawal_chain_cd.config.clone());
        let withdrawal_step_proof = add_proof_target_and_verify(withdrawal_step_vd, &mut builder);
        let new_chain_pis = WithdrawalStepPublicInputsTarget::from_pis(
            &withdrawal_step_proof.public_inputs,
            &withdrawal_chain_cd.config,
        );
        builder.register_public_inputs(&new_chain_pis.to_vec(&withdrawal_chain_cd.config));

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(
            data.common,
            withdrawal_chain_cd.clone(),
            "Common data mismatch in withdrawal chain circuit",
        );
        assert!(success, "Failed to build withdrawal chain circuit");

        Self {
            data,
            withdrawal_step_proof,
        }
    }

    pub fn generate_cd() -> CommonCircuitData<F, D> {
        let data = simple_recursion_circuit_data::<F, C, D>();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let verifier_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
        add_noop_gates(&mut builder, 1 << 12);
        let mut common = builder.build::<C>().common;
        common.num_public_inputs = WITHDRAWAL_STEP_PUBLIC_INPUTS_LEN + vd_vec_len(&common.config);
        common
    }

    pub fn prove(
        &self,
        withdrawal_step_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, WithdrawalChainCircuitError> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.withdrawal_step_proof, withdrawal_step_proof);
        self.data
            .prove(pw)
            .map_err(|e| WithdrawalChainCircuitError::FailedToProve(e.to_string()))
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), WithdrawalChainCircuitError> {
        check_cyclic_proof_verifier_data(proof, &self.data.verifier_only, &self.data.common)
            .map_err(|e| {
                WithdrawalChainCircuitError::ProofVerificationError(format!(
                    "Cyclic proof verifier data check failed: {e:?}"
                ))
            })?;
        self.data.verify(proof.clone()).map_err(|e| {
            WithdrawalChainCircuitError::ProofVerificationError(format!(
                "Failed to verify proof: {e:?}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuits::{
            balance::{
                balance_processor::BalanceProcessor,
                common::recipient::{
                    calculate_recipient_from_address, calculate_recipient_from_user_id,
                },
                spend_circuit::SpendCircuit,
            },
            test_utils::{
                balance_witness_generator::{
                    BalanceWitnessGenerator, ReceiveDepositData, SendTxData, SingleWithdrawalData,
                },
                block_witness_generator::{BlockWitnessGenerator, BlockWitnessGeneratorHandle},
            },
            withdraw::{
                single_withdrawal_circuit::SingleWithdawalCircuit,
                withdrawal_circuit::WithdrawalProofPublicInputs,
                withdrawal_processor::WithdrawalProcessor,
                withdrawal_step::{WithdrawalStepPublicInputs, WithdrawalStepWitness},
            },
        },
        common::{
            salt::Salt,
            transfer::Transfer,
            trees::{transfer_tree::TransferTree, tx_tree::TxTree},
            tx::Tx,
            user_id::UserId,
        },
        constants::MAX_NUM_TRANSFERS_PER_TX,
        ethereum_types::{
            address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
        },
        utils::conversion::ToU64 as _,
    };
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field as _},
        plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{SeedableRng, rngs::StdRng};

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_withdrawal_chain_circuit() {
        let spend_circuit = SpendCircuit::<F, C, D>::new();
        let balance_processor =
            BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
        let balance_vd = balance_processor.balance_vd();

        let mut rng = StdRng::seed_from_u64(42);
        let supported_user_counts = vec![1, MAX_NUM_TRANSFERS_PER_TX as u32, 512];
        let block_witness_generator =
            BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported_user_counts));

        let user_id = UserId::new(0, 1).unwrap();
        let salt = Salt::rand(&mut rng);
        let mut balance_witness_generator = BalanceWitnessGenerator::new(
            user_id,
            salt,
            block_witness_generator.clone(),
            &balance_processor,
        )
        .expect("balance witness generator");

        // Fund the account via deposit.
        let deposit_salt = Salt::rand(&mut rng);
        let deposit_recipient = calculate_recipient_from_user_id(user_id, deposit_salt);
        block_witness_generator
            .borrow_mut()
            .add_deposit(
                Address::rand(&mut rng),
                deposit_recipient,
                0,
                U256::from(10u32),
                Bytes32::default(),
            )
            .unwrap();
        block_witness_generator
            .borrow_mut()
            .add_block(0, &[], 0, Bytes32::default())
            .unwrap();
        let deposit_data = ReceiveDepositData {
            receiver: deposit_recipient,
            deposit_salt,
        };
        let deposit_witness = balance_witness_generator
            .receive_deposit_witness(&deposit_data)
            .expect("deposit witness");
        let deposit_balance_proof = balance_processor
            .prove_receive_deposit(&deposit_witness)
            .expect("deposit proof");
        balance_witness_generator
            .commit_receive_deposit(&deposit_balance_proof, &deposit_witness)
            .expect("commit deposit");

        // Build a transfer encoding a withdrawal.
        let withdrawal_address = Address::rand(&mut rng);
        let transfer = Transfer {
            recipient: calculate_recipient_from_address(withdrawal_address),
            token_index: 0,
            amount: U256::from(3u32),
            aux_data: Bytes32::default(),
        };
        let spend_witness = balance_witness_generator
            .spend_witness(&[transfer.clone()])
            .expect("spend witness");
        let spend_proof = spend_circuit.prove(&spend_witness).expect("spend proof");

        let mut transfer_tree = TransferTree::init();
        transfer_tree.push(transfer.clone());
        let transfer_index = 0u32;
        let transfer_merkle_proof = transfer_tree.prove(transfer_index as u64);
        let transfer_tree_root = transfer_tree.get_root();

        let tx = Tx {
            transfer_tree_root,
            nonce: balance_witness_generator.full_private_state.nonce,
        };
        let mut tx_tree = TxTree::init();
        tx_tree.update(user_id.local_id() as u64, tx.clone());
        let tx_tree_root = tx_tree.get_root();
        let tx_tree_root_bytes: Bytes32 = tx_tree_root.into();
        let tx_merkle_proof = tx_tree.prove(user_id.local_id() as u64);

        block_witness_generator
            .borrow_mut()
            .add_block(
                user_id.aggregator_id(),
                &[user_id.local_id()],
                0,
                tx_tree_root_bytes,
            )
            .unwrap();

        let send_tx_data = SendTxData {
            spend_proof: spend_proof.clone(),
            tx_tree_root: tx_tree_root_bytes,
            tx: tx.clone(),
            tx_merkle_proof: tx_merkle_proof.clone(),
        };
        let send_tx_witness = balance_witness_generator
            .send_tx_witness(&send_tx_data)
            .expect("send tx witness");
        let new_balance_proof = balance_processor
            .prove_send_tx(&send_tx_witness)
            .expect("send tx proof");
        balance_witness_generator
            .commit_send_tx(&new_balance_proof, &send_tx_witness, &spend_witness)
            .expect("commit send tx");

        let withdrawal_data = SingleWithdrawalData {
            tx_tree_root: tx_tree_root_bytes,
            tx: tx.clone(),
            tx_merkle_proof,
            transfer: transfer.clone(),
            transfer_index,
            transfer_merkle_proof,
        };
        let withdrawal_witness = balance_witness_generator
            .single_withdrawal_witness(&withdrawal_data)
            .expect("single withdrawal witness");

        let single_withdrawal_circuit = SingleWithdawalCircuit::<F, C, D>::new(&balance_vd);
        let single_withdrawal_vd = single_withdrawal_circuit.data.verifier_data();
        let single_withdrawal_proof = single_withdrawal_circuit
            .prove(&withdrawal_witness)
            .expect("single withdrawal proof");
        single_withdrawal_circuit
            .data
            .verify(single_withdrawal_proof.clone())
            .expect("single withdrawal proof verifies");

        let withdrawal_processor = WithdrawalProcessor::<F, C, D>::new(&single_withdrawal_vd);
        let withdrawal_chain_vd = withdrawal_processor.withdrawal_chain_vd();

        let step_witness = WithdrawalStepWitness::<F, C, D> {
            prev_withdrawal_chain_proof: None,
            single_withdrawal_proof: single_withdrawal_proof.clone(),
            update_public_state: withdrawal_witness.update_public_state.clone(),
        };

        let withdrawal_chain_proof = withdrawal_processor
            .prove_step(&step_witness)
            .expect("withdrawal chain proof");
        withdrawal_chain_vd
            .verify(withdrawal_chain_proof.clone())
            .expect("withdrawal chain proof verifies");

        let withdrawal_aggregator = Address::rand(&mut rng);
        let ext_public_state = block_witness_generator
            .borrow()
            .current_extended_public_state();
        let withdrawal_proof = withdrawal_processor
            .prove_final(
                &withdrawal_chain_proof,
                withdrawal_aggregator,
                &ext_public_state,
            )
            .expect("withdrawal proof");
        withdrawal_processor
            .withdrawal_vd()
            .verify(withdrawal_proof.clone())
            .expect("withdrawal proof verifies");

        let chain_inputs = WithdrawalStepPublicInputs::<F, C, D>::from_u64_slice(
            &withdrawal_chain_proof.public_inputs.to_u64_vec(),
            &withdrawal_chain_vd.common.config,
        )
        .expect("parse withdrawal chain public inputs");
        let ext_public_state_commitment = ext_public_state.commitment();
        let expected_withdrawal_inputs = WithdrawalProofPublicInputs {
            withdrawal_hash: chain_inputs.withdrawal_hash_chain,
            withdrawal_aggregator,
            ext_public_state_commitment,
            block_number: ext_public_state.inner.block_number,
        };
        let expected_hash = expected_withdrawal_inputs.hash();
        let mut expected_public_inputs: Vec<F> = expected_hash
            .to_u32_vec()
            .into_iter()
            .map(F::from_canonical_u32)
            .collect();
        expected_public_inputs.extend(
            ext_public_state_commitment
                .to_u32_vec()
                .into_iter()
                .map(F::from_canonical_u32),
        );
        expected_public_inputs.push(F::from_canonical_u64(
            ext_public_state.inner.block_number.as_u64(),
        ));

        assert_eq!(withdrawal_proof.public_inputs, expected_public_inputs);
    }
}
