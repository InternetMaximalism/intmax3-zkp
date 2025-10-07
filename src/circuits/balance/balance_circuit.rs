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
    circuits::balance::balance_pis::{BALANCE_PUBLIC_INPUTS_LEN, BalanceFullPublicInputsTarget},
    utils::{
        cyclic::{add_noop_gates, simple_recursion_circuit_data, vd_vec_len},
        recursively_verifiable::add_proof_target_and_verify,
    },
};

#[derive(Debug, Error)]
pub enum BalanceCircuitError {
    #[error("Failed to prove: {0}")]
    FailedToProve(String),

    #[error("Failed to verify: {0}")]
    ProofVerificationError(String),
}

pub struct BalanceCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub switch_proof: ProofWithPublicInputsTarget<D>,
}

impl<F, C, const D: usize> BalanceCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        balance_cd: &CommonCircuitData<F, D>,
        switch_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let switch_proof = add_proof_target_and_verify(switch_vd, &mut builder);
        let new_balance_pis = BalanceFullPublicInputsTarget::from_pis(
            &switch_proof.public_inputs,
            &balance_cd.config,
        );
        builder.register_public_inputs(&new_balance_pis.to_vec(&balance_cd.config));

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(
            data.common,
            balance_cd.clone(),
            "Common data mismatch in balance circuit"
        );
        assert!(success, "Failed to build balance circuit");

        Self { data, switch_proof }
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
        // pad degree should be ajusted to fullfill common data equality
        add_noop_gates(&mut builder, 1 << 12);
        let mut common = builder.build::<C>().common;
        common.num_public_inputs = BALANCE_PUBLIC_INPUTS_LEN + vd_vec_len(&common.config);
        common
    }

    pub fn prove(
        &self,
        switch_board_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceCircuitError> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.switch_proof, switch_board_proof);

        self.data
            .prove(pw)
            .map_err(|e| BalanceCircuitError::FailedToProve(e.to_string()))
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), BalanceCircuitError> {
        check_cyclic_proof_verifier_data(proof, &self.data.verifier_only, &self.data.common)
            .map_err(|e| {
                BalanceCircuitError::ProofVerificationError(format!(
                    "Cyclic proof verifier data check failed: {:?}",
                    e
                ))
            })?;
        self.data.verify(proof.clone()).map_err(|e| {
            BalanceCircuitError::ProofVerificationError(format!("Failed to verify proof: {:?}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        circuits::balance::{
            balance_circuit::BalanceCircuit,
            balance_pis::{BALANCE_PUBLIC_INPUTS_LEN, BalancePublicInputs},
            receive_deposit_circuit::ReceiveDepositCircuit,
            receive_transfer_circuit::ReceiveTransferCircuit,
            send_tx_circuit::SendTxCircuit,
            spend_circuit::SpendCircuit,
            switch_board::{BalanceSwichBoard, BalanceSwichBoardCircuit},
        },
        common::{salt::Salt, user_id::UserId},
        utils::conversion::ToU64,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_balance_circuit() {
        let balance_cd = BalanceCircuit::<F, C, D>::generate_cd();
        let spend_circuit = SpendCircuit::<F, C, D>::new();
        let spend_vd = spend_circuit.data.verifier_data();
        let receive_transfer_circuit =
            ReceiveTransferCircuit::<F, C, D>::new(&balance_cd, &spend_vd);
        let receive_deposit_circuit = ReceiveDepositCircuit::<F, C, D>::new(&balance_cd);
        let send_tx_circuit = SendTxCircuit::<F, C, D>::new(&balance_cd, &spend_vd);

        let switch_circuit = BalanceSwichBoardCircuit::new(
            &balance_cd.config,
            &receive_transfer_circuit.data.verifier_data(),
            &receive_deposit_circuit.data.verifier_data(),
            &send_tx_circuit.data.verifier_data(),
        );

        let balance_circuit =
            BalanceCircuit::<F, C, D>::new(&balance_cd, &switch_circuit.data.verifier_data());

        let balance_vd = balance_circuit.data.verifier_data();

        let mut rng = rand::thread_rng();
        let user_id = UserId(1);
        let salt = Salt::rand(&mut rng);

        let switch_board_witness = BalanceSwichBoard::<F, C, D> {
            initial_value: Some((user_id, salt)),
            receive_transfer_proof: None,
            receive_deposit_proof: None,
            send_tx_proof: None,
        };
        let switch_board_proof = switch_circuit
            .prove(&balance_vd, &switch_board_witness)
            .expect("Failed to prove switch board");

        let balance_proof = balance_circuit
            .prove(&switch_board_proof)
            .expect("Failed to prove balance circuit");

        balance_circuit
            .verify(&balance_proof)
            .expect("Failed to verify balance proof");

        let balance_pis = BalancePublicInputs::from_u64(
            &balance_proof.public_inputs[0..BALANCE_PUBLIC_INPUTS_LEN].to_u64_vec(),
        )
        .expect("Failed to parse balance public inputs");

        let expected_pis = BalancePublicInputs::new(user_id, salt);
        assert_eq!(balance_pis, expected_pis);
    }
}
