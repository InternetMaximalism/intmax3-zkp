use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::circuits::validity::forced_tx_hash_chain::{
    forced_tx_hash_chain_circuit::{ForcedTxHashChainCircuit, ForcedTxHashChainCircuitError},
    forced_tx_step::{ForcedTxStepCircuit, ForcedTxStepError, ForcedTxStepWitness},
};

#[derive(Debug, thiserror::Error)]
pub enum ForcedTxChainProcessorError {
    #[error("Forced tx step circuit error: {0}")]
    ForcedTxStepCircuitError(#[from] ForcedTxStepError),

    #[error("Forced tx hash chain circuit error: {0}")]
    ForcedTxHashChainCircuitError(#[from] ForcedTxHashChainCircuitError),
}

pub struct ForcedTxChainProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    forced_tx_step_circuit: ForcedTxStepCircuit<F, C, D>,
    forced_tx_hash_chain_circuit: ForcedTxHashChainCircuit<F, C, D>,
}

impl<F, C, const D: usize> ForcedTxChainProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let forced_tx_chain_cd = ForcedTxHashChainCircuit::<F, C, D>::generate_cd();
        let forced_tx_step_circuit = ForcedTxStepCircuit::<F, C, D>::new(&forced_tx_chain_cd);
        let forced_tx_hash_chain_circuit = ForcedTxHashChainCircuit::<F, C, D>::new(
            &forced_tx_chain_cd,
            &forced_tx_step_circuit.data.verifier_data(),
        );
        Self {
            forced_tx_step_circuit,
            forced_tx_hash_chain_circuit,
        }
    }

    pub fn forced_tx_chain_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.forced_tx_hash_chain_circuit.data.verifier_data()
    }

    pub fn prove_step(
        &self,
        witness: &ForcedTxStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ForcedTxChainProcessorError> {
        let forced_tx_step_proof = self
            .forced_tx_step_circuit
            .prove(&self.forced_tx_chain_vd(), witness)?;
        let forced_tx_chain_proof = self
            .forced_tx_hash_chain_circuit
            .prove(&forced_tx_step_proof)?;
        Ok(forced_tx_chain_proof)
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), ForcedTxHashChainCircuitError> {
        self.forced_tx_hash_chain_circuit.verify(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{
            forced_tx::ForcedTx,
            trees::account_tree::{AccountLeaf, AccountTree, SendLeaf, SendTree},
            u63::{BlockNumber, U63},
            user_id::UserId,
        },
        constants::{ACCOUNT_TREE_HEIGHT, SEND_TREE_HEIGHT},
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{SeedableRng, rngs::StdRng};

    use crate::circuits::validity::forced_tx_hash_chain::forced_tx_step::ForcedTxStepWitness;
    use crate::utils::poseidon_hash_out::PoseidonHashOut;

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_forced_tx_chain_processor() {
        let mut rng = StdRng::seed_from_u64(42);

        let processor = ForcedTxChainProcessor::<F, C, D>::new();
        let forced_tx_chain_vd = processor.forced_tx_chain_vd();

        let block_number = BlockNumber::new(5).unwrap();
        let user_id = UserId::new(1, 10).unwrap();
        let tx_hash = Bytes32::rand(&mut rng);

        // Set up account tree with an existing user
        let mut send_tree = SendTree::init();
        let prev_send_leaf = SendLeaf {
            prev: BlockNumber::new(1).unwrap(),
            cur: BlockNumber::new(3).unwrap(),
            tx_tree_root: Bytes32::rand(&mut rng),
        };
        send_tree.push(prev_send_leaf);
        let prev_account_leaf = AccountLeaf {
            index: send_tree.len() as u32,
            prev: BlockNumber::new(3).unwrap(),
            send_tree_root: send_tree.get_root(),
            pk_set_root: PoseidonHashOut::default(), // no registered key set
            threshold: 0,
        };

        let mut account_tree = AccountTree::new(ACCOUNT_TREE_HEIGHT);
        account_tree.update(user_id.as_u64(), prev_account_leaf.clone());

        let initial_account_tree_root = account_tree.get_root();
        let initial_forced_tx_hash_chain = Bytes32::default();
        let initial_forced_tx_count = U63::default();

        let account_merkle_proof = account_tree.prove(user_id.as_u64());
        let send_merkle_proof = send_tree.prove(prev_account_leaf.index.into());

        let forced_tx = ForcedTx { user_id, tx_hash };

        let first_witness = ForcedTxStepWitness::<F, C, D> {
            initial_value: Some((
                initial_forced_tx_hash_chain,
                initial_account_tree_root,
                initial_forced_tx_count,
            )),
            prev_forced_tx_chain_proof: None,
            forced_tx: forced_tx.clone(),
            block_number,
            prev_account_leaf: prev_account_leaf.clone(),
            account_merkle_proof,
            send_merkle_proof,
        };

        let first_public_inputs = first_witness
            .to_public_inputs(&forced_tx_chain_vd)
            .expect("first forced tx public inputs");
        assert_eq!(first_public_inputs.forced_tx_count.as_u64(), 1);
        assert_eq!(first_public_inputs.block_number, block_number);
        assert_ne!(
            first_public_inputs.account_tree_root,
            initial_account_tree_root,
            "account tree root should change after forced tx"
        );

        let expected_hash_chain =
            forced_tx.hash_with_prev_hash(initial_forced_tx_hash_chain);
        assert_eq!(
            first_public_inputs.forced_tx_hash_chain,
            expected_hash_chain
        );

        let first_proof = processor
            .prove_step(&first_witness)
            .expect("first forced tx chain proof");
        processor
            .verify(&first_proof)
            .expect("first forced tx chain proof verifies");
    }
}
