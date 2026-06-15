//! Channel-registration chain processor (mirror of `DepositChainProcessor`).

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::circuits::validity::channel_reg_hash_chain::{
    channel_reg_hash_chain_circuit::{ChannelRegHashChainCircuit, ChannelRegHashChainCircuitError},
    channel_reg_step::{ChannelRegStepCircuit, ChannelRegStepError, ChannelRegStepWitness},
};

#[derive(Debug, thiserror::Error)]
pub enum ChannelRegChainProcessorError {
    #[error("Channel reg step circuit error: {0}")]
    ChannelRegStepError(#[from] ChannelRegStepError),

    #[error("Channel reg hash chain circuit error: {0}")]
    ChannelRegHashChainCircuitError(#[from] ChannelRegHashChainCircuitError),
}

pub struct ChannelRegChainProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    channel_reg_step_circuit: ChannelRegStepCircuit<F, C, D>,
    channel_reg_hash_chain_circuit: ChannelRegHashChainCircuit<F, C, D>,
}

impl<F, C, const D: usize> ChannelRegChainProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let channel_reg_chain_cd = ChannelRegHashChainCircuit::<F, C, D>::generate_cd();
        let channel_reg_step_circuit = ChannelRegStepCircuit::<F, C, D>::new(&channel_reg_chain_cd);
        let channel_reg_hash_chain_circuit = ChannelRegHashChainCircuit::<F, C, D>::new(
            &channel_reg_chain_cd,
            &channel_reg_step_circuit.data.verifier_data(),
        );
        Self {
            channel_reg_step_circuit,
            channel_reg_hash_chain_circuit,
        }
    }

    pub fn channel_reg_chain_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.channel_reg_hash_chain_circuit.data.verifier_data()
    }

    pub fn prove_step(
        &self,
        witness: &ChannelRegStepWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ChannelRegChainProcessorError> {
        let channel_reg_step_proof = self
            .channel_reg_step_circuit
            .prove(&self.channel_reg_chain_vd(), witness)?;
        let channel_reg_chain_proof = self
            .channel_reg_hash_chain_circuit
            .prove(&channel_reg_step_proof)?;
        Ok(channel_reg_chain_proof)
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), ChannelRegHashChainCircuitError> {
        self.channel_reg_hash_chain_circuit.verify(proof)
    }
}

impl<F, C, const D: usize> Default for ChannelRegChainProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::validity::channel_reg_hash_chain::channel_reg_step::member_pubkeys_root_for,
        common::{
            channel_id::ChannelId,
            channel_registration::{ChannelRegRecord, MemberRegEntry},
            trees::channel_tree::{ChannelLeaf, ChannelTree},
            u63::{BlockNumber, U63},
        },
        ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _},
        utils::{conversion::ToField as _, poseidon_hash_out::PoseidonHashOut},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    fn make_record(channel_id: u32, member_count: u32) -> ChannelRegRecord {
        let mut members: [MemberRegEntry; crate::constants::MAX_CHANNEL_MEMBERS] =
            Default::default();
        for i in 0..(member_count as usize) {
            let s = (i as u32) + 1;
            members[i] = MemberRegEntry {
                pk_g: Bytes32::from(PoseidonHashOut::hash_inputs_u64(&[
                    channel_id as u64,
                    s as u64,
                    0x5e,
                ])),
                pk_b: Bytes32::from(PoseidonHashOut::hash_inputs_u64(&[
                    channel_id as u64,
                    s as u64,
                    0x7e,
                ])),
                regev_pk_digest: Bytes32::from(PoseidonHashOut::hash_inputs_u64(&[
                    channel_id as u64,
                    s as u64,
                    0x6e,
                ])),
                recipient: Address::from_u32_slice(&[0x3333_0000 + s; 5]).unwrap(),
            };
        }
        ChannelRegRecord {
            channel_id: ChannelId::new(channel_id as u64).unwrap(),
            bp_member_slot: 0,
            member_count,
            members,
        }
    }

    fn registered_leaf(record: &ChannelRegRecord) -> ChannelLeaf {
        ChannelLeaf {
            index: 0,
            prev: BlockNumber::default(),
            send_tree_root: ChannelLeaf::default().send_tree_root,
            member_pubkeys_root: member_pubkeys_root_for(record),
        }
    }

    /// Two registration steps over the cyclic chain (initial + chained-via-prev-proof). Validates
    /// keccak chain folding, the channel tree growth, and the count increment.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_channel_reg_chain_processor() {
        let processor = ChannelRegChainProcessor::<F, C, D>::new();
        let chain_vd = processor.channel_reg_chain_vd();

        let block_number = BlockNumber::new(7).unwrap();

        // Step 1: register channel 5.
        let initial_hash_chain = Bytes32::default();
        let channel_tree = ChannelTree::init();
        let initial_tree_root = channel_tree.get_root();

        let record1 = make_record(5, 3);
        let idx1 = record1.channel_id.as_u64();
        let proof1_merkle = channel_tree.prove(idx1);

        let first_witness = ChannelRegStepWitness::<F, C, D> {
            initial_value: Some((initial_hash_chain, initial_tree_root, U63::default())),
            prev_channel_reg_chain_proof: None,
            record: record1.clone(),
            channel_merkle_proof: proof1_merkle,
            block_number,
        };
        let first_pis = first_witness
            .to_public_inputs(&chain_vd)
            .expect("first public inputs");
        let first_proof = processor
            .prove_step(&first_witness)
            .expect("first chain proof");
        processor.verify(&first_proof).expect("first verifies");

        let expected_first_fields = first_pis
            .to_u64_vec(&processor.channel_reg_hash_chain_circuit.data.common.config)
            .to_field_vec::<F>();
        assert_eq!(first_proof.public_inputs, expected_first_fields);
        assert_eq!(first_pis.channel_reg_count.as_u64(), 1);
        assert_eq!(
            first_pis.channel_reg_hash_chain,
            record1.hash_with_prev_hash(initial_hash_chain)
        );

        // Build the channel tree state after step 1 for step 2's merkle proof.
        let mut channel_tree_after1 = channel_tree.clone();
        channel_tree_after1.update(idx1, registered_leaf(&record1));
        assert_eq!(channel_tree_after1.get_root(), first_pis.channel_tree_root);

        // Step 2: register channel 9, chaining from step 1's proof.
        let record2 = make_record(9, 16);
        let idx2 = record2.channel_id.as_u64();
        let proof2_merkle = channel_tree_after1.prove(idx2);

        let second_witness = ChannelRegStepWitness::<F, C, D> {
            initial_value: None,
            prev_channel_reg_chain_proof: Some(first_proof.clone()),
            record: record2.clone(),
            channel_merkle_proof: proof2_merkle,
            block_number,
        };
        let second_pis = second_witness
            .to_public_inputs(&chain_vd)
            .expect("second public inputs");
        let second_proof = processor
            .prove_step(&second_witness)
            .expect("second chain proof");
        processor.verify(&second_proof).expect("second verifies");

        let expected_second_fields = second_pis
            .to_u64_vec(&processor.channel_reg_hash_chain_circuit.data.common.config)
            .to_field_vec::<F>();
        assert_eq!(second_proof.public_inputs, expected_second_fields);
        assert_eq!(second_pis.channel_reg_count.as_u64(), 2);
        assert_eq!(
            second_pis.channel_reg_hash_chain,
            record2.hash_with_prev_hash(first_pis.channel_reg_hash_chain)
        );

        // Initial state is preserved across the chain.
        assert_eq!(
            second_pis.initial_channel_reg_hash_chain,
            initial_hash_chain
        );
        assert_eq!(second_pis.initial_channel_tree_root, initial_tree_root);

        let mut channel_tree_after2 = channel_tree_after1.clone();
        channel_tree_after2.update(idx2, registered_leaf(&record2));
        assert_eq!(channel_tree_after2.get_root(), second_pis.channel_tree_root);
    }
}
