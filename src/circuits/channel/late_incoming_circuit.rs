//! Post-close continuation of the ordinary ReceiveTransfer relation.
//!
//! L1 serializes the full Balance PI commitment, initially exposed by CloseAssetBacking.
//! The existing receive target authenticates the transfer and consumes its base nullifier.
//! A separately pinned recipient-binding proof opens final H1 and decrypts the exact delta whose
//! tx-leaf hash is the base transfer's aux_data. Only the newly received amount becomes credit.
use crate::{
    circuits::{
        balance::{
            balance_pis::{BalanceFullPublicInputs, BalanceFullPublicInputsTarget},
            receive_transfer_circuit::{ReceiveTransferTarget, ReceiveTransferWitness},
        },
        validity::block_hash_chain::ext_public_state::{
            ExtendedPublicState, ExtendedPublicStateTarget,
        },
    },
    ethereum_types::{
        address::Address,
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
    },
    utils::{conversion::ToU64, recursively_verifiable::add_proof_target_and_verify},
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use serde::{Deserialize, Serialize};

pub const LATE_INCOMING_PUBLIC_INPUTS_LEN: usize = 59;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LateIncomingPublicInputs {
    pub channel_id: u32,
    pub close_intent_digest: Bytes32,
    pub final_balance_state_h1: Bytes32,
    pub previous_balance_commitment: Bytes32,
    pub next_balance_commitment: Bytes32,
    pub finalized_extended_state_commitment: Bytes32,
    pub anchor_block_number: u64,
    pub receive_nullifier: Bytes32,
    pub recipient: Address,
    pub token_index: u32,
    pub amount: u64,
}
impl LateIncomingPublicInputs {
    pub fn from_u64_slice(v: &[u64]) -> anyhow::Result<Self> {
        anyhow::ensure!(v.len() == LATE_INCOMING_PUBLIC_INPUTS_LEN, "late PI length");
        anyhow::ensure!(v[58] == 1 && v[41] < (1 << 63), "late version/anchor");
        for (i, &x) in v.iter().enumerate() {
            anyhow::ensure!(i == 41 || x <= u32::MAX as u64, "noncanonical late PI");
        }
        let word = |i| Bytes32::from_u64_slice(&v[i..i + 8]).map_err(|e| anyhow::anyhow!("{e}"));
        Ok(Self {
            channel_id: v[0] as u32,
            close_intent_digest: word(1)?,
            final_balance_state_h1: word(9)?,
            previous_balance_commitment: word(17)?,
            next_balance_commitment: word(25)?,
            finalized_extended_state_commitment: word(33)?,
            anchor_block_number: v[41],
            receive_nullifier: word(42)?,
            recipient: Address::from_u64_slice(&v[50..55]).map_err(|e| anyhow::anyhow!("{e}"))?,
            token_index: v[55] as u32,
            amount: (v[56] << 32) | v[57],
        })
    }
}

pub struct LateIncomingCircuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    C::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    receive: ReceiveTransferTarget<D>,
    binding: ProofWithPublicInputsTarget<D>,
    extended: ExtendedPublicStateTarget,
    balance_vd: VerifierCircuitData<F, C, D>,
    binding_vd: VerifierCircuitData<F, C, D>,
}
impl<F, C, const D: usize> LateIncomingCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// `binding_vd` must be the new_late_binding PostCloseClaim circuit (66 PIs), never the
    /// historical inclusion-only claim circuit. All three verifier keys are constructor-pinned.
    pub fn new(
        balance_vd: &VerifierCircuitData<F, C, D>,
        spend_vd: &VerifierCircuitData<F, C, D>,
        binding_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        assert!(
            cfg!(feature = "authenticated-tail-receive"),
            "late receipts require authenticated-tail-receive verifier keys"
        );
        assert_eq!(binding_vd.common.num_public_inputs, 66);
        let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let receive = ReceiveTransferTarget::new(&mut b, &balance_vd.common, spend_vd);
        let previous = BalanceFullPublicInputsTarget::from_pis(
            &receive.prev_balance_proof.public_inputs,
            &balance_vd.common.config,
        );
        let pinned = b.constant_verifier_data(&balance_vd.verifier_only);
        b.connect_verifier_data(&previous.vd, &pinned);
        let binding = add_proof_target_and_verify(binding_vd, &mut b);
        let q = &binding.public_inputs;
        let three = b.constant(F::from_canonical_u32(3));
        b.connect(q[57], three);
        b.connect(q[8], previous.pis.channel_id.value);
        b.connect(q[56], receive.transfer_witness.transfer.token_index);
        Bytes32Target::from_slice(&q[58..66])
            .connect(&mut b, receive.transfer_witness.transfer.aux_data);
        // C2C amounts and encrypted deltas are u64, although base assets use U256.
        let amount = receive.transfer_witness.transfer.amount.to_vec();
        for limb in &amount[..6] {
            b.assert_zero(*limb);
        }
        b.connect(amount[6], q[38]);
        b.connect(amount[7], q[39]);
        let extended = ExtendedPublicStateTarget::new(&mut b, true);
        receive
            .new_full_pis
            .pis
            .public_state
            .connect(&mut b, &extended.inner);
        let root = extended.commitment(&mut b);
        let prev_hash = previous.commitment(&mut b, &balance_vd.common.config);
        let prev = Bytes32Target::from_hash_out(&mut b, prev_hash);
        let next_hash = receive
            .new_full_pis
            .commitment(&mut b, &balance_vd.common.config);
        let next = Bytes32Target::from_hash_out(&mut b, next_hash);
        let version = b.one();
        let pi = [
            vec![q[8]],
            q[0..8].to_vec(),
            q[40..48].to_vec(),
            prev.to_vec(),
            next.to_vec(),
            root.to_vec(),
            vec![extended.inner.block_number.value],
            receive.update_private_state.nullifier.to_vec(),
            q[25..30].to_vec(),
            vec![q[56]],
            q[38..40].to_vec(),
            vec![version],
        ]
        .concat();
        assert_eq!(pi.len(), LATE_INCOMING_PUBLIC_INPUTS_LEN);
        b.register_public_inputs(&pi);
        Self {
            data: b.build::<C>(),
            receive,
            binding,
            extended,
            balance_vd: balance_vd.clone(),
            binding_vd: binding_vd.clone(),
        }
    }

    pub fn prove(
        &self,
        receive: &ReceiveTransferWitness<F, C, D>,
        binding: &ProofWithPublicInputs<F, C, D>,
        extended: &ExtendedPublicState,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.balance_vd.verify(receive.prev_balance_proof.clone())?;
        self.balance_vd
            .verify(receive.sender_balance_proof.clone())?;
        self.binding_vd.verify(binding.clone())?;
        let next = receive.to_public_inputs(&self.balance_vd.common)?;
        anyhow::ensure!(next.vd == self.balance_vd.verifier_only, "wrong Balance VK");
        anyhow::ensure!(
            next.pis.public_state == extended.inner,
            "wrong finalized anchor"
        );
        let mut w = PartialWitness::new();
        self.receive.set_witness(&mut w, receive, &next);
        w.set_proof_with_pis_target(&self.binding, binding)?;
        self.extended.set_witness(&mut w, extended);
        Ok(self.data.prove(w)?)
    }

    /// The caller persists the ordinary Balance proof with this commitment to build the next
    /// receive. A source proof supplied for a different history cannot replace the L1 checkpoint.
    pub fn balance_commitment(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<Bytes32> {
        self.balance_vd.verify(proof.clone())?;
        let full = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
            &proof.public_inputs.to_u64_vec(),
            &self.balance_vd.common.config,
        )?;
        anyhow::ensure!(full.vd == self.balance_vd.verifier_only, "wrong Balance VK");
        Ok(Bytes32::from(
            full.commitment(&self.balance_vd.common.config),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn late_statement_rejects_old_layout_noncanonical_limbs_and_unknown_version() {
        let mut v = vec![0u64; LATE_INCOMING_PUBLIC_INPUTS_LEN];
        v[0] = 7;
        v[41] = (1u64 << 63) - 1;
        v[55] = 55;
        v[56] = 1;
        v[57] = 9;
        v[58] = 1;
        assert_eq!(
            LateIncomingPublicInputs::from_u64_slice(&v).unwrap().amount,
            (1u64 << 32) + 9
        );
        for index in 0..v.len() {
            let old = v[index];
            v[index] = if index == 41 { 1u64 << 63 } else { 1u64 << 32 };
            assert!(LateIncomingPublicInputs::from_u64_slice(&v).is_err());
            v[index] = old;
        }
        assert!(LateIncomingPublicInputs::from_u64_slice(&v[..58]).is_err());
        v[58] = 2;
        assert!(LateIncomingPublicInputs::from_u64_slice(&v).is_err());
    }
}
