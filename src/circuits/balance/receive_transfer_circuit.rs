use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    circuits::balance::{
        balance_pis::{
            BalanceFullPublicInputs, BalanceFullPublicInputsTarget, BalancePublicInputs,
            BalancePublicInputsError, BalancePublicInputsTarget,
        },
        common::{
            account_state::{AccountState, AccountStateTarget},
            recipient::{
                calculate_recipient_from_user_id, calculate_recipient_from_user_id_circuit,
            },
            transfer_witness::{TransferWitness, TransferWitnessTarget},
            tx_settlement::{TxSettlement, TxSettlementTarget},
            update_private_state::{UpdatePrivateState, UpdatePrivateStateTarget},
            update_public_state::{UpdatePublicState, UpdatePublicStateTarget},
        },
    },
    common::{
        balance_state::{settled_tx_chain_push, settled_tx_chain_push_circuit},
        salt::{Salt, SaltTarget},
        transfer::{SettledTransfer, SettledTransferTarget},
        u63::{BlockNumber, BlockNumberTarget},
    },
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait,
    },
    utils::{
        conversion::ToU64,
        cyclic::add_const_gate,
        serialize::{AllGateSerializer, AllGeneratorSerializer, CircuitSerializationError},
    },
};

#[derive(Debug, thiserror::Error)]
pub enum ReceiveTransferError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Balance public inputs error: {0}")]
    BalancePublicInputsError(#[from] BalancePublicInputsError),

    #[error("Invalid balance proof: {0}")]
    InvalidBalanceProof(String),

    #[error("Invalid balance verifier data: {0}")]
    InvalidBalanceVd(String),

    #[error("Invalid recipient: {0}")]
    InvalidRecipient(String),

    #[error("Block number error: {0}")]
    BlockNumberError(String),

    #[error("Spend public inputs error: {0}")]
    SpendPisError(String),

    #[error("Failed to prove: {0}")]
    FailedToProve(String),
}

#[derive(Clone, Debug)]
pub struct ReceiveTransferWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // Previous receiver balance proof
    pub prev_balance_proof: ProofWithPublicInputs<F, C, D>,

    // Previous sender balance proof right before this transfer
    pub sender_balance_proof: ProofWithPublicInputs<F, C, D>,

    /* sender_update_public_state.old ==
     * sender_balance_proof.public_state */
    pub sender_update_public_state: UpdatePublicState,

    /* receiver_update_public_state.old ==
     * prev_balance_proof.public_state */
    pub receiver_update_public_state: UpdatePublicState,

    // receiver's new block_r
    pub new_block_r: BlockNumber,

    // account state that proves no outgoing tx (prev_balance_proof.block_r, new_block_r]
    pub account_state: AccountState,

    // tx settlement that includes the transfer
    pub tx_settlement: TxSettlement<F, C, D>,

    // transfer witness that proves the transfer is included in tx_settlement.tx
    pub transfer_witness: TransferWitness,

    // salt for the transfer.recipient
    pub transfer_salt: Salt,

    // private state update
    pub update_private_state: UpdatePrivateState,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceiveTransferWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        balance_cd: &CommonCircuitData<F, D>,
    ) -> Result<BalanceFullPublicInputs<F, C, D>, ReceiveTransferError> {
        // obtain public inputs
        let prev_full_pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
            &self.prev_balance_proof.public_inputs.to_u64_vec(),
            &balance_cd.config,
        )?;
        let sender_full_pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
            &self.sender_balance_proof.public_inputs.to_u64_vec(),
            &balance_cd.config,
        )?;
        // balance vd check
        if prev_full_pis.vd != sender_full_pis.vd {
            return Err(ReceiveTransferError::InvalidBalanceVd(format!(
                "prev_full_pis.vd {:?} != sender_full_pis.vd {:?}",
                prev_full_pis.vd, sender_full_pis.vd
            )));
        }
        let balance_vd = &prev_full_pis.vd;

        let prev_balance_pis = &prev_full_pis.pis;
        let sender_balance_pis = &sender_full_pis.pis;

        let sender_user_id = sender_balance_pis.channel_id;
        let receiver_user_id = prev_balance_pis.channel_id;

        // check update_public_state connections
        if self.receiver_update_public_state.old != prev_balance_pis.public_state {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "receiver_update_public_state.old {:?} != prev_balance_pis.public_state {:?}",
                self.receiver_update_public_state.old, prev_balance_pis.public_state,
            )));
        }
        if self.sender_update_public_state.old != sender_balance_pis.public_state {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "sender_update_public_state.old {:?} != sender_balance_pis.public_state {:?}",
                self.sender_update_public_state.old, sender_balance_pis.public_state,
            )));
        }
        if self.receiver_update_public_state.new != self.sender_update_public_state.new {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "receiver_update_public_state.new {:?} != sender_update_public_state.new {:?}",
                self.receiver_update_public_state.new, self.sender_update_public_state.new,
            )));
        }
        let public_state = self.receiver_update_public_state.new.clone();

        // check account_state connections
        if self.account_state.channel_id != receiver_user_id {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "account_state.channel_id {:?} != receiver_user_id {:?}",
                self.account_state.channel_id, receiver_user_id,
            )));
        }
        if self.account_state.account_tree_root != public_state.account_tree_root {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "account_state.account_tree_root {:?} != public_state.account_tree_root {:?}",
                self.account_state.account_tree_root, public_state.account_tree_root,
            )));
        }

        // check tx settlement connections
        if self.tx_settlement.channel_id != sender_user_id {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "tx_settlement.channel_id {:?} != sender_user_id {:?}",
                self.tx_settlement.channel_id, sender_user_id,
            )));
        }
        if self.tx_settlement.public_state != public_state {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "tx_settlement.public_state {:?} != public_state {:?}",
                self.tx_settlement.public_state, public_state,
            )));
        }
        let tx = &self.tx_settlement.tx;

        // check transfer_witness connections
        if self.transfer_witness.transfer_tree_root != tx.transfer_tree_root {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "transfer_witness.transfer_tree_root {:?} != tx.transfer_tree_root {:?}",
                self.transfer_witness.transfer_tree_root, tx.transfer_tree_root,
            )));
        }

        // recipient check (salt check)
        let expected_recipient =
            calculate_recipient_from_user_id(receiver_user_id, self.transfer_salt);
        if self.transfer_witness.transfer.recipient != expected_recipient {
            return Err(ReceiveTransferError::InvalidRecipient(format!(
                "transfer.recipient {:?} != expected_recipient {:?}",
                self.transfer_witness.transfer.recipient, expected_recipient,
            )));
        }

        // block number checks
        let prev_block_r = prev_balance_pis.block_r;

        // check prev_block_r <= new_block_r <= public_state.block_number
        if self.new_block_r < prev_block_r || self.new_block_r > public_state.block_number {
            return Err(ReceiveTransferError::BlockNumberError(format!(
                "Not prev_block_r <= new_block_r <= public_state.block_number: {:?} <= {:?} <= {:?}",
                prev_block_r, self.new_block_r, public_state.block_number,
            )));
        }

        // if there is a previous outgoing tx check additional conditions
        if self.account_state.channel_leaf.prev != BlockNumber::default() {
            // user_witness.send_leaf.prev <= receiver_balance_proof.block_r
            if self.account_state.send_leaf.prev > prev_block_r {
                return Err(ReceiveTransferError::BlockNumberError(format!(
                    "Not account_state.send_leaf.prev <= prev_balance_pis.block_r: {:?} <= {:?}",
                    self.account_state.send_leaf.prev, prev_block_r,
                )));
            }

            // new_block_r < user_witness.send_leaf.cur
            if self.new_block_r >= self.account_state.send_leaf.cur {
                return Err(ReceiveTransferError::BlockNumberError(format!(
                    "Not new_block_r < account_state.send_leaf.cur: {:?} < {:?}",
                    self.new_block_r, self.account_state.send_leaf.cur,
                )));
            }
        }

        // Check receiving eligibilities:

        // tx_settlement_witness.tx_block_number() <= new_block_r
        if self.tx_settlement.tx_block_number() > self.new_block_r {
            return Err(ReceiveTransferError::BlockNumberError(format!(
                "Not tx_settlement.tx_block_number() <= new_block_r: {:?} <= {:?}",
                self.tx_settlement.tx_block_number(),
                self.new_block_r,
            )));
        }

        let spend_pis = self.tx_settlement.spend_pis().map_err(|e| {
            ReceiveTransferError::SpendPisError(format!("failed to get spend_pis: {e}"))
        })?;
        // sender_balance_pis.private_commitment ==
        // tx_settlement_witness.spent_proof.prev_private_commitment
        if sender_balance_pis.private_commitment != spend_pis.prev_private_commitment {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "sender_balance_pis.private_commitment {:?} != spend_pis.prev_private_commitment {:?}",
                sender_balance_pis.private_commitment, spend_pis.prev_private_commitment,
            )));
        }
        // tx_settlement_witness.spent_proof.is_valid == true
        if !spend_pis.is_valid {
            return Err(ReceiveTransferError::ConnectionError(
                "spend_pis.is_valid is false".to_string(),
            ));
        }

        // private state update
        let tx_block_number = self.tx_settlement.tx_block_number();
        let transfer = &self.transfer_witness.transfer;
        let settled_transfer = SettledTransfer::new(
            transfer.clone(),
            sender_user_id,
            self.transfer_witness.transfer_index,
            tx_block_number,
        );
        let nullifier = settled_transfer.nullifier();
        if self.update_private_state.token_index != transfer.token_index {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "update_private_state.token_index {:?} != transfer.token_index {:?}",
                self.update_private_state.token_index, transfer.token_index,
            )));
        }
        if self.update_private_state.amount != transfer.amount {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "update_private_state.amount {:?} != transfer.amount {:?}",
                self.update_private_state.amount, transfer.amount,
            )));
        }
        if self.update_private_state.nullifier != nullifier {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "update_private_state.nullifier {:?} != settled_transfer.nullifier {:?}",
                self.update_private_state.nullifier, nullifier,
            )));
        }
        if self.update_private_state.prev_private_state.commitment()
            != prev_balance_pis.private_commitment
        {
            return Err(ReceiveTransferError::ConnectionError(format!(
                "update_private_state.prev_private_state.commitment() {:?} != prev_balance_pis.private_commitment {:?}",
                self.update_private_state.prev_private_state.commitment(),
                prev_balance_pis.private_commitment,
            )));
        }
        let new_private_commitment = self.update_private_state.new_private_state.commitment();

        // detail2 §C-6/§F-1: for inter-channel transfers the merkle-bound `aux_data` carries the
        // tx leaf hash and is folded into the settled-tx chain; legacy / intra transfers carry
        // aux_data == 0 and leave the chain unchanged.
        let new_settled_tx_chain = if transfer.aux_data == Bytes32::default() {
            prev_balance_pis.settled_tx_chain
        } else {
            settled_tx_chain_push(prev_balance_pis.settled_tx_chain, transfer.aux_data)
        };

        let new_full_pis = BalanceFullPublicInputs {
            pis: BalancePublicInputs {
                channel_id: receiver_user_id,
                public_state,
                block_r: self.new_block_r,
                private_commitment: new_private_commitment,
                settled_tx_chain: new_settled_tx_chain,
            },
            vd: balance_vd.clone(),
        };
        Ok(new_full_pis)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiveTransferTarget<const D: usize> {
    pub prev_balance_proof: ProofWithPublicInputsTarget<D>,
    pub sender_balance_proof: ProofWithPublicInputsTarget<D>,
    pub sender_update_public_state: UpdatePublicStateTarget,
    pub receiver_update_public_state: UpdatePublicStateTarget,
    pub new_block_r: BlockNumberTarget,
    pub account_state: AccountStateTarget,
    pub tx_settlement: TxSettlementTarget<D>,
    pub transfer_witness: TransferWitnessTarget,
    pub transfer_salt: SaltTarget,
    pub update_private_state: UpdatePrivateStateTarget,
    pub new_full_pis: BalanceFullPublicInputsTarget,
}

impl<const D: usize> ReceiveTransferTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        balance_cd: &CommonCircuitData<F, D>,
        spend_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let prev_balance_proof = builder.add_virtual_proof_with_pis(balance_cd);
        let prev_balance_full_pis = BalanceFullPublicInputsTarget::from_pis(
            &prev_balance_proof.public_inputs,
            &balance_cd.config,
        );
        let sender_balance_proof = builder.add_virtual_proof_with_pis(balance_cd);
        let sender_balance_full_pis = BalanceFullPublicInputsTarget::from_pis(
            &sender_balance_proof.public_inputs,
            &balance_cd.config,
        );

        // Force a single verifier key shared between receiver and sender states.
        builder.connect_verifier_data(&prev_balance_full_pis.vd, &sender_balance_full_pis.vd);
        let vd = &prev_balance_full_pis.vd;

        // verify balance proofs
        builder.verify_proof::<C>(&prev_balance_proof, &vd, balance_cd);
        builder.verify_proof::<C>(&sender_balance_proof, &vd, balance_cd);

        let receiver_prev_pis = prev_balance_full_pis.pis.clone();
        let sender_prev_pis = sender_balance_full_pis.pis.clone();

        let sender_user_id = &sender_prev_pis.channel_id;
        let receiver_user_id = &receiver_prev_pis.channel_id;

        let sender_update_public_state = UpdatePublicStateTarget::new::<F, C, D>(builder);
        let receiver_update_public_state = UpdatePublicStateTarget::new::<F, C, D>(builder);
        let new_block_r = BlockNumberTarget::new(builder, true);
        let account_state = AccountStateTarget::new::<F, C, D>(builder, true);
        let tx_settlement = TxSettlementTarget::new(builder, spend_vd, true);
        let transfer_witness = TransferWitnessTarget::new::<F, C, D>(builder, true);
        let transfer_salt = SaltTarget::new(builder);
        let update_private_state = UpdatePrivateStateTarget::new::<F, C, D>(builder, true);

        // Receiver previous state matches proof; both sides agree on the updated public state.
        receiver_update_public_state
            .old
            .connect(builder, &receiver_prev_pis.public_state);
        sender_update_public_state
            .old
            .connect(builder, &sender_prev_pis.public_state);
        receiver_update_public_state
            .new
            .connect(builder, &sender_update_public_state.new);
        let public_state = &receiver_update_public_state.new;

        // check account_state connections
        account_state.channel_id.connect(builder, receiver_user_id);
        account_state
            .account_tree_root
            .connect(builder, public_state.account_tree_root);

        // check tx settlement connections
        tx_settlement.channel_id.connect(builder, &sender_user_id);
        tx_settlement.public_state.connect(builder, public_state);
        let tx = &tx_settlement.tx;

        // Transfer witness must come from the settled transaction.
        transfer_witness
            .transfer_tree_root
            .connect(builder, tx.transfer_tree_root);

        // recipient check (salt check)
        let expected_recipient = calculate_recipient_from_user_id_circuit(
            builder,
            &receiver_prev_pis.channel_id,
            &transfer_salt,
        );
        transfer_witness
            .transfer
            .recipient
            .connect(builder, expected_recipient);

        // block number checks
        let prev_block_r = receiver_prev_pis.block_r;

        // new_block_r >= prev_block_r
        new_block_r.enforce_ge(builder, &prev_block_r);

        // public_state.block_number >= new_block_r
        public_state.block_number.enforce_ge(builder, &new_block_r);

        let has_no_outgoint_tx = account_state.channel_leaf.prev.is_zero(builder);
        let has_outgoint_tx = builder.not(has_no_outgoint_tx);

        // user_witness.send_leaf.prev <= prev_block_r if has_outgoint_tx==true
        prev_block_r.conditional_ge(builder, &account_state.send_leaf.prev, has_outgoint_tx);

        // new_block_r < user_witness.send_leaf.cur if has_outgoint_tx==true
        account_state
            .send_leaf
            .cur
            .conditional_gt(builder, &new_block_r, has_outgoint_tx);

        // tx_block_number <= new_block_r so that the transfer can be received.
        let tx_block_number = tx_settlement.tx_block_number();
        new_block_r.enforce_ge(builder, &tx_block_number);

        // Sender commitment matches spend proof and the proof is marked valid.
        let spend_pis = tx_settlement.spend_pis();
        spend_pis
            .prev_private_commitment
            .connect(builder, sender_prev_pis.private_commitment.clone());
        builder.assert_one(spend_pis.is_valid.target);

        let settled_transfer = SettledTransferTarget {
            inner: transfer_witness.transfer.clone(),
            from: tx_settlement.channel_id.clone(),
            transfer_index: transfer_witness.transfer_index,
            block_number: tx_block_number.clone(),
        };
        let settled_nullifier = settled_transfer.nullifier(builder);

        builder.connect(
            transfer_witness.transfer.token_index,
            update_private_state.token_index,
        );
        transfer_witness
            .transfer
            .amount
            .connect(builder, update_private_state.amount.clone());
        update_private_state
            .nullifier
            .connect(builder, settled_nullifier);

        let prev_private_commitment = update_private_state.prev_private_state.commitment(builder);
        prev_private_commitment.connect(builder, receiver_prev_pis.private_commitment);
        let new_private_commitment = update_private_state.new_private_state.commitment(builder);

        // detail2 §C-6/§F-1 chain fold over the consumed transfer's aux_data, gated on
        // aux_data != 0 (legacy / intra-channel transfers leave the chain unchanged).
        //
        // SECURITY: the circuit only guarantees that the chain PI is a faithful fold of the
        // merkle-bound `aux_data` of the exact transfer leaf this proof consumed
        // (transfer_witness verifies the leaf — including aux_data — against
        // tx.transfer_tree_root, which is bound to the sender's settled tx). The *semantic*
        // correctness of `aux_data == tx_leaf_hash(...)` for inter-channel transfers is enforced
        // off-circuit at co-sign time (threat model F3-A), multi-layered with the §E-2
        // channelUpdateZKP verification and the receiving channel's independent recomputation.
        // The sender's own chain PI is NOT constrained here — the sender folds the same leaf in
        // their send step.
        let transfer_aux_data = transfer_witness.transfer.aux_data;
        let aux_is_zero = transfer_aux_data.is_zero::<F, D, Bytes32>(builder);
        let pushed_chain = settled_tx_chain_push_circuit::<F, C, D>(
            builder,
            receiver_prev_pis.settled_tx_chain,
            transfer_aux_data,
        );
        let new_settled_tx_chain = Bytes32Target::select(
            builder,
            aux_is_zero,
            receiver_prev_pis.settled_tx_chain,
            pushed_chain,
        );

        let new_pis = BalancePublicInputsTarget {
            channel_id: receiver_prev_pis.channel_id.clone(),
            public_state: receiver_update_public_state.new.clone(),
            block_r: new_block_r.clone(),
            private_commitment: new_private_commitment.clone(),
            settled_tx_chain: new_settled_tx_chain,
        };
        let new_full_pis = BalanceFullPublicInputsTarget {
            pis: new_pis,
            vd: prev_balance_full_pis.vd.clone(),
        };

        Self {
            prev_balance_proof,
            sender_balance_proof,
            sender_update_public_state,
            receiver_update_public_state,
            new_block_r,
            account_state,
            tx_settlement,
            transfer_witness,
            transfer_salt,
            update_private_state,
            new_full_pis,
        }
    }

    pub fn set_witness<F, C, W>(
        &self,
        witness: &mut W,
        value: &ReceiveTransferWitness<F, C, D>,
        new_full_pis: &BalanceFullPublicInputs<F, C, D>,
    ) where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
        W: WitnessWrite<F>,
    {
        witness.set_proof_with_pis_target(&self.prev_balance_proof, &value.prev_balance_proof);
        witness.set_proof_with_pis_target(&self.sender_balance_proof, &value.sender_balance_proof);
        self.sender_update_public_state
            .set_witness(witness, &value.sender_update_public_state);
        self.receiver_update_public_state
            .set_witness(witness, &value.receiver_update_public_state);
        self.new_block_r.set_witness(witness, value.new_block_r);
        self.account_state
            .set_witness(witness, &value.account_state);
        self.tx_settlement
            .set_witness::<F, C, _>(witness, &value.tx_settlement);
        self.transfer_witness
            .set_witness(witness, &value.transfer_witness);
        self.transfer_salt.set_witness(witness, value.transfer_salt);
        self.update_private_state
            .set_witness(witness, &value.update_private_state);
        self.new_full_pis.set_witness(witness, new_full_pis);
    }
}

#[derive(Debug)]
pub struct ReceiveTransferCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub balance_cd: CommonCircuitData<F, D>,
    pub target: ReceiveTransferTarget<D>,
    pub public_inputs: BalanceFullPublicInputsTarget,
}

impl<F, C, const D: usize> ReceiveTransferCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static + Default,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        balance_cd: &CommonCircuitData<F, D>,
        spend_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = ReceiveTransferTarget::new(&mut builder, &balance_cd, spend_vd);
        let public_inputs = target.new_full_pis.clone();
        builder.register_public_inputs(&public_inputs.to_vec(&balance_cd.config));

        // add some constantss gate to enable `conditionally_verify_proof`
        add_const_gate(&mut builder);
        let data = builder.build();

        Self {
            data,
            balance_cd: balance_cd.clone(),
            target,
            public_inputs,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CircuitSerializationError> {
        let gate_serializer = AllGateSerializer;
        let generator_serializer = AllGeneratorSerializer::<C, D>::default();
        let data_bytes = self
            .data
            .to_bytes(&gate_serializer, &generator_serializer)
            .map_err(|e| CircuitSerializationError::serialization("circuit data", e))?;
        let balance_cd_bytes = self
            .balance_cd
            .to_bytes(&gate_serializer)
            .map_err(|e| CircuitSerializationError::serialization("common circuit data", e))?;
        let target_bytes = bincode::serde::encode_to_vec(&self.target, bincode::config::standard())
            .map_err(|e| CircuitSerializationError::serialization("receive transfer target", e))?;
        let public_inputs_bytes =
            bincode::serde::encode_to_vec(&self.public_inputs, bincode::config::standard())
                .map_err(|e| {
                    CircuitSerializationError::serialization("balance public inputs target", e)
                })?;
        let circuit_bytes = ReceiveTransferCircuitBytes {
            data: data_bytes,
            balance_cd: balance_cd_bytes,
            target: target_bytes,
            public_inputs: public_inputs_bytes,
        };
        let bytes = bincode::serde::encode_to_vec(&circuit_bytes, bincode::config::standard())
            .map_err(|e| CircuitSerializationError::serialization("receive transfer circuit", e))?;
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CircuitSerializationError> {
        let (circuit_bytes, _) =
            bincode::serde::decode_from_slice::<ReceiveTransferCircuitBytes, _>(
                bytes,
                bincode::config::standard(),
            )
            .map_err(|e| {
                CircuitSerializationError::deserialization("receive transfer circuit", e)
            })?;
        let gate_serializer = AllGateSerializer;
        let generator_serializer = AllGeneratorSerializer::<C, D>::default();
        let data = CircuitData::<F, C, D>::from_bytes(
            &circuit_bytes.data,
            &gate_serializer,
            &generator_serializer,
        )
        .map_err(|e| CircuitSerializationError::deserialization("circuit data", e))?;
        let balance_cd =
            CommonCircuitData::<F, D>::from_bytes(circuit_bytes.balance_cd, &gate_serializer)
                .map_err(|e| {
                    CircuitSerializationError::deserialization("common circuit data", e)
                })?;
        let target = bincode::serde::decode_from_slice::<ReceiveTransferTarget<D>, _>(
            &circuit_bytes.target,
            bincode::config::standard(),
        )
        .map_err(|e| CircuitSerializationError::deserialization("receive transfer target", e))?
        .0;
        let public_inputs = bincode::serde::decode_from_slice::<BalanceFullPublicInputsTarget, _>(
            &circuit_bytes.public_inputs,
            bincode::config::standard(),
        )
        .map_err(|e| CircuitSerializationError::deserialization("balance public inputs target", e))?
        .0;
        Ok(Self {
            data,
            balance_cd,
            target,
            public_inputs,
        })
    }

    pub fn prove(
        &self,
        witness: &ReceiveTransferWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ReceiveTransferError> {
        let new_full_pis = witness.to_public_inputs(&self.balance_cd)?;
        let mut pw = PartialWitness::<F>::new();
        self.target
            .set_witness::<F, C, _>(&mut pw, witness, &new_full_pis);
        self.public_inputs.set_witness(&mut pw, &new_full_pis);
        self.data
            .prove(pw)
            .map_err(|e| ReceiveTransferError::FailedToProve(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveTransferCircuitBytes {
    pub data: Vec<u8>,
    pub balance_cd: Vec<u8>,
    pub target: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::balance::{
            balance_pis::{
                BALANCE_PUBLIC_INPUTS_LEN, BalanceFullPublicInputs, BalancePublicInputs,
            },
            common::{
                account_state::AccountState, recipient::calculate_recipient_from_user_id,
                transfer_witness::TransferWitness, update_private_state::UpdatePrivateState,
                update_public_state::UpdatePublicState,
            },
            spend_circuit::{SpendCircuit, SpendWitness},
        },
        common::{
            channel_id::ChannelId,
            private_state::FullPrivateState,
            public_state::PublicState,
            salt::Salt,
            transfer::Transfer,
            trees::{
                asset_tree::AssetTree,
                channel_tree::{ChannelLeaf, ChannelTree, SendLeaf, SendTree},
                nullifier_tree::NullifierTree,
                transfer_tree::TransferTree,
                tx_tree::TxTree,
            },
            tx::Tx,
            u63::BlockNumber,
        },
        constants::{
            ASSET_TREE_HEIGHT, CHANNEL_TREE_HEIGHT, MAX_NUM_TRANSFERS_PER_TX, SEND_TREE_HEIGHT,
            TRANSFER_TREE_HEIGHT,
        },
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256},
        utils::{
            conversion::ToField as _, cyclic::TestCyclicCircuit,
            poseidon_hash_out::PoseidonHashOut, trees::get_root::get_merkle_root_from_leaves,
        },
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_receive_transfer_circuit() {
        let mut rng = rand::thread_rng();

        let receiver_user_id = ChannelId::new(2).unwrap();
        let transfer_salt = Salt::rand(&mut rng);
        let recipient = calculate_recipient_from_user_id(receiver_user_id, transfer_salt);

        let mut sender_full_state = FullPrivateState::new(Salt::rand(&mut rng));
        let mut asset_tree_initial = AssetTree::new(ASSET_TREE_HEIGHT);
        let mut transfers = Vec::with_capacity(MAX_NUM_TRANSFERS_PER_TX);
        let mut before_balances = Vec::with_capacity(MAX_NUM_TRANSFERS_PER_TX);
        let mut asset_merkle_proofs = Vec::with_capacity(MAX_NUM_TRANSFERS_PER_TX);

        // Inter-channel transfers carry a nonzero aux_data (= tx leaf hash, detail2 §C-6); the
        // received transfer at index 0 uses one so the chain fold is exercised.
        let inter_channel_aux = Bytes32::from_u32_slice(&[11, 22, 33, 44, 55, 66, 77, 88]).unwrap();
        for i in 0..MAX_NUM_TRANSFERS_PER_TX {
            let amount = U256::from((i as u32) + 1);
            let base_balance = amount + U256::from(10u32);
            let transfer = Transfer {
                recipient: if i == 0 {
                    recipient
                } else {
                    Bytes32::default()
                },
                token_index: i as u32,
                amount,
                aux_data: if i == 0 {
                    inter_channel_aux
                } else {
                    Bytes32::default()
                },
            };
            asset_tree_initial.update(i as u64, base_balance);
            transfers.push(transfer);
        }

        let mut asset_tree_current = asset_tree_initial.clone();
        for transfer in &transfers {
            let index = transfer.token_index as u64;
            let balance = asset_tree_current.get_leaf(index);
            let proof = asset_tree_current.prove(index);
            before_balances.push(balance);
            asset_merkle_proofs.push(proof);
            let new_balance = balance - transfer.amount;
            asset_tree_current.update(index, new_balance);
        }
        let tx = Tx {
            transfer_tree_root: get_merkle_root_from_leaves(TRANSFER_TREE_HEIGHT, &transfers)
                .unwrap(),
            nonce: sender_full_state.nonce,
        };
        let sent_tx_merkle_proof = sender_full_state.sent_tx_tree.prove(tx.nonce as u64);

        sender_full_state.asset_tree = asset_tree_initial.clone();
        let prev_private_state_sender = sender_full_state.to_private_state();
        let spend_witness = SpendWitness {
            tx_nonce: prev_private_state_sender.nonce,
            prev_private_state: prev_private_state_sender.clone(),
            transfers: transfers.clone(),
            before_balances: before_balances.clone(),
            asset_merkle_proofs: asset_merkle_proofs.clone(),
            sent_tx_merkle_proof,
        };

        let spend_circuit = SpendCircuit::<F, C, D>::new();
        let spend_vd = spend_circuit.data.verifier_data();
        let spend_proof = spend_circuit
            .prove(&spend_witness)
            .expect("spend proof should succeed");
        let spend_pis = spend_witness
            .to_public_inputs()
            .expect("public inputs from spend witness");
        let tx = spend_pis.tx.clone();

        let mut tx_tree = TxTree::init();
        let key_id = 1u32;
        tx_tree.update(key_id as u64, tx.clone());
        let tx_merkle_proof = tx_tree.prove(key_id as u64);
        let tx_tree_root: PoseidonHashOut = tx_tree.get_root();

        let send_leaf_sender = SendLeaf {
            prev: BlockNumber::new(2).unwrap(),
            cur: BlockNumber::new(5).unwrap(),
            tx_tree_root: tx_tree_root.into(),
        };
        let mut send_tree_sender = SendTree::new(SEND_TREE_HEIGHT);
        send_tree_sender.push(send_leaf_sender.clone());
        let send_leaf_index_sender = 0u32;
        let send_merkle_proof_sender = send_tree_sender.prove(send_leaf_index_sender as u64);

        let send_leaf_receiver = SendLeaf {
            prev: BlockNumber::new(0).unwrap(),
            cur: BlockNumber::new(7).unwrap(),
            tx_tree_root: tx_tree_root.into(),
        };
        let mut send_tree_receiver = SendTree::new(SEND_TREE_HEIGHT);
        send_tree_receiver.push(send_leaf_receiver.clone());
        let send_leaf_index_receiver = 0u32;
        let send_merkle_proof_receiver = send_tree_receiver.prove(send_leaf_index_receiver as u64);

        let sender_user_id = ChannelId::new(key_id as u64).unwrap();

        let user_leaf_sender = ChannelLeaf {
            index: send_tree_sender.len() as u32,
            prev: send_leaf_sender.cur,
            send_tree_root: send_tree_sender.get_root(),
            member_pubkeys_root: ChannelLeaf::default().member_pubkeys_root,
        };
        let user_leaf_receiver = ChannelLeaf {
            index: send_tree_receiver.len() as u32,
            prev: send_leaf_receiver.prev,
            send_tree_root: send_tree_receiver.get_root(),
            member_pubkeys_root: ChannelLeaf::default().member_pubkeys_root,
        };

        let mut channel_tree = ChannelTree::new(CHANNEL_TREE_HEIGHT);
        channel_tree.update(sender_user_id.as_u64(), user_leaf_sender.clone());
        channel_tree.update(receiver_user_id.as_u64(), user_leaf_receiver.clone());
        let sender_user_merkle_proof = channel_tree.prove(sender_user_id.as_u64());
        let receiver_user_merkle_proof = channel_tree.prove(receiver_user_id.as_u64());
        let account_tree_root = channel_tree.get_root();

        let account_state_sender = AccountState::new(
            sender_user_id,
            account_tree_root,
            send_leaf_sender.clone(),
            send_leaf_index_sender,
            send_merkle_proof_sender.clone(),
            user_leaf_sender.clone(),
            sender_user_merkle_proof.clone(),
        )
        .expect("sender account state should be valid");
        let account_state_receiver = AccountState::new(
            receiver_user_id,
            account_tree_root,
            send_leaf_receiver.clone(),
            send_leaf_index_receiver,
            send_merkle_proof_receiver.clone(),
            user_leaf_receiver.clone(),
            receiver_user_merkle_proof.clone(),
        )
        .expect("receiver account state should be valid");

        let public_state = PublicState {
            block_number: BlockNumber::new(6).unwrap(),
            timestamp: 0,
            account_tree_root,
            deposit_tree_root: PoseidonHashOut::default(),
            prev_public_state_root: PoseidonHashOut::default(),
        };

        let sender_update_public_state =
            UpdatePublicState::new(public_state.clone(), public_state.clone(), None)
                .expect("sender update public state");
        let receiver_update_public_state =
            UpdatePublicState::new(public_state.clone(), public_state.clone(), None)
                .expect("receiver update public state");

        let tx_settlement = TxSettlement::new(
            &spend_vd,
            sender_user_id,
            tx.clone(),
            public_state.clone(),
            account_state_sender.clone(),
            tx_merkle_proof.clone(),
            spend_proof.clone(),
        )
        .expect("tx settlement");

        let mut transfer_tree = TransferTree::new(TRANSFER_TREE_HEIGHT);
        for transfer in &transfers {
            transfer_tree.push(transfer.clone());
        }
        let transfer_index = 0u32;
        let transfer_merkle_proof = transfer_tree.prove(transfer_index as u64);
        let transfer_tree_root = transfer_tree.get_root();
        assert_eq!(transfer_tree_root, tx.transfer_tree_root);

        let transfer_witness = TransferWitness::new(
            transfer_tree_root,
            transfers[transfer_index as usize].clone(),
            transfer_index,
            transfer_merkle_proof,
        )
        .expect("transfer witness");

        let mut receiver_full_state = FullPrivateState::new(Salt::rand(&mut rng));
        receiver_full_state.asset_tree = AssetTree::new(ASSET_TREE_HEIGHT);
        receiver_full_state.asset_tree.update(
            transfer_witness.transfer.token_index as u64,
            U256::from(11u32),
        );
        receiver_full_state.nullifier_tree = NullifierTree::init();
        let prev_private_state_receiver = receiver_full_state.to_private_state();

        let receiver_asset_tree = receiver_full_state.asset_tree.clone();
        let prev_balance_receiver =
            receiver_asset_tree.get_leaf(transfer_witness.transfer.token_index as u64);
        let asset_merkle_proof_receiver =
            receiver_asset_tree.prove(transfer_witness.transfer.token_index as u64);

        let mut receiver_nullifier_tree = receiver_full_state.nullifier_tree.clone();
        let tx_block_number = tx_settlement.tx_block_number();
        let settled_transfer = SettledTransfer::new(
            transfer_witness.transfer.clone(),
            sender_user_id,
            transfer_witness.transfer_index,
            tx_block_number,
        );
        let nullifier = settled_transfer.nullifier();
        let nullifier_proof = receiver_nullifier_tree
            .prove_and_insert(nullifier)
            .expect("nullifier proof");

        let update_private_state = UpdatePrivateState::new(
            transfer_witness.transfer.token_index,
            transfer_witness.transfer.amount,
            nullifier,
            &prev_private_state_receiver,
            &nullifier_proof,
            prev_balance_receiver,
            &asset_merkle_proof_receiver,
        )
        .expect("update private state");

        // Nonzero previous chain so the test exercises real folding, not just genesis push.
        let receiver_prev_chain = Bytes32::from_u32_slice(&[9, 9, 9, 9, 9, 9, 9, 9]).unwrap();
        let receiver_prev_balance_pis = BalancePublicInputs {
            channel_id: receiver_user_id,
            public_state: public_state.clone(),
            block_r: BlockNumber::new(4).unwrap(),
            private_commitment: prev_private_state_receiver.commitment(),
            settled_tx_chain: receiver_prev_chain,
        };
        let sender_prev_balance_pis = BalancePublicInputs {
            channel_id: sender_user_id,
            public_state: public_state.clone(),
            block_r: BlockNumber::new(5).unwrap(),
            private_commitment: spend_pis.prev_private_commitment,
            settled_tx_chain: Bytes32::default(),
        };

        let pis_len = BALANCE_PUBLIC_INPUTS_LEN;
        let balance_common_data = TestCyclicCircuit::<F, C, D>::generate_cd(pis_len);
        let balance_config = CircuitConfig::standard_recursion_config();
        let balance_circuit =
            TestCyclicCircuit::<F, C, D>::new(balance_config, pis_len, &balance_common_data);
        let balance_vd = balance_circuit.data.verifier_data();
        let balance_cd = balance_vd.common.clone();

        let receiver_prev_full_pis = BalanceFullPublicInputs {
            pis: receiver_prev_balance_pis.clone(),
            vd: balance_vd.verifier_only.clone(),
        };
        let sender_prev_full_pis = BalanceFullPublicInputs {
            pis: sender_prev_balance_pis.clone(),
            vd: balance_vd.verifier_only.clone(),
        };

        let receiver_fields = receiver_prev_full_pis
            .to_u64_vec(&balance_vd.common.config)
            .to_field_vec::<F>();
        let receiver_prev_balance_proof = balance_circuit
            .prove(Some(receiver_fields.as_slice()), None)
            .expect("receiver balance proof");

        let sender_fields = sender_prev_full_pis
            .to_u64_vec(&balance_vd.common.config)
            .to_field_vec::<F>();
        let sender_balance_proof = balance_circuit
            .prove(Some(sender_fields.as_slice()), None)
            .expect("sender balance proof");

        let witness = ReceiveTransferWitness {
            prev_balance_proof: receiver_prev_balance_proof.clone(),
            sender_balance_proof: sender_balance_proof.clone(),
            sender_update_public_state,
            receiver_update_public_state,
            new_block_r: BlockNumber::new(6).unwrap(),
            account_state: account_state_receiver,
            tx_settlement,
            transfer_witness,
            transfer_salt,
            update_private_state: update_private_state.clone(),
        };

        let circuit = ReceiveTransferCircuit::<F, C, D>::new(&balance_cd, &spend_vd);
        let proof = circuit
            .prove(&witness)
            .expect("receive transfer proof should succeed");

        circuit
            .data
            .verify(proof.clone())
            .expect("receive transfer proof verification");

        let expected = witness
            .to_public_inputs(&balance_cd)
            .expect("expected public inputs");
        let expected_fields = expected
            .to_u64_vec(&balance_vd.common.config)
            .to_field_vec::<F>();

        assert_eq!(proof.public_inputs, expected_fields);
        assert_eq!(
            expected.pis.private_commitment,
            update_private_state.new_private_state.commitment(),
        );
        // detail2 §C-6/§F-1: the nonzero aux_data of the consumed transfer is folded.
        assert_eq!(
            expected.pis.settled_tx_chain,
            crate::common::balance_state::settled_tx_chain_push(
                receiver_prev_chain,
                inter_channel_aux
            ),
        );
    }

    #[test]
    fn test_receive_transfer_circuit_serialization() {
        let pis_len = BALANCE_PUBLIC_INPUTS_LEN;
        let balance_common_data = TestCyclicCircuit::<F, C, D>::generate_cd(pis_len);
        let balance_config = CircuitConfig::standard_recursion_config();
        let balance_circuit =
            TestCyclicCircuit::<F, C, D>::new(balance_config, pis_len, &balance_common_data);
        let balance_vd = balance_circuit.data.verifier_data();
        let balance_cd = balance_vd.common.clone();

        let spend_circuit = SpendCircuit::<F, C, D>::new();
        let spend_vd = spend_circuit.data.verifier_data();
        let circuit = ReceiveTransferCircuit::<F, C, D>::new(&balance_cd, &spend_vd);

        let bytes = circuit.to_bytes().expect("circuit to bytes");
        let deserialized =
            ReceiveTransferCircuit::<F, C, D>::from_bytes(&bytes).expect("circuit from bytes");
        assert_eq!(circuit.data, deserialized.data);
    }
}
