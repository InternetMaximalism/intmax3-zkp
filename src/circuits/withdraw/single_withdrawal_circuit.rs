use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::cyclic_recursion::check_cyclic_proof_verifier_data,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    circuits::balance::{
        balance_pis::{BalanceFullPublicInputs, BalanceFullPublicInputsTarget},
        common::{
            account_state::{AccountState, AccountStateError, AccountStateTarget},
            recipient::{extract_address_from_recipient, extract_address_from_recipient_circuit},
            transfer_witness::{TransferWitness, TransferWitnessError, TransferWitnessTarget},
            update_public_state::{UpdatePublicState, UpdatePublicStateTarget},
        },
    },
    common::{
        private_state::{PrivateState, PrivateStateTarget},
        public_state::{PUBLIC_STATE_U64_LEN, PublicState, PublicStateError, PublicStateTarget},
        transfer::{SettledTransfer, SettledTransferTarget},
        trees::{
            sent_tx_tree::{SentTxMerkleProof, SentTxMerkleProofTarget},
            tx_tree::{TxMerkleProof, TxMerkleProofTarget},
        },
        tx::{Tx, TxTarget},
        withdrawal::{WITHDRAWAL_LEN, Withdrawal, WithdrawalTarget},
    },
    constants::{SENT_TX_TREE_HEIGHT, TX_TREE_HEIGHT},
    utils::{
        conversion::ToU64,
        poseidon_hash_out::PoseidonHashOut,
        recursively_verifiable::add_proof_target_and_verify_cyclic,
        serialize::{
            AllGateSerializer, AllGeneratorSerializer, CircuitSerializationError,
            deserialize_verifier_data, serialize_verifier_data,
        },
    },
};

pub const SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN: usize = PUBLIC_STATE_U64_LEN + WITHDRAWAL_LEN;

pub struct SingleWithdawalPublicInputs {
    pub public_state: PublicState,
    pub withdrawal: Withdrawal,
}

#[derive(Debug, Error)]
pub enum SingleWithdawalPublicInputsError {
    #[error("Invalid public inputs length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Failed to parse public state: {0}")]
    PublicState(#[from] PublicStateError),

    #[error("Failed to parse withdrawal: {0}")]
    Withdrawal(String),
}

impl SingleWithdawalPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let mut limbs = self.public_state.to_u64_vec();
        limbs.extend(self.withdrawal.to_u32_vec().into_iter().map(|x| x as u64));
        limbs
    }

    pub fn from_u64_slice(values: &[u64]) -> Result<Self, SingleWithdawalPublicInputsError> {
        if values.len() != SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN {
            return Err(SingleWithdawalPublicInputsError::InvalidLength {
                expected: SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN,
                actual: values.len(),
            });
        }

        let mut cursor = 0;

        let public_state =
            PublicState::from_u64_slice(&values[cursor..cursor + PUBLIC_STATE_U64_LEN])?;
        cursor += PUBLIC_STATE_U64_LEN;

        let withdraw_slice = &values[cursor..cursor + WITHDRAWAL_LEN];
        let withdrawal = Withdrawal::from_u64_slice(withdraw_slice)
            .map_err(|e| SingleWithdawalPublicInputsError::Withdrawal(e.to_string()))?;

        Ok(Self {
            public_state,
            withdrawal,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SingleWithdawalPublicInputsTarget {
    pub public_state: PublicStateTarget,
    pub withdrawal: WithdrawalTarget,
}

impl SingleWithdawalPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        [self.public_state.to_vec(), self.withdrawal.to_vec()].concat()
    }

    pub fn from_vec(values: &[Target]) -> Self {
        assert_eq!(
            values.len(),
            SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN,
            "SingleWithdawalPublicInputsTarget::from_vec length mismatch",
        );

        let mut cursor = 0;

        let public_state =
            PublicStateTarget::from_slice(&values[cursor..cursor + PUBLIC_STATE_U64_LEN]);
        cursor += PUBLIC_STATE_U64_LEN;

        let withdrawal = WithdrawalTarget::from_slice(&values[cursor..cursor + WITHDRAWAL_LEN]);

        Self {
            public_state,
            withdrawal,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &SingleWithdawalPublicInputs,
    ) {
        self.public_state.set_witness(witness, &value.public_state);
        self.withdrawal.set_witness(witness, &value.withdrawal);
    }
}

#[derive(Debug, Error)]
pub enum SingleWithdawalWitnessError {
    #[error("Balance proof verification failed: {0}")]
    BalanceProofVerification(String),

    #[error("Failed to parse balance public inputs: {0}")]
    BalancePublicInputs(String),

    #[error("Private state commitment mismatch: expected {expected:?}, got {actual:?}")]
    PrivateStateCommitmentMismatch {
        expected: PoseidonHashOut,
        actual: PoseidonHashOut,
    },

    #[error("Sent tx merkle proof verification failed: {0}")]
    SentTxMerkleProof(String),

    #[error("Tx merkle proof verification failed: {0}")]
    TxMerkleProof(String),

    #[error("Transfer witness verification failed: {0}")]
    TransferWitness(String),

    #[error("Invalid recipient: {0}")]
    InvalidRecipient(String),

    #[error("Inconsistent witness data: {0}")]
    InconsistentWitness(String),

    #[error("Account state verification failed: {0}")]
    AccountState(String),

    #[error("Public state update verification failed: {0}")]
    UpdatePublicState(String),

    #[error("Balance public state mismatch after update")]
    BalancePublicStateMismatch,
}

pub struct SingleWithdawalWitness<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // the balance proof of the user performing the withdrawal
    // it must contain the withdrawal in its sent tx tree
    pub balance_proof: ProofWithPublicInputs<F, C, D>,

    // the private state of the balance proof
    pub private_state: PrivateState,

    // the witness to update the public state of the balance proof to the latest
    pub update_public_state: UpdatePublicState,

    // the account state that proves the block number of the tx.
    pub account_state: AccountState,

    // the tx merkle proof of the tx that contains the withdrawal
    pub tx_merkle_proof: TxMerkleProof,

    // the tx that contains the withdrawal
    pub tx: Tx,

    // the sent tx merkle proof of the tx
    pub sent_tx_merkle_proof: SentTxMerkleProof,

    // the transfer witness of the withdrawal
    pub transfer_witness: TransferWitness,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SingleWithdawalWitness<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_public_inputs(
        &self,
        balance_vd: &VerifierCircuitData<F, C, D>,
    ) -> Result<SingleWithdawalPublicInputs, SingleWithdawalWitnessError> {
        // verify the balance proof
        check_cyclic_proof_verifier_data(
            &self.balance_proof,
            &balance_vd.verifier_only,
            &balance_vd.common,
        )
        .map_err(|e| {
            SingleWithdawalWitnessError::BalanceProofVerification(format!(
                "cyclic verifier data check failed: {e:?}",
            ))
        })?;
        balance_vd.verify(self.balance_proof.clone()).map_err(|e| {
            SingleWithdawalWitnessError::BalanceProofVerification(format!(
                "verification failed: {e:?}",
            ))
        })?;

        let balance_full_pis = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(
            &self.balance_proof.public_inputs.to_u64_vec(),
            &balance_vd.common.config,
        )
        .map_err(|e| SingleWithdawalWitnessError::BalancePublicInputs(e.to_string()))?;
        let balance_pis = balance_full_pis.pis;
        let user_id = balance_pis.user_id;

        // verify the private state by checking the commitment
        if balance_pis.private_commitment != self.private_state.commitment() {
            return Err(
                SingleWithdawalWitnessError::PrivateStateCommitmentMismatch {
                    expected: balance_pis.private_commitment,
                    actual: self.private_state.commitment(),
                },
            );
        }

        // verify the public state update
        self.update_public_state
            .verify()
            .map_err(|e| SingleWithdawalWitnessError::UpdatePublicState(e.to_string()))?;
        if self.update_public_state.old != balance_pis.public_state {
            return Err(SingleWithdawalWitnessError::BalancePublicStateMismatch);
        }
        let public_state = self.update_public_state.new.clone();

        // verify that the tx is included in the sent tx tree
        self.sent_tx_merkle_proof
            .verify(
                &self.tx,
                self.tx.nonce as u64,
                self.private_state.sent_tx_tree_root,
            )
            .map_err(|e| SingleWithdawalWitnessError::TxMerkleProof(e.to_string()))?;

        // verify the transfer witness
        if self.transfer_witness.transfer_tree_root != self.tx.transfer_tree_root {
            return Err(SingleWithdawalWitnessError::InconsistentWitness(format!(
                "transfer tree root mismatch: expected {:?}, got {:?}",
                self.tx.transfer_tree_root, self.transfer_witness.transfer_tree_root
            )));
        }
        self.transfer_witness
            .verify()
            .map_err(|e: TransferWitnessError| {
                SingleWithdawalWitnessError::TransferWitness(e.to_string())
            })?;

        // verify the account state
        if self.account_state.user_id != user_id {
            return Err(SingleWithdawalWitnessError::InconsistentWitness(format!(
                "account state user {:?} != balance proof user {:?}",
                self.account_state.user_id, user_id
            )));
        }
        if self.account_state.account_tree_root != public_state.account_tree_root {
            return Err(SingleWithdawalWitnessError::InconsistentWitness(format!(
                "account tree root mismatch: {:?} vs {:?}",
                self.account_state.account_tree_root, public_state.account_tree_root
            )));
        }
        self.account_state
            .verify()
            .map_err(|e: AccountStateError| {
                SingleWithdawalWitnessError::AccountState(e.to_string())
            })?;
        let tx_tree_root = self
            .account_state
            .send_leaf
            .tx_tree_root
            .reduce_to_hash_out();
        let tx_block_number = self.account_state.send_leaf.cur;

        // verify that the tx is included in the tx tree root
        self.tx_merkle_proof
            .verify(&self.tx, user_id.local_id() as u64, tx_tree_root)
            .map_err(|e| SingleWithdawalWitnessError::TxMerkleProof(e.to_string()))?;

        let transfer = self.transfer_witness.transfer.clone();
        let recipient = extract_address_from_recipient(transfer.recipient)
            .map_err(|e| SingleWithdawalWitnessError::InvalidRecipient(e.to_string()))?;

        let settled_transfer = SettledTransfer::new(
            transfer.clone(),
            user_id,
            self.transfer_witness.transfer_index,
            tx_block_number,
        );

        // construct the withdrawal
        let withdrawal = Withdrawal {
            recipient,
            token_index: transfer.token_index,
            amount: transfer.amount,
            nullifier: settled_transfer.nullifier(),
            aux_data: transfer.aux_data,
        };

        Ok(SingleWithdawalPublicInputs {
            public_state: self.update_public_state.new.clone(),
            withdrawal,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SingleWithdawalTarget<const D: usize> {
    pub balance_proof: ProofWithPublicInputsTarget<D>,
    pub private_state: PrivateStateTarget,
    pub update_public_state: UpdatePublicStateTarget,
    pub account_state: AccountStateTarget,
    pub tx_merkle_proof: TxMerkleProofTarget,
    pub tx: TxTarget,
    pub sent_tx_merkle_proof: SentTxMerkleProofTarget,
    pub transfer_witness: TransferWitnessTarget,
    pub public_inputs: SingleWithdawalPublicInputsTarget,
}

impl<const D: usize> SingleWithdawalTarget<D> {
    pub fn new<F, C>(
        builder: &mut CircuitBuilder<F, D>,
        balance_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let balance_proof = add_proof_target_and_verify_cyclic(balance_vd, builder);
        let balance_full_pis = BalanceFullPublicInputsTarget::from_pis(
            &balance_proof.public_inputs,
            &balance_vd.common.config,
        );
        let balance_pis = balance_full_pis.pis.clone();

        let private_state = PrivateStateTarget::new(builder);
        let update_public_state = UpdatePublicStateTarget::new::<F, C, D>(builder);
        let account_state = AccountStateTarget::new::<F, C, D>(builder, true);
        let tx = TxTarget::new(builder);
        builder.range_check(tx.nonce, SENT_TX_TREE_HEIGHT);
        let tx_merkle_proof = TxMerkleProofTarget::new(builder, TX_TREE_HEIGHT);
        let sent_tx_merkle_proof = SentTxMerkleProofTarget::new(builder, SENT_TX_TREE_HEIGHT);
        let transfer_witness = TransferWitnessTarget::new::<F, C, D>(builder, true);

        let private_commitment = private_state.commitment(builder);
        private_commitment.connect(builder, balance_pis.private_commitment.clone());

        update_public_state
            .old
            .connect(builder, &balance_pis.public_state);
        let public_state = update_public_state.new.clone();

        account_state.user_id.connect(builder, &balance_pis.user_id);
        account_state
            .account_tree_root
            .connect(builder, public_state.account_tree_root.clone());

        sent_tx_merkle_proof.verify::<F, C, D>(
            builder,
            &tx,
            tx.nonce,
            private_state.sent_tx_tree_root.clone(),
        );

        transfer_witness
            .transfer_tree_root
            .connect(builder, tx.transfer_tree_root.clone());

        let tx_tree_root = account_state
            .send_leaf
            .tx_tree_root
            .reduce_to_hash_out(builder);
        let local_id = balance_pis.user_id.local_id(builder);
        tx_merkle_proof.verify::<F, C, D>(builder, &tx, local_id, tx_tree_root);

        let recipient =
            extract_address_from_recipient_circuit(builder, &transfer_witness.transfer.recipient);

        let settled_transfer = SettledTransferTarget {
            inner: transfer_witness.transfer.clone(),
            from: balance_pis.user_id.clone(),
            transfer_index: transfer_witness.transfer_index,
            block_number: account_state.send_leaf.cur.clone(),
        };
        let nullifier = settled_transfer.nullifier(builder);

        let withdrawal = WithdrawalTarget {
            recipient,
            token_index: transfer_witness.transfer.token_index,
            amount: transfer_witness.transfer.amount.clone(),
            nullifier,
            aux_data: transfer_witness.transfer.aux_data.clone(),
        };

        let public_inputs = SingleWithdawalPublicInputsTarget {
            public_state,
            withdrawal,
        };

        Self {
            balance_proof,
            private_state,
            update_public_state,
            account_state,
            tx_merkle_proof,
            tx,
            sent_tx_merkle_proof,
            transfer_witness,
            public_inputs,
        }
    }

    pub fn set_witness<F, C, W>(&self, witness: &mut W, value: &SingleWithdawalWitness<F, C, D>)
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
        W: WitnessWrite<F>,
    {
        let (
            balance_proof,
            private_state,
            update_public_state,
            account_state,
            tx_merkle_proof,
            tx,
            sent_tx_merkle_proof,
            transfer_witness,
        ) = (
            &value.balance_proof,
            &value.private_state,
            &value.update_public_state,
            &value.account_state,
            &value.tx_merkle_proof,
            value.tx,
            &value.sent_tx_merkle_proof,
            &value.transfer_witness,
        );

        witness.set_proof_with_pis_target(&self.balance_proof, balance_proof);
        self.private_state.set_witness(witness, private_state);
        self.update_public_state
            .set_witness(witness, update_public_state);
        self.account_state.set_witness(witness, account_state);
        self.tx_merkle_proof.set_witness(witness, tx_merkle_proof);
        self.tx.set_witness::<W, F>(witness, tx);
        self.sent_tx_merkle_proof
            .set_witness(witness, sent_tx_merkle_proof);
        self.transfer_witness.set_witness(witness, transfer_witness);
    }
}

#[derive(Debug, Error)]
pub enum SingleWithdawalCircuitError {
    #[error("Witness error: {0}")]
    Witness(#[from] SingleWithdawalWitnessError),

    #[error("Failed to prove: {0}")]
    FailedToProve(String),
}

pub struct SingleWithdawalCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: SingleWithdawalTarget<D>,
    pub public_inputs: SingleWithdawalPublicInputsTarget,
    pub balance_vd: VerifierCircuitData<F, C, D>,
}

impl<F, C, const D: usize> SingleWithdawalCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(balance_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let target = SingleWithdawalTarget::new(&mut builder, balance_vd);
        let public_inputs = target.public_inputs.clone();
        builder.register_public_inputs(&public_inputs.to_vec());
        let data = builder.build::<C>();

        Self {
            data,
            target,
            public_inputs,
            balance_vd: balance_vd.clone(),
        }
    }

    pub fn prove(
        &self,
        witness: &SingleWithdawalWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, SingleWithdawalCircuitError> {
        let public_inputs = witness.to_public_inputs(&self.balance_vd)?;
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness::<F, C, _>(&mut pw, witness);
        self.public_inputs.set_witness(&mut pw, &public_inputs);
        self.data
            .prove(pw)
            .map_err(|e| SingleWithdawalCircuitError::FailedToProve(e.to_string()))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CircuitSerializationError> {
        let gate_serializer = AllGateSerializer;
        let generator_serializer = AllGeneratorSerializer::<C, D>::default();
        let data_bytes = self
            .data
            .to_bytes(&gate_serializer, &generator_serializer)
            .map_err(|e| {
                CircuitSerializationError::serialization("single withdrawal circuit data", e)
            })?;
        let balance_vd_bytes =
            serialize_verifier_data::<F, C, D>(&self.balance_vd).map_err(|e| {
                CircuitSerializationError::serialization("single withdrawal balance vd", e)
            })?;
        let payload = SingleWithdawalCircuitBytes::<D> {
            data: data_bytes,
            target: self.target.clone(),
            public_inputs: self.public_inputs.clone(),
            balance_vd: balance_vd_bytes,
        };
        bincode::serde::encode_to_vec(&payload, bincode::config::standard())
            .map_err(|e| CircuitSerializationError::serialization("single withdrawal circuit", e))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CircuitSerializationError> {
        let (payload, _) = bincode::serde::decode_from_slice::<SingleWithdawalCircuitBytes<D>, _>(
            bytes,
            bincode::config::standard(),
        )
        .map_err(|e| CircuitSerializationError::deserialization("single withdrawal circuit", e))?;
        let gate_serializer = AllGateSerializer;
        let generator_serializer = AllGeneratorSerializer::<C, D>::default();
        let data = CircuitData::<F, C, D>::from_bytes(
            &payload.data,
            &gate_serializer,
            &generator_serializer,
        )
        .map_err(|e| {
            CircuitSerializationError::deserialization("single withdrawal circuit data", e)
        })?;
        let balance_vd =
            deserialize_verifier_data::<F, C, D>(&payload.balance_vd).map_err(|e| {
                CircuitSerializationError::deserialization("single withdrawal balance vd", e)
            })?;
        Ok(Self {
            data,
            target: payload.target,
            public_inputs: payload.public_inputs,
            balance_vd,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SingleWithdawalCircuitBytes<const D: usize> {
    data: Vec<u8>,
    target: SingleWithdawalTarget<D>,
    public_inputs: SingleWithdawalPublicInputsTarget,
    balance_vd: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
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
                block_witness_generator::BlockWitnessGenerator,
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
            address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256,
        },
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{SeedableRng, rngs::StdRng};
    use std::sync::{Arc, RwLock};

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn test_single_withdrawal_circuit() {
        let supported_user_counts = vec![1, MAX_NUM_TRANSFERS_PER_TX as u32, 512];

        let spend_circuit = SpendCircuit::<F, C, D>::new();
        let balance_processor =
            BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
        let balance_vd = balance_processor.balance_vd();

        let block_witness_generator = Arc::new(RwLock::new(BlockWitnessGenerator::new(
            &supported_user_counts,
        )));

        let mut rng = StdRng::seed_from_u64(1234);
        let user_id = UserId::new(0, 1).unwrap();
        let salt = Salt::rand(&mut rng);
        let mut balance_witness_generator = BalanceWitnessGenerator::new(
            user_id,
            salt,
            block_witness_generator.clone(),
            &balance_processor,
        )
        .unwrap();

        // Fund the account via deposit.
        let deposit_salt = Salt::rand(&mut rng);
        let deposit_recipient = calculate_recipient_from_user_id(user_id, deposit_salt);
        block_witness_generator
            .write()
            .unwrap()
            .add_deposit(
                Address::rand(&mut rng),
                deposit_recipient,
                0,
                U256::from(10u32),
                Bytes32::default(),
            )
            .unwrap();
        block_witness_generator
            .write()
            .unwrap()
            .add_block(0, &[], 0, Bytes32::default())
            .unwrap();
        let deposit_data = ReceiveDepositData {
            receiver: deposit_recipient,
            deposit_salt,
        };
        let deposit_witness = balance_witness_generator
            .receive_deposit_witness(&deposit_data)
            .unwrap();
        let deposit_balance_proof = balance_processor
            .prove_receive_deposit(&deposit_witness)
            .unwrap();
        balance_witness_generator
            .commit_receive_deposit(&deposit_balance_proof, &deposit_witness)
            .unwrap();

        // Build a transfer that encodes a withdrawal to an explicit address.
        let withdrawal_address = Address::rand(&mut rng);
        let transfer = Transfer {
            recipient: calculate_recipient_from_address(withdrawal_address),
            token_index: 0,
            amount: U256::from(3u32),
            aux_data: Bytes32::default(),
        };
        let spend_witness = balance_witness_generator
            .spend_witness(&[transfer.clone()])
            .unwrap();
        let spend_proof = spend_circuit.prove(&spend_witness).unwrap();

        // Construct transfer and transaction witnesses.
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
            .write()
            .unwrap()
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
            .unwrap();
        let new_balance_proof = balance_processor.prove_send_tx(&send_tx_witness).unwrap();
        balance_witness_generator
            .commit_send_tx(&new_balance_proof, &send_tx_witness, &spend_witness)
            .unwrap();

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
            .unwrap();

        let circuit = SingleWithdawalCircuit::<F, C, D>::new(&balance_vd);
        let proof = circuit
            .prove(&withdrawal_witness)
            .expect("single withdrawal circuit should prove");
        circuit
            .data
            .verify(proof)
            .expect("single withdrawal proof should verify");
    }

    #[test]
    fn test_single_withdrawal_circuit_serialization() {
        let spend_circuit = SpendCircuit::<F, C, D>::new();
        let balance_processor =
            BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
        let balance_vd = balance_processor.balance_vd();

        let circuit = SingleWithdawalCircuit::<F, C, D>::new(&balance_vd);

        let bytes = circuit.to_bytes().expect("circuit to bytes");
        let deserialized =
            SingleWithdawalCircuit::<F, C, D>::from_bytes(&bytes).expect("circuit from bytes");

        assert_eq!(circuit.data, deserialized.data);
        assert_eq!(circuit.balance_vd, deserialized.balance_vd);

        let roundtrip_bytes = deserialized
            .to_bytes()
            .expect("circuit to bytes after deserialization");
        assert_eq!(bytes, roundtrip_bytes);
    }
}
