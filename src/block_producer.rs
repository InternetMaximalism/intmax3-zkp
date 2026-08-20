//! Production boundary for small-block construction.
//!
//! The legacy witness generator also contains deterministic fixture helpers that own every
//! member key. This facade deliberately exposes none of those helpers: registrations contain
//! public keys only, and an updating block is accepted only with a wallet-produced N-of-N
//! co-signed [`ChannelState`].

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{
    circuits::{
        test_utils::block_witness_generator::{
            BlockTxV2Witness, BlockWitnessGenerator, BlockWitnessGeneratorError, BpSigEvent,
            ChannelCosignBundle,
        },
        validity::block_hash_chain::block_hash_chain_processor::BlockHashChainProcessorWitness,
    },
    common::{
        channel::{ChannelRecord, ChannelState, InterChannelTx},
        channel_id::ChannelId,
        channel_registration::{ChannelRegRecord, MemberRegEntry},
        deposit::Deposit,
        public_state::get_num_users,
        tx::TxV2,
    },
    constants::{MAX_CHANNEL_MEMBERS, MAX_COSIGNERS},
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256},
    falcon_sig::{agg::FalconAggCircuit, agg_list::AggListCircuit},
    regev::RegevPk,
    wallet_core::{
        C, ChannelSnapshot, D, F, InterChannelDebitPayload, InterChannelTransferDescriptor,
        attach_small_block_signatures, verify_all_signatures,
        verify_inter_channel_descriptor_matches_debit, verify_snapshot,
    },
};
use plonky2::plonk::proof::ProofWithPublicInputs;

#[derive(Debug, thiserror::Error)]
pub enum ProductionBlockProducerError {
    #[error("invalid production registration: {0}")]
    InvalidRegistration(String),
    #[error("wallet authorization rejected: {0}")]
    WalletAuthorization(String),
    #[error(transparent)]
    Witness(#[from] BlockWitnessGeneratorError),
}

/// All public material the producer needs to register and later verify a channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductionChannelRegistration {
    pub channel_record: ChannelRecord,
    pub validity_record: ChannelRegRecord,
    pub regev_pks: Vec<RegevPk>,
}

impl ProductionChannelRegistration {
    /// Derive the validity-side registration from a fully verified wallet snapshot.
    pub fn from_snapshot(snapshot: &ChannelSnapshot) -> Result<Self, ProductionBlockProducerError> {
        verify_snapshot(snapshot, None).map_err(|e| {
            ProductionBlockProducerError::InvalidRegistration(format!(
                "channel snapshot verification failed: {e}"
            ))
        })?;

        let member_count = snapshot.record.member_count as usize;
        let mut entries: [MemberRegEntry; MAX_COSIGNERS] =
            std::array::from_fn(|_| MemberRegEntry::default());
        let mut regev_pks = Vec::with_capacity(member_count);
        for slot in 0..member_count {
            let member = snapshot
                .members
                .iter()
                .find(|member| member.slot as usize == slot)
                .ok_or_else(|| {
                    ProductionBlockProducerError::InvalidRegistration(format!(
                        "missing cosigner public data at slot {slot}"
                    ))
                })?;
            entries[slot] = MemberRegEntry {
                pk_g: member.pk_g,
                pk_b: member.pk_b,
                regev_pk_digest: Bytes32::from(member.regev_pk.poseidon_digest()),
                recipient: snapshot.state.balance_state.recipients[slot],
            };
            regev_pks.push(member.regev_pk.clone());
        }

        let validity_record = ChannelRegRecord {
            channel_id: snapshot.record.channel_id,
            bp_member_slot: snapshot.record.bp_member_slot as u32,
            member_count: snapshot.record.member_count as u32,
            // Option B: delegates are authenticated by the co-signed H1 tree and never enter the
            // fixed-16 L1 registration record.
            delegate_count: 0,
            members: entries,
        };

        let registration = Self {
            channel_record: snapshot.record.clone(),
            validity_record,
            regev_pks,
        };
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<(), ProductionBlockProducerError> {
        self.channel_record.validate().map_err(|e| {
            ProductionBlockProducerError::InvalidRegistration(format!(
                "channel record failed validation: {e}"
            ))
        })?;
        self.validity_record.validate().map_err(|e| {
            ProductionBlockProducerError::InvalidRegistration(format!(
                "validity record failed validation: {e}"
            ))
        })?;

        let member_count = self.channel_record.member_count as usize;
        if self.validity_record.channel_id != self.channel_record.channel_id
            || self.validity_record.member_count as usize != member_count
            || self.validity_record.bp_member_slot != self.channel_record.bp_member_slot as u32
        {
            return Err(ProductionBlockProducerError::InvalidRegistration(
                "wallet and validity records disagree on channel id, member count, or BP slot"
                    .to_string(),
            ));
        }
        if self.validity_record.delegate_count != 0 {
            return Err(ProductionBlockProducerError::InvalidRegistration(
                "production validity registration must be cosigner-only (delegate_count = 0)"
                    .to_string(),
            ));
        }
        if self.regev_pks.len() != member_count {
            return Err(ProductionBlockProducerError::InvalidRegistration(format!(
                "expected {member_count} Regev public keys, got {}",
                self.regev_pks.len()
            )));
        }
        for slot in 0..member_count {
            let entry = &self.validity_record.members[slot];
            if entry.pk_g != self.channel_record.member_pk_gs[slot] {
                return Err(ProductionBlockProducerError::InvalidRegistration(format!(
                    "slot {slot} Falcon identity differs between wallet and validity records"
                )));
            }
            let digest = Bytes32::from(self.regev_pks[slot].poseidon_digest());
            if entry.regev_pk_digest != digest {
                return Err(ProductionBlockProducerError::InvalidRegistration(format!(
                    "slot {slot} Regev public key does not match the registered digest"
                )));
            }
        }
        Ok(())
    }
}

/// Keyless block producer core. The wrapped generator is private so production callers cannot
/// reach its deterministic fixture-key registration APIs.
#[derive(Clone, Debug)]
pub struct ProductionBlockProducer {
    witness: BlockWitnessGenerator,
    channel_records: HashMap<ChannelId, ChannelRecord>,
    /// Last accepted N-of-N state for each channel. This is public, signed state only; no member
    /// key is ever retained. It is the replay/fork fence for subsequent descriptors.
    channel_heads: HashMap<ChannelId, ChannelState>,
    /// Canonical token-bearing transaction hashes already admitted by the producer.
    accepted_inter_channel_txs: HashSet<Bytes32>,
    /// Last admitted base-account send nonce per source channel. Channel transition counters are
    /// independent, so descriptor admission tracks this explicit IMI3 field separately.
    accepted_base_nonces: HashMap<ChannelId, u32>,
}

/// Secret-free channel head exposed by the service status command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductionChannelHead {
    pub channel_id: ChannelId,
    pub state_digest: Bytes32,
    pub epoch: u64,
    pub small_block_number: u64,
    pub state_version: u64,
}

/// Public fields copied from one canonical L1 `Deposited` event. The producer assigns the
/// monotone deposit index and containing block number itself; accepting either from a caller would
/// let an API request fork the deposit hash chain from the journaled head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductionDepositRequest {
    /// Monotone index emitted by `IntmaxRollup.Deposited`; it must equal the producer's next
    /// index. This is checked, never installed from the request.
    pub deposit_index: u64,
    pub depositor: Address,
    pub recipient: Bytes32,
    pub token_index: u32,
    pub amount: U256,
    pub aux_data: Bytes32,
    /// `depositHashChain` emitted by the same L1 receipt. This reconciles the journaled Rust leaf
    /// with the actual rollup event before the block becomes durable.
    pub expected_deposit_hash_chain: Bytes32,
}

impl ProductionBlockProducer {
    pub fn new(supported_user_counts: &[u32]) -> Self {
        Self {
            witness: BlockWitnessGenerator::new(supported_user_counts),
            channel_records: HashMap::new(),
            channel_heads: HashMap::new(),
            accepted_inter_channel_txs: HashSet::new(),
            accepted_base_nonces: HashMap::new(),
        }
    }

    /// Register a verified public snapshot and retain its signed state as the initial replay
    /// fence. The snapshot contains public keys, ciphertexts and signatures, but no member secret.
    pub fn register_snapshot(
        &mut self,
        snapshot: &ChannelSnapshot,
        timestamp: u64,
    ) -> Result<ChannelId, ProductionBlockProducerError> {
        let registration = ProductionChannelRegistration::from_snapshot(snapshot)?;
        let channel = registration.channel_record.channel_id;
        let mut candidate = self.clone();
        candidate.register_channel(registration, timestamp)?;
        candidate
            .channel_heads
            .insert(channel, snapshot.state.clone());
        if candidate.holds_any_local_signing_keys() {
            return Err(ProductionBlockProducerError::InvalidRegistration(
                "snapshot registration unexpectedly retained a local signing key".to_string(),
            ));
        }
        *self = candidate;
        Ok(channel)
    }

    /// Queue public registration data and produce its dedicated registration block.
    pub fn register_channel(
        &mut self,
        registration: ProductionChannelRegistration,
        timestamp: u64,
    ) -> Result<ChannelId, ProductionBlockProducerError> {
        registration.validate()?;
        let channel = registration.channel_record.channel_id;
        if self.channel_records.contains_key(&channel) {
            return Err(ProductionBlockProducerError::InvalidRegistration(format!(
                "channel {} is already registered",
                channel.as_u64()
            )));
        }

        // Keep registration atomic across both the witness state and the native record cache.
        let mut candidate = self.clone();
        candidate.witness.add_channel_registration_public(
            registration.validity_record,
            registration.regev_pks,
        )?;
        candidate.witness.add_registration_block(timestamp)?;
        if candidate.witness.holds_local_signing_keys(channel) {
            return Err(ProductionBlockProducerError::InvalidRegistration(
                "production registration unexpectedly retained a local signing key".to_string(),
            ));
        }
        candidate
            .channel_records
            .insert(channel, registration.channel_record);
        *self = candidate;
        Ok(channel)
    }

    /// Append a deposit observed on L1 and seal it in a dedicated, keyless block. The returned
    /// [`Deposit`] contains the producer-assigned index and block number and is the exact leaf
    /// later consumed by the live balance IVC.
    pub fn produce_deposit_block(
        &mut self,
        request: &ProductionDepositRequest,
        timestamp: u64,
    ) -> Result<Deposit, ProductionBlockProducerError> {
        if request.recipient == Bytes32::default() {
            return Err(ProductionBlockProducerError::InvalidRegistration(
                "deposit recipient must be non-zero".to_string(),
            ));
        }
        if request.deposit_index != self.witness.deposit_counts {
            return Err(ProductionBlockProducerError::WalletAuthorization(format!(
                "L1 deposit index {} is stale or skipped; producer expects {}",
                request.deposit_index, self.witness.deposit_counts
            )));
        }
        if timestamp <= self.last_timestamp() {
            return Err(ProductionBlockProducerError::WalletAuthorization(format!(
                "deposit block timestamp {timestamp} must be greater than the committed timestamp {}",
                self.last_timestamp()
            )));
        }

        let mut candidate = self.clone();
        candidate.witness.add_deposit(
            request.depositor,
            request.recipient,
            request.token_index,
            request.amount,
            request.aux_data,
        )?;
        candidate
            .witness
            .add_block(0, &[], timestamp, Bytes32::default())?;
        let deposit = candidate
            .witness
            .deposit_tree
            .leaves()
            .last()
            .cloned()
            .ok_or_else(|| {
                ProductionBlockProducerError::Witness(BlockWitnessGeneratorError::InvalidRequest(
                    "deposit block committed no deposit leaf".to_string(),
                ))
            })?;
        if deposit.depositor != request.depositor
            || deposit.deposit_index.as_u64() != request.deposit_index
            || deposit.token_index != request.token_index
            || deposit.amount != request.amount
            || deposit.aux_data != request.aux_data
        {
            return Err(ProductionBlockProducerError::Witness(
                BlockWitnessGeneratorError::InvalidRequest(
                    "sealed deposit differs from the canonical request".to_string(),
                ),
            ));
        }
        if candidate.witness.deposit_hash_chain != request.expected_deposit_hash_chain {
            return Err(ProductionBlockProducerError::WalletAuthorization(format!(
                "L1 depositHashChain {} does not match the Rust block's {}",
                request.expected_deposit_hash_chain, candidate.witness.deposit_hash_chain
            )));
        }
        if candidate.holds_any_local_signing_keys() {
            return Err(ProductionBlockProducerError::InvalidRegistration(
                "deposit production unexpectedly retained a local signing key".to_string(),
            ));
        }
        *self = candidate;
        Ok(deposit)
    }

    /// Verify the wallet's real N-of-N signatures, attach them to the transfer descriptor, and
    /// build the corresponding updating block. No signing API or secret key is reachable here.
    #[allow(clippy::too_many_arguments)]
    pub fn produce_inter_channel_block(
        &mut self,
        signed_state: &ChannelState,
        inter_channel_tx: &mut InterChannelTx,
        key_ids: &[u32],
        timestamp: u64,
        tx_v2_witness: BlockTxV2Witness,
    ) -> Result<(), ProductionBlockProducerError> {
        let channel = inter_channel_tx.source_channel_id;
        let record = self.channel_records.get(&channel).ok_or_else(|| {
            ProductionBlockProducerError::WalletAuthorization(format!(
                "source channel {} is not registered in this producer",
                channel.as_u64()
            ))
        })?;
        attach_small_block_signatures(record, signed_state, inter_channel_tx)
            .map_err(|e| ProductionBlockProducerError::WalletAuthorization(e.to_string()))?;

        let tx_tree_root = inter_channel_tx.signed_small_block.message.tx_tree_root;
        self.produce_cosigned_block(
            signed_state,
            key_ids,
            timestamp,
            tx_tree_root,
            tx_v2_witness,
        )
    }

    /// Admit one canonical inter-channel descriptor. All server-controlled block fields are
    /// derived here: one active key slot, deterministic padding, the descriptor's proved TxV2
    /// opening, and the already selected service timestamp. Caller-supplied key-id arrays are not
    /// part of this production API.
    pub fn produce_inter_channel_descriptor_block(
        &mut self,
        signed_state: &ChannelState,
        debit_payload: &InterChannelDebitPayload,
        descriptor: &InterChannelTransferDescriptor,
        timestamp: u64,
    ) -> Result<InterChannelTx, ProductionBlockProducerError> {
        verify_inter_channel_descriptor_matches_debit(debit_payload, descriptor).map_err(|e| {
            ProductionBlockProducerError::WalletAuthorization(format!(
                "descriptor/debit canonical binding failed: {e}"
            ))
        })?;
        if debit_payload.proposed_next_state.digest != signed_state.digest {
            return Err(ProductionBlockProducerError::WalletAuthorization(
                "signed state differs from the E-2-verified debit payload's proposed state"
                    .to_string(),
            ));
        }
        let registered_record = self
            .channel_records
            .get(&descriptor.source_channel_id)
            .ok_or_else(|| {
                ProductionBlockProducerError::WalletAuthorization(format!(
                    "source channel {} is not registered in this producer",
                    descriptor.source_channel_id.as_u64()
                ))
            })?;
        if debit_payload.record.signing_digest() != registered_record.signing_digest() {
            return Err(ProductionBlockProducerError::WalletAuthorization(
                "debit payload record differs from the producer's registered channel record"
                    .to_string(),
            ));
        }
        let opened_root = descriptor
            .tx_v2_merkle_proof
            .get_root(&descriptor.tx_v2, descriptor.source_channel_id.as_u64());
        if Bytes32::from(opened_root) != descriptor.tx_tree_root {
            return Err(ProductionBlockProducerError::WalletAuthorization(
                "descriptor TxV2 Merkle proof does not open its canonical H2 root".to_string(),
            ));
        }
        if self
            .accepted_inter_channel_txs
            .contains(&descriptor.tx_hash)
        {
            return Err(ProductionBlockProducerError::WalletAuthorization(format!(
                "inter-channel transaction {} was already accepted",
                descriptor.tx_hash
            )));
        }
        let expected_nonce = match self.accepted_base_nonces.get(&descriptor.source_channel_id) {
            Some(previous_nonce) => previous_nonce.checked_add(1).ok_or_else(|| {
                ProductionBlockProducerError::WalletAuthorization(
                    "base-account send nonce overflow".to_string(),
                )
            })?,
            // A production registration starts a fresh account/channel lifetime. Existing
            // accounts must be migrated through a journal format that carries an authenticated
            // live-IVC cursor rather than silently choosing an attacker-supplied first nonce.
            None => 0,
        };
        if descriptor.inter_channel_tx.base_nonce != expected_nonce {
            return Err(ProductionBlockProducerError::WalletAuthorization(format!(
                "base-account nonce is stale or skipped: got {}, expected {expected_nonce}",
                descriptor.inter_channel_tx.base_nonce
            )));
        }

        let num_users = get_num_users(1, &self.witness.supported_user_counts).ok_or_else(|| {
            ProductionBlockProducerError::WalletAuthorization(
                "producer supports no circuit arity capable of one active channel".to_string(),
            )
        })? as usize;
        let mut tx_v2_indices = vec![0u64; num_users];
        let mut tx_v2s = vec![TxV2::default(); num_users];
        let mut tx_v2_merkle_proofs = vec![descriptor.tx_v2_merkle_proof.clone(); num_users];
        tx_v2_indices[0] = descriptor.source_channel_id.as_u64();
        tx_v2s[0] = descriptor.tx_v2;
        tx_v2_merkle_proofs[0] = descriptor.tx_v2_merkle_proof.clone();

        let mut attached_tx = descriptor.inter_channel_tx.clone();
        let mut candidate = self.clone();
        candidate.produce_inter_channel_block(
            signed_state,
            &mut attached_tx,
            &[1],
            timestamp,
            BlockTxV2Witness {
                tx_v2_indices,
                tx_v2s,
                tx_v2_merkle_proofs,
            },
        )?;
        candidate
            .accepted_inter_channel_txs
            .insert(descriptor.tx_hash);
        candidate.accepted_base_nonces.insert(
            descriptor.source_channel_id,
            descriptor.inter_channel_tx.base_nonce,
        );
        *self = candidate;
        Ok(attached_tx)
    }

    /// Advance the producer's replay fence across N-of-N authorized channel transitions that do
    /// not create a base-layer block (in-channel sends, refreshes, token registration, and the
    /// two receive/import accounting steps). Without this explicit journaled bridge, the next
    /// real inter-channel descriptor would appear to skip the producer's stale channel head.
    ///
    /// These states are public authorization records, not trusted balance proofs. The live
    /// balance service independently proves their settlement effects. This method only accepts a
    /// contiguous, fully signed digest chain with the canonical zero-H2 marker and monotone
    /// counters, and updates no block/public-state witness.
    pub fn sync_offchain_heads(
        &mut self,
        signed_states: &[ChannelState],
    ) -> Result<ChannelId, ProductionBlockProducerError> {
        let first = signed_states.first().ok_or_else(|| {
            ProductionBlockProducerError::WalletAuthorization(
                "off-chain head synchronization requires at least one signed state".to_string(),
            )
        })?;
        let channel = first.channel_id;
        let record = self.channel_records.get(&channel).ok_or_else(|| {
            ProductionBlockProducerError::WalletAuthorization(format!(
                "channel {} is not registered in this producer",
                channel.as_u64()
            ))
        })?;
        let mut previous = self.channel_heads.get(&channel).cloned().ok_or_else(|| {
            ProductionBlockProducerError::WalletAuthorization(format!(
                "channel {} has no registered replay-fence head",
                channel.as_u64()
            ))
        })?;

        for (offset, state) in signed_states.iter().enumerate() {
            if state.channel_id != channel
                || state.channel_fund.channel_id != channel
                || state.balance_state.channel_id != channel
            {
                return Err(ProductionBlockProducerError::WalletAuthorization(format!(
                    "off-chain state {offset} belongs to a different channel"
                )));
            }
            verify_all_signatures(record, &[], state).map_err(|e| {
                ProductionBlockProducerError::WalletAuthorization(format!(
                    "off-chain state {offset} is not N-of-N authorized: {e}"
                ))
            })?;
            if state.h2_tag != Bytes32::default() {
                return Err(ProductionBlockProducerError::WalletAuthorization(format!(
                    "off-chain state {offset} has non-zero h2_tag and must be posted as a block"
                )));
            }
            if state.prev_digest != previous.digest {
                return Err(ProductionBlockProducerError::WalletAuthorization(format!(
                    "off-chain state {offset} does not extend the committed head"
                )));
            }
            let expected_epoch = previous.epoch.checked_add(1).ok_or_else(|| {
                ProductionBlockProducerError::WalletAuthorization(
                    "channel epoch overflow".to_string(),
                )
            })?;
            let expected_version = previous
                .balance_state
                .state_version
                .checked_add(1)
                .ok_or_else(|| {
                    ProductionBlockProducerError::WalletAuthorization(
                        "balance-state version overflow".to_string(),
                    )
                })?;
            let max_small_block = previous.small_block_number.checked_add(1).ok_or_else(|| {
                ProductionBlockProducerError::WalletAuthorization(
                    "small-block number overflow".to_string(),
                )
            })?;
            if state.epoch != expected_epoch
                || state.balance_state.state_version != expected_version
                || state.small_block_number < previous.small_block_number
                || state.small_block_number > max_small_block
                || state.close_freeze_nonce != previous.close_freeze_nonce
            {
                return Err(ProductionBlockProducerError::WalletAuthorization(format!(
                    "off-chain state {offset} has stale/skipped counters or a different close era"
                )));
            }
            previous = state.clone();
        }

        let mut candidate = self.clone();
        candidate.channel_heads.insert(channel, previous);
        if candidate.holds_any_local_signing_keys() {
            return Err(ProductionBlockProducerError::InvalidRegistration(
                "off-chain head synchronization unexpectedly retained a local signing key"
                    .to_string(),
            ));
        }
        *self = candidate;
        Ok(channel)
    }

    /// Lower-level production entry point for any channel update whose wallet state already binds
    /// a non-zero transaction-tree root. Native N-of-N verification fails early; the validity
    /// circuit re-verifies the same signatures during proving.
    pub fn produce_cosigned_block(
        &mut self,
        signed_state: &ChannelState,
        key_ids: &[u32],
        timestamp: u64,
        tx_tree_root: Bytes32,
        tx_v2_witness: BlockTxV2Witness,
    ) -> Result<(), ProductionBlockProducerError> {
        let channel = signed_state.channel_id;
        let record = self.channel_records.get(&channel).ok_or_else(|| {
            ProductionBlockProducerError::WalletAuthorization(format!(
                "channel {} is not registered in this producer",
                channel.as_u64()
            ))
        })?;
        verify_all_signatures(record, &[], signed_state).map_err(|e| {
            ProductionBlockProducerError::WalletAuthorization(format!(
                "channel {} is not N-of-N authorized: {e}",
                channel.as_u64()
            ))
        })?;
        if tx_tree_root == Bytes32::default() || signed_state.h2_tag != tx_tree_root {
            return Err(ProductionBlockProducerError::WalletAuthorization(
                "co-signed state must bind this block's non-zero tx_tree_root in h2_tag"
                    .to_string(),
            ));
        }
        if signed_state.channel_fund.channel_id != channel {
            return Err(ProductionBlockProducerError::WalletAuthorization(
                "co-signed state's channel_fund belongs to a different channel".to_string(),
            ));
        }
        if signed_state.balance_state.channel_id != channel {
            return Err(ProductionBlockProducerError::WalletAuthorization(
                "co-signed state's balance_state belongs to a different channel".to_string(),
            ));
        }
        if timestamp <= self.last_timestamp() {
            return Err(ProductionBlockProducerError::WalletAuthorization(format!(
                "block timestamp {timestamp} must be greater than the committed timestamp {}",
                self.last_timestamp()
            )));
        }
        if let Some(previous) = self.channel_heads.get(&channel) {
            if signed_state.prev_digest != previous.digest {
                return Err(ProductionBlockProducerError::WalletAuthorization(format!(
                    "channel {} state does not extend the committed head: prev_digest {} != {}",
                    channel.as_u64(),
                    signed_state.prev_digest,
                    previous.digest
                )));
            }
            let expected_small_block =
                previous.small_block_number.checked_add(1).ok_or_else(|| {
                    ProductionBlockProducerError::WalletAuthorization(
                        "small-block number overflow".to_string(),
                    )
                })?;
            let expected_epoch = previous.epoch.checked_add(1).ok_or_else(|| {
                ProductionBlockProducerError::WalletAuthorization(
                    "channel epoch overflow".to_string(),
                )
            })?;
            let expected_version = previous
                .balance_state
                .state_version
                .checked_add(1)
                .ok_or_else(|| {
                    ProductionBlockProducerError::WalletAuthorization(
                        "balance-state version overflow".to_string(),
                    )
                })?;
            if signed_state.small_block_number != expected_small_block
                || signed_state.epoch != expected_epoch
                || signed_state.balance_state.state_version != expected_version
                || signed_state.close_freeze_nonce != previous.close_freeze_nonce
            {
                return Err(ProductionBlockProducerError::WalletAuthorization(format!(
                    "channel {} state is stale, skipped, or from a different close era",
                    channel.as_u64()
                )));
            }
        }

        let mut candidate = self.clone();
        candidate.witness.next_channel_cosign = Some(ChannelCosignBundle {
            state: signed_state.clone(),
            signatures: signed_state.member_signatures.clone(),
        });
        candidate.witness.add_block_with_tx_v2(
            channel.as_u64() as u32,
            key_ids,
            timestamp,
            tx_tree_root,
            Some(tx_v2_witness),
        )?;
        candidate
            .channel_heads
            .insert(channel, signed_state.clone());
        *self = candidate;
        Ok(())
    }

    pub fn block_number(&self) -> u64 {
        self.witness.block_number.as_u64()
    }

    pub fn last_timestamp(&self) -> u64 {
        self.witness
            .blocks
            .last()
            .map(|block| block.timestamp)
            .unwrap_or_default()
    }

    pub fn registered_channel_count(&self) -> usize {
        self.channel_records.len()
    }

    pub fn channel_heads(&self) -> Vec<ProductionChannelHead> {
        let mut heads: Vec<_> = self
            .channel_heads
            .iter()
            .map(|(&channel_id, state)| ProductionChannelHead {
                channel_id,
                state_digest: state.digest,
                epoch: state.epoch,
                small_block_number: state.small_block_number,
                state_version: state.balance_state.state_version,
            })
            .collect();
        heads.sort_by_key(|head| head.channel_id.as_u64());
        heads
    }

    pub fn current_extended_public_state(
        &self,
    ) -> crate::circuits::validity::block_hash_chain::ext_public_state::ExtendedPublicState {
        self.witness.current_extended_public_state()
    }

    pub fn holds_any_local_signing_keys(&self) -> bool {
        self.channel_records
            .keys()
            .copied()
            .any(|channel| self.witness.holds_local_signing_keys(channel))
    }

    pub fn signature_events(&self) -> &[BpSigEvent] {
        &self.witness.bp_sig_events
    }

    pub fn block_witness(
        &self,
        block_number: crate::common::u63::BlockNumber,
    ) -> Option<BlockHashChainProcessorWitness> {
        self.witness.block_chain_witness.get(&block_number).cloned()
    }

    /// Clone the fully replayed public witness history for a wallet-owned balance prover. This is
    /// deliberately available only through the keyless facade, after the local-key invariant has
    /// been checked; production callers never receive fixture key-generation APIs from a fresh
    /// generator nor any member secret material.
    pub fn witness_handle(
        &self,
    ) -> Result<
        crate::circuits::test_utils::block_witness_generator::BlockWitnessGeneratorHandle,
        ProductionBlockProducerError,
    > {
        if self.holds_any_local_signing_keys() {
            return Err(ProductionBlockProducerError::InvalidRegistration(
                "refusing to export a witness history that owns local signing keys".to_string(),
            ));
        }
        Ok(
            crate::circuits::test_utils::block_witness_generator::BlockWitnessGeneratorHandle::new(
                self.witness.clone(),
            ),
        )
    }

    pub fn build_agg_sig_list_proof(
        &self,
        agg: &FalconAggCircuit<F, C, D>,
        agg_list: &AggListCircuit<F, C, D>,
    ) -> anyhow::Result<Option<ProofWithPublicInputs<F, C, D>>> {
        self.witness.build_agg_sig_list_proof(agg, agg_list)
    }
}

// Compile-time guard against accidentally shrinking the public member array assumptions used by
// `from_snapshot` while the wallet record remains wider for delegates.
const _: () = assert!(MAX_CHANNEL_MEMBERS >= MAX_COSIGNERS);
