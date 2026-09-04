//! Durable, keyless production block-producer service.
//!
//! The journal records public snapshots, N-of-N signed states and public transfer descriptors.
//! It never serializes `BlockWitnessGenerator` (whose fixture-only form can own test signers).
//! Every entry is hash chained and semantically replayed from genesis at startup. A mutation is
//! exposed to callers only after the candidate journal has been written, fsynced, atomically
//! renamed and its parent directory fsynced.

use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::{fd::AsRawFd as _, unix::fs::OpenOptionsExt as _};

use serde::{Deserialize, Serialize};

use crate::{
    block_producer::{
        ProductionBlockProducer, ProductionBlockProducerError, ProductionChannelHead,
        ProductionDepositRequest,
    },
    circuits::validity::block_hash_chain::ext_public_state::ExtendedPublicState,
    close_funding::CloseFundingPlan,
    common::{
        channel::{ChannelRecord, ChannelState},
        public_state::PublicState,
        u63::{BlockNumber, U63},
    },
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _},
    utils::poseidon_hash_out::PoseidonHashOut,
    wallet_core::{
        ChannelSnapshot, InterChannelDebitPayload, InterChannelTransferDescriptor, MemberInfo,
    },
};

pub const PRODUCTION_JOURNAL_MAGIC: &str = "INTMAX_KEYLESS_BLOCK_PRODUCER";
pub const PRODUCTION_JOURNAL_VERSION: u32 = 1;
pub const MEMBER_SET_UPDATE_RETIRED_REASON: &str = "direct member-set updates are retired; close the old channel by unanimous consent and migrate into a newly registered channel";
pub const IMMEDIATE_CLOSE_FUNDING_RETIRED_REASON: &str = "cooperative terminal-child close funding is retired; close the existing N-of-N signed head with its signer-independent exit kit";
const MAX_JOURNAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum BlockProducerServiceError {
    #[error("invalid service configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("request conflict: {0}")]
    Conflict(String),
    #[error("journal is locked by another producer: {0}")]
    Locked(String),
    #[error("journal verification failed: {0}")]
    Journal(String),
    #[error("service is fail-closed after an uncertain persistence result; restart required")]
    Poisoned,
    #[error(transparent)]
    Producer(#[from] ProductionBlockProducerError),
}

impl BlockProducerServiceError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfiguration(_) => "invalid_configuration",
            Self::InvalidRequest(_) => "invalid_request",
            Self::Conflict(_) => "conflict",
            Self::Locked(_) => "journal_locked",
            Self::Journal(_) => "journal_error",
            Self::Poisoned => "service_poisoned",
            Self::Producer(_) => "producer_rejected",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum ProductionJournalAction {
    Register {
        snapshot: ChannelSnapshot,
        timestamp: u64,
    },
    PostDeposit {
        deposit: ProductionDepositRequest,
        timestamp: u64,
    },
    SyncOffchainHeads {
        signed_states: Vec<ChannelState>,
        timestamp: u64,
    },
    PostInterChannel {
        signed_state: ChannelState,
        debit_payload: InterChannelDebitPayload,
        descriptor: InterChannelTransferDescriptor,
        timestamp: u64,
    },
    PostCloseFunding {
        signed_state: ChannelState,
        plan: CloseFundingPlan,
        timestamp: u64,
    },
    /// Exit-kit staging: the descriptor's block folded for a PROPOSED, still unsigned post-debit
    /// state on the prepared (non-authoritative) producer. It only ever exists as `prepared`; the
    /// authoritative journal records the `PostInterChannel` twin that `post_inter_channel`
    /// promotes it into once the real N-of-N arrives and reproduces the identical head.
    StagedInterChannelExitKit {
        proposed_state: ChannelState,
        debit_payload: InterChannelDebitPayload,
        descriptor: InterChannelTransferDescriptor,
        timestamp: u64,
    },
    /// detail2 §Q-3: one member-set-update block (rotate / add on the registered cluster).
    PostMemberSetUpdate {
        signed_state: ChannelState,
        old_members: Vec<MemberInfo>,
        new_record: ChannelRecord,
        new_members: Vec<MemberInfo>,
        timestamp: u64,
    },
}

impl ProductionJournalAction {
    const fn timestamp(&self) -> u64 {
        match self {
            Self::Register { timestamp, .. }
            | Self::PostDeposit { timestamp, .. }
            | Self::SyncOffchainHeads { timestamp, .. }
            | Self::PostInterChannel { timestamp, .. }
            | Self::PostCloseFunding { timestamp, .. }
            | Self::StagedInterChannelExitKit { timestamp, .. }
            | Self::PostMemberSetUpdate { timestamp, .. } => *timestamp,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProducerHeadSnapshot {
    block_number: u64,
    timestamp: u64,
    account_tree_root: PoseidonHashOut,
    deposit_tree_root: PoseidonHashOut,
    prev_public_state_root: PoseidonHashOut,
    block_hash_chain: Bytes32,
    deposit_hash_chain: Bytes32,
    deposit_count: u64,
    channel_reg_hash_chain: Bytes32,
    bp_sig_chain: Bytes32,
    registered_channel_count: usize,
    channel_heads: Vec<ProductionChannelHead>,
}

impl ProducerHeadSnapshot {
    fn capture(producer: &ProductionBlockProducer) -> Self {
        let ext = producer.current_extended_public_state();
        Self {
            block_number: producer.block_number(),
            timestamp: producer.last_timestamp(),
            account_tree_root: ext.inner.account_tree_root,
            deposit_tree_root: ext.inner.deposit_tree_root,
            prev_public_state_root: ext.inner.prev_public_state_root,
            block_hash_chain: ext.block_hash_chain,
            deposit_hash_chain: ext.deposit_hash_chain,
            deposit_count: ext.deposit_count.as_u64(),
            channel_reg_hash_chain: ext.channel_reg_hash_chain,
            bp_sig_chain: ext.bp_sig_chain,
            registered_channel_count: producer.registered_channel_count(),
            channel_heads: producer.channel_heads(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProductionJournalEntry {
    generation: u64,
    request_id: String,
    request_fingerprint: Bytes32,
    prev_entry_hash: Bytes32,
    action: ProductionJournalAction,
    result: ProducerHeadSnapshot,
    entry_hash: Bytes32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProductionJournalFile {
    magic: String,
    version: u32,
    supported_user_counts: Vec<u32>,
    generation: u64,
    tail_hash: Bytes32,
    entries: Vec<ProductionJournalEntry>,
    /// A semantically replayed candidate that is durable but is not yet authoritative. Keeping
    /// this optional field in journal v1 is backwards compatible: legacy files deserialize it as
    /// `None`, while its entry uses the same hash material it will retain after commit.
    #[serde(default)]
    prepared: Option<ProductionJournalEntry>,
}

impl ProductionJournalFile {
    fn empty(supported_user_counts: Vec<u32>) -> Result<Self, BlockProducerServiceError> {
        let tail_hash = journal_genesis_hash(&supported_user_counts)?;
        Ok(Self {
            magic: PRODUCTION_JOURNAL_MAGIC.to_string(),
            version: PRODUCTION_JOURNAL_VERSION,
            supported_user_counts,
            generation: 0,
            tail_hash,
            entries: Vec::new(),
            prepared: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockProducerReceipt {
    pub request_id: String,
    pub generation: u64,
    pub entry_hash: Bytes32,
    pub block_number: u64,
    pub timestamp: u64,
    pub extended_state_commitment: Bytes32,
    pub bp_sig_chain: Bytes32,
}

/// Immutable producer-journal checkpoint used by downstream proof services.
///
/// Unlike [`BlockProducerServiceStatus`], an anchor can be looked up after the producer has
/// advanced. The generation/entry-hash pair authenticates the journal prefix, while the extended
/// state commitment binds the exact validity state at that prefix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockProducerAnchor {
    pub generation: u64,
    pub entry_hash: Bytes32,
    pub block_number: u64,
    pub timestamp: u64,
    pub extended_state_commitment: Bytes32,
    pub bp_sig_chain: Bytes32,
}

impl BlockProducerAnchor {
    fn from_entry(entry: &ProductionJournalEntry) -> Self {
        Self {
            generation: entry.generation,
            entry_hash: entry.entry_hash,
            block_number: entry.result.block_number,
            timestamp: entry.result.timestamp,
            extended_state_commitment: extended_state_commitment(&entry.result),
            bp_sig_chain: entry.result.bp_sig_chain,
        }
    }
}

impl BlockProducerReceipt {
    fn from_entry(entry: &ProductionJournalEntry) -> Self {
        let result = &entry.result;
        let ext_commitment = extended_state_commitment(result);
        Self {
            request_id: entry.request_id.clone(),
            generation: entry.generation,
            entry_hash: entry.entry_hash,
            block_number: result.block_number,
            timestamp: result.timestamp,
            extended_state_commitment: ext_commitment,
            bp_sig_chain: result.bp_sig_chain,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockProducerServiceStatus {
    pub journal_version: u32,
    pub generation: u64,
    pub journal_head: Bytes32,
    pub block_number: u64,
    pub timestamp: u64,
    pub extended_state_commitment: Bytes32,
    pub block_hash_chain: Bytes32,
    pub channel_reg_hash_chain: Bytes32,
    pub bp_sig_chain: Bytes32,
    pub registered_channel_count: usize,
    pub channel_heads: Vec<ProductionChannelHead>,
    pub holds_local_signing_keys: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "command", rename_all = "camelCase")]
pub enum BlockProducerCommand {
    Status,
    Register {
        request_id: String,
        snapshot: ChannelSnapshot,
    },
    PostDeposit {
        request_id: String,
        deposit: ProductionDepositRequest,
    },
    SyncOffchainHeads {
        request_id: String,
        signed_states: Vec<ChannelState>,
    },
    PostInterChannel {
        request_id: String,
        signed_state: ChannelState,
        debit_payload: InterChannelDebitPayload,
        descriptor: InterChannelTransferDescriptor,
    },
    PostCloseFunding {
        request_id: String,
        signed_state: ChannelState,
        plan: CloseFundingPlan,
    },
    PrepareCloseFunding {
        request_id: String,
        signed_state: ChannelState,
        plan: CloseFundingPlan,
    },
    /// Stage the exit-kit block of a proposed, unsigned post-debit state (see
    /// [`BlockProducerService::prepare_inter_channel_exit_kit`]).
    PrepareInterChannelExitKit {
        request_id: String,
        proposed_state: ChannelState,
        debit_payload: InterChannelDebitPayload,
        descriptor: InterChannelTransferDescriptor,
    },
    AbandonPreparedInterChannelExitKit {
        request_id: String,
    },
    PostMemberSetUpdate {
        request_id: String,
        signed_state: ChannelState,
        old_members: Vec<MemberInfo>,
        new_record: ChannelRecord,
        new_members: Vec<MemberInfo>,
    },
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum BlockProducerCommandResult {
    Status(BlockProducerServiceStatus),
    Receipt(BlockProducerReceipt),
}

/// One process owns one journal lock and one in-memory producer. Circuit-owning callers can keep
/// the service alive for the whole daemon lifetime and consume recovered witnesses from the core.
pub struct BlockProducerService {
    journal_path: PathBuf,
    _journal_lock: JournalLock,
    disk: ProductionJournalFile,
    producer: ProductionBlockProducer,
    prepared_producer: Option<ProductionBlockProducer>,
    poisoned: bool,
}

impl BlockProducerService {
    pub fn open(
        journal_path: impl AsRef<Path>,
        supported_user_counts: &[u32],
    ) -> Result<Self, BlockProducerServiceError> {
        validate_supported_user_counts(supported_user_counts)?;
        let journal_path = journal_path.as_ref().to_path_buf();
        let parent = journal_parent(&journal_path);
        fs::create_dir_all(parent).map_err(|e| {
            BlockProducerServiceError::Journal(format!(
                "create journal directory {}: {e}",
                parent.display()
            ))
        })?;
        reject_symlink(&journal_path, "journal")?;
        let journal_lock = JournalLock::acquire(&journal_path)?;

        let disk = if journal_path.exists() {
            read_journal(&journal_path)?
        } else {
            let disk = ProductionJournalFile::empty(supported_user_counts.to_vec())?;
            persist_journal(&journal_path, &disk)?;
            disk
        };
        if disk.supported_user_counts != supported_user_counts {
            return Err(BlockProducerServiceError::InvalidConfiguration(format!(
                "journal circuit arities {:?} differ from requested {:?}",
                disk.supported_user_counts, supported_user_counts
            )));
        }
        let (producer, prepared_producer) = verify_and_replay(&disk)?;
        Ok(Self {
            journal_path,
            _journal_lock: journal_lock,
            disk,
            producer,
            prepared_producer,
            poisoned: false,
        })
    }

    pub fn status(&self) -> Result<BlockProducerServiceStatus, BlockProducerServiceError> {
        if self.poisoned {
            return Err(BlockProducerServiceError::Poisoned);
        }
        let head = ProducerHeadSnapshot::capture(&self.producer);
        Ok(BlockProducerServiceStatus {
            journal_version: self.disk.version,
            generation: self.disk.generation,
            journal_head: self.disk.tail_hash,
            block_number: head.block_number,
            timestamp: head.timestamp,
            extended_state_commitment: extended_state_commitment(&head),
            block_hash_chain: head.block_hash_chain,
            channel_reg_hash_chain: head.channel_reg_hash_chain,
            bp_sig_chain: head.bp_sig_chain,
            registered_channel_count: head.registered_channel_count,
            channel_heads: head.channel_heads,
            holds_local_signing_keys: self.producer.holds_any_local_signing_keys(),
        })
    }

    pub fn execute(
        &mut self,
        command: BlockProducerCommand,
    ) -> Result<BlockProducerCommandResult, BlockProducerServiceError> {
        match command {
            BlockProducerCommand::Status => Ok(BlockProducerCommandResult::Status(self.status()?)),
            BlockProducerCommand::Register {
                request_id,
                snapshot,
            } => Ok(BlockProducerCommandResult::Receipt(
                self.register(request_id, snapshot)?,
            )),
            BlockProducerCommand::PostDeposit {
                request_id,
                deposit,
            } => Ok(BlockProducerCommandResult::Receipt(
                self.post_deposit(request_id, deposit)?,
            )),
            BlockProducerCommand::SyncOffchainHeads {
                request_id,
                signed_states,
            } => Ok(BlockProducerCommandResult::Receipt(
                self.sync_offchain_heads(request_id, signed_states)?,
            )),
            BlockProducerCommand::PostInterChannel {
                request_id,
                signed_state,
                debit_payload,
                descriptor,
            } => Ok(BlockProducerCommandResult::Receipt(
                self.post_inter_channel(request_id, signed_state, debit_payload, descriptor)?,
            )),
            BlockProducerCommand::PostCloseFunding {
                request_id: _,
                signed_state: _,
                plan: _,
            } => Err(BlockProducerServiceError::InvalidRequest(
                IMMEDIATE_CLOSE_FUNDING_RETIRED_REASON.to_string(),
            )),
            BlockProducerCommand::PrepareCloseFunding { .. } => {
                Err(BlockProducerServiceError::InvalidRequest(
                    IMMEDIATE_CLOSE_FUNDING_RETIRED_REASON.to_string(),
                ))
            }
            BlockProducerCommand::PrepareInterChannelExitKit {
                request_id,
                proposed_state,
                debit_payload,
                descriptor,
            } => Ok(BlockProducerCommandResult::Receipt(
                self.prepare_inter_channel_exit_kit(
                    request_id,
                    proposed_state,
                    debit_payload,
                    descriptor,
                )?,
            )),
            BlockProducerCommand::AbandonPreparedInterChannelExitKit { request_id } => {
                self.abandon_prepared_inter_channel_exit_kit(&request_id)?;
                Ok(BlockProducerCommandResult::Status(self.status()?))
            }
            BlockProducerCommand::PostMemberSetUpdate { .. } => {
                Err(BlockProducerServiceError::InvalidRequest(
                    MEMBER_SET_UPDATE_RETIRED_REASON.to_string(),
                ))
            }
        }
    }

    pub fn register(
        &mut self,
        request_id: String,
        snapshot: ChannelSnapshot,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        self.ensure_healthy()?;
        self.ensure_no_prepared()?;
        validate_request_id(&request_id)?;
        let fingerprint = request_fingerprint("register", &snapshot)?;
        if let Some(receipt) = self.idempotent_receipt(&request_id, fingerprint)? {
            return Ok(receipt);
        }
        let timestamp = self.next_timestamp()?;
        self.apply_and_persist(
            request_id,
            fingerprint,
            ProductionJournalAction::Register {
                snapshot,
                timestamp,
            },
        )
    }

    pub fn post_inter_channel(
        &mut self,
        request_id: String,
        signed_state: ChannelState,
        debit_payload: InterChannelDebitPayload,
        descriptor: InterChannelTransferDescriptor,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        self.ensure_healthy()?;
        validate_request_id(&request_id)?;
        let fingerprint = request_fingerprint(
            "postInterChannel",
            &PostFingerprint {
                signed_state: &signed_state,
                debit_payload: &debit_payload,
                descriptor: &descriptor,
            },
        )?;
        if let Some(receipt) = self.idempotent_receipt(&request_id, fingerprint)? {
            return Ok(receipt);
        }
        if let Some(prepared) = self.disk.prepared.clone() {
            // A staged exit-kit block for exactly this transition is promoted in place: the real
            // N-of-N must reproduce the identical head the signer's exit kit was anchored on.
            let staged_fingerprint =
                staged_exit_kit_fingerprint(&signed_state, &debit_payload, &descriptor)?;
            let staged_timestamp = match &prepared.action {
                ProductionJournalAction::StagedInterChannelExitKit { timestamp, .. }
                    if prepared.request_fingerprint == staged_fingerprint =>
                {
                    *timestamp
                }
                _ => {
                    return Err(BlockProducerServiceError::Conflict(format!(
                        "prepared request {:?} freezes the authoritative producer and is not the \
                         staged exit-kit block of this transition",
                        prepared.request_id
                    )));
                }
            };
            let action = ProductionJournalAction::PostInterChannel {
                signed_state,
                debit_payload,
                descriptor,
                timestamp: staged_timestamp,
            };
            let (candidate, entry) =
                self.build_candidate_entry(request_id, fingerprint, action)?;
            if entry.result != prepared.result {
                return Err(BlockProducerServiceError::Conflict(
                    "the N-of-N block does not reproduce the staged exit-kit head; abandon the \
                     staged entry and prepare the exit kit again"
                        .to_string(),
                ));
            }
            let receipt = BlockProducerReceipt::from_entry(&entry);
            let mut next_disk = self.disk.clone();
            next_disk.prepared = None;
            next_disk.entries.push(entry);
            next_disk.generation = receipt.generation;
            next_disk.tail_hash = receipt.entry_hash;
            if let Err(error) = persist_journal(&self.journal_path, &next_disk) {
                self.poisoned = true;
                return Err(error);
            }
            self.disk = next_disk;
            self.producer = candidate;
            self.prepared_producer = None;
            return Ok(receipt);
        }
        for entry in &self.disk.entries {
            if let ProductionJournalAction::PostInterChannel {
                signed_state: accepted,
                descriptor: accepted_descriptor,
                ..
            } = &entry.action
            {
                if accepted.digest == signed_state.digest
                    || accepted_descriptor.tx_hash == descriptor.tx_hash
                {
                    return Err(BlockProducerServiceError::Conflict(format!(
                        "state {} or transaction {} was already admitted by request {}",
                        signed_state.digest, descriptor.tx_hash, entry.request_id
                    )));
                }
            }
        }
        let timestamp = self.next_timestamp()?;
        self.apply_and_persist(
            request_id,
            fingerprint,
            ProductionJournalAction::PostInterChannel {
                signed_state,
                debit_payload,
                descriptor,
                timestamp,
            },
        )
    }

    pub fn post_close_funding(
        &mut self,
        _request_id: String,
        _signed_state: ChannelState,
        _plan: CloseFundingPlan,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        Err(BlockProducerServiceError::InvalidRequest(
            IMMEDIATE_CLOSE_FUNDING_RETIRED_REASON.to_string(),
        ))
    }

    /// Durably stage one terminal close-funding mutation without advancing the authoritative
    /// journal tail or producer. The returned receipt identifies the candidate which downstream
    /// validity code must prove before calling [`Self::commit_prepared_close_funding`].
    pub fn prepare_close_funding(
        &mut self,
        request_id: String,
        signed_state: ChannelState,
        plan: CloseFundingPlan,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        self.ensure_healthy()?;
        validate_request_id(&request_id)?;
        let fingerprint = request_fingerprint(
            "postCloseFunding",
            &CloseFundingFingerprint {
                signed_state: &signed_state,
                plan: &plan,
            },
        )?;
        if let Some(receipt) = self.idempotent_receipt(&request_id, fingerprint)? {
            return Ok(receipt);
        }

        if let Some(prepared) = &self.disk.prepared {
            if prepared.request_id != request_id {
                return Err(BlockProducerServiceError::Conflict(format!(
                    "prepared request {:?} freezes the authoritative producer",
                    prepared.request_id
                )));
            }
            if prepared.request_fingerprint != fingerprint {
                return Err(BlockProducerServiceError::Conflict(format!(
                    "request id {request_id:?} is already prepared with different content"
                )));
            }
            return Ok(BlockProducerReceipt::from_entry(prepared));
        }

        for entry in &self.disk.entries {
            let accepted_digest = match &entry.action {
                ProductionJournalAction::PostCloseFunding {
                    signed_state: accepted,
                    ..
                }
                | ProductionJournalAction::PostInterChannel {
                    signed_state: accepted,
                    ..
                } => Some(accepted.digest),
                ProductionJournalAction::SyncOffchainHeads { signed_states, .. } => signed_states
                    .iter()
                    .find(|state| state.digest == signed_state.digest)
                    .map(|state| state.digest),
                _ => None,
            };
            if accepted_digest == Some(signed_state.digest) {
                return Err(BlockProducerServiceError::Conflict(format!(
                    "channel state {} was already admitted by request {}",
                    signed_state.digest, entry.request_id
                )));
            }
        }

        let timestamp = self.next_timestamp()?;
        let action = ProductionJournalAction::PostCloseFunding {
            signed_state,
            plan,
            timestamp,
        };
        let (candidate, entry) = self.build_candidate_entry(request_id, fingerprint, action)?;
        let receipt = BlockProducerReceipt::from_entry(&entry);
        let mut next_disk = self.disk.clone();
        next_disk.prepared = Some(entry);
        if let Err(error) = persist_journal(&self.journal_path, &next_disk) {
            self.poisoned = true;
            return Err(error);
        }
        self.disk = next_disk;
        self.prepared_producer = Some(candidate);
        Ok(receipt)
    }

    /// Promote the exact prepared close-funding entry to the authoritative journal. Persistence
    /// happens before the in-memory producer advances; any persistence error poisons the process
    /// because the durable rename/fsync boundary may be uncertain.
    pub fn commit_prepared_close_funding(
        &mut self,
        request_id: String,
        signed_state: &ChannelState,
        plan: &CloseFundingPlan,
        expected_anchor: &BlockProducerAnchor,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        self.ensure_healthy()?;
        validate_request_id(&request_id)?;
        let fingerprint = request_fingerprint(
            "postCloseFunding",
            &CloseFundingFingerprint { signed_state, plan },
        )?;
        if let Some(receipt) = self.idempotent_receipt(&request_id, fingerprint)? {
            let committed = self
                .disk
                .entries
                .iter()
                .find(|entry| entry.request_id == request_id)
                .expect("idempotent receipt came from an entry");
            if BlockProducerAnchor::from_entry(committed) != *expected_anchor {
                return Err(BlockProducerServiceError::Conflict(
                    "committed close-funding receipt does not match the expected prepared anchor"
                        .to_string(),
                ));
            }
            return Ok(receipt);
        }

        let prepared = self.disk.prepared.as_ref().ok_or_else(|| {
            BlockProducerServiceError::InvalidRequest(
                "no close-funding candidate is prepared".to_string(),
            )
        })?;
        if prepared.request_id != request_id || prepared.request_fingerprint != fingerprint {
            return Err(BlockProducerServiceError::Conflict(format!(
                "commit does not match prepared request {:?}",
                prepared.request_id
            )));
        }
        if BlockProducerAnchor::from_entry(prepared) != *expected_anchor {
            return Err(BlockProducerServiceError::Conflict(
                "prepared close-funding anchor does not match the proof-bound anchor".to_string(),
            ));
        }
        self.promote_prepared(expected_anchor)
    }

    /// Commit using only the exact proof-bound prepared anchor. This intentionally has no command
    /// variant: only the local validity acknowledgement path may cross this boundary.
    pub fn commit_prepared_close_funding_at_anchor(
        &mut self,
        expected_anchor: &BlockProducerAnchor,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        self.ensure_healthy()?;
        if let Some(committed) = self.committed_entry_at_anchor(expected_anchor) {
            if !matches!(
                &committed.action,
                ProductionJournalAction::PostCloseFunding { .. }
            ) {
                return Err(BlockProducerServiceError::Conflict(
                    "committed anchor is not a terminal close-funding entry".to_string(),
                ));
            }
            return Ok(BlockProducerReceipt::from_entry(committed));
        }
        if self.disk.prepared.is_none() {
            return Err(BlockProducerServiceError::InvalidRequest(
                "no close-funding candidate is prepared at the requested anchor".to_string(),
            ));
        }
        self.promote_prepared(expected_anchor)
    }

    fn promote_prepared(
        &mut self,
        expected_anchor: &BlockProducerAnchor,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        let prepared = self.disk.prepared.as_ref().ok_or_else(|| {
            BlockProducerServiceError::InvalidRequest(
                "no close-funding candidate is prepared".to_string(),
            )
        })?;
        if BlockProducerAnchor::from_entry(prepared) != *expected_anchor {
            return Err(BlockProducerServiceError::Conflict(
                "prepared close-funding anchor does not match the proof-bound anchor".to_string(),
            ));
        }
        if !matches!(
            &prepared.action,
            ProductionJournalAction::PostCloseFunding { .. }
        ) {
            return Err(BlockProducerServiceError::Journal(
                "prepared entry is not close funding".to_string(),
            ));
        }
        if self.prepared_producer.is_none() {
            return Err(BlockProducerServiceError::Journal(
                "verified prepared producer candidate is absent".to_string(),
            ));
        }
        let receipt = BlockProducerReceipt::from_entry(prepared);
        let mut next_disk = self.disk.clone();
        let entry = next_disk.prepared.take().expect("prepared checked above");
        next_disk.entries.push(entry);
        next_disk.generation = receipt.generation;
        next_disk.tail_hash = receipt.entry_hash;
        if let Err(error) = persist_journal(&self.journal_path, &next_disk) {
            self.poisoned = true;
            return Err(error);
        }
        // Persistence is now authoritative. Moving the already-verified candidate avoids a second
        // potentially large producer clone on the proof acknowledgement path.
        let candidate = self
            .prepared_producer
            .take()
            .expect("prepared producer presence was checked before persistence");
        self.disk = next_disk;
        self.producer = candidate;
        Ok(receipt)
    }

    /// Permanent compatibility tombstone for the retired direct member-set-update request.
    pub fn post_member_set_update(
        &mut self,
        _request_id: String,
        _signed_state: ChannelState,
        _old_members: Vec<MemberInfo>,
        _new_record: ChannelRecord,
        _new_members: Vec<MemberInfo>,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        Err(BlockProducerServiceError::InvalidRequest(
            MEMBER_SET_UPDATE_RETIRED_REASON.to_string(),
        ))
    }

    /// Deprecated audit-only implementation; excluded from every default/release build.
    #[cfg(feature = "deprecated-msu")]
    #[allow(dead_code, deprecated)]
    fn post_member_set_update_future(
        &mut self,
        request_id: String,
        signed_state: ChannelState,
        old_members: Vec<MemberInfo>,
        new_record: ChannelRecord,
        new_members: Vec<MemberInfo>,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        self.ensure_healthy()?;
        validate_request_id(&request_id)?;
        let fingerprint = request_fingerprint(
            "postMemberSetUpdate",
            &MemberSetUpdateFingerprint {
                signed_state: &signed_state,
                old_members: &old_members,
                new_record: &new_record,
                new_members: &new_members,
            },
        )?;
        if let Some(receipt) = self.idempotent_receipt(&request_id, fingerprint)? {
            return Ok(receipt);
        }
        for entry in &self.disk.entries {
            if let ProductionJournalAction::PostMemberSetUpdate {
                signed_state: accepted,
                ..
            } = &entry.action
            {
                if accepted.digest == signed_state.digest {
                    return Err(BlockProducerServiceError::Conflict(format!(
                        "member-set update state {} was already admitted by request {}",
                        signed_state.digest, entry.request_id
                    )));
                }
            }
        }
        let timestamp = self.next_timestamp()?;
        self.apply_and_persist(
            request_id,
            fingerprint,
            ProductionJournalAction::PostMemberSetUpdate {
                signed_state,
                old_members,
                new_record,
                new_members,
                timestamp,
            },
        )
    }

    pub fn post_deposit(
        &mut self,
        request_id: String,
        deposit: ProductionDepositRequest,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        self.ensure_healthy()?;
        self.ensure_no_prepared()?;
        validate_request_id(&request_id)?;
        let fingerprint = request_fingerprint("postDeposit", &deposit)?;
        if let Some(receipt) = self.idempotent_receipt(&request_id, fingerprint)? {
            return Ok(receipt);
        }
        let timestamp = self.next_timestamp()?;
        self.apply_and_persist(
            request_id,
            fingerprint,
            ProductionJournalAction::PostDeposit { deposit, timestamp },
        )
    }

    pub fn sync_offchain_heads(
        &mut self,
        request_id: String,
        signed_states: Vec<ChannelState>,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        self.ensure_healthy()?;
        self.ensure_no_prepared()?;
        validate_request_id(&request_id)?;
        if signed_states.is_empty() {
            return Err(BlockProducerServiceError::InvalidRequest(
                "signedStates must contain at least one state".to_string(),
            ));
        }
        let fingerprint = request_fingerprint("syncOffchainHeads", &signed_states)?;
        if let Some(receipt) = self.idempotent_receipt(&request_id, fingerprint)? {
            return Ok(receipt);
        }
        for state in &signed_states {
            for entry in &self.disk.entries {
                let already_admitted = match &entry.action {
                    ProductionJournalAction::PostInterChannel {
                        signed_state: accepted,
                        ..
                    } => accepted.digest == state.digest,
                    ProductionJournalAction::SyncOffchainHeads {
                        signed_states: accepted,
                        ..
                    } => accepted
                        .iter()
                        .any(|accepted| accepted.digest == state.digest),
                    _ => false,
                };
                if already_admitted {
                    return Err(BlockProducerServiceError::Conflict(format!(
                        "channel state {} was already admitted by request {}",
                        state.digest, entry.request_id
                    )));
                }
            }
        }
        let timestamp = self.next_timestamp()?;
        self.apply_and_persist(
            request_id,
            fingerprint,
            ProductionJournalAction::SyncOffchainHeads {
                signed_states,
                timestamp,
            },
        )
    }

    pub fn producer(&self) -> Result<&ProductionBlockProducer, BlockProducerServiceError> {
        self.ensure_healthy()?;
        Ok(&self.producer)
    }

    /// Return the durable, non-authoritative prepared receipt, if one exists.
    pub fn prepared_receipt(
        &self,
    ) -> Result<Option<BlockProducerReceipt>, BlockProducerServiceError> {
        self.ensure_healthy()?;
        Ok(self
            .disk
            .prepared
            .as_ref()
            .map(BlockProducerReceipt::from_entry))
    }

    /// Authenticate the prepared receipt against the exact close-funding request body.
    pub fn prepared_receipt_for_close_funding(
        &self,
        request_id: &str,
        signed_state: &ChannelState,
        plan: &CloseFundingPlan,
    ) -> Result<Option<BlockProducerReceipt>, BlockProducerServiceError> {
        self.ensure_healthy()?;
        let fingerprint = request_fingerprint(
            "postCloseFunding",
            &CloseFundingFingerprint { signed_state, plan },
        )?;
        let Some(prepared) = self.disk.prepared.as_ref() else {
            return Ok(None);
        };
        if prepared.request_id != request_id {
            return Ok(None);
        }
        if prepared.request_fingerprint != fingerprint {
            return Err(BlockProducerServiceError::Conflict(format!(
                "request id {request_id:?} is prepared with different content"
            )));
        }
        Ok(Some(BlockProducerReceipt::from_entry(prepared)))
    }

    /// Anchor for the durable candidate. This is intentionally separate from
    /// [`Self::current_anchor`], which remains the authoritative committed tail.
    pub fn prepared_anchor(
        &self,
    ) -> Result<Option<BlockProducerAnchor>, BlockProducerServiceError> {
        self.ensure_healthy()?;
        Ok(self
            .disk
            .prepared
            .as_ref()
            .map(BlockProducerAnchor::from_entry))
    }

    /// Borrow the semantically replayed prepared producer for proof construction without cloning
    /// its potentially large witness state. It remains non-authoritative until explicit commit.
    pub fn prepared_producer(
        &self,
    ) -> Result<Option<&ProductionBlockProducer>, BlockProducerServiceError> {
        self.ensure_healthy()?;
        Ok(self.prepared_producer.as_ref())
    }

    pub fn prepared_producer_clone(
        &self,
    ) -> Result<Option<ProductionBlockProducer>, BlockProducerServiceError> {
        Ok(self.prepared_producer()?.cloned())
    }

    /// Return the receipt authenticated by the verified, hash-chained journal for `request_id`.
    ///
    /// Downstream durable services use this to reconcile an older checkpoint after the producer
    /// has advanced. Comparing only with [`Self::status`] would authenticate the current head but
    /// could not prove that an earlier receipt actually occurred in this journal.
    pub fn receipt(
        &self,
        request_id: &str,
    ) -> Result<Option<BlockProducerReceipt>, BlockProducerServiceError> {
        self.ensure_healthy()?;
        Ok(self
            .disk
            .entries
            .iter()
            .find(|entry| entry.request_id == request_id)
            .map(BlockProducerReceipt::from_entry))
    }

    /// Return an authenticated historical journal anchor.
    ///
    /// Generation zero is the empty journal's domain-separated genesis hash and the producer's
    /// genesis extended state. Later generations are read from entries which were already fully
    /// hash-chain checked and semantically replayed by [`Self::open`].
    pub fn anchor_at_generation(
        &self,
        generation: u64,
    ) -> Result<Option<BlockProducerAnchor>, BlockProducerServiceError> {
        self.ensure_healthy()?;
        if generation > self.disk.generation {
            return Ok(None);
        }
        if generation == 0 {
            let genesis = ProductionBlockProducer::new(&self.disk.supported_user_counts);
            let head = ProducerHeadSnapshot::capture(&genesis);
            return Ok(Some(BlockProducerAnchor {
                generation: 0,
                entry_hash: journal_genesis_hash(&self.disk.supported_user_counts)?,
                block_number: head.block_number,
                timestamp: head.timestamp,
                extended_state_commitment: extended_state_commitment(&head),
                bp_sig_chain: head.bp_sig_chain,
            }));
        }
        let entry = &self.disk.entries[generation as usize - 1];
        Ok(Some(BlockProducerAnchor {
            generation,
            entry_hash: entry.entry_hash,
            block_number: entry.result.block_number,
            timestamp: entry.result.timestamp,
            extended_state_commitment: extended_state_commitment(&entry.result),
            bp_sig_chain: entry.result.bp_sig_chain,
        }))
    }

    /// Current head in the same historical-anchor format returned by
    /// [`Self::anchor_at_generation`].
    pub fn current_anchor(&self) -> Result<BlockProducerAnchor, BlockProducerServiceError> {
        self.anchor_at_generation(self.disk.generation)?
            .ok_or_else(|| BlockProducerServiceError::Journal("current anchor is absent".into()))
    }

    /// Resolve the exact authenticated extended state whose inner public state a Balance proof
    /// exposes. Balance proofs deliberately do not expose the extended hash-chain fields, so a
    /// caller must never fill those fields from the producer's *current* head after unrelated
    /// channels have advanced. The verified journal is the canonical archive for that preimage.
    ///
    /// If two journal generations somehow carry the same inner state with different extended
    /// commitments, the projection is ambiguous and fails closed. Repeated identical snapshots
    /// are harmless and collapse to the same result.
    pub fn extended_public_state_matching(
        &self,
        inner: &PublicState,
    ) -> Result<ExtendedPublicState, BlockProducerServiceError> {
        self.ensure_healthy()?;

        let genesis = ProductionBlockProducer::new(&self.disk.supported_user_counts);
        let genesis_head = ProducerHeadSnapshot::capture(&genesis);
        let mut matched: Option<ExtendedPublicState> = None;

        let mut consider = |head: &ProducerHeadSnapshot| -> Result<(), BlockProducerServiceError> {
            let candidate = extended_public_state(head);
            if candidate.inner != *inner {
                return Ok(());
            }
            if let Some(previous) = &matched {
                if previous.commitment() != candidate.commitment() {
                    return Err(BlockProducerServiceError::Conflict(
                        "balance public state matches multiple producer journal anchors with different extended commitments"
                            .into(),
                    ));
                }
            } else {
                matched = Some(candidate);
            }
            Ok(())
        };

        consider(&genesis_head)?;
        for entry in &self.disk.entries {
            consider(&entry.result)?;
        }
        // A prepared entry is durable and hash-linked to the journal tail; an exit kit proved
        // against it anchors on the exact head the pending commit must reproduce.
        if let Some(prepared) = &self.disk.prepared {
            consider(&prepared.result)?;
        }
        matched.ok_or_else(|| {
            BlockProducerServiceError::Conflict(
                "balance public state is absent from the authenticated producer journal".into(),
            )
        })
    }

    /// Reconstruct the keyless producer at one exact authenticated historical journal anchor.
    ///
    /// Terminal withdrawal proofs must use the extended public state which existed when their
    /// close-funding transaction was committed. Reusing the current producer after an unrelated
    /// channel advances would create a valid descendant proof whose public anchor no longer
    /// matches the immutable terminal receipt. The journal already contains every public input
    /// needed for deterministic replay, so no additional witness/proof bytes are persisted and no
    /// signing material is introduced.
    pub fn producer_at_anchor(
        &self,
        anchor: &BlockProducerAnchor,
    ) -> Result<ProductionBlockProducer, BlockProducerServiceError> {
        self.ensure_healthy()?;
        let authenticated = self
            .anchor_at_generation(anchor.generation)?
            .ok_or_else(|| {
                BlockProducerServiceError::Conflict(format!(
                    "producer anchor generation {} is beyond the committed journal",
                    anchor.generation
                ))
            })?;
        if authenticated != *anchor {
            return Err(BlockProducerServiceError::Conflict(
                "supplied producer anchor does not match the authenticated journal entry".into(),
            ));
        }

        if anchor.generation == self.disk.generation {
            return Ok(self.producer.clone());
        }

        let entry_count = usize::try_from(anchor.generation).map_err(|_| {
            BlockProducerServiceError::Journal(
                "historical producer generation does not fit this platform".into(),
            )
        })?;
        let mut producer = ProductionBlockProducer::new(&self.disk.supported_user_counts);
        for (index, entry) in self.disk.entries.iter().take(entry_count).enumerate() {
            apply_action(&mut producer, &entry.action).map_err(|error| {
                BlockProducerServiceError::Journal(format!(
                    "historical producer replay failed at entry {}: {error}",
                    index + 1
                ))
            })?;
            if ProducerHeadSnapshot::capture(&producer) != entry.result {
                return Err(BlockProducerServiceError::Journal(format!(
                    "historical producer replay diverged at entry {}",
                    index + 1
                )));
            }
        }
        if producer.holds_any_local_signing_keys() {
            return Err(BlockProducerServiceError::Journal(
                "historical producer replay retained a fixture signing key".into(),
            ));
        }
        Ok(producer)
    }

    /// Authenticate a deposit receipt against both its request id and canonical request body.
    pub fn receipt_for_deposit(
        &self,
        request_id: &str,
        deposit: &ProductionDepositRequest,
    ) -> Result<Option<BlockProducerReceipt>, BlockProducerServiceError> {
        self.ensure_healthy()?;
        self.idempotent_receipt(request_id, request_fingerprint("postDeposit", deposit)?)
    }

    /// Authenticate an inter-channel receipt against the exact signed state and descriptor that
    /// the producer semantically replayed. This prevents a receipt for an unrelated journal action
    /// from being used as a downstream balance-service checkpoint.
    pub fn receipt_for_inter_channel(
        &self,
        request_id: &str,
        signed_state: &ChannelState,
        debit_payload: &InterChannelDebitPayload,
        descriptor: &InterChannelTransferDescriptor,
    ) -> Result<Option<BlockProducerReceipt>, BlockProducerServiceError> {
        self.ensure_healthy()?;
        let fingerprint = request_fingerprint(
            "postInterChannel",
            &PostFingerprint {
                signed_state,
                debit_payload,
                descriptor,
            },
        )?;
        self.idempotent_receipt(request_id, fingerprint)
    }

    /// The receipt of the currently staged exit-kit block for exactly this proposed transition.
    pub fn receipt_for_staged_inter_channel_exit_kit(
        &self,
        request_id: &str,
        proposed_state: &ChannelState,
        debit_payload: &InterChannelDebitPayload,
        descriptor: &InterChannelTransferDescriptor,
    ) -> Result<Option<BlockProducerReceipt>, BlockProducerServiceError> {
        self.ensure_healthy()?;
        let fingerprint = staged_exit_kit_fingerprint(proposed_state, debit_payload, descriptor)?;
        match &self.disk.prepared {
            Some(prepared) if prepared.request_id == request_id => {
                if prepared.request_fingerprint != fingerprint
                    || !matches!(
                        &prepared.action,
                        ProductionJournalAction::StagedInterChannelExitKit { .. }
                    )
                {
                    return Err(BlockProducerServiceError::Conflict(format!(
                        "prepared request {request_id:?} was staged with different content"
                    )));
                }
                Ok(Some(BlockProducerReceipt::from_entry(prepared)))
            }
            _ => Ok(None),
        }
    }

    /// Stage the descriptor's block for a PROPOSED, unsigned post-debit state so the live balance
    /// service can prove the signer's exit kit against the exact block `post_inter_channel` will
    /// commit once the N-of-N arrives. Like a prepared close funding, a staged entry freezes every
    /// other producer mutation: the anchor a signer archived before signing must be the anchor
    /// that lands, or nothing lands.
    pub fn prepare_inter_channel_exit_kit(
        &mut self,
        request_id: String,
        proposed_state: ChannelState,
        debit_payload: InterChannelDebitPayload,
        descriptor: InterChannelTransferDescriptor,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        self.ensure_healthy()?;
        validate_request_id(&request_id)?;
        // A proposal may carry the proposer's own partial signatures; the staged block is
        // identified by the state digest, so every fingerprint is taken over the
        // signature-stripped proposal (the same normalisation `post_inter_channel` applies).
        let fingerprint = staged_exit_kit_fingerprint(&proposed_state, &debit_payload, &descriptor)?;
        if let Some(prepared) = &self.disk.prepared {
            if prepared.request_id == request_id && prepared.request_fingerprint == fingerprint {
                return Ok(BlockProducerReceipt::from_entry(prepared));
            }
            return Err(BlockProducerServiceError::Conflict(format!(
                "prepared request {:?} freezes the authoritative producer; commit or abandon it \
                 before staging another exit kit",
                prepared.request_id
            )));
        }
        if self
            .disk
            .entries
            .iter()
            .any(|entry| entry.request_id == request_id)
        {
            return Err(BlockProducerServiceError::Conflict(format!(
                "request id {request_id:?} already names a committed journal entry"
            )));
        }
        for entry in &self.disk.entries {
            let accepted_digest = match &entry.action {
                ProductionJournalAction::PostCloseFunding {
                    signed_state: accepted,
                    ..
                }
                | ProductionJournalAction::PostInterChannel {
                    signed_state: accepted,
                    ..
                } => Some(accepted.digest),
                ProductionJournalAction::SyncOffchainHeads { signed_states, .. } => signed_states
                    .iter()
                    .find(|state| state.digest == proposed_state.digest)
                    .map(|state| state.digest),
                _ => None,
            };
            if accepted_digest == Some(proposed_state.digest) {
                return Err(BlockProducerServiceError::Conflict(format!(
                    "channel state {} was already admitted by request {}",
                    proposed_state.digest, entry.request_id
                )));
            }
        }
        let timestamp = self.next_timestamp()?;
        let action = ProductionJournalAction::StagedInterChannelExitKit {
            proposed_state,
            debit_payload,
            descriptor,
            timestamp,
        };
        let (candidate, entry) = self.build_candidate_entry(request_id, fingerprint, action)?;
        let receipt = BlockProducerReceipt::from_entry(&entry);
        let mut next_disk = self.disk.clone();
        next_disk.prepared = Some(entry);
        if let Err(error) = persist_journal(&self.journal_path, &next_disk) {
            self.poisoned = true;
            return Err(error);
        }
        self.disk = next_disk;
        self.prepared_producer = Some(candidate);
        Ok(receipt)
    }

    /// Drop a staged exit-kit block that will not be committed (the signer refused, or the
    /// transition was rebuilt). Idempotent. A prepared close funding is never abandoned here: only
    /// the local validity acknowledgement decides its fate.
    pub fn abandon_prepared_inter_channel_exit_kit(
        &mut self,
        request_id: &str,
    ) -> Result<(), BlockProducerServiceError> {
        self.ensure_healthy()?;
        let Some(prepared) = &self.disk.prepared else {
            return Ok(());
        };
        if prepared.request_id != request_id {
            return Err(BlockProducerServiceError::Conflict(format!(
                "prepared request {:?} is not {request_id:?}",
                prepared.request_id
            )));
        }
        if !matches!(
            &prepared.action,
            ProductionJournalAction::StagedInterChannelExitKit { .. }
        ) {
            return Err(BlockProducerServiceError::InvalidRequest(
                "only a staged exit-kit block may be abandoned".to_string(),
            ));
        }
        let mut next_disk = self.disk.clone();
        next_disk.prepared = None;
        if let Err(error) = persist_journal(&self.journal_path, &next_disk) {
            self.poisoned = true;
            return Err(error);
        }
        self.disk = next_disk;
        self.prepared_producer = None;
        Ok(())
    }

    /// Authenticate a terminal close-funding receipt against its complete signed state and plan.
    pub fn receipt_for_close_funding(
        &self,
        request_id: &str,
        signed_state: &ChannelState,
        plan: &CloseFundingPlan,
    ) -> Result<Option<BlockProducerReceipt>, BlockProducerServiceError> {
        self.ensure_healthy()?;
        let fingerprint = request_fingerprint(
            "postCloseFunding",
            &CloseFundingFingerprint { signed_state, plan },
        )?;
        self.idempotent_receipt(request_id, fingerprint)
    }

    /// Retrieve an already-committed close-funding receipt only when both the canonical request
    /// body and the proof-bound prepared anchor match. This is the crash/replay lookup used after
    /// an acknowledgement may already have committed the candidate.
    pub fn committed_receipt_for_close_funding_at_anchor(
        &self,
        request_id: &str,
        signed_state: &ChannelState,
        plan: &CloseFundingPlan,
        prepared_anchor: &BlockProducerAnchor,
    ) -> Result<Option<BlockProducerReceipt>, BlockProducerServiceError> {
        self.ensure_healthy()?;
        let fingerprint = request_fingerprint(
            "postCloseFunding",
            &CloseFundingFingerprint { signed_state, plan },
        )?;
        let Some(entry) = self
            .disk
            .entries
            .iter()
            .find(|entry| entry.request_id == request_id)
        else {
            return Ok(None);
        };
        if entry.request_fingerprint != fingerprint {
            return Err(BlockProducerServiceError::Conflict(format!(
                "request id {request_id:?} was committed with different content"
            )));
        }
        if BlockProducerAnchor::from_entry(entry) != *prepared_anchor {
            return Err(BlockProducerServiceError::Conflict(
                "committed close-funding entry does not match the proof-bound prepared anchor"
                    .to_string(),
            ));
        }
        Ok(Some(BlockProducerReceipt::from_entry(entry)))
    }

    /// Look up any already-committed canonical journal receipt by its complete anchor. This is
    /// intentionally action-agnostic because the ordinary validity acknowledgement path uses the
    /// same crash-replay primitive. Terminal-only callers must separately check their action kind.
    pub fn committed_receipt_at_anchor(
        &self,
        committed_anchor: &BlockProducerAnchor,
    ) -> Result<Option<BlockProducerReceipt>, BlockProducerServiceError> {
        self.ensure_healthy()?;
        Ok(self
            .committed_entry_at_anchor(committed_anchor)
            .map(BlockProducerReceipt::from_entry))
    }

    fn committed_entry_at_anchor(
        &self,
        committed_anchor: &BlockProducerAnchor,
    ) -> Option<&ProductionJournalEntry> {
        if committed_anchor.generation == 0 || committed_anchor.generation > self.disk.generation {
            return None;
        }
        let entry_index = committed_anchor
            .generation
            .checked_sub(1)
            .and_then(|generation| usize::try_from(generation).ok());
        let Some(entry) = entry_index.and_then(|index| self.disk.entries.get(index)) else {
            return None;
        };
        if BlockProducerAnchor::from_entry(entry) != *committed_anchor {
            return None;
        }
        Some(entry)
    }

    fn ensure_healthy(&self) -> Result<(), BlockProducerServiceError> {
        if self.poisoned {
            Err(BlockProducerServiceError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn ensure_no_prepared(&self) -> Result<(), BlockProducerServiceError> {
        if let Some(prepared) = &self.disk.prepared {
            Err(BlockProducerServiceError::Conflict(format!(
                "prepared request {:?} freezes all other producer mutations until it is committed or abandoned",
                prepared.request_id
            )))
        } else {
            Ok(())
        }
    }

    fn next_timestamp(&self) -> Result<u64, BlockProducerServiceError> {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                BlockProducerServiceError::InvalidConfiguration(format!(
                    "system clock is before Unix epoch: {e}"
                ))
            })?
            .as_secs();
        // Journal-only head synchronization does not create a block and therefore does not move
        // `producer.last_timestamp()`. Order against the latest journal action as well, otherwise
        // two updates accepted within one wall-clock second would serialize with equal timestamps
        // and fail semantic replay on restart.
        let prior = self
            .disk
            .entries
            .last()
            .map(|entry| entry.action.timestamp())
            .unwrap_or_else(|| self.producer.last_timestamp())
            .max(self.producer.last_timestamp());
        let successor = prior.checked_add(1).ok_or_else(|| {
            BlockProducerServiceError::InvalidConfiguration(
                "producer timestamp is exhausted at u64::MAX".to_string(),
            )
        })?;
        Ok(wall.max(successor))
    }

    fn idempotent_receipt(
        &self,
        request_id: &str,
        fingerprint: Bytes32,
    ) -> Result<Option<BlockProducerReceipt>, BlockProducerServiceError> {
        let Some(entry) = self
            .disk
            .entries
            .iter()
            .find(|entry| entry.request_id == request_id)
        else {
            return Ok(None);
        };
        if entry.request_fingerprint != fingerprint {
            return Err(BlockProducerServiceError::Conflict(format!(
                "request id {request_id:?} was already used for different content"
            )));
        }
        Ok(Some(BlockProducerReceipt::from_entry(entry)))
    }

    fn apply_and_persist(
        &mut self,
        request_id: String,
        request_fingerprint: Bytes32,
        action: ProductionJournalAction,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        self.ensure_no_prepared()?;
        let (candidate, entry) =
            self.build_candidate_entry(request_id, request_fingerprint, action)?;
        let receipt = BlockProducerReceipt::from_entry(&entry);
        let mut next_disk = self.disk.clone();
        next_disk.entries.push(entry);
        next_disk.generation = receipt.generation;
        next_disk.tail_hash = receipt.entry_hash;
        if let Err(error) = persist_journal(&self.journal_path, &next_disk) {
            // A failed parent-directory fsync can leave an indeterminate (old or new) durable
            // name. Never continue from the in-memory predecessor; restart and replay the disk.
            self.poisoned = true;
            return Err(error);
        }
        self.disk = next_disk;
        self.producer = candidate;
        Ok(receipt)
    }

    fn build_candidate_entry(
        &self,
        request_id: String,
        request_fingerprint: Bytes32,
        action: ProductionJournalAction,
    ) -> Result<(ProductionBlockProducer, ProductionJournalEntry), BlockProducerServiceError> {
        let mut candidate = self.producer.clone();
        apply_action(&mut candidate, &action)?;
        if candidate.holds_any_local_signing_keys() {
            return Err(BlockProducerServiceError::Journal(
                "candidate producer retained fixture signing keys".to_string(),
            ));
        }
        let result = ProducerHeadSnapshot::capture(&candidate);
        let generation = self.disk.generation.checked_add(1).ok_or_else(|| {
            BlockProducerServiceError::Journal("journal generation overflow".to_string())
        })?;
        let mut entry = ProductionJournalEntry {
            generation,
            request_id,
            request_fingerprint,
            prev_entry_hash: self.disk.tail_hash,
            action,
            result,
            entry_hash: Bytes32::default(),
        };
        entry.entry_hash = journal_entry_hash(&entry)?;
        Ok((candidate, entry))
    }
}

/// Fingerprint domain of a staged exit-kit block: the proposed state (no signatures), the debit
/// payload and the descriptor.
const STAGED_INTER_CHANNEL_EXIT_KIT_DOMAIN: &str = "stageInterChannelExitKit";

/// Fingerprint of a staged exit-kit block over the signature-stripped proposal (state and the
/// payload's proposed state): the proposer may attach partial signatures and the co-signed post
/// carries the complete set, yet both name the same block.
fn staged_exit_kit_fingerprint(
    state: &ChannelState,
    debit_payload: &InterChannelDebitPayload,
    descriptor: &InterChannelTransferDescriptor,
) -> Result<Bytes32, BlockProducerServiceError> {
    let mut stripped_state = state.clone();
    stripped_state.member_signatures.clear();
    let mut stripped_payload = debit_payload.clone();
    stripped_payload.proposed_next_state.member_signatures.clear();
    request_fingerprint(
        STAGED_INTER_CHANNEL_EXIT_KIT_DOMAIN,
        &PostFingerprint {
            signed_state: &stripped_state,
            debit_payload: &stripped_payload,
            descriptor,
        },
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PostFingerprint<'a> {
    signed_state: &'a ChannelState,
    debit_payload: &'a InterChannelDebitPayload,
    descriptor: &'a InterChannelTransferDescriptor,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CloseFundingFingerprint<'a> {
    signed_state: &'a ChannelState,
    plan: &'a CloseFundingPlan,
}

fn apply_action(
    producer: &mut ProductionBlockProducer,
    action: &ProductionJournalAction,
) -> Result<(), BlockProducerServiceError> {
    match action {
        ProductionJournalAction::Register {
            snapshot,
            timestamp,
        } => {
            producer.register_snapshot(snapshot, *timestamp)?;
        }
        ProductionJournalAction::PostDeposit { deposit, timestamp } => {
            producer.produce_deposit_block(deposit, *timestamp)?;
        }
        ProductionJournalAction::SyncOffchainHeads { signed_states, .. } => {
            producer.sync_offchain_heads(signed_states)?;
        }
        ProductionJournalAction::PostInterChannel {
            signed_state,
            debit_payload,
            descriptor,
            timestamp,
        } => {
            producer.produce_inter_channel_descriptor_block(
                signed_state,
                debit_payload,
                descriptor,
                *timestamp,
            )?;
        }
        ProductionJournalAction::PostCloseFunding {
            signed_state,
            plan,
            timestamp,
        } => {
            producer.produce_close_funding_block(signed_state, plan, *timestamp)?;
        }
        ProductionJournalAction::StagedInterChannelExitKit {
            proposed_state,
            debit_payload,
            descriptor,
            timestamp,
        } => {
            producer.produce_inter_channel_descriptor_block_unsigned_staging(
                proposed_state,
                debit_payload,
                descriptor,
                *timestamp,
            )?;
        }
        ProductionJournalAction::PostMemberSetUpdate { .. } => {
            return Err(BlockProducerServiceError::InvalidRequest(
                MEMBER_SET_UPDATE_RETIRED_REASON.to_string(),
            ));
        }
    }
    Ok(())
}

fn verify_and_replay(
    disk: &ProductionJournalFile,
) -> Result<(ProductionBlockProducer, Option<ProductionBlockProducer>), BlockProducerServiceError> {
    if disk.magic != PRODUCTION_JOURNAL_MAGIC {
        return Err(BlockProducerServiceError::Journal(format!(
            "magic {:?} is not {:?}",
            disk.magic, PRODUCTION_JOURNAL_MAGIC
        )));
    }
    if disk.version != PRODUCTION_JOURNAL_VERSION {
        return Err(BlockProducerServiceError::Journal(format!(
            "unsupported journal version {} (expected {})",
            disk.version, PRODUCTION_JOURNAL_VERSION
        )));
    }
    validate_supported_user_counts(&disk.supported_user_counts)?;
    if let Some((index, _)) = disk.entries.iter().enumerate().find(|(_, entry)| {
        matches!(
            &entry.action,
            ProductionJournalAction::PostMemberSetUpdate { .. }
        )
    }) {
        return Err(BlockProducerServiceError::Journal(format!(
            "entry {} contains a disabled legacy member-set update; operator migration is required",
            index + 1
        )));
    }
    if let Some((index, _)) = disk.entries.iter().enumerate().find(|(_, entry)| {
        matches!(
            &entry.action,
            ProductionJournalAction::StagedInterChannelExitKit { .. }
        )
    }) {
        return Err(BlockProducerServiceError::Journal(format!(
            "entry {} is an unsigned exit-kit staging block inside the authoritative journal",
            index + 1
        )));
    }
    if disk.generation != disk.entries.len() as u64 {
        return Err(BlockProducerServiceError::Journal(format!(
            "generation {} disagrees with {} entries",
            disk.generation,
            disk.entries.len()
        )));
    }

    let mut producer = ProductionBlockProducer::new(&disk.supported_user_counts);
    let mut expected_prev = journal_genesis_hash(&disk.supported_user_counts)?;
    let mut request_ids = HashSet::new();
    let mut prior_timestamp = 0u64;
    for (index, entry) in disk.entries.iter().enumerate() {
        let expected_generation = index as u64 + 1;
        if entry.generation != expected_generation || entry.prev_entry_hash != expected_prev {
            return Err(BlockProducerServiceError::Journal(format!(
                "entry {expected_generation} has a broken generation or previous-hash link"
            )));
        }
        validate_request_id(&entry.request_id).map_err(|e| {
            BlockProducerServiceError::Journal(format!(
                "entry {expected_generation} request id: {e}"
            ))
        })?;
        if !request_ids.insert(entry.request_id.clone()) {
            return Err(BlockProducerServiceError::Journal(format!(
                "duplicate request id {:?} at entry {expected_generation}",
                entry.request_id
            )));
        }
        let expected_fingerprint = fingerprint_for_action(&entry.action)?;
        if entry.request_fingerprint != expected_fingerprint {
            return Err(BlockProducerServiceError::Journal(format!(
                "entry {expected_generation} request fingerprint mismatch"
            )));
        }
        if entry.action.timestamp() <= prior_timestamp {
            return Err(BlockProducerServiceError::Journal(format!(
                "entry {expected_generation} timestamp is not strictly monotonic"
            )));
        }
        let expected_hash = journal_entry_hash(entry)?;
        if entry.entry_hash != expected_hash {
            return Err(BlockProducerServiceError::Journal(format!(
                "entry {expected_generation} hash mismatch"
            )));
        }

        apply_action(&mut producer, &entry.action).map_err(|e| {
            BlockProducerServiceError::Journal(format!(
                "entry {expected_generation} semantic replay failed: {e}"
            ))
        })?;
        let actual = ProducerHeadSnapshot::capture(&producer);
        if actual != entry.result {
            return Err(BlockProducerServiceError::Journal(format!(
                "entry {expected_generation} replayed to a different producer head"
            )));
        }
        if producer.holds_any_local_signing_keys() {
            return Err(BlockProducerServiceError::Journal(format!(
                "entry {expected_generation} replay retained a fixture signing key"
            )));
        }
        prior_timestamp = entry.action.timestamp();
        expected_prev = entry.entry_hash;
    }
    if disk.tail_hash != expected_prev {
        return Err(BlockProducerServiceError::Journal(
            "journal tail hash does not match the verified entry chain".to_string(),
        ));
    }

    let prepared_producer = if let Some(prepared) = &disk.prepared {
        let expected_generation = disk.generation.checked_add(1).ok_or_else(|| {
            BlockProducerServiceError::Journal(
                "prepared entry generation overflows the journal".to_string(),
            )
        })?;
        if prepared.generation != expected_generation || prepared.prev_entry_hash != disk.tail_hash
        {
            return Err(BlockProducerServiceError::Journal(
                "prepared entry has a broken generation or previous-hash link".to_string(),
            ));
        }
        validate_request_id(&prepared.request_id).map_err(|e| {
            BlockProducerServiceError::Journal(format!("prepared entry request id: {e}"))
        })?;
        if request_ids.contains(&prepared.request_id) {
            return Err(BlockProducerServiceError::Journal(format!(
                "prepared request id {:?} already exists in the authoritative journal",
                prepared.request_id
            )));
        }
        if !matches!(
            &prepared.action,
            ProductionJournalAction::PostCloseFunding { .. }
                | ProductionJournalAction::StagedInterChannelExitKit { .. }
        ) {
            return Err(BlockProducerServiceError::Journal(
                "prepared entry is neither a terminal close funding nor a staged exit-kit block"
                    .to_string(),
            ));
        }
        let expected_fingerprint = fingerprint_for_action(&prepared.action)?;
        if prepared.request_fingerprint != expected_fingerprint {
            return Err(BlockProducerServiceError::Journal(
                "prepared entry request fingerprint mismatch".to_string(),
            ));
        }
        if prepared.action.timestamp() <= prior_timestamp {
            return Err(BlockProducerServiceError::Journal(
                "prepared entry timestamp is not strictly monotonic".to_string(),
            ));
        }
        let expected_hash = journal_entry_hash(prepared)?;
        if prepared.entry_hash != expected_hash {
            return Err(BlockProducerServiceError::Journal(
                "prepared entry hash mismatch".to_string(),
            ));
        }

        let mut candidate = producer.clone();
        apply_action(&mut candidate, &prepared.action).map_err(|e| {
            BlockProducerServiceError::Journal(format!(
                "prepared entry semantic replay failed: {e}"
            ))
        })?;
        if ProducerHeadSnapshot::capture(&candidate) != prepared.result {
            return Err(BlockProducerServiceError::Journal(
                "prepared entry replayed to a different producer head".to_string(),
            ));
        }
        if candidate.holds_any_local_signing_keys() {
            return Err(BlockProducerServiceError::Journal(
                "prepared entry replay retained a fixture signing key".to_string(),
            ));
        }
        Some(candidate)
    } else {
        None
    };
    Ok((producer, prepared_producer))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JournalGenesis<'a> {
    domain: &'static str,
    version: u32,
    supported_user_counts: &'a [u32],
}

fn journal_genesis_hash(
    supported_user_counts: &[u32],
) -> Result<Bytes32, BlockProducerServiceError> {
    hash_serializable(&JournalGenesis {
        domain: "INTMAX_BLOCK_PRODUCER_JOURNAL_GENESIS_V1",
        version: PRODUCTION_JOURNAL_VERSION,
        supported_user_counts,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JournalEntryHashMaterial<'a> {
    domain: &'static str,
    version: u32,
    generation: u64,
    request_id: &'a str,
    request_fingerprint: Bytes32,
    prev_entry_hash: Bytes32,
    action: &'a ProductionJournalAction,
    result: &'a ProducerHeadSnapshot,
}

fn journal_entry_hash(
    entry: &ProductionJournalEntry,
) -> Result<Bytes32, BlockProducerServiceError> {
    hash_serializable(&JournalEntryHashMaterial {
        domain: "INTMAX_BLOCK_PRODUCER_JOURNAL_ENTRY_V1",
        version: PRODUCTION_JOURNAL_VERSION,
        generation: entry.generation,
        request_id: &entry.request_id,
        request_fingerprint: entry.request_fingerprint,
        prev_entry_hash: entry.prev_entry_hash,
        action: &entry.action,
        result: &entry.result,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestFingerprint<'a, T> {
    domain: &'static str,
    kind: &'a str,
    body: &'a T,
}

fn request_fingerprint<T: Serialize>(
    kind: &str,
    body: &T,
) -> Result<Bytes32, BlockProducerServiceError> {
    hash_serializable(&RequestFingerprint {
        domain: "INTMAX_BLOCK_PRODUCER_REQUEST_V1",
        kind,
        body,
    })
}

fn fingerprint_for_action(
    action: &ProductionJournalAction,
) -> Result<Bytes32, BlockProducerServiceError> {
    match action {
        ProductionJournalAction::Register { snapshot, .. } => {
            request_fingerprint("register", snapshot)
        }
        ProductionJournalAction::PostDeposit { deposit, .. } => {
            request_fingerprint("postDeposit", deposit)
        }
        ProductionJournalAction::SyncOffchainHeads { signed_states, .. } => {
            request_fingerprint("syncOffchainHeads", signed_states)
        }
        ProductionJournalAction::PostInterChannel {
            signed_state,
            debit_payload,
            descriptor,
            ..
        } => request_fingerprint(
            "postInterChannel",
            &PostFingerprint {
                signed_state,
                debit_payload,
                descriptor,
            },
        ),
        ProductionJournalAction::PostCloseFunding {
            signed_state, plan, ..
        } => request_fingerprint(
            "postCloseFunding",
            &CloseFundingFingerprint { signed_state, plan },
        ),
        ProductionJournalAction::StagedInterChannelExitKit {
            proposed_state,
            debit_payload,
            descriptor,
            ..
        } => staged_exit_kit_fingerprint(proposed_state, debit_payload, descriptor),
        ProductionJournalAction::PostMemberSetUpdate {
            signed_state,
            old_members,
            new_record,
            new_members,
            ..
        } => request_fingerprint(
            "postMemberSetUpdate",
            &MemberSetUpdateFingerprint {
                signed_state,
                old_members,
                new_record,
                new_members,
            },
        ),
    }
}

#[derive(Serialize)]
struct MemberSetUpdateFingerprint<'a> {
    signed_state: &'a ChannelState,
    old_members: &'a [MemberInfo],
    new_record: &'a ChannelRecord,
    new_members: &'a [MemberInfo],
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<Bytes32, BlockProducerServiceError> {
    let bytes = serde_json::to_vec(value).map_err(|e| {
        BlockProducerServiceError::Journal(format!("canonical journal serialization: {e}"))
    })?;
    Bytes32::from_bytes_be(&keccak_hash::keccak(bytes).0).map_err(|e| {
        BlockProducerServiceError::Journal(format!("convert keccak journal hash: {e}"))
    })
}

fn extended_public_state(head: &ProducerHeadSnapshot) -> ExtendedPublicState {
    ExtendedPublicState::new(
        PublicState {
            block_number: BlockNumber::new(head.block_number)
                .expect("verified producer head block number fits U63"),
            timestamp: head.timestamp,
            account_tree_root: head.account_tree_root,
            deposit_tree_root: head.deposit_tree_root,
            prev_public_state_root: head.prev_public_state_root,
        },
        head.block_hash_chain,
        head.deposit_hash_chain,
        U63::new(head.deposit_count).expect("verified deposit count fits U63"),
        head.channel_reg_hash_chain,
        head.bp_sig_chain,
    )
}

fn extended_state_commitment(head: &ProducerHeadSnapshot) -> Bytes32 {
    extended_public_state(head).commitment()
}

fn read_journal(path: &Path) -> Result<ProductionJournalFile, BlockProducerServiceError> {
    let metadata = fs::metadata(path).map_err(|e| {
        BlockProducerServiceError::Journal(format!("stat journal {}: {e}", path.display()))
    })?;
    if !metadata.is_file() {
        return Err(BlockProducerServiceError::Journal(format!(
            "journal {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() == 0 || metadata.len() > MAX_JOURNAL_BYTES {
        return Err(BlockProducerServiceError::Journal(format!(
            "journal size {} is outside 1..={MAX_JOURNAL_BYTES} bytes",
            metadata.len()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|e| {
            BlockProducerServiceError::Journal(format!("read journal {}: {e}", path.display()))
        })?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let disk = ProductionJournalFile::deserialize(&mut deserializer).map_err(|e| {
        BlockProducerServiceError::Journal(format!("parse journal {}: {e}", path.display()))
    })?;
    deserializer.end().map_err(|e| {
        BlockProducerServiceError::Journal(format!(
            "journal {} has trailing or truncated data: {e}",
            path.display()
        ))
    })?;
    Ok(disk)
}

fn persist_journal(
    path: &Path,
    disk: &ProductionJournalFile,
) -> Result<(), BlockProducerServiceError> {
    let encoded = serde_json::to_vec(disk)
        .map_err(|e| BlockProducerServiceError::Journal(format!("serialize journal: {e}")))?;
    if encoded.is_empty() || encoded.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(BlockProducerServiceError::Journal(format!(
            "serialized journal size {} is outside 1..={MAX_JOURNAL_BYTES} bytes",
            encoded.len()
        )));
    }
    let parent = journal_parent(path);
    let file_name = path.file_name().ok_or_else(|| {
        BlockProducerServiceError::InvalidConfiguration(format!(
            "journal path {} has no file name",
            path.display()
        ))
    })?;
    let tmp_name = format!(
        ".{}.tmp.{}.{}.{}",
        file_name.to_string_lossy(),
        std::process::id(),
        disk.generation,
        rand::random::<u64>()
    );
    let tmp_path = parent.join(tmp_name);
    reject_symlink(&tmp_path, "journal temporary file")?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&tmp_path).map_err(|e| {
        BlockProducerServiceError::Journal(format!(
            "create temporary journal {}: {e}",
            tmp_path.display()
        ))
    })?;
    let write_result = (|| {
        file.write_all(&encoded)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, path)?;
        File::open(parent)?.sync_all()?;
        Ok::<(), std::io::Error>(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(BlockProducerServiceError::Journal(format!(
            "atomically persist journal {}: {error}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_supported_user_counts(counts: &[u32]) -> Result<(), BlockProducerServiceError> {
    if counts.is_empty()
        || counts.iter().any(|count| *count == 0)
        || counts.windows(2).any(|window| window[0] >= window[1])
    {
        return Err(BlockProducerServiceError::InvalidConfiguration(
            "supported user counts must be non-empty, non-zero and strictly increasing".to_string(),
        ));
    }
    if counts[0] < 1 {
        return Err(BlockProducerServiceError::InvalidConfiguration(
            "at least one circuit arity must admit a single active channel".to_string(),
        ));
    }
    Ok(())
}

fn validate_request_id(request_id: &str) -> Result<(), BlockProducerServiceError> {
    if request_id.is_empty()
        || request_id.len() > MAX_REQUEST_ID_BYTES
        || !request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(BlockProducerServiceError::InvalidRequest(format!(
            "requestId must be 1..={MAX_REQUEST_ID_BYTES} ASCII identifier characters"
        )));
    }
    Ok(())
}

fn journal_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), BlockProducerServiceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(BlockProducerServiceError::Journal(format!(
                "{label} {} must not be a symlink",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BlockProducerServiceError::Journal(format!(
            "inspect {label} {}: {error}",
            path.display()
        ))),
    }
}

struct JournalLock {
    file: File,
}

impl JournalLock {
    fn acquire(journal_path: &Path) -> Result<Self, BlockProducerServiceError> {
        let mut lock_name = journal_path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock_path = PathBuf::from(lock_name);
        reject_symlink(&lock_path, "journal lock")?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&lock_path).map_err(|e| {
            BlockProducerServiceError::Journal(format!(
                "open journal lock {}: {e}",
                lock_path.display()
            ))
        })?;

        #[cfg(unix)]
        {
            // SAFETY: `file` owns a valid descriptor for the lifetime of `JournalLock`.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                return Err(BlockProducerServiceError::Locked(format!(
                    "{} ({error})",
                    lock_path.display()
                )));
            }
        }
        #[cfg(not(unix))]
        {
            return Err(BlockProducerServiceError::InvalidConfiguration(
                "durable producer locking is currently supported only on Unix".to_string(),
            ));
        }
        Ok(Self { file })
    }
}

impl Drop for JournalLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            // SAFETY: the descriptor remains valid until this field is dropped after `drop`.
            let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}
