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
    common::channel::{ChannelRecord, ChannelState},
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _},
    utils::poseidon_hash_out::PoseidonHashOut,
    wallet_core::{ChannelSnapshot, InterChannelDebitPayload, InterChannelTransferDescriptor, MemberInfo},
};

pub const PRODUCTION_JOURNAL_MAGIC: &str = "INTMAX_KEYLESS_BLOCK_PRODUCER";
pub const PRODUCTION_JOURNAL_VERSION: u32 = 1;
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
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
        let producer = verify_and_replay(&disk)?;
        Ok(Self {
            journal_path,
            _journal_lock: journal_lock,
            disk,
            producer,
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
            BlockProducerCommand::PostMemberSetUpdate {
                request_id,
                signed_state,
                old_members,
                new_record,
                new_members,
            } => Ok(BlockProducerCommandResult::Receipt(
                self.post_member_set_update(
                    request_id,
                    signed_state,
                    old_members,
                    new_record,
                    new_members,
                )?,
            )),
        }
    }

    pub fn register(
        &mut self,
        request_id: String,
        snapshot: ChannelSnapshot,
    ) -> Result<BlockProducerReceipt, BlockProducerServiceError> {
        self.ensure_healthy()?;
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

    /// detail2 §Q-3: journaled admission of one member-set-update block. Same durability shape
    /// as `post_inter_channel`: idempotent by request id + fingerprint, refused when a state with
    /// the same digest was already admitted, applied through the journal so a crash replays it.
    pub fn post_member_set_update(
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

    fn ensure_healthy(&self) -> Result<(), BlockProducerServiceError> {
        if self.poisoned {
            Err(BlockProducerServiceError::Poisoned)
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
        let receipt = BlockProducerReceipt::from_entry(&entry);

        self.disk.entries.push(entry);
        self.disk.generation = generation;
        self.disk.tail_hash = receipt.entry_hash;
        if let Err(error) = persist_journal(&self.journal_path, &self.disk) {
            // A failed parent-directory fsync can leave an indeterminate (old or new) durable
            // name. Never continue from the in-memory predecessor; restart and replay the disk.
            self.poisoned = true;
            return Err(error);
        }
        self.producer = candidate;
        Ok(receipt)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PostFingerprint<'a> {
    signed_state: &'a ChannelState,
    debit_payload: &'a InterChannelDebitPayload,
    descriptor: &'a InterChannelTransferDescriptor,
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
        ProductionJournalAction::PostMemberSetUpdate {
            signed_state,
            old_members,
            new_record,
            new_members,
            timestamp,
        } => {
            producer.produce_member_set_update_block(
                signed_state,
                old_members,
                new_record,
                new_members,
                *timestamp,
            )?;
        }
    }
    Ok(())
}

fn verify_and_replay(
    disk: &ProductionJournalFile,
) -> Result<ProductionBlockProducer, BlockProducerServiceError> {
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
    Ok(producer)
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

fn extended_state_commitment(head: &ProducerHeadSnapshot) -> Bytes32 {
    use crate::{
        circuits::validity::block_hash_chain::ext_public_state::ExtendedPublicState,
        common::{
            public_state::PublicState,
            u63::{BlockNumber, U63},
        },
    };

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
    .commitment()
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
        ".{}.tmp.{}.{}",
        file_name.to_string_lossy(),
        std::process::id(),
        disk.generation
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
