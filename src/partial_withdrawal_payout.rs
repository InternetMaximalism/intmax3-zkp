//! Crash-safe orchestration state for proof-backed partial withdrawals.
//!
//! The balance/withdrawal prover owns private witness material; this module deliberately accepts
//! only its public proof artefacts.  It then records the irreversible L1 boundary in three durable
//! phases: prepared proof, settlement-manager finalization (`finalizePartialWithdrawal`), proof
//! payout (`withdrawNative`/`withdrawERC20`) and recipient pull (`withdraw`/`withdrawToken`). If the
//! proved recipient is external to the local signer, a durable handoff completes the local
//! workflow at the proof-payout boundary without claiming the recipient pulled. A caller may
//! resume any phase after a crash, but it may never replace an in-flight withdrawal or mark it
//! complete from an authorization alone.

#![cfg(not(target_arch = "wasm32"))]

use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::{
        fd::AsRawFd as _,
        unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    block_producer_service::{BlockProducerAnchor, BlockProducerReceipt},
    common::{channel_id::ChannelId, withdrawal::Withdrawal},
    ethereum_types::{
        address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256,
    },
    l1_finality::L1FinalizedCheckpoint,
    wallet_core::partial_withdrawal_auth_digest,
};

const SNAPSHOT_MAGIC: &[u8; 16] = b"INTMAX_PAYOUT_03";
pub const PARTIAL_WITHDRAWAL_PAYOUT_VERSION: u32 = 3;
const HEADER_BYTES: usize = 16 + 4 + 8 + 32;
const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PartialWithdrawalPayoutError {
    #[error("invalid partial-withdrawal payout request: {0}")]
    InvalidRequest(String),
    #[error("partial-withdrawal payout conflict: {0}")]
    Conflict(String),
    #[error("partial-withdrawal payout snapshot failed verification: {0}")]
    Snapshot(String),
    #[error("partial-withdrawal payout snapshot is locked: {0}")]
    Locked(String),
    #[error("payout store is fail-closed after an uncertain persistence result; restart required")]
    Poisoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PartialWithdrawalLane {
    Native,
    Erc20,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialWithdrawalProofMetrics {
    pub single_withdrawal_millis: u64,
    pub withdrawal_chain_millis: u64,
    pub withdrawal_final_millis: u64,
    pub wrap_mle_millis: u64,
    pub single_withdrawal_proof_bytes: usize,
    pub withdrawal_chain_proof_bytes: usize,
    pub withdrawal_final_proof_bytes: usize,
    pub mle_json_bytes: usize,
    pub peak_rss_bytes: Option<u64>,
}

/// Public output of the live prover.  `withdrawal` MUST have been decoded from the
/// single-withdrawal proof's public inputs, never reconstructed by the payout caller.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialWithdrawalProofArtifacts {
    pub withdrawal: Withdrawal,
    pub withdrawal_prover: Address,
    pub payout_json: String,
    pub withdrawal_mle_json: String,
    pub producer_anchor: BlockProducerAnchor,
    pub metrics: PartialWithdrawalProofMetrics,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparePartialWithdrawalPayout {
    pub chain_id: u64,
    pub rollup: Address,
    /// Settlement manager whose pending request creates this candidate's one-shot authorization.
    pub manager: Address,
    pub channel_id: ChannelId,
    pub signed_head_digest: Bytes32,
    /// The nonce consumed by the burn.  The live receipt carries the post-burn cursor separately.
    pub burn_base_nonce: u32,
    pub producer_receipt: BlockProducerReceipt,
    pub auth_digest: Bytes32,
    pub artifacts: PartialWithdrawalProofArtifacts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum L1CallKind {
    /// Final deployment CALL which binds a channel settlement manager to the backing rollup.
    /// It reuses the canonical receipt reader so settlement activation gets the same exact
    /// transaction/reorg/finality checks as fund-moving calls.
    RegisterSettlementManager,
    FinalizePartialWithdrawal,
    WithdrawNative,
    WithdrawErc20,
    PullNative,
    PullErc20,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct L1TransactionReceipt {
    pub tx_hash: Bytes32,
    pub block_hash: Bytes32,
    pub block_number: u64,
    pub chain_id: u64,
    pub from: Address,
    pub to: Address,
    pub success: bool,
    /// The receipt reader must classify the transaction from its actual calldata selector.
    pub call_kind: L1CallKind,
    /// Keccak of the complete transaction input, including selector and every proof byte.
    pub calldata_hash: Bytes32,
    pub transaction_nonce: u64,
    /// Independently read durable head that covered this receipt when it was adopted.  The CLI
    /// revalidates both this checkpoint and the receipt block on every resume.
    pub finalized_checkpoint: L1FinalizedCheckpoint,
    /// The authorization digest emitted by `ChannelSettlementManager` for a successful
    /// `finalizePartialWithdrawal()` call.  The function has no calldata arguments, so its
    /// canonical receipt must carry this event binding; post-state alone cannot prove which
    /// pending request the zero-argument call finalized.
    #[serde(default)]
    pub manager_finalized_auth_digest: Option<Bytes32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BroadcastIntent {
    pub caller: Address,
    pub start_block: u64,
    pub caller_nonce: u64,
    /// Keccak of the exact calldata produced by the local dry-run and intended for this nonce.
    pub calldata_hash: Bytes32,
    /// Exact on-chain pull-credit value observed immediately before the transaction may be sent.
    /// Persisting it before broadcast makes the post-receipt delta check recoverable after a
    /// process crash; a retry must never silently substitute a newer balance.
    pub credit_before: U256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayoutConfirmation {
    pub receipt: L1TransactionReceipt,
    /// Exact value of `partialWithdrawalAuthorized(authDigest)` observed after the successful
    /// payout receipt. IPW2 is one-shot, so this MUST be false: a true value would leave the same
    /// proof-independent authorization reusable with another proof-valid nullifier.
    pub authorization_observed: bool,
    pub finalized_anchor_observed: bool,
    pub nullifier_used_observed: bool,
    pub credit_before: U256,
    pub credit_after: U256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PullConfirmation {
    pub receipt: L1TransactionReceipt,
    pub credit_before: U256,
    pub credit_after: U256,
}

/// Canonical finalized evidence for the manager transition from pending request to the one-shot
/// rollup authorization.  Persisting this separately from the payout receipt prevents a restart
/// from treating an orphaned `finalizePartialWithdrawal` as an authorized fund transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizeConfirmation {
    pub receipt: L1TransactionReceipt,
    pub manager_pending_observed: bool,
    pub authorization_observed: bool,
    pub nullifier_used_observed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialWithdrawalCandidate {
    pub candidate_id: Bytes32,
    pub chain_id: u64,
    pub rollup: Address,
    pub manager: Address,
    pub channel_id: ChannelId,
    pub signed_head_digest: Bytes32,
    pub burn_base_nonce: u32,
    pub producer_receipt: BlockProducerReceipt,
    pub auth_digest: Bytes32,
    pub lane: PartialWithdrawalLane,
    pub artifacts: PartialWithdrawalProofArtifacts,
    pub finalize_broadcast: Option<BroadcastIntent>,
    /// Append-only replacement hashes for the exact manager-finalization sender/nonce/calldata.
    #[serde(default)]
    pub finalize_tx_hashes: Vec<Bytes32>,
    pub finalize_confirmation: Option<FinalizeConfirmation>,
    pub payout_broadcast: Option<BroadcastIntent>,
    /// Every transaction hash returned while (re)broadcasting the exact persisted payout intent.
    /// The vector is append-only because a dropped transaction may be replaced at the same nonce;
    /// either exact transaction is a valid receipt candidate, but no different calldata is.
    #[serde(default)]
    pub payout_tx_hashes: Vec<Bytes32>,
    pub payout_confirmation: Option<PayoutConfirmation>,
    /// The proof payout is final, but the proved recipient is a different account from the local
    /// broadcaster and must pull its own credit. This closes the local workflow without pretending
    /// that an unobserved recipient pull occurred.
    #[serde(default)]
    pub recipient_pull_delegated: bool,
    pub pull_broadcast: Option<BroadcastIntent>,
    #[serde(default)]
    pub pull_tx_hashes: Vec<Bytes32>,
    pub pull_confirmation: Option<PullConfirmation>,
}

impl PartialWithdrawalCandidate {
    pub fn is_complete(&self) -> bool {
        self.finalize_confirmation.is_some()
            && self.payout_confirmation.is_some()
            && (self.pull_confirmation.is_some() || self.recipient_pull_delegated)
    }
}

/// The four on-chain facts needed to resume a partial withdrawal without accidentally calling
/// `finalizePartialWithdrawal` after its one-shot IPW2 authorization has already been consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartialWithdrawalOnchainState {
    pub manager_pending: bool,
    pub pending_auth_digest: Bytes32,
    pub authorization: bool,
    pub nullifier_used: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartialWithdrawalResumeAction {
    FinalizePending,
    BroadcastPayout,
    ReconcilePayout,
    ContinueAfterPayout,
}

/// Decide the only safe next irreversible action from the durable journal and live L1 state.
///
/// `authorization == false && nullifier_used == true` is the normal post-payout state under IPW2,
/// not evidence that finalization is missing. Conversely, an already-used nullifier without a
/// pre-broadcast journal cannot be adopted: the operator would have no pinned caller/nonce/calldata
/// from which to prove that the observed state transition belongs to this candidate.
pub fn partial_withdrawal_resume_action(
    candidate: &PartialWithdrawalCandidate,
    state: PartialWithdrawalOnchainState,
) -> Result<PartialWithdrawalResumeAction, PartialWithdrawalPayoutError> {
    if state.authorization && state.nullifier_used {
        return Err(PartialWithdrawalPayoutError::Conflict(
            "IPW2 authorization is still live after the withdrawal nullifier was consumed".into(),
        ));
    }

    // An authorization is not self-authenticating local recovery evidence.  Before payout, the
    // exact manager call must have a send-before-persisted intent and a canonical finalized
    // receipt.  If a broadcast was recorded, FinalizePending means reconcile that exact nonce;
    // it never means blindly send a second transaction.
    if candidate.finalize_confirmation.is_none() {
        if candidate.payout_broadcast.is_some() || candidate.payout_confirmation.is_some() {
            return Err(PartialWithdrawalPayoutError::Conflict(
                "payout began without a finalized manager-finalization receipt".into(),
            ));
        }
        if state.manager_pending {
            if state.pending_auth_digest != candidate.auth_digest {
                return Err(PartialWithdrawalPayoutError::Conflict(
                    "settlement manager is pending a different partial-withdrawal authorization"
                        .into(),
                ));
            }
            return Ok(PartialWithdrawalResumeAction::FinalizePending);
        }
        if state.authorization && candidate.finalize_broadcast.is_some() {
            return Ok(PartialWithdrawalResumeAction::FinalizePending);
        }
        return Err(PartialWithdrawalPayoutError::Conflict(
            if state.authorization {
                "one-shot authorization exists without a durable manager-finalization intent"
            } else if state.nullifier_used {
                "withdrawal nullifier is used without a finalized manager-finalization receipt"
            } else {
                "partial withdrawal is neither manager-pending, authorized, nor already paid"
            }
            .into(),
        ));
    }

    if candidate.payout_confirmation.is_some() {
        if !state.nullifier_used || state.authorization {
            return Err(PartialWithdrawalPayoutError::Conflict(
                "stored payout confirmation disagrees with one-shot authorization/nullifier state"
                    .into(),
            ));
        }
        return Ok(PartialWithdrawalResumeAction::ContinueAfterPayout);
    }

    if state.nullifier_used {
        if candidate.payout_broadcast.is_none() {
            return Err(PartialWithdrawalPayoutError::Conflict(
                "withdrawal nullifier is used but no durable payout broadcast intent exists".into(),
            ));
        }
        return Ok(PartialWithdrawalResumeAction::ReconcilePayout);
    }

    if state.authorization {
        return Ok(if candidate.payout_broadcast.is_some() {
            PartialWithdrawalResumeAction::ReconcilePayout
        } else {
            PartialWithdrawalResumeAction::BroadcastPayout
        });
    }

    if candidate.payout_broadcast.is_some() {
        return Err(PartialWithdrawalPayoutError::Conflict(
            "payout was journaled for broadcast, but neither authorization nor used nullifier is present"
                .into(),
        ));
    }
    Err(PartialWithdrawalPayoutError::Conflict(
        "partial withdrawal is neither authorized nor already paid".into(),
    ))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PayoutSnapshot {
    version: u32,
    active: Option<PartialWithdrawalCandidate>,
    completed_nullifiers: Vec<Bytes32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CandidateIdentity<'a> {
    chain_id: u64,
    rollup: Address,
    manager: Address,
    channel_id: ChannelId,
    signed_head_digest: Bytes32,
    burn_base_nonce: u32,
    producer_receipt: &'a BlockProducerReceipt,
    auth_digest: Bytes32,
    withdrawal: &'a Withdrawal,
    withdrawal_prover: Address,
    producer_anchor: &'a BlockProducerAnchor,
    payout_json_digest: Bytes32,
    mle_json_digest: Bytes32,
}

pub struct PartialWithdrawalPayoutStore {
    path: PathBuf,
    _lock: SnapshotLock,
    disk: PayoutSnapshot,
    poisoned: bool,
}

impl PartialWithdrawalPayoutStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PartialWithdrawalPayoutError> {
        let path = prepare_path(path.as_ref())?;
        let lock = SnapshotLock::acquire(&path)?;
        let disk = if path.exists() {
            verify_private_mode(&path, "payout snapshot")?;
            read_snapshot(&path)?
        } else {
            let disk = PayoutSnapshot {
                version: PARTIAL_WITHDRAWAL_PAYOUT_VERSION,
                active: None,
                completed_nullifiers: Vec::new(),
            };
            persist_snapshot(&path, &disk)?;
            disk
        };
        verify_disk(&disk)?;
        Ok(Self {
            path,
            _lock: lock,
            disk,
            poisoned: false,
        })
    }

    pub fn active(
        &self,
    ) -> Result<Option<PartialWithdrawalCandidate>, PartialWithdrawalPayoutError> {
        self.ensure_healthy()?;
        Ok(self.disk.active.clone())
    }

    pub fn prepare(
        &mut self,
        request: PreparePartialWithdrawalPayout,
    ) -> Result<PartialWithdrawalCandidate, PartialWithdrawalPayoutError> {
        self.ensure_healthy()?;
        validate_prepare(&request)?;
        let candidate_id = candidate_id(&request)?;
        if let Some(active) = &self.disk.active {
            if active.candidate_id == candidate_id {
                return Ok(active.clone());
            }
            if !active.is_complete() {
                return Err(PartialWithdrawalPayoutError::Conflict(format!(
                    "candidate {} is still in flight; refusing replacement with {}",
                    active.candidate_id, candidate_id
                )));
            }
        }
        if self
            .disk
            .completed_nullifiers
            .contains(&request.artifacts.withdrawal.nullifier)
        {
            return Err(PartialWithdrawalPayoutError::Conflict(format!(
                "withdrawal nullifier {} already completed in this journal",
                request.artifacts.withdrawal.nullifier
            )));
        }
        let lane = lane_for(&request.artifacts.withdrawal);
        let candidate = PartialWithdrawalCandidate {
            candidate_id,
            chain_id: request.chain_id,
            rollup: request.rollup,
            manager: request.manager,
            channel_id: request.channel_id,
            signed_head_digest: request.signed_head_digest,
            burn_base_nonce: request.burn_base_nonce,
            producer_receipt: request.producer_receipt,
            auth_digest: request.auth_digest,
            lane,
            artifacts: request.artifacts,
            finalize_broadcast: None,
            finalize_tx_hashes: Vec::new(),
            finalize_confirmation: None,
            payout_broadcast: None,
            payout_tx_hashes: Vec::new(),
            payout_confirmation: None,
            recipient_pull_delegated: false,
            pull_broadcast: None,
            pull_tx_hashes: Vec::new(),
            pull_confirmation: None,
        };
        let mut disk = self.disk.clone();
        disk.active = Some(candidate.clone());
        self.commit(disk)?;
        Ok(candidate)
    }

    /// Persist the exact manager-finalization call before sending it.  This is intentionally a
    /// distinct phase from the proof payout: the one-shot authorization may be visible at `latest`
    /// while the creating receipt is not yet finalized and therefore must not authorize funds.
    pub fn mark_finalize_broadcast(
        &mut self,
        candidate_id: Bytes32,
        intent: BroadcastIntent,
    ) -> Result<PartialWithdrawalCandidate, PartialWithdrawalPayoutError> {
        self.mutate_candidate(candidate_id, |candidate| {
            if candidate.finalize_confirmation.is_some() {
                return Ok(());
            }
            if candidate.payout_broadcast.is_some() || candidate.payout_confirmation.is_some() {
                return Err(PartialWithdrawalPayoutError::Conflict(
                    "cannot begin manager finalization after the proof payout began".into(),
                ));
            }
            if intent.caller == Address::default()
                || intent.calldata_hash == Bytes32::default()
                || intent.credit_before != U256::default()
            {
                return Err(PartialWithdrawalPayoutError::InvalidRequest(
                    "manager-finalization intent requires a non-zero caller/calldata and zero credit"
                        .into(),
                ));
            }
            match &candidate.finalize_broadcast {
                Some(existing) if existing != &intent => {
                    Err(PartialWithdrawalPayoutError::Conflict(
                        "manager finalization already began with a different caller/block/nonce"
                            .into(),
                    ))
                }
                Some(_) => Ok(()),
                None => {
                    candidate.finalize_broadcast = Some(intent);
                    Ok(())
                }
            }
        })
    }

    pub fn record_finalize_tx_hash(
        &mut self,
        candidate_id: Bytes32,
        tx_hash: Bytes32,
    ) -> Result<PartialWithdrawalCandidate, PartialWithdrawalPayoutError> {
        self.mutate_candidate(candidate_id, |candidate| {
            if candidate.finalize_broadcast.is_none() {
                return Err(PartialWithdrawalPayoutError::InvalidRequest(
                    "cannot record manager-finalization transaction before its broadcast intent"
                        .into(),
                ));
            }
            if let Some(confirmation) = &candidate.finalize_confirmation {
                if confirmation.receipt.tx_hash != tx_hash {
                    return Err(PartialWithdrawalPayoutError::Conflict(
                        "cannot append a replacement hash after manager-finalization confirmation"
                            .into(),
                    ));
                }
                return Ok(());
            }
            push_tx_hash(&mut candidate.finalize_tx_hashes, tx_hash)
        })
    }

    pub fn confirm_finalize(
        &mut self,
        candidate_id: Bytes32,
        confirmation: FinalizeConfirmation,
    ) -> Result<PartialWithdrawalCandidate, PartialWithdrawalPayoutError> {
        self.mutate_candidate(candidate_id, |candidate| {
            validate_finalize_confirmation(candidate, &confirmation)?;
            match &candidate.finalize_confirmation {
                Some(existing) if existing != &confirmation => {
                    Err(PartialWithdrawalPayoutError::Conflict(
                        "manager finalization was already confirmed by a different receipt".into(),
                    ))
                }
                Some(_) => Ok(()),
                None => {
                    push_tx_hash(
                        &mut candidate.finalize_tx_hashes,
                        confirmation.receipt.tx_hash,
                    )?;
                    candidate.finalize_confirmation = Some(confirmation);
                    Ok(())
                }
            }
        })
    }

    pub fn mark_payout_broadcast(
        &mut self,
        candidate_id: Bytes32,
        intent: BroadcastIntent,
    ) -> Result<PartialWithdrawalCandidate, PartialWithdrawalPayoutError> {
        self.mutate_candidate(candidate_id, |candidate| {
            if candidate.finalize_confirmation.is_none() {
                return Err(PartialWithdrawalPayoutError::InvalidRequest(
                    "cannot begin proof payout before manager finalization has a finalized receipt"
                        .into(),
                ));
            }
            if candidate.payout_confirmation.is_some() {
                return Ok(());
            }
            if intent.caller == Address::default() || intent.calldata_hash == Bytes32::default() {
                return Err(PartialWithdrawalPayoutError::InvalidRequest(
                    "payout broadcast caller must be non-zero".into(),
                ));
            }
            match &candidate.payout_broadcast {
                Some(existing) if existing != &intent => {
                    Err(PartialWithdrawalPayoutError::Conflict(
                        "payout broadcast already began with a different caller/block/nonce".into(),
                    ))
                }
                Some(_) => Ok(()),
                None => {
                    candidate.payout_broadcast = Some(intent);
                    Ok(())
                }
            }
        })
    }

    pub fn confirm_payout(
        &mut self,
        candidate_id: Bytes32,
        confirmation: PayoutConfirmation,
    ) -> Result<PartialWithdrawalCandidate, PartialWithdrawalPayoutError> {
        self.mutate_candidate(candidate_id, |candidate| {
            validate_payout_confirmation(candidate, &confirmation)?;
            match &candidate.payout_confirmation {
                Some(existing) if existing != &confirmation => {
                    Err(PartialWithdrawalPayoutError::Conflict(
                        "payout was already confirmed by a different receipt".into(),
                    ))
                }
                Some(_) => Ok(()),
                None => {
                    push_tx_hash(
                        &mut candidate.payout_tx_hashes,
                        confirmation.receipt.tx_hash,
                    )?;
                    candidate.payout_confirmation = Some(confirmation);
                    Ok(())
                }
            }
        })
    }

    /// Persist a node-accepted transaction hash immediately after `eth_sendRawTransaction`, before
    /// waiting for its receipt. A retry can query every recorded replacement or fall back to the
    /// pinned sender/nonce scan if the process died in the send-to-persist gap.
    pub fn record_payout_tx_hash(
        &mut self,
        candidate_id: Bytes32,
        tx_hash: Bytes32,
    ) -> Result<PartialWithdrawalCandidate, PartialWithdrawalPayoutError> {
        self.mutate_candidate(candidate_id, |candidate| {
            if candidate.payout_broadcast.is_none() {
                return Err(PartialWithdrawalPayoutError::InvalidRequest(
                    "cannot record a payout transaction before its broadcast intent".into(),
                ));
            }
            if let Some(confirmation) = &candidate.payout_confirmation {
                if confirmation.receipt.tx_hash != tx_hash {
                    return Err(PartialWithdrawalPayoutError::Conflict(
                        "cannot append a replacement hash after payout confirmation".into(),
                    ));
                }
                return Ok(());
            }
            push_tx_hash(&mut candidate.payout_tx_hashes, tx_hash)
        })
    }

    /// Finish the local workflow at the proof-payout boundary when the proved recipient is not the
    /// broadcaster. The credit remains on-chain for that recipient; no pull receipt is fabricated.
    pub fn mark_recipient_pull_delegated(
        &mut self,
        candidate_id: Bytes32,
    ) -> Result<PartialWithdrawalCandidate, PartialWithdrawalPayoutError> {
        self.mutate_candidate(candidate_id, |candidate| {
            if candidate.payout_confirmation.is_none() {
                return Err(PartialWithdrawalPayoutError::InvalidRequest(
                    "cannot hand off the recipient pull before payout confirmation".into(),
                ));
            }
            if candidate.pull_broadcast.is_some() || candidate.pull_confirmation.is_some() {
                return Err(PartialWithdrawalPayoutError::Conflict(
                    "cannot hand off a recipient pull that already began locally".into(),
                ));
            }
            candidate.recipient_pull_delegated = true;
            Ok(())
        })
    }

    pub fn mark_pull_broadcast(
        &mut self,
        candidate_id: Bytes32,
        intent: BroadcastIntent,
    ) -> Result<PartialWithdrawalCandidate, PartialWithdrawalPayoutError> {
        self.mutate_candidate(candidate_id, |candidate| {
            if candidate.recipient_pull_delegated {
                return Err(PartialWithdrawalPayoutError::Conflict(
                    "recipient pull was delegated to the external proved recipient".into(),
                ));
            }
            let payout = candidate.payout_confirmation.as_ref().ok_or_else(|| {
                PartialWithdrawalPayoutError::InvalidRequest(
                    "cannot pull before the proof payout has a successful receipt".into(),
                )
            })?;
            if candidate.pull_confirmation.is_some() {
                return Ok(());
            }
            if intent.caller != candidate.artifacts.withdrawal.recipient
                || intent.credit_before != payout.credit_after
            {
                return Err(PartialWithdrawalPayoutError::InvalidRequest(
                    "pull intent must pin the proved recipient and exact post-payout credit".into(),
                ));
            }
            match &candidate.pull_broadcast {
                Some(existing) if existing != &intent => {
                    Err(PartialWithdrawalPayoutError::Conflict(
                        "recipient pull already began with a different caller/block/nonce".into(),
                    ))
                }
                Some(_) => Ok(()),
                None => {
                    candidate.pull_broadcast = Some(intent);
                    Ok(())
                }
            }
        })
    }

    pub fn confirm_pull(
        &mut self,
        candidate_id: Bytes32,
        confirmation: PullConfirmation,
    ) -> Result<PartialWithdrawalCandidate, PartialWithdrawalPayoutError> {
        self.mutate_candidate(candidate_id, |candidate| {
            validate_pull_confirmation(candidate, &confirmation)?;
            match &candidate.pull_confirmation {
                Some(existing) if existing != &confirmation => {
                    Err(PartialWithdrawalPayoutError::Conflict(
                        "recipient pull was already confirmed by a different receipt".into(),
                    ))
                }
                Some(_) => Ok(()),
                None => {
                    push_tx_hash(&mut candidate.pull_tx_hashes, confirmation.receipt.tx_hash)?;
                    candidate.pull_confirmation = Some(confirmation);
                    Ok(())
                }
            }
        })
    }

    pub fn record_pull_tx_hash(
        &mut self,
        candidate_id: Bytes32,
        tx_hash: Bytes32,
    ) -> Result<PartialWithdrawalCandidate, PartialWithdrawalPayoutError> {
        self.mutate_candidate(candidate_id, |candidate| {
            if candidate.pull_broadcast.is_none() {
                return Err(PartialWithdrawalPayoutError::InvalidRequest(
                    "cannot record a pull transaction before its broadcast intent".into(),
                ));
            }
            if let Some(confirmation) = &candidate.pull_confirmation {
                if confirmation.receipt.tx_hash != tx_hash {
                    return Err(PartialWithdrawalPayoutError::Conflict(
                        "cannot append a replacement hash after pull confirmation".into(),
                    ));
                }
                return Ok(());
            }
            push_tx_hash(&mut candidate.pull_tx_hashes, tx_hash)
        })
    }

    fn mutate_candidate(
        &mut self,
        candidate_id: Bytes32,
        update: impl FnOnce(&mut PartialWithdrawalCandidate) -> Result<(), PartialWithdrawalPayoutError>,
    ) -> Result<PartialWithdrawalCandidate, PartialWithdrawalPayoutError> {
        self.ensure_healthy()?;
        let mut disk = self.disk.clone();
        let candidate = disk.active.as_mut().ok_or_else(|| {
            PartialWithdrawalPayoutError::InvalidRequest("no prepared payout candidate".into())
        })?;
        if candidate.candidate_id != candidate_id {
            return Err(PartialWithdrawalPayoutError::Conflict(format!(
                "candidate id {} does not match active {}",
                candidate_id, candidate.candidate_id
            )));
        }
        update(candidate)?;
        let result = candidate.clone();
        if result.is_complete()
            && !disk
                .completed_nullifiers
                .contains(&result.artifacts.withdrawal.nullifier)
        {
            disk.completed_nullifiers
                .push(result.artifacts.withdrawal.nullifier);
        }
        self.commit(disk)?;
        Ok(result)
    }

    fn commit(&mut self, disk: PayoutSnapshot) -> Result<(), PartialWithdrawalPayoutError> {
        verify_disk(&disk)?;
        if let Err(error) = persist_snapshot(&self.path, &disk) {
            self.poisoned = true;
            return Err(error);
        }
        self.disk = disk;
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<(), PartialWithdrawalPayoutError> {
        if self.poisoned {
            Err(PartialWithdrawalPayoutError::Poisoned)
        } else {
            Ok(())
        }
    }
}

fn lane_for(withdrawal: &Withdrawal) -> PartialWithdrawalLane {
    if withdrawal.token_index == 0 {
        PartialWithdrawalLane::Native
    } else {
        PartialWithdrawalLane::Erc20
    }
}

fn validate_prepare(
    request: &PreparePartialWithdrawalPayout,
) -> Result<(), PartialWithdrawalPayoutError> {
    let withdrawal = &request.artifacts.withdrawal;
    if request.chain_id == 0
        || request.rollup == Address::default()
        || request.manager == Address::default()
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "chain id, rollup and settlement manager must be non-zero".into(),
        ));
    }
    if withdrawal.recipient == Address::default()
        || withdrawal.amount == U256::default()
        || withdrawal.aux_data == Bytes32::default()
        || request.artifacts.withdrawal_prover == Address::default()
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "a partial-withdrawal proof must commit a non-zero recipient, amount and auxData"
                .into(),
        ));
    }
    if request.signed_head_digest == Bytes32::default()
        || request.producer_receipt.request_id.trim().is_empty()
        || request.producer_receipt.entry_hash == Bytes32::default()
        || request.producer_receipt.extended_state_commitment == Bytes32::default()
        || request.artifacts.producer_anchor.entry_hash == Bytes32::default()
        || request.artifacts.producer_anchor.extended_state_commitment == Bytes32::default()
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "signed head, exact producer receipt and proof anchor must all be non-zero".into(),
        ));
    }
    let derived_auth = partial_withdrawal_auth_digest(withdrawal);
    if derived_auth != request.auth_digest {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(format!(
            "auth digest {} differs from proof-committed withdrawal digest {}",
            request.auth_digest, derived_auth
        )));
    }
    if request.producer_receipt.generation > request.artifacts.producer_anchor.generation
        || request.producer_receipt.block_number > request.artifacts.producer_anchor.block_number
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "withdrawal proof anchor predates its burn producer receipt".into(),
        ));
    }
    validate_payout_json(&request.artifacts)?;
    let mle: serde_json::Value = serde_json::from_str(&request.artifacts.withdrawal_mle_json)
        .map_err(|e| {
            PartialWithdrawalPayoutError::InvalidRequest(format!("invalid MLE JSON: {e}"))
        })?;
    if !mle.is_object() || request.artifacts.withdrawal_mle_json.is_empty() {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "withdrawal MLE artefact is empty or not an object".into(),
        ));
    }
    if request.artifacts.metrics.mle_json_bytes != request.artifacts.withdrawal_mle_json.len() {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "reported MLE byte size differs from the exact artefact".into(),
        ));
    }
    if request.artifacts.metrics.single_withdrawal_proof_bytes == 0
        || request.artifacts.metrics.withdrawal_chain_proof_bytes == 0
        || request.artifacts.metrics.withdrawal_final_proof_bytes == 0
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "live prover reported an empty withdrawal proof stage".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct PayoutJson {
    withdrawals: Vec<PayoutJsonWithdrawal>,
    withdrawal_prover: Address,
    block_number: u64,
    ext_commitment: Bytes32,
}

#[derive(Deserialize)]
struct PayoutJsonWithdrawal {
    recipient: Address,
    token_index: u32,
    amount: U256,
    nullifier: Bytes32,
    aux_data: Bytes32,
}

fn validate_payout_json(
    artifacts: &PartialWithdrawalProofArtifacts,
) -> Result<(), PartialWithdrawalPayoutError> {
    let payout: PayoutJson = serde_json::from_str(&artifacts.payout_json).map_err(|e| {
        PartialWithdrawalPayoutError::InvalidRequest(format!("invalid payout JSON: {e}"))
    })?;
    if payout.withdrawals.len() != 1 {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "partial-withdrawal payout must contain exactly one proof-committed leaf".into(),
        ));
    }
    let encoded = &payout.withdrawals[0];
    let proved = &artifacts.withdrawal;
    if encoded.recipient != proved.recipient
        || encoded.token_index != proved.token_index
        || encoded.amount != proved.amount
        || encoded.nullifier != proved.nullifier
        || encoded.aux_data != proved.aux_data
        || payout.withdrawal_prover != artifacts.withdrawal_prover
        || payout.block_number != artifacts.producer_anchor.block_number
        || payout.ext_commitment != artifacts.producer_anchor.extended_state_commitment
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "payout JSON differs from proof public inputs or producer anchor".into(),
        ));
    }
    Ok(())
}

fn candidate_id(
    request: &PreparePartialWithdrawalPayout,
) -> Result<Bytes32, PartialWithdrawalPayoutError> {
    let identity = CandidateIdentity {
        chain_id: request.chain_id,
        rollup: request.rollup,
        manager: request.manager,
        channel_id: request.channel_id,
        signed_head_digest: request.signed_head_digest,
        burn_base_nonce: request.burn_base_nonce,
        producer_receipt: &request.producer_receipt,
        auth_digest: request.auth_digest,
        withdrawal: &request.artifacts.withdrawal,
        withdrawal_prover: request.artifacts.withdrawal_prover,
        producer_anchor: &request.artifacts.producer_anchor,
        payout_json_digest: hash_bytes(request.artifacts.payout_json.as_bytes())?,
        mle_json_digest: hash_bytes(request.artifacts.withdrawal_mle_json.as_bytes())?,
    };
    let bytes = serde_json::to_vec(&identity).map_err(|e| {
        PartialWithdrawalPayoutError::InvalidRequest(format!("serialize candidate identity: {e}"))
    })?;
    hash_bytes(&bytes)
}

fn expected_payout_kind(lane: PartialWithdrawalLane) -> L1CallKind {
    match lane {
        PartialWithdrawalLane::Native => L1CallKind::WithdrawNative,
        PartialWithdrawalLane::Erc20 => L1CallKind::WithdrawErc20,
    }
}

fn expected_pull_kind(lane: PartialWithdrawalLane) -> L1CallKind {
    match lane {
        PartialWithdrawalLane::Native => L1CallKind::PullNative,
        PartialWithdrawalLane::Erc20 => L1CallKind::PullErc20,
    }
}

const MAX_REPLACEMENT_TX_HASHES: usize = 16;

fn push_tx_hash(
    hashes: &mut Vec<Bytes32>,
    tx_hash: Bytes32,
) -> Result<(), PartialWithdrawalPayoutError> {
    if tx_hash == Bytes32::default() {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "transaction hash must be non-zero".into(),
        ));
    }
    if hashes.contains(&tx_hash) {
        return Ok(());
    }
    if hashes.len() >= MAX_REPLACEMENT_TX_HASHES {
        return Err(PartialWithdrawalPayoutError::Conflict(
            "too many replacement transaction hashes for one broadcast intent".into(),
        ));
    }
    hashes.push(tx_hash);
    Ok(())
}

fn validate_finalize_confirmation(
    candidate: &PartialWithdrawalCandidate,
    confirmation: &FinalizeConfirmation,
) -> Result<(), PartialWithdrawalPayoutError> {
    let intent = candidate.finalize_broadcast.as_ref().ok_or_else(|| {
        PartialWithdrawalPayoutError::InvalidRequest(
            "persist a manager-finalization broadcast intent before accepting its receipt".into(),
        )
    })?;
    let receipt = &confirmation.receipt;
    receipt
        .finalized_checkpoint
        .covers_receipt(receipt.block_number, receipt.block_hash)
        .map_err(|error| PartialWithdrawalPayoutError::InvalidRequest(format!(
            "manager-finalization receipt is not covered by a durable L1 checkpoint: {error}"
        )))?;
    if receipt.tx_hash == Bytes32::default()
        || receipt.block_hash == Bytes32::default()
        || !receipt.success
        || receipt.chain_id != candidate.chain_id
        || receipt.finalized_checkpoint.chain_id != candidate.chain_id
        || receipt.from != intent.caller
        || receipt.to != candidate.manager
        || receipt.block_number < intent.start_block
        || receipt.transaction_nonce != intent.caller_nonce
        || receipt.calldata_hash != intent.calldata_hash
        || receipt.call_kind != L1CallKind::FinalizePartialWithdrawal
        || receipt.manager_finalized_auth_digest != Some(candidate.auth_digest)
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "manager-finalization receipt failed or targets the wrong chain/manager/function/auth digest"
                .into(),
        ));
    }
    if confirmation.manager_pending_observed
        || !confirmation.authorization_observed
        || confirmation.nullifier_used_observed
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "manager finalization must clear pending state, create this authorization and leave the nullifier unused"
                .into(),
        ));
    }
    Ok(())
}

fn validate_payout_confirmation(
    candidate: &PartialWithdrawalCandidate,
    confirmation: &PayoutConfirmation,
) -> Result<(), PartialWithdrawalPayoutError> {
    let receipt = &confirmation.receipt;
    let intent = candidate.payout_broadcast.as_ref().ok_or_else(|| {
        PartialWithdrawalPayoutError::InvalidRequest(
            "persist a payout broadcast intent before accepting its receipt".into(),
        )
    })?;
    if confirmation.credit_before != intent.credit_before {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "payout confirmation substituted a different pre-broadcast credit".into(),
        ));
    }
    receipt
        .finalized_checkpoint
        .covers_receipt(receipt.block_number, receipt.block_hash)
        .map_err(|error| PartialWithdrawalPayoutError::InvalidRequest(format!(
            "payout receipt is not covered by a durable L1 checkpoint: {error}"
        )))?;
    if receipt.tx_hash == Bytes32::default()
        || receipt.block_hash == Bytes32::default()
        || !receipt.success
        || receipt.chain_id != candidate.chain_id
        || receipt.finalized_checkpoint.chain_id != candidate.chain_id
        || receipt.from != intent.caller
        || receipt.to != candidate.rollup
        || receipt.block_number < intent.start_block
        || receipt.transaction_nonce != intent.caller_nonce
        || receipt.calldata_hash != intent.calldata_hash
        || receipt.call_kind != expected_payout_kind(candidate.lane)
        || receipt.manager_finalized_auth_digest.is_some()
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "payout receipt failed or targets the wrong chain/rollup/function".into(),
        ));
    }
    if confirmation.authorization_observed
        || !confirmation.finalized_anchor_observed
        || !confirmation.nullifier_used_observed
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "successful payout must consume authorization, retain the finalized anchor, and use the nullifier"
                .into(),
        ));
    }
    if confirmation.credit_after < confirmation.credit_before
        || confirmation.credit_after - confirmation.credit_before
            != candidate.artifacts.withdrawal.amount
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "on-chain recipient credit did not increase by the proof-committed amount".into(),
        ));
    }
    Ok(())
}

fn validate_pull_confirmation(
    candidate: &PartialWithdrawalCandidate,
    confirmation: &PullConfirmation,
) -> Result<(), PartialWithdrawalPayoutError> {
    let payout = candidate.payout_confirmation.as_ref().ok_or_else(|| {
        PartialWithdrawalPayoutError::InvalidRequest(
            "proof payout must precede pull confirmation".into(),
        )
    })?;
    let intent = candidate.pull_broadcast.as_ref().ok_or_else(|| {
        PartialWithdrawalPayoutError::InvalidRequest(
            "pull broadcast must precede pull confirmation".into(),
        )
    })?;
    if intent.caller != candidate.artifacts.withdrawal.recipient
        || confirmation.credit_before != intent.credit_before
        || intent.credit_before != payout.credit_after
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "recipient or pre-broadcast credit changed across the durable pull boundary".into(),
        ));
    }
    let receipt = &confirmation.receipt;
    receipt
        .finalized_checkpoint
        .covers_receipt(receipt.block_number, receipt.block_hash)
        .map_err(|error| PartialWithdrawalPayoutError::InvalidRequest(format!(
            "pull receipt is not covered by a durable L1 checkpoint: {error}"
        )))?;
    if receipt.tx_hash == Bytes32::default()
        || receipt.block_hash == Bytes32::default()
        || !receipt.success
        || receipt.chain_id != candidate.chain_id
        || receipt.finalized_checkpoint.chain_id != candidate.chain_id
        || receipt.to != candidate.rollup
        || receipt.from != candidate.artifacts.withdrawal.recipient
        || receipt.from != intent.caller
        || receipt.block_number < intent.start_block
        || receipt.transaction_nonce != intent.caller_nonce
        || receipt.calldata_hash != intent.calldata_hash
        || receipt.call_kind != expected_pull_kind(candidate.lane)
        || receipt.manager_finalized_auth_digest.is_some()
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "pull receipt failed or targets the wrong chain/rollup/caller/function".into(),
        ));
    }
    if confirmation.credit_before < candidate.artifacts.withdrawal.amount
        || confirmation.credit_after != U256::default()
    {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "recipient pull did not consume the on-chain credit".into(),
        ));
    }
    Ok(())
}

fn verify_disk(disk: &PayoutSnapshot) -> Result<(), PartialWithdrawalPayoutError> {
    if disk.version != PARTIAL_WITHDRAWAL_PAYOUT_VERSION {
        return Err(PartialWithdrawalPayoutError::Snapshot(format!(
            "unsupported version {}",
            disk.version
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for nullifier in &disk.completed_nullifiers {
        if !seen.insert(*nullifier) {
            return Err(PartialWithdrawalPayoutError::Snapshot(
                "completed nullifier ledger contains a duplicate".into(),
            ));
        }
    }
    if let Some(active) = &disk.active {
        let request = PreparePartialWithdrawalPayout {
            chain_id: active.chain_id,
            rollup: active.rollup,
            manager: active.manager,
            channel_id: active.channel_id,
            signed_head_digest: active.signed_head_digest,
            burn_base_nonce: active.burn_base_nonce,
            producer_receipt: active.producer_receipt.clone(),
            auth_digest: active.auth_digest,
            artifacts: active.artifacts.clone(),
        };
        validate_prepare(&request).map_err(|e| {
            PartialWithdrawalPayoutError::Snapshot(format!(
                "active candidate no longer validates: {e}"
            ))
        })?;
        let expected_id = candidate_id(&request).map_err(|e| {
            PartialWithdrawalPayoutError::Snapshot(format!(
                "active candidate identity cannot be recomputed: {e}"
            ))
        })?;
        if active.candidate_id != expected_id
            || active.lane != lane_for(&active.artifacts.withdrawal)
        {
            return Err(PartialWithdrawalPayoutError::Snapshot(
                "active candidate id or asset lane differs from its proof artefacts".into(),
            ));
        }
        if active.finalize_confirmation.is_some() && active.finalize_broadcast.is_none() {
            return Err(PartialWithdrawalPayoutError::Snapshot(
                "snapshot confirms manager finalization without its broadcast intent".into(),
            ));
        }
        verify_tx_hashes(
            &active.finalize_tx_hashes,
            active.finalize_broadcast.is_some(),
            "manager-finalization",
        )?;
        if active.finalize_broadcast.as_ref().is_some_and(|intent| {
            intent.caller == Address::default()
                || intent.calldata_hash == Bytes32::default()
                || intent.credit_before != U256::default()
        }) {
            return Err(PartialWithdrawalPayoutError::Snapshot(
                "snapshot contains an invalid manager-finalization intent".into(),
            ));
        }
        if (active.payout_broadcast.is_some() || active.payout_confirmation.is_some())
            && active.finalize_confirmation.is_none()
        {
            return Err(PartialWithdrawalPayoutError::Snapshot(
                "snapshot begins a proof payout without finalized manager authorization evidence"
                    .into(),
            ));
        }
        if active.payout_confirmation.is_some() && active.payout_broadcast.is_none() {
            return Err(PartialWithdrawalPayoutError::Snapshot(
                "snapshot confirms a proof payout without its broadcast intent".into(),
            ));
        }
        verify_tx_hashes(
            &active.payout_tx_hashes,
            active.payout_broadcast.is_some(),
            "payout",
        )?;
        if active.payout_broadcast.as_ref().is_some_and(|intent| {
            intent.caller == Address::default() || intent.calldata_hash == Bytes32::default()
        }) {
            return Err(PartialWithdrawalPayoutError::Snapshot(
                "snapshot contains a zero payout caller".into(),
            ));
        }
        if active.pull_broadcast.is_some() && active.payout_confirmation.is_none() {
            return Err(PartialWithdrawalPayoutError::Snapshot(
                "snapshot begins a recipient pull before confirming its proof payout".into(),
            ));
        }
        if active.recipient_pull_delegated
            && (active.payout_confirmation.is_none()
                || active.pull_broadcast.is_some()
                || active.pull_confirmation.is_some())
        {
            return Err(PartialWithdrawalPayoutError::Snapshot(
                "external recipient handoff lacks payout confirmation or overlaps a local pull"
                    .into(),
            ));
        }
        if active.pull_confirmation.is_some() && active.pull_broadcast.is_none() {
            return Err(PartialWithdrawalPayoutError::Snapshot(
                "snapshot confirms a recipient pull without its broadcast intent".into(),
            ));
        }
        verify_tx_hashes(
            &active.pull_tx_hashes,
            active.pull_broadcast.is_some(),
            "pull",
        )?;
        if let Some(intent) = &active.pull_broadcast {
            let payout = active.payout_confirmation.as_ref().ok_or_else(|| {
                PartialWithdrawalPayoutError::Snapshot(
                    "snapshot begins a pull without a payout confirmation".into(),
                )
            })?;
            if intent.caller != active.artifacts.withdrawal.recipient
                || intent.calldata_hash == Bytes32::default()
                || intent.credit_before != payout.credit_after
            {
                return Err(PartialWithdrawalPayoutError::Snapshot(
                    "stored pull intent substituted its recipient or pre-broadcast credit".into(),
                ));
            }
        }
        if let Some(confirmation) = &active.payout_confirmation {
            if !active
                .payout_tx_hashes
                .contains(&confirmation.receipt.tx_hash)
            {
                return Err(PartialWithdrawalPayoutError::Snapshot(
                    "payout confirmation receipt is absent from its transaction-hash journal"
                        .into(),
                ));
            }
            validate_payout_confirmation(active, confirmation).map_err(|e| {
                PartialWithdrawalPayoutError::Snapshot(format!(
                    "stored payout confirmation is invalid: {e}"
                ))
            })?;
        }
        if let Some(confirmation) = &active.finalize_confirmation {
            if !active
                .finalize_tx_hashes
                .contains(&confirmation.receipt.tx_hash)
            {
                return Err(PartialWithdrawalPayoutError::Snapshot(
                    "manager-finalization receipt is absent from its transaction-hash journal"
                        .into(),
                ));
            }
            validate_finalize_confirmation(active, confirmation).map_err(|e| {
                PartialWithdrawalPayoutError::Snapshot(format!(
                    "stored manager-finalization confirmation is invalid: {e}"
                ))
            })?;
        }
        if let Some(confirmation) = &active.pull_confirmation {
            if !active
                .pull_tx_hashes
                .contains(&confirmation.receipt.tx_hash)
            {
                return Err(PartialWithdrawalPayoutError::Snapshot(
                    "pull confirmation receipt is absent from its transaction-hash journal".into(),
                ));
            }
            validate_pull_confirmation(active, confirmation).map_err(|e| {
                PartialWithdrawalPayoutError::Snapshot(format!(
                    "stored pull confirmation is invalid: {e}"
                ))
            })?;
        }
        if active.is_complete() && !seen.contains(&active.artifacts.withdrawal.nullifier) {
            return Err(PartialWithdrawalPayoutError::Snapshot(
                "complete active payout is absent from the completed-nullifier ledger".into(),
            ));
        }
        if active.pull_confirmation.is_some() && active.payout_confirmation.is_none() {
            return Err(PartialWithdrawalPayoutError::Snapshot(
                "snapshot confirms a pull without a proof payout".into(),
            ));
        }
    }
    Ok(())
}

fn verify_tx_hashes(
    hashes: &[Bytes32],
    has_intent: bool,
    phase: &str,
) -> Result<(), PartialWithdrawalPayoutError> {
    if !hashes.is_empty() && !has_intent {
        return Err(PartialWithdrawalPayoutError::Snapshot(format!(
            "snapshot records a {phase} transaction without its broadcast intent"
        )));
    }
    if hashes.len() > MAX_REPLACEMENT_TX_HASHES {
        return Err(PartialWithdrawalPayoutError::Snapshot(format!(
            "snapshot contains too many {phase} replacement transactions"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    if hashes
        .iter()
        .any(|hash| *hash == Bytes32::default() || !seen.insert(*hash))
    {
        return Err(PartialWithdrawalPayoutError::Snapshot(format!(
            "snapshot contains a zero or duplicate {phase} transaction hash"
        )));
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> Result<Bytes32, PartialWithdrawalPayoutError> {
    Bytes32::from_bytes_be(&keccak_hash::keccak(bytes).0).map_err(|e| {
        PartialWithdrawalPayoutError::InvalidRequest(format!("convert keccak digest: {e}"))
    })
}

fn prepare_path(path: &Path) -> Result<PathBuf, PartialWithdrawalPayoutError> {
    if path.file_name().is_none() {
        return Err(PartialWithdrawalPayoutError::InvalidRequest(
            "payout snapshot path must name a file".into(),
        ));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|e| {
        PartialWithdrawalPayoutError::Snapshot(format!("create {}: {e}", parent.display()))
    })?;
    reject_symlink(path, "payout snapshot")?;
    Ok(path.to_path_buf())
}

fn reject_symlink(path: &Path, what: &str) -> Result<(), PartialWithdrawalPayoutError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(PartialWithdrawalPayoutError::Snapshot(
            format!("{what} {} is a symlink", path.display()),
        )),
        Ok(meta) if !meta.is_file() => Err(PartialWithdrawalPayoutError::Snapshot(format!(
            "{what} {} is not a regular file",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(PartialWithdrawalPayoutError::Snapshot(format!(
            "inspect {what} {}: {e}",
            path.display()
        ))),
    }
}

fn verify_private_mode(path: &Path, what: &str) -> Result<(), PartialWithdrawalPayoutError> {
    reject_symlink(path, what)?;
    let mode = fs::metadata(path)
        .map_err(|e| {
            PartialWithdrawalPayoutError::Snapshot(format!("stat {}: {e}", path.display()))
        })?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(PartialWithdrawalPayoutError::Snapshot(format!(
            "{what} {} must have mode 0600",
            path.display()
        )));
    }
    Ok(())
}

fn read_snapshot(path: &Path) -> Result<PayoutSnapshot, PartialWithdrawalPayoutError> {
    let mut file = File::open(path).map_err(|e| {
        PartialWithdrawalPayoutError::Snapshot(format!("open {}: {e}", path.display()))
    })?;
    let len = file
        .metadata()
        .map_err(|e| {
            PartialWithdrawalPayoutError::Snapshot(format!("stat {}: {e}", path.display()))
        })?
        .len();
    if len < HEADER_BYTES as u64 || len > MAX_SNAPSHOT_BYTES {
        return Err(PartialWithdrawalPayoutError::Snapshot(format!(
            "snapshot size {len} is outside {HEADER_BYTES}..={MAX_SNAPSHOT_BYTES}"
        )));
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.read_to_end(&mut bytes).map_err(|e| {
        PartialWithdrawalPayoutError::Snapshot(format!("read {}: {e}", path.display()))
    })?;
    if &bytes[..16] != SNAPSHOT_MAGIC {
        return Err(PartialWithdrawalPayoutError::Snapshot(
            "bad snapshot magic".into(),
        ));
    }
    let version = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    if version != PARTIAL_WITHDRAWAL_PAYOUT_VERSION {
        return Err(PartialWithdrawalPayoutError::Snapshot(format!(
            "unsupported snapshot version {version}"
        )));
    }
    let payload_len = u64::from_le_bytes(bytes[20..28].try_into().unwrap()) as usize;
    if payload_len != bytes.len() - HEADER_BYTES {
        return Err(PartialWithdrawalPayoutError::Snapshot(
            "snapshot payload length mismatch".into(),
        ));
    }
    let payload = &bytes[HEADER_BYTES..];
    if keccak_hash::keccak(payload).0.as_slice() != &bytes[28..60] {
        return Err(PartialWithdrawalPayoutError::Snapshot(
            "snapshot checksum mismatch".into(),
        ));
    }
    serde_json::from_slice(payload).map_err(|e| {
        PartialWithdrawalPayoutError::Snapshot(format!("decode snapshot payload: {e}"))
    })
}

fn persist_snapshot(
    path: &Path,
    disk: &PayoutSnapshot,
) -> Result<(), PartialWithdrawalPayoutError> {
    let payload = serde_json::to_vec(disk).map_err(|e| {
        PartialWithdrawalPayoutError::Snapshot(format!("encode payout snapshot: {e}"))
    })?;
    if payload.len() as u64 + HEADER_BYTES as u64 > MAX_SNAPSHOT_BYTES {
        return Err(PartialWithdrawalPayoutError::Snapshot(
            "payout snapshot exceeds maximum size".into(),
        ));
    }
    let mut encoded = Vec::with_capacity(HEADER_BYTES + payload.len());
    encoded.extend_from_slice(SNAPSHOT_MAGIC);
    encoded.extend_from_slice(&PARTIAL_WITHDRAWAL_PAYOUT_VERSION.to_le_bytes());
    encoded.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    encoded.extend_from_slice(&keccak_hash::keccak(&payload).0);
    encoded.extend_from_slice(&payload);

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        PartialWithdrawalPayoutError::Snapshot("snapshot filename is not UTF-8".into())
    })?;
    let temp = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    if temp.exists() {
        reject_symlink(&temp, "stale payout temp")?;
        fs::remove_file(&temp).map_err(|e| {
            PartialWithdrawalPayoutError::Snapshot(format!("remove {}: {e}", temp.display()))
        })?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| {
            PartialWithdrawalPayoutError::Snapshot(format!("create {}: {e}", temp.display()))
        })?;
    file.write_all(&encoded).map_err(|e| {
        PartialWithdrawalPayoutError::Snapshot(format!("write {}: {e}", temp.display()))
    })?;
    file.sync_all().map_err(|e| {
        PartialWithdrawalPayoutError::Snapshot(format!("fsync {}: {e}", temp.display()))
    })?;
    drop(file);
    fs::rename(&temp, path).map_err(|e| {
        PartialWithdrawalPayoutError::Snapshot(format!(
            "atomic replace {} -> {}: {e}",
            temp.display(),
            path.display()
        ))
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
        PartialWithdrawalPayoutError::Snapshot(format!("chmod {}: {e}", path.display()))
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| {
            PartialWithdrawalPayoutError::Snapshot(format!("fsync {}: {e}", parent.display()))
        })?;
    Ok(())
}

struct SnapshotLock(File);

impl SnapshotLock {
    fn acquire(path: &Path) -> Result<Self, PartialWithdrawalPayoutError> {
        let lock_path = PathBuf::from(format!("{}.lock", path.display()));
        reject_symlink(&lock_path, "payout lock")?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| {
                PartialWithdrawalPayoutError::Snapshot(format!("open {}: {e}", lock_path.display()))
            })?;
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            PartialWithdrawalPayoutError::Snapshot(format!("chmod {}: {e}", lock_path.display()))
        })?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(PartialWithdrawalPayoutError::Locked(
                lock_path.display().to_string(),
            ));
        }
        Ok(Self(file))
    }
}

impl Drop for SnapshotLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
