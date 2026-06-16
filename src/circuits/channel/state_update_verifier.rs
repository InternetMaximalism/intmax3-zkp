//! Channel state-update verification (detail2 §E-4 / abstract2 §3.1).
//!
//! v2 (Regev) model: balances are hidden Regev ciphertexts inside `BalanceState`. Co-signers
//! verify transitions through (a) public ciphertext recomputation (homomorphic adds on the
//! receiving slot), (b) the mandatory Plonky3 STARKs (E-1 channelTxZKP / E-2 channelUpdateZKP /
//! refresh) for the sender-side fresh re-encryptions, and (c) their own decryption when they are
//! the recipient. The SIS opening hand-off model (`LatticeOpening` / `LatticeBindingVerifier`)
//! and the dummy-delta receiver-set obfuscation are retired (detail2 §C-1, §A-1).

use plonky2_keccak::utils::solidity_keccak256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use crate::{common::channel::ChannelProofEnvelope, regev::RegevProofPurpose};
use crate::{
    common::{
        balance_state::settled_tx_chain_push,
        channel::{
            ChannelId, ChannelRecord, ChannelState, ChannelTransitionKind, ChannelTx,
            InterChannelTx, ProofBackend, TransitionProofRole, validate_all_member_signatures,
        },
    },
    constants::MAX_CHANNEL_MEMBERS,
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait as _, u256::U256},
    regev::{
        BALANCE_REFRESH_ZKP_DOMAIN, MAX_HOMO_ADDS_BEFORE_REFRESH, RealRegevProofVerifier,
        RegevCiphertext, RegevPk, RegevSk, RegevStatement, add_ciphertexts, decrypt_amount,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelStateUpdatePublicInputs {
    pub kind: ChannelTransitionKind,
    pub channel_id: ChannelId,
    pub prev_state_digest: Bytes32,
    pub next_state_digest: Bytes32,
    /// Public amount: meaningful for inter-channel transfers (base layer amounts are plaintext,
    /// abstract2 §4.5); 0 for in-channel transfers and refreshes (hidden amounts).
    pub amount: u64,
    pub prev_state_version: u64,
    pub next_state_version: u64,
    /// H2 tag of the next state (0 in-channel, the small block's tx_tree_root for sends).
    pub h2_tag: Bytes32,
    pub prev_settled_tx_chain: Bytes32,
    pub next_settled_tx_chain: Bytes32,
    pub receiver_entry_count: u64,
    pub sender_user_id_hash: Bytes32,
    pub receiver_user_id_hash: Bytes32,
    pub channel_fund_before: U256,
    pub channel_fund_after: U256,
    pub unallocated_before: U256,
    pub unallocated_after: U256,
    pub shared_nullifier_before: Bytes32,
    pub shared_nullifier_after: Bytes32,
    pub transition_digest: Bytes32,
}

impl ChannelStateUpdatePublicInputs {
    pub fn digest(&self) -> Bytes32 {
        let words = [
            vec![self.kind as u32],
            self.channel_id.to_u32_vec(),
            self.prev_state_digest.to_u32_vec(),
            self.next_state_digest.to_u32_vec(),
            split_u64(self.amount),
            split_u64(self.prev_state_version),
            split_u64(self.next_state_version),
            self.h2_tag.to_u32_vec(),
            self.prev_settled_tx_chain.to_u32_vec(),
            self.next_settled_tx_chain.to_u32_vec(),
            split_u64(self.receiver_entry_count),
            self.sender_user_id_hash.to_u32_vec(),
            self.receiver_user_id_hash.to_u32_vec(),
            self.channel_fund_before.to_u32_vec(),
            self.channel_fund_after.to_u32_vec(),
            self.unallocated_before.to_u32_vec(),
            self.unallocated_after.to_u32_vec(),
            self.shared_nullifier_before.to_u32_vec(),
            self.shared_nullifier_after.to_u32_vec(),
            self.transition_digest.to_u32_vec(),
        ]
        .concat();
        Bytes32::from_u32_slice(&solidity_keccak256(&words)).expect("keccak output must be bytes32")
    }
}

/// Verifier for transport-level proofs (Plonky2 intmax transport, close settlement, …).
/// Unchanged by the Regev migration.
pub trait ChannelProofVerifier {
    fn verify(
        &self,
        proof: &ChannelProofEnvelope,
        public_inputs: &ChannelStateUpdatePublicInputs,
    ) -> Result<(), ChannelStateUpdateError>;
}

/// Verifier for the lattice-layer Regev STARKs (detail2 §E-4). The plan refines detail2's
/// `public_inputs: &[u32]` into the typed [`RegevStatement`] from `regev::transfer_stark` — the
/// statement is always REBUILT by the relying party from independently checked data, never taken
/// from the proof carrier.
pub trait RegevProofVerifier {
    fn verify(
        &self,
        envelope: &ChannelProofEnvelope,
        purpose: RegevProofPurpose,
        statement: &RegevStatement,
    ) -> Result<(), ChannelStateUpdateError>;
}

impl RegevProofVerifier for RealRegevProofVerifier {
    fn verify(
        &self,
        envelope: &ChannelProofEnvelope,
        purpose: RegevProofPurpose,
        statement: &RegevStatement,
    ) -> Result<(), ChannelStateUpdateError> {
        // SECURITY: lattice-layer proofs ride exclusively in (ChannelStateUpdate, Plonky3)
        // envelopes — purpose separation INSIDE that slot is the STARK transcript domain word.
        if envelope.role != TransitionProofRole::ChannelStateUpdate {
            return Err(ChannelStateUpdateError::InvalidProofRole {
                expected: TransitionProofRole::ChannelStateUpdate,
                actual: envelope.role,
            });
        }
        if envelope.backend != ProofBackend::Plonky3 {
            return Err(ChannelStateUpdateError::InvalidProofBackend {
                expected: ProofBackend::Plonky3,
                actual: envelope.backend,
            });
        }
        RealRegevProofVerifier::verify(self, purpose, &envelope.proof, statement)
            .map_err(|err| ChannelStateUpdateError::ProofVerification(err.to_string()))
    }
}

#[derive(Debug, Error)]
pub enum ChannelStateUpdateError {
    #[error("invalid proof role: expected {expected:?}, got {actual:?}")]
    InvalidProofRole {
        expected: TransitionProofRole,
        actual: TransitionProofRole,
    },

    #[error("invalid proof backend: expected {expected:?}, got {actual:?}")]
    InvalidProofBackend {
        expected: ProofBackend,
        actual: ProofBackend,
    },

    #[error("invalid state linkage: {0}")]
    InvalidStateLinkage(String),

    #[error("invalid regev pk root: {0}")]
    InvalidRegevPkRoot(String),

    #[error("invalid state version: {0}")]
    InvalidStateVersion(String),

    #[error("invalid h2 tag: {0}")]
    InvalidH2Tag(String),

    #[error("invalid settled tx chain: {0}")]
    InvalidSettledTxChain(String),

    #[error("invalid ciphertext transition: {0}")]
    InvalidCiphertextTransition(String),

    #[error("invalid pending adds: {0}")]
    InvalidPendingAdds(String),

    #[error("invalid amount relation: {0}")]
    InvalidAmountRelation(String),

    #[error("invalid root transition: {0}")]
    InvalidRootTransition(String),

    #[error("invalid transition digest: {0}")]
    InvalidTransitionDigest(String),

    #[error("invalid receiver delta bundle: {0}")]
    InvalidReceiverDeltaBundle(String),

    #[error("invalid small block: {0}")]
    InvalidSmallBlock(String),

    #[error("invalid member signatures: {0}")]
    InvalidMemberSignatures(String),

    #[error("invalid decryption: {0}")]
    InvalidDecryption(String),

    #[error("proof verification failed: {0}")]
    ProofVerification(String),

    #[error("public input mismatch: {0}")]
    PublicInputMismatch(String),
}

// ---------------------------------------------------------------------------
// Witness structs
// ---------------------------------------------------------------------------

/// In-channel transfer (detail2 §E-4 InChannel checks; abstract2 §3.1/§3.2).
#[derive(Clone, Debug)]
pub struct InChannelTransferUpdateWitness {
    pub channel_record: ChannelRecord,
    /// All member Regev public keys, in member slot order. Checked against the
    /// L1-anchored `channel_record.regev_pk_root` before any use (F9-A).
    pub regev_pks: [RegevPk; MAX_CHANNEL_MEMBERS],
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    pub channel_tx: ChannelTx,
    pub sender_index: usize,
    pub recipient_index: usize,
    /// Set when the verifying member IS the recipient: enables the decryption check
    /// (abstract2 §3.1 "self-component decryption verification"). Must be paired with `expected_amount`.
    pub recipient_sk: Option<RegevSk>,
    pub expected_amount: Option<u64>,
}

/// Inter-channel send, sender side (detail2 §E-4; abstract2 §3.3).
#[derive(Clone, Debug)]
pub struct InterChannelSendUpdateWitness {
    pub channel_record: ChannelRecord,
    pub regev_pks: [RegevPk; MAX_CHANNEL_MEMBERS],
    /// The destination channel recipient's Regev public key (receiver_deltas[0] is encrypted to
    /// it). Authenticity is the destination channel's `regev_pk_root` concern; the sender-side
    /// co-signers verify the E-2 statement against the key the sender claims.
    pub destination_recipient_pk: RegevPk,
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    pub inter_channel_tx: InterChannelTx,
    /// Public (base-layer plaintext) transfer amount.
    pub amount: u64,
    pub transport_proof: ChannelProofEnvelope,
}

/// Fund import on the destination channel (confirmed incoming, before bundle application).
#[derive(Clone, Debug)]
pub struct InterChannelFundImportUpdateWitness {
    pub source_channel_record: ChannelRecord,
    pub receiver_channel_record: ChannelRecord,
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    pub inter_channel_tx: InterChannelTx,
    pub amount: u64,
    pub transport_proof: ChannelProofEnvelope,
}

/// Receiver-side application of a confirmed inbound transfer (abstract2 §3.4 flowReceive3).
#[derive(Clone, Debug)]
pub struct ReceiverBundleApplyUpdateWitness {
    pub receiver_channel_record: ChannelRecord,
    /// The RECEIVER channel's member keys (root-checked against `receiver_channel_record`).
    pub regev_pks: [RegevPk; MAX_CHANNEL_MEMBERS],
    /// The source channel sender's Regev public key (statement input for re-verifying the E-2
    /// proof signed into the IMIT digest).
    pub source_sender_pk: RegevPk,
    /// The sender's before/after balance ciphertexts from the SOURCE channel state.
    ///
    /// NOTE (witness-only data): these live in the sender channel's `BalanceState`, which the
    /// receiver cannot read from its own state. The sender shares them off-chain alongside the
    /// tx; they are NOT part of the signed `InterChannelTx`. They cannot be forged: the E-2
    /// STARK binds all four ciphertexts into its transcript, so `channel_update_zkp` (which IS
    /// in the IMIT signing digest) only verifies against the genuine pair (abstract2 §3.4
    /// flowReceive3 re-verification).
    pub sender_before_ct: RegevCiphertext,
    pub sender_after_ct: RegevCiphertext,
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    pub inter_channel_tx: InterChannelTx,
    pub amount: u64,
    pub recipient_index: usize,
    pub recipient_sk: Option<RegevSk>,
    pub expected_amount: Option<u64>,
}

/// detail2 §B-3 refresh: a member replaces their own balance slot with a fresh re-encryption of
/// the same (hidden) value, resetting the D3 add counter.
#[derive(Clone, Debug)]
pub struct BalanceRefreshUpdateWitness {
    pub channel_record: ChannelRecord,
    pub regev_pks: [RegevPk; MAX_CHANNEL_MEMBERS],
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    pub member_index: usize,
    pub refresh_proof: ChannelProofEnvelope,
}

// ---------------------------------------------------------------------------
// verify() implementations
// ---------------------------------------------------------------------------

impl InChannelTransferUpdateWitness {
    pub fn verify<VR>(
        &self,
        regev_verifier: &VR,
    ) -> Result<ChannelStateUpdatePublicInputs, ChannelStateUpdateError>
    where
        VR: RegevProofVerifier,
    {
        // (a) Member key authenticity (F9-A).
        verify_regev_pk_root(&self.channel_record, &self.regev_pks)?;
        // (b) State linkage and invariants.
        verify_state_linkage(&self.prev_state, &self.next_state)?;
        verify_balance_state_common(&self.channel_record, &self.prev_state, &self.next_state)?;
        require_h2_zero(&self.next_state)?;
        require_chain_unchanged(&self.prev_state, &self.next_state)?;
        ensure_same_channel_fund(&self.prev_state, &self.next_state)?;
        ensure_same_u256(
            "unallocated_confirmed_incoming",
            self.prev_state.unallocated_confirmed_incoming,
            self.next_state.unallocated_confirmed_incoming,
        )?;
        ensure_same_root(
            "shared_native_nullifier_root",
            self.prev_state.shared_native_nullifier_root,
            self.next_state.shared_native_nullifier_root,
        )?;
        // (c) All-member signatures on the next state (= hash(H1', 0) signatures, detail2 §D).
        verify_next_state_signatures(&self.channel_record, &self.next_state)?;
        // (d) Transaction digest and party consistency.
        let sender = member_index_pubkey_hash(&self.channel_record, self.sender_index)?;
        let recipient = member_index_pubkey_hash(&self.channel_record, self.recipient_index)?;
        if self.sender_index == self.recipient_index {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "sender and recipient must be distinct members".to_string(),
            ));
        }
        if self.channel_tx.sender_pk_g != sender {
            return Err(ChannelStateUpdateError::InvalidTransitionDigest(format!(
                "channel_tx.sender_pk_g {:?} does not match member index {}",
                self.channel_tx.sender_pk_g, self.sender_index
            )));
        }
        if self.channel_tx.recipient_pk_g != recipient {
            return Err(ChannelStateUpdateError::InvalidTransitionDigest(format!(
                "channel_tx.recipient_pk_g {:?} does not match member index {}",
                self.channel_tx.recipient_pk_g, self.recipient_index
            )));
        }
        // P3: the SENDER authorization is now the BabyBear hash-sig proof. This witness layer checks
        // it is PRESENT and that the claimed pk_b is canonical; the full hash-sig verification +
        // A11 two-key membership binding (m == decompose(tx_digest), pk_b PV == sender_pk_b, and
        // (pk_g, pk_b, regev_pk) ∈ one registered MemberLeaf) is performed by the channel-tx
        // acceptance path (`wallet_core::verify_channel_tx_sender_hash_sig`), which has the
        // authenticated channel member set this circuit-statement layer does not carry.
        if self.channel_tx.sender_hash_sig.is_empty() {
            return Err(ChannelStateUpdateError::InvalidMemberSignatures(
                "channel_tx sender hash-sig proof must not be empty".to_string(),
            ));
        }
        let tx_digest = ChannelTx::signing_digest(
            self.prev_state.channel_id,
            self.prev_state.digest,
            &self.channel_tx.enc_amount,
            self.channel_tx.nonce,
            self.channel_tx.sender_pk_g,
            self.channel_tx.recipient_pk_g,
        );
        // (e) Public ciphertext recomputation: the recipient slot is the homomorphic sum, the
        // uninvolved member's slot is bit-identical.
        let expected_recipient_slot = add_ciphertexts(
            &self.prev_state.balance_state.enc_balances[self.recipient_index],
            &self.channel_tx.enc_amount,
        )
        .map_err(|err| ChannelStateUpdateError::InvalidCiphertextTransition(err.to_string()))?;
        if self.next_state.balance_state.enc_balances[self.recipient_index]
            != expected_recipient_slot
        {
            return Err(ChannelStateUpdateError::InvalidCiphertextTransition(
                "recipient slot must equal add_ciphertexts(prev_recipient_slot, enc_amount)"
                    .to_string(),
            ));
        }
        for index in 0..MAX_CHANNEL_MEMBERS {
            if index != self.sender_index && index != self.recipient_index {
                ensure_slot_unchanged(&self.prev_state, &self.next_state, index)?;
            }
        }
        // (f) D3 add counters: recipient +1 under the refresh budget, sender reset (fresh
        // re-encryption), third member unchanged.
        require_pending_add_increment(&self.prev_state, &self.next_state, self.recipient_index)?;
        if self.next_state.balance_state.pending_adds[self.sender_index] != 0 {
            return Err(ChannelStateUpdateError::InvalidPendingAdds(
                "sender slot is freshly re-encrypted; its pending_adds must reset to 0".to_string(),
            ));
        }
        for index in 0..MAX_CHANNEL_MEMBERS {
            if index != self.sender_index && index != self.recipient_index {
                require_pending_adds_unchanged(&self.prev_state, &self.next_state, index)?;
            }
        }
        // (g) Mandatory E-1 channelTxZKP, statement rebuilt from checked data.
        let statement = RegevStatement::ChannelTx {
            sender_pk: self.regev_pks[self.sender_index].clone(),
            recipient_pk: self.regev_pks[self.recipient_index].clone(),
            before: self.prev_state.balance_state.enc_balances[self.sender_index].clone(),
            enc_amount: self.channel_tx.enc_amount.clone(),
            after: self.next_state.balance_state.enc_balances[self.sender_index].clone(),
        };
        regev_verifier.verify(
            &self.channel_tx.channel_tx_zkp,
            RegevProofPurpose::ChannelTx,
            &statement,
        )?;
        // (h) Recipient-only decryption check.
        if let Some(sk) = &self.recipient_sk {
            let expected = self.expected_amount.ok_or_else(|| {
                ChannelStateUpdateError::InvalidDecryption(
                    "recipient_sk requires expected_amount".to_string(),
                )
            })?;
            let decrypted = decrypt_amount(sk, &self.channel_tx.enc_amount)
                .map_err(|err| ChannelStateUpdateError::InvalidDecryption(err.to_string()))?;
            if decrypted != expected {
                return Err(ChannelStateUpdateError::InvalidDecryption(format!(
                    "enc_amount decrypts to {decrypted}, expected {expected}"
                )));
            }
            decrypt_amount(
                sk,
                &self.next_state.balance_state.enc_balances[self.recipient_index],
            )
            .map_err(|err| {
                ChannelStateUpdateError::InvalidDecryption(format!(
                    "next recipient balance slot does not decrypt: {err}"
                ))
            })?;
        }

        Ok(ChannelStateUpdatePublicInputs {
            kind: ChannelTransitionKind::InChannelTransfer,
            channel_id: self.prev_state.channel_id,
            prev_state_digest: self.prev_state.digest,
            next_state_digest: self.next_state.digest,
            // In-channel amounts stay hidden (recipient decryption + E-1 only).
            amount: 0,
            prev_state_version: self.prev_state.balance_state.state_version,
            next_state_version: self.next_state.balance_state.state_version,
            h2_tag: self.next_state.h2_tag,
            prev_settled_tx_chain: self.prev_state.balance_state.settled_tx_chain,
            next_settled_tx_chain: self.next_state.balance_state.settled_tx_chain,
            receiver_entry_count: 1,
            sender_user_id_hash: hash_member(self.channel_tx.sender_pk_g),
            receiver_user_id_hash: hash_member(self.channel_tx.recipient_pk_g),
            channel_fund_before: self.prev_state.channel_fund.amount,
            channel_fund_after: self.next_state.channel_fund.amount,
            unallocated_before: self.prev_state.unallocated_confirmed_incoming,
            unallocated_after: self.next_state.unallocated_confirmed_incoming,
            shared_nullifier_before: self.prev_state.shared_native_nullifier_root,
            shared_nullifier_after: self.next_state.shared_native_nullifier_root,
            transition_digest: tx_digest,
        })
    }
}

impl InterChannelSendUpdateWitness {
    pub fn verify<VP, VR>(
        &self,
        proof_verifier: &VP,
        regev_verifier: &VR,
    ) -> Result<ChannelStateUpdatePublicInputs, ChannelStateUpdateError>
    where
        VP: ChannelProofVerifier,
        VR: RegevProofVerifier,
    {
        verify_regev_pk_root(&self.channel_record, &self.regev_pks)?;
        verify_state_linkage(&self.prev_state, &self.next_state)?;
        verify_balance_state_common(&self.channel_record, &self.prev_state, &self.next_state)?;
        verify_next_state_signatures(&self.channel_record, &self.next_state)?;
        validate_signed_small_block(
            &self.channel_record,
            self.prev_state.channel_id,
            self.prev_state.close_freeze_nonce,
            &self.inter_channel_tx,
        )?;
        if self.prev_state.channel_id != self.inter_channel_tx.source_channel_id {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "source channel id mismatch".to_string(),
            ));
        }
        let message = &self.inter_channel_tx.signed_small_block.message;
        // SECURITY (detail2 §C-2): H2 = 0 is reserved for in-channel updates; an inter-channel
        // send with a zero tx_tree_root would alias the in-channel signing target.
        if message.tx_tree_root == Bytes32::default() {
            return Err(ChannelStateUpdateError::InvalidH2Tag(
                "inter-channel small block tx_tree_root must not be zero".to_string(),
            ));
        }
        if self.next_state.h2_tag != message.tx_tree_root {
            return Err(ChannelStateUpdateError::InvalidH2Tag(
                "next state h2_tag must equal the small block tx_tree_root".to_string(),
            ));
        }
        // detail2 §C-7: the signed small block's state_commitment_root IS H1' of the post-debit
        // balance state — this is the structural-atomicity binding (§D-3).
        if message.state_commitment_root != self.next_state.balance_state.h1() {
            return Err(ChannelStateUpdateError::InvalidSmallBlock(
                "small block state_commitment_root must equal next balance state h1".to_string(),
            ));
        }
        // detail2 §A-2: 1 small block = 1 tx = 1 real receiver.
        if self.inter_channel_tx.receiver_deltas.len() != 1 {
            return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
                format!(
                    "expected exactly 1 receiver delta (detail2 §A-2), got {}",
                    self.inter_channel_tx.receiver_deltas.len()
                ),
            ));
        }
        let receiver_delta = &self.inter_channel_tx.receiver_deltas[0];
        // One key per member: the receiver pubkey hash is self-describing (no key_id embedding to
        // re-check). Cross-channel membership of the receiver is the receiving channel's concern.
        // Chain push with the tx leaf (detail2 §C-6).
        let leaf = self
            .inter_channel_tx
            .tx_leaf_hash()
            .map_err(|err| ChannelStateUpdateError::InvalidSettledTxChain(err.to_string()))?;
        require_chain_push(&self.prev_state, &self.next_state, leaf)?;
        // Fund decrease by the public amount.
        if self.next_state.channel_fund.amount + u64_to_u256(self.amount)
            != self.prev_state.channel_fund.amount
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "channel fund must decrease by transfer amount".to_string(),
            ));
        }
        ensure_same_u256(
            "unallocated_confirmed_incoming",
            self.prev_state.unallocated_confirmed_incoming,
            self.next_state.unallocated_confirmed_incoming,
        )?;
        ensure_different_root(
            "shared_native_nullifier_root",
            self.prev_state.shared_native_nullifier_root,
            self.next_state.shared_native_nullifier_root,
        )?;
        // Sender slot rebind via the mandatory E-2 channelUpdateZKP. Other slots untouched.
        // The sender slot is located by its pubkey hash in the channel's member list.
        let sender_index = member_slot_index(
            &self.channel_record,
            self.inter_channel_tx.source_pk_g,
        )?;
        for index in 0..MAX_CHANNEL_MEMBERS {
            if index != sender_index {
                ensure_slot_unchanged(&self.prev_state, &self.next_state, index)?;
                require_pending_adds_unchanged(&self.prev_state, &self.next_state, index)?;
            }
        }
        if self.next_state.balance_state.pending_adds[sender_index] != 0 {
            return Err(ChannelStateUpdateError::InvalidPendingAdds(
                "sender slot is freshly re-encrypted; its pending_adds must reset to 0".to_string(),
            ));
        }
        let statement = RegevStatement::ChannelUpdate {
            sender_pk: self.regev_pks[sender_index].clone(),
            recipient_pk: self.destination_recipient_pk.clone(),
            before: self.prev_state.balance_state.enc_balances[sender_index].clone(),
            after: self.next_state.balance_state.enc_balances[sender_index].clone(),
            sender_delta: self.inter_channel_tx.sender_delta_ct.clone(),
            receiver_delta: receiver_delta.amount.clone(),
            amount: self.amount,
        };
        regev_verifier.verify(
            &self.inter_channel_tx.channel_update_zkp,
            RegevProofPurpose::ChannelUpdate,
            &statement,
        )?;
        if self.inter_channel_tx.transport_proof != self.transport_proof.proof {
            return Err(ChannelStateUpdateError::InvalidTransitionDigest(
                "transport proof bytes must match transport_proof".to_string(),
            ));
        }
        let public_inputs = ChannelStateUpdatePublicInputs {
            kind: ChannelTransitionKind::InterChannelSend,
            channel_id: self.prev_state.channel_id,
            prev_state_digest: self.prev_state.digest,
            next_state_digest: self.next_state.digest,
            amount: self.amount,
            prev_state_version: self.prev_state.balance_state.state_version,
            next_state_version: self.next_state.balance_state.state_version,
            h2_tag: self.next_state.h2_tag,
            prev_settled_tx_chain: self.prev_state.balance_state.settled_tx_chain,
            next_settled_tx_chain: self.next_state.balance_state.settled_tx_chain,
            receiver_entry_count: 1,
            sender_user_id_hash: hash_member(self.inter_channel_tx.source_pk_g),
            receiver_user_id_hash: hash_member(receiver_delta.receiver_pk_g),
            channel_fund_before: self.prev_state.channel_fund.amount,
            channel_fund_after: self.next_state.channel_fund.amount,
            unallocated_before: self.prev_state.unallocated_confirmed_incoming,
            unallocated_after: self.next_state.unallocated_confirmed_incoming,
            shared_nullifier_before: self.prev_state.shared_native_nullifier_root,
            shared_nullifier_after: self.next_state.shared_native_nullifier_root,
            transition_digest: self.inter_channel_tx.signing_digest(),
        };
        verify_proof(
            proof_verifier,
            &self.transport_proof,
            TransitionProofRole::IntmaxTransport,
            ProofBackend::Plonky2,
            &public_inputs,
        )?;
        Ok(public_inputs)
    }
}

impl InterChannelFundImportUpdateWitness {
    pub fn verify<VP>(
        &self,
        proof_verifier: &VP,
    ) -> Result<ChannelStateUpdatePublicInputs, ChannelStateUpdateError>
    where
        VP: ChannelProofVerifier,
    {
        verify_state_linkage(&self.prev_state, &self.next_state)?;
        verify_balance_state_common(
            &self.receiver_channel_record,
            &self.prev_state,
            &self.next_state,
        )?;
        verify_next_state_signatures(&self.receiver_channel_record, &self.next_state)?;
        validate_signed_small_block(
            &self.source_channel_record,
            self.inter_channel_tx.source_channel_id,
            self.inter_channel_tx
                .signed_small_block
                .message
                .close_freeze_nonce,
            &self.inter_channel_tx,
        )?;
        if self.prev_state.channel_id != self.inter_channel_tx.destination_channel_id {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "destination channel id mismatch".to_string(),
            ));
        }
        require_h2_zero(&self.next_state)?;
        // detail2 §C-6: deposit/fund imports chain the deposit hash. For the import transition
        // the chained leaf is the inter-channel tx's `tx_hash` — the same identifier that the
        // base layer settles and that `PostCloseIncomingClaim.incoming_tx_hash` references, so
        // the import is replayable/auditable against the L1 settle history.
        require_chain_push(
            &self.prev_state,
            &self.next_state,
            self.inter_channel_tx.tx_hash,
        )?;
        if self.next_state.channel_fund.amount
            != self.prev_state.channel_fund.amount + u64_to_u256(self.amount)
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "channel fund must increase by imported amount".to_string(),
            ));
        }
        if self.next_state.unallocated_confirmed_incoming
            != self.prev_state.unallocated_confirmed_incoming + u64_to_u256(self.amount)
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "unallocated_confirmed_incoming must increase by imported amount".to_string(),
            ));
        }
        // Balances are untouched by the import: every slot and counter must be bit-identical.
        for index in 0..MAX_CHANNEL_MEMBERS {
            ensure_slot_unchanged(&self.prev_state, &self.next_state, index)?;
            require_pending_adds_unchanged(&self.prev_state, &self.next_state, index)?;
        }
        ensure_different_root(
            "shared_native_nullifier_root",
            self.prev_state.shared_native_nullifier_root,
            self.next_state.shared_native_nullifier_root,
        )?;
        if self.inter_channel_tx.transport_proof != self.transport_proof.proof {
            return Err(ChannelStateUpdateError::InvalidTransitionDigest(
                "transport proof bytes must match transport_proof".to_string(),
            ));
        }
        let receiver_user_id = self
            .inter_channel_tx
            .receiver_deltas
            .first()
            .map(|delta| delta.receiver_pk_g)
            .ok_or_else(|| {
                ChannelStateUpdateError::InvalidReceiverDeltaBundle(
                    "fund import requires the receiver delta entry".to_string(),
                )
            })?;
        let public_inputs = ChannelStateUpdatePublicInputs {
            kind: ChannelTransitionKind::InterChannelFundImport,
            channel_id: self.prev_state.channel_id,
            prev_state_digest: self.prev_state.digest,
            next_state_digest: self.next_state.digest,
            amount: self.amount,
            prev_state_version: self.prev_state.balance_state.state_version,
            next_state_version: self.next_state.balance_state.state_version,
            h2_tag: self.next_state.h2_tag,
            prev_settled_tx_chain: self.prev_state.balance_state.settled_tx_chain,
            next_settled_tx_chain: self.next_state.balance_state.settled_tx_chain,
            receiver_entry_count: self.inter_channel_tx.receiver_deltas.len() as u64,
            sender_user_id_hash: hash_member(self.inter_channel_tx.source_pk_g),
            receiver_user_id_hash: hash_member(receiver_user_id),
            channel_fund_before: self.prev_state.channel_fund.amount,
            channel_fund_after: self.next_state.channel_fund.amount,
            unallocated_before: self.prev_state.unallocated_confirmed_incoming,
            unallocated_after: self.next_state.unallocated_confirmed_incoming,
            shared_nullifier_before: self.prev_state.shared_native_nullifier_root,
            shared_nullifier_after: self.next_state.shared_native_nullifier_root,
            transition_digest: self.inter_channel_tx.signing_digest(),
        };
        verify_proof(
            proof_verifier,
            &self.transport_proof,
            TransitionProofRole::IntmaxTransport,
            ProofBackend::Plonky2,
            &public_inputs,
        )?;
        Ok(public_inputs)
    }
}

impl ReceiverBundleApplyUpdateWitness {
    pub fn verify<VR>(
        &self,
        regev_verifier: &VR,
    ) -> Result<ChannelStateUpdatePublicInputs, ChannelStateUpdateError>
    where
        VR: RegevProofVerifier,
    {
        verify_regev_pk_root(&self.receiver_channel_record, &self.regev_pks)?;
        verify_state_linkage(&self.prev_state, &self.next_state)?;
        verify_balance_state_common(
            &self.receiver_channel_record,
            &self.prev_state,
            &self.next_state,
        )?;
        verify_next_state_signatures(&self.receiver_channel_record, &self.next_state)?;
        if self.prev_state.channel_id != self.inter_channel_tx.destination_channel_id {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "destination channel id mismatch".to_string(),
            ));
        }
        require_h2_zero(&self.next_state)?;
        ensure_same_channel_fund(&self.prev_state, &self.next_state)?;
        if self.prev_state.unallocated_confirmed_incoming
            != self.next_state.unallocated_confirmed_incoming + u64_to_u256(self.amount)
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "unallocated_confirmed_incoming must decrease by bundle amount".to_string(),
            ));
        }
        ensure_same_root(
            "shared_native_nullifier_root",
            self.prev_state.shared_native_nullifier_root,
            self.next_state.shared_native_nullifier_root,
        )?;
        if self.inter_channel_tx.receiver_deltas.len() != 1 {
            return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
                format!(
                    "expected exactly 1 receiver delta (detail2 §A-2), got {}",
                    self.inter_channel_tx.receiver_deltas.len()
                ),
            ));
        }
        let receiver_delta = &self.inter_channel_tx.receiver_deltas[0];
        let recipient =
            member_index_pubkey_hash(&self.receiver_channel_record, self.recipient_index)?;
        if receiver_delta.receiver_pk_g != recipient {
            return Err(ChannelStateUpdateError::InvalidReceiverDeltaBundle(
                format!(
                    "receiver delta user {:?} does not match member index {}",
                    receiver_delta.receiver_pk_g, self.recipient_index
                ),
            ));
        }
        // Chain push with the same tx leaf the sender chained (independent recomputation —
        // multi-layer defense for F3-A).
        let leaf = self
            .inter_channel_tx
            .tx_leaf_hash()
            .map_err(|err| ChannelStateUpdateError::InvalidSettledTxChain(err.to_string()))?;
        require_chain_push(&self.prev_state, &self.next_state, leaf)?;
        // Recipient slot: public homomorphic-add recomputation; other slots untouched.
        let expected_recipient_slot = add_ciphertexts(
            &self.prev_state.balance_state.enc_balances[self.recipient_index],
            &receiver_delta.amount,
        )
        .map_err(|err| ChannelStateUpdateError::InvalidCiphertextTransition(err.to_string()))?;
        if self.next_state.balance_state.enc_balances[self.recipient_index]
            != expected_recipient_slot
        {
            return Err(ChannelStateUpdateError::InvalidCiphertextTransition(
                "recipient slot must equal add_ciphertexts(prev_recipient_slot, receiver_delta)"
                    .to_string(),
            ));
        }
        for index in 0..MAX_CHANNEL_MEMBERS {
            if index != self.recipient_index {
                ensure_slot_unchanged(&self.prev_state, &self.next_state, index)?;
                require_pending_adds_unchanged(&self.prev_state, &self.next_state, index)?;
            }
        }
        require_pending_add_increment(&self.prev_state, &self.next_state, self.recipient_index)?;
        // Re-verify the E-2 proof that was signed into the IMIT digest (flowReceive3). The
        // sender-side before/after ciphertexts come from the off-chain witness share — the STARK
        // transcript binds them, so a forged pair cannot verify.
        let statement = RegevStatement::ChannelUpdate {
            sender_pk: self.source_sender_pk.clone(),
            recipient_pk: self.regev_pks[self.recipient_index].clone(),
            before: self.sender_before_ct.clone(),
            after: self.sender_after_ct.clone(),
            sender_delta: self.inter_channel_tx.sender_delta_ct.clone(),
            receiver_delta: receiver_delta.amount.clone(),
            amount: self.amount,
        };
        regev_verifier.verify(
            &self.inter_channel_tx.channel_update_zkp,
            RegevProofPurpose::ChannelUpdate,
            &statement,
        )?;
        // Recipient-only decryption check.
        if let Some(sk) = &self.recipient_sk {
            let expected = self.expected_amount.ok_or_else(|| {
                ChannelStateUpdateError::InvalidDecryption(
                    "recipient_sk requires expected_amount".to_string(),
                )
            })?;
            let decrypted = decrypt_amount(sk, &receiver_delta.amount)
                .map_err(|err| ChannelStateUpdateError::InvalidDecryption(err.to_string()))?;
            if decrypted != expected {
                return Err(ChannelStateUpdateError::InvalidDecryption(format!(
                    "receiver delta decrypts to {decrypted}, expected {expected}"
                )));
            }
            decrypt_amount(
                sk,
                &self.next_state.balance_state.enc_balances[self.recipient_index],
            )
            .map_err(|err| {
                ChannelStateUpdateError::InvalidDecryption(format!(
                    "next recipient balance slot does not decrypt: {err}"
                ))
            })?;
        }

        Ok(ChannelStateUpdatePublicInputs {
            kind: ChannelTransitionKind::ReceiverBundleApply,
            channel_id: self.prev_state.channel_id,
            prev_state_digest: self.prev_state.digest,
            next_state_digest: self.next_state.digest,
            amount: self.amount,
            prev_state_version: self.prev_state.balance_state.state_version,
            next_state_version: self.next_state.balance_state.state_version,
            h2_tag: self.next_state.h2_tag,
            prev_settled_tx_chain: self.prev_state.balance_state.settled_tx_chain,
            next_settled_tx_chain: self.next_state.balance_state.settled_tx_chain,
            receiver_entry_count: 1,
            sender_user_id_hash: hash_member(self.inter_channel_tx.source_pk_g),
            receiver_user_id_hash: hash_member(receiver_delta.receiver_pk_g),
            channel_fund_before: self.prev_state.channel_fund.amount,
            channel_fund_after: self.next_state.channel_fund.amount,
            unallocated_before: self.prev_state.unallocated_confirmed_incoming,
            unallocated_after: self.next_state.unallocated_confirmed_incoming,
            shared_nullifier_before: self.prev_state.shared_native_nullifier_root,
            shared_nullifier_after: self.next_state.shared_native_nullifier_root,
            transition_digest: self.inter_channel_tx.signing_digest(),
        })
    }
}

impl BalanceRefreshUpdateWitness {
    pub fn verify<VR>(
        &self,
        regev_verifier: &VR,
    ) -> Result<ChannelStateUpdatePublicInputs, ChannelStateUpdateError>
    where
        VR: RegevProofVerifier,
    {
        verify_regev_pk_root(&self.channel_record, &self.regev_pks)?;
        verify_state_linkage(&self.prev_state, &self.next_state)?;
        verify_balance_state_common(&self.channel_record, &self.prev_state, &self.next_state)?;
        verify_next_state_signatures(&self.channel_record, &self.next_state)?;
        require_h2_zero(&self.next_state)?;
        require_chain_unchanged(&self.prev_state, &self.next_state)?;
        ensure_same_channel_fund(&self.prev_state, &self.next_state)?;
        ensure_same_u256(
            "unallocated_confirmed_incoming",
            self.prev_state.unallocated_confirmed_incoming,
            self.next_state.unallocated_confirmed_incoming,
        )?;
        ensure_same_root(
            "shared_native_nullifier_root",
            self.prev_state.shared_native_nullifier_root,
            self.next_state.shared_native_nullifier_root,
        )?;
        let member = member_index_pubkey_hash(&self.channel_record, self.member_index)?;
        // Only the refreshed member's slot changes; everyone else's slot and counter are frozen.
        for index in 0..MAX_CHANNEL_MEMBERS {
            if index != self.member_index {
                ensure_slot_unchanged(&self.prev_state, &self.next_state, index)?;
                require_pending_adds_unchanged(&self.prev_state, &self.next_state, index)?;
            }
        }
        // D3: the refresh resets the member's add counter (any value -> 0).
        if self.next_state.balance_state.pending_adds[self.member_index] != 0 {
            return Err(ChannelStateUpdateError::InvalidPendingAdds(
                "refresh must reset the member's pending_adds to 0".to_string(),
            ));
        }
        let old_ct = &self.prev_state.balance_state.enc_balances[self.member_index];
        let new_ct = &self.next_state.balance_state.enc_balances[self.member_index];
        let statement = RegevStatement::BalanceRefresh {
            pk: self.regev_pks[self.member_index].clone(),
            old_ct: old_ct.clone(),
            new_ct: new_ct.clone(),
        };
        regev_verifier.verify(
            &self.refresh_proof,
            RegevProofPurpose::BalanceRefresh,
            &statement,
        )?;

        let transition_digest = Bytes32::from_u32_slice(&solidity_keccak256(
            &[
                vec![BALANCE_REFRESH_ZKP_DOMAIN, self.member_index as u32],
                old_ct.digest().to_u32_vec(),
                new_ct.digest().to_u32_vec(),
            ]
            .concat(),
        ))
        .expect("keccak output must be bytes32");
        Ok(ChannelStateUpdatePublicInputs {
            kind: ChannelTransitionKind::BalanceRefresh,
            channel_id: self.prev_state.channel_id,
            prev_state_digest: self.prev_state.digest,
            next_state_digest: self.next_state.digest,
            amount: 0,
            prev_state_version: self.prev_state.balance_state.state_version,
            next_state_version: self.next_state.balance_state.state_version,
            h2_tag: self.next_state.h2_tag,
            prev_settled_tx_chain: self.prev_state.balance_state.settled_tx_chain,
            next_settled_tx_chain: self.next_state.balance_state.settled_tx_chain,
            receiver_entry_count: 0,
            sender_user_id_hash: hash_member(member),
            receiver_user_id_hash: hash_member(member),
            channel_fund_before: self.prev_state.channel_fund.amount,
            channel_fund_after: self.next_state.channel_fund.amount,
            unallocated_before: self.prev_state.unallocated_confirmed_incoming,
            unallocated_after: self.next_state.unallocated_confirmed_incoming,
            shared_nullifier_before: self.prev_state.shared_native_nullifier_root,
            shared_nullifier_after: self.next_state.shared_native_nullifier_root,
            transition_digest,
        })
    }
}

// ---------------------------------------------------------------------------
// Shared checks
// ---------------------------------------------------------------------------

fn verify_state_linkage(
    prev_state: &ChannelState,
    next_state: &ChannelState,
) -> Result<(), ChannelStateUpdateError> {
    if prev_state.channel_id != next_state.channel_id {
        return Err(ChannelStateUpdateError::InvalidStateLinkage(
            "channel id mismatch".to_string(),
        ));
    }
    if next_state.epoch != prev_state.epoch + 1 {
        return Err(ChannelStateUpdateError::InvalidStateLinkage(
            "next epoch must equal prev epoch + 1".to_string(),
        ));
    }
    if next_state.prev_digest != prev_state.digest {
        return Err(ChannelStateUpdateError::InvalidStateLinkage(
            "next prev_digest must equal prev digest".to_string(),
        ));
    }
    if prev_state.digest != prev_state.signing_digest() {
        return Err(ChannelStateUpdateError::InvalidStateLinkage(
            "prev digest must match signing digest".to_string(),
        ));
    }
    if next_state.digest != next_state.signing_digest() {
        return Err(ChannelStateUpdateError::InvalidStateLinkage(
            "next digest must match signing digest".to_string(),
        ));
    }
    Ok(())
}

/// Common balance-state checks for every transition: canonical ciphertexts and D3 budgets on
/// both sides, channel-id consistency, and the strict `state_version` increment.
fn verify_balance_state_common(
    record: &ChannelRecord,
    prev_state: &ChannelState,
    next_state: &ChannelState,
) -> Result<(), ChannelStateUpdateError> {
    prev_state
        .balance_state
        .validate()
        .map_err(|err| ChannelStateUpdateError::InvalidCiphertextTransition(err.to_string()))?;
    next_state
        .balance_state
        .validate()
        .map_err(|err| ChannelStateUpdateError::InvalidCiphertextTransition(err.to_string()))?;
    if prev_state.balance_state.channel_id != prev_state.channel_id
        || next_state.balance_state.channel_id != next_state.channel_id
        || prev_state.channel_id != record.channel_id
    {
        return Err(ChannelStateUpdateError::InvalidStateLinkage(
            "balance state channel_id must match the state and record channel_id".to_string(),
        ));
    }
    if next_state.balance_state.state_version != prev_state.balance_state.state_version + 1 {
        return Err(ChannelStateUpdateError::InvalidStateVersion(format!(
            "state_version must increment by exactly 1 (prev {}, next {})",
            prev_state.balance_state.state_version, next_state.balance_state.state_version
        )));
    }
    Ok(())
}

fn verify_regev_pk_root(
    record: &ChannelRecord,
    regev_pks: &[RegevPk; MAX_CHANNEL_MEMBERS],
) -> Result<(), ChannelStateUpdateError> {
    for (index, pk) in regev_pks.iter().enumerate() {
        pk.validate().map_err(|err| {
            ChannelStateUpdateError::InvalidRegevPkRoot(format!(
                "regev_pks[{index}] is not canonical: {err}"
            ))
        })?;
    }
    let root = crate::regev::regev_pk_root(regev_pks);
    if root != record.regev_pk_root {
        return Err(ChannelStateUpdateError::InvalidRegevPkRoot(format!(
            "computed pk root {root:?} does not match channel record root {:?}",
            record.regev_pk_root
        )));
    }
    Ok(())
}

fn require_h2_zero(next_state: &ChannelState) -> Result<(), ChannelStateUpdateError> {
    if next_state.h2_tag != Bytes32::default() {
        return Err(ChannelStateUpdateError::InvalidH2Tag(
            "h2_tag must be zero for this transition kind (detail2 §C-2)".to_string(),
        ));
    }
    Ok(())
}

fn require_chain_unchanged(
    prev_state: &ChannelState,
    next_state: &ChannelState,
) -> Result<(), ChannelStateUpdateError> {
    if next_state.balance_state.settled_tx_chain != prev_state.balance_state.settled_tx_chain {
        return Err(ChannelStateUpdateError::InvalidSettledTxChain(
            "settled_tx_chain must remain unchanged for this transition kind".to_string(),
        ));
    }
    Ok(())
}

fn require_chain_push(
    prev_state: &ChannelState,
    next_state: &ChannelState,
    leaf: Bytes32,
) -> Result<(), ChannelStateUpdateError> {
    let expected = settled_tx_chain_push(prev_state.balance_state.settled_tx_chain, leaf);
    if next_state.balance_state.settled_tx_chain != expected {
        return Err(ChannelStateUpdateError::InvalidSettledTxChain(format!(
            "settled_tx_chain must equal push(prev_chain, leaf): expected {expected:?}, got {:?}",
            next_state.balance_state.settled_tx_chain
        )));
    }
    Ok(())
}

fn ensure_slot_unchanged(
    prev_state: &ChannelState,
    next_state: &ChannelState,
    index: usize,
) -> Result<(), ChannelStateUpdateError> {
    if prev_state.balance_state.enc_balances[index] != next_state.balance_state.enc_balances[index]
    {
        return Err(ChannelStateUpdateError::InvalidCiphertextTransition(
            format!("balance slot {index} must remain bit-identical"),
        ));
    }
    Ok(())
}

/// D3 enforcement at the application point: the receiving slot's counter must be strictly below
/// the refresh budget BEFORE the add, and must increment by exactly 1.
fn require_pending_add_increment(
    prev_state: &ChannelState,
    next_state: &ChannelState,
    index: usize,
) -> Result<(), ChannelStateUpdateError> {
    let before = prev_state.balance_state.pending_adds[index];
    let after = next_state.balance_state.pending_adds[index];
    if before >= MAX_HOMO_ADDS_BEFORE_REFRESH {
        return Err(ChannelStateUpdateError::InvalidPendingAdds(format!(
            "slot {index} has {before} pending adds; refresh required before another add (D3)"
        )));
    }
    if after != before + 1 {
        return Err(ChannelStateUpdateError::InvalidPendingAdds(format!(
            "slot {index} pending_adds must increment by 1 (before {before}, after {after})"
        )));
    }
    Ok(())
}

fn require_pending_adds_unchanged(
    prev_state: &ChannelState,
    next_state: &ChannelState,
    index: usize,
) -> Result<(), ChannelStateUpdateError> {
    if prev_state.balance_state.pending_adds[index] != next_state.balance_state.pending_adds[index]
    {
        return Err(ChannelStateUpdateError::InvalidPendingAdds(format!(
            "pending_adds[{index}] must remain unchanged"
        )));
    }
    Ok(())
}

/// Slot index of the member identified by `pubkey_hash` in the channel's ordered member list.
fn member_slot_index(
    record: &ChannelRecord,
    pubkey_hash: Bytes32,
) -> Result<usize, ChannelStateUpdateError> {
    record
        .member_pk_gs
        .iter()
        .position(|member| *member == pubkey_hash)
        .ok_or_else(|| {
            ChannelStateUpdateError::InvalidStateLinkage(format!(
                "pubkey hash {pubkey_hash:?} is not a channel member"
            ))
        })
}

/// The SPHINCS+ pubkey hash of the member at slot `index`.
fn member_index_pubkey_hash(
    record: &ChannelRecord,
    index: usize,
) -> Result<Bytes32, ChannelStateUpdateError> {
    record
        .member_pk_gs
        .get(index)
        .copied()
        .ok_or_else(|| {
            ChannelStateUpdateError::InvalidStateLinkage(format!(
                "member index {index} out of range (members: {MAX_CHANNEL_MEMBERS})"
            ))
        })
}

fn verify_next_state_signatures(
    record: &ChannelRecord,
    next_state: &ChannelState,
) -> Result<(), ChannelStateUpdateError> {
    validate_all_member_signatures(record, &next_state.member_signatures)
        .map_err(|err| ChannelStateUpdateError::InvalidMemberSignatures(err.to_string()))
}

fn validate_signed_small_block(
    source_channel_record: &ChannelRecord,
    expected_source_channel_id: ChannelId,
    expected_close_freeze_nonce: u64,
    inter_channel_tx: &InterChannelTx,
) -> Result<(), ChannelStateUpdateError> {
    let signed = &inter_channel_tx.signed_small_block;
    if inter_channel_tx.source_channel_id != expected_source_channel_id {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "source channel mismatch".to_string(),
        ));
    }
    if signed.message.channel_id != expected_source_channel_id {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "small block message channel mismatch".to_string(),
        ));
    }
    if signed.message.bp_member_slot != source_channel_record.bp_member_slot
        || signed.message.bp_pk_g
            != member_index_pubkey_hash(
                source_channel_record,
                source_channel_record.bp_member_slot as usize,
            )?
    {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "small block BP mismatch".to_string(),
        ));
    }
    if signed.message.close_freeze_nonce != expected_close_freeze_nonce {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "small block close_freeze_nonce mismatch".to_string(),
        ));
    }
    if signed.medium_block_number < signed.message.medium_epoch_hint {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "medium_block_number must be >= medium_epoch_hint".to_string(),
        ));
    }
    if signed.aggregated_signature_proof.is_empty() {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "aggregated signature proof must not be empty".to_string(),
        ));
    }
    if signed.confirmation_proof.is_empty() {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "confirmation proof must not be empty".to_string(),
        ));
    }
    validate_all_member_signatures(source_channel_record, &signed.signatures)
        .map_err(|err| ChannelStateUpdateError::InvalidSmallBlock(err.to_string()))
}

fn ensure_same_channel_fund(
    prev_state: &ChannelState,
    next_state: &ChannelState,
) -> Result<(), ChannelStateUpdateError> {
    if prev_state.channel_fund != next_state.channel_fund {
        return Err(ChannelStateUpdateError::InvalidRootTransition(
            "channel fund must remain unchanged".to_string(),
        ));
    }
    Ok(())
}

fn ensure_same_root(
    name: &str,
    before: Bytes32,
    after: Bytes32,
) -> Result<(), ChannelStateUpdateError> {
    if before != after {
        return Err(ChannelStateUpdateError::InvalidRootTransition(format!(
            "{name} must remain unchanged",
        )));
    }
    Ok(())
}

fn ensure_different_root(
    name: &str,
    before: Bytes32,
    after: Bytes32,
) -> Result<(), ChannelStateUpdateError> {
    if before == after {
        return Err(ChannelStateUpdateError::InvalidRootTransition(format!(
            "{name} must change",
        )));
    }
    Ok(())
}

fn ensure_same_u256(name: &str, before: U256, after: U256) -> Result<(), ChannelStateUpdateError> {
    if before != after {
        return Err(ChannelStateUpdateError::InvalidRootTransition(format!(
            "{name} must remain unchanged",
        )));
    }
    Ok(())
}

fn verify_proof<VP>(
    verifier: &VP,
    proof: &ChannelProofEnvelope,
    expected_role: TransitionProofRole,
    expected_backend: ProofBackend,
    public_inputs: &ChannelStateUpdatePublicInputs,
) -> Result<(), ChannelStateUpdateError>
where
    VP: ChannelProofVerifier,
{
    if proof.role != expected_role {
        return Err(ChannelStateUpdateError::InvalidProofRole {
            expected: expected_role,
            actual: proof.role,
        });
    }
    if proof.backend != expected_backend {
        return Err(ChannelStateUpdateError::InvalidProofBackend {
            expected: expected_backend,
            actual: proof.backend,
        });
    }
    verifier.verify(proof, public_inputs)
}

/// Keccak over a member's SPHINCS+ pubkey hash (8 u32 limbs) — the digest-friendly member id used
/// in the channel-state-update public inputs.
fn hash_member(pubkey_hash: Bytes32) -> Bytes32 {
    Bytes32::from_u32_slice(&solidity_keccak256(&pubkey_hash.to_u32_vec()))
        .expect("keccak output must be bytes32")
}

fn split_u64(value: u64) -> Vec<u32> {
    vec![(value >> 32) as u32, value as u32]
}

fn u64_to_u256(value: u64) -> U256 {
    U256::from_u32_slice(&[0, 0, 0, 0, 0, 0, (value >> 32) as u32, value as u32])
        .expect("u64 must fit in U256")
}

#[cfg(test)]
mod tests {
    use rand010::{SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::{
        common::{
            balance_state::BalanceState,
            channel::{ChannelFund, ChannelStatus, MemberSignature},
        },
        ethereum_types::u256::U256,
        regev::{
            RegevSecurityLevel, channel_keygen, encrypt_amount, prove_channel_tx, regev_pk_root,
        },
    };

    /// A distinct, canonical member SPHINCS+ pubkey hash (Bytes32) per seed.
    fn pubkey_hash(seed: u32) -> Bytes32 {
        Bytes32::from_u32_slice(&[
            seed,
            seed + 1,
            seed + 2,
            seed + 3,
            seed + 4,
            seed + 5,
            seed + 6,
            seed + 7,
        ])
        .unwrap()
    }

    /// Pad an active prefix of member pubkey hashes to the full MAX_CHANNEL_MEMBERS array (padding
    /// = `Bytes32::default()`, pad-to-MAX D6).
    fn pad_hashes(active: &[Bytes32]) -> [Bytes32; MAX_CHANNEL_MEMBERS] {
        std::array::from_fn(|i| active.get(i).copied().unwrap_or_default())
    }

    /// Pad an active prefix of Regev pubkeys to the full MAX_CHANNEL_MEMBERS array (padding =
    /// `RegevPk::padding()`).
    fn pad_pks(active: &[RegevPk]) -> [RegevPk; MAX_CHANNEL_MEMBERS] {
        std::array::from_fn(|i| active.get(i).cloned().unwrap_or_else(RegevPk::padding))
    }

    /// Full in-channel fixture: 3 real key pairs, real balance encryptions, a real E-1 STARK at
    /// RegevSecurityLevel::Test, and prev/next states wired per the v2 transition rules.
    struct InChannelFixture {
        witness: InChannelTransferUpdateWitness,
        sks: Vec<RegevSk>,
    }

    fn signatures_for(record: &ChannelRecord) -> Vec<MemberSignature> {
        // pad-to-MAX D6: only the ACTIVE members (0..member_count) sign.
        record
            .member_pk_gs
            .iter()
            .enumerate()
            .take(record.member_count as usize)
            .map(|(idx, hash)| MemberSignature {
                member_slot: idx as u8,
                pk_g: *hash,
                signature: vec![1 + idx as u8],
            })
            .collect()
    }

    fn in_channel_fixture() -> InChannelFixture {
        let mut rng = SmallRng::seed_from_u64(2024);
        let channel_id = ChannelId::new(5).unwrap();
        let (pk0, sk0) = channel_keygen(&mut rng);
        let (pk1, sk1) = channel_keygen(&mut rng);
        let (pk2, sk2) = channel_keygen(&mut rng);
        // pad-to-MAX D6: 3 active members + padding pks.
        let pks = pad_pks(&[pk0, pk1, pk2]);

        let record = ChannelRecord {
            channel_id,
            member_count: 3,
            delegate_count: 0,
            member_pk_gs: pad_hashes(&[
                pubkey_hash(10),
                pubkey_hash(20),
                pubkey_hash(30),
            ]),
            member_pubkeys_root: Bytes32::from_u32_slice(&[1, 1, 1, 1, 0, 0, 0, 0]).unwrap(),
            bp_member_slot: 0,
            special_close_penalty: U256::from(7u32),
            close_freeze_nonce: 0,
            status: ChannelStatus::Active,
            regev_pk_root: regev_pk_root(&pks),
        };

        // Balances: member0 (sender) holds 50, member1 (recipient) holds 10, member2 holds 30.
        let before_s = encrypt_amount(&mut rng, &pks[0], 50).unwrap();
        let before_r = encrypt_amount(&mut rng, &pks[1], 10).unwrap();
        let before_t = encrypt_amount(&mut rng, &pks[2], 30).unwrap();
        // Transfer 7 from member0 to member1.
        let enc_amount = encrypt_amount(&mut rng, &pks[1], 7).unwrap();
        let after_s = encrypt_amount(&mut rng, &pks[0], 43).unwrap();
        let after_r = add_ciphertexts(&before_r.0, &enc_amount.0).unwrap();

        let proof = prove_channel_tx(
            RegevSecurityLevel::Test,
            &pks[0],
            &pks[1],
            (&before_s.0, &before_s.1),
            (&enc_amount.0, &enc_amount.1),
            (&after_s.0, &after_s.1),
        )
        .unwrap();

        let fund = ChannelFund {
            channel_id,
            amount: U256::from(100u32),
            intmax_state_root: Bytes32::default(),
        };
        let prev_state = ChannelState {
            channel_id,
            epoch: 1,
            small_block_number: 0,
            close_freeze_nonce: 0,
            channel_fund: fund.clone(),
            balance_state: BalanceState {
                channel_id,
                member_count: 3,
                delegate_count: 0,
                enc_balances: BalanceState::pad_enc_balances(&[
                    before_s.0.clone(),
                    before_r.0.clone(),
                    before_t.0.clone(),
                ]),
                settled_tx_chain: Bytes32::default(),
                state_version: 3,
                pending_adds: BalanceState::pad_pending_adds(&[0, 2, 0]),
            },
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::default(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: signatures_for(&record),
        }
        .with_computed_digest();
        let next_state = ChannelState {
            epoch: 2,
            balance_state: BalanceState {
                channel_id,
                member_count: 3,
                delegate_count: 0,
                enc_balances: BalanceState::pad_enc_balances(&[
                    after_s.0.clone(),
                    after_r.clone(),
                    before_t.0.clone(),
                ]),
                settled_tx_chain: Bytes32::default(),
                state_version: 4,
                pending_adds: BalanceState::pad_pending_adds(&[0, 3, 0]),
            },
            prev_digest: prev_state.digest,
            ..prev_state.clone()
        }
        .with_computed_digest();

        let channel_tx = ChannelTx {
            recipient_pk_g: pubkey_hash(20),
            enc_amount: enc_amount.0,
            nonce: Bytes32::from_u32_slice(&[7, 7, 7, 7, 0, 0, 0, 0]).unwrap(),
            channel_tx_zkp: ChannelProofEnvelope {
                role: TransitionProofRole::ChannelStateUpdate,
                backend: ProofBackend::Plonky3,
                proof,
            },
            sender_pk_g: pubkey_hash(10),
            sender_hash_sig: vec![1, 2, 3],
            sender_pk_b: pubkey_hash(40),
        };

        InChannelFixture {
            witness: InChannelTransferUpdateWitness {
                channel_record: record,
                regev_pks: pks,
                prev_state,
                next_state,
                channel_tx,
                sender_index: 0,
                recipient_index: 1,
                recipient_sk: None,
                expected_amount: None,
            },
            sks: vec![sk0, sk1, sk2],
        }
    }

    const VERIFIER: RealRegevProofVerifier = RealRegevProofVerifier {
        level: RegevSecurityLevel::Test,
    };

    #[test]
    fn in_channel_transfer_happy_path_with_real_zkp() {
        let fixture = in_channel_fixture();
        let pis = fixture.witness.verify(&VERIFIER).unwrap();
        assert_eq!(pis.kind, ChannelTransitionKind::InChannelTransfer);
        assert_eq!(pis.amount, 0, "in-channel amounts stay hidden");
        assert_eq!(pis.prev_state_version, 3);
        assert_eq!(pis.next_state_version, 4);
        assert_eq!(pis.h2_tag, Bytes32::default());
    }

    #[test]
    fn in_channel_transfer_recipient_decryption_check() {
        let mut fixture = in_channel_fixture();
        // The recipient (member 1) decrypts the amount and their updated balance.
        fixture.witness.recipient_sk = Some(fixture.sks[1].clone());
        fixture.witness.expected_amount = Some(7);
        fixture.witness.verify(&VERIFIER).unwrap();

        // A wrong expected amount must be rejected.
        fixture.witness.expected_amount = Some(8);
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidDecryption(_))
        ));
    }

    #[test]
    fn in_channel_transfer_rejects_version_skip() {
        let mut fixture = in_channel_fixture();
        fixture.witness.next_state.balance_state.state_version += 1;
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidStateVersion(_))
        ));
    }

    #[test]
    fn in_channel_transfer_rejects_nonzero_h2_tag() {
        let mut fixture = in_channel_fixture();
        fixture.witness.next_state.h2_tag =
            Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidH2Tag(_))
        ));
    }

    #[test]
    fn in_channel_transfer_rejects_tampered_recipient_slot() {
        let mut fixture = in_channel_fixture();
        // Re-add the amount a second time (double credit) — public recomputation catches it.
        let double = add_ciphertexts(
            &fixture.witness.next_state.balance_state.enc_balances[1],
            &fixture.witness.channel_tx.enc_amount,
        )
        .unwrap();
        fixture.witness.next_state.balance_state.enc_balances[1] = double;
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidCiphertextTransition(_))
        ));
    }

    #[test]
    fn in_channel_transfer_rejects_pending_adds_at_budget() {
        let mut fixture = in_channel_fixture();
        // Recipient slot already at the refresh budget: the add MUST be refused (D3).
        fixture.witness.prev_state.balance_state.pending_adds[1] = MAX_HOMO_ADDS_BEFORE_REFRESH;
        fixture.witness.prev_state = fixture.witness.prev_state.clone().with_computed_digest();
        fixture.witness.next_state.balance_state.pending_adds[1] = MAX_HOMO_ADDS_BEFORE_REFRESH + 1;
        fixture.witness.next_state.prev_digest = fixture.witness.prev_state.digest;
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        // Either the budget gate or the next-state validate() (pending_adds > MAX) must fire.
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidPendingAdds(_)
                | ChannelStateUpdateError::InvalidCiphertextTransition(_))
        ));
    }

    #[test]
    fn in_channel_transfer_rejects_wrong_pk_root() {
        let mut fixture = in_channel_fixture();
        fixture.witness.channel_record.regev_pk_root =
            Bytes32::from_u32_slice(&[9, 9, 9, 9, 0, 0, 0, 0]).unwrap();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidRegevPkRoot(_))
        ));
    }

    #[test]
    fn in_channel_transfer_requires_plonky3_state_update_envelope() {
        let mut fixture = in_channel_fixture();
        fixture.witness.channel_tx.channel_tx_zkp.backend = ProofBackend::Plonky2;
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidProofBackend { .. })
        ));
        let mut fixture = in_channel_fixture();
        fixture.witness.channel_tx.channel_tx_zkp.role = TransitionProofRole::IntmaxTransport;
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidProofRole { .. })
        ));
    }

    #[test]
    fn in_channel_transfer_rejects_tampered_proof_bytes() {
        let mut fixture = in_channel_fixture();
        let len = fixture.witness.channel_tx.channel_tx_zkp.proof.len();
        fixture.witness.channel_tx.channel_tx_zkp.proof[len / 2] ^= 0x01;
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::ProofVerification(_))
        ));
    }
}
