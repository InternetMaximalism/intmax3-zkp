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
        balance_state::{BalanceState, settled_tx_chain_push},
        channel::{
            ChannelId, ChannelRecord, ChannelState, ChannelTransitionKind, ChannelTx,
            InterChannelTx, MerkleInclusionProof, ProofBackend, TransitionProofRole,
            burn_descriptor, l1_deposit_import_digest, token_register_next_state,
            validate_all_member_signatures, validate_member_signature_slots,
        },
    },
    constants::{MAX_CHANNEL_MEMBERS, MAX_CHANNEL_TOKENS},
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
    /// Per-token fund view (multitoken Phase 2b, TM-6/TM-7): the FULL `ChannelFund.amounts`
    /// vector before/after the transition, aligned to the H1-committed `token_registry` (local
    /// slot t = amounts\[t\]). ALWAYS full `MAX_CHANNEL_TOKENS` width — both in memory and in
    /// `digest()` (10 × 8 = 80 fixed u32 limbs per side; TM-11 fixed-width discipline), matching
    /// how the transition verifiers now move funds per token.
    pub channel_fund_before: [U256; MAX_CHANNEL_TOKENS],
    pub channel_fund_after: [U256; MAX_CHANNEL_TOKENS],
    pub unallocated_before: U256,
    pub unallocated_after: U256,
    pub shared_nullifier_before: Bytes32,
    pub shared_nullifier_after: Bytes32,
    pub transition_digest: Bytes32,
}

impl ChannelStateUpdatePublicInputs {
    /// Keccak digest of the PI word stream. LAYOUT (multitoken Phase 2b): the two former 8-limb
    /// `channel_fund_{before,after}` scalars are widened IN PLACE to the flat, ALWAYS-full-width
    /// 80-limb `amounts[0..10]` vectors (before at the former before position, after at the
    /// former after position) — same fixed-width injective discipline as the IMCH/IMCI amount
    /// segment widening (each field keeps its own fixed-width slot; no length prefixes, so the
    /// stream stays prefix-free per field). This digest has no domain word and is not signed —
    /// it is the transport-proof PI hash rebuilt by both sides from independently checked data.
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
            self.channel_fund_before
                .iter()
                .flat_map(U256::to_u32_vec)
                .collect(),
            self.channel_fund_after
                .iter()
                .flat_map(U256::to_u32_vec)
                .collect(),
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
    /// (abstract2 §3.1 "self-component decryption verification"). Must be paired with
    /// `expected_amount`.
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

/// L1 deposit import into an open channel (mid-channel top-up).
/// Trust anchor: the `receive_deposit` balance proof verified externally via
/// `verify_channel_backing`; no transport proof needed (unlike `InterChannelFundImport`).
#[derive(Clone, Debug)]
pub struct L1DepositImportUpdateWitness {
    pub channel_record: ChannelRecord,
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    pub amount: u64,
    pub deposit_nullifier: Bytes32,
    /// BASE-layer `token_index` of the imported L1 deposit (spec.md §1.2 — no longer dropped;
    /// detail2 §N-5, TM-7). Bound into the IMLD-v2 transition digest as its own limb.
    pub token_index: u32,
    pub depositor_slot: usize,
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
    /// LOCAL token position being refreshed (detail2 §B-3 × §N — TM-13: refreshes are per
    /// (member, token)). Must be an ACTIVE registry position (`< token_count`); the verify
    /// proves the ct replacement + counter reset happen at EXACTLY this position and every
    /// other position of the member's row (ciphertexts AND counters) is frozen.
    pub token_slot: usize,
    pub refresh_proof: ChannelProofEnvelope,
}

/// Witness for a `ChannelTransition::TokenRegister` (detail2 §N-1, TM-1/TM-9 — Phase 4
/// dispatch): append the BASE `token_index` at local position `token_count`. Carries NO
/// balance-state ZKP (`ChannelTransitionKind::required_state_backend()` is `None`): a
/// registration mutates no ciphertext — the registry lives only in the H1 header, so the
/// soundness gate is this witness verify (rebuild-equality against the canonical
/// `token_register_next_state`) plus the N-of-N member signatures over the next state, whose H1
/// commits the new registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenRegisterUpdateWitness {
    pub channel_record: ChannelRecord,
    pub prev_state: ChannelState,
    pub next_state: ChannelState,
    /// The BASE token_index being registered (the `TokenRegister` transition payload).
    pub token_index: u32,
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
        // Stage 3: an in-channel transfer is not a settle — the accumulator root is unchanged.
        require_accumulator_unchanged(
            self.prev_state.balance_state.settled_tx_accumulator_root,
            self.next_state.balance_state.settled_tx_accumulator_root,
        )?;
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
        // P3: the SENDER authorization is now the BabyBear hash-sig proof. This witness layer
        // checks it is PRESENT and that the claimed pk_b is canonical; the full hash-sig
        // verification + A11 two-key membership binding (m == decompose(tx_digest), pk_b PV
        // == sender_pk_b, and (pk_g, pk_b, regev_pk) ∈ one registered MemberLeaf) is
        // performed by the channel-tx acceptance path
        // (`wallet_core::verify_channel_tx_sender_hash_sig`), which has the authenticated
        // channel member set this circuit-statement layer does not carry.
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
            self.channel_tx.token_slot,
            self.channel_tx.sender_pk_g,
            self.channel_tx.recipient_pk_g,
        );
        // (e-0) TM-8: the SIGNED token slot must be an active registry position of the signed
        // prev state. Defense in depth: the layout bound (< MAX_CHANNEL_TOKENS) is checked
        // explicitly BEFORE the token_count bound, even though `validate()` already forces
        // `token_count <= MAX_CHANNEL_TOKENS` — the slot indexes fixed-width rows below and must
        // never rely on a transitive argument for its range.
        let token_slot = self.channel_tx.token_slot as usize;
        if token_slot >= MAX_CHANNEL_TOKENS {
            return Err(ChannelStateUpdateError::InvalidCiphertextTransition(
                format!(
                    "token_slot {token_slot} out of layout range (>= MAX_CHANNEL_TOKENS = \
                     {MAX_CHANNEL_TOKENS}, TM-8)"
                ),
            ));
        }
        if token_slot >= self.prev_state.balance_state.token_count as usize {
            return Err(ChannelStateUpdateError::InvalidCiphertextTransition(
                format!(
                    "token_slot {token_slot} out of range (>= token_count {}, TM-8)",
                    self.prev_state.balance_state.token_count
                ),
            ));
        }
        // (e) Public ciphertext recomputation at the SIGNED token position (TM-2 binding triple,
        // legs 2+3 natively): the recipient's `token_slot` position is the homomorphic sum;
        // every other position of BOTH involved rows and every uninvolved slot row is
        // bit-identical.
        let expected_recipient_ct = add_ciphertexts(
            &self.prev_state.balance_state.enc_balances[self.recipient_index][token_slot],
            &self.channel_tx.enc_amount,
        )
        .map_err(|err| ChannelStateUpdateError::InvalidCiphertextTransition(err.to_string()))?;
        if self.next_state.balance_state.enc_balances[self.recipient_index][token_slot]
            != expected_recipient_ct
        {
            return Err(ChannelStateUpdateError::InvalidCiphertextTransition(
                "recipient position must equal add_ciphertexts(prev_recipient_ct, enc_amount)"
                    .to_string(),
            ));
        }
        ensure_row_unchanged_except(
            &self.prev_state,
            &self.next_state,
            self.recipient_index,
            token_slot,
        )?;
        ensure_row_unchanged_except(
            &self.prev_state,
            &self.next_state,
            self.sender_index,
            token_slot,
        )?;
        for index in 0..MAX_CHANNEL_MEMBERS {
            if index != self.sender_index && index != self.recipient_index {
                ensure_slot_unchanged(&self.prev_state, &self.next_state, index)?;
            }
        }
        // (f) D3 add counters per (slot, token) — TM-13: recipient position +1 under the refresh
        // budget (its row otherwise frozen), sender position reset (fresh re-encryption, its row
        // otherwise frozen), uninvolved slots' rows unchanged.
        require_pending_add_increment(
            &self.prev_state,
            &self.next_state,
            self.recipient_index,
            token_slot,
        )?;
        if self.next_state.balance_state.pending_adds[self.sender_index][token_slot] != 0 {
            return Err(ChannelStateUpdateError::InvalidPendingAdds(
                "sender position is freshly re-encrypted; its pending_adds must reset to 0"
                    .to_string(),
            ));
        }
        require_pending_adds_unchanged_except(
            &self.prev_state,
            &self.next_state,
            self.sender_index,
            token_slot,
        )?;
        for index in 0..MAX_CHANNEL_MEMBERS {
            if index != self.sender_index && index != self.recipient_index {
                require_pending_adds_unchanged(&self.prev_state, &self.next_state, index)?;
            }
        }
        // (g) Mandatory E-1 channelTxZKP, statement rebuilt from checked data. TM-2 leg 4: E-1
        // is handed exactly the (prev, after) ciphertexts selected by the SIGNED token_slot.
        let statement = RegevStatement::ChannelTx {
            sender_pk: self.regev_pks[self.sender_index].clone(),
            recipient_pk: self.regev_pks[self.recipient_index].clone(),
            before: self.prev_state.balance_state.enc_balances[self.sender_index][token_slot]
                .clone(),
            enc_amount: self.channel_tx.enc_amount.clone(),
            after: self.next_state.balance_state.enc_balances[self.sender_index][token_slot]
                .clone(),
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
                &self.next_state.balance_state.enc_balances[self.recipient_index][token_slot],
            )
            .map_err(|err| {
                ChannelStateUpdateError::InvalidDecryption(format!(
                    "next recipient balance position does not decrypt: {err}"
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
            // Per-token PI view (Phase 2b): the FULL fund vectors, registry-aligned (see the
            // field doc on `ChannelStateUpdatePublicInputs`).
            channel_fund_before: self.prev_state.channel_fund.amounts,
            channel_fund_after: self.next_state.channel_fund.amounts,
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
        // Normal C2C pushes the tx leaf. A burn pushes the amount-committing IMBD descriptor that
        // is also the base Transfer's aux_data; this is the N-of-N-signed half of F-AUX-1.
        let tx_leaf = self
            .inter_channel_tx
            .tx_leaf_hash()
            .map_err(|err| ChannelStateUpdateError::InvalidSettledTxChain(err.to_string()))?;
        let chain_leaf = if self.inter_channel_tx.destination_channel_id.channel_id()
            == crate::constants::BURN_CHANNEL_ID as u32
        {
            burn_descriptor(
                tx_leaf,
                receiver_delta.receiver_pk_g,
                self.inter_channel_tx.token_index,
                u64_to_u256(self.amount),
            )
        } else {
            tx_leaf
        };
        require_chain_push(&self.prev_state, &self.next_state, chain_leaf)?;
        // Stage 3: the STRONG tx_hash-binding accumulator insertion check
        // (`require_accumulator_push`) is run by the WALLET co-signer with the persisted tree in
        // hand (`build_inter_channel_send`) — the transition witnesses here carry only the
        // prev/next `BalanceState` scalars, not the accumulator FRONTIER needed to verify
        // an incremental insertion, so the binding insertion check cannot live here. (The
        // finalized accumulator root is ultimately attested by the N-of-N signature over
        // H1.) The transition CIRCUITS do NOT change.
        // TM-6 (source-side registry resolution, §N-4): the SIGNED descriptor carries the BASE
        // token_index; resolve it against THIS channel's OWN H1-committed registry
        // (`registry[ts] == token_index && ts < token_count`; unregistered ⇒ reject
        // fail-closed). The fund decreases by the public amount at EXACTLY that local position;
        // every other fund position is proven frozen.
        let token_slot = resolve_token_slot(
            &self.prev_state.balance_state,
            self.inter_channel_tx.token_index,
        )?;
        // TM-16 obligation 5 (source-side symmetry): the descriptor's tx_hash must be the
        // token-bearing recompute over the SAME signed token_index the resolution above admitted.
        require_token_bearing_tx_hash(&self.inter_channel_tx)?;
        if self.next_state.channel_fund.amounts[token_slot] + u64_to_u256(self.amount)
            != self.prev_state.channel_fund.amounts[token_slot]
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "channel fund must decrease by transfer amount at the resolved token position"
                    .to_string(),
            ));
        }
        ensure_funds_unchanged_except(&self.prev_state, &self.next_state, token_slot)?;
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
        let sender_index =
            member_slot_index(&self.channel_record, self.inter_channel_tx.source_pk_g)?;
        // TM-2/TM-6: the sender rebind happens at the REGISTRY-RESOLVED token position; all
        // other positions of the sender row are frozen (the "others unchanged" leg), and every
        // uninvolved row is bit-identical.
        for index in 0..MAX_CHANNEL_MEMBERS {
            if index != sender_index {
                ensure_slot_unchanged(&self.prev_state, &self.next_state, index)?;
                require_pending_adds_unchanged(&self.prev_state, &self.next_state, index)?;
            }
        }
        ensure_row_unchanged_except(&self.prev_state, &self.next_state, sender_index, token_slot)?;
        if self.next_state.balance_state.pending_adds[sender_index][token_slot] != 0 {
            return Err(ChannelStateUpdateError::InvalidPendingAdds(
                "sender position is freshly re-encrypted; its pending_adds must reset to 0"
                    .to_string(),
            ));
        }
        require_pending_adds_unchanged_except(
            &self.prev_state,
            &self.next_state,
            sender_index,
            token_slot,
        )?;
        let statement = RegevStatement::ChannelUpdate {
            sender_pk: self.regev_pks[sender_index].clone(),
            recipient_pk: self.destination_recipient_pk.clone(),
            before: self.prev_state.balance_state.enc_balances[sender_index][token_slot].clone(),
            after: self.next_state.balance_state.enc_balances[sender_index][token_slot].clone(),
            sender_delta: self.inter_channel_tx.sender_delta_ct.clone(),
            receiver_delta: receiver_delta.amount.clone(),
            amount: self.amount,
            // TM-6: the E-2 transcript binds the SAME signed base token_index the registry
            // resolution above admitted.
            token_index: self.inter_channel_tx.token_index,
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
            // Per-token PI view (Phase 2b): the FULL fund vectors, registry-aligned (see the
            // field doc on `ChannelStateUpdatePublicInputs`).
            channel_fund_before: self.prev_state.channel_fund.amounts,
            channel_fund_after: self.next_state.channel_fund.amounts,
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
        // One incoming base transfer advances the receiver's live balance IVC exactly once. Its
        // merkle-bound aux_data is the canonical tx leaf, so the channel import must fold that
        // same tag; `tx_hash` remains the post-close accumulator identifier.
        let settle_tag = self
            .inter_channel_tx
            .tx_leaf_hash()
            .map_err(|err| ChannelStateUpdateError::InvalidSettledTxChain(err.to_string()))?;
        require_chain_push(&self.prev_state, &self.next_state, settle_tag)?;
        // Stage 3: the fund import is a settle advancement on the RECEIVING channel — its
        // accumulator MUST absorb the incoming `tx_hash` (this is the insertion a post-close claim
        // against THIS closed channel proves inclusion against). The STRONG tx_hash-binding push
        // check runs in the WALLET co-signer (`build_inter_channel_credit`) with the persisted
        // tree; the witness here lacks the frontier, so it cannot verify the incremental
        // insertion.
        // TM-6 (destination-side registry resolution, §N-4): the signed descriptor's BASE
        // token_index must resolve against the DESTINATION channel's OWN H1-committed registry
        // (unregistered ⇒ reject fail-closed), and the fund grows at exactly that local
        // position; every other fund position is proven frozen.
        let token_slot = resolve_token_slot(
            &self.prev_state.balance_state,
            self.inter_channel_tx.token_index,
        )?;
        // TM-16 obligation 1 (destination gate leg): the accumulator's `tx_hash` must be the
        // token-bearing recompute from the descriptor's own fields — this is what makes its
        // post-close-claim anchor commit the token this import credits (the chain itself folds
        // the base transfer's `tx_leaf`, as checked above).
        require_token_bearing_tx_hash(&self.inter_channel_tx)?;
        if self.next_state.channel_fund.amounts[token_slot]
            != self.prev_state.channel_fund.amounts[token_slot] + u64_to_u256(self.amount)
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "channel fund must increase by imported amount at the resolved token position"
                    .to_string(),
            ));
        }
        ensure_funds_unchanged_except(&self.prev_state, &self.next_state, token_slot)?;
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
            // Per-token PI view (Phase 2b): the FULL fund vectors, registry-aligned (see the
            // field doc on `ChannelStateUpdatePublicInputs`).
            channel_fund_before: self.prev_state.channel_fund.amounts,
            channel_fund_after: self.next_state.channel_fund.amounts,
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

impl L1DepositImportUpdateWitness {
    pub fn verify(&self) -> Result<ChannelStateUpdatePublicInputs, ChannelStateUpdateError> {
        verify_state_linkage(&self.prev_state, &self.next_state)?;
        verify_balance_state_common(&self.channel_record, &self.prev_state, &self.next_state)?;
        verify_next_state_signatures(&self.channel_record, &self.next_state)?;
        require_h2_zero(&self.next_state)?;
        require_chain_push(&self.prev_state, &self.next_state, self.deposit_nullifier)?;
        // TM-7 (three-way binding, general resolution — §N-5): the deposit's base token_index
        // must resolve via the SIGNED registry (`registry[t] == token_index && t < token_count`)
        // to the local slot whose fund grows; an unregistered token_index is REJECTED
        // fail-closed (never silently credited to token 0). Every other fund position is proven
        // frozen. Leg (b) of the binding — the depositor leaf's position-t ciphertext being the
        // credited one — is enforced by the co-signer gate's REBUILD-EQUALITY over the bundle
        // step (`wallet_core::verify_l1_deposit_import_transition` reconstructs the canonical
        // `l1_deposit_bundle_state` at the SAME resolved t and requires digest equality with
        // the proposal); THIS fund-import step leaves every leaf bit-identical (checked below).
        let token_slot = resolve_token_slot(&self.prev_state.balance_state, self.token_index)?;
        if self.next_state.channel_fund.amounts[token_slot]
            != self.prev_state.channel_fund.amounts[token_slot] + u64_to_u256(self.amount)
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "channel fund must increase by deposited amount at the resolved token position"
                    .to_string(),
            ));
        }
        ensure_funds_unchanged_except(&self.prev_state, &self.next_state, token_slot)?;
        if self.next_state.unallocated_confirmed_incoming
            != self.prev_state.unallocated_confirmed_incoming + u64_to_u256(self.amount)
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(
                "unallocated_confirmed_incoming must increase by deposited amount".to_string(),
            ));
        }
        for index in 0..MAX_CHANNEL_MEMBERS {
            ensure_slot_unchanged(&self.prev_state, &self.next_state, index)?;
            require_pending_adds_unchanged(&self.prev_state, &self.next_state, index)?;
        }
        ensure_different_root(
            "shared_native_nullifier_root",
            self.prev_state.shared_native_nullifier_root,
            self.next_state.shared_native_nullifier_root,
        )?;
        let depositor_pk_g = self.channel_record.member_pk_gs[self.depositor_slot];
        let transition_digest = l1_deposit_import_digest(
            self.prev_state.channel_id,
            self.deposit_nullifier,
            self.token_index,
            self.amount,
            self.depositor_slot as u16,
        );
        let public_inputs = ChannelStateUpdatePublicInputs {
            kind: ChannelTransitionKind::L1DepositImport,
            channel_id: self.prev_state.channel_id,
            prev_state_digest: self.prev_state.digest,
            next_state_digest: self.next_state.digest,
            amount: self.amount,
            prev_state_version: self.prev_state.balance_state.state_version,
            next_state_version: self.next_state.balance_state.state_version,
            h2_tag: self.next_state.h2_tag,
            prev_settled_tx_chain: self.prev_state.balance_state.settled_tx_chain,
            next_settled_tx_chain: self.next_state.balance_state.settled_tx_chain,
            receiver_entry_count: 0,
            sender_user_id_hash: hash_member(depositor_pk_g),
            receiver_user_id_hash: hash_member(depositor_pk_g),
            // Per-token PI view (Phase 2b): the FULL fund vectors, registry-aligned (see the
            // field doc on `ChannelStateUpdatePublicInputs`).
            channel_fund_before: self.prev_state.channel_fund.amounts,
            channel_fund_after: self.next_state.channel_fund.amounts,
            unallocated_before: self.prev_state.unallocated_confirmed_incoming,
            unallocated_after: self.next_state.unallocated_confirmed_incoming,
            shared_nullifier_before: self.prev_state.shared_native_nullifier_root,
            shared_nullifier_after: self.next_state.shared_native_nullifier_root,
            transition_digest,
        };
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
        // The preceding fund-import step already folded this one logical incoming transfer. The
        // bundle merely applies its ciphertext delta and must not advance either settle
        // commitment again.
        require_chain_unchanged(&self.prev_state, &self.next_state)?;
        require_accumulator_unchanged(
            self.prev_state.balance_state.settled_tx_accumulator_root,
            self.next_state.balance_state.settled_tx_accumulator_root,
        )?;
        // Recipient position: public homomorphic-add recomputation; other positions and slots
        // untouched.
        // TM-6 (destination-side registry resolution, §N-4): the credit lands at EXACTLY the
        // local position this channel's OWN H1-committed registry maps the signed base
        // token_index to (unregistered ⇒ reject fail-closed); all other positions of the
        // recipient row are proven frozen (TM-2 "others unchanged" leg), which is also what
        // makes the unversioned per-tx IMCK nullifier sound (one descriptor can never credit
        // two token positions — see `PostCloseIncomingClaim::derive_shared_native_nullifier`).
        let token_slot = resolve_token_slot(
            &self.prev_state.balance_state,
            self.inter_channel_tx.token_index,
        )?;
        // TM-16 defense in depth: even though the accumulator insertion occurs in the import step,
        // the bundle still rechecks the token-bearing descriptor it applies.
        require_token_bearing_tx_hash(&self.inter_channel_tx)?;
        let expected_recipient_ct = add_ciphertexts(
            &self.prev_state.balance_state.enc_balances[self.recipient_index][token_slot],
            &receiver_delta.amount,
        )
        .map_err(|err| ChannelStateUpdateError::InvalidCiphertextTransition(err.to_string()))?;
        if self.next_state.balance_state.enc_balances[self.recipient_index][token_slot]
            != expected_recipient_ct
        {
            return Err(ChannelStateUpdateError::InvalidCiphertextTransition(
                "recipient position must equal add_ciphertexts(prev_recipient_ct, receiver_delta)"
                    .to_string(),
            ));
        }
        ensure_row_unchanged_except(
            &self.prev_state,
            &self.next_state,
            self.recipient_index,
            token_slot,
        )?;
        for index in 0..MAX_CHANNEL_MEMBERS {
            if index != self.recipient_index {
                ensure_slot_unchanged(&self.prev_state, &self.next_state, index)?;
                require_pending_adds_unchanged(&self.prev_state, &self.next_state, index)?;
            }
        }
        require_pending_add_increment(
            &self.prev_state,
            &self.next_state,
            self.recipient_index,
            token_slot,
        )?;
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
            // TM-6: the E-2 transcript binds the SAME signed base token_index this side's
            // registry resolution admitted.
            token_index: self.inter_channel_tx.token_index,
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
                &self.next_state.balance_state.enc_balances[self.recipient_index][token_slot],
            )
            .map_err(|err| {
                ChannelStateUpdateError::InvalidDecryption(format!(
                    "next recipient balance position does not decrypt: {err}"
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
            // Per-token PI view (Phase 2b): the FULL fund vectors, registry-aligned (see the
            // field doc on `ChannelStateUpdatePublicInputs`).
            channel_fund_before: self.prev_state.channel_fund.amounts,
            channel_fund_after: self.next_state.channel_fund.amounts,
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
        // Stage 3: a balance refresh is not a settle — the accumulator root is unchanged.
        require_accumulator_unchanged(
            self.prev_state.balance_state.settled_tx_accumulator_root,
            self.next_state.balance_state.settled_tx_accumulator_root,
        )?;
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
        // D3 × TM-13: the refresh resets the member's add counter (any value -> 0) at the
        // SELECTED token position; the other 9 positions of the member's row are frozen
        // fail-closed (ciphertexts AND counters). TM-8: the selector must be an active registry
        // position (layout bound checked first — see the in-channel path rationale).
        let token_slot = self.token_slot;
        if token_slot >= MAX_CHANNEL_TOKENS {
            return Err(ChannelStateUpdateError::InvalidCiphertextTransition(
                format!(
                    "refresh token_slot {token_slot} out of layout range (>= MAX_CHANNEL_TOKENS \
                     = {MAX_CHANNEL_TOKENS}, TM-8)"
                ),
            ));
        }
        if token_slot >= self.prev_state.balance_state.token_count as usize {
            return Err(ChannelStateUpdateError::InvalidCiphertextTransition(
                format!(
                    "refresh token_slot {token_slot} out of range (>= token_count {}, TM-8)",
                    self.prev_state.balance_state.token_count
                ),
            ));
        }
        if self.next_state.balance_state.pending_adds[self.member_index][token_slot] != 0 {
            return Err(ChannelStateUpdateError::InvalidPendingAdds(
                "refresh must reset the member's pending_adds to 0".to_string(),
            ));
        }
        require_pending_adds_unchanged_except(
            &self.prev_state,
            &self.next_state,
            self.member_index,
            token_slot,
        )?;
        ensure_row_unchanged_except(
            &self.prev_state,
            &self.next_state,
            self.member_index,
            token_slot,
        )?;
        let old_ct = &self.prev_state.balance_state.enc_balances[self.member_index][token_slot];
        let new_ct = &self.next_state.balance_state.enc_balances[self.member_index][token_slot];
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

        // Transition-digest preimage (multitoken Phase 2b): `token_slot` is appended as its OWN
        // canonical u32 limb after `member_index` (TM-15 own-limb discipline). In-place widening
        // under the retained IMRF word is sound here: this fixed-width preimage has exactly this
        // one hashing site, is never signed, and is never recomputed in-circuit or on L1 — it
        // only feeds the PI `transition_digest` both sides rebuild from checked data.
        let transition_digest = Bytes32::from_u32_slice(&solidity_keccak256(
            &[
                vec![
                    BALANCE_REFRESH_ZKP_DOMAIN,
                    self.member_index as u32,
                    token_slot as u32,
                ],
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
            // Per-token PI view (Phase 2b): the FULL fund vectors, registry-aligned (see the
            // field doc on `ChannelStateUpdatePublicInputs`).
            channel_fund_before: self.prev_state.channel_fund.amounts,
            channel_fund_after: self.next_state.channel_fund.amounts,
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

impl TokenRegisterUpdateWitness {
    /// Cosigner-side gate for a proposed `TokenRegister` transition (detail2 §N-1). MUST pass
    /// before ANY member signs the proposed next state.
    ///
    /// SECURITY (TM-1/TM-9): this kind — and ONLY this kind — bypasses the registry/token_count
    /// immutability equality of `verify_balance_state_common` (see the SECURITY comment there);
    /// in exchange it enforces (c) the exact append semantics via
    /// `BalanceState::verify_token_register_transition` (a single rebuild-equality covering
    /// EVERY BalanceState field: balances, counters, recipients, chain, accumulator,
    /// member/delegate counts, channel id), (d) an explicit freeze of every non-balance-state
    /// channel field, and (e) a whole-`ChannelState` rebuild-equality against the canonical
    /// deterministic builder `token_register_next_state` — the same
    /// builder-shared-with-the-gate pattern as the deposit-import bundle step. N-of-N member
    /// signatures over the next state (whose H1 header commits the new registry + token_count,
    /// TM-9) authorize the registration like any other transition.
    pub fn verify(&self) -> Result<ChannelStateUpdatePublicInputs, ChannelStateUpdateError> {
        // (a) State linkage (digest self-consistency both sides, prev_digest chaining, epoch+1).
        verify_state_linkage(&self.prev_state, &self.next_state)?;
        // (b) Registry-agnostic common checks: `validate()` on both sides (canonical
        //     ciphertexts, D3 budgets, TM-8 fail-close), channel-id consistency, strict
        //     state_version+1, recipients immutability (B-1b).
        verify_balance_state_shared(&self.channel_record, &self.prev_state, &self.next_state)?;
        // (c) The registry append itself (TM-1): next.balance_state is EXACTLY prev +
        //     apply_token_register(token_index) — append at prev.token_count only, injectivity
        //     of the new base index against the active prefix, count+1, everything else
        //     untouched (one rebuild-equality covers all fields).
        BalanceState::verify_token_register_transition(
            &self.prev_state.balance_state,
            &self.next_state.balance_state,
            self.token_index,
        )
        .map_err(|err| ChannelStateUpdateError::InvalidStateLinkage(err.to_string()))?;
        // (d) FULL FREEZE of every non-balance-state channel field: a registration is a
        //     header-only state change (§N-1) — no fund movement, no settle, no small block.
        require_h2_zero(&self.next_state)?;
        require_chain_unchanged(&self.prev_state, &self.next_state)?;
        require_accumulator_unchanged(
            self.prev_state.balance_state.settled_tx_accumulator_root,
            self.next_state.balance_state.settled_tx_accumulator_root,
        )?;
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
        if self.next_state.small_block_number != self.prev_state.small_block_number {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "small_block_number must remain unchanged across a TokenRegister transition"
                    .to_string(),
            ));
        }
        if self.next_state.close_freeze_nonce != self.prev_state.close_freeze_nonce {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "close_freeze_nonce must remain unchanged across a TokenRegister transition"
                    .to_string(),
            ));
        }
        // (e) Whole-state rebuild-equality against the canonical builder (defense in depth: any
        //     residual field the explicit checks above might miss diverges the recomputed
        //     signing digest — signatures are collected on top of the canonical state, so they
        //     are excluded from the comparison).
        let mut expected = token_register_next_state(&self.prev_state, self.token_index)
            .map_err(|err| ChannelStateUpdateError::InvalidStateLinkage(err.to_string()))?;
        expected.member_signatures = self.next_state.member_signatures.clone();
        if expected != self.next_state {
            return Err(ChannelStateUpdateError::InvalidStateLinkage(
                "TokenRegister next state is not the canonical token_register_next_state(prev, \
                 token_index) (full-freeze rebuild-equality, TM-1)"
                    .to_string(),
            ));
        }
        // (f) All-member signatures on the next state (structural completeness; the REAL
        //     SingleSig verification is `verify_all_signatures` once the set is collected).
        verify_next_state_signatures(&self.channel_record, &self.next_state)?;

        Ok(ChannelStateUpdatePublicInputs {
            kind: ChannelTransitionKind::TokenRegister,
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
            sender_user_id_hash: Bytes32::default(),
            receiver_user_id_hash: Bytes32::default(),
            channel_fund_before: self.prev_state.channel_fund.amounts,
            channel_fund_after: self.next_state.channel_fund.amounts,
            unallocated_before: self.prev_state.unallocated_confirmed_incoming,
            unallocated_after: self.next_state.unallocated_confirmed_incoming,
            shared_nullifier_before: self.prev_state.shared_native_nullifier_root,
            shared_nullifier_after: self.next_state.shared_native_nullifier_root,
            // A TokenRegister has no independently-signed transition message: the payload
            // (token_index) is fully determined by the prev→next registry diff verified in (c),
            // and the H1 header of the SIGNED next state commits the new registry (TM-9). Bind
            // the PI to that signed digest.
            transition_digest: self.next_state.digest,
        })
    }
}

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
/// both sides, channel-id consistency, and the strict `state_version` increment. This is the
/// registry-agnostic core shared by ALL transition kinds INCLUDING `TokenRegister`; the
/// registry/token_count immutability equality lives in [`verify_balance_state_common`] (every
/// kind except `TokenRegister`) — see the SECURITY comment there.
fn verify_balance_state_shared(
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
    // SECURITY (B-1b): per-slot L1 exit addresses are IMMUTABLE across EVERY supported state
    // transition — recipient changes are NOT a supported transition. This runs in every
    // transition verifier (send / refresh / inter-channel send / fund import / bundle apply /
    // L1-deposit import all call verify_balance_state_common), so a proposed next state that
    // mutates ANY slot's recipient (including the proposer's own) is rejected fail-closed BEFORE
    // any cosigner signs it. A mutation would also flip that slot's leaf → slot-tree root → H1,
    // so an already-signed state cannot be reinterpreted either; this check closes the
    // remaining window (tricking cosigners into signing a redirected NEXT state).
    if prev_state.balance_state.recipients != next_state.balance_state.recipients {
        return Err(ChannelStateUpdateError::InvalidStateLinkage(
            "recipients must remain unchanged across a state transition (B-1b: recipient \
             changes are not a supported transition)"
                .to_string(),
        ));
    }
    Ok(())
}

/// [`verify_balance_state_shared`] PLUS the registry/token_count immutability equality — the
/// common path called by every transition verifier EXCEPT [`TokenRegisterUpdateWitness`].
///
/// SECURITY (TM-1/TM-9, security-review MAJOR 1): the token registry and token_count are
/// IMMUTABLE across every ordinary transition kind — the ONLY sanctioned way to change them is
/// the dedicated `TokenRegister` transition, dispatched through
/// [`TokenRegisterUpdateWitness::verify`] (Phase 4), which — and ONLY which — bypasses this
/// equality and instead enforces `BalanceState::verify_token_register_transition`
/// (append-at-token_count, injectivity, count+1) PLUS a full freeze of everything else
/// (balances, counters, funds, chain, accumulator, recipients — rebuild-equality against the
/// canonical `token_register_next_state`). Without this equality (mirroring the
/// recipients-immutability check above), a malicious proposer could bundle a registry remap or a
/// token_count bump into the next-state of any ordinary transfer/refresh/import and every
/// cosigner would sign it — re-pointing local token slots at a different base token's L1 escrow
/// under existing balances. Enforced unconditionally in this common path, which every transition
/// verifier other than TokenRegister calls.
fn verify_balance_state_common(
    record: &ChannelRecord,
    prev_state: &ChannelState,
    next_state: &ChannelState,
) -> Result<(), ChannelStateUpdateError> {
    verify_balance_state_shared(record, prev_state, next_state)?;
    if prev_state.balance_state.token_registry != next_state.balance_state.token_registry
        || prev_state.balance_state.token_count != next_state.balance_state.token_count
    {
        return Err(ChannelStateUpdateError::InvalidStateLinkage(
            "token_registry/token_count must remain unchanged across a state transition (TM-1/\
             TM-9: only a dedicated TokenRegister transition may change them)"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn verify_regev_pk_root(
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

// ---------------------------------------------------------------------------
// Stage 3 (post-close source-tx anchoring) — NATIVE off-chain co-signer checks for the settled-tx
// Merkle ACCUMULATOR. These are PURE NATIVE verification (NOT ZK constraints / circuit targets):
// the accumulator's faithfulness is attested by the EXISTING N-of-N co-signing — every honest
// co-signer runs these BEFORE signing the new H1, and the accumulator root rides in the signed H1
// (folded immediately after `settled_tx_chain`; see `BalanceState::h1`). The close circuit then
// verifies the N-of-N member signatures over the final H1, so the finalized accumulator root is
// signature-attested. The settle TRANSITION CIRCUITS do NOT change at all.
//
// SECURITY (leaf uniformity): the accumulator stores `tx_hash` UNIFORMLY at EVERY settle
// advancement (even where the hash CHAIN pushes `tx_leaf`), giving the post-close claim ONE
// canonical membership predicate (its `incoming_tx_hash`). The accumulator and `settled_tx_chain`
// are INDEPENDENT commitments storing DIFFERENT leaves.
// ---------------------------------------------------------------------------

/// Native co-signer check: `next_root` is EXACTLY the root after pushing `tx_hash` onto the prev
/// accumulator. The prev tree (the frontier) is required to compute an incremental insertion — a
/// root alone is insufficient. The caller (the wallet co-signer) holds the persisted per-channel
/// `IncrementalMerkleTree`. Returns `Ok` iff `Bytes32::from(push(prev_tree, tx_hash).get_root()) ==
/// next_root`.
///
/// SECURITY: this binds the inserted leaf to `tx_hash`, so a co-signer cannot be tricked into
/// signing an H1 whose accumulator root omits (or substitutes) the settle's `tx_hash`. The push
/// also asserts `len < 2^H` (capacity), inherited from `IncrementalMerkleTree::push`.
pub fn require_accumulator_push(
    prev_accumulator: &crate::utils::trees::incremental_merkle_tree::IncrementalMerkleTree<Bytes32>,
    tx_hash: Bytes32,
    next_root: Bytes32,
) -> Result<(), ChannelStateUpdateError> {
    let mut advanced = prev_accumulator.clone();
    advanced.push(tx_hash);
    let expected = Bytes32::from(advanced.get_root());
    if expected != next_root {
        return Err(ChannelStateUpdateError::InvalidSettledTxChain(format!(
            "settled_tx_accumulator_root must equal push(prev_accumulator, tx_hash): expected \
             {expected:?}, got {next_root:?}"
        )));
    }
    Ok(())
}

/// Native co-signer check: the accumulator root is UNCHANGED across an in-channel transfer or a
/// balance refresh (neither advances the settle history). Root-only (no tree needed): these
/// transitions must not touch the accumulator at all.
pub fn require_accumulator_unchanged(
    prev_root: Bytes32,
    next_root: Bytes32,
) -> Result<(), ChannelStateUpdateError> {
    if prev_root != next_root {
        return Err(ChannelStateUpdateError::InvalidSettledTxChain(
            "settled_tx_accumulator_root must remain unchanged for this transition kind"
                .to_string(),
        ));
    }
    Ok(())
}

/// The whole slot ROW (all `MAX_CHANNEL_TOKENS` ciphertext positions) must be bit-identical
/// prev -> next. Multi-token note: rows are full 10-wide vectors, so this single equality covers
/// every token position of an uninvolved slot (part of the TM-2 "others unchanged" obligation).
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

/// TM-2 (binding triple, "other 9 unchanged" leg): every ciphertext position of slot `index`
/// EXCEPT `token_slot` must be bit-identical prev -> next. Run on BOTH involved slots (sender and
/// recipient) so a transition signed for one token cannot smuggle a mutation into another
/// token's ciphertext of the same slot.
fn ensure_row_unchanged_except(
    prev_state: &ChannelState,
    next_state: &ChannelState,
    index: usize,
    token_slot: usize,
) -> Result<(), ChannelStateUpdateError> {
    for t in 0..MAX_CHANNEL_TOKENS {
        if t != token_slot
            && prev_state.balance_state.enc_balances[index][t]
                != next_state.balance_state.enc_balances[index][t]
        {
            return Err(ChannelStateUpdateError::InvalidCiphertextTransition(
                format!(
                    "balance slot {index} token position {t} must remain bit-identical (only \
                 token_slot {token_slot} may change, TM-2)"
                ),
            ));
        }
    }
    Ok(())
}

/// D3 enforcement at the application point, PER (slot, token) — TM-13: the receiving position's
/// counter must be strictly below the refresh budget BEFORE the add, must increment by exactly
/// 1, and every OTHER token position of the same slot must keep its counter (TM-2: pending_adds
/// increments only at `(recipient, token_slot)`).
fn require_pending_add_increment(
    prev_state: &ChannelState,
    next_state: &ChannelState,
    index: usize,
    token_slot: usize,
) -> Result<(), ChannelStateUpdateError> {
    let before = prev_state.balance_state.pending_adds[index][token_slot];
    let after = next_state.balance_state.pending_adds[index][token_slot];
    if before >= MAX_HOMO_ADDS_BEFORE_REFRESH {
        return Err(ChannelStateUpdateError::InvalidPendingAdds(format!(
            "slot {index} token {token_slot} has {before} pending adds; refresh required before \
             another add (D3)"
        )));
    }
    if after != before + 1 {
        return Err(ChannelStateUpdateError::InvalidPendingAdds(format!(
            "slot {index} token {token_slot} pending_adds must increment by 1 (before {before}, \
             after {after})"
        )));
    }
    require_pending_adds_unchanged_except(prev_state, next_state, index, token_slot)
}

/// The whole per-token counter ROW of slot `index` must be unchanged (all 10 positions).
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

/// Every counter position of slot `index` EXCEPT `token_slot` must be unchanged (TM-2/TM-13).
fn require_pending_adds_unchanged_except(
    prev_state: &ChannelState,
    next_state: &ChannelState,
    index: usize,
    token_slot: usize,
) -> Result<(), ChannelStateUpdateError> {
    for t in 0..MAX_CHANNEL_TOKENS {
        if t != token_slot
            && prev_state.balance_state.pending_adds[index][t]
                != next_state.balance_state.pending_adds[index][t]
        {
            return Err(ChannelStateUpdateError::InvalidPendingAdds(format!(
                "pending_adds[{index}][{t}] must remain unchanged (only token_slot {token_slot} \
                 may change)"
            )));
        }
    }
    Ok(())
}

/// SECURITY (TM-16 obligations 1/2/5): the descriptor-carried `tx_hash` — the settled-tx chain /
/// accumulator leaf and the post-close-claim anchor — must equal the token-bearing recompute
/// from the descriptor's OWN fields: `fold(ids(source, dest, token_index), fold(tx_tree_root,
/// tx_leaf))`. The token is single-sourced from `inter_channel_tx.token_index` (the SAME field
/// the registry resolutions and the E-2 IMU2 statement bind — obligation 2, no second wire
/// copy). Run by the SOURCE send witness (obligation 5, hygiene/symmetry) and by BOTH
/// destination witnesses (fund import + bundle apply) BEFORE their chain/accumulator absorb the
/// hash (obligation 1's gate leg): a source builder anchoring token X while the descriptor
/// resolves/credits token Y is rejected at absorb time, so the anchored leaf always commits the
/// token the destination actually credited.
fn require_token_bearing_tx_hash(
    inter_channel_tx: &InterChannelTx,
) -> Result<(), ChannelStateUpdateError> {
    let recomputed = inter_channel_tx
        .compute_tx_hash()
        .map_err(|err| ChannelStateUpdateError::InvalidSettledTxChain(err.to_string()))?;
    if recomputed != inter_channel_tx.tx_hash {
        return Err(ChannelStateUpdateError::InvalidSettledTxChain(
            "descriptor tx_hash != token-bearing recompute from (ids(src, dest, token_index), \
             tx_tree_root, tx_leaf) — rejecting fail-closed (TM-16)"
                .to_string(),
        ));
    }
    Ok(())
}

/// TM-6/TM-7 (fail-closed registry resolution, §N-4/§N-5): the unique ACTIVE local token slot t
/// with `token_registry[t] == token_index && t < token_count`. Uniqueness holds because
/// `validate()` (run by `verify_balance_state_common` before any resolution) enforces
/// injectivity of the active registry prefix (TM-1). An unregistered `token_index` is REJECTED —
/// value for a token this channel has not cosigned into its registry must never move.
fn resolve_token_slot(
    balance_state: &crate::common::balance_state::BalanceState,
    token_index: u32,
) -> Result<usize, ChannelStateUpdateError> {
    let token_count = (balance_state.token_count as usize).min(MAX_CHANNEL_TOKENS);
    balance_state.token_registry[..token_count]
        .iter()
        .position(|&index| index == token_index)
        .ok_or_else(|| {
            ChannelStateUpdateError::InvalidAmountRelation(format!(
                "base token_index {token_index} is not registered in this channel's active \
                 registry (token_count {token_count}) — rejecting fail-closed (TM-6/TM-7)"
            ))
        })
}

/// P2 (per-token conservation): every fund position EXCEPT the registry-resolved `token_slot`
/// must be unchanged across a transition that moves value in exactly one token (TM-2's
/// "others unchanged" leg, applied to the fund vector).
fn ensure_funds_unchanged_except(
    prev_state: &ChannelState,
    next_state: &ChannelState,
    token_slot: usize,
) -> Result<(), ChannelStateUpdateError> {
    for t in 0..MAX_CHANNEL_TOKENS {
        if t != token_slot
            && prev_state.channel_fund.amounts[t] != next_state.channel_fund.amounts[t]
        {
            return Err(ChannelStateUpdateError::InvalidAmountRelation(format!(
                "channel_fund.amounts[{t}] must remain unchanged (only the resolved token \
                 position {token_slot} may change, P2)"
            )));
        }
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
    record.member_pk_gs.get(index).copied().ok_or_else(|| {
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
    // These medium-block proof slots were never backed by a verifier.  Protocol v3 retires them
    // with a single canonical encoding instead of accepting arbitrary marker bytes in a signed
    // digest.
    if signed.message.medium_epoch_hint != 0 || signed.medium_block_number != 0 {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "retired medium-block numbers must be zero".to_string(),
        ));
    }
    if !signed.aggregated_signature_proof.is_empty() {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "retired aggregated signature proof must be empty".to_string(),
        ));
    }
    if !signed.confirmation_proof.is_empty() {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "retired confirmation proof must be empty".to_string(),
        ));
    }
    if inter_channel_tx.seal != Bytes32::default()
        || !inter_channel_tx.recipient_memo.is_empty()
        || !inter_channel_tx.transport_proof.is_empty()
        || inter_channel_tx.tx_inclusion_proof != MerkleInclusionProof::default()
    {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "retired inter-channel fields must use their canonical empty value".to_string(),
        ));
    }
    if inter_channel_tx.intmax_transfer_commitment == Bytes32::default() {
        return Err(ChannelStateUpdateError::InvalidSmallBlock(
            "intmax_transfer_commitment must commit the canonical base Transfer".to_string(),
        ));
    }
    // Slot/identity structure only: these are NOT channel-state co-signatures, so the Falcon
    // cosign length gate does not apply. The real small-block signature check is the B-2
    // validity-proof path (the bp's Falcon signature verified in-circuit by the list step).
    validate_member_signature_slots(source_channel_record, &signed.signatures)
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
        ethereum_types::{address::Address, u256::U256},
        regev::{
            RegevSecurityLevel, channel_keygen, encrypt_amount, prove_channel_tx, regev_pk_root,
        },
    };

    /// A distinct NONZERO per-slot L1 exit address per seed (B-1b: validate() rejects zero
    /// active recipients).
    fn recipient(seed: u32) -> Address {
        Address::from_u32_slice(&[seed + 1, seed + 2, seed + 3, seed + 4, seed + 5]).unwrap()
    }

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
                signature: crate::common::channel::structural_cosign_placeholder(1 + idx as u8),
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
            member_pk_gs: pad_hashes(&[pubkey_hash(10), pubkey_hash(20), pubkey_hash(30)]),
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
            amounts: ChannelFund::single_token_amounts(U256::from(100u32)),
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
                enc_balances: BalanceState::pad_enc_balances_token0(&[
                    before_s.0.clone(),
                    before_r.0.clone(),
                    before_t.0.clone(),
                ]),
                regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
                recipients: BalanceState::pad_recipients(&[
                    recipient(10),
                    recipient(20),
                    recipient(30),
                ]),
                settled_tx_chain: Bytes32::default(),
                settled_tx_accumulator_root: Bytes32::default(),
                state_version: 3,
                pending_adds: BalanceState::pad_pending_adds_token0(&[0, 2, 0]),
                token_registry: BalanceState::single_token_registry(0),
                token_count: 1,
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
                enc_balances: BalanceState::pad_enc_balances_token0(&[
                    after_s.0.clone(),
                    after_r.clone(),
                    before_t.0.clone(),
                ]),
                regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
                recipients: BalanceState::pad_recipients(&[
                    recipient(10),
                    recipient(20),
                    recipient(30),
                ]),
                settled_tx_chain: Bytes32::default(),
                settled_tx_accumulator_root: Bytes32::default(),
                state_version: 4,
                pending_adds: BalanceState::pad_pending_adds_token0(&[0, 3, 0]),
                token_registry: BalanceState::single_token_registry(0),
                token_count: 1,
            },
            prev_digest: prev_state.digest,
            ..prev_state.clone()
        }
        .with_computed_digest();

        let channel_tx = ChannelTx {
            token_slot: 0,
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
            &fixture.witness.next_state.balance_state.enc_balances[1][0],
            &fixture.witness.channel_tx.enc_amount,
        )
        .unwrap();
        fixture.witness.next_state.balance_state.enc_balances[1][0] = double;
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidCiphertextTransition(_))
        ));
    }

    /// B-1b: a transition that mutates ANY slot's L1 exit address is rejected fail-closed by
    /// every transition verifier (recipient changes are NOT a supported transition). This is the
    /// co-signer-side guard: without it a malicious proposer could trick the cosigners into
    /// signing a next state whose (otherwise valid-looking) recipients redirect a victim slot's
    /// payout. Covers both a VICTIM slot's recipient and the SENDER's own recipient.
    #[test]
    fn in_channel_transfer_rejects_recipients_mutation() {
        // Victim slot (recipient_index = 1): redirect its exit address.
        let mut fixture = in_channel_fixture();
        fixture.witness.next_state.balance_state.recipients[1] = recipient(666);
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidStateLinkage(_))
        ));

        // The sender's OWN recipient is equally immutable in B-1b.
        let mut fixture = in_channel_fixture();
        fixture.witness.next_state.balance_state.recipients[0] = recipient(667);
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidStateLinkage(_))
        ));
    }

    /// TM-1/TM-9 (security-review MAJOR 1): the token registry and token_count are IMMUTABLE
    /// across every current transition kind — an otherwise-valid transfer whose next-state
    /// remaps a registry entry (re-pointing a local token slot at a DIFFERENT base token's L1
    /// escrow) or bumps token_count (activating a token position without a cosigned
    /// TokenRegister) MUST be rejected by `verify_balance_state_common` before any cosigner
    /// signs. Both mutations keep the next state `validate()`-clean, so this pins the dedicated
    /// immutability equality (InvalidStateLinkage), not an incidental canonicality rejection.
    #[test]
    fn in_channel_transfer_rejects_token_registry_remap_and_count_bump() {
        // Registry remap: local token slot 0 re-pointed from base token 0 to base token 42.
        let mut fixture = in_channel_fixture();
        fixture.witness.next_state.balance_state.token_registry[0] = 42;
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidStateLinkage(_))
        ));

        // token_count bump (with a fresh injective registry entry, so next.validate() passes and
        // the immutability equality is what fires).
        let mut fixture = in_channel_fixture();
        fixture.witness.next_state.balance_state.token_registry[1] = 42;
        fixture.witness.next_state.balance_state.token_count = 2;
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidStateLinkage(_))
        ));
    }

    #[test]
    fn in_channel_transfer_rejects_pending_adds_at_budget() {
        let mut fixture = in_channel_fixture();
        // Recipient slot already at the refresh budget: the add MUST be refused (D3).
        fixture.witness.prev_state.balance_state.pending_adds[1][0] = MAX_HOMO_ADDS_BEFORE_REFRESH;
        fixture.witness.prev_state = fixture.witness.prev_state.clone().with_computed_digest();
        fixture.witness.next_state.balance_state.pending_adds[1][0] =
            MAX_HOMO_ADDS_BEFORE_REFRESH + 1;
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

    // ===================================================================================
    // TM-2 (multitoken Phase 2b) — the token binding triple on the generalized (non-genesis)
    // in-channel path. Every test documents WHICH leg of the triple it proves an adversary
    // cannot break; the fixture transfers TOKEN SLOT 1 of a 2-token channel so a missing
    // binding cannot hide behind the genesis default.
    // ===================================================================================

    /// Base token_index registered at local slot 1 of the two-token fixture (nonzero on
    /// purpose).
    const TOKEN1_BASE_INDEX: u32 = 55;

    /// Two-token fixture: registry `[0, 55]`, `token_count = 2`; members hold independent
    /// balances at BOTH token positions; the built transfer moves 7 of TOKEN SLOT 1 from
    /// member 0 to member 1 with a real position-1 E-1 proof.
    struct TwoTokenFixture {
        witness: InChannelTransferUpdateWitness,
        sks: Vec<RegevSk>,
        /// A spare, REAL token-0 E-1 proof + its (enc_amount, after) ciphertexts over the SAME
        /// sender/recipient keys (for the cross-position proof-substitution negative).
        token0_proof: Vec<u8>,
        token0_enc_amount: RegevCiphertext,
        token0_after: RegevCiphertext,
    }

    fn two_token_registry() -> [u32; MAX_CHANNEL_TOKENS] {
        let mut registry = [0u32; MAX_CHANNEL_TOKENS];
        registry[1] = TOKEN1_BASE_INDEX;
        registry
    }

    fn two_token_fixture() -> TwoTokenFixture {
        let mut rng = SmallRng::seed_from_u64(20262);
        let channel_id = ChannelId::new(6).unwrap();
        let (pk0, sk0) = channel_keygen(&mut rng);
        let (pk1, sk1) = channel_keygen(&mut rng);
        let (pk2, sk2) = channel_keygen(&mut rng);
        let pks = pad_pks(&[pk0, pk1, pk2]);

        let record = ChannelRecord {
            channel_id,
            member_count: 3,
            delegate_count: 0,
            member_pk_gs: pad_hashes(&[pubkey_hash(10), pubkey_hash(20), pubkey_hash(30)]),
            member_pubkeys_root: Bytes32::from_u32_slice(&[1, 1, 1, 1, 0, 0, 0, 0]).unwrap(),
            bp_member_slot: 0,
            special_close_penalty: U256::from(7u32),
            close_freeze_nonce: 0,
            status: ChannelStatus::Active,
            regev_pk_root: regev_pk_root(&pks),
        };

        // Token 0 balances (bystanders for this transfer).
        let s0 = encrypt_amount(&mut rng, &pks[0], 50).unwrap();
        let r0 = encrypt_amount(&mut rng, &pks[1], 10).unwrap();
        let t0 = encrypt_amount(&mut rng, &pks[2], 30).unwrap();
        // Token 1 balances: member 0 holds 40, member 1 holds 5, member 2 holds nothing
        // (canonical zero position).
        let s1 = encrypt_amount(&mut rng, &pks[0], 40).unwrap();
        let r1 = encrypt_amount(&mut rng, &pks[1], 5).unwrap();

        // The token-1 transfer: 7 from member 0 to member 1.
        let enc_amount1 = encrypt_amount(&mut rng, &pks[1], 7).unwrap();
        let after_s1 = encrypt_amount(&mut rng, &pks[0], 33).unwrap();
        let after_r1 = add_ciphertexts(&r1.0, &enc_amount1.0).unwrap();
        let proof1 = prove_channel_tx(
            RegevSecurityLevel::Test,
            &pks[0],
            &pks[1],
            (&s1.0, &s1.1),
            (&enc_amount1.0, &enc_amount1.1),
            (&after_s1.0, &after_s1.1),
        )
        .unwrap();

        // A REAL spare token-0 E-1 (same parties) for the proof-substitution negative.
        let enc_amount0 = encrypt_amount(&mut rng, &pks[1], 7).unwrap();
        let after_s0 = encrypt_amount(&mut rng, &pks[0], 43).unwrap();
        let proof0 = prove_channel_tx(
            RegevSecurityLevel::Test,
            &pks[0],
            &pks[1],
            (&s0.0, &s0.1),
            (&enc_amount0.0, &enc_amount0.1),
            (&after_s0.0, &after_s0.1),
        )
        .unwrap();

        let row = |a: &RegevCiphertext,
                   b: &RegevCiphertext|
         -> crate::common::balance_state::TokenCiphertexts {
            let mut row = crate::common::balance_state::zero_token_row();
            row[0] = a.clone();
            row[1] = b.clone();
            row
        };
        let zero1 = crate::regev::RegevCiphertext::padding();

        let fund = ChannelFund {
            channel_id,
            amounts: {
                let mut amounts = ChannelFund::single_token_amounts(U256::from(90u32));
                amounts[1] = U256::from(45u32);
                amounts
            },
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
                    row(&s0.0, &s1.0),
                    row(&r0.0, &r1.0),
                    row(&t0.0, &zero1),
                ]),
                regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
                recipients: BalanceState::pad_recipients(&[
                    recipient(10),
                    recipient(20),
                    recipient(30),
                ]),
                settled_tx_chain: Bytes32::default(),
                settled_tx_accumulator_root: Bytes32::default(),
                state_version: 3,
                pending_adds: {
                    let mut rows = BalanceState::pad_pending_adds_token0(&[0, 0, 0]);
                    rows[1][1] = 2; // recipient's token-1 counter has prior credits
                    rows
                },
                token_registry: two_token_registry(),
                token_count: 2,
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
                enc_balances: BalanceState::pad_enc_balances(&[
                    row(&s0.0, &after_s1.0),
                    row(&r0.0, &after_r1),
                    row(&t0.0, &zero1),
                ]),
                state_version: 4,
                pending_adds: {
                    let mut rows = BalanceState::pad_pending_adds_token0(&[0, 0, 0]);
                    rows[1][1] = 3; // +1 at exactly (recipient, token 1)
                    rows
                },
                ..prev_state.balance_state.clone()
            },
            prev_digest: prev_state.digest,
            ..prev_state.clone()
        }
        .with_computed_digest();

        let channel_tx = ChannelTx {
            token_slot: 1,
            recipient_pk_g: pubkey_hash(20),
            enc_amount: enc_amount1.0,
            nonce: Bytes32::from_u32_slice(&[7, 7, 7, 7, 0, 0, 0, 0]).unwrap(),
            channel_tx_zkp: ChannelProofEnvelope {
                role: TransitionProofRole::ChannelStateUpdate,
                backend: ProofBackend::Plonky3,
                proof: proof1,
            },
            sender_pk_g: pubkey_hash(10),
            sender_hash_sig: vec![1, 2, 3],
            sender_pk_b: pubkey_hash(40),
        };

        TwoTokenFixture {
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
            token0_proof: proof0,
            token0_enc_amount: enc_amount0.0,
            token0_after: after_s0.0,
        }
    }

    /// Completeness of the LIFTED gate: a token-slot-1 transfer with a real position-1 E-1 and a
    /// correctly-folded next state VERIFIES, the recipient decrypts the amount at position 1,
    /// and the transition digest binds token_slot 1 (differs from the same tx signed for slot
    /// 0).
    #[test]
    fn in_channel_transfer_token1_happy_path() {
        let fixture = two_token_fixture();
        let pis = fixture
            .witness
            .verify(&VERIFIER)
            .expect("token-1 transfer must verify");
        assert_eq!(pis.kind, ChannelTransitionKind::InChannelTransfer);
        // The transition digest commits token_slot in its own IMPA-v2 limb.
        let tx = &fixture.witness.channel_tx;
        let slot0_digest = ChannelTx::signing_digest(
            fixture.witness.prev_state.channel_id,
            fixture.witness.prev_state.digest,
            &tx.enc_amount,
            tx.nonce,
            0,
            tx.sender_pk_g,
            tx.recipient_pk_g,
        );
        assert_ne!(pis.transition_digest, slot0_digest);

        // Recipient decryption at position 1.
        let mut fixture = two_token_fixture();
        fixture.witness.recipient_sk = Some(fixture.sks[1].clone());
        fixture.witness.expected_amount = Some(7);
        fixture.witness.verify(&VERIFIER).unwrap();
    }

    /// TM-2 leg 2 (signed slot == mutated position), direction "sign token A, apply token B": a
    /// state fold that moves TOKEN 1 while the SIGNED `token_slot` says 0 must be rejected — the
    /// public recomputation runs at the signed position and finds it untouched.
    #[test]
    fn in_channel_transfer_rejects_signed_token_a_applied_token_b() {
        let mut fixture = two_token_fixture();
        fixture.witness.channel_tx.token_slot = 0;
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidCiphertextTransition(_))
        ));
    }

    /// TM-2 leg 2, complementary direction: a tx SIGNED for token 1 whose next state instead
    /// mutates token 0 of the involved rows is rejected (the signed position's recomputation
    /// fails; the token-0 mutation additionally trips the "others unchanged" leg).
    #[test]
    fn in_channel_transfer_rejects_apply_at_unsigned_position() {
        let mut fixture = two_token_fixture();
        // Craft a next state that leaves token 1 untouched and instead installs the spare
        // token-0 transfer at position 0.
        let prev = &fixture.witness.prev_state;
        let mut enc_balances = prev.balance_state.enc_balances.clone();
        enc_balances[0][0] = fixture.token0_after.clone();
        enc_balances[1][0] = add_ciphertexts(
            &prev.balance_state.enc_balances[1][0],
            &fixture.token0_enc_amount,
        )
        .unwrap();
        fixture.witness.next_state.balance_state.enc_balances = enc_balances;
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidCiphertextTransition(_))
        ));
    }

    /// TM-2 leg 2 ("the ONLY position of 10 whose ct changes"): a bystander-ciphertext mutation
    /// at ANOTHER token position — on the SENDER row and on the RECIPIENT row — is rejected even
    /// when the signed position's fold is perfectly valid.
    #[test]
    fn in_channel_transfer_rejects_bystander_ciphertext_mutation() {
        // Sender row, token 0 (a valid-looking fresh ciphertext, not garbage).
        let mut fixture = two_token_fixture();
        fixture.witness.next_state.balance_state.enc_balances[0][0] = fixture.token0_after.clone();
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidCiphertextTransition(_))
        ));

        // Recipient row, token 0 (a plausible homomorphic credit at the WRONG position).
        let mut fixture = two_token_fixture();
        let smuggled = add_ciphertexts(
            &fixture.witness.prev_state.balance_state.enc_balances[1][0],
            &fixture.token0_enc_amount,
        )
        .unwrap();
        fixture.witness.next_state.balance_state.enc_balances[1][0] = smuggled;
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidCiphertextTransition(_))
        ));
    }

    /// TM-2 leg 3 (`pending_adds` increments only at `(recipient, token_slot)`): an extra
    /// counter bump at another token position of the recipient row, or at an uninvolved slot's
    /// row, is rejected.
    #[test]
    fn in_channel_transfer_rejects_pending_adds_at_wrong_position() {
        // Wrong token position of the recipient row.
        let mut fixture = two_token_fixture();
        fixture.witness.next_state.balance_state.pending_adds[1][0] += 1;
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidPendingAdds(_))
        ));

        // Uninvolved slot's row (member 2), signed token position.
        let mut fixture = two_token_fixture();
        fixture.witness.next_state.balance_state.pending_adds[2][1] += 1;
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidPendingAdds(_))
        ));

        // Missing increment at the signed position (recipient counter frozen).
        let mut fixture = two_token_fixture();
        fixture.witness.next_state.balance_state.pending_adds[1][1] -= 1;
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidPendingAdds(_))
        ));
    }

    /// TM-2 leg 4 (E-1 handed exactly the ciphertexts selected by the SIGNED token_slot): a REAL
    /// E-1 proof generated over the token-0 ciphertexts must NOT verify a token-1 transfer —
    /// the statement is rebuilt from the position the signed slot selects, so the transcript
    /// diverges.
    #[test]
    fn in_channel_transfer_rejects_cross_position_e1_proof() {
        let mut fixture = two_token_fixture();
        fixture.witness.channel_tx.channel_tx_zkp.proof = fixture.token0_proof.clone();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::ProofVerification(_))
        ));
    }

    /// TM-8, signed-bound variant: a SIGNED `token_slot >= token_count` is rejected before any
    /// position is touched (both the first inactive position and the layout bound).
    #[test]
    fn in_channel_transfer_rejects_token_slot_beyond_token_count() {
        // token_slot = 2 with token_count = 2 (first inactive position).
        let mut fixture = two_token_fixture();
        fixture.witness.channel_tx.token_slot = 2;
        match fixture.witness.verify(&VERIFIER) {
            Err(ChannelStateUpdateError::InvalidCiphertextTransition(msg)) => {
                assert!(msg.contains("token_count"), "wrong rejection: {msg}");
            }
            other => panic!("expected token_count range rejection, got {other:?}"),
        }

        // token_slot = 10 and 255 (layout bound, TM-8 defense in depth).
        for bad in [MAX_CHANNEL_TOKENS as u8, u8::MAX] {
            let mut fixture = two_token_fixture();
            fixture.witness.channel_tx.token_slot = bad;
            match fixture.witness.verify(&VERIFIER) {
                Err(ChannelStateUpdateError::InvalidCiphertextTransition(msg)) => {
                    assert!(msg.contains("MAX_CHANNEL_TOKENS"), "wrong rejection: {msg}");
                }
                other => panic!("expected layout-bound rejection, got {other:?}"),
            }
        }
    }

    /// TM-8, doctored-header variant: an adversary shrinking BOTH states' `token_count` to 1
    /// (trying to reinterpret the active/inactive boundary under the same balances) is rejected
    /// fail-closed — `validate()` refuses nonzero ciphertexts beyond the claimed count before
    /// any position logic runs.
    #[test]
    fn in_channel_transfer_rejects_doctored_token_count_header() {
        let mut fixture = two_token_fixture();
        fixture.witness.prev_state.balance_state.token_count = 1;
        fixture.witness.prev_state.balance_state.token_registry = [0u32; MAX_CHANNEL_TOKENS];
        fixture.witness.prev_state = fixture.witness.prev_state.clone().with_computed_digest();
        fixture.witness.next_state.balance_state.token_count = 1;
        fixture.witness.next_state.balance_state.token_registry = [0u32; MAX_CHANNEL_TOKENS];
        fixture.witness.next_state.prev_digest = fixture.witness.prev_state.digest;
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidCiphertextTransition(_))
        ));
    }

    /// TM-13 at the generalized position: the D3 budget gate applies per (slot, token) — a
    /// recipient whose TOKEN-1 counter is at the budget refuses another token-1 credit.
    #[test]
    fn in_channel_transfer_rejects_budget_exhaustion_at_token1() {
        let mut fixture = two_token_fixture();
        fixture.witness.prev_state.balance_state.pending_adds[1][1] = MAX_HOMO_ADDS_BEFORE_REFRESH;
        fixture.witness.prev_state = fixture.witness.prev_state.clone().with_computed_digest();
        fixture.witness.next_state.balance_state.pending_adds[1][1] =
            MAX_HOMO_ADDS_BEFORE_REFRESH + 1;
        fixture.witness.next_state.prev_digest = fixture.witness.prev_state.digest;
        fixture.witness.next_state = fixture.witness.next_state.clone().with_computed_digest();
        assert!(matches!(
            fixture.witness.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidPendingAdds(_)
                | ChannelStateUpdateError::InvalidCiphertextTransition(_))
        ));
    }

    // ===================================================================================
    // TM-13 (multitoken Phase 2b) — refresh per (member, token): the token selector picks
    // EXACTLY one position; every other position's ciphertext AND counter is frozen.
    // ===================================================================================

    /// A refresh witness over the two-token fixture: member 1 refreshes TOKEN SLOT 1 (counter 2
    /// -> 0) while their token-0 counter (set to 1) and ciphertext must stay untouched.
    fn two_token_refresh_fixture() -> BalanceRefreshUpdateWitness {
        let mut rng = SmallRng::seed_from_u64(20263);
        let base = two_token_fixture();
        let mut prev_state = base.witness.prev_state.clone();
        // Token-0 credits pending on the refreshing member's row — must survive the refresh.
        prev_state.balance_state.pending_adds[1][0] = 1;
        let prev_state = prev_state.with_computed_digest();

        let old_ct = prev_state.balance_state.enc_balances[1][1].clone();
        let (new_ct, proof) = crate::regev::prove_balance_refresh(
            &mut rng,
            RegevSecurityLevel::Test,
            &base.witness.regev_pks[1],
            &base.sks[1],
            &old_ct,
        )
        .unwrap();

        let mut next_state = ChannelState {
            epoch: prev_state.epoch + 1,
            balance_state: BalanceState {
                state_version: prev_state.balance_state.state_version + 1,
                ..prev_state.balance_state.clone()
            },
            prev_digest: prev_state.digest,
            ..prev_state.clone()
        };
        next_state.balance_state.enc_balances[1][1] = new_ct;
        next_state.balance_state.pending_adds[1][1] = 0;
        let next_state = next_state.with_computed_digest();

        BalanceRefreshUpdateWitness {
            channel_record: base.witness.channel_record.clone(),
            regev_pks: base.witness.regev_pks.clone(),
            prev_state,
            next_state,
            member_index: 1,
            token_slot: 1,
            refresh_proof: ChannelProofEnvelope {
                role: TransitionProofRole::ChannelStateUpdate,
                backend: ProofBackend::Plonky3,
                proof,
            },
        }
    }

    /// TM-13 completeness: refreshing (member 1, token 1) verifies, and token 0 of the same row
    /// (ciphertext AND counter) is untouched by construction — pinned by explicit equality.
    #[test]
    fn balance_refresh_token1_happy_path_leaves_token0_untouched() {
        let w = two_token_refresh_fixture();
        let pis = w.verify(&VERIFIER).expect("token-1 refresh must verify");
        assert_eq!(pis.kind, ChannelTransitionKind::BalanceRefresh);
        assert_eq!(
            w.prev_state.balance_state.enc_balances[1][0],
            w.next_state.balance_state.enc_balances[1][0],
        );
        assert_eq!(w.next_state.balance_state.pending_adds[1][0], 1);
        assert_eq!(w.next_state.balance_state.pending_adds[1][1], 0);
    }

    /// TM-13: a refresh that ALSO resets the counter at an unselected position (token 0) is
    /// rejected — the reset happens at exactly (member, token_slot).
    #[test]
    fn balance_refresh_rejects_counter_reset_at_unselected_position() {
        let mut w = two_token_refresh_fixture();
        w.next_state.balance_state.pending_adds[1][0] = 0;
        w.next_state = w.next_state.with_computed_digest();
        assert!(matches!(
            w.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidPendingAdds(_))
        ));
    }

    /// TM-13/TM-2: a refresh that replaces the ciphertext at an unselected position of the
    /// member's row is rejected.
    #[test]
    fn balance_refresh_rejects_ciphertext_swap_at_unselected_position() {
        let mut w = two_token_refresh_fixture();
        // Move the refreshed ct into token 0 as well (a plausible-looking fresh ciphertext).
        w.next_state.balance_state.enc_balances[1][0] =
            w.next_state.balance_state.enc_balances[1][1].clone();
        w.next_state = w.next_state.with_computed_digest();
        assert!(matches!(
            w.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidCiphertextTransition(_))
        ));
    }

    /// TM-8: a refresh selector beyond the active registry (or the layout) is rejected before
    /// any position is touched.
    #[test]
    fn balance_refresh_rejects_out_of_range_token_slot() {
        let mut w = two_token_refresh_fixture();
        w.token_slot = 2;
        assert!(matches!(
            w.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidCiphertextTransition(_))
        ));
        let mut w = two_token_refresh_fixture();
        w.token_slot = MAX_CHANNEL_TOKENS;
        assert!(matches!(
            w.verify(&VERIFIER),
            Err(ChannelStateUpdateError::InvalidCiphertextTransition(_))
        ));
    }

    // ===================================================================================
    // Stage 3 — native settled-tx accumulator co-signer checks.
    // ===================================================================================

    use crate::utils::trees::incremental_merkle_tree::IncrementalMerkleTree;

    const ACC_H: usize = 20;

    /// `require_accumulator_push` ACCEPTS a root that is exactly push(prev_tree, tx_hash), and
    /// REJECTS a wrong/omitted leaf or a stale root.
    #[test]
    fn require_accumulator_push_accepts_correct_advance_rejects_wrong() {
        let mut tree = IncrementalMerkleTree::<Bytes32>::new(ACC_H);
        tree.push(pubkey_hash(1));
        let prev_root = Bytes32::from(tree.get_root());

        let tx_hash = pubkey_hash(42);
        let mut advanced = tree.clone();
        advanced.push(tx_hash);
        let next_root = Bytes32::from(advanced.get_root());

        // Correct advance.
        require_accumulator_push(&tree, tx_hash, next_root).expect("correct push must accept");

        // Wrong leaf (different tx_hash) produces a different root → reject for the claimed
        // next_root.
        assert!(
            require_accumulator_push(&tree, pubkey_hash(43), next_root).is_err(),
            "a wrong inserted leaf must be rejected"
        );

        // Omitted insertion: claiming the prev (unchanged) root as the post-push root is rejected.
        assert!(
            require_accumulator_push(&tree, tx_hash, prev_root).is_err(),
            "an omitted insertion (root unchanged) must be rejected"
        );
    }

    /// `require_accumulator_unchanged` ACCEPTS equal roots and REJECTS a changed root.
    #[test]
    fn require_accumulator_unchanged_rejects_change() {
        let root = pubkey_hash(7);
        require_accumulator_unchanged(root, root).expect("equal roots must accept");
        assert!(
            require_accumulator_unchanged(root, pubkey_hash(8)).is_err(),
            "a changed accumulator root must be rejected for an unchanged transition"
        );
    }

    /// Accumulator golden: the native `IncrementalMerkleTree` root over a sequence of `tx_hash`
    /// leaves, and the `Bytes32::from(get_root())` encoding, round-trips through `prove`/`verify`.
    /// (The in-circuit `verify` twin is exercised by the post-close-claim circuit test.)
    #[test]
    fn accumulator_native_root_and_inclusion_golden() {
        let mut tree = IncrementalMerkleTree::<Bytes32>::new(ACC_H);
        let leaves: Vec<Bytes32> = (0..7).map(|i| pubkey_hash(100 + i)).collect();
        for leaf in &leaves {
            tree.push(*leaf);
        }
        let root = tree.get_root();
        // Each leaf has a valid inclusion proof at its index; a wrong leaf does not.
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i as u64);
            proof
                .verify(leaf, i as u64, root)
                .expect("native inclusion must verify");
            assert!(
                proof.verify(&pubkey_hash(999), i as u64, root).is_err(),
                "a wrong leaf must fail native inclusion"
            );
        }
        // The Bytes32 encoding of the root is a canonical Poseidon→Bytes32 value (TryFrom
        // succeeds).
        let root_b32 = Bytes32::from(root);
        let recovered = crate::utils::poseidon_hash_out::PoseidonHashOut::try_from(root_b32)
            .expect("accumulator root Bytes32 must be a canonical poseidon encoding");
        assert_eq!(recovered, root);
    }

    // --- L1 deposit import tests ---

    fn l1_deposit_import_fixture() -> L1DepositImportUpdateWitness {
        let channel_id = ChannelId::new(7).unwrap();
        let hashes = pad_hashes(&[pubkey_hash(10), pubkey_hash(20), pubkey_hash(30)]);
        let record = ChannelRecord {
            channel_id,
            member_count: 3,
            delegate_count: 0,
            member_pk_gs: hashes,
            member_pubkeys_root: Bytes32::from_u32_slice(&[2, 2, 2, 2, 0, 0, 0, 0]).unwrap(),
            bp_member_slot: 0,
            special_close_penalty: U256::from(0u32),
            close_freeze_nonce: 0,
            status: ChannelStatus::Active,
            regev_pk_root: Bytes32::from_u32_slice(&[3, 3, 3, 3, 0, 0, 0, 0]).unwrap(),
        };
        let amount: u64 = 1000;
        let deposit_nullifier = pubkey_hash(42);
        let prev_chain = Bytes32::default();
        let prev_nullifier_root = pubkey_hash(99);
        let next_chain = settled_tx_chain_push(prev_chain, deposit_nullifier);
        let next_nullifier_root = settled_tx_chain_push(prev_nullifier_root, deposit_nullifier);
        let prev_fund = U256::from(5000u32);
        let next_fund = prev_fund + crate::wallet_core::u64_to_u256(amount);
        let prev_unalloc = U256::zero();
        let next_unalloc = prev_unalloc + crate::wallet_core::u64_to_u256(amount);
        let prev_state = ChannelState {
            channel_id,
            epoch: 1,
            small_block_number: 10,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id,
                amounts: ChannelFund::single_token_amounts(prev_fund),
                intmax_state_root: Bytes32::default(),
            },
            balance_state: BalanceState {
                channel_id,
                member_count: 3,
                delegate_count: 0,
                enc_balances: BalanceState::pad_enc_balances_token0(&[]),
                regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
                recipients: BalanceState::pad_recipients(&[
                    recipient(10),
                    recipient(20),
                    recipient(30),
                ]),
                settled_tx_chain: prev_chain,
                settled_tx_accumulator_root: Bytes32::default(),
                state_version: 5,
                pending_adds: BalanceState::pad_pending_adds_token0(&[0, 0, 0]),
                token_registry: BalanceState::single_token_registry(0),
                token_count: 1,
            },
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: prev_nullifier_root,
            unallocated_confirmed_incoming: prev_unalloc,
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: signatures_for(&record),
        }
        .with_computed_digest();
        let mut next_state = ChannelState {
            epoch: 2,
            small_block_number: 11,
            channel_fund: ChannelFund {
                channel_id,
                amounts: ChannelFund::single_token_amounts(next_fund),
                intmax_state_root: Bytes32::default(),
            },
            balance_state: BalanceState {
                channel_id,
                member_count: 3,
                delegate_count: 0,
                enc_balances: BalanceState::pad_enc_balances_token0(&[]),
                regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
                recipients: BalanceState::pad_recipients(&[
                    recipient(10),
                    recipient(20),
                    recipient(30),
                ]),
                settled_tx_chain: next_chain,
                settled_tx_accumulator_root: Bytes32::default(),
                state_version: 6,
                pending_adds: BalanceState::pad_pending_adds_token0(&[0, 0, 0]),
                token_registry: BalanceState::single_token_registry(0),
                token_count: 1,
            },
            shared_native_nullifier_root: next_nullifier_root,
            unallocated_confirmed_incoming: next_unalloc,
            prev_digest: prev_state.digest,
            member_signatures: signatures_for(&record),
            ..prev_state.clone()
        }
        .with_computed_digest();
        L1DepositImportUpdateWitness {
            channel_record: record,
            prev_state,
            next_state,
            amount,
            deposit_nullifier,
            // Genesis token (registry[0] = 0): the only importable token until Phase 2.
            token_index: 0,
            depositor_slot: 0,
        }
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn l1_deposit_import_happy_path() {
        let w = l1_deposit_import_fixture();
        let pis = w.verify().expect("happy path must succeed");
        assert_eq!(pis.kind, ChannelTransitionKind::L1DepositImport);
        assert_eq!(pis.amount, 1000);
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn l1_deposit_import_rejects_wrong_fund() {
        let mut w = l1_deposit_import_fixture();
        w.next_state.channel_fund.amounts[0] =
            w.prev_state.channel_fund.amounts[0] + U256::from(999u32);
        w.next_state = w.next_state.with_computed_digest();
        w.next_state.member_signatures = signatures_for(&w.channel_record);
        w.next_state = w.next_state.with_computed_digest();
        assert!(w.verify().is_err());
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn l1_deposit_import_rejects_wrong_unallocated() {
        let mut w = l1_deposit_import_fixture();
        w.next_state.unallocated_confirmed_incoming =
            w.prev_state.unallocated_confirmed_incoming + U256::from(999u32);
        w.next_state = w.next_state.with_computed_digest();
        w.next_state.member_signatures = signatures_for(&w.channel_record);
        w.next_state = w.next_state.with_computed_digest();
        assert!(w.verify().is_err());
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn l1_deposit_import_rejects_balance_change() {
        let mut rng = SmallRng::seed_from_u64(999);
        let mut w = l1_deposit_import_fixture();
        let (pk, _sk) = channel_keygen(&mut rng);
        let (ct, _witness) = encrypt_amount(&mut rng, &pk, 100).unwrap();
        w.next_state.balance_state.enc_balances[0][0] = ct;
        w.next_state = w.next_state.with_computed_digest();
        w.next_state.member_signatures = signatures_for(&w.channel_record);
        w.next_state = w.next_state.with_computed_digest();
        assert!(w.verify().is_err());
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn l1_deposit_import_rejects_wrong_chain() {
        let mut w = l1_deposit_import_fixture();
        w.next_state.balance_state.settled_tx_chain =
            settled_tx_chain_push(w.prev_state.balance_state.settled_tx_chain, pubkey_hash(77));
        w.next_state = w.next_state.with_computed_digest();
        w.next_state.member_signatures = signatures_for(&w.channel_record);
        w.next_state = w.next_state.with_computed_digest();
        assert!(w.verify().is_err());
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn l1_deposit_import_rejects_unchanged_nullifier_root() {
        let mut w = l1_deposit_import_fixture();
        w.next_state.shared_native_nullifier_root = w.prev_state.shared_native_nullifier_root;
        w.next_state = w.next_state.with_computed_digest();
        w.next_state.member_signatures = signatures_for(&w.channel_record);
        w.next_state = w.next_state.with_computed_digest();
        assert!(w.verify().is_err());
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn l1_deposit_import_rejects_nonzero_h2() {
        let mut w = l1_deposit_import_fixture();
        w.next_state.h2_tag = pubkey_hash(55);
        w.next_state = w.next_state.with_computed_digest();
        w.next_state.member_signatures = signatures_for(&w.channel_record);
        w.next_state = w.next_state.with_computed_digest();
        assert!(w.verify().is_err());
    }

    // --- TM-7 (multitoken Phase 2b): general registry resolution for deposit imports ---

    /// Rebuild the single-token fixture as a 2-token channel (registry `[0, 55]`) whose deposit
    /// carries base token_index 55 and whose fund grows at LOCAL POSITION 1.
    fn l1_deposit_import_two_token_fixture() -> L1DepositImportUpdateWitness {
        let mut w = l1_deposit_import_fixture();
        let register = |state: &mut ChannelState| {
            state.balance_state.token_registry = two_token_registry();
            state.balance_state.token_count = 2;
        };
        register(&mut w.prev_state);
        w.prev_state = w.prev_state.clone().with_computed_digest();
        register(&mut w.next_state);
        // Move the fund delta from position 0 to position 1 (the resolved slot for index 55).
        let amount = w.next_state.channel_fund.amounts[0] - w.prev_state.channel_fund.amounts[0];
        w.next_state.channel_fund.amounts[0] = w.prev_state.channel_fund.amounts[0];
        w.next_state.channel_fund.amounts[1] = w.prev_state.channel_fund.amounts[1] + amount;
        w.next_state.prev_digest = w.prev_state.digest;
        w.next_state = w.next_state.clone().with_computed_digest();
        w.token_index = TOKEN1_BASE_INDEX;
        w
    }

    /// TM-7 completeness: a deposit of a registered NON-genesis token resolves to its local slot
    /// and credits `channel_fund.amounts[1]`.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn l1_deposit_import_token1_happy_path() {
        let w = l1_deposit_import_two_token_fixture();
        let pis = w.verify().expect("token-1 deposit import must verify");
        assert_eq!(pis.kind, ChannelTransitionKind::L1DepositImport);
        assert_eq!(
            pis.channel_fund_after[1],
            pis.channel_fund_before[1] + u64_to_u256(w.amount)
        );
        assert_eq!(pis.channel_fund_after[0], pis.channel_fund_before[0]);
    }

    /// TM-7 fail-closed: a deposit whose base token_index is NOT in the channel's active
    /// registry is rejected — never silently credited to any position.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn l1_deposit_import_rejects_unregistered_token_index() {
        let mut w = l1_deposit_import_two_token_fixture();
        w.token_index = 77;
        match w.verify() {
            Err(ChannelStateUpdateError::InvalidAmountRelation(msg)) => {
                assert!(msg.contains("not registered"), "wrong rejection: {msg}");
            }
            other => panic!("expected unregistered-token rejection, got {other:?}"),
        }
    }

    /// TM-7 (P2 cross-token leg): a token-55 deposit whose next state bumps the fund at the
    /// WRONG position (the genesis token instead of the resolved slot 1) is rejected — both the
    /// resolved-position delta check and the others-frozen check refuse it.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn l1_deposit_import_rejects_fund_bump_at_wrong_token() {
        let mut w = l1_deposit_import_two_token_fixture();
        // Move the fund delta back to position 0 while still declaring token_index 55.
        let amount = w.next_state.channel_fund.amounts[1] - w.prev_state.channel_fund.amounts[1];
        w.next_state.channel_fund.amounts[1] = w.prev_state.channel_fund.amounts[1];
        w.next_state.channel_fund.amounts[0] = w.prev_state.channel_fund.amounts[0] + amount;
        w.next_state = w.next_state.with_computed_digest();
        w.next_state.member_signatures = signatures_for(&w.channel_record);
        w.next_state = w.next_state.with_computed_digest();
        assert!(matches!(
            w.verify(),
            Err(ChannelStateUpdateError::InvalidAmountRelation(_))
        ));
    }

    // ===================================================================================
    // TM-1/TM-9 (multitoken Phase 4) — the dedicated TokenRegister dispatch. The ONLY kind
    // allowed to change the registry, under a full freeze of everything else. Each negative
    // documents which freeze leg it proves an adversary cannot break.
    // ===================================================================================

    /// A well-formed TokenRegister witness over the in-channel fixture's prev state: registry
    /// `[0]` → `[0, 55]` via the canonical builder, N structural signatures.
    fn token_register_fixture() -> TokenRegisterUpdateWitness {
        let fixture = in_channel_fixture();
        let prev_state = fixture.witness.prev_state.clone();
        let record = fixture.witness.channel_record.clone();
        let mut next_state =
            token_register_next_state(&prev_state, 55).expect("canonical register step");
        next_state.member_signatures = signatures_for(&record);
        TokenRegisterUpdateWitness {
            channel_record: record,
            prev_state,
            next_state,
            token_index: 55,
        }
    }

    /// Happy path: the canonical append verifies and exposes the registration through the PIs.
    #[test]
    fn token_register_happy_path() {
        let w = token_register_fixture();
        let pis = w.verify().expect("canonical TokenRegister must verify");
        assert_eq!(pis.kind, ChannelTransitionKind::TokenRegister);
        assert_eq!(pis.amount, 0);
        assert_eq!(pis.next_state_version, pis.prev_state_version + 1);
        assert_eq!(pis.channel_fund_before, pis.channel_fund_after);
        assert_eq!(w.next_state.balance_state.token_count, 2);
        assert_eq!(w.next_state.balance_state.token_registry[1], 55);
        assert_eq!(pis.transition_digest, w.next_state.digest);
    }

    /// Freeze leg: a registration that ALSO touches a balance ciphertext (bundling a hidden
    /// balance edit under the registration's cosign round) must be rejected — the
    /// `verify_token_register_transition` rebuild-equality covers every ciphertext.
    #[test]
    fn token_register_rejects_balance_touch() {
        let mut w = token_register_fixture();
        w.next_state.balance_state.enc_balances[2][0] =
            w.next_state.balance_state.enc_balances[0][0].clone();
        w.next_state = w.next_state.with_computed_digest();
        assert!(matches!(
            w.verify(),
            Err(ChannelStateUpdateError::InvalidStateLinkage(_))
        ));
    }

    /// Freeze leg: a registration that touches a pending_adds counter (D3 budget grooming) must
    /// be rejected.
    #[test]
    fn token_register_rejects_pending_adds_touch() {
        let mut w = token_register_fixture();
        w.next_state.balance_state.pending_adds[1][0] += 1;
        w.next_state = w.next_state.with_computed_digest();
        assert!(matches!(
            w.verify(),
            Err(ChannelStateUpdateError::InvalidStateLinkage(_))
        ));
    }

    /// Freeze leg: a registration that moves channel funds (value smuggled into a header-only
    /// transition) must be rejected.
    #[test]
    fn token_register_rejects_fund_touch() {
        let mut w = token_register_fixture();
        w.next_state.channel_fund.amounts[0] += U256::from(1u32);
        w.next_state = w.next_state.with_computed_digest();
        assert!(matches!(
            w.verify(),
            Err(ChannelStateUpdateError::InvalidStateLinkage(_)
                | ChannelStateUpdateError::InvalidRootTransition(_))
        ));
    }

    /// Append semantics (TM-1): a write at the WRONG position, a duplicate base index, and a
    /// count skip are each rejected — the registry is append-only at exactly
    /// `prev.token_count`, injective over the active prefix, `count + 1`.
    #[test]
    fn token_register_rejects_wrong_append() {
        // (a) Append at position 2 instead of 1 (leaving a zero hole at 1).
        let mut w = token_register_fixture();
        w.next_state.balance_state.token_registry[1] = 0;
        w.next_state.balance_state.token_registry[2] = 55;
        w.next_state = w.next_state.with_computed_digest();
        assert!(
            w.verify().is_err(),
            "wrong-position append must be rejected"
        );

        // (b) Duplicate base index (55 declared, but the next registry re-registers 0).
        let mut w = token_register_fixture();
        w.next_state.balance_state.token_registry[1] = 0;
        w.next_state = w.next_state.with_computed_digest();
        assert!(w.verify().is_err(), "duplicate base index must be rejected");

        // (c) Count skip: two positions activated by one transition.
        let mut w = token_register_fixture();
        w.next_state.balance_state.token_registry[2] = 66;
        w.next_state.balance_state.token_count = 3;
        w.next_state = w.next_state.with_computed_digest();
        assert!(w.verify().is_err(), "count skip must be rejected");

        // (d) Declared token_index disagreeing with the appended one.
        let mut w = token_register_fixture();
        w.token_index = 77;
        assert!(matches!(
            w.verify(),
            Err(ChannelStateUpdateError::InvalidStateLinkage(_))
        ));
    }

    /// Linkage: a version skip (or an unchained prev_digest) is rejected like any transition.
    #[test]
    fn token_register_rejects_version_skip() {
        let mut w = token_register_fixture();
        w.next_state.balance_state.state_version += 1;
        w.next_state = w.next_state.with_computed_digest();
        assert!(w.verify().is_err(), "state_version skip must be rejected");
    }
}
