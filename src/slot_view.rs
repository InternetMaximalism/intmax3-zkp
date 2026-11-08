//! Per-slot channel view: what a DELEGATE holds instead of the full channel state.
//!
//! The co-signers (the sig-cluster, slots `0..member_count`) hold the full signed channel state.
//! A delegate holds only:
//!
//! * the signed state HEADER ([`ChannelStateHeader`]) — every IMCH / H1 field, with the slot rows
//!   replaced by their balance-slot Merkle root;
//! * its own slot's committed row ([`SlotRow`]) and that row's Merkle siblings;
//! * the settled-tx accumulator's next empty position (its leaf count + siblings), so an
//!   inter-channel send can append its `tx_hash` and recompute the accumulator root.
//!
//! From this it recomputes the slot root, H1 and the IMCH digest, and verifies the N-of-N
//! co-signatures — the same signatures that bind the full state — without ever seeing another
//! participant's row. Every operation a delegate starts is sent as a SLIM intent (no proposed
//! successor state); the co-signer rebuilds the full successor from its own trusted state
//! ([`inflate_refresh`], [`inflate_inter_channel_debit`], and the existing slim-send fold) and
//! runs the unchanged full-state transition verifiers on it.

use rand010::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    circuits::balance::common::recipient::{
        calculate_recipient_from_address, calculate_recipient_from_user_id,
        extract_address_from_recipient,
    },
    common::{
        balance_state::{BalanceState, SlotRow, settled_tx_chain_push, tx_leaf_hash},
        channel::{
            ChannelProofEnvelope, ChannelRecord, ChannelState, ChannelStateHeader, ChannelTx,
            InterChannelTx, MemberSignature, MerkleInclusionProof, ProofBackend,
            ReceiverBalanceDelta, SignedSmallBlock, SmallBlockRootMessage, TransitionProofRole,
            burn_descriptor, inter_channel_tx_hash, structural_cosign_placeholder,
        },
        channel_id::ChannelId,
        salt::Salt,
        trees::transfer_tree::TransferTree,
    },
    constants::{
        BALANCE_SLOT_TREE_HEIGHT, BURN_CHANNEL_ID, MAX_CHANNEL_MEMBERS, MAX_CHANNEL_TOKENS,
        MAX_SIG_CLUSTER,
    },
    ethereum_types::{address::Address, bytes32::Bytes32},
    regev::{
        AmountWitness, MAX_HOMO_ADDS_BEFORE_REFRESH, RegevCiphertext, RegevPk, RegevSecurityLevel,
        decrypt_amount, encrypt_amount, prove_balance_refresh_witnessed, prove_channel_tx_decrypted,
        prove_channel_update_decrypted,
    },
    utils::{
        poseidon_hash_out::PoseidonHashOut,
        trees::incremental_merkle_tree::{IncrementalMerkleProof, IncrementalMerkleTree},
    },
    wallet_core::{
        ChannelSnapshot, InterChannelDebitPayload, InterChannelTransferDescriptor, MemberInfo,
        MemberKeys, RefreshPayload, SETTLED_TX_ACCUMULATOR_HEIGHT, SlimSendPayload, WResult,
        WalletError, inter_channel_base_transfer, inter_channel_tx_v2, refresh_next_state,
        sign_channel_tx_sender, u64_to_u256, verify_state_sig,
    },
};

/// Wire format version of [`SlotView`].
pub const SLOT_VIEW_FORMAT: u32 = 1;

fn err<T>(m: impl Into<String>) -> WResult<T> {
    Err(WalletError(m.into()))
}

/// The record fields a delegate needs: the channel identity, the participant counts, the block
/// producer slot and the co-signers' signing identities (the only keys whose signatures a state
/// carries). `slot_pk_g` is the record's identity at the viewed slot as the co-signers hold it;
/// it is informational (a wrong value only makes the delegate's own sends fail verification).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotViewRecord {
    pub channel_id: ChannelId,
    pub member_count: u8,
    pub delegate_count: u16,
    pub bp_member_slot: u8,
    pub cosigner_pk_gs: Vec<Bytes32>,
    pub slot_pk_g: Bytes32,
}

/// One participant's view of a signed channel state. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotView {
    pub format: u32,
    pub record: SlotViewRecord,
    pub state: ChannelStateHeader,
    pub slot: u16,
    pub row: SlotRow,
    /// Siblings of `slot` in the balance-slot tree, leaf level first.
    pub slot_siblings: Vec<PoseidonHashOut>,
    /// Leaf count of the settled-tx accumulator and the siblings of its next (empty) position.
    /// [`Self::verify`] checks only that this position is empty under the signed root; the
    /// co-signer's rebuild of an inter-channel debit is what pins it to the true leaf count.
    pub accumulator_len: u64,
    pub accumulator_next_siblings: Vec<PoseidonHashOut>,
}

impl SlotView {
    /// Co-signer side: project the full signed snapshot onto `slot`.
    pub fn from_snapshot(snapshot: &ChannelSnapshot, slot: u16) -> WResult<Self> {
        Self::from_parts(
            &snapshot.record,
            &snapshot.state,
            &snapshot.settled_tx_accumulator,
            slot,
        )
    }

    pub fn from_parts(
        record: &ChannelRecord,
        state: &ChannelState,
        accumulator: &IncrementalMerkleTree<Bytes32>,
        slot: u16,
    ) -> WResult<Self> {
        let bs = &state.balance_state;
        let active = bs.member_count as usize + bs.delegate_count as usize;
        if slot as usize >= active {
            return err(format!(
                "slot view: slot {slot} is not an active slot (active {active})"
            ));
        }
        let member_count = record.member_count as usize;
        if member_count > MAX_SIG_CLUSTER || member_count > record.member_pk_gs.len() {
            return err("slot view: record member_count out of range");
        }
        let accumulator_len = accumulator.len() as u64;
        if accumulator.height() != SETTLED_TX_ACCUMULATOR_HEIGHT
            || accumulator_len >= 1u64 << SETTLED_TX_ACCUMULATOR_HEIGHT
        {
            return err("slot view: settled-tx accumulator has no free position");
        }
        let slot_proof = bs.slot_tree().prove(slot as u64);
        let accumulator_proof = accumulator.prove(accumulator_len);
        Ok(Self {
            format: SLOT_VIEW_FORMAT,
            record: SlotViewRecord {
                channel_id: record.channel_id,
                member_count: record.member_count,
                delegate_count: record.delegate_count,
                bp_member_slot: record.bp_member_slot,
                cosigner_pk_gs: record.member_pk_gs[..member_count].to_vec(),
                slot_pk_g: record.member_pk_gs[slot as usize],
            },
            state: state.header(),
            slot,
            row: bs.slot_row(slot as usize),
            slot_siblings: slot_proof.0.siblings,
            accumulator_len,
            accumulator_next_siblings: accumulator_proof.0.siblings,
        })
    }

    pub fn active_slots(&self) -> usize {
        self.state.balance_state.active_slots()
    }

    /// The balance-slot root `row` yields at `self.slot` through `self.slot_siblings`.
    pub fn slot_root_for(&self, row: &SlotRow) -> PoseidonHashOut {
        IncrementalMerkleProof::<PoseidonHashOut>::from_siblings(self.slot_siblings.clone())
            .get_root(&row.leaf_hash(), self.slot as u64)
    }

    /// The accumulator root after appending `tx_hash` at the next free position.
    pub fn accumulator_root_after_push(&self, tx_hash: Bytes32) -> Bytes32 {
        Bytes32::from(
            IncrementalMerkleProof::<Bytes32>::from_siblings(
                self.accumulator_next_siblings.clone(),
            )
            .get_root(&tx_hash, self.accumulator_len),
        )
    }

    /// Everything a delegate can check about a view without its keys: shape, the row's
    /// canonicality, the slot path against the signed header's root, the accumulator tail
    /// against the header's accumulator root, the recomputed IMCH digest, and every co-signer's
    /// signature over it.
    pub fn verify(&self) -> WResult<()> {
        if self.format != SLOT_VIEW_FORMAT {
            return err(format!("slot view: unsupported format {}", self.format));
        }
        let header = &self.state.balance_state;
        if self.record.channel_id != self.state.channel_id
            || header.channel_id != self.state.channel_id
            || self.state.channel_fund.channel_id != self.state.channel_id
        {
            return err("slot view: channel ids disagree");
        }
        if self.record.member_count != header.member_count
            || self.record.delegate_count != header.delegate_count
        {
            return err("slot view: record and state disagree on the participant counts");
        }
        let member_count = header.member_count as usize;
        if !(2..=MAX_SIG_CLUSTER).contains(&member_count) {
            return err(format!(
                "slot view: member_count {member_count} out of [2, {MAX_SIG_CLUSTER}]"
            ));
        }
        if self.record.cosigner_pk_gs.len() != member_count {
            return err("slot view: co-signer identity list does not match member_count");
        }
        for (i, pk_g) in self.record.cosigner_pk_gs.iter().enumerate() {
            if *pk_g == Bytes32::default()
                || self.record.cosigner_pk_gs[..i].contains(pk_g)
            {
                return err("slot view: co-signer identities must be nonzero and distinct");
            }
        }
        if self.record.bp_member_slot as usize >= member_count {
            return err("slot view: block producer is not a co-signer slot");
        }
        let active = self.active_slots();
        if active > MAX_CHANNEL_MEMBERS || self.slot as usize >= active {
            return err(format!(
                "slot view: slot {} outside the active region {active}",
                self.slot
            ));
        }
        let token_count = header.token_count as usize;
        if !(1..=MAX_CHANNEL_TOKENS).contains(&token_count) {
            return err(format!("slot view: token_count {token_count} out of range"));
        }
        self.verify_row(&self.row)?;
        if self.slot_siblings.len() != BALANCE_SLOT_TREE_HEIGHT {
            return err("slot view: slot path has the wrong height");
        }
        if self.slot_root_for(&self.row) != header.slot_tree_root {
            return err("slot view: the slot's row is not under the signed slot root");
        }
        if self.accumulator_next_siblings.len() != SETTLED_TX_ACCUMULATOR_HEIGHT
            || self.accumulator_len >= 1u64 << SETTLED_TX_ACCUMULATOR_HEIGHT
        {
            return err("slot view: accumulator tail has the wrong shape");
        }
        let empty_root = Bytes32::from(
            IncrementalMerkleProof::<Bytes32>::from_siblings(
                self.accumulator_next_siblings.clone(),
            )
            .get_root(&Bytes32::default(), self.accumulator_len),
        );
        if empty_root != header.settled_tx_accumulator_root {
            return err("slot view: accumulator tail does not match the signed accumulator root");
        }
        let digest = self.state.signing_digest();
        if self.state.digest != digest {
            return err("slot view: state.digest does not match the recomputed signing digest");
        }
        for slot in 0..member_count {
            let expected = self.record.cosigner_pk_gs[slot];
            let sig = self
                .state
                .member_signatures
                .iter()
                .find(|s| s.member_slot as usize == slot)
                .ok_or_else(|| WalletError(format!("slot view: missing signature for slot {slot}")))?;
            if sig.pk_g != expected {
                return err(format!("slot view: slot {slot} signature identity mismatch"));
            }
            verify_state_sig(expected, &digest, &sig.signature)?;
        }
        Ok(())
    }

    fn verify_row(&self, row: &SlotRow) -> WResult<()> {
        let token_count = self.state.balance_state.token_count as usize;
        if row.regev_pk_digest == Bytes32::default() {
            return err("slot view: active slot has no Regev key digest");
        }
        if row.recipient == Address::default() {
            return err("slot view: active slot has no L1 exit address");
        }
        for t in 0..MAX_CHANNEL_TOKENS {
            row.enc_balances[t]
                .validate()
                .map_err(|e| WalletError(format!("slot view: non-canonical ciphertext: {e}")))?;
            if row.pending_adds[t] > MAX_HOMO_ADDS_BEFORE_REFRESH as u32 {
                return err("slot view: pending_adds above the refresh budget");
            }
            if t >= token_count
                && (row.enc_balances[t] != *crate::common::balance_state::zero_ciphertext()
                    || row.pending_adds[t] != 0)
            {
                return err("slot view: inactive token position is not zero");
            }
        }
        Ok(())
    }

    /// [`Self::verify`] plus the checks that need this wallet's keys: the slot's committed Regev
    /// key is this wallet's, and every active token position decrypts.
    pub fn verify_for(&self, keys: &MemberKeys) -> WResult<()> {
        self.verify()?;
        if self.row.regev_pk_digest != Bytes32::from(keys.regev_pk.poseidon_digest()) {
            return err("slot view: the slot's Regev key is not this wallet's key");
        }
        for t in 0..self.state.balance_state.token_count as usize {
            decrypt_amount(&keys.regev_sk, &self.row.enc_balances[t]).map_err(|e| {
                WalletError(format!("slot view: own balance at token {t} does not decrypt: {e:?}"))
            })?;
        }
        Ok(())
    }

    pub fn local_token_slot(&self, token_index: u32) -> WResult<usize> {
        let header = &self.state.balance_state;
        header.token_registry[..header.token_count as usize]
            .iter()
            .position(|&t| t == token_index)
            .ok_or_else(|| WalletError(format!("token {token_index} is not registered in this channel")))
    }

    fn check_token_slot(&self, token_slot: u8) -> WResult<usize> {
        let ts = token_slot as usize;
        if ts >= MAX_CHANNEL_TOKENS || ts >= self.state.balance_state.token_count as usize {
            return err(format!(
                "token_slot {ts} out of range (token_count {})",
                self.state.balance_state.token_count
            ));
        }
        Ok(ts)
    }

    fn check_own_key(&self, keys: &MemberKeys) -> WResult<()> {
        if self.row.regev_pk_digest != Bytes32::from(keys.regev_pk.poseidon_digest()) {
            return err("the viewed slot is not this wallet's slot");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// In-channel send
// ---------------------------------------------------------------------------

pub struct ViewSend {
    pub payload: SlimSendPayload,
    pub after_witness: AmountWitness,
    pub new_balance: u64,
}

/// Build an in-channel send from a slot view. `recipient` is the recipient slot's public
/// participant record as the relay serves it; the co-signers re-derive the E-1 statement and the
/// tx digest from their own record, so a wrong record only makes the send fail verification.
#[allow(clippy::too_many_arguments)]
pub fn build_view_send(
    keys: &MemberKeys,
    view: &SlotView,
    recipient: &MemberInfo,
    token_slot: u8,
    amount: u64,
    nonce: Bytes32,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<ViewSend> {
    view.check_own_key(keys)?;
    if recipient.slot == view.slot {
        return err("sender and recipient must differ");
    }
    if recipient.slot as usize >= view.active_slots() {
        return err("recipient slot is not an active slot");
    }
    recipient
        .regev_pk
        .validate()
        .map_err(|e| WalletError(format!("recipient Regev key: {e}")))?;
    let ts = view.check_token_slot(token_slot)?;
    let before_ct = &view.row.enc_balances[ts];
    let before_amount = decrypt_amount(&keys.regev_sk, before_ct)
        .map_err(|e| WalletError(format!("{e:?}")))?;
    if before_amount < amount {
        return err("insufficient balance");
    }
    let (enc_amount, enc_amount_w) = encrypt_amount(rng, &recipient.regev_pk, amount)
        .map_err(|e| WalletError(format!("{e:?}")))?;
    let new_balance = before_amount - amount;
    let (after_ct, after_w) = encrypt_amount(rng, &keys.regev_pk, new_balance)
        .map_err(|e| WalletError(format!("{e:?}")))?;
    let proof = prove_channel_tx_decrypted(
        level,
        &keys.regev_pk,
        &keys.regev_sk,
        &recipient.regev_pk,
        before_ct,
        (&enc_amount, &enc_amount_w),
        (&after_ct, &after_w),
    )
    .map_err(|e| WalletError(format!("{e:?}")))?;
    let sender_hash = keys.pk_g();
    let tx_digest = ChannelTx::signing_digest(
        view.state.channel_id,
        view.state.digest,
        &enc_amount,
        nonce,
        token_slot,
        sender_hash,
        recipient.pk_g,
    );
    let sender_hash_sig = sign_channel_tx_sender(keys, &tx_digest, level)?;
    let channel_tx = ChannelTx {
        recipient_pk_g: recipient.pk_g,
        token_slot,
        enc_amount,
        nonce,
        channel_tx_zkp: ChannelProofEnvelope {
            role: TransitionProofRole::ChannelStateUpdate,
            backend: ProofBackend::Plonky3,
            proof,
        },
        sender_pk_g: sender_hash,
        sender_hash_sig,
        sender_pk_b: keys.pk_b(),
    };
    Ok(ViewSend {
        payload: SlimSendPayload {
            anchor_digest: view.state.digest,
            sender_index: view.slot,
            recipient_index: recipient.slot,
            channel_tx,
            after_ct,
        },
        after_witness: after_w,
        new_balance,
    })
}

// ---------------------------------------------------------------------------
// Balance refresh
// ---------------------------------------------------------------------------

/// A refresh intent: the value-preserving re-encryption of one own token position, without a
/// proposed successor state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlimRefreshPayload {
    pub anchor_digest: Bytes32,
    pub member_index: u16,
    pub token_slot: u8,
    pub refresh_proof: ChannelProofEnvelope,
    pub new_ct: RegevCiphertext,
}

pub fn build_view_refresh(
    keys: &MemberKeys,
    view: &SlotView,
    token_slot: u8,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<(SlimRefreshPayload, AmountWitness)> {
    view.check_own_key(keys)?;
    let ts = view.check_token_slot(token_slot)?;
    let old_ct = &view.row.enc_balances[ts];
    let (new_ct, new_witness, proof) =
        prove_balance_refresh_witnessed(rng, level, &keys.regev_pk, &keys.regev_sk, old_ct)
            .map_err(|e| WalletError(format!("{e:?}")))?;
    Ok((
        SlimRefreshPayload {
            anchor_digest: view.state.digest,
            member_index: view.slot,
            token_slot,
            refresh_proof: ChannelProofEnvelope {
                role: TransitionProofRole::ChannelStateUpdate,
                backend: ProofBackend::Plonky3,
                proof,
            },
            new_ct,
        },
        new_witness,
    ))
}

/// Co-signer side: rebuild the full [`RefreshPayload`] from a slim refresh against the trusted
/// head, so the unchanged refresh transition verifier runs on it.
pub fn inflate_refresh(
    snapshot: &ChannelSnapshot,
    slim: &SlimRefreshPayload,
) -> WResult<RefreshPayload> {
    if slim.anchor_digest != snapshot.state.digest {
        return err("stale refresh: the anchor is not the channel head");
    }
    let active = snapshot.state.balance_state.member_count as usize
        + snapshot.state.balance_state.delegate_count as usize;
    if slim.member_index as usize >= active {
        return err("refresh slot is not an active slot");
    }
    let proposed_next_state = refresh_next_state(
        &snapshot.state,
        slim.member_index,
        slim.token_slot,
        slim.new_ct.clone(),
    )?;
    Ok(RefreshPayload {
        member_index: slim.member_index,
        token_slot: slim.token_slot,
        refresh_proof: slim.refresh_proof.clone(),
        proposed_next_state,
        members: snapshot.members.clone(),
        record: snapshot.record.clone(),
    })
}

// ---------------------------------------------------------------------------
// Inter-channel send and L1 burn
// ---------------------------------------------------------------------------

/// An inter-channel debit intent: the E-2-bearing [`InterChannelTx`] (whose signed small block
/// already names the successor's H1) plus the sender's fresh post-debit ciphertext and the digest
/// of the successor the sender computed from its view. The co-signer rebuilds the successor from
/// its own state and refuses unless the digests agree.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlimInterChannelDebitPayload {
    pub anchor_digest: Bytes32,
    pub sender_index: u16,
    pub proposed_digest: Bytes32,
    pub inter_channel_tx: InterChannelTx,
    pub amount: u64,
    pub after_ct: RegevCiphertext,
    pub destination_recipient_pk: RegevPk,
    /// The successor's fresh `shared_native_nullifier_root` (sender-chosen, §C-3).
    pub new_nullifier_root: Bytes32,
}

pub struct BuiltViewInterChannelSend {
    pub debit_payload: SlimInterChannelDebitPayload,
    pub transfer_descriptor: InterChannelTransferDescriptor,
    pub new_balance_witness: AmountWitness,
    pub new_balance: u64,
}

/// The settled-tx-chain leaf an inter-channel debit pushes: the burn descriptor for an L1 burn,
/// the tx leaf otherwise. Recomputed by the co-signer from the signed tx.
fn debit_chain_leaf(tx: &InterChannelTx, amount: u64) -> WResult<(Bytes32, Bytes32)> {
    let delta = tx
        .receiver_deltas
        .first()
        .ok_or_else(|| WalletError("inter-channel tx has no receiver delta".into()))?;
    let tx_leaf = tx_leaf_hash(
        tx.source_pk_g,
        tx.sender_delta_ct.digest(),
        delta.receiver_pk_g,
        delta.receiver_regev_pk_digest,
        delta.amount.digest(),
    );
    let chain_leaf = if tx.destination_channel_id.channel_id() == BURN_CHANNEL_ID {
        burn_descriptor(
            tx.source_channel_id,
            tx.base_nonce,
            tx_leaf,
            delta.receiver_pk_g,
            tx.token_index,
            u64_to_u256(amount),
        )
    } else {
        tx_leaf
    };
    Ok((tx_leaf, chain_leaf))
}

/// Inter-channel send from a slot view. Mirrors `wallet_core::build_inter_channel_send_with`
/// field for field; the successor HEADER is computed from the view (own row replaced through the
/// own slot path, accumulator appended through its tail).
#[allow(clippy::too_many_arguments)]
pub fn build_view_inter_channel_send(
    keys: &MemberKeys,
    view: &SlotView,
    destination_channel_id: ChannelId,
    destination_recipient_slot: u16,
    destination_recipient_pk: RegevPk,
    destination_recipient_pk_g: Bytes32,
    destination_base_transfer_salt: Salt,
    token_index: u32,
    base_nonce: u32,
    amount: u64,
    new_nullifier_root: Bytes32,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<BuiltViewInterChannelSend> {
    view.check_own_key(keys)?;
    let prev = &view.state;
    let token_slot = view.local_token_slot(token_index)?;
    let before_ct = view.row.enc_balances[token_slot].clone();
    let before_amount = decrypt_amount(&keys.regev_sk, &before_ct)
        .map_err(|e| WalletError(format!("{e:?}")))?;
    if before_amount < amount {
        return err("insufficient balance");
    }
    if destination_channel_id == view.record.channel_id {
        return err("inter-channel send destination must be a DIFFERENT channel");
    }
    if new_nullifier_root == prev.shared_native_nullifier_root {
        return err("shared_native_nullifier_root must advance on a send (detail2 §C-3)");
    }
    if prev.channel_fund.amounts[token_slot] < u64_to_u256(amount) {
        return err("channel fund below the debit amount");
    }
    let sender_pk = keys.regev_pk.clone();
    let sender_pk_g = keys.pk_g();
    let map = |e: crate::regev::RegevError| WalletError(format!("{e:?}"));
    let (after_ct, after_w) = encrypt_amount(rng, &sender_pk, before_amount - amount).map_err(map)?;
    let (sender_delta_ct, sender_delta_w) = encrypt_amount(rng, &sender_pk, amount).map_err(map)?;
    let (receiver_delta_ct, receiver_delta_w) =
        encrypt_amount(rng, &destination_recipient_pk, amount).map_err(map)?;
    let e2 = prove_channel_update_decrypted(
        level,
        &sender_pk,
        &keys.regev_sk,
        &destination_recipient_pk,
        &before_ct,
        (&after_ct, &after_w),
        (&sender_delta_ct, &sender_delta_w),
        (&receiver_delta_ct, &receiver_delta_w),
        amount,
        token_index,
    )
    .map_err(map)?;

    let destination_recipient_pk_digest = Bytes32::from(destination_recipient_pk.poseidon_digest());
    let tx_leaf = tx_leaf_hash(
        sender_pk_g,
        sender_delta_ct.digest(),
        destination_recipient_pk_g,
        destination_recipient_pk_digest,
        receiver_delta_ct.digest(),
    );
    let is_burn = destination_channel_id.channel_id() == BURN_CHANNEL_ID;
    let burn_aux = if is_burn {
        burn_descriptor(
            view.record.channel_id,
            base_nonce,
            tx_leaf,
            destination_recipient_pk_g,
            token_index,
            u64_to_u256(amount),
        )
    } else {
        tx_leaf
    };
    if is_burn && destination_base_transfer_salt != Salt::default() {
        return err("burn transfer must carry the canonical zero destination base transfer salt");
    }
    if is_burn {
        extract_address_from_recipient(destination_recipient_pk_g).map_err(|error| {
            WalletError(format!(
                "burn transfer recipient must be canonical ADDRESS_TAG: {error}"
            ))
        })?;
    }
    let base_recipient = if is_burn {
        destination_recipient_pk_g
    } else {
        calculate_recipient_from_user_id(destination_channel_id, destination_base_transfer_salt)
    };
    let base_transfer = inter_channel_base_transfer(base_recipient, token_index, amount, burn_aux);
    let mut transfer_tree = TransferTree::init();
    transfer_tree.push(base_transfer.clone());
    let src_id = view.record.channel_id.as_u64();
    let (tx_v2, tx_v2_tree) = inter_channel_tx_v2(view.record.channel_id, &base_transfer, base_nonce);
    debug_assert_eq!(tx_v2.transfer_tree_root, transfer_tree.get_root());
    let tx_tree_root: Bytes32 = tx_v2_tree.get_root().into();
    let tx_v2_merkle_proof = tx_v2_tree.prove(src_id);
    let tx_hash = inter_channel_tx_hash(
        view.record.channel_id,
        destination_channel_id,
        token_index,
        tx_tree_root,
        tx_leaf,
    );

    // Successor header: own row replaced (fresh `after`, add counter reset), fund debited, chain
    // and accumulator advanced, version/epoch/small block bumped, H2 = tx tree root.
    let mut next_row = view.row.clone();
    next_row.enc_balances[token_slot] = after_ct.clone();
    next_row.pending_adds[token_slot] = 0;
    let mut next = prev.clone();
    next.epoch = prev.epoch + 1;
    next.small_block_number = prev.small_block_number + 1;
    next.channel_fund.amounts[token_slot] -= u64_to_u256(amount);
    next.balance_state.slot_tree_root = view.slot_root_for(&next_row);
    next.balance_state.settled_tx_chain =
        settled_tx_chain_push(prev.balance_state.settled_tx_chain, burn_aux);
    next.balance_state.settled_tx_accumulator_root = view.accumulator_root_after_push(tx_hash);
    next.balance_state.state_version = prev.balance_state.state_version + 1;
    next.h2_tag = tx_tree_root;
    next.shared_native_nullifier_root = new_nullifier_root;
    next.prev_digest = prev.digest;
    next.member_signatures = Vec::new();
    next.digest = next.signing_digest();
    let h1_prime = next.balance_state.h1();

    let mut inter_channel_tx = InterChannelTx {
        tx_inclusion_proof: MerkleInclusionProof::default(),
        signed_small_block: SignedSmallBlock {
            message: SmallBlockRootMessage {
                channel_id: view.record.channel_id,
                bp_member_slot: view.record.bp_member_slot,
                bp_pk_g: view.record.cosigner_pk_gs[view.record.bp_member_slot as usize],
                small_block_number: next.small_block_number,
                prev_small_block_root: Bytes32::default(),
                tx_tree_root,
                state_commitment_root: h1_prime,
                medium_epoch_hint: 0,
                close_freeze_nonce: prev.close_freeze_nonce,
            },
            signatures: (0..view.record.member_count)
                .map(|slot| MemberSignature {
                    member_slot: slot,
                    pk_g: view.record.cosigner_pk_gs[slot as usize],
                    signature: structural_cosign_placeholder(1),
                })
                .collect(),
            aggregated_signature_proof: Vec::new(),
            medium_block_number: 0,
            confirmation_proof: Vec::new(),
        },
        sender_delta_ct: sender_delta_ct.clone(),
        source_channel_id: view.record.channel_id,
        destination_channel_id,
        token_index,
        base_nonce,
        destination_base_transfer_salt,
        source_pk_g: sender_pk_g,
        seal: Bytes32::default(),
        tx_hash,
        intmax_transfer_commitment: Bytes32::from(base_transfer.poseidon_hash()),
        recipient_memo: Vec::new(),
        receiver_deltas: vec![ReceiverBalanceDelta {
            receiver_pk_g: destination_recipient_pk_g,
            receiver_regev_pk_digest: destination_recipient_pk_digest,
            amount: receiver_delta_ct.clone(),
        }],
        channel_update_zkp: ChannelProofEnvelope {
            role: TransitionProofRole::ChannelStateUpdate,
            backend: ProofBackend::Plonky3,
            proof: e2,
        },
        transport_proof: Vec::new(),
        sender_hash_sig: Vec::new(),
        sender_pk_b: keys.pk_b(),
    };
    inter_channel_tx.sender_hash_sig =
        sign_channel_tx_sender(keys, &inter_channel_tx.signing_digest(), level)?;

    Ok(BuiltViewInterChannelSend {
        debit_payload: SlimInterChannelDebitPayload {
            anchor_digest: prev.digest,
            sender_index: view.slot,
            proposed_digest: next.digest,
            inter_channel_tx: inter_channel_tx.clone(),
            amount,
            after_ct: after_ct.clone(),
            destination_recipient_pk: destination_recipient_pk.clone(),
            new_nullifier_root,
        },
        transfer_descriptor: InterChannelTransferDescriptor {
            source_channel_id: view.record.channel_id,
            destination_channel_id,
            recipient_slot: destination_recipient_slot,
            amount,
            tx_hash,
            tx_tree_root,
            source_pk_g: sender_pk_g,
            receiver_pk_g: destination_recipient_pk_g,
            destination_base_transfer_salt,
            source_pk: sender_pk,
            receiver_pk: destination_recipient_pk,
            sender_before_ct: before_ct,
            sender_after_ct: after_ct,
            sender_delta_ct,
            receiver_delta: receiver_delta_ct,
            inter_channel_tx,
            tx_v2,
            tx_v2_merkle_proof,
        },
        new_balance_witness: after_w,
        new_balance: before_amount - amount,
    })
}

/// L1 burn (partial withdrawal) from a slot view: an inter-channel send to `BURN_CHANNEL_ID`
/// whose base recipient is the ADDRESS_TAG of `withdrawal_l1_address`.
#[allow(clippy::too_many_arguments)]
pub fn build_view_burn_send(
    keys: &MemberKeys,
    view: &SlotView,
    withdrawal_l1_address: Address,
    token_index: u32,
    base_nonce: u32,
    amount: u64,
    new_nullifier_root: Bytes32,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<BuiltViewInterChannelSend> {
    let burn_recipient = calculate_recipient_from_address(withdrawal_l1_address);
    let burn_channel = ChannelId::new(BURN_CHANNEL_ID as u64)
        .map_err(|e| WalletError(format!("BURN_CHANNEL_ID is not a valid ChannelId: {e:?}")))?;
    build_view_inter_channel_send(
        keys,
        view,
        burn_channel,
        0,
        RegevPk::padding(),
        burn_recipient,
        Salt::default(),
        token_index,
        base_nonce,
        amount,
        new_nullifier_root,
        level,
        rng,
    )
}

/// Co-signer side: rebuild the full [`InterChannelDebitPayload`] (and the successor's
/// accumulator) from a slim debit against the trusted head. Refuses unless the rebuilt
/// successor's digest is the one the sender computed — the sender's signed small block already
/// names that successor's H1, so a disagreement means the two sides hold different states.
pub fn inflate_inter_channel_debit(
    snapshot: &ChannelSnapshot,
    slim: &SlimInterChannelDebitPayload,
) -> WResult<(InterChannelDebitPayload, IncrementalMerkleTree<Bytes32>)> {
    let prev = &snapshot.state;
    if slim.anchor_digest != prev.digest {
        return err("stale inter-channel debit: the anchor is not the channel head");
    }
    let sender = slim.sender_index as usize;
    let active =
        prev.balance_state.member_count as usize + prev.balance_state.delegate_count as usize;
    if sender >= active {
        return err("inter-channel debit sender is not an active slot");
    }
    let tx = &slim.inter_channel_tx;
    let token_slot = crate::wallet_core::resolve_local_token_slot(&prev.balance_state, tx.token_index)?;
    if prev.channel_fund.amounts[token_slot] < u64_to_u256(slim.amount) {
        return err("channel fund below the debit amount");
    }
    let (_tx_leaf, chain_leaf) = debit_chain_leaf(tx, slim.amount)?;
    let mut accumulator = snapshot.settled_tx_accumulator.clone();
    if accumulator.len() as u64 >= 1u64 << accumulator.height() {
        return err("settled-tx accumulator is full");
    }
    accumulator.push(tx.tx_hash);
    let mut enc_balances = prev.balance_state.enc_balances.clone();
    enc_balances[sender][token_slot] = slim.after_ct.clone();
    let mut pending_adds = prev.balance_state.pending_adds.clone();
    pending_adds[sender][token_slot] = 0;
    let mut channel_fund = prev.channel_fund.clone();
    channel_fund.amounts[token_slot] -= u64_to_u256(slim.amount);
    let next = ChannelState {
        epoch: prev.epoch + 1,
        small_block_number: prev.small_block_number + 1,
        channel_fund,
        balance_state: BalanceState {
            enc_balances,
            pending_adds,
            settled_tx_chain: settled_tx_chain_push(prev.balance_state.settled_tx_chain, chain_leaf),
            settled_tx_accumulator_root: Bytes32::from(accumulator.get_root()),
            state_version: prev.balance_state.state_version + 1,
            ..prev.balance_state.clone()
        },
        h2_tag: tx.signed_small_block.message.tx_tree_root,
        shared_native_nullifier_root: slim.new_nullifier_root,
        prev_digest: prev.digest,
        member_signatures: Vec::new(),
        ..prev.clone()
    }
    .with_computed_digest();
    if next.digest != slim.proposed_digest {
        return err(
            "inter-channel debit: the successor rebuilt from the channel head does not match the \
             sender's proposal",
        );
    }
    Ok((
        InterChannelDebitPayload {
            sender_index: slim.sender_index,
            proposed_next_state: next,
            inter_channel_tx: tx.clone(),
            amount: slim.amount,
            members: snapshot.members.clone(),
            record: snapshot.record.clone(),
            destination_recipient_pk: slim.destination_recipient_pk.clone(),
            aggregate_manifest: None,
        },
        accumulator,
    ))
}

#[cfg(test)]
#[cfg(not(debug_assertions))]
mod tests {
    use rand010::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        ethereum_types::u32limb_trait::U32LimbTrait as _,
        regev::encrypt_amount,
        wallet_core::{
            add_signature, assemble_genesis_state, build_inter_channel_send_token_at_base_nonce_decrypted,
            build_record, build_send_token_decrypted, default_settled_tx_accumulator,
            regev_pks_array, sign_state, verify_inter_channel_send_transition,
            verify_refresh_transition, verify_slim_send_tx,
        },
    };

    const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Test;

    /// Two co-signers (slots 0, 1) and two delegates (slots 2, 3), signed genesis.
    fn channel(rng: &mut StdRng, balances: [u64; 4]) -> (ChannelSnapshot, Vec<MemberKeys>) {
        let keys: Vec<MemberKeys> = (0..4).map(|_| MemberKeys::generate(rng)).collect();
        let members: Vec<MemberInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| MemberInfo {
                slot: i as u16,
                pk_g: k.pk_g(),
                pk_b: k.pk_b(),
                regev_pk: k.regev_pk.clone(),
            })
            .collect();
        let record = build_record(21, &members, 0, 2).unwrap();
        let mut cts = Vec::new();
        for (i, &b) in balances.iter().enumerate() {
            cts.push(encrypt_amount(rng, &keys[i].regev_pk, b).unwrap().0);
        }
        let pkds: Vec<Bytes32> = keys
            .iter()
            .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()))
            .collect();
        let recipients: Vec<Address> = (0..4)
            .map(|i| Address::from_u32_slice(&[0x7E57_0000u32 + i; 5]).unwrap())
            .collect();
        let fund: u64 = balances.iter().sum();
        let mut state = assemble_genesis_state(&record, &cts, &pkds, &recipients, fund).unwrap();
        for s in 0..2u8 {
            let sig = sign_state(&keys[s as usize], s, &state).unwrap();
            add_signature(&mut state, sig);
        }
        (
            ChannelSnapshot {
                record,
                state,
                members,
                settled_tx_accumulator: default_settled_tx_accumulator(),
            },
            keys,
        )
    }

    #[test]
    fn view_recomputes_the_signed_digest_and_verifies() {
        let mut rng = StdRng::seed_from_u64(0x51_07);
        let (snapshot, keys) = channel(&mut rng, [5, 6, 7, 8]);
        for slot in 0..4u16 {
            let view = SlotView::from_snapshot(&snapshot, slot).unwrap();
            assert_eq!(view.state.balance_state.h1(), snapshot.state.balance_state.h1());
            assert_eq!(view.state.signing_digest(), snapshot.state.digest);
            view.verify_for(&keys[slot as usize]).expect("own view verifies");
            assert!(view.verify_for(&keys[(slot as usize + 1) % 4]).is_err());
        }
        // The view carries one row, never the other participants' rows.
        let json = serde_json::to_string(&SlotView::from_snapshot(&snapshot, 2).unwrap()).unwrap();
        let full = serde_json::to_string(&snapshot).unwrap();
        assert!(json.len() * 3 < full.len(), "view {} B vs snapshot {} B", json.len(), full.len());
    }

    #[test]
    fn tampered_views_are_refused() {
        let mut rng = StdRng::seed_from_u64(0x51_08);
        let (snapshot, keys) = channel(&mut rng, [5, 6, 7, 8]);
        let view = SlotView::from_snapshot(&snapshot, 3).unwrap();
        view.verify_for(&keys[3]).unwrap();

        let mut bad = view.clone();
        bad.row.enc_balances[0] = encrypt_amount(&mut rng, &keys[3].regev_pk, 999).unwrap().0;
        assert!(bad.verify().is_err(), "a row not under the signed root");

        let mut bad = view.clone();
        bad.slot_siblings[4] = PoseidonHashOut::hash_inputs_u64(&[1]);
        assert!(bad.verify().is_err(), "a forged path");

        let mut bad = view.clone();
        bad.slot = 2;
        assert!(bad.verify().is_err(), "the row moved to another slot");

        let mut bad = view.clone();
        bad.state.member_signatures.pop();
        assert!(bad.verify().is_err(), "a missing co-signature");

        let mut bad = view.clone();
        bad.state.epoch += 1;
        assert!(bad.verify().is_err(), "a header field not under the signatures");

        let mut bad = view.clone();
        bad.record.cosigner_pk_gs[1] = keys[3].pk_g();
        assert!(bad.verify().is_err(), "a substituted co-signer");

        let mut bad = view.clone();
        bad.accumulator_next_siblings[0] = PoseidonHashOut::hash_inputs_u64(&[2]);
        assert!(bad.verify().is_err(), "an accumulator tail not under the signed root");
        // The tail proves only that `accumulator_len` is an EMPTY position under the signed root;
        // a later empty position verifies too. That is liveness-only: a debit appended at the
        // wrong position yields a successor the co-signer's rebuild refuses
        // (`inflate_inter_channel_debit` compares digests).
    }

    #[test]
    fn view_send_is_the_full_builders_send_and_verifies_as_a_slim_tx() {
        let (snapshot, keys) = channel(&mut StdRng::seed_from_u64(0x51_09), [5, 6, 7, 8]);
        let nonce = Bytes32::from_u32_slice(&[9; 8]).unwrap();
        let view = SlotView::from_snapshot(&snapshot, 2).unwrap();
        let recipient = snapshot.members[3].clone();
        let from_view = build_view_send(
            &keys[2], &view, &recipient, 0, 3, nonce, LEVEL, &mut StdRng::seed_from_u64(77),
        )
        .unwrap();
        let from_full = build_send_token_decrypted(
            &keys[2], &snapshot, 2, 3, 0, 3, nonce, LEVEL, &mut StdRng::seed_from_u64(77),
        )
        .unwrap();
        let full_slim = from_full.payload.to_slim();
        assert_eq!(from_view.payload.anchor_digest, full_slim.anchor_digest);
        assert_eq!(from_view.payload.after_ct, full_slim.after_ct);
        assert_eq!(from_view.payload.channel_tx.enc_amount, full_slim.channel_tx.enc_amount);
        assert_eq!(from_view.new_balance, 7 - 3);
        let pks = regev_pks_array(&snapshot.members);
        verify_slim_send_tx(
            &snapshot.state, &snapshot.record, &snapshot.members, &pks, &from_view.payload, LEVEL,
            None, None,
        )
        .expect("the co-signer accepts the view-built send");
    }

    #[test]
    fn view_refresh_inflates_to_a_verified_refresh() {
        let mut rng = StdRng::seed_from_u64(0x51_0A);
        let (snapshot, keys) = channel(&mut rng, [5, 6, 7, 8]);
        let view = SlotView::from_snapshot(&snapshot, 3).unwrap();
        let (slim, _w) = build_view_refresh(&keys[3], &view, 0, LEVEL, &mut rng).unwrap();
        let fat = inflate_refresh(&snapshot, &slim).unwrap();
        verify_refresh_transition(&snapshot.state, &snapshot.record, &fat, LEVEL)
            .expect("the co-signer accepts the view-built refresh");
        let mut stale = slim.clone();
        stale.anchor_digest = Bytes32::default();
        assert!(inflate_refresh(&snapshot, &stale).is_err());
    }

    #[test]
    fn view_inter_channel_send_rebuilds_the_senders_successor() {
        let (snapshot, keys) = channel(&mut StdRng::seed_from_u64(0x51_0B), [5, 6, 7, 8]);
        let view = SlotView::from_snapshot(&snapshot, 2).unwrap();
        let dest_keys = MemberKeys::generate(&mut StdRng::seed_from_u64(0xDE57));
        let dest = ChannelId::new(22).unwrap();
        let token = snapshot.state.balance_state.token_registry[0];
        let nullifier = Bytes32::from_u32_slice(&[0xAB; 8]).unwrap();
        let salt = Salt::default();
        let built = build_view_inter_channel_send(
            &keys[2], &view, dest, 1, dest_keys.regev_pk.clone(), dest_keys.pk_g(), salt, token, 0,
            4, nullifier, LEVEL, &mut StdRng::seed_from_u64(91),
        )
        .unwrap();
        let (fat, accumulator) = inflate_inter_channel_debit(&snapshot, &built.debit_payload)
            .expect("the co-signer rebuilds the sender's successor");
        assert_eq!(fat.proposed_next_state.digest, built.debit_payload.proposed_digest);
        assert_eq!(
            Bytes32::from(accumulator.get_root()),
            fat.proposed_next_state.balance_state.settled_tx_accumulator_root
        );
        verify_inter_channel_send_transition(&snapshot.state, &snapshot.record, &fat, LEVEL)
            .expect("the unchanged full-state verifier accepts it");

        // Same randomness through the full-state builder gives the same successor.
        let full = build_inter_channel_send_token_at_base_nonce_decrypted(
            &keys[2], &snapshot, 2, dest, 1, dest_keys.regev_pk.clone(), dest_keys.pk_g(), salt,
            token, 0, 4, nullifier, LEVEL, &mut StdRng::seed_from_u64(91),
        )
        .unwrap();
        assert_eq!(full.debit_payload.proposed_next_state.digest, built.debit_payload.proposed_digest);

        let mut tampered = built.debit_payload.clone();
        tampered.amount = 3;
        assert!(inflate_inter_channel_debit(&snapshot, &tampered).is_err());
    }

    #[test]
    fn view_burn_rebuilds_the_senders_successor() {
        let (snapshot, keys) = channel(&mut StdRng::seed_from_u64(0x51_0C), [5, 6, 7, 8]);
        let view = SlotView::from_snapshot(&snapshot, 3).unwrap();
        let token = snapshot.state.balance_state.token_registry[0];
        let to = Address::from_u32_slice(&[0x1234_5678; 5]).unwrap();
        let nullifier = Bytes32::from_u32_slice(&[0xCD; 8]).unwrap();
        let built = build_view_burn_send(
            &keys[3], &view, to, token, 0, 2, nullifier, LEVEL, &mut StdRng::seed_from_u64(5),
        )
        .unwrap();
        let (fat, _acc) = inflate_inter_channel_debit(&snapshot, &built.debit_payload).unwrap();
        verify_inter_channel_send_transition(&snapshot.state, &snapshot.record, &fat, LEVEL)
            .expect("the burn verifies");
    }
}
