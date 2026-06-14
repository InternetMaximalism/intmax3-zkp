//! Core logic for the single-member browser wallet + CLI companion (Regev channel model).
//!
//! This module is target-independent (native CLI + wasm wallet both use it). It implements one
//! channel member's slice of the in-channel transfer protocol (detail2 §E-1/§E-4, abstract2
//! §3.1/§3.2): SPHINCS+ + Regev key management, genesis contribution, building/verifying an
//! in-channel `ChannelTx` with its mandatory E-1 STARK proof, co-signing `ChannelState`, and
//! decrypting one's own hidden balance.
//!
//! SECURITY: the channel library's `validate_all_member_signatures` is structural only (it does
//! NOT run SLH-DSA verify — see tasks/wallet-threat-model.md A-1). This module therefore verifies
//! every member's REAL SPHINCS+ signature (`crypto_sign_verify`) over the exact signing digest,
//! re-derives `regev_pk_root`, rebuilds every E-1 statement from authenticated state (never from
//! the tx carrier), and decrypts its own balance slot on every state it adopts. Secret material
//! (`SpxKeyPair`, `RegevSk`, `AmountWitness`) never leaves this module via any serialized type.

use rand010::Rng;
use serde::{Deserialize, Serialize};
use sphincsplus_poseidon::verify::crypto_sign_verify;

use crate::{
    circuits::{
        channel::state_update_verifier::InChannelTransferUpdateWitness,
        test_utils::sphincs_sign::{SpxKeyPair, pk_hash_from_pk_bytes, sphincs_keygen, sphincs_sign},
    },
    common::{
        balance_state::BalanceState,
        channel::{
            ChannelFund, ChannelProofEnvelope, ChannelRecord, ChannelState, ChannelStatus,
            ChannelTx, MemberSignature, ProofBackend, TransitionProofRole,
        },
        channel_id::ChannelId,
    },
    constants::MAX_CHANNEL_MEMBERS,
    ethereum_types::{bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait},
    regev::{
        AmountWitness, RegevCiphertext, RegevPk, RegevSecurityLevel, RegevSk, RealRegevProofVerifier,
        add_ciphertexts, channel_keygen, decrypt_amount, encrypt_amount, prove_channel_tx,
        regev_pk_root,
    },
};

/// Wallet errors. Strings are user-facing; no secret material is ever included.
#[derive(Debug, Clone)]
pub struct WalletError(pub String);

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for WalletError {}

/// Map any displayable error into a `WalletError` (for use in `.map_err`).
fn we<E: core::fmt::Display>(e: E) -> WalletError {
    WalletError(e.to_string())
}
fn bail<T>(m: impl Into<String>) -> Result<T, WalletError> {
    Err(WalletError(m.into()))
}

/// Reject an out-of-range slot before it is used to index a fixed-size member array. SECURITY:
/// `slot` originates from attacker-shaped JSON; an unchecked `u8 >= 16` index is a wasm OOB trap.
fn check_slot(slot: usize, member_count: usize) -> WResult<()> {
    if slot >= MAX_CHANNEL_MEMBERS {
        return bail(format!("slot {slot} exceeds MAX_CHANNEL_MEMBERS"));
    }
    if slot >= member_count {
        return bail(format!("slot {slot} is not an active member (member_count {member_count})"));
    }
    Ok(())
}

pub type WResult<T> = Result<T, WalletError>;

// ---------------------------------------------------------------------------
// Secret-bearing key material (never serialized)
// ---------------------------------------------------------------------------

/// One member's full key material. Held only in process memory; never crosses a serialization
/// boundary (no `Serialize`).
pub struct MemberKeys {
    pub kp: SpxKeyPair,
    pub regev_pk: RegevPk,
    pub regev_sk: RegevSk,
}

impl MemberKeys {
    pub fn generate(rng: &mut impl Rng) -> Self {
        let mut sk_seed = [0u8; 16];
        let mut sk_prf = [0u8; 16];
        let mut pub_seed = [0u8; 16];
        rng.fill_bytes(&mut sk_seed);
        rng.fill_bytes(&mut sk_prf);
        rng.fill_bytes(&mut pub_seed);
        let kp = sphincs_keygen(sk_seed, sk_prf, pub_seed);
        let (regev_pk, regev_sk) = channel_keygen(rng);
        Self {
            kp,
            regev_pk,
            regev_sk,
        }
    }

    /// This member's identity = SPHINCS+ pubkey hash (the value stored in `ChannelRecord`).
    pub fn sphincs_pk_hash(&self) -> Bytes32 {
        pk_hash_from_pk_bytes(&self.kp.pk_bytes).into()
    }
}

// ---------------------------------------------------------------------------
// SPHINCS+ digest signing / verification (matches the in-circuit msg encoding)
// ---------------------------------------------------------------------------

/// Encode a 32-byte channel digest as the SPHINCS+ message: each of the 8 u32 limbs widened to a
/// little-endian u64 (64 bytes). Identical to `block_witness_generator`'s channel-digest signing
/// path, so native verification agrees with the in-circuit gadget.
fn digest_msg_bytes(digest: &Bytes32) -> Vec<u8> {
    digest
        .to_u32_vec()
        .into_iter()
        .flat_map(|limb| (limb as u64).to_le_bytes())
        .collect()
}

fn sign_digest(kp: &SpxKeyPair, digest: &Bytes32) -> Vec<u8> {
    sphincs_sign(&digest_msg_bytes(digest), kp).to_vec()
}

/// Verify a member's REAL SPHINCS+ signature over `digest`. `pk_bytes` is the 32-byte public key.
pub fn verify_sphincs_sig(pk_bytes: &[u8], digest: &Bytes32, sig: &[u8]) -> WResult<()> {
    crypto_sign_verify(sig, &digest_msg_bytes(digest), pk_bytes)
        .map_err(|e| WalletError(format!("SPHINCS+ signature verification failed: {e}")))
}

// ---------------------------------------------------------------------------
// Serializable public channel view (crosses the browser<->CLI boundary)
// ---------------------------------------------------------------------------

/// Public information about one member (no secrets). `sphincs_pk_hex` is the 32-byte SPHINCS+
/// public key (needed to verify that member's signatures); the wallet checks it hashes to the
/// `ChannelRecord` slot's pubkey hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberInfo {
    pub slot: u8,
    pub sphincs_pk_hex: String,
    pub regev_pk: RegevPk,
}

/// A complete, signed channel snapshot shared between members.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelSnapshot {
    pub record: ChannelRecord,
    pub state: ChannelState,
    pub members: Vec<MemberInfo>,
}

/// A send payload: the `ChannelTx` (with its E-1 proof + sender signature) plus the proposed next
/// state carrying only the sender's signature so far. Co-signers verify, then add their signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendPayload {
    pub sender_index: u8,
    pub recipient_index: u8,
    pub channel_tx: ChannelTx,
    pub proposed_next_state: ChannelState,
    pub members: Vec<MemberInfo>,
    pub record: ChannelRecord,
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> WResult<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return bail("hex string has odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| WalletError(e.to_string())))
        .collect()
}

impl MemberInfo {
    pub fn sphincs_pk_bytes(&self) -> WResult<Vec<u8>> {
        hex_decode(&self.sphincs_pk_hex)
    }
}

/// Build the full 16-slot Regev pk array from a member list (padding = `RegevPk::padding()`).
fn regev_pks_array(members: &[MemberInfo]) -> [RegevPk; MAX_CHANNEL_MEMBERS] {
    let mut arr: [RegevPk; MAX_CHANNEL_MEMBERS] = std::array::from_fn(|_| RegevPk::padding());
    for m in members {
        if (m.slot as usize) < MAX_CHANNEL_MEMBERS {
            arr[m.slot as usize] = m.regev_pk.clone();
        }
    }
    arr
}

fn member_at(members: &[MemberInfo], slot: usize) -> WResult<&MemberInfo> {
    members
        .iter()
        .find(|m| m.slot as usize == slot)
        .ok_or_else(|| WalletError(format!("no member at slot {slot}")))
}

/// `member_pubkeys_root` (keccak form): a keccak over the active member SPHINCS+ pubkey-hash
/// limbs, in slot order. Deterministic and nonzero; binds the member set at the L1 boundary.
fn member_pubkeys_root(record: &ChannelRecord) -> Bytes32 {
    let mut words = Vec::new();
    for i in 0..record.member_count as usize {
        words.extend(record.member_sphincs_pubkey_hashes[i].to_u32_vec());
    }
    Bytes32::from_u32_slice(&plonky2_keccak::utils::solidity_keccak256(&words))
        .expect("keccak output is bytes32")
}

// ---------------------------------------------------------------------------
// Channel construction (CLI assembles the genesis from member contributions)
// ---------------------------------------------------------------------------

/// Build the `ChannelRecord` for an `n`-member channel from the members' pubkeys.
/// `members` must cover slots `0..n` exactly. `bp_member_slot` is the block proposer.
pub fn build_record(
    channel_id: u32,
    members: &[MemberInfo],
    bp_member_slot: u8,
) -> WResult<ChannelRecord> {
    let n = members.len();
    if !(2..=MAX_CHANNEL_MEMBERS).contains(&n) {
        return bail(format!("member_count {n} out of range (2..={MAX_CHANNEL_MEMBERS})"));
    }
    let mut hashes: [Bytes32; MAX_CHANNEL_MEMBERS] = std::array::from_fn(|_| Bytes32::default());
    for slot in 0..n {
        let m = member_at(members, slot)?;
        let pk = m.sphincs_pk_bytes()?;
        hashes[slot] = pk_hash_from_pk_bytes(
            &pk.as_slice()
                .try_into()
                .map_err(|_| WalletError("sphincs pk must be 32 bytes".into()))?,
        )
        .into();
    }
    let regev_pks = regev_pks_array(members);
    let mut record = ChannelRecord {
        channel_id: ChannelId::new(channel_id as u64).map_err(|e| WalletError(format!("{e:?}")))?,
        member_count: n as u8,
        member_sphincs_pubkey_hashes: hashes,
        member_pubkeys_root: Bytes32::default(),
        bp_member_slot,
        special_close_penalty: U256::from(0u32),
        close_freeze_nonce: 0,
        status: ChannelStatus::Active,
        regev_pk_root: regev_pk_root(&regev_pks),
    };
    record.member_pubkeys_root = member_pubkeys_root(&record);
    record.validate().map_err(|e| WalletError(format!("{e:?}")))?;
    Ok(record)
}

/// Assemble an UNSIGNED genesis `ChannelState` from per-member genesis ciphertexts (slot order).
pub fn assemble_genesis_state(
    record: &ChannelRecord,
    enc_balances_active: &[RegevCiphertext],
    fund_amount: u64,
) -> WResult<ChannelState> {
    if enc_balances_active.len() != record.member_count as usize {
        return bail("genesis ciphertext count must equal member_count");
    }
    let state = ChannelState {
        channel_id: record.channel_id,
        epoch: 1,
        small_block_number: 0,
        close_freeze_nonce: 0,
        channel_fund: ChannelFund {
            channel_id: record.channel_id,
            amount: U256::from(fund_amount.min(u32::MAX as u64) as u32),
            intmax_state_root: Bytes32::default(),
        },
        balance_state: BalanceState {
            channel_id: record.channel_id,
            member_count: record.member_count,
            enc_balances: BalanceState::pad_enc_balances(enc_balances_active),
            settled_tx_chain: Bytes32::default(),
            state_version: 0,
            pending_adds: BalanceState::pad_pending_adds(&vec![0u32; record.member_count as usize]),
        },
        h2_tag: Bytes32::default(),
        shared_native_nullifier_root: Bytes32::default(),
        unallocated_confirmed_incoming: U256::zero(),
        prev_digest: Bytes32::default(),
        digest: Bytes32::default(),
        member_signatures: Vec::new(),
    }
    .with_computed_digest();
    Ok(state)
}

// ---------------------------------------------------------------------------
// Signing & verification of channel states
// ---------------------------------------------------------------------------

/// Produce this member's `MemberSignature` over `state.signing_digest()`.
pub fn sign_state(keys: &MemberKeys, slot: u8, state: &ChannelState) -> MemberSignature {
    let digest = state.signing_digest();
    MemberSignature {
        member_slot: slot,
        sphincs_pubkey_hash: keys.sphincs_pk_hash(),
        signature: sign_digest(&keys.kp, &digest),
    }
}

/// Insert/replace a member signature in slot order.
pub fn add_signature(state: &mut ChannelState, sig: MemberSignature) {
    state.member_signatures.retain(|s| s.member_slot != sig.member_slot);
    state.member_signatures.push(sig);
    state.member_signatures.sort_by_key(|s| s.member_slot);
}

/// Verify that EVERY active member's real SPHINCS+ signature is present and valid over
/// `state.signing_digest()`, and that each signer's pubkey hashes to the record slot.
pub fn verify_all_signatures(
    record: &ChannelRecord,
    members: &[MemberInfo],
    state: &ChannelState,
) -> WResult<()> {
    let digest = state.signing_digest();
    if state.digest != digest {
        return bail("state.digest does not match recomputed signing_digest()");
    }
    for slot in 0..record.member_count as usize {
        let expected_hash = record.member_sphincs_pubkey_hashes[slot];
        let sig = state
            .member_signatures
            .iter()
            .find(|s| s.member_slot as usize == slot)
            .ok_or_else(|| WalletError(format!("missing signature for slot {slot}")))?;
        if sig.sphincs_pubkey_hash != expected_hash {
            return bail(format!("slot {slot} signature pubkey hash mismatch"));
        }
        let m = member_at(members, slot)?;
        let pk = m.sphincs_pk_bytes()?;
        // Bind the revealed pubkey to the record's committed hash before trusting it.
        let pk_hash: Bytes32 = pk_hash_from_pk_bytes(
            &pk.as_slice()
                .try_into()
                .map_err(|_| WalletError("sphincs pk must be 32 bytes".into()))?,
        )
        .into();
        if pk_hash != expected_hash {
            return bail(format!("slot {slot} member pubkey does not match record hash"));
        }
        verify_sphincs_sig(&pk, &digest, &sig.signature)?;
    }
    Ok(())
}

/// Full import verification of a signed snapshot (tasks/wallet-threat-model.md §G):
/// record.validate, regev_pk_root match, member-pubkey binding, all real signatures, balance-state
/// validity, and (if `my_slot`/`my_keys` given) own-slot decryption sanity.
pub fn verify_snapshot(
    snapshot: &ChannelSnapshot,
    my_keys: Option<(&MemberKeys, u8)>,
) -> WResult<()> {
    snapshot
        .record
        .validate()
        .map_err(|e| WalletError(format!("{e:?}")))?;
    // Members must cover slots 0..member_count bijectively (no duplicates, no out-of-range or
    // padding-slot entries). Prevents malformed/duplicate slot lists slipping past the root check.
    let mc = snapshot.record.member_count as usize;
    if snapshot.members.len() != mc {
        return bail(format!(
            "members list has {} entries but member_count is {mc}",
            snapshot.members.len()
        ));
    }
    let mut seen = [false; MAX_CHANNEL_MEMBERS];
    for m in &snapshot.members {
        check_slot(m.slot as usize, mc)?;
        if seen[m.slot as usize] {
            return bail(format!("duplicate member slot {}", m.slot));
        }
        seen[m.slot as usize] = true;
    }
    // regev_pk_root binding (F9-A).
    let regev_pks = regev_pks_array(&snapshot.members);
    if regev_pk_root(&regev_pks) != snapshot.record.regev_pk_root {
        return bail("regev_pk_root mismatch: member Regev keys not anchored to the record");
    }
    snapshot
        .state
        .balance_state
        .validate()
        .map_err(|e| WalletError(format!("{e:?}")))?;
    verify_all_signatures(&snapshot.record, &snapshot.members, &snapshot.state)?;
    if let Some((keys, slot)) = my_keys {
        check_slot(slot as usize, mc)?;
        let m = member_at(&snapshot.members, slot as usize)?;
        if m.regev_pk != keys.regev_pk {
            return bail("my slot's Regev pk in the snapshot does not match my key");
        }
        if snapshot.record.member_sphincs_pubkey_hashes[slot as usize] != keys.sphincs_pk_hash() {
            return bail("my slot's SPHINCS+ hash in the record does not match my key");
        }
        // Confirm we can decrypt our own balance slot (no panic / valid ciphertext).
        decrypt_amount(
            &keys.regev_sk,
            &snapshot.state.balance_state.enc_balances[slot as usize],
        )
        .map_err(|e| WalletError(format!("own balance slot does not decrypt: {e}")))?;
    }
    Ok(())
}

/// Decrypt this member's hidden balance from a snapshot.
pub fn decrypt_balance(keys: &MemberKeys, snapshot: &ChannelSnapshot, slot: u8) -> WResult<u64> {
    check_slot(slot as usize, snapshot.state.balance_state.member_count as usize)?;
    decrypt_amount(
        &keys.regev_sk,
        &snapshot.state.balance_state.enc_balances[slot as usize],
    )
    .map_err(we)
}

// ---------------------------------------------------------------------------
// In-channel send
// ---------------------------------------------------------------------------

/// The output of building a send: the payload to hand to co-signers, plus the sender's fresh
/// `after`-balance witness (the wallet must keep this to be able to send again without refreshing).
pub struct BuiltSend {
    pub payload: SendPayload,
    pub new_balance_witness: AmountWitness,
    pub new_balance: u64,
}

/// Build an in-channel transfer of `amount` from `sender_slot` to `recipient_slot`.
///
/// `before_witness` is the sender's `AmountWitness` for their CURRENT balance ciphertext (held
/// locally since genesis/last refresh). `before_amount` is the sender's current plaintext balance.
/// Produces the E-1 proof, the signed `ChannelTx`, and the proposed next state carrying only the
/// sender's signature.
#[allow(clippy::too_many_arguments)]
pub fn build_send(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    sender_slot: u8,
    recipient_slot: u8,
    amount: u64,
    before_amount: u64,
    before_witness: &AmountWitness,
    nonce: Bytes32,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<BuiltSend> {
    if sender_slot == recipient_slot {
        return bail("sender and recipient must differ");
    }
    let mc = snapshot.record.member_count as usize;
    check_slot(sender_slot as usize, mc)?;
    check_slot(recipient_slot as usize, mc)?;
    let record = &snapshot.record;
    let members = &snapshot.members;
    let prev = &snapshot.state;
    if prev.balance_state.pending_adds[sender_slot as usize] != 0 {
        return bail(
            "sender slot has pending homomorphic adds; refresh required before sending (not yet implemented in MVP)",
        );
    }
    if before_amount < amount {
        return bail("insufficient balance");
    }
    let regev_pks = regev_pks_array(members);
    let sender_pk = &regev_pks[sender_slot as usize];
    let recipient_pk = &regev_pks[recipient_slot as usize];

    // Encrypt the amount to the recipient; re-encrypt the sender's new balance (fresh witness).
    let (enc_amount, enc_amount_w) = encrypt_amount(rng, recipient_pk, amount).map_err(we)?;
    let new_balance = before_amount - amount;
    let (after_ct, after_w) = encrypt_amount(rng, sender_pk, new_balance).map_err(we)?;

    // E-1 channelTxZKP over (before, enc_amount, after).
    let proof = prove_channel_tx(
        level,
        sender_pk,
        recipient_pk,
        (&prev.balance_state.enc_balances[sender_slot as usize], before_witness),
        (&enc_amount, &enc_amount_w),
        (&after_ct, &after_w),
    )
    .map_err(we)?;

    // Recipient slot = public homomorphic sum.
    let recipient_after =
        add_ciphertexts(&prev.balance_state.enc_balances[recipient_slot as usize], &enc_amount)
            .map_err(we)?;

    // Proposed next state.
    let mut enc_balances = prev.balance_state.enc_balances.clone();
    enc_balances[sender_slot as usize] = after_ct;
    enc_balances[recipient_slot as usize] = recipient_after;
    let mut pending_adds = prev.balance_state.pending_adds;
    pending_adds[sender_slot as usize] = 0;
    pending_adds[recipient_slot as usize] += 1;

    let next_state = ChannelState {
        epoch: prev.epoch + 1,
        balance_state: BalanceState {
            enc_balances,
            state_version: prev.balance_state.state_version + 1,
            pending_adds,
            ..prev.balance_state.clone()
        },
        prev_digest: prev.digest,
        member_signatures: Vec::new(),
        ..prev.clone()
    }
    .with_computed_digest();

    let sender_hash = record.member_sphincs_pubkey_hashes[sender_slot as usize];
    let recipient_hash = record.member_sphincs_pubkey_hashes[recipient_slot as usize];
    let tx_digest = ChannelTx::signing_digest(
        prev.channel_id,
        prev.digest,
        &enc_amount,
        nonce,
        sender_hash,
        recipient_hash,
    );
    let channel_tx = ChannelTx {
        recipient_sphincs_pubkey_hash: recipient_hash,
        enc_amount,
        nonce,
        channel_tx_zkp: ChannelProofEnvelope {
            role: TransitionProofRole::ChannelStateUpdate,
            backend: ProofBackend::Plonky3,
            proof,
        },
        sender_sphincs_pubkey_hash: sender_hash,
        sender_signature: sign_digest(&keys.kp, &tx_digest),
    };

    let mut proposed = next_state;
    let sender_sig = sign_state(keys, sender_slot, &proposed);
    add_signature(&mut proposed, sender_sig);

    Ok(BuiltSend {
        payload: SendPayload {
            sender_index: sender_slot,
            recipient_index: recipient_slot,
            channel_tx,
            proposed_next_state: proposed,
            members: members.clone(),
            record: record.clone(),
        },
        new_balance_witness: after_w,
        new_balance,
    })
}

/// Verify a proposed in-channel transfer against the prev state, using the hardened
/// `InChannelTransferUpdateWitness::verify` (rebuilds the E-1 statement from authenticated state)
/// PLUS the sender's REAL SPHINCS+ signature. `recipient_sk`/`expected_amount` enable the
/// recipient's own-slot decryption check. NOTE: the witness verify checks structural member
/// signatures only; `verify_all_signatures` must be called separately once all signatures present.
#[allow(clippy::too_many_arguments)]
pub fn verify_send_transition(
    prev: &ChannelState,
    payload: &SendPayload,
    level: RegevSecurityLevel,
    recipient_sk: Option<&RegevSk>,
    expected_amount: Option<u64>,
) -> WResult<()> {
    // The sender's real signature over the ChannelTx digest.
    let tx_digest = ChannelTx::signing_digest(
        prev.channel_id,
        prev.digest,
        &payload.channel_tx.enc_amount,
        payload.channel_tx.nonce,
        payload.channel_tx.sender_sphincs_pubkey_hash,
        payload.channel_tx.recipient_sphincs_pubkey_hash,
    );
    let sender = member_at(&payload.members, payload.sender_index as usize)?;
    verify_sphincs_sig(&sender.sphincs_pk_bytes()?, &tx_digest, &payload.channel_tx.sender_signature)?;

    // `InChannelTransferUpdateWitness::verify` requires a STRUCTURALLY complete signature set
    // (one non-empty sig per active slot with the right pubkey hash). A co-signer validates the
    // transition BEFORE the real signatures are collected, so fill placeholder structural sigs
    // here — they do not affect `signing_digest()` (member signatures are excluded from it). The
    // REAL SLH-DSA multi-signature check is `verify_all_signatures`, run once the set is complete.
    let mut next_for_check = payload.proposed_next_state.clone();
    fill_placeholder_sigs(&payload.record, &mut next_for_check);

    let witness = InChannelTransferUpdateWitness {
        channel_record: payload.record.clone(),
        regev_pks: regev_pks_array(&payload.members),
        prev_state: prev.clone(),
        next_state: next_for_check,
        channel_tx: payload.channel_tx.clone(),
        sender_index: payload.sender_index as usize,
        recipient_index: payload.recipient_index as usize,
        recipient_sk: recipient_sk.cloned(),
        expected_amount,
    };
    let verifier = RealRegevProofVerifier { level };
    witness
        .verify(&verifier)
        .map_err(|e| WalletError(format!("in-channel transition invalid: {e:?}")))?;
    Ok(())
}

/// Fill every active slot with a placeholder (correctly-tagged, non-empty) signature so the
/// library's structural signature check passes. Used only for transition validation; never for
/// the authoritative `verify_all_signatures` check.
fn fill_placeholder_sigs(record: &ChannelRecord, state: &mut ChannelState) {
    state.member_signatures = (0..record.member_count as usize)
        .map(|slot| MemberSignature {
            member_slot: slot as u8,
            sphincs_pubkey_hash: record.member_sphincs_pubkey_hashes[slot],
            signature: vec![1],
        })
        .collect();
}
