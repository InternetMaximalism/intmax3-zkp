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

use rand::SeedableRng as _;
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
        prove_hash_sig, regev_pk_root, verify_hash_sig,
        hash_sig::{BabyBearPublicKey, BabyBearSecretKey, decompose_digest_to_limbs},
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
    /// SPHINCS+ keypair — STILL used for member channel-STATE (IMCH) co-signing (`sign_state` /
    /// `verify_all_signatures`). NOTE (P3): the channel-tx SENDER signature has been migrated to the
    /// BabyBear hash-sig (`baby_key`); the member-state co-signing remains SPHINCS+ because the
    /// Goldilocks `poseidon_sig` scheme has no native standalone verifier (it is verified by the ZK
    /// single-sig/list proof at the validity/close layer, not in the wallet).
    pub kp: SpxKeyPair,
    /// P3 BabyBear hash-sig secret key — authorizes the channel-tx SENDER (IMPA) over the channel-tx
    /// `signing_digest`. Its `pk_b` is committed in the member's registered `MemberLeaf` (A11).
    pub baby_key: BabyBearSecretKey,
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
        // Derive the BabyBear hash-sig key from a fresh 32-byte seed drawn from the wallet RNG.
        // `BabyBearSecretKey::random` is defined over `rand` 0.8 (the regev layer), so we bridge by
        // seeding a 0.8 `StdRng` from wallet entropy rather than sharing the `rand010` RNG directly.
        let mut baby_seed = [0u8; 32];
        rng.fill_bytes(&mut baby_seed);
        let mut baby_rng = rand::rngs::StdRng::from_seed(baby_seed);
        let baby_key = BabyBearSecretKey::random(&mut baby_rng);
        let (regev_pk, regev_sk) = channel_keygen(rng);
        Self {
            kp,
            baby_key,
            regev_pk,
            regev_sk,
        }
    }

    /// This member's identity = SPHINCS+ pubkey hash (the value stored in `ChannelRecord`).
    pub fn pk_g(&self) -> Bytes32 {
        pk_hash_from_pk_bytes(&self.kp.pk_bytes).into()
    }

    /// This member's BabyBear hash-sig public key `pk_b` (canonical `Bytes32` digest), committed in
    /// the registered `MemberLeaf` for the A11 two-key binding.
    pub fn pk_b(&self) -> Bytes32 {
        self.baby_key.public_key().to_bytes32()
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
///
/// NOTE (P3): this is now used ONLY for member channel-STATE (IMCH) co-signing
/// (`verify_all_signatures`). The channel-tx SENDER (IMPA) signature is the BabyBear hash-sig
/// (`verify_channel_tx_sender_hash_sig`).
pub fn verify_sphincs_sig(pk_bytes: &[u8], digest: &Bytes32, sig: &[u8]) -> WResult<()> {
    crypto_sign_verify(sig, &digest_msg_bytes(digest), pk_bytes)
        .map_err(|e| WalletError(format!("SPHINCS+ signature verification failed: {e}")))
}

// ---------------------------------------------------------------------------
// P3: channel-tx SENDER BabyBear hash-signature (IMPA) signing / verification
// ---------------------------------------------------------------------------

/// Produce the channel-tx SENDER hash-sig proof over `tx_digest` (the IMPA `signing_digest`).
/// Returns the proof bytes; the sender's `pk_b` is recorded separately on the `ChannelTx`.
///
/// SECURITY: the message is the 16-limb INJECTIVE decomposition of `tx_digest`
/// (`decompose_digest_to_limbs`), the SAME map the verifier recomputes; the proof's public values
/// bind `[pk_b ‖ m]`. Production verification uses `RegevSecurityLevel::Production` — but the
/// `level` is the caller's (tests pass `Test`).
fn sign_channel_tx_sender(
    keys: &MemberKeys,
    tx_digest: &Bytes32,
    level: RegevSecurityLevel,
) -> WResult<Vec<u8>> {
    let m = decompose_digest_to_limbs(tx_digest);
    let (proof, _pvs) = prove_hash_sig(level, &keys.baby_key, &m).map_err(we)?;
    Ok(proof)
}

/// Verify the channel-tx SENDER hash-sig and bind it to the tx digest, the claimed `pk_b`, and the
/// sender's registered `MemberLeaf` (A11). All four checks below are SOUNDNESS-CRITICAL.
///
/// SECURITY (A11 — off-chain trust assumption): the binding of `(pk_g, pk_b, regev_pk)` to ONE
/// registered member is enforced HERE by every co-signer running this check against the channel's
/// member set. There is no on-chain enforcement of the two-key pairing for in-channel transfers;
/// the channel-tx is accepted only by parties that run this membership check. This mirrors the
/// existing off-chain-verification trust model for the channelTxZKP.
///
/// * `level` MUST be `RegevSecurityLevel::Production` in production (84 FRI queries). `Test` is
///   8-query (≈8-bit) and exists for the test suite only.
/// * `registered_pk_g` / `registered_pk_b` / `registered_regev_pk` are the sender slot's registered
///   `MemberLeaf` components (looked up by the caller from the authenticated channel member set).
#[allow(clippy::too_many_arguments)]
pub fn verify_channel_tx_sender_hash_sig(
    channel_tx: &ChannelTx,
    tx_digest: &Bytes32,
    level: RegevSecurityLevel,
    registered_pk_g: Bytes32,
    registered_pk_b: Bytes32,
    registered_regev_pk: &RegevPk,
    sender_regev_pk: &RegevPk,
) -> WResult<()> {
    // (1) The proof must be present (atomicity: a balance-reduction without an owner sig is rejected).
    if channel_tx.sender_hash_sig.is_empty() {
        return bail("channel_tx sender hash-sig proof must not be empty");
    }
    // (2) A11 membership — the claimed (pk_g, pk_b, regev_pk) triple must be the SAME registered
    // member (the sender slot's leaf). Binds pk_b to the member that owns pk_g and the Regev key.
    if channel_tx.sender_pk_g != registered_pk_g {
        return bail("A11: channel_tx.sender_pk_g is not the registered member at the sender slot");
    }
    if channel_tx.sender_pk_b != registered_pk_b {
        return bail("A11: channel_tx.sender_pk_b is not the registered member's pk_b");
    }
    if sender_regev_pk != registered_regev_pk {
        return bail("A11: sender Regev pk is not the registered member's Regev key");
    }
    // (3) Reconstruct the EXPECTED public values [pk_b ‖ m] from the registered pk_b and the
    // recomputed IMPA digest decomposition — never from the proof carrier.
    let pk_b = BabyBearPublicKey::from_bytes32(&channel_tx.sender_pk_b).map_err(we)?;
    let m = decompose_digest_to_limbs(tx_digest);
    let mut pvs: Vec<_> = Vec::with_capacity(pk_b.digest.len() + m.len());
    pvs.extend_from_slice(&pk_b.digest);
    pvs.extend_from_slice(&m);
    // (4) Verify the STARK against those bound public values. `verify_hash_sig` absorbs the PVs into
    // the Fiat-Shamir transcript, so a proof minted for a different (pk_b, m) is rejected.
    verify_hash_sig(level, &channel_tx.sender_hash_sig, &pvs).map_err(we)?;
    Ok(())
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
    /// P3: the member's BabyBear hash-sig public key `pk_b` (canonical `Bytes32` digest). Used for
    /// the A11 membership check on the channel-tx sender; bound into the registered `MemberLeaf`.
    pub pk_b: Bytes32,
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
        words.extend(record.member_pk_gs[i].to_u32_vec());
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
        member_pk_gs: hashes,
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
        pk_g: keys.pk_g(),
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
        let expected_hash = record.member_pk_gs[slot];
        let sig = state
            .member_signatures
            .iter()
            .find(|s| s.member_slot as usize == slot)
            .ok_or_else(|| WalletError(format!("missing signature for slot {slot}")))?;
        if sig.pk_g != expected_hash {
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
        if snapshot.record.member_pk_gs[slot as usize] != keys.pk_g() {
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

    let sender_hash = record.member_pk_gs[sender_slot as usize];
    let recipient_hash = record.member_pk_gs[recipient_slot as usize];
    let tx_digest = ChannelTx::signing_digest(
        prev.channel_id,
        prev.digest,
        &enc_amount,
        nonce,
        sender_hash,
        recipient_hash,
    );
    // P3: the SENDER authorizes the transfer with a BabyBear hash-sig over the IMPA tx digest.
    let sender_hash_sig = sign_channel_tx_sender(keys, &tx_digest, level)?;
    let channel_tx = ChannelTx {
        recipient_pk_g: recipient_hash,
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
    // The sender's REAL authorization over the ChannelTx digest (P3: BabyBear hash-sig, replaces
    // the SPHINCS+ sender signature). The IMPA `signing_digest` preimage is UNCHANGED.
    let tx_digest = ChannelTx::signing_digest(
        prev.channel_id,
        prev.digest,
        &payload.channel_tx.enc_amount,
        payload.channel_tx.nonce,
        payload.channel_tx.sender_pk_g,
        payload.channel_tx.recipient_pk_g,
    );
    let sender_slot = payload.sender_index as usize;
    check_slot(sender_slot, payload.record.member_count as usize)?;
    let sender = member_at(&payload.members, sender_slot)?;
    // A11: the sender slot's REGISTERED (pk_g, pk_b, regev_pk) from the authenticated member set.
    // The member list is bound to the record by `verify_snapshot` (regev_pk_root + per-slot pk_g);
    // here we additionally bind pk_b via the hash-sig membership check.
    let registered_pk_g = payload.record.member_pk_gs[sender_slot];
    verify_channel_tx_sender_hash_sig(
        &payload.channel_tx,
        &tx_digest,
        level,
        registered_pk_g,
        sender.pk_b,
        &sender.regev_pk,
        &sender.regev_pk,
    )?;

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
            pk_g: record.member_pk_gs[slot],
            signature: vec![1],
        })
        .collect();
}
