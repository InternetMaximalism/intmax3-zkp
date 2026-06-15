//! Core logic for the single-member browser wallet + CLI companion (Regev channel model).
//!
//! This module is target-independent (native CLI + wasm wallet both use it). It implements one
//! channel member's slice of the in-channel transfer protocol (detail2 §E-1/§E-4, abstract2
//! §3.1/§3.2): Goldilocks (state co-signing) + BabyBear (channel-tx sender) + Regev key
//! management, genesis contribution, building/verifying an in-channel `ChannelTx` with its
//! mandatory E-1 STARK proof, co-signing `ChannelState`, and decrypting one's own hidden balance.
//!
//! SECURITY: the channel library's `validate_all_member_signatures` is structural only (it does
//! NOT run the real signature check — see tasks/wallet-threat-model.md A-1). This module therefore
//! verifies every member's REAL Goldilocks `SingleSigCircuit` signature proof (P4-2) over the exact
//! IMCH signing digest, the channel-tx SENDER's BabyBear hash-sig (P3) over the IMPA digest,
//! re-derives `regev_pk_root` and the Poseidon `member_pubkeys_root` (binding the full
//! `(pk_g, pk_b, regev_pk)` member triple — P4-1), rebuilds every E-1 statement from authenticated
//! state (never from the tx carrier), and decrypts its own balance slot on every state it adopts.
//! Secret material (`GoldilocksSecretKey`, `BabyBearSecretKey`, `RegevSk`, `AmountWitness`) never
//! leaves this module via any serialized type.

use std::sync::OnceLock;

use plonky2::plonk::proof::ProofWithPublicInputs;
use rand::SeedableRng as _;
use rand010::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    circuits::channel::state_update_verifier::InChannelTransferUpdateWitness,
    poseidon_sig::{
        GoldilocksSecretKey,
        circuit::{C, D, F, SingleSigCircuit},
    },
    common::{
        balance_state::BalanceState,
        channel::{
            ChannelFund, ChannelProofEnvelope, ChannelRecord, ChannelState, ChannelStatus,
            ChannelTx, MemberSignature, ProofBackend, TransitionProofRole,
        },
        channel_id::ChannelId,
        trees::key_tree::{MemberLeaf, MemberTree},
    },
    constants::MAX_CHANNEL_MEMBERS,
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32},
        u256::U256,
        u32limb_trait::U32LimbTrait,
    },
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
    /// Goldilocks Poseidon-preimage signing key (P4-2) — the member's channel-STATE (IMCH)
    /// co-signing key, replacing the prior SPHINCS+ keypair. `sign_state` proves a
    /// `SingleSigCircuit` over the state's IMCH `signing_digest` with this key; the proof IS the
    /// member's signature. Its public key `pk_g = GoldilocksSecretKey::public_key()` is the member's
    /// canonical on-chain-anchored identity (the value stored in `ChannelRecord.member_pk_gs` and
    /// committed in the registered `MemberLeaf`). The validity/close ZK list-proof aggregation over
    /// these same per-member signatures is the existing P2b path; the wallet's local agreement is
    /// per-member individual proof verification (`verify_all_signatures`).
    pub signing_key: GoldilocksSecretKey,
    /// P3 BabyBear hash-sig secret key — authorizes the channel-tx SENDER (IMPA) over the channel-tx
    /// `signing_digest`. Its `pk_b` is committed in the member's registered `MemberLeaf` (A11).
    pub baby_key: BabyBearSecretKey,
    pub regev_pk: RegevPk,
    pub regev_sk: RegevSk,
}

impl MemberKeys {
    pub fn generate(rng: &mut impl Rng) -> Self {
        // Goldilocks state-signing key: draw a 32-byte seed from the wallet RNG and derive the
        // 4-limb (≈256-bit) secret key (D2 entropy target).
        let mut sig_seed = [0u8; 32];
        rng.fill_bytes(&mut sig_seed);
        let signing_key = GoldilocksSecretKey::from_seed(sig_seed);
        // Derive the BabyBear hash-sig key from a fresh 32-byte seed drawn from the wallet RNG.
        // `BabyBearSecretKey::random` is defined over `rand` 0.8 (the regev layer), so we bridge by
        // seeding a 0.8 `StdRng` from wallet entropy rather than sharing the `rand010` RNG directly.
        let mut baby_seed = [0u8; 32];
        rng.fill_bytes(&mut baby_seed);
        let mut baby_rng = rand::rngs::StdRng::from_seed(baby_seed);
        let baby_key = BabyBearSecretKey::random(&mut baby_rng);
        let (regev_pk, regev_sk) = channel_keygen(rng);
        Self {
            signing_key,
            baby_key,
            regev_pk,
            regev_sk,
        }
    }

    /// This member's identity = Goldilocks public key (the value stored in `ChannelRecord`).
    pub fn pk_g(&self) -> Bytes32 {
        self.signing_key.public_key()
    }

    /// This member's BabyBear hash-sig public key `pk_b` (canonical `Bytes32` digest), committed in
    /// the registered `MemberLeaf` for the A11 two-key binding.
    pub fn pk_b(&self) -> Bytes32 {
        self.baby_key.public_key().to_bytes32()
    }
}

// ---------------------------------------------------------------------------
// Goldilocks Poseidon-preimage channel-STATE (IMCH) co-signing (P4-2)
// ---------------------------------------------------------------------------

/// Process-wide shared `SingleSigCircuit` (the Goldilocks Poseidon-preimage single-signature
/// circuit). Building it is expensive (it constructs a full Plonky2 circuit), so we build it ONCE
/// and reuse it for every `sign_state` (prove) and `verify_all_signatures` (verify). The circuit is
/// deterministic, so the signer and every verifier reproduce byte-identical common/verifier data —
/// a member's proof verifies against any party's instance.
///
/// SECURITY: the circuit's statement is `pk = Poseidon([DOMAIN_PK_G] ‖ sk)` with `m` a registered
/// PUBLIC INPUT (see `poseidon_sig::circuit`). The proof binds exactly `(pk, m)`; this module never
/// trusts a `(pk, m)` claimed by a peer — it reconstructs the expected public inputs from the
/// authenticated member set + the recomputed `signing_digest()` and checks the proof against them.
fn single_sig_circuit() -> &'static SingleSigCircuit {
    static CIRCUIT: OnceLock<SingleSigCircuit> = OnceLock::new();
    CIRCUIT.get_or_init(SingleSigCircuit::new)
}

/// Produce a member's Goldilocks `SingleSigCircuit` proof over `digest` (the IMCH state
/// `signing_digest`). The serialized proof bytes ARE the member's signature.
fn sign_digest(sk: &GoldilocksSecretKey, digest: &Bytes32) -> WResult<Vec<u8>> {
    let proof = single_sig_circuit()
        .prove(sk, *digest)
        .map_err(|e| WalletError(format!("single-sig proving failed: {e}")))?;
    Ok(proof.to_bytes())
}

/// Verify a member's Goldilocks `SingleSigCircuit` proof over `digest`, bound to the claimed public
/// key `pk_g`. The proof's public inputs are `[pk_g(8), m(8)]`; this reconstructs them from the
/// AUTHENTICATED `pk_g` and the recomputed `digest` and checks the proof verifies against exactly
/// those values — so a proof minted for a different `(pk_g, m)` is rejected.
///
/// SECURITY (P4-2): this replaces the prior SPHINCS+ `crypto_sign_verify`. Unforgeability reduces
/// to Poseidon-Goldilocks preimage resistance on `sk` (threat model §2.1). The same per-member
/// proofs are aggregated into the recursive list proof on the validity/close (on-chain) path; here
/// the wallet's local agreement is individual proof verification.
pub fn verify_state_sig(pk_g: Bytes32, digest: &Bytes32, sig: &[u8]) -> WResult<()> {
    let circuit = single_sig_circuit();
    let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(sig.to_vec(), &circuit.data.common)
        .map_err(|e| WalletError(format!("single-sig proof deserialization failed: {e}")))?;
    // Bind the proof's public inputs to the EXPECTED [pk_g(8), m(8)] before trusting the proof.
    let mut expected: Vec<u32> = Vec::with_capacity(2 * BYTES32_LEN);
    expected.extend(pk_g.to_u32_vec());
    expected.extend(digest.to_u32_vec());
    let actual: Vec<u32> = proof.public_inputs.iter().map(|f| f.0 as u32).collect();
    if actual.len() != expected.len() || actual != expected {
        return bail("single-sig proof public inputs do not match the expected (pk_g, digest)");
    }
    circuit
        .data
        .verify(proof)
        .map_err(|e| WalletError(format!("single-sig signature verification failed: {e}")))
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
/// * `registered_pk_g` / `registered_pk_b` are the sender slot's registered `MemberLeaf` identity
///   components, looked up by the caller from the AUTHENTICATED channel member set. The member's
///   Regev key lives in the same `MemberLeaf`, so it is authenticated by the caller's
///   `member_pubkeys_root` anchoring and bound into the E-1 statement — it is not re-checked here.
pub fn verify_channel_tx_sender_hash_sig(
    channel_tx: &ChannelTx,
    tx_digest: &Bytes32,
    level: RegevSecurityLevel,
    registered_pk_g: Bytes32,
    registered_pk_b: Bytes32,
) -> WResult<()> {
    // (1) The proof must be present (atomicity: a balance-reduction without an owner sig is rejected).
    if channel_tx.sender_hash_sig.is_empty() {
        return bail("channel_tx sender hash-sig proof must not be empty");
    }
    // (2) A11 membership — the claimed (pk_g, pk_b) must be the registered sender slot's leaf
    // components. `registered_pk_g`/`registered_pk_b` come from the AUTHENTICATED member set (the
    // caller binds the member root to the trusted channel record), so this ties pk_b to the member
    // that owns pk_g. The Regev key in the same leaf is authenticated by that anchoring + the E-1
    // statement, so it is not separately checked here (the prior self-comparison was a no-op).
    if channel_tx.sender_pk_g != registered_pk_g {
        return bail("A11: channel_tx.sender_pk_g is not the registered member at the sender slot");
    }
    if channel_tx.sender_pk_b != registered_pk_b {
        return bail("A11: channel_tx.sender_pk_b is not the registered member's pk_b");
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

/// Public information about one member (no secrets). `pk_g` is the member's Goldilocks
/// Poseidon-preimage signing public key (`GoldilocksSecretKey::public_key()`, P4-2) — the value
/// stored at the member's slot in `ChannelRecord.member_pk_gs` and committed in the registered
/// `MemberLeaf`; it is the public key against which that member's `SingleSigCircuit` state-signature
/// proofs verify.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberInfo {
    pub slot: u8,
    /// The member's Goldilocks signing public key `pk_g` (canonical `Bytes32`).
    pub pk_g: Bytes32,
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

/// The canonical Poseidon `MemberTree` root over the channel's registered member leaves
/// `MemberLeaf{pk_g, pk_b, regev_pk_digest}`, in slot order (active slots `0..member_count`;
/// padding slots are empty leaves, pad-to-MAX D6).
///
/// SECURITY (P4-1, A11): this is the SAME root the validity / registration circuits commit
/// (`block_witness_generator::ChannelMemberKeys::member_tree.get_root()`,
/// `channel_reg_step`). Anchoring the wallet's `ChannelRecord.member_pubkeys_root` to this root
/// (instead of the previous keccak-over-`pk_g`-only) commits the FULL `(pk_g, pk_b, regev_pk)`
/// triple jointly, so a peer cannot substitute one member's `pk_b` (or Regev key) independently of
/// their `pk_g`. The off-chain channel-tx A11 check then reads `pk_b` from this AUTHENTICATED set.
///
/// `members` MUST cover slots `0..member_count` bijectively (the caller checks this via
/// `verify_snapshot` / `check_slot`); `pk_g` for each slot is taken from the record (the value the
/// member signatures are bound to), while `pk_b` and the Regev digest come from the per-member
/// `MemberInfo`.
fn member_pubkeys_root(record: &ChannelRecord, members: &[MemberInfo]) -> WResult<Bytes32> {
    let mut tree = MemberTree::init();
    for slot in 0..record.member_count as usize {
        let m = member_at(members, slot)?;
        tree.push(MemberLeaf {
            pk_g: record.member_pk_gs[slot].reduce_to_hash_out(),
            pk_b: m.pk_b.reduce_to_hash_out(),
            regev_pk_digest: m.regev_pk.poseidon_digest(),
        });
    }
    Ok(Bytes32::from(tree.get_root()))
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
    for (slot, hash) in hashes.iter_mut().enumerate().take(n) {
        let m = member_at(members, slot)?;
        // The member identity = the member's Goldilocks signing public key `pk_g`.
        *hash = m.pk_g;
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
    record.member_pubkeys_root = member_pubkeys_root(&record, members)?;
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

/// Produce this member's `MemberSignature` over `state.signing_digest()` (P4-2: a Goldilocks
/// `SingleSigCircuit` proof over the IMCH digest — the proof bytes are the signature).
pub fn sign_state(keys: &MemberKeys, slot: u8, state: &ChannelState) -> WResult<MemberSignature> {
    let digest = state.signing_digest();
    Ok(MemberSignature {
        member_slot: slot,
        pk_g: keys.pk_g(),
        signature: sign_digest(&keys.signing_key, &digest)?,
    })
}

/// Insert/replace a member signature in slot order.
pub fn add_signature(state: &mut ChannelState, sig: MemberSignature) {
    state.member_signatures.retain(|s| s.member_slot != sig.member_slot);
    state.member_signatures.push(sig);
    state.member_signatures.sort_by_key(|s| s.member_slot);
}

/// Verify that EVERY active member's real Goldilocks `SingleSigCircuit` signature proof is present
/// and valid over `state.signing_digest()`, and that each signer's `pk_g` is the registered member
/// at the slot (P4-2).
///
/// SECURITY: each member's proof is verified INDIVIDUALLY (the wallet's local N-of-N agreement).
/// The on-chain aggregation of these same per-member signatures into the recursive list proof (in
/// slot order, validity/close) is the existing P2b path and is NOT re-implemented here. Each
/// signer's `pk_g` is checked `∈` the registered member set (it must equal
/// `record.member_pk_gs[slot]`, and the proof is verified against exactly that `pk_g`), so a proof
/// by a non-member or for a different message is rejected.
pub fn verify_all_signatures(
    record: &ChannelRecord,
    _members: &[MemberInfo],
    state: &ChannelState,
) -> WResult<()> {
    let digest = state.signing_digest();
    if state.digest != digest {
        return bail("state.digest does not match recomputed signing_digest()");
    }
    for slot in 0..record.member_count as usize {
        // The signer's pk_g MUST be the registered member at this slot (∈ member set).
        let expected_pk_g = record.member_pk_gs[slot];
        let sig = state
            .member_signatures
            .iter()
            .find(|s| s.member_slot as usize == slot)
            .ok_or_else(|| WalletError(format!("missing signature for slot {slot}")))?;
        if sig.pk_g != expected_pk_g {
            return bail(format!("slot {slot} signature pubkey hash mismatch"));
        }
        // Verify the member's SingleSig proof, bound to the registered pk_g and the recomputed IMCH
        // digest. (`verify_state_sig` re-checks the proof's [pk_g, m] public inputs internally.)
        verify_state_sig(expected_pk_g, &digest, &sig.signature)?;
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
    // SECURITY (P4-1, A11): authenticate the FULL member set — including each member's `pk_b` — by
    // recomputing the canonical Poseidon `MemberTree` root over `MemberLeaf{pk_g, pk_b,
    // regev_pk_digest}` from the (now slot-bijective) member list and binding it to the record's
    // `member_pubkeys_root`. Before P4-1 the record committed only `pk_g` (keccak), so a peer could
    // swap in an attacker `pk_b`; this check rejects any member list whose `(pk_g, pk_b, regev_pk)`
    // triple at any slot does not match the registered set.
    let recomputed_root = member_pubkeys_root(&snapshot.record, &snapshot.members)?;
    if recomputed_root != snapshot.record.member_pubkeys_root {
        return bail(
            "member_pubkeys_root mismatch: the member (pk_g, pk_b, regev_pk) set is not anchored to the record",
        );
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
            return bail("my slot's pk_g in the record does not match my key");
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
    let sender_sig = sign_state(keys, sender_slot, &proposed)?;
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
/// PLUS the sender's REAL BabyBear hash-sig (P3). `recipient_sk`/`expected_amount` enable the
/// recipient's own-slot decryption check. NOTE: the witness verify checks structural member
/// signatures only; `verify_all_signatures` must be called separately once all signatures present.
#[allow(clippy::too_many_arguments)]
pub fn verify_send_transition(
    prev: &ChannelState,
    trusted_record: &ChannelRecord,
    payload: &SendPayload,
    level: RegevSecurityLevel,
    recipient_sk: Option<&RegevSk>,
    expected_amount: Option<u64>,
) -> WResult<()> {
    // SECURITY (P4-1, A11 caller-layer): the peer-supplied `payload` carries its OWN `record` /
    // `members`. Bind the payload's record to the session's TRUSTED, already-verified channel record
    // (the member set is immutable for the channel's lifetime) so the A11 membership check runs
    // against the truly-registered members — NOT an attacker-supplied, self-consistent foreign record.
    // The IMCR `signing_digest` commits the whole record (member_pk_gs, member_pubkeys_root,
    // regev_pk_root, …); the downstream member_pubkeys_root recompute then transitively binds
    // `payload.members` to this trusted set.
    if payload.record.signing_digest() != trusted_record.signing_digest() {
        return bail("A11: payload record is not the channel's registered (trusted) record");
    }
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
    let mc = payload.record.member_count as usize;
    check_slot(sender_slot, mc)?;
    // SECURITY (P4-1, A11): authenticate the payload's member set BEFORE trusting any `pk_b` /
    // `regev_pk` it carries. `verify_send_transition` runs on a peer-supplied `SendPayload` that has
    // its OWN `record` + `members` (it is NOT necessarily the snapshot already passed through
    // `verify_snapshot`), so we must independently (a) check the member list covers slots
    // `0..member_count` bijectively and (b) recompute the canonical Poseidon `MemberTree` root over
    // `MemberLeaf{pk_g, pk_b, regev_pk_digest}` and bind it to `record.member_pubkeys_root`. Only
    // then are the per-slot `pk_b` and Regev keys authenticated against the registered set, closing
    // the P3-5 gap where `pk_b` was read from the raw payload.
    if payload.members.len() != mc {
        return bail(format!(
            "members list has {} entries but member_count is {mc}",
            payload.members.len()
        ));
    }
    let mut seen = [false; MAX_CHANNEL_MEMBERS];
    for m in &payload.members {
        check_slot(m.slot as usize, mc)?;
        if seen[m.slot as usize] {
            return bail(format!("duplicate member slot {}", m.slot));
        }
        seen[m.slot as usize] = true;
    }
    let recomputed_root = member_pubkeys_root(&payload.record, &payload.members)?;
    if recomputed_root != payload.record.member_pubkeys_root {
        return bail(
            "member_pubkeys_root mismatch: payload member set not anchored to the record",
        );
    }
    // Regev keys consumed by the E-1 statement below (built from `payload.members`, which the
    // member_pubkeys_root recompute bound to the trusted record's set).
    let regev_pks = regev_pks_array(&payload.members);
    let sender = member_at(&payload.members, sender_slot)?;
    // A11: the sender slot's REGISTERED (pk_g, pk_b) — authenticated, since `payload.record` is the
    // trusted record and `payload.members` is bound to its `member_pubkeys_root`.
    let registered_pk_g = payload.record.member_pk_gs[sender_slot];
    verify_channel_tx_sender_hash_sig(
        &payload.channel_tx,
        &tx_digest,
        level,
        registered_pk_g,
        sender.pk_b,
    )?;

    // `InChannelTransferUpdateWitness::verify` requires a STRUCTURALLY complete signature set
    // (one non-empty sig per active slot with the right pubkey hash). A co-signer validates the
    // transition BEFORE the real signatures are collected, so fill placeholder structural sigs
    // here — they do not affect `signing_digest()` (member signatures are excluded from it). The
    // REAL multi-signature check (per-member SingleSig proofs) is `verify_all_signatures`, run once
    // the set is complete.
    let mut next_for_check = payload.proposed_next_state.clone();
    fill_placeholder_sigs(&payload.record, &mut next_for_check);

    let witness = InChannelTransferUpdateWitness {
        channel_record: payload.record.clone(),
        regev_pks,
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
