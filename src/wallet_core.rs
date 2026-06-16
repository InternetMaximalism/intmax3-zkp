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

use plonky2::plonk::{circuit_data::VerifierCircuitData, proof::ProofWithPublicInputs};
use rand::SeedableRng as _;
use rand010::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    circuits::balance::balance_pis::BalanceFullPublicInputs,
    circuits::channel::state_update_verifier::{
        BalanceRefreshUpdateWitness, InChannelTransferUpdateWitness,
    },
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
        add_ciphertexts, channel_keygen, decrypt_amount, encrypt_amount,
        prove_balance_refresh_witnessed, prove_channel_tx,
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
///
/// `active_count` is the number of ACTIVE PARTICIPANTS = `member_count + delegate_count` (delegate
/// account). Active participants are co-signing members (`0..member_count`) AND delegates
/// (`member_count..member_count+delegate_count`); both have a balance slot and can send/receive,
/// so every balance / send / receive / decrypt / snapshot-membership gate admits the full active
/// region. This check is NOT a co-sign gate — co-signing is enforced separately over
/// `0..member_count` only (`verify_all_signatures`, `validate_all_member_signatures`). With
/// `delegate_count = 0`, `active_count == member_count` and this is byte-for-byte the legacy check.
fn check_slot(slot: usize, active_count: usize) -> WResult<()> {
    if slot >= MAX_CHANNEL_MEMBERS {
        return bail(format!("slot {slot} exceeds MAX_CHANNEL_MEMBERS"));
    }
    if slot >= active_count {
        return bail(format!(
            "slot {slot} is not an active participant (active_count {active_count})"
        ));
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

/// The channel's intmax NATIVE-balance backing: the base-layer balance proof for this channel's
/// `channel_id` (detail2 §2.1 `balanceProof` / §F-1). Its public inputs expose `channel_id` and
/// the `settled_tx_chain` fold over every deposit / inter-channel settle the channel has absorbed.
/// Carried alongside the snapshot so co-signers can reconcile the signed `BalanceState` against a
/// real, validity-backed balance proof BEFORE signing (the fail-closed gate below).
///
/// SECURITY: this is the cryptographic object that makes the channel genuinely intmax3-backed. A
/// snapshot WITHOUT a valid attestation is an unbacked channel; co-signing it is unsafe (a close
/// could later attempt to withdraw value that was never deposited — detail2 §2.4 `withdrawCap`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelBalanceAttestation {
    /// Serialized `ProofWithPublicInputs<F, C, D>` of the channel's base-layer balance proof,
    /// verifiable against the `BalanceProcessor`'s `balance_vd()`.
    pub balance_proof: Vec<u8>,
}

/// A complete, signed channel snapshot shared between members. The deposit-backing attestation is
/// NOT embedded here (it is a co-signer-side artifact passed separately to [`verify_channel_backing`])
/// so the snapshot wire format stays unchanged and the browser delegate need not carry it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelSnapshot {
    pub record: ChannelRecord,
    pub state: ChannelState,
    pub members: Vec<MemberInfo>,
}

/// detail2 §F-1 / §3.1 reconciliation, enforced **fail-closed**: returns `Ok` only when the channel
/// is genuinely backed by a verified intmax deposit balance proof. EVERY co-signer MUST call this
/// before signing a `ChannelState`; on any failure it MUST refuse to sign (an unbacked channel
/// leaves members unable to withdraw real value at close — the user-mandated safety invariant).
///
/// Checks (all required):
/// 1. the attestation's balance proof VERIFIES against `balance_vd` (a real, validity-backed proof);
/// 2. `balanceProof.PI.channel_id == record.channel_id` (the proof is for THIS channel);
/// 3. `balanceProof.PI.settled_tx_chain == state.balance_state.settled_tx_chain` (detail2 §F-1: the
///    signed state's settle history is exactly the one the balance proof absorbed).
///
/// The plaintext native balance is hidden inside `balanceProof.PI.private_commitment`, so the
/// amount-equivalence `Σ enc_balances == channel_fund == attested balance` is NOT re-checked here —
/// it is enforced by the in-channel E-1/E-2 range ZKPs and the close `withdrawCap` (detail2 §2.4).
pub fn verify_channel_backing(
    record: &ChannelRecord,
    state: &ChannelState,
    attestation: Option<&ChannelBalanceAttestation>,
    balance_vd: &VerifierCircuitData<F, C, D>,
) -> WResult<()> {
    let att = attestation.ok_or_else(|| {
        WalletError(
            "refusing to co-sign: channel has NO intmax deposit-backing attestation (detail2 \
             §F-1/§3.1). An unbacked channel cannot withdraw real value at close — unsafe."
                .into(),
        )
    })?;
    let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
        att.balance_proof.clone(),
        &balance_vd.common,
    )
    .map_err(|e| WalletError(format!("backing balance proof deserialization failed: {e}")))?;

    // 1. The base-layer balance proof must really verify (it is validity-proof-backed: the balance
    //    circuit only advances against a proven `PublicState`). A fabricated proof is rejected here.
    balance_vd
        .verify(proof.clone())
        .map_err(|e| WalletError(format!("backing balance proof verification FAILED: {e}")))?;

    // The balance proof is a cyclic-recursion proof: its public inputs are
    // `[BalancePublicInputs ‖ embedded verifier-data]`. GoldilocksField PIs are stored canonically
    // (`.0 < ORDER`), matching `to_u64_vec`. Parse both halves.
    let pi_u64: Vec<u64> = proof.public_inputs.iter().map(|f| f.0).collect();
    let full = BalanceFullPublicInputs::<F, C, D>::from_u64_slice(&pi_u64, &balance_vd.common.config)
        .map_err(|e| WalletError(format!("backing balance proof public-input parse failed: {e}")))?;

    // Cyclic-recursion binding: the proof's self-referential verifier data must be the EXPECTED
    // balance circuit. Without this a valid proof from a DIFFERENT circuit carrying a look-alike
    // `BalancePublicInputs` could be substituted. `circuit_digest` uniquely identifies the circuit.
    if full.vd.circuit_digest != balance_vd.verifier_only.circuit_digest {
        return bail(
            "backing balance proof's embedded verifier data is not the expected balance circuit \
             (cyclic-recursion binding failed)",
        );
    }
    let pis = full.pis;

    // 2. The proof must attest THIS channel's balance, not some other channel's.
    if pis.channel_id != record.channel_id {
        return bail(format!(
            "backing balance proof is for channel {:?}, not this channel {:?}",
            pis.channel_id, record.channel_id
        ));
    }

    // 3. detail2 §F-1: the signed BalanceState's settle history must be exactly the one the balance
    //    proof folded in. This is the seam binding the off-chain channel state to on-chain deposits.
    if pis.settled_tx_chain != state.balance_state.settled_tx_chain {
        return bail(
            "backing balance proof settled_tx_chain != signed BalanceState.settled_tx_chain \
             (detail2 §F-1): the channel state is not the one this deposit balance backs",
        );
    }

    Ok(())
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
/// `MemberLeaf{pk_g, pk_b, regev_pk_digest}`, in slot order (active slots
/// `0..member_count+delegate_count`; padding slots are empty leaves, pad-to-MAX D6).
///
/// SECURITY (P4-1, A11): this is the SAME root the validity / registration circuits commit
/// (`block_witness_generator::ChannelMemberKeys::member_tree.get_root()`,
/// `channel_reg_step`). Anchoring the wallet's `ChannelRecord.member_pubkeys_root` to this root
/// (instead of the previous keccak-over-`pk_g`-only) commits the FULL `(pk_g, pk_b, regev_pk)`
/// triple jointly, so a peer cannot substitute one member's `pk_b` (or Regev key) independently of
/// their `pk_g`. The off-chain channel-tx A11 check then reads `pk_b` from this AUTHENTICATED set.
///
/// `members` MUST cover slots `0..member_count+delegate_count` bijectively (the caller checks this
/// via `verify_snapshot` / `check_slot`); `pk_g` for each slot is taken from the record (the value
/// the member signatures are bound to), while `pk_b` and the Regev digest come from the per-member
/// `MemberInfo`.
///
/// SECURITY (delegate account): the loop covers ACTIVE participants = members
/// (`0..member_count`) AND delegates (`member_count..member_count+delegate_count`). Delegates carry
/// a real `MemberLeaf{pk_g, pk_b, regev_pk_digest}` identity so they can send (A11) and withdraw at
/// close, distinguished from members ONLY by slot index. This MUST match the Phase-1 native
/// `member_pubkeys_root_for` (channel_reg_step.rs, loops `0..member_count+delegate_count`) and the
/// keccak reg-chain, so the wallet's `member_pubkeys_root` equals the registered root. With
/// `delegate_count = 0` this is byte-for-byte the legacy `0..member_count` loop.
fn member_pubkeys_root(record: &ChannelRecord, members: &[MemberInfo]) -> WResult<Bytes32> {
    let mut tree = MemberTree::init();
    let active = record.member_count as usize + record.delegate_count as usize;
    for slot in 0..active {
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

/// Build the `ChannelRecord` for a channel from its ACTIVE participants' pubkeys (delegate account).
/// `members` covers slots `0..active` (active = co-signing members `0..member_count` followed by
/// `delegate_count` delegates `member_count..active`), bijectively. `bp_member_slot` is the block
/// proposer and MUST be a co-signing member (`< member_count`). Pass `delegate_count = 0` for a
/// classic member-only channel (byte-for-byte the legacy build).
pub fn build_record(
    channel_id: u32,
    members: &[MemberInfo],
    bp_member_slot: u8,
    delegate_count: u8,
) -> WResult<ChannelRecord> {
    let active = members.len();
    let dc = delegate_count as usize;
    // active = member_count + delegate_count. Require active <= MAX, delegate_count <= active, and
    // member_count = active - delegate_count >= 2 (the channel must keep >= 2 co-signing members).
    if active > MAX_CHANNEL_MEMBERS || dc > active || active - dc < 2 {
        return bail(format!(
            "invalid active {active} / delegate_count {dc} (need member_count >= 2 and active <= \
             {MAX_CHANNEL_MEMBERS})"
        ));
    }
    let member_count = active - dc;
    // bp must be a co-signing member, not a delegate.
    if bp_member_slot as usize >= member_count {
        return bail(format!(
            "bp_member_slot {bp_member_slot} must be a co-signing member (< member_count {member_count})"
        ));
    }
    let mut hashes: [Bytes32; MAX_CHANNEL_MEMBERS] = std::array::from_fn(|_| Bytes32::default());
    for (slot, hash) in hashes.iter_mut().enumerate().take(active) {
        let m = member_at(members, slot)?;
        // Each active participant's identity = its Goldilocks signing public key `pk_g`.
        *hash = m.pk_g;
    }
    let regev_pks = regev_pks_array(members);
    let mut record = ChannelRecord {
        channel_id: ChannelId::new(channel_id as u64).map_err(|e| WalletError(format!("{e:?}")))?,
        member_count: member_count as u8,
        delegate_count,
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

/// Assemble an UNSIGNED genesis `ChannelState` from per-ACTIVE-participant genesis ciphertexts
/// (slot order: members then delegates). `enc_balances_active` must have one ciphertext per active
/// slot (`member_count + delegate_count`); with `delegate_count = 0` this equals the legacy
/// member-only behavior.
pub fn assemble_genesis_state(
    record: &ChannelRecord,
    enc_balances_active: &[RegevCiphertext],
    fund_amount: u64,
) -> WResult<ChannelState> {
    // Legacy/UNBACKED genesis: zero settle-chain + zero intmax_state_root. A channel assembled this
    // way has NO deposit backing, so `verify_channel_backing` REFUSES to co-sign it (fail-closed).
    assemble_genesis_state_backed(
        record,
        enc_balances_active,
        fund_amount,
        Bytes32::default(),
        Bytes32::default(),
    )
}

/// Genuine deposit-BACKED genesis (detail2 §F-1). `settled_tx_chain` MUST equal the channel's
/// base-layer `balanceProof.PI.settled_tx_chain` (the deposit settle-history that funds the channel),
/// and `intmax_state_root` anchors the `ChannelFund` to that intmax state. The resulting genesis
/// reconciles with the channel's [`ChannelBalanceAttestation`], so co-signers accept it. `fund_amount`
/// should equal the deposited native value (the close `withdrawCap`).
pub fn assemble_genesis_state_backed(
    record: &ChannelRecord,
    enc_balances_active: &[RegevCiphertext],
    fund_amount: u64,
    settled_tx_chain: Bytes32,
    intmax_state_root: Bytes32,
) -> WResult<ChannelState> {
    let active = record.member_count as usize + record.delegate_count as usize;
    if enc_balances_active.len() != active {
        return bail("genesis ciphertext count must equal member_count + delegate_count");
    }
    let state = ChannelState {
        channel_id: record.channel_id,
        epoch: 1,
        small_block_number: 0,
        close_freeze_nonce: 0,
        channel_fund: ChannelFund {
            channel_id: record.channel_id,
            amount: U256::from(fund_amount.min(u32::MAX as u64) as u32),
            intmax_state_root,
        },
        balance_state: BalanceState {
            channel_id: record.channel_id,
            member_count: record.member_count,
            delegate_count: record.delegate_count,
            enc_balances: BalanceState::pad_enc_balances(enc_balances_active),
            settled_tx_chain,
            state_version: 0,
            pending_adds: BalanceState::pad_pending_adds(&vec![0u32; active]),
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

/// CHECK-AND-SIGN (detail2 §3.1 `agreeBalanceState`, atomic / non-bypassable): produce this member's
/// signature over `state` **only if** the `settled_tx_chain` embedded in the state matches the
/// signer's held intmax balance state — i.e. the channel's native `balanceProof` attestation
/// reconciles (channel_id + settled_tx_chain, [`verify_channel_backing`]). On any mismatch it returns
/// an error and produces NO signature.
///
/// This is the single operation a co-signer must use: a member never signs a channel state whose
/// settle history disagrees with the intmax balance it actually holds. Prefer this over a bare
/// [`sign_state`] on every co-sign path (genesis agreement, send co-sign, refresh, delegate join).
pub fn sign_state_if_backed(
    keys: &MemberKeys,
    slot: u8,
    record: &ChannelRecord,
    state: &ChannelState,
    attestation: &ChannelBalanceAttestation,
    balance_vd: &VerifierCircuitData<F, C, D>,
) -> WResult<MemberSignature> {
    // The gate: the state's settled_tx_chain MUST equal the held balance proof's settled_tx_chain
    // (and the proof must verify and be for this channel). Refuse to sign otherwise.
    verify_channel_backing(record, state, Some(attestation), balance_vd)?;
    sign_state(keys, slot, state)
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
    // The members list must cover ALL active participants — members (`0..member_count`) AND
    // delegates (`member_count..member_count+delegate_count`) — bijectively (no duplicates, no
    // out-of-range or padding-slot entries). Prevents malformed/duplicate slot lists slipping past
    // the root check. With `delegate_count = 0`, `active == member_count` (legacy behavior).
    let active = snapshot.record.member_count as usize + snapshot.record.delegate_count as usize;
    if snapshot.members.len() != active {
        return bail(format!(
            "members list has {} entries but active participants (member_count + delegate_count) is {active}",
            snapshot.members.len()
        ));
    }
    let mut seen = [false; MAX_CHANNEL_MEMBERS];
    for m in &snapshot.members {
        check_slot(m.slot as usize, active)?;
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
        // A delegate (slot in `member_count..active`) verifies/decrypts its own slot exactly like a
        // member, so admit the full active region.
        check_slot(slot as usize, active)?;
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
    // Delegates own a balance slot too; admit the full active region (members + delegates).
    let bs = &snapshot.state.balance_state;
    let active = bs.member_count as usize + bs.delegate_count as usize;
    check_slot(slot as usize, active)?;
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
    // Sender and recipient may each be a member OR a delegate (delegate account): both have a
    // balance slot and send/receive with the identical proofs, so admit the full active region
    // (`member_count + delegate_count`). The sender's authorization is still its own BabyBear
    // hash-sig (A11) — only the slot region widened.
    let active = snapshot.record.member_count as usize + snapshot.record.delegate_count as usize;
    check_slot(sender_slot as usize, active)?;
    check_slot(recipient_slot as usize, active)?;
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
    // SECURITY/delegate account: a co-signing MEMBER sender (slot < member_count) contributes its
    // own Goldilocks state signature here (it is one of the N-of-N). A DELEGATE sender
    // (slot >= member_count) is send-only — it authorizes the debit with its BabyBear A11 hash-sig
    // (above) but does NOT co-sign channel state, so it adds NO state signature; the N-of-N members
    // co-sign the resulting state. (A delegate signature would be ignored by verify_all_signatures
    // anyway, but emitting it would contradict the send-only model and waste a proof.)
    if (sender_slot as usize) < prev.balance_state.member_count as usize {
        let sender_sig = sign_state(keys, sender_slot, &proposed)?;
        add_signature(&mut proposed, sender_sig);
    }

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
    // The sender may be a member OR a delegate (delegate account): a delegate sends with the
    // identical E-1 + A11 mechanism, distinguished only by slot region. Admit the full active
    // region (`member_count + delegate_count`); co-signing (`0..member_count`) is unaffected.
    let active = payload.record.member_count as usize + payload.record.delegate_count as usize;
    check_slot(sender_slot, active)?;
    // SECURITY (P4-1, A11): authenticate the payload's member set BEFORE trusting any `pk_b` /
    // `regev_pk` it carries. `verify_send_transition` runs on a peer-supplied `SendPayload` that has
    // its OWN `record` + `members` (it is NOT necessarily the snapshot already passed through
    // `verify_snapshot`), so we must independently (a) check the member list covers the active
    // slots `0..member_count+delegate_count` (members + delegates) bijectively and (b) recompute the
    // canonical Poseidon `MemberTree` root over
    // `MemberLeaf{pk_g, pk_b, regev_pk_digest}` and bind it to `record.member_pubkeys_root`. Only
    // then are the per-slot `pk_b` and Regev keys authenticated against the registered set, closing
    // the P3-5 gap where `pk_b` was read from the raw payload.
    if payload.members.len() != active {
        return bail(format!(
            "members list has {} entries but active participants (member_count + delegate_count) is {active}",
            payload.members.len()
        ));
    }
    let mut seen = [false; MAX_CHANNEL_MEMBERS];
    for m in &payload.members {
        check_slot(m.slot as usize, active)?;
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

// ---------------------------------------------------------------------------
// Balance refresh (detail2 §B-3): re-encrypt one's own slot to clean digits so it can SEND again
// after RECEIVING (a homomorphic credit raises `pending_adds`, which blocks the next send until a
// refresh). The owner proves `old_ct` and `new_ct` encrypt the SAME value (RefreshAir); the members
// co-sign the resulting state. Identical for a member or a delegate slot (slot-agnostic).
// ---------------------------------------------------------------------------

/// A proposed balance-refresh transition for the co-signers to verify + sign. Carries the value-
/// preserving re-encryption proof; no amount/recipient (the slot's value is unchanged).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshPayload {
    pub member_index: u8,
    pub refresh_proof: ChannelProofEnvelope,
    pub proposed_next_state: ChannelState,
    pub members: Vec<MemberInfo>,
    pub record: ChannelRecord,
}

/// Build a balance-refresh for `slot` (this wallet's own slot): re-encrypt the current balance to a
/// FRESH ciphertext (clean digits, same value), prove `old_ct ≡ new_ct` (RefreshAir), and propose
/// the next state (slot's ct replaced, its `pending_adds` reset to 0, version++). Returns the payload
/// for the members to co-sign AND the fresh `AmountWitness` so the wallet can SEND from the slot
/// afterwards. A DELEGATE slot does NOT co-sign state; a member slot self-signs (it is N-of-N).
pub fn build_refresh(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    slot: u8,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<(RefreshPayload, AmountWitness)> {
    let active =
        snapshot.record.member_count as usize + snapshot.record.delegate_count as usize;
    check_slot(slot as usize, active)?;
    let prev = &snapshot.state;
    let regev_pks = regev_pks_array(&snapshot.members);
    let pk = &regev_pks[slot as usize];
    let old_ct = &prev.balance_state.enc_balances[slot as usize];

    // Value-preserving re-encryption + proof (also returns the fresh ct's witness so we can send).
    let (new_ct, new_witness, proof) =
        prove_balance_refresh_witnessed(rng, level, pk, &keys.regev_sk, old_ct).map_err(we)?;

    let mut enc_balances = prev.balance_state.enc_balances.clone();
    enc_balances[slot as usize] = new_ct;
    let mut pending_adds = prev.balance_state.pending_adds;
    pending_adds[slot as usize] = 0;
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

    let mut proposed = next_state;
    if (slot as usize) < prev.balance_state.member_count as usize {
        // A co-signing MEMBER self-signs (N-of-N). A DELEGATE is send-only — no state signature.
        let sig = sign_state(keys, slot, &proposed)?;
        add_signature(&mut proposed, sig);
    }

    let payload = RefreshPayload {
        member_index: slot,
        refresh_proof: ChannelProofEnvelope {
            role: TransitionProofRole::ChannelStateUpdate,
            backend: ProofBackend::Plonky3,
            proof,
        },
        proposed_next_state: proposed,
        members: snapshot.members.clone(),
        record: snapshot.record.clone(),
    };
    Ok((payload, new_witness))
}

/// Verify a proposed balance-refresh against the prev state (a co-signer runs this before signing):
/// the `BalanceRefreshUpdateWitness` checks only the refreshed slot changes, its counter resets to 0,
/// and the RefreshAir proof attests `old_ct` and `new_ct` encrypt the SAME hidden value (no inflation).
pub fn verify_refresh_transition(
    prev: &ChannelState,
    record: &ChannelRecord,
    payload: &RefreshPayload,
    level: RegevSecurityLevel,
) -> WResult<()> {
    let active = record.member_count as usize + record.delegate_count as usize;
    check_slot(payload.member_index as usize, active)?;
    // Anchor the carried member set to the trusted record (same as the send path).
    let recomputed_root = member_pubkeys_root(&payload.record, &payload.members)?;
    if recomputed_root != payload.record.member_pubkeys_root {
        return bail("member_pubkeys_root mismatch: payload member set not anchored to the record");
    }
    let regev_pks = regev_pks_array(&payload.members);
    let mut next_for_check = payload.proposed_next_state.clone();
    fill_placeholder_sigs(&payload.record, &mut next_for_check);
    let witness = BalanceRefreshUpdateWitness {
        channel_record: record.clone(),
        regev_pks,
        prev_state: prev.clone(),
        next_state: next_for_check,
        member_index: payload.member_index as usize,
        refresh_proof: payload.refresh_proof.clone(),
    };
    let verifier = RealRegevProofVerifier { level };
    witness
        .verify(&verifier)
        .map_err(|e| WalletError(format!("balance-refresh transition invalid: {e:?}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 2 delegate-account SEND authorization — tests
// ---------------------------------------------------------------------------
//
// These tests live INLINE (not in tests/wallet_core_e2e.rs) so they can build a delegate-bearing
// channel with the SAME private `member_pubkeys_root` / `regev_pks_array` helpers the verify path
// uses — guaranteeing the test record's `member_pubkeys_root` is byte-identical to what
// `verify_send_transition` recomputes, with no risk of a divergent hand-rolled Poseidon root.
//
// What these tests prove (delegate-account threat model §3):
//   * DA-send-happy — a DELEGATE (slot >= member_count) sends with the IDENTICAL E-1 + A11
//     mechanism as a member; `verify_send_transition` + `verify_channel_tx_sender_hash_sig` ACCEPT.
//     This is the positive existence proof that the widened `check_slot`/`member_pubkeys_root`
//     gates admit the delegate region.
//   * DA2 — an unauthorized delegate send is REJECTED: (a) a hash-sig minted by a key that is NOT
//     the delegate's registered `pk_b` (even though internally self-consistent) fails the A11
//     anchoring; (b) a send claiming a delegate slot whose `sender_pk_g/pk_b` do not match the
//     registered MemberLeaf fails A11. Closes threat DA2.
//   * DA1 — a state that debits a delegate slot with NO corresponding delegate-signed ChannelTx is
//     REJECTED by the transition layer (the E-1 statement is rebuilt from authenticated state and
//     the sender hash-sig is mandatory). Closes threat DA1 at the TRANSITION layer (DLG-1); the
//     accepted residual risk against FULLY-COLLUDING members is DLG-2, out of scope here.
//   * regression — a member_count=3, delegate_count=0 channel behaves exactly as before (the
//     widened gates are a no-op when active == member_count).
#[cfg(test)]
#[cfg(not(debug_assertions))]
mod delegate_send_tests {
    use super::*;
    use crate::common::channel::{ChannelFund, ChannelStatus, ChannelTx};
    use rand::SeedableRng as _;
    use rand010::{SeedableRng as _, rngs::StdRng};

    const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Test;

    fn member_info(slot: u8, keys: &MemberKeys) -> MemberInfo {
        MemberInfo {
            slot,
            pk_g: keys.pk_g(),
            pk_b: keys.pk_b(),
            regev_pk: keys.regev_pk.clone(),
        }
    }

    /// Build a channel record with `member_count` co-signing members followed by `delegate_count`
    /// delegates (one `MemberKeys` per active slot, in slot order). Uses the SAME private
    /// `member_pubkeys_root` / `regev_pks_array` the verify path uses.
    fn build_delegate_record(
        channel_id: u32,
        keys: &[MemberKeys],
        member_count: u8,
        delegate_count: u8,
    ) -> (ChannelRecord, Vec<MemberInfo>) {
        let active = member_count as usize + delegate_count as usize;
        assert_eq!(keys.len(), active, "one key per active slot");
        let members: Vec<MemberInfo> =
            keys.iter().enumerate().map(|(i, k)| member_info(i as u8, k)).collect();
        // Exercise the PUBLIC delegate-aware build path (build_record derives member_count =
        // active - delegate_count and validates bp is a co-signing member).
        let record = build_record(channel_id, &members, 0, delegate_count).unwrap();
        assert_eq!(record.member_count, member_count);
        assert_eq!(record.delegate_count, delegate_count);
        (record, members)
    }

    /// Assemble a genesis `ChannelState` over the FULL active set (members + delegates). Mirrors
    /// `assemble_genesis_state`, but accepts `active`-length ciphertext / pending-add vectors so a
    /// delegate's genesis balance slot is populated.
    fn assemble_active_genesis(
        record: &ChannelRecord,
        enc_balances_active: &[RegevCiphertext],
        fund_amount: u64,
    ) -> ChannelState {
        // Exercise the PUBLIC delegate-aware genesis path (accepts active-length ciphertexts).
        assemble_genesis_state(record, enc_balances_active, fund_amount).unwrap()
    }

    /// Delegate account (Phase 4): the PUBLIC wallet build path (`build_record` +
    /// `assemble_genesis_state`) creates a delegate-bearing channel and enforces the region guards.
    #[test]
    fn build_record_delegate_guards() {
        let mut rng = StdRng::seed_from_u64(0xB11D);
        let keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut rng)).collect();
        let members: Vec<MemberInfo> =
            keys.iter().enumerate().map(|(i, k)| member_info(i as u8, k)).collect();

        // 2 co-signing members + 1 delegate (active = 3): OK, member_count derived as active - dc.
        let r = build_record(77, &members, 0, 1).expect("delegate record");
        assert_eq!((r.member_count, r.delegate_count), (2, 1));
        r.validate().expect("delegate record valid");

        // bp in the delegate region (slot 2) is rejected — bp must be a co-signing member.
        assert!(build_record(77, &members, 2, 1).is_err());
        // member_count would be 1 (2 active, 1 delegate) — rejected (need >= 2 co-signers).
        let two: Vec<MemberInfo> = members[..2].to_vec();
        assert!(build_record(77, &two, 0, 1).is_err());
        // delegate_count > active — rejected.
        assert!(build_record(77, &members, 0, 4).is_err());

        // Genesis assembly requires one ciphertext per ACTIVE slot (members + delegates).
        let encs: Vec<RegevCiphertext> = keys
            .iter()
            .map(|k| encrypt_amount(&mut rng, &k.regev_pk, 10).unwrap().0)
            .collect();
        let g = assemble_genesis_state(&r, &encs, 30).expect("active genesis");
        assert_eq!(g.balance_state.delegate_count, 1);
        g.balance_state.validate().expect("genesis balance valid");
        // A member_count-only ciphertext count is rejected (must cover the delegate slot too).
        assert!(assemble_genesis_state(&r, &encs[..2], 30).is_err());
    }

    /// A 2-member + 1-delegate channel (delegate in slot 2) with real keys, a genesis with a
    /// balance for every active slot, and both MEMBERS' real co-signatures over the genesis.
    /// Returns (record, all-active-keys, members, signed genesis, genesis witnesses).
    fn setup_delegate_channel(
        rng: &mut StdRng,
        channel_id: u32,
        balances: [u64; 3],
    ) -> (
        ChannelRecord,
        Vec<MemberKeys>,
        Vec<MemberInfo>,
        ChannelState,
        Vec<AmountWitness>,
    ) {
        // slots 0,1 = co-signing members; slot 2 = delegate.
        let keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(rng)).collect();
        let (record, members) = build_delegate_record(channel_id, &keys, 2, 1);

        let mut cts = Vec::new();
        let mut witnesses = Vec::new();
        let mut fund = 0u64;
        for (i, &bal) in balances.iter().enumerate() {
            let (ct, w) = encrypt_amount(rng, &keys[i].regev_pk, bal).unwrap();
            cts.push(ct);
            witnesses.push(w);
            fund += bal;
        }
        let mut genesis = assemble_active_genesis(&record, &cts, fund);
        // ONLY the members (slots 0,1) co-sign — the delegate (slot 2) does NOT (N-of-N excludes it).
        let g0 = sign_state(&keys[0], 0, &genesis).unwrap();
        add_signature(&mut genesis, g0);
        let g1 = sign_state(&keys[1], 1, &genesis).unwrap();
        add_signature(&mut genesis, g1);

        (record, keys, members, genesis, witnesses)
    }

    /// DA-send-happy: the DELEGATE (slot 2) builds a ChannelTx sending to a member (slot 0), with
    /// its OWN BabyBear hash-sig (A11) over the IMPA digest and the E-1 channelTxZKP. The transition
    /// + sender hash-sig MUST verify (the members would then co-sign). Asserts the delegate's slot is
    /// debited and the recipient credited.
    ///
    /// PROVES: the widened `check_slot` (active region) + `member_pubkeys_root` (members + delegates)
    /// admit a delegate sender; a delegate sends with the IDENTICAL mechanism as a member.
    #[test]
    fn da_send_happy_delegate_sends_to_member() {
        let mut rng = StdRng::seed_from_u64(0xDADADA);
        let (bal0, bal1, bal_d) = (50u64, 30u64, 20u64);
        let (record, keys, members, genesis, witnesses) =
            setup_delegate_channel(&mut rng, 11, [bal0, bal1, bal_d]);
        let snapshot = ChannelSnapshot {
            record: record.clone(),
            state: genesis,
            members: members.clone(),
        };
        // Both members AND the delegate fully verify the signed genesis (real roots / own-slot
        // decrypt). The delegate verifying its own slot exercises the widened `verify_snapshot`.
        verify_snapshot(&snapshot, Some((&keys[0], 0))).expect("member verify genesis");
        verify_snapshot(&snapshot, Some((&keys[2], 2))).expect("DELEGATE verify genesis");
        assert_eq!(decrypt_balance(&keys[2], &snapshot, 2).unwrap(), bal_d);

        // The delegate (slot 2) sends 8 to member 0.
        let amount = 8u64;
        let BuiltSend { mut payload, .. } = build_send(
            &keys[2],
            &snapshot,
            2, // delegate sender
            0, // member recipient
            amount,
            bal_d,
            &witnesses[2],
            Bytes32::default(),
            LEVEL,
            &mut rng,
        )
        .expect("delegate build_send");

        // Recipient (member 0) verifies the transition + E-1 proof + the delegate's A11 hash-sig.
        verify_send_transition(
            &snapshot.state,
            &snapshot.record,
            &payload,
            LEVEL,
            Some(&keys[0].regev_sk),
            Some(amount),
        )
        .expect("delegate send transition must verify");

        // Explicit A11 sender hash-sig check against the delegate's REGISTERED leaf at slot 2.
        let tx_digest = ChannelTx::signing_digest(
            snapshot.state.channel_id,
            snapshot.state.digest,
            &payload.channel_tx.enc_amount,
            payload.channel_tx.nonce,
            payload.channel_tx.sender_pk_g,
            payload.channel_tx.recipient_pk_g,
        );
        verify_channel_tx_sender_hash_sig(
            &payload.channel_tx,
            &tx_digest,
            LEVEL,
            record.member_pk_gs[2],
            members[2].pk_b,
        )
        .expect("delegate A11 sender hash-sig must verify");

        // Members co-sign the result (delegate does NOT).
        let s0 = sign_state(&keys[0], 0, &payload.proposed_next_state).unwrap();
        add_signature(&mut payload.proposed_next_state, s0);
        let s1 = sign_state(&keys[1], 1, &payload.proposed_next_state).unwrap();
        add_signature(&mut payload.proposed_next_state, s1);
        let final_snapshot = ChannelSnapshot {
            record,
            state: payload.proposed_next_state,
            members,
        };
        verify_all_signatures(
            &final_snapshot.record,
            &final_snapshot.members,
            &final_snapshot.state,
        )
        .expect("member n-of-n must verify (delegate excluded)");

        // The delegate slot is debited; the recipient member is credited.
        assert_eq!(decrypt_balance(&keys[2], &final_snapshot, 2).unwrap(), bal_d - amount);
        assert_eq!(decrypt_balance(&keys[0], &final_snapshot, 0).unwrap(), bal0 + amount);
    }

    /// DA2 (a): the delegate send but with the hash-sig produced by a DIFFERENT key (not the
    /// delegate's registered `pk_b`), with the `pk_b` swapped in the payload member list AND a
    /// matching forged hash-sig — so the inner hash-sig is internally valid. The A11 anchoring
    /// (member_pubkeys_root recompute) MUST reject it.
    ///
    /// PROVES (DA2): a delegate slot cannot be debited by a non-registered signing key.
    #[test]
    fn da2_delegate_send_wrong_key_rejected() {
        let mut rng = StdRng::seed_from_u64(0xD2D2D2);
        let (record, keys, members, genesis, witnesses) =
            setup_delegate_channel(&mut rng, 12, [50, 30, 20]);
        let snapshot = ChannelSnapshot {
            record: record.clone(),
            state: genesis,
            members: members.clone(),
        };
        let amount = 8u64;
        let BuiltSend { payload, .. } = build_send(
            &keys[2], &snapshot, 2, 0, amount, 20, &witnesses[2], Bytes32::default(), LEVEL,
            &mut rng,
        )
        .expect("delegate build_send");

        // Attacker key forges a self-consistent hash-sig over the SAME IMPA digest.
        let attacker_baby =
            BabyBearSecretKey::random(&mut rand::rngs::StdRng::seed_from_u64(0xBAD));
        let attacker_pk_b = attacker_baby.public_key().to_bytes32();
        let tx_digest = ChannelTx::signing_digest(
            snapshot.state.channel_id,
            snapshot.state.digest,
            &payload.channel_tx.enc_amount,
            payload.channel_tx.nonce,
            payload.channel_tx.sender_pk_g,
            payload.channel_tx.recipient_pk_g,
        );
        let m = decompose_digest_to_limbs(&tx_digest);
        let (attacker_sig, _pvs) = prove_hash_sig(LEVEL, &attacker_baby, &m).unwrap();

        let mut tampered = payload.clone();
        tampered.channel_tx.sender_pk_b = attacker_pk_b;
        tampered.channel_tx.sender_hash_sig = attacker_sig;
        for mi in tampered.members.iter_mut() {
            if mi.slot == 2 {
                mi.pk_b = attacker_pk_b;
            }
        }
        let res = verify_send_transition(
            &snapshot.state,
            &snapshot.record,
            &tampered,
            LEVEL,
            Some(&keys[0].regev_sk),
            Some(amount),
        );
        let err = res.expect_err("DA2: delegate send with non-registered pk_b MUST be rejected");
        assert!(
            err.to_string().contains("member_pubkeys_root"),
            "rejection must come from the member-set anchoring (A11), got: {err}"
        );
    }

    /// DA2 (b): a send whose `sender_pk_g/pk_b` claim a delegate slot but do not match the
    /// registered MemberLeaf at that slot. Here we keep the honest member list (so the
    /// member_pubkeys_root anchoring passes) but tamper the ChannelTx's claimed sender_pk_b to a
    /// value that is not the registered delegate's pk_b. The direct A11 check rejects it.
    ///
    /// PROVES (DA2): the A11 binding ties the ChannelTx's claimed (pk_g, pk_b) to the registered
    /// leaf at the sender slot.
    #[test]
    fn da2_delegate_send_mismatched_leaf_rejected() {
        let mut rng = StdRng::seed_from_u64(0xD2BBBB);
        let (record, keys, members, genesis, witnesses) =
            setup_delegate_channel(&mut rng, 13, [50, 30, 20]);
        let snapshot = ChannelSnapshot {
            record: record.clone(),
            state: genesis,
            members: members.clone(),
        };
        let amount = 8u64;
        let BuiltSend { payload, .. } = build_send(
            &keys[2], &snapshot, 2, 0, amount, 20, &witnesses[2], Bytes32::default(), LEVEL,
            &mut rng,
        )
        .expect("delegate build_send");

        let tx_digest = ChannelTx::signing_digest(
            snapshot.state.channel_id,
            snapshot.state.digest,
            &payload.channel_tx.enc_amount,
            payload.channel_tx.nonce,
            payload.channel_tx.sender_pk_g,
            payload.channel_tx.recipient_pk_g,
        );
        // The ChannelTx's claimed pk_b does NOT match the registered delegate leaf (members[2].pk_b
        // is the real one). Direct A11 check with the WRONG claimed pk_b must reject. We feed a
        // foreign pk_b as the "registered" value to model a leaf/claim mismatch.
        let mut tampered_tx = payload.channel_tx.clone();
        let foreign = MemberKeys::generate(&mut rng);
        tampered_tx.sender_pk_b = foreign.pk_b();
        let res = verify_channel_tx_sender_hash_sig(
            &tampered_tx,
            &tx_digest,
            LEVEL,
            record.member_pk_gs[2],
            members[2].pk_b, // the genuinely registered delegate pk_b
        );
        let err = res.expect_err("DA2: ChannelTx pk_b not matching the registered leaf MUST reject");
        assert!(
            err.to_string().contains("A11"),
            "rejection must be the A11 leaf-binding, got: {err}"
        );
    }

    /// DA1: a state transition that LOWERS the delegate's balance with NO corresponding
    /// delegate-signed ChannelTx is rejected by `verify_send_transition`. We take an honest
    /// member-0 -> member-1 send and tamper the delegate's (uninvolved) slot ciphertext in the
    /// proposed next state. The transition verifier requires every uninvolved slot to be bit-
    /// identical AND the sender slot's E-1 statement to be rebuilt from authenticated state, so a
    /// fabricated delegate debit with no authorizing ChannelTx is rejected.
    ///
    /// PROVES (DA1 at the TRANSITION layer / DLG-1): honest members will not co-sign a delegate
    /// debit lacking the delegate's own send authorization — the verifier rejects it before any
    /// co-signature. (Residual DLG-2 collusion risk is accepted out of scope.)
    #[test]
    fn da1_fabricated_delegate_debit_rejected() {
        let mut rng = StdRng::seed_from_u64(0xD1D1D1);
        let (record, keys, members, genesis, witnesses) =
            setup_delegate_channel(&mut rng, 14, [50, 30, 20]);
        let snapshot = ChannelSnapshot {
            record: record.clone(),
            state: genesis,
            members: members.clone(),
        };
        // Honest member-0 -> member-1 send (the delegate at slot 2 is NOT involved).
        let amount = 5u64;
        let BuiltSend { mut payload, .. } = build_send(
            &keys[0], &snapshot, 0, 1, amount, 50, &witnesses[0], Bytes32::default(), LEVEL,
            &mut rng,
        )
        .expect("member build_send");

        // ATTACK: re-encrypt the delegate's slot to a LOWER balance (a fabricated debit) with no
        // ChannelTx authorizing it. The members would have to co-sign this — honest members refuse,
        // and the transition verifier rejects it because slot 2 is uninvolved yet changed.
        let (forged_lower, _w) = encrypt_amount(&mut rng, &keys[2].regev_pk, 1u64).unwrap();
        let mut tampered_state = payload.proposed_next_state.clone();
        tampered_state.balance_state.enc_balances[2] = forged_lower;
        let tampered_state = tampered_state.with_computed_digest();
        payload.proposed_next_state = tampered_state;

        let res = verify_send_transition(
            &snapshot.state,
            &snapshot.record,
            &payload,
            LEVEL,
            Some(&keys[1].regev_sk),
            Some(amount),
        );
        assert!(
            res.is_err(),
            "DA1: a fabricated delegate debit with no authorizing ChannelTx MUST be rejected"
        );
    }

    /// Regression: a member_count=3, delegate_count=0 channel behaves EXACTLY as before — the
    /// widened active-region gates are a no-op when active == member_count. A member send verifies
    /// and balances reconcile.
    #[test]
    fn regression_no_delegates_unchanged() {
        let mut rng = StdRng::seed_from_u64(0x3030);
        let keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut rng)).collect();
        let (record, members) = build_delegate_record(15, &keys, 3, 0);
        assert_eq!(record.delegate_count, 0);

        let (b0, b1, b2) = (40u64, 25u64, 35u64);
        let mut cts = Vec::new();
        let mut ws = Vec::new();
        for (i, &b) in [b0, b1, b2].iter().enumerate() {
            let (ct, w) = encrypt_amount(&mut rng, &keys[i].regev_pk, b).unwrap();
            cts.push(ct);
            ws.push(w);
        }
        let mut genesis = assemble_active_genesis(&record, &cts, b0 + b1 + b2);
        for i in 0..3 {
            let s = sign_state(&keys[i], i as u8, &genesis).unwrap();
            add_signature(&mut genesis, s);
        }
        let snapshot = ChannelSnapshot {
            record: record.clone(),
            state: genesis,
            members: members.clone(),
        };
        verify_snapshot(&snapshot, Some((&keys[0], 0))).expect("verify genesis (3 members)");

        let amount = 6u64;
        let BuiltSend { mut payload, .. } = build_send(
            &keys[0], &snapshot, 0, 1, amount, b0, &ws[0], Bytes32::default(), LEVEL, &mut rng,
        )
        .expect("member build_send");
        verify_send_transition(
            &snapshot.state,
            &snapshot.record,
            &payload,
            LEVEL,
            Some(&keys[1].regev_sk),
            Some(amount),
        )
        .expect("member send transition (no delegates) must verify");
        for i in 0..3 {
            let s = sign_state(&keys[i], i as u8, &payload.proposed_next_state).unwrap();
            add_signature(&mut payload.proposed_next_state, s);
        }
        let final_snapshot = ChannelSnapshot {
            record,
            state: payload.proposed_next_state,
            members,
        };
        verify_all_signatures(
            &final_snapshot.record,
            &final_snapshot.members,
            &final_snapshot.state,
        )
        .expect("3-of-3 must verify");
        assert_eq!(decrypt_balance(&keys[0], &final_snapshot, 0).unwrap(), b0 - amount);
        assert_eq!(decrypt_balance(&keys[1], &final_snapshot, 1).unwrap(), b1 + amount);
    }
}
