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
    circuits::{
        balance::balance_pis::BalanceFullPublicInputs,
        channel::state_update_verifier::{
            BalanceRefreshUpdateWitness, ChannelProofVerifier, ChannelStateUpdateError,
            ChannelStateUpdatePublicInputs, InChannelTransferUpdateWitness,
            InterChannelFundImportUpdateWitness, InterChannelSendUpdateWitness,
            ReceiverBundleApplyUpdateWitness, require_accumulator_push,
        },
    },
    common::{
        balance_state::{BalanceState, settled_tx_chain_push, tx_leaf_hash},
        channel::{
            ChannelFund, ChannelProofEnvelope, ChannelRecord, ChannelState, ChannelStatus,
            ChannelTx, InterChannelTx, MemberSignature, MerkleInclusionProof, ProofBackend,
            ReceiverBalanceDelta, SignedSmallBlock, SmallBlockRootMessage, TransitionProofRole,
        },
        channel_id::ChannelId,
        transfer::Transfer,
        trees::{
            key_tree::{MemberLeaf, MemberTree},
            transfer_tree::TransferTree,
            tx_v2_tree::{TxV2MerkleProof, TxV2Tree},
        },
        tx::{TxClass, TxV2},
    },
    constants::MAX_CHANNEL_MEMBERS,
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32},
        u32limb_trait::U32LimbTrait,
        u256::U256,
    },
    poseidon_sig::{
        GoldilocksSecretKey,
        circuit::{C, D, F, SingleSigCircuit},
    },
    regev::{
        AmountWitness, RealRegevProofVerifier, RegevCiphertext, RegevPk, RegevSecurityLevel,
        RegevSk, add_ciphertexts, channel_keygen, decrypt_amount, encrypt_amount,
        hash_sig::{BabyBearPublicKey, BabyBearSecretKey, decompose_digest_to_limbs},
        prove_balance_refresh_witnessed, prove_channel_tx, prove_channel_update, prove_hash_sig,
        regev_pk_root, verify_hash_sig,
    },
    utils::{
        poseidon_hash_out::PoseidonHashOut, trees::incremental_merkle_tree::IncrementalMerkleTree,
    },
};

/// Stage 3: height of the per-channel settled-tx Merkle ACCUMULATOR (`IncrementalMerkleTree<
/// Bytes32>`). `H = 20` ⇒ up to `2^20 ≈ 1M` settles per channel (far beyond any real channel).
/// Native `push` asserts `len < 2^H`. Leaves are the `tx_hash` of every settle (uniformly), the
/// same identifier the post-close claim binds via `incoming_tx_hash`.
pub const SETTLED_TX_ACCUMULATOR_HEIGHT: usize = 20;

/// The empty (genesis) settled-tx accumulator root: `Bytes32::from(IncrementalMerkleTree::new(H)
/// .get_root())`, the SAME injective Poseidon→Bytes32 encoding Stage 1 uses. Seeds genesis states.
pub fn empty_settled_tx_accumulator_root() -> Bytes32 {
    Bytes32::from(IncrementalMerkleTree::<Bytes32>::new(SETTLED_TX_ACCUMULATOR_HEIGHT).get_root())
}

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
    /// member's signature. Its public key `pk_g = GoldilocksSecretKey::public_key()` is the
    /// member's canonical on-chain-anchored identity (the value stored in
    /// `ChannelRecord.member_pk_gs` and committed in the registered `MemberLeaf`). The
    /// validity/close ZK list-proof aggregation over these same per-member signatures is the
    /// existing P2b path; the wallet's local agreement is per-member individual proof
    /// verification (`verify_all_signatures`).
    pub signing_key: GoldilocksSecretKey,
    /// P3 BabyBear hash-sig secret key — authorizes the channel-tx SENDER (IMPA) over the
    /// channel-tx `signing_digest`. Its `pk_b` is committed in the member's registered
    /// `MemberLeaf` (A11).
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
        // seeding a 0.8 `StdRng` from wallet entropy rather than sharing the `rand010` RNG
        // directly.
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
    // (1) The proof must be present (atomicity: a balance-reduction without an owner sig is
    // rejected).
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
    // (4) Verify the STARK against those bound public values. `verify_hash_sig` absorbs the PVs
    // into the Fiat-Shamir transcript, so a proof minted for a different (pk_b, m) is rejected.
    verify_hash_sig(level, &channel_tx.sender_hash_sig, &pvs).map_err(we)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Serializable public channel view (crosses the browser<->CLI boundary)
// ---------------------------------------------------------------------------

/// Public information about one member (no secrets). `pk_g` is the member's Goldilocks
/// Poseidon-preimage signing public key (`GoldilocksSecretKey::public_key()`, P4-2) — the value
/// stored at the member's slot in `ChannelRecord.member_pk_gs` and committed in the registered
/// `MemberLeaf`; it is the public key against which that member's `SingleSigCircuit`
/// state-signature proofs verify.
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
/// NOT embedded here (it is a co-signer-side artifact passed separately to
/// [`verify_channel_backing`]) so the snapshot wire format stays unchanged and the browser delegate
/// need not carry it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelSnapshot {
    pub record: ChannelRecord,
    pub state: ChannelState,
    pub members: Vec<MemberInfo>,
    /// Stage 3: the per-channel settled-tx Merkle ACCUMULATOR (`IncrementalMerkleTree<Bytes32>`,
    /// height [`SETTLED_TX_ACCUMULATOR_HEIGHT`]). Its leaves are the `tx_hash` of every settle the
    /// channel has absorbed (uniformly), so `Bytes32::from(tree.get_root())` MUST equal
    /// `state.balance_state.settled_tx_accumulator_root` at all times. The wallet threads it
    /// through every inter-channel advancement (push `tx_hash`, recompute the root); intra-channel
    /// transfers / refreshes leave it untouched. Persisting it here is what lets the wallet later
    /// generate the post-close inclusion proof (the design's "wallet persistence" follow-up). For
    /// backward compatibility on the wire, it defaults to an empty tree when absent.
    #[serde(default = "default_settled_tx_accumulator")]
    pub settled_tx_accumulator: IncrementalMerkleTree<Bytes32>,
}

/// Default (empty) settled-tx accumulator for serde backward-compat on [`ChannelSnapshot`] and for
/// seeding a genesis snapshot (the empty tree, matching `empty_settled_tx_accumulator_root()`).
pub fn default_settled_tx_accumulator() -> IncrementalMerkleTree<Bytes32> {
    IncrementalMerkleTree::<Bytes32>::new(SETTLED_TX_ACCUMULATOR_HEIGHT)
}

/// detail2 §F-1 / §3.1 reconciliation, enforced **fail-closed**: returns `Ok` only when the channel
/// is genuinely backed by a verified intmax deposit balance proof. EVERY co-signer MUST call this
/// before signing a `ChannelState`; on any failure it MUST refuse to sign (an unbacked channel
/// leaves members unable to withdraw real value at close — the user-mandated safety invariant).
///
/// Checks (all required):
/// 1. the attestation's balance proof VERIFIES against `balance_vd` (a real, validity-backed
///    proof);
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
    let proof =
        ProofWithPublicInputs::<F, C, D>::from_bytes(att.balance_proof.clone(), &balance_vd.common)
            .map_err(|e| {
                WalletError(format!("backing balance proof deserialization failed: {e}"))
            })?;

    // 1. The base-layer balance proof must really verify (it is validity-proof-backed: the balance
    //    circuit only advances against a proven `PublicState`). A fabricated proof is rejected
    //    here.
    balance_vd
        .verify(proof.clone())
        .map_err(|e| WalletError(format!("backing balance proof verification FAILED: {e}")))?;

    // The balance proof is a cyclic-recursion proof: its public inputs are
    // `[BalancePublicInputs ‖ embedded verifier-data]`. GoldilocksField PIs are stored canonically
    // (`.0 < ORDER`), matching `to_u64_vec`. Parse both halves.
    let pi_u64: Vec<u64> = proof.public_inputs.iter().map(|f| f.0).collect();
    let full =
        BalanceFullPublicInputs::<F, C, D>::from_u64_slice(&pi_u64, &balance_vd.common.config)
            .map_err(|e| {
                WalletError(format!(
                    "backing balance proof public-input parse failed: {e}"
                ))
            })?;

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
    //    proof folded in. This is the seam binding the off-chain channel state to on-chain
    //    deposits.
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

/// Build the `ChannelRecord` for a channel from its ACTIVE participants' pubkeys (delegate
/// account). `members` covers slots `0..active` (active = co-signing members `0..member_count`
/// followed by `delegate_count` delegates `member_count..active`), bijectively. `bp_member_slot` is
/// the block proposer and MUST be a co-signing member (`< member_count`). Pass `delegate_count = 0`
/// for a classic member-only channel (byte-for-byte the legacy build).
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
    record
        .validate()
        .map_err(|e| WalletError(format!("{e:?}")))?;
    Ok(record)
}

/// Assemble an UNSIGNED genesis `ChannelState` from per-ACTIVE-participant genesis ciphertexts
/// (slot order: members then delegates). `enc_balances_active` must have one ciphertext per active
/// slot (`member_count + delegate_count`); with `delegate_count = 0` this equals the legacy
/// member-only behavior.
pub fn assemble_genesis_state(
    record: &ChannelRecord,
    enc_balances_active: &[RegevCiphertext],
    regev_pk_digests_active: &[Bytes32],
    fund_amount: u64,
) -> WResult<ChannelState> {
    // Legacy/UNBACKED genesis: zero settle-chain + zero intmax_state_root. A channel assembled this
    // way has NO deposit backing, so `verify_channel_backing` REFUSES to co-sign it (fail-closed).
    assemble_genesis_state_backed(
        record,
        enc_balances_active,
        regev_pk_digests_active,
        fund_amount,
        Bytes32::default(),
        Bytes32::default(),
    )
}

/// Genuine deposit-BACKED genesis (detail2 §F-1). `settled_tx_chain` MUST equal the channel's
/// base-layer `balanceProof.PI.settled_tx_chain` (the deposit settle-history that funds the
/// channel), and `intmax_state_root` anchors the `ChannelFund` to that intmax state. The resulting
/// genesis reconciles with the channel's [`ChannelBalanceAttestation`], so co-signers accept it.
/// `fund_amount` should equal the deposited native value (the close `withdrawCap`).
pub fn assemble_genesis_state_backed(
    record: &ChannelRecord,
    enc_balances_active: &[RegevCiphertext],
    regev_pk_digests_active: &[Bytes32],
    fund_amount: u64,
    settled_tx_chain: Bytes32,
    intmax_state_root: Bytes32,
) -> WResult<ChannelState> {
    let active = record.member_count as usize + record.delegate_count as usize;
    if enc_balances_active.len() != active {
        return bail("genesis ciphertext count must equal member_count + delegate_count");
    }
    // Decryption Stage 1: one Regev pk Poseidon digest per ACTIVE slot (members then delegates),
    // each `Bytes32::from(member.regev_pk.poseidon_digest())`. Folded into the signed H1 so the
    // claim circuit can bind the witnessed `(a, b)` to the member's registered key.
    if regev_pk_digests_active.len() != active {
        return bail("genesis Regev pk digest count must equal member_count + delegate_count");
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
            regev_pk_digests: BalanceState::pad_regev_pk_digests(regev_pk_digests_active),
            settled_tx_chain,
            // Stage 3: genesis seeds the EMPTY-tree accumulator root. Each subsequent inter-channel
            // advancement pushes `tx_hash` and sets the new root (see the build_* sites below).
            settled_tx_accumulator_root: empty_settled_tx_accumulator_root(),
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

/// CHECK-AND-SIGN (detail2 §3.1 `agreeBalanceState`, atomic / non-bypassable): produce this
/// member's signature over `state` **only if** the `settled_tx_chain` embedded in the state matches
/// the signer's held intmax balance state — i.e. the channel's native `balanceProof` attestation
/// reconciles (channel_id + settled_tx_chain, [`verify_channel_backing`]). On any mismatch it
/// returns an error and produces NO signature.
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
    state
        .member_signatures
        .retain(|s| s.member_slot != sig.member_slot);
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
        (
            &prev.balance_state.enc_balances[sender_slot as usize],
            before_witness,
        ),
        (&enc_amount, &enc_amount_w),
        (&after_ct, &after_w),
    )
    .map_err(we)?;

    // Recipient slot = public homomorphic sum.
    let recipient_after = add_ciphertexts(
        &prev.balance_state.enc_balances[recipient_slot as usize],
        &enc_amount,
    )
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
        // §C-2 (no small block): the next-state h2_tag MUST be zero. `..prev.clone()` would
        // otherwise inherit a NON-zero h2_tag left by a preceding inter-channel send (which
        // sets h2_tag = tx_tree_root), making the very next intra send / refresh fail
        // InvalidH2Tag.
        h2_tag: Bytes32::default(),
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
    // `members`. Bind the payload's record to the session's TRUSTED, already-verified channel
    // record (the member set is immutable for the channel's lifetime) so the A11 membership
    // check runs against the truly-registered members — NOT an attacker-supplied,
    // self-consistent foreign record. The IMCR `signing_digest` commits the whole record
    // (member_pk_gs, member_pubkeys_root, regev_pk_root, …); the downstream member_pubkeys_root
    // recompute then transitively binds `payload.members` to this trusted set.
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
    // `regev_pk` it carries. `verify_send_transition` runs on a peer-supplied `SendPayload` that
    // has its OWN `record` + `members` (it is NOT necessarily the snapshot already passed
    // through `verify_snapshot`), so we must independently (a) check the member list covers the
    // active slots `0..member_count+delegate_count` (members + delegates) bijectively and (b)
    // recompute the canonical Poseidon `MemberTree` root over
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
        return bail("member_pubkeys_root mismatch: payload member set not anchored to the record");
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
/// the next state (slot's ct replaced, its `pending_adds` reset to 0, version++). Returns the
/// payload for the members to co-sign AND the fresh `AmountWitness` so the wallet can SEND from the
/// slot afterwards. A DELEGATE slot does NOT co-sign state; a member slot self-signs (it is
/// N-of-N).
pub fn build_refresh(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    slot: u8,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<(RefreshPayload, AmountWitness)> {
    let active = snapshot.record.member_count as usize + snapshot.record.delegate_count as usize;
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
        // §C-2 (no small block): the next-state h2_tag MUST be zero. `..prev.clone()` would
        // otherwise inherit a NON-zero h2_tag left by a preceding inter-channel send (which
        // sets h2_tag = tx_tree_root), making the very next intra send / refresh fail
        // InvalidH2Tag.
        h2_tag: Bytes32::default(),
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
/// the `BalanceRefreshUpdateWitness` checks only the refreshed slot changes, its counter resets to
/// 0, and the RefreshAir proof attests `old_ct` and `new_ct` encrypt the SAME hidden value (no
/// inflation).
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

// ===========================================================================
// Inter-channel send (detail2 §C-6/§E-2/§C-7, abstract2 §3.3/§3.4)
//
// Two legs, both driven entirely from this module's reusable functions:
//   LEG A (source channel A — debit): `build_inter_channel_send` produces the post-debit
//     `a_send` state + the REAL E-2 `channelUpdateZKP`, computes the 1-tx `TxV2Tree` INTERNALLY
//     (so `tx_tree_root = H2` and the inclusion proof are produced here, not by the browser), and
//     CALLS `InterChannelSendUpdateWitness::verify` as a self-check before returning. A co-signer
//     re-runs that same witness via `verify_inter_channel_send_transition` before signing.
//   LEG B (destination channel B — credit): `build_inter_channel_credit` applies
//     `InterChannelFundImportUpdateWitness` then `ReceiverBundleApplyUpdateWitness`;
//     `verify_inter_channel_credit_transition` is the FAIL-CLOSED gate a B co-signer runs before
//     signing, enforcing the cross-channel invariants the per-channel witnesses cannot see
//     (invariant 1: A is N-of-N co-signed; invariant 2: amount consistency end-to-end; invariant 3:
//     receiver pk_g == B's recipient slot AND decrypts to amount; invariant 4: channel-id binding;
//     invariant 5: A's small-block state_commitment_root == a_signed_state.h1() and tx_tree_root
//     matches; invariant 7: TxV2 inclusion).
//
// SECURITY (trusted records): both `verify_*` functions TAKE the trusted channel record(s) as
// parameters and bind the payload/descriptor's record to them — they NEVER trust a record carried
// inside the peer-supplied payload. Invariant 6 (replay ledger) and pinning the trusted A-record to
// the on-chain registration are CLI-layer concerns; these functions are designed to accept the
// trusted A record so that wiring is possible without changing this API.
//
// SECURITY (replay — invariant 6, NEEDS-CLI-WIRING): this module does NOT maintain a consumed-tx
// ledger. A B co-signer MUST refuse to credit a `descriptor.tx_hash` it has already credited; the
// import only requires the shared_native_nullifier_root to ADVANCE, not that the tx_hash is unused.
// Replay protection is the CLI's responsibility (a per-destination-channel consumed-tx_hash set).
//
// SECURITY (delegate account, active-region slots): a recipient (and a sender) may be a co-signing
// MEMBER (slot `< member_count`) OR a DELEGATE (slot `member_count..member_count+delegate_count`):
// both own a balance slot and may receive. Every slot bound below uses the ACTIVE region
// `member_count + delegate_count` via `check_slot`, NOT `member_count` — so a delegate recipient is
// admitted, and (the security-critical direction) `recipient_slot` is rejected BEFORE it indexes
// `member_pk_gs[recipient_slot]` if it is a PADDING slot (which would otherwise read
// `Bytes32::default()` and silently strand value) or out of range. Co-signing remains
// `0..member_count` (`verify_all_signatures`), unchanged.
// ===========================================================================

/// A built inter-channel debit (LEG A) ready to hand to channel-A co-signers and to channel B.
///
/// `debit_payload` is everything A's co-signers need to RE-VERIFY the debit (it carries the
/// proposed post-debit state, the E-2-bearing `inter_channel_tx`, and the trusted-record binding).
/// `transfer_descriptor` is everything channel B needs to RE-VERIFY and credit.
/// `new_balance_witness` is the sender's fresh `AmountWitness` for its post-debit ciphertext (kept
/// locally so the sender can send again without a refresh).
pub struct BuiltInterChannelSend {
    pub debit_payload: InterChannelDebitPayload,
    pub transfer_descriptor: InterChannelTransferDescriptor,
    pub new_balance_witness: AmountWitness,
    pub new_balance: u64,
    /// Stage 3: channel A's settled-tx accumulator AFTER pushing this send's `tx_hash`. Persist it
    /// as A's new `ChannelSnapshot::settled_tx_accumulator` (root ==
    /// `proposed_next_state.balance_state.settled_tx_accumulator_root`).
    pub settled_tx_accumulator:
        crate::utils::trees::incremental_merkle_tree::IncrementalMerkleTree<Bytes32>,
}

/// The channel-A-side payload (crosses browser↔relay↔CLI). Mirrors `SendPayload` for the
/// inter-channel case: the proposed post-debit state + the E-2-bearing `InterChannelTx`, plus the
/// authenticated member set + record so a co-signer can bind to the trusted record.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterChannelDebitPayload {
    pub sender_index: u8,
    pub proposed_next_state: ChannelState,
    pub inter_channel_tx: InterChannelTx,
    pub amount: u64,
    pub members: Vec<MemberInfo>,
    pub record: ChannelRecord,
    /// The destination channel recipient's Regev public key (the key `receiver_deltas[0].amount`
    /// is encrypted to). The E-2 statement is verified against this key; its authenticity (that it
    /// is channel B's recipient slot key) is channel B's concern, enforced in
    /// `verify_inter_channel_credit_transition`.
    pub destination_recipient_pk: RegevPk,
}

/// Everything channel B needs to re-verify the inbound transfer and credit its recipient slot
/// (crosses browser↔relay↔CLI). Carries the source/destination ids, the recipient slot, the public
/// amount, the tx leaf identifiers, the computed `tx_tree_root` (= H2) + the TxV2 inclusion proof,
/// the sender's before/after ciphertexts (off-chain witness share for the E-2 re-verification),
/// both deltas, the `InterChannelTx` (carries the E-2 proof + signed small block), and the TxV2
/// itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterChannelTransferDescriptor {
    pub source_channel_id: ChannelId,
    pub destination_channel_id: ChannelId,
    pub recipient_slot: u8,
    pub amount: u64,
    pub tx_hash: Bytes32,
    /// `H2` = the 1-tx `TxV2Tree` root, computed inside `build_inter_channel_send`.
    pub tx_tree_root: Bytes32,
    pub source_pk_g: Bytes32,
    pub receiver_pk_g: Bytes32,
    /// The SOURCE channel sender's Regev public key (the key the E-2 was proven under for the
    /// sender side). Channel B cannot read A's Regev key array, so it is shipped explicitly; the
    /// E-2 transcript binds the real key + all four ciphertexts, so a forged `source_pk` cannot
    /// re-verify.
    pub source_pk: RegevPk,
    /// The DESTINATION channel recipient's Regev public key. Bound to B's recipient slot key
    /// inside `verify_inter_channel_credit_transition` (channel B re-derives the recipient pk_g
    /// from its OWN authenticated member set and rejects any mismatch).
    pub receiver_pk: RegevPk,
    pub sender_before_ct: RegevCiphertext,
    pub sender_after_ct: RegevCiphertext,
    pub sender_delta_ct: RegevCiphertext,
    pub receiver_delta: RegevCiphertext,
    pub inter_channel_tx: InterChannelTx,
    pub tx_v2: TxV2,
    pub tx_v2_merkle_proof: TxV2MerkleProof,
}

/// A built inter-channel credit (LEG B): the import state (`ChannelFund` += amount; unallocated
/// += amount) followed by the bundle-apply state (recipient slot += delta; unallocated -= amount).
/// Both states carry the building member's signature; co-signers add theirs after re-verifying.
pub struct BuiltInterChannelCredit {
    pub fund_import_state: ChannelState,
    pub bundle_apply_state: ChannelState,
    /// Stage 3: the per-channel settled-tx accumulator AFTER both settle advancements (the import
    /// `tx_hash` push and the bundle-apply `tx_hash` push). Persist it as the channel's new
    /// `ChannelSnapshot::settled_tx_accumulator` — its root equals
    /// `bundle_apply_state.balance_state.settled_tx_accumulator_root`, and it is what lets the
    /// wallet later generate the post-close Merkle inclusion proof for an incoming `tx_hash`.
    pub settled_tx_accumulator:
        crate::utils::trees::incremental_merkle_tree::IncrementalMerkleTree<Bytes32>,
}

/// Structural transport verifier: the inter-channel send/import witnesses require a
/// `ChannelProofVerifier` for the (DEPRECATED, abstract2 §3.4) transport proof envelope. The wallet
/// supplies the same non-empty bytes on both sides, so this only asserts non-emptiness — the real
/// security comes from the E-2 STARK (`RealRegevProofVerifier`) and the channel-A member
/// signatures.
struct WalletStructuralTransport;
impl ChannelProofVerifier for WalletStructuralTransport {
    fn verify(
        &self,
        p: &ChannelProofEnvelope,
        _: &ChannelStateUpdatePublicInputs,
    ) -> Result<(), ChannelStateUpdateError> {
        if p.proof.is_empty() {
            return Err(ChannelStateUpdateError::ProofVerification(
                "empty transport proof".into(),
            ));
        }
        Ok(())
    }
}

/// Structural per-member small-block signatures (base-layer artifact). The REAL small-block
/// signature verification is the B-2 validity-proof path (out of scope for the wallet wiring
/// layer); here we only need `validate_all_member_signatures` (structural) to pass inside the
/// witness.
fn structural_small_block_sigs(record: &ChannelRecord) -> Vec<MemberSignature> {
    (0..record.member_count)
        .map(|i| MemberSignature {
            member_slot: i,
            pk_g: record.member_pk_gs[i as usize],
            signature: vec![1 + i],
        })
        .collect()
}

/// LEG A — build the inter-channel debit on the SOURCE channel.
///
/// `snapshot` is channel A; `sender_slot` is a channel-A ACTIVE participant (member OR delegate,
/// located by its `pk_g`). `before_*` are the sender's CURRENT plaintext balance + `AmountWitness`
/// (held locally). `new_nullifier_root` advances the shared native nullifier (detail2 §C-3: a send
/// MUST change it). Produces the post-debit `a_send` (state_version+1, channel_fund -= amount,
/// settled_tx_chain pushes the tx leaf, `h2_tag = tx_tree_root`; delegate_count + the untouched
/// slots' pending_adds preserved via the `..prev.balance_state.clone()` spread), the REAL E-2, the
/// 1-tx `TxV2Tree` (root + inclusion proof computed INTERNALLY), self-signs the building member's
/// slot if it is a co-signing member, and CALLS `InterChannelSendUpdateWitness::verify` to
/// self-check before returning.
#[allow(clippy::too_many_arguments)]
pub fn build_inter_channel_send(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    sender_slot: u8,
    destination_channel_id: ChannelId,
    destination_recipient_slot: u8,
    destination_recipient_pk: RegevPk,
    destination_recipient_pk_g: Bytes32,
    amount: u64,
    before_amount: u64,
    before_witness: &AmountWitness,
    new_nullifier_root: Bytes32,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<BuiltInterChannelSend> {
    let record = &snapshot.record;
    let members = &snapshot.members;
    let prev = &snapshot.state;
    // The sender may be a member OR a delegate: both own a balance slot and may send. Admit the
    // full active region (`member_count + delegate_count`).
    let active = record.member_count as usize + record.delegate_count as usize;
    check_slot(sender_slot as usize, active)?;
    if record.member_pk_gs[sender_slot as usize] != keys.pk_g() {
        return bail("sender_slot pk_g does not match the building member's key");
    }
    if prev.balance_state.pending_adds[sender_slot as usize] != 0 {
        return bail("sender slot has pending homomorphic adds; refresh required before sending");
    }
    if before_amount < amount {
        return bail("insufficient balance");
    }
    if destination_channel_id == record.channel_id {
        return bail("inter-channel send destination must be a DIFFERENT channel");
    }
    if new_nullifier_root == prev.shared_native_nullifier_root {
        return bail("shared_native_nullifier_root must advance on a send (detail2 §C-3)");
    }
    let regev_pks = regev_pks_array(members);
    let sender_pk = regev_pks[sender_slot as usize].clone();
    let sender_pk_g = record.member_pk_gs[sender_slot as usize];

    // E-2 statement ciphertexts. `before` MUST be the exact ciphertext the verifier reads from
    // `prev_state.enc_balances[sender_slot]` (so `before_witness` is the witness for THAT
    // ciphertext).
    let before_ct = prev.balance_state.enc_balances[sender_slot as usize].clone();
    let (after_ct, after_w) =
        encrypt_amount(rng, &sender_pk, before_amount - amount).map_err(we)?;
    let (sender_delta_ct, sender_delta_w) = encrypt_amount(rng, &sender_pk, amount).map_err(we)?;
    let (receiver_delta_ct, receiver_delta_w) =
        encrypt_amount(rng, &destination_recipient_pk, amount).map_err(we)?;

    // REAL E-2 channelUpdateZKP (detail2 §E-2): binds before/after/sender_delta under the sender
    // key, receiver_delta under the destination key, conservation `before = after + amount`, and
    // both deltas == the public amount.
    let e2 = prove_channel_update(
        level,
        &sender_pk,
        &destination_recipient_pk,
        (&before_ct, before_witness),
        (&after_ct, &after_w),
        (&sender_delta_ct, &sender_delta_w),
        (&receiver_delta_ct, &receiver_delta_w),
        amount,
    )
    .map_err(we)?;

    // The tx leaf chained into settled_tx_chain (detail2 §C-6): binds both participants + both
    // delta ciphertext digests.
    let tx_leaf = tx_leaf_hash(
        sender_pk_g,
        sender_delta_ct.digest(),
        destination_recipient_pk_g,
        receiver_delta_ct.digest(),
    );

    // The inter-channel tx's small block carries the channel's own 1-tx TxV2 tree (detail2 §A-2).
    // Computed INTERNALLY (root = H2; inclusion proof) so the browser need not.
    let mut transfer_tree = TransferTree::init();
    transfer_tree.push(Transfer {
        recipient: destination_recipient_pk_g,
        token_index: 0,
        // Full u64 precision (no u32 truncation): the transfer leaf binds the EXACT amount into the
        // TxV2 tree root the descriptor ships + B re-verifies.
        amount: u64_to_u256(amount),
        aux_data: Bytes32::default(),
    });
    let tx_v2 = TxV2 {
        tx_class: TxClass::UserTransfer,
        transfer_tree_root: transfer_tree.get_root(),
        nonce: (prev.small_block_number + 1) as u32,
        channel_action_root: PoseidonHashOut::default(),
    };
    let src_id = record.channel_id.as_u64();
    let mut tx_v2_tree = TxV2Tree::init();
    tx_v2_tree.update(src_id, tx_v2);
    let tx_v2_root_h = tx_v2_tree.get_root();
    let tx_tree_root: Bytes32 = tx_v2_root_h.into(); // = H2
    let tx_v2_merkle_proof = tx_v2_tree.prove(src_id);

    // Stage 3: the inter-channel `tx_hash` — the accumulator leaf (uniformly) AND the L1-settled
    // identifier. Computed BEFORE the post-debit state so its accumulator root already reflects the
    // insertion (and so h1() below folds the advanced root).
    let tx_hash = inter_channel_tx_hash(
        record.channel_id,
        destination_channel_id,
        tx_tree_root,
        tx_leaf,
    );
    // Push `tx_hash` into channel A's settled-tx accumulator and read off the new root.
    let mut next_accumulator = snapshot.settled_tx_accumulator.clone();
    next_accumulator.push(tx_hash);
    let next_accumulator_root = Bytes32::from(next_accumulator.get_root());
    // Stage 3 native co-signer check: the new root is EXACTLY push(prev_accumulator, tx_hash).
    require_accumulator_push(
        &snapshot.settled_tx_accumulator,
        tx_hash,
        next_accumulator_root,
    )
    .map_err(|e| WalletError(format!("inter-channel send accumulator push: {e:?}")))?;

    // a_send = post-debit channel-A state. Its h1() = H1' bound into the small block's
    // state_commitment_root (detail2 §C-7) AND h2_tag = tx_tree_root. The `..prev.*.clone()`
    // spreads preserve member_count, delegate_count, channel_id, and all untouched slots'
    // enc_balances + pending_adds — only the sender slot's ciphertext changes.
    let mut enc_balances = prev.balance_state.enc_balances.clone();
    enc_balances[sender_slot as usize] = after_ct.clone();
    let mut a_send = ChannelState {
        epoch: prev.epoch + 1,
        small_block_number: prev.small_block_number + 1,
        channel_fund: ChannelFund {
            amount: prev.channel_fund.amount - u64_to_u256(amount),
            ..prev.channel_fund.clone()
        },
        balance_state: BalanceState {
            enc_balances,
            settled_tx_chain: settled_tx_chain_push(prev.balance_state.settled_tx_chain, tx_leaf),
            // Stage 3: the accumulator advances by inserting `tx_hash` at the prev tree length.
            settled_tx_accumulator_root: next_accumulator_root,
            state_version: prev.balance_state.state_version + 1,
            ..prev.balance_state.clone()
        },
        h2_tag: tx_tree_root,
        shared_native_nullifier_root: new_nullifier_root,
        prev_digest: prev.digest,
        member_signatures: Vec::new(),
        ..prev.clone()
    }
    .with_computed_digest();
    let h1_prime = a_send.balance_state.h1();
    let inter_channel_tx = InterChannelTx {
        tx_inclusion_proof: MerkleInclusionProof::default(),
        signed_small_block: SignedSmallBlock {
            message: SmallBlockRootMessage {
                channel_id: record.channel_id,
                bp_member_slot: record.bp_member_slot,
                bp_pk_g: record.member_pk_gs[record.bp_member_slot as usize],
                small_block_number: a_send.small_block_number,
                prev_small_block_root: Bytes32::default(),
                tx_tree_root,
                state_commitment_root: h1_prime,
                medium_epoch_hint: 3,
                close_freeze_nonce: prev.close_freeze_nonce,
            },
            signatures: structural_small_block_sigs(record),
            aggregated_signature_proof: vec![9, 9],
            medium_block_number: 4,
            confirmation_proof: vec![8, 8],
        },
        sender_delta_ct: sender_delta_ct.clone(),
        source_channel_id: record.channel_id,
        destination_channel_id,
        source_pk_g: sender_pk_g,
        seal: Bytes32::default(),
        tx_hash,
        intmax_transfer_commitment: Bytes32::default(),
        recipient_memo: vec![1],
        receiver_deltas: vec![ReceiverBalanceDelta {
            receiver_pk_g: destination_recipient_pk_g,
            amount: receiver_delta_ct.clone(),
        }],
        channel_update_zkp: ChannelProofEnvelope {
            role: TransitionProofRole::ChannelStateUpdate,
            backend: ProofBackend::Plonky3,
            proof: e2,
        },
        transport_proof: vec![7, 7, 7],
    };

    // If the building participant is a co-signing MEMBER (slot < member_count) it self-signs the
    // post-debit state (one of the N-of-N). A DELEGATE sender does NOT co-sign state.
    if (sender_slot as usize) < record.member_count as usize {
        let sender_sig = sign_state(keys, sender_slot, &a_send)?;
        add_signature(&mut a_send, sender_sig);
    }

    // SELF-CHECK: the post-debit state must pass the REAL inter-channel send witness BEFORE we hand
    // it to co-signers. The witness's `verify_next_state_signatures` is STRUCTURAL (one non-empty
    // sig per member slot) — it does NOT run the real SingleSig proofs (that is
    // `verify_all_signatures`, run once the full set is collected). At build time only the building
    // member (if any) has signed, so fill placeholder structural sigs on a CLONE for the
    // self-check; the RETURNED `a_send` carries only the building member's REAL signature
    // (co-signers add the rest). Placeholder sigs do not affect `signing_digest()` (member
    // signatures are excluded from it), so the digest binding is unchanged.
    let mut next_for_check = a_send.clone();
    fill_placeholder_sigs(record, &mut next_for_check);
    let transport = ChannelProofEnvelope {
        role: TransitionProofRole::IntmaxTransport,
        backend: ProofBackend::Plonky2,
        proof: inter_channel_tx.transport_proof.clone(),
    };
    let witness = InterChannelSendUpdateWitness {
        channel_record: record.clone(),
        regev_pks,
        destination_recipient_pk: destination_recipient_pk.clone(),
        prev_state: prev.clone(),
        next_state: next_for_check,
        inter_channel_tx: inter_channel_tx.clone(),
        amount,
        transport_proof: transport,
    };
    let regev_verifier = RealRegevProofVerifier { level };
    witness
        .verify(&WalletStructuralTransport, &regev_verifier)
        .map_err(|e| WalletError(format!("inter-channel send self-check failed: {e:?}")))?;

    Ok(BuiltInterChannelSend {
        debit_payload: InterChannelDebitPayload {
            sender_index: sender_slot,
            proposed_next_state: a_send,
            inter_channel_tx: inter_channel_tx.clone(),
            amount,
            members: members.clone(),
            record: record.clone(),
            destination_recipient_pk: destination_recipient_pk.clone(),
        },
        transfer_descriptor: InterChannelTransferDescriptor {
            source_channel_id: record.channel_id,
            destination_channel_id,
            recipient_slot: destination_recipient_slot,
            amount,
            tx_hash,
            tx_tree_root,
            source_pk_g: sender_pk_g,
            receiver_pk_g: destination_recipient_pk_g,
            source_pk: sender_pk.clone(),
            receiver_pk: destination_recipient_pk.clone(),
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
        settled_tx_accumulator: next_accumulator,
    })
}

/// LEG A co-signer's pre-sign check: bind `debit_payload.record` to the TRUSTED channel-A record
/// (like `verify_send_transition`), then re-run `InterChannelSendUpdateWitness::verify` over the
/// authenticated state. On success the co-signer may `sign_state(a_send)`. NOTE: the witness checks
/// STRUCTURAL member signatures only; the authoritative N-of-N check is `verify_all_signatures`
/// once the full signature set is collected.
pub fn verify_inter_channel_send_transition(
    prev: &ChannelState,
    trusted_record: &ChannelRecord,
    debit_payload: &InterChannelDebitPayload,
    level: RegevSecurityLevel,
) -> WResult<()> {
    // SECURITY: never trust the record carried in the payload; bind it to the session's trusted,
    // already-verified channel-A record (immutable member set). The IMCR signing_digest commits the
    // whole record; the member_pubkeys_root recompute then transitively binds `payload.members`.
    if debit_payload.record.signing_digest() != trusted_record.signing_digest() {
        return bail("payload record is not the channel's registered (trusted) record");
    }
    // Authenticate the payload member set against the trusted record before trusting its Regev
    // keys. The member list covers the ACTIVE region (members + delegates) bijectively.
    let active = trusted_record.member_count as usize + trusted_record.delegate_count as usize;
    if debit_payload.members.len() != active {
        return bail(format!(
            "members list has {} entries but active participants is {active}",
            debit_payload.members.len()
        ));
    }
    let mut seen = [false; MAX_CHANNEL_MEMBERS];
    for m in &debit_payload.members {
        check_slot(m.slot as usize, active)?;
        if seen[m.slot as usize] {
            return bail(format!("duplicate member slot {}", m.slot));
        }
        seen[m.slot as usize] = true;
    }
    let regev_pks = regev_pks_array(&debit_payload.members);
    if regev_pk_root(&regev_pks) != trusted_record.regev_pk_root {
        return bail("regev_pk_root mismatch: member Regev keys not anchored to the record");
    }
    if member_pubkeys_root(trusted_record, &debit_payload.members)?
        != trusted_record.member_pubkeys_root
    {
        return bail("member_pubkeys_root mismatch: member set not anchored to the trusted record");
    }
    // STRUCTURAL signature completeness (see build_inter_channel_send): a co-signer validates the
    // transition BEFORE the full real signature set is collected, so fill placeholder structural
    // sigs. The authoritative N-of-N check is `verify_all_signatures`, run once the set is
    // complete.
    let mut next_for_check = debit_payload.proposed_next_state.clone();
    fill_placeholder_sigs(trusted_record, &mut next_for_check);
    let transport = ChannelProofEnvelope {
        role: TransitionProofRole::IntmaxTransport,
        backend: ProofBackend::Plonky2,
        proof: debit_payload.inter_channel_tx.transport_proof.clone(),
    };
    let witness = InterChannelSendUpdateWitness {
        channel_record: trusted_record.clone(),
        regev_pks,
        destination_recipient_pk: debit_payload.destination_recipient_pk.clone(),
        prev_state: prev.clone(),
        next_state: next_for_check,
        inter_channel_tx: debit_payload.inter_channel_tx.clone(),
        amount: debit_payload.amount,
        transport_proof: transport,
    };
    let regev_verifier = RealRegevProofVerifier { level };
    witness
        .verify(&WalletStructuralTransport, &regev_verifier)
        .map_err(|e| WalletError(format!("inter-channel send transition invalid: {e:?}")))?;
    Ok(())
}

/// LEG B — build the inter-channel credit on the DESTINATION channel.
///
/// Applies `InterChannelFundImportUpdateWitness` (ChannelFund += amount; unallocated += amount;
/// settled_tx_chain pushes `tx_hash`) then `ReceiverBundleApplyUpdateWitness` (recipient slot +=
/// delta; unallocated -= amount; settled_tx_chain pushes the same tx leaf as A). The building
/// member self-signs both states (if it is a co-signing member); both witnesses are CALLED as
/// self-checks. `b_snapshot` is channel B; `keys` belong to a channel-B member (used for the
/// recipient decryption check when it owns the slot).
///
/// SECURITY: this builder's per-channel witness self-checks verify B-LOCAL invariants (fund/unalloc
/// accounting, the homomorphic credit, the E-2 re-verification against B's recipient key + the
/// off-chain sender ciphertexts). They CANNOT see the CROSS-channel facts — that A's debit is
/// N-of-N co-signed under the TRUSTED A record, the channel-id/H1'/tx_tree_root binding, the TxV2
/// inclusion. A channel-B co-signer MUST call [`verify_inter_channel_credit_transition`] (the
/// fail-closed gate, which takes the TRUSTED A + B records) BEFORE accepting/signing the states
/// this builder returns. The `source_record_placeholder` used for the import witness here is
/// reconstructed from the descriptor's own small block and is NOT a trust anchor; it can never
/// accept a transfer the gate rejects, because the gate is the authoritative A-record binding
/// (invariant 1).
pub fn build_inter_channel_credit(
    keys: &MemberKeys,
    b_snapshot: &ChannelSnapshot,
    descriptor: &InterChannelTransferDescriptor,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<BuiltInterChannelCredit> {
    let _ = rng; // No fresh randomness needed: the credit is a deterministic homomorphic add.
    let b_record = &b_snapshot.record;
    let b_prev = &b_snapshot.state;
    // SECURITY (delegate active region): a delegate is a valid recipient, so admit the full active
    // region. This ALSO rejects a `recipient_slot` that points at a PADDING slot before it indexes
    // `member_pk_gs[recipient_slot]` (which would otherwise read `Bytes32::default()`).
    let active = b_record.member_count as usize + b_record.delegate_count as usize;
    let recipient_slot = descriptor.recipient_slot as usize;
    check_slot(recipient_slot, active)?;
    if b_record.channel_id != descriptor.destination_channel_id {
        return bail("destination channel id mismatch with channel B record");
    }
    let amount = descriptor.amount;
    let inter_channel_tx = &descriptor.inter_channel_tx;
    let transport = ChannelProofEnvelope {
        role: TransitionProofRole::IntmaxTransport,
        backend: ProofBackend::Plonky2,
        proof: inter_channel_tx.transport_proof.clone(),
    };

    // ---- Fund import: ChannelFund += amount; unallocated += amount; chain pushes tx_hash. ----
    let import_nullifier =
        advance_nullifier(b_prev.shared_native_nullifier_root, descriptor.tx_hash);
    // Stage 3: the fund import is a settle advancement on the RECEIVING channel — the accumulator
    // MUST absorb the incoming `tx_hash` (uniform leaf). This is the insertion a post-close claim
    // against THIS channel later proves inclusion against, so the receiver side advancing is
    // load-bearing for Stage 3. Insert and read off the new root BEFORE building the state so h1()
    // below folds the advanced root.
    let mut import_accumulator = b_snapshot.settled_tx_accumulator.clone();
    import_accumulator.push(inter_channel_tx.tx_hash);
    let import_accumulator_root = Bytes32::from(import_accumulator.get_root());
    require_accumulator_push(
        &b_snapshot.settled_tx_accumulator,
        inter_channel_tx.tx_hash,
        import_accumulator_root,
    )
    .map_err(|e| WalletError(format!("fund import accumulator push: {e:?}")))?;
    let mut fund_import_state = ChannelState {
        epoch: b_prev.epoch + 1,
        small_block_number: b_prev.small_block_number + 1,
        channel_fund: ChannelFund {
            amount: b_prev.channel_fund.amount + u64_to_u256(amount),
            ..b_prev.channel_fund.clone()
        },
        balance_state: BalanceState {
            settled_tx_chain: settled_tx_chain_push(
                b_prev.balance_state.settled_tx_chain,
                inter_channel_tx.tx_hash,
            ),
            // Stage 3: the accumulator advances by inserting `tx_hash` at the prev tree length.
            settled_tx_accumulator_root: import_accumulator_root,
            state_version: b_prev.balance_state.state_version + 1,
            ..b_prev.balance_state.clone()
        },
        unallocated_confirmed_incoming: b_prev.unallocated_confirmed_incoming + u64_to_u256(amount),
        shared_native_nullifier_root: import_nullifier,
        prev_digest: b_prev.digest,
        member_signatures: Vec::new(),
        ..b_prev.clone()
    }
    .with_computed_digest();
    sign_member_if_present(keys, b_record, &mut fund_import_state)?;
    // Structural-signature completeness for the witness self-check (see build_inter_channel_send):
    // the building member has signed; fill placeholders for the rest. The returned state keeps only
    // the real building-member signature; co-signers add the rest after re-verifying.
    let mut import_for_check = fund_import_state.clone();
    fill_placeholder_sigs(b_record, &mut import_for_check);
    let import_witness = InterChannelFundImportUpdateWitness {
        source_channel_record: source_record_placeholder(inter_channel_tx, b_record)?,
        receiver_channel_record: b_record.clone(),
        prev_state: b_prev.clone(),
        next_state: import_for_check,
        inter_channel_tx: inter_channel_tx.clone(),
        amount,
        transport_proof: transport.clone(),
    };
    import_witness
        .verify(&WalletStructuralTransport)
        .map_err(|e| WalletError(format!("fund import self-check failed: {e:?}")))?;

    // ---- Bundle apply: recipient slot += delta; unallocated -= amount; chain pushes tx leaf. ----
    let receiver_delta = &inter_channel_tx.receiver_deltas[0];
    let recipient_after = add_ciphertexts(
        &fund_import_state.balance_state.enc_balances[recipient_slot],
        &receiver_delta.amount,
    )
    .map_err(we)?;
    let mut bundle_enc = fund_import_state.balance_state.enc_balances.clone();
    bundle_enc[recipient_slot] = recipient_after;
    let mut bundle_pending = fund_import_state.balance_state.pending_adds;
    bundle_pending[recipient_slot] += 1;
    // The bundle apply chains the SAME tx leaf the sender chained into A (detail2 §C-6; the witness
    // independently recomputes it via `inter_channel_tx.tx_leaf_hash()` — multi-layer F3-A
    // defense).
    let bundle_leaf = inter_channel_tx
        .tx_leaf_hash()
        .map_err(|e| WalletError(format!("bundle tx_leaf_hash: {e}")))?;
    // Stage 3 (uniform-leaf decision): the bundle apply is a second settle advancement; the
    // accumulator absorbs `tx_hash` again here (the CHAIN pushes `bundle_leaf` = tx_leaf, but the
    // accumulator stores `tx_hash` UNIFORMLY at every advancement). Advance the import-time tree.
    let mut bundle_accumulator = import_accumulator.clone();
    bundle_accumulator.push(inter_channel_tx.tx_hash);
    let bundle_accumulator_root = Bytes32::from(bundle_accumulator.get_root());
    require_accumulator_push(
        &import_accumulator,
        inter_channel_tx.tx_hash,
        bundle_accumulator_root,
    )
    .map_err(|e| WalletError(format!("bundle apply accumulator push: {e:?}")))?;
    let mut bundle_apply_state = ChannelState {
        epoch: fund_import_state.epoch + 1,
        balance_state: BalanceState {
            enc_balances: bundle_enc,
            settled_tx_chain: settled_tx_chain_push(
                fund_import_state.balance_state.settled_tx_chain,
                bundle_leaf,
            ),
            // Stage 3: advance the accumulator by inserting `tx_hash` again (uniform leaf).
            settled_tx_accumulator_root: bundle_accumulator_root,
            state_version: fund_import_state.balance_state.state_version + 1,
            pending_adds: bundle_pending,
            ..fund_import_state.balance_state.clone()
        },
        unallocated_confirmed_incoming: fund_import_state.unallocated_confirmed_incoming
            - u64_to_u256(amount),
        prev_digest: fund_import_state.digest,
        member_signatures: Vec::new(),
        ..fund_import_state.clone()
    }
    .with_computed_digest();
    sign_member_if_present(keys, b_record, &mut bundle_apply_state)?;

    // The recipient decryption check only applies when THIS member owns the recipient slot.
    let owns_recipient = b_record.member_pk_gs[recipient_slot] == keys.pk_g();
    let regev_pks = regev_pks_array(&b_snapshot.members);
    let mut bundle_for_check = bundle_apply_state.clone();
    fill_placeholder_sigs(b_record, &mut bundle_for_check);
    let bundle_witness = ReceiverBundleApplyUpdateWitness {
        receiver_channel_record: b_record.clone(),
        regev_pks,
        source_sender_pk: descriptor.source_pk.clone(),
        sender_before_ct: descriptor.sender_before_ct.clone(),
        sender_after_ct: descriptor.sender_after_ct.clone(),
        prev_state: fund_import_state.clone(),
        next_state: bundle_for_check,
        inter_channel_tx: inter_channel_tx.clone(),
        amount,
        recipient_index: recipient_slot,
        recipient_sk: owns_recipient.then(|| keys.regev_sk.clone()),
        expected_amount: owns_recipient.then_some(amount),
    };
    let regev_verifier = RealRegevProofVerifier { level };
    bundle_witness
        .verify(&regev_verifier)
        .map_err(|e| WalletError(format!("receiver bundle self-check failed: {e:?}")))?;

    Ok(BuiltInterChannelCredit {
        fund_import_state,
        bundle_apply_state,
        settled_tx_accumulator: bundle_accumulator,
    })
}

/// LEG B FAIL-CLOSED gate: a channel-B co-signer's pre-sign check enforcing the cross-channel
/// invariants that the per-channel witnesses cannot see. REFUSES on any failure. Both trusted
/// records (A and B) are PARAMETERS — never read from the descriptor/payload.
///
/// Enforces:
///   (1) A's `a_signed_state` is N-of-N co-signed under `a_trusted_record`
/// (`verify_all_signatures`);   (2) the amount is consistent across descriptor / the re-verified
/// E-2 / the witness inputs;   (3) `receiver_delta.pk_g == B member at recipient_slot` AND decrypts
/// to `amount` (the gate       always checks the pk_g binding; the decryption is checked when this
/// member owns the slot,       via the bundle witness in `build_inter_channel_credit`);
///   (4) `inter_channel_tx.{source,destination}_channel_id == A/B ids`;
///   (5) A's small-block `state_commitment_root == a_signed_state.balance_state.h1()` AND
///       `tx_tree_root == descriptor.tx_tree_root` (!= 0); B recomputes the same tx leaf;
///   (7) TxV2 inclusion: `descriptor.tx_v2_merkle_proof.verify(tx_v2, A_id, tx_tree_root)`.
#[allow(clippy::too_many_arguments)]
pub fn verify_inter_channel_credit_transition(
    b_prev: &ChannelState,
    b_trusted_record: &ChannelRecord,
    descriptor: &InterChannelTransferDescriptor,
    a_signed_state: &ChannelState,
    a_trusted_record: &ChannelRecord,
    level: RegevSecurityLevel,
) -> WResult<()> {
    let inter_channel_tx = &descriptor.inter_channel_tx;
    let small_block = &inter_channel_tx.signed_small_block.message;

    // (3-pre) SECURITY (delegate active region): bound `recipient_slot` to B's ACTIVE region BEFORE
    // it indexes `member_pk_gs[recipient_slot]`. Without this, a `recipient_slot` in the padding
    // region would read `Bytes32::default()`, and a descriptor with `receiver_pk_g == default`
    // would pass the pk_g binding below while crediting a NON-PARTICIPANT slot (value stranded). An
    // out-of-MAX slot would panic. This is the one defect the delegate adaptation introduced over
    // the pre-delegate reference; closing it here keeps the gate fail-closed.
    let b_active =
        b_trusted_record.member_count as usize + b_trusted_record.delegate_count as usize;
    check_slot(descriptor.recipient_slot as usize, b_active)?;

    // (4) Channel-id binding: the tx must be FROM A and TO B (both trusted records), and the
    // descriptor's ids must agree.
    if inter_channel_tx.source_channel_id != a_trusted_record.channel_id
        || small_block.channel_id != a_trusted_record.channel_id
        || descriptor.source_channel_id != a_trusted_record.channel_id
    {
        return bail("invariant 4: inter_channel_tx source channel id != trusted A id");
    }
    if inter_channel_tx.destination_channel_id != b_trusted_record.channel_id
        || descriptor.destination_channel_id != b_trusted_record.channel_id
    {
        return bail("invariant 4: inter_channel_tx destination channel id != trusted B id");
    }

    // (1) A's signed state is N-of-N co-signed under the TRUSTED A record. This is the
    // cross-channel root of trust: B credits only because A's members all attested the debit
    // (and thus the E-2 + the post-debit H1' bound into the small block). This is ALSO what
    // makes the sender-key binding sound: A's send witness proved the E-2 under A's
    // AUTHENTICATED `regev_pks[sender_index]`, and here we confirm A's members co-signed
    // exactly that state — so the only E-2 B ever credits is the one over A's real sender key.
    verify_all_signatures(a_trusted_record, &[], a_signed_state)
        .map_err(|e| WalletError(format!("invariant 1: A state not N-of-N co-signed: {e}")))?;

    // (5) A's small block binds H1' = a_signed_state.h1() and tx_tree_root; both must match what
    // the descriptor (and thus the credit) is built from. tx_tree_root != 0 (H2=0 is reserved
    // for in-channel updates — already enforced by the send witness, re-checked here
    // defensively).
    if small_block.state_commitment_root != a_signed_state.balance_state.h1() {
        return bail("invariant 5: small block state_commitment_root != A signed state h1()");
    }
    if descriptor.tx_tree_root == Bytes32::default() {
        return bail("invariant 5: tx_tree_root must not be zero (H2=0 reserved for in-channel)");
    }
    if small_block.tx_tree_root != descriptor.tx_tree_root
        || a_signed_state.h2_tag != descriptor.tx_tree_root
    {
        return bail("invariant 5: tx_tree_root mismatch (small block / A h2_tag / descriptor)");
    }

    // (2) Amount consistency: the descriptor amount must match the small-block-bound E-2 statement.
    // Re-verify the REAL E-2 against the descriptor's ciphertexts + the descriptor amount, so a
    // tampered `descriptor.amount` (with the real proof) is rejected by the STARK transcript.
    let amount = descriptor.amount;
    let receiver_delta = inter_channel_tx
        .receiver_deltas
        .first()
        .ok_or_else(|| WalletError("invariant 2: inter_channel_tx has no receiver delta".into()))?;
    if receiver_delta.amount != descriptor.receiver_delta
        || inter_channel_tx.sender_delta_ct != descriptor.sender_delta_ct
    {
        return bail("invariant 2: descriptor deltas disagree with the inter_channel_tx");
    }

    // (3) Receiver binding: the delta's pk_g MUST be channel B's member at `recipient_slot` (bound
    // above to the active region).
    let b_recipient_pk_g = b_trusted_record.member_pk_gs[descriptor.recipient_slot as usize];
    if receiver_delta.receiver_pk_g != b_recipient_pk_g {
        return bail("invariant 3: receiver_delta pk_g != B member at recipient_slot");
    }
    if descriptor.receiver_pk_g != b_recipient_pk_g {
        return bail("invariant 3: descriptor receiver_pk_g != B member at recipient_slot");
    }

    // (5 cont.) B independently recomputes the SAME tx leaf the sender chained.
    let recomputed_leaf = tx_leaf_hash(
        descriptor.source_pk_g,
        descriptor.sender_delta_ct.digest(),
        descriptor.receiver_pk_g,
        descriptor.receiver_delta.digest(),
    );
    let tx_leaf_from_tx = inter_channel_tx
        .tx_leaf_hash()
        .map_err(|e| WalletError(format!("invariant 5: tx_leaf_hash: {e}")))?;
    if recomputed_leaf != tx_leaf_from_tx {
        return bail("invariant 5: B-recomputed tx leaf != inter_channel_tx leaf");
    }

    // (2 cont.) Re-verify the REAL E-2 over the descriptor's ciphertexts + amount. SECURITY: the
    // sender key MUST be a channel-A member's key — confirm `source_pk_g` is in the trusted A
    // member set (binds the leaf used in (5) to a real member). The E-2 transcript binds all
    // four ciphertexts + both keys; combined with invariant 1 (A co-signed the E-2 over its OWN
    // authenticated sender key), a forged `source_pk`/amount cannot verify against a state A
    // signed.
    let _a_sender_slot = a_trusted_record
        .member_pk_gs
        .iter()
        .position(|m| *m == descriptor.source_pk_g)
        .ok_or_else(|| WalletError("invariant 2: source_pk_g is not a channel-A member".into()))?;
    let statement = crate::regev::RegevStatement::ChannelUpdate {
        sender_pk: descriptor.source_pk.clone(),
        recipient_pk: descriptor.receiver_pk.clone(),
        before: descriptor.sender_before_ct.clone(),
        after: descriptor.sender_after_ct.clone(),
        sender_delta: descriptor.sender_delta_ct.clone(),
        receiver_delta: descriptor.receiver_delta.clone(),
        amount,
    };
    let regev_verifier = RealRegevProofVerifier { level };
    use crate::circuits::channel::state_update_verifier::RegevProofVerifier as RegevProofVerifierTrait;
    // Call the TRAIT method (not the inherent one): it checks the envelope role/backend AND maps to
    // the `ChannelStateUpdateError` shape, exactly as the witnesses do.
    RegevProofVerifierTrait::verify(
        &regev_verifier,
        &inter_channel_tx.channel_update_zkp,
        crate::regev::RegevProofPurpose::ChannelUpdate,
        &statement,
    )
    .map_err(|e| WalletError(format!("invariant 2: E-2 re-verification failed: {e:?}")))?;

    // (7) TxV2 inclusion in the small block's tx tree: the receiver confirms the tx is in the
    // (validity-provable) small block (flowReceive3-1). The proof verifies the TxV2 leaf at index
    // A_id against the tx_tree_root committed in A's signed small block.
    let tx_tree_root_h = PoseidonHashOut::try_from(descriptor.tx_tree_root).map_err(|e| {
        WalletError(format!(
            "invariant 7: tx_tree_root is not a hash out: {e:?}"
        ))
    })?;
    descriptor
        .tx_v2_merkle_proof
        .verify(
            &descriptor.tx_v2,
            descriptor.source_channel_id.as_u64(),
            tx_tree_root_h,
        )
        .map_err(|e| WalletError(format!("invariant 7: TxV2 inclusion proof failed: {e:?}")))?;

    // Defensive: B prev must actually be channel B's state (the credit applies onto it).
    if b_prev.channel_id != b_trusted_record.channel_id {
        return bail("b_prev is not the trusted channel-B state");
    }
    Ok(())
}

// --- inter-channel helpers ---

/// Lossless `u64 → U256` (full 64-bit precision; the high u32 lands in limb 6, the low in limb 7).
/// SECURITY: use THIS, never `U256::from(v.min(u32::MAX) as u32)`, for any value-conservation
/// comparison — a u32 truncation would let a >2^32 transfer pass a fund-delta check it does not
/// actually satisfy.
pub fn u64_to_u256(v: u64) -> U256 {
    U256::from_u32_slice(&[0, 0, 0, 0, 0, 0, (v >> 32) as u32, v as u32]).unwrap()
}

/// A deterministic, prev-bound advance of the shared native nullifier root (detail2 §C-3: the
/// import and bundle steps each change the root). INTENTIONALLY SIMPLE: a keccak-style fold over
/// the prev root + a context tag; the only protocol requirement at the wiring layer is that
/// consecutive states differ (`ensure_different_root`).
fn advance_nullifier(prev: Bytes32, tag: Bytes32) -> Bytes32 {
    settled_tx_chain_push(prev, tag)
}

/// `tx_hash` identifier for the inter-channel tx (the L1-settled identifier referenced by the fund
/// import chain, and the ledger key for the replay/spent ledgers on BOTH channels). INTENTIONALLY
/// SIMPLE: a domain-free fold over (source_channel_id, destination_channel_id, tx_tree_root,
/// tx_leaf); it only needs to be a deterministic, collision-resistant identifier bound to this tx.
///
/// SECURITY (HIGH-1, dest binding): the destination channel id is folded in so the ledger key is
/// DEST-BOUND. Without it, the same (source, tx_tree_root, tx_leaf) tuple would hash identically
/// regardless of which channel B it is credited into, so a tx already credited into one destination
/// could not be distinguished from a (distinct) transfer aimed at another destination in a shared
/// ledger. Binding the dest id makes the ledger key unambiguous per (A→B) pair — defense in depth
/// on top of the per-channel applied/spent ledgers.
fn inter_channel_tx_hash(
    source_channel_id: ChannelId,
    destination_channel_id: ChannelId,
    tx_tree_root: Bytes32,
    tx_leaf: Bytes32,
) -> Bytes32 {
    let mixed = settled_tx_chain_push(tx_tree_root, tx_leaf);
    let ids = Bytes32::from_u32_slice(&{
        let mut w = [0u32; BYTES32_LEN];
        w[BYTES32_LEN - 1] = source_channel_id.as_u64() as u32;
        w[BYTES32_LEN - 2] = destination_channel_id.as_u64() as u32;
        w
    })
    .unwrap();
    settled_tx_chain_push(ids, mixed)
}

/// Sign `state` with `keys` IFF `keys` is a co-signing member of `record` (slot < member_count).
/// The building member is one of the N-of-N; co-signers add the rest after re-verifying. A delegate
/// builder does NOT co-sign state (it is send-only at the co-sign layer).
fn sign_member_if_present(
    keys: &MemberKeys,
    record: &ChannelRecord,
    state: &mut ChannelState,
) -> WResult<()> {
    if let Some(slot) = record
        .member_pk_gs
        .iter()
        .take(record.member_count as usize)
        .position(|m| *m == keys.pk_g())
    {
        let sig = sign_state(keys, slot as u8, state)?;
        add_signature(state, sig);
    }
    Ok(())
}

/// The source channel record stub used for the fund-import small-block validation. The import
/// witness's `validate_signed_small_block` checks the small block's BP slot/pk_g against THIS
/// record; the descriptor carries A's signed small block, so we must validate against A's
/// registered record. Since channel B may not hold A's full record in this wiring layer, we
/// reconstruct the minimal fields the validator reads (bp_member_slot, member_pk_gs[bp],
/// member_count) FROM the signed small block itself — but ONLY the structural BP-consistency is
/// checked here; the AUTHORITATIVE A-record binding (invariant 1) is enforced in
/// `verify_inter_channel_credit_transition` against the TRUSTED A record. This stub never gates
/// value: it cannot accept a tx that the trusted-A gate rejects.
fn source_record_placeholder(
    inter_channel_tx: &InterChannelTx,
    fallback: &ChannelRecord,
) -> WResult<ChannelRecord> {
    let msg = &inter_channel_tx.signed_small_block.message;
    let mut member_pk_gs: [Bytes32; MAX_CHANNEL_MEMBERS] =
        std::array::from_fn(|_| Bytes32::default());
    // The validator reads member_pk_gs[bp_member_slot]; structural member-sig validation also reads
    // member_pk_gs[slot] for each signature. Reconstruct from the small block's own signature set.
    let member_count = inter_channel_tx.signed_small_block.signatures.len().max(2) as u8;
    for sig in &inter_channel_tx.signed_small_block.signatures {
        if (sig.member_slot as usize) < MAX_CHANNEL_MEMBERS {
            member_pk_gs[sig.member_slot as usize] = sig.pk_g;
        }
    }
    Ok(ChannelRecord {
        channel_id: inter_channel_tx.source_channel_id,
        member_count,
        // This stub's small block carries only co-signing-member signatures (the bp + the N-of-N);
        // it never references A's delegate region, so delegate_count = 0 is the structurally
        // minimal and correct value for the fields the import validator reads. It is NOT a
        // trust anchor (invariant 1 against the TRUSTED A record is authoritative).
        delegate_count: 0,
        member_pk_gs,
        member_pubkeys_root: Bytes32::default(),
        bp_member_slot: msg.bp_member_slot,
        special_close_penalty: U256::from(0u32),
        close_freeze_nonce: msg.close_freeze_nonce,
        status: ChannelStatus::Active,
        regev_pk_root: fallback.regev_pk_root,
    })
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

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A-3 P2: real (non-test) channel-close proving. Wires the wallet's signed `ChannelState` + the N
// active members' Goldilocks signing keys + the channel's base-layer balance proof into a REAL
// `ChannelCloseCircuit` proof. SOUNDNESS IS ENFORCED IN-CIRCUIT (A-3 P2 threat model): H1/IMCH
// recompute + bind, balance-proof channel_id/settled_tx_chain binding, the recursive ListCircuit
// commitment C'==C over the members' REAL single-sigs, the member_set_commitment keccak, and the
// active-bit decomposition. `ChannelCloseCircuit::prove` recomputes and overrides
// `member_set_commitment`, so a tampered commitment is rejected. The Rust-side preconditions below
// fail CLOSED before any (expensive) proving so a malformed input never produces a proof.
// ─────────────────────────────────────────────────────────────────────────────────────────────

use crate::{
    circuits::channel::{
        close_circuit::{ChannelCloseCircuit, ChannelCloseFullWitness, MemberCloseAuth},
        close_pis::ChannelCloseWitness,
    },
    common::channel::{CloseIntent, CloseWithdrawal},
    poseidon_sig::list::{ListCircuit, list_commitment},
};

/// Process-built close-proving context: a `ListCircuit` (over the shared `SingleSigCircuit`) and the
/// `ChannelCloseCircuit` bound to the channel's balance verifier data. Each circuit is expensive to
/// build, so construct ONE `CloseProver` per process and reuse it.
pub struct CloseProver {
    list: ListCircuit,
    close_circuit: ChannelCloseCircuit<F, C, D>,
}

impl CloseProver {
    /// Build the close-proving circuits. `balance_vd` is the channel's base-layer balance verifier
    /// data (the same value cached in `balance_vd.bin` / produced by the `BalanceProcessor`).
    pub fn new(balance_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let list = ListCircuit::new(&single_sig_circuit().verifier_data());
        let close_circuit = ChannelCloseCircuit::<F, C, D>::new(balance_vd, &list.verifier_data());
        Self { list, close_circuit }
    }

    /// Build the full close witness from the wallet's signed final `ChannelState`, the N ACTIVE
    /// members' signing keys (slot order), and the channel's base-layer balance proof. The members
    /// each sign the IMCH digest (`state.digest`) with a real `SingleSigCircuit` proof, folded into
    /// the recursive `ListCircuit` proof the close circuit re-checks against its rebuilt commitment.
    ///
    /// SECURITY: fail-closed preconditions reject malformed inputs early; the in-circuit gates are
    /// the actual soundness boundary. `CloseIntent::new` additionally fail-closed-checks
    /// channel_id / digest / H1 / intmax_state_root / burn_amount / unallocated==0 bindings.
    pub fn build_full_witness(
        &self,
        state: &ChannelState,
        member_keys: &[MemberKeys],
        balance_proof: ProofWithPublicInputs<F, C, D>,
        close_nonce: u64,
        burn_tx_hash: Bytes32,
        snapshot_medium_block_number: u64,
    ) -> WResult<ChannelCloseFullWitness<F, C, D>> {
        let member_count = state.balance_state.member_count as usize;
        if !(2..=MAX_CHANNEL_MEMBERS).contains(&member_count) {
            return bail(format!(
                "close: member_count {member_count} out of [2, {MAX_CHANNEL_MEMBERS}]"
            ));
        }
        if member_keys.len() != member_count {
            return bail(format!(
                "close: need exactly member_count={member_count} active-member signing keys, got {}",
                member_keys.len()
            ));
        }
        // Distinct member pk_g over the active set (the circuit also enforces A5 distinctness; we
        // fail early for a clearer error and to avoid wasted proving).
        let pk_gs: Vec<Bytes32> = member_keys.iter().map(|k| k.signing_key.public_key()).collect();
        for i in 0..pk_gs.len() {
            for j in (i + 1)..pk_gs.len() {
                if pk_gs[i] == pk_gs[j] {
                    return bail(format!("close: duplicate member pk_g at active slots {i} and {j}"));
                }
            }
        }

        // Derive the close-tx and close-intent. `CloseIntent::new` performs the binding checks.
        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_balance_state_h1: state.balance_state.h1(),
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash,
            burn_amount: state.channel_fund.amount,
            zkp: Vec::new(),
        };
        let close_intent =
            CloseIntent::new(close_nonce, state, &close_tx, snapshot_medium_block_number)
                .map_err(|e| WalletError(format!("close intent binding failed: {e:?}")))?;
        let close = ChannelCloseWitness {
            final_channel_state: state.clone(),
            close_tx,
            close_intent,
        };

        // Fold the N member IMCH single-sigs into the recursive ListCircuit proof, in slot order —
        // exactly the order the close circuit rebuilds C' over (digest, pk_g_i) pairs.
        let digest = state.digest;
        let pairs: Vec<(Bytes32, Bytes32)> = pk_gs.iter().map(|pk| (digest, *pk)).collect();
        let mut member_auth: Vec<MemberCloseAuth> = Vec::with_capacity(member_count);
        let mut prev: Option<ProofWithPublicInputs<F, C, D>> = None;
        for (i, keys) in member_keys.iter().enumerate() {
            let sig = single_sig_circuit()
                .prove(&keys.signing_key, digest)
                .map_err(|e| WalletError(format!("member {i} single-sig proving failed: {e}")))?;
            let prefix = list_commitment(&pairs[0..i]);
            prev = Some(
                self.list
                    .prove_append(&sig, prefix, &prev)
                    .map_err(|e| WalletError(format!("list fold at member {i} failed: {e:?}")))?,
            );
            member_auth.push(MemberCloseAuth { pk_g: pk_gs[i] });
        }
        let list_proof =
            prev.ok_or_else(|| WalletError("close: empty active member set".into()))?;

        Ok(ChannelCloseFullWitness {
            close,
            final_balance_proof: balance_proof,
            member_auth,
            list_proof,
        })
    }

    /// Prove the close circuit. All soundness gates run in-circuit; `prove` overrides the
    /// member-set commitment with the correct keccak so a tampered commitment cannot pass.
    pub fn prove(
        &self,
        witness: &ChannelCloseFullWitness<F, C, D>,
    ) -> WResult<ProofWithPublicInputs<F, C, D>> {
        self.close_circuit
            .prove(witness)
            .map_err(|e| WalletError(format!("close proof failed: {e:?}")))
    }

    /// Wrap the close proof and produce its MLE/WHIR proof JSON for the on-chain
    /// `ChannelSettlementVerifier.verifyCloseIntent` (the SAME pipeline as
    /// `bin/generate_close_fixture.rs`). The returned JSON is exactly what Solidity's
    /// `FixtureLib.parseProof` consumes; the 95 raw close PI limbs are embedded as `publicInputs`,
    /// which the manager's strict limb-bind re-checks. Verifies the MLE proof locally before
    /// returning (fail-closed): never hand back a proof that does not self-verify.
    pub fn prove_mle(&self, close_proof: &ProofWithPublicInputs<F, C, D>) -> WResult<String> {
        use plonky2::iop::witness::{PartialWitness, WitnessWrite};

        use crate::utils::{
            mle_prover::{export_mle_json, prove_with_mle, setup_mle_vk, verify_mle_proof},
            wrapper::WrapperCircuit,
        };

        let wrapper = WrapperCircuit::<F, C, C, D>::new(&self.close_circuit.data.verifier_data());
        let wrapped = wrapper
            .prove(close_proof)
            .map_err(|e| WalletError(format!("close wrap proof failed: {e:?}")))?;
        wrapper
            .data
            .verify(wrapped)
            .map_err(|e| WalletError(format!("close wrap proof verify failed: {e:?}")))?;
        let vk = setup_mle_vk::<F, C, D>(&wrapper.data);
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&wrapper.wrap_proof, close_proof)
            .map_err(|e| WalletError(format!("close wrap witness binding failed: {e:?}")))?;
        let mle = prove_with_mle::<F, C, D>(&wrapper.data, pw)
            .map_err(|e| WalletError(format!("close MLE prove failed: {e:?}")))?;
        verify_mle_proof(&wrapper.data, &vk, &mle.proof)
            .map_err(|e| WalletError(format!("close MLE self-verify failed: {e:?}")))?;
        Ok(export_mle_json(&mle.proof, &wrapper.data.common))
    }

    /// Verifier data for the close circuit (so a caller can verify a close proof locally).
    pub fn close_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.close_circuit.data.verifier_data()
    }
}

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
        let members: Vec<MemberInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| member_info(i as u8, k))
            .collect();
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
        regev_pk_digests_active: &[Bytes32],
        fund_amount: u64,
    ) -> ChannelState {
        // Exercise the PUBLIC delegate-aware genesis path (accepts active-length ciphertexts).
        assemble_genesis_state(
            record,
            enc_balances_active,
            regev_pk_digests_active,
            fund_amount,
        )
        .unwrap()
    }

    /// Delegate account (Phase 4): the PUBLIC wallet build path (`build_record` +
    /// `assemble_genesis_state`) creates a delegate-bearing channel and enforces the region guards.
    #[test]
    fn build_record_delegate_guards() {
        let mut rng = StdRng::seed_from_u64(0xB11D);
        let keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut rng)).collect();
        let members: Vec<MemberInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| member_info(i as u8, k))
            .collect();

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
        // Decryption Stage 1: matching per-active-slot Regev pk digests.
        let pkds: Vec<Bytes32> = keys
            .iter()
            .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()))
            .collect();
        let g = assemble_genesis_state(&r, &encs, &pkds, 30).expect("active genesis");
        assert_eq!(g.balance_state.delegate_count, 1);
        g.balance_state.validate().expect("genesis balance valid");
        // A member_count-only ciphertext count is rejected (must cover the delegate slot too).
        assert!(assemble_genesis_state(&r, &encs[..2], &pkds[..2], 30).is_err());
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
        let pkds: Vec<Bytes32> = keys
            .iter()
            .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()))
            .collect();
        let mut genesis = assemble_active_genesis(&record, &cts, &pkds, fund);
        // ONLY the members (slots 0,1) co-sign — the delegate (slot 2) does NOT (N-of-N excludes
        // it).
        let g0 = sign_state(&keys[0], 0, &genesis).unwrap();
        add_signature(&mut genesis, g0);
        let g1 = sign_state(&keys[1], 1, &genesis).unwrap();
        add_signature(&mut genesis, g1);

        (record, keys, members, genesis, witnesses)
    }

    /// DA-send-happy: the DELEGATE (slot 2) builds a ChannelTx sending to a member (slot 0), with
    /// its OWN BabyBear hash-sig (A11) over the IMPA digest and the E-1 channelTxZKP. The
    /// transition
    /// + sender hash-sig MUST verify (the members would then co-sign). Asserts the delegate's slot
    ///   is
    /// debited and the recipient credited.
    ///
    /// PROVES: the widened `check_slot` (active region) + `member_pubkeys_root` (members +
    /// delegates) admit a delegate sender; a delegate sends with the IDENTICAL mechanism as a
    /// member.
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
            settled_tx_accumulator: default_settled_tx_accumulator(),
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
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        verify_all_signatures(
            &final_snapshot.record,
            &final_snapshot.members,
            &final_snapshot.state,
        )
        .expect("member n-of-n must verify (delegate excluded)");

        // The delegate slot is debited; the recipient member is credited.
        assert_eq!(
            decrypt_balance(&keys[2], &final_snapshot, 2).unwrap(),
            bal_d - amount
        );
        assert_eq!(
            decrypt_balance(&keys[0], &final_snapshot, 0).unwrap(),
            bal0 + amount
        );
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
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        let amount = 8u64;
        let BuiltSend { payload, .. } = build_send(
            &keys[2],
            &snapshot,
            2,
            0,
            amount,
            20,
            &witnesses[2],
            Bytes32::default(),
            LEVEL,
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
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        let amount = 8u64;
        let BuiltSend { payload, .. } = build_send(
            &keys[2],
            &snapshot,
            2,
            0,
            amount,
            20,
            &witnesses[2],
            Bytes32::default(),
            LEVEL,
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
        let err =
            res.expect_err("DA2: ChannelTx pk_b not matching the registered leaf MUST reject");
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
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        // Honest member-0 -> member-1 send (the delegate at slot 2 is NOT involved).
        let amount = 5u64;
        let BuiltSend { mut payload, .. } = build_send(
            &keys[0],
            &snapshot,
            0,
            1,
            amount,
            50,
            &witnesses[0],
            Bytes32::default(),
            LEVEL,
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
        let pkds: Vec<Bytes32> = keys
            .iter()
            .map(|k| Bytes32::from(k.regev_pk.poseidon_digest()))
            .collect();
        let mut genesis = assemble_active_genesis(&record, &cts, &pkds, b0 + b1 + b2);
        for i in 0..3 {
            let s = sign_state(&keys[i], i as u8, &genesis).unwrap();
            add_signature(&mut genesis, s);
        }
        let snapshot = ChannelSnapshot {
            record: record.clone(),
            state: genesis,
            members: members.clone(),
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        verify_snapshot(&snapshot, Some((&keys[0], 0))).expect("verify genesis (3 members)");

        let amount = 6u64;
        let BuiltSend { mut payload, .. } = build_send(
            &keys[0],
            &snapshot,
            0,
            1,
            amount,
            b0,
            &ws[0],
            Bytes32::default(),
            LEVEL,
            &mut rng,
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
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        verify_all_signatures(
            &final_snapshot.record,
            &final_snapshot.members,
            &final_snapshot.state,
        )
        .expect("3-of-3 must verify");
        assert_eq!(
            decrypt_balance(&keys[0], &final_snapshot, 0).unwrap(),
            b0 - amount
        );
        assert_eq!(
            decrypt_balance(&keys[1], &final_snapshot, 1).unwrap(),
            b1 + amount
        );
    }

    // ── A-3 P2: real close proving (CloseProver) ───────────────────────────────────────────────

    /// Build a closable genesis channel (member_count=3, no delegates) + a REAL genesis balance
    /// proof, then prove the close circuit through `CloseProver` and verify it. This exercises the
    /// whole real-input close path end-to-end (no test_fixture): member single-sigs over the IMCH
    /// digest, the recursive list fold, the balance-proof binding, and the in-circuit soundness
    /// gates. HEAVY: builds the balance + close circuits and proves a close (minutes, multi-GB).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a3_close_prover_builds_and_verifies_real_close_proof() {
        use crate::{
            circuits::balance::{balance_processor::BalanceProcessor, spend_circuit::SpendCircuit},
            common::{channel_id::ChannelId, salt::Salt},
        };

        let mut rng = StdRng::seed_from_u64(0x0c105e);
        let channel = 5u32;
        let keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut rng)).collect();
        let members: Vec<MemberInfo> =
            keys.iter().enumerate().map(|(i, k)| member_info(i as u8, k)).collect();
        let record = build_record(channel, &members, 0, 0).expect("record");
        let encs: Vec<RegevCiphertext> = keys
            .iter()
            .map(|k| encrypt_amount(&mut rng, &k.regev_pk, 10).unwrap().0)
            .collect();
        let pkds: Vec<Bytes32> =
            members.iter().map(|m| Bytes32::from(m.regev_pk.poseidon_digest())).collect();
        let mut state = assemble_genesis_state(&record, &encs, &pkds, 30).expect("genesis");
        for (i, k) in keys.iter().enumerate() {
            let s = sign_state(k, i as u8, &state).expect("sign genesis");
            add_signature(&mut state, s);
        }

        // REAL genesis balance proof (settled_tx_chain = 0, matching the genesis state).
        let spend = SpendCircuit::<F, C, D>::new();
        let bp = BalanceProcessor::<F, C, D>::new(&spend.data.verifier_data());
        let balance_proof = bp
            .prove_initial(
                ChannelId::new(channel as u64).unwrap(),
                Salt::rand(&mut rand::thread_rng()),
            )
            .expect("genesis balance proof");

        let prover = CloseProver::new(&bp.balance_vd());

        // Negative (fail-closed precondition, no proving): member-key count != member_count.
        assert!(
            prover
                .build_full_witness(&state, &keys[..2], balance_proof.clone(), 1, Bytes32::default(), 1)
                .is_err(),
            "close must reject a member-key count != member_count"
        );

        // Positive: build the full witness, prove, and verify.
        let witness = prover
            .build_full_witness(&state, &keys, balance_proof, 1, Bytes32::default(), 1)
            .expect("close full witness");
        let proof = prover.prove(&witness).expect("close proof");
        prover.close_vd().verify(proof).expect("real close proof verifies");
    }
}
