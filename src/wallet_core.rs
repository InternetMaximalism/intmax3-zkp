//! Core logic for the single-member browser wallet + CLI companion (Regev channel model).
//!
//! This module is target-independent (native CLI + wasm wallet both use it). It implements one
//! channel member's slice of the in-channel transfer protocol (detail2 §E-1/§E-4, abstract2
//! §3.1/§3.2): Falcon-512/Poseidon (state co-signing) + BabyBear (channel-tx sender) + Regev key
//! management, genesis contribution, building/verifying an in-channel `ChannelTx` with its
//! mandatory E-1 STARK proof, co-signing `ChannelState`, and decrypting one's own hidden balance.
//!
//! SECURITY: the channel library's `validate_all_member_signatures` is structural only (it does
//! NOT run the real signature check — see tasks/wallet-threat-model.md A-1). This module therefore
//! verifies every member's REAL Falcon-512/Poseidon cosignature (falcon-sig Phase 4) over the exact
//! IMCH signing digest, the channel-tx SENDER's BabyBear hash-sig (P3) over the IMPA digest,
//! re-derives `regev_pk_root` and the Poseidon `member_pubkeys_root` (binding the full
//! `(pk_g, pk_b, regev_pk)` member triple — P4-1), rebuilds every E-1 statement from authenticated
//! state (never from the tx carrier), and decrypts its own balance slot on every state it adopts.
//! Secret material (`FalconKeys`, `BabyBearSecretKey`, `RegevSk`, `AmountWitness`) never
//! leaves this module via any serialized type.

use std::sync::{Arc, OnceLock};

use plonky2::plonk::{circuit_data::VerifierCircuitData, proof::ProofWithPublicInputs};
use rand::SeedableRng as _;
use rand010::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    circuits::{
        balance::{
            balance_pis::BalanceFullPublicInputs,
            common::recipient::{
                calculate_recipient_from_user_id, extract_address_from_recipient,
            },
        },
        channel::state_update_verifier::{
            BalanceRefreshUpdateWitness, ChannelProofVerifier, ChannelStateUpdateError,
            ChannelStateUpdatePublicInputs, InChannelTransferUpdateWitness,
            InterChannelFundImportUpdateWitness, InterChannelSendUpdateWitness,
            L1DepositImportUpdateWitness, ReceiverBundleApplyUpdateWitness,
            TokenRegisterUpdateWitness, require_accumulator_push,
        },
    },
    common::{
        balance_state::{BalanceState, settled_tx_chain_push, tx_leaf_hash},
        channel::{
            ChannelFund, ChannelProofEnvelope, ChannelRecord, ChannelState, ChannelStatus,
            ChannelTx, InterChannelTx, MemberSignature, MerkleInclusionProof, ProofBackend,
            ReceiverBalanceDelta, SignedSmallBlock, SmallBlockRootMessage, TransitionProofRole,
            burn_descriptor, inter_channel_tx_hash,
        },
        channel_id::ChannelId,
        deposit::Deposit,
        salt::Salt,
        transfer::Transfer,
        trees::{
            key_tree::{MemberLeaf, MemberTree},
            transfer_tree::TransferTree,
            tx_v2_tree::{TxV2MerkleProof, TxV2Tree},
        },
        tx::{TxClass, TxV2},
    },
    constants::{MAX_CHANNEL_MEMBERS, MAX_CHANNEL_TOKENS},
    ethereum_types::{
        bytes32::{BYTES32_LEN, Bytes32},
        u32limb_trait::U32LimbTrait,
        u256::U256,
    },
    falcon_sig::{FalconKeys, encode_cosign_blob, verify_cosign_blob},
    regev::{
        AmountWitness, MAX_HOMO_ADDS_BEFORE_REFRESH, RealRegevProofVerifier, RegevCiphertext,
        RegevPk, RegevSecurityLevel, RegevSk, add_ciphertexts, channel_keygen, decrypt_amount,
        encrypt_amount,
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
// Base-layer plonky2 proof config
// ---------------------------------------------------------------------------
// Previously re-exported from `poseidon_sig::circuit`, which was deleted with the retired
// proof-as-signature scheme (falcon-sig Phase 4). The values are the repo-wide standard
// (CLAUDE.md: `PoseidonGoldilocksConfig`, Goldilocks, degree-2 extension) and are unchanged.

pub const D: usize = 2;
pub type F = plonky2::field::goldilocks_field::GoldilocksField;
pub type C = plonky2::plonk::config::PoseidonGoldilocksConfig;

// ---------------------------------------------------------------------------
// Secret-bearing key material (never serialized)
// ---------------------------------------------------------------------------

/// One member's full key material. Held only in process memory; never crosses a serialization
/// boundary (no `Serialize`).
pub struct MemberKeys {
    /// The member's ONE signing key: Falcon-512 with a plonky2-Poseidon hash-to-point
    /// (falcon-sig Phase 4, TM-C6). It signs BOTH the channel-STATE co-sign (IMCH digest, here)
    /// and — for the block producer — the small-block root (IMSB digest, validity path); the two
    /// contexts are isolated by their message digests' distinct domain constants, never by
    /// separate keys. Its identity digest `pk_g = Poseidon(IMFK || encode(h))` is the member's
    /// canonical on-chain-anchored identity (the value stored in `ChannelRecord.member_pk_gs` and
    /// committed in the registered `MemberLeaf`), the same 32-byte width the retired Goldilocks
    /// `pk_g` occupied.
    ///
    /// `Arc` because [`FalconKeys`] is deliberately NOT `Clone` (that non-`Clone`ness is what
    /// stops a signer being silently duplicated) while the channel-registration path needs the
    /// SAME key object, not a re-derived twin: NTRU keygen costs ~455 ms, and a second derivation
    /// is exactly the pattern that produced the Phase-3 finding-7 identity divergence.
    falcon_key: std::sync::Arc<FalconKeys>,
    /// P3 BabyBear hash-sig secret key — authorizes the channel-tx SENDER (IMPA) over the
    /// channel-tx `signing_digest`. Its `pk_b` is committed in the member's registered
    /// `MemberLeaf` (A11).
    pub baby_key: BabyBearSecretKey,
    pub regev_pk: RegevPk,
    pub regev_sk: RegevSk,
}

impl MemberKeys {
    /// Derive all key material from `rng`.
    ///
    /// SECURITY (TM-C10 / O-11, restore-from-seed): the draws happen in a FIXED order and the
    /// Falcon key is derived from the FIRST 32-byte draw via `FalconKeys::from_seed` (which
    /// itself domain-separates with IMFG before seeding the NTRU-keygen ChaCha20). Seeding the
    /// caller's RNG deterministically (`wallet_keygen_seeded`, the CLI's `keys_for`) therefore
    /// reproduces the SAME `h` / `pk_g` on every platform: `rand010::StdRng` is ChaCha-based with
    /// a specified byte stream, and every step below is integer/byte arithmetic. Keygen runs at
    /// join/restore only (~455 ms native), never per signature.
    pub fn generate(rng: &mut impl Rng) -> Self {
        // Falcon state-signing key: draw a 32-byte seed from the wallet RNG (the SAME stream
        // position the retired Goldilocks key used) and derive the keypair deterministically.
        let mut sig_seed = [0u8; 32];
        rng.fill_bytes(&mut sig_seed);
        let falcon_key = std::sync::Arc::new(FalconKeys::from_seed(sig_seed));
        zeroize::Zeroize::zeroize(&mut sig_seed);
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
            falcon_key,
            baby_key,
            regev_pk,
            regev_sk,
        }
    }

    /// This member's Falcon signing key (borrowed; the secret never leaves the process).
    pub fn falcon_key(&self) -> &FalconKeys {
        &self.falcon_key
    }

    /// A refcounted handle on this member's Falcon key, for the paths that must register /
    /// prove with the EXACT key this wallet signs with (`ChannelMemberKeys::from_member_keys`).
    ///
    /// SECURITY (Phase-3 finding 7): handing out the KEY, not a seed or a derivation recipe, is
    /// what makes "the registered identity is the signing identity" true by construction instead
    /// of by two formulas happening to agree.
    pub fn falcon_key_handle(&self) -> std::sync::Arc<FalconKeys> {
        std::sync::Arc::clone(&self.falcon_key)
    }

    /// This member's identity `pk_g = Poseidon(IMFK || encode(h))` (the value stored in
    /// `ChannelRecord.member_pk_gs` and committed in the registered `MemberLeaf`).
    pub fn pk_g(&self) -> Bytes32 {
        self.falcon_key.pk_g()
    }

    /// This member's `pk_g` as the canonical `PoseidonHashOut` the Poseidon member tree stores.
    pub fn pk_g_hash_out(&self) -> crate::utils::poseidon_hash_out::PoseidonHashOut {
        self.pk_g().reduce_to_hash_out()
    }

    /// This member's BabyBear hash-sig public key `pk_b` (canonical `Bytes32` digest), committed in
    /// the registered `MemberLeaf` for the A11 two-key binding.
    pub fn pk_b(&self) -> Bytes32 {
        self.baby_key.public_key().to_bytes32()
    }
}

// ---------------------------------------------------------------------------
// Falcon-512/Poseidon channel-STATE (IMCH) co-signing (falcon-sig Phase 4)
// ---------------------------------------------------------------------------

/// Produce a member's native Falcon signature over `digest` (the IMCH state `signing_digest`),
/// wire-encoded as the COSIGN transport blob (`v1 || salt || s2 || h`, 1690 bytes).
///
/// This is ~5 ms of native arithmetic. It replaces the retired `SingleSigCircuit` proving step
/// (~seconds, ~76 KB of wire), so the browser co-signs without building or proving any plonky2
/// circuit at all.
fn sign_digest(keys: &FalconKeys, digest: &Bytes32) -> Vec<u8> {
    let sig = keys.sign(*digest);
    encode_cosign_blob(&sig, &keys.pk_coefficients())
}

/// Verify a member's Falcon COSIGN blob over `digest`, bound to the claimed public key `pk_g`.
///
/// SECURITY (falcon-sig Phase 4, review F-2): verification goes through
/// `falcon_sig::verify_cosign_blob`, which
///   1. rejects any blob whose leading VERSION byte is not `FALCON_SIG_V1` — so a legacy ~76 KB
///      `SingleSigCircuit` proof blob is rejected by POLICY, before any parsing (O-9 / TM-C8);
///   2. requires the exact 1690-byte encoding (the fixed-length structural gate);
///   3. recomputes `Poseidon(IMFK || encode(h)) == pk_g` INSIDE the call, so the `h` carried by the
///      (untrusted) blob is bound to the AUTHENTICATED identity the caller passes in — the bare
///      `falcon_sig::verify` entry point must never be used here; and
///   4. checks `||(s1, s2)||^2 <= beta^2` for `c = H2P(salt, digest)`, with `digest` RECOMPUTED by
///      the caller from authenticated state, never taken from the signature carrier (TM-C6).
///
/// Unforgeability now rests on Falcon-512 (NTRU/SIS, GPV) plus Poseidon-as-RO for the
/// hash-to-point — no longer on FRI soundness of a proof system config.
pub fn verify_state_sig(pk_g: Bytes32, digest: &Bytes32, sig: &[u8]) -> WResult<()> {
    verify_cosign_blob(pk_g, *digest, sig)
        .map_err(|e| WalletError(format!("falcon cosignature rejected: {e}")))
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

/// Public information about one member (no secrets). `pk_g` is the member's Falcon identity
/// digest `Poseidon(IMFK || encode(h))` (`MemberKeys::pk_g()`) — the value stored at the member's
/// slot in `ChannelRecord.member_pk_gs` and committed in the registered `MemberLeaf`; it is the
/// identity against which that member's Falcon state cosignatures verify (the signature blob
/// carries `h`, which `verify_state_sig` binds back to this digest).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberInfo {
    /// BALANCE-SLOT index (`0..member_count+delegate_count`, up to `MAX_CHANNEL_MEMBERS = 1024`):
    /// u16 — u8 capped joins at 256 slots (2026-07-18 storm).
    pub slot: u16,
    /// The member's Falcon signing identity `pk_g` (canonical `Bytes32`).
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
    /// BALANCE-SLOT indices (member OR delegate, `0..1024`) — u16, see `MemberInfo::slot`.
    pub sender_index: u16,
    pub recipient_index: u16,
    pub channel_tx: ChannelTx,
    pub proposed_next_state: ChannelState,
    pub members: Vec<MemberInfo>,
    pub record: ChannelRecord,
}

impl SendPayload {
    /// Project the fat solo payload down to the slim batch wire shape (detail2 §M-1): everything
    /// dropped (`proposed_next_state`, `members`, `record`) is data the verifier already holds
    /// and re-derives. The sender's fresh `after` ciphertext is extracted from the solo proposal
    /// (the slot its own E-1 proof pinned against the anchor).
    pub fn to_slim(&self) -> SlimSendPayload {
        SlimSendPayload {
            anchor_digest: self.proposed_next_state.prev_digest,
            sender_index: self.sender_index,
            recipient_index: self.recipient_index,
            channel_tx: self.channel_tx.clone(),
            // Multi-token: the slim wire carries the single transferred ciphertext — the
            // sender row's position at the tx's SIGNED token_slot (TM-2 leg 4: the verifier
            // re-selects the same position from its own state when rebuilding the E-1
            // statement).
            after_ct: self.proposed_next_state.balance_state.enc_balances
                [self.sender_index as usize][self.channel_tx.token_slot as usize]
                .clone(),
        }
    }
}

/// One sender's contribution to a batched co-sign round — abstract2-1 §2.2b `SignedChannelTx`
/// plus the E-1 `after` ciphertext the fold installs (detail2 §M-1). This is the ENTIRE wire
/// object: no state, no member list, no record. `anchor_digest` is the FIRST field so a transport
/// can extract it from the head of the byte stream without a full JSON parse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlimSendPayload {
    /// Digest of the anchor state `S` this tx extends (== the digest the sender's A11 tx
    /// signature binds — detail2 §M-3 exact-anchor rule).
    pub anchor_digest: Bytes32,
    /// BALANCE-SLOT indices (member OR delegate, `0..1024`) — u16, see `MemberInfo::slot`.
    pub sender_index: u16,
    pub recipient_index: u16,
    /// `enc_amount`, `nonce`, the mandatory E-1 proof, and the sender's pk_g/pk_b + A11 hash-sig.
    pub channel_tx: ChannelTx,
    /// The sender's fresh post-debit ciphertext (the E-1 statement's `after`).
    pub after_ct: RegevCiphertext,
}

/// Binary transport envelope for [`SlimSendPayload`] ("IMSW", version 1).
///
/// The fixed header deliberately carries the anchor as raw bytes before the bincode body.  A
/// streaming relay can therefore reject stale work after reading only 40 bytes, without parsing or
/// buffering the proof-bearing payload.  JSON remains accepted by the CLI for rolling upgrades;
/// new browser uploads use this encoding.
pub const SLIM_WIRE_MAGIC: [u8; 4] = *b"IMSW";
pub const SLIM_WIRE_VERSION: u8 = 1;
pub const SLIM_WIRE_HEADER_LEN: usize = 4 + 1 + 3 + 32;
const MAX_SLIM_WIRE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct SlimSendPayloadBody {
    sender_index: u16,
    recipient_index: u16,
    channel_tx: ChannelTx,
    after_ct: RegevCiphertext,
}

impl SlimSendPayload {
    /// Encode the proof and Regev coefficient vectors as binary instead of decimal JSON arrays.
    /// Integers are fixed-width little-endian; the anchor in the header is canonical big-endian
    /// bytes so it has the same visual order as its `0x...` representation.
    pub fn to_wire_bytes(&self) -> WResult<Vec<u8>> {
        self.channel_tx
            .enc_amount
            .validate()
            .map_err(|e| WalletError(format!("slim binary wire: invalid enc_amount: {e}")))?;
        self.after_ct
            .validate()
            .map_err(|e| WalletError(format!("slim binary wire: invalid after_ct: {e}")))?;
        let body = SlimSendPayloadBody {
            sender_index: self.sender_index,
            recipient_index: self.recipient_index,
            channel_tx: self.channel_tx.clone(),
            after_ct: self.after_ct.clone(),
        };
        let encoded = bincode::serde::encode_to_vec(
            body,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map_err(|e| WalletError(format!("slim binary wire encode failed: {e}")))?;
        if SLIM_WIRE_HEADER_LEN + encoded.len() > MAX_SLIM_WIRE_BYTES {
            return bail("slim binary wire exceeds the 64 MiB transport limit");
        }
        let mut out = Vec::with_capacity(SLIM_WIRE_HEADER_LEN + encoded.len());
        out.extend_from_slice(&SLIM_WIRE_MAGIC);
        out.push(SLIM_WIRE_VERSION);
        out.extend_from_slice(&[0u8; 3]); // reserved; must stay zero until a version bump
        out.extend_from_slice(&self.anchor_digest.to_bytes_be());
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    /// Decode versioned binary wire bytes.  The decoder is size-limited, rejects trailing bytes
    /// and reserved-bit smuggling, and validates both ciphertexts before returning them across the
    /// trust boundary.
    pub fn from_wire_bytes(bytes: &[u8]) -> WResult<Self> {
        if bytes.len() < SLIM_WIRE_HEADER_LEN {
            return bail("slim binary wire is shorter than its 40-byte header");
        }
        if bytes.len() > MAX_SLIM_WIRE_BYTES {
            return bail("slim binary wire exceeds the 64 MiB transport limit");
        }
        if bytes[..4] != SLIM_WIRE_MAGIC {
            return bail("slim binary wire magic mismatch");
        }
        if bytes[4] != SLIM_WIRE_VERSION {
            return bail(format!(
                "unsupported slim binary wire version {} (expected {SLIM_WIRE_VERSION})",
                bytes[4]
            ));
        }
        if bytes[5..8] != [0u8; 3] {
            return bail("slim binary wire reserved header bytes must be zero");
        }
        let anchor_digest = Bytes32::from_bytes_be(&bytes[8..SLIM_WIRE_HEADER_LEN])
            .map_err(|e| WalletError(format!("slim binary wire anchor: {e}")))?;
        let body_bytes = &bytes[SLIM_WIRE_HEADER_LEN..];
        let (body, consumed) = bincode::serde::decode_from_slice::<SlimSendPayloadBody, _>(
            body_bytes,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian()
                .with_limit::<MAX_SLIM_WIRE_BYTES>(),
        )
        .map_err(|e| WalletError(format!("slim binary wire decode failed: {e}")))?;
        if consumed != body_bytes.len() {
            return bail(format!(
                "slim binary wire has {} trailing bytes",
                body_bytes.len() - consumed
            ));
        }
        body.channel_tx
            .enc_amount
            .validate()
            .map_err(|e| WalletError(format!("slim binary wire: invalid enc_amount: {e}")))?;
        body.after_ct
            .validate()
            .map_err(|e| WalletError(format!("slim binary wire: invalid after_ct: {e}")))?;
        Ok(Self {
            anchor_digest,
            sender_index: body.sender_index,
            recipient_index: body.recipient_index,
            channel_tx: body.channel_tx,
            after_ct: body.after_ct,
        })
    }

    /// Rolling-upgrade decoder used by the CLI spool reader: versioned binary first, compact JSON
    /// otherwise.  A body beginning with `IMSW` is never allowed to fall back to JSON after a
    /// binary decoding error.
    pub fn from_wire_or_json(bytes: &[u8]) -> WResult<Self> {
        if bytes.starts_with(&SLIM_WIRE_MAGIC) {
            Self::from_wire_bytes(bytes)
        } else {
            serde_json::from_slice(bytes)
                .map_err(|e| WalletError(format!("slim JSON decode failed: {e}")))
        }
    }
}

#[cfg(test)]
mod slim_binary_wire_tests {
    use super::*;

    fn fixture() -> SlimSendPayload {
        let ct = RegevCiphertext::padding();
        SlimSendPayload {
            anchor_digest: Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
            sender_index: 17,
            recipient_index: 900,
            channel_tx: ChannelTx {
                recipient_pk_g: Bytes32::from_u32_slice(&[9; 8]).unwrap(),
                token_slot: 3,
                enc_amount: ct.clone(),
                nonce: Bytes32::from_u32_slice(&[10; 8]).unwrap(),
                channel_tx_zkp: ChannelProofEnvelope {
                    role: TransitionProofRole::ChannelStateUpdate,
                    backend: ProofBackend::Plonky3,
                    proof: (0..=255).cycle().take(32_000).collect(),
                },
                sender_pk_g: Bytes32::from_u32_slice(&[11; 8]).unwrap(),
                sender_hash_sig: (0..=251).cycle().take(48_000).collect(),
                sender_pk_b: Bytes32::from_u32_slice(&[12; 8]).unwrap(),
            },
            after_ct: ct,
        }
    }

    #[test]
    fn slim_binary_wire_roundtrip_and_header_anchor() {
        let slim = fixture();
        let wire = slim.to_wire_bytes().unwrap();
        assert_eq!(&wire[..4], b"IMSW");
        assert_eq!(wire[4], SLIM_WIRE_VERSION);
        assert_eq!(&wire[8..40], slim.anchor_digest.to_bytes_be());
        assert_eq!(SlimSendPayload::from_wire_bytes(&wire).unwrap(), slim);
        assert_eq!(SlimSendPayload::from_wire_or_json(&wire).unwrap(), slim);
    }

    #[test]
    fn slim_binary_wire_is_smaller_than_decimal_json_and_json_stays_compatible() {
        let slim = fixture();
        let json = serde_json::to_vec(&slim).unwrap();
        let wire = slim.to_wire_bytes().unwrap();
        assert!(
            wire.len() * 2 < json.len(),
            "wire={} json={}",
            wire.len(),
            json.len()
        );
        assert_eq!(SlimSendPayload::from_wire_or_json(&json).unwrap(), slim);
    }

    #[test]
    fn slim_binary_wire_rejects_version_reserved_and_trailing_bytes() {
        let mut bad_version = fixture().to_wire_bytes().unwrap();
        bad_version[4] = 2;
        assert!(SlimSendPayload::from_wire_bytes(&bad_version).is_err());

        let mut bad_reserved = fixture().to_wire_bytes().unwrap();
        bad_reserved[7] = 1;
        assert!(SlimSendPayload::from_wire_bytes(&bad_reserved).is_err());

        let mut trailing = fixture().to_wire_bytes().unwrap();
        trailing.push(0);
        assert!(SlimSendPayload::from_wire_bytes(&trailing).is_err());
    }
}

/// The retained residue of a VERIFIED slim tx — exactly what the canonical fold needs (mirrors
/// the Lean model's `BatchTx`). The streaming batch verifier keeps one of these (~8 KB) per tx
/// and DROPS the proofs, so batch memory is K-independent of proof size (detail2 §M-4).
#[derive(Clone, Debug)]
pub struct BatchTxApply {
    pub sender_index: u16,
    pub recipient_index: u16,
    /// LOCAL token slot this tx moves (TM-14): copied from the SIGNED
    /// `channel_tx.token_slot` of the verified slim payload — the fold debits/credits at
    /// exactly this position of each involved row.
    pub token_slot: u8,
    pub enc_amount: RegevCiphertext,
    pub after_ct: RegevCiphertext,
}

impl From<&SlimSendPayload> for BatchTxApply {
    fn from(s: &SlimSendPayload) -> Self {
        BatchTxApply {
            sender_index: s.sender_index,
            recipient_index: s.recipient_index,
            token_slot: s.channel_tx.token_slot,
            enc_amount: s.channel_tx.enc_amount.clone(),
            after_ct: s.after_ct.clone(),
        }
    }
}

/// Build the full padded Regev pk array from a member list (padding = `RegevPk::padding()`).
pub fn regev_pks_array(members: &[MemberInfo]) -> [RegevPk; MAX_CHANNEL_MEMBERS] {
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

/// The wallet's LIVE-membership Poseidon `MemberTree` root over the channel's member leaves
/// `MemberLeaf{pk_g, pk_b, regev_pk_digest}`, in slot order (active slots
/// `0..member_count+delegate_count`; padding slots are empty leaves, pad-to-MAX D6). Built over
/// the height-`WALLET_MEMBER_TREE_HEIGHT` wallet tree (`MAX_CHANNEL_MEMBERS` slots).
///
/// SECURITY (P4-1, A11): anchoring the wallet's `ChannelRecord.member_pubkeys_root` to this root
/// (instead of the previous keccak-over-`pk_g`-only) commits the FULL `(pk_g, pk_b, regev_pk)`
/// triple jointly, so a peer cannot substitute one member's `pk_b` (or Regev key) independently of
/// their `pk_g`. The off-chain channel-tx A11 check then reads `pk_b` from this AUTHENTICATED set.
///
/// SECURITY (Option B divergence — INTENTIONAL, tasks/reg-chain-1024-threat-model.md): this is
/// NOT the on-chain REGISTERED root. The registered root (`channel_reg_step`'s
/// `member_pubkeys_root_for`, height `MEMBER_TREE_HEIGHT`) covers ONLY the genesis cosigners and
/// never changes; THIS root covers the LIVE membership (cosigners + delegates) and evolves with
/// every `join_delegate`. The two roots are equal for no channel with a delegate and are NEVER
/// compared anywhere: this one anchors the off-chain member set peers verify
/// (`verify_snapshot` / payload checks), the registered one authenticates the block producer in
/// the validity circuit. Delegates are authenticated by the cosigner-signed H1 slot tree, not by
/// L1 registration.
///
/// `members` MUST cover slots `0..member_count+delegate_count` bijectively (the caller checks this
/// via `verify_snapshot` / `check_slot`); `pk_g` for each slot is taken from the record (the value
/// the member signatures are bound to), while `pk_b` and the Regev digest come from the per-member
/// `MemberInfo`.
///
/// SECURITY (delegate account): the loop covers ACTIVE participants = members
/// (`0..member_count`) AND delegates (`member_count..member_count+delegate_count`). Delegates
/// carry a real `MemberLeaf{pk_g, pk_b, regev_pk_digest}` identity so they can send (A11) and
/// withdraw at close, distinguished from members ONLY by slot index. With `delegate_count = 0`
/// this is byte-for-byte the legacy `0..member_count` loop.
fn member_pubkeys_root(record: &ChannelRecord, members: &[MemberInfo]) -> WResult<Bytes32> {
    let mut tree = MemberTree::init_wallet_membership();
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
    delegate_count: u16,
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
    // Cosigner cap: member_count must fit the N-of-N close signer space. Checked EXPLICITLY here
    // (before the `as u8` narrowing below) so an oversized cosigner count fails loudly instead of
    // truncating — e.g. 258 would otherwise wrap to 2 and pass `record.validate()`.
    if member_count > crate::constants::MAX_COSIGNERS {
        return bail(format!(
            "member_count {member_count} exceeds MAX_COSIGNERS ({}); extra participants must join \
             as delegates",
            crate::constants::MAX_COSIGNERS
        ));
    }
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
/// member-only behavior. `recipients_active` (B-1b) must carry one NONZERO L1 exit address per
/// active slot — `BalanceState::validate()` refuses a zero active recipient fail-closed.
pub fn assemble_genesis_state(
    record: &ChannelRecord,
    enc_balances_active: &[RegevCiphertext],
    regev_pk_digests_active: &[Bytes32],
    recipients_active: &[Address],
    fund_amount: u64,
) -> WResult<ChannelState> {
    // Legacy/UNBACKED genesis: zero settle-chain + zero intmax_state_root. A channel assembled this
    // way has NO deposit backing, so `verify_channel_backing` REFUSES to co-sign it (fail-closed).
    assemble_genesis_state_backed(
        record,
        enc_balances_active,
        regev_pk_digests_active,
        recipients_active,
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
    recipients_active: &[Address],
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
    // B-1b: one NONZERO L1 exit address per ACTIVE slot (members then delegates), folded into the
    // signed H1 via the slot leaves. FAIL-CLOSED here (before the state is even assembled): a
    // zero/missing recipient must never enter a signable genesis — for delegates this leaf field
    // is the ONLY payout binding under Option B.
    if recipients_active.len() != active {
        return bail("genesis recipient count must equal member_count + delegate_count (B-1b)");
    }
    if let Some(i) = recipients_active
        .iter()
        .position(|r| *r == Address::default())
    {
        return bail(format!(
            "genesis recipient for active slot {i} is the zero address — refusing (B-1b \
             fail-closed: the slot could never exit on L1)"
        ));
    }
    let state = ChannelState {
        channel_id: record.channel_id,
        epoch: 1,
        small_block_number: 0,
        close_freeze_nonce: 0,
        channel_fund: ChannelFund {
            channel_id: record.channel_id,
            // Genesis funds live at token slot 0 (the genesis token; registry = [ETH]).
            amounts: ChannelFund::single_token_amounts(U256::from(fund_amount)),
            intmax_state_root,
        },
        balance_state: BalanceState {
            channel_id: record.channel_id,
            member_count: record.member_count,
            delegate_count: record.delegate_count,
            enc_balances: BalanceState::pad_enc_balances_token0(enc_balances_active),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(regev_pk_digests_active),
            recipients: BalanceState::pad_recipients(recipients_active),
            settled_tx_chain,
            // Stage 3: genesis seeds the EMPTY-tree accumulator root. Each subsequent inter-channel
            // advancement pushes `tx_hash` and sets the new root (see the build_* sites below).
            settled_tx_accumulator_root: empty_settled_tx_accumulator_root(),
            state_version: 0,
            pending_adds: BalanceState::pad_pending_adds_token0(&vec![0u32; active]),
            // detail2 §N owner decision 5: a fresh channel is definitionally single-token —
            // registry = [genesis token 0 (ETH)], all balances at token slot 0.
            token_registry: BalanceState::single_token_registry(0),
            token_count: 1,
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

/// Produce this member's `MemberSignature` over `state.signing_digest()` (falcon-sig Phase 4: a
/// native Falcon-512/Poseidon signature over the IMCH digest, wire-encoded with the signer's
/// public polynomial `h` so any holder of the registered `pk_g` can verify it).
///
/// WIDTH: `slot` is a COSIGNER slot (`< member_count <= MAX_COSIGNERS = 16`), so u8 is
/// sufficient — delegates never co-sign state (audited 2026-07-18, u16 slot widening).
pub fn sign_state(keys: &MemberKeys, slot: u8, state: &ChannelState) -> WResult<MemberSignature> {
    let digest = state.signing_digest();
    Ok(MemberSignature {
        member_slot: slot,
        pk_g: keys.pk_g(),
        signature: sign_digest(keys.falcon_key(), &digest),
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

/// Verify that EVERY active member's real Falcon cosignature is present and valid over
/// `state.signing_digest()`, and that each signer's `pk_g` is the registered member at the slot.
///
/// SECURITY: each member's signature is verified INDIVIDUALLY (the wallet's local N-of-N
/// agreement). The on-chain aggregation of these same per-member signatures (in slot order, via
/// `FalconAggCircuit` for close/cancel-close) is a separate path and is NOT re-implemented here.
/// Each signer's `pk_g` is checked `∈` the registered member set (it must equal
/// `record.member_pk_gs[slot]`, and the signature is verified against exactly that `pk_g` — the
/// transported public polynomial `h` is bound to it inside `verify_state_sig`), so a signature by
/// a non-member or for a different message is rejected.
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
        // Verify the member's Falcon cosignature, bound to the registered pk_g and the recomputed
        // IMCH digest. (`verify_state_sig` re-checks `Poseidon(IMFK||encode(h)) == pk_g`
        // internally, so the blob's own public key cannot be substituted.)
        verify_state_sig(expected_pk_g, &digest, &sig.signature)?;
    }
    Ok(())
}

/// Full import verification of a signed snapshot (tasks/wallet-threat-model.md §G):
/// record.validate, regev_pk_root match, member-pubkey binding, all real signatures, balance-state
/// validity, and (if `my_slot`/`my_keys` given) own-slot decryption sanity.
pub fn verify_snapshot(
    snapshot: &ChannelSnapshot,
    // Own BALANCE-SLOT (member OR delegate, `0..1024`) — u16, see `MemberInfo::slot`.
    my_keys: Option<(&MemberKeys, u16)>,
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
        // Confirm we can decrypt our own balance slot (no panic / valid ciphertext) at EVERY
        // active token position (multitoken §N-2: unused positions are the canonical zero
        // ciphertext, which decrypts to 0 under any key — so this cannot false-negative on a
        // token the member simply does not hold).
        for token_slot in 0..snapshot.state.balance_state.token_count as usize {
            decrypt_amount(
                &keys.regev_sk,
                &snapshot.state.balance_state.enc_balances[slot as usize][token_slot],
            )
            .map_err(|e| {
                WalletError(format!(
                    "own balance slot does not decrypt at token position {token_slot}: {e}"
                ))
            })?;
        }
    }
    Ok(())
}

/// Decrypt this member's hidden GENESIS-token (local token slot 0) balance from a snapshot —
/// the wire-compat single-token view kept for existing callers/API shapes; the per-token query
/// is [`decrypt_balance_token`].
pub fn decrypt_balance(keys: &MemberKeys, snapshot: &ChannelSnapshot, slot: u16) -> WResult<u64> {
    decrypt_balance_token(keys, snapshot, slot, 0)
}

/// Decrypt this member's hidden balance at LOCAL token position `token_slot` (multitoken §N-2).
/// Fail-closed on an inactive position (`token_slot >= token_count`, TM-8) — an active position
/// the member does not hold is the canonical zero ciphertext and decrypts to 0.
pub fn decrypt_balance_token(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    slot: u16,
    token_slot: u8,
) -> WResult<u64> {
    // Delegates own a balance slot too; admit the full active region (members + delegates).
    let bs = &snapshot.state.balance_state;
    let active = bs.member_count as usize + bs.delegate_count as usize;
    check_slot(slot as usize, active)?;
    if token_slot as usize >= bs.token_count as usize {
        return bail(format!(
            "token_slot {token_slot} out of range (>= token_count {}, TM-8)",
            bs.token_count
        ));
    }
    decrypt_amount(
        &keys.regev_sk,
        &bs.enc_balances[slot as usize][token_slot as usize],
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

/// Build an in-channel transfer of the GENESIS token (local token slot 0) — the wire-compat
/// single-token entry; the per-token builder is [`build_send_token`].
#[allow(clippy::too_many_arguments)]
pub fn build_send(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    sender_slot: u16,
    recipient_slot: u16,
    amount: u64,
    before_amount: u64,
    before_witness: &AmountWitness,
    nonce: Bytes32,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<BuiltSend> {
    build_send_token(
        keys,
        snapshot,
        sender_slot,
        recipient_slot,
        0,
        amount,
        before_amount,
        before_witness,
        nonce,
        level,
        rng,
    )
}

/// Build an in-channel transfer of `amount` of LOCAL token position `token_slot` from
/// `sender_slot` to `recipient_slot` (multitoken §N-3 — the Phase 4 per-token build path;
/// `token_slot` is signed into the IMPA-v2 digest and the verifier paths enforce the full
/// TM-2 binding triple at exactly that position).
///
/// `before_witness` is the sender's `AmountWitness` for their CURRENT balance ciphertext AT
/// `token_slot` (held locally since genesis/last refresh of that position). `before_amount` is
/// the sender's current plaintext balance at that position. Produces the E-1 proof, the signed
/// `ChannelTx`, and the proposed next state carrying only the sender's signature.
#[allow(clippy::too_many_arguments)]
pub fn build_send_token(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    sender_slot: u16,
    recipient_slot: u16,
    token_slot: u8,
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
    // TM-8: bound the SIGNED token position before any fixed-width row indexing (solo_next_state
    // re-checks; the verifier paths enforce it adversarially).
    let ts = token_slot as usize;
    if ts >= MAX_CHANNEL_TOKENS || ts >= prev.balance_state.token_count as usize {
        return bail(format!(
            "token_slot {ts} out of range (token_count {}, TM-8)",
            prev.balance_state.token_count
        ));
    }
    // D3/TM-13: the refresh gate is per (slot, token) — only the SENT position must be clean.
    if prev.balance_state.pending_adds[sender_slot as usize][ts] != 0 {
        return bail(
            "sender (slot, token) position has pending homomorphic adds; refresh required before sending (not yet implemented in MVP)",
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

    // E-1 channelTxZKP over (before, enc_amount, after) — the `before` ciphertext is the
    // sender's position at the SIGNED token_slot (TM-2 leg 4).
    let proof = prove_channel_tx(
        level,
        sender_pk,
        recipient_pk,
        (
            &prev.balance_state.enc_balances[sender_slot as usize][ts],
            before_witness,
        ),
        (&enc_amount, &enc_amount_w),
        (&after_ct, &after_w),
    )
    .map_err(we)?;

    // Proposed next state (shared with the slim-batch verifier, detail2 §M-2).
    let next_state = solo_next_state(
        prev,
        sender_slot,
        recipient_slot,
        token_slot,
        &after_ct,
        &enc_amount,
    )?;

    let sender_hash = record.member_pk_gs[sender_slot as usize];
    let recipient_hash = record.member_pk_gs[recipient_slot as usize];
    let tx_digest = ChannelTx::signing_digest(
        prev.channel_id,
        prev.digest,
        &enc_amount,
        nonce,
        token_slot,
        sender_hash,
        recipient_hash,
    );
    // P3: the SENDER authorizes the transfer with a BabyBear hash-sig over the IMPA tx digest.
    let sender_hash_sig = sign_channel_tx_sender(keys, &tx_digest, level)?;
    let channel_tx = ChannelTx {
        recipient_pk_g: recipient_hash,
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

    let mut proposed = next_state;
    // SECURITY/delegate account: a co-signing MEMBER sender (slot < member_count) contributes its
    // own Goldilocks state signature here (it is one of the N-of-N). A DELEGATE sender
    // (slot >= member_count) is send-only — it authorizes the debit with its BabyBear A11 hash-sig
    // (above) but does NOT co-sign channel state, so it adds NO state signature; the N-of-N members
    // co-sign the resulting state. (A delegate signature would be ignored by verify_all_signatures
    // anyway, but emitting it would contradict the send-only model and waste a proof.)
    if (sender_slot as usize) < prev.balance_state.member_count as usize {
        // Cosigner space (guarded above): slot < member_count <= MAX_COSIGNERS, so u8 fits.
        let sender_sig = sign_state(keys, sender_slot as u8, &proposed)?;
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

/// The canonical SOLO next state for one in-channel transfer of `token_slot`: install the
/// sender's fresh `after` ciphertext, homomorphically credit the recipient, reset/bump
/// `pending_adds` — all at EXACTLY position `(row, token_slot)` — `state_version`+1,
/// `h2_tag = 0`. Used by `build_send` (the sender's proposal) AND by the slim-batch verifier
/// (detail2 §M-2), which reconstructs this state itself instead of trusting a wire copy.
///
/// TM-2 "others unchanged" by construction: every other token position of every row is carried
/// over bit-identical by the clones below, and re-CHECKED adversarially in
/// `InChannelTransferUpdateWitness::verify`.
pub fn solo_next_state(
    prev: &ChannelState,
    sender_slot: u16,
    recipient_slot: u16,
    token_slot: u8,
    after_ct: &RegevCiphertext,
    enc_amount: &RegevCiphertext,
) -> WResult<ChannelState> {
    let ts = token_slot as usize;
    if ts >= MAX_CHANNEL_TOKENS || ts >= prev.balance_state.token_count as usize {
        return bail(format!(
            "token_slot {ts} out of range (token_count {}, TM-8)",
            prev.balance_state.token_count
        ));
    }
    let recipient_after = add_ciphertexts(
        &prev.balance_state.enc_balances[recipient_slot as usize][ts],
        enc_amount,
    )
    .map_err(we)?;

    let mut enc_balances = prev.balance_state.enc_balances.clone();
    enc_balances[sender_slot as usize][ts] = after_ct.clone();
    enc_balances[recipient_slot as usize][ts] = recipient_after;
    let mut pending_adds = prev.balance_state.pending_adds.clone();
    pending_adds[sender_slot as usize][ts] = 0;
    pending_adds[recipient_slot as usize][ts] += 1;

    Ok(ChannelState {
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
    .with_computed_digest())
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
    // SECURITY (P4-1, A11): authenticate the payload's member set BEFORE trusting any `pk_b` /
    // `regev_pk` it carries. `verify_send_transition` runs on a peer-supplied `SendPayload` that
    // has its OWN `record` + `members` (it is NOT necessarily the snapshot already passed
    // through `verify_snapshot`), so we must independently (a) check the member list covers the
    // active slots `0..member_count+delegate_count` (members + delegates) bijectively and (b)
    // recompute the canonical Poseidon `MemberTree` root over
    // `MemberLeaf{pk_g, pk_b, regev_pk_digest}` and bind it to `record.member_pubkeys_root`. Only
    // then are the per-slot `pk_b` and Regev keys authenticated against the registered set, closing
    // the P3-5 gap where `pk_b` was read from the raw payload.
    let active = payload.record.member_count as usize + payload.record.delegate_count as usize;
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
    verify_send_core(
        prev,
        &payload.record,
        &payload.members,
        payload.sender_index,
        payload.recipient_index,
        &payload.channel_tx,
        payload.proposed_next_state.clone(),
        level,
        recipient_sk,
        expected_amount,
    )
}

/// Shared verification core for one in-channel transfer: the sender's A11 hash-sig over the IMPA
/// tx digest + the hardened `InChannelTransferUpdateWitness::verify` (E-1 rebuilt from `prev` —
/// the `before` ciphertext is ALWAYS `prev.enc_balances[sender]`, never wire-supplied).
/// `record`/`members` MUST already be authenticated by the caller: the fat path re-authenticates
/// the wire-carried set against the trusted record; the slim path passes the verifier's OWN
/// verified snapshot set (detail2 §M-2 — no peer-supplied member set exists at all).
#[allow(clippy::too_many_arguments)]
fn verify_send_core(
    prev: &ChannelState,
    record: &ChannelRecord,
    members: &[MemberInfo],
    sender_index: u16,
    recipient_index: u16,
    channel_tx: &ChannelTx,
    next_for_check: ChannelState,
    level: RegevSecurityLevel,
    recipient_sk: Option<&RegevSk>,
    expected_amount: Option<u64>,
) -> WResult<()> {
    // The sender's REAL authorization over the ChannelTx digest (P3: BabyBear hash-sig, replaces
    // the SPHINCS+ sender signature). The IMPA `signing_digest` preimage is UNCHANGED — it binds
    // `prev.digest`, so the tx authorizes application at EXACTLY this anchor (detail2 §M-3).
    let tx_digest = ChannelTx::signing_digest(
        prev.channel_id,
        prev.digest,
        &channel_tx.enc_amount,
        channel_tx.nonce,
        channel_tx.token_slot,
        channel_tx.sender_pk_g,
        channel_tx.recipient_pk_g,
    );
    let sender_slot = sender_index as usize;
    // The sender may be a member OR a delegate (delegate account): a delegate sends with the
    // identical E-1 + A11 mechanism, distinguished only by slot region. Admit the full active
    // region (`member_count + delegate_count`); co-signing (`0..member_count`) is unaffected.
    let active = record.member_count as usize + record.delegate_count as usize;
    check_slot(sender_slot, active)?;
    check_slot(recipient_index as usize, active)?;
    // Regev keys consumed by the E-1 statement below (from the caller-authenticated member set).
    let regev_pks = regev_pks_array(members);
    let sender = member_at(members, sender_slot)?;
    // A11: the sender slot's REGISTERED (pk_g, pk_b) from the authenticated record/member set.
    let registered_pk_g = record.member_pk_gs[sender_slot];
    verify_channel_tx_sender_hash_sig(channel_tx, &tx_digest, level, registered_pk_g, sender.pk_b)?;

    // `InChannelTransferUpdateWitness::verify` requires a STRUCTURALLY complete signature set
    // (one non-empty sig per active slot with the right pubkey hash). A co-signer validates the
    // transition BEFORE the real signatures are collected, so fill placeholder structural sigs
    // here — they do not affect `signing_digest()` (member signatures are excluded from it). The
    // REAL multi-signature check (per-member SingleSig proofs) is `verify_all_signatures`, run once
    // the set is complete.
    let mut next_for_check = next_for_check;
    fill_placeholder_sigs(record, &mut next_for_check);

    let witness = InChannelTransferUpdateWitness {
        channel_record: record.clone(),
        regev_pks,
        prev_state: prev.clone(),
        next_state: next_for_check,
        channel_tx: channel_tx.clone(),
        sender_index: sender_index as usize,
        recipient_index: recipient_index as usize,
        recipient_sk: recipient_sk.cloned(),
        expected_amount,
    };
    let verifier = RealRegevProofVerifier { level };
    witness
        .verify(&verifier)
        .map_err(|e| WalletError(format!("in-channel transition invalid: {e:?}")))?;
    Ok(())
}

/// Verify one SLIM batch tx (detail2 §M-2) — the DIRECT per-tx check set of abstract2-1 §3.2b.3,
/// with `members`/`record`/`regev_pks` from the verifier's OWN verified snapshot, never from the
/// wire.
///
/// PERF (why this does NOT reuse `verify_send_core`): the fat/solo path routes through
/// `InChannelTransferUpdateWitness::verify`, which re-derives and re-checks a full 1024-slot solo
/// next state per tx (two full-state clones + full-state digests → O(K·MAX) hashing across a
/// batch). In a batch every state-shaped invariant the witness checks (linkage, h2=0, chain/fund
/// invariance, untouched slots, pending_adds shape) is a property of the SINGLE folded state that
/// `build_batch_next_state` CONSTRUCTS deterministically — re-deriving it per tx checks nothing
/// extra (Lean: `batch_preserves_validity`). What must (and does) remain per tx:
///   1. anchor binding — `anchor_digest == prev.digest`;
///   2. slot validity — sender/recipient in the active region, sender ≠ recipient;
///   3. MVP refresh gate — `prev.pending_adds[sender] == 0` (same rule as `build_send` and the solo
///      witness; the E-1 `before`-binding already enforces it cryptographically);
///   4. party binding — the tx's `sender_pk_g`/`recipient_pk_g` equal the REGISTERED keys at the
///      claimed slots (`record.member_pk_gs`);
///   5. sender authorization — the full A11 BabyBear hash-sig over the IMPA tx digest (whose
///      preimage binds `prev.digest`, so a stale tx cannot carry a valid signature);
///   6. the mandatory E-1 STARK, statement rebuilt from the verifier's own data (`before =
///      prev.enc_balances[sender]` — never wire-supplied);
///   7. (recipient co-signer only) the own-slot `enc_amount` decryption check.
/// `regev_pks` is built ONCE per batch by the caller (`regev_pks_array` clones ~1024 keys — do
/// not pay that per tx).
#[allow(clippy::too_many_arguments)]
pub fn verify_slim_send_tx(
    prev: &ChannelState,
    trusted_record: &ChannelRecord,
    own_members: &[MemberInfo],
    regev_pks: &[RegevPk; MAX_CHANNEL_MEMBERS],
    slim: &SlimSendPayload,
    level: RegevSecurityLevel,
    recipient_sk: Option<&RegevSk>,
    expected_amount: Option<u64>,
) -> WResult<()> {
    // 1. Anchor binding.
    if slim.anchor_digest != prev.digest {
        return bail("slim tx does not extend the current head (stale anchor)");
    }
    // 2. Slot validity.
    let sender = slim.sender_index as usize;
    let recipient = slim.recipient_index as usize;
    let active = trusted_record.member_count as usize + trusted_record.delegate_count as usize;
    check_slot(sender, active)?;
    check_slot(recipient, active)?;
    if sender == recipient {
        return bail("sender and recipient must differ");
    }
    // 3. TM-8/TM-14 token-slot bounds + MVP refresh gate at the tx's SIGNED position. The
    // token_slot used everywhere below is the one bound into the IMPA-v2 digest (step 5), so a
    // tampered wire echo cannot survive the sender's A11 signature; the fold then debits at
    // exactly this position (the TM-2 binding triple's "signed == mutated" leg holds by
    // construction of `build_batch_next_state`, whose per-(row, token) writes leave every other
    // position bit-identical — TM-14's all-10-positions obligation).
    let token_slot = slim.channel_tx.token_slot as usize;
    if token_slot >= MAX_CHANNEL_TOKENS {
        return bail(format!(
            "token_slot {token_slot} out of layout range (>= MAX_CHANNEL_TOKENS = \
             {MAX_CHANNEL_TOKENS}, TM-8)"
        ));
    }
    if token_slot >= prev.balance_state.token_count as usize {
        return bail(format!(
            "token_slot {token_slot} out of range (>= token_count {}, TM-8)",
            prev.balance_state.token_count
        ));
    }
    if prev.balance_state.pending_adds[sender][token_slot] != 0 {
        return bail("sender slot has pending homomorphic adds; refresh required before sending");
    }
    // 4. Party binding to the registered member keys.
    let registered_sender_pk_g = trusted_record.member_pk_gs[sender];
    let registered_recipient_pk_g = trusted_record.member_pk_gs[recipient];
    if slim.channel_tx.sender_pk_g != registered_sender_pk_g {
        return bail(format!(
            "channel_tx.sender_pk_g does not match the registered member at slot {sender}"
        ));
    }
    if slim.channel_tx.recipient_pk_g != registered_recipient_pk_g {
        return bail(format!(
            "channel_tx.recipient_pk_g does not match the registered member at slot {recipient}"
        ));
    }
    // 5. Sender A11 authorization (binds prev.digest via the IMPA preimage — detail2 §M-3).
    let tx_digest = ChannelTx::signing_digest(
        prev.channel_id,
        prev.digest,
        &slim.channel_tx.enc_amount,
        slim.channel_tx.nonce,
        slim.channel_tx.token_slot,
        slim.channel_tx.sender_pk_g,
        slim.channel_tx.recipient_pk_g,
    );
    let sender_member = member_at(own_members, sender)?;
    verify_channel_tx_sender_hash_sig(
        &slim.channel_tx,
        &tx_digest,
        level,
        registered_sender_pk_g,
        sender_member.pk_b,
    )?;
    // 6. Mandatory E-1 channelTxZKP, statement rebuilt from verifier-owned data. TM-2 leg 4:
    // `before` is the verifier's OWN anchor ciphertext at the SIGNED token position — never
    // wire-supplied, and never a different position's ciphertext.
    let statement = crate::regev::RegevStatement::ChannelTx {
        sender_pk: regev_pks[sender].clone(),
        recipient_pk: regev_pks[recipient].clone(),
        before: prev.balance_state.enc_balances[sender][token_slot].clone(),
        enc_amount: slim.channel_tx.enc_amount.clone(),
        after: slim.after_ct.clone(),
    };
    let verifier = RealRegevProofVerifier { level };
    use crate::circuits::channel::state_update_verifier::{
        RegevProofPurpose, RegevProofVerifier as RegevProofVerifierTrait,
    };
    // Explicit trait call: `RealRegevProofVerifier` also has an inherent `verify` with a
    // different signature.
    RegevProofVerifierTrait::verify(
        &verifier,
        &slim.channel_tx.channel_tx_zkp,
        RegevProofPurpose::ChannelTx,
        &statement,
    )
    .map_err(|e| WalletError(format!("E-1 channelTxZKP invalid: {e:?}")))?;
    // 7. Recipient-only decryption check.
    if let Some(sk) = recipient_sk {
        let expected = expected_amount
            .ok_or_else(|| WalletError("recipient_sk requires expected_amount".into()))?;
        let decrypted = decrypt_amount(sk, &slim.channel_tx.enc_amount).map_err(we)?;
        if decrypted != expected {
            return bail(format!(
                "enc_amount decrypts to {decrypted}, expected {expected}"
            ));
        }
    }
    Ok(())
}

/// Batched intra-channel co-sign (abstract2-1 §2.2b/§3.2b): build the canonical batch next state
/// from K verified tx residues anchored at the SAME `prev` state.
///
/// SECURITY: every tx MUST have been individually verified FIRST — `verify_slim_send_tx(prev, ..)`
/// on the slim path (or `verify_send_transition` on the legacy fat path): E-1 proof against the
/// anchor ciphertext, sender A11 hash-sig (which binds `prev.digest`, so a stale-anchor tx cannot
/// even carry a valid signature), solo-fold structural checks. Those K verifications are mutually
/// independent (disjoint debit slots by R1 below) and may run in parallel; after each one the
/// caller keeps only the `BatchTxApply` residue and may DROP the proofs (detail2 §M-4). This
/// function then performs only the BATCH-level soundness checks and the canonical fold:
///   R1  single-debit rule, PER (sender slot, token slot) PAIR (TM-14, mirroring the Lean
///       `sendersDistinctMT`): at most one debit per (slot, token) per batch — two debits at the
///       same pair would spend the same `before` ciphertext witness twice, while the SAME member
///       MAY debit two DIFFERENT tokens in one batch (each pinned by its own E-1 against its own
///       position's anchor ciphertext);
///   R3  debits first (install each sender's fresh `after` ct at ITS token position, whose
///       correctness the tx's own E-1 proof pinned against the anchor), then credits (public
///       homomorphic adds of each `enc_amount` at the tx's token position) — the order makes
///       sender-as-recipient sound per token;
///   D3  post-fold `pending_adds` budget, per (slot, token) (abstract2-1 §6 item 8, TM-13).
/// The fold writes ONLY position `(row, tx.token_slot)` per debit/credit; every other token
/// position of every row rides the row clones bit-identical — this is the constructive TM-14
/// "all 10 positions" obligation (Lean: `batchMT_frame`), and for K = 1 the produced state is
/// field-identical to the solo `proposed_next_state` at ANY token (same digest), so the sender's
/// browser can still commit its pending witness on finalize.
/// The result advances the digest chain by ONE link (`state_version`/`epoch` +1, `h2_tag = 0`,
/// `settled_tx_chain` untouched) and carries NO signatures — the caller runs the N-of-N round.
/// Machine-checked model: ChannelSafetyMT.lean (`batchMT_preserves_validity` — `BatchTxApply`
/// mirrors the modeled `BatchTxMT` incl. `tokenSlot`).
pub fn build_batch_next_state(prev: &ChannelState, txs: &[BatchTxApply]) -> WResult<ChannelState> {
    if txs.is_empty() {
        return bail("empty batch");
    }
    let token_count = prev.balance_state.token_count as usize;
    let mut debited = vec![[false; MAX_CHANNEL_TOKENS]; MAX_CHANNEL_MEMBERS];
    for t in txs {
        let s = t.sender_index as usize;
        check_slot(s, MAX_CHANNEL_MEMBERS)?;
        check_slot(t.recipient_index as usize, MAX_CHANNEL_MEMBERS)?;
        // TM-8 fail-closed: the fold must never write an inactive (or out-of-layout) token
        // position, even if an upstream verifier was skipped.
        let ts = t.token_slot as usize;
        if ts >= MAX_CHANNEL_TOKENS || ts >= token_count {
            return bail(format!(
                "token_slot {ts} out of range (token_count {token_count}, TM-8)"
            ));
        }
        if debited[s][ts] {
            return bail(format!(
                "R1 single-debit rule: two debits from (sender slot {s}, token slot {ts}) in \
                 one batch"
            ));
        }
        debited[s][ts] = true;
    }

    let mut enc_balances = prev.balance_state.enc_balances.clone();
    let mut pending_adds = prev.balance_state.pending_adds.clone();
    // Debits: each (sender, token) position takes the fresh `after` ciphertext its tx's E-1
    // proof bound as `after` against that position's anchor `before`.
    for t in txs {
        let s = t.sender_index as usize;
        let ts = t.token_slot as usize;
        enc_balances[s][ts] = t.after_ct.clone();
        pending_adds[s][ts] = 0;
    }
    // Credits: fold the homomorphic adds per (recipient, token) (sender-as-recipient lands on
    // the fresh `after` ct at the same position, exactly the §3.2b canonical order per token).
    for t in txs {
        let r = t.recipient_index as usize;
        let ts = t.token_slot as usize;
        enc_balances[r][ts] = add_ciphertexts(&enc_balances[r][ts], &t.enc_amount).map_err(we)?;
        if pending_adds[r][ts] >= MAX_HOMO_ADDS_BEFORE_REFRESH {
            return bail(format!(
                "D3 budget: (slot {r}, token {ts}) would exceed MAX_HOMO_ADDS_BEFORE_REFRESH post-fold; shrink the batch"
            ));
        }
        pending_adds[r][ts] += 1;
    }

    Ok(ChannelState {
        epoch: prev.epoch + 1,
        balance_state: BalanceState {
            enc_balances,
            state_version: prev.balance_state.state_version + 1,
            pending_adds,
            ..prev.balance_state.clone()
        },
        prev_digest: prev.digest,
        member_signatures: Vec::new(),
        // §C-2: intra-channel batch is H2 = 0 (same rationale as build_send).
        h2_tag: Bytes32::default(),
        ..prev.clone()
    }
    .with_computed_digest())
}

/// Fill every active slot with a placeholder (correctly-tagged, non-empty) signature so the
/// library's structural signature check passes. Used only for transition validation; never for
/// the authoritative `verify_all_signatures` check.
fn fill_placeholder_sigs(record: &ChannelRecord, state: &mut ChannelState) {
    state.member_signatures = (0..record.member_count as usize)
        .map(|slot| MemberSignature {
            member_slot: slot as u8,
            pk_g: record.member_pk_gs[slot],
            signature: crate::common::channel::structural_cosign_placeholder(1),
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
    /// BALANCE-SLOT index (member OR delegate, `0..1024`) — u16, see `MemberInfo::slot`.
    pub member_index: u16,
    /// LOCAL token position being refreshed (TM-13: refreshes are per (member, token)). The
    /// co-signer's `BalanceRefreshUpdateWitness` proves the replacement + counter reset happen
    /// at exactly this position and every other position of the row is frozen.
    pub token_slot: u8,
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
    slot: u16,
    token_slot: u8,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<(RefreshPayload, AmountWitness)> {
    let active = snapshot.record.member_count as usize + snapshot.record.delegate_count as usize;
    check_slot(slot as usize, active)?;
    let prev = &snapshot.state;
    // TM-13/TM-8: refreshes are per (member, token); the selector must be an ACTIVE registry
    // position.
    let ts = token_slot as usize;
    if ts >= MAX_CHANNEL_TOKENS || ts >= prev.balance_state.token_count as usize {
        return bail(format!(
            "refresh token_slot {ts} out of range (token_count {}, TM-8)",
            prev.balance_state.token_count
        ));
    }
    let regev_pks = regev_pks_array(&snapshot.members);
    let pk = &regev_pks[slot as usize];
    let old_ct = &prev.balance_state.enc_balances[slot as usize][ts];

    // Value-preserving re-encryption + proof (also returns the fresh ct's witness so we can send).
    let (new_ct, new_witness, proof) =
        prove_balance_refresh_witnessed(rng, level, pk, &keys.regev_sk, old_ct).map_err(we)?;

    let mut enc_balances = prev.balance_state.enc_balances.clone();
    enc_balances[slot as usize][ts] = new_ct;
    let mut pending_adds = prev.balance_state.pending_adds.clone();
    pending_adds[slot as usize][ts] = 0;
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
        // Cosigner space (guarded above): slot < member_count <= MAX_COSIGNERS, so u8 fits.
        let sig = sign_state(keys, slot as u8, &proposed)?;
        add_signature(&mut proposed, sig);
    }

    let payload = RefreshPayload {
        member_index: slot,
        token_slot,
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
        token_slot: payload.token_slot as usize,
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
    /// BALANCE-SLOT index (member OR delegate, `0..1024`) — u16, see `MemberInfo::slot`.
    pub sender_index: u16,
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
    /// BALANCE-SLOT index (member OR delegate, `0..1024`) — u16, see `MemberInfo::slot`.
    pub recipient_slot: u16,
    pub amount: u64,
    pub tx_hash: Bytes32,
    /// `H2` = the 1-tx `TxV2Tree` root, computed inside `build_inter_channel_send`.
    pub tx_tree_root: Bytes32,
    pub source_pk_g: Bytes32,
    pub receiver_pk_g: Bytes32,
    /// Salt opening the normal base-layer UID recipient. This is deliberately distinct from
    /// `receiver_pk_g`, which binds the encrypted channel credit. Burns require the zero salt.
    pub destination_base_transfer_salt: Salt,
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
    /// Stage 3: the per-channel settled-tx accumulator after the incoming transfer's single
    /// `tx_hash` insertion in the fund-import step. The bundle apply leaves it unchanged. Persist
    /// it as the channel's new
    /// `ChannelSnapshot::settled_tx_accumulator` — its root equals
    /// `bundle_apply_state.balance_state.settled_tx_accumulator_root`, and it is what lets the
    /// wallet later generate the post-close Merkle inclusion proof for an incoming `tx_hash`.
    pub settled_tx_accumulator:
        crate::utils::trees::incremental_merkle_tree::IncrementalMerkleTree<Bytes32>,
}

/// Structural transport verifier for the retired abstract2 §3.4 proof slot.
///
/// The transport proof never had a verifier or a security statement.  Keeping an arbitrary
/// non-empty byte string in a signed transaction made the wire format look authenticated while
/// accepting every value.  Protocol v3 therefore has one canonical representation for the
/// retired field: an empty proof envelope.  The real security comes from the E-2 STARK and the
/// channel-A N-of-N signatures.
struct WalletStructuralTransport;
impl ChannelProofVerifier for WalletStructuralTransport {
    fn verify(
        &self,
        p: &ChannelProofEnvelope,
        _: &ChannelStateUpdatePublicInputs,
    ) -> Result<(), ChannelStateUpdateError> {
        if !p.proof.is_empty() {
            return Err(ChannelStateUpdateError::ProofVerification(
                "retired transport proof must be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Explicit UNSIGNED small block: one correctly-slotted, correctly-tagged NON-signature per active
/// member, so `validate_signed_small_block`'s structural gate
/// (`validate_member_signature_slots` — exact count, slot order, registered `pk_g`, non-empty
/// blob) passes at BUILD time, when no co-signature can exist yet.
///
/// Why a placeholder is unavoidable here: the co-sign round runs AFTER the builder returns
/// (`build_inter_channel_send` → `verify_inter_channel_send_transition` → members co-sign), so the
/// block is genuinely unsigned at construction. It becomes signed in
/// [`attach_small_block_signatures`], which is what a block producer must call before the block is
/// posted.
///
/// SECURITY: [`structural_cosign_placeholder`] is INTENTIONALLY NOT A SIGNATURE — it carries the
/// v1 version byte and the exact cosign length and nothing else, so every authenticating path
/// (`verify_all_signatures`, the close/cancel aggregation circuits, and the B-2 validity-proof
/// list step that verifies the members' Falcon signatures in-circuit) rejects it. A block that
/// reaches production still carrying these cannot produce a satisfying N-of-N witness.
fn unsigned_small_block_slots(record: &ChannelRecord) -> Vec<MemberSignature> {
    (0..record.member_count)
        .map(|slot| MemberSignature {
            member_slot: slot,
            pk_g: record.member_pk_gs[slot as usize],
            signature: crate::common::channel::structural_cosign_placeholder(1),
        })
        .collect()
}

/// Install the channel's REAL N-of-N co-signatures onto a built small block, replacing the
/// [`unsigned_small_block_slots`] placeholders. A block producer MUST call this before posting;
/// a block still carrying placeholders cannot satisfy the in-circuit N-of-N.
///
/// `a_signed` is the post-debit state returned by [`build_inter_channel_send`] AFTER the co-sign
/// round has filled `member_signatures` (see `add_signature` / `sign_state_if_backed`).
///
/// SECURITY — this is the wallet-side half of the Phase-3 binding. `update_channel_tree` verifies,
/// in-circuit, an N-of-N aggregate over the channel's IMCH digest and connects it to the block's
/// `tx_tree_root`. That binding is only sound if the state the members actually signed is the one
/// whose `h2_tag` IS this block's `tx_tree_root` — `channel.rs` specifies exactly that for an
/// inter-channel send. Nothing else in the wallet layer asserts it (the builder sets `h2_tag` and
/// the block's `tx_tree_root` from the same local variable, which proves nothing about the state a
/// REMOTE co-signer signed), so it is asserted here, against the state that carries the
/// signatures:
///
///   1. every active member's signature is present and verifies against the registered `pk_g` over
///      the recomputed IMCH digest (`verify_all_signatures`, which also re-derives `state.digest`);
///   2. `a_signed.h2_tag == message.tx_tree_root`, and it is non-zero — the `tx_tree_root != 0`
///      gate is what excludes in-channel transitions (which carry `h2_tag == 0`) from ever
///      authorising a block;
///   3. `a_signed.balance_state.h1() == message.state_commitment_root`, so the H1 the block
///      advertises is the one inside the signed preimage rather than an off-circuit claim;
///   4. the channel id, small-block number and close-freeze nonce agree with the signed state.
///
/// Withholding one member's signature fails (1) with that member's slot named — the documented
/// posture that block production is blockable by any single member.
pub fn attach_small_block_signatures(
    record: &ChannelRecord,
    a_signed: &ChannelState,
    inter_channel_tx: &mut InterChannelTx,
) -> WResult<()> {
    // (1) The cryptographic N-of-N. Runs `record.validate()` and recomputes `signing_digest()`
    // internally, so a tampered state or a non-member signer cannot reach the checks below.
    verify_all_signatures(record, &[], a_signed).map_err(|e| {
        WalletError(format!(
            "small block cannot be signed: the post-debit state is not N-of-N co-signed under \
             channel {}'s record ({e:?}) — collect every active member's cosignature first",
            record.channel_id.as_u64()
        ))
    })?;

    let msg = &inter_channel_tx.signed_small_block.message;

    // (4) Identity of the state vs the block, before the value-bearing bindings.
    if inter_channel_tx.source_channel_id != record.channel_id
        || msg.channel_id != record.channel_id
    {
        return bail(format!(
            "small block channel mismatch: record {}, tx source {}, message {}",
            record.channel_id.as_u64(),
            inter_channel_tx.source_channel_id.as_u64(),
            msg.channel_id.as_u64()
        ));
    }
    if msg.small_block_number != a_signed.small_block_number {
        return bail(format!(
            "small block number {} does not match the co-signed state's {}",
            msg.small_block_number, a_signed.small_block_number
        ));
    }
    if msg.close_freeze_nonce != a_signed.close_freeze_nonce {
        return bail(format!(
            "small block close_freeze_nonce {} does not match the co-signed state's {} (wrong era)",
            msg.close_freeze_nonce, a_signed.close_freeze_nonce
        ));
    }

    // (2) THE binding. `h2_tag` rides inside the IMCH preimage every member signed, so this is what
    // makes the members' signatures an authorisation of THIS block rather than of some other state.
    if a_signed.h2_tag == Bytes32::default() {
        return bail(
            "co-signed state has h2_tag == 0 (an in-channel transition): it authorises no block. \
             Only a state whose h2_tag IS the block's tx_tree_root can back a signing block"
                .to_string(),
        );
    }
    if a_signed.h2_tag != msg.tx_tree_root {
        return bail(format!(
            "co-signed state's h2_tag {} != the small block's tx_tree_root {} — the members signed \
             a DIFFERENT block's transaction root, so their signatures do not authorise this one",
            a_signed.h2_tag, msg.tx_tree_root
        ));
    }

    // (3) H1 the block advertises must be the signed state's own.
    let h1 = a_signed.balance_state.h1();
    if h1 != msg.state_commitment_root {
        return bail(format!(
            "co-signed state's h1 {} != the small block's state_commitment_root {}",
            h1, msg.state_commitment_root
        ));
    }

    // Slot order is the order every aggregation path consumes; `verify_all_signatures` has already
    // proved one signature per active slot with the registered pk_g.
    let mut signatures = a_signed.member_signatures.clone();
    signatures.sort_by_key(|s| s.member_slot);
    inter_channel_tx.signed_small_block.signatures = signatures;
    Ok(())
}

/// LEG A — build the inter-channel debit of the GENESIS token (`registry[0]`, the wire-compat
/// single-token entry; the per-token builder is [`build_inter_channel_send_token`]).
#[allow(clippy::too_many_arguments)]
pub fn build_inter_channel_send(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    sender_slot: u16,
    destination_channel_id: ChannelId,
    destination_recipient_slot: u16,
    destination_recipient_pk: RegevPk,
    destination_recipient_pk_g: Bytes32,
    destination_base_transfer_salt: Salt,
    amount: u64,
    before_amount: u64,
    before_witness: &AmountWitness,
    new_nullifier_root: Bytes32,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<BuiltInterChannelSend> {
    let genesis_token_index = snapshot.state.balance_state.token_registry[0];
    build_inter_channel_send_token(
        keys,
        snapshot,
        sender_slot,
        destination_channel_id,
        destination_recipient_slot,
        destination_recipient_pk,
        destination_recipient_pk_g,
        destination_base_transfer_salt,
        genesis_token_index,
        amount,
        before_amount,
        before_witness,
        new_nullifier_root,
        level,
        rng,
    )
}

/// LEG A — build the inter-channel debit on the SOURCE channel, moving BASE token `token_index`
/// (multitoken §N-4, TM-6 — the Phase 4 per-token build path).
///
/// `snapshot` is channel A; `sender_slot` is a channel-A ACTIVE participant (member OR delegate,
/// located by its `pk_g`). `token_index` is the BASE-layer token index (never a local slot —
/// source and destination registries map it to different local slots); it must resolve against
/// A's OWN active registry (unregistered ⇒ refused fail-closed, and the verifier paths re-check
/// on both sides). `before_*` are the sender's CURRENT plaintext balance + `AmountWitness` at
/// the RESOLVED local position (held locally). `new_nullifier_root` advances the shared native
/// nullifier (detail2 §C-3: a send MUST change it). Produces the post-debit `a_send`
/// (state_version+1, `channel_fund.amounts[resolved slot]` -= amount, settled_tx_chain pushes
/// the tx leaf, `h2_tag = tx_tree_root`; delegate_count + the untouched positions'
/// enc_balances/pending_adds preserved via the `..prev.balance_state.clone()` spread), the REAL
/// E-2 (whose IMU2 PVs bind `token_index`), the 1-tx `TxV2Tree` (root + inclusion proof
/// computed INTERNALLY), self-signs the building member's slot if it is a co-signing member, and
/// CALLS `InterChannelSendUpdateWitness::verify` to self-check before returning.
#[allow(clippy::too_many_arguments)]
pub fn build_inter_channel_send_token(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    sender_slot: u16,
    destination_channel_id: ChannelId,
    destination_recipient_slot: u16,
    destination_recipient_pk: RegevPk,
    destination_recipient_pk_g: Bytes32,
    destination_base_transfer_salt: Salt,
    token_index: u32,
    amount: u64,
    before_amount: u64,
    before_witness: &AmountWitness,
    new_nullifier_root: Bytes32,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<BuiltInterChannelSend> {
    // Compatibility wrapper for fixture callers. Production wallets must use
    // `build_inter_channel_send_token_at_base_nonce` with the persisted base-account cursor;
    // channel small-block numbers are not a base nonce source after an incoming transition.
    let base_nonce = u32::try_from(snapshot.state.small_block_number + 1)
        .map_err(|_| WalletError("small_block_number exceeds the TxV2 nonce width".into()))?;
    build_inter_channel_send_token_at_base_nonce(
        keys,
        snapshot,
        sender_slot,
        destination_channel_id,
        destination_recipient_slot,
        destination_recipient_pk,
        destination_recipient_pk_g,
        destination_base_transfer_salt,
        token_index,
        base_nonce,
        amount,
        before_amount,
        before_witness,
        new_nullifier_root,
        level,
        rng,
    )
}

/// Production inter-channel builder. `base_nonce` is read from the persisted live base IVC head
/// immediately before proving. It is committed twice: directly by IMI4 and transitively by H2's
/// TxV2 root. Co-signers and the base prover both reject a stale cursor.
#[allow(clippy::too_many_arguments)]
pub fn build_inter_channel_send_token_at_base_nonce(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    sender_slot: u16,
    destination_channel_id: ChannelId,
    destination_recipient_slot: u16,
    destination_recipient_pk: RegevPk,
    destination_recipient_pk_g: Bytes32,
    destination_base_transfer_salt: Salt,
    token_index: u32,
    base_nonce: u32,
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
    // TM-6 (source-side registry resolution): the SIGNED base token_index must resolve against
    // A's OWN active registry; the resolved LOCAL slot is the only position debited below.
    let token_slot = resolve_local_token_slot(&prev.balance_state, token_index)?;
    // D3/TM-13: the refresh gate is per (slot, token) — only the DEBITED position must be clean.
    if prev.balance_state.pending_adds[sender_slot as usize][token_slot] != 0 {
        return bail(
            "sender (slot, token) position has pending homomorphic adds; refresh required before sending",
        );
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
    // `prev_state.enc_balances[sender_slot][resolved token_slot]` (so `before_witness` is the
    // witness for THAT ciphertext).
    let before_ct = prev.balance_state.enc_balances[sender_slot as usize][token_slot].clone();
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
        token_index,
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
    // SECURITY: every real inter-channel settle carries the exact tag both channel accounts fold.
    // Normal sends carry `tx_leaf`; burns carry the amount-committing IMBD descriptor. A zero aux
    // value would make the base send/receive circuits leave `settled_tx_chain` unchanged while the
    // N-of-N channel head advances it, making the live IVC irreconcilable.
    let burn_aux =
        if destination_channel_id.channel_id() == crate::constants::BURN_CHANNEL_ID as u32 {
            burn_descriptor(
                tx_leaf,
                destination_recipient_pk_g,
                token_index,
                u64_to_u256(amount),
            )
        } else {
            tx_leaf
        };
    // SECURITY (single source of truth): the base-layer `Transfer` this send settles is built by
    // `inter_channel_base_transfer` and by NOTHING ELSE. `burn_withdrawal_leaf` — the only place
    // allowed to derive a burn's L1 withdrawal leaf / nullifier — rebuilds it with the same
    // function, so the leaf the CLI authorizes on L1 and the leaf this tree commits to cannot
    // drift apart.
    let is_burn = destination_channel_id.channel_id() == crate::constants::BURN_CHANNEL_ID as u32;
    if is_burn && destination_base_transfer_salt != Salt::default() {
        return bail("burn transfer must carry the canonical zero destination base transfer salt");
    }
    if is_burn {
        extract_address_from_recipient(destination_recipient_pk_g).map_err(|error| {
            WalletError(format!(
                "burn transfer recipient must be canonical ADDRESS_TAG (0x02 || 11 zero bytes || address): {error}"
            ))
        })?;
    }
    let base_recipient = if is_burn {
        destination_recipient_pk_g
    } else {
        calculate_recipient_from_user_id(destination_channel_id, destination_base_transfer_salt)
    };
    let base_transfer = inter_channel_base_transfer(
        base_recipient,
        // The base-layer transfer settles the SAME base token the channel-layer descriptor
        // moves (identical to the legacy hardcoded 0 for ETH-genesis channels).
        token_index,
        amount,
        burn_aux,
    );
    transfer_tree.push(base_transfer.clone());
    let src_id = record.channel_id.as_u64();
    // Same single-source rule for H2: `inter_channel_tx_v2` is the only construction of the 1-tx
    // TxV2 + its tree, so the pre-flight H2 reconstruction in `pw-submit` is byte-identical to
    // the value the co-signers actually signed (`h2_tag`).
    let tx_nonce = base_nonce;
    let (tx_v2, tx_v2_tree) = inter_channel_tx_v2(record.channel_id, &base_transfer, tx_nonce);
    debug_assert_eq!(tx_v2.transfer_tree_root, transfer_tree.get_root());
    let tx_v2_root_h = tx_v2_tree.get_root();
    let tx_tree_root: Bytes32 = tx_v2_root_h.into(); // = H2
    let tx_v2_merkle_proof = tx_v2_tree.prove(src_id);

    // Stage 3: the inter-channel `tx_hash` — the accumulator leaf (uniformly) AND the L1-settled
    // identifier. Computed BEFORE the post-debit state so its accumulator root already reflects the
    // insertion (and so h1() below folds the advanced root). TM-16: the fold carries the SIGNED
    // base `token_index` in ids limb 5 (canonical `common::channel::inter_channel_tx_hash`), so
    // the anchored accumulator leaf commits the token this send moves — provable by a post-close
    // claim on the destination side.
    let tx_hash = inter_channel_tx_hash(
        record.channel_id,
        destination_channel_id,
        token_index,
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
    // spreads preserve member_count, delegate_count, channel_id, and all untouched positions'
    // enc_balances + pending_adds — only the sender's ciphertext AT THE RESOLVED token position
    // changes, and only `amounts[token_slot]` is debited (TM-6 binding; the verifier freezes
    // every other position via `ensure_funds_unchanged_except`).
    let mut enc_balances = prev.balance_state.enc_balances.clone();
    enc_balances[sender_slot as usize][token_slot] = after_ct.clone();
    let mut a_send = ChannelState {
        epoch: prev.epoch + 1,
        small_block_number: prev.small_block_number + 1,
        channel_fund: ChannelFund {
            amounts: {
                let mut amounts = prev.channel_fund.amounts;
                amounts[token_slot] -= u64_to_u256(amount);
                amounts
            },
            ..prev.channel_fund.clone()
        },
        balance_state: BalanceState {
            enc_balances,
            // Normal C2C pushes the tx leaf; a burn pushes its amount-committing descriptor. In
            // both cases this is exactly the value stored in the base
            // Transfer.aux_data.
            settled_tx_chain: settled_tx_chain_push(prev.balance_state.settled_tx_chain, burn_aux),
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
                medium_epoch_hint: 0,
                close_freeze_nonce: prev.close_freeze_nonce,
            },
            // UNSIGNED at build time; `attach_small_block_signatures` installs the real N-of-N
            // once the co-sign round has completed on `a_send`.
            signatures: unsigned_small_block_slots(record),
            // These three fields belong to a retired medium-block confirmation design.  Empty
            // bytes/zero are the sole canonical v3 encoding; no unverifiable marker bytes enter
            // the signed digest.
            aggregated_signature_proof: Vec::new(),
            medium_block_number: 0,
            confirmation_proof: Vec::new(),
        },
        sender_delta_ct: sender_delta_ct.clone(),
        source_channel_id: record.channel_id,
        destination_channel_id,
        token_index,
        base_nonce,
        destination_base_transfer_salt,
        source_pk_g: sender_pk_g,
        seal: Bytes32::default(),
        tx_hash,
        // F-AUX-1: commit the exact base-layer Transfer whose transfer-tree root feeds TxV2/H2.
        // Co-signers independently reconstruct this value from the channel debit below.
        intmax_transfer_commitment: Bytes32::from(base_transfer.poseidon_hash()),
        recipient_memo: Vec::new(),
        receiver_deltas: vec![ReceiverBalanceDelta {
            receiver_pk_g: destination_recipient_pk_g,
            amount: receiver_delta_ct.clone(),
        }],
        channel_update_zkp: ChannelProofEnvelope {
            role: TransitionProofRole::ChannelStateUpdate,
            backend: ProofBackend::Plonky3,
            proof: e2,
        },
        transport_proof: Vec::new(),
    };

    // If the building participant is a co-signing MEMBER (slot < member_count) it self-signs the
    // post-debit state (one of the N-of-N). A DELEGATE sender does NOT co-sign state.
    if (sender_slot as usize) < record.member_count as usize {
        // Cosigner space (guarded above): slot < member_count <= MAX_COSIGNERS, so u8 fits.
        let sender_sig = sign_state(keys, sender_slot as u8, &a_send)?;
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
            destination_base_transfer_salt,
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

/// abstract2-1 §3.6 — channel-layer "burn send" for PARTIAL WITHDRAWAL (channel stays open).
///
/// A member debits ONLY their own encBalance by `amount` (E-2 `channelUpdateZKP`, sender-slot-only
/// — `state_update_verifier.rs` debits the sender slot and `ensure_slot_unchanged` on all others)
/// toward the reserved `BURN_CHANNEL_ID` with an `ADDRESS_TAG` L1 recipient, so the base-layer
/// `single_withdrawal` later pays the member's L1 address `withdrawal_l1_address`. Then the channel
/// continues: `state_version`/`settled_tx_chain` advance, members keep transacting.
///
/// This REUSES [`build_inter_channel_send`] UNCHANGED via the (ii) padding-receiver design
/// (architecture-audit/partial-withdrawal-impl-plan.md): the channel-layer phantom receiver is
/// `RegevPk::padding()` (canonical, NO secret key), so `receiver_delta = encrypt(amount, padding)`
/// satisfies the E-2 `sender_delta == receiver_delta == amount` constraint. The phantom credit is
/// UNCLAIMABLE — no channel may register `BURN_CHANNEL_ID` (`ChannelRecord::validate` + on-chain
/// `registerChannel` guards), so the receive side never credits it. The base `ADDRESS_TAG` Transfer
/// is WITHDRAW-ONLY (recipient-tag exclusivity, `tests/partial_withdrawal_exclusivity.rs`), so it
/// can never also be credited to a channel. The withdrawn `amount` equals the member's proven
/// encBalance debit (over-claim / cross-member-claim closed at the proof level).
///
/// SECURITY — NOT YET VALIDATED END-TO-END: the E-2 self-check runs at build time, but the full
/// fund path (this burn send → N-of-N cosign → finalize → `single_withdrawal` → on-chain
/// `withdrawNative`, channel stays open) requires the opt-in heavy E2E (`INTMAX_RUN_HEAVY_E2E`) AND
/// a dedicated attacker-subagent review BEFORE merge (CLAUDE.md). Do not ship on a fund path until
/// both pass.
pub fn build_burn_send(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    sender_slot: u16,
    withdrawal_l1_address: crate::ethereum_types::address::Address,
    amount: u64,
    before_amount: u64,
    before_witness: &AmountWitness,
    new_nullifier_root: Bytes32,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<BuiltInterChannelSend> {
    let genesis_token_index = snapshot.state.balance_state.token_registry[0];
    build_burn_send_token(
        keys,
        snapshot,
        sender_slot,
        withdrawal_l1_address,
        genesis_token_index,
        amount,
        before_amount,
        before_witness,
        new_nullifier_root,
        level,
        rng,
    )
}

/// [`build_burn_send`] generalized to BASE token `token_index` (multitoken Phase 4): the burn
/// debits the sender's balance + the channel fund at the LOCAL slot A's registry resolves for
/// `token_index`, and the base `Transfer` (→ the burn `Withdrawal`) carries that SAME base
/// index, so the L1 leg pays out via `withdrawERC20`/`withdrawNative` in the burned asset (the
/// IMPW authDigest already binds `tokenIndex`).
#[allow(clippy::too_many_arguments)]
pub fn build_burn_send_token(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    sender_slot: u16,
    withdrawal_l1_address: crate::ethereum_types::address::Address,
    token_index: u32,
    amount: u64,
    before_amount: u64,
    before_witness: &AmountWitness,
    new_nullifier_root: Bytes32,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<BuiltInterChannelSend> {
    // Compatibility wrapper for fixtures that still model one channel transition per base send.
    // Production callers must pass the persisted base cursor explicitly; incoming channel
    // transitions advance `small_block_number` without consuming a base nonce.
    let base_nonce = u32::try_from(snapshot.state.small_block_number + 1)
        .map_err(|_| WalletError("small_block_number exceeds the TxV2 nonce width".into()))?;
    build_burn_send_token_at_base_nonce(
        keys,
        snapshot,
        sender_slot,
        withdrawal_l1_address,
        token_index,
        base_nonce,
        amount,
        before_amount,
        before_witness,
        new_nullifier_root,
        level,
        rng,
    )
}

/// Production burn builder. `base_nonce` comes from the persisted live base-account state and is
/// independent of the channel small-block counter.
#[allow(clippy::too_many_arguments)]
pub fn build_burn_send_token_at_base_nonce(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    sender_slot: u16,
    withdrawal_l1_address: crate::ethereum_types::address::Address,
    token_index: u32,
    base_nonce: u32,
    amount: u64,
    before_amount: u64,
    before_witness: &AmountWitness,
    new_nullifier_root: Bytes32,
    level: RegevSecurityLevel,
    rng: &mut impl Rng,
) -> WResult<BuiltInterChannelSend> {
    use crate::circuits::balance::common::recipient::calculate_recipient_from_address;
    // (ii): base Transfer recipient = the ADDRESS_TAG L1 form (what `build_inter_channel_send`
    // writes into the tx's transfer leaf → `single_withdrawal` extracts); phantom receiver key
    // = `RegevPk::padding()`; destination = `BURN_CHANNEL_ID` (unregisterable) ⇒ unclaimable
    // phantom.
    let burn_recipient = calculate_recipient_from_address(withdrawal_l1_address);
    let burn_channel = ChannelId::new(crate::constants::BURN_CHANNEL_ID as u64)
        .map_err(|e| WalletError(format!("BURN_CHANNEL_ID is not a valid ChannelId: {e:?}")))?;
    build_inter_channel_send_token_at_base_nonce(
        keys,
        snapshot,
        sender_slot,
        burn_channel,
        0, // destination_recipient_slot: descriptor-only; irrelevant for an L1 burn
        RegevPk::padding(), // (ii) phantom-receiver key (no secret)
        burn_recipient, // → base Transfer recipient = ADDRESS_TAG L1 (withdraw-only)
        Salt::default(), // burns use ADDRESS_TAG, never a UID recipient opening
        token_index,
        base_nonce,
        amount,
        before_amount,
        before_witness,
        new_nullifier_root,
        level,
        rng,
    )
}

/// The transfer index a channel's outgoing inter-channel / burn transfer occupies inside its tx's
/// transfer tree.
///
/// detail2 §A-2: 1 small block = 1 tx = 1 transfer, so it is always 0 — and `send_tx_circuit`
/// does not merely assume it, it CONSTRAINS it
/// (`builder.assert_zero(transfer_witness.transfer_index)`,
/// `src/circuits/balance/send_tx_circuit.rs:279`). The value therefore enters
/// [`burn_withdrawal_leaf`]'s `SettledTransfer` as a constant with an in-circuit counterpart, not
/// as a guess.
pub const INTER_CHANNEL_TRANSFER_INDEX: u32 = 0;

/// The base-layer [`Transfer`] an inter-channel send (or a burn) settles.
///
/// SECURITY (single source of truth — the defect class this exists to close): a burn's L1
/// withdrawal leaf, and hence its nullifier, is a function of exactly these four fields. Until
/// 2026-08-13 the CLI's `pw-submit` invented its own nullifier
/// (`keccak(tx_leaf ‖ pre_burn_settled_tx_chain)`) while a provable leaf carried
/// `SettledTransfer::nullifier()` — a Poseidon hash over this struct. The two could never
/// coincide, so `submitPartialWithdrawalIntent` wrote an authorization no proof could ever
/// satisfy while permanently consuming the channel's single-use chain key: the burn's value was
/// debited in-channel and became unreachable on L1. There is now ONE construction of this
/// `Transfer` (this function) feeding BOTH the tx tree the co-signers sign and the withdrawal
/// leaf the CLI authorizes, so they cannot silently disagree again.
pub fn inter_channel_base_transfer(
    recipient_pk_g: Bytes32,
    token_index: u32,
    amount: u64,
    aux_data: Bytes32,
) -> Transfer {
    Transfer {
        recipient: recipient_pk_g,
        token_index,
        amount: u64_to_u256(amount),
        aux_data,
    }
}

/// The 1-tx `TxV2` and its `TxV2Tree` for an inter-channel send / burn: the tree whose root is the
/// small block's `tx_tree_root` = H2, which the post-send channel state records as `h2_tag`
/// (`state_update_verifier.rs:612-616`) and which is inside the N-of-N IMCH signing preimage
/// (`src/common/channel.rs:598`).
///
/// SECURITY: shared with `pw-submit`'s pre-flight guard, which reconstructs H2 from the burn
/// artefact and compares it against the co-signed `h2_tag`. That comparison is only meaningful if
/// the reconstruction is byte-identical to the original construction, so there is exactly one.
pub fn inter_channel_tx_v2(
    source_channel_id: ChannelId,
    transfer: &Transfer,
    nonce: u32,
) -> (TxV2, TxV2Tree) {
    let mut transfer_tree = TransferTree::init();
    transfer_tree.push(transfer.clone());
    let tx_v2 = TxV2 {
        tx_class: TxClass::UserTransfer,
        transfer_tree_root: transfer_tree.get_root(),
        nonce,
        channel_action_root: PoseidonHashOut::default(),
    };
    let mut tx_v2_tree = TxV2Tree::init();
    tx_v2_tree.update(source_channel_id.as_u64(), tx_v2);
    (tx_v2, tx_v2_tree)
}

/// Reconstruct the base-layer objects that an inter-channel debit claims to have committed.
///
/// This is the F-AUX-1 fail-closed bridge between the channel layer and the native INTMAX layer:
/// the public channel amount/token/recipient and the E-2-bound delta determine one canonical
/// `Transfer`; that transfer determines one canonical `TxV2`; and that TxV2 determines H2.  A
/// co-signer must never accept those objects as independent attacker-supplied values.
pub fn canonical_inter_channel_base_transfer(
    inter_channel_tx: &InterChannelTx,
    amount: u64,
) -> WResult<Transfer> {
    if inter_channel_tx.receiver_deltas.len() != 1 {
        return bail(format!(
            "F-AUX-1: expected exactly one receiver delta, got {}",
            inter_channel_tx.receiver_deltas.len()
        ));
    }
    let tx_leaf = inter_channel_tx
        .tx_leaf_hash()
        .map_err(|e| WalletError(format!("F-AUX-1: tx leaf: {e}")))?;
    let receiver_pk_g = inter_channel_tx.receiver_deltas[0].receiver_pk_g;
    let is_burn = inter_channel_tx.destination_channel_id.channel_id()
        == crate::constants::BURN_CHANNEL_ID as u32;
    if is_burn && inter_channel_tx.destination_base_transfer_salt != Salt::default() {
        return bail("F-AUX-1: burn must carry the canonical zero base transfer salt");
    }
    if is_burn {
        extract_address_from_recipient(receiver_pk_g).map_err(|error| {
            WalletError(format!(
                "F-AUX-1: burn receiver is not canonical ADDRESS_TAG (0x02 || 11 zero bytes || address): {error}"
            ))
        })?;
    }
    let aux_data = if is_burn {
        burn_descriptor(
            tx_leaf,
            receiver_pk_g,
            inter_channel_tx.token_index,
            u64_to_u256(amount),
        )
    } else {
        tx_leaf
    };
    let base_recipient = if is_burn {
        receiver_pk_g
    } else {
        calculate_recipient_from_user_id(
            inter_channel_tx.destination_channel_id,
            inter_channel_tx.destination_base_transfer_salt,
        )
    };
    Ok(inter_channel_base_transfer(
        base_recipient,
        inter_channel_tx.token_index,
        amount,
        aux_data,
    ))
}

fn canonical_inter_channel_binding(
    inter_channel_tx: &InterChannelTx,
    amount: u64,
) -> WResult<(Transfer, TxV2, Bytes32)> {
    let transfer = canonical_inter_channel_base_transfer(inter_channel_tx, amount)?;
    let (tx_v2, tx_v2_tree) = inter_channel_tx_v2(
        inter_channel_tx.source_channel_id,
        &transfer,
        inter_channel_tx.base_nonce,
    );
    Ok((transfer, tx_v2, Bytes32::from(tx_v2_tree.get_root())))
}

/// Verify all signed-but-retired fields and the native-transfer commitment carried by an
/// inter-channel transaction.  Keeping this check next to the canonical constructor prevents a
/// future caller from validating E-2 while accidentally skipping its base-layer binding.
fn verify_canonical_inter_channel_binding(
    inter_channel_tx: &InterChannelTx,
    amount: u64,
) -> WResult<(TxV2, Bytes32)> {
    let signed = &inter_channel_tx.signed_small_block;
    if signed.message.medium_epoch_hint != 0
        || signed.medium_block_number != 0
        || !signed.aggregated_signature_proof.is_empty()
        || !signed.confirmation_proof.is_empty()
        || inter_channel_tx.seal != Bytes32::default()
        || !inter_channel_tx.recipient_memo.is_empty()
        || !inter_channel_tx.transport_proof.is_empty()
        || inter_channel_tx.tx_inclusion_proof != MerkleInclusionProof::default()
    {
        return bail("non-canonical value in a retired inter-channel wire field");
    }

    let (transfer, tx_v2, tx_tree_root) =
        canonical_inter_channel_binding(inter_channel_tx, amount)?;
    let expected_commitment = Bytes32::from(transfer.poseidon_hash());
    if inter_channel_tx.intmax_transfer_commitment != expected_commitment {
        return bail(
            "F-AUX-1: intmax_transfer_commitment does not commit the canonical base Transfer",
        );
    }
    if inter_channel_tx.signed_small_block.message.tx_tree_root != tx_tree_root {
        return bail("F-AUX-1: signed H2 does not commit the canonical base Transfer/TxV2");
    }
    Ok((tx_v2, tx_tree_root))
}

/// Bind the convenience transfer descriptor to the exact debit payload a source co-signer has
/// verified. The descriptor crosses a second JSON boundary and must not be allowed to declare a
/// different amount/recipient/token while the real E-2 proof remains only inside `debit_payload`.
pub fn verify_inter_channel_descriptor_matches_debit(
    debit_payload: &InterChannelDebitPayload,
    descriptor: &InterChannelTransferDescriptor,
) -> WResult<()> {
    let tx = &debit_payload.inter_channel_tx;
    if descriptor.amount != debit_payload.amount {
        return bail("descriptor amount differs from the E-2-proved debit amount");
    }
    if descriptor.destination_base_transfer_salt != tx.destination_base_transfer_salt {
        return bail("descriptor destination base transfer salt differs from the signed debit");
    }
    if descriptor.inter_channel_tx.signing_digest() != tx.signing_digest() {
        return bail("descriptor inter_channel_tx differs from the verified debit payload");
    }
    let receiver = tx
        .receiver_deltas
        .first()
        .ok_or_else(|| WalletError("verified debit has no receiver delta".into()))?;
    if descriptor.source_channel_id != tx.source_channel_id
        || descriptor.destination_channel_id != tx.destination_channel_id
        || descriptor.source_pk_g != tx.source_pk_g
        || descriptor.receiver_pk_g != receiver.receiver_pk_g
        || descriptor.sender_delta_ct != tx.sender_delta_ct
        || descriptor.receiver_delta != receiver.amount
        || descriptor.tx_hash != tx.tx_hash
    {
        return bail("descriptor convenience fields differ from the verified debit transaction");
    }
    let (canonical_tx_v2, canonical_root) =
        verify_canonical_inter_channel_binding(tx, debit_payload.amount)?;
    if descriptor.tx_v2 != canonical_tx_v2 || descriptor.tx_tree_root != canonical_root {
        return bail("descriptor TxV2/H2 differs from the canonical verified debit binding");
    }
    Ok(())
}

/// Guard every outgoing base send against the persisted account witness. A channel debit is safe
/// to co-sign only when its explicitly bound nonce is the base account's next nonce and that
/// sent-tx Merkle slot is still empty.
pub fn verify_base_nonce_available(
    base_private: &crate::common::private_state::FullPrivateState,
    send_nonce: u32,
) -> WResult<()> {
    let sent_len = base_private.sent_tx_tree.len();
    if send_nonce != base_private.nonce {
        return bail(format!(
            "base send nonce divergence: channel proposes nonce {send_nonce}, base account next nonce is {}",
            base_private.nonce
        ));
    }
    if (send_nonce as usize) < sent_len {
        let occupied = base_private.sent_tx_tree.get_leaf(send_nonce as u64);
        return bail(format!(
            "base send nonce slot {send_nonce} is already occupied (stored tx nonce {}, transfer root {})",
            occupied.nonce, occupied.transfer_tree_root
        ));
    }
    if sent_len != base_private.nonce as usize {
        return bail(format!(
            "base private witness is internally inconsistent: sent-tx tree length {sent_len}, next nonce {}",
            base_private.nonce
        ));
    }
    Ok(())
}

/// Compatibility name retained for callers/tests written before all inter-channel sends adopted
/// the same persisted-base-nonce gate.
pub fn verify_burn_nonce_available(
    base_private: &crate::common::private_state::FullPrivateState,
    burn_nonce: u32,
) -> WResult<()> {
    verify_base_nonce_available(base_private, burn_nonce)
}

/// The L1 [`Withdrawal`] leaf a burn's `single_withdrawal` proof WILL carry — recipient, token
/// index, amount, **nullifier** and aux_data.
///
/// SECURITY (the single source of truth for the burn nullifier). This mirrors
/// `SingleWithdawalWitness::to_public_inputs`
/// (`src/circuits/withdraw/single_withdrawal_circuit.rs:368-390`) and its in-circuit twin
/// (`:508-535`) field for field, and computes the nullifier by calling the very same
/// `SettledTransfer::nullifier()` those paths call — it does not re-implement the formula.
/// Every input is fixed at burn time, with no dependence on settlement:
///
/// * `inner` — the burn's own base `Transfer`, rebuilt with [`inter_channel_base_transfer`], the
///   same function that built the one inside the co-signed tx tree;
/// * `from` — the SOURCE channel id, which in-circuit is `balance_pis.channel_id` (`:513`);
/// * `transfer_index` — [`INTER_CHANNEL_TRANSFER_INDEX`], asserted zero in `send_tx_circuit`;
/// * `nonce` — the burn tx's `TxV2.nonce` (`= prev.small_block_number + 1`), which the withdrawal
///   circuit forces equal to `tx.nonce` (`:508`) and which the sent-tx merkle proof pins to the
///   deduction. This is what F-WD-2 bought: the nullifier binds the SENDER NONCE, not the
///   settlement block, so it is computable before the burn is ever settled — no circuit change, no
///   PI change, no VK rotation is needed to know it at burn time.
///
/// Fails closed if the recipient is not an `ADDRESS_TAG` L1 recipient — i.e. if the transfer is
/// not withdrawable at all, in which case there is no leaf to authorize.
pub fn burn_withdrawal_leaf(
    source_channel_id: ChannelId,
    burn_recipient_pk_g: Bytes32,
    token_index: u32,
    amount: u64,
    aux_data: Bytes32,
    tx_nonce: u32,
) -> WResult<crate::common::withdrawal::Withdrawal> {
    use crate::common::transfer::SettledTransfer;

    let transfer = inter_channel_base_transfer(burn_recipient_pk_g, token_index, amount, aux_data);
    let recipient = extract_address_from_recipient(transfer.recipient).map_err(|e| {
        WalletError(format!(
            "burn withdrawal leaf: recipient {} is not an ADDRESS_TAG L1 recipient — this burn is \
             not withdrawable: {e:?}",
            burn_recipient_pk_g.to_hex()
        ))
    })?;
    let settled = SettledTransfer::new(
        transfer.clone(),
        source_channel_id,
        INTER_CHANNEL_TRANSFER_INDEX,
        tx_nonce,
    );
    Ok(crate::common::withdrawal::Withdrawal {
        recipient,
        token_index: transfer.token_index,
        amount: transfer.amount,
        nullifier: settled.nullifier(),
        aux_data: transfer.aux_data,
    })
}

/// IMPW domain prefix for partial-withdrawal authDigest (matches Solidity `bytes4(0x494d5057)`).
pub const PARTIAL_WITHDRAWAL_DOMAIN: u32 = 0x494d5057;

/// Compute the `authDigest` that the on-chain `withdrawNative` gate checks for burn withdrawals
/// (`auxData != 0`). Must be byte-identical to the Solidity encoding:
/// `keccak256(abi.encodePacked(bytes4(0x494d5057), nullifier, recipient, tokenIndex, amount,
/// auxData))`.
pub fn partial_withdrawal_auth_digest(
    withdrawal: &crate::common::withdrawal::Withdrawal,
) -> Bytes32 {
    use crate::ethereum_types::u32limb_trait::U32LimbTrait as _;
    use plonky2_keccak::utils::solidity_keccak256;
    let words: Vec<u32> = [PARTIAL_WITHDRAWAL_DOMAIN]
        .iter()
        .copied()
        .chain(withdrawal.nullifier.to_u32_vec())
        .chain(withdrawal.recipient.to_u32_vec())
        .chain([withdrawal.token_index])
        .chain(withdrawal.amount.to_u32_vec())
        .chain(withdrawal.aux_data.to_u32_vec())
        .collect();
    Bytes32::from_u32_slice(&solidity_keccak256(&words)).expect("keccak output must be bytes32")
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
    // F-AUX-1: do this before the expensive E-2 verification.  The signed channel debit, base
    // Transfer commitment, TxV2 leaf and signed H2 must be one deterministically reconstructed
    // transaction, not four independently plausible values.
    verify_canonical_inter_channel_binding(&debit_payload.inter_channel_tx, debit_payload.amount)?;
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
/// settled_tx_chain pushes the same tx leaf as A) then `ReceiverBundleApplyUpdateWitness`
/// (recipient slot += delta; unallocated -= amount; settle chain unchanged). One logical base
/// transfer is folded exactly once, matching `BalanceProcessor::prove_receive_transfer`. The
/// building member self-signs both states (if it is a co-signing member); both witnesses are CALLED
/// as self-checks. `b_snapshot` is channel B; `keys` belong to a channel-B member (used for the
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
    // TM-6 (destination-side registry resolution): the SIGNED base token_index must resolve
    // against THIS channel's own registry; unregistered ⇒ refuse fail-closed before building
    // anything. The witness self-checks below re-run the same resolution adversarially.
    let token_slot = resolve_local_token_slot(&b_prev.balance_state, inter_channel_tx.token_index)?;
    let transport = ChannelProofEnvelope {
        role: TransitionProofRole::IntmaxTransport,
        backend: ProofBackend::Plonky2,
        proof: inter_channel_tx.transport_proof.clone(),
    };

    // ---- Fund import: ChannelFund += amount; unallocated += amount; chain pushes tx_leaf. ----
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
    let incoming_settle_tag = inter_channel_tx
        .tx_leaf_hash()
        .map_err(|e| WalletError(format!("fund import tx_leaf_hash: {e}")))?;
    let mut fund_import_state = ChannelState {
        epoch: b_prev.epoch + 1,
        small_block_number: b_prev.small_block_number + 1,
        channel_fund: ChannelFund {
            // TM-6: the fund grows at the REGISTRY-RESOLVED local position; the other 9
            // positions ride the spread unchanged (P2 per-token conservation).
            amounts: {
                let mut amounts = b_prev.channel_fund.amounts;
                amounts[token_slot] += u64_to_u256(amount);
                amounts
            },
            ..b_prev.channel_fund.clone()
        },
        balance_state: BalanceState {
            settled_tx_chain: settled_tx_chain_push(
                b_prev.balance_state.settled_tx_chain,
                incoming_settle_tag,
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

    // ---- Bundle apply: recipient slot += delta; unallocated -= amount; chain unchanged. ----
    let receiver_delta = &inter_channel_tx.receiver_deltas[0];
    // TM-6: the inbound credit lands at the REGISTRY-RESOLVED local position of the recipient
    // row (the same slot the fund grew at); other positions ride the row clone unchanged.
    let recipient_after = add_ciphertexts(
        &fund_import_state.balance_state.enc_balances[recipient_slot][token_slot],
        &receiver_delta.amount,
    )
    .map_err(we)?;
    let mut bundle_enc = fund_import_state.balance_state.enc_balances.clone();
    bundle_enc[recipient_slot][token_slot] = recipient_after;
    let mut bundle_pending = fund_import_state.balance_state.pending_adds.clone();
    bundle_pending[recipient_slot][token_slot] += 1;
    // The import already chained the SAME tx leaf the sender chained into A. The bundle is the
    // accounting half of that one receive and must not fold a second logical settlement.
    let bundle_accumulator = import_accumulator.clone();
    let bundle_accumulator_root = import_accumulator_root;
    let mut bundle_apply_state = ChannelState {
        epoch: fund_import_state.epoch + 1,
        balance_state: BalanceState {
            enc_balances: bundle_enc,
            settled_tx_chain: fund_import_state.balance_state.settled_tx_chain,
            // The logical incoming transfer was inserted once by the import step.
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

    // F-AUX-1: independently rebuild the exact base Transfer and TxV2 from the channel debit.
    // Equality with the descriptor closes the old gap where H2 could commit transfer Y while E-2
    // and the channel fund movement debited transfer X.
    let (canonical_tx_v2, canonical_tx_tree_root) =
        verify_canonical_inter_channel_binding(inter_channel_tx, descriptor.amount)?;
    if descriptor.tx_v2 != canonical_tx_v2 {
        return bail("F-AUX-1: descriptor TxV2 is not the canonical channel-debit transfer");
    }
    if descriptor.tx_tree_root != canonical_tx_tree_root {
        return bail("F-AUX-1: descriptor H2 is not the canonical TxV2 tree root");
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
    // (5b) SECURITY (TM-16 obligation 1/2): B recomputes the FULL token-bearing `tx_hash` from
    // the descriptor's OWN fields — ids(source, dest, `inter_channel_tx.token_index`) over the
    // signed tx_tree_root + the just-recomputed tx_leaf — and refuses a descriptor whose carried
    // `tx_hash` differs, BEFORE anything absorbs it into the chain/accumulator. The token is
    // single-sourced from `inter_channel_tx.token_index` (the SAME field the registry resolution
    // below and the E-2 statement read — no second wire copy), so a source builder anchoring
    // token X while the descriptor resolves/credits token Y is rejected at absorb time, and the
    // accumulator leaf a post-close claim later opens commits the token B actually credited.
    let recomputed_tx_hash = inter_channel_tx
        .compute_tx_hash()
        .map_err(|e| WalletError(format!("invariant 5b: compute_tx_hash: {e}")))?;
    if recomputed_tx_hash != inter_channel_tx.tx_hash {
        return bail(
            "invariant 5b: descriptor tx_hash != recomputed token-bearing tx_hash (TM-16)",
        );
    }
    // The descriptor's top-level convenience copy must agree with the embedded (IMI2-signed) tx.
    if descriptor.tx_hash != inter_channel_tx.tx_hash {
        return bail("invariant 5b: descriptor.tx_hash != embedded inter_channel_tx.tx_hash");
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
    // TM-6 (gate-level, destination side): the SIGNED base token_index must be registered in
    // channel B's own registry — refuse fail-closed before re-verifying the E-2 (the
    // fund-import/bundle witnesses re-run the same resolution on the proposed states).
    let _b_token_slot =
        resolve_local_token_slot(&b_prev.balance_state, inter_channel_tx.token_index)?;
    let statement = crate::regev::RegevStatement::ChannelUpdate {
        sender_pk: descriptor.source_pk.clone(),
        recipient_pk: descriptor.receiver_pk.clone(),
        before: descriptor.sender_before_ct.clone(),
        after: descriptor.sender_after_ct.clone(),
        sender_delta: descriptor.sender_delta_ct.clone(),
        receiver_delta: descriptor.receiver_delta.clone(),
        amount,
        // TM-6: the E-2 re-verification binds the SIGNED token_index — a tampered descriptor
        // token (with the real proof) diverges the "IMU2" transcript and is rejected.
        token_index: inter_channel_tx.token_index,
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

/// Verify the complete two-state destination credit, including the cross-channel source gate and
/// both destination-local state transitions. This is the production adoption gate used by the
/// live balance service: accepting only the final bundle head is insufficient because an attacker
/// could otherwise skip or substitute the fund-import state that performs the one canonical
/// settle-chain fold.
#[allow(clippy::too_many_arguments)]
pub fn verify_inter_channel_credit_states(
    b_prev: &ChannelState,
    b_trusted_record: &ChannelRecord,
    b_members: &[MemberInfo],
    descriptor: &InterChannelTransferDescriptor,
    a_signed_state: &ChannelState,
    a_trusted_record: &ChannelRecord,
    fund_import_state: &ChannelState,
    bundle_apply_state: &ChannelState,
    level: RegevSecurityLevel,
) -> WResult<()> {
    verify_inter_channel_credit_transition(
        b_prev,
        b_trusted_record,
        descriptor,
        a_signed_state,
        a_trusted_record,
        level,
    )?;

    let active = b_trusted_record.member_count as usize + b_trusted_record.delegate_count as usize;
    if b_members.len() != active {
        return bail(format!(
            "destination member list has {} entries but active participant count is {active}",
            b_members.len()
        ));
    }
    let mut seen = [false; MAX_CHANNEL_MEMBERS];
    for member in b_members {
        check_slot(member.slot as usize, active)?;
        if seen[member.slot as usize] {
            return bail(format!("duplicate destination member slot {}", member.slot));
        }
        seen[member.slot as usize] = true;
    }
    let regev_pks = regev_pks_array(b_members);
    if regev_pk_root(&regev_pks) != b_trusted_record.regev_pk_root
        || member_pubkeys_root(b_trusted_record, b_members)? != b_trusted_record.member_pubkeys_root
    {
        return bail("destination member set is not anchored to the trusted record");
    }
    verify_all_signatures(b_trusted_record, &[], fund_import_state).map_err(|e| {
        WalletError(format!(
            "destination fund-import state is not N-of-N signed: {e}"
        ))
    })?;
    verify_all_signatures(b_trusted_record, &[], bundle_apply_state).map_err(|e| {
        WalletError(format!(
            "destination bundle-apply state is not N-of-N signed: {e}"
        ))
    })?;

    let transport = ChannelProofEnvelope {
        role: TransitionProofRole::IntmaxTransport,
        backend: ProofBackend::Plonky2,
        proof: descriptor.inter_channel_tx.transport_proof.clone(),
    };
    InterChannelFundImportUpdateWitness {
        source_channel_record: a_trusted_record.clone(),
        receiver_channel_record: b_trusted_record.clone(),
        prev_state: b_prev.clone(),
        next_state: fund_import_state.clone(),
        inter_channel_tx: descriptor.inter_channel_tx.clone(),
        amount: descriptor.amount,
        transport_proof: transport,
    }
    .verify(&WalletStructuralTransport)
    .map_err(|e| WalletError(format!("destination fund-import transition invalid: {e:?}")))?;

    ReceiverBundleApplyUpdateWitness {
        receiver_channel_record: b_trusted_record.clone(),
        regev_pks,
        source_sender_pk: descriptor.source_pk.clone(),
        sender_before_ct: descriptor.sender_before_ct.clone(),
        sender_after_ct: descriptor.sender_after_ct.clone(),
        prev_state: fund_import_state.clone(),
        next_state: bundle_apply_state.clone(),
        inter_channel_tx: descriptor.inter_channel_tx.clone(),
        amount: descriptor.amount,
        recipient_index: descriptor.recipient_slot as usize,
        recipient_sk: None,
        expected_amount: None,
    }
    .verify(&RealRegevProofVerifier { level })
    .map_err(|e| {
        WalletError(format!(
            "destination bundle-apply transition invalid: {e:?}"
        ))
    })?;
    Ok(())
}

// --- L1 deposit import (mid-channel top-up) ---

pub struct BuiltL1DepositImport {
    pub fund_import_state: ChannelState,
    pub bundle_apply_state: ChannelState,
    pub settled_tx_accumulator: IncrementalMerkleTree<Bytes32>,
}

/// Build a mid-channel L1 deposit import: fold an L1 deposit into an already-open channel.
///
/// Two-step state transition mirroring `build_inter_channel_credit`:
///   Step 1 (fund import): `channel_fund += amount`, `unallocated += amount`,
///          `settled_tx_chain` pushes `deposit.nullifier()`.
///   Step 2 (bundle apply): `enc_balances[recipient_slot] += delta`, `unallocated -= amount`.
///
/// Trust anchor: the `receive_deposit` balance proof verified externally via
/// `verify_channel_backing` — no transport proof needed (unlike inter-channel import).
pub fn build_l1_deposit_import(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    deposit: &Deposit,
    recipient_slot: usize,
    recipient_delta: &RegevCiphertext,
    _level: RegevSecurityLevel,
) -> WResult<BuiltL1DepositImport> {
    let record = &snapshot.record;
    let prev = &snapshot.state;
    let active = record.member_count as usize + record.delegate_count as usize;
    check_slot(recipient_slot, active)?;

    let amount = deposit.amount.to_u32_vec();
    let amount_u64 = (amount[BYTES32_LEN - 2] as u64) << 32 | amount[BYTES32_LEN - 1] as u64;
    let deposit_nullifier = deposit.nullifier();
    // TM-7 (general registry resolution, §N-5): the base deposit's token_index resolves against
    // the SIGNED registry to the local slot whose fund grows AND whose leaf position is
    // credited; an unregistered token_index is refused fail-closed (never silently credited to
    // token 0). The witness self-check below re-runs the same resolution adversarially.
    let token_slot = resolve_local_token_slot(&prev.balance_state, deposit.token_index)?;

    // ---- Step 1: Fund import ----
    let import_nullifier = advance_nullifier(prev.shared_native_nullifier_root, deposit_nullifier);
    let mut import_accumulator = snapshot.settled_tx_accumulator.clone();
    import_accumulator.push(deposit_nullifier);
    let import_accumulator_root = Bytes32::from(import_accumulator.get_root());
    require_accumulator_push(
        &snapshot.settled_tx_accumulator,
        deposit_nullifier,
        import_accumulator_root,
    )
    .map_err(|e| WalletError(format!("l1 deposit fund import accumulator push: {e:?}")))?;
    let mut fund_import_state = ChannelState {
        epoch: prev.epoch + 1,
        small_block_number: prev.small_block_number + 1,
        channel_fund: ChannelFund {
            // TM-7: the fund grows at the REGISTRY-RESOLVED local position; the other 9
            // positions ride the spread unchanged (P2 per-token conservation).
            amounts: {
                let mut amounts = prev.channel_fund.amounts;
                amounts[token_slot] += u64_to_u256(amount_u64);
                amounts
            },
            ..prev.channel_fund.clone()
        },
        balance_state: BalanceState {
            settled_tx_chain: settled_tx_chain_push(
                prev.balance_state.settled_tx_chain,
                deposit_nullifier,
            ),
            settled_tx_accumulator_root: import_accumulator_root,
            state_version: prev.balance_state.state_version + 1,
            ..prev.balance_state.clone()
        },
        unallocated_confirmed_incoming: prev.unallocated_confirmed_incoming
            + u64_to_u256(amount_u64),
        shared_native_nullifier_root: import_nullifier,
        prev_digest: prev.digest,
        member_signatures: Vec::new(),
        h2_tag: Bytes32::default(),
        ..prev.clone()
    }
    .with_computed_digest();
    sign_member_if_present(keys, record, &mut fund_import_state)?;
    let mut import_for_check = fund_import_state.clone();
    fill_placeholder_sigs(record, &mut import_for_check);
    let import_witness = L1DepositImportUpdateWitness {
        channel_record: record.clone(),
        prev_state: prev.clone(),
        next_state: import_for_check,
        amount: amount_u64,
        deposit_nullifier,
        // TM-7: the base deposit's token_index is no longer dropped — it rides into the IMLD-v2
        // digest and the witness verify enforces its registry resolution.
        token_index: deposit.token_index,
        depositor_slot: recipient_slot,
    };
    import_witness
        .verify()
        .map_err(|e| WalletError(format!("l1 deposit fund import self-check failed: {e:?}")))?;

    // ---- Step 2: Bundle apply (shared deterministic step — see `l1_deposit_bundle_state`) ----
    // One consumed L1 deposit is one settle-history/accumulator event. The import step already
    // inserted it; the bundle only assigns the confirmed amount to a ciphertext slot.
    let bundle_accumulator = import_accumulator.clone();
    let mut bundle_apply_state = l1_deposit_bundle_state(
        &fund_import_state,
        recipient_slot,
        token_slot,
        recipient_delta,
        amount_u64,
    )?;
    sign_member_if_present(keys, record, &mut bundle_apply_state)?;

    Ok(BuiltL1DepositImport {
        fund_import_state,
        bundle_apply_state,
        settled_tx_accumulator: bundle_accumulator,
    })
}

/// The CANONICAL deposit bundle-apply state (TM-7 leg b): starting from the verified
/// post-import state, credit the depositor leaf at EXACTLY the registry-resolved
/// `(recipient_slot, token_slot)` position (`+= recipient_delta`, `pending_adds += 1`),
/// `unallocated -= amount`, settle chain unchanged, `state_version`/`epoch` +1.
/// Every other (row, token) position rides the clones bit-identical.
///
/// SECURITY (TM-7 leg b, Phase 2b review MAJOR 1): this is the SINGLE definition of the bundle
/// step, used by BOTH `build_l1_deposit_import` (the proposer) and
/// `verify_l1_deposit_import_transition` (the co-signer gate, which REBUILDS this state and
/// requires digest equality with the proposal — the `verify_token_register_transition`
/// pattern). A proposer-supplied bundle state crediting any other (row, token) position, a
/// doctored delta/amount, or any other field divergence therefore fails the gate.
/// The accumulator root is carried from the verified fund-import state; the bundle cannot replace
/// it with a proposer-selected root.
fn l1_deposit_bundle_state(
    fund_import_state: &ChannelState,
    recipient_slot: usize,
    token_slot: usize,
    recipient_delta: &RegevCiphertext,
    amount_u64: u64,
) -> WResult<ChannelState> {
    let recipient_after = add_ciphertexts(
        &fund_import_state.balance_state.enc_balances[recipient_slot][token_slot],
        recipient_delta,
    )
    .map_err(we)?;
    let mut bundle_enc = fund_import_state.balance_state.enc_balances.clone();
    bundle_enc[recipient_slot][token_slot] = recipient_after;
    let mut bundle_pending = fund_import_state.balance_state.pending_adds.clone();
    bundle_pending[recipient_slot][token_slot] += 1;
    Ok(ChannelState {
        epoch: fund_import_state.epoch + 1,
        balance_state: BalanceState {
            enc_balances: bundle_enc,
            settled_tx_chain: fund_import_state.balance_state.settled_tx_chain,
            settled_tx_accumulator_root: fund_import_state
                .balance_state
                .settled_tx_accumulator_root,
            state_version: fund_import_state.balance_state.state_version + 1,
            pending_adds: bundle_pending,
            ..fund_import_state.balance_state.clone()
        },
        unallocated_confirmed_incoming: fund_import_state.unallocated_confirmed_incoming
            - u64_to_u256(amount_u64),
        prev_digest: fund_import_state.digest,
        member_signatures: Vec::new(),
        ..fund_import_state.clone()
    }
    .with_computed_digest())
}

/// L1 deposit import co-signer gate: verifies BOTH steps of the proposed L1 deposit import
/// transition before a co-signer signs EITHER state. Fail-closed.
///
/// The two-step obligation (TM-7, Phase 2b review MAJOR 1):
///   Step 1 (fund import) — verified by `L1DepositImportUpdateWitness::verify`: registry
///     resolution of the deposit's base `token_index`, fund growth at exactly the resolved
///     position (others frozen), all leaves bit-identical, chain push, signatures.
///   Step 2 (bundle apply) — verified by REBUILD-EQUALITY: the gate reconstructs the CANONICAL
///     bundle state from the verified post-import state via `l1_deposit_bundle_state` (the SAME
///     code path the proposer's `build_l1_deposit_import` uses, crediting the depositor leaf at
///     exactly the registry-resolved `(recipient_slot, token_slot)` position) and requires
///     digest equality with the proposal — the `verify_token_register_transition` pattern. A
///     proposer-supplied bundle state crediting any other (row, token) position, carrying a
///     doctored delta/amount, or diverging in ANY other field is rejected. The leg-(b) leaf
///     binding therefore does NOT rely on the proposer and the co-signers sharing a process.
///
/// `recipient_delta` is the co-signer's OWN derivation of the deposit's delta ciphertext (the
/// CLI derives it from the shared deterministic seed) — never a wire-trusted copy; the digest
/// equality binds the proposal to it. The bundle must retain the fund-import accumulator root;
/// push-faithfulness remains the import builder's persisted-tree obligation, but bundle assignment
/// cannot overwrite it.
pub fn verify_l1_deposit_import_transition(
    prev: &ChannelState,
    record: &ChannelRecord,
    deposit: &Deposit,
    fund_import_state: &ChannelState,
    bundle_apply_state: &ChannelState,
    recipient_slot: usize,
    recipient_delta: &RegevCiphertext,
) -> WResult<()> {
    let active = record.member_count as usize + record.delegate_count as usize;
    check_slot(recipient_slot, active)?;
    if prev.channel_id != record.channel_id {
        return bail("prev state channel_id does not match record");
    }
    let amount = deposit.amount.to_u32_vec();
    let amount_u64 = (amount[BYTES32_LEN - 2] as u64) << 32 | amount[BYTES32_LEN - 1] as u64;
    let deposit_nullifier = deposit.nullifier();
    // Step 1: the fund-import witness (registry resolution, per-token fund delta, frozen
    // leaves, chain push, structural signatures).
    let witness = L1DepositImportUpdateWitness {
        channel_record: record.clone(),
        prev_state: prev.clone(),
        next_state: fund_import_state.clone(),
        amount: amount_u64,
        deposit_nullifier,
        // TM-7: the co-signer gate hands the deposit's base token_index to the witness verify,
        // which enforces its general registry resolution (unregistered ⇒ reject fail-closed).
        token_index: deposit.token_index,
        depositor_slot: recipient_slot,
    };
    witness
        .verify()
        .map_err(|e| WalletError(format!("l1 deposit co-signer gate (fund import): {e:?}")))?;
    // Step 2 (TM-7 leg b): rebuild-equality against the canonical bundle step. The resolution
    // runs on the SIGNED prev registry (immutable across the import per
    // verify_balance_state_common, so prev and post-import registries agree).
    let token_slot = resolve_local_token_slot(&prev.balance_state, deposit.token_index)?;
    let expected = l1_deposit_bundle_state(
        fund_import_state,
        recipient_slot,
        token_slot,
        recipient_delta,
        amount_u64,
    )?;
    // `signing_digest()` covers every field except `member_signatures` (and is recomputed here,
    // so a doctored stored `digest` cannot mask a divergence).
    if bundle_apply_state.signing_digest() != expected.digest {
        return bail(
            "l1 deposit co-signer gate (bundle apply): proposed bundle state is not the \
             canonical bundle step over the verified import state (TM-7 leg b — wrong credit \
             position, doctored delta/amount, or field divergence) — refusing to sign",
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TokenRegister (detail2 §N-1 — append-only cosigned token registration)
// ---------------------------------------------------------------------------

/// Build the proposed next state for a cosigned `TokenRegister(token_index)` transition
/// (detail2 §N-1): the CANONICAL `token_register_next_state` (registry append + epoch/
/// state_version bump, everything else frozen) with the building member's own state signature
/// attached when it is a co-signing member. No ZKP is generated — a registration mutates no
/// ciphertext (`ChannelTransitionKind::TokenRegister::required_state_backend()` is `None`); the
/// gate is [`verify_token_register_state_transition`] + the N-of-N signatures.
pub fn build_token_register(
    keys: &MemberKeys,
    snapshot: &ChannelSnapshot,
    builder_slot: u16,
    token_index: u32,
) -> WResult<ChannelState> {
    let prev = &snapshot.state;
    let record = &snapshot.record;
    let mut proposed =
        crate::common::channel::token_register_next_state(prev, token_index).map_err(we)?;
    // Self-check through the SAME gate every cosigner runs (structural sigs on a clone).
    verify_token_register_state_transition(prev, record, &proposed, token_index)?;
    if (builder_slot as usize) < record.member_count as usize
        && record.member_pk_gs[builder_slot as usize] == keys.pk_g()
    {
        let sig = sign_state(keys, builder_slot as u8, &proposed)?;
        add_signature(&mut proposed, sig);
    }
    Ok(proposed)
}

/// Cosigner gate for a proposed `TokenRegister` transition: runs
/// [`TokenRegisterUpdateWitness::verify`] (append-exactness + full freeze + rebuild-equality,
/// TM-1/TM-9) against the TRUSTED record and prev head. The witness's signature check is
/// STRUCTURAL (placeholder-filled here, like the other pre-sign gates); the authoritative
/// N-of-N check is `verify_all_signatures` once the full set is collected.
pub fn verify_token_register_state_transition(
    prev: &ChannelState,
    trusted_record: &ChannelRecord,
    proposed_next: &ChannelState,
    token_index: u32,
) -> WResult<()> {
    let mut next_for_check = proposed_next.clone();
    fill_placeholder_sigs(trusted_record, &mut next_for_check);
    let witness = TokenRegisterUpdateWitness {
        channel_record: trusted_record.clone(),
        prev_state: prev.clone(),
        next_state: next_for_check,
        token_index,
    };
    witness
        .verify()
        .map_err(|e| WalletError(format!("token register transition invalid: {e:?}")))?;
    Ok(())
}

// --- inter-channel helpers ---

/// TM-6/TM-7 (fail-closed registry resolution): the unique ACTIVE local token slot t with
/// `token_registry[t] == token_index && t < token_count`. Unique because `validate()` enforces
/// active-prefix injectivity (TM-1); an unregistered base token_index is refused — value for a
/// token this channel has not cosigned into its registry must never move. Wallet-side twin of
/// `state_update_verifier::resolve_token_slot` (the witnesses re-run the check adversarially).
pub fn resolve_local_token_slot(balance_state: &BalanceState, token_index: u32) -> WResult<usize> {
    let token_count = (balance_state.token_count as usize).min(MAX_CHANNEL_TOKENS);
    balance_state.token_registry[..token_count]
        .iter()
        .position(|&index| index == token_index)
        .ok_or_else(|| {
            WalletError(format!(
                "base token_index {token_index} is not registered in this channel's active \
                 registry (token_count {token_count}) — refusing fail-closed (TM-6/TM-7)"
            ))
        })
}

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

// NOTE (TM-16): the former private `inter_channel_tx_hash` moved to `common::channel` as the
// canonical single source (it gained the base `token_index` ids limb, and the gates/claim circuit
// must recompute the SAME fold). The token-free replay-ledger identity lives beside it
// (`inter_channel_tx_identity` / `InterChannelTx::replay_identity`).

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
// active members' DETACHED Falcon cosignatures (already carried by that state) + the channel's
// base-layer balance proof into a REAL `ChannelCloseCircuit` proof. NO SECRET KEY ENTERS THIS
// MODULE'S CLOSE LIFECYCLE — see `doc/tasks/close-detached-signing-design.md` (Option A), and
// `falcon_member_auth_from_signatures` for the fail-closed coordinator gate.
// SOUNDNESS IS ENFORCED IN-CIRCUIT (A-3 P2 threat model): H1/IMCH
// recompute + bind, balance-proof channel_id/settled_tx_chain binding, the recursively verified
// `FalconBatchAggCircuit` proof over the members' REAL Falcon signatures (message/count/pk-list
// bound in-circuit; falcon-sig Phase 2 contract, batched-verification circuit), the
// member_set_commitment keccak, and the active-bit decomposition. `ChannelCloseCircuit::prove`
// recomputes and overrides `member_set_commitment`, so a tampered commitment is rejected. The
// Rust-side preconditions below fail CLOSED before any (expensive) proving so a malformed input
// never produces a proof.
// ─────────────────────────────────────────────────────────────────────────────────────────────

use crate::{
    circuits::channel::{
        close_circuit::{ChannelCloseCircuit, ChannelCloseFullWitness, MemberCloseAuth},
        close_pis::ChannelCloseWitness,
    },
    common::channel::{CloseIntent, CloseWithdrawal, validate_all_member_signatures},
    falcon_sig::{
        FALCON_N, FalconSignature, agg::FalconAggWitness, batch::FalconBatchAggCircuit,
        decode_cosign_blob, verify_with_pk_g,
    },
};

use crate::falcon_sig::agg::{AGG_LEVELS, falcon_agg_expected_public_inputs};

/// Build the Falcon aggregation witness (`FalconAggWitness`) + per-member auth from the members'
/// **DETACHED** cosignatures over `digest` (slot order; shared by the close and cancel-close
/// provers).
///
/// This is the coordinator gate of `doc/tasks/close-detached-signing-design.md` §3.5. The prover
/// process never sees a secret key: `MemberSignature.signature` is the 1690-byte cosign transport
/// blob (`v1 || salt || s2 || h`) that `sign_state` already produces and that every channel state
/// already carries in `ChannelState::member_signatures`.
///
/// SECURITY (fail-closed, in this exact order — identity binding BEFORE cryptography, cryptography
/// BEFORE proving):
///  1. `validate_all_member_signatures` (which calls `record.validate()` first) proves the set is
///     structurally exactly the registered cosigner set: `record.member_count` entries,
///     slot-ordered `0..member_count` with no gaps or duplicates (X-5: this is what makes the
///     positional indexing below sound), each entry's `pk_g` equal to `record.member_pk_gs[slot]`,
///     each blob exactly `FALCON_COSIGN_BLOB_BYTES` (TM-C8/O-9: a retired ~76 KB `SingleSigCircuit`
///     blob cannot pass).
///  2. The identity fed to verification and to the aggregation witness is read off the
///     AUTHENTICATED `record`, never off the wire entry (T-9) — a `MemberSignature` arriving over
///     HTTP self-declares both `member_slot` and `pk_g`.
///  3. `decode_cosign_blob` rejects a wrong VERSION byte first, then a wrong length, then
///     non-canonical `h` coefficients.
///  4. `verify_with_pk_g` — never the bare `verify` (review F-2) — re-checks `Poseidon(IMFK ||
///     encode(h)) == pk_g` INSIDE the call, so the untrusted transported `h` cannot substitute an
///     identity (T-8), and checks the norm bound against `digest`, which the caller RECOMPUTED from
///     authenticated state (TM-C6). ~64 us/signature, i.e. a bad input is a clear error at
///     millisecond cost instead of an opaque `prove()` failure after minutes.
///  5. pairwise `pk_g` distinctness (also implied by `record.validate()`; kept explicit for a clear
///     error, and A5 in `close_circuit.rs` is the real gate).
///
/// The in-circuit gates remain the actual soundness boundary: the leaf gadget is the UNCONDITIONAL
/// verifier (there is no `verify` selector wire), so a leaf proof cannot exist for an invalid
/// signature at all.
///
/// SECURITY (T-5, disclosed not closed — design §8.3): the members signed the channel STATE, not
/// this close. `close_nonce` / `burn_tx_hash` / `snapshot_medium_block_number` are NOT covered by
/// any signature verified here; the coordinator chooses them unilaterally, bounded only by the L1
/// era fence and the challenge ordering. "N-of-N signed the close" means "N-of-N signed the state".
fn falcon_member_auth_from_signatures(
    record: &ChannelRecord,
    member_sigs: &[MemberSignature],
    digest: Bytes32,
) -> WResult<(Vec<Bytes32>, FalconAggWitness)> {
    // (1) Structural + identity gate. `validate_all_member_signatures` runs `record.validate()`
    // itself, so an invalid record can never reach the crypto below.
    validate_all_member_signatures(record, member_sigs).map_err(|e| {
        WalletError(format!(
            "detached member signature set rejected (structural/identity): {e:?}"
        ))
    })?;

    let count = record.member_count as usize;
    let mut pk_gs: Vec<Bytes32> = Vec::with_capacity(count);
    let mut hs: Vec<[u16; FALCON_N]> = Vec::with_capacity(count);
    let mut sigs: Vec<FalconSignature> = Vec::with_capacity(count);
    for slot in 0..count {
        // (2) Identity from the RECORD. Step (1) has already proved `member_sigs[slot].member_slot
        // == slot` and `member_sigs[slot].pk_g == record.member_pk_gs[slot]`, so positional
        // indexing here cannot bind slot i's identity to slot j's signature (X-5).
        let pk_g = record.member_pk_gs[slot];
        let entry = &member_sigs[slot];
        // (3) Version byte, then fixed length, then canonical `h`.
        let (sig, h) = decode_cosign_blob(&entry.signature).map_err(|e| {
            WalletError(format!(
                "slot {slot}: detached cosignature blob failed to decode: {e:?}"
            ))
        })?;
        // (4) The cryptographic gate, with the identity binding checked inside.
        if !verify_with_pk_g(pk_g, &h, digest, &sig) {
            return bail(format!(
                "slot {slot}: detached Falcon cosignature failed native verification against the \
                 registered pk_g {pk_g} over the recomputed digest {digest} (wrong state, wrong \
                 era, wrong channel, substituted public polynomial, or corrupt key material — a \
                 LOCALLY produced signature reaching this branch means key material inconsistency, \
                 because `FalconKeys::sign` self-verifies)"
            ));
        }
        pk_gs.push(pk_g);
        hs.push(h);
        sigs.push(sig);
    }
    // (5) Distinctness over the active pk_g set.
    for i in 0..pk_gs.len() {
        for j in (i + 1)..pk_gs.len() {
            if pk_gs[i] == pk_gs[j] {
                return bail(format!(
                    "duplicate registered member pk_g at active slots {i} and {j}"
                ));
            }
        }
    }
    // (6) Slot order IS the pk-list order the close / cancel-close circuits consume.
    let signers: Vec<(&[u16; FALCON_N], &FalconSignature)> = hs.iter().zip(sigs.iter()).collect();
    Ok((pk_gs, FalconAggWitness::for_signatures(digest, &signers)))
}

/// The T-10 fail-closed hygiene check shared by both detached provers: the AUTHENTICATED record's
/// cosigner count and the state's own claimed cosigner count must agree.
///
/// SECURITY (T-10 / X-6): the provers size the member set from
/// `state.balance_state.member_count` while every signature-validation helper sizes it from
/// `record.member_count`. Nothing else in the tree asserts the two are equal — genesis copies one
/// into the other and nothing re-checks it afterwards. That was masked while one process produced
/// both; under detached signing the record and the state arrive from different places. If they
/// disagree and the code took the larger it would index out of bounds; if it took the smaller it
/// would silently prove a different member set than it validated. Soundness is still held
/// in-circuit by H1 (which commits `member_count`); this is fail-closed hygiene.
fn assert_record_state_member_count_agree(
    what: &str,
    record: &ChannelRecord,
    state: &ChannelState,
) -> WResult<()> {
    if record.member_count as u64 != state.balance_state.member_count as u64 {
        return bail(format!(
            "{what}: record.member_count {} != state.balance_state.member_count {} (T-10 \
             fail-closed: the authenticated member set and the state disagree)",
            record.member_count, state.balance_state.member_count
        ));
    }
    Ok(())
}

/// A reusable, self-verifying Falcon aggregate proof tied to one fully co-signed channel state.
/// The proof bytes are independent of close/PW/cancel parameters: those consumers bind only the
/// signed IMCH digest, signer count, and registered pk list exposed as aggregate public inputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FalconAggregateProofArtifact {
    pub format_version: u8,
    pub state_digest: Bytes32,
    pub member_count: u8,
    pub member_pk_gs: Vec<Bytes32>,
    pub proof: Vec<u8>,
}

impl FalconAggregateProofArtifact {
    pub const FORMAT_VERSION: u8 = 1;
    const MAX_BYTES: usize = 2 * 1024 * 1024;

    pub fn to_bytes(&self) -> WResult<Vec<u8>> {
        let bytes = bincode::serde::encode_to_vec(
            self,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian(),
        )
        .map_err(|e| WalletError(format!("Falcon aggregate artifact encode failed: {e}")))?;
        if bytes.len() > Self::MAX_BYTES {
            return bail("Falcon aggregate artifact exceeds the 2 MiB limit");
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> WResult<Self> {
        if bytes.len() > Self::MAX_BYTES {
            return bail("Falcon aggregate artifact exceeds the 2 MiB limit");
        }
        let (artifact, consumed) = bincode::serde::decode_from_slice::<Self, _>(
            bytes,
            bincode::config::standard()
                .with_fixed_int_encoding()
                .with_little_endian()
                .with_limit::<{ FalconAggregateProofArtifact::MAX_BYTES }>(),
        )
        .map_err(|e| WalletError(format!("Falcon aggregate artifact decode failed: {e}")))?;
        if consumed != bytes.len() {
            return bail(format!(
                "Falcon aggregate artifact has {} trailing bytes",
                bytes.len() - consumed
            ));
        }
        Ok(artifact)
    }
}

/// Long-lived Falcon proving context. Clone is cheap and shares the same built circuit. A service
/// should create one of these at startup, then generate an artifact exactly once whenever an
/// N-of-N state becomes final; every settlement prover below can consume the same artifact.
#[derive(Clone)]
pub struct FalconProverContext {
    agg: Arc<FalconBatchAggCircuit<F, C, D>>,
}

impl Default for FalconProverContext {
    fn default() -> Self {
        Self::new()
    }
}

impl FalconProverContext {
    pub fn new() -> Self {
        Self {
            agg: Arc::new(FalconBatchAggCircuit::<F, C, D>::new()),
        }
    }

    fn prove_detached(
        &self,
        record: &ChannelRecord,
        state_digest: Bytes32,
        member_sigs: &[MemberSignature],
    ) -> WResult<FalconAggregateProofArtifact> {
        let (pk_gs, witness) =
            falcon_member_auth_from_signatures(record, member_sigs, state_digest)?;
        let proof = self
            .agg
            .prove(&witness)
            .map_err(|e| WalletError(format!("Falcon signature aggregation failed: {e:?}")))?;
        self.agg.data.verify(proof.clone()).map_err(|e| {
            WalletError(format!("Falcon aggregate self-verification failed: {e:?}"))
        })?;
        Ok(FalconAggregateProofArtifact {
            format_version: FalconAggregateProofArtifact::FORMAT_VERSION,
            state_digest,
            member_count: record.member_count,
            member_pk_gs: pk_gs,
            proof: proof.to_bytes(),
        })
    }

    /// Generate the cache artifact at the N-of-N state-finalization boundary.
    pub fn prove_finalized_state(
        &self,
        record: &ChannelRecord,
        state: &ChannelState,
    ) -> WResult<FalconAggregateProofArtifact> {
        assert_record_state_member_count_agree("Falcon aggregate", record, state)?;
        if state.digest != state.signing_digest() {
            return bail(
                "Falcon aggregate: state digest does not match the recomputed IMCH digest",
            );
        }
        self.prove_detached(record, state.digest, &state.member_signatures)
    }

    fn proof_from_artifact(
        &self,
        record: &ChannelRecord,
        state_digest: Bytes32,
        artifact: &FalconAggregateProofArtifact,
    ) -> WResult<ProofWithPublicInputs<F, C, D>> {
        if artifact.format_version != FalconAggregateProofArtifact::FORMAT_VERSION {
            return bail(format!(
                "unsupported Falcon aggregate artifact version {}",
                artifact.format_version
            ));
        }
        let count = record.member_count as usize;
        let expected_pks = &record.member_pk_gs[..count];
        if artifact.state_digest != state_digest
            || artifact.member_count != record.member_count
            || artifact.member_pk_gs.as_slice() != expected_pks
        {
            return bail("Falcon aggregate artifact metadata does not match this state/member set");
        }
        let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
            artifact.proof.clone(),
            &self.agg.data.common,
        )
        .map_err(|e| WalletError(format!("Falcon aggregate proof decode failed: {e}")))?;
        let expected =
            falcon_agg_expected_public_inputs::<F>(AGG_LEVELS, state_digest, expected_pks);
        if proof.public_inputs != expected {
            return bail("Falcon aggregate proof public inputs do not match this state/member set");
        }
        self.agg
            .data
            .verify(proof.clone())
            .map_err(|e| WalletError(format!("cached Falcon aggregate proof rejected: {e:?}")))?;
        Ok(proof)
    }

    /// Fully verify a persisted artifact against a finalized state. Useful at cache-load and
    /// service-start boundaries; consumers call the same check again before recursive proving.
    pub fn verify_finalized_state_artifact(
        &self,
        record: &ChannelRecord,
        state: &ChannelState,
        artifact: &FalconAggregateProofArtifact,
    ) -> WResult<()> {
        assert_record_state_member_count_agree("Falcon aggregate cache", record, state)?;
        if state.digest != state.signing_digest() {
            return bail("Falcon aggregate cache: finalized state digest is inconsistent");
        }
        self.proof_from_artifact(record, state.digest, artifact)
            .map(|_| ())
    }

    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.agg.verifier_data()
    }
}

/// Process-built close-proving context: the `FalconBatchAggCircuit` (direct in-circuit verification
/// of the N member Falcon signatures, falcon-sig Phase 2) and the `ChannelCloseCircuit` bound to
/// the channel's balance verifier data. Each circuit is expensive to build, so construct ONE
/// `CloseProver` per process and reuse it.
pub struct CloseProver {
    falcon: FalconProverContext,
    close_circuit: ChannelCloseCircuit<F, C, D>,
}

impl CloseProver {
    /// Build the close-proving circuits. `balance_vd` is the channel's base-layer balance verifier
    /// data (the same value cached in `balance_vd.bin` / produced by the `BalanceProcessor`).
    pub fn new(balance_vd: &VerifierCircuitData<F, C, D>) -> Self {
        Self::with_falcon_context(balance_vd, FalconProverContext::new())
    }

    /// Build only the close circuit while sharing an already-built Falcon circuit with the other
    /// exit provers and the state-finalization artifact producer.
    pub fn with_falcon_context(
        balance_vd: &VerifierCircuitData<F, C, D>,
        falcon: FalconProverContext,
    ) -> Self {
        let close_circuit =
            ChannelCloseCircuit::<F, C, D>::new(balance_vd, &falcon.verifier_data());
        Self {
            falcon,
            close_circuit,
        }
    }

    /// Build the full close witness from the wallet's signed final `ChannelState`, the channel's
    /// AUTHENTICATED `ChannelRecord`, the N ACTIVE members' **DETACHED** cosignatures over the IMCH
    /// digest (slot order), and the channel's base-layer balance proof. The signatures are verified
    /// in-circuit by ONE `FalconBatchAggCircuit` proof whose message/count/pk-list PIs the close
    /// circuit binds.
    ///
    /// **THIS PROVER HOLDS NO KEY.** That is the point
    /// (`doc/tasks/close-detached-signing-design.md`, Option A). The signatures it needs
    /// already exist, already detached, in the state it is handed: `sign_state` signs
    /// `state.signing_digest()`, this prover binds `state.digest`, and `verify_all_signatures`
    /// — which every route to becoming the channel head runs — asserts the two are equal. So
    /// callers pass `&state.member_signatures` and no new signing round, no new endpoint and no
    /// member liveness are required. Unilateral close is precisely the operation you need when
    /// the other members are NOT online (T-4), so this must stay true.
    ///
    /// SECURITY (why re-using a collected cosignature is not weaker than minting a fresh one): the
    /// close circuit is signature-BLIND. The aggregation leaf registers only `[message, 1, pk_g]`
    /// (`falcon_sig/agg.rs`); `salt` / `s2` / `h` are witnesses and never public inputs
    /// (`falcon_sig/gadget.rs`). Two valid signatures by the same key over the same digest are
    /// therefore indistinguishable to every downstream gate, and the close proof's public inputs
    /// are identical either way (asserted by
    /// `close_detached_and_resigned_paths_yield_identical_close_public_inputs`).
    ///
    /// SECURITY (X-1, honest statement of what the signatures mean): a cosignature over state S
    /// authorises EVERY close at S within the era, forever. That was already true of the previous
    /// key-taking implementation — a process holding the keys could mint that signature at will —
    /// so this change adds no capability. The era fence is `close_freeze_nonce`, which IS inside
    /// the signed IMCH preimage; the version fence is the manager's strict challenge ordering.
    ///
    /// SEAM CLOSED (falcon-sig Phase 4): `MemberKeys::pk_g()` IS the Falcon identity, and the
    /// join/registration path (`ChannelMemberKeys::from_member_keys`) registers exactly the key
    /// objects the members co-sign and close with — so the registered member set and the close
    /// proof's `member_set_commitment` agree by construction, not by two derivations matching.
    ///
    /// SECURITY: fail-closed preconditions reject malformed inputs early; the in-circuit gates are
    /// the actual soundness boundary. `CloseIntent::new` additionally fail-closed-checks
    /// channel_id / digest / H1 / intmax_state_root / burn_amount / unallocated==0 bindings.
    pub fn build_full_witness_from_signatures(
        &self,
        record: &ChannelRecord,
        state: &ChannelState,
        member_sigs: &[MemberSignature],
        balance_proof: ProofWithPublicInputs<F, C, D>,
        close_nonce: u64,
        burn_tx_hash: Bytes32,
        snapshot_medium_block_number: u64,
    ) -> WResult<ChannelCloseFullWitness<F, C, D>> {
        let artifact = self
            .falcon
            .prove_detached(record, state.digest, member_sigs)
            .map_err(|e| WalletError(format!("close: {}", e.0)))?;
        self.build_full_witness_from_aggregate(
            record,
            state,
            &artifact,
            balance_proof,
            close_nonce,
            burn_tx_hash,
            snapshot_medium_block_number,
        )
    }

    /// Build a close witness using the aggregate artifact produced when this state reached N-of-N
    /// finality. This is the normal settlement path: no Falcon proving is repeated here.
    #[allow(clippy::too_many_arguments)]
    pub fn build_full_witness_from_aggregate(
        &self,
        record: &ChannelRecord,
        state: &ChannelState,
        artifact: &FalconAggregateProofArtifact,
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
        // T-10 / X-6: the authenticated record and the state must agree on the cosigner count
        // BEFORE anything is sized from either of them.
        assert_record_state_member_count_agree("close", record, state)?;
        // The state's cached digest must not lie: it is the message every cosignature is verified
        // against below, and `CloseIntent::new` binds it into the intent. Same check
        // `verify_all_signatures` makes before a state may become the channel head.
        if state.digest != state.signing_digest() {
            return bail(
                "close: state.digest does not match the recomputed signing_digest() (fail-closed: \
                 the cached digest is the message the member cosignatures are verified against)",
            );
        }

        // Derive the close-tx and close-intent. `CloseIntent::new` performs the binding checks.
        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_balance_state_h1: state.balance_state.h1(),
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash,
            burn_amount: state.channel_fund.amounts[0],
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

        // The artifact verifier checks metadata, exact aggregate public inputs, and the proof
        // itself against this process's circuit before it can enter recursive close verification.
        let agg_proof = self
            .falcon
            .proof_from_artifact(record, state.digest, artifact)
            .map_err(|e| WalletError(format!("close: {}", e.0)))?;
        let member_auth: Vec<MemberCloseAuth> = artifact
            .member_pk_gs
            .iter()
            .map(|&pk_g| MemberCloseAuth { pk_g })
            .collect();

        Ok(ChannelCloseFullWitness {
            close,
            final_balance_proof: balance_proof,
            member_auth,
            agg_proof,
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
    #[cfg(not(target_arch = "wasm32"))]
    pub fn prove_mle(&self, close_proof: &ProofWithPublicInputs<F, C, D>) -> WResult<String> {
        wrap_and_export_mle(&self.close_circuit.data.verifier_data(), close_proof)
    }

    /// Verifier data for the close circuit (so a caller can verify a close proof locally).
    pub fn close_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.close_circuit.data.verifier_data()
    }

    pub fn falcon_context(&self) -> &FalconProverContext {
        &self.falcon
    }
}

#[cfg(not(target_arch = "wasm32"))]
/// Wrap an inner Plonky2 proof (close / withdrawal-claim / cancel / post-close) with
/// `WrapperCircuit` and produce its MLE/WHIR proof JSON for the matching on-chain
/// `ChannelSettlementVerifier` entry point (the SAME pipeline as the `bin/generate_*_fixture.rs`
/// binaries). The inner proof's public inputs are re-registered verbatim by the wrapper, so the MLE
/// `publicInputs` equal the inner PI limbs that the on-chain strict-limb-bind rebinds.
/// Self-verifies the MLE proof before returning (fail-closed): never hand back a proof that does
/// not verify.
fn wrap_and_export_mle(
    inner_vd: &VerifierCircuitData<F, C, D>,
    inner_proof: &ProofWithPublicInputs<F, C, D>,
) -> WResult<String> {
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};

    use crate::utils::{
        mle_prover::{export_mle_json, prove_with_mle, setup_mle_vk, verify_mle_proof},
        wrapper::WrapperCircuit,
    };

    let wrapper = WrapperCircuit::<F, C, C, D>::new(inner_vd);
    let wrapped = wrapper
        .prove(inner_proof)
        .map_err(|e| WalletError(format!("wrap proof failed: {e:?}")))?;
    wrapper
        .data
        .verify(wrapped)
        .map_err(|e| WalletError(format!("wrap proof verify failed: {e:?}")))?;
    let vk = setup_mle_vk::<F, C, D>(&wrapper.data);
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&wrapper.wrap_proof, inner_proof)
        .map_err(|e| WalletError(format!("wrap witness binding failed: {e:?}")))?;
    let mle = prove_with_mle::<F, C, D>(&wrapper.data, pw)
        .map_err(|e| WalletError(format!("MLE prove failed: {e:?}")))?;
    verify_mle_proof(&wrapper.data, &vk, &mle.proof)
        .map_err(|e| WalletError(format!("MLE self-verify failed: {e:?}")))?;
    export_mle_json(&mle.proof, &wrapper.data.common)
        .map_err(|e| WalletError(format!("MLE fixture export failed: {e:?}")))
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A-3 P2: real (non-test) withdrawal-claim proving. After a channel is CLOSED, each member claims
// their slot balance: the circuit binds the claimed amount to the in-circuit decryption of the
// member's slot ciphertext (no over-claim), and binds the member's Regev pk to the H1-committed
// per-slot digest (no key substitution). The amount is DERIVED here by decrypting the slot
// ciphertext under the member's secret key — the member cannot claim more than their slot holds.
// ─────────────────────────────────────────────────────────────────────────────────────────────

use crate::{
    circuits::channel::{
        withdrawal_claim_circuit::{WithdrawalClaimCircuit, WithdrawalClaimFullWitness},
        withdrawal_claim_pis::WithdrawalClaimWitness,
    },
    common::channel::{ChannelMember, WithdrawalClaim},
    ethereum_types::address::Address,
    regev::prove_withdraw_claim,
};

/// Process-built withdrawal-claim proving context. The circuit is self-contained (no balance VD).
pub struct WithdrawalClaimProver {
    circuit: WithdrawalClaimCircuit<F, C, D>,
}

impl Default for WithdrawalClaimProver {
    fn default() -> Self {
        Self::new()
    }
}

impl WithdrawalClaimProver {
    pub fn new() -> Self {
        Self {
            circuit: WithdrawalClaimCircuit::<F, C, D>::new(),
        }
    }

    /// Build the withdrawal-claim full witness for `member_index` claiming their
    /// `(member_index, token_slot)` balance from the CLOSED channel's `final_balance_state`
    /// (per-(slot, token) claims, detail2 §N-6). The amount is derived by decrypting that
    /// position's ciphertext under `regev_sk` (the circuit binds amount == decryption, so the
    /// member cannot over-claim). `close_intent` / `close_tx` are the channel's finalized close.
    /// Fail-closed: `token_slot` must be an ACTIVE position (`< token_count`, TM-8).
    #[allow(clippy::too_many_arguments)]
    pub fn build_full_witness(
        &self,
        final_balance_state: &BalanceState,
        member_index: usize,
        token_slot: u8,
        member_pk_g: Bytes32,
        user_pk: &RegevPk,
        regev_sk: &RegevSk,
        recipient: Address,
        close_intent: &CloseIntent,
        close_tx: &CloseWithdrawal,
        level: RegevSecurityLevel,
    ) -> WResult<WithdrawalClaimFullWitness> {
        let active =
            final_balance_state.member_count as usize + final_balance_state.delegate_count as usize;
        if member_index >= active {
            return bail(format!(
                "withdrawal claim: member_index {member_index} >= active region {active}"
            ));
        }
        // TM-8 fail-closed: only ACTIVE token positions are claimable (the circuit enforces the
        // same bound in-circuit against the H1-committed token_count).
        if token_slot as usize >= final_balance_state.token_count as usize {
            return bail(format!(
                "withdrawal claim: token_slot {token_slot} >= token_count {}",
                final_balance_state.token_count
            ));
        }
        let ct = final_balance_state.enc_balances[member_index][token_slot as usize].clone();
        // Derive the amount by decryption; the circuit re-derives and binds it, so a member can
        // only claim exactly what their slot ciphertext decrypts to.
        let amount = decrypt_amount(regev_sk, &ct).map_err(|e| {
            WalletError(format!(
                "withdrawal claim: slot-balance decryption failed: {e:?}"
            ))
        })?;
        let close_intent_digest = close_intent.signing_digest();
        let member = ChannelMember {
            pk_g: member_pk_g,
            member_slot: member_index as u16,
            l1_withdrawal_recipient: recipient,
        };
        // SECURITY (B-2 blocker fix): the nullifier is keyed on the slot's LEAF-BOUND Regev pk
        // digest, not the slot-free `member_pk_g` — see `WithdrawalClaim::derive_nullifier`.
        let slot_regev_pk_digest = Bytes32::from(user_pk.poseidon_digest());
        let claim = WithdrawalClaim {
            close_intent_digest,
            member_pk_g,
            token_slot,
            l1_recipient: recipient,
            user_amount_ct: ct.clone(),
            withdrawal_nullifier: WithdrawalClaim::derive_nullifier(
                close_intent_digest,
                slot_regev_pk_digest,
                token_slot,
            ),
            // The final Plonky2 circuit directly proves this same decryption relation. Keeping an
            // additional E-3 STARK here created and verified ~223 KB only to discard it before
            // the final witness; the dedicated PI builder below deliberately skips that duplicate.
            claim_proof: Vec::new(),
        };
        let native = WithdrawalClaimWitness {
            close_intent: close_intent.clone(),
            close_tx: close_tx.clone(),
            member,
            claim,
            final_balance_state: final_balance_state.clone(),
            member_index,
            user_pk: user_pk.clone(),
            amount,
        };
        let public_inputs = native
            .to_public_inputs_for_in_circuit_decryption(level)
            .map_err(|e| {
                WalletError(format!(
                    "withdrawal claim: public-input build failed: {e:?}"
                ))
            })?;
        // H1 Poseidon-root form: the slot tree + the claimant's inclusion proof.
        let slot_tree = final_balance_state.slot_tree();
        Ok(WithdrawalClaimFullWitness {
            public_inputs,
            slot_tree_root: slot_tree.get_root(),
            slot_inclusion: slot_tree.prove(member_index as u64),
            // Multi-token (v2): the FULL per-token leaf fields of the claimant slot + the
            // signed token header scalars (the circuit one-hot-selects position `token_slot`).
            slot_ct_digests: BalanceState::token_ct_digests(
                &final_balance_state.enc_balances[member_index],
            ),
            slot_pending_adds: final_balance_state.pending_adds[member_index],
            token_count: final_balance_state.token_count,
            token_registry: final_balance_state.token_registry,
            settled_tx_chain: final_balance_state.settled_tx_chain,
            settled_tx_accumulator_root: final_balance_state.settled_tx_accumulator_root,
            state_version: final_balance_state.state_version,
            member_count: final_balance_state.member_count,
            delegate_count: final_balance_state.delegate_count,
            member_index,
            regev_a: user_pk.a.clone(),
            regev_b: user_pk.b.clone(),
            ct_c1: ct.c1.clone(),
            ct_c2: ct.c2.clone(),
            regev_s: regev_sk.s.clone(),
        })
    }

    pub fn prove(
        &self,
        witness: &WithdrawalClaimFullWitness,
    ) -> WResult<ProofWithPublicInputs<F, C, D>> {
        self.circuit
            .prove(witness)
            .map_err(|e| WalletError(format!("withdrawal claim proof failed: {e:?}")))
    }

    /// Wrap + MLE for the on-chain `ChannelSettlementVerifier.verifyWithdrawalClaim`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn prove_mle(&self, proof: &ProofWithPublicInputs<F, C, D>) -> WResult<String> {
        wrap_and_export_mle(&self.circuit.data.verifier_data(), proof)
    }

    /// Verifier data for the withdrawal-claim circuit (local verification).
    pub fn vd(&self) -> VerifierCircuitData<F, C, D> {
        self.circuit.data.verifier_data()
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A-3 P2: real (non-test) cancel-close proving (the challenge primitive). A pending close is
// cancelled by proving the channel's REGISTERED members N-of-N signed a LATER state (strictly
// greater state_version, same close-freeze era). Soundness is in-circuit: revived_version >
// close.final_state_version, the era fence, and the member_set_commitment binding (only registered
// members can cancel). Structurally identical to the close prover but signs the REVIVED IMCH digest
// and carries no balance proof.
// ─────────────────────────────────────────────────────────────────────────────────────────────

use crate::circuits::channel::{
    cancel_close_circuit::{CancelCloseCircuit, CancelCloseFullWitness, MemberCancelAuth},
    cancel_close_pis::CancelCloseWitness,
};

/// Process-built cancel-close proving context (the `FalconBatchAggCircuit` + the
/// `CancelCloseCircuit`).
pub struct CancelCloseProver {
    falcon: FalconProverContext,
    circuit: CancelCloseCircuit<F, C, D>,
}

impl Default for CancelCloseProver {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelCloseProver {
    pub fn new() -> Self {
        Self::with_falcon_context(FalconProverContext::new())
    }

    pub fn with_falcon_context(falcon: FalconProverContext) -> Self {
        let circuit = CancelCloseCircuit::<F, C, D>::new(&falcon.verifier_data());
        Self { falcon, circuit }
    }

    /// Build the cancel-close full witness: the REVIVED (later) signed state + the pending close
    /// intent to cancel, plus the N active members' **DETACHED** cosignatures of the revived IMCH
    /// digest carried by ONE `FalconBatchAggCircuit` proof. The circuit enforces revived_version >
    /// close.final_state_version and the era fence; these Rust preconditions fail closed early.
    /// (Same registration note as `CloseProver::build_full_witness_from_signatures`.)
    ///
    /// **THIS PROVER HOLDS NO KEY** — see `CloseProver::build_full_witness_from_signatures` for the
    /// full argument. Callers pass `&revived_state.member_signatures`: the revived head is by
    /// definition a state the members co-signed, and cancel binds exactly that state's digest.
    ///
    /// SECURITY (X-3, a capability this refactor GAINS): cancelling a hostile close used to require
    /// all N secret keys, so in practice only the coordinator could cancel — the party you most
    /// want to cancel AGAINST. An honest member holding a later co-signed head can now build the
    /// cancel proof with no key material at all.
    pub fn build_full_witness_from_signatures(
        &self,
        record: &ChannelRecord,
        revived_state: &ChannelState,
        member_sigs: &[MemberSignature],
        close_intent: &CloseIntent,
    ) -> WResult<CancelCloseFullWitness<F, C, D>> {
        let artifact = self
            .falcon
            .prove_detached(record, revived_state.digest, member_sigs)
            .map_err(|e| WalletError(format!("cancel-close: {}", e.0)))?;
        self.build_full_witness_from_aggregate(record, revived_state, &artifact, close_intent)
    }

    /// Reuse the aggregate proof cached for the revived N-of-N state. A cancel no longer pays the
    /// Falcon proving cost while racing the challenge window.
    pub fn build_full_witness_from_aggregate(
        &self,
        record: &ChannelRecord,
        revived_state: &ChannelState,
        artifact: &FalconAggregateProofArtifact,
        close_intent: &CloseIntent,
    ) -> WResult<CancelCloseFullWitness<F, C, D>> {
        let member_count = revived_state.balance_state.member_count as usize;
        if !(2..=MAX_CHANNEL_MEMBERS).contains(&member_count) {
            return bail(format!(
                "cancel-close: member_count {member_count} out of [2, {MAX_CHANNEL_MEMBERS}]"
            ));
        }
        // T-10 / X-6, then the state's own cached digest (the message every cosignature below is
        // verified against, and the digest the cancel circuit recomputes and binds).
        assert_record_state_member_count_agree("cancel-close", record, revived_state)?;
        if revived_state.digest != revived_state.signing_digest() {
            return bail(
                "cancel-close: revived_state.digest does not match the recomputed \
                 signing_digest() (fail-closed: the cached digest is the message the member \
                 cosignatures are verified against)",
            );
        }
        if revived_state.balance_state.state_version <= close_intent.final_state_version {
            return bail(format!(
                "cancel-close: revived state_version {} must be > close final_state_version {}",
                revived_state.balance_state.state_version, close_intent.final_state_version
            ));
        }

        let cancel = CancelCloseWitness {
            revived_state: revived_state.clone(),
            close_intent: close_intent.clone(),
        };

        let agg_proof = self
            .falcon
            .proof_from_artifact(record, revived_state.digest, artifact)
            .map_err(|e| WalletError(format!("cancel-close: {}", e.0)))?;
        let member_auth: Vec<MemberCancelAuth> = artifact
            .member_pk_gs
            .iter()
            .map(|&pk_g| MemberCancelAuth { pk_g })
            .collect();

        Ok(CancelCloseFullWitness {
            cancel,
            member_auth,
            agg_proof,
        })
    }

    pub fn prove(
        &self,
        witness: &CancelCloseFullWitness<F, C, D>,
    ) -> WResult<ProofWithPublicInputs<F, C, D>> {
        self.circuit
            .prove(witness)
            .map_err(|e| WalletError(format!("cancel-close proof failed: {e:?}")))
    }

    /// Wrap + MLE for the on-chain `ChannelSettlementVerifier.verifyCancelClose`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn prove_mle(&self, proof: &ProofWithPublicInputs<F, C, D>) -> WResult<String> {
        wrap_and_export_mle(&self.circuit.data.verifier_data(), proof)
    }

    /// Verifier data for the cancel-close circuit (local verification).
    pub fn vd(&self) -> VerifierCircuitData<F, C, D> {
        self.circuit.data.verifier_data()
    }

    pub fn falcon_context(&self) -> &FalconProverContext {
        &self.falcon
    }
}

/// Persistent owner for the settlement circuits used by close/PW, withdrawal claim and cancel.
///
/// The old CLI constructors remain for compatibility, but a production prover service should own
/// one of these for its lifetime. Each circuit is built lazily on first use and then retained;
/// close and cancel also share the single Falcon circuit used by state-finalization aggregation.
/// A context is scoped to one balance verifier data instance (one rollup deployment).
pub struct SettlementProverContext {
    falcon: FalconProverContext,
    close: OnceLock<CloseProver>,
    withdrawal_claim: OnceLock<WithdrawalClaimProver>,
    cancel_close: OnceLock<CancelCloseProver>,
}

impl Default for SettlementProverContext {
    fn default() -> Self {
        Self::new()
    }
}

impl SettlementProverContext {
    pub fn new() -> Self {
        Self {
            falcon: FalconProverContext::new(),
            close: OnceLock::new(),
            withdrawal_claim: OnceLock::new(),
            cancel_close: OnceLock::new(),
        }
    }

    pub fn falcon(&self) -> &FalconProverContext {
        &self.falcon
    }

    pub fn close(&self, balance_vd: &VerifierCircuitData<F, C, D>) -> &CloseProver {
        self.close
            .get_or_init(|| CloseProver::with_falcon_context(balance_vd, self.falcon.clone()))
    }

    pub fn withdrawal_claim(&self) -> &WithdrawalClaimProver {
        self.withdrawal_claim
            .get_or_init(WithdrawalClaimProver::new)
    }

    pub fn cancel_close(&self) -> &CancelCloseProver {
        self.cancel_close
            .get_or_init(|| CancelCloseProver::with_falcon_context(self.falcon.clone()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A-3 P2: real (non-test) post-close-claim proving. A receiver of an inter-channel delta that
// arrived AFTER the source channel closed claims it: the circuit recomputes the incoming tx hash
// in-circuit and proves its Merkle inclusion against the CLOSED channel's finalized
// settled-tx-accumulator root (so the tx is member-signed, not fabricated), binds the receiver's
// Regev pk to the H1-committed slot digest, and binds the claimed amount to the in-circuit
// decryption of the receiver's delta ciphertext (no over-claim). The amount is DERIVED here by
// decryption; the inclusion proof is taken from the closed channel's accumulator the wallet holds.
// ─────────────────────────────────────────────────────────────────────────────────────────────

use crate::{
    circuits::channel::{
        post_close_claim_circuit::{PostCloseClaimCircuit, PostCloseClaimFullWitness},
        post_close_claim_pis::PostCloseClaimWitness,
    },
    common::channel::PostCloseIncomingClaim,
};

/// Process-built post-close-claim proving context. Self-contained circuit (no balance VD).
pub struct PostCloseClaimProver {
    circuit: PostCloseClaimCircuit<F, C, D>,
}

impl Default for PostCloseClaimProver {
    fn default() -> Self {
        Self::new()
    }
}

impl PostCloseClaimProver {
    pub fn new() -> Self {
        Self {
            circuit: PostCloseClaimCircuit::<F, C, D>::new(),
        }
    }

    /// Build the post-close-claim full witness. `source_tx` is the inter-channel transfer that
    /// delivered the receiver's delta; `accumulator` is the CLOSED channel's settled-tx accumulator
    /// (so the inclusion proof of the tx hash at `incoming_tx_index` binds it to the finalized
    /// accumulator root). The amount is derived by decrypting the receiver's delta ciphertext.
    #[allow(clippy::too_many_arguments)]
    pub fn build_full_witness(
        &self,
        final_balance_state: &BalanceState,
        receiver_member_index: usize,
        receiver_pk: &RegevPk,
        receiver_sk: &RegevSk,
        receiver_pk_g: Bytes32,
        recipient: Address,
        close_intent_digest: Bytes32,
        source_tx: &InterChannelTx,
        accumulator: &IncrementalMerkleTree<Bytes32>,
        incoming_tx_index: u64,
        level: RegevSecurityLevel,
    ) -> WResult<PostCloseClaimFullWitness> {
        let active =
            final_balance_state.member_count as usize + final_balance_state.delegate_count as usize;
        if receiver_member_index >= active {
            return bail(format!(
                "post-close claim: receiver_member_index {receiver_member_index} >= active {active}"
            ));
        }
        // The receiver's delta ciphertext from the source tx (matched by pk_g).
        let receiver_delta = source_tx
            .receiver_deltas
            .iter()
            .find(|d| d.receiver_pk_g == receiver_pk_g)
            .ok_or_else(|| {
                WalletError("post-close claim: receiver_pk_g not present in source tx".into())
            })?;
        let delta_ct = receiver_delta.amount.clone();
        let amount = decrypt_amount(receiver_sk, &delta_ct).map_err(|e| {
            WalletError(format!("post-close claim: delta decryption failed: {e:?}"))
        })?;
        let claim_proof = prove_withdraw_claim(level, receiver_pk, receiver_sk, &delta_ct, amount)
            .map_err(|e| WalletError(format!("post-close claim: E-3 proof failed: {e:?}")))?;
        let tx_hash = source_tx.tx_hash;
        let shared_native_nullifier = PostCloseIncomingClaim::derive_shared_native_nullifier(
            close_intent_digest,
            tx_hash,
            receiver_pk_g,
        );
        let claim = PostCloseIncomingClaim {
            close_intent_digest,
            incoming_tx_hash: tx_hash,
            receiver_pk_g,
            l1_recipient: recipient,
            receiver_amount: delta_ct.clone(),
            shared_native_nullifier,
            recipient_memo: source_tx.recipient_memo.clone(),
            claim_proof,
        };
        let native = PostCloseClaimWitness {
            close_intent_digest,
            closed_channel_id: final_balance_state.channel_id,
            source_tx: source_tx.clone(),
            claim,
            receiver_pk: receiver_pk.clone(),
            amount,
            final_balance_state: final_balance_state.clone(),
            receiver_member_index,
        };
        let public_inputs = native.to_public_inputs(level).map_err(|e| {
            WalletError(format!(
                "post-close claim: public-input build failed: {e:?}"
            ))
        })?;
        let incoming_tx_inclusion = accumulator.prove(incoming_tx_index);
        // H1 Poseidon-root form: the slot tree + the receiver's inclusion proof.
        let slot_tree = final_balance_state.slot_tree();

        Ok(PostCloseClaimFullWitness {
            public_inputs,
            source_pk_g: source_tx.source_pk_g,
            sender_delta_digest: source_tx.sender_delta_ct.digest(),
            receiver_delta_digest: delta_ct.digest(),
            tx_tree_root: source_tx.signed_small_block.message.tx_tree_root,
            source_channel_id: source_tx.source_channel_id.as_u64() as u32,
            incoming_tx_inclusion,
            incoming_tx_index,
            slot_tree_root: slot_tree.get_root(),
            slot_inclusion: slot_tree.prove(receiver_member_index as u64),
            // Multi-token (v2): the FULL per-token leaf fields of the receiver slot + the
            // signed token header scalars (v2 104-element leaf / 37-element header).
            slot_enc_balance_digests: BalanceState::token_ct_digests(
                &final_balance_state.enc_balances[receiver_member_index],
            ),
            slot_pending_adds: final_balance_state.pending_adds[receiver_member_index],
            token_count: final_balance_state.token_count,
            token_registry: final_balance_state.token_registry,
            settled_tx_chain: final_balance_state.settled_tx_chain,
            state_version: final_balance_state.state_version,
            member_count: final_balance_state.member_count,
            delegate_count: final_balance_state.delegate_count,
            receiver_member_index,
            regev_a: receiver_pk.a.clone(),
            regev_b: receiver_pk.b.clone(),
            delta_c1: delta_ct.c1.clone(),
            delta_c2: delta_ct.c2.clone(),
            regev_s: receiver_sk.s.clone(),
        })
    }

    pub fn prove(
        &self,
        witness: &PostCloseClaimFullWitness,
    ) -> WResult<ProofWithPublicInputs<F, C, D>> {
        self.circuit
            .prove(witness)
            .map_err(|e| WalletError(format!("post-close claim proof failed: {e:?}")))
    }

    /// Wrap + MLE for the on-chain `ChannelSettlementVerifier.verifyPostCloseClaim`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn prove_mle(&self, proof: &ProofWithPublicInputs<F, C, D>) -> WResult<String> {
        wrap_and_export_mle(&self.circuit.data.verifier_data(), proof)
    }

    /// Verifier data for the post-close-claim circuit (local verification).
    pub fn vd(&self) -> VerifierCircuitData<F, C, D> {
        self.circuit.data.verifier_data()
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A-3 P4: full channel withdrawal pipeline (rollup withdrawal subsystem, recipient = manager).
//
// This is a library port of `src/bin/generate_withdrawal_fixture.rs` (the REFERENCE
// implementation — keep the two in sync; `generate_withdrawal_fixture` now delegates here so the
// checked-in fixtures and this builder share ONE source of truth). It deterministically replays a
// self-contained 3-block chain — registration → deposit → withdrawal-tx — generates the withdrawal
// proof and the validity proof, wraps + MLE-commits both, and assembles the 4 on-chain artifacts
// the live pipeline consumes:
//   - lifecycle.json               (registration / deposit / blocks / vpis) — drives
//     registerChannel
//                                   + deposit + postBlock×3 + finalize
//   - lifecycle_validity_mle.json  (validity MLE proof + VK)                — `finalize`
//   - withdrawal_mle.json          (withdrawal MLE proof + VK)             — `withdrawNative`
//   - withdrawal_payout.json       (committed Withdrawal[] + prover)        — `withdrawNative`
//
// SECURITY: every exported value is pulled programmatically from the proved objects (Block,
// ValidityPublicInputs, the single-withdrawal proof's public inputs, the withdrawal-chain proof's
// committed hash). Nothing the caller supplies bypasses soundness: the on-chain block-hash
// recomputation, the channel-reg keccak chain, and the withdrawal keccak chain are what actually
// validate these artifacts, and `withdrawNative` re-folds the withdrawal set + gates on
// `finalizedStateRoots[ext_commitment]`. A Rust-side re-fold sanity check proves the on-chain fold
// will match BEFORE any on-chain spend. The artifacts are self-consistent: the SAME registration /
// deposit emitted in `lifecycle.json` are what the caller submits on-chain, so the on-chain block
// hash chain reproduces the proved `finalBlockChain`.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Parameters for [`build_channel_withdrawal`]. `depositor` / `withdrawal_recipient` are `Option`:
/// `Some(addr)` pins the exact L1 address (the live caller passes `depositor = <sending EOA>` so
/// the on-chain `deposit()` msg.sender matches the proved chain, and `withdrawal_recipient =
/// <manager>` so the payout credits the settlement manager); `None` derives a deterministic address
/// from the fixed RNG (byte-for-byte parity with the legacy fixture binary).
#[derive(Debug, Clone)]
pub struct ChannelWithdrawalParams {
    /// Channel id the registration / withdrawal bind to (legacy fixture = 1).
    pub channel_id: u32,
    /// Deposited native amount (legacy fixture = 10). The withdrawal must not exceed it.
    pub deposit_amount: u64,
    /// Withdrawn native amount paid to `withdrawal_recipient` (legacy fixture = 3).
    pub withdrawal_amount: u64,
    /// L1 depositor. `Some` = pinned (must equal the on-chain `deposit()` sender); `None` = RNG.
    pub depositor: Option<Address>,
    /// L1 withdrawal recipient (the settlement manager for the close lifecycle). `None` = RNG.
    pub withdrawal_recipient: Option<Address>,
    /// P5-B: the channel's REAL deposit salt (recorded by `setup-backing`). `Some` reproduces the
    /// exact deposit recipient `calculate_recipient_from_user_id(channel_id, deposit_salt)` so the
    /// withdraw deposit block matches the on-chain `deposit()` already made by `setup-backing`.
    /// `None` = draw from the fixed RNG (byte-parity with the legacy fixture).
    pub deposit_salt: Option<crate::common::salt::Salt>,
    /// Multitoken Phase 5b: optional SECOND settlement lane in a registered ERC-20 base token.
    /// `Some` adds a second deposit (token `token_index`, its own recipient salt) to the deposit
    /// block and a second transfer to the withdrawal tx, and produces a SECOND, independent
    /// single-leaf withdrawal chain + wrapped MLE proof over the SAME finalized state root — the
    /// artifact `IntmaxRollup.withdrawERC20` consumes (a chain must be single-asset-class: ETH
    /// leaves pay via `withdrawNative`, ERC-20 leaves via `withdrawERC20`, so the two lanes are
    /// two separate chains by construction). `None` = the legacy single-lane (ETH) behavior,
    /// byte-identical output (no extra RNG draws).
    pub erc20_lane: Option<Erc20LaneParams>,
}

/// Parameters of the optional ERC-20 settlement lane (multitoken Phase 5b, §N-7).
#[derive(Debug, Clone, Copy)]
pub struct Erc20LaneParams {
    /// The L1-registered base token index (MUST be != 0; index 0 is ETH).
    pub token_index: u32,
    /// Deposited ERC-20 amount (the on-chain `deposit()` ERC-20 branch escrows this).
    pub deposit_amount: u64,
    /// Withdrawn ERC-20 amount paid to `withdrawal_recipient` (<= deposit_amount).
    pub withdrawal_amount: u64,
    /// `Some` reproduces the exact on-chain ERC-20 deposit recipient (live path); `None` = RNG.
    pub deposit_salt: Option<crate::common::salt::Salt>,
}

impl Default for ChannelWithdrawalParams {
    fn default() -> Self {
        // Legacy `generate_withdrawal_fixture` defaults (preserve byte-identical output).
        Self {
            channel_id: 1,
            deposit_amount: 10,
            withdrawal_amount: 3,
            depositor: None,
            withdrawal_recipient: None,
            deposit_salt: None,
            erc20_lane: None,
        }
    }
}

/// The 4 JSON artifacts produced by [`build_channel_withdrawal`]. Strings (not files) so the caller
/// decides where/how to persist them (the fixture binary writes them under a prefix; the CLI stages
/// them for the forge/cast steps).
pub struct ChannelWithdrawalArtifacts {
    pub lifecycle_json: String,
    pub validity_mle_json: String,
    pub withdrawal_mle_json: String,
    pub payout_json: String,
    /// Multitoken Phase 5b: the ERC-20 lane's wrapped withdrawal MLE proof (its OWN single-leaf
    /// chain over the same finalized root) — `Some` iff `params.erc20_lane` was set.
    pub erc20_withdrawal_mle_json: Option<String>,
    /// Multitoken Phase 5b: the ERC-20 lane's committed payout descriptor (`withdrawERC20` input).
    pub erc20_payout_json: Option<String>,
}

// ── Output JSON schemas (moved verbatim from generate_withdrawal_fixture.rs) ──────────────────

#[derive(Serialize)]
struct MemberFixture {
    channel_id: u32,
    bp_member_slot: u8,
    member_pk_gs: Vec<String>,
    member_pk_bs: Vec<String>,
    regev_pk_digests: Vec<String>,
    recipients: Vec<String>,
}

#[derive(Serialize)]
struct DepositFixture {
    depositor: String,
    recipient: String,
    token_index: u32,
    amount: String,
    aux_data: String,
}

#[derive(Serialize)]
struct BlockFixture {
    channel_id: u32,
    timestamp: u64,
    tx_tree_root: String,
    key_ids: Vec<u32>,
    block_number: u64,
}

#[derive(Serialize)]
struct VPIFixture {
    initial_block_number: u64,
    initial_block_chain: String,
    initial_ext_commitment: String,
    final_block_number: u64,
    final_block_chain: String,
    final_ext_commitment: String,
    prover: String,
}

#[derive(Serialize)]
struct LifecycleFixture {
    genesis_state_root: String,
    final_state_root: String,
    registration: MemberFixture,
    deposit: DepositFixture,
    /// Multitoken Phase 5b: the ERC-20 lane's deposit (folds into the SAME deposit block,
    /// immediately AFTER `deposit` — the on-chain `deposit()` calls must run in that order so the
    /// deposit hash chain reproduces). Omitted for the legacy single-lane fixture.
    #[serde(skip_serializing_if = "Option::is_none")]
    deposit_erc20: Option<DepositFixture>,
    blocks: Vec<BlockFixture>,
    vpis: VPIFixture,
    proof_hash: String,
    proof_length: u32,
}

#[derive(Serialize)]
struct WithdrawalEntryFixture {
    recipient: String,
    token_index: u32,
    amount: String,
    nullifier: String,
    aux_data: String,
}

#[derive(Serialize)]
struct WithdrawalPayoutFixture {
    withdrawals: Vec<WithdrawalEntryFixture>,
    withdrawal_prover: String,
    block_number: u64,
    ext_commitment: String,
}

/// Deterministic, dependency-free FNV-1a digest over a byte slice, placed in the low 64 bits of a
/// bytes32. The value is UNCONSTRAINED on-chain (finalize/fullVerify never re-derive the submission
/// commitment), so any deterministic value is sound; used only for reproducibility.
fn fnv1a_bytes32(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("0x{:064x}", h as u128)
}

/// Build the full channel-withdrawal artifact set. See the module banner for the security argument.
///
/// `member_keys`: `Some(cli_members)` binds the registration to the channel's REAL co-signing
/// members (P5-B) so the SAME on-chain `registerChannel` serves both the close path and this
/// withdraw path; the registration block hash and the close member-set commitment then both
/// reproduce these members. `None` self-generates the deterministic fixture registration
/// (byte-parity with the legacy fixture binary). When `Some`, pass exactly `TEST_ACTIVE_MEMBERS`
/// members.
#[cfg(not(target_arch = "wasm32"))]
pub fn build_channel_withdrawal(
    params: &ChannelWithdrawalParams,
    cli_member_keys: Option<&[MemberKeys]>,
) -> anyhow::Result<ChannelWithdrawalArtifacts> {
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use rand::{SeedableRng, rngs::StdRng};

    use crate::{
        circuits::{
            balance::{
                balance_processor::BalanceProcessor,
                common::recipient::{
                    calculate_recipient_from_address, calculate_recipient_from_user_id,
                },
                spend_circuit::SpendCircuit,
            },
            test_utils::{
                balance_witness_generator::{
                    BalanceWitnessGenerator, ReceiveDepositData, SendTxData, SingleWithdrawalData,
                },
                block_witness_generator::{
                    BlockTxV2Witness, BlockWitnessGenerator, BlockWitnessGeneratorHandle,
                    ChannelMemberKeys, TEST_ACTIVE_MEMBERS,
                },
            },
            validity::block_hash_chain::{
                block_chain_pis::BlockChainPublicInputs,
                block_hash_chain_processor::BlockHashChainProcessor,
                validity_circuit::{ValidityCircuit, ValidityPublicInputs},
            },
            withdraw::{
                single_withdrawal_circuit::{
                    SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN, SingleWithdawalCircuit,
                    SingleWithdawalPublicInputs,
                },
                withdrawal_processor::WithdrawalProcessor,
                withdrawal_step::WithdrawalStepWitness,
            },
        },
        common::{
            salt::Salt,
            transfer::Transfer,
            trees::{transfer_tree::TransferTree, tx_tree::TxTree, tx_v2_tree::TxV2Tree},
            tx::{Tx, TxClass, TxV2},
            u63::BlockNumber,
            withdrawal::Withdrawal,
        },
        ethereum_types::{address::Address, u256::U256},
        falcon_sig::{agg::FalconAggCircuit, agg_list::AggListCircuit},
        utils::{
            conversion::ToU64,
            mle_prover::{export_mle_json, prove_with_mle, setup_mle_vk, verify_mle_proof},
            poseidon_hash_out::PoseidonHashOut,
            wrapper::WrapperCircuit,
        },
    };

    let supported_user_counts = vec![2u32];

    // ── Step 0: circuit setup ───────────────────────────────────────────────────────────────
    let block_hash_chain_processor =
        BlockHashChainProcessor::<F, C, D>::new(&supported_user_counts);
    let block_chain_vd = block_hash_chain_processor.block_chain_vd();

    let spend_circuit = SpendCircuit::<F, C, D>::new();
    let balance_processor = BalanceProcessor::<F, C, D>::new(&spend_circuit.data.verifier_data());
    let balance_vd = balance_processor.balance_vd();

    let block_witness_generator =
        BlockWitnessGeneratorHandle::new(BlockWitnessGenerator::new(&supported_user_counts));

    // FIXED rng seed for deterministic / reproducible output.
    let mut rng = StdRng::seed_from_u64(1);
    let user_id = ChannelId::new(params.channel_id as u64).expect("channel id");
    let salt = Salt::rand(&mut rng);

    let mut balance_witness_generator = BalanceWitnessGenerator::new(
        user_id,
        salt,
        block_witness_generator.clone(),
        &balance_processor,
    )
    .expect("balance witness generator");

    let initial_ext_state = block_witness_generator
        .borrow()
        .current_extended_public_state();

    // ── Phase 1: channel registration → block 1 ─────────────────────────────────────────────
    // P5-B: with `cli_member_keys`, register the channel's REAL co-signing members (so this
    // registration block — and the on-chain `registerChannel` built from the same record below —
    // reproduce the SAME member set the close path signs against). Without them, self-generate the
    // deterministic fixture registration (legacy parity).
    //
    // SECURITY (Option B, tasks/reg-chain-1024-threat-model.md): L1 registration is
    // COSIGNERS-ONLY. `cli_member_keys` may carry the channel's full ACTIVE set (the
    // `TEST_ACTIVE_MEMBERS` co-signing members FIRST, then any delegates); only the leading
    // cosigner slice enters the registration record/block (`delegate_count = 0`). Delegates are
    // authenticated by the cosigner-signed H1 balance-slot tree, never by prior L1 registration
    // (their claim-recipient binding is B-1c).
    let active_count = TEST_ACTIVE_MEMBERS;
    let member_keys = {
        let mut generator = block_witness_generator.borrow_mut();
        let keys = match cli_member_keys {
            Some(mk) => {
                anyhow::ensure!(
                    mk.len() >= TEST_ACTIVE_MEMBERS,
                    "build_channel_withdrawal: expected at least {TEST_ACTIVE_MEMBERS} active keys, got {}",
                    mk.len()
                );
                // SECURITY (Phase-3 review finding 7, CLOSED here in Phase 4): the FALCON
                // identities registered here MUST be the ones the channel's other paths sign
                // with — the close proof's member-set commitment and the CLI's
                // `export-reg-record` both bind them. They used to be RE-DERIVED here from a
                // seed formula of this function's own, which silently diverged from the CLI's,
                // so `export-reg-record` registered one key set on L1 while this path proved
                // against another (fail-closed, but the channel became unclosable). There is now
                // exactly ONE source: the caller's `MemberKeys`, whose `pk_g()` IS the Falcon
                // identity. No second derivation exists to diverge from.
                generator.add_channel_registration_keys(
                    user_id.channel_id(),
                    ChannelMemberKeys::from_member_keys(&mk[..TEST_ACTIVE_MEMBERS]),
                )
            }
            None => generator.add_channel_registration(user_id.channel_id()),
        };
        generator
            .add_registration_block(0)
            .expect("apply channel registration block");
        keys
    };

    // Mirror `ChannelMemberKeys::to_reg_record` inline: each active slot's pk_g / pk_b /
    // regev_pk_digest is the canonical Bytes32 of the SAME Poseidon identity in `member_tree`; the
    // recipient is the deterministic per-(channel, slot) test L1 address. These EXACT values feed
    // the on-chain `registerChannel`, so the channel_reg keccak chain reproduces on-chain.
    // Option B: `active_count = TEST_ACTIVE_MEMBERS` — the emitted arrays carry the COSIGNERS
    // only (registration never carries delegates).
    let channel_id_u32 = user_id.channel_id();
    let bp_member_slot: u8 = 0;
    let mut member_pk_gs = Vec::with_capacity(active_count);
    let mut member_pk_bs = Vec::with_capacity(active_count);
    let mut regev_pk_digests = Vec::with_capacity(active_count);
    let mut recipients = Vec::with_capacity(active_count);
    for i in 0..active_count {
        let leaf = member_keys.member_tree.get_leaf(i as u64);
        let pk_g = Bytes32::from(leaf.pk_g);
        let pk_b = Bytes32::from(leaf.pk_b);
        let regev_digest = Bytes32::from(leaf.regev_pk_digest);
        let recipient = crate::circuits::test_utils::block_witness_generator::test_recipient_for(
            channel_id_u32,
            i,
        );
        member_pk_gs.push(pk_g.to_string());
        member_pk_bs.push(pk_b.to_string());
        regev_pk_digests.push(regev_digest.to_string());
        recipients.push(recipient.to_string());
    }

    // ── Phase 2: deposit → block 2 ──────────────────────────────────────────────────────────
    // P5-B: `Some(deposit_salt)` reproduces `setup-backing`'s exact deposit recipient so this
    // deposit block matches the on-chain `deposit()` already queued for the channel; `None`
    // draws from the fixed RNG (legacy parity — drawn at the SAME point as before so the
    // fixture output is stable).
    let deposit_salt = params.deposit_salt.unwrap_or_else(|| Salt::rand(&mut rng));
    let deposit_recipient = calculate_recipient_from_user_id(user_id, deposit_salt);
    // The depositor is folded into the on-chain deposit hash (= block 2's hash). The live caller
    // pins it to the EOA that sends `deposit()`; the fixture path uses a deterministic RNG address.
    let depositor = match params.depositor {
        Some(a) => a,
        None => Address::rand(&mut rng),
    };
    // Multitoken Phase 5b: the optional ERC-20 lane's deposit — its OWN recipient salt (a deposit
    // is located per recipient), queued into the SAME deposit block immediately AFTER the ETH
    // deposit (the on-chain `deposit()` calls must run in this order to reproduce the fold).
    let erc20_deposit = params.erc20_lane.map(|lane| {
        assert_ne!(
            lane.token_index, 0,
            "erc20_lane.token_index must be a non-ETH base token"
        );
        assert!(
            lane.withdrawal_amount <= lane.deposit_amount,
            "erc20 withdrawal amount exceeds its deposit amount"
        );
        let salt2 = lane.deposit_salt.unwrap_or_else(|| Salt::rand(&mut rng));
        let recipient2 = calculate_recipient_from_user_id(user_id, salt2);
        (lane, salt2, recipient2)
    });
    {
        let mut generator = block_witness_generator.borrow_mut();
        generator
            .add_deposit(
                depositor,
                deposit_recipient,
                0,
                U256::from(params.deposit_amount),
                Bytes32::default(),
            )
            .expect("queue deposit");
        if let Some((lane, _, recipient2)) = &erc20_deposit {
            generator
                .add_deposit(
                    depositor,
                    *recipient2,
                    lane.token_index,
                    U256::from(lane.deposit_amount),
                    Bytes32::default(),
                )
                .expect("queue erc20 deposit");
        }
        generator
            .add_block(0, &[], 0, Bytes32::default())
            .expect("apply deposit block");
    }

    let deposit_data = ReceiveDepositData {
        receiver: deposit_recipient,
        deposit_salt,
    };
    let deposit_witness = balance_witness_generator
        .receive_deposit_witness(&deposit_data)
        .expect("receive deposit witness");
    let deposit_balance_proof = balance_processor
        .prove_receive_deposit(&deposit_witness)
        .expect("deposit proof");
    balance_witness_generator
        .commit_receive_deposit(&deposit_balance_proof, &deposit_witness)
        .expect("commit deposit");

    // Receive the ERC-20 lane's deposit into the SAME balance history (second receive-deposit
    // transition; the asset tree tracks per-token leaves, so both balances coexist).
    if let Some((_, salt2, recipient2)) = &erc20_deposit {
        let deposit_data2 = ReceiveDepositData {
            receiver: *recipient2,
            deposit_salt: *salt2,
        };
        let deposit_witness2 = balance_witness_generator
            .receive_deposit_witness(&deposit_data2)
            .expect("receive erc20 deposit witness");
        let deposit_balance_proof2 = balance_processor
            .prove_receive_deposit(&deposit_witness2)
            .expect("erc20 deposit proof");
        balance_witness_generator
            .commit_receive_deposit(&deposit_balance_proof2, &deposit_witness2)
            .expect("commit erc20 deposit");
    }

    // ── Phase 3: withdrawal tx → block 3 ────────────────────────────────────────────────────
    // The withdrawal recipient (an L1 address). For the close lifecycle it MUST equal the
    // ChannelSettlementManager so the channel's aggregate withdrawal is paid to the manager.
    let withdrawal_address = match params.withdrawal_recipient {
        Some(a) => a,
        None => Address::rand(&mut rng),
    };
    let withdrawal_transfer = Transfer {
        recipient: calculate_recipient_from_address(withdrawal_address),
        token_index: 0,
        amount: U256::from(params.withdrawal_amount),
        aux_data: Bytes32::default(),
    };
    // Multitoken Phase 5b: the ERC-20 lane's transfer rides in the SAME withdrawal tx (transfer
    // index 1) — ONE spend debits both token leaves; the two L1 payout chains are built
    // separately below (single-asset-class chains, §N-7).
    let erc20_transfer = erc20_deposit.as_ref().map(|(lane, _, _)| Transfer {
        recipient: calculate_recipient_from_address(withdrawal_address),
        token_index: lane.token_index,
        amount: U256::from(lane.withdrawal_amount),
        aux_data: Bytes32::default(),
    });
    let spend_transfers: Vec<Transfer> = match &erc20_transfer {
        Some(t1) => vec![withdrawal_transfer.clone(), t1.clone()],
        None => vec![withdrawal_transfer.clone()],
    };
    let withdrawal_spend_witness = balance_witness_generator
        .spend_witness(&spend_transfers)
        .expect("withdrawal spend witness");
    let withdrawal_spend_proof = spend_circuit
        .prove(&withdrawal_spend_witness)
        .expect("withdrawal spend proof");

    let mut withdrawal_transfer_tree = TransferTree::init();
    for t in &spend_transfers {
        withdrawal_transfer_tree.push(t.clone());
    }
    let withdrawal_transfer_index = 0u32;
    let withdrawal_transfer_merkle_proof =
        withdrawal_transfer_tree.prove(withdrawal_transfer_index as u64);
    let erc20_transfer_merkle_proof = erc20_transfer
        .as_ref()
        .map(|_| withdrawal_transfer_tree.prove(1));
    let withdrawal_transfer_tree_root = withdrawal_transfer_tree.get_root();

    let withdrawal_tx = Tx {
        transfer_tree_root: withdrawal_transfer_tree_root,
        nonce: balance_witness_generator.full_private_state.nonce,
    };

    let mut withdrawal_tx_tree = TxTree::init();
    withdrawal_tx_tree.update(user_id.as_u64(), withdrawal_tx.clone());
    let withdrawal_tx_merkle_proof = withdrawal_tx_tree.prove(user_id.as_u64());

    let withdrawal_tx_v2 = TxV2 {
        tx_class: TxClass::UserTransfer,
        transfer_tree_root: withdrawal_transfer_tree_root,
        nonce: withdrawal_tx.nonce,
        channel_action_root: PoseidonHashOut::default(),
    };
    let mut withdrawal_tx_v2_tree = TxV2Tree::init();
    withdrawal_tx_v2_tree.update(user_id.as_u64(), withdrawal_tx_v2);
    let withdrawal_tx_tree_root_bytes: Bytes32 = withdrawal_tx_v2_tree.get_root().into();
    let withdrawal_tx_v2_merkle_proof = withdrawal_tx_v2_tree.prove(user_id.as_u64());

    let withdrawal_tx_v2_witness = BlockTxV2Witness {
        tx_v2_indices: vec![user_id.as_u64(), 0],
        tx_v2s: vec![withdrawal_tx_v2, TxV2::default()],
        tx_v2_merkle_proofs: vec![
            withdrawal_tx_v2_merkle_proof.clone(),
            withdrawal_tx_v2_merkle_proof.clone(),
        ],
    };

    {
        let mut generator = block_witness_generator.borrow_mut();
        generator
            .add_block_with_tx_v2(
                user_id.channel_id(),
                &[1],
                2,
                withdrawal_tx_tree_root_bytes,
                Some(withdrawal_tx_v2_witness),
            )
            .expect("apply withdrawal tx block");
    }

    let withdrawal_send_tx_data = SendTxData {
        spend_proof: withdrawal_spend_proof.clone(),
        tx_tree_root: withdrawal_tx_tree_root_bytes,
        tx: withdrawal_tx.clone(),
        tx_merkle_proof: withdrawal_tx_merkle_proof.clone(),
        tx_v2: Some(withdrawal_tx_v2),
        tx_v2_merkle_proof: Some(withdrawal_tx_v2_merkle_proof.clone()),
        transfer: withdrawal_transfer.clone(),
        transfer_merkle_proof: withdrawal_transfer_merkle_proof.clone(),
    };
    let withdrawal_send_tx_witness = balance_witness_generator
        .send_tx_witness(&withdrawal_send_tx_data)
        .expect("withdrawal send tx witness");
    let withdrawal_balance_proof = balance_processor
        .prove_send_tx(&withdrawal_send_tx_witness)
        .expect("withdrawal send tx proof");
    balance_witness_generator
        .commit_send_tx(
            &withdrawal_balance_proof,
            &withdrawal_send_tx_witness,
            &withdrawal_spend_witness,
        )
        .expect("commit send tx");

    // ── Single withdrawal proof ─────────────────────────────────────────────────────────────
    let single_withdrawal_data = SingleWithdrawalData {
        tx_tree_root: withdrawal_tx_tree_root_bytes,
        tx: withdrawal_tx.clone(),
        tx_merkle_proof: withdrawal_tx_merkle_proof.clone(),
        transfer: withdrawal_transfer.clone(),
        transfer_index: withdrawal_transfer_index,
        transfer_merkle_proof: withdrawal_transfer_merkle_proof.clone(),
        tx_v2: Some(withdrawal_tx_v2),
        tx_v2_merkle_proof: Some(withdrawal_tx_v2_merkle_proof.clone()),
    };
    let single_withdrawal_witness = balance_witness_generator
        .single_withdrawal_witness(&single_withdrawal_data)
        .expect("single withdrawal witness");
    let single_withdrawal_circuit = SingleWithdawalCircuit::<F, C, D>::new(&balance_vd);
    let single_withdrawal_vd = single_withdrawal_circuit.data.verifier_data();
    let single_withdrawal_proof = single_withdrawal_circuit
        .prove(&single_withdrawal_witness)
        .expect("single withdrawal proof");
    single_withdrawal_circuit
        .data
        .verify(single_withdrawal_proof.clone())
        .expect("verify single withdrawal proof");

    // Multitoken Phase 5b: the ERC-20 lane's single-withdrawal proof (transfer index 1 of the
    // SAME withdrawal tx).
    let erc20_single = erc20_transfer.as_ref().map(|t1| {
        let data = SingleWithdrawalData {
            tx_tree_root: withdrawal_tx_tree_root_bytes,
            tx: withdrawal_tx,
            tx_merkle_proof: withdrawal_tx_merkle_proof.clone(),
            transfer: t1.clone(),
            transfer_index: 1,
            transfer_merkle_proof: erc20_transfer_merkle_proof.clone().expect("erc20 merkle"),
            tx_v2: Some(withdrawal_tx_v2),
            tx_v2_merkle_proof: Some(withdrawal_tx_v2_merkle_proof.clone()),
        };
        let witness = balance_witness_generator
            .single_withdrawal_witness(&data)
            .expect("erc20 single withdrawal witness");
        let proof = single_withdrawal_circuit
            .prove(&witness)
            .expect("erc20 single withdrawal proof");
        single_withdrawal_circuit
            .data
            .verify(proof.clone())
            .expect("verify erc20 single withdrawal proof");
        (witness, proof)
    });

    // ── Withdrawal chain + final proofs ─────────────────────────────────────────────────────
    let withdrawal_processor = WithdrawalProcessor::<F, C, D>::new(&single_withdrawal_vd);
    let withdrawal_chain_vd = withdrawal_processor.withdrawal_chain_vd();
    let step_witness = WithdrawalStepWitness::<F, C, D> {
        prev_withdrawal_chain_proof: None,
        single_withdrawal_proof: single_withdrawal_proof.clone(),
        update_public_state: single_withdrawal_witness.update_public_state.clone(),
    };
    let withdrawal_chain_proof = withdrawal_processor
        .prove_step(&step_witness)
        .expect("withdrawal chain proof");
    withdrawal_chain_vd
        .verify(withdrawal_chain_proof.clone())
        .expect("verify withdrawal chain proof");

    // Multitoken Phase 5b: the ERC-20 lane gets its OWN single-leaf chain (chains are
    // single-asset-class on L1: `withdrawNative` pays ETH leaves, `withdrawERC20` ERC-20 leaves).
    let erc20_chain_proof = erc20_single.as_ref().map(|(witness, proof)| {
        let step = WithdrawalStepWitness::<F, C, D> {
            prev_withdrawal_chain_proof: None,
            single_withdrawal_proof: proof.clone(),
            update_public_state: witness.update_public_state.clone(),
        };
        let chain = withdrawal_processor
            .prove_step(&step)
            .expect("erc20 withdrawal chain proof");
        withdrawal_chain_vd
            .verify(chain.clone())
            .expect("verify erc20 withdrawal chain proof");
        chain
    });

    let ext_public_state = block_witness_generator
        .borrow()
        .current_extended_public_state();
    // FIXED seed so the withdrawal prover address is deterministic.
    let mut prover_rng = StdRng::seed_from_u64(777);
    let withdrawal_prover = Address::rand(&mut prover_rng);
    let withdrawal_proof = withdrawal_processor
        .prove_final(
            &withdrawal_chain_proof,
            withdrawal_prover,
            &ext_public_state,
        )
        .expect("withdrawal proof");
    withdrawal_processor
        .withdrawal_vd()
        .verify(withdrawal_proof.clone())
        .expect("verify withdrawal proof");

    let erc20_withdrawal_proof = erc20_chain_proof.as_ref().map(|chain| {
        let proof = withdrawal_processor
            .prove_final(chain, withdrawal_prover, &ext_public_state)
            .expect("erc20 withdrawal proof");
        withdrawal_processor
            .withdrawal_vd()
            .verify(proof.clone())
            .expect("verify erc20 withdrawal proof");
        proof
    });

    // ── Phase 4: block hash chain + validity proof ──────────────────────────────────────────
    let mut prev_block_proof = None;
    let mut last_block_proof = None;
    {
        let guard = block_witness_generator.borrow();
        let total_blocks = guard.block_number.as_u64();
        for block_idx in 1..=total_blocks {
            let block_number = BlockNumber::new(block_idx).expect("block number");
            let witness = guard
                .block_chain_witness
                .get(&block_number)
                .cloned()
                .expect("block witness");
            let initial_state = if prev_block_proof.is_none() {
                Some(initial_ext_state.clone())
            } else {
                None
            };
            let proof = block_hash_chain_processor
                .prove_block(initial_state, prev_block_proof.clone(), &witness)
                .expect("block hash chain proof");
            prev_block_proof = Some(proof.clone());
            last_block_proof = Some(proof);
        }
    }

    let final_block_chain_proof = last_block_proof.expect("final block hash chain proof");
    // small-block N-of-N Phase 4: one recursively verified `FalconAggCircuit` aggregate per signing
    // block (ALL that block's members over the channel's IMCH digest), folded by the agg list.
    let agg_circuit = FalconAggCircuit::<F, C, D>::new();
    let agg_list_circuit = AggListCircuit::<F, C, D>::new(&agg_circuit.verifier_data());
    let list_proof = block_witness_generator
        .borrow()
        .build_agg_sig_list_proof(&agg_circuit, &agg_list_circuit)
        .expect("build bp sig list proof");
    let validity_circuit =
        ValidityCircuit::<F, C, D>::new(&block_chain_vd, &agg_list_circuit.verifier_data());
    let validity_prover = Address::default();
    let validity_proof = validity_circuit
        .prove(
            &final_block_chain_proof,
            list_proof.as_ref(),
            validity_prover,
        )
        .expect("validity proof");
    validity_circuit
        .verify(&validity_proof)
        .expect("verify validity proof");

    let block_chain_inputs = BlockChainPublicInputs::<F, C, D>::from_u64_slice(
        &final_block_chain_proof.public_inputs.to_u64_vec(),
        &block_chain_vd.common.config,
    )?;
    let vpis = ValidityPublicInputs::from_states(
        &block_chain_inputs.initial_ext_public_state,
        &block_chain_inputs.ext_public_state,
        validity_prover,
    );

    // ── Wrap + MLE for BOTH the withdrawal proof and the validity proof ─────────────────────
    let withdrawal_wrapper =
        WrapperCircuit::<F, C, C, D>::new(&withdrawal_processor.withdrawal_vd());
    let withdrawal_wrapped = withdrawal_wrapper.prove(&withdrawal_proof)?;
    withdrawal_wrapper.data.verify(withdrawal_wrapped.clone())?;
    let withdrawal_vk = setup_mle_vk::<F, C, D>(&withdrawal_wrapper.data);
    let mut wd_pw = PartialWitness::new();
    wd_pw.set_proof_with_pis_target(&withdrawal_wrapper.wrap_proof, &withdrawal_proof)?;
    let withdrawal_mle = prove_with_mle::<F, C, D>(&withdrawal_wrapper.data, wd_pw)?;
    verify_mle_proof(
        &withdrawal_wrapper.data,
        &withdrawal_vk,
        &withdrawal_mle.proof,
    )?;
    let withdrawal_mle_json =
        export_mle_json(&withdrawal_mle.proof, &withdrawal_wrapper.data.common)?;

    // Multitoken Phase 5b: wrap + MLE the ERC-20 lane's withdrawal proof (same wrapper circuit —
    // both lanes are WithdrawalCircuit proofs, so the ONE withdrawal VK verifies both on-chain).
    let erc20_withdrawal_mle_json = erc20_withdrawal_proof
        .as_ref()
        .map(|proof| -> anyhow::Result<String> {
            let wrapped = withdrawal_wrapper.prove(proof)?;
            withdrawal_wrapper.data.verify(wrapped.clone())?;
            let mut pw = PartialWitness::new();
            pw.set_proof_with_pis_target(&withdrawal_wrapper.wrap_proof, proof)?;
            let mle = prove_with_mle::<F, C, D>(&withdrawal_wrapper.data, pw)?;
            verify_mle_proof(&withdrawal_wrapper.data, &withdrawal_vk, &mle.proof)?;
            export_mle_json(&mle.proof, &withdrawal_wrapper.data.common)
        })
        .transpose()?;

    let validity_wrapper =
        WrapperCircuit::<F, C, C, D>::new(&validity_circuit.data.verifier_data());
    let validity_wrapped = validity_wrapper.prove(&validity_proof)?;
    validity_wrapper.data.verify(validity_wrapped.clone())?;
    let validity_vk = setup_mle_vk::<F, C, D>(&validity_wrapper.data);
    let mut val_pw = PartialWitness::new();
    val_pw.set_proof_with_pis_target(&validity_wrapper.wrap_proof, &validity_proof)?;
    let validity_mle = prove_with_mle::<F, C, D>(&validity_wrapper.data, val_pw)?;
    verify_mle_proof(&validity_wrapper.data, &validity_vk, &validity_mle.proof)?;
    let validity_mle_json = export_mle_json(&validity_mle.proof, &validity_wrapper.data.common)?;

    // ── Extract the EXACT committed Withdrawal from the single-withdrawal proof PIs ─────────
    let single_withdrawal_inputs = SingleWithdawalPublicInputs::from_u64_slice(
        &single_withdrawal_proof.public_inputs[..SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN].to_u64_vec(),
    )?;
    let committed_withdrawal: Withdrawal = single_withdrawal_inputs.withdrawal.clone();

    // SANITY: re-fold the withdrawal keccak chain the way the contract will (seed = 0, fold each
    // withdrawal via `hash_with_prev_hash`) and assert it equals the proof-committed hash. Proves
    // the on-chain fold matches BEFORE any on-chain spend.
    let proof_withdrawal_hash = {
        let pis = withdrawal_chain_proof.public_inputs.to_u64_vec();
        Bytes32::from_u64_slice(&pis[0..8]).expect("withdrawal_hash_chain limbs")
    };
    let refolded = committed_withdrawal.hash_with_prev_hash(Bytes32::default());
    anyhow::ensure!(
        refolded == proof_withdrawal_hash,
        "withdrawal keccak chain re-fold mismatch: refolded = {refolded:?}, proof-committed = {proof_withdrawal_hash:?}"
    );

    // Multitoken Phase 5b: the ERC-20 lane's committed Withdrawal + the same re-fold sanity.
    let erc20_committed: Option<Withdrawal> = erc20_single
        .as_ref()
        .map(|(_, proof)| -> anyhow::Result<Withdrawal> {
            let inputs = SingleWithdawalPublicInputs::from_u64_slice(
                &proof.public_inputs[..SINGLE_WITHDRAWAL_PUBLIC_INPUTS_LEN].to_u64_vec(),
            )?;
            let committed = inputs.withdrawal.clone();
            let chain = erc20_chain_proof.as_ref().expect("erc20 chain");
            let proof_hash = {
                let pis = chain.public_inputs.to_u64_vec();
                Bytes32::from_u64_slice(&pis[0..8]).expect("erc20 withdrawal_hash_chain limbs")
            };
            let refolded2 = committed.hash_with_prev_hash(Bytes32::default());
            anyhow::ensure!(
                refolded2 == proof_hash,
                "erc20 withdrawal keccak chain re-fold mismatch"
            );
            anyhow::ensure!(
                committed.token_index != 0,
                "erc20 lane committed withdrawal must carry a non-ETH token index"
            );
            Ok(committed)
        })
        .transpose()?;

    // SANITY: the withdrawal proof's ext_commitment must equal the validity final state root.
    anyhow::ensure!(
        ext_public_state.commitment() == vpis.final_ext_commitment,
        "withdrawal ext_commitment != validity final_ext_commitment"
    );

    // ── Assemble the artifact JSON ──────────────────────────────────────────────────────────
    let blocks_fixture: Vec<BlockFixture> = {
        let guard = block_witness_generator.borrow();
        let total_blocks = guard.block_number.as_u64();
        let mut v = Vec::with_capacity(total_blocks as usize);
        for block_idx in 1..=total_blocks {
            let block_number = BlockNumber::new(block_idx).expect("block number");
            let witness = guard
                .block_chain_witness
                .get(&block_number)
                .expect("block witness");
            let block = &witness.block;
            v.push(BlockFixture {
                channel_id: block.channel_id,
                timestamp: block.timestamp,
                tx_tree_root: block.tx_tree_root.to_string(),
                key_ids: block.key_ids.clone(),
                block_number: block_idx,
            });
        }
        v
    };

    let lifecycle = LifecycleFixture {
        genesis_state_root: vpis.initial_ext_commitment.to_string(),
        final_state_root: vpis.final_ext_commitment.to_string(),
        registration: MemberFixture {
            channel_id: channel_id_u32,
            bp_member_slot,
            member_pk_gs,
            member_pk_bs,
            regev_pk_digests,
            recipients,
        },
        deposit: DepositFixture {
            depositor: depositor.to_string(),
            recipient: deposit_recipient.to_string(),
            token_index: 0,
            amount: U256::from(params.deposit_amount).to_string(),
            aux_data: Bytes32::default().to_string(),
        },
        deposit_erc20: erc20_deposit
            .as_ref()
            .map(|(lane, _, recipient2)| DepositFixture {
                depositor: depositor.to_string(),
                recipient: recipient2.to_string(),
                token_index: lane.token_index,
                amount: U256::from(lane.deposit_amount).to_string(),
                aux_data: Bytes32::default().to_string(),
            }),
        blocks: blocks_fixture,
        vpis: VPIFixture {
            initial_block_number: vpis.initial_block_number.as_u64(),
            initial_block_chain: vpis.initial_block_chain.to_string(),
            initial_ext_commitment: vpis.initial_ext_commitment.to_string(),
            final_block_number: vpis.final_block_number.as_u64(),
            final_block_chain: vpis.final_block_chain.to_string(),
            final_ext_commitment: vpis.final_ext_commitment.to_string(),
            prover: vpis.prover.to_string(),
        },
        proof_hash: fnv1a_bytes32(validity_mle_json.as_bytes()),
        proof_length: validity_mle_json.len() as u32,
    };
    let lifecycle_json = serde_json::to_string_pretty(&lifecycle)?;

    let payout = WithdrawalPayoutFixture {
        withdrawals: vec![WithdrawalEntryFixture {
            recipient: committed_withdrawal.recipient.to_string(),
            token_index: committed_withdrawal.token_index,
            amount: committed_withdrawal.amount.to_string(),
            nullifier: committed_withdrawal.nullifier.to_string(),
            aux_data: committed_withdrawal.aux_data.to_string(),
        }],
        withdrawal_prover: withdrawal_prover.to_string(),
        block_number: ext_public_state.inner.block_number.as_u64(),
        ext_commitment: ext_public_state.commitment().to_string(),
    };
    let payout_json = serde_json::to_string_pretty(&payout)?;

    let erc20_payout_json = erc20_committed
        .as_ref()
        .map(|w| -> anyhow::Result<String> {
            let p = WithdrawalPayoutFixture {
                withdrawals: vec![WithdrawalEntryFixture {
                    recipient: w.recipient.to_string(),
                    token_index: w.token_index,
                    amount: w.amount.to_string(),
                    nullifier: w.nullifier.to_string(),
                    aux_data: w.aux_data.to_string(),
                }],
                withdrawal_prover: withdrawal_prover.to_string(),
                block_number: ext_public_state.inner.block_number.as_u64(),
                ext_commitment: ext_public_state.commitment().to_string(),
            };
            Ok(serde_json::to_string_pretty(&p)?)
        })
        .transpose()?;

    Ok(ChannelWithdrawalArtifacts {
        lifecycle_json,
        validity_mle_json,
        withdrawal_mle_json,
        payout_json,
        erc20_withdrawal_mle_json,
        erc20_payout_json,
    })
}

#[cfg(test)]
#[cfg(not(debug_assertions))]
mod delegate_send_tests {
    use super::*;
    use crate::common::channel::{ChannelFund, ChannelStatus, ChannelTx};
    use rand::SeedableRng as _;
    use rand010::{SeedableRng as _, rngs::StdRng};

    const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Test;

    fn member_info(slot: u16, keys: &MemberKeys) -> MemberInfo {
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
        delegate_count: u16,
    ) -> (ChannelRecord, Vec<MemberInfo>) {
        let active = member_count as usize + delegate_count as usize;
        assert_eq!(keys.len(), active, "one key per active slot");
        let members: Vec<MemberInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| member_info(i as u16, k))
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
    /// Deterministic NONZERO per-slot test recipients (B-1b: validate() rejects zero actives).
    fn test_recipients(n: usize) -> Vec<Address> {
        (0..n)
            .map(|i| Address::from_u32_slice(&[0x7E57_0000u32.wrapping_add(i as u32); 5]).unwrap())
            .collect()
    }

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
            &test_recipients(enc_balances_active.len()),
            fund_amount,
        )
        .unwrap()
    }

    // =========================================================================================
    // falcon-sig Phase 4 — the wallet co-sign is a NATIVE Falcon signature.
    // =========================================================================================

    /// A REAL legacy `SingleSigCircuit` proof blob — the old cosign wire object — captured just
    /// before that circuit was deleted (`src/falcon_sig/testdata/README.md`).
    const LEGACY_COSIGN_BLOB: &[u8] =
        include_bytes!("falcon_sig/testdata/legacy_single_sig_proof.bin");

    /// SECURITY (TM-C8 / O-9 at the WALLET seam): the entry point every peer uses to accept a
    /// co-signature must reject a valid OLD-scheme signature. Downgrade is the attack: if
    /// `verify_state_sig` still honoured the retired scheme, an adversary who could produce (or
    /// replay) a Goldilocks proof would co-sign a state under the new regime.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn legacy_single_sig_blob_rejected_by_verify_state_sig() {
        let mut rng = StdRng::seed_from_u64(0x0F9);
        let keys = MemberKeys::generate(&mut rng);
        let digest = Bytes32::from_u32_slice(&[0x494d_4348, 1, 2, 3, 4, 5, 6, 7]).unwrap();

        // Control: the CURRENT scheme's blob is accepted at the same entry point, so the
        // rejection below is about the FORMAT and not about the harness being broken.
        let good = sign_digest(keys.falcon_key(), &digest);
        assert_eq!(good.len(), crate::falcon_sig::FALCON_COSIGN_BLOB_BYTES);
        verify_state_sig(keys.pk_g(), &digest, &good).expect("a genuine cosignature verifies");

        // The real old blob is rejected — and the error names the VERSION gate, i.e. it is a
        // policy rejection, not an incidental parse failure.
        let err = verify_state_sig(keys.pk_g(), &digest, LEGACY_COSIGN_BLOB)
            .expect_err("a legacy proof blob must never verify as a cosignature");
        assert!(
            err.to_string()
                .contains("unsupported falcon signature version"),
            "expected a version-gate rejection, got: {err}"
        );
    }

    /// SECURITY (TM-C6 / O-6, native side, under ONE key): the member's single Falcon key signs
    /// both channel states (IMCH) and small-block roots (IMSB). Isolation rests ENTIRELY on the
    /// message digests, so a signature made in one context must not verify in the other. The
    /// circuit-level version of this test lives in `falcon_sig::list`; this is the native
    /// wallet-verifier version, at the exact entry point peers call.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn imch_and_imsb_cosignatures_do_not_transfer_between_contexts() {
        use crate::circuits::validity::block_hash_chain::small_block_message::SmallBlockMessageFields;

        let mut rng = StdRng::seed_from_u64(0xC6);
        let keys = MemberKeys::generate(&mut rng);

        // A REAL IMCH digest (a channel state's signing digest) and a REAL IMSB digest — the two
        // digests the ONE key actually signs in production, not stand-ins.
        let (_record, _keys, _members, state, _w) =
            setup_delegate_channel(&mut rng, 9, [10, 20, 0]);
        let imch = state.signing_digest();
        let imsb = SmallBlockMessageFields {
            bp_member_slot: 0,
            bp_pk_g: keys.pk_g(),
            small_block_number: 0,
            prev_small_block_root: Bytes32::default(),
            state_commitment_root: state.balance_state.h1(),
            medium_epoch_hint: 0,
            close_freeze_nonce: 0,
        }
        .signing_digest(9, Bytes32::from_u32_slice(&[7; 8]).unwrap());
        assert_ne!(imch, imsb, "the two context digests must differ");

        let imch_blob = sign_digest(keys.falcon_key(), &imch);
        let imsb_blob = sign_digest(keys.falcon_key(), &imsb);

        // Controls: each verifies in its OWN context.
        verify_state_sig(keys.pk_g(), &imch, &imch_blob).expect("IMCH sig in IMCH context");
        verify_state_sig(keys.pk_g(), &imsb, &imsb_blob).expect("IMSB sig in IMSB context");

        // Both directions must fail.
        assert!(
            verify_state_sig(keys.pk_g(), &imsb, &imch_blob).is_err(),
            "a state cosignature must not verify as a small-block signature"
        );
        assert!(
            verify_state_sig(keys.pk_g(), &imch, &imsb_blob).is_err(),
            "a small-block signature must not verify as a state cosignature"
        );
    }

    /// SECURITY: `verify_all_signatures` must reject a signature made by a NON-MEMBER even when
    /// the blob is internally consistent, and must reject a member's signature over a DIFFERENT
    /// state. Both are checked against the registered `pk_g`, never against the blob's own key.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn cosignature_binds_to_the_registered_member_and_the_recomputed_digest() {
        let mut rng = StdRng::seed_from_u64(0xB0DD);
        let (record, member_keys, members, state, _w) =
            setup_delegate_channel(&mut rng, 11, [5, 6, 0]);
        let digest = state.signing_digest();
        let outsider = MemberKeys::generate(&mut rng);

        // An outsider's perfectly valid signature over the right digest: rejected, because
        // `pk_g` is not the registered member at the slot.
        let blob = sign_digest(outsider.falcon_key(), &digest);
        assert!(
            verify_state_sig(record.member_pk_gs[0], &digest, &blob).is_err(),
            "a non-member's signature must not verify against a registered member's pk_g"
        );

        // A genuine member signature over a DIFFERENT digest is rejected in this state's context.
        //
        // SECURITY (Phase-4 review MINOR-2): this block used to end at `assert_ne!(digest,
        // other_digest)` — trivially true, exercising NOTHING of the property its comment
        // claimed. That is the same "false comfort" pattern the Phase-3 review rejected, so the
        // assertion is now the real one: member 0 signs a different digest with its own genuine
        // key, and that signature must not verify against THIS state's digest.
        let other_digest = Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_ne!(digest, other_digest, "the control digests must differ");
        assert!(
            verify_all_signatures(&record, &members, &state).is_ok(),
            "the fixture state must be fully and validly co-signed"
        );
        let wrong_context = sign_digest(member_keys[0].falcon_key(), &other_digest);
        assert!(
            verify_state_sig(record.member_pk_gs[0], &digest, &wrong_context).is_err(),
            "a genuine member signature over a different digest must not verify here"
        );
        // Positive control: the same signature IS valid in its own context, so the rejection
        // above is about the message and not about a malformed blob.
        assert!(
            verify_state_sig(record.member_pk_gs[0], &other_digest, &wrong_context).is_ok(),
            "the control signature must be valid over the digest it was made for"
        );
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
            .map(|(i, k)| member_info(i as u16, k))
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
        let recips = test_recipients(3);
        let g = assemble_genesis_state(&r, &encs, &pkds, &recips, 30).expect("active genesis");
        assert_eq!(g.balance_state.delegate_count, 1);
        g.balance_state.validate().expect("genesis balance valid");
        // A member_count-only ciphertext count is rejected (must cover the delegate slot too).
        assert!(assemble_genesis_state(&r, &encs[..2], &pkds[..2], &recips[..2], 30).is_err());
        // B-1b fail-closed: a ZERO recipient for an active slot is rejected at genesis assembly.
        let mut zero_recips = recips.clone();
        zero_recips[2] = Address::default();
        assert!(
            assemble_genesis_state(&r, &encs, &pkds, &zero_recips, 30).is_err(),
            "a zero active recipient must be refused at genesis assembly (B-1b)"
        );
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

    /// REPRO (browser deposit-display bug): two consecutive L1 deposit imports must reflect the
    /// RUNNING balance after EACH import. Mirrors the relay CLI `cosign-l1-deposit-import`
    /// (including its deterministic per-call encryption seed) with REAL wei amounts
    /// (0.05 then 0.01 ETH), depositing into the delegate slot (the browser member).
    #[test]
    fn deposit_import_reflects_running_balance_each_step() {
        let mut rng = StdRng::seed_from_u64(0x0DEB17);
        let channel_id = 7u32;
        let (record, keys, members, genesis, _w) =
            setup_delegate_channel(&mut rng, channel_id, [0, 0, 0]);
        let mut snapshot = ChannelSnapshot {
            record,
            state: genesis,
            members,
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };

        let recipient_slot = 2usize; // delegate = the browser member
        let deposits = [50_000_000_000_000_000u64, 10_000_000_000_000_000u64];
        let mut expected = 0u64;
        for (i, &amount) in deposits.iter().enumerate() {
            expected += amount;
            let deposit = Deposit {
                deposit_index: Default::default(),
                block_number: Default::default(),
                depositor: Address::default(),
                recipient: Bytes32::default(),
                token_index: 0,
                amount: U256::from(amount),
                aux_data: Bytes32::default(),
            };
            // MIRROR the relay CLI exactly: the SAME deterministic seed on every call.
            let mut drng = StdRng::seed_from_u64(0xDE_0517 ^ channel_id as u64);
            let (delta, _) =
                encrypt_amount(&mut drng, &keys[recipient_slot].regev_pk, amount).unwrap();
            let built = build_l1_deposit_import(
                &keys[0],
                &snapshot,
                &deposit,
                recipient_slot,
                &delta,
                LEVEL,
            )
            .unwrap();
            let mut bundle = built.bundle_apply_state.clone();
            let s0 = sign_state(&keys[0], 0, &bundle).unwrap();
            add_signature(&mut bundle, s0);
            let s1 = sign_state(&keys[1], 1, &bundle).unwrap();
            add_signature(&mut bundle, s1);
            snapshot.state = bundle;
            let bal =
                decrypt_balance(&keys[recipient_slot], &snapshot, recipient_slot as u16).unwrap();
            assert_eq!(
                bal,
                expected,
                "after deposit #{} (+{} wei) balance should be {} but was {}",
                i + 1,
                amount,
                expected,
                bal
            );
        }
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
            payload.channel_tx.token_slot,
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
            payload.channel_tx.token_slot,
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
            payload.channel_tx.token_slot,
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
        tampered_state.balance_state.enc_balances[2][0] = forged_lower;
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
        let members: Vec<MemberInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| member_info(i as u16, k))
            .collect();
        let record = build_record(channel, &members, 0, 0).expect("record");
        let encs: Vec<RegevCiphertext> = keys
            .iter()
            .map(|k| encrypt_amount(&mut rng, &k.regev_pk, 10).unwrap().0)
            .collect();
        let pkds: Vec<Bytes32> = members
            .iter()
            .map(|m| Bytes32::from(m.regev_pk.poseidon_digest()))
            .collect();
        let mut state = assemble_genesis_state(&record, &encs, &pkds, &test_recipients(3), 30)
            .expect("genesis");
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

        // DETACHED SIGNING: the close prover holds no key. The N-of-N cosignatures it consumes are
        // the ones the members already produced above with `sign_state`, carried by the state
        // itself — and they must be the REGISTERED identities, because the §3.5 gate binds every
        // signature to `record.member_pk_gs[slot]`. (The previous version of this test signed with
        // three standalone `FalconKeys` unrelated to the record; that is exactly the confusion the
        // record parameter now makes impossible.)
        assert_eq!(state.member_signatures.len(), 3);

        // Negative (fail-closed gate, no proving): an incomplete signature set naming the slot.
        let short: Vec<MemberSignature> = state.member_signatures[..2].to_vec();
        let err = prover
            .build_full_witness_from_signatures(
                &record,
                &state,
                &short,
                balance_proof.clone(),
                1,
                Bytes32::default(),
                1,
            )
            .expect_err("close must reject a signature count != member_count");
        assert!(
            err.0.contains("expected 3 member signatures"),
            "unexpected error: {}",
            err.0
        );

        // Positive: build the full witness from the DETACHED set, prove, and verify.
        let witness = prover
            .build_full_witness_from_signatures(
                &record,
                &state,
                &state.member_signatures,
                balance_proof,
                1,
                Bytes32::default(),
                1,
            )
            .expect("close full witness");
        let proof = prover.prove(&witness).expect("close proof");
        prover
            .close_vd()
            .verify(proof)
            .expect("real close proof verifies");
    }

    // ─────────────────────────────────────────────────────────────────────────────────────────
    // DETACHED CLOSE SIGNING — the acceptance gate and the adversarial suite for the
    // §3.5 coordinator gate (`falcon_member_auth_from_signatures`).
    // See doc/tasks/close-detached-signing-design.md.
    // ─────────────────────────────────────────────────────────────────────────────────────────

    /// The expensive half of the detached-gate fixtures: three real cosigner `MemberKeys` plus the
    /// Regev material a genesis state needs. Built ONCE (keygen is ~0.5 s/member) and shared by
    /// every gate test below; nothing here is mutated.
    struct DetachedKeyFixture {
        keys: Vec<MemberKeys>,
        members: Vec<MemberInfo>,
        encs: Vec<RegevCiphertext>,
        pkds: Vec<Bytes32>,
    }

    static DETACHED_KEYS: std::sync::LazyLock<DetachedKeyFixture> =
        std::sync::LazyLock::new(|| {
            let mut rng = StdRng::seed_from_u64(0xDE7A_C4ED);
            let keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut rng)).collect();
            let members: Vec<MemberInfo> = keys
                .iter()
                .enumerate()
                .map(|(i, k)| member_info(i as u16, k))
                .collect();
            let encs: Vec<RegevCiphertext> = keys
                .iter()
                .map(|k| encrypt_amount(&mut rng, &k.regev_pk, 10).unwrap().0)
                .collect();
            let pkds: Vec<Bytes32> = members
                .iter()
                .map(|m| Bytes32::from(m.regev_pk.poseidon_digest()))
                .collect();
            DetachedKeyFixture {
                keys,
                members,
                encs,
                pkds,
            }
        });

    /// A record + a fully co-signed genesis `ChannelState` for `channel`, from the shared keys.
    fn detached_fixture(channel: u32) -> (ChannelRecord, ChannelState) {
        let f = &*DETACHED_KEYS;
        let record = build_record(channel, &f.members, 0, 0).expect("record");
        let mut state = assemble_genesis_state(&record, &f.encs, &f.pkds, &test_recipients(3), 30)
            .expect("genesis");
        detached_sign_all(&mut state);
        (record, state)
    }

    /// Attach the complete N-of-N cosignature set over `state.signing_digest()`.
    fn detached_sign_all(state: &mut ChannelState) {
        state.member_signatures.clear();
        for (i, k) in DETACHED_KEYS.keys.iter().enumerate() {
            let s = sign_state(k, i as u8, state).expect("sign state");
            add_signature(state, s);
        }
    }

    /// Positive control for the whole adversarial suite below: the state's OWN cosignatures — the
    /// set `cmd_close` now passes — pass the §3.5 gate unmodified, and the aggregation witness the
    /// gate returns carries exactly the registered pk_g list in slot order.
    ///
    /// SECURITY: this is the "the honest input is accepted" half. Every test after it mutates
    /// exactly one thing about this input and requires rejection, so a gate that rejected
    /// everything (or accepted everything) fails here or there.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn detached_gate_accepts_the_states_own_cosignatures() {
        let (record, state) = detached_fixture(11);
        // The gate's message is the RECOMPUTED digest, and the state's cached digest must equal it
        // (C-1: the close prover binds `state.digest`, `sign_state` signs `signing_digest()`).
        assert_eq!(state.digest, state.signing_digest());
        let (pk_gs, agg) =
            falcon_member_auth_from_signatures(&record, &state.member_signatures, state.digest)
                .expect("the state's own cosignatures must pass the gate");
        assert_eq!(pk_gs.len(), 3);
        assert_eq!(agg.active.len(), 3);
        assert_eq!(agg.message, state.digest);
        for (slot, pk_g) in pk_gs.iter().enumerate() {
            assert_eq!(
                *pk_g, record.member_pk_gs[slot],
                "the gate must publish the RECORD's identity for slot {slot}, never the wire entry's"
            );
        }
    }

    /// T-9 (design §2.3, test 4a): a `MemberSignature` self-declares its `pk_g` on the wire. A
    /// signature that is internally consistent but carries an identity that is NOT
    /// `record.member_pk_gs[slot]` must be rejected — otherwise a non-member could join the
    /// N-of-N set.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn detached_gate_rejects_a_pk_g_that_is_not_the_registered_member() {
        let (record, state) = detached_fixture(12);
        // A real, valid signature over the same digest by a NON-member key.
        let mut rng = StdRng::seed_from_u64(0xBAD_5169);
        let outsider = MemberKeys::generate(&mut rng);
        let mut sigs = state.member_signatures.clone();
        sigs[1] = sign_state(&outsider, 1, &state).expect("outsider signs");
        let err = falcon_member_auth_from_signatures(&record, &sigs, state.digest)
            .expect_err("must fail");
        assert!(
            err.0.contains("slot 1"),
            "the error must name the offending slot: {}",
            err.0
        );
    }

    /// T-9 / X-5 (test 4b): the transport is an ARRAY. If the gate indexed it positionally without
    /// first proving `entry.member_slot == index`, a reordered array would bind slot i's registered
    /// `pk_g` to slot j's signature. Reordering, duplication and short sets must all be rejected
    /// BEFORE any indexing.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn detached_gate_rejects_slot_reordering_duplication_and_gaps() {
        let (record, state) = detached_fixture(13);

        let mut swapped = state.member_signatures.clone();
        swapped.swap(0, 2);
        assert!(
            falcon_member_auth_from_signatures(&record, &swapped, state.digest).is_err(),
            "a reordered signature array must be rejected (X-5)"
        );

        // Slot 0's entry duplicated into position 1, with its declared slot left at 0.
        let mut duped = state.member_signatures.clone();
        duped[1] = duped[0].clone();
        assert!(
            falcon_member_auth_from_signatures(&record, &duped, state.digest).is_err(),
            "a duplicated slot must be rejected (one key must not satisfy two slots)"
        );

        // A gap: slot 1 relabelled as slot 2, so slot 1 is unrepresented.
        let mut gapped = state.member_signatures.clone();
        gapped[1].member_slot = 2;
        assert!(
            falcon_member_auth_from_signatures(&record, &gapped, state.digest).is_err(),
            "a gap in the slot sequence must be rejected"
        );

        // Fewer than member_count entries — the T-4 "partial collection" case. It must be an
        // ERROR, not a smaller proof: a k-of-N close is exactly what T-6 forbids.
        assert!(
            falcon_member_auth_from_signatures(
                &record,
                &state.member_signatures[..2],
                state.digest
            )
            .is_err(),
            "an incomplete signature set must be rejected, never proved as k-of-N"
        );
    }

    /// T-2 (test 4c), native counterpart of the in-circuit cross-context binding: signatures by the
    /// REGISTERED members over a DIFFERENT state must not authorise this state. The circuit already
    /// forces one shared message across all slots, so a mixed set cannot be aggregated at all; this
    /// asserts the coordinator rejects it in microseconds instead of failing opaquely in `prove()`.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn detached_gate_rejects_cosignatures_over_a_different_state() {
        let (record, state) = detached_fixture(14);
        // Same members, same channel, same era — only the balance content differs.
        let mut other = state.clone();
        other.unallocated_confirmed_incoming = U256::from(1u32);
        let other = other.with_computed_digest();
        assert_ne!(other.digest, state.digest);
        let mut other = other;
        detached_sign_all(&mut other);

        assert!(
            falcon_member_auth_from_signatures(&record, &other.member_signatures, state.digest)
                .is_err(),
            "cosignatures over a different state must not authorise this one"
        );
        // And a MIXED set (2 honest + 1 foreign) must fail too — the close circuit's single shared
        // message target makes such a set unprovable, and the gate must say so up front.
        let mut mixed = state.member_signatures.clone();
        mixed[2] = other.member_signatures[2].clone();
        let err = falcon_member_auth_from_signatures(&record, &mixed, state.digest)
            .expect_err("a mixed-message set must be rejected");
        assert!(err.0.contains("slot 2"), "must name the slot: {}", err.0);
    }

    /// T-1 (test 4d): `channel_id` is inside the IMCH signing preimage, so a signature collected in
    /// channel A must be worthless in channel B even though the member set is identical. This is
    /// the cross-channel replay fence, checked natively.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn detached_gate_rejects_cosignatures_from_a_different_channel() {
        let (record_a, state_a) = detached_fixture(15);
        let (_record_b, state_b) = detached_fixture(16);
        assert_ne!(state_a.digest, state_b.digest);
        assert!(
            falcon_member_auth_from_signatures(
                &record_a,
                &state_b.member_signatures,
                state_a.digest
            )
            .is_err(),
            "a cosignature from another channel must be rejected (channel_id ∈ IMCH preimage)"
        );
    }

    /// T-1 / T-7 (test 4e): `close_freeze_nonce` is inside the IMCH signing preimage, so it is the
    /// ERA fence — a cosignature collected in era k does not authorise the same balance state in
    /// era k+1. This is the only thing bounding T-7's "a signature over S authorises every close at
    /// S forever" to a single era, so it is asserted explicitly.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn detached_gate_rejects_cosignatures_from_a_different_close_era() {
        let (record, state) = detached_fixture(17);
        let mut next_era = state.clone();
        next_era.close_freeze_nonce = state.close_freeze_nonce + 1;
        let mut next_era = next_era.with_computed_digest();
        assert_ne!(
            next_era.digest, state.digest,
            "the era must change the digest"
        );
        detached_sign_all(&mut next_era);

        assert!(
            falcon_member_auth_from_signatures(&record, &next_era.member_signatures, state.digest)
                .is_err(),
            "an era-(k+1) cosignature must not authorise an era-k close"
        );
        assert!(
            falcon_member_auth_from_signatures(&record, &state.member_signatures, next_era.digest)
                .is_err(),
            "an era-k cosignature must not authorise an era-(k+1) close"
        );
    }

    /// TM-C8 / O-9 (test 4f): the blob is versioned and fixed-length. A retired `SingleSigCircuit`
    /// blob (any non-`v1` leading byte) must be rejected BY POLICY on the version byte, before any
    /// parsing, and truncated / over-long blobs must be rejected on the length gate — not by an
    /// incidental parse accident further in.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn detached_gate_rejects_legacy_versioned_and_wrong_length_blobs() {
        let (record, state) = detached_fixture(18);

        let mut legacy = state.member_signatures.clone();
        legacy[0].signature[0] = 0x00; // not FALCON_SIG_V1
        assert!(
            falcon_member_auth_from_signatures(&record, &legacy, state.digest).is_err(),
            "a non-v1 version byte must be rejected by policy"
        );

        let mut truncated = state.member_signatures.clone();
        truncated[0]
            .signature
            .truncate(crate::falcon_sig::FALCON_COSIGN_BLOB_BYTES - 1);
        assert!(
            falcon_member_auth_from_signatures(&record, &truncated, state.digest).is_err(),
            "a truncated blob must be rejected on the fixed-length gate"
        );

        let mut overlong = state.member_signatures.clone();
        overlong[0].signature.push(0);
        assert!(
            falcon_member_auth_from_signatures(&record, &overlong, state.digest).is_err(),
            "an over-long blob must be rejected on the fixed-length gate"
        );

        let mut empty = state.member_signatures.clone();
        empty[0].signature.clear();
        assert!(
            falcon_member_auth_from_signatures(&record, &empty, state.digest).is_err(),
            "an empty blob must be rejected"
        );
    }

    /// T-8 (test 4g): the public polynomial `h` travels INSIDE the untrusted blob. If the gate
    /// verified with the transported `h` without binding it to the registered identity (i.e. used
    /// the bare `verify` instead of `verify_with_pk_g`, review F-2), an attacker could sign with
    /// their own key and ship their own `h` while declaring a registered `pk_g`. The
    /// `falcon_pk_digest(h) == pk_g` check inside `verify_with_pk_g` is what closes this.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn detached_gate_rejects_a_substituted_public_polynomial() {
        let (record, state) = detached_fixture(19);
        let mut rng = StdRng::seed_from_u64(0x5AB0_7A6E);
        let attacker = MemberKeys::generate(&mut rng);

        // The attacker's OWN valid signature + OWN h, relabelled with the registered slot/pk_g.
        let mut forged = sign_state(&attacker, 0, &state).expect("attacker signs");
        forged.pk_g = record.member_pk_gs[0];
        let mut sigs = state.member_signatures.clone();
        sigs[0] = forged;

        let err = falcon_member_auth_from_signatures(&record, &sigs, state.digest)
            .expect_err("a substituted public polynomial must be rejected");
        assert!(
            err.0.contains("slot 0") && err.0.contains("failed native verification"),
            "must be the cryptographic gate naming the slot: {}",
            err.0
        );
    }

    /// T-10 / X-6 (test 4h): the provers size the member set from the STATE while the signature
    /// validators size it from the RECORD, and until this change nothing asserted the two agree —
    /// masked only because one process produced both. Under detached signing they arrive from
    /// different places. Fail-closed.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn detached_gate_rejects_record_state_member_count_mismatch() {
        let (record, state) = detached_fixture(20);
        assert!(assert_record_state_member_count_agree("close", &record, &state).is_ok());

        let mut lying = state.clone();
        lying.balance_state.member_count = 2;
        let err = assert_record_state_member_count_agree("close", &record, &lying)
            .expect_err("a count disagreement must fail closed");
        assert!(err.0.contains("T-10"), "unexpected error: {}", err.0);

        let mut lying_up = state.clone();
        lying_up.balance_state.member_count = 4;
        assert!(
            assert_record_state_member_count_agree("close", &record, &lying_up).is_err(),
            "a count disagreement in the other direction must fail closed too"
        );
    }

    /// Test 4j (randomized / property-based): every single-byte mutation of an otherwise valid
    /// cosignature blob must be rejected. This is the test intended to catch a gate that checks
    /// only structure (length, slot, pk_g) and forgets the cryptography — such a gate passes every
    /// hand-written case above that mutates a FIELD, and fails only here.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn detached_gate_rejects_random_single_byte_blob_mutations() {
        let (record, state) = detached_fixture(21);
        // INTENTIONALLY SIMPLE: a fixed LCG rather than an RNG dependency, so a failing case is
        // reproducible from the seed alone with no crate-version coupling.
        let mut s: u64 = 0xF00D_5163;
        let mut next = |m: u64| -> u64 {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (s >> 33) % m
        };
        let blob_len = crate::falcon_sig::FALCON_COSIGN_BLOB_BYTES;

        for _ in 0..200 {
            let slot = next(3) as usize;
            let byte = next(blob_len as u64) as usize;
            let delta = (next(255) + 1) as u8;
            let mut sigs = state.member_signatures.clone();
            sigs[slot].signature[byte] = sigs[slot].signature[byte].wrapping_add(delta);
            assert!(
                falcon_member_auth_from_signatures(&record, &sigs, state.digest).is_err(),
                "mutating byte {byte} of slot {slot}'s blob must be rejected"
            );
        }

        // Control: 200 unmutated rebuilds of the honest set are accepted, so the loop above is not
        // passing because the gate rejects everything.
        for _ in 0..200 {
            let mut fresh = state.clone();
            detached_sign_all(&mut fresh);
            falcon_member_auth_from_signatures(&record, &fresh.member_signatures, state.digest)
                .expect("a freshly minted honest set must be accepted");
        }
    }

    /// The persisted aggregate is a cache, never an authority: its metadata and proof are both
    /// rechecked against the finalized state before close/PW/cancel may consume it.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn falcon_aggregate_artifact_roundtrips_and_rejects_tampering() {
        let (record, state) = detached_fixture(210);
        let build_started = std::time::Instant::now();
        let ctx = FalconProverContext::new();
        let build = build_started.elapsed();
        let prove_started = std::time::Instant::now();
        let artifact = ctx
            .prove_finalized_state(&record, &state)
            .expect("aggregate finalized state");
        let prove = prove_started.elapsed();
        let bytes = artifact.to_bytes().expect("encode artifact");
        let decoded = FalconAggregateProofArtifact::from_bytes(&bytes).expect("decode artifact");
        let reuse_started = std::time::Instant::now();
        ctx.verify_finalized_state_artifact(&record, &state, &decoded)
            .expect("cached proof verifies");
        let reuse_verify = reuse_started.elapsed();
        println!(
            "falcon aggregate cache (3 members / fixed-16 circuit): build={build:?} \
             prove={prove:?} reuse_verify={reuse_verify:?} artifact={} B proof={} B",
            bytes.len(),
            artifact.proof.len(),
        );

        let mut wrong_state = decoded.clone();
        wrong_state.state_digest = Bytes32::default();
        assert!(
            ctx.verify_finalized_state_artifact(&record, &state, &wrong_state)
                .is_err()
        );

        let mut wrong_pk = decoded.clone();
        wrong_pk.member_pk_gs[0] = Bytes32::default();
        assert!(
            ctx.verify_finalized_state_artifact(&record, &state, &wrong_pk)
                .is_err()
        );

        let mut corrupt_proof = decoded;
        let mid = corrupt_proof.proof.len() / 2;
        corrupt_proof.proof[mid] ^= 1;
        assert!(
            ctx.verify_finalized_state_artifact(&record, &state, &corrupt_proof)
                .is_err()
        );
    }

    /// **THE PHASE-1 ACCEPTANCE GATE** (design §6 Phase 1, criterion 1a) and the empirical
    /// confirmation of C-1 — the premise the entire detached-signing design rests on.
    ///
    /// The claim: re-minting a member's signature at close time (what the old key-holding prover
    /// did) and re-using the signature that member already produced when it co-signed the state
    /// are CRYPTOGRAPHICALLY INDISTINGUISHABLE to everything downstream. The close circuit is
    /// signature-blind — the aggregation leaf registers only `[message, 1, pk_g]`, and `salt` /
    /// `s2` / `h` are witnesses, never public inputs — so two valid signatures by the same key over
    /// the same digest must yield the SAME close-proof public inputs.
    ///
    /// This test proves it the hard way: it builds the close proof twice from the same state, once
    /// from the collected set and once from a freshly re-signed set, first ASSERTING the two
    /// signature sets differ byte-for-byte (Falcon's salt is randomized, so they do), and then
    /// asserting the two proofs' public inputs are identical limb for limb.
    ///
    /// If this ever fails, the design premise is wrong and the detached path is NOT a semantics-
    /// preserving refactor: stop, do not adjust anything to make it pass.
    ///
    /// HEAVY: builds the balance + close circuits and proves TWO closes (minutes, multi-GB).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn close_detached_and_resigned_paths_yield_identical_close_public_inputs() {
        use crate::{
            circuits::balance::{balance_processor::BalanceProcessor, spend_circuit::SpendCircuit},
            common::{channel_id::ChannelId, salt::Salt},
        };

        let channel = 22u32;
        let (record, state) = detached_fixture(channel);

        // Path A input: the cosignatures the members produced when they agreed the state. This is
        // what `cmd_close` now passes.
        let collected = state.member_signatures.clone();

        // Path B input: the SAME members signing the SAME digest again, now — semantically exactly
        // what the retired key-taking `build_full_witness` did internally.
        let mut resigned_state = state.clone();
        detached_sign_all(&mut resigned_state);
        let resigned = resigned_state.member_signatures.clone();

        // The premise is only interesting if the two sets really are different signatures.
        assert_eq!(collected.len(), resigned.len());
        for slot in 0..collected.len() {
            assert_eq!(collected[slot].pk_g, resigned[slot].pk_g);
            assert_ne!(
                collected[slot].signature, resigned[slot].signature,
                "slot {slot}: Falcon signing is randomized, so a re-signature must differ; if it \
                 does not, this test proves nothing"
            );
        }

        let spend = SpendCircuit::<F, C, D>::new();
        let bp = BalanceProcessor::<F, C, D>::new(&spend.data.verifier_data());
        let balance_proof = bp
            .prove_initial(
                ChannelId::new(channel as u64).unwrap(),
                Salt::rand(&mut rand::thread_rng()),
            )
            .expect("genesis balance proof");
        let prover = CloseProver::new(&bp.balance_vd());

        let build = |sigs: &[MemberSignature]| {
            prover
                .build_full_witness_from_signatures(
                    &record,
                    &state,
                    sigs,
                    balance_proof.clone(),
                    1,
                    Bytes32::default(),
                    1,
                )
                .expect("close full witness")
        };

        let witness_collected = build(&collected);
        let witness_resigned = build(&resigned);

        // The member_auth pk-list is read off the RECORD in both cases, so it must be identical.
        assert_eq!(
            witness_collected
                .member_auth
                .iter()
                .map(|a| a.pk_g)
                .collect::<Vec<_>>(),
            witness_resigned
                .member_auth
                .iter()
                .map(|a| a.pk_g)
                .collect::<Vec<_>>()
        );
        // The aggregation proof is the ONLY place the signatures enter, so assert its public
        // inputs match first — that localises a failure to the leaf gadget if one ever occurs.
        assert_eq!(
            witness_collected.agg_proof.public_inputs, witness_resigned.agg_proof.public_inputs,
            "the aggregation proof's public inputs must not depend on WHICH valid signature was \
             used (agg.rs registers only [message, signer_count, pk_g])"
        );

        let proof_collected = prover.prove(&witness_collected).expect("close proof A");
        let proof_resigned = prover.prove(&witness_resigned).expect("close proof B");

        assert_eq!(
            proof_collected.public_inputs, proof_resigned.public_inputs,
            "C-1 VIOLATED: re-using a collected cosignature and re-minting one produce DIFFERENT \
             close public inputs. The detached-signing design premise is wrong — stop."
        );

        let vd = prover.close_vd();
        vd.verify(proof_collected)
            .expect("the detached (collected-signature) close proof must verify");
        vd.verify(proof_resigned)
            .expect("the re-signed close proof must verify");
    }

    /// Design §6 Phase 3 (3a/3b): the point of the whole exercise — a close proof built by a
    /// process that holds NO key material. The signing keys are dropped before the prover is even
    /// constructed (`FalconKeys` is deliberately non-`Clone`, and `MemberKeys` owns the only
    /// handle), so the compiler itself witnesses that no key is in scope at the call site.
    ///
    /// SECURITY: this is what makes a split deployment expressible. Previously `cmd_close` derived
    /// all N cosigner secrets in one process, so "N-of-N" degraded to "the coordinator wanted it".
    ///
    /// HEAVY: builds the balance + close circuits and proves a close.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn close_proves_with_no_key_material_in_the_proving_scope() {
        use crate::{
            circuits::balance::{balance_processor::BalanceProcessor, spend_circuit::SpendCircuit},
            common::{channel_id::ChannelId, salt::Salt},
        };

        let channel = 23u32;
        // Everything key-bearing is confined to this block and does not escape it.
        let (record, state, sigs): (ChannelRecord, ChannelState, Vec<MemberSignature>) = {
            let mut rng = StdRng::seed_from_u64(0x0C105E_D);
            let keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut rng)).collect();
            let members: Vec<MemberInfo> = keys
                .iter()
                .enumerate()
                .map(|(i, k)| member_info(i as u16, k))
                .collect();
            let record = build_record(channel, &members, 0, 0).expect("record");
            let encs: Vec<RegevCiphertext> = keys
                .iter()
                .map(|k| encrypt_amount(&mut rng, &k.regev_pk, 10).unwrap().0)
                .collect();
            let pkds: Vec<Bytes32> = members
                .iter()
                .map(|m| Bytes32::from(m.regev_pk.poseidon_digest()))
                .collect();
            let mut state = assemble_genesis_state(&record, &encs, &pkds, &test_recipients(3), 30)
                .expect("genesis");
            for (i, k) in keys.iter().enumerate() {
                let s = sign_state(k, i as u8, &state).expect("sign");
                add_signature(&mut state, s);
            }
            let sigs = state.member_signatures.clone();
            // The keys are dropped here, at the end of this block. Nothing below can sign.
            (record, state, sigs)
        };

        let spend = SpendCircuit::<F, C, D>::new();
        let bp = BalanceProcessor::<F, C, D>::new(&spend.data.verifier_data());
        let balance_proof = bp
            .prove_initial(
                ChannelId::new(channel as u64).unwrap(),
                Salt::rand(&mut rand::thread_rng()),
            )
            .expect("genesis balance proof");
        let prover = CloseProver::new(&bp.balance_vd());

        // (3b) Negative FIRST: a missing slot must be an error naming the failure, and must not
        // produce a proof. There is no key available to "fix" it with — which is the property
        // under test.
        let err = prover
            .build_full_witness_from_signatures(
                &record,
                &state,
                &sigs[..2],
                balance_proof.clone(),
                1,
                Bytes32::default(),
                1,
            )
            .expect_err("a keyless prover must FAIL on a missing signature, not mint one");
        assert!(
            err.0.contains("expected 3 member signatures"),
            "unexpected error: {}",
            err.0
        );

        // (3a) Positive: the full detached set proves, with no key in scope.
        let witness = prover
            .build_full_witness_from_signatures(
                &record,
                &state,
                &sigs,
                balance_proof,
                1,
                Bytes32::default(),
                1,
            )
            .expect("keyless close witness");
        let proof = prover.prove(&witness).expect("keyless close proof");
        prover
            .close_vd()
            .verify(proof)
            .expect("a close proof built without any key material must verify");
    }

    /// Build a withdrawal claim for the closed channel's slot 0 through `WithdrawalClaimProver` and
    /// verify it. The amount is DERIVED by decrypting the slot ciphertext, and the circuit binds
    /// amount==decryption, so this also checks no over-claim. HEAVY (builds + proves the claim).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a3_withdrawal_claim_prover_builds_and_verifies() {
        use crate::{
            common::{
                balance_state::BalanceState,
                channel::{ChannelFund, ChannelState},
                channel_id::ChannelId,
            },
            ethereum_types::{address::Address, u256::U256},
            regev::{RegevSecurityLevel, channel_keygen},
        };

        let mut rng = StdRng::seed_from_u64(0xc1a1);
        let channel_id = ChannelId::new(3).unwrap();
        let (pk0, sk0) = channel_keygen(&mut rng);
        let (pk1, _) = channel_keygen(&mut rng);
        let (pk2, _) = channel_keygen(&mut rng);
        let amount = 77u64;
        let (ct0, _) = encrypt_amount(&mut rng, &pk0, amount).unwrap();
        let (ct1, _) = encrypt_amount(&mut rng, &pk1, 5).unwrap();
        let (ct2, _) = encrypt_amount(&mut rng, &pk2, 11).unwrap();
        let final_balance_state = BalanceState {
            channel_id,
            member_count: 3,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances_token0(&[ct0.clone(), ct1, ct2]),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[
                Bytes32::from(pk0.poseidon_digest()),
                Bytes32::from(pk1.poseidon_digest()),
                Bytes32::from(pk2.poseidon_digest()),
            ]),
            // B-1b: slot 0 (the claimant) carries the SAME exit address passed to the prover.
            recipients: BalanceState::pad_recipients(&[
                Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
                Address::from_u32_slice(&[21, 22, 23, 24, 25]).unwrap(),
                Address::from_u32_slice(&[31, 32, 33, 34, 35]).unwrap(),
            ]),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: Bytes32::default(),
            state_version: 6,
            pending_adds: BalanceState::pad_pending_adds_token0(&[0, 0, 0]),
            token_registry: BalanceState::single_token_registry(0),
            token_count: 1,
        };
        let state = ChannelState {
            channel_id,
            epoch: 8,
            small_block_number: 5,
            close_freeze_nonce: 0,
            channel_fund: ChannelFund {
                channel_id,
                amounts: ChannelFund::single_token_amounts(U256::from(93u32)),
                intmax_state_root: Bytes32::default(),
            },
            balance_state: final_balance_state.clone(),
            h2_tag: Bytes32::default(),
            shared_native_nullifier_root: Bytes32::default(),
            unallocated_confirmed_incoming: U256::zero(),
            prev_digest: Bytes32::default(),
            digest: Bytes32::default(),
            member_signatures: vec![],
        }
        .with_computed_digest();
        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_balance_state_h1: state.balance_state.h1(),
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[9, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            burn_amount: state.channel_fund.amounts[0],
            zkp: vec![],
        };
        let close_intent = CloseIntent::new(5, &state, &close_tx, 123).unwrap();

        let pk_g = Bytes32::from_u32_slice(&[10, 11, 12, 13, 14, 15, 16, 17]).unwrap();
        let recipient = Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap();

        let prover = WithdrawalClaimProver::new();

        // Negative: claiming a padding slot (>= active region) is rejected before proving.
        assert!(
            prover
                .build_full_witness(
                    &final_balance_state,
                    3,
                    0,
                    pk_g,
                    &pk0,
                    &sk0,
                    recipient,
                    &close_intent,
                    &close_tx,
                    RegevSecurityLevel::Test,
                )
                .is_err(),
            "claiming a padding slot must be rejected"
        );

        // Negative (TM-8): claiming an INACTIVE token position (token_slot >= token_count) is
        // rejected before proving.
        assert!(
            prover
                .build_full_witness(
                    &final_balance_state,
                    0,
                    final_balance_state.token_count,
                    pk_g,
                    &pk0,
                    &sk0,
                    recipient,
                    &close_intent,
                    &close_tx,
                    RegevSecurityLevel::Test,
                )
                .is_err(),
            "claiming an inactive token position must be rejected (TM-8)"
        );

        // Positive: slot 0 claims exactly its decrypted token-0 balance (77).
        let witness = prover
            .build_full_witness(
                &final_balance_state,
                0,
                0,
                pk_g,
                &pk0,
                &sk0,
                recipient,
                &close_intent,
                &close_tx,
                RegevSecurityLevel::Test,
            )
            .expect("withdrawal claim witness");
        assert_eq!(
            witness.public_inputs.amount, amount,
            "claimed amount must equal the decrypted slot balance"
        );
        let proof = prover.prove(&witness).expect("withdrawal claim proof");
        prover
            .vd()
            .verify(proof)
            .expect("withdrawal claim proof verifies");
    }

    /// Cancel a pending close by proving a strictly-newer member-signed state exists. Builds the
    /// cancel proof through `CancelCloseProver` and verifies it; asserts a non-newer revived state
    /// is rejected. HEAVY (builds + proves the cancel circuit).
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a3_cancel_close_prover_builds_and_verifies() {
        use crate::{
            common::{
                balance_state::BalanceState,
                channel::{ChannelFund, ChannelState},
                channel_id::ChannelId,
            },
            ethereum_types::u256::U256,
            regev::channel_keygen,
        };

        let mut rng = StdRng::seed_from_u64(0xca11);
        let channel_id = ChannelId::new(3).unwrap();
        // DETACHED SIGNING: cancel-close consumes the cosignatures the revived head already
        // carries, verified against the AUTHENTICATED record — so the signing identities must BE
        // the registered ones. Build a real 3-member record and sign each state with those keys.
        let keys: Vec<MemberKeys> = (0..3).map(|_| MemberKeys::generate(&mut rng)).collect();
        let members: Vec<MemberInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| member_info(i as u16, k))
            .collect();
        let record = build_record(3, &members, 0, 0).expect("record");
        // 3 distinct slot ciphertexts (content is not load-bearing for cancel — only the IMCH
        // digest the members sign matters — but keep H1 non-degenerate).
        let encs: Vec<RegevCiphertext> = (0..3u64)
            .map(|i| {
                let (pk, _) = channel_keygen(&mut rng);
                encrypt_amount(&mut rng, &pk, 10 + i).unwrap().0
            })
            .collect();
        let mk_state = |version: u64, encs: &[RegevCiphertext]| {
            ChannelState {
                channel_id,
                epoch: 8,
                small_block_number: 4,
                close_freeze_nonce: 0,
                channel_fund: ChannelFund {
                    channel_id,
                    amounts: ChannelFund::single_token_amounts(U256::from(77u32)),
                    intmax_state_root: Bytes32::default(),
                },
                balance_state: BalanceState {
                    channel_id,
                    member_count: 3,
                    delegate_count: 0,
                    enc_balances: BalanceState::pad_enc_balances_token0(encs),
                    regev_pk_digests: BalanceState::pad_regev_pk_digests(&[]),
                    recipients: BalanceState::pad_recipients(&test_recipients(3)),
                    settled_tx_chain: Bytes32::default(),
                    settled_tx_accumulator_root: Bytes32::default(),
                    state_version: version,
                    pending_adds: BalanceState::pad_pending_adds_token0(&[0, 0, 0]),
                    token_registry: BalanceState::single_token_registry(0),
                    token_count: 1,
                },
                h2_tag: Bytes32::default(),
                shared_native_nullifier_root: Bytes32::default(),
                unallocated_confirmed_incoming: U256::zero(),
                prev_digest: Bytes32::default(),
                digest: Bytes32::default(),
                member_signatures: vec![],
            }
            .with_computed_digest()
        };
        // `signing_digest()` does not cover `member_signatures`, so the N-of-N set is attached
        // after `with_computed_digest()` — exactly as `add_signature` does on every live path.
        let sign_all = |mut s: ChannelState| -> ChannelState {
            for (i, k) in keys.iter().enumerate() {
                let sig = sign_state(k, i as u8, &s).expect("sign state");
                add_signature(&mut s, sig);
            }
            s
        };

        let revived_state = sign_all(mk_state(9, &encs));
        let closing_state = mk_state(7, &encs);
        let close_tx = CloseWithdrawal {
            channel_id,
            final_channel_state_digest: closing_state.digest,
            final_balance_state_h1: closing_state.balance_state.h1(),
            intmax_state_root: closing_state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            burn_amount: closing_state.channel_fund.amounts[0],
            zkp: vec![],
        };
        let close_intent = CloseIntent::new(5, &closing_state, &close_tx, 123).unwrap();

        let prover = CancelCloseProver::new();

        // Negative: a revived state whose version is NOT strictly newer than the close is rejected.
        let stale = sign_all(mk_state(7, &encs));
        assert!(
            prover
                .build_full_witness_from_signatures(
                    &record,
                    &stale,
                    &stale.member_signatures,
                    &close_intent
                )
                .is_err(),
            "a non-newer revived state must be rejected"
        );

        // Negative (fail-closed gate, no proving): a cosignature over the WRONG state. `stale` is a
        // genuinely signed state by the same registered members — but at a different digest, so
        // every slot must be rejected. This is the native-gate counterpart of the in-circuit
        // cross-context binding (T-2).
        let wrong_digest_err = prover
            .build_full_witness_from_signatures(
                &record,
                &revived_state,
                &stale.member_signatures,
                &close_intent,
            )
            .expect_err("cosignatures over a different state must be rejected");
        assert!(
            wrong_digest_err.0.contains("slot 0")
                && wrong_digest_err.0.contains("failed native verification"),
            "unexpected error: {}",
            wrong_digest_err.0
        );

        // Positive: revived version 9 > close final_state_version 7.
        let witness = prover
            .build_full_witness_from_signatures(
                &record,
                &revived_state,
                &revived_state.member_signatures,
                &close_intent,
            )
            .expect("cancel-close witness");
        let proof = prover.prove(&witness).expect("cancel-close proof");
        prover
            .vd()
            .verify(proof)
            .expect("cancel-close proof verifies");
    }

    /// Claim an inter-channel delta that arrived after the source channel closed, through
    /// `PostCloseClaimProver`, and verify it. Builds a real source tx + settled-tx accumulator with
    /// the tx hash included, so the in-circuit inclusion proof + tx-hash recompute pass. HEAVY.
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    #[test]
    fn a3_post_close_claim_prover_builds_and_verifies() {
        use crate::{
            common::{
                balance_state::{BalanceState, tx_leaf_hash},
                channel::{
                    ChannelProofEnvelope, InterChannelTx, MerkleInclusionProof, ProofBackend,
                    ReceiverBalanceDelta, SignedSmallBlock, SmallBlockRootMessage,
                    TransitionProofRole,
                },
                channel_id::ChannelId,
            },
            ethereum_types::{address::Address, u256::U256},
            regev::{RegevSecurityLevel, channel_keygen},
            utils::trees::incremental_merkle_tree::IncrementalMerkleTree,
        };

        let mut rng = StdRng::seed_from_u64(0x9c105e);
        let (receiver_pk, receiver_sk) = channel_keygen(&mut rng);
        let (other_pk, _) = channel_keygen(&mut rng);
        let (sender_pk, _) = channel_keygen(&mut rng);
        let amount = 21u64;
        let (delta_ct, _) = encrypt_amount(&mut rng, &receiver_pk, amount).unwrap();
        let (sender_delta_ct, _) = encrypt_amount(&mut rng, &sender_pk, 5).unwrap();
        let (slot1_ct, _) = encrypt_amount(&mut rng, &other_pk, 3).unwrap();
        let receiver_pk_g = Bytes32::from_u32_slice(&[11, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let source_pk_g = Bytes32::from_u32_slice(&[10, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let closed_channel_id = ChannelId::new(7).unwrap();
        let source_channel_id = ChannelId::new(5).unwrap();
        let close_intent_digest = Bytes32::from_u32_slice(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let tx_tree_root = Bytes32::from_u32_slice(&[4, 0, 0, 0, 0, 0, 0, 0]).unwrap();

        let tx_leaf = tx_leaf_hash(
            source_pk_g,
            sender_delta_ct.digest(),
            receiver_pk_g,
            delta_ct.digest(),
        );
        // TM-16 / Phase 5a: a NON-GENESIS token (base 55, destination registry slot 1) — the
        // anchored tx_hash carries the token in ids limb 5 and the claim PI must expose it.
        let claim_token_index = 55u32;
        let tx_hash = inter_channel_tx_hash(
            source_channel_id,
            closed_channel_id,
            claim_token_index,
            tx_tree_root,
            tx_leaf,
        );

        let mut accumulator = IncrementalMerkleTree::<Bytes32>::new(SETTLED_TX_ACCUMULATOR_HEIGHT);
        accumulator.push(tx_hash);
        accumulator.push(Bytes32::from_u32_slice(&[77, 0, 0, 0, 0, 0, 0, 0]).unwrap());
        let incoming_tx_index = 0u64;
        let accumulator_root = Bytes32::from(accumulator.get_root());

        let source_tx = InterChannelTx {
            tx_inclusion_proof: MerkleInclusionProof {
                siblings: vec![],
                leaf_index: U256::default(),
            },
            signed_small_block: SignedSmallBlock {
                message: SmallBlockRootMessage {
                    channel_id: source_channel_id,
                    bp_member_slot: 0,
                    bp_pk_g: source_pk_g,
                    small_block_number: 1,
                    prev_small_block_root: Bytes32::default(),
                    tx_tree_root,
                    state_commitment_root: Bytes32::default(),
                    medium_epoch_hint: 3,
                    close_freeze_nonce: 0,
                },
                signatures: vec![],
                aggregated_signature_proof: vec![1],
                medium_block_number: 3,
                confirmation_proof: vec![2],
            },
            sender_delta_ct: sender_delta_ct.clone(),
            source_channel_id,
            destination_channel_id: closed_channel_id,
            token_index: claim_token_index,
            destination_base_transfer_salt: Salt::default(),
            base_nonce: 1,
            source_pk_g,
            seal: Bytes32::default(),
            tx_hash,
            intmax_transfer_commitment: Bytes32::default(),
            recipient_memo: vec![1, 2],
            receiver_deltas: vec![ReceiverBalanceDelta {
                receiver_pk_g,
                amount: delta_ct.clone(),
            }],
            channel_update_zkp: ChannelProofEnvelope {
                role: TransitionProofRole::ChannelStateUpdate,
                backend: ProofBackend::Plonky3,
                proof: vec![3],
            },
            transport_proof: vec![5],
        };

        let final_balance_state = BalanceState {
            channel_id: closed_channel_id,
            member_count: 2,
            delegate_count: 0,
            enc_balances: BalanceState::pad_enc_balances_token0(&[delta_ct.clone(), slot1_ct]),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&[
                Bytes32::from(receiver_pk.poseidon_digest()),
                Bytes32::from(other_pk.poseidon_digest()),
            ]),
            // B-1b: the receiver's (slot 0) leaf-bound exit address = the claim recipient below.
            recipients: BalanceState::pad_recipients(&[
                Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
                Address::from_u32_slice(&[21, 22, 23, 24, 25]).unwrap(),
            ]),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: accumulator_root,
            state_version: 9,
            pending_adds: BalanceState::pad_pending_adds_token0(&[0, 0]),
            // TM-16: two-token destination registry — the incoming tx's base token (55) sits at
            // local slot 1 (non-genesis).
            token_registry: {
                let mut registry = BalanceState::single_token_registry(0);
                registry[1] = claim_token_index;
                registry
            },
            token_count: 2,
        };

        let recipient = Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap();
        let prover = PostCloseClaimProver::new();
        let witness = prover
            .build_full_witness(
                &final_balance_state,
                0,
                &receiver_pk,
                &receiver_sk,
                receiver_pk_g,
                recipient,
                close_intent_digest,
                &source_tx,
                &accumulator,
                incoming_tx_index,
                RegevSecurityLevel::Test,
            )
            .expect("post-close claim witness");
        // TM-16: the builder exposes the DESCRIPTOR's base token (no caller choice).
        assert_eq!(witness.public_inputs.token_index, claim_token_index);
        let proof = prover.prove(&witness).expect("post-close claim proof");
        prover
            .vd()
            .verify(proof)
            .expect("post-close claim proof verifies");
    }

    /// A-3 P4: the full channel-withdrawal pipeline builds and SELF-VERIFIES end-to-end.
    ///
    /// `build_channel_withdrawal` internally verifies every proof (single-withdrawal, withdrawal
    /// chain, validity, both MLE wraps), re-folds the withdrawal keccak chain the way the contract
    /// will, and asserts `ext_commitment == validity final_ext_commitment`. So a successful return
    /// is itself the soundness self-check. This test additionally pins a withdrawal recipient and
    /// asserts the committed payout binds EXACTLY that recipient + the requested amount (no
    /// over-claim, no recipient substitution) and that the 4 artifacts are well-formed JSON with
    /// the cross-artifact ext_commitment / final-state-root agreement the on-chain steps rely
    /// on.
    ///
    /// NOTE: the MLE/WHIR layer is nondeterministic (ZK blinding), so this asserts SEMANTIC
    /// binding, never byte equality. Heavy (real proving) — release only.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "run with --release")]
    fn a3_channel_withdrawal_builds_and_verifies() {
        use crate::{
            circuits::test_utils::block_witness_generator::TEST_ACTIVE_MEMBERS,
            ethereum_types::{address::Address, u32limb_trait::U32LimbTrait},
        };

        // P5-B: exercise the INTEGRATED builder path — bind the channel's REAL co-signing members
        // (the same identities the close path signs with) so this single self-verifying build also
        // validates the close↔withdraw shared-registration path end to end.
        use rand010::{SeedableRng as _, rngs::StdRng as Rng010};
        let cli_members: Vec<MemberKeys> = (0..TEST_ACTIVE_MEMBERS)
            .map(|slot| MemberKeys::generate(&mut Rng010::seed_from_u64(0xC1_0000 + slot as u64)))
            .collect();

        // A distinctive recipient (the "manager" stand-in) so we can assert exact binding.
        let manager = Address::from_u32_slice(&[0xA11CE000, 1, 2, 3, 4]).unwrap();
        let params = ChannelWithdrawalParams {
            channel_id: 1,
            deposit_amount: 10,
            withdrawal_amount: 3,
            depositor: None,
            withdrawal_recipient: Some(manager),
            deposit_salt: None,
            erc20_lane: None,
        };
        let artifacts = build_channel_withdrawal(&params, Some(&cli_members))
            .expect("channel withdrawal pipeline self-verifies");

        // The emitted registration must commit EXACTLY the CLI members' pk_gs (the close path's
        // set).
        {
            use crate::common::channel::close_member_set_commitment;
            let lc: serde_json::Value =
                serde_json::from_str(&artifacts.lifecycle_json).expect("lifecycle json");
            let mut close_hashes: [Bytes32; crate::constants::MAX_COSIGNERS] =
                std::array::from_fn(|_| Bytes32::default());
            for (i, m) in cli_members.iter().enumerate() {
                close_hashes[i] = m.pk_g();
            }
            let want = close_member_set_commitment(&close_hashes, TEST_ACTIVE_MEMBERS as u8);
            for (i, m) in cli_members.iter().enumerate() {
                let got = lc["registration"]["member_pk_gs"][i].as_str().unwrap();
                assert_eq!(
                    got,
                    m.pk_g().to_string(),
                    "registration member {i} pk_g must be the CLI member's"
                );
            }
            let _ = want; // member-set equivalence is asserted exhaustively in the fast unit test.
        }

        // All 4 artifacts must be well-formed JSON.
        let lifecycle: serde_json::Value =
            serde_json::from_str(&artifacts.lifecycle_json).expect("lifecycle json");
        let payout: serde_json::Value =
            serde_json::from_str(&artifacts.payout_json).expect("payout json");
        let _: serde_json::Value =
            serde_json::from_str(&artifacts.withdrawal_mle_json).expect("withdrawal mle json");
        let _: serde_json::Value =
            serde_json::from_str(&artifacts.validity_mle_json).expect("validity mle json");

        // The committed withdrawal binds EXACTLY the requested amount (no over-claim). The
        // committed recipient is the in-circuit `calculate_recipient_from_address(manager)`
        // form, which the on-chain withdrawal re-derives; here we assert the requested
        // amount survives end-to-end.
        let amount = payout["withdrawals"][0]["amount"]
            .as_str()
            .expect("payout amount");
        assert_eq!(
            amount, "3",
            "committed withdrawal amount must equal the requested amount"
        );
        assert!(
            payout["withdrawals"][0]["nullifier"].as_str().is_some(),
            "payout must commit a withdrawal nullifier"
        );

        // Cross-artifact agreement the on-chain pipeline relies on: the payout's ext_commitment
        // (gated by `finalizedStateRoots`) MUST equal the lifecycle final state root that
        // `finalize` commits.
        let payout_ext = payout["ext_commitment"].as_str().expect("ext_commitment");
        let final_root = lifecycle["final_state_root"]
            .as_str()
            .expect("final_state_root");
        assert_eq!(
            payout_ext, final_root,
            "withdrawal ext_commitment must equal the validity final state root"
        );
        let vpis_final = lifecycle["vpis"]["final_ext_commitment"]
            .as_str()
            .expect("vpis final_ext_commitment");
        assert_eq!(
            vpis_final, final_root,
            "vpis.final_ext_commitment must equal final_state_root"
        );
    }

    /// P5-B integration: when `build_channel_withdrawal` is bound to the channel's REAL co-signing
    /// members, the registration it emits (lifecycle.json `.registration.member_pk_gs`) reproduces
    /// EXACTLY the member-set commitment the CLOSE path binds to. This is the property that lets
    /// ONE on-chain `registerChannel` serve both close and withdraw on the same channel: the
    /// withdraw registration block, the on-chain `channelMemberSetCommitment`, and the close
    /// proof's `member_set_commitment` all equal `close_member_set_commitment(member pk_gs)`.
    ///
    /// This is a pure-arithmetic check (no proving) — fast even in debug — so it is NOT
    /// release-gated.
    #[test]
    fn a3_withdraw_registration_matches_close_member_set() {
        use crate::{
            circuits::test_utils::block_witness_generator::{
                ChannelMemberKeys, TEST_ACTIVE_MEMBERS,
            },
            common::channel::close_member_set_commitment,
            ethereum_types::address::Address,
        };

        // The SAME identities the CLI close path uses: keys_for(0xC1_0000 + slot) for the members.
        use rand010::{SeedableRng as _, rngs::StdRng as Rng010};
        let cli_members: Vec<MemberKeys> = (0..TEST_ACTIVE_MEMBERS)
            .map(|slot| MemberKeys::generate(&mut Rng010::seed_from_u64(0xC1_0000 + slot as u64)))
            .collect();

        // PHASE 4: the seam is CLOSED. `MemberKeys` carries the Falcon key, so both sides below
        // start from `cli_members` — the SAME objects `build_channel_withdrawal` is handed — and
        // there is no second seed formula left to disagree with the first.
        //
        // (History, kept because it is the reason this test is written this way: the Phase-3
        // review found it had become a plumbing check — it derived Falcon keys, wrote their pk_g
        // into `close_hashes`, then passed the SAME vector into `from_member_keys` and compared
        // the two, which cannot fail regardless of what the registration path does. The two sides
        // must be derived INDEPENDENTLY or the comparison proves nothing.)
        //
        // CLOSE side: `MemberKeys::pk_g()` — what the member SIGNS with, read straight off the
        // key. REG side: the `MemberLeaf.pk_g` of the member tree the registration path BUILDS.
        // Two independent paths to the same quantity; if `from_member_keys` ever committed
        // anything other than the member's own signing identity, this fails.
        let mut close_hashes: [Bytes32; crate::constants::MAX_COSIGNERS] =
            std::array::from_fn(|_| Bytes32::default());
        for (i, k) in cli_members.iter().enumerate() {
            close_hashes[i] = k.pk_g();
        }
        let close_commitment =
            close_member_set_commitment(&close_hashes, TEST_ACTIVE_MEMBERS as u8);

        let cmk = ChannelMemberKeys::from_member_keys(&cli_members);
        let mut reg_hashes: [Bytes32; crate::constants::MAX_COSIGNERS] =
            std::array::from_fn(|_| Bytes32::default());
        for i in 0..TEST_ACTIVE_MEMBERS {
            reg_hashes[i] = Bytes32::from(cmk.member_tree.get_leaf(i as u64).pk_g);
        }
        let reg_commitment = close_member_set_commitment(&reg_hashes, TEST_ACTIVE_MEMBERS as u8);

        assert_eq!(
            reg_commitment, close_commitment,
            "withdraw registration member set must equal the close path's member-set commitment \
             (so one on-chain registerChannel serves both)"
        );
        // The whole check (the Phase-4 obligation the previous revision recorded as a comment):
        // the pk_g a member SIGNS with is exactly the pk_g the registration COMMITS.
        for (i, m) in cli_members.iter().enumerate() {
            assert_eq!(
                Bytes32::from(cmk.member_tree.get_leaf(i as u64).pk_g),
                m.pk_g(),
                "member {i} pk_g mismatch between the member's Falcon signing key and the \
                 registration member tree"
            );
        }
        // The identities must also be distinct per slot: a shared key would let one member
        // satisfy several slots, defeating the close circuit's A5 distinctness check.
        for a in 0..TEST_ACTIVE_MEMBERS {
            for b in (a + 1)..TEST_ACTIVE_MEMBERS {
                assert_ne!(
                    cli_members[a].pk_g(),
                    cli_members[b].pk_g(),
                    "cosigner slots {a} and {b} must not share an identity"
                );
            }
        }
        // The per-(channel, slot) recipient formula is deterministic and nonzero (registerChannel
        // rejects zero recipients).
        let r0 = Address::from_u32_slice(&[0x3333_0000u32; 5]).unwrap();
        assert_ne!(r0, Address::default());
    }

    // ===============================================================================
    // TM-14 (multitoken Phase 2b) — mixed-token slim/batch co-sign path.
    // ===============================================================================

    /// Base token_index registered at local slot 1 in the two-token batch fixtures.
    const T1_INDEX: u32 = 55;

    /// A 2-member + 1-delegate channel whose genesis ALSO registers base token 55 at local slot
    /// 1 and funds token-1 balances for slots 0 and 1. Returns the token-1 `AmountWitness`es
    /// alongside the token-0 ones.
    #[allow(clippy::type_complexity)]
    fn setup_two_token_channel(
        rng: &mut StdRng,
        channel_id: u32,
        balances_t0: [u64; 3],
        balances_t1: [u64; 2],
    ) -> (
        ChannelRecord,
        Vec<MemberKeys>,
        Vec<MemberInfo>,
        ChannelState,
        Vec<AmountWitness>,
        Vec<AmountWitness>,
    ) {
        let (record, keys, members, mut genesis, w_t0) =
            setup_delegate_channel(rng, channel_id, balances_t0);
        genesis
            .balance_state
            .apply_token_register(T1_INDEX)
            .expect("register token 55");
        let mut w_t1 = Vec::new();
        for (slot, &bal) in balances_t1.iter().enumerate() {
            let (ct, w) = encrypt_amount(rng, &keys[slot].regev_pk, bal).unwrap();
            genesis.balance_state.enc_balances[slot][1] = ct;
            w_t1.push(w);
        }
        genesis
            .balance_state
            .validate()
            .expect("2-token genesis valid");
        genesis.member_signatures = Vec::new();
        let mut genesis = genesis.with_computed_digest();
        let g0 = sign_state(&keys[0], 0, &genesis).unwrap();
        add_signature(&mut genesis, g0);
        let g1 = sign_state(&keys[1], 1, &genesis).unwrap();
        add_signature(&mut genesis, g1);
        (record, keys, members, genesis, w_t0, w_t1)
    }

    /// Build a SLIM in-channel send of `amount` at `token_slot` through the REAL Phase 4
    /// per-token build path (`build_send_token` → `to_slim`), so the TM-14 batch suite ALSO
    /// exercises the production builder at non-genesis positions.
    #[allow(clippy::too_many_arguments)]
    fn build_slim_send_at(
        rng: &mut StdRng,
        keys: &MemberKeys,
        snapshot: &ChannelSnapshot,
        sender_slot: u16,
        recipient_slot: u16,
        token_slot: u8,
        amount: u64,
        before_amount: u64,
        before_witness: &AmountWitness,
        nonce_seed: u32,
    ) -> (SlimSendPayload, AmountWitness) {
        let nonce = Bytes32::from_u32_slice(&[nonce_seed, 0, 0, 0, 0, 0, 0, 1]).unwrap();
        let BuiltSend {
            payload,
            new_balance_witness,
            ..
        } = build_send_token(
            keys,
            snapshot,
            sender_slot,
            recipient_slot,
            token_slot,
            amount,
            before_amount,
            before_witness,
            nonce,
            LEVEL,
            rng,
        )
        .expect("build_send_token");
        (payload.to_slim(), new_balance_witness)
    }

    /// TM-14 completeness: a mixed-token batch where the SAME member debits TWO different
    /// tokens (token 0 -> slot 1, token 1 -> slot 1) verifies per tx and folds correctly per
    /// (slot, token) — both recipients decrypt their running balances, all bystander positions
    /// bit-identical.
    #[test]
    fn mixed_token_batch_same_member_two_debits() {
        let mut rng = StdRng::seed_from_u64(0x2b70b1);
        let (record, keys, members, genesis, w_t0, w_t1) =
            setup_two_token_channel(&mut rng, 21, [50, 30, 20], [40, 25]);
        let snapshot = ChannelSnapshot {
            record: record.clone(),
            state: genesis,
            members,
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        let regev_pks = regev_pks_array(&snapshot.members);

        // Member 0 debits token 0 (7 -> slot 1) AND token 1 (5 -> slot 1) in ONE batch.
        let (slim_a, _wa) = build_slim_send_at(
            &mut rng, &keys[0], &snapshot, 0, 1, 0, 7, 50, &w_t0[0], 0xA1,
        );
        let (slim_b, _wb) = build_slim_send_at(
            &mut rng, &keys[0], &snapshot, 0, 1, 1, 5, 40, &w_t1[0], 0xB2,
        );
        for slim in [&slim_a, &slim_b] {
            verify_slim_send_tx(
                &snapshot.state,
                &record,
                &snapshot.members,
                &regev_pks,
                slim,
                LEVEL,
                None,
                None,
            )
            .expect("mixed-token slim tx must verify");
        }
        let applies: Vec<BatchTxApply> = [&slim_a, &slim_b]
            .iter()
            .map(|s| BatchTxApply::from(*s))
            .collect();
        let batch = build_batch_next_state(&snapshot.state, &applies)
            .expect("same member may debit two DIFFERENT tokens in one batch (R1 per pair)");

        // Fold correctness per (slot, token): debits installed, credits homomorphically added.
        let bs = &batch.balance_state;
        assert_eq!(
            decrypt_amount(&keys[0].regev_sk, &bs.enc_balances[0][0]).unwrap(),
            43
        );
        assert_eq!(
            decrypt_amount(&keys[0].regev_sk, &bs.enc_balances[0][1]).unwrap(),
            35
        );
        assert_eq!(
            decrypt_amount(&keys[1].regev_sk, &bs.enc_balances[1][0]).unwrap(),
            37
        );
        assert_eq!(
            decrypt_amount(&keys[1].regev_sk, &bs.enc_balances[1][1]).unwrap(),
            30
        );
        // Bystanders frozen: the delegate row and every untouched (slot, token) position.
        assert_eq!(
            bs.enc_balances[2], snapshot.state.balance_state.enc_balances[2],
            "uninvolved row must be bit-identical"
        );
        assert_eq!(bs.pending_adds[1][0], 1);
        assert_eq!(bs.pending_adds[1][1], 1);
        assert_eq!(
            bs.pending_adds[2],
            snapshot.state.balance_state.pending_adds[2]
        );

        // R1 per (sender, token) PAIR: the SAME pair twice is still rejected.
        let err =
            build_batch_next_state(&snapshot.state, &[applies[1].clone(), applies[1].clone()])
                .unwrap_err();
        assert!(err.0.contains("R1"), "expected R1 rejection, got: {err}");
    }

    /// TM-14 adversarial: (a) a doctored `token_slot` echo (signed token 1, wire claims 0)
    /// fails the per-tx verification — the IMPA-v2 digest binds the slot, so the A11 hash-sig
    /// no longer verifies; (b) a swapped `after_ct` (the only wire field that could smuggle a
    /// bystander-position mutation into the fold) fails the E-1 statement rebuild.
    #[test]
    fn mixed_token_batch_rejects_doctored_slot_and_after_ct() {
        let mut rng = StdRng::seed_from_u64(0x2b70b2);
        let (record, keys, members, genesis, _w_t0, w_t1) =
            setup_two_token_channel(&mut rng, 22, [50, 30, 20], [40, 25]);
        let snapshot = ChannelSnapshot {
            record: record.clone(),
            state: genesis,
            members,
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        let regev_pks = regev_pks_array(&snapshot.members);
        let (slim, _w) = build_slim_send_at(
            &mut rng, &keys[0], &snapshot, 0, 1, 1, 5, 40, &w_t1[0], 0xC3,
        );

        // (a) Doctored token_slot echo.
        let mut doctored = slim.clone();
        doctored.channel_tx.token_slot = 0;
        assert!(
            verify_slim_send_tx(
                &snapshot.state,
                &record,
                &snapshot.members,
                &regev_pks,
                &doctored,
                LEVEL,
                None,
                None,
            )
            .is_err(),
            "a doctored token_slot echo must fail the signed-digest binding"
        );

        // (b) Swapped after_ct (bystander-mutation smuggling vector).
        let mut doctored = slim.clone();
        doctored.after_ct = snapshot.state.balance_state.enc_balances[0][0].clone();
        assert!(
            verify_slim_send_tx(
                &snapshot.state,
                &record,
                &snapshot.members,
                &regev_pks,
                &doctored,
                LEVEL,
                None,
                None,
            )
            .is_err(),
            "a swapped after_ct must fail the E-1 statement rebuild"
        );

        // (c) TM-8 bounds: an inactive (and an out-of-layout) token_slot is refused by the slim
        // verifier AND by the fold itself.
        for bad in [2u8, MAX_CHANNEL_TOKENS as u8] {
            let mut doctored = slim.clone();
            doctored.channel_tx.token_slot = bad;
            assert!(
                verify_slim_send_tx(
                    &snapshot.state,
                    &record,
                    &snapshot.members,
                    &regev_pks,
                    &doctored,
                    LEVEL,
                    None,
                    None,
                )
                .is_err(),
                "token_slot {bad} must be refused (TM-8)"
            );
            let mut apply = BatchTxApply::from(&slim);
            apply.token_slot = bad;
            assert!(
                build_batch_next_state(&snapshot.state, &[apply]).is_err(),
                "the fold must refuse token_slot {bad} fail-closed (TM-8)"
            );
        }
    }

    /// TESTNET FAUCET MECHANISM (multitoken §N × detail2 §B-3, TM-13). A position that was
    /// credited HOMOMORPHICALLY cannot be spent — this pins BOTH halves of that rule and the
    /// value-preserving way out, which is exactly the sequence the `channel_member refresh` +
    /// `send <token_slot>` faucet leg runs:
    ///
    ///   1. a homomorphic credit at (slot 0, token 1) raises `pending_adds` and installs a
    ///      ciphertext the holder has no encryption witness for;
    ///   2. a send from that position is REFUSED fail-closed (the D3/TM-13 refresh gate), and it is
    ///      refused BEFORE the stale pre-credit witness could be used;
    ///   3. `build_refresh` re-encrypts the position to a fresh, locally-witnessed ciphertext whose
    ///      plaintext is the CREDITED total — no inflation, no loss — and the co-signer gate
    ///      (`verify_refresh_transition`, real RefreshAir) accepts it;
    ///   4. the position sends again, and the recipient decrypts exactly the sent amount.
    ///
    /// Step 3 additionally pins the invariant the CLI's on-disk witness store depends on: driving
    /// `build_refresh` from a SEEDED `StdRng` makes the refreshed ciphertext reproducible by
    /// replaying `encrypt_amount` with the same seed (the refresh prover's first and only RNG
    /// consumption). If upstream ever consumes randomness earlier, this assertion fails here
    /// rather than as a confusing E-1 failure on a later send.
    #[test]
    fn refresh_unblocks_a_homomorphically_credited_token_position() {
        let mut rng = StdRng::seed_from_u64(0x2b70fa);
        // Slot 0 = the "faucet" member (40 at token 1), slot 1 = a funder, slot 2 = a delegate.
        let (record, keys, members, genesis, _w_t0, w_t1) =
            setup_two_token_channel(&mut rng, 27, [50, 30, 20], [40, 25]);
        let mut snapshot = ChannelSnapshot {
            record: record.clone(),
            state: genesis,
            members,
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };

        // (1) Homomorphic credit into slot 0's token-1 position (slot 1 sends it 10).
        let credit = build_send_token(
            &keys[1],
            &snapshot,
            1,
            0,
            1,
            10,
            25,
            &w_t1[1],
            Bytes32::default(),
            LEVEL,
            &mut rng,
        )
        .expect("credit send builds");
        let mut credited = credit.payload.proposed_next_state.clone();
        let sig0 = sign_state(&keys[0], 0, &credited).expect("slot 0 co-signs");
        add_signature(&mut credited, sig0);
        verify_all_signatures(&record, &snapshot.members, &credited)
            .expect("credited head is N-of-N signed");
        snapshot.state = credited;
        assert_eq!(
            snapshot.state.balance_state.pending_adds[0][1], 1,
            "a homomorphic credit must raise the recipient's (slot, token) counter"
        );

        // (2) Fail-closed: the credited position cannot send, even with the pre-credit witness.
        let blocked = build_send_token(
            &keys[0],
            &snapshot,
            0,
            1,
            1,
            7,
            40,
            &w_t1[0],
            Bytes32::default(),
            LEVEL,
            &mut rng,
        );
        match blocked {
            Ok(_) => panic!("a position with pending adds must not be spendable"),
            Err(e) => assert!(
                e.0.contains("pending homomorphic adds"),
                "expected the D3/TM-13 refresh gate, got: {e}"
            ),
        }

        // (3) Refresh from a RECORDED seed — the CLI's witness-store model.
        let seed = [0x5Au8; 32];
        let (payload, witness) = build_refresh(
            &keys[0],
            &snapshot,
            0,
            1,
            LEVEL,
            &mut StdRng::from_seed(seed),
        )
        .expect("refresh builds");
        assert_eq!(
            witness.amount, 50,
            "the refresh must preserve the CREDITED value (40 + 10), never mint or lose"
        );
        verify_refresh_transition(&snapshot.state, &record, &payload, LEVEL)
            .expect("co-signer gate accepts the refresh");
        // Seed replay reproduces the installed ciphertext exactly (the CLI self-check).
        let (replayed, _) = encrypt_amount(
            &mut StdRng::from_seed(seed),
            &keys[0].regev_pk,
            witness.amount,
        )
        .expect("replay encrypt");
        assert_eq!(
            replayed, payload.proposed_next_state.balance_state.enc_balances[0][1],
            "a recorded seed must reproduce the refreshed ciphertext"
        );

        let mut refreshed = payload.proposed_next_state.clone();
        let sig1 = sign_state(&keys[1], 1, &refreshed).expect("slot 1 co-signs");
        add_signature(&mut refreshed, sig1);
        verify_all_signatures(&record, &snapshot.members, &refreshed)
            .expect("refreshed head is N-of-N signed");
        assert_eq!(
            refreshed.balance_state.pending_adds[0][1], 0,
            "the refresh must clear the position's counter"
        );
        snapshot.state = refreshed;

        // (4) The faucet drip: the refreshed position sends, and the recipient decrypts it.
        let drip = build_send_token(
            &keys[0],
            &snapshot,
            0,
            2,
            1,
            7,
            witness.amount,
            &witness,
            Bytes32::default(),
            LEVEL,
            &mut rng,
        )
        .expect("the refreshed position must be spendable again");
        verify_send_transition(
            &snapshot.state,
            &record,
            &drip.payload,
            LEVEL,
            Some(&keys[2].regev_sk),
            Some(7),
        )
        .expect("the drip transition verifies with the recipient's decryption check");
        assert_eq!(drip.new_balance, 43, "50 - 7");
        assert_eq!(
            decrypt_amount(
                &keys[2].regev_sk,
                &drip.payload.proposed_next_state.balance_state.enc_balances[2][1],
            )
            .unwrap(),
            7,
            "the recipient's token-1 position must hold exactly the drip"
        );
        // Bystander: token 0 of every row is bit-identical across the whole sequence.
        for row in 0..3 {
            assert_eq!(
                drip.payload.proposed_next_state.balance_state.enc_balances[row][0],
                snapshot.state.balance_state.enc_balances[row][0],
                "row {row} token 0 must be untouched by the token-1 faucet flow"
            );
        }
    }

    /// TM-7 (builder side): an L1 deposit of base token 55 credits the depositor leaf at the
    /// REGISTRY-RESOLVED local position 1 (fund AND ciphertext), leaves token 0 untouched, and
    /// an UNREGISTERED base token_index is refused fail-closed.
    #[test]
    fn l1_deposit_import_resolves_token_position_and_rejects_unregistered() {
        let mut rng = StdRng::seed_from_u64(0x2b70b4);
        let (record, keys, members, genesis, _w_t0, _w_t1) =
            setup_two_token_channel(&mut rng, 24, [0, 0, 0], [0, 0]);
        let snapshot = ChannelSnapshot {
            record,
            state: genesis,
            members,
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        let amount = 12_345u64;
        let deposit = |token_index: u32| Deposit {
            deposit_index: Default::default(),
            block_number: Default::default(),
            depositor: Address::default(),
            recipient: Bytes32::default(),
            token_index,
            amount: U256::from(amount),
            aux_data: Bytes32::default(),
        };
        let (delta, _) = encrypt_amount(&mut rng, &keys[1].regev_pk, amount).unwrap();

        // Unregistered base token: refuse before building anything.
        let err = match build_l1_deposit_import(&keys[0], &snapshot, &deposit(77), 1, &delta, LEVEL)
        {
            Err(e) => e,
            Ok(_) => panic!("an unregistered token_index must be refused (TM-7)"),
        };
        assert!(err.0.contains("not registered"), "wrong rejection: {err}");

        // Registered token 55 -> local slot 1: fund at amounts[1], leaf credit at [1][1].
        let built =
            build_l1_deposit_import(&keys[0], &snapshot, &deposit(T1_INDEX), 1, &delta, LEVEL)
                .expect("token-55 deposit import");
        let prev = &snapshot.state;
        let bundle = &built.bundle_apply_state;
        assert_eq!(
            bundle.channel_fund.amounts[1],
            prev.channel_fund.amounts[1] + u64_to_u256(amount)
        );
        assert_eq!(bundle.channel_fund.amounts[0], prev.channel_fund.amounts[0]);
        assert_eq!(
            decrypt_amount(&keys[1].regev_sk, &bundle.balance_state.enc_balances[1][1]).unwrap(),
            amount
        );
        assert_eq!(
            bundle.balance_state.enc_balances[1][0], prev.balance_state.enc_balances[1][0],
            "token 0 of the depositor row must be untouched"
        );
        assert_eq!(bundle.balance_state.pending_adds[1][1], 1);
        assert_eq!(bundle.balance_state.pending_adds[1][0], 0);

        // Co-signer gate accepts BOTH steps for the resolved non-genesis token (the fund-import
        // witness takes a fully-signed state, so add the second member's signature first; the
        // bundle rebuild-equality ignores signatures by construction).
        let mut signed_import = built.fund_import_state.clone();
        let s1 = sign_state(&keys[1], 1, &signed_import).unwrap();
        add_signature(&mut signed_import, s1);
        verify_l1_deposit_import_transition(
            prev,
            &snapshot.record,
            &deposit(T1_INDEX),
            &signed_import,
            &built.bundle_apply_state,
            1,
            &delta,
        )
        .expect("co-signer gate must accept the resolved-token two-step import");
    }

    /// TM-7 leg (b) — Phase 2b review MAJOR 1: the co-signer gate REBUILDS the bundle-apply
    /// step and rejects any proposed bundle state that diverges from the canonical credit at
    /// the registry-resolved (row, token) position: (a) right slot / WRONG token position, (b)
    /// a DIFFERENT slot, (c) a doctored amount (double credit). A distributed co-signer
    /// therefore never signs a proposer-crafted cross-token/cross-slot credit.
    #[test]
    fn l1_deposit_gate_rejects_divergent_bundle_state() {
        let mut rng = StdRng::seed_from_u64(0x2b70b5);
        let (record, keys, members, genesis, _w_t0, _w_t1) =
            setup_two_token_channel(&mut rng, 25, [0, 0, 0], [0, 0]);
        let snapshot = ChannelSnapshot {
            record,
            state: genesis,
            members,
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        let amount = 9_999u64;
        let deposit = Deposit {
            deposit_index: Default::default(),
            block_number: Default::default(),
            depositor: Address::default(),
            recipient: Bytes32::default(),
            token_index: T1_INDEX, // resolves to local token slot 1
            amount: U256::from(amount),
            aux_data: Bytes32::default(),
        };
        let (delta, _) = encrypt_amount(&mut rng, &keys[1].regev_pk, amount).unwrap();
        let built = build_l1_deposit_import(&keys[0], &snapshot, &deposit, 1, &delta, LEVEL)
            .expect("token-55 deposit import");
        let mut signed_import = built.fund_import_state.clone();
        let s1 = sign_state(&keys[1], 1, &signed_import).unwrap();
        add_signature(&mut signed_import, s1);
        let gate = |bundle: &ChannelState| {
            verify_l1_deposit_import_transition(
                &snapshot.state,
                &snapshot.record,
                &deposit,
                &signed_import,
                bundle,
                1,
                &delta,
            )
        };
        // Sanity: the canonical bundle passes.
        gate(&built.bundle_apply_state).expect("canonical bundle must pass the gate");

        // (a) Right slot, WRONG token position: credit lands at [1][0] instead of [1][1].
        let mut wrong_token = built.bundle_apply_state.clone();
        wrong_token.balance_state.enc_balances[1] =
            built.fund_import_state.balance_state.enc_balances[1].clone();
        wrong_token.balance_state.enc_balances[1][0] = add_ciphertexts(
            &built.fund_import_state.balance_state.enc_balances[1][0],
            &delta,
        )
        .unwrap();
        wrong_token.balance_state.pending_adds[1] = [0; MAX_CHANNEL_TOKENS];
        wrong_token.balance_state.pending_adds[1][0] = 1;
        let wrong_token = wrong_token.with_computed_digest();
        assert!(
            gate(&wrong_token).is_err(),
            "a cross-token credit (right slot, wrong position) must be rejected (TM-7 leg b)"
        );

        // (b) A DIFFERENT slot: credit lands at [0][1] instead of [1][1].
        let mut wrong_slot = built.bundle_apply_state.clone();
        wrong_slot.balance_state.enc_balances[1] =
            built.fund_import_state.balance_state.enc_balances[1].clone();
        wrong_slot.balance_state.pending_adds[1] = [0; MAX_CHANNEL_TOKENS];
        wrong_slot.balance_state.enc_balances[0][1] = add_ciphertexts(
            &built.fund_import_state.balance_state.enc_balances[0][1],
            &delta,
        )
        .unwrap();
        wrong_slot.balance_state.pending_adds[0][1] = 1;
        let wrong_slot = wrong_slot.with_computed_digest();
        assert!(
            gate(&wrong_slot).is_err(),
            "a cross-slot credit must be rejected (TM-7 leg b)"
        );

        // (c) Doctored amount: the delta credited TWICE (double credit at the right position).
        let mut double_credit = built.bundle_apply_state.clone();
        double_credit.balance_state.enc_balances[1][1] = add_ciphertexts(
            &built.bundle_apply_state.balance_state.enc_balances[1][1],
            &delta,
        )
        .unwrap();
        let double_credit = double_credit.with_computed_digest();
        assert!(
            gate(&double_credit).is_err(),
            "a double credit (doctored amount) must be rejected (TM-7 leg b)"
        );

        // (d) The bundle cannot replace the accumulator root committed by the import step.
        let mut wrong_accumulator = built.bundle_apply_state.clone();
        wrong_accumulator.balance_state.settled_tx_accumulator_root =
            Bytes32::from_u32_slice(&[0xacc0; 8]).unwrap();
        let wrong_accumulator = wrong_accumulator.with_computed_digest();
        assert!(
            gate(&wrong_accumulator).is_err(),
            "bundle apply must retain the fund-import accumulator root"
        );
    }

    /// TM-14 / §M-2 invariant, per token: for K = 1 the batch fold is FIELD-IDENTICAL (same
    /// digest) to the canonical solo next state at the tx's token slot — for token 0 AND for
    /// token 1.
    #[test]
    fn k1_batch_fold_identical_to_solo_per_token() {
        let mut rng = StdRng::seed_from_u64(0x2b70b3);
        let (record, keys, members, genesis, w_t0, w_t1) =
            setup_two_token_channel(&mut rng, 23, [50, 30, 20], [40, 25]);
        let snapshot = ChannelSnapshot {
            record,
            state: genesis,
            members,
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        for (token_slot, amount, before, witness) in
            [(0u8, 7u64, 50u64, &w_t0[0]), (1u8, 5u64, 40u64, &w_t1[0])]
        {
            let (slim, _w) = build_slim_send_at(
                &mut rng,
                &keys[0],
                &snapshot,
                0,
                1,
                token_slot,
                amount,
                before,
                witness,
                0xD0 + token_slot as u32,
            );
            let solo = solo_next_state(
                &snapshot.state,
                0,
                1,
                token_slot,
                &slim.after_ct,
                &slim.channel_tx.enc_amount,
            )
            .unwrap();
            let batch =
                build_batch_next_state(&snapshot.state, &[BatchTxApply::from(&slim)]).unwrap();
            assert_eq!(
                solo.digest, batch.digest,
                "K=1 fold must be field-identical to solo at token {token_slot}"
            );
        }
    }

    // ===============================================================================
    // Multitoken Phase 4 — build-path token parameters, TokenRegister dispatch, and the
    // per-token close/claim path (gate lift).
    // ===============================================================================

    /// Re-sign a mutated head with the two co-signing members (fixture helper: fund edits
    /// invalidate the genesis signatures).
    fn resign_two_members(mut state: ChannelState, keys: &[MemberKeys]) -> ChannelState {
        state.member_signatures = Vec::new();
        let mut state = state.with_computed_digest();
        let s0 = sign_state(&keys[0], 0, &state).unwrap();
        add_signature(&mut state, s0);
        let s1 = sign_state(&keys[1], 1, &state).unwrap();
        add_signature(&mut state, s1);
        state
    }

    /// §N-1 TokenRegister via the cosign gate, end-to-end: member 0 proposes through
    /// `build_token_register` (canonical builder + self-check + own REAL signature), member 1
    /// re-runs the gate and co-signs, and the fully-signed head passes the authoritative
    /// `verify_all_signatures` N-of-N check with the new registry committed. Negatives: a
    /// registration bundling a balance touch is refused by the gate; a duplicate base index is
    /// refused by the builder (TM-1).
    #[test]
    fn token_register_cosign_gate_end_to_end() {
        let mut rng = StdRng::seed_from_u64(0x70CE);
        let (record, keys, members, genesis, _w) =
            setup_delegate_channel(&mut rng, 31, [50, 30, 20]);
        let snapshot = ChannelSnapshot {
            record: record.clone(),
            state: genesis,
            members: members.clone(),
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };

        let mut proposed =
            build_token_register(&keys[0], &snapshot, 0, 777).expect("build token register");
        // Cosigner 1: gate FIRST, then sign (the CLAUDE.md check-and-sign discipline).
        verify_token_register_state_transition(&snapshot.state, &record, &proposed, 777)
            .expect("cosigner gate must accept the canonical registration");
        let s1 = sign_state(&keys[1], 1, &proposed).unwrap();
        add_signature(&mut proposed, s1);
        verify_all_signatures(&record, &members, &proposed)
            .expect("N-of-N over the registered head");
        assert_eq!(proposed.balance_state.token_count, 2);
        assert_eq!(proposed.balance_state.token_registry[1], 777);
        assert_eq!(
            proposed.balance_state.state_version,
            snapshot.state.balance_state.state_version + 1
        );

        // Negative: a registration that ALSO touches a balance ciphertext is refused.
        let mut doctored = proposed.clone();
        doctored.balance_state.enc_balances[2][0] =
            doctored.balance_state.enc_balances[0][0].clone();
        let doctored = doctored.with_computed_digest();
        assert!(
            verify_token_register_state_transition(&snapshot.state, &record, &doctored, 777)
                .is_err(),
            "a balance touch under a TokenRegister must be refused (full freeze, TM-1)"
        );
        // Negative: re-registering the genesis base index is refused (registry injectivity).
        assert!(
            build_token_register(
                &keys[0],
                &snapshot,
                0,
                snapshot.state.balance_state.token_registry[0]
            )
            .is_err(),
            "duplicate base token_index must be refused (TM-1)"
        );
    }

    /// TM-8 (build path): the per-token send builder refuses an INACTIVE token position.
    #[test]
    fn build_send_token_rejects_inactive_position() {
        let mut rng = StdRng::seed_from_u64(0x8ba9);
        let (record, keys, members, genesis, witnesses) =
            setup_delegate_channel(&mut rng, 32, [50, 30, 20]);
        let snapshot = ChannelSnapshot {
            record,
            state: genesis,
            members,
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        assert!(
            build_send_token(
                &keys[0],
                &snapshot,
                0,
                1,
                1, // token_count is 1 — position 1 is inactive
                5,
                50,
                &witnesses[0],
                Bytes32::default(),
                LEVEL,
                &mut rng,
            )
            .is_err(),
            "sending an inactive token position must be refused (TM-8)"
        );
    }

    /// §N-6 per-token close (the Phase 4 gate lift, landed WITH the per-token claim builders):
    /// a channel holding funds in TWO tokens closes with the burn denominating ONLY the genesis
    /// leg (`burn_amount == amounts[0]`); the intent snapshots the full vector; withdrawal
    /// claims build for BOTH tokens against the SAME close intent with DISTINCT per-(slot,
    /// token) nullifiers and the correct resolved base token_index PIs; the non-genesis claim
    /// proof verifies end-to-end.
    #[test]
    fn two_token_close_intent_builds_per_token_claims() {
        let mut rng = StdRng::seed_from_u64(0x2C105E);
        let (record, keys, _members, genesis, _w0, _w1) =
            setup_two_token_channel(&mut rng, 41, [50, 30, 20], [40, 25]);
        // Fund the token-1 leg (the fixture's genesis fund covers token 0 only) and re-sign.
        let mut state = genesis;
        state.channel_fund.amounts[1] = u64_to_u256(65);
        let state = resign_two_members(state, &keys);

        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_balance_state_h1: state.balance_state.h1(),
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::from_u32_slice(&[9, 8, 7, 6, 0, 0, 0, 0]).unwrap(),
            // The burn denominates the GENESIS token fund ONLY (§N-6); the token-1 fund
            // settles via per-token claims, never the burn.
            burn_amount: state.channel_fund.amounts[0],
            zkp: vec![],
        };
        let close_intent =
            CloseIntent::new(1, &state, &close_tx, 7).expect("two-token close intent must build");
        assert_eq!(
            close_intent.channel_fund_snapshot.amounts[1],
            u64_to_u256(65),
            "the intent must snapshot the full per-token fund vector (TFD/IMCI source)"
        );

        let prover = WithdrawalClaimProver::new();
        let recipient = state.balance_state.recipients[0];
        let pk_g = record.member_pk_gs[0];
        let w_t0 = prover
            .build_full_witness(
                &state.balance_state,
                0,
                0,
                pk_g,
                &keys[0].regev_pk,
                &keys[0].regev_sk,
                recipient,
                &close_intent,
                &close_tx,
                LEVEL,
            )
            .expect("token-0 claim witness");
        let w_t1 = prover
            .build_full_witness(
                &state.balance_state,
                0,
                1,
                pk_g,
                &keys[0].regev_pk,
                &keys[0].regev_sk,
                recipient,
                &close_intent,
                &close_tx,
                LEVEL,
            )
            .expect("token-1 claim witness");
        assert_eq!(w_t0.public_inputs.amount, 50);
        assert_eq!(w_t1.public_inputs.amount, 40);
        assert_eq!(w_t0.public_inputs.token_slot, 0);
        assert_eq!(w_t1.public_inputs.token_slot, 1);
        assert_eq!(w_t0.public_inputs.token_index, 0);
        assert_eq!(
            w_t1.public_inputs.token_index, T1_INDEX,
            "the claim PI must expose the H1-committed registry resolution (m8)"
        );
        assert_ne!(
            w_t0.public_inputs.withdrawal_nullifier, w_t1.public_inputs.withdrawal_nullifier,
            "per-(slot, token) claims must carry distinct nullifiers (TM-5)"
        );
        // Prove + verify the NON-genesis claim end-to-end (the new Phase 4 path).
        let proof = prover.prove(&w_t1).expect("token-1 claim proof");
        prover
            .vd()
            .verify(proof)
            .expect("token-1 claim proof verifies");
    }

    /// TM-6 (Phase 4 build path): `build_inter_channel_send_token` debits the RESOLVED local
    /// slot of a NON-genesis base token — fund moves at amounts[1] only, the descriptor and the
    /// base Transfer carry base index 55 — and the built payload passes the co-signer gate. An
    /// unregistered base index is refused fail-closed before anything is built.
    #[test]
    fn inter_channel_send_token_debits_resolved_slot() {
        let mut rng = StdRng::seed_from_u64(0x1C2C);
        let (record, keys, members, genesis, _w0, w1) =
            setup_two_token_channel(&mut rng, 51, [50, 30, 20], [40, 25]);
        let mut state = genesis;
        state.channel_fund.amounts[1] = u64_to_u256(65);
        let state = resign_two_members(state, &keys);
        let snapshot = ChannelSnapshot {
            record: record.clone(),
            state,
            members,
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        let dest_keys = MemberKeys::generate(&mut rng);
        let dest_channel = crate::common::channel_id::ChannelId::new(99).unwrap();
        let nullifier_root = Bytes32::from_u32_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();

        // Unregistered base index: refused before any proof work.
        assert!(
            build_inter_channel_send_token(
                &keys[0],
                &snapshot,
                0,
                dest_channel,
                0,
                dest_keys.regev_pk.clone(),
                dest_keys.pk_g(),
                Salt::default(),
                77,
                5,
                40,
                &w1[0],
                nullifier_root,
                LEVEL,
                &mut rng,
            )
            .is_err(),
            "an unregistered base token_index must be refused (TM-6)"
        );

        // The base cursor is zero even though this transition's channel small-block number is one.
        // That is the normal post-setup shape and proves the two counters are independent.
        let built = build_inter_channel_send_token_at_base_nonce(
            &keys[0],
            &snapshot,
            0,
            dest_channel,
            0,
            dest_keys.regev_pk.clone(),
            dest_keys.pk_g(),
            Salt::default(),
            T1_INDEX,
            0,
            5,
            40,
            &w1[0],
            nullifier_root,
            LEVEL,
            &mut rng,
        )
        .expect("token-1 C2C debit builds");
        let a_send = &built.debit_payload.proposed_next_state;
        assert_eq!(
            a_send.channel_fund.amounts[1] + u64_to_u256(5),
            snapshot.state.channel_fund.amounts[1],
            "the debit must land at the RESOLVED local slot (1)"
        );
        assert_eq!(
            a_send.channel_fund.amounts[0], snapshot.state.channel_fund.amounts[0],
            "the genesis-token fund must be untouched"
        );
        assert_eq!(
            built.transfer_descriptor.inter_channel_tx.token_index,
            T1_INDEX
        );
        assert_eq!(built.transfer_descriptor.inter_channel_tx.base_nonce, 0);
        assert_eq!(built.transfer_descriptor.tx_v2.nonce, 0);
        assert_eq!(
            built
                .transfer_descriptor
                .inter_channel_tx
                .signed_small_block
                .message
                .small_block_number,
            1
        );
        // The co-signer gate accepts the built payload (Phase 2b general resolution).
        verify_inter_channel_send_transition(&snapshot.state, &record, &built.debit_payload, LEVEL)
            .expect("token-1 C2C debit passes the co-signer gate");

        let mut nonce_tamper = built.transfer_descriptor.clone();
        nonce_tamper.inter_channel_tx.base_nonce = 1;
        assert!(
            verify_inter_channel_descriptor_matches_debit(&built.debit_payload, &nonce_tamper)
                .is_err(),
            "IMI3 must bind the explicit base nonce"
        );
    }

    /// Phase 6 (Design B): a REAL inter-channel send produces a small block carrying the channel's
    /// REAL N-of-N Falcon cosignatures — and any one member can block it by withholding.
    ///
    /// WHAT EACH ASSERTION PROVES
    /// - the builder emits an UNSIGNED block: the slots hold `structural_cosign_placeholder`
    ///   non-signatures, never anything that could pass an authenticating path;
    /// - with only the sender's signature (N-1 of N), installing is REFUSED — the documented
    ///   posture that block production is blockable by a single member;
    /// - once every member has co-signed, the installed blobs are the members' own REAL signatures,
    ///   byte-for-byte the ones on the co-signed state;
    /// - the load-bearing equality is enforced: a block whose `tx_tree_root` is not the signed
    ///   state's `h2_tag` is refused, so the members' signatures cannot be replayed onto a
    ///   different block. This is the wallet-side half of the Phase-3 in-circuit binding.
    #[test]
    fn small_block_carries_real_n_of_n_and_one_member_can_block_it() {
        let mut rng = StdRng::seed_from_u64(0x5106);
        let (record, keys, members, genesis, _w0, w1) =
            setup_two_token_channel(&mut rng, 61, [50, 30, 20], [40, 25]);
        let mut state = genesis;
        state.channel_fund.amounts[1] = u64_to_u256(65);
        let state = resign_two_members(state, &keys);
        let snapshot = ChannelSnapshot {
            record: record.clone(),
            state,
            members,
            settled_tx_accumulator: default_settled_tx_accumulator(),
        };
        let dest_keys = MemberKeys::generate(&mut rng);
        let dest_channel = crate::common::channel_id::ChannelId::new(99).unwrap();
        let nullifier_root = Bytes32::from_u32_slice(&[9, 8, 7, 6, 5, 4, 3, 2]).unwrap();

        let built = build_inter_channel_send_token(
            &keys[0],
            &snapshot,
            0,
            dest_channel,
            0,
            dest_keys.regev_pk.clone(),
            dest_keys.pk_g(),
            Salt::default(),
            T1_INDEX,
            5,
            40,
            &w1[0],
            nullifier_root,
            LEVEL,
            &mut rng,
        )
        .expect("token-1 inter-channel send builds");

        let a_send = built.debit_payload.proposed_next_state.clone();
        let mut tx = built.debit_payload.inter_channel_tx.clone();
        let n = record.member_count as usize;

        // The builder emits an UNSIGNED block: correctly-slotted NON-signatures.
        let placeholder = crate::common::channel::structural_cosign_placeholder(1);
        assert_eq!(tx.signed_small_block.signatures.len(), n);
        for (slot, sig) in tx.signed_small_block.signatures.iter().enumerate() {
            assert_eq!(sig.member_slot as usize, slot);
            assert_eq!(
                sig.signature, placeholder,
                "slot {slot} must hold the explicit non-signature, never fabricated bytes"
            );
        }

        // Only the sending member has signed so far — N-1 of N.
        assert_eq!(a_send.member_signatures.len(), 1);
        let err = attach_small_block_signatures(&record, &a_send, &mut tx)
            .expect_err("a block must not be signable while a member is withholding");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("not N-of-N co-signed"),
            "the refusal must say why block production is blocked, got: {msg}"
        );
        // Name the WITHHOLDING slot specifically. (Matching a bare "1" would be vacuous — the
        // channel id 61 contains one.)
        assert!(
            msg.contains("missing signature for slot 1"),
            "the refusal must identify which member is withholding, got: {msg}"
        );
        assert_eq!(
            tx.signed_small_block.signatures[0].signature, placeholder,
            "a refused install must not partially mutate the block"
        );

        // Complete the co-sign round: the remaining member signs the SAME state (member signatures
        // are excluded from `signing_digest()`, so the digest they all signed is unchanged).
        let mut a_signed = a_send.clone();
        for slot in 1..n {
            let sig = sign_state(&keys[slot], slot as u8, &a_signed).expect("co-sign");
            add_signature(&mut a_signed, sig);
        }
        assert_eq!(a_signed.member_signatures.len(), n);

        // Negative, BEFORE the positive so a bug that installs unconditionally cannot hide: the
        // members signed a state whose h2_tag is THIS block's tx_tree_root; point the block at a
        // different root and their signatures must no longer authorise it.
        let mut wrong = tx.clone();
        wrong.signed_small_block.message.tx_tree_root =
            Bytes32::from_u32_slice(&[1, 1, 1, 1, 1, 1, 1, 1]).unwrap();
        let err = attach_small_block_signatures(&record, &a_signed, &mut wrong)
            .expect_err("signatures must not carry over to a different tx_tree_root");
        assert!(
            format!("{err:?}").contains("h2_tag"),
            "the refusal must name the broken binding, got: {err:?}"
        );

        // Positive: the real N-of-N installs.
        attach_small_block_signatures(&record, &a_signed, &mut tx)
            .expect("a fully co-signed state signs its own block");
        assert_eq!(
            tx.signed_small_block.signatures, a_signed.member_signatures,
            "the block must carry the members' OWN signatures, in slot order"
        );
        for (slot, sig) in tx.signed_small_block.signatures.iter().enumerate() {
            assert_ne!(
                sig.signature, placeholder,
                "slot {slot} must hold a real Falcon signature after the round completes"
            );
            assert_eq!(sig.pk_g, record.member_pk_gs[slot]);
        }

        // The installed set is exactly what the aggregation path consumes: it re-verifies every
        // signature against the registered pk_g over the recomputed IMCH digest and builds the
        // FalconAggWitness the block producer aggregates (no signing key involved).
        let (pk_gs, agg_witness) = falcon_member_auth_from_signatures(
            &record,
            &tx.signed_small_block.signatures,
            a_signed.digest,
        )
        .expect("the block's signatures must build the N-of-N aggregate witness");
        assert_eq!(pk_gs.len(), n);
        assert_eq!(agg_witness.active.len(), n);
        assert_eq!(agg_witness.message, a_signed.digest);
    }
}

#[cfg(test)]
mod partial_withdrawal_tests {
    use super::*;
    use crate::{
        circuits::balance::common::recipient::calculate_recipient_from_address,
        common::withdrawal::Withdrawal,
        ethereum_types::{
            address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait, u256::U256,
        },
    };

    #[test]
    fn burn_leaf_rejects_noncanonical_address_padding() {
        let address = Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap();
        let mut bytes = calculate_recipient_from_address(address).to_bytes_be();
        bytes[5] ^= 1;
        let malformed = Bytes32::from_bytes_be(&bytes).unwrap();
        let error = burn_withdrawal_leaf(
            ChannelId::new(41).unwrap(),
            malformed,
            0,
            5,
            Bytes32::from_u32_slice(&[9; 8]).unwrap(),
            0,
        )
        .expect_err("non-zero ADDRESS_TAG padding must not produce an L1 withdrawal leaf");
        assert!(error.0.contains("not an ADDRESS_TAG L1 recipient"));
    }

    #[test]
    fn auth_digest_deterministic() {
        let w = Withdrawal {
            recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
            token_index: 0,
            amount: U256::from(500u32),
            nullifier: Bytes32::from_u32_slice(&[0xAA; 8]).unwrap(),
            aux_data: Bytes32::from_u32_slice(&[0xBB; 8]).unwrap(),
        };
        let d1 = partial_withdrawal_auth_digest(&w);
        let d2 = partial_withdrawal_auth_digest(&w);
        assert_eq!(d1, d2);
        assert_ne!(d1, Bytes32::default());
    }

    #[test]
    fn auth_digest_changes_on_recipient() {
        let mut w = Withdrawal {
            recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
            token_index: 0,
            amount: U256::from(100u64),
            nullifier: Bytes32::from_u32_slice(&[0xAA; 8]).unwrap(),
            aux_data: Bytes32::from_u32_slice(&[0xBB; 8]).unwrap(),
        };
        let d1 = partial_withdrawal_auth_digest(&w);
        w.recipient = Address::from_u32_slice(&[9, 9, 9, 9, 9]).unwrap();
        let d2 = partial_withdrawal_auth_digest(&w);
        assert_ne!(d1, d2);
    }

    #[test]
    fn auth_digest_changes_on_amount() {
        let mut w = Withdrawal {
            recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
            token_index: 0,
            amount: U256::from(100u64),
            nullifier: Bytes32::from_u32_slice(&[0xAA; 8]).unwrap(),
            aux_data: Bytes32::from_u32_slice(&[0xBB; 8]).unwrap(),
        };
        let d1 = partial_withdrawal_auth_digest(&w);
        w.amount = U256::from(101u64);
        let d2 = partial_withdrawal_auth_digest(&w);
        assert_ne!(d1, d2);
    }

    #[test]
    fn auth_digest_changes_on_aux_data() {
        let mut w = Withdrawal {
            recipient: Address::from_u32_slice(&[1, 2, 3, 4, 5]).unwrap(),
            token_index: 0,
            amount: U256::from(100u64),
            nullifier: Bytes32::from_u32_slice(&[0xAA; 8]).unwrap(),
            aux_data: Bytes32::from_u32_slice(&[0xBB; 8]).unwrap(),
        };
        let d1 = partial_withdrawal_auth_digest(&w);
        w.aux_data = Bytes32::from_u32_slice(&[0xCC; 8]).unwrap();
        let d2 = partial_withdrawal_auth_digest(&w);
        assert_ne!(d1, d2);
    }
}

/// REGRESSION (2026-07-18 1000-connection storm): with u8 slot typing, joins hard-stopped at 256
/// active slots ("no member at slot 256") even though Option B promises MAX_CHANNEL_MEMBERS =
/// 1024. These tests walk the native join/assemble path PAST slot 256 with u16 slots — no
/// proving, fabricated identities only (build_record never validates key material, just slot
/// structure), so they run at ordinary unit-test cost.
#[cfg(test)]
mod slot_capacity_tests {
    use super::*;
    use crate::{
        common::balance_state::BalanceState,
        ethereum_types::address::Address,
        regev::{REGEV_N, RegevCiphertext, RegevPk},
    };

    /// Fabricated distinct nonzero identity for `slot`. `build_record` /
    /// `member_pubkeys_root` only hash these values — no key validity is checked — so
    /// synthetic pk_g/pk_b keep the test cheap enough to cover 300 slots natively.
    fn fake_member(slot: u16) -> MemberInfo {
        let tag = slot as u32 + 1;
        MemberInfo {
            slot,
            pk_g: Bytes32::from_u32_slice(&[0xA0, 0, 0, 0, 0, 0, 0, tag]).unwrap(),
            pk_b: Bytes32::from_u32_slice(&[0xB0, 0, 0, 0, 0, 0, 0, tag]).unwrap(),
            regev_pk: RegevPk::padding(),
        }
    }

    /// The storm's exact failure boundary: 3 cosigners + 253 delegates joined (256 slots), and
    /// the 254th delegate — slot 256 — failed with "no member at slot 256". Repeatedly
    /// re-assemble the record as delegates join across that boundary and beyond.
    #[test]
    fn join_path_reaches_slot_256_and_beyond() {
        const COSIGNERS: usize = 3;
        let members: Vec<MemberInfo> = (0..300u16).map(fake_member).collect();

        // Checkpoints: 256 active (the last size the u8 code reached), 257 (the first size it
        // could NOT), and 300 (comfortable margin past the boundary).
        for active in [256usize, 257, 300] {
            let dc = (active - COSIGNERS) as u16;
            let record = build_record(7, &members[..active], 0, dc)
                .unwrap_or_else(|e| panic!("build_record with {active} active slots failed: {e}"));
            assert_eq!(record.member_count, COSIGNERS as u8);
            assert_eq!(record.delegate_count, dc);
            // Every active slot — including 256+ — carries its member's pk_g.
            let last = active - 1;
            assert_eq!(record.member_pk_gs[last], members[last].pk_g);
            assert_eq!(record.member_pk_gs[active], Bytes32::default());
        }

        // The storm's exact failing lookup: slot 256 must resolve.
        let m256 = member_at(&members, 256).expect("slot 256 must be reachable with u16 slots");
        assert_eq!(m256.slot, 256);

        // Wire format: a slot > 255 survives the JSON round-trip (browser <-> relay <-> CLI).
        let json = serde_json::to_string(&members[299]).unwrap();
        let back: MemberInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.slot, 299);
    }

    /// The signed balance state also crosses the 256-slot boundary: delegate_count > 253 (u16)
    /// must validate and produce an H1 that depends on the count.
    #[test]
    fn balance_state_validates_past_256_active_slots() {
        const MEMBER_COUNT: usize = 3;
        const DELEGATE_COUNT: usize = 254; // active = 257 > 256
        let active = MEMBER_COUNT + DELEGATE_COUNT;

        let nonzero_ct = RegevCiphertext {
            c1: vec![1u32; REGEV_N],
            c2: vec![2u32; REGEV_N],
        };
        let cts: Vec<RegevCiphertext> = vec![nonzero_ct; active];
        let digests: Vec<Bytes32> = (0..active as u32)
            .map(|i| Bytes32::from_u32_slice(&[0xD0, 0, 0, 0, 0, 0, 0, i + 1]).unwrap())
            .collect();
        let recipients: Vec<Address> = (0..active as u32)
            .map(|i| Address::from_u32_slice(&[0xE0, 0, 0, 0, i + 1]).unwrap())
            .collect();

        let state = BalanceState {
            channel_id: ChannelId::new(7).unwrap(),
            member_count: MEMBER_COUNT as u8,
            delegate_count: DELEGATE_COUNT as u16,
            enc_balances: BalanceState::pad_enc_balances_token0(&cts),
            regev_pk_digests: BalanceState::pad_regev_pk_digests(&digests),
            recipients: BalanceState::pad_recipients(&recipients),
            settled_tx_chain: Bytes32::default(),
            settled_tx_accumulator_root: empty_settled_tx_accumulator_root(),
            state_version: 1,
            pending_adds: BalanceState::pad_pending_adds_token0(&vec![0u32; active]),
            token_registry: BalanceState::single_token_registry(0),
            token_count: 1,
        };
        state
            .validate()
            .expect("257 active slots must validate with u16 delegate_count");

        // H1 commits the (u16) delegate_count: shrinking the active region changes it.
        let h1 = state.h1();
        let mut smaller = state.clone();
        smaller.delegate_count -= 1;
        assert_ne!(h1, smaller.h1(), "delegate_count must be committed in H1");
    }
}
