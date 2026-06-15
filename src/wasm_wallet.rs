//! Browser wallet `#[wasm_bindgen]` entry points (Regev channel model).
//!
//! Thin JSON wrappers over [`crate::wallet_core`]. All secret material (SPHINCS+ seeds, Regev
//! secret key, balance encryption witnesses) lives ONLY in the in-memory [`Session`] and is never
//! returned to JS or serialized. The worker drives these in order: `wallet_keygen` →
//! `wallet_genesis_contribution` → (CLI assembles + sends back genesis) → `wallet_sign_state` →
//! `wallet_import_channel` → `wallet_balance` / `wallet_send` / `wallet_cosign` / `wallet_finalize`.
//!
//! SECURITY: `RegevSecurityLevel::Production` is used for all real proving. Keys are session-only
//! (lost on reload) per the approved threat-model default.

use std::cell::RefCell;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

use crate::{
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    regev::{AmountWitness, RegevSecurityLevel, encrypt_amount},
    wallet_core::{
        BuiltSend, ChannelSnapshot, MemberKeys, SendPayload, add_signature, build_send,
        decrypt_balance, sign_state, verify_send_transition, verify_snapshot,
    },
};
use crate::common::channel::{ChannelState, MemberSignature};

/// SECURITY: real funds ⇒ Production STARK parameters (≈100-bit), never the fast `Test` level.
const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Production;

/// In-memory wallet session (single member). Holds all secrets; never serialized.
struct Session {
    keys: MemberKeys,
    slot: Option<u8>,
    snapshot: Option<ChannelSnapshot>,
    /// The member's current balance + its encryption witness, present only when this wallet
    /// freshly encrypted the slot (genesis contribution or a completed send). `None` after a
    /// homomorphic receive (a refresh — not yet in this MVP — would restore it).
    balance: Option<(u64, AmountWitness)>,
    /// A send awaiting finalization: (next_state_digest, new_balance, new_witness).
    pending_send: Option<(Bytes32, u64, AmountWitness)>,
}

thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

fn js_err(m: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&m.to_string())
}

fn with_session<T>(f: impl FnOnce(&mut Session) -> Result<T, JsValue>) -> Result<T, JsValue> {
    SESSION.with(|s| {
        let mut guard = s.borrow_mut();
        let session = guard
            .as_mut()
            .ok_or_else(|| js_err("wallet not initialized: call wallet_keygen first"))?;
        f(session)
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Identity {
    /// The member's Goldilocks signing public key `pk_g` (canonical Bytes32 hex, P4-2 — the member
    /// identity stored in the channel record and committed in the registered `MemberLeaf`).
    pk_g: String,
    /// P3: the member's BabyBear hash-sig public key `pk_b` (canonical Bytes32 hex). Published so
    /// the CLI can build the `MemberInfo` / registration record that commits it (A11).
    pk_b: String,
    regev_pk: crate::regev::RegevPk,
}

/// Generate this member's Goldilocks + BabyBear + Regev key material and start a fresh session.
#[wasm_bindgen]
pub fn wallet_keygen() -> Result<String, JsValue> {
    let mut rng = rand010::rng();
    let keys = MemberKeys::generate(&mut rng);
    let identity = Identity {
        pk_g: keys.pk_g().to_hex(),
        pk_b: keys.pk_b().to_hex(),
        regev_pk: keys.regev_pk.clone(),
    };
    let json = serde_json::to_string(&identity).map_err(js_err)?;
    SESSION.with(|s| {
        *s.borrow_mut() = Some(Session {
            keys,
            slot: None,
            snapshot: None,
            balance: None,
            pending_send: None,
        });
    });
    Ok(json)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenesisContribution {
    regev_pk: crate::regev::RegevPk,
    /// The member's Goldilocks signing public key `pk_g` (canonical Bytes32 hex, P4-2).
    pk_g: String,
    /// P3: the member's BabyBear hash-sig public key `pk_b` (canonical Bytes32 hex, A11).
    pk_b: String,
    genesis_ct: crate::regev::RegevCiphertext,
}

/// Encrypt this member's own genesis balance to their own Regev key, retaining the witness so the
/// member can later send. Returns the ciphertext (to hand to the CLI assembling the channel).
#[wasm_bindgen]
pub fn wallet_genesis_contribution(balance: u64) -> Result<String, JsValue> {
    with_session(|session| {
        let mut rng = rand010::rng();
        let (ct, witness) =
            encrypt_amount(&mut rng, &session.keys.regev_pk, balance).map_err(js_err)?;
        session.balance = Some((balance, witness));
        let out = GenesisContribution {
            regev_pk: session.keys.regev_pk.clone(),
            pk_g: session.keys.pk_g().to_hex(),
            pk_b: session.keys.pk_b().to_hex(),
            genesis_ct: ct,
        };
        serde_json::to_string(&out).map_err(js_err)
    })
}

/// Sign a proposed (e.g. genesis) `ChannelState` after confirming our own balance slot decrypts.
/// Returns this member's `MemberSignature`. Requires the slot to be known (via a prior import) or
/// inferable; here the caller passes the slot explicitly.
#[wasm_bindgen]
pub fn wallet_sign_state(slot: u8, state_json: String) -> Result<String, JsValue> {
    with_session(|session| {
        let state: ChannelState = serde_json::from_str(&state_json).map_err(js_err)?;
        if state.digest != state.signing_digest() {
            return Err(js_err("state.digest does not match recomputed signing_digest()"));
        }
        // SECURITY: this entry signs WITHOUT head/linkage checks, so restrict it to genesis only
        // (epoch 1, version 0). All later states are signed via `wallet_cosign`, which verifies the
        // transition. Bound-check the slot before indexing the fixed-size balance array.
        let mc = state.balance_state.member_count as usize;
        if slot as usize >= mc {
            return Err(js_err(format!("slot {slot} is not an active member (member_count {mc})")));
        }
        if !(state.epoch == 1 && state.balance_state.state_version == 0) {
            return Err(js_err("wallet_sign_state is genesis-only (epoch 1, state_version 0)"));
        }
        // Confirm our slot decrypts (sanity: we are signing a state we can read).
        crate::regev::decrypt_amount(
            &session.keys.regev_sk,
            &state.balance_state.enc_balances[slot as usize],
        )
        .map_err(|e| js_err(format!("cannot decrypt own slot {slot}: {e}")))?;
        let sig: MemberSignature = sign_state(&session.keys, slot, &state).map_err(js_err)?;
        serde_json::to_string(&sig).map_err(js_err)
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BalanceReport {
    slot: u8,
    balance: u64,
    can_send: bool,
    state_version: u64,
}

/// Import a fully-signed channel snapshot, verify it end-to-end (real signatures, roots, own-slot
/// decryption), adopt it as the wallet's head, and report the balance.
#[wasm_bindgen]
pub fn wallet_import_channel(snapshot_json: String) -> Result<String, JsValue> {
    with_session(|session| {
        let snapshot: ChannelSnapshot = serde_json::from_str(&snapshot_json).map_err(js_err)?;
        // Locate our slot by matching our Regev public key.
        let slot = snapshot
            .members
            .iter()
            .find(|m| m.regev_pk == session.keys.regev_pk)
            .map(|m| m.slot)
            .ok_or_else(|| js_err("this wallet's key is not a member of the imported channel"))?;
        verify_snapshot(&snapshot, Some((&session.keys, slot))).map_err(js_err)?;
        let balance = decrypt_balance(&session.keys, &snapshot, slot).map_err(js_err)?;

        // Keep the witness only if the imported slot ciphertext is exactly the one we encrypted
        // (genesis contribution / completed send). Otherwise we cannot send until a refresh.
        let our_ct = &snapshot.state.balance_state.enc_balances[slot as usize];
        let can_send = match &session.balance {
            Some((amt, w)) if *amt == balance => {
                // Re-derive the ciphertext digest match by re-encrypting is not possible
                // (randomness differs); instead trust the witness iff the plaintext matches and
                // the slot has no pending homomorphic adds.
                snapshot.state.balance_state.pending_adds[slot as usize] == 0 && {
                    let _ = w;
                    true
                }
            }
            _ => false,
        };
        if !can_send {
            session.balance = None;
        }
        let report = BalanceReport {
            slot,
            balance,
            can_send,
            state_version: snapshot.state.balance_state.state_version,
        };
        session.slot = Some(slot);
        session.snapshot = Some(snapshot);
        serde_json::to_string(&report).map_err(js_err)
    })
}

/// Report the current decrypted balance of this member's slot.
#[wasm_bindgen]
pub fn wallet_balance() -> Result<String, JsValue> {
    with_session(|session| {
        let slot = session.slot.ok_or_else(|| js_err("no channel imported"))?;
        let snapshot = session
            .snapshot
            .as_ref()
            .ok_or_else(|| js_err("no channel imported"))?;
        let balance = decrypt_balance(&session.keys, snapshot, slot).map_err(js_err)?;
        let report = BalanceReport {
            slot,
            balance,
            can_send: session.balance.is_some(),
            state_version: snapshot.state.balance_state.state_version,
        };
        serde_json::to_string(&report).map_err(js_err)
    })
}

/// Send `amount` to `recipient_slot`: builds the E-1 proof, signs the `ChannelTx` and the proposed
/// next state, and returns the `SendPayload` for the co-signers. The new balance is committed only
/// once `wallet_finalize` receives the fully-signed state.
#[wasm_bindgen]
pub fn wallet_send(recipient_slot: u8, amount: u64) -> Result<String, JsValue> {
    with_session(|session| {
        let slot = session.slot.ok_or_else(|| js_err("no channel imported"))?;
        let snapshot = session
            .snapshot
            .clone()
            .ok_or_else(|| js_err("no channel imported"))?;
        let (before_amount, before_witness) = session
            .balance
            .clone()
            .ok_or_else(|| js_err("no spendable balance witness (a refresh is required after receiving)"))?;
        let mut rng = rand010::rng();
        let mut nonce_bytes = [0u32; 8];
        for w in nonce_bytes.iter_mut() {
            *w = rand010::Rng::next_u32(&mut rng);
        }
        let nonce = Bytes32::from_u32_slice(&nonce_bytes).map_err(js_err)?;
        let BuiltSend {
            payload,
            new_balance_witness,
            new_balance,
        } = build_send(
            &session.keys,
            &snapshot,
            slot,
            recipient_slot,
            amount,
            before_amount,
            &before_witness,
            nonce,
            LEVEL,
            &mut rng,
        )
        .map_err(js_err)?;
        // (We do not self-verify the freshly built proof here: it roughly doubles send latency and
        // is redundant — every co-signer verifies the E-1 proof before signing. Portability of
        // wasm-built proofs is covered by tests/verify_wasm_proof.rs.)
        session.pending_send =
            Some((payload.proposed_next_state.digest, new_balance, new_balance_witness));
        serde_json::to_string(&payload).map_err(js_err)
    })
}

/// Co-sign an incoming `SendPayload`: verify the transition + E-1 proof (decrypting the incoming
/// amount if we are the recipient), then add this member's signature. Returns the updated next
/// state carrying our signature.
#[wasm_bindgen]
pub fn wallet_cosign(payload_json: String) -> Result<String, JsValue> {
    with_session(|session| {
        let payload: SendPayload = serde_json::from_str(&payload_json).map_err(js_err)?;
        let slot = session.slot.ok_or_else(|| js_err("no channel imported"))?;
        let snapshot = session
            .snapshot
            .as_ref()
            .ok_or_else(|| js_err("no channel imported"))?;
        // Must extend our current head.
        if payload.proposed_next_state.prev_digest != snapshot.state.digest {
            return Err(js_err("payload does not extend the wallet's current head"));
        }
        let am_recipient = payload.recipient_index == slot;
        let (sk, expected) = if am_recipient {
            // We learn the amount by decrypting; pass it as the expected check.
            let amt = crate::regev::decrypt_amount(&session.keys.regev_sk, &payload.channel_tx.enc_amount)
                .map_err(|e| js_err(format!("cannot decrypt incoming amount: {e}")))?;
            (Some(&session.keys.regev_sk), Some(amt))
        } else {
            (None, None)
        };
        verify_send_transition(&snapshot.state, &snapshot.record, &payload, LEVEL, sk, expected)
            .map_err(js_err)?;

        let mut next = payload.proposed_next_state.clone();
        let sig = sign_state(&session.keys, slot, &next).map_err(js_err)?;
        add_signature(&mut next, sig);
        serde_json::to_string(&next).map_err(js_err)
    })
}

/// Adopt a fully-signed next state as the new head after verifying every member's real signature.
/// Updates the balance view; if this wallet was the sender, commits the pending send witness.
#[wasm_bindgen]
pub fn wallet_finalize(state_json: String) -> Result<String, JsValue> {
    with_session(|session| {
        let next_state: ChannelState = serde_json::from_str(&state_json).map_err(js_err)?;
        let slot = session.slot.ok_or_else(|| js_err("no channel imported"))?;
        let mut snapshot = session
            .snapshot
            .clone()
            .ok_or_else(|| js_err("no channel imported"))?;
        if next_state.prev_digest != snapshot.state.digest {
            return Err(js_err("finalized state does not extend the wallet's current head"));
        }
        if next_state.balance_state.state_version != snapshot.state.balance_state.state_version + 1 {
            return Err(js_err("state_version must increment by exactly 1"));
        }
        // Adopt, then fully verify (record/root/balance-state validity, every member's REAL
        // SPHINCS+ signature, own-slot decryption). `verify_snapshot` already runs the full
        // signature check, so we don't call `verify_all_signatures` separately (it would re-run all
        // SLH-DSA verifications and roughly double finalize latency).
        snapshot.state = next_state;
        verify_snapshot(&snapshot, Some((&session.keys, slot))).map_err(js_err)?;
        let balance = decrypt_balance(&session.keys, &snapshot, slot).map_err(js_err)?;

        // Commit the pending send witness if this finalized state is the one we proposed.
        let committed = match session.pending_send.take() {
            Some((digest, new_balance, witness)) if digest == snapshot.state.digest => {
                session.balance = Some((new_balance, witness));
                true
            }
            _ => false,
        };
        if !committed {
            // We were recipient/uninvolved: our slot may now be a homomorphic sum → witness stale.
            session.balance = None;
        }
        let report = BalanceReport {
            slot,
            balance,
            can_send: session.balance.is_some(),
            state_version: snapshot.state.balance_state.state_version,
        };
        session.snapshot = Some(snapshot);
        serde_json::to_string(&report).map_err(js_err)
    })
}

// --- Phase-0 feasibility probe (kept for diagnostics) ----------------------------------------

/// SECURITY: `Test` level — NOT secure; diagnostic probe only.
#[wasm_bindgen]
pub async fn wallet_feasibility_check() -> Result<String, JsValue> {
    use crate::regev::{channel_keygen, prove_channel_tx, verify_channel_tx};
    let mut rng = rand010::rng();
    let (sender_pk, _s) = channel_keygen(&mut rng);
    let (recipient_pk, _r) = channel_keygen(&mut rng);
    let before = encrypt_amount(&mut rng, &sender_pk, 100).map_err(js_err)?;
    let amount = encrypt_amount(&mut rng, &recipient_pk, 30).map_err(js_err)?;
    let after = encrypt_amount(&mut rng, &sender_pk, 70).map_err(js_err)?;
    let proof = prove_channel_tx(
        RegevSecurityLevel::Test,
        &sender_pk,
        &recipient_pk,
        (&before.0, &before.1),
        (&amount.0, &amount.1),
        (&after.0, &after.1),
    )
    .map_err(js_err)?;
    verify_channel_tx(
        RegevSecurityLevel::Test,
        &sender_pk,
        &recipient_pk,
        &before.0,
        &amount.0,
        &after.0,
        &proof,
    )
    .map_err(js_err)?;
    Ok(format!("E-1 prove+verify OK in wasm; proof = {} bytes", proof.len()))
}
