//! Browser/Node wallet `#[wasm_bindgen]` entry points (Regev channel model).
//!
//! Thin JSON wrappers over [`crate::wallet_core`]. All secret material (SPHINCS+ seeds, Regev
//! secret key, balance encryption witnesses) lives ONLY in the in-memory [`Session`] and is never
//! returned to JS or serialized. The worker drives these in order: `wallet_keygen` →
//! `wallet_genesis_contribution` → (CLI assembles + sends back genesis) → `wallet_sign_state` →
//! `wallet_import_view` (delegates: own slot view only; co-signers may `wallet_import_channel`) →
//! `wallet_balance` / `wallet_send` / `wallet_cosign` (co-signers) / `wallet_finalize`.
//!
//! SECURITY: `RegevSecurityLevel::Production` is used for all real proving. Keys are session-only
//! (lost on reload) per the approved threat-model default.

use std::{cell::RefCell, collections::BTreeMap};

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

use crate::{
    channel_credit_safety::{ChannelCreditBounds, OwnedPlaintexts},
    circuits::channel::withdrawal_claim_pis::{
        WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN, WithdrawalClaimPublicInputs,
    },
    common::{
        channel::{ChannelState, CloseIntent, CloseWithdrawal, MemberSignature, close_state_id},
        channel_id::ChannelId,
    },
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    regev::{AmountWitness, RegevCiphertext, RegevSecurityLevel, decrypt_amount, encrypt_amount},
    slot_view::{
        SlimInterChannelDebitPayload, SlotView, build_view_burn_send,
        build_view_inter_channel_send, build_view_refresh, build_view_send,
    },
    utils::conversion::ToU64 as _,
    wallet_core::{
        ChannelSnapshot, InterChannelTransferDescriptor, MemberInfo, MemberKeys, SendPayload,
        SlimSendPayload, WithdrawalClaimProver, add_signature, sign_state,
        verify_exit_kit_preserving_successor, verify_send_transition, verify_snapshot,
    },
};

/// SECURITY: real funds ⇒ Production STARK parameters (≈100-bit), never the fast `Test` level.
const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Production;

/// In-memory wallet session (single member). Holds all secrets; never serialized.
struct Session {
    keys: MemberKeys,
    /// BALANCE-SLOT index (member OR delegate) of this wallet in the imported channel.
    slot: Option<u32>,
    /// This wallet's view of the channel head: the signed header, its own slot row and the row's
    /// Merkle path. A DELEGATE never holds more than this (it never sees another participant's
    /// row); every send/refresh/burn/claim is built from it.
    view: Option<SlotView>,
    /// CO-SIGNER sessions only (slot < member_count): the full verified head, needed to verify
    /// and co-sign other participants' transitions. Always `None` for a delegate.
    cosigner_snapshot: Option<ChannelSnapshot>,
    /// The channel id and co-signer identities seen at the first import. The sig-cluster cannot
    /// change after deployment, so every later view must name the same set.
    pinned: Option<(ChannelId, Vec<Bytes32>)>,
    /// The member's current balance + its encryption witness AT ONE token position:
    /// `(token_slot, amount, witness)`. `None` after a homomorphic receive.
    balance: Option<(u8, u64, AmountWitness)>,
    /// A send/refresh/burn awaiting the co-signed head that installs it.
    pending: Option<PendingDebit>,
    /// SECURITY (B-1b, obligation 1): the L1 exit address this wallet SUBMITTED in its genesis
    /// contribution; every import asserts the slot's signed recipient equals it.
    expected_recipient: Option<crate::ethereum_types::address::Address>,
    /// Signer-side credit-safety bounds (co-signer sessions only).
    credit_safety_bounds: BTreeMap<String, ChannelCreditBounds>,
}

/// A debit this wallet built and is waiting to see installed: once a verified head carries
/// `expected_ct` at `token_slot` of this wallet's row, `witness` opens it with `new_balance`.
struct PendingDebit {
    token_slot: u8,
    expected_ct: RegevCiphertext,
    new_balance: u64,
    witness: AmountWitness,
}

fn owned_credit_plaintexts(
    session: &Session,
    state: &ChannelState,
    slot: u32,
) -> Result<OwnedPlaintexts, JsValue> {
    state.balance_state.validate().map_err(js_err)?;
    let active =
        state.balance_state.member_count as usize + state.balance_state.delegate_count as usize;
    if slot as usize >= active {
        return Err(js_err("credit-safety: own slot is not active"));
    }
    let mut known = OwnedPlaintexts::new();
    for row in 0..active {
        for token in 0..state.balance_state.token_count as usize {
            let ciphertext = &state.balance_state.enc_balances[row][token];
            if ciphertext == crate::common::balance_state::zero_ciphertext() {
                known.insert((row, token), 0);
            } else if row == slot as usize {
                let amount = crate::regev::decrypt_amount(&session.keys.regev_sk, ciphertext)
                    .map_err(js_err)?;
                known.insert((row, token), amount);
            }
        }
    }
    Ok(known)
}

fn credit_bounds_for(
    session: &Session,
    state: &ChannelState,
    slot: u32,
) -> Result<ChannelCreditBounds, JsValue> {
    if let Some(bounds) = session.credit_safety_bounds.get(&state.digest.to_hex()) {
        bounds.validate_for(state).map_err(js_err)?;
        return Ok(bounds.clone());
    }
    ChannelCreditBounds::bootstrap(state, &owned_credit_plaintexts(session, state, slot)?)
        .map_err(js_err)
}

fn remember_credit_head(
    session: &mut Session,
    state: &ChannelState,
    slot: u32,
) -> Result<(), JsValue> {
    let bounds = credit_bounds_for(session, state, slot)?;
    session.credit_safety_bounds.clear();
    session
        .credit_safety_bounds
        .insert(state.digest.to_hex(), bounds);
    Ok(())
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
    keygen_with_rng(&mut rng)
}

/// Like [`wallet_keygen`], but derives ALL key material DETERMINISTICALLY from a caller-supplied
/// 32-byte master seed (hex). Same seed ⇒ same `(pk_g, pk_b, regev_pk)` ⇒ same channel slot on
/// re-import, so the browser can restore the SAME account/slot across reloads.
///
/// SECURITY: this relaxes the module's "secrets are session-only, never persisted" default. The
/// caller is responsible for the recovery seed: anyone who reads it controls the account, while
/// losing it makes the signed slot unspendable. Browser `localStorage` persistence is testnet-only;
/// a production Node daemon must inject the seed from an operator-controlled secret store. The
/// derived secret keys remain inside this WASM session and are never serialized.
#[wasm_bindgen]
pub fn wallet_keygen_seeded(seed_hex: String) -> Result<String, JsValue> {
    use rand010::SeedableRng;
    let seed = parse_seed32(&seed_hex)?;
    let mut rng = rand010::rngs::StdRng::from_seed(seed);
    keygen_with_rng(&mut rng)
}

fn keygen_with_rng(rng: &mut impl rand010::Rng) -> Result<String, JsValue> {
    let keys = MemberKeys::generate(rng);
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
            view: None,
            cosigner_snapshot: None,
            pinned: None,
            balance: None,
            pending: None,
            expected_recipient: None,
            credit_safety_bounds: BTreeMap::new(),
        });
    });
    Ok(json)
}

/// Parse a `0x`-optional 64-hex-char string into a 32-byte seed.
fn parse_seed32(seed_hex: &str) -> Result<[u8; 32], JsValue> {
    let h = seed_hex.strip_prefix("0x").unwrap_or(seed_hex);
    if h.len() != 64 {
        return Err(js_err("seed must be exactly 32 bytes (64 hex chars)"));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16)
            .map_err(|e| js_err(format!("invalid seed hex: {e}")))?;
    }
    Ok(out)
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
    /// B-1b: this member's L1 exit address (canonical 0x-hex). Leaf-bound into the
    /// cosigner-signed H1 balance slot — a delegate's ONLY payout binding under Option B.
    recipient: String,
}

/// Encrypt this member's own genesis balance to their own Regev key, retaining the witness so the
/// member can later send. Returns the ciphertext (to hand to the CLI assembling the channel).
///
/// B-1b API CHANGE (minimal, documented): `recipient` is the member's L1 exit address (hex,
/// 0x-prefixed 20 bytes — the browser passes the user's MetaMask address). It is REQUIRED and
/// must be NONZERO: this address is folded into the cosigner-signed H1 balance-slot leaf and is
/// the ONLY thing binding a delegate's L1 payout (no L1 registration for delegates under
/// Option B). Fail-closed: a malformed or zero address is rejected here, before any contribution
/// leaves the wallet.
#[wasm_bindgen]
pub fn wallet_genesis_contribution(balance: u64, recipient: String) -> Result<String, JsValue> {
    with_session(|session| {
        // SECURITY (B-1b fail-closed): parse + reject the zero address BEFORE emitting a
        // contribution the cosigners could sign.
        let recipient_addr =
            crate::ethereum_types::address::Address::from_hex(&recipient).map_err(js_err)?;
        if recipient_addr == crate::ethereum_types::address::Address::default() {
            return Err(js_err(
                "recipient must be a NONZERO L1 address (B-1b: the leaf-bound exit address is \
                 this slot's only payout binding; address(0) could never exit)",
            ));
        }
        // SECURITY (A-1): `genesis_ct` is emitted for WIRE COMPATIBILITY only — the cosigners no
        // longer install it. Both `create_channel` and `join_delegate`
        // (src/bin/channel_member.rs) open a new delegate slot at the CANONICAL ZERO ciphertext,
        // because a self-declared, Regev-encrypted opening balance is unbacked value that no
        // cosigner can inspect. A wallet therefore ALWAYS opens at 0 regardless of the `balance`
        // argument (production already passes 0), and it is funded afterwards through the L1
        // deposit import or an in-channel transfer. `wallet_import_channel` detects the installed
        // canonical zero and adopts the matching public zero witness, so the witness cached here is
        // superseded rather than relied on — see the note there.
        let mut rng = rand010::rng();
        let (ct, witness) =
            encrypt_amount(&mut rng, &session.keys.regev_pk, balance).map_err(js_err)?;
        // Genesis contributions fund the GENESIS token position (0).
        session.balance = Some((0, balance, witness));
        // SECURITY (B-1b, obligation 1): remember the exact address we asked to be paid, so import
        // can prove the cosigner-signed leaf binds THIS address and not a relay-substituted one.
        session.expected_recipient = Some(recipient_addr);
        let out = GenesisContribution {
            regev_pk: session.keys.regev_pk.clone(),
            pk_g: session.keys.pk_g().to_hex(),
            pk_b: session.keys.pk_b().to_hex(),
            genesis_ct: ct,
            recipient: recipient_addr.to_hex(),
        };
        serde_json::to_string(&out).map_err(js_err)
    })
}

/// Sign a proposed (e.g. genesis) `ChannelState` after confirming our own balance slot decrypts.
/// Returns this member's `MemberSignature`. Requires the slot to be known (via a prior import) or
/// inferable; here the caller passes the slot explicitly.
#[wasm_bindgen]
pub fn wallet_sign_state(slot: u32, state_json: String) -> Result<String, JsValue> {
    with_session(|session| {
        let state: ChannelState = serde_json::from_str(&state_json).map_err(js_err)?;
        if state.digest != state.signing_digest() {
            return Err(js_err(
                "state.digest does not match recomputed signing_digest()",
            ));
        }
        // SECURITY: this entry signs WITHOUT head/linkage checks, so restrict it to genesis only
        // (epoch 1, version 0). All later states are signed via `wallet_cosign`, which verifies the
        // transition. Bound-check the slot before indexing the fixed-size balance array.
        let mc = state.balance_state.member_count as usize;
        if slot as usize >= mc {
            return Err(js_err(format!(
                "slot {slot} is not an active member (member_count {mc})"
            )));
        }
        if !(state.epoch == 1 && state.balance_state.state_version == 0) {
            return Err(js_err(
                "wallet_sign_state is genesis-only (epoch 1, state_version 0)",
            ));
        }
        state.balance_state.validate().map_err(js_err)?;
        let active = mc + state.balance_state.delegate_count as usize;
        crate::wallet_core::validate_new_exit_key_digests(
            &state.balance_state.regev_pk_digests[..active],
        )
        .map_err(js_err)?;
        for slot in 0..active {
            for token in 0..state.balance_state.token_count as usize {
                state.balance_state.enc_balances[slot][token]
                    .validate_balance_exit_shape()
                    .map_err(js_err)?;
            }
        }
        let expected_recipient = session.expected_recipient.ok_or_else(|| {
            js_err("set your recoverable L1 recipient in a genesis contribution before signing")
        })?;
        if state.balance_state.recipients[slot as usize] != expected_recipient
            || state.balance_state.regev_pk_digests[slot as usize]
                != Bytes32::from(session.keys.regev_pk.poseidon_digest())
        {
            return Err(js_err(
                "genesis does not bind this wallet's expected recipient and Regev key",
            ));
        }
        // Confirm our slot decrypts at EVERY active token position (sanity: we are signing a
        // state we can read; unused positions are the canonical zero ct — decrypts to 0 under
        // any key, so this cannot false-negative on a token we do not hold).
        for t in 0..state.balance_state.token_count as usize {
            crate::regev::decrypt_amount(
                &session.keys.regev_sk,
                &state.balance_state.enc_balances[slot as usize][t],
            )
            .map_err(|e| js_err(format!("cannot decrypt own slot {slot} token {t}: {e}")))?;
        }
        // Cosigner space: slot < member_count <= MAX_SIG_CLUSTER (checked above), so u8 fits.
        let sig: MemberSignature = sign_state(&session.keys, slot as u8, &state).map_err(js_err)?;
        serde_json::to_string(&sig).map_err(js_err)
    })
}

/// Serialize a `u64` amount as a DECIMAL STRING rather than a JSON number.
///
/// CORRECTNESS: these reports cross the wasm → JavaScript boundary as JSON text, and `JSON.parse`
/// coerces every JSON number to an IEEE-754 double — so any integer above 2^53 (≈9.007e15) is
/// silently rounded at PARSE time, before a single line of wallet code runs. Real wei balances
/// routinely exceed that (0.05 ETH = 5e16 wei), so a numeric wire value cannot carry a real
/// balance exactly and the browser would display a value off by a few wei. A decimal string
/// crosses exactly and the page parses it with `BigInt`.
///
/// INTENTIONALLY SIMPLE: this is a display-only DTO. These fields are never re-signed, re-proved,
/// or fed back into a co-sign payload (send/burn amounts are re-derived from user input), so this
/// is a wire-format fix, not a protocol change.
fn ser_u64_dec_string<S: serde::Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&v.to_string())
}

/// One active token position's decrypted balance (multitoken §N-2).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenBalanceEntry {
    /// LOCAL token slot (position in this channel's registry).
    token_slot: u8,
    /// BASE-layer token index the slot is registered for (`registry[token_slot]`).
    token_index: u32,
    /// Base units, wire-encoded as a decimal string — see [`ser_u64_dec_string`].
    #[serde(serialize_with = "ser_u64_dec_string")]
    balance: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BalanceReport {
    slot: u32,
    /// GENESIS-token (local slot 0) balance — the wire-compat scalar kept for existing callers;
    /// the per-token view is `balances`. Base units, wire-encoded as a decimal string — see
    /// [`ser_u64_dec_string`].
    #[serde(serialize_with = "ser_u64_dec_string")]
    balance: u64,
    /// Always `true` since the decrypted send: every position this wallet's key decrypts is
    /// spendable directly, with or without pending homomorphic credits (kept for wire compat).
    can_send: bool,
    state_version: u64,
    /// Per-token balances over ALL active registry positions (multitoken Phase 4).
    balances: Vec<TokenBalanceEntry>,
    /// The token position a held encryption witness backs, if any (informational — the
    /// decrypted send does not need one; kept for wire compat with older pages).
    witness_token_slot: Option<u8>,
}

/// Build the standard per-token balance report for `slot` from a verified snapshot.
fn balance_report(session: &Session, view: &SlotView) -> Result<BalanceReport, JsValue> {
    let header = &view.state.balance_state;
    let mut balances = Vec::with_capacity(header.token_count as usize);
    for t in 0..header.token_count {
        balances.push(TokenBalanceEntry {
            token_slot: t,
            token_index: header.token_registry[t as usize],
            balance: decrypt_amount(&session.keys.regev_sk, &view.row.enc_balances[t as usize])
                .map_err(js_err)?,
        });
    }
    let balance = balances.first().map(|b| b.balance).unwrap_or(0);
    Ok(BalanceReport {
        slot: view.slot,
        balance,
        can_send: true,
        state_version: header.state_version,
        balances,
        witness_token_slot: session.balance.as_ref().map(|(t, _, _)| *t),
    })
}

fn assert_own_recipient_bound(session: &Session, view: &SlotView) -> Result<(), JsValue> {
    if session
        .expected_recipient
        .is_some_and(|expected| view.row.recipient != expected)
    {
        return Err(js_err(
            "SECURITY: my slot's cosigner-signed L1 recipient does not match the address I \
             submitted — the relay may have substituted my exit address; refusing import",
        ));
    }
    Ok(())
}

/// Verify `view` for this wallet and make it the session head. Shared by import and finalize.
fn adopt_view(session: &mut Session, view: SlotView) -> Result<BalanceReport, JsValue> {
    view.verify_for(&session.keys).map_err(js_err)?;
    let identity = (view.record.channel_id, view.record.cosigner_pk_gs.clone());
    match &session.pinned {
        Some(pinned) if *pinned != identity => {
            return Err(js_err(
                "SECURITY: the view names a different channel or co-signer set than this wallet \
                 joined; refusing it",
            ));
        }
        _ => {}
    }
    assert_own_recipient_bound(session, &view)?;
    if session.slot.is_some_and(|slot| slot != view.slot) {
        return Err(js_err("the view is for another slot than this wallet's"));
    }
    // A pending debit commits once a verified head installs exactly the ciphertext we built.
    if let Some(p) = session.pending.take() {
        let ts = p.token_slot as usize;
        if view.row.enc_balances[ts] == p.expected_ct && view.row.pending_adds[ts] == 0 {
            session.balance = Some((p.token_slot, p.new_balance, p.witness));
        } else if view.state.balance_state.state_version
            <= session
                .view
                .as_ref()
                .map(|v| v.state.balance_state.state_version)
                .unwrap_or(0)
        {
            // Not installed yet and the head did not move past it: keep waiting.
            session.pending = Some(p);
        }
    }
    // Keep the witness only while it still opens the installed ciphertext. A canonical-zero
    // position adopts the public all-zero witness (A-1 finding 4), which opens only 0.
    let held_token_slot = session.balance.as_ref().map(|(t, _, _)| *t);
    let can_send = match &session.balance {
        Some((token_slot, amt, _w)) => {
            let ts = *token_slot as usize;
            let bal_at = decrypt_amount(&session.keys.regev_sk, &view.row.enc_balances[ts])
                .map_err(js_err)?;
            *amt == bal_at && view.row.pending_adds[ts] == 0
        }
        None => false,
    };
    let ts = held_token_slot.unwrap_or(0) as usize;
    let installed_is_canonical_zero = view.row.enc_balances[ts]
        == *crate::common::balance_state::zero_ciphertext()
        && view.row.pending_adds[ts] == 0;
    if installed_is_canonical_zero {
        session.balance = Some((ts as u8, 0, crate::regev::encrypt::zero_amount_witness()));
    } else if !can_send {
        session.balance = None;
    }
    let report = balance_report(session, &view)?;
    session.pinned = Some(identity);
    session.slot = Some(view.slot);
    session.view = Some(view);
    Ok(report)
}

fn current_view(session: &Session) -> Result<SlotView, JsValue> {
    session
        .view
        .clone()
        .ok_or_else(|| js_err("no channel imported"))
}

/// Import this wallet's view of the channel head (the only import a DELEGATE may make): the
/// signed header, its own slot row and the row's Merkle path. Verifies the co-signatures over
/// the recomputed digest, the row under the signed slot root, the slot's Regev key and L1
/// recipient, and that every own token position decrypts.
#[wasm_bindgen]
pub fn wallet_import_view(view_json: String) -> Result<String, JsValue> {
    with_session(|session| {
        let view: SlotView = serde_json::from_str(&view_json).map_err(js_err)?;
        let report = adopt_view(session, view)?;
        serde_json::to_string(&report).map_err(js_err)
    })
}

/// CO-SIGNER import of the full signed snapshot (a co-signer verifies other participants'
/// transitions, so it holds the whole state). Refused for a delegate slot: a delegate imports
/// only its slot view ([`wallet_import_view`]).
#[wasm_bindgen]
pub fn wallet_import_channel(snapshot_json: String) -> Result<String, JsValue> {
    with_session(|session| {
        let snapshot: ChannelSnapshot = serde_json::from_str(&snapshot_json).map_err(js_err)?;
        let slot = snapshot
            .members
            .iter()
            .find(|m| m.regev_pk == session.keys.regev_pk)
            .map(|m| m.slot)
            .ok_or_else(|| js_err("this wallet's key is not a member of the imported channel"))?;
        if slot >= snapshot.record.member_count as u32 {
            return Err(js_err(
                "delegates hold only their own slot: import the slot view (wallet_import_view), \
                 not the full channel snapshot",
            ));
        }
        verify_snapshot(&snapshot, Some((&session.keys, slot))).map_err(js_err)?;
        let view = SlotView::from_snapshot(&snapshot, slot).map_err(js_err)?;
        let report = adopt_view(session, view)?;
        remember_credit_head(session, &snapshot.state, slot)?;
        session.cosigner_snapshot = Some(snapshot);
        serde_json::to_string(&report).map_err(js_err)
    })
}

#[wasm_bindgen]
pub fn wallet_balance() -> Result<String, JsValue> {
    with_session(|session| {
        let view = current_view(session)?;
        let report = balance_report(session, &view)?;
        serde_json::to_string(&report).map_err(js_err)
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FinalizedClaimContext {
    close_intent_digest: Bytes32,
    final_channel_state_digest: Bytes32,
    final_balance_state_h1: Bytes32,
}

/// Exact `ChannelSettlementManager.WithdrawalClaim` calldata, derived only from proved public
/// inputs. `amount` is a decimal string so JavaScript cannot round a legitimate u64 wei value.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WithdrawalClaimDescriptor {
    close_intent_digest: String,
    member_pk_g: String,
    recipient: String,
    user_amount_digest: String,
    #[serde(serialize_with = "ser_u64_dec_string")]
    amount: u64,
    token_slot: u8,
    token_index: u32,
    withdrawal_nullifier: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WithdrawalClaimArtifact {
    claim: WithdrawalClaimDescriptor,
    /// Strict canonical wire-v3 full fixture emitted by the MLE V2 API. It contains the public
    /// proof and verifier metadata, never the Regev secret witness. The Node submitter
    /// validates its duplicated views and submits the exact `.compactProof.bytes`; it must
    /// never reconstruct an ABI proof tuple.
    mle_proof: serde_json::Value,
}

/// Produce a complete on-chain withdrawal-claim artifact without exporting the Regev secret.
///
/// Fail-closed binding order:
/// 1. the in-memory snapshot has already passed `wallet_import_channel`'s signature/root checks;
/// 2. its state digest and H1 must equal the manager's finalized values supplied by the caller;
/// 3. the close state-id is recomputed from the signed state and its next freeze nonce, and must
///    equal the manager's finalized close-intent digest;
/// 4. the claim circuit opens this wallet's active slot, binds its signed recipient and Regev pk,
///    and proves decryption of the selected token ciphertext;
/// 5. both the inner proof and the MLE/WHIR wrapper self-verify before any artifact is returned.
///
/// The caller may import an older, locally archived signed snapshot before calling this function
/// when an adversary finalized a stale close. That import is authenticated exactly like a live
/// snapshot and the three finalized bindings above prevent proving against the wrong history.
#[wasm_bindgen]
pub fn wallet_withdrawal_claim(
    finalized_context_json: String,
    token_slot: u8,
) -> Result<String, JsValue> {
    with_session(|session| {
        let finalized: FinalizedClaimContext =
            serde_json::from_str(&finalized_context_json).map_err(js_err)?;
        let view = current_view(session)?;
        let state = &view.state;

        if state.digest != finalized.final_channel_state_digest {
            return Err(js_err(
                "imported slot view is not the manager's finalized channel state",
            ));
        }
        let balance_h1 = state.balance_state.h1();
        if balance_h1 != finalized.final_balance_state_h1 {
            return Err(js_err(
                "imported slot view balance H1 is not the manager's finalized H1",
            ));
        }
        let finalized_freeze_nonce = state
            .close_freeze_nonce
            .checked_add(1)
            .ok_or_else(|| js_err("finalized close freeze nonce overflow"))?;
        let expected_close_id =
            close_state_id(state.channel_id, state.digest, finalized_freeze_nonce);
        if expected_close_id != finalized.close_intent_digest {
            return Err(js_err(
                "manager finalized close-intent digest is not the close state-id of the imported view",
            ));
        }
        let close_tx = CloseWithdrawal {
            channel_id: state.channel_id,
            final_channel_state_digest: state.digest,
            final_balance_state_h1: balance_h1,
            intmax_state_root: state.channel_fund.intmax_state_root,
            burn_tx_hash: Bytes32::default(),
            burn_amount: state.channel_fund.amounts[0],
            zkp: Vec::new(),
        };
        let close_intent = CloseIntent::from_header(state, &close_tx).map_err(js_err)?;
        if close_intent.signing_digest() != finalized.close_intent_digest {
            return Err(js_err(
                "locally reconstructed finalized close state-id mismatch",
            ));
        }

        let recipient = view.row.recipient;
        let prover = WithdrawalClaimProver::new();
        let witness = WithdrawalClaimProver::full_witness_from_view(
            &view,
            token_slot,
            session.keys.pk_g(),
            &session.keys.regev_pk,
            &session.keys.regev_sk,
            &close_intent,
            &close_tx,
            LEVEL,
        )
        .map_err(js_err)?;
        let proof = prover.prove(&witness).map_err(js_err)?;
        prover
            .vd()
            .verify(proof.clone())
            .map_err(|e| js_err(format!("withdrawal claim self-verification failed: {e:?}")))?;
        let mle_json = prover.prove_mle(&proof).map_err(js_err)?;

        let pi_limbs = proof.public_inputs[..WITHDRAWAL_CLAIM_PUBLIC_INPUTS_LEN].to_u64_vec();
        let pis = WithdrawalClaimPublicInputs::from_u64_slice(&pi_limbs).map_err(js_err)?;
        if pis.close_intent_digest != finalized.close_intent_digest
            || pis.final_balance_state_h1 != finalized.final_balance_state_h1
            || pis.channel_id != state.channel_id
            || pis.recipient != recipient
            || pis.token_slot != token_slot
        {
            return Err(js_err(
                "proved withdrawal public inputs differ from the finalized local statement",
            ));
        }

        let artifact = WithdrawalClaimArtifact {
            claim: WithdrawalClaimDescriptor {
                close_intent_digest: pis.close_intent_digest.to_string(),
                member_pk_g: pis.member_pk_g.to_string(),
                recipient: pis.recipient.to_hex(),
                user_amount_digest: pis.user_amount_digest.to_string(),
                amount: pis.amount,
                token_slot: pis.token_slot,
                token_index: pis.token_index,
                withdrawal_nullifier: pis.withdrawal_nullifier.to_string(),
            },
            mle_proof: serde_json::from_str(&mle_json)
                .map_err(|e| js_err(format!("invalid MLE exporter JSON: {e}")))?,
        };
        serde_json::to_string(&artifact).map_err(js_err)
    })
}

/// Send `amount` of LOCAL token position `token_slot` (OPTIONAL — `undefined`/omitted = 0, the
/// genesis token; multitoken §N-3) to `recipient_slot`: builds the refresh-free decrypted-send
/// proof (the current balance ciphertext is opened by decryption under this wallet's Regev secret
/// key — no encryption witness, no refresh, even right after a homomorphic credit), signs the
/// `ChannelTx` (IMPA-v2 binds the token slot) and the proposed next state, and returns the
/// `SendPayload` for the co-signers. The new balance is committed only once `wallet_finalize`
/// receives the fully-signed state.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recipient {
    slot: u32,
    pk_g: String,
    pk_b: String,
    regev_pk: crate::regev::RegevPk,
}

impl Recipient {
    fn into_member(self) -> Result<MemberInfo, JsValue> {
        Ok(MemberInfo {
            slot: self.slot,
            pk_g: Bytes32::from_hex(&self.pk_g).map_err(js_err)?,
            pk_b: Bytes32::from_hex(&self.pk_b).map_err(js_err)?,
            regev_pk: self.regev_pk,
        })
    }
}

fn fresh_bytes32(rng: &mut impl rand010::Rng) -> Result<Bytes32, JsValue> {
    let mut words = [0u32; 8];
    for w in words.iter_mut() {
        *w = rand010::Rng::next_u32(rng);
    }
    Bytes32::from_u32_slice(&words).map_err(js_err)
}

/// In-channel send from this wallet's slot view. `recipient_json` is the recipient slot's public
/// participant record (`{slot, pkG, pkB, regevPk}`) as the relay serves it. Returns the SLIM send
/// payload (no proposed state: the co-signers build the successor from their own head).
#[wasm_bindgen]
pub fn wallet_send(
    recipient_json: String,
    amount: u64,
    token_slot: Option<u8>,
) -> Result<String, JsValue> {
    let token_slot = token_slot.unwrap_or(0);
    with_session(|session| {
        let view = current_view(session)?;
        let recipient: Recipient = serde_json::from_str(&recipient_json).map_err(js_err)?;
        let recipient = recipient.into_member()?;
        let mut rng = rand010::rng();
        let nonce = fresh_bytes32(&mut rng)?;
        let built = build_view_send(
            &session.keys,
            &view,
            &recipient,
            token_slot,
            amount,
            nonce,
            LEVEL,
            &mut rng,
        )
        .map_err(js_err)?;
        session.pending = Some(PendingDebit {
            token_slot,
            expected_ct: built.payload.after_ct.clone(),
            new_balance: built.new_balance,
            witness: built.after_witness,
        });
        serde_json::to_string(&built.payload).map_err(js_err)
    })
}

/// Encode a slim send payload (as returned by [`wallet_send`]) into the versioned binary slim
/// wire, so the browser never re-encodes Regev coefficient vectors as decimal JSON.
#[wasm_bindgen]
pub fn wallet_slim_send_wire(payload_json: String) -> Result<Vec<u8>, JsValue> {
    let payload: SlimSendPayload = serde_json::from_str(&payload_json).map_err(js_err)?;
    payload.to_wire_bytes().map_err(js_err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InterChannelOut<'a> {
    debit_payload: &'a SlimInterChannelDebitPayload,
    transfer_descriptor: &'a InterChannelTransferDescriptor,
}

/// Inter-channel send from this wallet's slot view. `dest_recipient_json` = `{ "regevPk": ..,
/// "pkG": "0x.." }` of the destination channel's recipient slot. Returns `{ debitPayload (slim),
/// transferDescriptor }`. The debit commits when a co-signed head installs it.
/// `token_index` defaults to this channel's genesis token; `base_nonce` is required (read the
/// live base head immediately before proving).
#[wasm_bindgen]
pub fn wallet_send_inter_channel(
    to_channel: u32,
    to_slot: u32,
    amount: u64,
    dest_recipient_json: String,
    token_index: Option<u32>,
    base_nonce: Option<u32>,
) -> Result<String, JsValue> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DestRecipient {
        regev_pk: crate::regev::RegevPk,
        pk_g: String,
    }
    with_session(|session| {
        let view = current_view(session)?;
        let token_index = token_index.unwrap_or(view.state.balance_state.token_registry[0]);
        let base_nonce = base_nonce.ok_or_else(|| {
            js_err("base nonce is required: read the current live base head immediately before proving")
        })?;
        let local_slot = view.local_token_slot(token_index).map_err(js_err)?;
        let dest: DestRecipient = serde_json::from_str(&dest_recipient_json).map_err(js_err)?;
        let dest_pk_g = Bytes32::from_hex(&dest.pk_g).map_err(js_err)?;
        let dest_channel = ChannelId::new(to_channel as u64).map_err(js_err)?;
        let mut rng = rand010::rng();
        let new_nullifier_root = fresh_bytes32(&mut rng)?;
        // `Salt::rand` is bound to the rand-0.8 `Rng`; see wallet_core's callers.
        let destination_base_transfer_salt =
            crate::common::salt::Salt::rand(&mut rand::thread_rng());
        let built = build_view_inter_channel_send(
            &session.keys,
            &view,
            dest_channel,
            to_slot,
            dest.regev_pk,
            dest_pk_g,
            destination_base_transfer_salt,
            token_index,
            base_nonce,
            amount,
            new_nullifier_root,
            LEVEL,
            &mut rng,
        )
        .map_err(js_err)?;
        session.pending = Some(PendingDebit {
            token_slot: local_slot as u8,
            expected_ct: built.debit_payload.after_ct.clone(),
            new_balance: built.new_balance,
            witness: built.new_balance_witness.clone(),
        });
        let out = InterChannelOut {
            debit_payload: &built.debit_payload,
            transfer_descriptor: &built.transfer_descriptor,
        };
        serde_json::to_string(&out).map_err(js_err)
    })
}

/// L1 partial withdrawal (burn) from this wallet's slot view: an inter-channel send to
/// `BURN_CHANNEL_ID` paid to `withdrawal_address_hex`.
#[wasm_bindgen]
pub fn wallet_burn_send(
    amount: u64,
    withdrawal_address_hex: String,
    token_index: Option<u32>,
    base_nonce: Option<u32>,
) -> Result<String, JsValue> {
    with_session(|session| {
        let view = current_view(session)?;
        let token_index = token_index.unwrap_or(view.state.balance_state.token_registry[0]);
        let base_nonce = base_nonce.ok_or_else(|| {
            js_err("base nonce is required: read the current live base head immediately before proving")
        })?;
        let local_slot = view.local_token_slot(token_index).map_err(js_err)?;
        let address = crate::ethereum_types::address::Address::from_hex(&withdrawal_address_hex)
            .map_err(js_err)?;
        let mut rng = rand010::rng();
        let new_nullifier_root = fresh_bytes32(&mut rng)?;
        let built = build_view_burn_send(
            &session.keys,
            &view,
            address,
            token_index,
            base_nonce,
            amount,
            new_nullifier_root,
            LEVEL,
            &mut rng,
        )
        .map_err(js_err)?;
        session.pending = Some(PendingDebit {
            token_slot: local_slot as u8,
            expected_ct: built.debit_payload.after_ct.clone(),
            new_balance: built.new_balance,
            witness: built.new_balance_witness.clone(),
        });
        let out = InterChannelOut {
            debit_payload: &built.debit_payload,
            transfer_descriptor: &built.transfer_descriptor,
        };
        serde_json::to_string(&out).map_err(js_err)
    })
}

/// Re-encrypt one own token position to a fresh ciphertext (value unchanged). Returns the slim
/// refresh payload; the refreshed witness commits when a co-signed head installs it.
#[wasm_bindgen]
pub fn wallet_refresh(token_slot: Option<u8>) -> Result<String, JsValue> {
    let token_slot = token_slot.unwrap_or(0);
    with_session(|session| {
        let view = current_view(session)?;
        let value = decrypt_amount(
            &session.keys.regev_sk,
            view.row
                .enc_balances
                .get(token_slot as usize)
                .ok_or_else(|| js_err("token_slot out of range"))?,
        )
        .map_err(js_err)?;
        let mut rng = rand010::rng();
        let (payload, new_witness) =
            build_view_refresh(&session.keys, &view, token_slot, LEVEL, &mut rng)
                .map_err(js_err)?;
        session.pending = Some(PendingDebit {
            token_slot,
            expected_ct: payload.new_ct.clone(),
            new_balance: value,
            witness: new_witness,
        });
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
            .cosigner_snapshot
            .as_ref()
            .ok_or_else(|| js_err("only a co-signer session (full snapshot import) can co-sign"))?;
        // Must extend our current head.
        if payload.proposed_next_state.prev_digest != snapshot.state.digest {
            return Err(js_err("payload does not extend the wallet's current head"));
        }
        let am_recipient = payload.recipient_index == slot;
        // SECURITY (review C02, 2026-10-16): the complete public verification (sender hash-sig,
        // decrypted E-1, structural fold) runs BEFORE the session's secret key touches the
        // payload; an unauthenticated payload is rejected without any decryption.
        if am_recipient {
            crate::wallet_core::verify_send_transition_as_recipient(
                &snapshot.state,
                &snapshot.record,
                &payload,
                LEVEL,
                &session.keys.regev_sk,
            )
            .map_err(js_err)?;
        } else {
            verify_send_transition(
                &snapshot.state,
                &snapshot.record,
                &payload,
                LEVEL,
                None,
                None,
            )
            .map_err(js_err)?;
        }

        let mut next = payload.proposed_next_state.clone();
        // Co-signing is COSIGNER-only: a delegate session must not emit a state signature
        // (send-only model; a delegate sig would be structurally ignored anyway).
        let mc = snapshot.record.member_count;
        if slot >= mc as u32 {
            return Err(js_err(format!(
                "slot {slot} is a delegate (member_count {mc}); delegates do not co-sign state"
            )));
        }
        // Signer-independent exit: the browser holds no pre-sign exit-kit receipt, so it may only
        // release a signature over an H2=0 successor whose exact backing statement equals the
        // durable head's. This is the same refusal the CLI applies at its signing primitive.
        verify_exit_kit_preserving_successor(&snapshot.state, &next).map_err(js_err)?;
        let before_bounds = credit_bounds_for(session, &snapshot.state, slot)?;
        let after_bounds = before_bounds
            .advance_authenticated(
                &snapshot.state,
                &next,
                &owned_credit_plaintexts(session, &next, slot)?,
            )
            .map_err(js_err)?;
        let sig = sign_state(&session.keys, slot as u8, &next).map_err(js_err)?;
        add_signature(&mut next, sig);
        // The shipped worker persists the exact signing decision in IndexedDB before posting
        // this result outside the worker. SDK hosts must provide the same durable boundary.
        session
            .credit_safety_bounds
            .retain(|key, _| key == &snapshot.state.digest.to_hex());
        session
            .credit_safety_bounds
            .insert(next.digest.to_hex(), after_bounds);
        serde_json::to_string(&next).map_err(js_err)
    })
}

/// Adopt a fully-signed next state as the new head after verifying every member's real signature.
/// Updates the balance view; if this wallet was the sender, commits the pending send witness.
/// Adopt the co-signed head returned for an operation this wallet started (or any later head):
/// `view_json` is this wallet's slot view of it. It must verify like an import and advance the
/// wallet's head; a pending debit commits when the view installs the ciphertext it built.
#[wasm_bindgen]
pub fn wallet_finalize(view_json: String) -> Result<String, JsValue> {
    with_session(|session| {
        let view: SlotView = serde_json::from_str(&view_json).map_err(js_err)?;
        let current = current_view(session)?;
        if view.state.balance_state.state_version <= current.state.balance_state.state_version {
            return Err(js_err(
                "finalized view does not advance the wallet's current head",
            ));
        }
        if view.state.balance_state.state_version == current.state.balance_state.state_version + 1
            && view.state.prev_digest != current.state.digest
        {
            return Err(js_err(
                "finalized view does not extend the wallet's current head",
            ));
        }
        let report = adopt_view(session, view)?;
        serde_json::to_string(&report).map_err(js_err)
    })
}

/// CO-SIGNER finalize: adopt the full co-signed successor state of the held snapshot.
#[wasm_bindgen]
pub fn wallet_finalize_state(state_json: String) -> Result<String, JsValue> {
    with_session(|session| {
        let next_state: ChannelState = serde_json::from_str(&state_json).map_err(js_err)?;
        let slot = session.slot.ok_or_else(|| js_err("no channel imported"))?;
        let mut snapshot = session.cosigner_snapshot.clone().ok_or_else(|| {
            js_err("only a co-signer session holds the full state; delegates finalize a view")
        })?;
        if next_state.prev_digest != snapshot.state.digest {
            return Err(js_err(
                "finalized state does not extend the wallet's current head",
            ));
        }
        if next_state.balance_state.state_version != snapshot.state.balance_state.state_version + 1
        {
            return Err(js_err("state_version must increment by exactly 1"));
        }
        snapshot.state = next_state;
        verify_snapshot(&snapshot, Some((&session.keys, slot))).map_err(js_err)?;
        let view = SlotView::from_snapshot(&snapshot, slot).map_err(js_err)?;
        let report = adopt_view(session, view)?;
        remember_credit_head(session, &snapshot.state, slot)?;
        session.cosigner_snapshot = Some(snapshot);
        serde_json::to_string(&report).map_err(js_err)
    })
}

// --- Phase-0 feasibility probe (kept for diagnostics) ----------------------------------------

/// SECURITY: `Test` level — NOT secure; diagnostic probe only. Gated behind the
/// `diagnostics` cargo feature (off by default) so it is NOT exported in the
/// production wallet WASM — a shipped Test-level prover would be a misuse footgun.
/// Build the diagnostic page with `--features diagnostics`.
#[cfg(feature = "diagnostics")]
#[wasm_bindgen]
pub async fn wallet_feasibility_check() -> Result<String, JsValue> {
    // The witnessed E-1 prover/verifier this probe used are test-only since C2 (co-signers accept
    // only the decrypted purposes); the probe measures the DECRYPTED E-1 the wallet actually ships.
    use crate::regev::{channel_keygen, prove_channel_tx_decrypted, verify_channel_tx_decrypted};
    let mut rng = rand010::rng();
    let (sender_pk, sender_sk) = channel_keygen(&mut rng);
    let (recipient_pk, _r) = channel_keygen(&mut rng);
    let before = encrypt_amount(&mut rng, &sender_pk, 100).map_err(js_err)?;
    let amount = encrypt_amount(&mut rng, &recipient_pk, 30).map_err(js_err)?;
    let after = encrypt_amount(&mut rng, &sender_pk, 70).map_err(js_err)?;
    let proof = prove_channel_tx_decrypted(
        RegevSecurityLevel::Test,
        &sender_pk,
        &sender_sk,
        &recipient_pk,
        &before.0,
        (&amount.0, &amount.1),
        (&after.0, &after.1),
    )
    .map_err(js_err)?;
    verify_channel_tx_decrypted(
        RegevSecurityLevel::Test,
        &sender_pk,
        &recipient_pk,
        &before.0,
        &amount.0,
        &after.0,
        &proof,
    )
    .map_err(js_err)?;
    Ok(format!(
        "E-1 prove+verify OK in wasm; proof = {} bytes",
        proof.len()
    ))
}
