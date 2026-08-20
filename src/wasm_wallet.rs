//! Browser wallet `#[wasm_bindgen]` entry points (Regev channel model).
//!
//! Thin JSON wrappers over [`crate::wallet_core`]. All secret material (SPHINCS+ seeds, Regev
//! secret key, balance encryption witnesses) lives ONLY in the in-memory [`Session`] and is never
//! returned to JS or serialized. The worker drives these in order: `wallet_keygen` →
//! `wallet_genesis_contribution` → (CLI assembles + sends back genesis) → `wallet_sign_state` →
//! `wallet_import_channel` → `wallet_balance` / `wallet_send` / `wallet_cosign` /
//! `wallet_finalize`.
//!
//! SECURITY: `RegevSecurityLevel::Production` is used for all real proving. Keys are session-only
//! (lost on reload) per the approved threat-model default.

use std::cell::RefCell;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

use crate::{
    common::channel::{ChannelState, MemberSignature},
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    regev::{AmountWitness, RegevSecurityLevel, encrypt_amount},
    wallet_core::{
        BuiltSend, ChannelSnapshot, MemberKeys, SendPayload, add_signature, build_refresh,
        build_send_token, decrypt_balance_token, resolve_local_token_slot, sign_state,
        verify_send_transition, verify_snapshot,
    },
};

/// SECURITY: real funds ⇒ Production STARK parameters (≈100-bit), never the fast `Test` level.
const LEVEL: RegevSecurityLevel = RegevSecurityLevel::Production;

/// In-memory wallet session (single member). Holds all secrets; never serialized.
struct Session {
    keys: MemberKeys,
    /// BALANCE-SLOT index (member OR delegate, `0..MAX_CHANNEL_MEMBERS = 1024`) — u16.
    slot: Option<u16>,
    snapshot: Option<ChannelSnapshot>,
    /// The member's current balance + its encryption witness AT ONE token position (multitoken
    /// §N-2 — the witness backs exactly one `(slot, token)` ciphertext):
    /// `(token_slot, amount, witness)`. Present only when this wallet freshly encrypted that
    /// position (genesis contribution at token 0, a completed send, or a refresh of the
    /// position). `None` after a homomorphic receive (a refresh restores it).
    balance: Option<(u8, u64, AmountWitness)>,
    /// A send/refresh awaiting finalization:
    /// (next_state_digest, token_slot, new_balance, new_witness).
    pending_send: Option<(Bytes32, u8, u64, AmountWitness)>,
    /// SECURITY (B-1b, obligation 1): the L1 exit address this wallet SUBMITTED in its genesis
    /// contribution. Under Option B a joining delegate has no on-chain registration to cross-check
    /// its recipient, so a malicious relay could substitute a different address between the
    /// contribution and cosigner signing. We remember what we asked for and, on every import,
    /// assert `recipients[my_slot]` equals it — fail-closed. `None` until a contribution is made
    /// (e.g. a pure importer with no contribution of its own).
    expected_recipient: Option<crate::ethereum_types::address::Address>,
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
/// SECURITY (testnet only): this relaxes the module's "secrets are session-only, never persisted"
/// default — the caller (JS) generates and stores the seed (localStorage) and is responsible for
/// it. The seed deterministically derives the Goldilocks/BabyBear/Regev secret keys, so anyone who
/// reads the seed controls the account. Do NOT use seed-persistence for mainnet-value keys.
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
            snapshot: None,
            balance: None,
            pending_send: None,
            expected_recipient: None,
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
pub fn wallet_sign_state(slot: u16, state_json: String) -> Result<String, JsValue> {
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
        // Cosigner space: slot < member_count <= MAX_COSIGNERS (checked above), so u8 fits.
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
    slot: u16,
    /// GENESIS-token (local slot 0) balance — the wire-compat scalar kept for existing callers;
    /// the per-token view is `balances`. Base units, wire-encoded as a decimal string — see
    /// [`ser_u64_dec_string`].
    #[serde(serialize_with = "ser_u64_dec_string")]
    balance: u64,
    can_send: bool,
    state_version: u64,
    /// Per-token balances over ALL active registry positions (multitoken Phase 4).
    balances: Vec<TokenBalanceEntry>,
    /// The token position the held send-witness backs (None ⇒ cannot send any token until a
    /// refresh). `can_send` refers to THIS position.
    witness_token_slot: Option<u8>,
}

/// Build the standard per-token balance report for `slot` from a verified snapshot.
fn balance_report(
    session: &Session,
    snapshot: &ChannelSnapshot,
    slot: u16,
) -> Result<BalanceReport, JsValue> {
    let bs = &snapshot.state.balance_state;
    let mut balances = Vec::with_capacity(bs.token_count as usize);
    for t in 0..bs.token_count {
        balances.push(TokenBalanceEntry {
            token_slot: t,
            token_index: bs.token_registry[t as usize],
            balance: decrypt_balance_token(&session.keys, snapshot, slot, t).map_err(js_err)?,
        });
    }
    let balance = balances.first().map(|b| b.balance).unwrap_or(0);
    Ok(BalanceReport {
        slot,
        balance,
        can_send: session.balance.is_some(),
        state_version: bs.state_version,
        balances,
        witness_token_slot: session.balance.as_ref().map(|(t, _, _)| *t),
    })
}

/// SECURITY (B-1b, obligation 1 from the recipient-binding adversarial review): a joining delegate
/// has no L1 registration cross-checking its exit address, so a malicious relay could substitute a
/// different `recipient` between the delegate's contribution and cosigner signing. The cosigners
/// cannot detect it (they don't know the delegate's intended address). This is the delegate's own
/// fail-closed guard: if we submitted a contribution (`expected_recipient` is set), the imported,
/// cosigner-signed leaf at our slot MUST bind exactly that address. A mismatch means our funds
/// would exit to someone else — refuse the import rather than adopt a poisoned head.
fn assert_own_recipient_bound(
    session: &Session,
    snapshot: &ChannelSnapshot,
    slot: u16,
) -> Result<(), JsValue> {
    if let Some(expected) = session.expected_recipient {
        let bound = snapshot.state.balance_state.recipients[slot as usize];
        if bound != expected {
            return Err(js_err(
                "SECURITY: my slot's cosigner-signed L1 recipient does not match the address I \
                 submitted — the relay may have substituted my exit address; refusing import",
            ));
        }
    }
    Ok(())
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
        assert_own_recipient_bound(session, &snapshot, slot)?;

        // Keep the witness only if the imported (slot, token) ciphertext is exactly the one we
        // encrypted (completed send / refresh of that position). Otherwise we cannot send that
        // token until a refresh.
        //
        // SECURITY (A-1 finding 4 — the CANONICAL-ZERO case must be handled EXPLICITLY):
        // the plaintext comparison below is NOT a proof that our witness opens the installed
        // ciphertext, because re-deriving the ciphertext by re-encrypting is impossible (fresh
        // randomness). It is a heuristic, and A-1 broke it in the direction that matters. Since
        // A-1 the cosigners install the CANONICAL ZERO ciphertext at a new delegate slot — at
        // genesis (`create_channel`) and at join (`join_delegate`) — instead of the ciphertext this
        // wallet contributed. So:
        //   * a wallet that contributed a NONZERO balance is the SAFE case: `amt != 0 == bal_at`,
        //     the heuristic drops the witness, and it must refresh — correct.
        //   * a wallet that contributed ZERO is the PRODUCTION case (`wallet-live.html` passes
        //     `toBase('0')`): `0 == 0` passes the compare, and the old code RETAINED a witness for
        //     our own `encrypt_amount(rng, pk, 0)`, which does NOT open the installed canonical
        //     zero. The first send would then fail fail-closed inside the E-1 witness check
        //     (`regev::transfer_stark::check_amount_witness`) — sound, but a dead-end for the user.
        // The fix is exact rather than defensive: when the installed ciphertext IS the canonical
        // zero, the correct witness is the PUBLIC all-zero witness (`zero_amount_witness()`), which
        // opens `padding()` under any key and can only ever open the amount 0. Adopt it and keep
        // the wallet able to send.
        let held_token_slot = session.balance.as_ref().map(|(t, _, _)| *t);
        let can_send = match &session.balance {
            Some((token_slot, amt, _w)) => {
                let ts = *token_slot as usize;
                let bal_at = decrypt_balance_token(&session.keys, &snapshot, slot, *token_slot)
                    .map_err(js_err)?;
                *amt == bal_at && snapshot.state.balance_state.pending_adds[slot as usize][ts] == 0
            }
            None => false,
        };
        // SECURITY: order matters — the canonical-zero adoption runs AFTER `can_send` is decided,
        // and only when the installed ciphertext is literally the canonical zero AND the position
        // is free of pending homomorphic adds (an add would have moved the ciphertext away from
        // the canonical zero anyway; the check is belt-and-braces).
        let ts = held_token_slot.unwrap_or(0);
        let installed_is_canonical_zero = snapshot.state.balance_state.enc_balances[slot as usize]
            [ts as usize]
            == *crate::common::balance_state::zero_ciphertext()
            && snapshot.state.balance_state.pending_adds[slot as usize][ts as usize] == 0;
        if installed_is_canonical_zero {
            session.balance = Some((ts, 0, crate::regev::encrypt::zero_amount_witness()));
        } else if !can_send {
            session.balance = None;
        }
        let report = balance_report(session, &snapshot, slot)?;
        session.slot = Some(slot);
        session.snapshot = Some(snapshot);
        serde_json::to_string(&report).map_err(js_err)
    })
}

/// Report the current decrypted balances of this member's slot: the token-0 scalar (wire
/// compat) plus the per-token `balances` array over all active registry positions.
#[wasm_bindgen]
pub fn wallet_balance() -> Result<String, JsValue> {
    with_session(|session| {
        let slot = session.slot.ok_or_else(|| js_err("no channel imported"))?;
        let snapshot = session
            .snapshot
            .clone()
            .ok_or_else(|| js_err("no channel imported"))?;
        let report = balance_report(session, &snapshot, slot)?;
        serde_json::to_string(&report).map_err(js_err)
    })
}

/// Send `amount` of LOCAL token position `token_slot` (OPTIONAL — `undefined`/omitted = 0, the
/// genesis token; multitoken §N-3) to `recipient_slot`: builds the E-1 proof, signs the
/// `ChannelTx` (IMPA-v2 binds the token slot) and the proposed next state, and returns the
/// `SendPayload` for the co-signers. The held witness must back exactly this token position
/// (fail-closed otherwise — a refresh of the position restores it). The new balance is
/// committed only once `wallet_finalize` receives the fully-signed state.
#[wasm_bindgen]
pub fn wallet_send(
    recipient_slot: u16,
    amount: u64,
    token_slot: Option<u8>,
) -> Result<String, JsValue> {
    let token_slot = token_slot.unwrap_or(0);
    with_session(|session| {
        let slot = session.slot.ok_or_else(|| js_err("no channel imported"))?;
        let snapshot = session
            .snapshot
            .clone()
            .ok_or_else(|| js_err("no channel imported"))?;
        let (witness_token, before_amount, before_witness) =
            session.balance.clone().ok_or_else(|| {
                js_err("no spendable balance witness (a refresh is required after receiving)")
            })?;
        // The witness backs exactly ONE (slot, token) ciphertext — never sign an E-1 statement
        // over a position the witness does not open.
        if witness_token != token_slot {
            return Err(js_err(format!(
                "held balance witness is for token position {witness_token}, not {token_slot} — \
                 refresh token {token_slot} first"
            )));
        }
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
        } = build_send_token(
            &session.keys,
            &snapshot,
            slot,
            recipient_slot,
            token_slot,
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
        session.pending_send = Some((
            payload.proposed_next_state.digest,
            token_slot,
            new_balance,
            new_balance_witness,
        ));
        serde_json::to_string(&payload).map_err(js_err)
    })
}

/// Project a just-built [`SendPayload`] into the versioned binary slim wire. Keeping this inside
/// Rust avoids re-encoding megabytes of Regev coefficients and proof bytes as decimal JSON in the
/// browser, while reusing the exact production projection and codec consumed by the CLI.
#[wasm_bindgen]
pub fn wallet_slim_send_wire(payload_json: String) -> Result<Vec<u8>, JsValue> {
    let payload: SendPayload = serde_json::from_str(&payload_json).map_err(js_err)?;
    payload.to_slim().to_wire_bytes().map_err(js_err)
}

/// Inter-channel send: debit `amount` from this wallet's slot and produce the cross-channel
/// transfer to `to_slot` in `to_channel`. `dest_recipient_json` = `{ "regevPk": <RegevPk>, "pkG":
/// "0x.." }` of the destination channel's recipient slot (the browser reads it from channel B's
/// snapshot). Returns `{ "debitPayload": <InterChannelDebitPayload>, "transferDescriptor":
/// <InterChannelTransferDescriptor> }`: the browser POSTs the debit payload to channel A's
/// `/api/inter/debit` (A members co-sign), then the descriptor + A's co-signed state to channel B's
/// `/api/inter/credit`. The debit commits on `wallet_finalize` of A's co-signed state. Mirrors
/// `wallet_send`.
/// `token_index` (OPTIONAL — `undefined`/omitted = this channel's genesis `registry[0]`) is the
/// BASE-layer token index to move (multitoken §N-4, TM-6): it must be registered in the SOURCE
/// channel's registry (fail-closed otherwise), the held witness must back the resolved local
/// position, and the destination channel resolves the same base index against its OWN registry.
#[wasm_bindgen]
pub fn wallet_send_inter_channel(
    to_channel: u32,
    to_slot: u16,
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
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Out<'a> {
        debit_payload: &'a crate::wallet_core::InterChannelDebitPayload,
        transfer_descriptor: &'a crate::wallet_core::InterChannelTransferDescriptor,
    }
    with_session(|session| {
        let slot = session.slot.ok_or_else(|| js_err("no channel imported"))?;
        let snapshot = session
            .snapshot
            .clone()
            .ok_or_else(|| js_err("no channel imported"))?;
        let (witness_token, before_amount, before_witness) =
            session.balance.clone().ok_or_else(|| {
                js_err("no spendable balance witness (a refresh is required after receiving)")
            })?;
        let token_index = token_index.unwrap_or(snapshot.state.balance_state.token_registry[0]);
        let base_nonce = base_nonce.ok_or_else(|| {
            js_err(
                "base nonce is required: read the current live base head immediately before proving",
            )
        })?;
        // The held witness must back the LOCAL position this base token resolves to (TM-6).
        let local_slot =
            resolve_local_token_slot(&snapshot.state.balance_state, token_index).map_err(js_err)?;
        if witness_token as usize != local_slot {
            return Err(js_err(format!(
                "held balance witness is for token position {witness_token}, but base token \
                 {token_index} resolves to position {local_slot} — refresh that position first"
            )));
        }
        let dest: DestRecipient = serde_json::from_str(&dest_recipient_json).map_err(js_err)?;
        let dest_pk_g = Bytes32::from_hex(&dest.pk_g).map_err(js_err)?;
        let dest_channel =
            crate::common::channel_id::ChannelId::new(to_channel as u64).map_err(js_err)?;
        let mut rng = rand010::rng();
        // Fresh shared_native_nullifier_root for this debit (must differ from prev; §C-3).
        let mut nr = [0u32; 8];
        for w in nr.iter_mut() {
            *w = rand010::Rng::next_u32(&mut rng);
        }
        let new_nullifier_root = Bytes32::from_u32_slice(&nr).map_err(js_err)?;
        // The UID recipient opening is public in the returned descriptor, but is generated in
        // Rust so every caller gets a fresh canonical salt without a JS-side encoding ambiguity.
        let destination_base_transfer_salt = crate::common::salt::Salt::rand(&mut rng);
        let built = crate::wallet_core::build_inter_channel_send_token_at_base_nonce(
            &session.keys,
            &snapshot,
            slot,
            dest_channel,
            to_slot,
            dest.regev_pk,
            dest_pk_g,
            destination_base_transfer_salt,
            token_index,
            base_nonce,
            amount,
            before_amount,
            &before_witness,
            new_nullifier_root,
            LEVEL,
            &mut rng,
        )
        .map_err(js_err)?;
        // The sender's debit commits when wallet_finalize receives channel A's co-signed state.
        session.pending_send = Some((
            built.debit_payload.proposed_next_state.digest,
            witness_token,
            built.new_balance,
            built.new_balance_witness.clone(),
        ));
        let out = Out {
            debit_payload: &built.debit_payload,
            transfer_descriptor: &built.transfer_descriptor,
        };
        serde_json::to_string(&out).map_err(js_err)
    })
}

/// Burn `amount` from this wallet's slot for a partial withdrawal to `withdrawal_address_hex`
/// (an L1 Ethereum address, hex with 0x prefix). Internally calls `build_burn_send` which wraps
/// `build_inter_channel_send` with `BURN_CHANNEL_ID` + `RegevPk::padding()` (architecture-audit
/// /partial-withdrawal-impl-plan.md). Returns `{ debitPayload, transferDescriptor }` — the
/// browser POSTs `debitPayload` to `/api/cosign-burn` for N-of-N co-signing, then finalizes.
/// Mirrors `wallet_send_inter_channel`.
/// `token_index` (OPTIONAL — `undefined`/omitted = the genesis `registry[0]`) is the BASE token
/// to burn (multitoken §N): the debit lands at the local position the source registry resolves,
/// and the resulting L1 partial withdrawal pays out in that asset (IMPW binds `tokenIndex`).
#[wasm_bindgen]
pub fn wallet_burn_send(
    amount: u64,
    withdrawal_address_hex: String,
    token_index: Option<u32>,
    base_nonce: Option<u32>,
) -> Result<String, JsValue> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Out<'a> {
        debit_payload: &'a crate::wallet_core::InterChannelDebitPayload,
        transfer_descriptor: &'a crate::wallet_core::InterChannelTransferDescriptor,
    }
    with_session(|session| {
        let slot = session.slot.ok_or_else(|| js_err("no channel imported"))?;
        let snapshot = session
            .snapshot
            .clone()
            .ok_or_else(|| js_err("no channel imported"))?;
        let (witness_token, before_amount, before_witness) =
            session.balance.clone().ok_or_else(|| {
                js_err("no spendable balance witness (a refresh is required after receiving)")
            })?;
        let token_index = token_index.unwrap_or(snapshot.state.balance_state.token_registry[0]);
        let base_nonce = base_nonce.ok_or_else(|| {
            js_err(
                "base nonce is required: read the current live base head immediately before proving",
            )
        })?;
        let local_slot =
            resolve_local_token_slot(&snapshot.state.balance_state, token_index).map_err(js_err)?;
        if witness_token as usize != local_slot {
            return Err(js_err(format!(
                "held balance witness is for token position {witness_token}, but base token \
                 {token_index} resolves to position {local_slot} — refresh that position first"
            )));
        }
        let address = crate::ethereum_types::address::Address::from_hex(&withdrawal_address_hex)
            .map_err(js_err)?;
        let mut rng = rand010::rng();
        let mut nr = [0u32; 8];
        for w in nr.iter_mut() {
            *w = rand010::Rng::next_u32(&mut rng);
        }
        let new_nullifier_root = Bytes32::from_u32_slice(&nr).map_err(js_err)?;
        let built = crate::wallet_core::build_burn_send_token_at_base_nonce(
            &session.keys,
            &snapshot,
            slot,
            address,
            token_index,
            base_nonce,
            amount,
            before_amount,
            &before_witness,
            new_nullifier_root,
            LEVEL,
            &mut rng,
        )
        .map_err(js_err)?;
        session.pending_send = Some((
            built.debit_payload.proposed_next_state.digest,
            witness_token,
            built.new_balance,
            built.new_balance_witness.clone(),
        ));
        let out = Out {
            debit_payload: &built.debit_payload,
            transfer_descriptor: &built.transfer_descriptor,
        };
        serde_json::to_string(&out).map_err(js_err)
    })
}

/// Balance-refresh THIS wallet's own (slot, token) position: re-encrypt the current balance to
/// clean digits (same value) so the position can SEND again after receiving (a received
/// homomorphic credit blocks the next send until a refresh). `token_slot` (OPTIONAL —
/// `undefined`/omitted = 0, the genesis token) selects the LOCAL token position (multitoken
/// §B-3 × §N, TM-13 — refreshes are per (member, token); the verifier enforces any active
/// selector). Returns the `RefreshPayload` for the members to co-sign; once finalized, the
/// position is spendable again. Identical for a member or a delegate slot.
#[wasm_bindgen]
pub fn wallet_refresh(token_slot: Option<u8>) -> Result<String, JsValue> {
    let token_slot = token_slot.unwrap_or(0);
    with_session(|session| {
        let slot = session.slot.ok_or_else(|| js_err("no channel imported"))?;
        let snapshot = session
            .snapshot
            .clone()
            .ok_or_else(|| js_err("no channel imported"))?;
        let value =
            decrypt_balance_token(&session.keys, &snapshot, slot, token_slot).map_err(js_err)?;
        let mut rng = rand010::rng();
        let (payload, new_witness) =
            build_refresh(&session.keys, &snapshot, slot, token_slot, LEVEL, &mut rng)
                .map_err(js_err)?;
        // The refreshed position holds the SAME value with a fresh witness; commit it on
        // finalize so the wallet can send that token again.
        session.pending_send = Some((
            payload.proposed_next_state.digest,
            token_slot,
            value,
            new_witness,
        ));
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
            let amt = crate::regev::decrypt_amount(
                &session.keys.regev_sk,
                &payload.channel_tx.enc_amount,
            )
            .map_err(|e| js_err(format!("cannot decrypt incoming amount: {e}")))?;
            (Some(&session.keys.regev_sk), Some(amt))
        } else {
            (None, None)
        };
        verify_send_transition(
            &snapshot.state,
            &snapshot.record,
            &payload,
            LEVEL,
            sk,
            expected,
        )
        .map_err(js_err)?;

        let mut next = payload.proposed_next_state.clone();
        // Co-signing is COSIGNER-only: a delegate session must not emit a state signature
        // (send-only model; a delegate sig would be structurally ignored anyway).
        let mc = snapshot.record.member_count;
        if slot >= mc as u16 {
            return Err(js_err(format!(
                "slot {slot} is a delegate (member_count {mc}); delegates do not co-sign state"
            )));
        }
        let sig = sign_state(&session.keys, slot as u8, &next).map_err(js_err)?;
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
            return Err(js_err(
                "finalized state does not extend the wallet's current head",
            ));
        }
        if next_state.balance_state.state_version != snapshot.state.balance_state.state_version + 1
        {
            return Err(js_err("state_version must increment by exactly 1"));
        }
        // Adopt, then fully verify (record/root/balance-state validity, every member's REAL
        // Goldilocks SingleSig proof, own-slot decryption). `verify_snapshot` already runs the full
        // signature check, so we don't call `verify_all_signatures` separately (it would re-run all
        // SingleSig proof verifications and roughly double finalize latency).
        snapshot.state = next_state;
        verify_snapshot(&snapshot, Some((&session.keys, slot))).map_err(js_err)?;
        assert_own_recipient_bound(session, &snapshot, slot)?;

        // Commit the pending send/refresh witness (with its token position) if this finalized
        // state is the one we proposed.
        let committed = match session.pending_send.take() {
            Some((digest, token_slot, new_balance, witness)) if digest == snapshot.state.digest => {
                session.balance = Some((token_slot, new_balance, witness));
                true
            }
            _ => false,
        };
        if !committed {
            // We were recipient/uninvolved: our slot may now be a homomorphic sum → witness stale.
            session.balance = None;
        }
        let report = balance_report(session, &snapshot, slot)?;
        session.snapshot = Some(snapshot);
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
    Ok(format!(
        "E-1 prove+verify OK in wasm; proof = {} bytes",
        proof.len()
    ))
}
