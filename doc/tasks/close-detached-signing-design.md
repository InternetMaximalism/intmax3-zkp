# Threat model + design: detached member signing on the channel-close path

Branch: `feat/falcon-poseidon-sig` (HEAD `4574348`). Status: **DESIGN ONLY — no code written, nothing
committed.** Requires owner sign-off on §8 before any implementation.

Related: `doc/tasks/falcon-sig-threat-model.md` (TM-C5..TM-C10, the Falcon migration's own model),
`doc/tasks/b2-delegate-close-threat-model.md` (close PI limb 94; the style this doc follows),
`doc/tasks/reg-chain-1024-threat-model.md` (Option B — L1 registration is cosigners-only),
`doc/tasks/delegate-account-threat-model.md` (DLG-1/DLG-2), `doc/tasks/wallet-threat-model.md`.

---

## 0. Executive summary, and four corrections to the problem statement

The core claim in the problem statement is **confirmed**: `CloseProver::build_full_witness`
(`src/wallet_core.rs:3422`) is generic over `K: Borrow<FalconKeys>`, takes secret keys, and mints
signatures internally through `falcon_member_auth_for_digest` (`src/wallet_core.rs:3364`, signing at
`:3375`). `CancelCloseProver::build_full_witness` (`src/wallet_core.rs:3766`, signing via the same
helper at `:3809`) has the identical shape. The CLI feeds both from one deterministic seed base
(`src/bin/channel_member.rs:360` → `:353` → `:335`, `CLI_COSIGNER_SEED_BASE` at `:349`), and the API
drives that CLI (`api/routes/close.js:48`, `:76`, `:98`; `api/routes/full-withdrawal.js:100`). So the
deployed close path does require a single process to hold all N cosigner keys.

Four corrections, each of which materially changes the design:

**C-1 (the big one). The signatures the close prover needs already exist, already detached, in the
state it is handed.** Members sign `state.signing_digest()` when they co-sign the state
(`sign_state`, `src/wallet_core.rs:822-828`), and the close prover signs `state.digest`
(`src/wallet_core.rs:3477`). `verify_all_signatures` asserts `state.digest ==
state.signing_digest()` (`src/wallet_core.rs:879-881`), so these are **the same digest**. The close
circuit binds the aggregation proof's message to the in-circuit recomputed IMCH digest
(`src/circuits/channel/close_circuit.rs:786-789`) and is completely blind to *which* valid signature
was used — the leaf circuit registers only `[message, 1, pk_g]` (`src/falcon_sig/agg.rs:269-274`) and
`salt`/`s2`/`h` are never public inputs (`src/falcon_sig/gadget.rs:600-605`). Therefore re-signing
and re-using are cryptographically indistinguishable, and the close path can consume
`state.member_signatures` (`src/common/channel.rs:558`) verbatim. **No new signing round is needed
for close.** This removes the entire "partial-collection stalling" surface the problem statement
asked about, for the recommended option.

**C-2. The send path's "detached cosign flow" is real, but it is the *wasm wallet*, not the CLI.**
`cosign-burn-send` (`src/bin/channel_member.rs:3771`) and `cosign` (`:3143`) both loop over
`state.controlled` and sign with locally derived keys — the CLI holds several members' keys there
too. The genuinely detached implementation is `wallet_cosign` (`src/wasm_wallet.rs:708-755`) and
`wallet_sign_state` (`src/wasm_wallet.rs:212-247`): a browser session holds exactly one `MemberKeys`,
verifies the transition, signs its own slot, and hands back a `MemberSignature`. That *is* the model
to follow — and §3 follows it — but the CLI is not an example of it.

The structural difference between send and close is sharper than "the CLI holds many keys": the
send/cosign path is **key-count agnostic** (each process signs the slots it controls, skipping slots
already signed — `src/bin/channel_member.rs:3135-3146`), so a correctly split deployment works
unmodified. `cmd_close` bypasses `state.controlled` entirely and derives all N keys from the seed
base (`src/bin/channel_member.rs:872`), so a correctly split deployment **cannot close at all**.
That is the defect.

**C-3. `api/routes/close.js:23` does not need keys.** `POST /close/request` sets
`CLOSE_REQUEST_ONLY=1`, and `cmd_close` returns before any proving or key derivation
(`src/bin/channel_member.rs:831-856`). The key-bearing API entry points are `close.js:48`
(submit-intent), `close.js:76` (challenge), `close.js:98` (cancel), and `full-withdrawal.js:100`
(the combined request+submit).

**C-4. "Compromise of the API host = ability to close any channel" understates the exposure by a
large margin.** The cosigner keys are not stored on the host at all — they are *recomputed on
demand* from `keys_for(CLI_COSIGNER_SEED_BASE + slot)` where `CLI_COSIGNER_SEED_BASE = 0xC1_0000` is
a compile-time constant in this public repository (`src/bin/channel_member.rs:349`) and
`keys_for(seed) = MemberKeys::generate(&mut StdRng::seed_from_u64(seed))`
(`src/bin/channel_member.rs:335-337`). `MemberKeys::generate` is documented as fully deterministic
from the RNG stream (`src/wallet_core.rs:171-200`). There is no env override on that path. **Anyone
who can read this repository can derive every cosigner Falcon key of every CLI/API-driven channel**,
without compromising anything. Detached signing is necessary but not sufficient; see T-0 and §8.1.

---

## 1. Exact current state

### 1.1 The two call sites that consume secret keys on the close lifecycle

| # | Function | File:line | Takes | Signs | Digest | Prod? |
|---|---|---|---|---|---|---|
| 1 | `CloseProver::build_full_witness` | `src/wallet_core.rs:3422` | `&[K: Borrow<FalconKeys>]` | internally, `:3478` → `:3375` | `state.digest` (`:3477`) = IMCH `ChannelState::signing_digest()` (`src/common/channel.rs:579-603`) | **yes** |
| 2 | `CancelCloseProver::build_full_witness` | `src/wallet_core.rs:3766` | `&[K: Borrow<FalconKeys>]` | internally, `:3809` → `:3375` | `revived_state.digest` (`:3808`), same IMCH form | **yes** |

Both funnel through the one helper `falcon_member_auth_for_digest` (`src/wallet_core.rs:3364-3388`):
per member it reads `pk_g()` (`:3373`), `pk_coefficients()` (`:3374`), signs (`:3375`), re-verifies
with `verify_with_pk_g` (`:3376`), and finally builds `FalconAggWitness::for_signatures(digest,
&signers)` from `(&h, &sig)` pairs (`:3386-3387`).

**The problem statement's guess is right: `FalconAggWitness::for_signatures`
(`src/falcon_sig/agg.rs:212-222`) already takes `(&[u16; FALCON_N], &FalconSignature)` pairs.** It
never sees a secret key. The aggregation plumbing is already the correct shape; only the ~25 lines
above it are wrong.

The complete list of callers of those two methods (verified repo-wide):

| Caller | File:line | Kind | Key source |
|---|---|---|---|
| `cmd_close` | `src/bin/channel_member.rs:885` | CLI / production | `cli_falcon_keys(member_count)` at `:872` |
| `cmd_cancel_close` | `src/bin/channel_member.rs:1364` | CLI / production | `cli_falcon_keys(member_count)` at `:1344` |
| `a3_close_prover_builds_and_verifies_real_close_proof` | `src/wallet_core.rs:5739`, `:5753` | unit test | `FalconKeys::from_seed([0xc1 + i; 32])` at `:5732-5734` |
| `a3_cancel_close_prover_builds_and_verifies` | `src/wallet_core.rs:6001`, `:6008` | unit test | `FalconKeys::from_seed([0xca + i; 32])` at `:5936-5938` |

That is the **entire** blast radius: 2 production sites, 2 test functions.

### 1.2 What the CLI does

`cli_falcon_keys` (`src/bin/channel_member.rs:360-365`) → `cli_cosigner_keys` (`:353-357`) →
`keys_for(CLI_COSIGNER_SEED_BASE + slot)` (`:335-337`, `:349`). It derives keys for slots
`0..state.balance_state.member_count`, **not** for `state.controlled`. Every other CLI cosigning site
(`cmd_cosign` `:3143`, `cmd_cosign_burn_send` `:3771`, `cmd_cosign_refresh` `:3298`,
`cmd_cosign_inter_transfer` `:3514`/`:3651`, `create_channel` `:2526`, `join_delegate` `:2708`,
`cmd_cosign_l1_deposit_import` `:4705`/`:4714`, `cmd_refresh` `:4076`, `cmd_register_token` `:3950`)
loops over `state.controlled` and skips slots already signed — i.e. those are already correct for a
split deployment.

### 1.3 What the API does

Single global bearer token (`api/server.js:23` → `api/lib/security.js:50-67`); GET/HEAD are
unauthenticated by default (`security.js:51-54`). **There is no per-member, per-slot or per-caller
authorization anywhere in `api/routes/`.** The CLI is invoked via `execFileSync` with `{...process.env,
INTMAX_CHANNEL}` (`api/lib/cli.js:41-49`). Key-bearing entry points:

| Endpoint | File:line | argv | env |
|---|---|---|---|
| `POST /close/submit-intent` | `api/routes/close.js:48` | `['close', manager, RPC]` | `CLOSE_SV`, `CLOSE_SKIP_REQUEST=1` |
| `POST /close/challenge` | `api/routes/close.js:76` | `['close', manager, RPC]` | `CLOSE_SV`, `CLOSE_SKIP_REQUEST=1` |
| `POST /close/cancel` | `api/routes/close.js:98` | `['cancel-close', manager, RPC]` | `CANCEL_SV` |
| `POST /full-withdrawal/request` | `api/routes/full-withdrawal.js:100` | `['close', manager, RPC]` | `CLOSE_SV` |

`INTMAX_CLI_COSIGNERS` and `DELEGATE_SEED` are never set by `api/`; they reach the CLI only by
inheritance from the server process (`api/lib/cli.js:47`).

The API *already* accepts remote members' detached signatures on the send path: `POST /cosign`
writes the request body verbatim to `payload.json` (`api/routes/channel-send.js:11`) and the body's
`proposed_next_state.member_signatures[]` carries the browser member's Falcon signature, which
`cmd_cosign` preserves (`src/bin/channel_member.rs:3135-3142`). So "a signature blob arrives over
HTTP and is honoured" is an existing, working pattern — just not for close.

### 1.4 Must-change vs. may-keep-local-keys

**Must change (production close lifecycle, single-party-holds-all-N is a protocol defect):**
- `CloseProver::build_full_witness` (`src/wallet_core.rs:3422`)
- `CancelCloseProver::build_full_witness` (`src/wallet_core.rs:3766`)
- `cmd_close` (`src/bin/channel_member.rs:872`, `:885`) and `cmd_cancel_close` (`:1344`, `:1364`)

**Test convenience that may keep deriving keys locally:**
- The two unit tests above (`src/wallet_core.rs:5732`, `:5936`) — they generate keys and would simply
  sign first, then call the detached entry point.
- All fixture generators. **They do not go through these methods at all**:
  `src/bin/generate_close_fixture.rs:143` calls `close_circuit::test_fixture::build_close_full_witness_two_token`
  (signing via `member_auth_for_sks`, `src/circuits/channel/close_circuit.rs:1437`), and
  `src/bin/generate_cancel_close_fixture.rs:63` calls
  `cancel_close_circuit::test_fixture::build_full_witness` (`src/circuits/channel/cancel_close_circuit.rs:1019`).
  The `test_fixture` modules are feature-gated (`close_circuit.rs:1065`,
  `cancel_close_circuit.rs:785`) and are legitimately key-holding: they *are* the N members.

**Out of scope but adjacent, and worth stating so nobody thinks it was missed:**
- `build_channel_withdrawal` (`src/wallet_core.rs:4210-4213`) takes `Option<&[MemberKeys]>` — a full
  set of secret-bearing objects. But it only *signs* with one of them: the block-producer slot's
  Falcon key (`src/circuits/test_utils/block_witness_generator.rs:1043-1044`, with `bp_member_slot =
  0` set in `build_channel_withdrawal`). The other N-1 are used for their **public** identities in
  the registration tree (`ChannelMemberKeys::from_member_keys`,
  `src/circuits/test_utils/block_witness_generator.rs:291-318`). So the honest requirement there is
  "N public identities + 1 secret", not "N secrets". Fixing that is a smaller, separate change; the
  API route `full-withdrawal.js:127` (`withdraw`) is the consumer.
- `cmd_export_reg_record` (`src/bin/channel_member.rs:2183`) uses `cli_active_keys()` for public
  values only.

### 1.5 The pre-existing detached transport (this is what §3 reuses)

```
MemberSignature { member_slot: u8, pk_g: Bytes32, signature: SignatureBytes }   src/common/channel.rs:415-426
sign_state(keys, slot, state) -> MemberSignature                                src/wallet_core.rs:822-828
  └─ sign_digest -> encode_cosign_blob(sig, h)  = v1 || salt(40) || s2(625) || h(1024) = 1690 B
                                                                                src/wallet_core.rs:245-248,
                                                                                src/falcon_sig/mod.rs:407-419, :96
verify_state_sig(pk_g, digest, blob) -> verify_cosign_blob                      src/wallet_core.rs:265-268,
                                                                                src/falcon_sig/mod.rs:464-474
decode_cosign_blob(blob) -> (FalconSignature, [u16; FALCON_N])                  src/falcon_sig/mod.rs:428-456
verify_with_pk_g(pk_g, h, digest, sig)                                          src/falcon_sig/mod.rs:512-525
add_signature / verify_all_signatures                                           src/wallet_core.rs:855-861, :873-899
validate_all_member_signatures (structural: slot order, pk_g, fixed 1690 B)     src/common/channel.rs:1452-1468
```

`decode_cosign_blob` → `verify_with_pk_g` → `FalconAggWitness::for_signatures` is a complete path
from a wire blob to the aggregation witness. Nothing new has to be invented.

---

## 2. Threat model (written before the design, per CLAUDE.md)

### 2.0 Assets, actors, trust boundary

**Assets.** (a) The channel's escrowed L1 funds, released by `finalizeClose` and the per-slot claims.
(b) The choice of *which* channel state is finalized (a stale state misallocates the pot between
members). (c) Liveness of close — funds are only recoverable through it.

**Actors.** N cosigning members (`member_count <= MAX_COSIGNERS = 16`, `src/constants.rs:131`);
delegates (never co-sign state — `src/wasm_wallet.rs:747-752`); the **coordinator** (the party that
assembles the witness, proves, and submits — today, the API host); L1.

**Trust boundary today.** One process (the API host) holds/derives all N keys, holds the single
bearer token, and holds the L1 deposit key (`src/bin/channel_member.rs:542`). It is a single point of
total compromise for the channel.

### 2.1 T-0 (CRITICAL, pre-existing, and a precondition for this whole effort) — cosigner keys are publicly derivable

As established in C-4: `CLI_COSIGNER_SEED_BASE = 0xC1_0000` (`src/bin/channel_member.rs:349`) is a
public constant, `keys_for` is `StdRng::seed_from_u64(seed)` (`:335-337`), and `MemberKeys::generate`
is deterministic by design and by documented contract (`src/wallet_core.rs:171-200`). The delegate
seed defaults to the integer `1` (`src/bin/channel_member.rs:380-384`).

**Consequence.** For any channel driven by this CLI/API (which includes the live demo channels), an
arbitrary internet party can reconstruct every cosigner's Falcon secret key, forge the N-of-N
signature set over any `ChannelState` they can construct, and produce a valid close proof. The
in-circuit gates do not help: they check that N *registered* keys signed, and the attacker holds
those keys.

**Relevance to this design.** Detaching signature *collection* while the keys remain publicly
derivable is security theatre. The two must be sequenced (§8.1). This is stated first because it is
the single largest finding of this investigation and it was not in the problem statement.

Note for contrast: the browser wallet is fine. `wallet_keygen` draws from the OS CSPRNG
(`src/wasm_wallet.rs:87-90`); `wallet_keygen_seeded` (`:102`) is explicitly documented as
testnet-only with the seed in the caller's localStorage (`:95-99`).

### 2.2 What an adversary gains from the current design, assuming T-0 were fixed

| ID | Capability | Reachable by | Bounded by |
|---|---|---|---|
| A-1 | Close the channel at **any state the host ever held**, at any time | anyone with the API bearer token, or code execution on the host | L1 era fence + challenge ordering (§2.4); cancel-close if another party notices |
| A-2 | Close at a **stale** state, misallocating the pot | same | `cancel-close` (`src/circuits/channel/cancel_close_circuit.rs:465-467`) — but that requires *another* party to hold a later state and be able to prove it, which today no other party can (they'd need N keys too) |
| A-3 | Choose `close_nonce`, `burn_tx_hash`, `snapshot_medium_block_number` freely | same (env `CLOSE_NONCE` / `CLOSE_BURN_TX` / `CLOSE_SNAPSHOT_MBN`, `src/bin/channel_member.rs:858-863`) | see T-5 — these are **not** covered by any member signature |
| A-4 | Route claims to an arbitrary `recipient` | any bearer-token holder (`api/routes/close.js:141`, `:156`) | the contract requires the claim caller be the proof-bound recipient; the recipient itself is bound to the cosigner-signed slot leaf (B-1b) |
| A-5 | Forge a *new* state entirely (not merely replay an old one) | code execution on the host, since it can sign any state | nothing off-chain; only the balance-proof/backing checks in the transition verifiers, which the host also runs |

A-5 is the qualitative point: with all N keys in one place, the "N-of-N" property is vacuous. Every
soundness argument in `close_circuit.rs` that ends "…so the members must have signed it" degrades to
"…so the API host must have wanted it".

### 2.3 New attack surface introduced by a detached-signature protocol

Enumerated as requested. Each is analysed against the **recommended** design (§3, Option A: reuse the
signatures already in the state) and against the alternative (Option B: a fresh close-signing round).

**T-1 — Signature replay across channels / eras / digests.**
The signed message is `ChannelState::signing_digest()` (`src/common/channel.rs:579-603`), whose
preimage opens with `CHANNEL_STATE_DOMAIN` and includes `channel_id` (`:583`), `epoch` (`:584`),
`small_block_number` (`:585`), **`close_freeze_nonce`** (`:586`), `balance_state.h1()` (`:594`),
`prev_digest` (`:597`), `h2_tag` (`:598`) and `state_version` (`:599`). So a signature is
cryptographically bound to (channel, era, version, full balance commitment).
*Cross-channel:* closed by `channel_id` in the preimage **and** by the close PI limb 0 strict bind on
L1. *Cross-era:* closed by `close_freeze_nonce` in the preimage. *Cross-digest (IMCH vs IMSB vs
IMCI):* closed by the leading domain constant — this is exactly TM-C6 in
`doc/tasks/falcon-sig-threat-model.md:146-155`, and there is an explicit negative test
(`src/circuits/channel/close_circuit.rs:2134-2143`, `channel_close_circuit_rejects_cross_context_agg_message`).
**Verdict: no new exposure.** Option A adds nothing because the signature was already published
inside the state object, which already circulates over HTTP (`api/routes/channel-send.js:11`).

**T-2 — Mix-and-match of signatures from different intents.**
The aggregation circuit forces **one shared message** across all slots: the leaf exposes its own
`message_digest` wire (`src/falcon_sig/agg.rs:269`), every level propagates it, and the close circuit
connects the top-level message to the single recomputed state digest
(`src/circuits/channel/close_circuit.rs:786-789`). Two signatures over *different* states cannot be
combined into one agg proof. **Verdict: closed in-circuit, unconditionally.** The coordinator gate
in §3.5 additionally rejects it early.

**T-3 — Split view (a malicious coordinator showing different digests to different signers).**
Under **Option A this threat does not exist for close**, because there is no close-time request: the
coordinator consumes signatures produced during the ordinary cosign round, which is already
split-view-resistant by construction — each member recomputes the digest from the state it verified
(`wallet_cosign`, `src/wasm_wallet.rs:717-741`) and each member's own head must be extended (`:718`).
Under **Option B**, a split view would let a coordinator collect signatures over *k* different
digests; but T-2 means those cannot be aggregated, so the only achievable outcome is a stall, which
is T-4. Mitigation regardless: the signing request must carry the **full `ChannelState`**, never a
digest (§3.4), so a member always recomputes.

**T-4 — Partial-collection stalling / griefing.**
Under **Option A: not applicable.** The signature set is complete or the state was never a valid head
— `verify_all_signatures` (`src/wallet_core.rs:873-899`) is the gate on adopting a head
(`cmd_finalize`, `src/bin/channel_member.rs:3852`; `wallet_finalize`, `src/wasm_wallet.rs:760`).
Under **Option B**, a single silent member blocks close indefinitely.
This asymmetry is the strongest argument for Option A: **close liveness must not depend on members
being online**, because close is precisely the operation you need when they are not. The current
protocol already has this property; a naive detached redesign would destroy it.

**T-5 — Coordinator freedom over the unsigned close parameters (NEW FINDING, pre-existing).**
`close_nonce`, `burn_tx_hash` and `snapshot_medium_block_number` enter `CloseIntent`
(`src/common/channel.rs:1023-1037`) and the close PIs (limbs 1..3, 41..49, 65..67) but are **not** in
`ChannelState::signing_digest()`. The close circuit only folds them into the IMCI keccak
(`src/circuits/channel/close_circuit.rs:654-698`); nothing in-circuit ties them to a member
signature. So *any* coordinator — today's all-keys host, or tomorrow's detached one — chooses them
unilaterally.
Residual bound: L1 requires `intent.closeFreezeNonce == currentCloseFreezeNonce`
(`contracts/src/ChannelSettlementManager.sol:883`, `:899`) and enforces strict lexicographic
`(finalEpoch, finalStateVersion)` challenge ordering (`:1634-1637`).
**This is not fixable inside the recommended design** — binding those fields to member consent
requires members to sign the IMCI digest, i.e. a second signed message and a circuit change.
⇒ Owner decision §8.3. It must be written down that "N-of-N signed the close" today means "N-of-N
signed the *state*", not "N-of-N approved *this* close transaction".

**T-6 — Downgrade to fewer signers.**
Closed in-circuit: the aggregation proof's `signer_count` PI is connected to the close circuit's
`member_count` PI (`src/circuits/channel/close_circuit.rs:792-795`), `member_count` is `Σ active_bits`
with a floor of 1 (`:523-528`, `:538`), it is hashed into H1 (`:609-621`), and H1 is inside the
signed IMCH preimage (`src/common/channel.rs:594`). A prover cannot present k < N signatures without
producing a *different* H1, which the members did not sign. Additionally A5 distinctness
(`close_circuit.rs:863-872`) forbids padding one key N times. Explicit negative test:
`channel_close_circuit_rejects_undersigned_active_slot` (`close_circuit.rs:1666-1673`).
**Verdict: closed, and independent of who collects the signatures.**

**T-7 — Reusing a collected signature for a DIFFERENT close.**
This is the question the problem statement flagged, and the honest answer is uncomfortable:
*a signature over state S authorises **every** close at S, forever, at that era.* There is no
per-close nonce in the signed message. The only fences are:
  - the **era fence**: `close_freeze_nonce` is in the signed preimage (`src/common/channel.rs:586`),
    and `CloseIntent::new` sets `intent.close_freeze_nonce = state.close_freeze_nonce + 1`
    (`:1028`), which L1 compares against its own counter, incremented on each `requestClose`
    (`contracts/src/ChannelSettlementManager.sol:854`, checked at `:883`/`:899`);
  - the **version fence** for challenges (`ChannelSettlementManager.sol:1634-1637`);
  - `cancel-close`'s own era fence `revived.close_freeze_nonce + 1 == close.close_freeze_nonce`
    (`src/circuits/channel/cancel_close_pis.rs:115-119`, in-circuit at
    `src/circuits/channel/cancel_close_circuit.rs:470-472`).

  **T-7a (NEW FINDING — availability bug in the era fence).** Nothing in the wallet ever increments
  `ChannelState.close_freeze_nonce`. Every construction sets it to `0` or copies it from the previous
  state (`src/wallet_core.rs:696`, `:776`, `:2194`); the only `+ 1` in the whole tree is inside
  `CloseIntent::new` (`src/common/channel.rs:1028`) and the two cancel fences. Meanwhile L1 bumps
  `currentCloseFreezeNonce` on **every** `requestClose`
  (`contracts/src/ChannelSettlementManager.sol:854`). So after one cancelled close, the manager
  expects era 2 while the wallet can only ever produce era 1 ⇒ `InvalidFreezeNonce`, and the channel
  can never be closed again. This is the same class of unsatisfiable-era problem already documented
  for A45 partial-withdrawal cancel (`api/routes/partial-withdrawal.js:129-133`, which returns 501
  precisely for this reason). It bounds T-7's replay window to "one era" only by accident — it
  bounds *everything* to one era. Not caused by this design; must not be papered over by it.

**T-8 — Malicious/garbage signature submitted by a member or by a MITM.**
Rejected by the coordinator gate (§3.5) before any proving, and by the circuit regardless: the leaf
gadget is the *unconditional* verifier — there is no `verify` selector wire
(`src/falcon_sig/agg.rs:227-234`), so a leaf proof cannot exist for an invalid signature. The
transported `h` is untrusted and is bound to the authenticated `pk_g` inside `verify_with_pk_g`
(`src/falcon_sig/mod.rs:521`) and again in-circuit (`src/falcon_sig/gadget.rs:592`).
**Verdict: closed. But the coordinator gate must exist anyway**, so a bad input is a clear error at
millisecond cost instead of an opaque `prove()` failure after minutes.

**T-9 — Slot/identity confusion in the detached transport.**
A `MemberSignature` carries a self-declared `member_slot` and `pk_g` (`src/common/channel.rs:417-425`),
both attacker-controlled on the wire. Existing mitigation: `verify_all_signatures` requires
`sig.pk_g == record.member_pk_gs[slot]` (`src/wallet_core.rs:890`) and
`validate_member_signature_slots` requires exact slot ordering and no gaps
(`src/common/channel.rs:1491-1502`). **The new gate must do the same, against the authenticated
`ChannelRecord` and not against the state's own claims.**

**T-10 — Count-source mismatch (NEW FINDING).** The close prover derives N from
`state.balance_state.member_count` (`src/wallet_core.rs:3431`) while every signature-validation
helper derives it from `record.member_count` (`src/common/channel.rs:1484`,
`src/wallet_core.rs:882`). I found **no site anywhere that asserts these two are equal** — genesis
copies one into the other (`src/wallet_core.rs:785`) and nothing re-checks it afterwards. Today this
is masked because the same process produces both. In a detached design the record and the state
arrive from different places, so the new gate **must** assert
`record.member_count == state.balance_state.member_count`, fail-closed. (Soundness is still held
in-circuit by H1, which commits `member_count`; this is a fail-closed hygiene requirement, not a
soundness hole.)

**T-11 — Replay of a *whole signed state* as a close of a different channel's manager.**
The close PI limb 0 is `channel_id` and is strict-equality bound on L1
(`contracts/src/ChannelSettlementVerifier.sol`, close-limb bind), and each manager is per-channel.
Unchanged by this design.

**T-12 — Timing/side channels.** Signing moves *out* of the coordinator process under this design;
`FalconKeys::sign` and its sampler remain unchanged (`src/falcon_sig/mod.rs:196-233`). TM-C4 applies
unchanged. Verification (`verify_with_pk_g`) operates on public data only.

### 2.4 What is already closed and must stay closed

- Agg message ≡ recomputed IMCH state digest (`close_circuit.rs:786-789`;
  `cancel_close_circuit.rs:488-491`).
- Agg `signer_count` ≡ `member_count` ≡ `Σ active_bits`, and `member_count` ∈ H1 (`close_circuit.rs:792-795`,
  `:523-528`, `:609-621`).
- pk_g list is **read off the verified agg proof's PIs**, not witnessed (`close_circuit.rs:797-803`);
  `MemberCloseAuth` carries only `pk_g` (`close_circuit.rs:346-353`) and a disagreement makes witness
  generation fail rather than produce a proof (`close_circuit.rs:975-978`).
- A5 distinctness over pk_g (`close_circuit.rs:820-872`).
- `member_set_commitment` recomputed and overridden by `prove` (`close_circuit.rs:805-818`, `:874-876`).

### 2.5 Residual, accepted, or referred upward

T-0 (§8.1), T-5 (§8.3), T-7a (§8.4), plus the pre-existing set: R3 (no in-circuit
`Σ slot balances <= fund`), DLG-2, A-1 of `b2-delegate-close-threat-model.md` (unbacked delegate
contributions), and the absence of per-caller authorization in `api/` (§8.2).

---

## 3. The design

### 3.1 Core insight

The close prover should never see a key. It should take, per active slot, a **verified detached
authorization** — and the natural, already-existing carrier for that is `MemberSignature`
(`src/common/channel.rs:415-426`), whose `signature` field is the 1690-byte cosign blob decodable to
exactly the `(h, sig)` pair `FalconAggWitness::for_signatures` wants.

Because the close digest **is** the state digest (§0 C-1), the N-of-N set already sits in
`state.member_signatures` of the very `ChannelState` the caller passes in. The close prover currently
throws that away and re-mints equivalent signatures.

### 3.2 Options

**Option A — detached prover input, sourced from the state's own cosignatures. (RECOMMENDED.)**
`build_full_witness` takes `&[MemberSignature]`; `cmd_close` passes `state.member_signatures`. No new
round, no new endpoint, no liveness dependency, no split-view surface, zero semantic change (§0 C-1
proves the signatures are interchangeable). Removes the key parameter from the production close path
entirely.

**Option B — detached prover input plus an explicit close-signing round.** Same prover change, but
the coordinator asks each member to freshly sign the head IMCH digest at close time. Cryptographically
identical output (the circuit cannot tell), but adds T-3 and T-4 surface, and makes close liveness
depend on members being online — the opposite of what unilateral close is for.
*Only* worth it if the owner wants close to be an explicit, observable member decision. It does **not**
give members veto power in any meaningful sense, because the old signatures remain valid forever
(T-7).

**Option C — a genuinely close-specific member authorization** (members sign `CloseIntent::signing_digest()`,
so `close_nonce`/`burn_tx_hash`/`snapshot_medium_block_number` become member-approved, closing T-5).
This changes the digest the agg circuit binds ⇒ **circuit change ⇒ new close VK ⇒ full fixture and
on-chain redeploy.** Out of scope here. ⇒ §8.3.

**Recommendation: Option A, with the transport type defined so Option B is a pure superset** (a
future `close-sign` command produces the same `MemberSignature` the prover already accepts).

### 3.3 The prover split

```rust
// src/wallet_core.rs — replaces falcon_member_auth_for_digest's key-taking half.

/// A member's DETACHED authorization for `digest`: the registered identity plus the wire cosign
/// blob (`v1 || salt || s2 || h`). Carries no secret material. This is exactly the shape of
/// `common::channel::MemberSignature` — reuse that type rather than minting a parallel one.
type DetachedAuth = MemberSignature;   // { member_slot: u8, pk_g: Bytes32, signature: Vec<u8> }

/// Verify + decode N detached authorizations into the aggregation witness.
/// Replaces the signing half of `falcon_member_auth_for_digest` (src/wallet_core.rs:3364).
fn falcon_member_auth_from_signatures(
    record: &ChannelRecord,          // AUTHENTICATED member set — never the state's own claims
    sigs: &[MemberSignature],
    digest: Bytes32,
) -> WResult<(Vec<Bytes32>, FalconAggWitness)>;
```

Signature of the new entry points (both provers, symmetric):

```rust
impl CloseProver {
    pub fn build_full_witness_from_signatures(
        &self,
        record: &ChannelRecord,
        state: &ChannelState,
        member_sigs: &[MemberSignature],
        balance_proof: ProofWithPublicInputs<F, C, D>,
        close_nonce: u64,
        burn_tx_hash: Bytes32,
        snapshot_medium_block_number: u64,
    ) -> WResult<ChannelCloseFullWitness<F, C, D>>;
}

impl CancelCloseProver {
    pub fn build_full_witness_from_signatures(
        &self,
        record: &ChannelRecord,
        revived_state: &ChannelState,
        member_sigs: &[MemberSignature],
        close_intent: &CloseIntent,
    ) -> WResult<CancelCloseFullWitness<F, C, D>>;
}
```

`record` is a **new required parameter** and that is deliberate: without it the coordinator has no
authenticated member set to bind slots and `pk_g` to (T-9), and today's key-taking API smuggles that
authentication in by construction. Callers already hold it (`st.snapshot.record`,
`src/bin/channel_member.rs:867`).

Everything downstream of `falcon_member_auth_*` is unchanged: `MemberCloseAuth { pk_g }` list
(`src/wallet_core.rs:3479-3480`), `self.agg.prove(&agg_witness)` (`:3481-3484`), the returned
`ChannelCloseFullWitness`. The existing `FalconAggWitness::for_signatures` (`src/falcon_sig/agg.rs:212`)
is used verbatim.

The old key-taking methods become **thin deprecated wrappers** (sign-then-delegate) so the detached
path is the only real implementation, then are deleted in Phase 2 (§6).

### 3.4 Signing-request payload (needed only for Option B / for a future `close-sign` CLI)

The member **must** be able to recompute the digest. Concretely they need everything
`ChannelState::signing_digest()` hashes (`src/common/channel.rs:579-603`), which means the whole
`ChannelState` — plus enough context to decide whether signing is *correct*, not merely well-formed:

```jsonc
// CloseSigningRequest — proposed wire type. Nothing here is trusted by the signer.
{
  "record":  { /* ChannelRecord — the signer MUST compare signing_digest() to its OWN trusted record */ },
  "state":   { /* full ChannelState; the signer recomputes signing_digest() and IGNORES state.digest */ },
  "context": {                       // ADVISORY ONLY — see the warning below
    "closeNonce": 1,
    "burnTxHash": "0x…",
    "snapshotMediumBlockNumber": 1,
    "manager": "0x…",
    "chainId": 31337
  }
}
```

Explicitly **not** in the request: any digest, any hash, any "please sign this 32-byte value". A
coordinator-supplied digest is exactly the split-view lever (T-3) and must never be accepted.

Signer-side checks before signing (mirroring `wallet_cosign`, `src/wasm_wallet.rs:717-741`):
1. `record.signing_digest()` equals the signer's own trusted record's — bind the member set.
2. Recompute `state.signing_digest()`; require it to equal `state.digest`
   (`src/wallet_core.rs:879-881` does the same).
3. `state.prev_digest == my_head.digest`, or `state == my_head` — never sign a state that does not
   extend what this member believes.
4. Own slot decrypts at every active token position (`src/wasm_wallet.rs:234-243`).
5. `slot < record.member_count` — delegates must refuse (`src/wasm_wallet.rs:745-752`).

**Warning that must appear in the code and in any UI:** `context` is *not covered by the signature*
(T-5). A member signing this request is authorizing "state S may be closed at", not "close with these
parameters". Presenting it as consent to the close transaction would be a lie.

**Response payload:** exactly `MemberSignature` as it already serializes
(`#[serde(rename_all = "camelCase")]`, `src/common/channel.rs:415-416`) — `{ memberSlot, pkG,
signature }`, the `signature` being the 1690-byte blob. Identical to what `wallet_cosign` and
`wallet_sign_state` already return.

### 3.5 The coordinator's pre-proving gate (fail-closed, cheap)

Runs entirely before `agg.prove()` (which is the expensive step). Order matters: identity binding
before cryptography, cryptography before proving.

1. `record.validate()`; assert `record.member_count == state.balance_state.member_count` — **T-10**.
2. `state.digest == state.signing_digest()` — reject a state whose cached digest lies
   (`src/wallet_core.rs:879-881`).
3. `validate_all_member_signatures(record, sigs)` (`src/common/channel.rs:1452`): exactly
   `member_count` entries, slot-ordered `0..member_count`, `sig.pk_g == record.member_pk_gs[slot]`,
   each blob exactly `FALCON_COSIGN_BLOB_BYTES` (`src/falcon_sig/mod.rs:96`).
4. Per slot: `decode_cosign_blob` (`src/falcon_sig/mod.rs:428`) → `(sig, h)`; then
   `verify_with_pk_g(record.member_pk_gs[slot], &h, digest, &sig)` (`src/falcon_sig/mod.rs:512`) —
   **the existing cheap gate the problem statement identified, ~64 µs/sig**, and it re-checks
   `falcon_pk_digest(h) == pk_g` internally (`:521`) so the transported `h` cannot substitute an
   identity. Never call bare `verify` here (review F-2, `src/falcon_sig/mod.rs:506-511`).
5. pk_g pairwise distinctness (mirrors the existing early check at `src/wallet_core.rs:3446-3454`;
   A5 is the real gate, `close_circuit.rs:863-872`).
6. Build `FalconAggWitness::for_signatures(digest, &[(&h_i, &sig_i)])` in slot order — the slot order
   **is** the pk-list order the close circuit consumes (`src/wallet_core.rs:3475-3476`).

Equivalently: step 3+4 together are exactly `verify_all_signatures`
(`src/wallet_core.rs:873-899`) plus a decode. Implementing the gate as "call `verify_all_signatures`,
then decode" is acceptable and preferable — one authenticator, not two.

**On a bad or missing signature:** return a `WalletError` naming the slot and the failure class
(missing / wrong slot order / wrong pk_g / wrong length / decode failure / verification failure).
Never proceed to prove; never fall back to deriving a key. Note that `FalconKeys::sign` self-verifies
(`src/falcon_sig/mod.rs:222-230`), so a *locally produced* signature failing this gate means key
material corruption — that error string should say so, as `src/wallet_core.rs:3377-3380` already does.

### 3.6 CLI / API surface

**Option A (recommended) — no new surface at all.**
- `cmd_close`: delete line `src/bin/channel_member.rs:872` (`cli_falcon_keys`); pass
  `&st.snapshot.record` and `&state.member_signatures` to the new entry point.
- `cmd_cancel_close`: same at `:1344`/`:1364`.
- Delete `cli_falcon_keys` (`:360-365`) once unused. `cli_cosigner_keys` stays (still used by
  `cli_active_keys`, `:375-386`, for registration public values).
- `api/routes/close.js` and `api/routes/full-withdrawal.js`: **unchanged**. Same argv, same env.

**Optional, additive (needed for Option B, useful for operations regardless):**
- CLI: `channel_member close-sign <state.json> <out_sig.json>` — signs the signer's own controlled
  slots only (loop over `state.controlled`, exactly like `cmd_cosign`, `:3135-3146`).
- CLI: `channel_member close --sigs <sigs.json>` — take the detached set from a file instead of from
  `state.member_signatures`, so an externally collected set can be used.
- wasm: `wallet_close_sign(state_json) -> MemberSignature` — a thin, checked wrapper reusing the
  `wallet_sign_state` validation set (`src/wasm_wallet.rs:212-247`) minus the genesis-only gate.
- API: `POST /api/v1/channel/:ch/close/sign` accepting a `CloseSigningRequest` and returning a
  `MemberSignature`. **Would require per-member authorization to be meaningful** (§8.2) — the current
  single shared bearer token (`api/lib/security.js:50-67`) cannot distinguish members.

---

## 4. What must NOT change

Say this loudly, because the design's whole value is that it is a **Rust-side plumbing change with no
cryptographic surface**:

- **The in-circuit gates are the soundness boundary.** Nothing in
  `src/circuits/channel/close_circuit.rs` or `cancel_close_circuit.rs` changes. Not one target, not
  one `connect`. The Rust gate in §3.5 is a fail-closed convenience, exactly as
  `src/wallet_core.rs:3359-3363` already documents.
- **The digest definition does not change.** `ChannelState::signing_digest()`
  (`src/common/channel.rs:579-603`) and `CloseIntent::signing_digest()` (`:1050-1076`) stay
  byte-identical. Members keep signing IMCH.
- **The PI layouts do not change.** Close stays 103 limbs (`src/circuits/channel/close_pis.rs:48`);
  cancel-close stays 27 (`src/circuits/channel/cancel_close_pis.rs:38`); the agg proof stays 137
  (`src/falcon_sig/agg.rs:162`).
- **The verifying keys do not change.** No circuit is rebuilt differently, so `close_vd()`
  (`src/wallet_core.rs:3517`), the wrapper, and the MLE VK are bit-identical. **No on-chain VK
  re-latch, no contract change, no redeploy.**
- **`MemberSignature`'s wire format does not change** (`src/common/channel.rs:415-426`), so no
  browser, snapshot or API payload schema moves.

If any future revision of this design would touch the list above, that is Option C, and it is a
different, much larger project (§8.3).

---

## 5. Migration and compatibility

**The test CLI can keep its seed-derived keys — yes, and it should, as a thin wrapper.** Concretely:
the demo CLI signs first (`sign_state`, `src/wallet_core.rs:822`) and then calls the detached path.
But note that under Option A it does not even need that: the head state loaded by `cmd_close`
(`src/bin/channel_member.rs:867-868`) already carries a complete, verified N-of-N set, because every
route to becoming the head runs `verify_all_signatures` (`cmd_finalize`, `:3852`) or constructs the
full set (`create_channel`, `:2526`; `cmd_cosign`, `:3143-3146`). So the demo CLI simply stops
deriving keys on the close path. **That makes the detached path the only path — the stated goal.**

The unit tests (`src/wallet_core.rs:5686`, `:5922`) keep generating keys, sign the state, and call
the new entry point. That is the "sign then call detached" wrapper in test form, and it also becomes
the natural place for the new negative tests (§6 Phase 4).

**Fixture churn: essentially none, and this is the pleasant surprise.** The fixture generators do not
call these methods (§1.4): `generate_close_fixture` goes through
`close_circuit::test_fixture::build_close_full_witness_two_token`
(`src/bin/generate_close_fixture.rs:143` → `src/circuits/channel/close_circuit.rs:1437`) and
`generate_cancel_close_fixture` through `cancel_close_circuit::test_fixture::build_full_witness`
(`src/bin/generate_cancel_close_fixture.rs:63`). Both operate on `&[FalconKeys]` inside a
feature-gated test module and are unaffected.

Combined with §4 (no VK change), the checked-in artifacts stay valid:
`contracts/test/data/close_intent.json`, `close_intent_mle.json`, `cancel_close.json`,
`cancel_close_mle.json`, the `close_lifecycle*` quartet, `withdrawal_claim*`, `post_close_claim*`,
and the deliberately-stale `sepolia_*` set. **No 39 GB regeneration run is required**
(cf. `doc/tasks/falcon-sig-phase5-notes.md:85-97`).

What does churn: the two unit tests above; any snapshot of `cmd_close`'s stderr in the CLI E2Es
(`tests/close_lifecycle_cli_e2e.rs:361`, `tests/two_token_cli_e2e.rs:488` — they assert on
`"close intent submitted"` / `"submitCloseIntent OK"`, which is unaffected); and the two doc comments
at `src/wallet_core.rs:3408-3421` / `:3761-3765`.

---

## 6. Phased plan

Every phase has a falsifiable acceptance criterion. **No phase in 1–4 forces fixture regeneration**;
that is called out explicitly per phase.

### Phase 0 — Owner sign-off. No code.
Decide §8.1 (T-0 sequencing), §8.2 (per-member API authz), §8.3 (Option A vs C, and the T-5
disclosure), §8.4 (T-7a era-fence bug), and Option A vs B.
**Accept when:** §8 is answered in writing in this file.

### Phase 1 — Detached entry points beside the existing ones. Additive only.
Add `falcon_member_auth_from_signatures` and both `build_full_witness_from_signatures` methods (§3.3),
with the full §3.5 gate. Keep the key-taking methods, reimplemented as sign-then-delegate wrappers.
**Accept when, all falsifiable:**
- (1a) A test proves the two paths are equivalent: build a witness both ways from the same state and
  assert the resulting close proofs have **identical public inputs** (they must — the circuit is
  signature-blind, `src/falcon_sig/agg.rs:269-274`). This is the empirical confirmation of C-1; if it
  fails, the whole design premise is wrong and work stops.
- (1b) `CloseProver::close_vd().common` digest and `CancelCloseProver::vd().common` digest are
  byte-identical to `main`'s. Falsifies any accidental circuit change.
- (1c) `cargo test --release -p intmax3-zkp --lib close` and `… cancel_close` green.
- **Fixtures: untouched.**

### Phase 2 — Make the detached path the only path.
Rewrite `cmd_close` (`src/bin/channel_member.rs:872`, `:885`) and `cmd_cancel_close` (`:1344`, `:1364`)
to pass `&st.snapshot.record` + `&state.member_signatures`. Delete `cli_falcon_keys`
(`src/bin/channel_member.rs:360-365`) and the key-taking prover methods.
**Accept when:**
- (2a) `rg 'FalconKeys|falcon_key' src/bin/channel_member.rs` returns **zero** hits inside `cmd_close`
  and `cmd_cancel_close`.
- (2b) `rg 'Borrow<FalconKeys>' src/wallet_core.rs` returns zero hits.
- (2c) `cargo test --test close_lifecycle_cli_e2e --release -- --ignored` green (this is the real
  end-to-end proof that a close still lands on-chain).
- (2d) `cargo test --test two_token_cli_e2e --release -- --ignored` green.
- **Fixtures: untouched** — verified by `git status contracts/test/data` being clean after (2c)/(2d).

### Phase 3 — Prove the split deployment actually works. (The point of the whole exercise.)
Add an integration test that runs close with the signing keys *absent from the proving process*:
construct a head state whose `member_signatures` were produced by N independent `MemberKeys`
instances, drop the keys (`FalconKeys` is deliberately non-`Clone`, `src/wallet_core.rs:155-158`),
then prove.
**Accept when:**
- (3a) The test compiles and passes with no `FalconKeys` in scope at the `build_full_witness_from_signatures`
  call site.
- (3b) A companion negative: removing one slot's signature ⇒ error at the §3.5 gate naming that slot,
  and **no proof is produced** (assert the error, not a panic).
- **Fixtures: untouched.**

### Phase 4 — Adversarial test suite for the new gate.
Per CLAUDE.md §4 categories. Each test states what it proves about security:
- (4a) T-9: a signature whose `pk_g` is not `record.member_pk_gs[slot]` ⇒ reject.
- (4b) T-9: correct `pk_g`, wrong `member_slot` / out-of-order / duplicated slot ⇒ reject.
- (4c) T-2: a signature over a *different* state's digest ⇒ reject (native gate) and, separately, ⇒
  the agg proof cannot be built for a mixed message set.
- (4d) T-1: a valid signature from a **different channel_id** state ⇒ reject.
- (4e) T-1: a valid signature from the **same state at a different `close_freeze_nonce`** ⇒ reject.
- (4f) TM-C8: a `SingleSigCircuit`-era blob and a truncated/over-long blob ⇒ reject on the version
  byte / length (`src/falcon_sig/mod.rs:431-441`).
- (4g) T-8: a blob carrying an attacker's `h` for a registered `pk_g` ⇒ reject inside
  `verify_with_pk_g` (`src/falcon_sig/mod.rs:521`).
- (4h) T-10: `record.member_count != state.balance_state.member_count` ⇒ reject.
- (4i) T-6 regression: the existing `channel_close_circuit_rejects_undersigned_active_slot`
  (`src/circuits/channel/close_circuit.rs:1666`) still passes.
- (4j) Property test: 100+ random valid sets prove; 100+ random single-field mutations reject.
**Accept when:** all green, and each has a comment naming the threat ID it closes.
- **Fixtures: untouched.**

### Phase 5 — (Conditional on §8.1) Real key provenance.
Replace `CLI_COSIGNER_SEED_BASE` derivation with per-member key material that is generated once from
a CSPRNG and stored outside the repo (the browser wallet already does this correctly —
`src/wasm_wallet.rs:87-90`). Re-key the live channels.
**Accept when:** `rg 'CLI_COSIGNER_SEED_BASE' src/` has no hit on a production close/cosign path; the
live channels' `pk_g` values differ from those derivable from `0xC1_0000 + slot`.
- **⚠️ FIXTURE/DEPLOY IMPACT: heavy.** Changing member identities changes `member_set_commitment` and
  the registration record, which is the co-generation constraint recorded at
  `src/circuits/test_utils/block_witness_generator.rs:236-242` and
  `contracts/test/CloseLifecycleE2E.t.sol:102`. If test-fixture identities are also touched, the full
  ordered regeneration chain of `doc/tasks/falcon-sig-phase5-notes.md:85-97` applies (peak ~39 GB).
  **It is possible and strongly preferable to re-key only the LIVE channels and leave the
  deterministic test-fixture identities alone** — they are legitimately deterministic test vectors.
  That keeps this phase's fixture cost at zero.

### Phase 6 — (Optional, only if §8.1/§8.2 chose it) Collection surface.
`close-sign` CLI subcommand, `wallet_close_sign` wasm export, `POST /close/sign` with per-member auth.
**Accept when:** a three-process test (three separate CLI working dirs, each holding one slot's key)
produces a close proof; no process ever holds two keys.
- **Fixtures: untouched.**

---

## 7. Adversarial pass

Taking the attacker's side against Option A, reported regardless of confidence (CLAUDE.md §2).

- **X-1 (the strongest objection).** "Reusing the cosign signature conflates *agreeing a state* with
  *authorizing a close*." True — but it is already conflated: the circuit binds the agg message to the
  state digest (`close_circuit.rs:786-789`) and nothing else, and the current key-taking prover mints
  a fresh signature over that same digest, which any holder of the keys can do at will. Option A adds
  **zero** capability. What it does is make the pre-existing conflation *visible*, which is a reason
  to document it (§8.3), not a reason to reject the design.
- **X-2.** "A member who wants to stop a close can refuse to sign." False today and false under
  Option A: refusal happens at the state-agreement layer only; once a member has cosigned state S,
  every close at S is authorized forever within the era (T-7). Under Option B it would *look* like a
  veto without being one — a UI that implied otherwise would be actively misleading.
- **X-3.** A coordinator hoards an old fully-signed state and closes at it later. Possible today and
  under Option A alike. Defences: the L1 grace window (`GRACE_BEFORE_PROCESS_SECS`, checked at
  `contracts/src/ChannelSettlementManager.sol:894-897`), the challenge period, and `cancel-close`.
  Under a *split* deployment `cancel-close` finally becomes usable by a party other than the
  coordinator — which is a **security improvement** delivered by this design, and worth stating: today
  no honest member can cancel, because cancelling also needs all N keys
  (`src/bin/channel_member.rs:1344`).
- **X-4.** Malleability: could an attacker mutate a member's blob into a different valid one and gain
  anything? The blob encoding is bijective by construction (`src/falcon_sig/mod.rs:355-369` re-encode
  check; `:398-401`), and the circuit is signature-blind anyway, so even a successful re-encoding
  changes nothing observable. Note the flip side: **nothing binds "this specific signature was
  consumed"**, so there is no per-signature nullifier to build a "sign once per close" scheme on
  without a circuit change.
- **X-5 (implementation hazard).** Reading `state.member_signatures[i]` positionally instead of
  looking up by `member_slot` would let a reordered array bind slot i's `pk_g` to slot j's signature.
  `validate_member_signature_slots` (`src/common/channel.rs:1491-1502`) forbids reordering — the new
  gate must call it *before* any indexing, and must index the **record**, not the state, for `pk_g`.
- **X-6 (implementation hazard).** Deriving N from the state (`src/wallet_core.rs:3431`) while
  validating against the record (`src/common/channel.rs:1484`) — T-10. If they disagree and the code
  takes the larger, it indexes out of bounds; if it takes the smaller, it silently proves a different
  member set than validated. Assert equality first.
- **X-7.** Could a delegate's signature be smuggled in? `validate_member_signature_slots` requires
  exactly `record.member_count` entries at slots `0..member_count`
  (`src/common/channel.rs:1485-1497`), delegates live at `member_count..`, and `wallet_cosign` refuses
  to sign from a delegate slot (`src/wasm_wallet.rs:745-752`). Closed at three layers.
- **X-8.** Cross-protocol: could an IMSB small-block signature (also Falcon, also this member's key —
  `src/circuits/test_utils/block_witness_generator.rs:1043-1044`) be presented as a cosignature?
  Domain-separated preimages (TM-C6); explicit in-circuit negative test at
  `src/circuits/channel/close_circuit.rs:2134-2143`. Add the *native*-gate counterpart as (4c).
- **X-9.** Nothing in this design touches the transcript/Fiat-Shamir surface of the MLE/WHIR wrapper:
  the close proof's PIs are unchanged (§4), so `wrap_and_export_mle` (`src/wallet_core.rs:3530`) sees
  an identical input distribution. The CLAUDE.md Fiat-Shamir checklist has no items in scope for this
  change — stated explicitly so the absence is a finding, not an omission.
- **X-10 (found in passing, out of scope).** `api/routes/close.js:141`, `:156` and `:175`, `:180` take
  a caller-supplied `recipient` with no binding to the caller; the only defence is that
  `claimWithdrawalCredit` pays `msg.sender`. Worth its own item.
- **X-11 (found in passing).** `api/routes/close.js:2-3` imports `fs`, `wc`, `rollupOf`, `readJson`
  and uses none of them. Cosmetic.

No attack was found that Option A enables and that the current key-taking design prevents.

---

## 8. Owner decisions (do not decide these silently)

**8.1 — Sequencing against T-0 (the publicly derivable cosigner keys).** This is the highest-severity
finding in this document and it is *independent* of the refactor. Options: (i) fix T-0 first, ship
detached signing after — correct but slower; (ii) ship detached signing first (it is a safe, VK-neutral
refactor that makes T-0's fix *possible*, since a split deployment is only expressible once the prover
stops taking keys); (iii) both in one change. **My recommendation: (ii), immediately followed by (i),
with T-0 recorded as a known-critical against the live deployment in the meantime** — the refactor is
a prerequisite for any real fix and cannot make T-0 worse. But "how long the live channels run with
publicly derivable keys" is a risk-acceptance call, not mine.

**8.2 — Per-member authorization in the API.** A `POST /close/sign` endpoint (Phase 6) is meaningless
under one shared bearer token (`api/lib/security.js:50-67`). Either members sign out-of-band (CLI /
browser, no API change — the Option A default), or the API grows real per-member identity. Which?

**8.3 — Disclose or close T-5.** Members do not authorize `close_nonce`, `burn_tx_hash` or
`snapshot_medium_block_number`. Option A leaves that true and *documents* it; Option C makes it false
at the cost of a new signed digest, a circuit change, a new close VK, full fixture regeneration and an
on-chain redeploy. **Recommendation: document now (a `// SECURITY:` note at
`src/wallet_core.rs:3456-3468` and in the `CloseSigningRequest` type), and file Option C separately.**

**8.4 — T-7a, the era-fence availability bug.** The wallet never increments
`ChannelState.close_freeze_nonce` while L1 increments `currentCloseFreezeNonce` on every
`requestClose` (`contracts/src/ChannelSettlementManager.sol:854`), so a channel appears to be
permanently unclosable after one cancelled close. This is the same unresolved era-fence interaction
that keeps A45 at 501 (`api/routes/partial-withdrawal.js:129-133`). It is not caused by this design
and I did not attempt to fix it. In scope for this work, or its own item?

**8.5 — Option A vs Option B.** A (reuse; no round; keeps unilateral-close liveness) or B (explicit
close-signing round; adds T-3/T-4; gives no real veto per X-2). **Recommendation: A**, with the
transport shaped so B is a later superset.

---

## 9. What this design does NOT fix

- T-0 — publicly derivable cosigner keys (§8.1; Phase 5).
- T-5 — coordinator freedom over `close_nonce` / `burn_tx_hash` / `snapshot_medium_block_number`
  (§8.3).
- T-7 / T-7a — a cosignature authorizes every close at that state within the era; and the era counter
  desynchronization (§8.4).
- The absence of per-caller authorization in `api/` (§8.2, X-10).
- `build_channel_withdrawal`'s `Option<&[MemberKeys]>` (§1.4) — a separate, smaller "N public
  identities + 1 secret" fix on the base-layer withdrawal lane.
- R3 (no in-circuit `Σ slot balances <= channel fund`), DLG-2, and A-1 of
  `doc/tasks/b2-delegate-close-threat-model.md` — all unchanged and previously owner-flagged.
- The `cmd_cosign` / `cosign-burn-send` family still holding several members' keys in the demo CLI
  (`src/bin/channel_member.rs:3143`, `:3771`) — those paths are already key-count agnostic, so this is
  a deployment posture, not a code defect.

---

# 10. IMPLEMENTATION (Option A) — what was actually done

Implemented on `feat/falcon-poseidon-sig` (from HEAD `4574348`), **uncommitted**. Option A as
recommended in §8.5. No circuit, digest, PI layout or VK was touched; no fixture was regenerated.

Note on line numbers: §0–§9 above cite line numbers from HEAD `4574348`. The working tree carried
substantial uncommitted work from three other tasks (co-signer key provenance, the backing-deposit
tri-state guard, the replay-ledger strictness fix), all in `src/bin/channel_member.rs` and the CLI
E2E tests, so live line numbers are shifted. **None of that work was reverted or weakened.** In
particular the key-provenance fix's `keys_for` fail-closed behaviour and its
`INTMAX_COSIGNER_KEYFILE` / `INTMAX_INSECURE_DETERMINISTIC_KEYS` gate are intact and are now simply
unreachable from the close lifecycle.

## 10.1 C-1 was re-verified from source before any code was written

Every link asserted in §0 C-1 was independently confirmed against the working tree:

| Link | Where | Confirmed |
|---|---|---|
| `ChannelState.member_signatures: Vec<MemberSignature>` | `src/common/channel.rs` | yes |
| `sign_state` signs `state.signing_digest()` | `src/wallet_core.rs` (`let digest = state.signing_digest();`) | yes |
| the close prover binds `state.digest` | `CloseProver::build_full_witness` (`let digest = state.digest;`) | yes |
| `verify_all_signatures` asserts `state.digest == state.signing_digest()` | `src/wallet_core.rs` | yes |
| the agg leaf registers only `[message(8), 1, pk_g(8)]` | `src/falcon_sig/agg.rs` `FalconLeafCircuit::new` | yes |
| `salt` / `s2` / `h` are witnesses, never PIs | `src/falcon_sig/gadget.rs` `FalconSigVerifyTarget` | yes |
| the close circuit connects the agg message to the recomputed state digest | `close_circuit.rs` `agg_message.connect(..., state_digest)` | yes |
| `FalconAggWitness::for_signatures` takes `(&[u16; FALCON_N], &FalconSignature)` and never sees a key | `src/falcon_sig/agg.rs` | yes |

Then confirmed **empirically** by the Phase-1 gate (§10.5). No STOP condition arose.

## 10.2 Code changes

**`src/wallet_core.rs`**
- **Removed** `falcon_member_auth_for_digest<K: Borrow<FalconKeys>>` — the ~25 lines that took
  secret keys and minted signatures.
- **Added** `falcon_member_auth_from_signatures(record: &ChannelRecord, member_sigs:
  &[MemberSignature], digest: Bytes32) -> WResult<(Vec<Bytes32>, FalconAggWitness)>` implementing
  the §3.5 gate in the prescribed order: `validate_all_member_signatures` (which runs
  `record.validate()` itself) → per-slot `decode_cosign_blob` → `verify_with_pk_g` (never bare
  `verify`, review F-2) → pairwise `pk_g` distinctness → `FalconAggWitness::for_signatures` in slot
  order. The identity fed to verification and published in the pk-list is read off the
  **record**, never off the wire entry (T-9, X-5). Every failure path names the slot and the
  failure class.
- **Added** `assert_record_state_member_count_agree(what, record, state)` — the T-10 / X-6
  fail-closed check that `record.member_count == state.balance_state.member_count`, which nothing
  in the tree asserted before.
- `CloseProver::build_full_witness<K>` → **`CloseProver::build_full_witness_from_signatures(record,
  state, member_sigs, balance_proof, close_nonce, burn_tx_hash, snapshot_medium_block_number)`**,
  exactly the §3.3 signature. Also added the `state.digest == state.signing_digest()` gate (§3.5
  step 2), which the key-taking version did not need and did not have.
- `CancelCloseProver::build_full_witness<K>` → **`build_full_witness_from_signatures(record,
  revived_state, member_sigs, close_intent)`**, symmetric, with the same two new gates.
- `rg 'Borrow<FalconKeys>' src/wallet_core.rs` → **zero hits** (§6 Phase 2 criterion 2b).

**`src/bin/channel_member.rs`**
- `cmd_close`: no longer derives keys; passes `&st.snapshot.record` and `&state.member_signatures`.
- `cmd_cancel_close`: same, with `&revived_state.member_signatures`.
- **Deleted** `cli_falcon_keys` and its only caller-chain member `cli_cosigner_keys`. No
  close-lifecycle path in the binary derives a signing key (§6 Phase 2 criterion 2a).

**`api/routes/close.js`, `api/routes/full-withdrawal.js`**
- Argv and env **unchanged**, as §3.6 prescribes — the fix is entirely inside the CLI. Added a
  `SECURITY:` block at the top of `close.js` recording that the four heavy routes are no longer
  key-bearing, that `/request` never was, and that §8.2 (no per-caller authz) and T-5 (§8.3) remain
  open. `full-withdrawal.js`'s `/request` carries a pointer to it.

## 10.3 Deviations from the phased plan (three, all deliberate)

**D-1. The key-taking wrappers were not kept through Phase 1; Phases 1 and 2 were merged.**
§6 Phase 1 says "keep the key-taking methods, reimplemented as sign-then-delegate wrappers", and
Phase 2 then deletes them. That intermediate state is not expressible cleanly: the detached entry
point requires a `ChannelRecord` to bind slots and `pk_g` to (T-9), and a key-taking wrapper has no
record — it would have to synthesise the authenticated member set from the keys it holds, which is
precisely the smuggled-in authentication the record parameter exists to remove. Rather than write
code whose only purpose is to be deleted, the key-taking methods were removed in one step and the
tests sign inline before calling the detached entry point, which is what §5 already prescribes
("The unit tests keep generating keys, sign the state, and call the new entry point"). The
acceptance criteria of both phases are met (§10.5). **There is exactly one proving path.**

**D-2. The Phase-1 equivalence gate compares REUSED vs FRESHLY RE-SIGNED, through the one entry
point.** Following from D-1, "both paths" is realised as the two *semantic* inputs rather than two
*functions*: path A is the cosignature set collected at co-sign time (what `cmd_close` now passes),
path B is the same members signing the same digest again at close time (exactly what the retired
key-taking prover did internally). The test first asserts the two sets differ byte-for-byte —
Falcon's salt is randomized, so a re-signature is a genuinely different signature — and then
asserts the two close proofs' public inputs are identical. This is a *stronger* statement of C-1
than comparing two functions that would have shared the same downstream code.

**D-3. The `cli_falcon_identities_agree_across_close_register_and_withdraw` test was re-pointed,
not deleted.** It previously compared `cli_active_keys()` (what `export-reg-record` registers /
`withdraw` proves with) against `cli_falcon_keys()` ("what `close` signs with"). `close` signs with
nothing now, so that second producer no longer exists. The test now walks `cli_members()` — the
single function that both populates the `ChannelRecord` and persists the `ControlledMember.
keygen_seed` every co-signing command feeds to `keys_for` to mint `state.member_signatures`. The
invariant is checked one link earlier and one link wider (registered `pk_g` == co-signing identity
== withdraw/export identity), and it is now the link that matters: a divergence surfaces as the
close prover's §3.5 gate rejecting every cosignature on a `pk_g` mismatch, i.e. an unclosable
channel. No assertion was weakened; two were added.

Also worth recording, though not a deviation: the pre-existing unit test
`a3_close_prover_builds_and_verifies_real_close_proof` used to sign with three standalone
`FalconKeys` that were **not** the record's registered members, with a comment explaining that this
was fine because the test asserts nothing about an L1 member-set match. Under the detached entry
point that input is now impossible — the gate binds every signature to `record.member_pk_gs[slot]`.
The test uses the state's own cosignatures instead. That confusion being no longer expressible is
one of the concrete wins of the `record` parameter.

## 10.4 Tests added (§6 Phases 1, 3, 4)

All in `src/wallet_core.rs`'s test module. The ten `detached_gate_*` tests share one `LazyLock`
key fixture and run in ~14 s total; each names the threat ID it closes.

| Test | Phase / threat | What it proves about security |
|---|---|---|
| `close_detached_and_resigned_paths_yield_identical_close_public_inputs` | **1a** | C-1 empirically: byte-different signature sets ⇒ identical agg PIs **and** identical close PIs. The premise. |
| `close_proves_with_no_key_material_in_the_proving_scope` | **3a/3b** | A close proof built by a process holding no key; keys dropped before the prover exists. Plus: a missing slot is an error, and there is no key available to "fix" it with. |
| `detached_gate_accepts_the_states_own_cosignatures` | positive control | The honest input passes, and the published pk-list is the RECORD's, not the wire's. |
| `detached_gate_rejects_a_pk_g_that_is_not_the_registered_member` | 4a / T-9 | A valid signature by a non-member cannot join the N-of-N set. |
| `detached_gate_rejects_slot_reordering_duplication_and_gaps` | 4b / T-9, X-5 | Reorder / duplicate / gap / short set all rejected before any indexing; a k-of-N set is an error, never a smaller proof (T-6). |
| `detached_gate_rejects_cosignatures_over_a_different_state` | 4c / T-2 | Same members, different state ⇒ rejected; a mixed-message set names the offending slot. |
| `detached_gate_rejects_cosignatures_from_a_different_channel` | 4d / T-1 | `channel_id` ∈ IMCH preimage ⇒ cross-channel replay fence holds natively. |
| `detached_gate_rejects_cosignatures_from_a_different_close_era` | 4e / T-1, T-7 | `close_freeze_nonce` ∈ IMCH preimage ⇒ the era fence, in both directions. This is the only thing bounding T-7. |
| `detached_gate_rejects_legacy_versioned_and_wrong_length_blobs` | 4f / TM-C8, O-9 | Non-v1 version byte rejected by policy; truncated / over-long / empty rejected on the length gate. |
| `detached_gate_rejects_a_substituted_public_polynomial` | 4g / T-8 | An attacker's own `h` + own signature under a registered `pk_g` label is rejected inside `verify_with_pk_g` — i.e. the review-F-2 binding is actually being used. |
| `detached_gate_rejects_record_state_member_count_mismatch` | 4h / T-10, X-6 | The record/state count disagreement fails closed in both directions. |
| `detached_gate_rejects_random_single_byte_blob_mutations` | 4j | 200 single-byte mutations all rejected, plus a 200-iteration honest control so "rejects everything" cannot pass. This is the test that catches a gate that checks structure and forgets the cryptography. |

Existing negative tests were left untouched, including
`channel_close_circuit_rejects_undersigned_active_slot` (4i) and
`channel_close_circuit_rejects_cross_context_agg_message`.

## 10.5 Acceptance criteria — evidence

| Criterion | Result |
|---|---|
| §6 1a — identical close PIs both ways | **PASS**, 88.9 s |
| §6 1b — no circuit change ⇒ VK unchanged | **PASS** structurally: `git diff --stat` shows **zero** files under `src/circuits/`; `close_vd()` / `vd()` are derived from circuits that were not rebuilt differently. Not re-derived numerically — see UNVERIFIED below. |
| §6 1c — close / cancel-close lib tests | **PASS** (`a3_close_prover_builds_and_verifies_real_close_proof`, `a3_cancel_close_prover_builds_and_verifies`, + the keyless test: 3/3, 189.9 s) |
| §6 2a — no `FalconKeys` in `cmd_close` / `cmd_cancel_close` | **PASS**, both helpers deleted outright |
| §6 2b — `rg 'Borrow<FalconKeys>' src/wallet_core.rs` | **PASS**, zero hits |
| §6 3a/3b — keyless proving + named-slot negative | **PASS** |
| §6 4a–4j | **PASS**, 10/10, 13.6 s |
| §6 2d — `two_token_cli_e2e --ignored` | **PASS**, 1/1, 437 s. Real anvil + forge + `channel_member close` proving the DETACHED path end to end and landing `submitCloseIntent` on chain. |
| Fixtures untouched | **PASS**, `git status contracts/test/data` clean before AND after the E2E; `git diff --stat contracts/` shows no fixture change |
| `cargo check --release --lib --tests --bins` | **PASS**, no errors |
| `cargo fmt` | applied |
| `cd contracts && forge test` | **PASS**, 271 passed / 0 failed / 0 skipped, 18 suites |
| `cargo test --release --test inter_channel_cli` | **PASS**, 13/13 (includes the co-signer key-provenance fail-closed tests from the concurrent task — unaffected) |

**UNVERIFIED — §6 criterion 2c (`close_lifecycle_cli_e2e --ignored`).** A run of that test started by
an earlier session was still resident, hung for ~46 h at 0 % CPU inside `forge script
DeployCloseCli.s.sol`, with its anvil holding the port the test hard-codes (`PORT = 8554`,
`tests/close_lifecycle_cli_e2e.rs`). Starting a second one would have collided on that port, which is
the failure mode the task brief warned about. `two_token_cli_e2e` (port 8557, free) was run instead:
it drives the same `cmd_close` code path through the same CLI to a real on-chain
`submitCloseIntent`, so the detached path IS covered end to end — but 2c specifically has not been
re-run. The stale process was left alone rather than killed, since it belongs to another session.

**UNVERIFIED — §6 criterion 1b, numerically.** The claim "the close/cancel VK is bit-identical to
`main`'s" was established structurally (no file under `src/circuits/` differs; the provers' circuit
construction is untouched) rather than by dumping and diffing the two `common` digests against a
`main` checkout. Given the change is confined to how the aggregation WITNESS is assembled, and the
Phase-1 gate shows the resulting proofs' PIs are identical, a VK change would be very surprising —
but it was not measured.

## 10.6 Nothing in §8 was decided silently

This implementation is Phase 1–4 of §6 only. It does **not** touch T-0 (§8.1), T-5 (§8.3) or T-7a
(§8.4), and adds no collection surface (§6 Phase 6, §8.2). All four remain owner decisions. T-5 and
T-7 are now documented in code where the design asked for them (a `SECURITY:` note on
`falcon_member_auth_from_signatures` and on `build_full_witness_from_signatures`), per the §8.3
recommendation to "document now".

One capability is **gained**, and it is worth recording because it was listed as an argument for the
design rather than an outcome of it (X-3): cancelling a hostile close previously required all N
secret keys, so in practice only the coordinator could cancel — the very party a cancel defends
against. Any holder of a later co-signed head can now build the cancel proof with no key material.
