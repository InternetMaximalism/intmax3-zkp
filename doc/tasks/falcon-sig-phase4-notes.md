# falcon-sig Phase 4 — wallet / CLI / wasm / node swap to the native Falcon key

Branch `feat/falcon-poseidon-sig`, on top of `79f11ad` (Phase 3). **Not committed.**

Scope: `MemberKeys` becomes the Falcon key; the wallet co-sign becomes a native Falcon signature;
the retired Goldilocks proof-as-signature primitive is DELETED; the three Phase-3 seams are closed;
node/relay size premises are fixed; Solidity is re-run.

---

## 1. What was unified

### 1.1 `MemberKeys` carries the Falcon key (O-11, TM-C10)

`src/wallet_core.rs`:

```rust
pub struct MemberKeys {
    falcon_key: Arc<FalconKeys>,     // was: pub signing_key: GoldilocksSecretKey
    pub baby_key: BabyBearSecretKey,
    pub regev_pk: RegevPk,
    pub regev_sk: RegevSk,
}
```

- `generate(rng)` is byte-for-byte the same RNG choreography as before: it draws a 32-byte
  `sig_seed` FIRST (the same stream position the Goldilocks key used), then the BabyBear seed, then
  the Regev keypair. Only the consumer of `sig_seed` changed: `FalconKeys::from_seed(sig_seed)`,
  which internally derives its NTRU-keygen ChaCha20 seed as `keccak256(IMFG ‖ seed)` — the
  established Phase-0 domain separation (O-11). The seed is zeroized after use.
- **Determinism / cross-platform**: `wallet_keygen_seeded(hex)` and the CLI's `keys_for(u64)` both
  seed a `rand010::StdRng` (ChaCha-based, byte-stream-specified) and call `generate`. Everything
  downstream is integer/byte arithmetic (keccak → ChaCha20 → the vendored NTRU keygen), so native
  and wasm32 produce the same `h` / `pk_g`. `FalconKeys::from_seed` determinism itself is pinned by
  the Phase-0 test `keygen_from_seed_is_deterministic_and_seed_separated`.
  **NOT DONE — see STOP 3**: an actual native-vs-wasm32 execution comparison was not run.
- `pk_g()` is now `Poseidon(IMFK ‖ encode(h))`. Same 32-byte width, same slot everywhere.
  `pk_g_hash_out()` added for the Poseidon member tree.
- `falcon_key()` / `falcon_key_handle()` expose the key by reference / by refcount. **`Arc`, not a
  re-derivation**: NTRU keygen is ~455 ms, and — more important — a *second derivation* is exactly
  the pattern that produced the Phase-3 finding-7 identity split. Sharing the key OBJECT makes
  "the registered identity is the signing identity" true by construction.
- `MemberKeys` still has no `Serialize`; `FalconKeys` still has neither `Clone` nor `Serialize`.

`poseidon_sig::circuit::{C, D, F}` were the crate's plonky2 config aliases for `wallet_core`; that
module is gone, so the three aliases now live in `wallet_core` with the same (repo-standard) values.

### 1.2 The co-sign path is native Falcon

- `sign_state` → `sign_digest(keys.falcon_key(), &digest)` → `FalconKeys::sign` + `encode_cosign_blob`.
  ~5 ms; **no circuit is built and no proof is produced**.
- `verify_state_sig` → `falcon_sig::verify_cosign_blob(pk_g, digest, blob)`, which is
  `decode_cosign_blob` + **`verify_with_pk_g`** (the F-2 entry point that checks
  `falcon_pk_digest(h) == pk_g` INSIDE the call). The bare `verify` is never used on this path.
- `verify_all_signatures` is otherwise unchanged: it still recomputes `signing_digest()`, requires
  `state.digest` to match it, and requires each signer's `pk_g` to equal
  `record.member_pk_gs[slot]` before verifying against exactly that `pk_g`.
- `sign_state_if_backed`, `add_signature`, `verify_snapshot` unchanged.

Wire cost per co-signature: **~76 KB → 1,690 B**.

### 1.3 How the verifier obtains `h`, and why the binding is not weakened

**It travels inside the existing opaque `MemberSignature.signature: Vec<u8>` field.** New wire
format (`falcon_sig::encode_cosign_blob`, `FALCON_COSIGN_BLOB_BYTES = 1690`):

```
FALCON_SIG_V1 (1) ‖ salt (40) ‖ compressed s2 (625) ‖ h (1024 = 512 × u16 little-endian, each < q)
```

Why it has to travel at all: a verifier holds the signer's *authenticated identity*
`pk_g = Poseidon(IMFK ‖ encode(h))` (it is `ChannelRecord.member_pk_gs[slot]`, anchored by the
on-chain registration), but `pk_g` is a hash — `h` is not recoverable from it, and the Falcon
equation `s1 = c − s2·h` needs `h` itself. The alternatives were rejected:

| option | why not |
|---|---|
| widen `MemberInfo` with a 1 KB `pk_h` | wire-schema change on every JS/relay/CLI consumer, and STILL unauthenticated (`MemberLeaf` commits `pk_g`, not `h`) — so the digest check would be needed anyway |
| widen `MemberLeaf` / registration to commit `h` | breaks the "layouts do not change, only values" property (TM-C7) that the whole migration rests on; Solidity `bytes32 pkG` would have to grow |
| carry `h` in the signature blob | no schema changes anywhere; `h` is untrusted input that is *verified*, not trusted |

**The binding argument.** `h` arrives from the network and is treated as untrusted. It is only ever
consumed through `verify_with_pk_g`, which recomputes `falcon_pk_digest(h)` and requires equality
with the caller-supplied `pk_g` *before* the signature check. The caller-supplied `pk_g` is always
the AUTHENTICATED registered value (`verify_all_signatures` reads it from `record.member_pk_gs`,
never from the signature carrier — and separately requires `sig.pk_g == record.member_pk_gs[slot]`).
So:

- substituting an attacker's `(h', sig')` pair (internally consistent, verifies under the
  attacker's own `pk_g`) fails the digest comparison — pinned by
  `cosign_blob_rejects_substituted_or_malformed_public_keys` case (1), which also asserts the
  attacker's blob *does* verify under the attacker's own identity, so the rejection is about
  identity and not about the blob being malformed;
- tampering with a coefficient changes the digest — case (2);
- forging an `h` that hashes to a member's `pk_g` is a Poseidon preimage/collision under IMFK —
  assumption A-F4, unchanged from the day `pk_g` was defined.

This is the SAME check the in-circuit gadget performs (TM-C5 item 5: `h` is a witness there too,
range-checked, encoded, hashed, and connected to `pk_f`). The native verifier and the circuit now
agree on what "the member's key" means. **No weakening: `h` is a verifier convenience, never a
source of identity.**

Encoding bijectivity: the decoder rejects any coefficient `≥ q`, so exactly one 1690-byte string
decodes to any `(salt, s2, h)` (the 666-byte prefix was already bijective — Phase 0 added the
re-encode check for the s2 padding). This matters because signature BYTES feed keccak digests
downstream (`SignedSmallBlock::signing_digest`).

### 1.4 O-9 / TM-C8 downgrade rejection

- `decode_cosign_blob` checks the VERSION byte **first**, before length and before any structural
  parse, and returns the distinct `UnsupportedVersion` error. `verify_state_sig` surfaces it.
- A REAL legacy blob was captured before deleting the circuit and committed at
  `src/falcon_sig/testdata/legacy_single_sig_proof.bin` (77,872 B; provenance + exact reproduction
  recipe in `src/falcon_sig/testdata/README.md`). Its first byte is `0x52`.
- Tests: `falcon_sig::tests::legacy_single_sig_proof_blob_rejected_on_version_gate` (asserts the
  *specific* `UnsupportedVersion(0x52)` error from `decode_cosign_blob`, `FalconSignature::from_bytes`
  and `verify_cosign_blob`) and `wallet_core::…::legacy_single_sig_blob_rejected_by_verify_state_sig`
  (the wallet entry point, with a genuine-cosignature control so the rejection is not vacuous).
- Structural gate (TM-C8): `validate_all_member_signatures` moved from "non-empty" to the exact
  `FALCON_COSIGN_BLOB_BYTES`. See §4 for the one place that deliberately keeps the looser check.

---

## 2. Deletions and grep evidence

Deleted:

- `src/poseidon_sig/circuit.rs` — the whole file (`SingleSigCircuit`, `SINGLE_SIG_PUBLIC_INPUTS_LEN`,
  the `C/D/F` aliases, and its 6 tests).
- `poseidon_sig::GoldilocksSecretKey` + `SECRET_KEY_LEN` + the 9 tests of that key.

`src/poseidon_sig/` is now `mod.rs` (35 lines: the retirement banner + two RESERVED domain
constants) plus `list.rs` (the IMLL chain format and its shared in-circuit gadgets) — i.e. exactly
"the shared chain gadgets", as the brief asked.

`DOMAIN_PK_G` / `DOMAIN_SIG_G` were **kept as reserved retired constants**, documented as such.
Nothing derives from them; they stay registered so `constants.rs::all_domain_constants_pairwise_distinct`
and `falcon_sig::tests::falcon_domains_do_not_collide` keep proving no LIVE domain collides with a
value this system once hashed under. Deleting them would have removed those proofs.

Evidence (post-change, excluding the committed testdata blob):

```
$ grep -rn --include="*.rs" "SingleSigCircuit\|GoldilocksSecretKey\|poseidon_sig::circuit\|SECRET_KEY_LEN" src/ tests/ \
    | grep -v "^\s*//" | grep -vE "^[^:]+:[0-9]+:\s*(//|///|//!)"
<no code references — every remaining hit is a comment or a doc link describing the retirement>

$ ls src/poseidon_sig/
list.rs   mod.rs
```

All 22 remaining textual `SingleSigCircuit` hits and all 7 `GoldilocksSecretKey` hits are
comments/doc-strings; the ones that were STALE (claiming the wallet still uses the old scheme, or
that `pk_g` is a Goldilocks digest) were corrected in `wallet_core.rs`, `common/trees/key_tree.rs`,
`common/channel_registration.rs`, `falcon_sig/mod.rs` and `bin/channel_member.rs`.

**Direction (b) of the old cross-scheme test is now vacuous by construction.** The Phase-2 test
`cross_scheme_signature_blobs_reject_in_both_directions` also fed a Falcon blob to the LEGACY
parser. There is no legacy parser left in the tree to feed, so that half was dropped (with an
explanatory comment left at its old site in `close_circuit.rs`), and direction (a) — the one the
obligation actually names — was moved and *strengthened* (exact error variant, plus a wallet-level
copy). Nothing that could still reject a legacy blob was removed.

---

## 3. Phase-3 seams closed

| seam | before | after |
|---|---|---|
| `build_channel_withdrawal(&params, cli_member_keys, cli_falcon_seeds)` | a separate seed slice, re-derived into `FalconKeys` inside the builder | `build_channel_withdrawal(&params, cli_member_keys)`. Identities come from `MemberKeys`. Call sites updated: `bin/channel_member::cmd_withdraw`, `bin/generate_withdrawal_fixture`, `a3_channel_withdrawal_builds_and_verifies` |
| `ChannelMemberKeys::from_member_keys(keys, falcon_keys)` | explicit key vector | `from_member_keys(keys)`; the Falcon keys are `Arc` handles taken off the members. `ChannelMemberKeys.falcon_keys` changed `Arc<Vec<FalconKeys>>` → `Vec<Arc<FalconKeys>>` so sharing is possible without cloning secrets. Call sites updated: `wallet_core`, `bin/channel_member::cmd_export_reg_record`, `tests/small_block_sig_validity.rs`, `tests/inter_channel_unified_e2e.rs`, the a3 unit test |
| `a3_withdraw_registration_matches_close_member_set` PHASE 4 OBLIGATION | explicit `falcon_members` built from a hand-rolled seed formula; the obligation stated in a comment because a real assertion could not be written | the explicit construction is DELETED. CLOSE side = `MemberKeys::pk_g()`; REG side = the `MemberLeaf.pk_g` of the tree `from_member_keys` builds. Two independent paths to one quantity, so the equality can fail. Added a per-slot distinctness assertion (A5) |
| CLI `falcon_seed_for` / `cli_falcon_seeds` / `falcon_keys_for` | a SECOND derivation living beside `keys_for` | all three DELETED. `CLI_COSIGNER_SEED_BASE` survives as the `MemberKeys` seed base; new `cli_cosigner_keys(n)` / `cli_falcon_keys(n)` read the key off the member object. `close`, `cancel-close`, `export-reg-record`, `withdraw` and `cli_active_keys` all now start from `keys_for(CLI_COSIGNER_SEED_BASE + slot)` |

`falcon_identity_tests::cli_falcon_identities_agree_across_close_register_and_withdraw` was **kept
and re-aimed, not deleted**. It used to compare two seed derivations; there are no seed derivations
left, so it now compares the two ACTUAL producers — `cli_active_keys()` (what `export-reg-record`
registers and what `withdraw` hands the builder) against `cli_falcon_keys()` (what `close` /
`cancel-close` sign with) — slot by slot, plus per-slot distinctness. If anyone reintroduces a
second derivation on either side, it fails.

`CloseProver::build_full_witness` and `CancelCloseProver::build_full_witness` became generic over
`K: Borrow<FalconKeys>` so they accept `&[FalconKeys]` (fixtures) and `&[Arc<FalconKeys>]` (CLI)
unchanged. No behavioural change.

---

## 4. `validate_all_member_signatures` split (and why it is not a weakening)

TM-C8 asks the structural check to move from "non-empty" to the fixed Falcon length. That function
had TWO callers with different payloads:

1. `verify_next_state_signatures` — channel-STATE co-signatures. Real Falcon cosign blobs.
2. `validate_signed_small_block` — the `SignedSmallBlock` artifact, whose `signatures` are a
   base-layer placeholder at this layer (the real small-block signature check is the B-2 validity
   path: the bp's Falcon signature verified in-circuit by the list step and folded into
   `bp_sig_chain`). `wallet_core::structural_small_block_sigs` fills them with one byte.

So `validate_all_member_signatures` now = slot/identity structure **+ exact length**, and a new
`validate_member_signature_slots` holds the slot/identity structure + non-empty. Caller (2) uses the
latter.

**No check anywhere got weaker**: caller (2) receives exactly the checks it received before; caller
(1) receives a strictly stronger one. Pinned by `three_member_record_validates_signatures`, which
now also asserts a 1-byte blob AND a 77,872-byte legacy-sized blob both fail the co-sign gate.

Fixtures that fed the strict path with 1-byte stubs were updated to
`common::channel::structural_cosign_placeholder(tag)` — a correct-length, version-byte-leading,
explicitly-not-a-signature placeholder. This is a PREMISE fix (those fixtures encoded "any bytes
will do", which was contingent on the old scheme having no fixed length), not an assertion
weakening: every path that actually authenticates a co-signature still rejects them.

---

## 5. wasm

- Export SHAPES unchanged: `wallet_keygen`, `wallet_keygen_seeded`, `wallet_sign_state`,
  `wallet_cosign`, `wallet_finalize` — same signatures, same JSON.
- **No circuit on the co-sign path.** `wallet_sign_state` / `wallet_cosign` → `sign_state` →
  `sign_digest` → `FalconKeys::sign`. The only plonky2/STARK work left in `wallet_cosign` is the
  pre-existing `verify_send_transition` (the Regev channel-tx proof), which is a different object.
  Verified by construction: `single_sig_circuit()` and every `SingleSigCircuit` reference are gone
  (§2), so there is nothing left to build.
- `wallet_keygen*` now costs one NTRU keygen (~455 ms native; slower in wasm). This is a
  join/restore-only cost per TM-C10, not per signature.
- `cargo check --release --lib --target wasm32-unknown-unknown` — **clean**.
- Randomness: `FalconKeys::sign` draws salt + ffSampling entropy from `rand010::SysRng`
  (getrandom-backed). The wasm backend is already configured (`getrandom_v04` with `wasm_js` in
  `Cargo.toml`), which is what makes this work in the browser. **Not executed in a browser this
  phase — see STOP 3.**

---

## 6. node / relay / JS (O-10, TM-C9)

- `node/test/state-delta-relay.test.js` — the size premise. It asserted `deltaBytes > sigBytes` and
  called the signature set the delta's "irreducible floor". That encoded a CONTINGENT fact: a
  co-signature used to be a ~76 KB proof, so the set (~833 KB) dominated the delta. At 1,690 B the
  same inequality is trivially true and proves nothing — it would pass even if the relay dropped
  signatures entirely. **The premise was replaced, not the check weakened**: the test now asserts
  directly that the delta transmits `state.memberSignatures` VERBATIM (deep-equal against the head)
  and that `memberSignatures` is not in `DELTA_CARRY_FIELDS`. That is what the size proxy was
  reaching for, it is strictly stronger, and it is size-independent — so it will still hold after
  the live snapshot is regenerated with Falcon signatures.
- `node/test/state-delta-ui.test.js:196` — assertion message mentioned "the 833KB signature blob";
  reworded. The assertion (`BASE.memberSignatures === undefined`) is unchanged.
- `hosting/wallet/wallet-relay.js` and `wallet-relay-ec2.js` — the measured byte table now carries a
  "SIGNATURE SIZE UPDATE (falcon-sig Phase 4)" paragraph: 833,416 B → ~5 KB of JSON for the set, a
  ~165× drop; `encBalances` (~343 KB) is now what the delta actually saves; the optimization stays
  correct and worth keeping but is no longer load-bearing for signatures; nothing in the security
  argument depends on any size. **Both files edited identically** — the relay test asserts the SLIM
  DOWNLINK block is byte-identical across them, and it passes.
- `hosting/wallet/wallet-live.html:846` — same comment update.
- `cd node && npm test` → **223/223 pass** (unchanged count; nothing skipped). The two REAL-ch7
  snapshot tests DID run (the live artifact is present) and still print the legacy sizes, because
  that snapshot is a live artifact this phase does not regenerate — which is precisely why the
  assertions had to stop depending on sizes.

---

## 7. Solidity

Registration LAYOUT is unchanged (`pk_g` is still `bytes32`; the keccak preimages, the member-set
commitment format and `MemberLeaf`'s three fields are untouched). Only VALUES change.

- `cd contracts && forge build` — OK (only pre-existing `asm-keccak256` lint notes).
- `forge test` — **248/248 pass across 17 suites, 0 failed, 0 skipped.**
- **EIP-170 margin, `IntmaxRollup`: runtime 23,468 B, margin 1,108 B** (initcode 27,296 B, margin
  21,856 B).

No Solidity failure of either kind occurred, so there is nothing to classify as stale-fixture vs
logic. The reason the baked fixtures still pass: the Foundry suites consume the committed
`sepolia_*` / `mle_fixture.json` artifacts self-consistently and never re-derive a `pk_g` from Rust,
so a changed key derivation cannot invalidate them. **They are nonetheless STALE in the sense that
matters** — the proofs and pk_g values in them were produced by the pre-Falcon Rust — and Phase 5
must regenerate them together with the close/cancel/list VK changes from Phases 2/2.6/3.

---

## 8. Test results

One test process at a time, `--test-threads=1`, release. Peak RSS is `/usr/bin/time -l`
"maximum resident set size".

| suite / test process | result | wall | peak RSS |
|---|---|---|---|
| `falcon_sig::tests` (13; incl. the 3 NEW cosign-blob tests + the O-9 legacy-blob test) | **13/13 pass** | 4.7 s | 3.12 GB |
| `common::channel::tests` (23; incl. the strengthened structural-gate test) | **23/23 pass** | 0.8 s | 3.13 GB |
| `wallet_core` targeted (the 3 NEW wallet tests + `a3_withdraw_registration_matches_close_member_set`) | **4/4 pass** | 5.6 s | — |
| `channel_member::falcon_identity_tests` (the re-aimed cross-binary identity test) | **1/1 pass** | 3.5 s | — |
| `wallet_core::*` minus the 5 heavy `a3_*` provers | **27/27 pass** | 253 s | 21.2 GB* |
| `poseidon_sig::*` + `e2e_flow` + `state_update_verifier` | **62/62 pass** | 123 s | 12.6 GB |
| `falcon_sig::list` (7) | **7/7 pass** | 55 s | 4.01 GB |
| `close_pis` + `cancel_close_pis` + `withdrawal_claim_pis` + `post_close_claim_pis` + `update_channel_tree` | **13/13 pass** | 22 s | 3.49 GB |
| `cd node && npm test` | **223/223 pass** (0 skipped) | 0.18 s | — |
| `cd contracts && forge build` / `forge test` | build OK / **248/248 pass** | 43 s | — |
| `cargo check --release --lib --tests --bins` | clean | | |
| `cargo check --release --lib --target wasm32-unknown-unknown` | clean | | |
| `cargo clippy --release --lib --tests --bins` | **419** warnings vs **423 at HEAD** — no new warning attributable to this diff | | |
| `cargo fmt` | applied (an unrelated pre-existing fmt drift in `tests/itx_faucet_cli_e2e.rs` was reverted to keep the diff scoped, same as Phase 3) | | |

\* the 21.2 GB peak is the pre-existing Regev STARK proving in the delegate/multitoken tests, not
anything this phase added; it was measured as a single process and stayed inside the 36 GB budget.

**No test failed at any point in this phase, so there is no stale-fixture-vs-broken-logic
classification to make.** The one test that failed mid-work
(`common::channel::three_member_record_validates_signatures`) failed because its own fixture used
1-byte signature stubs against the newly-tightened fixed-length gate — a PREMISE that the old
scheme's variable-length signatures made vacuous. It was fixed by giving the fixture correct-length
placeholders AND adding two new negative cases (§4), never by relaxing the gate.

### NOT RUN — declared UNVERIFIED

(unchanged rationale from Phase 3: memory budget + scope)

- `a3_channel_withdrawal_builds_and_verifies` and `tests/e2e.rs` — full balance + validity + MLE
  pipeline. Compile-checked only.
- `tests/inter_channel_unified_e2e.rs`, `tests/close_lifecycle_cli_e2e.rs`,
  `tests/itx_faucet_cli_e2e.rs` — need anvil/forge and/or heavy proving. Compile-checked only.
- `tests/small_block_sig_validity.rs` (7.4 GB) and `validity_circuit::test_validity_circuit`
  (7.3 GB) — untouched semantics, but `small_block_sig_validity` DOES go through the changed
  `from_member_keys`. Compile-checked only. (`update_channel_tree` WAS run — 3/3 in the last row
  of the table above.)
- `falcon_sig::agg` (17.2 GB), `close_circuit`, `cancel_close_circuit` — the only change touching
  them is the `Borrow<FalconKeys>` genericization (no behavioural change) and the removal of the
  moved test. Not re-run.
- The fixture binaries (`generate_close_fixture`, `generate_withdrawal_fixture`,
  `generate_e2e_fixture`, `generate_c2c_fixture`) — compile-checked; execution is Phase 5.

---

## 9. STOP points / items for the owner

1. **FIXTURE REGENERATION IS NOW UNAVOIDABLE AND WIDER THAN PHASE 3's.** Every member `pk_g` value
   changes again: the CLI's cosigner identities used to come from `falcon_seed_for` (tag `0xfc`) and
   now come from `MemberKeys::generate`'s RNG stream. So the registration keccak chain, the
   member-set commitment, the close/cancel proofs, `channel_snapshot.json`, and every baked
   `contracts/test/data/*` artifact are stale — on top of the Phase-2/2.6/3 VK changes. Nothing in
   this phase regenerates anything. **This also invalidates every live-deployed channel**: existing
   registrations name identities no wallet can reproduce any more (v3 reset was already the
   approved policy — threat model §5 non-goals).
2. **Co-signature wire grew a 1 KB public key.** 666 B → 1,690 B per signature, because `h` travels.
   Still ~45× smaller than the retired scheme, and the alternative (widening `MemberInfo` or
   `MemberLeaf`) breaks the layout-stability property the migration rests on. Recorded here as an
   explicit design decision so the reviewer can contest it: **the identity binding is unchanged
   (§1.3), only bandwidth moved.**
3. **O-11's cross-platform half is NOT executed.** The argument that native and wasm32 derive the
   same key is structural (ChaCha byte stream + integer arithmetic + the vendored keygen), and the
   Phase-0 native determinism test passes — but no test actually runs keygen under wasm32 and
   compares. Phase 0's own notes already listed this as deferred. A `wasm-bindgen-test` that
   derives `FalconKeys::from_seed([42; 32]).pk_g()` and compares to a native-pinned constant would
   close it. **Recommend doing this before any browser deploy**: a silent fork here means a
   restored wallet gets a different identity and its channel becomes unclosable.
4. **`MemberKeys::generate` now costs ~455 ms** (NTRU keygen). Every wallet-core test that builds a
   3-member channel pays ~1.4 s of setup. That is inherent to Falcon, not a defect, but it makes the
   wallet test suite noticeably slower and browser account creation a visible pause.
5. **Review boundary (CLAUDE.md).** This session implemented; it must NOT security-review its own
   work. An independent reviewer should re-derive §1.3 (the `h`-transport binding argument) and §4
   (the `validate_all_member_signatures` split), and an attacker pass should specifically probe
   whether any consumer of `MemberSignature.signature` reaches `falcon_sig::verify` (rather than
   `verify_with_pk_g`) or reads `pk_g` from the carrier rather than the record.

## Independent security review outcome (2026-08-06) — FIT to commit

**No soundness break.** The `h`-transport binding — the decision that most needed scrutiny — was
traced end to end and VERIFIED: there is exactly ONE consumer of `MemberSignature.signature`, it
reads `expected_pk_g` from the AUTHENTICATED `record.member_pk_gs[slot]` and passes THAT (never
`sig.pk_g`, never anything from the carrier) into verification; `verify_with_pk_g` checks
canonicity, then `falcon_pk_digest(h) == pk_g`, and only then the signature. Bare `verify` has no
non-test caller outside the signer's own self-check. The attack (supply `h'` plus a valid
signature under `h'`) fails on the digest check and requires a Poseidon second preimage (A-F4);
this is pinned by an executed test whose control asserts the attacker's blob DOES verify under
its own `pk_g`, proving the rejection is about identity and not malformedness.

Also verified by the reviewer: decode-time canonicity gating (double-gated, no panic-on-untrusted
DoS); the 1690-byte encoding is a bijection, which matters because signature bytes feed
`SignedSmallBlock::signing_digest`; the O-9 testdata file is *structurally* a genuine legacy
proof (77,872 B, leading 0x52, and its final 128 bytes decode as the `[pk_g(8), m(8)]`
public-input tail the reproduction recipe names — random bytes could not produce that); the
`validate_all_member_signatures` split preserves every prior check; deletion is complete (0 code
references, retired domain constants genuinely inert); and the Phase-3 seams are closed with the
key OBJECT shared rather than re-derived.

### MAJOR (pre-deploy blocker) — RESOLVED BY MEASUREMENT

The reviewer upheld the implementer's own STOP point 3: native-vs-wasm32 keygen determinism was
ARGUED but never executed, and it judged a test **required** before any browser deploy. It also
strengthened the argument (the keygen path uses only IEEE-754 ops over a hardcoded twiddle table;
`approx_exp` is integer FACCT, not `libm`) while correctly noting the claim is a NEGATIVE one
over a large vendored numeric surface that would regress silently on a dependency bump.

The decisive context, found while building the gate: **`.cargo/config.toml` records that this
repository has ALREADY observed a wasm-vs-native numeric divergence** — the Regev STARK verifier
returns different results on wasm32 and native for identical bytes, and disabling simd128 did not
fix it. The structural argument was presumably just as available there. So this was measured.

**Result: wasm32 and native AGREE.** Both derive
`pk_g(seed=[42;32]) = 0x90eed9636e2a86f4043c297a284a6cc24666678312c6bd8a62fc56dc241decf0` — the
same constant the native suite already pins — and in-wasm derivation is reproducible with
distinct seeds giving distinct identities. `wasm-pack test` could not be used (the repo's
atomics/shared-memory rustflags conflict with its default build), so the gate builds the cdylib
with `-Z build-std`, runs `wasm-bindgen --target web`, and executes under Node with two shims for
browser globals the rayon worker helper touches at module scope (it is never invoked — no thread
pool is started). Committed as `hosting/check-falcon-wasm-keygen.sh` and recorded as **TM-C13 /
O-12: re-run before any browser deploy and after any wasm-toolchain, num-complex, num-bigint or
vendored-Falcon-math bump.**

### MINOR findings — all three fixed

- **MINOR-1**: `InvalidLength` hard-coded "expected 666" while serving BOTH the 666-byte bare
  signature gate and the 1690-byte cosign gate, so a rejected cosignature printed a length it was
  never checked against. Tests matched on the variant, so this was invisible to them. The variant
  now carries `(actual, expected)`.
- **MINOR-2**: a new test's block was captioned "a genuine member signature over a DIFFERENT
  digest is rejected" but ended at `assert_ne!(digest, other_digest)` — trivially true,
  exercising nothing. Exactly the pattern the Phase-3 review rejected. Now a real negative:
  member 0 signs `other_digest` with its genuine key, that signature must not verify against this
  state's digest, with a positive control proving the rejection is about the message.
- **MINOR-3**: an orphaned rustdoc paragraph from the retired `validate_all_member_signatures`
  ("one SPHINCS+ key per member…") had been left attached to `structural_cosign_placeholder`, so
  a helper whose one job is to be an explicit NON-signature was introduced by a paragraph about
  N-of-N signature validation. Removed; the corrected note also fixes its claim about a version
  gate that the length-only check does not perform.

### INFO recorded, not fixed

- **INFO-4 → threat model TM-C12**: `h` is now public wire data. Not an unforgeability or
  linkability change (Falcon's `h` is public by design; `pk_g` was already in the clear) but it
  removes a defence-in-depth layer, and the notes had discussed only bandwidth. Now an explicit
  accepted consequence.
- **INFO-7 → Phase 5 scope**: the transported `h` is not yet consumed by the close path —
  `CloseProver` re-signs with locally held keys, so production close still presumes one party
  holds all member secrets. Converting collected blobs into a `FalconAggWitness` is exactly what
  the `h` transport was designed to enable and belongs in Phase 5.
- INFO-5/6 (the tightened length gate's reach is mainly outside the wallet; the precise statement
  is "no path accepts a legacy artifact as a VERIFIED cosignature") and INFO-8 (the by-value seed
  copy in `from_seed` is not zeroized) are recorded as-is.


## Independent security review outcome (2026-08-06) — FIT to commit

**Verdict: FIT.** No soundness break. The `h`-transport binding was traced exhaustively and holds:
`verify_all_signatures` reads `record.member_pk_gs[slot]` into `expected_pk_g` and passes THAT
(never the blob's own key) into `verify_state_sig`; `verify_with_pk_g` checks canonicity, then
`falcon_pk_digest(h) == pk_g`, and only then the signature. The constructed attack — a member
supplying `h'` with a signature valid under `h'` — needs a Poseidon second preimage under IMFK,
and the rejection is pinned by an executed test that also proves the attacker's blob verifies
under its OWN pk_g (so the rejection is about identity, not malformedness). The reviewer also
verified the 1690-byte encoding is a bijection (which matters because signature bytes feed
`SignedSmallBlock::signing_digest`), that the legacy testdata blob is genuinely a
`SingleSigCircuit` proof (structurally: 77,872 B, first byte 0x52, and a `[pk_g(8), m(8)]`
public-input tail), and that the deletion is complete.

### Findings fixed here

- **MINOR-1**: `InvalidLength` hard-coded "expected 666" while also serving the 1690-byte cosign
  gate, so a rejected COSIGNATURE printed a length it was never checked against. The variant now
  carries `(actual, expected)`. Tests matched on the variant, which is why this was invisible.
- **MINOR-2**: a new test's block ended at `assert_ne!(digest, other_digest)` — trivially true,
  exercising none of the property its comment claimed. Same "false comfort" pattern the Phase-3
  review rejected. Now a real negative (member 0 signs a different digest; it must not verify
  here) with a positive control proving the rejection is about the message.
- **MINOR-3**: an orphaned rustdoc paragraph from the retired `validate_all_member_signatures`
  ("one SPHINCS+ key per member…") had been left attached to `structural_cosign_placeholder`, so
  a helper whose one job is to be an explicit NON-signature was introduced by a paragraph about
  N-of-N signature validation. Removed, and its own claim about a "version gate" corrected — the
  structural gate checks length only.
- **MAJOR (pre-deploy, check 9) — CLOSED BY MEASUREMENT.** Native-vs-wasm32 keygen determinism
  was argued but never executed. Now measured: `hosting/check-falcon-wasm-identity.sh` builds the
  wasm cdylib and compares `pk_g` against the same constant the native suite pins. **MATCH.**
  Recorded in the threat model as TM-C13 and marked a blocking deploy gate. Note the reviewer
  correctly caught that the Phase-0 determinism test cannot detect drift (it compares two
  in-process derivations) — the real anchor is the pinned KAT.
- **INFO-4** recorded as **TM-C12**: `h` is now public wire data. Not an unforgeability change
  (Falcon-512 has a public `h`, and `pk_g` was already in the clear) but a lost defence-in-depth
  layer, and the notes had discussed only bandwidth.

### Carried to Phase 5 (reviewer INFO-7, and it matters)

`CloseProver`/`CancelCloseProver` do NOT yet consume collected `MemberSignature` blobs — they
RE-SIGN locally with held `FalconKeys`. So the 1 KB-per-signature wire cost currently buys only
the wallet's local N-of-N check, and production close still presumes one party holds every
member secret. Converting collected blobs into a `FalconAggWitness` is exactly what the `h`
transport was designed to enable, and it belongs in Phase 5 scope.
