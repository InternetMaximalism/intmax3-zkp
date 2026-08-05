# falcon-sig Phase 3 — validity path: list step swaps to DIRECT in-circuit Falcon verification

Branch `feat/falcon-poseidon-sig`, on top of `d08e9ae` (Phase 2.6). **Not committed.**

## 1. MEASUREMENT (the deliverable)

Apple Silicon (M-series), 36 GB, release build, `standard_recursion_config`, 2026-08-05.
Peak RSS is `/usr/bin/time -l` "maximum resident set size" (bytes), each row from a run of exactly
one test process (`--test-threads=1`).

### 1.1 Circuit degrees — BEFORE vs AFTER

| circuit | BEFORE (HEAD d08e9ae) | AFTER (this phase) |
|---|---|---|
| `ListStepCircuit` | 2^12 (recursive SingleSig verify) | **2^16** (direct Falcon verify) |
| `ListCircuit` (cyclic wrapper) | 2^14 | **2^14 — UNCHANGED** |
| `ValidityCircuit` | 2^16 | **2^16 — UNCHANGED** |
| validity dummy list proof | 76 PIs, constructs | **76 PIs, constructs — UNCHANGED** |

**The validity degree did NOT move.** The MLE/WHIR wrapper downstream therefore sees the same
circuit SHAPE; only VK/digest VALUES change (see §6). Both "before" rows were measured on the
unmodified tree by temporarily instrumenting `validity_circuit::tests::test_validity_circuit`;
both "after" rows by the same instrumentation after the swap.

Why the cyclic wrapper survives: `CyclicChainCircuit::new` asserts `data.common == common_data`
against a FIXED template (`common_data_for_hash_chain_circuit`, padded past `1 << 13` gates ⇒
2^14). Verifying a 2^16 inner proof instead of a 2^12 one costs ~4 extra Merkle-path levels per
FRI query per oracle (~450–900 gates); the template had that much headroom, so the assert still
passes and `list_vd.common` is byte-identical. **This was the phase's identified risk point and it
is cleared empirically, not by argument** (`falcon_sig::list::tests::list_step_and_cyclic_degrees`
would panic inside `CyclicChainCircuit::new` otherwise).

### 1.2 New `ListStepCircuit`

| metric | value |
|---|---|
| gates (pre-padding) | **51,764** |
| degree | **2^16** |
| public inputs | 16 (`[prev_chain(8), new_chain(8)]` — unchanged) |
| build | 2.26–2.40 s |
| prove (1 step) | **1.89 s** |
| peak RSS (build + 1 step prove, fresh process) | **3.51 GB** |

The gate count is the Phase-1 gadget (51,735 for the `FalconLeafCircuit`) plus ~29 gates for the
IMLL leaf + chain fold — i.e. the chain arithmetic is free next to Falcon, exactly as expected.

### 1.3 Test-process costs (all PASSED)

| test process | result | wall | peak RSS |
|---|---|---|---|
| `falcon_sig::list` (7 tests, one process) | **7/7 pass** | 55 s | **4.08 GB** |
| `poseidon_sig` (18 tests) | **18/18 pass** | 0.08 s | — |
| `update_channel_tree` (3 tests) | **3/3 pass** | 17.8 s | 3.54 GB |
| `validity_circuit::tests::test_validity_circuit` | **pass** | 41 s | 7.34 GB (was 6.59 GB) |
| `tests/small_block_sig_validity.rs` | **pass** | 50 s | **7.39 GB** |
| `wallet_core::…::a3_withdraw_registration_matches_close_member_set` | **pass** | 1.5 s | — |

`small_block_sig_validity` is the end-to-end pin: a REAL bp Falcon signature over a REAL IMSB
digest, folded by the new list step, recursively verified by the validity circuit, with
`C == final.bp_sig_chain` asserted in-circuit.

## 2. What changed

### 2.1 The list step (the substance)

`src/falcon_sig/list.rs` (NEW) holds `ListStepCircuit` / `ListCircuit`. The step now:

- instantiates the Phase-1 `FalconSigVerifyTarget::new` — the **UNCONDITIONAL** gadget: there is no
  `verify` gate wire in this circuit at all, so the norm bound (Falcon's sole accept/reject
  decision) is always live. A step proof exists only if a genuine signature exists. (The retired
  step got the same guarantee from a recursive `SingleSigCircuit` proof at a build-fixed VK.)
- folds `leaf = Poseidon(IMLL ‖ m ‖ pk)` where `pk = sig.pk_g` (the gadget's own wire, internally
  constrained to `Poseidon(IMFK ‖ encode(h))`) and `m = sig.message_digest` (the wire
  `c = H2P(salt, m)` — and hence the norm bound — is computed from).
- exposes `[prev_chain(8), new_chain(8)]`, byte-identically to before.

`src/poseidon_sig/list.rs` keeps ONLY the FORMAT: `LIST_LEAF_DOMAIN` (IMLL), `list_leaf`,
`list_chain_step`, `list_commitment`, `leaf_target`, `chain_step_target`. Those gadgets are
untouched, and `update_channel_tree.rs` still calls exactly them.

### 2.2 Producer wiring (test-utils / fixture path)

`ChannelMemberKeys` (in `block_witness_generator.rs`, which is **not** `cfg(test)`-gated — it is
linked into the lib and bins) now carries `falcon_keys: Arc<Vec<FalconKeys>>` instead of
`secret_keys: Vec<GoldilocksSecretKey>`, and its `MemberLeaf.pk_g` is the FALCON digest. `Arc`
only because `FalconKeys` is deliberately not `Clone` while this struct is cloned everywhere;
`Debug` is now a hand-written redacting impl.

`bp_sig_events` became `Vec<BpSigEvent { digest, pk_g, witness }>`: the bp's Falcon signature is
produced NATIVELY at `add_block` time (~ms) over exactly the IMSB digest whose `bp_pk_g` limb is
that same key, and stored as the gadget witness the list step consumes.
`build_bp_sig_list_proof` lost its `SingleSigCircuit` argument.

One canonical derivation now exists for deterministic member Falcon keys:
`block_witness_generator::deterministic_member_falcon_keys(channel_id, n)`. Phase 2's
`close_circuit::test_fixture::deterministic_falcon_keys` was reduced to a delegating wrapper with
the **identical seed formula** (`s[0..4]=channel_id, s[8]=0xfa, s[31]=slot+1`) — so no existing
close-fixture key value changes.

### 2.3 Consumers re-pinned

`ValidityCircuit::new(block_chain_vd, list_vd)` is structurally untouched: the conditional-verify
gate (`add_proof_target_and_conditionally_verify` on `should_verify_list = !(chain == 0)`) and
`DummyProof::new(&list_vd.common)` both still work, because `list_vd` is the CYCLIC circuit's data
and that is unchanged (§1.1). Only comments were updated.

`from_member_keys(keys, falcon_keys)` gained the explicit Falcon-key argument (see §5, seam 1);
its five call sites were updated.

## 3. Message binding (TM-C5 item 4) — the argument

**Claim: the binding is exactly as strong as before, by the same mechanism.**

The step's `message_digest` is a free witness INSIDE the step circuit. So was the retired step's
`m`: it came from the `SingleSigCircuit` proof's public inputs, and that proof's own `m` was a free
witness bound only by being a registered PI. In neither design does the step circuit know what an
IMSB digest is.

The binding is EXTERNAL and unchanged, in three links:

1. `update_channel_tree.rs:787-796` RECOMPUTES the IMSB digest in-circuit —
   `SmallBlockMessageFieldsTarget::compute_signing_digest(builder, channel_id, tx_tree_root)`, a
   keccak over the SMALL_BLOCK_DOMAIN preimage — from block-level wires. It is not a witness.
2. `update_channel_tree.rs:1016-1027` folds `(that recomputed digest, bp_pk_g)` into `bp_sig_chain`
   using the SAME `leaf_target` / `chain_step_target` gadgets the step uses. `bp_pk_g` is a witness
   but is pinned three ways: it is a keccak preimage limb of the digest just recomputed; it is
   forced canonical by `to_hash_out`; and it is the `pk_g` of a `MemberLeaf` proven included at the
   bp slot of the channel leaf's registered `member_pubkeys_root`.
3. `validity_circuit.rs:230-237` asserts `C == final.bp_sig_chain` whenever the chain is non-zero
   (and the gate is the COMPUTED chain, not a prover flag).

Because the IMLL leaf hash commits to BOTH `m` and `pk`, link 3 forces every step's `(m, pk)` to
equal the consumer's `(recomputed IMSB digest, registered bp_pk_g)` pair up to a Poseidon
collision. A prover who witnesses a different `message_digest` produces a different chain and the
equality fails.

What Phase 3 ADDS on top of the old design: previously the step proved only "someone knows `sk`
with `Poseidon(IMPG‖sk) = pk`", with `m` bound to that proof merely by being a PI. Now the step
proves "`‖(s1,s2)‖² ≤ β²` for `c = H2P(salt, m)` under `h` with `Poseidon(IMFK‖encode(h)) = pk`" —
`m` enters the accepted predicate through the hash-to-point, so the message is inside the
signature equation rather than beside it. Pinned by
`tests::step_rejects_signature_over_a_different_message`.

**Not weaker than today. STOP not required.**

## 4. TM-C6 / O-6 — cross-context isolation under ONE key

One Falcon key signs BOTH the channel-state co-sign (IMCH digest, consumed by close /
cancel-close via `FalconAggCircuit`) and the small-block root (IMSB digest, consumed by this list
step). The gadget verifies against whatever digest sits on its `message_digest` wire, so isolation
rests ENTIRELY on:

- the two digests being distinct keccak outputs over preimages that start with distinct domain
  constants — `CHANNEL_STATE_DOMAIN` = "IMCH" (0x494d4348) vs `SMALL_BLOCK_DOMAIN` = "IMSB"
  (0x494d5342) — and having different fixed-width field layouts; and
- neither consumer ever accepting a caller-supplied message: close/cancel connect the aggregation's
  `message` PI to their in-circuit-recomputed IMCH digest (Phase 2 §3), and the validity path binds
  this chain to its in-circuit-recomputed IMSB digest (§3 above).

The property is INHERITED from `sk_g`, not new — but the phase must not weaken it, so it is now
pinned **at the level the circuits actually consume, in both directions**, by
`falcon_sig::list::tests::imch_and_imsb_signatures_reject_in_both_directions`:

1. ONE `FalconKeys` signs a REAL IMCH digest (`ChannelState::signing_digest()` via
   `close_circuit::test_fixture::final_state_n(3, …)`) and a REAL IMSB digest
   (`SmallBlockMessageFields::signing_digest(channel_id, tx_tree_root)`, whose preimage even
   carries that key's own `pk_g`). The two digests are asserted distinct.
2. Native control: each signature verifies in its own context and FAILS in the other.
3. **Direction 1** — the IMCH signature is presented to the IMSB list step with
   `message_digest = imsb`: `ListStepCircuit::prove` must FAIL. Control: the genuine IMSB signature
   proves and verifies at the same step.
4. **Direction 2** — the IMSB signature is presented to the close-context aggregation leaf
   (`FalconLeafCircuit`) with `message_digest = imch`: `prove` must FAIL. Control: the genuine IMCH
   signature proves and verifies at the same leaf.

Result: PASS (in the 4.08 GB / 55 s `falcon_sig::list` process). Note this is a stronger test than
a native-only one because it exercises the two REAL circuit entry points, one per context.

## 5. Deletions and grep evidence

Deleted:
- `src/poseidon_sig/consumer.rs` — the whole file (`ListConsumerCircuit`, a demonstration gadget
  with ZERO call sites outside its own tests).
- `poseidon_sig::list::ListStepCircuit` and `poseidon_sig::list::ListCircuit` (the SingleSig-based
  producer) and their tests.

Evidence (post-change):

```
$ grep -rn --include="*.rs" "ListConsumerCircuit\|poseidon_sig::consumer\|consumer::" src/ tests/ | wc -l
0
$ grep -rn --include="*.rs" "poseidon_sig::list::ListCircuit\|poseidon_sig::list::ListStepCircuit" src/ tests/ | wc -l
0
```

**NOT deleted — `SingleSigCircuit` + `GoldilocksSecretKey` (brief option (a)).** Exactly two live
consumers remain, both out of Phase 3's scope:

1. `src/wallet_core.rs` — `single_sig_circuit()` / `sign_digest` / `verify_state_sig` /
   `verify_all_signatures`, i.e. the WALLET's channel-state co-sign, and `MemberKeys.signing_key`.
   This is Phase 4's explicit deliverable ("`MemberKeys` single Falcon signing key from seed;
   `sign_state`/`verify_state_sig`/`verify_all_signatures` → Falcon native"). Deleting it here
   would have forced the Phase-4 wallet swap.
2. `src/circuits/channel/close_circuit.rs:2189-2201` — the O-9 downgrade test builds a REAL legacy
   `SingleSigCircuit` proof blob and asserts the Falcon parser rejects it (version/length gate).
   Replacing that with a random blob would strictly WEAKEN the test, so the circuit must outlive
   the migration until that test is retired.

`src/poseidon_sig/mod.rs` now documents this retirement status inline so the next phase knows
precisely what may go.

## 6. STOP points / items for the owner

1. **VK CHANGE (gates merge).** The list VK changed, therefore the validity circuit digest changed,
   therefore every downstream baked artefact derived from the validity proof (MLE wrapper inputs,
   fixtures, on-chain-pinned constants) is stale. Degrees did NOT move, so nothing structural
   downstream changes — but every fixture must regenerate (Phase 5, together with the Phase-2
   close/cancel regeneration).
2. **PHASE SEAM 1 — `MemberKeys` still has no Falcon key.** `ChannelMemberKeys::from_member_keys`
   therefore takes the members' Falcon keys as an explicit argument. Call sites and what they pass:
   - `wallet_core::build_channel_withdrawal` (PRODUCTION) → `deterministic_member_falcon_keys`;
   - `bin/channel_member::cmd_export_reg_record` (PRODUCTION CLI) → `falcon_keys_for(0xC1_0000 +
     slot)`, i.e. **the exact keys the CLI close/cancel paths sign with** — this CLOSES the Phase-2
     CLI seam (the registered member set now matches the close proof's member-set commitment);
   - `tests/small_block_sig_validity.rs`, `tests/inter_channel_unified_e2e.rs`,
     `wallet_core`'s `a3_withdraw_registration_matches_close_member_set` → the deterministic
     derivation.
   Phase 4 must delete the argument and use `MemberKeys`'s own Falcon key.
3. **PHASE SEAM 1 has a live TRIPWIRE.** `a3_withdraw_registration_matches_close_member_set` was
   updated (it could not compile otherwise): it still asserts the registration member set equals
   the close member set, now over the FALCON identities, and it additionally asserts
   `MemberKeys::pk_g() != <the registered Falcon pk_g>` with a comment instructing Phase 4 to flip
   that to `assert_eq!` and drop the plumbing. The gap is pinned, not hidden. **No test was
   modified to make a failing assertion pass** — the only semantic change is which key is the
   member identity, which is exactly what this phase changes.
4. **`update_channel_tree` tests now use REAL Falcon `pk_g` values** (`FalconKeys::from_seed(..).
   pk_g()`) instead of Goldilocks digests. The circuit is agnostic to the derivation (it consumes
   an opaque canonical 32-byte digest), but the tests should mirror what the path now carries.
   `GoldilocksSecretKey` no longer appears anywhere on the validity path.
5. **Review boundary (CLAUDE.md).** This session implemented; it must NOT security-review its own
   work. An independent reviewer / attacker subagent should re-derive §3 (message binding) and §4
   (TM-C6) before merge, and in particular re-check the claim that nothing in the step circuit lets
   a prover decouple `pk` from `h` or `m` from `c`.

## 7. Verification performed

- `cargo check --release --lib --tests --bins` — clean.
- `cargo check --release --features close-fixture-bin --lib --bins` — clean.
- `cargo check --release --lib --target wasm32-unknown-unknown` — clean.
- `cargo clippy --release --lib --tests` — ZERO warnings attributable to `src/falcon_sig/list.rs`,
  `src/poseidon_sig/list.rs`, `src/circuits/test_utils/block_witness_generator.rs` (pre-existing
  warnings elsewhere unchanged).
- `cargo fmt` — applied (an unrelated pre-existing fmt drift in `tests/itx_faucet_cli_e2e.rs` was
  reverted to keep the diff scoped).
- Tests: see §1.3 — `falcon_sig::list` 7/7, `poseidon_sig` 18/18, `update_channel_tree` 3/3,
  `validity_circuit::test_validity_circuit`, `tests/small_block_sig_validity.rs`,
  `a3_withdraw_registration_matches_close_member_set`. All PASS.

### NOT RUN — declared UNVERIFIED (memory / scope, per the brief)

- `tests/e2e.rs` and `src/wallet_core.rs`'s `a3_channel_withdrawal_builds_and_verifies` — both build
  the BALANCE circuit family plus the MLE/WHIR wrap on top of the validity chain. Compile-checked
  only.
- `tests/inter_channel_unified_e2e.rs` — additionally requires anvil/forge. Compile-checked only.
  Its wallet-tree assertion compares wallet-root vs a wallet-height tree over the SAME Goldilocks
  wallet leaves, so it is not expected to be affected; unverified nonetheless.
- `src/bin/generate_c2c_fixture.rs`, `src/bin/generate_e2e_fixture.rs`,
  `src/bin/generate_close_fixture.rs` — compile-checked; NOT executed (fixture regeneration is
  Phase 5).
- `falcon_sig::agg` (17.2 GB for the whole suite) and the `close_circuit` / `cancel_close_circuit`
  suites — untouched by this phase apart from the `deterministic_falcon_keys` delegation, whose
  seed formula is byte-identical; not re-run.
- `falcon_sig::gadget`'s `falcon_sig_circuit_measure_1_3_16` (the 2^20 / 22 GB harness) —
  deliberately not run.

## Independent security review outcome (2026-08-05/06)

**Soundness: FIT.** The headline question — can a prover get a `bp_sig_chain` accepted that does
not correspond to a genuine Falcon signature, by the actual bp, over the IMSB digest the circuit
recomputed? — is answered **NO**.

Verified by the reviewer (executed `validity_circuit::test_validity_circuit` and
`falcon_sig::list` 7/7; the rest static):

- **Message binding holds and the consumer side is provably unchanged**: the non-test diff of
  `update_channel_tree.rs` is ONE COMMENT HUNK, so its constraint system is bit-identical to HEAD.
  On the step side, `message_digest` is a witness but NOT a dangling one — `FalconSigGadgetWitness`
  has no `c` field at all; `c` is computed in-circuit from `(salt, message_digest)` and feeds the
  norm bound, so tampering `m` randomizes all 512 coefficients and the 26-bit slack check fails.
- **Correction to our own claim**: the notes said Phase 3 STRENGTHENS the binding. The reviewer
  calls that defensible but overstated, and is right. The retired `SingleSigCircuit` registered
  `m` as a public input, and a proof minted for `m1` does not verify against `m2` — that PI WAS
  the binding. The honest statement is **not weaker**, and architecturally cleaner because `m`
  now enters the hard predicate rather than being a PI of a proof-of-knowledge.
- **`pk` binding**: one `h` allocation feeds both `pk_digest_circuit` and the NTT; `bp_pk_g` is
  pinned four independent ways on the consumer side. No path folds one pk while signing another.
- **TM-C6/O-6**: the cross-context test is genuine, at both circuit entry points, with
  non-trivial honest controls. The two digests are fixed-width keccak whose FIRST WORD differs
  (`0x494d4348` vs `0x494d5342`), so cross-context validity needs a keccak collision.
- **Cyclic wrapper — stronger than we claimed**: `cyclic_chain_circuit.rs:76` is a RELEASE-mode
  `assert_eq!` on the full `CommonCircuitData`, run on every `ListCircuit::new()`. A future
  gadget-size change cannot silently exceed the template; it panics at build time. This also makes
  "validity degree unchanged" provable rather than empirical.
- **Deletions clean**: 0 active references; every deleted test has a Falcon successor plus two new
  negatives; no circuit accepts a legacy proof as a cosignature anywhere.

### FINDING 7 (MAJOR) — FIXED. Two production paths registered DIFFERENT Falcon keys.

`cmd_export_reg_record` derived from `falcon_keys_for(0xC1_0000 + slot)` (seed tag 0xfc) while
`cmd_withdraw` reached `build_channel_withdrawal`, which RE-DERIVED its own keys from
`deterministic_member_falcon_keys(channel_id, n)` (tag 0xfa). Different seeds => different
`pk_g` => different `member_pubkeys_root`, `channel_reg` keccak chain and
`close_member_set_commitment`. They meet in `close_lifecycle_cli_e2e`: `export-reg-record` feeds
L1 `registerChannel`, then `withdraw` proves against the other set. Fail-closed (nothing forged
is accepted) but a real LIVENESS break — the channel becomes unclosable — and NEW in Phase 3: at
HEAD both went through `from_member_keys` off the same `MemberKeys.signing_key`.

FIX, structural rather than cosmetic: `build_channel_withdrawal` no longer derives keys. It takes
`cli_falcon_seeds: Option<&[[u8;32]]>` and re-derives from the CALLER's seeds (seeds, not key
objects, because `FalconKeys` is deliberately neither `Clone` nor `Serialize` and a seed is the
only representation that crosses the boundary without widening that surface; `from_seed` is
deterministic per TM-C10). The deterministic derivation remains the default for fixture binaries,
which have no CLI keys. On the CLI side every site now derives from ONE helper,
`falcon_seed_for(CLI_COSIGNER_SEED_BASE + slot)`. **The agreement is now visible at the call site
instead of being an accident of two formulas happening to match.**

### FINDING 6 (MAJOR) — FIXED. The tripwire did not work, and the test hid finding 7.

`assert_ne!(m.pk_g(), close_hashes[i])` compared a Goldilocks digest with a Falcon digest derived
from an unrelated seed: they differ for reasons unrelated to whether Phase 4 landed, so it would
have stayed GREEN after Phase 4 while the invariant it named was broken. Worse, the test's main
assertions had lost fidelity — `close_hashes` was overwritten from the very `falcon_members`
vector passed into `from_member_keys` three lines later, so `reg_commitment == close_commitment`
compared two values with one source and could not fail. `close_commitment` was computed twice and
the first was dead (shadowed). The doc comment claimed to walk "the exact path
`build_channel_withdrawal` takes", which stopped being true when that function grew its own
derivation. This is the repo's known "tests stop at a mock boundary" failure mode, and it is
precisely why finding 7 went unnoticed.

FIX: the fake `assert_ne!` is REMOVED (a comment states the Phase-4 obligation instead — false
comfort is worse than silence); the dead shadow is gone; the false comment is corrected; and the
two sides are now derived independently (close side from `FalconKeys::pk_g()`, reg side from the
member tree the registration builds), so the comparison can actually fail. The cross-BINARY
property that finding 7 violated is pinned where those call sites live, by the new
`channel_member::falcon_identity_tests::cli_falcon_identities_agree_across_close_register_and_withdraw`,
which also asserts per-slot seed distinctness (a shared seed would let one key satisfy several
member slots, defeating the close circuit's A5 distinctness check).

### Other review items addressed

- MINOR (slot truncation): `deterministic_member_falcon_keys` encodes the slot in one byte;
  added an `assert!(slot < 255)` — unreachable at `MAX_COSIGNERS = 16`, but this repo already
  shipped and fixed a u8-slot-256 bug once.
- MINOR (stale docs): corrected the CLI comment claiming registration "still carries the
  GOLDILOCKS pk_g" (false since Phase 3 — actively misleading), the `key_tree` doc naming
  `GoldilocksSecretKey::public_key()`, and the `poseidon_sig/list.rs` reference to the relocated
  step circuit.
- INFO (recorded, not fixed): `ListStepCircuit::prove` never sets `witness.pk_g` (it is a derived
  wire there), so a pk_g-tamper test written AT THE LIST LEVEL would be silently vacuous — the
  gadget's own `wrong_pk_g_rejected` is the real coverage.

### Reviewer-declared UNVERIFIED

`tests/small_block_sig_validity.rs` (implementer reports pass), `tests/e2e.rs`,
`a3_channel_withdrawal_builds_and_verifies`, `tests/inter_channel_unified_e2e.rs`,
`tests/close_lifecycle_cli_e2e.rs` (would likely have exposed finding 7 — needs anvil/forge), the
fixture bins, and the `agg`/`close`/`cancel_close` suites. `ValidityCircuit.degree_bits()` was not
printed directly; its INVARIANCE is proven by the release-mode `common` assert above.

After the fixes: `falcon_sig::list` 7/7, `a3_withdraw_registration_matches_close_member_set` +
`a3_withdrawal_claim_prover_builds_and_verifies` 2/2,
`cli_falcon_identities_agree_across_close_register_and_withdraw` 1/1,
`cargo check --release --lib --tests --bins` clean.
