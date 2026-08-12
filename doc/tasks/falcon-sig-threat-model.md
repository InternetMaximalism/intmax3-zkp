# Threat Model: Falcon-512 (Poseidon hash-to-point) replacing the Goldilocks signing key

Branch: `feat/falcon-poseidon-sig` (cut from main @ 1fb724f). Status: APPROVED (owner, 2026-08-05).

## 0. Scope (owner decisions 2026-08-05, revised: UNIFIED single signing key)

Replace the plonky2-proof-as-signature scheme everywhere the **Goldilocks signing key** is used
— exactly the surface `sk_g` covers today. Today ONE key signs both the channel state co-sign
(IMCH) and the bp's small-block root (IMSB), isolated by message-domain separation; the Falcon
key inherits that structure 1:1, so members keep ONE signing key (plus the untouched `pk_b`
sender key and Regev decryption keys).

| Surface | Today | After |
|---|---|---|
| Channel state co-sign (IMCH digest, `MemberSignature`) — wallet/wasm/CLI sign + native N-of-N verify | `SingleSigCircuit` proof bytes (~76 KB) | **Falcon-512/Poseidon signature (~666 B), native verify** |
| Close circuit signature check | recursive verify of one `AggLevelCircuit` proof | **direct in-circuit verification of N Falcon signatures** |
| Cancel-close circuit | same as close | same as close |
| Validity path: bp's IMSB signature, aggregated by `ListCircuit`, accumulated in `bp_sig_chain` | `SingleSigCircuit` proof as leaf, recursively verified per list step | **same list/chain structure; the list step verifies a Falcon signature directly in-circuit** |
| BabyBear `pk_b` channel-tx sender sig (Plonky3), Regev encryption keys | — | **UNCHANGED** |

Structural consequences:
- `pk_g` is **redefined in place**: `pk_g = Poseidon(IMFK ‖ encode(h))` instead of
  `Poseidon(IMPG‖sk_g)`. Same 32-byte width, same slot in `MemberLeaf` (stays 3 fields),
  same L1 registration keccak layout, same Solidity `bytes32 pkG`, same IMLL chain format
  (`Poseidon(IMLL‖m‖pk)` binds a 32-byte pk). **No new identity field.** Values change; layouts
  do not.
- The whole `poseidon_sig` primitive family is deleted: `SingleSigCircuit`,
  `AggLevelCircuit`/`SigAggregator`, and the recursive-verify leaf of `ListCircuit`. The
  list/chain SHAPE survives (`list_leaf`/`chain_step_target` gadgets and the `bp_sig_chain`
  accumulator are format-stable); only the list step's leaf verification is replaced by the
  in-circuit Falcon verifier gadget.
- VK cascade: list VK changes → validity chain VKs change; close/cancel-close VKs change.
  **Total fixture/VK regeneration** (routine in this repo; multitoken and Regev-2048 precedent).
- `update_channel_tree`'s in-circuit chain fold is untouched (it folds `(m, pk)` pairs of
  unchanged width); `SmallBlockRootMessage` preimages keep `bp_pk_g(8)` limbs whose VALUES are
  now Falcon pk digests.
- `SignedSmallBlock::signing_digest()` keccaks signature length+bytes — the bp signature
  shrinks to ~666 B, changing those digests (fixture regen covers it; no layout change).

## 1. The scheme

Falcon-512 (n=512, q=12289) with hash-to-point instantiated by the **in-tree plonky2 Poseidon
(Goldilocks, width 12)** instead of SHAKE-256 — the construction Miden ships as
`falcon512_poseidon2` (we swap their Poseidon2 for plonky2 Poseidon so the close circuit
verifies with native gates). Vendored from `0xMiden/crypto`; ffSampling/samplerz/FFT/keygen
untouched. Verification equation: `s1 = c − s2·h mod q mod (X^512+1)`, accept iff
`‖(s1,s2)‖² ≤ β² = 34 034 726`.

Member cosign identity: `pk_f = Poseidon(IMFK ‖ encode(h))` — a 32-byte digest, same width as
every other identity field.

## 2. Security assumptions (delta vs today)

| # | Assumption | Status |
|---|---|---|
| A-F1 | NTRU/SIS hardness at Falcon-512 parameters | **NEW.** NIST-selected (FN-DSA, FIPS 206 draft 2025-08); ROM proof ePrint 2024/1769. |
| A-F2 | plonky2 Poseidon modeled as RO for hash-to-point | **NEW in role, not in kind** — the system already rests on Poseidon everywhere. Precedent: ePrint 2024/1553 (RPO-as-RO), Miden production use. |
| A-F3 | Hash-to-point close to uniform on Z_q^512 | Full-64-bit-element reduction mod q: bias ≈ 2^-50/coeff, ≈ 2^-41 total (Falcon spec's sanctioned no-rejection variant). **O-1: one FULL field element per coefficient; never split or reuse sponge output.** |
| A-F4 | Poseidon preimage resistance for `pk_f = Poseidon(IMFK‖encode(h))` | Same class as today's pk_g. |

The cosigner path's security **no longer depends on FRI soundness** — a proof-system
config bug can no longer mint cosignatures. (It still can on the untouched validity path.)

## 3. Threats and obligations

### TM-C1 — Hash-to-point bias / structure abuse
Bias or structure in `c` weakens the GPV forgery bound. **Mitigations:** O-1; fixed sponge
layout (absorb 40-byte salt, then the 32-byte message digest, fixed 64-squeeze of 512
coefficients at rate 8); new capacity domain constant `IMFH` (register in detail2 §G-2 with
non-collision tests vs IMPG/IMSG/IMLL/MBLF/IMFK). **O-2: native H2P and in-circuit H2P pinned
equal by shared-vector tests (random + all-zero + max-canonical inputs).**

### TM-C2 — Salt handling
40-byte CSPRNG salt per signature, sampled once outside the retry loop (FN-DSA draft behavior).
NOT deterministic signing (CARDIS-2023 fault attack on det-Falcon; multi-runtime consistency).
**O-3: RNG sources explicit at both call sites (salt, ffSampling); a CI test fails loudly on a
constant salt across two signatures — the `cmd_send` constant-seed bug (77594be) is the
precedent this guards.**

### TM-C3 — Gaussian sampler integrity
Key recovery via biased ffSampling is Falcon's classic implementation failure. **Mitigation: do
not touch it.** Vendor `falcon512_poseidon2` with provenance pinned (upstream commit hash in the
vendor README); CI diff proves only `hash_to_point.rs` (+permutation import) differs. Validate
untouched math by running upstream's own tests on the pristine copy first, then round-trip +
norm-distribution tests on our instantiation. **(O-4)**

### TM-C4 — Side channels in signing
f64 ffSampling under wasm/JIT is not constant-time-audited. Position: browser signs the user's
own key; ~1 ms signing + randomized salt leaves little to measure remotely; CLI/relay run native.
**Accepted residual risk, documented. Fallback if hardened later: Pornin's `rust-fn-dsa`
integer-only path.** Note the relay co-signs with ITS OWN cosigner keys as a service — same
acceptance applies but is a *server* context; revisit if relay keys ever guard third-party funds
beyond the demo topology.

### TM-C5 — In-circuit verification soundness (the new critical surface)
Close/cancel-close must verify with no prover slack:
1. `s2` canonical: centered coefficients in (−q/2, q/2], range-checked;
2. `s1 = c − s2·h` via NTT mod q — every reduction carries a range-checked quotient
   (14-bit q: products fit Goldilocks with margin);
3. norm `‖(s1,s2)‖² ≤ β²` over CENTERED values; max possible sum 1024·(q/2)² < 2^36 — no
   field wrap; test at β² (accept) and β²+1 (reject);
4. `c` recomputed in-circuit from (salt witness, recomputed IMCH digest — NOT a witness);
5. `h` witnessed (512 coeffs, range-checked < q), encoded exactly as native `encode(h)`,
   Poseidon-hashed, connected to the member's `pk_f`.
**O-5: adversarial tests per item: norm boundary, non-canonical s2 (q-overflow AND centered
confusion), tampered salt, s2 = 0, non-canonical h, valid-sig-wrong-pk. Each must fail.**

### TM-C12 — The public polynomial `h` is now published with every cosignature (ACCEPTED)

Before Phase 4 the Falcon public polynomial never left the wallet: only
`pk_g = Poseidon(IMFK‖encode(h))` was registered, and the close/agg circuits expose `pk_g` as a
public input with `h` as a witness. Phase 4's cosign wire carries `h` inside the (already opaque)
`MemberSignature.signature` blob — `v1(1) ‖ salt(40) ‖ s2(625) ‖ h(1024)` = 1690 B — so anyone
observing a cosignature now sees the full 1 KB `h`.

**This is not an unforgeability weakening**: Falcon-512 is defined with a PUBLIC `h`, and
`MemberSignature.pk_g` was already in the clear, so linkability is unchanged. What it removes is
a defence-in-depth layer (`h` used to be secret-by-accident). Accepted deliberately; recorded
here because the Phase-4 notes discussed only bandwidth and never confidentiality.

`h` is untrusted input: it is consumed ONLY through `verify_with_pk_g`, which range-checks
canonicity and recomputes `falcon_pk_digest(h) == pk_g` against the AUTHENTICATED
`record.member_pk_gs[slot]` BEFORE the signature check. Substituting `h'` therefore requires a
Poseidon second preimage under IMFK (A-F4).

### TM-C13 — wasm32 vs native keygen determinism (MEASURED, gated)

`FalconKeys::from_seed` must derive the same `pk_g` on wasm32 as natively, or a wallet created
or restored in the browser is a DIFFERENT member than the one registered on L1: its
cosignatures stop verifying and the channel becomes permanently unclosable (funds stuck), with
no error at the moment of divergence.

The structural argument is strong (keygen touches only IEEE-754 `+ - * / floor round sqrt` over
a hardcoded twiddle table; `approx_exp` is integer FACCT, not `libm::exp`; Rust neither contracts
to FMA nor reassociates without fast-math). **It is nevertheless MEASURED, because this
repository has already observed a wasm-vs-native numeric divergence in a proof path** — see
`.cargo/config.toml`, which records that the Regev STARK verifier returns different results on
wasm32 and native for identical bytes and that disabling simd128 did not fix it. A negative claim
over a large vendored numeric surface is exactly the kind of argument that failed there.

**Result (2026-08-06): MATCH.** `hosting/check-falcon-wasm-identity.sh` builds the wasm cdylib
and asserts `FalconKeys::from_seed([42;32]).pk_g()` equals the same pinned constant the native
suite pins. **This script is a BLOCKING gate on any browser deploy** and must be re-run after any
dependency bump touching the numeric surface.

### TM-C6 — Cross-context isolation under ONE key (IMCH vs IMSB)
The single Falcon key signs both state co-signs (IMCH digests) and small-block roots (IMSB
digests) — exactly as `sk_g` does today. Isolation rests on the message digests: both are
keccak digests whose preimages open with distinct domain constants, so no message can verify in
both roles. This property is INHERITED, not new, but the swap must not weaken it: every
verifier recomputes the expected digest for ITS context and never accepts a caller-supplied
message. **O-6: negative tests — a valid cosign signature replayed as a bp/IMSB signature (and
vice versa) must reject in both the native verifier and each circuit; a Falcon signature blob
fed to any legacy SingleSig-proof parser and an old proof blob fed to the Falcon verifier must
both reject.**

### TM-C7 — pk_g redefinition, padding argument, A11
`pk_g`'s DERIVATION changes (Poseidon of `encode(h)` under IMFK instead of Poseidon of `sk`
under IMPG); every layout that carries it is width-stable and unchanged: `MemberLeaf` (3
fields), registration keccak `pk_g‖pk_b‖regev‖recipient`, `member_set_commitment` keccak
`[IMCM, member_count, pk_g_0..15]` (domain can stay IMCM — the committed VALUES change but the
format does not; decide at Phase 2 whether a version-distinguishing domain is warranted and
record the argument either way). Re-argue at their sites: (a) padding — a padding slot's
`pk_g = 0x0…0`, forging it real requires a Poseidon preimage of the zero digest under IMFK
(same strength as today's argument under IMPG); (b) A5 distinctness over U256 keys — unaffected
by what the digest commits to; (c) A11 two-key binding (`pk_g`,`pk_b` in the same MemberLeaf) —
format-stable, but the mismatched-pair rejection suite re-runs against Falcon-derived pk_g
(**O-7**). All registration-bearing fixtures regenerate (values, not layout). **O-8:
Rust↔Solidity shared vectors re-pinned wherever pk_g values enter digests.**

### TM-C8 — Old-format signature replay / downgrade
After the swap, a ~76 KB SingleSig proof blob must never verify as a cosignature.
**O-9: `MemberSignature.signature` gets a leading format-version byte; the new verifier rejects
version ≠ FALCON_V1 before parsing; explicit test that a valid OLD proof blob is rejected (not
merely "fails to parse"). The structural checks (`validate_all_member_signatures`) update their
size sanity from "non-empty" to the fixed Falcon encoding length.**

### TM-C9 — Wire/size-sensitive consumers
`SignedSmallBlock::signing_digest()` keccaks signature bytes+length — the bp signature shrinks,
so these digests change (regen covers it). Node tests assert the delta payload exceeds the
signature set (inverts at 666 B — fix the tests' premise; they encoded a contingent fact).
Slim-downlink carryHash and relay byte-table comments reference 833 KB signatures (update; the
downlink optimization remains sound, just far less necessary). **O-10: sweep every size assumption found
by the surface map. Wire field names (`pkG` etc.) are kept — the key's meaning changes, its
identity role does not.**

### TM-C10 — Key derivation and restore
`MemberKeys::from_seed(32B)` must yield the Falcon keypair deterministically (seeded ChaCha20
driving NTRU keygen), or restore-from-seed silently forks identities. **O-11: same-seed ⇒ same
`h`/`pk_f` test, cross-platform (native vs wasm32) keygen determinism test; keygen (~10–50 ms
native) runs at join/restore only, never per signature.**

### TM-C12 — The public polynomial `h` is now published with every cosignature (ACCEPTED)

Phase 4 carries `h` (1 KB) inside `MemberSignature.signature` so the verifier can check a
signature without a schema change: `v1(1) ‖ salt(40) ‖ s2(625) ‖ h(1024)` = 1690 B.

Before Phase 4, `h` never left the wallet — only `pk_g = Poseidon(IMFK‖encode(h))` was
registered, and the close/agg circuits expose `pk_g` as a public input with `h` as a witness.
Every cosignature now publishes `h` to anyone who observes the wire.

**This is not an unforgeability weakening**: Falcon-512 is defined with a PUBLIC `h`, and
security rests on NTRU/SIS (A-F1), not on hiding it. Nor does it change linkability —
`MemberSignature.pk_g` was already in the clear. What it removes is a defence-in-depth layer:
an attacker who wanted `h` previously had to invert a Poseidon digest.

**Accepted, and recorded here because the Phase-4 notes discussed only bandwidth.** The
alternative (widening `MemberInfo`/`MemberLeaf`) was rejected: it would still need the same
digest check AND would break the layout stability the whole migration rests on. The binding is
unchanged either way — `h` is untrusted input consumed only through `verify_with_pk_g`, which
recomputes `falcon_pk_digest(h) == pk_g` against the AUTHENTICATED `record.member_pk_gs[slot]`
BEFORE the signature check, so substituting `h'` requires a Poseidon second preimage (A-F4).

### TM-C13 — wasm32/native keygen determinism (MEASURED, gate script in-tree)

A wallet created or restored in the browser must derive the same `pk_g` from a seed as the CLI
does; otherwise the L1 registration names an identity the wallet cannot reproduce, its
co-signatures stop verifying, and the channel is permanently unclosable — funds stuck, with no
error at the moment of divergence.

NTRU keygen runs f64 arithmetic. The structural argument for determinism is strong (only
IEEE-754 `+ - * / floor round sqrt` over a hardcoded twiddle table; `approx_exp` is integer
FACCT, not `libm::exp`; Rust neither contracts to FMA nor reassociates without fast-math), but
it is a NEGATIVE claim over a large vendored numeric surface — and **this repository has already
observed a wasm-vs-native numeric divergence** in the Regev STARK verifier (recorded in
`.cargo/config.toml`; disabling simd128 did not fix it). So it is measured, not argued.

**Measured 2026-08-06: wasm32 and native agree** — both give
`pk_g(seed=[42;32]) = 0x90eed963…decf0`, the same constant the native suite pins. Reproduce with
`hosting/check-falcon-wasm-keygen.sh`. **O-12: re-run this before any browser deploy and after
any bump of the wasm toolchain, `num-complex`, `num-bigint`, or the vendored Falcon math.**

### TM-C11 — Algebraic-hash margin
Poseidon in a new role (H2P). No known applicable attack; consistent with the system-wide
Poseidon dependency; plonky2's audited-parameter instance, no custom constants. **Monitored.**

## 4. Explicitly out of scope
- Fault injection (no HSM claims).
- `pk_b` Plonky3 sender sig, Regev keys.
- Threshold/aggregate Falcon — independent signatures verified directly (close) or per list
  step (validity).
- FN-DSA wire compatibility (H2P differs by design; parameters/sampler track the draft).

## 5. Non-goals confirmed with owner
- No dual-scheme transition period: v3 testnet resets (same policy as multitoken).
