# Threat Model: Falcon-512 (Poseidon hash-to-point) for channel COSIGNER signatures

Branch: `feat/falcon-poseidon-sig` (cut from main @ 1fb724f). Status: DRAFT — awaiting owner approval.

## 0. Scope (owner decision 2026-08-05)

Replace the plonky2-proof-as-signature scheme **only where channel cosigners sign**:

| Surface | Today | After |
|---|---|---|
| Channel state co-sign (IMCH digest, `MemberSignature`) — wallet/wasm/CLI sign + native N-of-N verify | `SingleSigCircuit` proof bytes (~76 KB) | **Falcon-512/Poseidon signature (~666 B), native verify** |
| Close circuit signature check | recursive verify of one `AggLevelCircuit` proof | **direct in-circuit verification of N Falcon signatures** |
| Cancel-close circuit | same as close | same as close |
| Validity path: bp's IMSB small-block signature, `ListCircuit`, `bp_sig_chain` accumulator | `SingleSigCircuit` + recursive list | **UNCHANGED** |
| BabyBear `pk_b` channel-tx sender sig (Plonky3), Regev encryption keys | — | **UNCHANGED** |

Consequences of the reduced scope:
- `SingleSigCircuit` and `ListCircuit` **stay in the tree** (validity consumers). Only
  `AggLevelCircuit`/`SigAggregator` become dead and are deleted.
- The VK cascade shrinks to: Close and CancelClose circuits get new VKs (their `agg_vd`
  constant is replaced by the in-circuit Falcon verifier logic). Validity/wrapper VKs for the
  validity chain are untouched; **only close/cancel-close(+downstream claim circuits if their
  VKs pin close) fixtures regenerate**, not the validity MLE set — EXCEPT any fixture that bakes
  `MemberSignature` blobs or the registration preimage (see TM-C7), which is most lifecycle
  fixtures. Enumerate at Phase 5, do not assume.
- `sk_g`/`pk_g` remain live as the **bp/validity signing key**. The member now holds an
  ADDITIONAL Falcon keypair for co-signing. Key separation is deliberate (TM-C6).

Each member's keys after this change: `sk_g` (Goldilocks, bp/IMSB only), **`sk_f` (Falcon-512,
state co-sign — NEW)**, `sk_b` (BabyBear, tx sender), Regev decryption keys.

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

### TM-C6 — Key separation and A11 extension (now a three-signing-key member)
`sk_g` (bp/IMSB) and `sk_f` (cosign) coexist. Threats: (a) cross-use — a cosign artifact
accepted on the bp path or vice versa: excluded structurally (different verifier stacks:
Falcon-native/in-circuit vs SingleSig-proof; different message domains IMCH vs IMSB; **O-6:
negative test feeding a Falcon signature to `list_leaf`-side consumers and a SingleSig proof to
the Falcon verifier — both must reject**); (b) binding — `pk_f` must be inseparably bound to the
same member as `pk_g`/`pk_b`/regev at registration (A11 pattern): `pk_f` joins `MemberLeaf` and
the per-slot L1 registration keccak preimage. **O-7: mismatched-pair rejection tests for every
pair involving pk_f; delegate-count and slot semantics unchanged.**

### TM-C7 — Registration preimage & member-set commitment migration
`MemberLeaf` gains `pk_f` (3→4 fields) and the registration keccak preimage per slot becomes
`pk_g‖pk_b‖pk_f‖regev‖recipient` — this **invalidates every baked fixture** that contains a
registration (the delegate-account migration is precedent, including its "stale fixture
generator" gotcha). The close/cancel-close member-set commitment switches to bind the keys the
circuit actually verifies against: keccak `[IMC2, member_count, pk_f_0..15]` (new domain IMC2;
IMCM retired to the pinned-value non-collision test). Solidity `registeredMemberSetCommitment`
recomputes over pk_f; `channelBpPkG` stays pk_g (bp path untouched). **O-8: Rust↔Solidity
shared-vector re-pin for the new commitment; padding argument re-written: a padding slot's
`pk_f = 0x0…0` and forging it real requires a Poseidon preimage of the zero digest under IMFK
(state the argument at the new site).**

### TM-C8 — Old-format signature replay / downgrade
After the swap, a ~76 KB SingleSig proof blob must never verify as a cosignature.
**O-9: `MemberSignature.signature` gets a leading format-version byte; the new verifier rejects
version ≠ FALCON_V1 before parsing; explicit test that a valid OLD proof blob is rejected (not
merely "fails to parse"). The structural checks (`validate_all_member_signatures`) update their
size sanity from "non-empty" to the fixed Falcon encoding length.**

### TM-C9 — Wire/size-sensitive consumers
`SignedSmallBlock::signing_digest()` keccaks signature bytes+length (stays SingleSig — bp path —
so UNCHANGED); node tests assert the delta payload exceeds the signature set (inverts at 666 B —
fix the tests' premise, they encoded a contingent fact); slim-downlink carryHash and the relay
byte-table comments reference 833 KB signatures (update). **O-10: sweep every size assumption
found by the surface map; the wallet wire keeps field names (`memberSlot`, `pkG`→ stays for bp
identity? NO — `MemberSignature.pk_g` field is renamed `pk_f` in meaning; keep the JSON key
stable only if the migration story requires it — decide at Phase 4 with a version bump, not
silent reuse).**

### TM-C10 — Key derivation and restore
`MemberKeys::from_seed(32B)` must yield the Falcon keypair deterministically (seeded ChaCha20
driving NTRU keygen), or restore-from-seed silently forks identities. **O-11: same-seed ⇒ same
`h`/`pk_f` test, cross-platform (native vs wasm32) keygen determinism test; keygen (~10–50 ms
native) runs at join/restore only, never per signature.**

### TM-C11 — Algebraic-hash margin
Poseidon in a new role (H2P). No known applicable attack; consistent with the system-wide
Poseidon dependency; plonky2's audited-parameter instance, no custom constants. **Monitored.**

## 4. Explicitly out of scope
- Fault injection (no HSM claims).
- Validity path (IMSB/ListCircuit/bp_sig_chain), `pk_b` Plonky3 sender sig, Regev keys.
- Threshold/aggregate Falcon — N independent signatures verified directly.
- FN-DSA wire compatibility (H2P differs by design; parameters/sampler track the draft).

## 5. Non-goals confirmed with owner
- No dual-scheme transition period: v3 testnet resets (same policy as multitoken).
