# Poseidon-preimage signature — key-entropy & preimage-security note

Scope: the **Goldilocks** member key introduced in Phase 1 (`src/poseidon_sig/`). The BabyBear key
(Phase 3) gets its own analysis when it lands. See `tasks/poseidon-signature-threat-model.md` for the
full threat model and the approved decisions (D1 two-key, D2 ≥256-bit).

## Scheme recap

- `sk ∈ Goldilocks^4` (canonical limbs).
- `pk  = Poseidon_Goldilocks([DOMAIN_PK_G]  ‖ sk)`  → `Bytes32` (4 Goldilocks limbs).
- `sig = Poseidon_Goldilocks([DOMAIN_SIG_G] ‖ sk ‖ m)` (witness-only).

Unforgeability reduces to **preimage resistance** of Poseidon-Goldilocks on `sk`: forging a signature
for a target `pk` requires producing `sk'` with `pk = Poseidon([DOMAIN_PK_G] ‖ sk')`, i.e. a preimage.

## Why `SECRET_KEY_LEN = 4`

Two independent quantities must each carry ≥256 bits to hit the D2 target (256-bit classical /
128-bit quantum):

1. **Secret-key entropy.** The Goldilocks prime is `p = 2^64 − 2^32 + 1 ≈ 2^63.9999999998`. A uniform
   canonical element therefore carries `log2(p) ≈ 63.99999999986` bits. Four independent limbs give
   `≈ 255.99999999944` bits of key entropy — effectively the full 256-bit target. A brute-force key
   search is `≈ 2^256` classically and `≈ 2^128` under Grover.

2. **Digest / output space.** `pk` is a `Bytes32` built from the 4-limb `PoseidonHashOut`
   (`4 × log2(p) ≈ 256` bits of usable output). The preimage search space on the *output* side is thus
   also ≈256-bit, so the output width does not become the weak link.

Because both the input and output spaces are ≈256-bit, the preimage attack stays at ≈256-bit classical
/ ≈128-bit quantum. Using fewer limbs (e.g. 2) would drop key entropy to ≈128-bit classical / ≈64-bit
quantum, below the post-quantum-conscious target inherited from SPHINCS+ — hence rejected.

## Security-basis caveat (carried from the threat model)

This replaces standardized SPHINCS+ (a conservative, audited hash-based signature) with a bespoke
"Poseidon-preimage-as-signature" on an algebraic hash. The trade-off (much cheaper in-circuit, smaller
proofs, still plausibly post-quantum via preimage resistance) is **user-approved**. `SECRET_KEY_LEN`
and the domain constants are approved security parameters: per CLAUDE.md they must not be changed
silently.

## Randomness source

`GoldilocksSecretKey::rand` requires a CSPRNG (e.g. `OsRng`); `from_seed` expects a 32-byte
high-entropy seed (CSPRNG or KDF output). Key unpredictability is a precondition of unforgeability.

## Sampling-uniformity footnote

`rand` draws each limb uniformly over `[0, p−1)` (mirroring `PoseidonHashOut::rand`), excluding the
single value `p−1`. The resulting entropy loss is `< 2^-63` bits per limb and is cryptographically
irrelevant. `from_limbs` / `from_seed` reduce arbitrary u64 inputs into the canonical range.
