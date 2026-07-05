# Regev decryption-noise analysis (channel parameter set)

Worst-case (not heuristic) noise analysis for the channel Regev parameter set,
justifying `MAX_HOMO_ADDS_BEFORE_REFRESH = 64` (design decision D1/D3, threat
finding F5-B). All bounds are exact infinity-norms derived from the *bounded*
distributions the STARKs range-check; none rely on a tail/Gaussian argument.

## 1. Parameters

| Symbol | Value | Source |
|---|---|---|
| `n` (ring dimension) | `128` | `REGEV_N`, detail2 §B-1 |
| `q` (ciphertext modulus = field prime, BabyBear) | `2_013_265_921 = 2^31 − 2^27 + 1` | `REGEV_Q` |
| `eta` (CBD parameter) | `2` (noise in `[−2, 2]`) | `REGEV_ETA` |
| `t` (plaintext modulus) | `2^8 = 256` | `REGEV_PLAIN_BITS = 8` |
| `Δ = floor(q / t)` | `7_864_320 = 15·2^19` | `DELTA_U32` |
| `Δ/2` | `3_932_160 ≈ 2^21.91` | `HALF_DELTA_U32` |
| Value encoding (D1) | 1 bit per coefficient, 64 low coefficients | `encode_amount` |
| `MAX_HOMO_ADDS_BEFORE_REFRESH` | `64` | `params.rs` |

Compile-time identities pinned in `transfer_stark.rs` (load-bearing for the
E-3 digit-extraction soundness, re-derived below):
`q = 256·Δ + 1`, `Δ = 15·2^19`, `Δ` even.

Secret/randomness ranges, all enforced in-circuit by degree-3 vanishing
constraints (`x(x−1)(x+1)` for ternary, `x(x−1)(x−2)` on each CBD half):

* `s` (secret key), `r` (encryption randomness): ternary, `|·| ≤ 1`.
* `e` (key noise), `e1`, `e2` (encryption noise): `CBD(2)`, `|·| ≤ 2`,
  represented as `u − v` with `u, v ∈ {0,1,2}`.

## 2. Per-coefficient noise of one fresh ciphertext

For a fresh encryption `c1 = a·r + e1`, `c2 = b·r + e2 + Δ·m` under
`b = a·s + e`, the decryption value polynomial is

```
v = c2 − c1·s
  = (a·s + e)·r + e2 + Δ·m − (a·r + e1)·s
  = Δ·m + (e·r + e2 − e1·s)        (all products negacyclic, mod x^n + 1)
```

so the per-coefficient decryption noise is

```
noise = e·r + e2 − e1·s     ∈ R_q = Z_q[x]/(x^n + 1).
```

**Exact infinity-norm bound.** In a negacyclic convolution of two length-`n`
polynomials, every output coefficient is a signed sum of exactly `n` coefficient
products (`x^n ≡ −1` folds the upper half back with a minus sign), so

```
‖e·r‖_∞   ≤ n · ‖e‖_∞  · ‖r‖_∞ = 128 · 2 · 1 = 256
‖e1·s‖_∞  ≤ n · ‖e1‖_∞ · ‖s‖_∞ = 128 · 2 · 1 = 256
‖e2‖_∞    ≤ 2                                  (added coefficient-wise, no convolution)
```

Therefore the worst-case per-coefficient noise of **one** fresh ciphertext is

```
B_fresh := ‖noise‖_∞ ≤ 256 + 256 + 2 = 514.
```

This is the exact worst case, not an estimate: it is attained when the relevant
`e, r, e1, s` coefficients simultaneously sit at their range bounds with aligned
signs. Because the encryption STARK (E-1/E-2) and the decryption STARK (E-3,
refresh) range-check `r` to ternary and the CBD halves to `{0,1,2}`, an
**adversarially chosen but well-formed** ciphertext cannot exceed `B_fresh`
either — the same bounds that hold for honest ciphertexts are enforced on every
ciphertext a sound proof accepts.

## 3. Accumulated noise after homomorphic additions

Homomorphic addition is coefficient-wise (`add_ciphertexts`): for
`ct_Σ = Σ_k ct_k`, decryption is linear, so

```
v_Σ = c2_Σ − c1_Σ·s = Σ_k (Δ·m_k + noise_k) = Δ·(Σ_k m_k) + Σ_k noise_k.
```

The noise adds, hence after `N` homomorphic additions of fresh ciphertexts
(under the *same* receiver key, which is the only operation that accumulates
noise — the sender re-encrypts, see detail2 §B-3):

```
B_acc(N) := ‖Σ_k noise_k‖_∞ ≤ N · B_fresh = N · 514.
```

For `N = 64`:

```
B_acc(64) ≤ 64 · 514 = 32_896 ≈ 2^15.0.
```

(The receiver key noise `e` and secret `s` are common to all terms, so a tighter
bound `‖e·(Σ r_k) + Σ e2_k − (Σ e1_k)·s‖_∞` also exists, but the linear
`N·B_fresh` bound already gives a large margin and is the conservative
worst case.)

## 4. Digit headroom

Each set message bit contributes a digit of `1` to its coefficient; after `N`
stacked additions of binary messages the per-coefficient digit reaches at most
`N`. The decode step (`decrypt_amount` and the E-3 normalization adder) requires
every digit `< t = 256`:

```
digit_max(64) = 64  <  256.     Headroom factor 256/64 = 4×.
```

So `64` keeps a 4× digit margin. The digit constraint, not the noise
constraint, is the binding one (see §7).

## 5. Decryption-correctness condition

Decryption rounds each coefficient `v_i = Δ·d_i + noise_i` to the nearest
multiple of `Δ`. The digit `d_i` is recovered correctly iff the centered noise
stays strictly inside the half-step:

```
|noise_i| < Δ/2 = 3_932_160.
```

With the accumulated bound:

```
B_acc(64) = 32_896  <  Δ/2 = 3_932_160.     Noise margin Δ/2 / B_acc ≈ 119.5×.
```

Because the noise distribution is **bounded** (finite support `[−B_acc, B_acc]`)
and `B_acc(64) < Δ/2`, every coefficient is decoded correctly with **zero**
failure probability — there is no tail that crosses the rounding boundary. This
holds for honest *and* adversarial-but-well-formed ciphertexts, since the STARK
range-checks pin every component to the same bounds used to derive `B_acc`.

### E-3 circuit noise-range capacity

The E-3 / refresh decryption AIR proves, per coefficient, the field identity

```
v_i + Δ/2 = Δ·d_i + ns_i,   d_i ∈ [0, 256),   ns_i ∈ [0, Δ),
```

where `ns_i = noise_i + Δ/2` is the **shifted** centered noise. The shifted
range `[0, Δ)` is constructed exactly (not approximately) by the limb layout
`ns = lo + (u + v)·2^19` with `lo` a 19-bit value and `u, v` two 3-bit values,
each individually range-checked, so `u + v ∈ [0, 14]` (no separate `u+v ≤ 14`
constraint is required — it follows from `u, v ≤ 7`) and

```
ns_max = (2^19 − 1) + 14·2^19 = 15·2^19 − 1 = Δ − 1.
```

This exact `[0, Δ)` range is what makes digit recovery **unique** mod `q`: if
two pairs `(d, ns)`, `(d', ns')` satisfy the identity for the same `v`, then
`Δ·(d−d') + (ns−ns') ≡ 0 (mod q)` with absolute value at most
`255·Δ + (Δ−1) = 256·Δ − 1 = q − 2 < q`, forcing the difference to be exactly
zero, hence `d = d'` and `ns = ns'`. A looser `[0, 2^23)` decomposition would
allow `255·Δ + 2^23 ≥ q` and let an adversary alias digit 0 as digit 255; the
19+3+3 split closes that gap.

Within the protocol budget the *used* shifted-noise window is
`[Δ/2 − B_acc(64), Δ/2 + B_acc(64)] = [3_899_264, 3_965_056]`, comfortably
inside the circuit's `[0, Δ)` capacity (`Δ = 7_864_320`), with `Δ/2 ≫ B_acc`.
There is no risk of the shifted noise wrapping below `0` or reaching `Δ`.

### Rounding-convention consistency

Upstream `decrypt` uses `round(v·t/q)`, whose digit boundaries sit at
`Δ·d − Δ/2 + d/256` — offset by `< 1` from this circuit's boundaries at
`Δ·d − Δ/2`. The two agree everywhere except when `|noise| = Δ/2` exactly
(`≈ 2^21.9`), which is unreachable for `B_acc(64) ≈ 2^15`. The prover
additionally re-derives the value from the circuit's own decomposition and
refuses if it disagrees with the claimed amount, so a boundary disagreement can
never yield an accepted-but-wrong proof.

## 6. Safety margins (summary, N = 64)

| Constraint | Limit | Worst case @ 64 | Margin |
|---|---|---|---|
| Digit headroom | `< 256` | `64` | `4×` |
| Decryption noise | `< Δ/2 = 3_932_160` | `≤ 32_896` | `≈ 119.5×` |
| E-3 shifted-noise range | `[0, Δ) = [0, 7_864_320)` | `[3_899_264, 3_965_056]` | inside, `Δ/2 ≫ B_acc` |
| Decryption failure probability | — | `0` (bounded support) | — |

## 7. Conclusion: is MAX = 64 approved-safe, and what is the true maximum?

**`MAX_HOMO_ADDS_BEFORE_REFRESH = 64` is approved-safe.** At `N = 64` the
worst-case decryption noise (`≤ 32_896`) is `≈ 119×` below the decryption
threshold `Δ/2`, the worst-case digit (`64`) is `4×` below the digit modulus
`t = 256`, and decryption failure probability is exactly `0` because all
distributions are bounded and the worst case stays inside both budgets — for
honest and adversarial-but-well-formed ciphertexts alike.

**True maximum.** The two constraints give:

* Digit: `N < 256`  ⇒  `N ≤ 255`.
* Noise: `N · 514 < Δ/2 = 3_932_160`  ⇒  `N < 7_650`.

The **digit headroom is the binding constraint**: the protocol could in
principle tolerate up to `N = 255` homomorphic additions before a refresh
becomes mandatory (the noise budget alone would allow `~7_650`). The chosen
`64` therefore sits at roughly one quarter of the hard maximum, leaving a
deliberate safety buffer on the binding (digit) axis and an enormous buffer on
the noise axis. No change to `64` is recommended; if a larger batch were ever
needed, any value up to `255` would remain decryption-correct, but `64` is the
conservative, approved value.
