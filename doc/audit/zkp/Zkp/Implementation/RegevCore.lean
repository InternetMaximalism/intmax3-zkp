import Std
import Zkp.Implementation.DecryptionGadget

/-!
# Regev (Ring-LWE) channel encryption layer

Hand-written semantic model of the production code in `src/regev/params.rs`,
`src/regev/keys.rs`, `src/regev/encrypt.rs` and the re-export/hash helper in
`src/regev/mod.rs`. This is NOT a refinement proof of the Rust sources, of the
`regev_plonky3` crate, or of any compiled circuit: the Lean definitions are a
restatement of what those files do, and the theorems are about the restatement.

What is deliberately NOT claimed here:

* No lattice hardness. `RingLweHardness` is never stated; secrecy of an amount
  given `(a, b, c1, c2)` is outside the model.
* No decryption correctness. The upstream `regev_plonky3::encrypt` / `decrypt`
  ring arithmetic (NTT, negacyclic reduction, centred rounding) is an opaque
  callback; that a ciphertext decrypts to the digits of the encoded amount, and
  that coefficient-wise ciphertext addition induces digit-wise addition, are
  explicit premises (`DecryptsTo`, `HomomorphicDigits`), not results.
* No randomness quality. The RNG, the ternary secret sampling and the CBD(2)
  noise distribution are boundaries; `cbdWorstCaseNoise` restates the source's
  worst-case comment as arithmetic, it does not bound sampled noise.
* No hash binding. Digests are modelled as the exact word streams handed to
  keccak / Poseidon; collision resistance and "equal digest implies equal key"
  are not proved.
* Nothing about enforcement. `maxHomoAddsBeforeRefresh` is a constant here; the
  per-member `pending_adds` counter that must enforce it lives in the state
  update circuits, outside these files.

The `Zkp.Implementation.DecryptionGadget` import is used only to cross-check the
constants and the amount encoding: that module models the in-circuit decryption
of exactly this scheme, so the parameter set and the 64-bit little-endian
message layout must agree, and the agreement is stated as theorems.
-/

namespace Zkp.Implementation.RegevCore

/-! ## Parameter set (`src/regev/params.rs`) -/

/-- Ring dimension `n` of `R_q = Z_q[x]/(x^n + 1)` (`REGEV_N`). -/
def regevN : Nat := 2048
/-- Centred-binomial noise parameter `η` (`REGEV_ETA`). -/
def regevEta : Nat := 2
/-- log2 of the plaintext modulus `t` (`REGEV_PLAIN_BITS`). -/
def regevPlainBits : Nat := 8
/-- Ciphertext modulus `q`, the BabyBear prime (`REGEV_Q`). -/
def regevQ : Nat := 2013265921
/-- Homomorphic-addition budget before a refresh (`MAX_HOMO_ADDS_BEFORE_REFRESH`). -/
def maxHomoAddsBeforeRefresh : Nat := 64
/-- Plaintext modulus `t = 2 ^ REGEV_PLAIN_BITS`. -/
def plainModulus : Nat := 2 ^ regevPlainBits

/-- The `RegevParams` record `channel_regev_params()` builds. -/
structure Params where
  n : Nat
  eta : Nat
  plainBits : Nat
  deriving DecidableEq, Repr

def channelParams : Params := ⟨regevN, regevEta, regevPlainBits⟩

theorem regev_constants_pinned :
    regevN = 2048 ∧ regevEta = 2 ∧ regevPlainBits = 8 ∧ regevQ = 2013265921 ∧
    maxHomoAddsBeforeRefresh = 64 ∧ plainModulus = 256 ∧
    channelParams = ⟨2048, 2, 8⟩ := by
  refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- `RegevParams::validate` requires a power-of-two ring degree (negacyclic NTT). -/
theorem ring_degree_is_power_of_two : regevN = 2 ^ 11 := by decide

/-- The scaling factor `Δ` and its half, as pinned by the decryption gadget:
`t · Δ + 1 = q`. -/
theorem constants_agree_with_decryption_gadget :
    regevN = DecryptionGadget.ringN ∧
    regevQ = DecryptionGadget.q ∧
    plainModulus * DecryptionGadget.delta + 1 = regevQ ∧
    DecryptionGadget.halfDelta * 2 = DecryptionGadget.delta ∧
    DecryptionGadget.delta = 7864320 := by
  refine ⟨rfl, rfl, by decide, by decide, rfl⟩

/-- The source's worst-case accumulated CBD(2) noise after `adds` homomorphic
additions: `adds · (4n + 2)` (a restatement of the `params.rs` comment, not a
bound on sampled noise). -/
def cbdWorstCaseNoise (adds : Nat) : Nat := adds * (4 * regevN + 2)

/-- Digit headroom and the noise margin quoted in `params.rs`: 64 additions keep
the per-coefficient digit below `t = 256` and the accumulated noise below `Δ/2`. -/
theorem noise_and_digit_budget :
    cbdWorstCaseNoise maxHomoAddsBeforeRefresh = 524416 ∧
    cbdWorstCaseNoise maxHomoAddsBeforeRefresh < DecryptionGadget.halfDelta ∧
    maxHomoAddsBeforeRefresh < plainModulus ∧
    DecryptionGadget.halfDelta = 3932160 := by
  refine ⟨by decide, by decide, by decide, rfl⟩

/-! ## Domain separators (`src/regev/keys.rs`, `src/regev/encrypt.rs`) -/

/-- `REGEV_PK_DOMAIN` ("IMRK"). -/
def regevPkDomain : Nat := 0x494d524b
/-- `REGEV_PK_ROOT_DOMAIN` ("IMRR"). -/
def regevPkRootDomain : Nat := 0x494d5252
/-- `REGEV_PK_POSEIDON_DOMAIN` ("IMRP"). -/
def regevPkPoseidonDomain : Nat := 0x494d5250
/-- `REGEV_CT_DOMAIN` ("IMRC"). -/
def regevCtDomain : Nat := 0x494d5243

theorem domain_separators_distinct :
    regevPkDomain ≠ regevPkRootDomain ∧ regevPkDomain ≠ regevPkPoseidonDomain ∧
    regevPkDomain ≠ regevCtDomain ∧ regevPkRootDomain ≠ regevPkPoseidonDomain ∧
    regevPkRootDomain ≠ regevCtDomain ∧ regevPkPoseidonDomain ≠ regevCtDomain := by
  refine ⟨by decide, by decide, by decide, by decide, by decide, by decide⟩

/-! ## Errors and data (`src/regev/encrypt.rs`, `src/regev/keys.rs`)

The Rust variants carry `String` payloads; the model keeps only the variant,
so error-message content is out of scope. -/

inductive RegevError where
  | invalidPk
  | invalidSk
  | invalidCiphertext
  | decryptOverflow
  | invalidWitness
  | proofCodec
  | proofVerification
  | purposeMismatch
  deriving DecidableEq, Repr

/-- `RegevPk { a, b }`: uniform `a` and `b = a·s + e`, canonical `u32` coefficients. -/
structure RegevPk where
  a : List Nat
  b : List Nat
  deriving DecidableEq, Repr

/-- `RegevSk { s }`: the ternary secret, entries in `{-1, 0, 1}`. Never serialised
and never part of any digest in the source; the model likewise never feeds it to
a digest word stream. -/
structure RegevSk where
  s : List Int
  deriving DecidableEq, Repr

/-- `RegevCiphertext { c1, c2 }`. -/
structure RegevCiphertext where
  c1 : List Nat
  c2 : List Nat
  deriving DecidableEq, Repr

/-- The ternary-secret shape check the source states as a comment/test invariant. -/
def TernarySecret (sk : RegevSk) : Prop :=
  sk.s.length = regevN ∧ ∀ x ∈ sk.s, -1 ≤ x ∧ x ≤ 1

def coeffsCanonical (xs : List Nat) : Bool := xs.all (fun c => decide (c < regevQ))

theorem coeffs_canonical_iff (xs : List Nat) :
    coeffsCanonical xs = true ↔ ∀ c ∈ xs, c < regevQ := by
  simp [coeffsCanonical]

/-- `RegevPk::padding()`. -/
def RegevPk.padding : RegevPk :=
  ⟨List.replicate regevN 0, List.replicate regevN 0⟩

/-- `RegevCiphertext::padding()`. -/
def RegevCiphertext.padding : RegevCiphertext :=
  ⟨List.replicate regevN 0, List.replicate regevN 0⟩

/-- `RegevPk::validate`: exact length first, then canonicality over `a` then `b`. -/
def RegevPk.validate (pk : RegevPk) : Except RegevError Unit :=
  if pk.a.length = regevN ∧ pk.b.length = regevN then
    if coeffsCanonical (pk.a ++ pk.b) then .ok () else .error .invalidPk
  else .error .invalidPk

/-- `RegevCiphertext::validate`. -/
def RegevCiphertext.validate (ct : RegevCiphertext) : Except RegevError Unit :=
  if ct.c1.length = regevN ∧ ct.c2.length = regevN then
    if coeffsCanonical (ct.c1 ++ ct.c2) then .ok () else .error .invalidCiphertext
  else .error .invalidCiphertext

theorem pk_validate_ok_iff (pk : RegevPk) :
    pk.validate = .ok () ↔
      pk.a.length = regevN ∧ pk.b.length = regevN ∧ ∀ c ∈ pk.a ++ pk.b, c < regevQ := by
  unfold RegevPk.validate
  by_cases hl : pk.a.length = regevN ∧ pk.b.length = regevN
  · by_cases hc : coeffsCanonical (pk.a ++ pk.b) = true
    · simp [hl, hc, hl.1, hl.2, (coeffs_canonical_iff _).1 hc]
    · simp [hl, hc]
      intro h1 h2
      exact fun h3 => hc ((coeffs_canonical_iff _).2 h3)
  · simp [hl]
    intro h1 h2
    exact absurd ⟨h1, h2⟩ hl

theorem ct_validate_ok_iff (ct : RegevCiphertext) :
    ct.validate = .ok () ↔
      ct.c1.length = regevN ∧ ct.c2.length = regevN ∧ ∀ c ∈ ct.c1 ++ ct.c2, c < regevQ := by
  unfold RegevCiphertext.validate
  by_cases hl : ct.c1.length = regevN ∧ ct.c2.length = regevN
  · by_cases hc : coeffsCanonical (ct.c1 ++ ct.c2) = true
    · simp [hl, hc, hl.1, hl.2, (coeffs_canonical_iff _).1 hc]
    · simp [hl, hc]
      intro h1 h2
      exact fun h3 => hc ((coeffs_canonical_iff _).2 h3)
  · simp [hl]
    intro h1 h2
    exact absurd ⟨h1, h2⟩ hl

/-- Component widths: a validated ciphertext has exactly `REGEV_N` coefficients in
each of `c1` and `c2`, every one below `q`. -/
theorem ct_component_widths (ct : RegevCiphertext) (h : ct.validate = .ok ()) :
    ct.c1.length = regevN ∧ ct.c2.length = regevN ∧
    (∀ c ∈ ct.c1, c < regevQ) ∧ (∀ c ∈ ct.c2, c < regevQ) := by
  obtain ⟨h1, h2, h3⟩ := (ct_validate_ok_iff ct).1 h
  refine ⟨h1, h2, ?_, ?_⟩
  · intro c hc; exact h3 c (List.mem_append.2 (Or.inl hc))
  · intro c hc; exact h3 c (List.mem_append.2 (Or.inr hc))

theorem pk_component_widths (pk : RegevPk) (h : pk.validate = .ok ()) :
    pk.a.length = regevN ∧ pk.b.length = regevN ∧
    (∀ c ∈ pk.a, c < regevQ) ∧ (∀ c ∈ pk.b, c < regevQ) := by
  obtain ⟨h1, h2, h3⟩ := (pk_validate_ok_iff pk).1 h
  refine ⟨h1, h2, ?_, ?_⟩
  · intro c hc; exact h3 c (List.mem_append.2 (Or.inl hc))
  · intro c hc; exact h3 c (List.mem_append.2 (Or.inr hc))

theorem replicate_zero_canonical (n : Nat) :
    ∀ c ∈ List.replicate n (0 : Nat), c < regevQ := by
  intro c hc
  rw [List.eq_of_mem_replicate hc]
  decide

theorem padding_ct_validates : RegevCiphertext.padding.validate = .ok () := by
  refine (ct_validate_ok_iff _).2 ⟨?_, ?_, ?_⟩
  · exact List.length_replicate _ _
  · exact List.length_replicate _ _
  · intro c hc
    rcases List.mem_append.1 hc with h | h <;> exact replicate_zero_canonical _ _ h

theorem padding_pk_validates : RegevPk.padding.validate = .ok () := by
  refine (pk_validate_ok_iff _).2 ⟨?_, ?_, ?_⟩
  · exact List.length_replicate _ _
  · exact List.length_replicate _ _
  · intro c hc
    rcases List.mem_append.1 hc with h | h <;> exact replicate_zero_canonical _ _ h

/-- `RegevCiphertext::validate_balance_exit_shape`: host acceptance for a newly
accepted balance. Canonical zero stays acceptable as an empty slot; zero `c1`
with nonzero `c2` is refused. -/
def RegevCiphertext.validateBalanceExitShape (ct : RegevCiphertext) :
    Except RegevError Unit := do
  let _ ← ct.validate
  if ct.c1.all (fun c => c == 0) ∧ ct.c2.any (fun c => c != 0) then
    .error .invalidCiphertext
  else
    .ok ()

theorem exit_shape_accepts_padding :
    RegevCiphertext.padding.validateBalanceExitShape = .ok () := by
  unfold RegevCiphertext.validateBalanceExitShape
  rw [padding_ct_validates]
  have h : RegevCiphertext.padding.c2.any (fun c => c != 0) = false := by
    simp [RegevCiphertext.padding]
  simp [h]

theorem exit_shape_refuses_zero_c1_nonzero_c2 (ct : RegevCiphertext)
    (hv : ct.validate = .ok ())
    (h1 : ∀ c ∈ ct.c1, c = 0) (h2 : ∃ c ∈ ct.c2, c ≠ 0) :
    ct.validateBalanceExitShape = .error .invalidCiphertext := by
  unfold RegevCiphertext.validateBalanceExitShape
  rw [hv]
  have ha : ct.c1.all (fun c => c == 0) = true := by
    simp only [List.all_eq_true, beq_iff_eq]
    exact fun c hc => h1 c hc
  have hb : ct.c2.any (fun c => c != 0) = true := by
    obtain ⟨c, hc, hne⟩ := h2
    simp only [List.any_eq_true, bne_iff_ne, ne_eq]
    exact ⟨c, hc, hne⟩
  simp [ha, hb]

/-! ## Digest preimages (`keys.rs::digest`, `keys.rs::poseidon_digest`,
`encrypt.rs::digest`, `keys.rs::regev_pk_root`)

The hash itself is a boundary: the model produces the exact word stream and
nothing else. `none` models the source's `assert!(validate().is_ok())` panic —
no digest exists for a non-canonical key or ciphertext. -/

def RegevPk.digestWords (pk : RegevPk) : Option (List Nat) :=
  match pk.validate with
  | .ok _ => some ([regevPkDomain, regevN] ++ pk.a ++ pk.b)
  | .error _ => none

def RegevPk.poseidonWords (pk : RegevPk) : Option (List Nat) :=
  match pk.validate with
  | .ok _ => some ([regevPkPoseidonDomain, regevN] ++ pk.a ++ pk.b)
  | .error _ => none

def RegevCiphertext.digestWords (ct : RegevCiphertext) : Option (List Nat) :=
  match ct.validate with
  | .ok _ => some ([regevCtDomain, ct.c1.length] ++ ct.c1 ++ ct.c2)
  | .error _ => none

theorem pk_digest_none_on_invalid (pk : RegevPk) (h : pk.validate ≠ .ok ()) :
    pk.digestWords = none ∧ pk.poseidonWords = none := by
  constructor <;>
    (unfold RegevPk.digestWords RegevPk.poseidonWords
     cases hv : pk.validate with
     | ok u => cases u; exact absurd hv h
     | error e => rfl)

theorem ct_digest_none_on_invalid (ct : RegevCiphertext) (h : ct.validate ≠ .ok ()) :
    ct.digestWords = none := by
  unfold RegevCiphertext.digestWords
  cases hv : ct.validate with
  | ok u => cases u; exact absurd hv h
  | error e => rfl

theorem digest_preimage_lengths (pk : RegevPk) (ct : RegevCiphertext)
    (hp : pk.validate = .ok ()) (hc : ct.validate = .ok ()) :
    pk.digestWords = some ([regevPkDomain, regevN] ++ pk.a ++ pk.b) ∧
    ct.digestWords = some ([regevCtDomain, regevN] ++ ct.c1 ++ ct.c2) ∧
    ([regevPkDomain, regevN] ++ pk.a ++ pk.b).length = 4098 ∧
    ([regevCtDomain, regevN] ++ ct.c1 ++ ct.c2).length = 4098 := by
  obtain ⟨ha, hb, _⟩ := (pk_validate_ok_iff pk).1 hp
  obtain ⟨h1, h2, _⟩ := (ct_validate_ok_iff ct).1 hc
  refine ⟨by simp [RegevPk.digestWords, hp], ?_, by simp [ha, hb, regevN], by simp [h1, h2, regevN]⟩
  simp [RegevCiphertext.digestWords, hc, h1]

/-- The keccak ciphertext-digest preimage agrees, word for word, with the stream
the in-circuit gadget model commits to. -/
theorem ct_digest_words_match_decryption_gadget (ct : RegevCiphertext)
    (h : ct.validate = .ok ()) :
    ct.digestWords = DecryptionGadget.ciphertextDigestWords ct.c1 ct.c2 := by
  obtain ⟨h1, h2, _⟩ := (ct_validate_ok_iff ct).1 h
  rw [DecryptionGadget.ciphertext_digest_exact_words ct.c1 ct.c2 h1 h2]
  simp [RegevCiphertext.digestWords, h, h1, regevCtDomain, regevN, DecryptionGadget.ringN]

/-- The Poseidon member-tree preimage agrees with the in-circuit gadget model. -/
theorem pk_poseidon_words_match_decryption_gadget (pk : RegevPk)
    (h : pk.validate = .ok ()) :
    pk.poseidonWords = DecryptionGadget.publicKeyDigestWords pk.a pk.b := by
  obtain ⟨h1, h2, _⟩ := (pk_validate_ok_iff pk).1 h
  rw [DecryptionGadget.public_key_digest_exact_words pk.a pk.b h1 h2]
  simp [RegevPk.poseidonWords, h, regevPkPoseidonDomain, regevN, DecryptionGadget.ringN]

/-- `regev_pk_root`: `[IMRR, len] ++ digest(pk_0) ++ … ++ digest(pk_{len-1})`.
`digestOf` is the opaque keccak-output-to-words callback. -/
def pkRootWords (digestOf : RegevPk → List Nat) (pks : List RegevPk) : List Nat :=
  [regevPkRootDomain, pks.length] ++ pks.bind digestOf

/-- Member order is part of the root preimage: swapping two members whose digests
differ changes the hashed word stream. This is a statement about the preimage,
not about the hash. -/
theorem pk_root_preimage_order_sensitive (digestOf : RegevPk → List Nat)
    (x y : RegevPk) (hx : (digestOf x).length = 8) (hy : (digestOf y).length = 8)
    (hne : digestOf x ≠ digestOf y) :
    pkRootWords digestOf [x, y] ≠ pkRootWords digestOf [y, x] := by
  intro heq
  simp only [pkRootWords, List.bind, List.map, List.join, List.append_nil,
    List.length_cons, List.length_nil] at heq
  have h := List.append_cancel_left heq
  exact hne (List.append_inj_left h (by rw [hx, hy]))

/-- The root preimage also separates member counts: a prefix of the member list
produces a different length word. -/
theorem pk_root_preimage_binds_count (digestOf : RegevPk → List Nat)
    (pks qs : List RegevPk) (h : pks.length ≠ qs.length) :
    pkRootWords digestOf pks ≠ pkRootWords digestOf qs := by
  intro heq
  simp only [pkRootWords, List.cons_append, List.nil_append] at heq
  exact h (by injection heq with _ h2; injection h2 with h3 _; exact h3)

/-! ## Amount encoding (`encode_amount` / upstream `encode_value_message`)

Deviation D1: one bit per coefficient, 64 low coefficients little-endian, zero
above. -/

/-- Number of message coefficients carrying amount bits. -/
def amountBits : Nat := 64

def bitAt (v i : Nat) : Nat := v / 2 ^ i % 2

/-- `encode_amount(amount)`. -/
def encodeAmount (v : Nat) : List Nat :=
  (List.range amountBits).map (bitAt v) ++ List.replicate (regevN - amountBits) 0

/-! ### Arithmetic and list helpers -/

theorem range_length_eq (n : Nat) : (List.range n).length = n := by
  have h : ∀ n (acc : List Nat), (List.range.loop n acc).length = n + acc.length := by
    intro n
    induction n with
    | zero => intro acc; simp [List.range.loop]
    | succ n ih => intro acc; simp only [List.range.loop, ih, List.length_cons]; omega
  simpa [List.range] using h n []

theorem range_succ_append (n : Nat) : List.range (n + 1) = List.range n ++ [n] := by
  have h : ∀ n (acc l : List Nat),
      List.range.loop n (acc ++ l) = List.range.loop n acc ++ l := by
    intro n
    induction n with
    | zero => intro acc l; rfl
    | succ n ih => intro acc l; simpa [List.range.loop] using ih (n :: acc) l
  show List.range.loop (n + 1) [] = _
  simp only [List.range.loop]
  simpa [List.range] using h n [] [n]

theorem mod_two_pow_split (A v : Nat) (hA : 0 < A) :
    v % (A * 2) = v % A + v / A % 2 * A := by
  have h1 : A * (v / A) + v % A = v := Nat.div_add_mod v A
  have h2 : 2 * (v / A / 2) + v / A % 2 = v / A := Nat.div_add_mod (v / A) 2
  have hm : v % A < A := Nat.mod_lt _ hA
  have hr : v / A % 2 < 2 := Nat.mod_lt _ (by decide)
  rw [← h2] at h1
  rw [Nat.mul_add, ← Nat.mul_assoc] at h1
  have hv : v = (v % A + v / A % 2 * A) + A * 2 * (v / A / 2) := by
    rw [Nat.mul_comm (v / A % 2) A]; omega
  have hlt : v % A + v / A % 2 * A < A * 2 := by
    have hcase : v / A % 2 = 0 ∨ v / A % 2 = 1 := by omega
    rcases hcase with h | h <;> rw [h] <;> omega
  calc v % (A * 2)
      = ((v % A + v / A % 2 * A) + A * 2 * (v / A / 2)) % (A * 2) := by rw [← hv]
    _ = (v % A + v / A % 2 * A) % (A * 2) := by rw [Nat.add_mul_mod_self_left]
    _ = v % A + v / A % 2 * A := Nat.mod_eq_of_lt hlt

theorem mod_two_pow_succ (v w : Nat) :
    v % 2 ^ (w + 1) = v % 2 ^ w + bitAt v w * 2 ^ w := by
  rw [Nat.pow_succ]
  exact mod_two_pow_split (2 ^ w) v (Nat.pos_pow_of_pos _ (by decide))

/-- Weighted little-endian value of a digit list starting at weight `2 ^ i`.
This is the quantity the `decrypt_amount` loop accumulates. -/
def listWeighted : List Nat → Nat → Nat
  | [], _ => 0
  | d :: ds, i => d * 2 ^ i + listWeighted ds (i + 1)

theorem list_weighted_append (xs : List Nat) :
    ∀ (ys : List Nat) (i : Nat),
      listWeighted (xs ++ ys) i = listWeighted xs i + listWeighted ys (i + xs.length) := by
  induction xs with
  | nil => intro ys i; simp [listWeighted]
  | cons d ds ih =>
    intro ys i
    simp only [List.cons_append, listWeighted, ih ys (i + 1), List.length_cons]
    have : i + 1 + ds.length = i + (ds.length + 1) := by omega
    rw [this]
    omega

theorem list_weighted_replicate_zero (m : Nat) :
    ∀ i, listWeighted (List.replicate m 0) i = 0 := by
  induction m with
  | zero => intro i; rfl
  | succ m ih => intro i; simp [List.replicate, listWeighted, ih (i + 1)]

theorem list_weighted_bits (v : Nat) :
    ∀ w, listWeighted ((List.range w).map (bitAt v)) 0 = v % 2 ^ w := by
  intro w
  induction w with
  | zero => simp [List.range, List.range.loop, listWeighted]
  | succ w ih =>
    rw [range_succ_append, List.map_append, list_weighted_append, ih]
    simp only [List.map, listWeighted, List.length_map, range_length_eq, Nat.zero_add]
    rw [mod_two_pow_succ v w]
    omega

theorem list_weighted_zip_add (xs : List Nat) :
    ∀ (ys : List Nat) (i : Nat), xs.length = ys.length →
      listWeighted (List.zipWith (fun a b => a + b) xs ys) i
        = listWeighted xs i + listWeighted ys i := by
  induction xs with
  | nil =>
    intro ys i h
    cases ys with
    | nil => simp [listWeighted]
    | cons _ _ => simp at h
  | cons d ds ih =>
    intro ys i h
    cases ys with
    | nil => simp at h
    | cons e es =>
      have hlen : ds.length = es.length := by simpa using h
      simp only [List.zipWith_cons_cons, listWeighted, ih es (i + 1) hlen]
      have : (d + e) * 2 ^ i = d * 2 ^ i + e * 2 ^ i := by
        rw [Nat.add_mul]
      omega

theorem map_const_range (n : Nat) (c : Nat) (f : Nat → Nat) (hf : ∀ i, f i = c) :
    (List.range n).map f = List.replicate n c := by
  induction n with
  | zero => rfl
  | succ n ih =>
    rw [range_succ_append, List.map_append, ih]
    simp [List.map, hf n, List.replicate_succ']

/-! ### Encoding layout theorems -/

theorem encode_amount_length (v : Nat) : (encodeAmount v).length = regevN := by
  simp [encodeAmount, range_length_eq, amountBits, regevN]

theorem encode_amount_prefix_length (v : Nat) :
    ((List.range amountBits).map (bitAt v)).length = amountBits := by
  simp [range_length_eq]

theorem encode_amount_entries_are_bits (v i : Nat) (h : i < amountBits) :
    ((List.range amountBits).map (bitAt v)).getD i 0 = bitAt v i ∧ bitAt v i < 2 := by
  constructor
  · have hlt : i < ((List.range amountBits).map (bitAt v)).length := by
      simpa [range_length_eq] using h
    rw [List.getD_eq_get _ _ hlt]
    simp only [List.get_map]
    congr 1
    have hr : i < (List.range amountBits).length := by simpa [range_length_eq] using h
    have := List.get_range (n := amountBits) ⟨i, hr⟩
    simpa using this
  · exact Nat.mod_lt _ (by decide)

/-- The encoding is exactly the message layout the in-circuit decryption gadget
models: 64 little-endian bits, zero-padded to the ring degree. -/
theorem encode_amount_matches_decryption_gadget (v : Nat) :
    encodeAmount v = DecryptionGadget.encodeAmount v := by
  simp only [encodeAmount, DecryptionGadget.encodeAmount, DecryptionGadget.bitsOf,
    List.map_append, List.map_map, List.map_replicate, amountBits, regevN,
    DecryptionGadget.ringN]
  congr 1
  · refine List.map_congr_left ?_
    intro i _
    have h : bitAt v i < 2 := Nat.mod_lt _ (by decide)
    by_cases hb : bitAt v i = 1
    · simp [Function.comp, bitAt, DecryptionGadget.boolNat, ← hb] at *
      simp [hb]
    · have h0 : bitAt v i = 0 := by omega
      simp [Function.comp, bitAt, DecryptionGadget.boolNat] at *
      simp [h0]
  · rfl

theorem encode_amount_zero : encodeAmount 0 = List.replicate regevN 0 := by
  have h : (List.range amountBits).map (bitAt 0) = List.replicate amountBits 0 :=
    map_const_range _ _ _ (fun i => by simp [bitAt])
  rw [encodeAmount, h]
  have : regevN = amountBits + (regevN - amountBits) := by decide
  rw [this]
  exact (List.replicate_add _ _ _).symm

/-! ## The decryption decode loop (`decrypt_amount`) -/

/-- Mirrors the `for (i, &d) in digits.iter().enumerate()` loop: zero digits are
skipped, a nonzero digit at weight `2 ^ 64` or above is an error rather than a
panic, and the accumulated `u128` must fit `u64`. -/
def decodeLoop : List Nat → Nat → Nat → Except RegevError Nat
  | [], _, value => if value < 2 ^ 64 then .ok value else .error .decryptOverflow
  | d :: ds, i, value =>
      if d = 0 then decodeLoop ds (i + 1) value
      else if 64 ≤ i then .error .decryptOverflow
      else decodeLoop ds (i + 1) (value + d * 2 ^ i)

def decodeValue (digits : List Nat) : Except RegevError Nat := decodeLoop digits 0 0

theorem decode_loop_prefix (xs : List Nat) :
    ∀ (rest : List Nat) (i value : Nat), i + xs.length ≤ 64 →
      decodeLoop (xs ++ rest) i value
        = decodeLoop rest (i + xs.length) (value + listWeighted xs i) := by
  induction xs with
  | nil => intro rest i value _; simp [listWeighted]
  | cons d ds ih =>
    intro rest i value hle
    simp only [List.length_cons] at hle
    have hi : i < 64 := by omega
    have hstep : decodeLoop (d :: (ds ++ rest)) i value
        = decodeLoop (ds ++ rest) (i + 1) (value + d * 2 ^ i) := by
      by_cases hd : d = 0
      · simp [decodeLoop, hd]
      · simp [decodeLoop, hd, Nat.not_le.2 hi]
    simp only [List.cons_append, hstep, ih rest (i + 1) (value + d * 2 ^ i) (by omega),
      listWeighted, List.length_cons]
    have hidx : i + 1 + ds.length = i + (ds.length + 1) := by omega
    rw [hidx, Nat.add_assoc]

theorem decode_loop_zero_prefix (m : Nat) :
    ∀ (rest : List Nat) (i value : Nat),
      decodeLoop (List.replicate m 0 ++ rest) i value = decodeLoop rest (i + m) value := by
  induction m with
  | zero => intro rest i value; simp
  | succ m ih =>
    intro rest i value
    simp only [List.replicate, List.cons_append]
    rw [show decodeLoop (0 :: (List.replicate m 0 ++ rest)) i value
        = decodeLoop (List.replicate m 0 ++ rest) (i + 1) value by simp [decodeLoop],
      ih rest (i + 1) value]
    congr 1
    omega

/-- A digit list of at most 64 significant positions followed by zeros decodes to
its weighted value. -/
theorem decode_padded (xs : List Nat) (m : Nat) (hlen : xs.length ≤ 64)
    (hv : listWeighted xs 0 < 2 ^ 64) :
    decodeValue (xs ++ List.replicate m 0) = .ok (listWeighted xs 0) := by
  unfold decodeValue
  rw [decode_loop_prefix xs (List.replicate m 0) 0 0 (by omega)]
  rw [decode_loop_zero_prefix m [] (0 + xs.length) (0 + listWeighted xs 0)]
  simp [decodeLoop, hv]

/-- A nonzero digit at weight `2 ^ 64` or above is rejected (the source returns
`DecryptOverflow` here instead of letting the upstream decoder panic). -/
theorem decode_rejects_high_digit (d : Nat) (rest : List Nat) (hd : d ≠ 0) :
    decodeValue (List.replicate 64 0 ++ (d :: rest)) = .error .decryptOverflow := by
  unfold decodeValue
  rw [decode_loop_zero_prefix 64 (d :: rest) 0 0]
  simp [decodeLoop, hd]

/-! ### Round trip, injectivity and additivity -/

theorem decode_encode_roundtrip (v : Nat) (h : v < 2 ^ 64) :
    decodeValue (encodeAmount v) = .ok v := by
  have hw : listWeighted ((List.range amountBits).map (bitAt v)) 0 = v := by
    rw [list_weighted_bits v amountBits]
    exact Nat.mod_eq_of_lt (by simpa [amountBits] using h)
  have hlen : ((List.range amountBits).map (bitAt v)).length ≤ 64 := by
    simp [range_length_eq, amountBits]
  have := decode_padded ((List.range amountBits).map (bitAt v)) (regevN - amountBits)
    hlen (by rw [hw]; exact h)
  rw [encodeAmount, this, hw]

/-- The encoding is injective on the `u64` range that `encode_amount` accepts. -/
theorem encode_amount_injective_on_u64 (v w : Nat) (hv : v < 2 ^ 64) (hw : w < 2 ^ 64)
    (h : encodeAmount v = encodeAmount w) : v = w := by
  have h1 := decode_encode_roundtrip v hv
  have h2 := decode_encode_roundtrip w hw
  rw [h, h2] at h1
  exact (Except.ok.injEq _ _ ▸ h1).symm

/-- Coefficient-wise digit addition, the plaintext-side effect the source relies
on for homomorphic addition. -/
def addDigits (x y : List Nat) : List Nat := List.zipWith (fun a b => a + b) x y

theorem add_digits_of_encodings (a b : Nat) :
    addDigits (encodeAmount a) (encodeAmount b)
      = List.zipWith (fun x y => x + y) ((List.range amountBits).map (bitAt a))
          ((List.range amountBits).map (bitAt b))
        ++ List.replicate (regevN - amountBits) 0 := by
  unfold addDigits encodeAmount
  rw [List.zipWith_append _ _ _ _ _ (by simp [range_length_eq])]
  congr 1
  induction (regevN - amountBits) with
  | zero => rfl
  | succ m ih => simp [List.replicate, ih]

/-- Digit-wise addition of two encoded amounts decodes to the sum, exactly the
`add_ciphertexts` claim at the plaintext level, and the reason the digit
headroom `t = 256` bounds the number of stacked additions. -/
theorem encoded_digit_sum_decodes_to_sum (a b : Nat) (ha : a < 2 ^ 64)
    (hb : b < 2 ^ 64) (hab : a + b < 2 ^ 64) :
    decodeValue (addDigits (encodeAmount a) (encodeAmount b)) = .ok (a + b) := by
  have hla : ((List.range amountBits).map (bitAt a)).length
      = ((List.range amountBits).map (bitAt b)).length := by simp [range_length_eq]
  have hwa : listWeighted ((List.range amountBits).map (bitAt a)) 0 = a := by
    rw [list_weighted_bits a amountBits]
    exact Nat.mod_eq_of_lt (by simpa [amountBits] using ha)
  have hwb : listWeighted ((List.range amountBits).map (bitAt b)) 0 = b := by
    rw [list_weighted_bits b amountBits]
    exact Nat.mod_eq_of_lt (by simpa [amountBits] using hb)
  have hsum : listWeighted (List.zipWith (fun x y => x + y)
      ((List.range amountBits).map (bitAt a)) ((List.range amountBits).map (bitAt b))) 0
      = a + b := by
    rw [list_weighted_zip_add _ _ 0 hla, hwa, hwb]
  have hlen : (List.zipWith (fun x y => x + y) ((List.range amountBits).map (bitAt a))
      ((List.range amountBits).map (bitAt b))).length ≤ 64 := by
    simp [List.length_zipWith, range_length_eq, amountBits]
  rw [add_digits_of_encodings a b]
  rw [decode_padded _ (regevN - amountBits) hlen (by rw [hsum]; exact hab), hsum]

/-! ## Ciphertext addition (`add_ciphertexts`) -/

def addCoeffs (x y : List Nat) : List Nat :=
  List.zipWith (fun a b => (a + b) % regevQ) x y

/-- `add_ciphertexts`: both operands are validated (left first), then the sum is
taken coefficient-wise with an explicit reduction mod `q`. -/
def addCiphertexts (a b : RegevCiphertext) : Except RegevError RegevCiphertext := do
  let _ ← a.validate
  let _ ← b.validate
  .ok ⟨addCoeffs a.c1 b.c1, addCoeffs a.c2 b.c2⟩

theorem add_ciphertexts_checks_left_operand_first (a b : RegevCiphertext)
    (h : a.validate ≠ .ok ()) : addCiphertexts a b = .error .invalidCiphertext := by
  unfold addCiphertexts
  cases hv : a.validate with
  | ok u => cases u; exact absurd hv h
  | error e =>
    have : e = RegevError.invalidCiphertext := by
      unfold RegevCiphertext.validate at hv
      split at hv <;> split at hv <;> simp_all
    simp [this]

theorem add_ciphertexts_rejects_noncanonical_right (a b : RegevCiphertext)
    (ha : a.validate = .ok ()) (h : b.validate ≠ .ok ()) :
    addCiphertexts a b = .error .invalidCiphertext := by
  unfold addCiphertexts
  rw [ha]
  cases hv : b.validate with
  | ok u => cases u; exact absurd hv h
  | error e =>
    have : e = RegevError.invalidCiphertext := by
      unfold RegevCiphertext.validate at hv
      split at hv <;> split at hv <;> simp_all
    simp [this]

theorem add_coeffs_canonical (x y : List Nat) :
    ∀ c ∈ addCoeffs x y, c < regevQ := by
  intro c hc
  unfold addCoeffs at hc
  have := List.exists_of_mem_zipWith hc
  obtain ⟨a, b, _, _, hEq⟩ := this
  rw [← hEq]
  exact Nat.mod_lt _ (by decide)

theorem add_coeffs_length (x y : List Nat) (hx : x.length = regevN)
    (hy : y.length = regevN) : (addCoeffs x y).length = regevN := by
  simp [addCoeffs, List.length_zipWith, hx, hy]

/-- The sum of two accepted ciphertexts is itself canonical and of the right
shape, so the pending-balance accumulator never leaves the accepted domain. -/
theorem add_ciphertexts_result_validates (a b c : RegevCiphertext)
    (h : addCiphertexts a b = .ok c) : c.validate = .ok () := by
  unfold addCiphertexts at h
  cases ha : a.validate with
  | error e => rw [ha] at h; simp at h
  | ok ua =>
    cases hb : b.validate with
    | error e => rw [ha, hb] at h; simp at h
    | ok ub =>
      rw [ha, hb] at h
      simp only [Except.bind_ok, Except.ok.injEq] at h
      cases ua; cases ub
      obtain ⟨ha1, ha2, _⟩ := (ct_validate_ok_iff a).1 ha
      obtain ⟨hb1, hb2, _⟩ := (ct_validate_ok_iff b).1 hb
      subst h
      refine (ct_validate_ok_iff _).2 ⟨?_, ?_, ?_⟩
      · exact add_coeffs_length _ _ ha1 hb1
      · exact add_coeffs_length _ _ ha2 hb2
      · intro c hc
        rcases List.mem_append.1 hc with h' | h'
        · exact add_coeffs_canonical _ _ _ h'
        · exact add_coeffs_canonical _ _ _ h'

theorem add_coeffs_zero_left (ys : List Nat) :
    ∀ n, ys.length = n → (∀ c ∈ ys, c < regevQ) →
      addCoeffs (List.replicate n 0) ys = ys := by
  induction ys with
  | nil => intro n hn _; cases n with
    | zero => rfl
    | succ m => simp at hn
  | cons y ys ih =>
    intro n hn hc
    cases n with
    | zero => simp at hn
    | succ m =>
      have hlen : ys.length = m := by simpa using hn
      have hy : y < regevQ := hc y (by simp)
      have hrest : ∀ c ∈ ys, c < regevQ := fun c h => hc c (by simp [h])
      simp only [List.replicate, addCoeffs, List.zipWith_cons_cons, Nat.zero_add]
      rw [Nat.mod_eq_of_lt hy]
      have := ih m hlen hrest
      unfold addCoeffs at this
      rw [this]

/-- The all-zero padding ciphertext is a homomorphic identity: receiving a normal
ciphertext into an empty slot replaces it exactly. -/
theorem add_ciphertexts_padding_identity (ct : RegevCiphertext)
    (h : ct.validate = .ok ()) :
    addCiphertexts RegevCiphertext.padding ct = .ok ct := by
  obtain ⟨h1, h2, h3⟩ := (ct_validate_ok_iff ct).1 h
  unfold addCiphertexts
  rw [padding_ct_validates, h]
  simp only [Except.bind_ok]
  have e1 : addCoeffs RegevCiphertext.padding.c1 ct.c1 = ct.c1 :=
    add_coeffs_zero_left ct.c1 regevN h1
      (fun c hc => h3 c (List.mem_append.2 (Or.inl hc)))
  have e2 : addCoeffs RegevCiphertext.padding.c2 ct.c2 = ct.c2 :=
    add_coeffs_zero_left ct.c2 regevN h2
      (fun c hc => h3 c (List.mem_append.2 (Or.inr hc)))
  rw [e1, e2]

/-! ## Encryption, decryption and the boundaries they cross

`encryptOracle` and `digitOracle` stand for `regev_plonky3::encrypt` and
`regev_plonky3::decrypt` together with the RNG and the CBD(2) noise sampler.
Nothing about their outputs is assumed except where a theorem takes an explicit
premise. -/

structure EncryptionRandomness where
  r : List Int
  e1u : List Nat
  e1v : List Nat
  e2u : List Nat
  e2v : List Nat
  k1 : List Int
  k2 : List Int
  deriving DecidableEq, Repr

/-- `AmountWitness`: the plaintext amount plus the STARK witness material.
Sender-private in the source (not `Serialize`). -/
structure AmountWitness where
  amount : Nat
  m : List Nat
  rnd : EncryptionRandomness
  deriving DecidableEq, Repr

def zeroRandomness : EncryptionRandomness :=
  ⟨List.replicate regevN 0, List.replicate regevN 0, List.replicate regevN 0,
   List.replicate regevN 0, List.replicate regevN 0,
   List.replicate regevN 0, List.replicate regevN 0⟩

/-- `zero_amount_witness()`: the public all-zero opening of the padding ciphertext. -/
def zeroAmountWitness : AmountWitness :=
  ⟨0, List.replicate regevN 0, zeroRandomness⟩

/-- The zero witness really carries the encoding of the amount it claims, and its
randomness satisfies the ternary / CBD range predicates the E-1 witness check
applies. -/
theorem zero_amount_witness_opens_zero :
    zeroAmountWitness.amount = 0 ∧
    zeroAmountWitness.m = encodeAmount 0 ∧
    (∀ x ∈ zeroAmountWitness.rnd.r, -1 ≤ x ∧ x ≤ 1) ∧
    (∀ x ∈ zeroAmountWitness.rnd.e1u, x ≤ 2) ∧
    (∀ x ∈ zeroAmountWitness.rnd.e2v, x ≤ 2) ∧
    zeroAmountWitness.m.length = regevN := by
  refine ⟨rfl, encode_amount_zero.symm, ?_, ?_, ?_, List.length_replicate _ _⟩
  · intro x hx; rw [List.eq_of_mem_replicate hx]; exact ⟨by decide, by decide⟩
  · intro x hx; rw [List.eq_of_mem_replicate hx]; decide
  · intro x hx; rw [List.eq_of_mem_replicate hx]; decide

/-- `encrypt_amount`: validate the key, encode the amount, then call the upstream
encryptor with that message. -/
def encryptAmount (encryptOracle : RegevPk → List Nat → RegevCiphertext × EncryptionRandomness)
    (pk : RegevPk) (amount : Nat) :
    Except RegevError (RegevCiphertext × AmountWitness) := do
  let _ ← pk.validate
  let message := encodeAmount amount
  let (ct, rnd) := encryptOracle pk message
  .ok (ct, ⟨amount, message, rnd⟩)

theorem encrypt_amount_witness_message (encryptOracle) (pk : RegevPk) (amount : Nat)
    (ct : RegevCiphertext) (w : AmountWitness)
    (h : encryptAmount encryptOracle pk amount = .ok (ct, w)) :
    w.amount = amount ∧ w.m = encodeAmount amount := by
  unfold encryptAmount at h
  cases hv : pk.validate with
  | error e => rw [hv] at h; simp at h
  | ok u =>
    rw [hv] at h
    simp only [Except.bind_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨_, hw⟩ := h
    rw [← hw]
    exact ⟨rfl, rfl⟩

/-- A non-canonical public key is refused before the upstream encryptor is
reached: the result does not depend on the oracle at all. -/
theorem encrypt_amount_refuses_before_oracle (o1 o2) (pk : RegevPk) (amount : Nat)
    (h : pk.validate ≠ .ok ()) :
    encryptAmount o1 pk amount = .error .invalidPk ∧
    encryptAmount o2 pk amount = .error .invalidPk := by
  have key : ∀ o, encryptAmount o pk amount = .error .invalidPk := by
    intro o
    unfold encryptAmount
    cases hv : pk.validate with
    | ok u => cases u; exact absurd hv h
    | error e =>
      have : e = RegevError.invalidPk := by
        unfold RegevPk.validate at hv
        split at hv <;> split at hv <;> simp_all
      simp [this]
  exact ⟨key o1, key o2⟩

/-- `decrypt_amount`: secret-key shape first, then ciphertext canonicality, then
the upstream digit decode. -/
def decryptAmount (digitOracle : RegevSk → RegevCiphertext → List Nat)
    (sk : RegevSk) (ct : RegevCiphertext) : Except RegevError Nat := do
  if sk.s.length ≠ regevN then .error .invalidSk
  let _ ← ct.validate
  decodeValue (digitOracle sk ct)

theorem decrypt_amount_checks_secret_key_first (o1 o2) (sk : RegevSk)
    (ct : RegevCiphertext) (h : sk.s.length ≠ regevN) :
    decryptAmount o1 sk ct = .error .invalidSk ∧
    decryptAmount o2 sk ct = .error .invalidSk := by
  constructor <;> (unfold decryptAmount; simp [h])

/-- A non-canonical ciphertext never reaches the upstream decryptor. -/
theorem decrypt_amount_refuses_noncanonical_before_oracle (o1 o2) (sk : RegevSk)
    (ct : RegevCiphertext) (hs : sk.s.length = regevN) (h : ct.validate ≠ .ok ()) :
    decryptAmount o1 sk ct = .error .invalidCiphertext ∧
    decryptAmount o2 sk ct = .error .invalidCiphertext := by
  have key : ∀ o, decryptAmount o sk ct = .error .invalidCiphertext := by
    intro o
    unfold decryptAmount
    simp only [hs, ne_eq, not_true_eq_false, if_false]
    cases hv : ct.validate with
    | ok u => cases u; exact absurd hv h
    | error e =>
      have : e = RegevError.invalidCiphertext := by
        unfold RegevCiphertext.validate at hv
        split at hv <;> split at hv <;> simp_all
      simp [this]
  exact ⟨key o1, key o2⟩

/-! ### The two undischarged cryptographic premises -/

/-- "The oracle decrypts this ciphertext to the digits of this amount." Holds in
the source only within the noise budget and only for the matching key; it is
never derived here. -/
def DecryptsTo (digitOracle : RegevSk → RegevCiphertext → List Nat)
    (sk : RegevSk) (ct : RegevCiphertext) (digits : List Nat) : Prop :=
  digitOracle sk ct = digits

/-- "Coefficient-wise ciphertext addition induces digit-wise plaintext addition."
This is the Ring-LWE homomorphism together with the digit/noise budget of
`MAX_HOMO_ADDS_BEFORE_REFRESH`; it is a premise, not a result. -/
def HomomorphicDigits (digitOracle : RegevSk → RegevCiphertext → List Nat)
    (sk : RegevSk) : Prop :=
  ∀ x y z : RegevCiphertext, addCiphertexts x y = .ok z →
    digitOracle sk z = addDigits (digitOracle sk x) (digitOracle sk y)

/-- Under the two premises above, adding the ciphertexts of two balances and
decrypting yields the sum of the amounts. This is the pending-balance property
`add_ciphertexts` exists for; every cryptographic step of it is a hypothesis. -/
theorem homomorphic_pending_balance (digitOracle) (sk : RegevSk) (x y z : RegevCiphertext)
    (a b : Nat) (hs : sk.s.length = regevN)
    (hx : DecryptsTo digitOracle sk x (encodeAmount a))
    (hy : DecryptsTo digitOracle sk y (encodeAmount b))
    (hhom : HomomorphicDigits digitOracle sk)
    (hadd : addCiphertexts x y = .ok z)
    (ha : a < 2 ^ 64) (hb : b < 2 ^ 64) (hab : a + b < 2 ^ 64) :
    decryptAmount digitOracle sk z = .ok (a + b) := by
  have hz : z.validate = .ok () := add_ciphertexts_result_validates x y z hadd
  unfold decryptAmount
  simp only [hs, ne_eq, not_true_eq_false, if_false]
  rw [hz]
  simp only [Except.bind_ok]
  rw [hhom x y z hadd]
  unfold DecryptsTo at hx hy
  rw [hx, hy]
  exact encoded_digit_sum_decodes_to_sum a b ha hb hab

/-! ## A concrete normal trace -/

/-- Encoding, decoding and digit addition on small amounts: a non-vacuous
positive instance of the encoding lemmas. -/
theorem normal_amount_trace :
    decodeValue (encodeAmount 5) = .ok 5 ∧
    decodeValue (encodeAmount 0) = .ok 0 ∧
    decodeValue (addDigits (encodeAmount 5) (encodeAmount 7)) = .ok 12 ∧
    (encodeAmount 5).length = regevN := by
  refine ⟨decode_encode_roundtrip 5 (by decide), decode_encode_roundtrip 0 (by decide), ?_,
    encode_amount_length 5⟩
  exact encoded_digit_sum_decodes_to_sum 5 7 (by decide) (by decide) (by decide)

/-- A padding slot is accepted everywhere the source accepts it, and absorbs a
normal ciphertext without changing it. -/
theorem normal_padding_trace (ct : RegevCiphertext) (h : ct.validate = .ok ()) :
    RegevCiphertext.padding.validate = .ok () ∧
    RegevCiphertext.padding.validateBalanceExitShape = .ok () ∧
    addCiphertexts RegevCiphertext.padding ct = .ok ct := by
  exact ⟨padding_ct_validates, exit_shape_accepts_padding,
    add_ciphertexts_padding_identity ct h⟩

end Zkp.Implementation.RegevCore
