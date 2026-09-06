import Std

/-!
Source-oriented model of `src/circuits/channel/decryption_gadget.rs` production code.
This is NOT a Rust/Plonky2 refinement theorem or a proof of cryptographic security.
Raw gates below specialize the repository's Goldilocks invocation of the generic
Rust helper; no guarantee for every possible `RichField` is asserted. They are
modular equations, not a plaintext/decryption oracle. Integer
representatives, Boolean wire semantics, range-check lowering, hash implementations,
Rust arithmetic/array/write behavior, and the NTT implementation are separate
boundaries. In particular `FieldProducts` is an explicit, currently undischarged
prime-field arithmetic premise; it is not a claimed consequence of compilation.

Signed scalar wires use centered representatives and unsigned scalar wires use
canonical representatives. `Representatives` describes that semantic convention,
not an extra circuit check. Native input building, arbitrary witness filling, and
adversarial gate assignments are distinct. No uniqueness of the secret key, intended
owner, ciphertext plaintext, or funds entitlement is inferred from these equations.
`buildPhases` and `NativeMachineDomain` are documentation-only order/domain records
(the source's phase order and its machine-integer widths); no theorem references
them and they are not proved properties.
-/
namespace Zkp.Implementation.DecryptionGadget

set_option maxRecDepth 4096
set_option maxHeartbeats 3000000

def ringN : Nat := 2048
def q : Nat := 2013265921
def fieldP : Nat := 18446744069414584321
def delta : Nat := 7864320
def halfDelta : Nat := 3932160
def kappaBits : Nat := 13
def boolNat (b : Bool) : Nat := if b then 1 else 0
def FZero (x : Int) : Prop := x % (fieldP : Int) = 0
def RangeGate (bits : Nat) (x : Int) : Prop :=
  0 ≤ x % (fieldP : Int) ∧ x % (fieldP : Int) < (2 ^ bits : Nat)
def Centered (x : Int) : Prop :=
  -(fieldP / 2 : Nat) ≤ x ∧ x ≤ (fieldP / 2 : Nat)
def Canonical (x : Nat) : Prop := x < fieldP
def StrictQGate (x : Nat) : Prop :=
  RangeGate 31 x ∧ RangeGate 31 ((q : Int) - 1 - x)
def KappaGate (k : Int) : Prop :=
  RangeGate kappaBits (k + ringN) ∧
  RangeGate kappaBits (2 * (ringN : Int) - (k + ringN))
def TernaryGate (s : Int) : Prop := FZero (s * ((s - 1) * (s + 1)))
def ErrorHalfGate (x : Nat) : Prop :=
  FZero ((x : Int) * (((x : Int) - 1) * ((x : Int) - 2)))

def packBits : List Bool → Nat
  | [] => 0
  | b :: bs => boolNat b + 2 * packBits bs
def weighted : List Nat → Nat
  | [] => 0
  | d :: ds => d + 2 * weighted ds
def bitsOf (width x : Nat) : List Bool :=
  (List.range width).map fun i => decide (x / 2 ^ i % 2 = 1)
def sumZ (f : Nat → Int) : Nat → Int
  | 0 => 0
  | n + 1 => sumZ f n + f n
def coeff (xs : List Nat) (i : Nat) : Int := (xs.getD i 0 : Nat)
def signedCoeff (xs : List Int) (i : Nat) : Int := xs.getD i 0
def negacyclicTerm (n i m : Nat) (x s : Nat → Int) : Int :=
  if m ≤ i then x m * s (i - m) else -(x m * s (n + i - m))
def negacyclicCoeff (n : Nat) (x s : Nat → Int) (i : Nat) : Int :=
  sumZ (fun m => negacyclicTerm n i m x s) n
-- Independent ordinary-product degree selection (before reduction by X^n + 1).
def schoolbookTerm (n k m : Nat) (x s : Nat → Int) : Int :=
  if m ≤ k ∧ k - m < n then x m * s (k - m) else 0
def schoolbookCoeff (n : Nat) (x s : Nat → Int) (k : Nat) : Int :=
  sumZ (fun m => schoolbookTerm n k m x s) n
def nativeNegacyclic (x : List Nat) (s : List Int) : List Int :=
  (List.range x.length).map (negacyclicCoeff x.length (coeff x) (signedCoeff s))

structure Inputs where
  a : List Nat
  b : List Nat
  c1 : List Nat
  c2 : List Nat
  deriving Repr, DecidableEq

def InputLengths (i : Inputs) : Prop :=
  i.a.length = ringN ∧ i.b.length = ringN ∧
  i.c1.length = ringN ∧ i.c2.length = ringN
instance (i : Inputs) : Decidable (InputLengths i) := inferInstanceAs
  (Decidable (i.a.length = ringN ∧ i.b.length = ringN ∧
    i.c1.length = ringN ∧ i.c2.length = ringN))
def InputPolys (i : Inputs) : List (List Nat) := [i.a, i.b, i.c1, i.c2]
-- This is the is_equal/AND fold, not an inverse of a sum of coefficients.
def polyNonzero (xs : List Nat) : Bool := !(xs.all fun x => x == 0)

structure CoreRow where
  s : Int
  epkU : Nat
  epkV : Nat
  asRem : Nat
  asKappa : Int
  asWrap : Int
  v : Nat
  csKappa : Int
  digitBits : List Bool
  noiseLo : List Bool
  noiseU : List Bool
  noiseV : List Bool
  bit : Bool
  carry : Nat
  digitWrap : Bool
  deriving Repr, DecidableEq

def CoreRow.digit (r : CoreRow) : Nat := packBits r.digitBits
def CoreRow.noise (r : CoreRow) : Nat :=
  packBits r.noiseLo + (packBits r.noiseU + packBits r.noiseV) * 2 ^ 19
def CoreRow.shape (r : CoreRow) : Prop :=
  r.digitBits.length = 8 ∧ r.noiseLo.length = 19 ∧
  r.noiseU.length = 3 ∧ r.noiseV.length = 3
def CoreRow.representatives (r : CoreRow) : Prop :=
  Centered r.s ∧ Canonical r.epkU ∧ Canonical r.epkV ∧
  Canonical r.asRem ∧ Centered r.asKappa ∧ Centered r.asWrap ∧
  Canonical r.v ∧ Centered r.csKappa ∧ Canonical r.carry
def Representatives (i : Inputs) (rows : List CoreRow) : Prop :=
  (∀ xs ∈ InputPolys i, ∀ x ∈ xs, Canonical x) ∧
  ∀ r ∈ rows, r.representatives
def firstCarry : List CoreRow → Nat
  | [] => 0
  | r :: _ => r.carry
def CarryGates : List CoreRow → Prop
  | [] => True
  | r :: rs => RangeGate 8 r.carry ∧
      FZero ((r.digit : Int) + r.carry - boolNat r.bit - 2 * firstCarry rs) ∧
      CarryGates rs
def RowGates (i : Inputs) (rows : List CoreRow) (index : Nat) (r : CoreRow) : Prop :=
  let secret := fun j => (rows.map CoreRow.s).getD j 0
  TernaryGate r.s ∧ ErrorHalfGate r.epkU ∧ ErrorHalfGate r.epkV ∧
  KappaGate r.asKappa ∧ StrictQGate r.asRem ∧ TernaryGate r.asWrap ∧
  FZero (negacyclicCoeff ringN (coeff i.a) secret index - r.asRem - r.asKappa * q) ∧
  FZero (coeff i.b index - ((r.epkU : Int) - r.epkV) - r.asRem - r.asWrap * q) ∧
  KappaGate r.csKappa ∧ StrictQGate r.v ∧
  FZero (negacyclicCoeff ringN (coeff i.c1) secret index -
    (coeff i.c2 index - r.v) - r.csKappa * q) ∧
  FZero ((r.v : Int) + halfDelta - delta * r.digit - r.noise - boolNat r.digitWrap * q)
def CoreGates (i : Inputs) (rows : List CoreRow) (exposeAmount : Bool) : Prop :=
  InputLengths i ∧ rows.length = ringN ∧
  (∀ xs ∈ InputPolys i, ∀ x ∈ xs, StrictQGate x) ∧
  polyNonzero i.a = true ∧ polyNonzero i.c1 = true ∧
  (∀ r ∈ rows, r.shape) ∧
  (∀ j r, rows[j]? = some r → RowGates i rows j r) ∧
  FZero (firstCarry rows) ∧ CarryGates rows ∧
  (exposeAmount = true → ∀ r ∈ rows.drop 64, r.bit = false)
def amountLimbs (exposeAmount : Bool) (rows : List CoreRow) : Option (Nat × Nat) :=
  if exposeAmount then
    some (packBits ((rows.take 32).map CoreRow.bit),
      packBits (((rows.drop 32).take 32).map CoreRow.bit))
  else none

-- Logical build phases preserve the source's guard/allocation/connection order.
inductive BuildPhase where
  | lengths | strictInputs | nonzeroInputs | allocate | smallness
  | keyReduce | keyBind | decryptReduce | digitExtract | carry | amount
  deriving Repr, DecidableEq
def buildPhases (exposeAmount : Bool) : List BuildPhase :=
  [.lengths, .strictInputs, .nonzeroInputs, .allocate, .smallness] ++
  ((List.range ringN).bind fun _ => [.keyReduce, .keyBind, .decryptReduce, .digitExtract]) ++
  [.carry] ++ if exposeAmount then [.amount] else []

theorem parameters_pinned :
    256 * delta + 1 = q ∧ delta = 15 * 2 ^ 19 ∧ halfDelta * 2 = delta ∧
    2 ^ kappaBits > 2 * ringN ∧ 2 ^ (kappaBits - 1) ≤ 2 * ringN ∧
    q - 1 < 2 ^ 31 := by decide

theorem boolNat_bound (b : Bool) : boolNat b ≤ 1 := by cases b <;> decide

theorem packBits_bound (bs : List Bool) : packBits bs < 2 ^ bs.length := by
  induction bs with
  | nil => simp [packBits]
  | cons b bs ih =>
    have hb := boolNat_bound b
    simp only [packBits, List.length_cons, Nat.pow_succ]
    omega

theorem packBits_is_weighted (bs : List Bool) :
    packBits bs = weighted (bs.map boolNat) := by
  induction bs with
  | nil => rfl
  | cons b bs ih => simp [packBits, weighted, ih]

theorem row_digit_bound (r : CoreRow) (h : r.shape) : r.digit < 256 := by
  have hp := packBits_bound r.digitBits
  rw [h.1] at hp
  exact hp

theorem row_noise_bound (r : CoreRow) (h : r.shape) : r.noise < delta := by
  have hl := packBits_bound r.noiseLo
  have hu := packBits_bound r.noiseU
  have hv := packBits_bound r.noiseV
  rw [h.2.1] at hl
  rw [h.2.2.1] at hu
  rw [h.2.2.2] at hv
  simp only [CoreRow.noise, delta]
  omega

theorem bounded_modular_zero (x : Int)
    (hl : -(fieldP : Int) < x) (hh : x < fieldP) (hz : FZero x) : x = 0 := by
  simp only [FZero, fieldP] at *
  omega

theorem strictQ_from_actual_checks (x : Nat) (hc : Canonical x)
    (h : StrictQGate x) : x < q := by
  simp only [Canonical, StrictQGate, RangeGate, fieldP, q] at *
  omega

theorem kappa_from_actual_checks (k : Int) (hc : Centered k)
    (h : KappaGate k) : -(ringN : Int) ≤ k ∧ k ≤ ringN := by
  simp only [Centered, KappaGate, RangeGate, kappaBits, fieldP, ringN] at *
  omega

theorem carry_from_actual_range (c : Nat) (hc : Canonical c)
    (h : RangeGate 8 c) : c < 256 := by
  simp only [Canonical, RangeGate, fieldP] at *
  omega

-- A primitive field-arithmetic dependency, deliberately not asserted as an axiom.
def FieldProducts : Prop := ∀ x y : Int, FZero (x * y) → FZero x ∨ FZero y

theorem ternary_from_cubic (hf : FieldProducts) (x : Int)
    (hc : Centered x) (hg : TernaryGate x) : x = -1 ∨ x = 0 ∨ x = 1 := by
  have h := hf x ((x - 1) * (x + 1)) hg
  rcases h with hx | ht
  · have he := bounded_modular_zero x (by unfold Centered fieldP at hc; unfold fieldP; omega)
      (by unfold Centered fieldP at hc; unfold fieldP; omega) hx
    exact Or.inr (Or.inl he)
  · rcases hf (x - 1) (x + 1) ht with hm | hp
    · have he := bounded_modular_zero (x - 1)
        (by unfold Centered fieldP at hc; unfold fieldP; omega)
        (by unfold Centered fieldP at hc; unfold fieldP; omega) hm
      exact Or.inr (Or.inr (by omega))
    · have he := bounded_modular_zero (x + 1)
        (by unfold Centered fieldP at hc; unfold fieldP; omega)
        (by unfold Centered fieldP at hc; unfold fieldP; omega) hp
      exact Or.inl (by omega)

theorem error_half_from_cubic (hf : FieldProducts) (x : Nat)
    (hc : Canonical x) (hg : ErrorHalfGate x) : x = 0 ∨ x = 1 ∨ x = 2 := by
  rcases hf x (((x : Int) - 1) * ((x : Int) - 2)) hg with hx | ht
  · have he := bounded_modular_zero x (by unfold fieldP; omega)
      (by exact_mod_cast hc) hx
    exact Or.inl (by omega)
  · rcases hf ((x : Int) - 1) ((x : Int) - 2) ht with hm | hp
    · have he := bounded_modular_zero ((x : Int) - 1)
        (by unfold fieldP; omega) (by unfold Canonical fieldP at hc; unfold fieldP; omega) hm
      exact Or.inr (Or.inl (by omega))
    · have he := bounded_modular_zero ((x : Int) - 2)
        (by unfold fieldP; omega) (by unfold Canonical fieldP at hc; unfold fieldP; omega) hp
      exact Or.inr (Or.inr (by omega))

theorem sumZ_congr (f g : Nat → Int) (n : Nat) (h : ∀ i, i < n → f i = g i) :
    sumZ f n = sumZ g n := by
  induction n with
  | zero => rfl
  | succ n ih => simp only [sumZ]; rw [ih (by intros; apply h; omega), h n (by omega)]

theorem sumZ_sub (f g : Nat → Int) (n : Nat) :
    sumZ (fun i => f i - g i) n = sumZ f n - sumZ g n := by
  induction n with
  | zero => rfl
  | succ n ih => simp only [sumZ, ih]; omega

theorem negacyclic_term_schoolbook (n i m : Nat) (x s : Nat → Int)
    (hi : i < n) (hm : m < n) :
    negacyclicTerm n i m x s = schoolbookTerm n i m x s - schoolbookTerm n (n+i) m x s := by
  by_cases h : m ≤ i
  · have h₁ : m ≤ i ∧ i - m < n := ⟨h, by omega⟩
    have h₂ : ¬ (m ≤ n + i ∧ n + i - m < n) := by omega
    simp [negacyclicTerm, schoolbookTerm, h, h₁, h₂]
  · have h₁ : ¬ (m ≤ i ∧ i - m < n) := by omega
    have h₂ : m ≤ n + i ∧ n + i - m < n := by omega
    simp [negacyclicTerm, schoolbookTerm, h, h₁, h₂]

theorem negacyclic_is_schoolbook_reduction (n i : Nat) (x s : Nat → Int) (hi : i < n) :
    negacyclicCoeff n x s i = schoolbookCoeff n x s i - schoolbookCoeff n x s (n+i) := by
  unfold negacyclicCoeff schoolbookCoeff
  rw [← sumZ_sub]
  exact sumZ_congr _ _ n (fun m hm => negacyclic_term_schoolbook n i m x s hi hm)

theorem negacyclic_zero_secret (n i : Nat) (x : Nat → Int) :
    negacyclicCoeff n x (fun _ => 0) i = 0 := by
  unfold negacyclicCoeff
  have hz : ∀ k, sumZ (fun m => negacyclicTerm n i m x (fun _ => 0)) k = 0 := by
    intro k
    induction k with
    | zero => rfl
    | succ k ih => simp only [sumZ, ih]; simp [negacyclicTerm]
  exact hz n

theorem sumZ_bounds (f : Nat → Int) (n : Nat) (b : Int)
    (h : ∀ i, i < n → -b ≤ f i ∧ f i ≤ b) :
    -(n : Int) * b ≤ sumZ f n ∧ sumZ f n ≤ n * b := by
  induction n with
  | zero => simp [sumZ]
  | succ n ih =>
    have hn := ih (by intros; apply h; omega)
    have hm := h n (by omega)
    simp only [Int.neg_mul] at hn
    simp only [sumZ, Int.ofNat_add, Int.ofNat_one, Int.add_mul, Int.neg_add,
      Int.neg_mul, Int.one_mul]
    omega

theorem ring_coefficient_bound (x s : Nat → Int) (i : Nat)
    (hx : ∀ m, m < ringN → 0 ≤ x m ∧ x m < q)
    (hs : ∀ j, j < ringN → s j = -1 ∨ s j = 0 ∨ s j = 1)
    (hi : i < ringN) :
    -(ringN : Int) * (q - 1) ≤ negacyclicCoeff ringN x s i ∧
    negacyclicCoeff ringN x s i ≤ ringN * (q - 1) := by
  apply sumZ_bounds
  intro m hm
  have hx' := hx m hm
  by_cases h : m ≤ i
  · have hs' := hs (i-m) (by omega)
    rcases hs' with hs' | hs' | hs' <;> simp [negacyclicTerm, h, hs'] <;> omega
  · have hs' := hs (ringN+i-m) (by omega)
    rcases hs' with hs' | hs' | hs' <;> simp [negacyclicTerm, h, hs'] <;> omega

theorem ring_intermediate_machine_bound :
    ringN * (q - 1) < 2 ^ 42 ∧
    (2 * ringN + 2) * q < fieldP ∧ ringN * (q - 1) < 2 ^ 63 := by decide

theorem reduction_gate_integer (lo k : Int) (rem : Nat)
    (hl : -(ringN : Int) * (q-1) ≤ lo ∧ lo ≤ ringN * (q-1))
    (hk : -(ringN : Int) ≤ k ∧ k ≤ ringN) (hr : rem < q)
    (hg : FZero (lo - rem - k*q)) : lo = rem + k*q := by
  have hz := bounded_modular_zero (lo-rem-k*q)
    (by simp only [ringN, q, fieldP] at *; omega)
    (by simp only [ringN, q, fieldP] at *; omega) hg
  omega

theorem decryption_gate_integer (lo k : Int) (c2 v : Nat)
    (hl : -(ringN : Int) * (q-1) ≤ lo ∧ lo ≤ ringN * (q-1))
    (hk : -(ringN : Int) ≤ k ∧ k ≤ ringN) (hc : c2 < q) (hv : v < q)
    (hg : FZero (lo - ((c2 : Int)-v) - k*q)) : lo = (c2 : Int)-v + k*q := by
  have hz := bounded_modular_zero (lo-((c2 : Int)-v)-k*q)
    (by simp only [ringN, q, fieldP] at *; omega)
    (by simp only [ringN, q, fieldP] at *; omega) hg
  omega

theorem key_binding_gate_integer (b rem u v : Nat) (wrap : Int)
    (hb : b < q) (hr : rem < q) (hu : u ≤ 2) (hv : v ≤ 2)
    (hw : wrap = -1 ∨ wrap = 0 ∨ wrap = 1)
    (hg : FZero ((b : Int)-((u : Int)-v)-rem-wrap*q)) :
    (b : Int) = (rem : Int) + ((u : Int)-v) + wrap*q := by
  have hz := bounded_modular_zero ((b : Int)-((u : Int)-v)-rem-wrap*q)
    (by rcases hw with h | h | h <;> simp only [h, q, fieldP] at * <;> omega)
    (by rcases hw with h | h | h <;> simp only [h, q, fieldP] at * <;> omega) hg
  omega

theorem digit_gate_integer (v d noise : Nat) (wrap : Bool)
    (hv : v < q) (hd : d < 256) (hn : noise < delta)
    (hg : FZero ((v : Int)+halfDelta-delta*d-noise-boolNat wrap*q)) :
    v + halfDelta = delta*d + noise + boolNat wrap*q := by
  have hw := boolNat_bound wrap
  have hz := bounded_modular_zero ((v : Int)+halfDelta-delta*d-noise-boolNat wrap*q)
    (by simp only [q, delta, halfDelta, fieldP] at *; omega)
    (by simp only [q, delta, halfDelta, fieldP] at *; omega) hg
  omega

def coreDigit (v : Nat) : Nat := ((v + halfDelta) % q) / delta
def coreNoise (v : Nat) : Nat := ((v + halfDelta) % q) % delta
def coreWrap (v : Nat) : Bool := decide (q ≤ v + halfDelta)
-- Direct upstream Regev decrypt rounding, intentionally a separate definition.
def upstreamDigit (v : Nat) : Nat := ((v * 256 + q / 2) / q) % 256

theorem digit_solution_unique (v d noise : Nat) (wrap : Bool)
    (_hv : v < q) (hd : d < 256) (hn : noise < delta)
    (he : v + halfDelta = delta*d + noise + boolNat wrap*q) :
    d = coreDigit v ∧ noise = coreNoise v ∧ wrap = coreWrap v := by
  have ht : delta*d+noise < q := by simp only [delta, q] at *; omega
  have hm : (v+halfDelta)%q = delta*d+noise := by
    rw [he]
    simp [Nat.add_mod, Nat.mul_mod, Nat.mod_eq_of_lt ht]
  constructor
  · unfold coreDigit; rw [hm]; simp only [delta] at *; omega
  · constructor
    · unfold coreNoise; rw [hm]; simp only [delta] at *; omega
    · cases wrap with
      | false =>
        have hh : ¬ q ≤ v+halfDelta := by simp [boolNat] at he; omega
        simp [coreWrap, hh]
      | true =>
        have hh : q ≤ v+halfDelta := by simp [boolNat] at he; omega
        simp [coreWrap, hh]

/-- At the digit boundary (`coreDigit v = 256`, i.e. `(v + Delta/2) mod q = q - 1`) no
in-range `(d, ns, dwrap)` satisfies the digit gate: `digit_gate_integer` turns the gate
into the integer equation and `digit_solution_unique` then forces `d = coreDigit v ≥ 256`,
contradicting the 8-bit digit. This is the circuit-side counterpart of
`native_digit_failure_exact` (the native builder refuses the same `v`). -/
theorem digit_boundary_gate_unsatisfiable (v : Nat) (hv : v < q) (h : 256 ≤ coreDigit v) :
    ¬ ∃ (d noise : Nat) (wrap : Bool), d < 256 ∧ noise < delta ∧
      FZero ((v : Int)+halfDelta-delta*d-noise-boolNat wrap*q) := by
  rintro ⟨d, noise, wrap, hd, hn, hg⟩
  have he := digit_gate_integer v d noise wrap hv hd hn hg
  have hu := (digit_solution_unique v d noise wrap hv hd hn he).1
  omega

theorem upstream_rounding_definition (v : Nat) :
    upstreamDigit v = ((v * 256 + q/2) / q) % 256 := rfl

-- This last identity is only a definitional comparison, not a parity theorem.
-- A useful upstream bridge still requires proved noise/rounding-domain conditions.

def IntegerCarries : List CoreRow → Prop
  | [] => True
  | r :: rs => r.digit + r.carry = boolNat r.bit + 2 * firstCarry rs ∧ IntegerCarries rs

theorem carry_gate_integer (d c bit next : Nat)
    (hd : d < 256) (hc : c < 256) (hb : bit ≤ 1) (hn : next < 256)
    (hg : FZero ((d : Int)+c-bit-2*next)) : d+c = bit+2*next := by
  have hz := bounded_modular_zero ((d : Int)+c-bit-2*next)
    (by unfold fieldP; omega) (by unfold fieldP; omega) hg
  omega

theorem carry_gates_lift (rows : List CoreRow)
    (shape : ∀ r ∈ rows, r.shape) (reps : ∀ r ∈ rows, r.representatives)
    (gates : CarryGates rows) : IntegerCarries rows := by
  induction rows with
  | nil => trivial
  | cons r rs ih =>
    have hr : r ∈ r::rs := by simp
    have hc := carry_from_actual_range r.carry (reps r hr).2.2.2.2.2.2.2.2 gates.1
    have hn : firstCarry rs < 256 := by
      cases rs with
      | nil => decide
      | cons t ts =>
        exact carry_from_actual_range t.carry (reps t (by simp)).2.2.2.2.2.2.2.2 gates.2.2.1
    exact ⟨carry_gate_integer _ _ _ _ (row_digit_bound r (shape r hr)) hc
      (boolNat_bound r.bit) hn gates.2.1,
      ih (by intros; apply shape; simp_all) (by intros; apply reps; simp_all) gates.2.2⟩

theorem carry_telescope (rows : List CoreRow) (h : IntegerCarries rows) :
    weighted (rows.map CoreRow.digit) + firstCarry rows = packBits (rows.map CoreRow.bit) := by
  induction rows with
  | nil => rfl
  | cons r rs ih =>
    have ht := ih h.2
    have he := h.1
    simp only [List.map_cons, weighted, packBits, firstCarry]
    omega

theorem carry_tight_bound (rows : List CoreRow) (h : IntegerCarries rows)
    (hd : ∀ r ∈ rows, r.digit < 256) (h0 : firstCarry rows ≤ 254) :
    ∀ r ∈ rows, r.carry ≤ 254 := by
  induction rows with
  | nil => simp
  | cons r rs ih =>
    have hnext : firstCarry rs ≤ 254 := by
      have he := h.1
      have hr := hd r (by simp)
      have hb := boolNat_bound r.bit
      simp only [firstCarry] at h0
      omega
    intro t ht
    rcases List.mem_cons.mp ht with he | ht
    · subst t; exact h0
    · exact ih h.2 (by intros; apply hd; simp_all) hnext t ht

theorem private_mode_no_amount (rows : List CoreRow) : amountLimbs false rows = none := rfl

theorem exposed_amount_exact_order (rows : List CoreRow) :
    amountLimbs true rows = some (packBits ((rows.take 32).map CoreRow.bit),
      packBits (((rows.drop 32).take 32).map CoreRow.bit)) := rfl

theorem packBits_append (xs ys : List Bool) :
    packBits (xs ++ ys) = packBits xs + 2^xs.length * packBits ys := by
  induction xs with
  | nil => simp [packBits]
  | cons b bs ih =>
    change boolNat b + 2 * packBits (bs ++ ys) =
      boolNat b + 2 * packBits bs + 2^(bs.length+1)*packBits ys
    rw [ih]
    simp only [Nat.pow_succ, Nat.mul_add, Nat.mul_assoc, Nat.mul_left_comm]
    omega

theorem packBits_all_false (bs : List Bool) (h : ∀ b ∈ bs, b = false) :
    packBits bs = 0 := by
  induction bs with
  | nil => rfl
  | cons b bs ih =>
    have hb := h b (by simp)
    have ht := ih (by intros; apply h; simp_all)
    simp [packBits, hb, ht, boolNat]

theorem first_carry_zero (rows : List CoreRow)
    (reps : ∀ r ∈ rows, r.representatives) (h : FZero (firstCarry rows)) :
    firstCarry rows = 0 := by
  cases rows with
  | nil => rfl
  | cons r rs =>
    have hc := (reps r (by simp)).2.2.2.2.2.2.2.2
    have hz := bounded_modular_zero (firstCarry (r::rs))
      (by unfold firstCarry fieldP; omega)
      (by simpa [firstCarry] using hc) h
    simp only [firstCarry] at hz ⊢
    omega

theorem core_exact_binary_value (i : Inputs) (rows : List CoreRow) (expose : Bool)
    (reps : Representatives i rows) (gates : CoreGates i rows expose) :
    weighted (rows.map CoreRow.digit) = packBits (rows.map CoreRow.bit) := by
  have hcarry := carry_gates_lift rows gates.2.2.2.2.2.1 reps.2 gates.2.2.2.2.2.2.2.2.1
  have hz := first_carry_zero rows reps.2 gates.2.2.2.2.2.2.2.1
  have ht := carry_telescope rows hcarry
  omega

theorem core_carries_at_most_254 (i : Inputs) (rows : List CoreRow) (expose : Bool)
    (reps : Representatives i rows) (gates : CoreGates i rows expose) :
    ∀ r ∈ rows, r.carry ≤ 254 := by
  have hshape := gates.2.2.2.2.2.1
  have hcarry := carry_gates_lift rows hshape reps.2 gates.2.2.2.2.2.2.2.2.1
  have hz := first_carry_zero rows reps.2 gates.2.2.2.2.2.2.2.1
  exact carry_tight_bound rows hcarry (fun r hr => row_digit_bound r (hshape r hr)) (by omega)

theorem row_lookup (rows : List CoreRow) (k : Nat) (hk : k < rows.length) :
    ∃ rk, rows[k]? = some rk ∧ (rows.map CoreRow.s).getD k 0 = rk.s := by
  have h : rows[k]? = some rows[k] := List.getElem?_eq_getElem hk
  exact ⟨rows[k], h, by rw [List.getD_eq_getElem?, List.getElem?_map, h]; rfl⟩

theorem getD_mem_of_lt (xs : List Nat) (m : Nat) (hm : m < xs.length) : xs.getD m 0 ∈ xs := by
  rw [List.getD_eq_getElem?, List.getElem?_eq_getElem hm]
  exact List.getElem_mem xs m hm

theorem index_lt_of_lookup (rows : List CoreRow) (j : Nat) (r : CoreRow)
    (hj : rows[j]? = some r) : j < rows.length := by
  rcases List.getElem?_eq_some.mp hj with ⟨h, _⟩
  exact h

theorem input_coeff_bound (i : Inputs) (rows : List CoreRow) (e : Bool)
    (reps : Representatives i rows) (gates : CoreGates i rows e)
    (xs : List Nat) (hxs : xs ∈ InputPolys i) (m : Nat) (hm : m < xs.length) :
    xs.getD m 0 < q :=
  strictQ_from_actual_checks _ (reps.1 xs hxs _ (getD_mem_of_lt xs m hm))
    (gates.2.2.1 xs hxs _ (getD_mem_of_lt xs m hm))

theorem core_secret_ternary (hf : FieldProducts) (i : Inputs) (rows : List CoreRow) (e : Bool)
    (reps : Representatives i rows) (gates : CoreGates i rows e) (k : Nat) (hk : k < ringN) :
    (rows.map CoreRow.s).getD k 0 = -1 ∨ (rows.map CoreRow.s).getD k 0 = 0 ∨
      (rows.map CoreRow.s).getD k 0 = 1 := by
  have hk' : k < rows.length := by rw [gates.2.1]; exact hk
  rcases row_lookup rows k hk' with ⟨rk, hrk, hs⟩
  obtain ⟨hter, -⟩ := gates.2.2.2.2.2.2.1 k rk hrk
  rw [hs]
  exact ternary_from_cubic hf rk.s (reps.2 rk (List.getElem?_mem hrk)).1 hter

/-- Composition of the per-row gate lemmas: for any satisfying assignment (`Representatives`
convention, `CoreGates` as assembled at the end of `decryption_core`, and the
`FieldProducts` premise used to read the cubic gates), every row `j` satisfies the exact
integer equations behind the key reduction, the key binding, the decrypt reduction and the
digit decomposition, and its `(d, ns, dwrap)` triple is the canonical one pinned by `v`.
Nothing is omitted: all six conjuncts are discharged from the existing per-row lemmas. The
statement is still about modular equations over the model's integer representatives; it
does not identify the secret, the plaintext, or the owner. -/
theorem core_row_integer (hf : FieldProducts) (i : Inputs) (rows : List CoreRow) (e : Bool)
    (reps : Representatives i rows) (gates : CoreGates i rows e)
    (j : Nat) (r : CoreRow) (hj : rows[j]? = some r) :
    let sec := fun k => (rows.map CoreRow.s).getD k 0
    negacyclicCoeff ringN (coeff i.a) sec j = r.asRem + r.asKappa * q ∧
    coeff i.b j = r.asRem + ((r.epkU : Int) - r.epkV) + r.asWrap * q ∧
    negacyclicCoeff ringN (coeff i.c1) sec j = coeff i.c2 j - r.v + r.csKappa * q ∧
    r.digit = coreDigit r.v ∧ r.noise = coreNoise r.v ∧ r.digitWrap = coreWrap r.v := by
  intro sec
  have hjl : j < rows.length := index_lt_of_lookup rows j r hj
  have hjn : j < ringN := by rw [← gates.2.1]; exact hjl
  have hmem : r ∈ rows := List.getElem?_mem hj
  have hrep := reps.2 r hmem
  have hshape := gates.2.2.2.2.2.1 r hmem
  obtain ⟨_, hu, hv, hak, har, haw, hga, hgb, hck, hcv, hgc, hgd⟩ :=
    gates.2.2.2.2.2.2.1 j r hj
  have hsec : ∀ k, k < ringN → sec k = -1 ∨ sec k = 0 ∨ sec k = 1 :=
    fun k hk => core_secret_ternary hf i rows e reps gates k hk
  have hpoly : ∀ xs ∈ InputPolys i, ∀ m, m < ringN → 0 ≤ coeff xs m ∧ coeff xs m < q := by
    intro xs hxs m hm
    have hl : xs.length = ringN := by
      simp only [InputPolys, List.mem_cons, List.not_mem_nil, or_false] at hxs
      rcases hxs with h | h | h | h <;> subst xs
      · exact gates.1.1
      · exact gates.1.2.1
      · exact gates.1.2.2.1
      · exact gates.1.2.2.2
    have hb := input_coeff_bound i rows e reps gates xs hxs m (by rw [hl]; exact hm)
    unfold coeff
    omega
  have hla := ring_coefficient_bound (coeff i.a) sec j (hpoly i.a (by simp [InputPolys])) hsec hjn
  have hlc := ring_coefficient_bound (coeff i.c1) sec j (hpoly i.c1 (by simp [InputPolys])) hsec hjn
  have hkappa_a := kappa_from_actual_checks r.asKappa hrep.2.2.2.2.1 hak
  have hkappa_c := kappa_from_actual_checks r.csKappa hrep.2.2.2.2.2.2.2.1 hck
  have hrem := strictQ_from_actual_checks r.asRem hrep.2.2.2.1 har
  have hvq := strictQ_from_actual_checks r.v hrep.2.2.2.2.2.2.1 hcv
  have hu' := error_half_from_cubic hf r.epkU hrep.2.1 hu
  have hv' := error_half_from_cubic hf r.epkV hrep.2.2.1 hv
  have hw' := ternary_from_cubic hf r.asWrap hrep.2.2.2.2.2.1 haw
  have hb := hpoly i.b (by simp [InputPolys]) j hjn
  have hc2 := hpoly i.c2 (by simp [InputPolys]) j hjn
  have hd := digit_gate_integer r.v r.digit r.noise r.digitWrap hvq
    (row_digit_bound r hshape) (row_noise_bound r hshape) hgd
  refine ⟨?_, ?_, ?_, ?_⟩
  · exact reduction_gate_integer _ r.asKappa r.asRem hla hkappa_a hrem hga
  · exact key_binding_gate_integer (i.b.getD j 0) r.asRem r.epkU r.epkV r.asWrap
      (by unfold coeff at hb; omega) hrem (by omega) (by omega) hw' hgb
  · exact decryption_gate_integer _ r.csKappa (i.c2.getD j 0) r.v hlc hkappa_c
      (by unfold coeff at hc2; omega) hvq hgc
  · exact digit_solution_unique r.v r.digit r.noise r.digitWrap hvq
      (row_digit_bound r hshape) (row_noise_bound r hshape) hd

theorem exposed_high_bits_zero (i : Inputs) (rows : List CoreRow)
    (gates : CoreGates i rows true) : packBits ((rows.drop 64).map CoreRow.bit) = 0 := by
  apply packBits_all_false
  intro b hb
  rcases List.mem_map.mp hb with ⟨r,hr,he⟩
  rw [← he]
  exact gates.2.2.2.2.2.2.2.2.2 rfl r hr

theorem exposed_value_u64 (i : Inputs) (rows : List CoreRow)
    (reps : Representatives i rows) (gates : CoreGates i rows true) :
    weighted (rows.map CoreRow.digit) < 2^64 := by
  rw [core_exact_binary_value i rows true reps gates]
  have hz := exposed_high_bits_zero i rows gates
  have hp := packBits_append ((rows.take 64).map CoreRow.bit) ((rows.drop 64).map CoreRow.bit)
  rw [← List.map_append, List.take_append_drop] at hp
  rw [hz] at hp
  simp only [Nat.mul_zero, Nat.add_zero] at hp
  rw [hp]
  have hb := packBits_bound ((rows.take 64).map CoreRow.bit)
  have hl : ((rows.take 64).map CoreRow.bit).length = 64 := by
    simp [gates.2.1, ringN, Nat.min_def]
  rw [hl] at hb
  exact hb

theorem exposed_value_from_lo_hi (i : Inputs) (rows : List CoreRow)
    (reps : Representatives i rows) (gates : CoreGates i rows true) :
    weighted (rows.map CoreRow.digit) =
      packBits ((rows.take 32).map CoreRow.bit) +
        2^32 * packBits (((rows.drop 32).take 32).map CoreRow.bit) := by
  rw [core_exact_binary_value i rows true reps gates]
  have hz := exposed_high_bits_zero i rows gates
  have hp := packBits_append ((rows.take 64).map CoreRow.bit) ((rows.drop 64).map CoreRow.bit)
  rw [← List.map_append, List.take_append_drop, hz] at hp
  simp only [Nat.mul_zero, Nat.add_zero] at hp
  rw [hp]
  have hs := List.take_add rows 32 32
  change rows.take 64 = _ at hs
  rw [hs, List.map_append, packBits_append]
  have hl : ((rows.take 32).map CoreRow.bit).length = 32 := by
    simp [gates.2.1, ringN, Nat.min_def]
  rw [hl]

-- Native algorithms. Mathematical integers expose the operations and guards; their
-- refinement to Rust's fixed-width arithmetic, debug assertions, indexing and
-- `unwrap` is not asserted. NativeMachineDomain below records the relevant widths.
def truncDiv (x y : Int) : Int :=
  if x < 0 then -((x.natAbs / y.natAbs : Nat) : Int) else (x.natAbs / y.natAbs : Nat)
def truncRem (x y : Int) : Int := x - truncDiv x y * y
def reduceWithQuotient (lo : Int) : Nat × Int :=
  let r := truncRem lo q
  let rem := if r < 0 then r + q else r
  (rem.toNat, truncDiv (lo-rem) q)
def euclideanReduce (lo : Int) : Nat × Int := ((lo % q).toNat, lo / q)
def centeredDiff (b rem : Nat) : Int :=
  let d := ((b : Int)-rem) % q
  if d > (q : Int)/2 then d-q else d

theorem truncDiv_q_formula (x : Int) :
    truncDiv x q = if x < 0 then -((-x)/(q : Int)) else x/(q : Int) := by
  unfold truncDiv
  split
  · rename_i h
    simp only [Int.ofNat_ediv, Int.natAbs_ofNat]
    rw [Int.ofNat_natAbs_of_nonpos (by omega : x ≤ 0)]
  · rename_i h
    simp only [Int.ofNat_ediv, Int.natAbs_ofNat]
    rw [Int.natAbs_of_nonneg (by omega : 0 ≤ x)]

theorem native_reduction_is_euclidean (lo : Int) :
    reduceWithQuotient lo = euclideanReduce lo := by
  let r := lo - truncDiv lo q * q
  have hr : (if r < 0 then r + q else r) = lo % q := by
    dsimp [r]
    rw [truncDiv_q_formula]
    split <;> split <;> simp only [q] at * <;> omega
  change ((if r < 0 then r+q else r).toNat,
    truncDiv (lo-(if r < 0 then r+q else r)) q) = euclideanReduce lo
  rw [hr, truncDiv_q_formula]
  unfold euclideanReduce
  apply Prod.ext
  · rfl
  · split <;> simp only [q] at * <;> omega

theorem native_reduction_equation (lo : Int) :
    lo = (reduceWithQuotient lo).1 + (reduceWithQuotient lo).2 * (q : Int) := by
  rw [native_reduction_is_euclidean]
  simp only [euclideanReduce]
  have hn := Int.emod_nonneg lo (by decide : (q : Int) ≠ 0)
  have he := Int.emod_add_ediv' lo (q : Int)
  rw [Int.toNat_of_nonneg hn]
  omega

theorem native_reduction_canonical (lo : Int) : (reduceWithQuotient lo).1 < q := by
  rw [native_reduction_is_euclidean]
  simp only [euclideanReduce]
  have hn := Int.emod_nonneg lo (by decide : (q : Int) ≠ 0)
  have hh := Int.emod_lt_of_pos lo (by decide : (0 : Int) < q)
  have he := Int.toNat_of_nonneg hn
  omega

theorem native_reduction_quotient_bound (lo : Int)
    (h : -(ringN : Int)*(q-1) ≤ lo ∧ lo ≤ ringN*(q-1)) :
    -(ringN : Int) ≤ (reduceWithQuotient lo).2 ∧
      (reduceWithQuotient lo).2 ≤ ringN := by
  rw [native_reduction_is_euclidean]
  simp only [euclideanReduce, ringN, q] at *
  omega

theorem centered_diff_bound (b rem : Nat) :
    -((q-1 : Nat)/2 : Nat) ≤ centeredDiff b rem ∧
      centeredDiff b rem ≤ ((q-1 : Nat)/2 : Nat) := by
  have hn := Int.emod_nonneg ((b : Int)-rem) (by decide : (q : Int) ≠ 0)
  simp only [centeredDiff, q] at *
  split <;> omega

theorem centered_diff_modulo (b rem : Nat) :
    centeredDiff b rem % (q : Int) = ((b : Int)-rem) % q := by
  simp only [centeredDiff, q]
  split <;> omega

structure NativeWitness where
  s : List Int
  epkU : List Nat
  epkV : List Nat
  asRem : List Nat
  asKappa : List Int
  asWrap : List Int
  v : List Nat
  csKappa : List Int
  digits : List Nat
  noiseShifted : List Nat
  digitWrap : List Bool
  bits : List Nat
  carries : List Nat
  value : Nat
  deriving Repr, DecidableEq

inductive NativeError where
  | lengths | secret | degenerate | noncanonical | keyNoise | keyDebugAssertion
  | decryptDebugAssertion | digit | highDigit | valueOverflow | carry | finalCarry
  deriving Repr, DecidableEq
structure KeyRow where
  rem : Nat
  kappa : Int
  wrap : Int
  u : Nat
  v : Nat
  deriving Repr, DecidableEq
structure DecryptRow where
  v : Nat
  kappa : Int
  deriving Repr, DecidableEq
structure DigitRow where
  digit : Nat
  noise : Nat
  wrap : Bool
  deriving Repr, DecidableEq
def buildKeyRow (debug : Bool) (b : Nat) (lo : Int) : Except NativeError KeyRow := do
  let (rem, kappa) := reduceWithQuotient lo
  let e := centeredDiff b rem
  if e < -2 ∨ e > 2 then throw .keyNoise
  let wnum := (b : Int)-e-rem
  if debug && decide (truncRem wnum q ≠ 0) then throw .keyDebugAssertion
  pure ⟨rem, kappa, truncDiv wnum q, (max e 0).toNat, (max (-e) 0).toNat⟩
def buildDecryptRow (debug : Bool) (c2 : Nat) (lo : Int) : Except NativeError DecryptRow := do
  let rem := (reduceWithQuotient lo).1
  let v := (((c2 : Int)-rem) % q).toNat
  let target := lo-((c2 : Int)-v)
  if debug && decide (truncRem target q ≠ 0) then throw .decryptDebugAssertion
  pure ⟨v, truncDiv target q⟩
def nativeV (lo : Int) (c2 : Nat) : Nat :=
  (((c2 : Int)-(reduceWithQuotient lo).1) % q).toNat
def nativeCsKappa (lo : Int) (c2 : Nat) : Int :=
  truncDiv (lo-((c2 : Int)-nativeV lo c2)) q

theorem native_decrypt_constructed_equation (lo : Int) (c2 : Nat) :
    lo = (c2 : Int)-nativeV lo c2 + nativeCsKappa lo c2*q ∧ nativeV lo c2 < q := by
  have hr := native_reduction_equation lo
  have hn := Int.emod_nonneg ((c2 : Int)-(reduceWithQuotient lo).1)
    (by decide : (q : Int) ≠ 0)
  have he := Int.toNat_of_nonneg hn
  unfold nativeCsKappa nativeV
  rw [truncDiv_q_formula]
  simp only [q] at *
  split <;> constructor <;> omega

theorem native_decrypt_constructed_quotient_bound (lo : Int) (c2 : Nat)
    (hl : -(ringN : Int)*(q-1) ≤ lo ∧ lo ≤ ringN*(q-1)) (hc : c2 < q) :
    -(ringN : Int) ≤ nativeCsKappa lo c2 ∧ nativeCsKappa lo c2 ≤ ringN := by
  have he := native_decrypt_constructed_equation lo c2
  simp only [ringN, q] at *
  omega

theorem native_key_halves (e : Int) (h : -2 ≤ e ∧ e ≤ 2) :
    (max e 0).toNat ≤ 2 ∧ (max (-e) 0).toNat ≤ 2 ∧
    ((max e 0).toNat : Int) - (max (-e) 0).toNat = e := by
  -- `max`/`toNat` are opaque to `omega`; split on the sign of the centered noise.
  rcases Int.le_total 0 e with he | he
  · have h1 : max e 0 = e := Int.max_eq_left he
    have h2 : max (-e) 0 = 0 := Int.max_eq_right (by omega)
    have h3 := Int.toNat_of_nonneg he
    rw [h1, h2, Int.toNat_zero]
    omega
  · have h1 : max e 0 = 0 := Int.max_eq_right he
    have h2 : max (-e) 0 = -e := Int.max_eq_left (by omega)
    have h3 := Int.toNat_of_nonneg (by omega : (0:Int) ≤ -e)
    rw [h1, h2, Int.toNat_zero]
    omega

theorem native_key_wrap_constructed (b rem : Nat) (hb : b < q) (hr : rem < q)
    (he : -2 ≤ centeredDiff b rem ∧ centeredDiff b rem ≤ 2) :
    let wrap := truncDiv ((b : Int)-centeredDiff b rem-rem) q
    (b : Int) = (rem : Int)+centeredDiff b rem+wrap*q ∧
      (wrap = -1 ∨ wrap = 0 ∨ wrap = 1) := by
  have hm := centered_diff_modulo b rem
  dsimp only
  rw [truncDiv_q_formula]
  split <;> simp only [q] at * <;> constructor <;> omega
def buildDigitRow (v : Nat) : Except NativeError DigitRow := do
  let d := coreDigit v
  if d ≥ 256 then throw .digit
  pure ⟨d, coreNoise v, coreWrap v⟩
def decodeDigits : List Nat → Nat → Nat → Except NativeError Nat
  | [], _, value => if value < 2^64 then .ok value else .error .valueOverflow
  | d :: ds, i, value =>
    if d = 0 then decodeDigits ds (i+1) value
    else if i ≥ 64 then .error .highDigit
    else decodeDigits ds (i+1) (value+d*2^i)
def encodeAmount (value : Nat) : List Nat :=
  ((bitsOf 64 value) ++ List.replicate (ringN-64) false).map boolNat
def buildCarries : List Nat → List Nat → Nat → Except NativeError (List Nat)
  | [], [], carry => if carry = 0 then .ok [] else .error .finalCarry
  | d::ds, b::bs, carry => do
    let t := (d : Int)+carry-b
    if t < 0 ∨ truncRem t 2 ≠ 0 then throw .carry
    let tail ← buildCarries ds bs ((truncDiv t 2).toNat % 2^16)
    pure (carry :: tail)
  | _, _, _ => .error .lengths
def mapExcept {α β ε : Type} (f : α → Except ε β) : List α → Except ε (List β)
  | [] => .ok []
  | x::xs => do
    let y ← f x
    let ys ← mapExcept f xs
    pure (y::ys)
def nativeBuild (debug : Bool) (i : Inputs) (s : List Int) : Except NativeError NativeWitness := do
  if ¬ InputLengths i ∨ s.length ≠ ringN then throw .lengths
  if s.any (fun x => decide (x < -1 ∨ x > 1)) then throw .secret
  if !polyNonzero i.a || !polyNonzero i.c1 then throw .degenerate
  if (i.a ++ i.b ++ i.c1 ++ i.c2).any (fun x => decide (x ≥ q)) then throw .noncanonical
  let alo := nativeNegacyclic i.a s
  let keys ← mapExcept (fun (j,lo) => buildKeyRow debug (i.b.getD j 0) lo) alo.enum
  let clo := nativeNegacyclic i.c1 s
  let decs ← mapExcept (fun (j,lo) => buildDecryptRow debug (i.c2.getD j 0) lo) clo.enum
  let digits ← mapExcept (fun d => buildDigitRow d.v) decs
  let value ← decodeDigits (digits.map DigitRow.digit) 0 0
  let bits := encodeAmount value
  let carries ← buildCarries (digits.map DigitRow.digit) bits 0
  pure ⟨s, keys.map KeyRow.u, keys.map KeyRow.v, keys.map KeyRow.rem,
    keys.map KeyRow.kappa, keys.map KeyRow.wrap, decs.map DecryptRow.v,
    decs.map DecryptRow.kappa, digits.map DigitRow.digit, digits.map DigitRow.noise,
    digits.map DigitRow.wrap, bits, carries, value⟩

def NativeMachineDomain (w : NativeWitness) : Prop :=
  (∀ x ∈ w.s, -128 ≤ x ∧ x < 128) ∧
  (∀ x ∈ w.epkU ++ w.epkV ++ w.digits ++ w.bits, x < 2^8) ∧
  (∀ x ∈ w.asRem ++ w.v ++ w.noiseShifted, x < 2^32) ∧
  (∀ x ∈ w.asKappa ++ w.asWrap ++ w.csKappa, -(2^63 : Int) < x ∧ x < 2^63) ∧
  (∀ x ∈ w.carries, x < 2^16) ∧ w.value < 2^64

def fillRow (w : NativeWitness) (j : Nat) : CoreRow :=
  let noise := w.noiseShifted.getD j 0
  let hi := noise / 2^19
  let nu := min hi 7
  let nv := hi-nu
  ⟨w.s.getD j 0, w.epkU.getD j 0, w.epkV.getD j 0, w.asRem.getD j 0,
   w.asKappa.getD j 0, w.asWrap.getD j 0, w.v.getD j 0, w.csKappa.getD j 0,
   bitsOf 8 (w.digits.getD j 0), bitsOf 19 noise, bitsOf 3 nu, bitsOf 3 nv,
   decide (w.bits.getD j 0 = 1), w.carries.getD j 0, w.digitWrap.getD j false⟩
def FillLengths (w : NativeWitness) : Prop :=
  ([w.s.length, w.epkU.length, w.epkV.length, w.asRem.length, w.asKappa.length,
    w.asWrap.length, w.v.length, w.csKappa.length, w.digits.length,
    w.noiseShifted.length, w.digitWrap.length, w.bits.length, w.carries.length].all
    fun n => decide (ringN ≤ n)) = true
instance (w : NativeWitness) : Decidable (FillLengths w) :=
  inferInstanceAs (Decidable (_ = true))
inductive WriteSlot where
  | s | epkU | epkV | asRem | asKappa | asWrap | v | csKappa
  | digitBit (j : Nat) | noiseLo (j : Nat) | noiseU (j : Nat) | noiseV (j : Nat)
  | bit | carry | digitWrap
  deriving Repr, DecidableEq
structure WriteOp where
  row : Nat
  slot : WriteSlot
  value : Int
  deriving Repr, DecidableEq
def rowWrites (j : Nat) (r : CoreRow) : List WriteOp :=
  [⟨j,.s,r.s⟩, ⟨j,.epkU,r.epkU⟩, ⟨j,.epkV,r.epkV⟩, ⟨j,.asRem,r.asRem⟩,
   ⟨j,.asKappa,r.asKappa⟩, ⟨j,.asWrap,r.asWrap⟩, ⟨j,.v,r.v⟩, ⟨j,.csKappa,r.csKappa⟩] ++
  (r.digitBits.enum.map fun (k,b) => ⟨j,.digitBit k,boolNat b⟩) ++
  (r.noiseLo.enum.map fun (k,b) => ⟨j,.noiseLo k,boolNat b⟩) ++
  (r.noiseU.enum.map fun (k,b) => ⟨j,.noiseU k,boolNat b⟩) ++
  (r.noiseV.enum.map fun (k,b) => ⟨j,.noiseV k,boolNat b⟩) ++
  [⟨j,.bit,boolNat r.bit⟩, ⟨j,.carry,r.carry⟩, ⟨j,.digitWrap,boolNat r.digitWrap⟩]
-- Prefix writes before a short-array panic or conflicting-wire unwrap are not
-- modeled as transactional: actual execution is the sequential `rowWrites` stream.
def fillWrites (w : NativeWitness) : Option (List WriteOp) :=
  if FillLengths w then some ((List.range ringN).bind fun j => rowWrites j (fillRow w j))
  else none
def fillDecryptionCore (_exposeAmount : Bool) (w : NativeWitness) : Option (List WriteOp) :=
  fillWrites w

def ciphertextDigestWords (c1 c2 : List Nat) : Option (List Nat) :=
  if c1.length = ringN ∧ c2.length = ringN then some ([0x494d5243, ringN] ++ c1 ++ c2)
  else none
def publicKeyDigestWords (a b : List Nat) : Option (List Nat) :=
  if a.length = ringN ∧ b.length = ringN then some ([0x494d5250, ringN] ++ a ++ b)
  else none
-- Hash invocation and output encoding are explicit dependency requests, not
-- assumptions that equal digests establish equal polynomials.
inductive HashRequest where
  | keccakU32 (words : List Nat)
  | poseidonFieldsToCanonicalBytes32 (words : List Nat)
  deriving Repr, DecidableEq
def ciphertextDigestRequest (c1 c2 : List Nat) : Option HashRequest :=
  (ciphertextDigestWords c1 c2).map HashRequest.keccakU32
def publicKeyDigestRequest (a b : List Nat) : Option HashRequest :=
  (publicKeyDigestWords a b).map HashRequest.poseidonFieldsToCanonicalBytes32

theorem ciphertext_digest_exact_words (c1 c2 : List Nat)
    (h1 : c1.length = ringN) (h2 : c2.length = ringN) :
    ciphertextDigestWords c1 c2 = some ([0x494d5243,ringN] ++ c1 ++ c2) := by
  simp [ciphertextDigestWords, h1, h2]

theorem public_key_digest_exact_words (a b : List Nat)
    (h1 : a.length = ringN) (h2 : b.length = ringN) :
    publicKeyDigestWords a b = some ([0x494d5250,ringN] ++ a ++ b) := by
  simp [publicKeyDigestWords, h1, h2]

theorem digest_payload_length (a b : List Nat)
    (h1 : a.length = ringN) (h2 : b.length = ringN) (tag : Nat) :
    ([tag,ringN] ++ a ++ b).length = 4098 := by
  simp [h1, h2, ringN]

theorem fill_ignores_value (w : NativeWitness) (value : Nat) (j : Nat) :
    fillRow {w with value := value} j = fillRow w j := rfl

theorem fill_bit_is_equality_to_one (w : NativeWitness) (j : Nat) :
    (fillRow w j).bit = decide (w.bits.getD j 0 = 1) := rfl

theorem fill_noise_high_halves (w : NativeWitness) (j : Nat) :
    (fillRow w j).noiseU = bitsOf 3 (min (w.noiseShifted.getD j 0 / 2^19) 7) ∧
    (fillRow w j).noiseV = bitsOf 3
      (w.noiseShifted.getD j 0 / 2^19 - min (w.noiseShifted.getD j 0 / 2^19) 7) := ⟨rfl,rfl⟩

theorem fill_ignores_expose_amount (w : NativeWitness) :
    fillDecryptionCore true w = fillDecryptionCore false w := rfl

theorem bitsOf_length (width x : Nat) : (bitsOf width x).length = width := by
  have h : ∀ n (acc : List Nat), (List.range.loop n acc).length = n + acc.length := by
    intro n
    induction n with
    | zero => intro acc; simp [List.range.loop]
    | succ n ih => intro acc; simp only [List.range.loop, ih, List.length_cons]; omega
  simp only [bitsOf, List.length_map, List.range]
  simpa using h width []

theorem fill_row_allocation_shape (w : NativeWitness) (j : Nat) : (fillRow w j).shape := by
  simp [CoreRow.shape, fillRow, bitsOf_length]

theorem row_write_count (r : CoreRow) (j : Nat) (hs : r.shape) :
    (rowWrites j r).length = 44 := by
  simp [rowWrites, hs.1, hs.2.1, hs.2.2.1, hs.2.2.2]

theorem native_build_length_refusal (debug : Bool) (i : Inputs) (s : List Int)
    (h : ¬ InputLengths i ∨ s.length ≠ ringN) :
    nativeBuild debug i s = .error .lengths := by
  simp [nativeBuild, h, Bind.bind, Except.bind, Pure.pure, Except.pure]

theorem native_digit_success_exact (v : Nat) (h : coreDigit v < 256) :
    buildDigitRow v = .ok ⟨coreDigit v, coreNoise v, coreWrap v⟩ := by
  simp [buildDigitRow, Nat.not_le.mpr h, Bind.bind, Except.bind, Pure.pure, Except.pure]

theorem native_digit_failure_exact (v : Nat) (h : 256 ≤ coreDigit v) :
    buildDigitRow v = .error .digit := by
  simp [buildDigitRow, h, Bind.bind, Except.bind, Pure.pure, Except.pure]

theorem truncRem_multiple_q (k : Int) : truncRem (k * q) q = 0 := by
  unfold truncRem
  rw [truncDiv_q_formula]
  simp only [q]
  split <;> omega

/-- The decrypt row is built from the non-canonical difference `c2 - rem` reduced mod q, in
both debug modes. The debug assertion `target % q == 0` can never fire: by
`native_decrypt_constructed_equation` the row's own `cs_kappa` is the exact truncating
quotient of `target`, so `target` is a multiple of `q` (first conjunct). -/
theorem native_decrypt_uses_noncanonical_difference (debug : Bool) (c2 : Nat) (lo : Int) :
    truncRem (lo-((c2 : Int)-nativeV lo c2)) q = 0 ∧
    buildDecryptRow debug c2 lo =
      .ok ⟨((((c2 : Int)-(reduceWithQuotient lo).1)%q).toNat),
        truncDiv (lo-((c2 : Int)-((((c2 : Int)-(reduceWithQuotient lo).1)%q).toNat))) q⟩ := by
  have he := (native_decrypt_constructed_equation lo c2).1
  have hk : lo-((c2 : Int)-nativeV lo c2) = nativeCsKappa lo c2 * q := by
    simp only [q] at he ⊢; omega
  have hd : truncRem (lo-((c2 : Int)-nativeV lo c2)) q = 0 := by
    rw [hk]; exact truncRem_multiple_q _
  refine ⟨hd, ?_⟩
  unfold nativeV at hd
  simp [buildDecryptRow, hd, Bind.bind, Except.bind, Pure.pure, Except.pure]

theorem noise_native_high_halves_in_range (noise : Nat) (h : noise < delta) :
    min (noise/2^19) 7 < 8 ∧ noise/2^19 - min (noise/2^19) 7 < 8 ∧
    noise%2^19 + (min (noise/2^19) 7 + (noise/2^19 - min (noise/2^19) 7))*2^19 = noise := by
  simp only [delta] at h
  omega

-- A positive local production trace, and the zero-padding rows used alongside it.
-- These are kernel-checked algebraic examples, not executions of production crypto.
theorem normal_positive_native_trace :
    buildKeyRow true 0 0 = .ok ⟨0,0,0,0,0⟩ ∧
    buildDecryptRow true delta 0 = .ok ⟨delta,0⟩ ∧
    buildDigitRow delta = .ok ⟨1,halfDelta,false⟩ ∧
    decodeDigits [1] 0 0 = .ok 1 ∧
    buildCarries [1] [1] 0 = .ok [0] := by
  exact ⟨rfl,rfl,rfl,rfl,rfl⟩

theorem normal_zero_padding_trace :
    buildKeyRow true 0 0 = .ok ⟨0,0,0,0,0⟩ ∧
    buildDecryptRow true 0 0 = .ok ⟨0,0⟩ ∧
    buildDigitRow 0 = .ok ⟨0,halfDelta,false⟩ ∧
    buildCarries [0] [0] 0 = .ok [0] := by
  exact ⟨rfl,rfl,rfl,rfl⟩

def normalZeroRow : CoreRow :=
  ⟨0,0,0,0,0,0,0,0,List.replicate 8 false,bitsOf 19 halfDelta,
    bitsOf 3 7,bitsOf 3 0,false,0,false⟩
def normalInputs : Inputs :=
  ⟨List.replicate ringN 1,List.replicate ringN 0,
    List.replicate ringN 1,List.replicate ringN 0⟩
def normalRows : List CoreRow := List.replicate ringN normalZeroRow

theorem normal_zero_row_numeric :
    normalZeroRow.shape ∧ normalZeroRow.representatives ∧
    normalZeroRow.digit = 0 ∧ normalZeroRow.noise = halfDelta ∧
    StrictQGate 0 ∧ StrictQGate 1 ∧ KappaGate 0 ∧ TernaryGate 0 ∧ ErrorHalfGate 0 := by
  unfold CoreRow.shape CoreRow.representatives Centered Canonical CoreRow.digit CoreRow.noise
    StrictQGate RangeGate KappaGate TernaryGate ErrorHalfGate FZero normalZeroRow
  unfold RangeGate
  decide

theorem replicate_zero_lookup (n j : Nat) : (List.replicate n (0 : Int)).getD j 0 = 0 := by
  rw [List.getD_eq_getElem?, List.getElem?_replicate]
  split <;> rfl

theorem normal_secret_is_zero (j : Nat) : (normalRows.map CoreRow.s).getD j 0 = 0 := by
  simp only [normalRows, List.map_replicate, normalZeroRow]
  exact replicate_zero_lookup ringN j

theorem normal_rows_carries (n : Nat) : CarryGates (List.replicate n normalZeroRow) := by
  induction n with
  | zero => trivial
  | succ n ih =>
    rw [List.replicate_succ]
    change RangeGate 8 0 ∧ FZero ((normalZeroRow.digit : Int)+0-0-2*firstCarry
      (List.replicate n normalZeroRow)) ∧ CarryGates (List.replicate n normalZeroRow)
    have hf : firstCarry (List.replicate n normalZeroRow) = 0 := by
      cases n <;> rfl
    rw [hf, normal_zero_row_numeric.2.2.1]
    exact ⟨by unfold RangeGate; decide, by unfold FZero; decide, ih⟩

theorem normal_row_gates (j : Nat) : RowGates normalInputs normalRows j normalZeroRow := by
  have hs : (fun k => (normalRows.map CoreRow.s).getD k 0) = (fun _ => 0) := by
    funext k; exact normal_secret_is_zero k
  have hb : coeff normalInputs.b j = 0 := by
    simp only [coeff, normalInputs]
    rw [List.getD_eq_getElem?, List.getElem?_replicate]
    split <;> rfl
  have hc : coeff normalInputs.c2 j = 0 := hb
  unfold RowGates
  rw [hs]
  dsimp only
  rw [negacyclic_zero_secret, negacyclic_zero_secret, hb, hc]
  change TernaryGate 0 ∧ ErrorHalfGate 0 ∧ ErrorHalfGate 0 ∧ KappaGate 0 ∧
    StrictQGate 0 ∧ TernaryGate 0 ∧ FZero 0 ∧ FZero 0 ∧ KappaGate 0 ∧
    StrictQGate 0 ∧ FZero 0 ∧ FZero ((0 : Int)+halfDelta-delta*normalZeroRow.digit-
      normalZeroRow.noise-0*q)
  rw [normal_zero_row_numeric.2.2.1, normal_zero_row_numeric.2.2.2.1]
  unfold TernaryGate ErrorHalfGate KappaGate StrictQGate RangeGate FZero
  decide

/-- Satisfiability witness at the production dimension: it exhibits the all-zero
assignment (zero secret, zero rows, `a = c1 = 1`, `b = c2 = 0`), not a production trace. -/
theorem zero_padding_dimension_satisfiable :
    Representatives normalInputs normalRows ∧ CoreGates normalInputs normalRows true := by
  have hr : ∀ r ∈ normalRows, r = normalZeroRow := by
    intros r h; exact (List.mem_replicate.mp h).2
  have hp : ∀ xs ∈ InputPolys normalInputs, ∀ x ∈ xs, x = 0 ∨ x = 1 := by
    intro xs hxs x hx
    simp only [InputPolys, List.mem_cons, List.not_mem_nil, or_false] at hxs
    rcases hxs with h | h | h | h <;> subst xs <;>
      simp only [normalInputs, List.mem_replicate] at hx <;> omega
  constructor
  · constructor
    · intros xs hxs x hx; rcases hp xs hxs x hx with h | h <;> subst x <;> unfold Canonical <;> decide
    · intros r h; rw [hr r h]; exact normal_zero_row_numeric.2.1
  · refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · simp [InputLengths, normalInputs]
    · simp [normalRows]
    · intros xs hxs x hx
      rcases hp xs hxs x hx with h | h <;> subst x
      · exact normal_zero_row_numeric.2.2.2.2.1
      · exact normal_zero_row_numeric.2.2.2.2.2.1
    · decide
    · decide
    · intros r h; rw [hr r h]; exact normal_zero_row_numeric.1
    · intros j r h
      have he : r = normalZeroRow := hr r (List.getElem?_mem h)
      rw [he]; exact normal_row_gates j
    · unfold FZero; decide
    · exact normal_rows_carries ringN
    · intros _ r h
      have hm : r ∈ normalRows := by
        rw [← List.take_append_drop 64 normalRows]
        exact List.mem_append_right _ h
      have he : r = normalZeroRow := hr r hm
      rw [he]; rfl

end Zkp.Implementation.DecryptionGadget
