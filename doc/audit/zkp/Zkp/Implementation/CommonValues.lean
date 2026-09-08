import Std

/-!
# Common leaf value types: word layouts, encoders, nullifier preimages

Handwritten semantic model of the leaf value types under `src/common/`:
`tx.rs`, `transfer.rs`, `deposit.rs`, `withdrawal.rs`, `channel_id.rs`, `u63.rs`,
`salt.rs`, `error.rs`, `mod.rs`.

This is NOT a refinement proof of the Rust sources, of the plonky2 circuit
lowering, or of the Solidity consumers. Nothing here is machine-extracted from
the source; every definition is a hand transcription and can disagree with the
code it claims to model. What is kernel-checked is only the internal consistency
of this model plus the arithmetic facts stated about it.

Explicit undischarged premises (named boundaries):
* `poseidonAbsorb` / `keccakAbsorb`: hashes are opaque. No collision resistance
  and no injectivity is assumed or proved. Statements about hash agreement are
  conditional on an explicit premise about the two concrete compared preimages.
* `rangeCheck`: plonky2's `builder.range_check(x, b)` is modeled as
  "the canonical representative of `x` is `< 2 ^ b`". The gate lowering that is
  supposed to implement that is not modeled.
* Native/target refinement: `to_u64_vec` (native) and `to_vec` (target) are
  transcribed separately and only *compared*; that the circuit really lays out
  the same words is not proved.
* serde: every value type here derives `Deserialize` on its private field
  (`U63(u64)`, `ChannelId(u32)`, `PoseidonHashOut`), so a deserialized value
  bypasses `new` / `validate_components`. The model keeps the raw carrier
  separate from the constructor and states which facts need canonicality.
* Tree/merkle/leaf semantics (`Leafable`) beyond the leaf preimage are out of
  scope; so are the callers that decide what a nullifier is compared against.
-/

namespace Zkp.Implementation.CommonValues

/-- Decidable equality for `Except`, so that closed decoder runs can be checked
by `decide`. -/
instance instDecidableEqExcept {ε α : Type} [DecidableEq ε] [DecidableEq α] :
    DecidableEq (Except ε α)
  | .error x, .error y =>
      if h : x = y then isTrue (by rw [h])
      else isFalse (fun hc => by injection hc with h'; exact h h')
  | .ok x, .ok y =>
      if h : x = y then isTrue (by rw [h])
      else isFalse (fun hc => by injection hc with h'; exact h h')
  | .error _, .ok _ => isFalse (fun hc => Except.noConfusion hc)
  | .ok _, .error _ => isFalse (fun hc => Except.noConfusion hc)

theorem two_pow_pos (n : Nat) : 0 < 2 ^ n := by
  induction n with
  | zero => decide
  | succ k ih =>
    rw [Nat.pow_succ]
    omega

theorem two_pow_63_eq : (2 : Nat) ^ 63 = 9223372036854775808 := by decide
theorem two_pow_32_eq : (2 : Nat) ^ 32 = 4294967296 := by decide

/-! ## 0. Pinned constants -/

/-- `2 ^ 32`, pinned as a literal so `omega` can use it. -/
def twoPow32 : Nat := 4294967296
/-- `2 ^ 31` (`U63_HIGH_MAX + 1`). -/
def twoPow31 : Nat := 2147483648
/-- `2 ^ 63`. -/
def twoPow63 : Nat := 9223372036854775808
/-- `2 ^ 64`, the `u64` wrap point used by `checked_add`. -/
def twoPow64 : Nat := 18446744073709551616
/-- `u32::MAX`. -/
def u32Max : Nat := 4294967295
/-- Goldilocks order `2 ^ 64 - 2 ^ 32 + 1`. -/
def goldilocksOrder : Nat := 18446744069414584321

theorem two_pow_32_pinned : twoPow32 = 2 ^ 32 := by decide
theorem two_pow_31_pinned : twoPow31 = 2 ^ 31 := by decide
theorem two_pow_63_pinned : twoPow63 = 2 ^ 63 := by decide
theorem two_pow_64_pinned : twoPow64 = 2 ^ 64 := by decide
theorem u32_max_pinned : u32Max = 2 ^ 32 - 1 := by decide
theorem goldilocks_order_pinned : goldilocksOrder = 2 ^ 64 - 2 ^ 32 + 1 := by decide

/-- `POSEIDON_HASH_OUT_LEN` (src/utils/poseidon_hash_out.rs:36). -/
def poseidonHashOutLen : Nat := 4
/-- `BYTES32_LEN` = `U256_LEN` (src/ethereum_types). -/
def bytes32Len : Nat := 8
/-- `U256_LEN`. -/
def u256Len : Nat := 8
/-- `ADDRESS_LEN`. -/
def addressLen : Nat := 5
/-- `TX_LEN = POSEIDON_HASH_OUT_LEN + 1` (tx.rs:27). -/
def txLen : Nat := poseidonHashOutLen + 1
/-- `CHANNEL_ACTION_LEN = 1 + 1 + 1 + 8 + 8 + POSEIDON_HASH_OUT_LEN` (tx.rs:28). -/
def channelActionLen : Nat := 1 + 1 + 1 + 8 + 8 + poseidonHashOutLen
/-- `TX_V2_LEN = 1 + POSEIDON_HASH_OUT_LEN + 1 + POSEIDON_HASH_OUT_LEN` (tx.rs:29). -/
def txV2Len : Nat := 1 + poseidonHashOutLen + 1 + poseidonHashOutLen
/-- `TRANSFER_LEN = BYTES32_LEN + 1 + U256_LEN + BYTES32_LEN` (transfer.rs:26). -/
def transferLen : Nat := bytes32Len + 1 + u256Len + bytes32Len
/-- `WITHDRAWAL_LEN = ADDRESS_LEN + 1 + U256_LEN + 2 * BYTES32_LEN` (withdrawal.rs:20). -/
def withdrawalLen : Nat := addressLen + 1 + u256Len + 2 * bytes32Len
/-- `SALT_LEN = POSEIDON_HASH_OUT_LEN` (salt.rs:15). -/
def saltLen : Nat := poseidonHashOutLen
/-- `CHANNEL_ID_BITS` (src/constants.rs:16). -/
def channelIdBits : Nat := 32
/-- `U63_BITS` (u63.rs:14). -/
def u63Bits : Nat := 63
/-- `U63_LOW_BITS` (u63.rs:15). -/
def u63LowBits : Nat := 32
/-- `U63_HIGH_BITS = U63_BITS - U63_LOW_BITS` (u63.rs:16). -/
def u63HighBits : Nat := u63Bits - u63LowBits
/-- `U63_MAX_VALUE = (1 << 63) - 1` (u63.rs:17). -/
def u63MaxValue : Nat := 9223372036854775807
/-- `U63_HIGH_MAX = (1 << 31) - 1` (u63.rs:18). -/
def u63HighMax : Nat := 2147483647
/-- `MEMBER_SET_UPDATE_DOMAIN` = big-endian "IMMS" (src/constants.rs:262). -/
def memberSetUpdateDomain : Nat := 0x494d4d53
/-- plonky2 Poseidon sponge rate for Goldilocks (`SPONGE_RATE`). -/
def spongeRate : Nat := 8

theorem tx_len_pinned : txLen = 5 := by decide
theorem channel_action_len_pinned : channelActionLen = 23 := by decide
theorem tx_v2_len_pinned : txV2Len = 10 := by decide
theorem transfer_len_pinned : transferLen = 25 := by decide
theorem withdrawal_len_pinned : withdrawalLen = 30 := by decide
theorem salt_len_pinned : saltLen = 4 := by decide
theorem channel_id_bits_pinned : channelIdBits = 32 := by decide
theorem u63_bits_pinned : u63Bits = 63 := by decide
theorem u63_high_bits_pinned : u63HighBits = 31 := by decide
theorem u63_max_value_pinned : u63MaxValue = twoPow63 - 1 := by decide
theorem u63_high_max_pinned : u63HighMax = twoPow31 - 1 := by decide
theorem member_set_update_domain_is_imms :
    memberSetUpdateDomain =
      73 * 16777216 + 77 * 65536 + 77 * 256 + 83 := by decide

/-! ## 1. Word containers

`PoseidonHashOut` is four `u64` field words; `Bytes32`/`U256` are eight `u32`
limbs; `Address` is five `u32` limbs. Only the layout is modeled: the field
elements are plain `Nat`s here and canonicality is a stated premise, never an
invariant of the type. -/

structure Hash4 where
  w0 : Nat
  w1 : Nat
  w2 : Nat
  w3 : Nat
  deriving DecidableEq, Repr

structure Limbs8 where
  l0 : Nat
  l1 : Nat
  l2 : Nat
  l3 : Nat
  l4 : Nat
  l5 : Nat
  l6 : Nat
  l7 : Nat
  deriving DecidableEq, Repr

structure Limbs5 where
  a0 : Nat
  a1 : Nat
  a2 : Nat
  a3 : Nat
  a4 : Nat
  deriving DecidableEq, Repr

def hashWords (h : Hash4) : List Nat := [h.w0, h.w1, h.w2, h.w3]
def limbWords (b : Limbs8) : List Nat := [b.l0, b.l1, b.l2, b.l3, b.l4, b.l5, b.l6, b.l7]
def addrWords (a : Limbs5) : List Nat := [a.a0, a.a1, a.a2, a.a3, a.a4]

def zeroHash : Hash4 := ⟨0, 0, 0, 0⟩
def zeroLimbs8 : Limbs8 := ⟨0, 0, 0, 0, 0, 0, 0, 0⟩
def zeroLimbs5 : Limbs5 := ⟨0, 0, 0, 0, 0⟩

theorem hash_words_length (h : Hash4) : (hashWords h).length = poseidonHashOutLen := by
  simp [hashWords, poseidonHashOutLen]

theorem limb_words_length (b : Limbs8) : (limbWords b).length = bytes32Len := by
  simp [limbWords, bytes32Len]

theorem addr_words_length (a : Limbs5) : (addrWords a).length = addressLen := by
  simp [addrWords, addressLen]

/-- Every component is a `u32` limb. -/
def Limbs8.Canonical (b : Limbs8) : Prop := ∀ x ∈ limbWords b, x ≤ u32Max
def Limbs5.Canonical (a : Limbs5) : Prop := ∀ x ∈ addrWords a, x ≤ u32Max
/-- Field words of a genuine `PoseidonHashOut` are canonical Goldilocks
representatives. `PoseidonHashOut::from_u64_slice` (poseidon_hash_out.rs:55)
does NOT enforce this: it only checks the length. -/
def Hash4.Canonical (h : Hash4) : Prop := ∀ x ∈ hashWords h, x < goldilocksOrder

/-- `impl From<PoseidonHashOut> for Bytes32` (poseidon_hash_out.rs:239-253):
each field word becomes `[high, low]`, high first. This is the conversion at the
end of `SettledTransfer::nullifier` and `Deposit::nullifier`. -/
def hashToBytes32 (h : Hash4) : Limbs8 :=
  ⟨h.w0 / twoPow32, h.w0 % twoPow32,
   h.w1 / twoPow32, h.w1 % twoPow32,
   h.w2 / twoPow32, h.w2 % twoPow32,
   h.w3 / twoPow32, h.w3 % twoPow32⟩

/-- The `[high, low]` split is exact on `u64` words (quotient and remainder by
`2 ^ 32` determine the word), so the `PoseidonHashOut -> Bytes32` step of both
`nullifier()` functions loses nothing. It is the Poseidon call before it, not
this conversion, that needs a collision premise. -/
theorem hash_to_bytes32_injective_on_u64_words {a b : Hash4}
    (h : hashToBytes32 a = hashToBytes32 b) : a = b := by
  cases a with
  | mk a0 a1 a2 a3 =>
    cases b with
    | mk b0 b1 b2 b3 =>
      simp only [hashToBytes32, twoPow32, Limbs8.mk.injEq] at h
      obtain ⟨h0, h1, h2, h3, h4, h5, h6, h7⟩ := h
      simp only [Hash4.mk.injEq]
      refine ⟨?_, ?_, ?_, ?_⟩ <;> omega

/-! ## 2. `src/common/error.rs` -/

inductive CommonError where
  | txMerkleProofVerificationFailed (detail : String)
  | missingData (detail : String)
  | invalidData (detail : String)
  | nullifierAlreadyExists (detail : String)
  | invalidSpentValue (detail : String)
  | genesisBlockNotAllowed
  | invalidBlock (detail : String)
  | invalidWitness (detail : String)
  | invalidProof (detail : String)
  deriving DecidableEq, Repr

/-- Variant index in source declaration order (error.rs:3-28). -/
def commonErrorTag : CommonError → Nat
  | .txMerkleProofVerificationFailed _ => 0
  | .missingData _ => 1
  | .invalidData _ => 2
  | .nullifierAlreadyExists _ => 3
  | .invalidSpentValue _ => 4
  | .genesisBlockNotAllowed => 5
  | .invalidBlock _ => 6
  | .invalidWitness _ => 7
  | .invalidProof _ => 8

def commonErrorSamples : List CommonError :=
  [.txMerkleProofVerificationFailed "", .missingData "", .invalidData "",
   .nullifierAlreadyExists "", .invalidSpentValue "", .genesisBlockNotAllowed,
   .invalidBlock "", .invalidWitness "", .invalidProof ""]

theorem common_error_has_nine_variants : commonErrorSamples.length = 9 := by decide

theorem common_error_tags_are_distinct :
    commonErrorSamples.map commonErrorTag = [0, 1, 2, 3, 4, 5, 6, 7, 8] := by decide

/-- Every parse failure in these files is reported as one single variant,
`InvalidData`, with a free-form string. Callers therefore cannot distinguish a
length error from a range error from a bad enum tag by matching on the error. -/
def parseErrorsUsedInCommonValues : List Nat := [commonErrorTag (.invalidData "")]

theorem common_values_parse_errors_are_one_variant :
    parseErrorsUsedInCommonValues = [2] := by decide

/-! ## 3. `src/common/u63.rs` -/

inductive U63Error where
  | valueOverflow (value : Nat)
  | invalidHigh (high : Nat) (bits : Nat)
  | invalidU32SliceLength (got : Nat) (expected : Nat)
  | invalidU64SliceLength (got : Nat) (expected : Nat)
  deriving DecidableEq, Repr

/-- `pub struct U63(u64)`. The carrier is the raw `u64`; `Canonical` is what
`new` establishes and what `Default`/`Deserialize` do not. -/
structure U63 where
  raw : Nat
  deriving DecidableEq, Repr

def U63.Canonical (x : U63) : Prop := x.raw ≤ u63MaxValue
def U63.NativeRep (x : U63) : Prop := x.raw < twoPow64

/-- `U63::new` (u63.rs:38-43). -/
def u63New (value : Nat) : Except U63Error U63 :=
  if value > u63MaxValue then .error (.valueOverflow value) else .ok ⟨value⟩

/-- `U63::from_parts` (u63.rs:45-51). The source's `|` is modeled as `+`, which
agrees because `low` is a `u32` (premise `low < twoPow32` in every theorem). -/
def u63FromParts (high low : Nat) : Except U63Error U63 :=
  if high > u63HighMax then .error (.invalidHigh high u63HighBits)
  else u63New (high * twoPow32 + low)

/-- `U63::high` (u63.rs:62-64): `((self.0 >> 32) & U63_HIGH_MAX) as u32`. The
mask is `2 ^ 31 - 1`, i.e. it drops bit 63 of a non-canonical carrier. -/
def u63High (x : U63) : Nat := (x.raw / twoPow32) % twoPow31
/-- `U63::low` (u63.rs:66-68). -/
def u63Low (x : U63) : Nat := x.raw % twoPow32
/-- `U63::to_u32_vec` (u63.rs:74-77): `[high, low]`. -/
def u63ToU32Vec (x : U63) : List Nat := [u63High x, u63Low x]
/-- `U63::to_u64_vec` (u63.rs:79-81): a single word. -/
def u63ToU64Vec (x : U63) : List Nat := [x.raw]

/-- `U63::from_u32_slice` (u63.rs:83-88). -/
def u63FromU32Slice (slice : List Nat) : Except U63Error U63 :=
  match slice with
  | [high, low] => u63FromParts high low
  | s => .error (.invalidU32SliceLength s.length 2)

/-- `U63::from_u64_slice` (u63.rs:90-95). -/
def u63FromU64Slice (slice : List Nat) : Except U63Error U63 :=
  match slice with
  | [v] => u63New v
  | s => .error (.invalidU64SliceLength s.length 1)

/-- `U63::add` (u63.rs:97-103): `checked_add` first (whose `None` case reports
`ValueOverflow(self.0)` — the receiver, not the sum), then `U63::new`. -/
def u63Add (x : U63) (y : Nat) : Except U63Error U63 :=
  if x.raw + y ≥ twoPow64 then .error (.valueOverflow x.raw)
  else u63New (x.raw + y)

theorem u63_new_ok_iff (v : Nat) : u63New v = .ok ⟨v⟩ ↔ v ≤ u63MaxValue := by
  constructor
  · intro h
    by_cases hv : v > u63MaxValue
    · simp [u63New, hv] at h
    · omega
  · intro h
    have : ¬ (v > u63MaxValue) := by omega
    simp [u63New, this]

theorem u63_new_rejects_two_pow_63 : u63New twoPow63 = .error (.valueOverflow twoPow63) := by
  decide

theorem u63_new_accepts_max : u63New u63MaxValue = .ok ⟨u63MaxValue⟩ := by decide

/-- The 63-bit bound really is `2 ^ 63 - 1` inclusive. -/
theorem u63_new_ok_values_are_below_two_pow_63 {v : Nat} {x : U63}
    (h : u63New v = .ok x) : x.raw < twoPow63 := by
  by_cases hv : v > u63MaxValue
  · simp [u63New, hv] at h
  · simp only [u63New, if_neg hv] at h
    have hx : x = ⟨v⟩ := by injection h with h; exact h.symm
    subst hx
    show v < twoPow63
    simp only [u63MaxValue] at hv
    simp only [twoPow63]
    omega

/-- **Unreachable check.** `from_parts` already bounds `high` by `2 ^ 31 - 1`,
and `low` is a `u32`, so the value handed to `new` is always `≤ 2 ^ 63 - 1`:
the `ValueOverflow` branch of the inner `U63::new` call can never fire. -/
theorem u63_from_parts_inner_new_check_is_unreachable (high low : Nat)
    (hh : high ≤ u63HighMax) (hl : low < twoPow32) :
    u63FromParts high low = .ok ⟨high * twoPow32 + low⟩ := by
  have hnot : ¬ (high > u63HighMax) := by omega
  have hbound : high * twoPow32 + low ≤ u63MaxValue := by
    have : high * twoPow32 ≤ u63HighMax * twoPow32 :=
      Nat.mul_le_mul_right _ hh
    simp only [u63HighMax, twoPow32, u63MaxValue] at *
    omega
  simp only [u63FromParts, if_neg hnot]
  exact (u63_new_ok_iff _).2 hbound

/-- The only reachable error of `from_parts` on native (`u32`) inputs is
`InvalidHigh`. -/
theorem u63_from_parts_error_is_always_invalid_high {high low : Nat} {e : U63Error}
    (hl : low < twoPow32) (h : u63FromParts high low = .error e) :
    e = .invalidHigh high u63HighBits := by
  by_cases hh : high > u63HighMax
  · simp only [u63FromParts, if_pos hh] at h
    injection h with h; exact h.symm
  · have hh' : high ≤ u63HighMax := by omega
    rw [u63_from_parts_inner_new_check_is_unreachable high low hh' hl] at h
    exact absurd h (by simp)

theorem u63_from_parts_rejects_high_2_pow_31 (low : Nat) :
    u63FromParts twoPow31 low = .error (.invalidHigh twoPow31 u63HighBits) := by
  simp [u63FromParts, twoPow31, u63HighMax]

/-- `add` never wraps: any accepted result is the exact integer sum. -/
theorem u63_add_no_wraparound {x : U63} {y : Nat} {z : U63}
    (h : u63Add x y = .ok z) : z.raw = x.raw + y := by
  by_cases hc : x.raw + y ≥ twoPow64
  · simp [u63Add, hc] at h
  · simp only [u63Add, if_neg hc] at h
    by_cases hv : x.raw + y > u63MaxValue
    · simp [u63New, hv] at h
    · simp only [u63New, if_neg hv] at h
      have : z = ⟨x.raw + y⟩ := by injection h with h; exact h.symm
      subst this; rfl

theorem u63_add_ok_iff {x : U63} {y : Nat} :
    u63Add x y = .ok ⟨x.raw + y⟩ ↔ x.raw + y ≤ u63MaxValue := by
  constructor
  · intro h
    by_cases hc : x.raw + y ≥ twoPow64
    · simp [u63Add, hc] at h
    · simp only [u63Add, if_neg hc] at h
      exact (u63_new_ok_iff _).1 h
  · intro h
    have hc : ¬ (x.raw + y ≥ twoPow64) := by
      simp only [u63MaxValue] at h
      simp only [twoPow64]
      omega
    simp only [u63Add, if_neg hc]
    exact (u63_new_ok_iff _).2 h

/-- Any accepted sum is still in range: `add` cannot leave the 63-bit domain. -/
theorem u63_add_result_canonical {x : U63} {y : Nat} {z : U63}
    (h : u63Add x y = .ok z) : z.Canonical := by
  by_cases hc : x.raw + y ≥ twoPow64
  · simp [u63Add, hc] at h
  · simp only [u63Add, if_neg hc] at h
    by_cases hv : x.raw + y > u63MaxValue
    · simp [u63New, hv] at h
    · simp only [u63New, if_neg hv] at h
      have : z = ⟨x.raw + y⟩ := by injection h with h; exact h.symm
      subst this
      simp only [U63.Canonical]
      omega

/-- The 63-bit boundary: `max + 1` is rejected by the range check, not by
`checked_add`. -/
theorem u63_add_at_boundary_reports_the_sum :
    u63Add ⟨u63MaxValue⟩ 1 = .error (.valueOverflow twoPow63) := by decide

/-- **Wrong payload on the `checked_add` path.** When the `u64` addition itself
overflows, the reported value is the receiver `self.0`, not the operand or the
sum, so the two overflow paths report incomparable numbers. -/
theorem u63_add_u64_overflow_reports_receiver_not_sum :
    u63Add ⟨1⟩ (twoPow64 - 1) = .error (.valueOverflow 1) := by decide

theorem u63_add_two_error_paths_are_distinguishable :
    u63Add ⟨u63MaxValue⟩ 1 ≠ u63Add ⟨1⟩ (twoPow64 - 1) := by decide

/-- `to_u32_vec` has exactly two limbs, `to_u64_vec` exactly one. -/
theorem u63_to_u32_vec_length (x : U63) : (u63ToU32Vec x).length = 2 := by
  simp [u63ToU32Vec]

theorem u63_to_u64_vec_length (x : U63) : (u63ToU64Vec x).length = 1 := by
  simp [u63ToU64Vec]

/-- On canonical values the `u32` limb encoding round-trips exactly. -/
theorem u63_u32_roundtrip_on_canonical (x : U63) (hx : x.Canonical) :
    u63FromU32Slice (u63ToU32Vec x) = .ok x := by
  cases x with
  | mk raw =>
    simp only [U63.Canonical] at hx
    have hh : raw / twoPow32 % twoPow31 ≤ u63HighMax := by
      simp only [twoPow31, u63HighMax]
      omega
    have hl : raw % twoPow32 < twoPow32 := by
      simp only [twoPow32]
      omega
    simp only [u63ToU32Vec, u63FromU32Slice, u63High, u63Low]
    rw [u63_from_parts_inner_new_check_is_unreachable _ _ hh hl]
    have : raw / twoPow32 % twoPow31 * twoPow32 + raw % twoPow32 = raw := by
      simp only [twoPow31, twoPow32, u63MaxValue] at *
      omega
    rw [this]

/-- **Many-to-one.** The high mask drops bit 63, so on the raw `u64` carrier the
`u32` limb encoding is not injective. This is only reachable for a
non-canonical `U63` — which `Deserialize`/transmuted state can produce, since
serde is derived directly on the private `u64` field and never calls `new`. -/
theorem u63_to_u32_vec_is_many_to_one_on_raw_carrier :
    u63ToU32Vec ⟨twoPow63⟩ = u63ToU32Vec ⟨0⟩ ∧ (⟨twoPow63⟩ : U63) ≠ ⟨0⟩ := by
  constructor
  · decide
  · intro h
    injection h with h
    simp [twoPow63] at h

/-- The `u64` encoding, by contrast, is injective on the whole carrier. -/
theorem u63_to_u64_vec_injective {a b : U63} (h : u63ToU64Vec a = u63ToU64Vec b) : a = b := by
  cases a; cases b
  simp only [u63ToU64Vec, List.cons.injEq, and_true] at h
  simp [h]

theorem u63_from_u32_slice_length_check (s : List Nat) (h : s.length ≠ 2) :
    u63FromU32Slice s = .error (.invalidU32SliceLength s.length 2) := by
  match s with
  | [] => rfl
  | [_] => rfl
  | [_, _] => simp at h
  | _ :: _ :: _ :: _ => rfl

theorem u63_from_u64_slice_length_check (s : List Nat) (h : s.length ≠ 1) :
    u63FromU64Slice s = .error (.invalidU64SliceLength s.length 1) := by
  match s with
  | [] => rfl
  | [_] => simp at h
  | _ :: _ :: _ => rfl

/-- Non-canonical words are rejected by the `u64` parser (unlike the `u32`
parser, whose masking silently accepts them). -/
theorem u63_from_u64_slice_rejects_non_canonical :
    u63FromU64Slice [twoPow63] = .error (.valueOverflow twoPow63) := by decide

/-! ## 4. `src/common/channel_id.rs` -/

inductive ChannelIdError where
  | invalidChannelId (detail : String)
  | invalidValue (detail : String)
  deriving DecidableEq, Repr

/-- `validate_components` message (channel_id.rs:112-116). -/
def errZeroReserved : ChannelIdError :=
  .invalidChannelId "channel_id=0 is reserved for dummy"
/-- `u32::try_from` failure message (channel_id.rs:47-49). -/
def errNotFourBytes (v : Nat) : ChannelIdError :=
  .invalidValue s!"channel id {v} does not fit in 4 bytes"
/-- `from_u64_slice` length failure (channel_id.rs:103-106). Note it reuses the
same `InvalidValue` variant as the range failure, so only the message
distinguishes them. -/
def errSliceLength (n : Nat) : ChannelIdError :=
  .invalidValue s!"channel id expects a single u32 limb, got {n}"

/-- `pub struct ChannelId(u32)` — the raw carrier, again reachable by serde
without `new`. -/
structure ChannelId where
  raw : Nat
  deriving DecidableEq, Repr

/-- `validate_components` (channel_id.rs:111-118): rejects the reserved id 0. -/
def channelIdValidate (c : Nat) : Except ChannelIdError Unit :=
  if c = 0 then .error errZeroReserved else .ok ()

/-- `ChannelId::new` (channel_id.rs:46-52): `u32::try_from` (the 32-bit bound)
and then `validate_components` (the reserved-0 rejection), in that order. -/
def channelIdNew (value : Nat) : Except ChannelIdError ChannelId :=
  if value ≥ twoPow32 then .error (errNotFourBytes value)
  else match channelIdValidate value with
    | .ok _ => .ok ⟨value⟩
    | .error e => .error e

/-- `ChannelId::dummy` (channel_id.rs:54-56). -/
def channelIdDummy : ChannelId := ⟨0⟩
/-- `from_u64` / `from_u63` / `TryFrom<u64>` all forward to `new`. -/
def channelIdFromU64 (v : Nat) : Except ChannelIdError ChannelId := channelIdNew v
/-- `to_u32_vec` / `to_u64_vec` (channel_id.rs:84-90): a single word. -/
def channelIdWords (c : ChannelId) : List Nat := [c.raw]
/-- `ChannelIdTarget::to_vec` / `to_u64_vec` (channel_id.rs:201-214). -/
def channelIdTargetWords (c : ChannelId) : List Nat := [c.raw]

/-- `from_u64_slice` (channel_id.rs:101-109). -/
def channelIdFromU64Slice (values : List Nat) : Except ChannelIdError ChannelId :=
  match values with
  | [v] => channelIdFromU64 v
  | s => .error (errSliceLength s.length)

/-- `as_bytes` (channel_id.rs:72-74): big-endian `u32`. -/
def channelIdBytes (c : ChannelId) : List Nat :=
  [c.raw / 16777216 % 256, c.raw / 65536 % 256, c.raw / 256 % 256, c.raw % 256]

/-- `from_bytes` (channel_id.rs:78-82): `u32::from_be_bytes` then the SAME
`validate_components`, so 0 is rejected here too. -/
def channelIdFromBytes (b : List Nat) : Except ChannelIdError ChannelId :=
  match b with
  | [b0, b1, b2, b3] =>
      let v := b0 * 16777216 + b1 * 65536 + b2 * 256 + b3
      match channelIdValidate v with
      | .ok _ => .ok ⟨v⟩
      | .error e => .error e
  | s => .error (errSliceLength s.length)

theorem channel_id_new_ok_iff (v : Nat) :
    channelIdNew v = .ok ⟨v⟩ ↔ (0 < v ∧ v < twoPow32) := by
  by_cases hr : v ≥ twoPow32
  · simp only [channelIdNew, if_pos hr]
    constructor
    · intro h; exact absurd h (by simp)
    · intro hc; omega
  · by_cases hz : v = 0
    · subst hz
      simp only [channelIdNew, if_neg hr, channelIdValidate, if_pos rfl]
      constructor
      · intro h; exact absurd h (by simp)
      · intro hc; exact absurd hc.1 (by simp)
    · simp only [channelIdNew, if_neg hr, channelIdValidate, if_neg hz]
      constructor
      · intro _; exact ⟨Nat.pos_of_ne_zero hz, by omega⟩
      · intro _; trivial

/-- The reserved id is rejected by the constructor... -/
theorem channel_id_new_rejects_zero : channelIdNew 0 = .error errZeroReserved := by
  have hr : ¬ (0 ≥ twoPow32) := by simp [twoPow32]
  simp only [channelIdNew, if_neg hr, channelIdValidate, if_pos rfl]

/-- ...and the 32-bit bound is enforced before it, with its own error. -/
theorem channel_id_new_rejects_two_pow_32 :
    channelIdNew twoPow32 = .error (errNotFourBytes twoPow32) := by
  simp only [channelIdNew, if_pos (Nat.le_refl twoPow32)]

theorem channel_id_new_range_error_precedes_zero_error (v : Nat) (h : v ≥ twoPow32) :
    channelIdNew v = .error (errNotFourBytes v) := by
  simp only [channelIdNew, if_pos h]

theorem channel_id_new_max_accepted : channelIdNew (twoPow32 - 1) = .ok ⟨twoPow32 - 1⟩ := by
  apply (channel_id_new_ok_iff _).2
  simp only [twoPow32]
  omega

/-- **The dummy is not in the image of the validating constructor.** Every
`ChannelAction::default()` (tx.rs:304-315) carries `ChannelId::dummy()`, so any
consumer that re-parses a default action through `new`/`from_u64` fails. -/
theorem channel_id_dummy_is_unreachable_from_new (v : Nat) :
    channelIdNew v ≠ .ok channelIdDummy := by
  intro h
  by_cases hr : v ≥ twoPow32
  · rw [channel_id_new_range_error_precedes_zero_error v hr] at h
    exact absurd h (by simp)
  · by_cases hz : v = 0
    · subst hz
      rw [channel_id_new_rejects_zero] at h
      exact absurd h (by simp)
    · simp only [channelIdNew, if_neg hr, channelIdValidate, if_neg hz, channelIdDummy] at h
      injection h with h
      injection h with h
      exact hz h

theorem channel_id_words_length (c : ChannelId) : (channelIdWords c).length = 1 := by
  simp [channelIdWords]

theorem channel_id_native_target_layout_agrees (c : ChannelId) :
    channelIdWords c = channelIdTargetWords c := rfl

theorem channel_id_words_injective {a b : ChannelId} (h : channelIdWords a = channelIdWords b) :
    a = b := by
  cases a; cases b
  simp only [channelIdWords, List.cons.injEq, and_true] at h
  simp [h]

theorem channel_id_from_u64_slice_length_check (s : List Nat) (h : s.length ≠ 1) :
    channelIdFromU64Slice s = .error (errSliceLength s.length) := by
  match s with
  | [] => rfl
  | [_] => simp at h
  | _ :: _ :: _ => rfl

/-- The single-word encoding round-trips exactly on ids the constructor accepts. -/
theorem channel_id_words_roundtrip {c : ChannelId} (hz : 0 < c.raw) (hr : c.raw < twoPow32) :
    channelIdFromU64Slice (channelIdWords c) = .ok c := by
  cases c with
  | mk raw =>
    simp only [channelIdWords, channelIdFromU64Slice, channelIdFromU64]
    exact (channel_id_new_ok_iff raw).2 ⟨hz, hr⟩

/-- `from_bytes ∘ as_bytes` is the identity on accepted ids: the byte layout the
keccak signing digests depend on is faithful. -/
theorem channel_id_bytes_roundtrip {c : ChannelId} (hz : 0 < c.raw) (hr : c.raw < twoPow32) :
    channelIdFromBytes (channelIdBytes c) = .ok c := by
  cases c with
  | mk raw =>
    simp only [] at hz hr
    simp only [twoPow32] at hr
    have hv : raw / 16777216 % 256 * 16777216 + raw / 65536 % 256 * 65536 +
        raw / 256 % 256 * 256 + raw % 256 = raw := by omega
    have hz0 : ¬ (raw = 0) := by omega
    simp only [channelIdBytes, channelIdFromBytes, hv, channelIdValidate, if_neg hz0]

theorem channel_id_from_bytes_rejects_zero :
    channelIdFromBytes [0, 0, 0, 0] = .error errZeroReserved := by
  simp only [channelIdFromBytes, channelIdValidate, if_pos rfl]

/-! ## 5. Field arithmetic behind the target-side comparisons

`ChannelIdTarget`/`U63Target` implement `enforce_ge` as
`range_check(self - lower, BITS)` over Goldilocks. The subtraction is a FIELD
subtraction, so soundness depends on `2 ^ BITS` being small enough relative to
the modulus that a negative difference cannot land back in range. -/

/-- `builder.range_check(x, bits)` as a predicate on the canonical
representative. The gate lowering itself is a boundary. -/
def rangeCheck (x bits : Nat) : Prop := x < 2 ^ bits

/-- Goldilocks subtraction on canonical representatives. -/
def fieldSub (a b : Nat) : Nat := (a + goldilocksOrder - b) % goldilocksOrder
/-- `builder.add_const(x, 1)`. -/
def fieldAddOne (a : Nat) : Nat := (a + 1) % goldilocksOrder

/-- What `enforce_ge` actually constrains. -/
def enforceGeAccepts (bits a b : Nat) : Prop := rangeCheck (fieldSub a b) bits
/-- What `enforce_gt` actually constrains (`enforce_ge` against `lower + 1`). -/
def enforceGtAccepts (bits a b : Nat) : Prop := enforceGeAccepts bits a (fieldAddOne b)
/-- `conditional_ge` with the selector false: the constrained value is `0`. -/
def conditionalGeAccepts (bits a b : Nat) (cond : Bool) : Prop :=
  if cond then rangeCheck (fieldSub a b) bits else rangeCheck 0 bits

theorem field_sub_of_ge {a b : Nat} (hb : b ≤ a) (ha : a < goldilocksOrder) :
    fieldSub a b = a - b := by
  have h1 : a + goldilocksOrder - b = goldilocksOrder + (a - b) := by omega
  have h2 : a - b < goldilocksOrder := by omega
  simp only [fieldSub, h1, Nat.add_mod_left]
  exact Nat.mod_eq_of_lt h2

theorem field_sub_of_lt {a b : Nat} (hab : a < b) (hb : b < goldilocksOrder) :
    fieldSub a b = goldilocksOrder - (b - a) := by
  have h1 : a + goldilocksOrder - b = goldilocksOrder - (b - a) := by omega
  have h2 : goldilocksOrder - (b - a) < goldilocksOrder := by
    simp only [goldilocksOrder]; omega
  simp only [fieldSub, h1]
  exact Nat.mod_eq_of_lt h2

/-- `ChannelIdTarget::enforce_ge` IS sound for range-checked ids: with both sides
below `2 ^ 32`, a 32-bit range check on the difference holds exactly when
`lower ≤ self`. -/
theorem channel_id_enforce_ge_sound_when_range_checked {a b : Nat}
    (ha : a < twoPow32) (hb : b < twoPow32) :
    enforceGeAccepts channelIdBits a b ↔ b ≤ a := by
  simp only [twoPow32] at ha hb
  rcases Nat.lt_or_ge a b with hab | hba
  · have hbg : b < goldilocksOrder := by simp only [goldilocksOrder]; omega
    simp only [enforceGeAccepts, rangeCheck, channelIdBits, field_sub_of_lt hab hbg,
      two_pow_32_eq, goldilocksOrder]
    constructor
    · intro h; omega
    · intro h; omega
  · have hag : a < goldilocksOrder := by simp only [goldilocksOrder]; omega
    simp only [enforceGeAccepts, rangeCheck, channelIdBits, field_sub_of_ge hba hag,
      two_pow_32_eq]
    constructor
    · intro _; exact hba
    · intro _; omega

/-- **`U63Target::enforce_ge` is NOT sound on the full 63-bit domain.** The
modulus is `2 ^ 64 - 2 ^ 32 + 1`, so a negative difference wraps to
`p - (lower - self)`, which is below `2 ^ 63` — and therefore passes the 63-bit
range check — exactly when `lower - self > 2 ^ 63 - 2 ^ 32 + 1`. Every witness
in that window is accepted although `self < lower`. -/
theorem u63_enforce_ge_unsound_window {a b : Nat}
    (ha : a < twoPow63) (hb : b < twoPow63) (hab : a < b) :
    enforceGeAccepts u63Bits a b ↔ goldilocksOrder - twoPow63 < b - a := by
  simp only [twoPow63] at ha hb
  have hbg : b < goldilocksOrder := by simp only [goldilocksOrder]; omega
  simp only [enforceGeAccepts, rangeCheck, u63Bits, field_sub_of_lt hab hbg,
    two_pow_63_eq, goldilocksOrder, twoPow63]
  constructor
  · intro h; omega
  · intro h; omega

/-- A concrete accepted witness for `0 ≥ 2 ^ 63 - 1`. -/
theorem u63_enforce_ge_accepts_a_strictly_smaller_value :
    enforceGeAccepts u63Bits 0 u63MaxValue ∧ ¬ (u63MaxValue ≤ 0) := by
  constructor
  · simp only [enforceGeAccepts, rangeCheck, u63Bits, fieldSub, goldilocksOrder, u63MaxValue]
    decide
  · simp [u63MaxValue]

/-- The unsound window is not narrow: it contains `2 ^ 32 - 1` differences. -/
theorem u63_enforce_ge_unsound_window_size :
    twoPow63 - (goldilocksOrder - twoPow63) - 1 = twoPow32 - 2 := by decide

/-- `enforce_gt` inherits the hole and adds one of its own: `add_const(lower, 1)`
wraps, so an (unchecked) `lower = p - 1` is compared against `0`. -/
theorem u63_enforce_gt_wraps_when_lower_is_field_max (a : Nat) (ha : a < twoPow63) :
    enforceGtAccepts u63Bits a (goldilocksOrder - 1) := by
  simp only [twoPow63] at ha
  have h1 : fieldAddOne (goldilocksOrder - 1) = 0 := by decide
  have h2 : fieldSub a 0 = a % goldilocksOrder := by
    simp only [fieldSub, Nat.sub_zero]
    exact Nat.add_mod_right a goldilocksOrder
  have h3 : a % goldilocksOrder = a := by
    apply Nat.mod_eq_of_lt
    simp only [goldilocksOrder]
    omega
  simp only [enforceGtAccepts, enforceGeAccepts, rangeCheck, u63Bits, h1, h2, h3,
    two_pow_63_eq]
  omega

/-- `conditional_ge`/`conditional_gt` impose nothing at all when the selector is
false — the constrained value is a literal zero. -/
theorem conditional_ge_is_vacuous_when_false (bits a b : Nat) :
    conditionalGeAccepts bits a b false := by
  simp only [conditionalGeAccepts, Bool.false_eq_true, if_false, rangeCheck]
  exact two_pow_pos bits

/-! ## 6. `src/common/tx.rs` -/

structure Tx where
  transferTreeRoot : Hash4
  nonce : Nat
  deriving DecidableEq, Repr

/-- `Tx::to_u64_vec` (tx.rs:43-52), including its `assert_eq!(len, TX_LEN)`. -/
def txWords (t : Tx) : List Nat := hashWords t.transferTreeRoot ++ [t.nonce]
/-- `TxTarget::to_vec` (tx.rs:94-103), transcribed separately. -/
def txTargetWords (t : Tx) : List Nat := hashWords t.transferTreeRoot ++ [t.nonce]

def txDefault : Tx := ⟨zeroHash, 0⟩

/-- `Tx::from_u64_slice` (tx.rs:54-68). The `PoseidonHashOut::from_u64_slice`
call is `.unwrap()`ed; the length check above it makes that unwrap unreachable.
`input[4] as u32` TRUNCATES. -/
def txFromU64Slice (input : List Nat) : Except CommonError Tx :=
  if input.length ≠ txLen then
    .error (.invalidData s!"Invalid input length for Tx: expected 5, got {input.length}")
  else
    match input with
    | [a, b, c, d, n] => .ok ⟨⟨a, b, c, d⟩, n % twoPow32⟩
    | s => .error (.invalidData s!"Invalid input length for Tx: expected 5, got {s.length}")

theorem tx_words_length (t : Tx) : (txWords t).length = txLen := by
  simp [txWords, hashWords, txLen, poseidonHashOutLen]

theorem tx_native_target_layout_agrees (t : Tx) : txWords t = txTargetWords t := rfl

theorem tx_nonce_at_offset_4 (t : Tx) : (txWords t)[4]? = some t.nonce := rfl

theorem tx_words_injective {a b : Tx} (h : txWords a = txWords b) : a = b := by
  cases a with
  | mk ra na =>
    cases b with
    | mk rb nb =>
      cases ra; cases rb
      simp only [txWords, hashWords, List.cons_append, List.nil_append, List.cons.injEq] at h
      obtain ⟨rfl, rfl, rfl, rfl, rfl, _⟩ := h
      rfl

theorem tx_from_u64_slice_length_check (s : List Nat) (h : s.length ≠ txLen) :
    txFromU64Slice s =
      .error (.invalidData s!"Invalid input length for Tx: expected 5, got {s.length}") := by
  simp only [txFromU64Slice, if_pos h]

theorem tx_roundtrip_on_canonical_nonce {t : Tx} (h : t.nonce < twoPow32) :
    txFromU64Slice (txWords t) = .ok t := by
  cases t with
  | mk r n =>
    cases r with
    | mk w0 w1 w2 w3 =>
      simp only [] at h
      have hlen : ¬ ((txWords ⟨⟨w0, w1, w2, w3⟩, n⟩).length ≠ txLen) := by
        simp [txWords, hashWords, txLen, poseidonHashOutLen]
      simp only [txFromU64Slice, if_neg hlen, txWords, hashWords, List.cons_append,
        List.nil_append]
      rw [Nat.mod_eq_of_lt h]

/-- **Many-to-one.** `input[4] as u32` truncates, so distinct word vectors decode
to the same `Tx`; the decoder accepts a nonce word no encoder can produce. -/
theorem tx_from_u64_slice_truncates_the_nonce :
    txFromU64Slice [0, 0, 0, 0, twoPow32] = txFromU64Slice [0, 0, 0, 0, 0] ∧
      ([0, 0, 0, 0, twoPow32] : List Nat) ≠ [0, 0, 0, 0, 0] := by
  constructor
  · decide
  · simp [twoPow32]

/-- The `PoseidonHashOut::from_u64_slice(...).unwrap()` inside `from_u64_slice`
can never panic: the branch is guarded by the exact length check. -/
theorem tx_hash_unwrap_is_unreachable (s : List Nat) (h : s.length = txLen) :
    ∃ t, txFromU64Slice s = .ok t := by
  have hlen : ¬ (s.length ≠ txLen) := by simp [h]
  match s with
  | [a, b, c, d, n] =>
      exact ⟨⟨⟨a, b, c, d⟩, n % twoPow32⟩, by simp only [txFromU64Slice, if_neg hlen]⟩
  | [] => simp [txLen, poseidonHashOutLen] at h
  | [_] => simp [txLen, poseidonHashOutLen] at h
  | [_, _] => simp [txLen, poseidonHashOutLen] at h
  | [_, _, _] => simp [txLen, poseidonHashOutLen] at h
  | [_, _, _, _] => simp [txLen, poseidonHashOutLen] at h
  | _ :: _ :: _ :: _ :: _ :: _ :: _ => simp [txLen, poseidonHashOutLen] at h

/-- Decoded hash words are unconstrained: `from_u64_slice` never checks that a
`PoseidonHashOut` word is a canonical Goldilocks element, so a decoded `Tx` can
carry words `≥ p` that the hash gadget silently reduces. -/
theorem tx_from_u64_slice_accepts_non_canonical_hash_words :
    txFromU64Slice [goldilocksOrder, 0, 0, 0, 0] =
      .ok ⟨⟨goldilocksOrder, 0, 0, 0⟩, 0⟩ := by decide

/-! ### `TxClass` and `ChannelActionKind` -/

inductive TxClass where
  | userTransfer
  | channelAction
  deriving DecidableEq, Repr

def txClassAsU32 : TxClass → Nat
  | .userTransfer => 0
  | .channelAction => 1

/-- `TxClass::from_u32` (tx.rs:188-196). -/
def txClassFromU32 (v : Nat) : Except CommonError TxClass :=
  match v with
  | 0 => .ok .userTransfer
  | 1 => .ok .channelAction
  | n => .error (.invalidData s!"invalid tx class: {n}")

inductive ChannelActionKind where
  | interChannelSend
  | channelClose
  | memberSetUpdate
  deriving DecidableEq, Repr

def channelActionKindAsU32 : ChannelActionKind → Nat
  | .interChannelSend => 0
  | .channelClose => 1
  | .memberSetUpdate => 2

/-- `ChannelActionKind::from_u32` (tx.rs:218-227). -/
def channelActionKindFromU32 (v : Nat) : Except CommonError ChannelActionKind :=
  match v with
  | 0 => .ok .interChannelSend
  | 1 => .ok .channelClose
  | 2 => .ok .memberSetUpdate
  | n => .error (.invalidData s!"invalid channel action kind: {n}")

theorem tx_class_tags_pinned :
    txClassAsU32 .userTransfer = 0 ∧ txClassAsU32 .channelAction = 1 := by decide

theorem channel_action_kind_tags_pinned :
    channelActionKindAsU32 .interChannelSend = 0 ∧
      channelActionKindAsU32 .channelClose = 1 ∧
      channelActionKindAsU32 .memberSetUpdate = 2 := by decide

theorem tx_class_from_u32_roundtrip (c : TxClass) : txClassFromU32 (txClassAsU32 c) = .ok c := by
  cases c <;> rfl

theorem channel_action_kind_from_u32_roundtrip (k : ChannelActionKind) :
    channelActionKindFromU32 (channelActionKindAsU32 k) = .ok k := by
  cases k <;> rfl

theorem tx_class_from_u32_rejects_two : ∃ m, txClassFromU32 2 = .error (.invalidData m) :=
  ⟨_, rfl⟩

theorem channel_action_kind_from_u32_rejects_three :
    ∃ m, channelActionKindFromU32 3 = .error (.invalidData m) := ⟨_, rfl⟩

/-! ### `ChannelAction` -/

/-- The source field `seal` is spelled `sealHash` here only because `seal` is a
Lean command keyword. -/
structure ChannelAction where
  kind : ChannelActionKind
  sourceChannelId : ChannelId
  destinationChannelId : ChannelId
  txHash : Limbs8
  sealHash : Limbs8
  payloadHash : Hash4
  deriving DecidableEq, Repr

/-- `ChannelAction::to_u64_vec` (tx.rs:258-268). NOTE: unlike `Tx`, this encoder
carries NO `assert_eq!` on the length. -/
def channelActionWords (a : ChannelAction) : List Nat :=
  [channelActionKindAsU32 a.kind] ++ channelIdWords a.sourceChannelId ++
    channelIdWords a.destinationChannelId ++ limbWords a.txHash ++ limbWords a.sealHash ++
    hashWords a.payloadHash

/-- `ChannelActionTarget::to_vec` (tx.rs:371-381), transcribed separately. -/
def channelActionTargetWords (a : ChannelAction) : List Nat :=
  [channelActionKindAsU32 a.kind] ++ channelIdTargetWords a.sourceChannelId ++
    channelIdTargetWords a.destinationChannelId ++ limbWords a.txHash ++ limbWords a.sealHash ++
    hashWords a.payloadHash

/-- `impl Default for ChannelAction` (tx.rs:304-315) = `Leafable::empty_leaf`. -/
def channelActionDefault : ChannelAction :=
  ⟨.interChannelSend, channelIdDummy, channelIdDummy, zeroLimbs8, zeroLimbs8, zeroHash⟩

/-- `Bytes32::from_u64_slice` (u32limb_trait.rs:29-40): rejects any word above
`u32::MAX` with an error (not a panic). -/
def limbs8FromU64Slice (s : List Nat) : Except CommonError Limbs8 :=
  match s with
  | [a, b, c, d, e, f, g, h] =>
      if a ≤ u32Max ∧ b ≤ u32Max ∧ c ≤ u32Max ∧ d ≤ u32Max ∧
          e ≤ u32Max ∧ f ≤ u32Max ∧ g ≤ u32Max ∧ h ≤ u32Max then
        .ok ⟨a, b, c, d, e, f, g, h⟩
      else .error (.invalidData "OutOfU32Range")
  | s => .error (.invalidData s!"invalid length: {s.length}")

/-- `ChannelAction::from_u64_slice` (tx.rs:270-301), in source check order:
length, kind (TRUNCATING `as u32`), source id, destination id, tx hash, seal,
payload hash (unchecked). -/
def channelActionFromU64Slice (input : List Nat) : Except CommonError ChannelAction :=
  if input.length ≠ channelActionLen then
    .error (.invalidData
      s!"Invalid input length for ChannelAction: expected 23, got {input.length}")
  else
  match input with
  | [k, src, dst, t0, t1, t2, t3, t4, t5, t6, t7,
     s0, s1, s2, s3, s4, s5, s6, s7, p0, p1, p2, p3] => do
      let kind ← channelActionKindFromU32 (k % twoPow32)
      let source ← match channelIdFromU64 src with
        | .ok c => pure c
        | .error _ => .error (.invalidData "invalid source channel id")
      let dest ← match channelIdFromU64 dst with
        | .ok c => pure c
        | .error _ => .error (.invalidData "invalid destination channel id")
      let txHash ← limbs8FromU64Slice [t0, t1, t2, t3, t4, t5, t6, t7]
      let sealHash ← limbs8FromU64Slice [s0, s1, s2, s3, s4, s5, s6, s7]
      pure ⟨kind, source, dest, txHash, sealHash, ⟨p0, p1, p2, p3⟩⟩
  | s => .error (.invalidData
      s!"Invalid input length for ChannelAction: expected 23, got {s.length}")

theorem channel_action_words_length (a : ChannelAction) :
    (channelActionWords a).length = channelActionLen := by
  simp [channelActionWords, channelIdWords, limbWords, hashWords, channelActionLen,
    poseidonHashOutLen]

theorem channel_action_native_target_layout_agrees (a : ChannelAction) :
    channelActionWords a = channelActionTargetWords a := rfl

theorem channel_action_words_injective {a b : ChannelAction}
    (h : channelActionWords a = channelActionWords b) : a = b := by
  cases a with
  | mk ka sa da ta la pa =>
    cases b with
    | mk kb sb db tb lb pb =>
      cases sa; cases da; cases ta; cases la; cases pa
      cases sb; cases db; cases tb; cases lb; cases pb
      simp only [channelActionWords, channelIdWords, limbWords, hashWords,
        List.cons_append, List.nil_append, List.append_assoc, List.cons.injEq] at h
      obtain ⟨hk, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
        rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, _⟩ := h
      cases ka <;> cases kb <;> simp_all [channelActionKindAsU32]

/-- A concrete accepted decode: the positive example for this file. -/
theorem channel_action_roundtrip_example :
    channelActionFromU64Slice
      (channelActionWords ⟨.channelClose, ⟨4⟩, ⟨9⟩, zeroLimbs8, zeroLimbs8, zeroHash⟩) =
      .ok ⟨.channelClose, ⟨4⟩, ⟨9⟩, zeroLimbs8, zeroLimbs8, zeroHash⟩ := by
  decide

/-- **The empty leaf does not round-trip.** `ChannelAction::default()` — the
`Leafable::empty_leaf` that pads every channel-action tree — encodes fine, but
decoding it fails, because `ChannelId::dummy()` is the reserved 0 that
`ChannelId::new` rejects. Encoder and decoder therefore disagree on the value
the tree itself is built from. -/
theorem channel_action_default_encoding_is_not_decodable :
    channelActionFromU64Slice (channelActionWords channelActionDefault) =
      .error (.invalidData "invalid source channel id") := by
  decide

/-- **Many-to-one.** The kind tag is read as `input[0] as u32`, so word values
that differ by a multiple of `2 ^ 32` decode to the same action; in particular a
word no encoder can produce is silently accepted as `InterChannelSend`. -/
theorem channel_action_kind_tag_truncation :
    channelActionFromU64Slice
        (twoPow32 :: 4 :: 9 :: List.replicate 20 0) =
      channelActionFromU64Slice (0 :: 4 :: 9 :: List.replicate 20 0) := by
  decide

/-- Out-of-`u32` words in the hash fields ARE rejected (error, not truncation). -/
theorem channel_action_rejects_out_of_u32_tx_hash :
    channelActionFromU64Slice
        (0 :: 4 :: 9 :: twoPow32 :: List.replicate 19 0) =
      .error (.invalidData "OutOfU32Range") := by
  decide

theorem channel_action_from_u64_slice_length_check (s : List Nat) (h : s.length ≠ channelActionLen) :
    channelActionFromU64Slice s = .error (.invalidData
      s!"Invalid input length for ChannelAction: expected 23, got {s.length}") := by
  simp only [channelActionFromU64Slice, if_pos h]

/-! ### `member_set_update_payload` (tx.rs:247-255) -/

/-- The Poseidon preimage of the member-set-update payload: the "IMMS" domain
word followed by the two roots. -/
def memberSetUpdatePreimage (prevRoot newRoot : Hash4) : List Nat :=
  memberSetUpdateDomain :: (hashWords prevRoot ++ hashWords newRoot)

theorem member_set_update_preimage_length (p n : Hash4) :
    (memberSetUpdatePreimage p n).length = 9 := by
  simp [memberSetUpdatePreimage, hashWords]

theorem member_set_update_preimage_starts_with_domain (p n : Hash4) :
    (memberSetUpdatePreimage p n)[0]? = some memberSetUpdateDomain := rfl

theorem member_set_update_preimage_injective {p n p' n' : Hash4}
    (h : memberSetUpdatePreimage p n = memberSetUpdatePreimage p' n') : p = p' ∧ n = n' := by
  cases p; cases n; cases p'; cases n'
  simp only [memberSetUpdatePreimage, hashWords, List.cons_append, List.nil_append,
    List.cons.injEq] at h
  obtain ⟨_, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, _⟩ := h
  exact ⟨rfl, rfl⟩

/-- Commitment binding is stated only for the two concrete compared preimages;
Poseidon collision resistance is a premise, never a theorem. -/
theorem member_set_update_payload_binds_this_pair (poseidonAbsorb : List Nat → Hash4)
    (p n p' n' : Hash4)
    (binding : poseidonAbsorb (memberSetUpdatePreimage p n) =
        poseidonAbsorb (memberSetUpdatePreimage p' n') →
      memberSetUpdatePreimage p n = memberSetUpdatePreimage p' n')
    (equal : poseidonAbsorb (memberSetUpdatePreimage p n) =
        poseidonAbsorb (memberSetUpdatePreimage p' n')) : p = p' ∧ n = n' :=
  member_set_update_preimage_injective (binding equal)

/-! ### `TxV2` -/

structure TxV2 where
  txClass : TxClass
  transferTreeRoot : Hash4
  nonce : Nat
  channelActionRoot : Hash4
  deriving DecidableEq, Repr

/-- `TxV2::to_u64_vec` (tx.rs:425-433). -/
def txV2Words (t : TxV2) : List Nat :=
  [txClassAsU32 t.txClass] ++ hashWords t.transferTreeRoot ++ [t.nonce] ++
    hashWords t.channelActionRoot
/-- `TxV2Target::to_vec` (tx.rs:508-516), transcribed separately. -/
def txV2TargetWords (t : TxV2) : List Nat :=
  [txClassAsU32 t.txClass] ++ hashWords t.transferTreeRoot ++ [t.nonce] ++
    hashWords t.channelActionRoot

/-- `TxV2::from_u64_slice` (tx.rs:435-458). Both `input[0] as u32` and
`input[5] as u32` truncate. -/
def txV2FromU64Slice (input : List Nat) : Except CommonError TxV2 :=
  if input.length ≠ txV2Len then
    .error (.invalidData s!"Invalid input length for TxV2: expected 10, got {input.length}")
  else
  match input with
  | [c, r0, r1, r2, r3, n, a0, a1, a2, a3] => do
      let cls ← txClassFromU32 (c % twoPow32)
      pure ⟨cls, ⟨r0, r1, r2, r3⟩, n % twoPow32, ⟨a0, a1, a2, a3⟩⟩
  | s => .error (.invalidData s!"Invalid input length for TxV2: expected 10, got {s.length}")

theorem tx_v2_from_u64_slice_length_check (s : List Nat) (h : s.length ≠ txV2Len) :
    txV2FromU64Slice s =
      .error (.invalidData s!"Invalid input length for TxV2: expected 10, got {s.length}") := by
  simp only [txV2FromU64Slice, if_pos h]

theorem tx_v2_words_length (t : TxV2) : (txV2Words t).length = txV2Len := by
  simp [txV2Words, hashWords, txV2Len, poseidonHashOutLen]

theorem tx_v2_native_target_layout_agrees (t : TxV2) : txV2Words t = txV2TargetWords t := rfl

theorem tx_v2_words_injective {a b : TxV2} (h : txV2Words a = txV2Words b) : a = b := by
  cases a with
  | mk ca ra na aa =>
    cases b with
    | mk cb rb nb ab =>
      cases ra; cases aa; cases rb; cases ab
      simp only [txV2Words, hashWords, List.cons_append, List.nil_append,
        List.append_assoc, List.cons.injEq] at h
      obtain ⟨hc, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, _⟩ := h
      cases ca <;> cases cb <;> simp_all [txClassAsU32]

theorem tx_v2_roundtrip_on_canonical_nonce {t : TxV2} (h : t.nonce < twoPow32) :
    txV2FromU64Slice (txV2Words t) = .ok t := by
  cases t with
  | mk c r n a =>
    cases r; cases a
    simp only [] at h
    cases c <;>
      simp only [txV2Words, hashWords, txClassAsU32, txV2FromU64Slice, txClassFromU32,
        List.cons_append, List.nil_append, Nat.mod_eq_of_lt h] <;> rfl

/-- **Validation bypass by truncation.** `TxClass::from_u32` is applied AFTER the
`as u32` cast, so `2 ^ 32` decodes to `UserTransfer` even though the tag word is
neither 0 nor 1. -/
theorem tx_v2_class_tag_truncation_bypasses_validation :
    txV2FromU64Slice (twoPow32 :: List.replicate 9 0) =
      .ok ⟨.userTransfer, zeroHash, 0, zeroHash⟩ := by decide

theorem tx_v2_from_u64_slice_rejects_class_two :
    ∃ m, txV2FromU64Slice (2 :: List.replicate 9 0) = .error (.invalidData m) := ⟨_, rfl⟩

/-! ### Poseidon padding: what the sponge cannot separate

`PoseidonHashOut::hash_inputs_u64` calls `hash_no_pad`, whose FIRST absorbed
chunk is written into an all-zero state. Any input of length `≤ SPONGE_RATE` is
therefore absorbed exactly as its zero-extension to `SPONGE_RATE` words. The
permutation itself stays opaque. -/

/-- The first absorbed chunk of a short input. -/
def firstChunkState (input : List Nat) : List Nat :=
  (input ++ List.replicate spongeRate 0).take spongeRate

/-- A `Tx` with `nonce = 0` — the `Leafable::empty_leaf` shape, and any tx whose
sender nonce happens to be 0 — is absorbed exactly like the bare four-word
transfer tree root. Anything that Poseidon-hashes a lone `PoseidonHashOut` in
the same domain collides with such a `Tx` leaf without breaking Poseidon. -/
theorem tx_with_zero_nonce_absorbs_like_its_bare_root (h : Hash4) :
    firstChunkState (txWords ⟨h, 0⟩) = firstChunkState (hashWords h) := by
  cases h
  rfl

/-- Consequence, stated with the sponge as an explicit premise rather than an
assumed hash property. -/
theorem tx_zero_nonce_hash_equals_root_hash (poseidonAbsorb : List Nat → Hash4)
    (firstChunkDetermines : ∀ x y : List Nat, x.length ≤ spongeRate → y.length ≤ spongeRate →
      firstChunkState x = firstChunkState y → poseidonAbsorb x = poseidonAbsorb y)
    (h : Hash4) : poseidonAbsorb (txWords ⟨h, 0⟩) = poseidonAbsorb (hashWords h) := by
  refine firstChunkDetermines _ _ ?_ ?_ (tx_with_zero_nonce_absorbs_like_its_bare_root h)
  · cases h; simp [txWords, hashWords, spongeRate]
  · cases h; simp [hashWords, spongeRate]

/-- The other preimages in this file are longer than the rate, so this
zero-extension argument does NOT extend to them: their chunk boundaries fall
inside a permuted (non-zero) state. Lengths are pairwise distinct, which is a
necessary but NOT sufficient condition for domain separation. -/
theorem poseidon_preimage_lengths_are_pairwise_distinct :
    [txLen, 9, txV2Len, channelActionLen, transferLen, 28, 32] =
      [5, 9, 10, 23, 25, 28, 32] := by decide

/-! ## 7. `src/common/transfer.rs` -/

structure Transfer where
  recipient : Limbs8
  tokenIndex : Nat
  amount : Limbs8
  auxData : Limbs8
  deriving DecidableEq, Repr

/-- `Transfer::to_u64_vec` (transfer.rs:73-84), with its `assert_eq!`. -/
def transferWords (t : Transfer) : List Nat :=
  limbWords t.recipient ++ [t.tokenIndex] ++ limbWords t.amount ++ limbWords t.auxData
/-- `TransferTarget::to_vec` (transfer.rs:130-141), transcribed separately. -/
def transferTargetWords (t : Transfer) : List Nat :=
  limbWords t.recipient ++ [t.tokenIndex] ++ limbWords t.amount ++ limbWords t.auxData

structure SettledTransfer where
  inner : Transfer
  from_ : ChannelId
  transferIndex : Nat
  nonce : Nat
  deriving DecidableEq, Repr

/-- `SettledTransfer::to_u64_vec` (transfer.rs:110-118) — the nullifier
preimage. Note there is no length assertion and no domain tag. -/
def settledTransferWords (s : SettledTransfer) : List Nat :=
  transferWords s.inner ++ channelIdWords s.from_ ++ [s.transferIndex] ++ [s.nonce]
/-- `SettledTransferTarget::to_vec` (transfer.rs:224-232), transcribed separately. -/
def settledTransferTargetWords (s : SettledTransfer) : List Nat :=
  transferTargetWords s.inner ++ channelIdTargetWords s.from_ ++ [s.transferIndex] ++ [s.nonce]

/-- `SettledTransfer::nullifier` (transfer.rs:124-126): Poseidon over the words,
then the `PoseidonHashOut -> Bytes32` split. -/
def settledTransferNullifier (poseidonAbsorb : List Nat → Hash4) (s : SettledTransfer) : Limbs8 :=
  hashToBytes32 (poseidonAbsorb (settledTransferWords s))

theorem transfer_words_length (t : Transfer) : (transferWords t).length = transferLen := by
  simp [transferWords, limbWords, transferLen, bytes32Len, u256Len]

theorem transfer_native_target_layout_agrees (t : Transfer) :
    transferWords t = transferTargetWords t := rfl

theorem settled_transfer_words_length (s : SettledTransfer) :
    (settledTransferWords s).length = transferLen + 3 := by
  simp [settledTransferWords, transferWords, limbWords, channelIdWords, transferLen,
    bytes32Len, u256Len]

theorem settled_transfer_native_target_layout_agrees (s : SettledTransfer) :
    settledTransferWords s = settledTransferTargetWords s := rfl

theorem transfer_words_injective {a b : Transfer} (h : transferWords a = transferWords b) :
    a = b := by
  cases a with
  | mk ra ta aa xa =>
    cases b with
    | mk rb tb ab xb =>
      cases ra; cases aa; cases xa; cases rb; cases ab; cases xb
      simp only [transferWords, limbWords, List.cons_append, List.nil_append,
        List.append_assoc, List.cons.injEq] at h
      obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
        rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, _⟩ := h
      rfl

/-- The nullifier preimage determines the settled transfer, so the nullifier
binds (recipient, token, amount, aux, sender channel, transfer index, nonce).
This is layout injectivity only — hash binding stays a premise. -/
theorem settled_transfer_words_injective {a b : SettledTransfer}
    (h : settledTransferWords a = settledTransferWords b) : a = b := by
  cases a with
  | mk ia fa xa na =>
    cases b with
    | mk ib fb xb nb =>
      cases ia with
      | mk ra ta aa da =>
        cases ib with
        | mk rb tb ab db =>
          cases ra; cases aa; cases da; cases fa
          cases rb; cases ab; cases db; cases fb
          simp only [settledTransferWords, transferWords, limbWords, channelIdWords,
            List.cons_append, List.nil_append, List.append_assoc, List.cons.injEq] at h
          obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
            rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, _⟩ := h
          rfl

/-- F-WD-2: the preimage's last word is the sender `nonce`, and no settlement
block number appears anywhere in it, so re-settling one deduction cannot produce
two nullifiers. -/
theorem settled_transfer_nullifier_preimage_ends_with_nonce (s : SettledTransfer) :
    (settledTransferWords s).drop 27 = [s.nonce] := by
  cases s with
  | mk i f x n =>
    cases i with
    | mk r t a d => cases r; cases a; cases d; cases f; rfl

theorem settled_transfer_nullifier_preimage_has_sender_at_25 (s : SettledTransfer) :
    (settledTransferWords s)[25]? = some s.from_.raw := by
  cases s with
  | mk i f x n =>
    cases i with
    | mk r t a d => cases r; cases a; cases d; cases f; rfl

/-- Nullifier equality forces equality of the settled transfers only under an
explicit binding premise about this one compared pair. -/
theorem settled_transfer_nullifier_binds_this_pair (poseidonAbsorb : List Nat → Hash4)
    (a b : SettledTransfer)
    (binding : poseidonAbsorb (settledTransferWords a) = poseidonAbsorb (settledTransferWords b) →
      settledTransferWords a = settledTransferWords b)
    (equal : settledTransferNullifier poseidonAbsorb a =
      settledTransferNullifier poseidonAbsorb b) : a = b := by
  apply settled_transfer_words_injective
  apply binding
  exact hash_to_bytes32_injective_on_u64_words equal

/-- The sender field of a settled transfer is a raw `ChannelId` carrier: nothing
in this encoder re-validates it, so the reserved dummy id 0 can appear inside a
nullifier preimage. -/
theorem settled_transfer_accepts_dummy_sender (t : Transfer) (i n : Nat) :
    (settledTransferWords ⟨t, channelIdDummy, i, n⟩)[25]? = some 0 := by
  cases t with
  | mk r ti a d => cases r; cases a; cases d; rfl

/-! ## 8. `src/common/deposit.rs` -/

structure Deposit where
  depositIndex : U63
  blockNumber : U63
  depositor : Limbs5
  recipient : Limbs8
  tokenIndex : Nat
  amount : Limbs8
  auxData : Limbs8
  deriving DecidableEq, Repr

/-- `Deposit::to_u64_vec` (deposit.rs:68-78) — the `poseidon_hash`/`nullifier`
preimage; it DOES include `deposit_index` and `block_number`. -/
def depositWords (d : Deposit) : List Nat :=
  [d.depositIndex.raw, d.blockNumber.raw] ++ addrWords d.depositor ++ limbWords d.recipient ++
    [d.tokenIndex] ++ limbWords d.amount ++ limbWords d.auxData
/-- `DepositTarget::to_u64_vec` (deposit.rs:116-126), transcribed separately. -/
def depositTargetWords (d : Deposit) : List Nat :=
  [d.depositIndex.raw, d.blockNumber.raw] ++ addrWords d.depositor ++ limbWords d.recipient ++
    [d.tokenIndex] ++ limbWords d.amount ++ limbWords d.auxData

/-- `Deposit::hash_with_prev_hash` (deposit.rs:101-112) — the on-chain
`depositHashChain` keccak fold. It OMITS `deposit_index` and `block_number`. -/
def depositChainPreimage (prevHash : Limbs8) (d : Deposit) : List Nat :=
  limbWords prevHash ++ addrWords d.depositor ++ limbWords d.recipient ++ [d.tokenIndex] ++
    limbWords d.amount ++ limbWords d.auxData

def depositDefault : Deposit :=
  ⟨⟨0⟩, ⟨0⟩, zeroLimbs5, zeroLimbs8, 0, zeroLimbs8, zeroLimbs8⟩

/-- `Deposit::nullifier` (deposit.rs:96-98). -/
def depositNullifier (poseidonAbsorb : List Nat → Hash4) (d : Deposit) : Limbs8 :=
  hashToBytes32 (poseidonAbsorb (depositWords d))

theorem deposit_words_length (d : Deposit) : (depositWords d).length = 32 := by
  simp [depositWords, addrWords, limbWords]

theorem deposit_native_target_layout_agrees (d : Deposit) :
    depositWords d = depositTargetWords d := rfl

theorem deposit_chain_preimage_length (p : Limbs8) (d : Deposit) :
    (depositChainPreimage p d).length = 38 := by
  simp [depositChainPreimage, addrWords, limbWords]

theorem deposit_words_injective {a b : Deposit} (h : depositWords a = depositWords b) : a = b := by
  cases a with
  | mk ia ba da ra ta ma xa =>
    cases b with
    | mk ib bb db rb tb mb xb =>
      cases ia; cases ba; cases da; cases ra; cases ma; cases xa
      cases ib; cases bb; cases db; cases rb; cases mb; cases xb
      simp only [depositWords, addrWords, limbWords, List.cons_append, List.nil_append,
        List.append_assoc, List.cons.injEq] at h
      obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
        rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
        rfl, _⟩ := h
      rfl

/-- **The on-chain fold is many-to-one in exactly the two fields the nullifier
depends on.** Two deposits differing only in `deposit_index`/`block_number` have
identical `hash_with_prev_hash` preimages, so the L1 hash chain cannot pin them
down; only the Poseidon nullifier can. -/
theorem deposit_chain_preimage_ignores_index_and_block (p : Limbs8) (d : Deposit) (i b : U63) :
    depositChainPreimage p { d with depositIndex := i, blockNumber := b } =
      depositChainPreimage p d := by
  cases d; rfl

/-- ...and the nullifier preimage does depend on the index, so leaving
`deposit_index` at its default collapses distinct deposits onto one nullifier
(the threat documented in the source comment at deposit.rs:36-39). -/
theorem deposit_nullifier_preimage_depends_on_index (d : Deposit) (i : U63)
    (hne : d.depositIndex ≠ i) :
    depositWords { d with depositIndex := i } ≠ depositWords d := by
  intro h
  apply hne
  have := deposit_words_injective h
  cases d
  injection this with h1
  exact h1.symm

theorem deposit_default_index_is_zero : depositDefault.depositIndex = ⟨0⟩ := rfl

/-- The nullifier preimage is exactly the on-chain fold preimage with the index
and block number prepended: the fold sees the last 30 words, the nullifier sees
all 32. -/
theorem deposit_words_split (p : Limbs8) (d : Deposit) :
    depositWords d =
      [d.depositIndex.raw, d.blockNumber.raw] ++ (depositChainPreimage p d).drop 8 := by
  cases p; cases d; rfl

/-- Consequence: two deposits the on-chain fold cannot distinguish and that both
left `deposit_index`/`block_number` at their defaults get the SAME nullifier —
the collision documented in the source comment at deposit.rs:36-39. -/
theorem deposit_default_index_collapses_nullifier_preimage
    (poseidonAbsorb : List Nat → Hash4) (a b : Deposit)
    (hi : a.depositIndex = b.depositIndex) (hb : a.blockNumber = b.blockNumber)
    (hfold : depositChainPreimage zeroLimbs8 a = depositChainPreimage zeroLimbs8 b) :
    depositNullifier poseidonAbsorb a = depositNullifier poseidonAbsorb b := by
  simp only [depositNullifier, deposit_words_split zeroLimbs8 a, deposit_words_split zeroLimbs8 b,
    hi, hb, hfold]

/-- The deposit index and block number are `U63`s whose canonical range is a
premise, not an invariant of the encoder: `to_u64_vec` copies the raw carrier. -/
theorem deposit_words_copy_raw_u63_carrier (d : Deposit) :
    (depositWords d)[0]? = some d.depositIndex.raw ∧
      (depositWords d)[1]? = some d.blockNumber.raw := by
  cases d with
  | mk i b dp r t m x => cases i; cases b; cases dp; cases r; cases m; cases x; exact ⟨rfl, rfl⟩

/-! ## 9. `src/common/withdrawal.rs` -/

structure Withdrawal where
  recipient : Limbs5
  tokenIndex : Nat
  amount : Limbs8
  nullifier : Limbs8
  auxData : Limbs8
  deriving DecidableEq, Repr

/-- `Withdrawal::to_u32_vec` (withdrawal.rs:43-54), with its `assert_eq!`. -/
def withdrawalWords (w : Withdrawal) : List Nat :=
  addrWords w.recipient ++ [w.tokenIndex] ++ limbWords w.amount ++ limbWords w.nullifier ++
    limbWords w.auxData
/-- `WithdrawalTarget::to_vec` (withdrawal.rs:114-125), transcribed separately. -/
def withdrawalTargetWords (w : Withdrawal) : List Nat :=
  addrWords w.recipient ++ [w.tokenIndex] ++ limbWords w.amount ++ limbWords w.nullifier ++
    limbWords w.auxData

/-- `Withdrawal::hash_with_prev_hash` (withdrawal.rs:97-100). -/
def withdrawalChainPreimage (prevHash : Limbs8) (w : Withdrawal) : List Nat :=
  limbWords prevHash ++ withdrawalWords w

/-- Result of a partial function that can also PANIC (`assert!`, `unwrap`). -/
inductive Outcome (α : Type) where
  | ok (value : α)
  | err (e : CommonError)
  | panics (reason : String)
  deriving DecidableEq, Repr

/-- `Withdrawal::from_u32_slice` (withdrawal.rs:56-84). The three
`from_u32_slice(..).unwrap()` calls are unreachable because the slices handed to
them have the exact expected lengths. -/
def withdrawalFromU32Slice (s : List Nat) : Except CommonError Withdrawal :=
  if s.length ≠ withdrawalLen then
    .error (.invalidData s!"Invalid input length for Withdrawal: expected 30, got {s.length}")
  else
  match s with
  | [r0, r1, r2, r3, r4, ti, a0, a1, a2, a3, a4, a5, a6, a7,
     n0, n1, n2, n3, n4, n5, n6, n7, x0, x1, x2, x3, x4, x5, x6, x7] =>
      .ok ⟨⟨r0, r1, r2, r3, r4⟩, ti, ⟨a0, a1, a2, a3, a4, a5, a6, a7⟩,
        ⟨n0, n1, n2, n3, n4, n5, n6, n7⟩, ⟨x0, x1, x2, x3, x4, x5, x6, x7⟩⟩
  | s => .error (.invalidData
      s!"Invalid input length for Withdrawal: expected 30, got {s.length}")

/-- `Withdrawal::from_u64_slice` (withdrawal.rs:86-95). The `assert!` inside the
`map` runs over the WHOLE slice BEFORE `from_u32_slice` sees it, so an
out-of-`u32` word aborts the process instead of returning `InvalidData` — and it
does so even when the length is wrong. -/
def withdrawalFromU64Slice (s : List Nat) : Outcome Withdrawal :=
  if s.any (fun x => decide (x > u32Max)) then
    .panics "assert!(x <= u32::MAX as u64)"
  else
    match withdrawalFromU32Slice s with
    | .ok w => .ok w
    | .error e => .err e

theorem withdrawal_words_length (w : Withdrawal) :
    (withdrawalWords w).length = withdrawalLen := by
  simp [withdrawalWords, addrWords, limbWords, withdrawalLen, addressLen, u256Len, bytes32Len]

theorem withdrawal_native_target_layout_agrees (w : Withdrawal) :
    withdrawalWords w = withdrawalTargetWords w := rfl

theorem withdrawal_chain_preimage_length (p : Limbs8) (w : Withdrawal) :
    (withdrawalChainPreimage p w).length = 38 := by
  simp [withdrawalChainPreimage, limbWords, withdrawalWords, addrWords]

theorem withdrawal_words_injective {a b : Withdrawal}
    (h : withdrawalWords a = withdrawalWords b) : a = b := by
  cases a with
  | mk ra ta aa na xa =>
    cases b with
    | mk rb tb ab nb xb =>
      cases ra; cases aa; cases na; cases xa; cases rb; cases ab; cases nb; cases xb
      simp only [withdrawalWords, addrWords, limbWords, List.cons_append, List.nil_append,
        List.append_assoc, List.cons.injEq] at h
      obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
        rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, _⟩ := h
      rfl

theorem withdrawal_u32_roundtrip (w : Withdrawal) :
    withdrawalFromU32Slice (withdrawalWords w) = .ok w := by
  cases w with
  | mk r t a n x =>
    cases r; cases a; cases n; cases x
    rfl

theorem withdrawal_from_u32_slice_length_check (s : List Nat) (h : s.length ≠ withdrawalLen) :
    withdrawalFromU32Slice s = .error (.invalidData
      s!"Invalid input length for Withdrawal: expected 30, got {s.length}") := by
  simp only [withdrawalFromU32Slice, if_pos h]

/-- **Panic, not error.** A single out-of-`u32` word makes the `u64` entry point
abort the process; the length error it should have returned is never reached. -/
theorem withdrawal_from_u64_panics_before_the_length_check :
    withdrawalFromU64Slice [twoPow32] = .panics "assert!(x <= u32::MAX as u64)" := by decide

theorem withdrawal_from_u64_panics_on_out_of_u32_word (w : Withdrawal) :
    withdrawalFromU64Slice (twoPow32 :: withdrawalWords w) =
      .panics "assert!(x <= u32::MAX as u64)" := by
  cases w with
  | mk r t a n x =>
    cases r; cases a; cases n; cases x
    simp [withdrawalFromU64Slice, withdrawalWords, addrWords, limbWords, u32Max, twoPow32]

/-- On in-range words it behaves like the `u32` entry point. -/
theorem withdrawal_from_u64_agrees_on_canonical_words (w : Withdrawal)
    (h : ∀ x ∈ withdrawalWords w, x ≤ u32Max) :
    withdrawalFromU64Slice (withdrawalWords w) = .ok w := by
  have hno : ¬ (withdrawalWords w).any (fun x => decide (x > u32Max)) := by
    simp only [List.any_eq_true, not_exists, decide_eq_true_eq]
    intro x
    simp only [not_and, decide_eq_true_eq]
    intro hx
    exact Nat.not_lt.2 (h x hx)
  simp only [withdrawalFromU64Slice, if_neg hno, withdrawal_u32_roundtrip w]

/-- **Cross-type keccak preimage collision.** The deposit hash chain and the
withdrawal hash chain absorb the SAME number of 32-bit words (38) with freely
chosen fields, so a deposit-chain preimage and a withdrawal-chain preimage can
be byte-identical. Separation of the two chains rests entirely on the contracts
keeping them in different storage, not on the preimages. -/
theorem deposit_and_withdrawal_chain_preimages_can_coincide :
    depositChainPreimage zeroLimbs8 depositDefault =
      withdrawalChainPreimage zeroLimbs8
        ⟨zeroLimbs5, 0, zeroLimbs8, zeroLimbs8, zeroLimbs8⟩ := by decide

theorem deposit_and_withdrawal_chain_preimages_have_equal_length (p q : Limbs8)
    (d : Deposit) (w : Withdrawal) :
    (depositChainPreimage p d).length = (withdrawalChainPreimage q w).length := by
  rw [deposit_chain_preimage_length, withdrawal_chain_preimage_length]

/-! ## 10. `src/common/salt.rs` -/

/-- `pub struct Salt(pub PoseidonHashOut)` — a transparent newtype. -/
structure Salt where
  value : Hash4
  deriving DecidableEq, Repr

/-- `Salt::to_u64_vec` (salt.rs:44-46). -/
def saltWords (s : Salt) : List Nat := hashWords s.value
/-- `SaltTarget::to_vec` (salt.rs:61-63), transcribed separately. -/
def saltTargetWords (s : Salt) : List Nat := hashWords s.value

theorem salt_words_length (s : Salt) : (saltWords s).length = saltLen := by
  simp [saltWords, hashWords, saltLen, poseidonHashOutLen]

theorem salt_native_target_layout_agrees (s : Salt) : saltWords s = saltTargetWords s := rfl

theorem salt_words_injective {a b : Salt} (h : saltWords a = saltWords b) : a = b := by
  cases a with
  | mk va =>
    cases b with
    | mk vb =>
      cases va; cases vb
      simp only [saltWords, hashWords, List.cons.injEq, and_true] at h
      obtain ⟨rfl, rfl, rfl, rfl⟩ := h
      rfl

/-- The newtype adds NO domain separation: a salt and the bare hash it wraps
encode to the very same words, so any preimage that embeds a salt is
indistinguishable from one that embeds an unrelated `PoseidonHashOut`. Salt is
blinding, not typing. -/
theorem salt_encoding_is_transparent (h : Hash4) : saltWords ⟨h⟩ = hashWords h := rfl

/-! ## 11. `src/common/mod.rs` -/

def commonModules : List String :=
  ["balance_state", "block", "channel", "channel_id", "channel_message",
   "channel_registration", "deposit", "error", "private_state", "public_state",
   "salt", "transfer", "trees", "tx", "u63", "withdrawal"]

def modeledHere : List String :=
  ["tx", "transfer", "deposit", "withdrawal", "channel_id", "u63", "salt", "error"]

theorem common_mod_declares_sixteen_modules : commonModules.length = 16 := by decide

theorem modeled_files_are_declared_in_common_mod :
    ∀ m ∈ modeledHere, m ∈ commonModules := by decide

/-! ## 12. Positive traces

A concrete, non-vacuous end-to-end trace through the value layer: build a
channel id, a settled transfer and a deposit from native inputs and check every
encoder length and every accepted decode. -/

def exampleChannelId : ChannelId := ⟨7⟩
def exampleTransfer : Transfer :=
  ⟨⟨1, 2, 3, 4, 5, 6, 7, 8⟩, 3, ⟨0, 0, 0, 0, 0, 0, 0, 1000⟩, zeroLimbs8⟩
def exampleSettled : SettledTransfer := ⟨exampleTransfer, exampleChannelId, 2, 11⟩
def exampleDeposit : Deposit :=
  ⟨⟨5⟩, ⟨9⟩, ⟨1, 2, 3, 4, 5⟩, ⟨0, 0, 0, 0, 0, 0, 0, 42⟩, 3, ⟨0, 0, 0, 0, 0, 0, 0, 500⟩,
    zeroLimbs8⟩
def exampleWithdrawal : Withdrawal :=
  ⟨⟨1, 2, 3, 4, 5⟩, 3, ⟨0, 0, 0, 0, 0, 0, 0, 500⟩, ⟨9, 9, 9, 9, 9, 9, 9, 9⟩, zeroLimbs8⟩

theorem example_channel_id_is_accepted : channelIdNew 7 = .ok exampleChannelId := by
  simp [channelIdNew, channelIdValidate, twoPow32, exampleChannelId]

theorem example_trace_lengths :
    (settledTransferWords exampleSettled).length = 28 ∧
      (depositWords exampleDeposit).length = 32 ∧
      (withdrawalWords exampleWithdrawal).length = 30 ∧
      (depositChainPreimage zeroLimbs8 exampleDeposit).length = 38 := by decide

theorem example_withdrawal_decodes :
    withdrawalFromU64Slice (withdrawalWords exampleWithdrawal) = .ok exampleWithdrawal := by
  decide

theorem example_u63_add_succeeds : u63Add ⟨5⟩ 4 = .ok ⟨9⟩ := by decide

theorem example_channel_action_encodes_to_23_words :
    (channelActionWords ⟨.memberSetUpdate, ⟨1⟩, ⟨2⟩, zeroLimbs8, zeroLimbs8, zeroHash⟩).length
      = 23 := by decide

end Zkp.Implementation.CommonValues
