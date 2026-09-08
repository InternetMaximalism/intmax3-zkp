import Std
import Zkp.Implementation.U256Arithmetic

/-!
# Current Ethereum limb types: the u32-limb codec substrate

Handwritten implementation model of the whole `src/ethereum_types/` directory:
`u32limb_trait.rs` (368 lines), `u64.rs` (357), `bytes32.rs` (325),
`bytes16.rs` (232), `address.rs` (185), `error.rs` (107), `mod.rs` (10);
all read in full. This is NOT a refinement proof of the Rust code, of `hex`,
`num::BigUint`, `serde`, `rand`, plonky2's builder, or of the LLVM lowering of
Rust integer casts. Limbs are modeled as `Nat` under an explicit `Canonical`
predicate (every limb `< 2^32`) rather than as machine `u32`; a Rust `u32`
array is canonical by typing, so the predicate is a modeling device that also
lets the model exhibit what happens when a *field* wire escapes u32 range.

What the model covers, per source construct:
* the `U32LimbTrait` limb-count contract and the shared big-endian encoders
  `to_u32_vec` / `from_u32_slice` / `to_u64_vec` / `from_u64_slice` /
  `to_bytes_be` / `from_bytes_be` / `to_bits_be` / `from_bits_be` /
  `to_hex` / `from_hex`, plus `zero` / `one` / `rand` / `Default`;
* the four concrete limb counts (U64 2, Bytes16 4, Address 5, Bytes32 8) and
  their byte widths, with `BYTES32_LEN = U256_LEN` pinned against the already
  built `Zkp.Implementation.U256Arithmetic.limbCount`;
* the `U64` hi/lo split convention, its `Ord`, and its panicking `Add`/`Sub`;
* `Bytes32::remove_3bits` (native and target) as an explicit 8-to-1 mask;
* `Bytes16: TryFrom<BigUint>` little-endian digits, resize and reverse;
* the target-side counterparts: allocation with and without `range_check`,
  `from_slice` length panics, `from_bytes_be` byte range checks and its
  refusal to zero-pad, `get_witness`'s truncating `as u32` cast, and the
  `U64Target` add/sub carry/borrow chains, whose local gadget contract is
  reused from `U256Arithmetic.AddTrace` / `SubTrace`.

What the model deliberately does NOT establish (see the map `boundaries`):
plonky2 gate lowering (`range_check`, `split_le`, `le_sum`, `add_many_u32`,
`sub_u32`, `list_le_circuit`), the Goldilocks field embedding, `hex` crate
internals beyond the odd-length / invalid-character contract modeled here,
`num::BigUint::to_u32_digits`, serde round trips, RNG quality, and any claim
that a value passing these codecs is authorized, funded or proof-backed.
Strings are modeled as `List Char`, so Rust `&str` UTF-8 handling is out of
scope; `EthereumTypeError`'s `source()` chain is not modeled, only `Display`.

Silent-loss findings stated as theorems rather than assumed away:
`get_witness` reduces a canonical field value mod `2^32` with no error;
`from_bytes_be` / `from_bits_be` / `from_hex` left-pad, so shorter inputs
collide with longer ones; `remove_3bits` is eight-to-one; and the target
`from_bytes_be` panics on exactly the short inputs the native one accepts.
`bits_be_to_u32` is modeled only on the 32-bit chunks the source feeds it;
on a shorter slice the source's `1 << (31 - i)` would not be a base-2 value.
-/

namespace Zkp.Implementation.EthereumTypes

instance instDecidableEqExcept {e a : Type} [DecidableEq e] [DecidableEq a] :
    DecidableEq (Except e a)
  | .error x, .error y =>
      if h : x = y then isTrue (by rw [h])
      else isFalse (by intro hc; exact h (Except.error.inj hc))
  | .ok x, .ok y =>
      if h : x = y then isTrue (by rw [h])
      else isFalse (by intro hc; exact h (Except.ok.inj hc))
  | .error _, .ok _ => isFalse (by intro hc; exact Except.noConfusion hc)
  | .ok _, .error _ => isFalse (by intro hc; exact Except.noConfusion hc)

/-! ## Constants: limb counts and widths (`mod.rs`, the four type modules) -/

def wordBase : Nat := 4294967296
def byteBase : Nat := 256
def u32Max : Nat := 4294967295
def u64Limit : Nat := 18446744073709551616

def u64Len : Nat := 2
def bytes16Len : Nat := 4
def addressLen : Nat := 5
def u256Len : Nat := 8
def bytes32Len : Nat := u256Len

theorem word_base_pinned : wordBase = 2 ^ 32 := by decide
theorem u64_limit_pinned : u64Limit = 2 ^ 64 := by decide
theorem u32_max_pinned : u32Max = wordBase - 1 := by decide
theorem u64_len_pinned : u64Len = 2 := rfl
theorem bytes16_len_pinned : bytes16Len = 4 := rfl
theorem address_len_pinned : addressLen = 5 := rfl
theorem bytes32_len_pinned : bytes32Len = 8 := rfl

/-- Source `bytes32.rs:15`: `pub const BYTES32_LEN: usize = U256_LEN;`. -/
theorem bytes32_len_is_u256_len : bytes32Len = u256Len := rfl

theorem bytes32_len_matches_u256_model : bytes32Len = U256Arithmetic.limbCount := rfl

theorem word_base_matches_u256_model : wordBase = U256Arithmetic.wordBase := by decide

def byteWidth (numLimbs : Nat) : Nat := 4 * numLimbs

theorem u64_is_eight_bytes : byteWidth u64Len = 8 := rfl
theorem bytes16_is_sixteen_bytes : byteWidth bytes16Len = 16 := rfl
theorem address_is_twenty_bytes : byteWidth addressLen = 20 := rfl
theorem bytes32_is_thirty_two_bytes : byteWidth bytes32Len = 32 := rfl

theorem bytes16_holds_one_hundred_twenty_eight_bits :
    wordBase ^ bytes16Len = 2 ^ 128 := by decide

theorem bytes32_holds_two_hundred_fifty_six_bits :
    wordBase ^ bytes32Len = 2 ^ 256 := by decide

/-- Source `mod.rs:1-7`: the seven declared submodules of `ethereum_types`. -/
def ethereumTypesModules : List String :=
  ["address", "bytes16", "bytes32", "error", "u256", "u32limb_trait", "u64"]

theorem ethereum_types_module_list_pinned : ethereumTypesModules.length = 7 := by decide

/-! ## `error.rs`: the error enum and its `thiserror` display strings -/

inductive HexError where
  | oddLength
  | invalidHexCharacter (c : Char) (index : Nat)
  deriving DecidableEq, Repr

inductive EthError where
  | hexParseError (msg : String)
  | integerParseError (msg : String)
  | valueTooLarge (msg : String)
  | invalidLength (expected : String) (actual : Nat)
  | invalidLengthSimple (n : Nat)
  | outOfU32Range
  | invalidHex (e : HexError)
  | conversionError (msg : String)
  deriving DecidableEq, Repr

/-- Source `mod.rs:10` / `u32limb_trait.rs:17`: `Result<T> = Result<T, EthereumTypeError>`. -/
abbrev EthResult (a : Type) := Except EthError a

def EthError.display : EthError → String
  | .hexParseError m => "Failed to parse hex string: " ++ m
  | .integerParseError m => "Failed to parse integer: " ++ m
  | .valueTooLarge m => "Value too large: " ++ m
  | .invalidLength e a => "Invalid length: expected " ++ e ++ ", got " ++ toString a
  | .invalidLengthSimple n => "Invalid length: " ++ toString n
  | .outOfU32Range => "Out of u32 range"
  | .invalidHex _ => "Invalid hex"
  | .conversionError m => "Conversion error: " ++ m

theorem out_of_u32_range_display : EthError.outOfU32Range.display = "Out of u32 range" := rfl

/-- The `#[error("Invalid hex")]` attribute drops the wrapped `hex::FromHexError`
from the message: two different hex failures are indistinguishable in `Display`. -/
theorem invalid_hex_display_erases_cause (e1 e2 : HexError) :
    (EthError.invalidHex e1).display = (EthError.invalidHex e2).display := rfl

theorem invalid_hex_is_still_injective_as_a_value (e1 e2 : HexError)
    (h : EthError.invalidHex e1 = EthError.invalidHex e2) : e1 = e2 := by
  cases h; rfl

/-- Panics are a distinct outcome from the `Result` error channel: `expect`,
`unwrap`, `assert_eq!`, `checked_add(..).unwrap_or_else(panic!)` and slice
indexing all abort instead of returning `Err`. -/
inductive Fault where
  | err (e : EthError)
  | panic (msg : String)
  deriving DecidableEq, Repr

def expectOk (msg : String) : EthResult a → Except Fault a
  | .ok x => .ok x
  | .error _ => .error (.panic msg)

/-! ## List helpers -/

theorem take_append_of_length (l1 l2 : List Nat) (n : Nat) (h : l1.length = n) :
    (l1 ++ l2).take n = l1 := by subst h; simp

theorem drop_append_of_length (l1 l2 : List Nat) (n : Nat) (h : l1.length = n) :
    (l1 ++ l2).drop n = l2 := by subst h; simp

theorem take_append_bits (l1 l2 : List Bool) (n : Nat) (h : l1.length = n) :
    (l1 ++ l2).take n = l1 := by subst h; simp

theorem drop_append_bits (l1 l2 : List Bool) (n : Nat) (h : l1.length = n) :
    (l1 ++ l2).drop n = l2 := by subst h; simp

/-! ## Positional digits: the shared base-`b` machinery for bytes and bits -/

def digitsLE (base : Nat) : Nat → Nat → List Nat
  | 0, _ => []
  | k + 1, x => (x % base) :: digitsLE base k (x / base)

def valueLE (base : Nat) : List Nat → Nat
  | [] => 0
  | d :: ds => d + base * valueLE base ds

def digitsBE (base k x : Nat) : List Nat := (digitsLE base k x).reverse

def valueBE (base : Nat) (ds : List Nat) : Nat := valueLE base ds.reverse

theorem digits_le_length (base k x : Nat) : (digitsLE base k x).length = k := by
  induction k generalizing x with
  | zero => rfl
  | succ k ih => simp [digitsLE, ih]

theorem digits_be_length (base k x : Nat) : (digitsBE base k x).length = k := by
  simp [digitsBE, digits_le_length]

theorem digits_le_lt (base : Nat) (hb : 0 < base) (k x : Nat) :
    ∀ d ∈ digitsLE base k x, d < base := by
  induction k generalizing x with
  | zero => intro d hd; simp [digitsLE] at hd
  | succ k ih =>
      intro d hd
      simp only [digitsLE, List.mem_cons] at hd
      rcases hd with rfl | hd
      · exact Nat.mod_lt _ hb
      · exact ih (x / base) d hd

theorem digits_be_lt (base : Nat) (hb : 0 < base) (k x : Nat) :
    ∀ d ∈ digitsBE base k x, d < base := by
  intro d hd
  simp only [digitsBE, List.mem_reverse] at hd
  exact digits_le_lt base hb k x d hd

/-- The one arithmetic fact behind every positional round trip in this file. -/
theorem mod_split (base m x : Nat) (hb : 0 < base) (hm : 0 < m) :
    x % (base * m) = x % base + base * ((x / base) % m) := by
  have hd : base * (x / base) + x % base = x := Nat.div_add_mod x base
  have hd2 : m * ((x / base) / m) + (x / base) % m = x / base :=
    Nat.div_add_mod (x / base) m
  have hr : x % base < base := Nat.mod_lt _ hb
  have hs : (x / base) % m < m := Nat.mod_lt _ hm
  have hstep : (x / base) % m + 1 ≤ m := hs
  have hmul : base * ((x / base) % m + 1) ≤ base * m := Nat.mul_le_mul_left base hstep
  have hsucc : base * ((x / base) % m + 1) = base * ((x / base) % m) + base :=
    Nat.mul_succ base ((x / base) % m)
  have hlt : x % base + base * ((x / base) % m) < base * m := by omega
  have hexp : base * (m * ((x / base) / m)) = base * m * ((x / base) / m) :=
    (Nat.mul_assoc base m ((x / base) / m)).symm
  have hcombine : base * (m * ((x / base) / m) + (x / base) % m) + x % base = x := by
    rw [hd2]; exact hd
  have hdist : base * (m * ((x / base) / m) + (x / base) % m)
      = base * (m * ((x / base) / m)) + base * ((x / base) % m) :=
    Nat.mul_add base _ _
  rw [hdist, hexp] at hcombine
  have key : x = (x % base + base * ((x / base) % m)) + base * m * ((x / base) / m) := by omega
  calc x % (base * m)
      = ((x % base + base * ((x / base) % m)) + base * m * ((x / base) / m)) % (base * m) := by
        rw [← key]
    _ = (x % base + base * ((x / base) % m)) % (base * m) :=
        Nat.add_mul_mod_self_left (x % base + base * ((x / base) % m)) (base * m) ((x / base) / m)
    _ = x % base + base * ((x / base) % m) := Nat.mod_eq_of_lt hlt

theorem value_digits_le (base : Nat) (hb : 0 < base) (k x : Nat) :
    valueLE base (digitsLE base k x) = x % base ^ k := by
  induction k generalizing x with
  | zero => simp [digitsLE, valueLE, Nat.mod_one]
  | succ k ih =>
      have hpow : 0 < base ^ k := Nat.pos_pow_of_pos k hb
      have hcomm : base ^ (k + 1) = base * base ^ k := by
        rw [Nat.pow_succ, Nat.mul_comm]
      simp only [digitsLE, valueLE, ih, hcomm]
      exact (mod_split base (base ^ k) x hb hpow).symm

theorem value_digits_be (base : Nat) (hb : 0 < base) (k x : Nat) :
    valueBE base (digitsBE base k x) = x % base ^ k := by
  simp only [valueBE, digitsBE, List.reverse_reverse]
  exact value_digits_le base hb k x

theorem value_le_append_zeros (base : Nat) (ds : List Nat) (k : Nat) :
    valueLE base (ds ++ List.replicate k 0) = valueLE base ds := by
  induction ds with
  | nil =>
      simp only [List.nil_append]
      induction k with
      | zero => rfl
      | succ k ih => simp [List.replicate, valueLE, ih]
  | cons d ds ih => simp [valueLE, ih]

/-! ## `U32LimbTrait`: limb-vector conversions (`u32limb_trait.rs:20-53`) -/

/-- A limb list is canonical when each limb fits in a Rust `u32`. -/
def Canonical (limbs : List Nat) : Prop := ∀ x ∈ limbs, x < wordBase

def toU32Vec (v : List Nat) : List Nat := v

/-- Source `from_u32_slice` for every concrete type: a pure length check,
then an infallible `try_into`. No canonicality or value check exists. -/
def fromU32Slice (numLimbs : Nat) (limbs : List Nat) : EthResult (List Nat) :=
  if limbs.length = numLimbs then .ok limbs
  else .error (.invalidLengthSimple limbs.length)

theorem from_u32_slice_ok_iff (numLimbs : Nat) (xs ys : List Nat) :
    fromU32Slice numLimbs xs = .ok ys ↔ xs.length = numLimbs ∧ ys = xs := by
  unfold fromU32Slice
  by_cases h : xs.length = numLimbs
  · simp [h, eq_comm]
  · simp [h]

theorem from_u32_slice_rejects_wrong_length (numLimbs : Nat) (xs : List Nat)
    (h : xs.length ≠ numLimbs) :
    fromU32Slice numLimbs xs = .error (.invalidLengthSimple xs.length) := by
  simp [fromU32Slice, h]

theorem from_u32_slice_round_trip (numLimbs : Nat) (v : List Nat) (h : v.length = numLimbs) :
    fromU32Slice numLimbs (toU32Vec v) = .ok v := by
  simp [fromU32Slice, toU32Vec, h]

theorem from_u32_slice_is_injective (numLimbs : Nat) (xs ys v : List Nat)
    (hx : fromU32Slice numLimbs xs = .ok v) (hy : fromU32Slice numLimbs ys = .ok v) :
    xs = ys := by
  rw [from_u32_slice_ok_iff] at hx hy
  exact hx.2.symm.trans hy.2

theorem from_u32_slice_result_has_exact_limb_count (numLimbs : Nat) (xs ys : List Nat)
    (h : fromU32Slice numLimbs xs = .ok ys) : ys.length = numLimbs := by
  rw [from_u32_slice_ok_iff] at h
  rw [h.2]; exact h.1

/-- `to_u64_vec` is the widening `as u64` cast: on `Nat` it is the identity. -/
def toU64Vec (v : List Nat) : List Nat := v

theorem to_u64_vec_is_lossless (v : List Nat) : toU64Vec v = toU32Vec v := rfl

/-- Source `from_u64_slice`: `.map(..).collect::<Result<Vec<_>>>()?` stops at the
first out-of-range element, in order, before the length check runs. -/
def checkAllU32 : List Nat → EthResult (List Nat)
  | [] => .ok []
  | x :: xs =>
      if x > u32Max then .error .outOfU32Range
      else match checkAllU32 xs with
        | .error e => .error e
        | .ok ys => .ok (x :: ys)

def fromU64Slice (numLimbs : Nat) (input : List Nat) : EthResult (List Nat) :=
  match checkAllU32 input with
  | .error e => .error e
  | .ok checked => fromU32Slice numLimbs checked

theorem check_all_u32_ok_iff (xs ys : List Nat) :
    checkAllU32 xs = .ok ys ↔ Canonical xs ∧ ys = xs := by
  induction xs generalizing ys with
  | nil =>
      simp only [checkAllU32, Except.ok.injEq]
      constructor
      · intro h; exact ⟨by intro w hw; simp at hw, h.symm⟩
      · intro h; exact h.2.symm
  | cons x xs ih =>
      unfold checkAllU32
      by_cases hx : x > u32Max
      · simp only [if_pos hx]
        constructor
        · intro h; simp at h
        · intro h
          have hxc := h.1 x (by simp)
          unfold Canonical u32Max wordBase at *
          omega
      · simp only [if_neg hx]
        have hxc : x < wordBase := by unfold u32Max wordBase at *; omega
        cases hc : checkAllU32 xs with
        | error e =>
            constructor
            · intro h; simp at h
            · intro h
              have hz : Canonical xs := fun w hw => h.1 w (by simp [hw])
              have hcz := (ih xs).mpr ⟨hz, rfl⟩
              rw [hc] at hcz; simp at hcz
        | ok zs =>
            have hz := (ih zs).mp hc
            constructor
            · intro h
              simp only [Except.ok.injEq] at h
              refine ⟨?_, ?_⟩
              · intro w hw
                simp only [List.mem_cons] at hw
                rcases hw with rfl | hw
                · exact hxc
                · exact hz.1 w hw
              · rw [← h, hz.2]
            · intro h
              rw [h.2, hz.2]

theorem from_u64_slice_ok_iff (numLimbs : Nat) (xs ys : List Nat) :
    fromU64Slice numLimbs xs = .ok ys ↔
      Canonical xs ∧ xs.length = numLimbs ∧ ys = xs := by
  unfold fromU64Slice
  cases hc : checkAllU32 xs with
  | error e =>
      constructor
      · intro h; simp at h
      · intro h
        have hcz := (check_all_u32_ok_iff xs xs).mpr ⟨h.1, rfl⟩
        rw [hc] at hcz; simp at hcz
  | ok zs =>
      have hz := (check_all_u32_ok_iff xs zs).mp hc
      simp only [hz.2, from_u32_slice_ok_iff]
      exact ⟨fun h => ⟨hz.1, h.1, h.2⟩, fun h => ⟨h.2.1, h.2.2⟩⟩

/-- `from_u64_slice` is a *checked* narrowing: a word at or above `2^32` is
rejected with `OutOfU32Range`, never truncated. -/
theorem from_u64_slice_rejects_out_of_range :
    fromU64Slice u64Len [wordBase, 0] = .error .outOfU32Range := by decide

theorem from_u64_slice_reports_range_before_length :
    fromU64Slice u64Len [wordBase, 0, 0, 0] = .error .outOfU32Range := by decide

theorem to_u64_vec_from_u64_slice_round_trip (numLimbs : Nat) (v : List Nat)
    (hlen : v.length = numLimbs) (hc : Canonical v) :
    fromU64Slice numLimbs (toU64Vec v) = .ok v :=
  (from_u64_slice_ok_iff numLimbs v v).mpr ⟨hc, hlen, rfl⟩

/-! ## `zero`, `one`, `Default`, `rand` (`u32limb_trait.rs:42-53,107-111`) -/

def zeroLimbs (numLimbs : Nat) : List Nat := List.replicate numLimbs 0

/-- Source `one()`: `limbs[NUM_LIMBS - 1] = 1`, i.e. the *last* (least
significant, big-endian) limb. -/
def oneLimbs (numLimbs : Nat) : List Nat := List.replicate (numLimbs - 1) 0 ++ [1]

/-- `#[derive(Default)]` on a `[u32; N]` field is the all-zero limb array. -/
def defaultLimbs (numLimbs : Nat) : List Nat := List.replicate numLimbs 0

def zeroNative (numLimbs : Nat) : Except Fault (List Nat) :=
  expectOk "Creating zero value failed" (fromU32Slice numLimbs (zeroLimbs numLimbs))

/-- With `NUM_LIMBS = 0` the source's `limbs[NUM_LIMBS - 1]` underflows `usize`
and indexes far out of bounds; no concrete type in the crate hits this. -/
def oneNative (numLimbs : Nat) : Except Fault (List Nat) :=
  if numLimbs = 0 then .error (.panic "index out of bounds in one()")
  else expectOk "Creating one value failed" (fromU32Slice numLimbs (oneLimbs numLimbs))

def randNative (numLimbs : Nat) (sample : List Nat) : Except Fault (List Nat) :=
  expectOk "Creating random value failed" (fromU32Slice numLimbs sample)

theorem zero_native_never_fails (numLimbs : Nat) :
    zeroNative numLimbs = .ok (zeroLimbs numLimbs) := by
  simp [zeroNative, expectOk, fromU32Slice, zeroLimbs]

theorem default_equals_zero (numLimbs : Nat) : defaultLimbs numLimbs = zeroLimbs numLimbs := rfl

theorem zero_limbs_are_canonical (numLimbs : Nat) : Canonical (zeroLimbs numLimbs) := by
  intro x hx
  have hx0 := List.eq_of_mem_replicate hx
  simp [hx0, wordBase]

theorem one_native_never_fails (numLimbs : Nat) (h : 0 < numLimbs) :
    oneNative numLimbs = .ok (oneLimbs numLimbs) := by
  have hne : ¬ numLimbs = 0 := by omega
  have hlen : (oneLimbs numLimbs).length = numLimbs := by
    simp [oneLimbs]; omega
  simp [oneNative, hne, expectOk, fromU32Slice, hlen]

theorem one_is_in_the_least_significant_limb (numLimbs : Nat) :
    (oneLimbs numLimbs).drop (numLimbs - 1) = [1] :=
  drop_append_of_length _ _ _ (by simp)

theorem one_limbs_address : oneLimbs addressLen = [0, 0, 0, 0, 1] := by decide
theorem one_limbs_u64 : oneLimbs u64Len = [0, 1] := by decide

/-- `rand` builds exactly `NUM_LIMBS` limbs, so its `expect` is unreachable;
every u32 sample is accepted, there is no rejection sampling. -/
theorem rand_native_never_fails (numLimbs : Nat) (sample : List Nat)
    (h : sample.length = numLimbs) : randNative numLimbs sample = .ok sample := by
  simp [randNative, expectOk, fromU32Slice, h]

/-! ## Big-endian bytes (`u32limb_trait.rs:55-75`) -/

def u32ToBytesBe (x : Nat) : List Nat := digitsBE byteBase 4 x
def bytesBeToU32 (bs : List Nat) : Nat := valueBE byteBase bs

def toBytesBe : List Nat → List Nat
  | [] => []
  | x :: xs => u32ToBytesBe x ++ toBytesBe xs

/-- Source: `padded_bytes[4*NUM_LIMBS - bytes.len()..].copy_from_slice(bytes)`,
i.e. zero-extension on the LEFT. -/
def padLeftBytes (total : Nat) (bs : List Nat) : List Nat :=
  List.replicate (total - bs.length) 0 ++ bs

def packBytes : Nat → List Nat → List Nat
  | 0, _ => []
  | k + 1, bs => bytesBeToU32 (bs.take 4) :: packBytes k (bs.drop 4)

def fromBytesBe (numLimbs : Nat) (bytes : List Nat) : EthResult (List Nat) :=
  if bytes.length > 4 * numLimbs then .error (.invalidLengthSimple bytes.length)
  else fromU32Slice numLimbs (packBytes numLimbs (padLeftBytes (4 * numLimbs) bytes))

theorem u32_to_bytes_be_length (x : Nat) : (u32ToBytesBe x).length = 4 := by
  simp [u32ToBytesBe, digits_be_length]

theorem u32_to_bytes_be_are_bytes (x : Nat) : ∀ b ∈ u32ToBytesBe x, b < 256 :=
  digits_be_lt byteBase (by decide) 4 x

theorem word_bytes_round_trip (x : Nat) (h : x < wordBase) :
    bytesBeToU32 (u32ToBytesBe x) = x := by
  unfold bytesBeToU32 u32ToBytesBe
  rw [value_digits_be byteBase (by decide) 4 x]
  have hbb : (byteBase : Nat) ^ 4 = wordBase := by decide
  rw [hbb]
  exact Nat.mod_eq_of_lt h

theorem to_bytes_be_length (v : List Nat) : (toBytesBe v).length = 4 * v.length := by
  induction v with
  | nil => rfl
  | cons x xs ih => simp [toBytesBe, u32_to_bytes_be_length, ih]; omega

theorem to_bytes_be_are_bytes (v : List Nat) : ∀ b ∈ toBytesBe v, b < 256 := by
  induction v with
  | nil => intro b hb; simp [toBytesBe] at hb
  | cons x xs ih =>
      intro b hb
      simp only [toBytesBe, List.mem_append] at hb
      rcases hb with hb | hb
      · exact u32_to_bytes_be_are_bytes x b hb
      · exact ih b hb

theorem pack_bytes_length (k : Nat) (bs : List Nat) : (packBytes k bs).length = k := by
  induction k generalizing bs with
  | zero => rfl
  | succ k ih => simp [packBytes, ih]

theorem pack_to_bytes_be (v : List Nat) (hc : Canonical v) :
    packBytes v.length (toBytesBe v) = v := by
  induction v with
  | nil => rfl
  | cons x xs ih =>
      have hx : x < wordBase := hc x (by simp)
      have ht : Canonical xs := fun w hw => hc w (by simp [hw])
      have hlen : (u32ToBytesBe x).length = 4 := u32_to_bytes_be_length x
      simp only [List.length_cons, packBytes, toBytesBe]
      rw [take_append_of_length _ _ 4 hlen, drop_append_of_length _ _ 4 hlen,
        word_bytes_round_trip x hx, ih ht]

theorem from_bytes_be_round_trip (numLimbs : Nat) (v : List Nat)
    (hlen : v.length = numLimbs) (hc : Canonical v) :
    fromBytesBe numLimbs (toBytesBe v) = .ok v := by
  have hb : (toBytesBe v).length = 4 * numLimbs := by rw [to_bytes_be_length, hlen]
  have hnot : ¬ (toBytesBe v).length > 4 * numLimbs := by omega
  have hpad : padLeftBytes (4 * numLimbs) (toBytesBe v) = toBytesBe v := by
    simp [padLeftBytes, hb]
  rw [fromBytesBe, if_neg hnot, hpad, ← hlen, pack_to_bytes_be v hc]
  simp [fromU32Slice]

theorem to_bytes_be_is_injective_on_canonical (v w : List Nat)
    (hv : Canonical v) (hw : Canonical w) (hl : v.length = w.length)
    (h : toBytesBe v = toBytesBe w) : v = w := by
  have hv' := pack_to_bytes_be v hv
  have hw' := pack_to_bytes_be w hw
  rw [hl, h, hw'] at hv'
  exact hv'.symm

theorem from_bytes_be_rejects_too_long (numLimbs : Nat) (bytes : List Nat)
    (h : bytes.length > 4 * numLimbs) :
    fromBytesBe numLimbs bytes = .error (.invalidLengthSimple bytes.length) := by
  simp [fromBytesBe, h]

theorem from_bytes_be_rejects_twenty_one_bytes :
    fromBytesBe addressLen (List.replicate 21 0) = .error (.invalidLengthSimple 21) := by decide

/-- SILENT MANY-TO-ONE: byte inputs shorter than `4 * NUM_LIMBS` are zero
extended on the left, so `[1]` and `[0,1]` decode to the same value with no
error and no way for the caller to tell them apart. -/
theorem from_bytes_be_ignores_leading_zero_bytes :
    fromBytesBe addressLen [1] = fromBytesBe addressLen [0, 1] ∧
      ([1] : List Nat) ≠ [0, 1] := by
  refine ⟨by decide, by decide⟩

theorem from_bytes_be_always_yields_full_width (numLimbs : Nat) (bytes ys : List Nat)
    (h : fromBytesBe numLimbs bytes = .ok ys) : (toBytesBe ys).length = 4 * numLimbs := by
  rw [to_bytes_be_length]
  unfold fromBytesBe at h
  by_cases hb : bytes.length > 4 * numLimbs
  · rw [if_pos hb] at h; simp at h
  · rw [if_neg hb] at h
    rw [from_u32_slice_ok_iff] at h
    rw [h.2, pack_bytes_length]

/-! ## Big-endian bits (`u32limb_trait.rs:77-95,352-368`) -/

def u32ToBitsBe (x : Nat) : List Bool := (digitsBE 2 32 x).map (fun d => d == 1)

def bitsBeToU32 (bs : List Bool) : Nat :=
  valueBE 2 (bs.map (fun b => if b then 1 else 0))

def toBitsBe : List Nat → List Bool
  | [] => []
  | x :: xs => u32ToBitsBe x ++ toBitsBe xs

def padLeftBits (total : Nat) (bs : List Bool) : List Bool :=
  List.replicate (total - bs.length) false ++ bs

def packBits : Nat → List Bool → List Nat
  | 0, _ => []
  | k + 1, bs => bitsBeToU32 (bs.take 32) :: packBits k (bs.drop 32)

def fromBitsBe (numLimbs : Nat) (bits : List Bool) : EthResult (List Nat) :=
  if bits.length > 32 * numLimbs then .error (.invalidLengthSimple bits.length)
  else fromU32Slice numLimbs (packBits numLimbs (padLeftBits (32 * numLimbs) bits))

theorem binary_digit_map_round_trip (ds : List Nat) (h : ∀ d ∈ ds, d < 2) :
    ((ds.map (fun d => d == 1)).map (fun b => if b then 1 else 0)) = ds := by
  induction ds with
  | nil => rfl
  | cons d ds ih =>
      have hd : d < 2 := h d (by simp)
      have ht : ∀ e ∈ ds, e < 2 := fun e he => h e (by simp [he])
      have hcases : d = 0 ∨ d = 1 := by omega
      simp only [List.map_cons]
      rw [ih ht]
      rcases hcases with rfl | rfl <;> simp

theorem u32_to_bits_be_length (x : Nat) : (u32ToBitsBe x).length = 32 := by
  simp [u32ToBitsBe, digits_be_length]

theorem word_bits_round_trip (x : Nat) (h : x < wordBase) :
    bitsBeToU32 (u32ToBitsBe x) = x := by
  unfold bitsBeToU32 u32ToBitsBe
  rw [binary_digit_map_round_trip _ (digits_be_lt 2 (by decide) 32 x),
    value_digits_be 2 (by decide) 32 x]
  exact Nat.mod_eq_of_lt h

theorem to_bits_be_length (v : List Nat) : (toBitsBe v).length = 32 * v.length := by
  induction v with
  | nil => rfl
  | cons x xs ih => simp [toBitsBe, u32_to_bits_be_length, ih]; omega

theorem pack_bits_length (k : Nat) (bs : List Bool) : (packBits k bs).length = k := by
  induction k generalizing bs with
  | zero => rfl
  | succ k ih => simp [packBits, ih]

theorem pack_to_bits_be (v : List Nat) (hc : Canonical v) :
    packBits v.length (toBitsBe v) = v := by
  induction v with
  | nil => rfl
  | cons x xs ih =>
      have hx : x < wordBase := hc x (by simp)
      have ht : Canonical xs := fun w hw => hc w (by simp [hw])
      have hlen : (u32ToBitsBe x).length = 32 := u32_to_bits_be_length x
      simp only [List.length_cons, packBits, toBitsBe]
      rw [take_append_bits _ _ 32 hlen, drop_append_bits _ _ 32 hlen,
        word_bits_round_trip x hx, ih ht]

theorem from_bits_be_round_trip (numLimbs : Nat) (v : List Nat)
    (hlen : v.length = numLimbs) (hc : Canonical v) :
    fromBitsBe numLimbs (toBitsBe v) = .ok v := by
  have hb : (toBitsBe v).length = 32 * numLimbs := by rw [to_bits_be_length, hlen]
  have hnot : ¬ (toBitsBe v).length > 32 * numLimbs := by omega
  have hpad : padLeftBits (32 * numLimbs) (toBitsBe v) = toBitsBe v := by
    simp [padLeftBits, hb]
  rw [fromBitsBe, if_neg hnot, hpad, ← hlen, pack_to_bits_be v hc]
  simp [fromU32Slice]

theorem to_bits_be_is_injective_on_canonical (v w : List Nat)
    (hv : Canonical v) (hw : Canonical w) (hl : v.length = w.length)
    (h : toBitsBe v = toBitsBe w) : v = w := by
  have hv' := pack_to_bits_be v hv
  have hw' := pack_to_bits_be w hw
  rw [hl, h, hw'] at hv'
  exact hv'.symm

theorem from_bits_be_rejects_too_long (numLimbs : Nat) (bits : List Bool)
    (h : bits.length > 32 * numLimbs) :
    fromBitsBe numLimbs bits = .error (.invalidLengthSimple bits.length) := by
  simp [fromBitsBe, h]

/-- SILENT MANY-TO-ONE, the same shape as the byte parser. -/
theorem from_bits_be_ignores_leading_false_bits :
    fromBitsBe u64Len [true] = fromBitsBe u64Len [false, true] ∧
      ([true] : List Bool) ≠ [false, true] := by
  refine ⟨by decide, by decide⟩

/-! ## Hex (`u32limb_trait.rs:97-105`), via the `hex` crate contract -/

def hexDigitVal (c : Char) : Option Nat :=
  let n := c.toNat
  if 48 ≤ n ∧ n ≤ 57 then some (n - 48)
  else if 97 ≤ n ∧ n ≤ 102 then some (n - 87)
  else if 65 ≤ n ∧ n ≤ 70 then some (n - 55)
  else none

def hexCharOf (d : Nat) : Char :=
  if d < 10 then Char.ofNat (48 + d) else Char.ofNat (87 + d)

def encodeByte (b : Nat) : List Char := [hexCharOf (b / 16), hexCharOf (b % 16)]

def hexEncode : List Nat → List Char
  | [] => []
  | b :: bs => encodeByte b ++ hexEncode bs

def decodeHexPairs (idx : Nat) : List Char → Except HexError (List Nat)
  | [] => .ok []
  | [c] => .error (.invalidHexCharacter c idx)
  | c1 :: c2 :: rest =>
      match hexDigitVal c1 with
      | none => .error (.invalidHexCharacter c1 idx)
      | some h1 =>
        match hexDigitVal c2 with
        | none => .error (.invalidHexCharacter c2 (idx + 1))
        | some h2 =>
          match decodeHexPairs (idx + 2) rest with
          | .error e => .error e
          | .ok bs => .ok ((16 * h1 + h2) :: bs)

/-- `hex::decode` reports odd length before it inspects any character. -/
def hexDecode (cs : List Char) : Except HexError (List Nat) :=
  if cs.length % 2 = 1 then .error .oddLength else decodeHexPairs 0 cs

/-- `hex_str.strip_prefix("0x").unwrap_or(hex_str)`: at most ONE prefix. -/
def stripHexPrefix : List Char → List Char
  | '0' :: 'x' :: rest => rest
  | cs => cs

def fromHexChars (numLimbs : Nat) (cs : List Char) : EthResult (List Nat) :=
  match hexDecode (stripHexPrefix cs) with
  | .error e => .error (.invalidHex e)
  | .ok bytes => fromBytesBe numLimbs bytes

def fromHex (numLimbs : Nat) (s : String) : EthResult (List Nat) :=
  fromHexChars numLimbs s.toList

/-- `"0x".to_string() + &hex::encode(self.to_bytes_be())`, as a character list. -/
def toHexChars (v : List Nat) : List Char := '0' :: 'x' :: hexEncode (toBytesBe v)

theorem hex_digit_char_round_trip : ∀ d, d < 16 → hexDigitVal (hexCharOf d) = some d := by
  decide

theorem hex_encode_length (bs : List Nat) : (hexEncode bs).length = 2 * bs.length := by
  induction bs with
  | nil => rfl
  | cons b bs ih => simp [hexEncode, encodeByte, ih]; omega

theorem to_hex_is_fixed_width (v : List Nat) :
    (toHexChars v).length = 2 + 8 * v.length := by
  simp [toHexChars, hex_encode_length, to_bytes_be_length]
  omega

theorem hex_decode_pairs_of_encode (bs : List Nat) (h : ∀ b ∈ bs, b < 256) (idx : Nat) :
    decodeHexPairs idx (hexEncode bs) = .ok bs := by
  induction bs generalizing idx with
  | nil => rfl
  | cons b bs ih =>
      have hb : b < 256 := h b (by simp)
      have ht : ∀ c ∈ bs, c < 256 := fun c hc => h c (by simp [hc])
      have h1 : b / 16 < 16 := by omega
      have h2 : b % 16 < 16 := by omega
      simp only [hexEncode, encodeByte, List.cons_append, List.nil_append, decodeHexPairs]
      rw [hex_digit_char_round_trip _ h1, hex_digit_char_round_trip _ h2]
      simp only [List.append_eq, List.nil_append]
      rw [ih ht (idx + 2)]
      have hbb : 16 * (b / 16) + b % 16 = b := by omega
      rw [hbb]

theorem hex_decode_of_encode (bs : List Nat) (h : ∀ b ∈ bs, b < 256) :
    hexDecode (hexEncode bs) = .ok bs := by
  have hlen : (hexEncode bs).length % 2 = 1 → False := by
    rw [hex_encode_length]; omega
  unfold hexDecode
  rw [if_neg (by intro hc; exact hlen hc)]
  exact hex_decode_pairs_of_encode bs h 0

theorem from_hex_to_hex_round_trip (numLimbs : Nat) (v : List Nat)
    (hlen : v.length = numLimbs) (hc : Canonical v) :
    fromHexChars numLimbs (toHexChars v) = .ok v := by
  unfold fromHexChars toHexChars
  have hstrip : stripHexPrefix ('0' :: 'x' :: hexEncode (toBytesBe v)) =
      hexEncode (toBytesBe v) := rfl
  rw [hstrip, hex_decode_of_encode _ (to_bytes_be_are_bytes v)]
  exact from_bytes_be_round_trip numLimbs v hlen hc

/-- SILENT MANY-TO-ONE: short hex strings are left-padded, so distinct strings
parse to the same value; `to_hex` then re-emits the full width, so the parser
is not a bijection with the printer. -/
theorem from_hex_ignores_leading_zero_nibbles :
    fromHexChars addressLen ['0', 'x', '0', '1']
      = fromHexChars addressLen ['0', 'x', '0', '0', '0', '1'] ∧
      (['0', 'x', '0', '1'] : List Char) ≠ ['0', 'x', '0', '0', '0', '1'] := by
  refine ⟨by decide, by decide⟩

theorem from_hex_rejects_odd_length :
    fromHexChars addressLen ['0', 'x', '1'] = .error (.invalidHex .oddLength) := by decide

/-- Only one `0x` is stripped: a doubled prefix fails as an invalid character. -/
theorem from_hex_strips_at_most_one_prefix :
    fromHexChars addressLen ['0', 'x', '0', 'x', '1', '2']
      = .error (.invalidHex (.invalidHexCharacter 'x' 1)) := by decide

theorem from_hex_rejects_over_length :
    fromHexChars u64Len ['0', 'x', '0', '0', '0', '0', '0', '0', '0', '0', '0',
      '0', '0', '0', '0', '0', '0', '0', '0', '0']
      = .error (.invalidLengthSimple 9) := by decide

/-! ## `u64.rs`: the hi/lo split, ordering, and panicking arithmetic -/

/-- `From<u64> for U64`: `hi = value >> 32`, `lo = value as u32`, stored
big-endian as `[hi, lo]`. -/
def u64Split (x : Nat) : List Nat := [x / wordBase, x % wordBase]

/-- `From<U64> for u64`: `(hi << 32) | lo`. -/
def u64Join : List Nat → Nat
  | hi :: lo :: _ => hi * wordBase + lo
  | _ => 0

theorem u64_hi_lo_convention (x : Nat) : u64Split x = [x / wordBase, x % wordBase] := rfl

theorem u64_split_has_two_limbs (x : Nat) : (u64Split x).length = u64Len := rfl

theorem u64_split_is_canonical (x : Nat) : Canonical (u64Split x) ↔ x / wordBase < wordBase := by
  constructor
  · intro h; exact h _ (by simp [u64Split])
  · intro h w hw
    simp only [u64Split, List.mem_cons, List.not_mem_nil, or_false] at hw
    rcases hw with rfl | rfl
    · exact h
    · exact Nat.mod_lt _ (by unfold wordBase; omega)

theorem u64_split_of_u64_range_is_canonical (x : Nat) (h : x < u64Limit) :
    Canonical (u64Split x) := by
  rw [u64_split_is_canonical]
  unfold wordBase u64Limit at *
  omega

theorem u64_from_to_round_trip (x : Nat) (h : x < u64Limit) :
    u64Join (u64Split x) = x ∧ Canonical (u64Split x) := by
  refine ⟨?_, u64_split_of_u64_range_is_canonical x h⟩
  show x / wordBase * wordBase + x % wordBase = x
  unfold wordBase at *
  omega

theorem u64_to_from_round_trip (limbs : List Nat) (hlen : limbs.length = u64Len)
    (hc : Canonical limbs) : u64Split (u64Join limbs) = limbs := by
  cases limbs with
  | nil => simp [u64Len] at hlen
  | cons hi t =>
    cases t with
    | nil => simp [u64Len] at hlen
    | cons lo t2 =>
      cases t2 with
      | cons z t3 => simp [u64Len] at hlen
      | nil =>
        have hlo : lo < wordBase := hc lo (by simp)
        show u64Split (hi * wordBase + lo) = [hi, lo]
        simp only [u64Split, List.cons.injEq, and_true]
        unfold wordBase at *
        omega

theorem u64_join_is_injective_on_canonical (a b : List Nat)
    (ha : a.length = u64Len) (hb : b.length = u64Len)
    (hca : Canonical a) (hcb : Canonical b) (h : u64Join a = u64Join b) : a = b := by
  have h1 := u64_to_from_round_trip a ha hca
  have h2 := u64_to_from_round_trip b hb hcb
  rw [← h1, ← h2, h]

/-- `impl Ord for U64` compares the `[hi, lo]` array lexicographically, which
coincides with numeric `u64` order exactly because `lo < 2^32`. -/
theorem u64_lexicographic_order_is_numeric (hi1 lo1 hi2 lo2 : Nat)
    (h1 : lo1 < wordBase) (h2 : lo2 < wordBase) :
    (hi1 * wordBase + lo1 ≤ hi2 * wordBase + lo2) ↔ (hi1 < hi2 ∨ (hi1 = hi2 ∧ lo1 ≤ lo2)) := by
  unfold wordBase at *
  omega

def u64Add (a b : Nat) : Except Fault Nat :=
  if a + b < u64Limit then .ok (a + b) else .error (.panic "Addition overflow")

def u64Sub (a b : Nat) : Except Fault Nat :=
  if b ≤ a then .ok (a - b) else .error (.panic "Subtraction underflow")

theorem u64_add_is_exact_when_it_returns (a b c : Nat) (h : u64Add a b = .ok c) :
    c = a + b ∧ a + b < u64Limit := by
  unfold u64Add at h
  by_cases hlt : a + b < u64Limit
  · rw [if_pos hlt] at h; simp at h; exact ⟨h.symm, hlt⟩
  · rw [if_neg hlt] at h; simp at h

/-- `checked_add(..).unwrap_or_else(|| panic!(..))` aborts; it does NOT wrap. -/
theorem u64_add_panics_on_overflow :
    u64Add (u64Limit - 1) 1 = .error (.panic "Addition overflow") := by decide

theorem u64_sub_panics_on_underflow :
    u64Sub 0 1 = .error (.panic "Subtraction underflow") := by decide

theorem u64_sub_is_exact_when_it_returns (a b c : Nat) (h : u64Sub a b = .ok c) :
    c = a - b ∧ b ≤ a := by
  unfold u64Sub at h
  by_cases hle : b ≤ a
  · rw [if_pos hle] at h; simp at h; exact ⟨h.symm, hle⟩
  · rw [if_neg hle] at h; simp at h

/-! ## `bytes32.rs`: `remove_3bits` and the `U256` conversions -/

def top3BitMask : Nat := 536870912

theorem top_3_bit_mask_pinned : top3BitMask = 2 ^ 29 := by decide

/-- `limbs[0] &= (1 << 29) - 1` on a canonical limb keeps the low 29 bits. -/
def remove3Bits : List Nat → List Nat
  | [] => []
  | x :: xs => (x % top3BitMask) :: xs

theorem remove_3bits_clears_the_top_three_bits (x : Nat) (xs : List Nat) :
    remove3Bits (x :: xs) = (x % top3BitMask) :: xs ∧ x % top3BitMask < top3BitMask := by
  exact ⟨rfl, Nat.mod_lt _ (by decide)⟩

theorem remove_3bits_preserves_the_other_limbs (x : Nat) (xs : List Nat) :
    (remove3Bits (x :: xs)).drop 1 = xs := by simp [remove3Bits]

theorem remove_3bits_preserves_length (v : List Nat) :
    (remove3Bits v).length = v.length := by
  cases v <;> simp [remove3Bits]

theorem remove_3bits_is_idempotent (v : List Nat) :
    remove3Bits (remove3Bits v) = remove3Bits v := by
  cases v with
  | nil => rfl
  | cons x xs =>
      simp only [remove3Bits, List.cons.injEq, and_true, top3BitMask]
      omega

/-- MANY-TO-ONE BY CONSTRUCTION: exactly eight distinct canonical `Bytes32`
values share each image, because the top three bits are discarded. -/
theorem remove_3bits_is_eight_to_one (k m : Nat) (xs : List Nat)
    (hk : k < 8) (hm : m < top3BitMask) :
    remove3Bits ((k * top3BitMask + m) :: xs) = m :: xs ∧
      k * top3BitMask + m < wordBase := by
  constructor
  · simp only [remove3Bits, List.cons.injEq, and_true]
    unfold top3BitMask at *
    omega
  · unfold top3BitMask wordBase at *
    omega

theorem remove_3bits_concrete_collision :
    remove3Bits [top3BitMask, 0, 0, 0, 0, 0, 0, 0] = remove3Bits [0, 0, 0, 0, 0, 0, 0, 0] ∧
      ([top3BitMask, 0, 0, 0, 0, 0, 0, 0] : List Nat) ≠ [0, 0, 0, 0, 0, 0, 0, 0] := by
  refine ⟨by decide, by decide⟩

/-- The target `remove_3bits` re-sums the low 29 bits of `split_le(limb, 32)`,
which agrees with the native mask exactly when the limb really is 32-bit. -/
def targetRemove3Bits (v : List Nat) : List Nat := remove3Bits v

theorem target_remove_3bits_matches_native (v : List Nat) :
    targetRemove3Bits v = remove3Bits v := rfl

def bytes32ToU256 (v : List Nat) : Except Fault (List Nat) :=
  expectOk "Converting from Bytes32 to U256 should never fail" (fromU32Slice u256Len v)

def u256ToBytes32 (v : List Nat) : Except Fault (List Nat) :=
  expectOk "Converting from U256 to Bytes32 should never fail" (fromU32Slice bytes32Len v)

/-- Both `expect`s are unreachable because the two limb counts are equal. -/
theorem bytes32_u256_conversions_never_panic (v : List Nat) (h : v.length = bytes32Len) :
    bytes32ToU256 v = .ok v ∧ u256ToBytes32 v = .ok v := by
  constructor <;>
    simp [bytes32ToU256, u256ToBytes32, expectOk, fromU32Slice, h, u256Len, bytes32Len]

theorem bytes32_u256_conversion_is_the_identity_on_limbs (v : List Nat)
    (h : v.length = bytes32Len) : bytes32ToU256 v = .ok v :=
  (bytes32_u256_conversions_never_panic v h).1

/-! ## `bytes16.rs`: the `BigUint` conversions -/

/-- `BigUint::to_u32_digits()` is little-endian; the source resizes to four
digits then reverses to the crate's big-endian limb order. -/
def bytes16FromDigits (digits : List Nat) : EthResult (List Nat) :=
  if digits.length > bytes16Len then
    .error (.valueTooLarge "Value has too many digits for Bytes16")
  else .ok ((digits ++ List.replicate (bytes16Len - digits.length) 0).reverse)

def bytes16ToBigUint (v : List Nat) : Nat := valueLE wordBase v.reverse

theorem bytes16_from_digits_rejects_too_large :
    bytes16FromDigits [1, 2, 3, 4, 5]
      = .error (.valueTooLarge "Value has too many digits for Bytes16") := by decide

theorem bytes16_from_digits_is_big_endian :
    bytes16FromDigits [239, 18] = .ok [0, 0, 18, 239] := by decide

theorem bytes16_from_digits_has_exact_limb_count (digits v : List Nat)
    (h : bytes16FromDigits digits = .ok v) : v.length = bytes16Len := by
  unfold bytes16FromDigits at h
  by_cases hd : digits.length > bytes16Len
  · rw [if_pos hd] at h; simp at h
  · rw [if_neg hd] at h
    simp only [Except.ok.injEq] at h
    rw [← h]
    simp only [List.length_reverse, List.length_append, List.length_replicate]
    omega

theorem bytes16_biguint_round_trip (digits v : List Nat)
    (h : bytes16FromDigits digits = .ok v) :
    bytes16ToBigUint v = valueLE wordBase digits := by
  unfold bytes16FromDigits at h
  by_cases hd : digits.length > bytes16Len
  · rw [if_pos hd] at h; simp at h
  · rw [if_neg hd] at h
    simp only [Except.ok.injEq] at h
    rw [← h]
    simp only [bytes16ToBigUint, List.reverse_reverse]
    exact value_le_append_zeros wordBase digits (bytes16Len - digits.length)

/-! ## `address.rs`: the twenty-byte, five-limb layout -/

def addressFromU32Slice (limbs : List Nat) : EthResult (List Nat) :=
  fromU32Slice addressLen limbs

theorem address_has_five_limbs_and_twenty_bytes :
    addressLen = 5 ∧ byteWidth addressLen = 20 := by decide

theorem address_rejects_four_limbs :
    addressFromU32Slice [1, 2, 3, 4] = .error (.invalidLengthSimple 4) := by decide

theorem address_to_bytes_be_is_twenty_bytes (v : List Nat) (h : v.length = addressLen) :
    (toBytesBe v).length = 20 := by rw [to_bytes_be_length, h]; decide

theorem address_to_hex_is_forty_two_characters (v : List Nat) (h : v.length = addressLen) :
    (toHexChars v).length = 42 := by rw [to_hex_is_fixed_width, h]; decide

/-! ## Target side (`u32limb_trait.rs:115-350`, `u64.rs:44-60,170-263`) -/

structure TargetAlloc where
  numLimbs : Nat
  rangeChecked : Bool
  deriving DecidableEq, Repr

/-- `_new_range_unchecked` allocates virtual targets and nothing else;
`_new_range_checked` additionally emits `range_check(x, 32)` per limb. -/
def newRangeUnchecked (numLimbs : Nat) : TargetAlloc := ⟨numLimbs, false⟩
def newRangeChecked (numLimbs : Nat) : TargetAlloc := ⟨numLimbs, true⟩
def newTarget (numLimbs : Nat) (rangeCheck : Bool) : TargetAlloc :=
  if rangeCheck then newRangeChecked numLimbs else newRangeUnchecked numLimbs

/-- The constraints an assignment must satisfy for a given allocation. -/
def AllocAccepts (t : TargetAlloc) (assignment : List Nat) : Prop :=
  assignment.length = t.numLimbs ∧ (t.rangeChecked = true → Canonical assignment)

theorem new_dispatches_on_the_range_check_flag (numLimbs : Nat) :
    newTarget numLimbs true = newRangeChecked numLimbs ∧
      newTarget numLimbs false = newRangeUnchecked numLimbs := by
  refine ⟨rfl, rfl⟩

/-- `new(builder, false)` leaves the limb wires completely unconstrained, so a
field element at or above `2^32` is a legal witness for a `Bytes32Target`. -/
theorem unchecked_allocation_accepts_out_of_range_limbs :
    AllocAccepts (newRangeUnchecked addressLen) [wordBase, 0, 0, 0, 0] := by
  refine ⟨rfl, ?_⟩
  intro h
  simp [newRangeUnchecked] at h

theorem checked_allocation_rejects_out_of_range_limbs :
    ¬ AllocAccepts (newRangeChecked addressLen) [wordBase, 0, 0, 0, 0] := by
  intro h
  have hbad := h.2 rfl wordBase (by simp)
  exact absurd hbad (Nat.lt_irrefl _)

theorem checked_allocation_accepts_canonical_limbs :
    AllocAccepts (newRangeChecked addressLen) [1, 2, 3, 4, 5] := by
  refine ⟨rfl, ?_⟩
  intro _ w hw
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hw
  unfold wordBase
  rcases hw with rfl | rfl | rfl | rfl | rfl <;> omega

/-- `Self::from_slice` panics on a wrong-length slice (`assert_eq!` for the
Address/Bytes32/Bytes16 targets, a bare `try_into().unwrap()` for `U64Target`). -/
def targetFromSlice (numLimbs : Nat) (limbs : List Nat) : Except Fault (List Nat) :=
  if limbs.length = numLimbs then .ok limbs
  else .error (.panic "Invalid length for target limbs")

theorem target_from_slice_panics_on_wrong_length (numLimbs : Nat) (limbs : List Nat)
    (h : limbs.length ≠ numLimbs) :
    targetFromSlice numLimbs limbs = .error (.panic "Invalid length for target limbs") := by
  simp [targetFromSlice, h]

theorem native_returns_an_error_where_the_target_panics (limbs : List Nat)
    (h : limbs.length ≠ addressLen) :
    fromU32Slice addressLen limbs = .error (.invalidLengthSimple limbs.length) ∧
      targetFromSlice addressLen limbs = .error (.panic "Invalid length for target limbs") :=
  ⟨from_u32_slice_rejects_wrong_length _ _ h, target_from_slice_panics_on_wrong_length _ _ h⟩

/-- Target `from_bytes_be` asserts an EXACT byte count and range-checks each
byte to 8 bits; unlike the native parser it does not zero-pad. -/
def targetFromBytesBe (numLimbs : Nat) (bytes : List Nat) : Except Fault (List Nat) :=
  if bytes.length = 4 * numLimbs then .ok (packBytes numLimbs bytes)
  else .error (.panic "Invalid length for U32 limb target bytes")

def ByteRangeChecked (bytes : List Nat) : Prop := ∀ b ∈ bytes, b < 256

theorem target_from_bytes_be_panics_where_native_pads :
    targetFromBytesBe addressLen [1] = .error (.panic "Invalid length for U32 limb target bytes") ∧
      fromBytesBe addressLen [1] = .ok [0, 0, 0, 0, 1] := by
  refine ⟨by decide, by decide⟩

theorem target_from_bytes_be_matches_native_on_full_width (numLimbs : Nat) (bytes : List Nat)
    (h : bytes.length = 4 * numLimbs) :
    targetFromBytesBe numLimbs bytes = .ok (packBytes numLimbs bytes) ∧
      fromBytesBe numLimbs bytes = .ok (packBytes numLimbs bytes) := by
  refine ⟨by simp [targetFromBytesBe, h], ?_⟩
  have hnot : ¬ bytes.length > 4 * numLimbs := by omega
  have hpad : padLeftBytes (4 * numLimbs) bytes = bytes := by simp [padLeftBytes, h]
  rw [fromBytesBe, if_neg hnot, hpad]
  simp [fromU32Slice, pack_bytes_length]

def targetToBytesBe (v : List Nat) : List Nat := toBytesBe v

theorem target_bytes_round_trip (v : List Nat) (hc : Canonical v) :
    targetFromBytesBe v.length (targetToBytesBe v) = .ok v := by
  have hlen : (targetToBytesBe v).length = 4 * v.length := to_bytes_be_length v
  rw [targetFromBytesBe, if_pos hlen]
  exact congrArg Except.ok (pack_to_bytes_be v hc)

theorem target_to_bytes_be_is_byte_ranged (v : List Nat) :
    ByteRangeChecked (targetToBytesBe v) := to_bytes_be_are_bytes v

/-- `get_witness` reads each wire, calls `to_canonical_u64()` and then casts
`as u32`: a truncating cast, NOT a checked narrowing like `from_u64_slice`. -/
def canonicalU64ToU32 (x : Nat) : Nat := x % wordBase

def targetGetWitness (numLimbs : Nat) (fieldValues : List Nat) : EthResult (List Nat) :=
  fromU32Slice numLimbs (fieldValues.map canonicalU64ToU32)

theorem canonical_map_is_the_identity (v : List Nat) (hc : Canonical v) :
    v.map canonicalU64ToU32 = v := by
  induction v with
  | nil => rfl
  | cons x xs ih =>
      have hx : x < wordBase := hc x (by simp)
      have ht : Canonical xs := fun w hw => hc w (by simp [hw])
      simp only [List.map_cons, canonicalU64ToU32, Nat.mod_eq_of_lt hx, ih ht]

theorem target_get_witness_is_faithful_on_canonical_wires (numLimbs : Nat) (v : List Nat)
    (hlen : v.length = numLimbs) (hc : Canonical v) :
    targetGetWitness numLimbs v = .ok v := by
  rw [targetGetWitness, canonical_map_is_the_identity v hc]
  simp [fromU32Slice, hlen]

/-- SILENT TRUNCATION: a wire carrying a field value at or above `2^32`, which
an unchecked allocation permits, is reduced mod `2^32` with no error, so two
different witnesses read back as the same native value. -/
theorem target_get_witness_silently_truncates :
    targetGetWitness u64Len [wordBase, 0] = .ok [0, 0] ∧
      targetGetWitness u64Len [0, 0] = .ok [0, 0] ∧
      ([wordBase, 0] : List Nat) ≠ [0, 0] := by
  refine ⟨by decide, by decide, by decide⟩

theorem checked_narrowing_and_truncating_cast_disagree :
    fromU64Slice u64Len [wordBase, 0] = .error .outOfU32Range ∧
      targetGetWitness u64Len [wordBase, 0] = .ok [0, 0] := by
  refine ⟨by decide, by decide⟩

/-- `U64Target::from_u32_target` range-checks the wire and puts it in the LOW
(second, big-endian) limb, zeroing the high limb. -/
def u64TargetFromU32Target (x : Nat) : List Nat := [0, x]

theorem u64_target_from_u32_target_is_the_low_limb (x : Nat) :
    u64TargetFromU32Target x = [0, x] ∧ u64Join (u64TargetFromU32Target x) = x := by
  refine ⟨rfl, ?_⟩
  show 0 * wordBase + x = x
  omega

/-- The `U64Target` add/sub loops are the same reversed carry/borrow chain the
`U256Target` ones use, so the local gadget contract is reused verbatim from the
already built `U256Arithmetic` model, at two limbs instead of eight. -/
def U64AddGates (a b r : List Nat) : Prop :=
  a.length = u64Len ∧ b.length = u64Len ∧ r.length = u64Len ∧
    U256Arithmetic.AddTrace U256Arithmetic.wordBase a.reverse b.reverse r.reverse 0 0

def U64SubGates (a b r : List Nat) : Prop :=
  a.length = u64Len ∧ b.length = u64Len ∧ r.length = u64Len ∧
    U256Arithmetic.SubTrace U256Arithmetic.wordBase a.reverse b.reverse r.reverse 0 0

theorem u64_target_add_is_exact (a b r : List Nat) (h : U64AddGates a b r) :
    U256Arithmetic.valueBE a + U256Arithmetic.valueBE b = U256Arithmetic.valueBE r := by
  simpa [U256Arithmetic.valueBE] using U256Arithmetic.add_trace_integer_equation h.2.2.2

theorem u64_target_sub_cannot_underflow (a b r : List Nat) (h : U64SubGates a b r) :
    U256Arithmetic.valueBE b ≤ U256Arithmetic.valueBE a := by
  have he := U256Arithmetic.sub_trace_integer_equation h.2.2.2
  simp only [U256Arithmetic.valueBE]
  simp at he
  omega

theorem u64_target_sub_is_the_difference (a b r : List Nat) (h : U64SubGates a b r) :
    U256Arithmetic.valueBE r = U256Arithmetic.valueBE a - U256Arithmetic.valueBE b := by
  have he := U256Arithmetic.sub_trace_integer_equation h.2.2.2
  simp only [U256Arithmetic.valueBE]
  simp at he
  omega

/-- `is_le` delegates to the imported `list_le_circuit`; the model keeps it as
a named premise instead of claiming the crate's comparator is correct. -/
structure ListLeSpec where
  le : List Nat → List Nat → Bool
  sound : ∀ a b, a.length = u64Len → b.length = u64Len → Canonical a → Canonical b →
    (le a b = true ↔ u64Join a ≤ u64Join b)

theorem u64_is_lt_is_le_and_not_equal (spec : ListLeSpec) (a b : List Nat)
    (ha : a.length = u64Len) (hb : b.length = u64Len)
    (hca : Canonical a) (hcb : Canonical b) :
    (spec.le a b = true ∧ a ≠ b) ↔ u64Join a < u64Join b := by
  constructor
  · intro h
    have hle := (spec.sound a b ha hb hca hcb).mp h.1
    rcases Nat.lt_or_ge (u64Join a) (u64Join b) with hlt | hge
    · exact hlt
    · exact absurd (u64_join_is_injective_on_canonical a b ha hb hca hcb (by omega)) h.2
  · intro h
    refine ⟨(spec.sound a b ha hb hca hcb).mpr (by omega), ?_⟩
    intro hab
    rw [hab] at h
    omega

/-! ## Non-vacuous normal traces -/

theorem normal_address_hex_round_trip :
    fromHexChars addressLen
        ['0', 'x', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f',
         '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f',
         '1', '2', '3', '4', '5', '6', '7', '8']
      = .ok [0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678] := by decide

theorem normal_address_hex_without_prefix :
    fromHexChars addressLen
        ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f',
         '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f',
         '1', '2', '3', '4', '5', '6', '7', '8']
      = .ok [0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678] := by decide

theorem normal_empty_hex_is_the_default_value :
    fromHexChars addressLen ['0', 'x'] = .ok (defaultLimbs addressLen) := by decide

theorem normal_bytes16_hex_round_trip :
    fromHexChars bytes16Len
        ['0', 'x', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f',
         '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f']
      = .ok [0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef] := by decide

theorem normal_bytes32_bytes_round_trip :
    fromBytesBe bytes32Len
        (toBytesBe [0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef,
                    0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef])
      = .ok [0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef,
             0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef] := by decide

theorem normal_u64_value_round_trip : u64Join (u64Split 123) = 123 := by decide

theorem normal_u64_target_add : U64AddGates [0, 7] [0, 2] [0, 9] := by
  refine ⟨rfl, rfl, rfl, ?_⟩
  simp only [List.reverse_cons, List.reverse_nil, List.nil_append, List.cons_append]
  exact .cons (next := 0) (by decide) (.cons (next := 0) (by decide) (.nil 0))

theorem normal_u64_target_sub : U64SubGates [0, 9] [0, 2] [0, 7] := by
  refine ⟨rfl, rfl, rfl, ?_⟩
  simp only [List.reverse_cons, List.reverse_nil, List.nil_append, List.cons_append]
  exact .cons (next := 0) (by decide) (.cons (next := 0) (by decide) (.nil 0))

theorem normal_u64_target_add_with_inter_limb_carry :
    U64AddGates [0, U256Arithmetic.wordBase - 1] [0, 1] [1, 0] := by
  refine ⟨rfl, rfl, rfl, ?_⟩
  simp only [List.reverse_cons, List.reverse_nil, List.nil_append, List.cons_append]
  exact .cons (next := 1) (by decide) (.cons (next := 0) (by decide) (.nil 0))

end Zkp.Implementation.EthereumTypes
