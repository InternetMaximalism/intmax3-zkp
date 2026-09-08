import Std

/-!
# Vendored Falcon-512 reference implementation

Handwritten semantic model of the vendored third-party Falcon-512 tree under
src/falcon_sig/vendor/ (mod.rs, hash_to_point.rs, signature.rs, keys/mod.rs,
keys/public_key.rs, keys/secret_key.rs, math/mod.rs, math/field.rs,
math/polynomial.rs, math/fft.rs, math/ffsampling.rs, math/samplerz.rs).

This is NOT a refinement proof of the Rust source, of rustc, or of plonky2.
It is a local model of the data layouts and of the checks the vendored code
actually performs, together with kernel-checked theorems about that model.
-/
namespace Zkp.Implementation.FalconVendor

/-! ## Section 1: parameters (vendor/mod.rs, keys/secret_key.rs, math/mod.rs) -/

/-- The Falcon modulus `q` (`MODULUS` in vendor/mod.rs). -/
def falconQ : Nat := 12289
/-- Falcon-512 ring degree `N`. -/
def falconN : Nat := 512
/-- `LOG_N`, the header nibble for degree 512. -/
def falconLogN : Nat := 9
/-- `FALCON_ENCODING_BITS`: public-key coefficients are packed 14 bits each. -/
def falconEncodingBits : Nat := 14
/-- `SIG_NONCE_LEN`: the salt is 40 bytes. -/
def sigNonceLen : Nat := 40
/-- `NONCE_ELEMENTS`: the salt is repacked into 8 field elements. -/
def nonceElements : Nat := 8
/-- `PK_LEN`. -/
def pkLen : Nat := 897
/-- `SK_LEN`. -/
def skLen : Nat := 1281
/-- `SIG_POLY_BYTE_LEN`: the compressed `s2` encoding is a fixed 625 bytes. -/
def sigPolyByteLen : Nat := 625
/-- `SIG_L2_BOUND` = beta^2, the squared-norm acceptance bound. -/
def sigL2Bound : Nat := 34034726
/-- `WIDTH_SMALL_POLY_COEFFICIENT` (f, g). -/
def widthSmallPolyCoefficient : Nat := 6
/-- `WIDTH_BIG_POLY_COEFFICIENT` (F, G). -/
def widthBigPolyCoefficient : Nat := 8
/-- `MAX_SMALL_POLY_COEFFICIENT_SIZE` = 2^(6-1) - 1. -/
def maxSmallPolyCoefficient : Nat := 31
/-- `MAX_BIG_POLY_COEFFICIENT_SIZE` = 2^(8-1) - 1. -/
def maxBigPolyCoefficient : Nat := 127
/-- `SignatureHeader::default()` = `0b1011_1001`. -/
def signatureHeaderByte : Nat := 185
/-- The high nibble of the secret-key header byte. -/
def secretKeyHeaderNibble : Nat := 5
/-- Largest magnitude a compressed signature coefficient may take. -/
def maxSigCoefficient : Nat := 2047
/-- `DOMAIN_FALCON_H2P` = ASCII "IMFH", the capacity domain separator. -/
def domainFalconH2P : Nat := 1229801032
/-- plonky2 Poseidon `SPONGE_WIDTH`. -/
def spongeWidth : Nat := 12
/-- plonky2 Poseidon `SPONGE_RATE`. -/
def spongeRate : Nat := 8
/-- Number of squeezing permutations: `N / SPONGE_RATE`. -/
def squeezeRounds : Nat := 64
/-- The Goldilocks modulus `p = 2^64 - 2^32 + 1` of the host field. -/
def goldilocksP : Nat := 18446744069414584321
/-- `u32` wrap-around used by the bit accumulators. -/
def u32Mod : Nat := 4294967296

theorem falcon_q_pinned : falconQ = 12289 := rfl
theorem falcon_n_pinned : falconN = 512 := rfl
theorem falcon_log_n_pinned : 2 ^ falconLogN = falconN := by decide
theorem falcon_encoding_bits_pinned : falconEncodingBits = 14 := rfl
theorem sig_nonce_len_pinned : sigNonceLen = 40 := rfl
theorem sig_l2_bound_pinned : sigL2Bound = 34034726 := rfl
theorem goldilocks_p_pinned : goldilocksP = 2 ^ 64 - 2 ^ 32 + 1 := by decide
theorem domain_falcon_h2p_is_ascii_imfh :
    domainFalconH2P = 73 * 2 ^ 24 + 77 * 2 ^ 16 + 70 * 2 ^ 8 + 72 := by decide

/-- 14 bits are enough for a canonical coefficient, and no fewer. -/
theorem encoding_bits_cover_modulus :
    falconQ < 2 ^ falconEncodingBits ∧ 2 ^ (falconEncodingBits - 1) < falconQ := by decide

/-- `MAX_SMALL_POLY_COEFFICIENT_SIZE = (1 << (WIDTH_SMALL - 1)) - 1`. -/
theorem max_small_poly_coefficient_derived :
    maxSmallPolyCoefficient = 2 ^ (widthSmallPolyCoefficient - 1) - 1 := by decide
/-- `MAX_BIG_POLY_COEFFICIENT_SIZE = (1 << (WIDTH_BIG - 1)) - 1`. -/
theorem max_big_poly_coefficient_derived :
    maxBigPolyCoefficient = 2 ^ (widthBigPolyCoefficient - 1) - 1 := by decide

/-- The public key is one header byte plus exactly `N * 14 / 8` payload bytes,
    with no leftover bits (the `acc_len > 0` tail branch of `write_into` is dead). -/
theorem pk_len_layout :
    pkLen = 1 + falconN * falconEncodingBits / 8 ∧ falconN * falconEncodingBits % 8 = 0 := by
  decide

/-- The secret key is one header byte plus the f, g and F chunks. -/
theorem sk_len_layout :
    skLen = 1 + (falconN * widthSmallPolyCoefficient + 7) / 8
              + (falconN * widthSmallPolyCoefficient + 7) / 8
              + (falconN * widthBigPolyCoefficient + 7) / 8 := by decide

/-- Both secret-key widths divide the coefficient stream into whole bytes. -/
theorem sk_widths_are_byte_aligned :
    falconN * widthSmallPolyCoefficient % 8 = 0 ∧ falconN * widthBigPolyCoefficient % 8 = 0 := by
  decide

/-- The signature header byte is `0cc1nnnn` with the leading bit flipped:
    high nibble `0b1011`, low nibble `LOG_N`. -/
theorem signature_header_layout :
    signatureHeaderByte / 16 = 11 ∧ signatureHeaderByte % 16 = falconLogN := by decide

/-! ## Section 2: `FalconFelt` (vendor/math/field.rs)

`FalconFelt(u32)` stores a canonical representative. `FalconFelt::new` takes an
`i16` and reduces with Rust's truncating `%`, then adds `q` back when the input
was negative; the model below mirrors that sign handling exactly. -/

/-- Model of `FalconFelt::new(value: i16)`. -/
def feltNew (v : Int) : Nat :=
  if 0 ≤ v then v.natAbs % falconQ else falconQ - v.natAbs % falconQ

/-- Model of `FalconFelt::value()` on a canonical representative. -/
def feltValue (a : Nat) : Nat := a

/-- Model of `FalconFelt::balanced_value()`. -/
def balancedValue (a : Nat) : Int :=
  if falconQ / 2 < a then (a : Int) - (falconQ : Int) else (a : Int)

/-- Model of `impl Add for FalconFelt` (the overflowing add / conditional
    subtract trick), stated on canonical inputs. -/
def feltAddWrapping (a b : Nat) : Nat := if a + b < falconQ then a + b else a + b - falconQ
/-- Modular addition. -/
def feltAdd (a b : Nat) : Nat := (a + b) % falconQ
/-- Model of `impl Neg for FalconFelt`. -/
def feltNeg (a : Nat) : Nat := if a = 0 then 0 else falconQ - a
/-- Model of `FalconFelt::multiply` / `impl Mul`. -/
def feltMul (a b : Nat) : Nat := a * b % falconQ
/-- Subtraction, as `self + (-rhs)` in the source. -/
def feltSub (a b : Nat) : Nat := feltAdd a (feltNeg b)

theorem felt_new_nonneg_canonical (v : Int) (h : 0 ≤ v) : feltNew v < falconQ := by
  simp only [feltNew, if_pos h]
  exact Nat.mod_lt _ (by decide)

theorem felt_new_neg_canonical (v : Int) (h : v < 0) (hnz : v.natAbs % falconQ ≠ 0) :
    feltNew v < falconQ := by
  simp only [feltNew, if_neg (by omega : ¬ (0 : Int) ≤ v)]
  have : v.natAbs % falconQ < falconQ := Nat.mod_lt _ (by decide)
  omega

/-- SECURITY / edge case: `FalconFelt::new` is NOT canonical on negative
    multiples of the modulus. `new(-q)` returns the non-canonical value `q`
    (`i16` admits both `-12289` and `-24578`). -/
theorem felt_new_negative_multiple_of_q_is_not_canonical :
    feltNew (-(falconQ : Int)) = falconQ := by decide

theorem balanced_value_range (a : Nat) (h : a < falconQ) :
    -6144 ≤ balancedValue a ∧ balancedValue a ≤ 6144 := by
  simp only [balancedValue, falconQ] at h ⊢
  split <;> omega

theorem balanced_value_of_small (a : Nat) (h : a ≤ falconQ / 2) : balancedValue a = (a : Int) := by
  simp only [balancedValue]
  rw [if_neg (by omega)]

theorem felt_add_wrapping_eq_mod (a b : Nat) (ha : a < falconQ) (hb : b < falconQ) :
    feltAddWrapping a b = feltAdd a b := by
  unfold feltAddWrapping feltAdd
  split
  · rw [Nat.mod_eq_of_lt (by omega)]
  · rw [Nat.mod_eq_sub_mod (by omega), Nat.mod_eq_of_lt (by omega)]

theorem felt_add_canonical (a b : Nat) : feltAdd a b < falconQ := Nat.mod_lt _ (by decide)
theorem felt_mul_canonical (a b : Nat) : feltMul a b < falconQ := Nat.mod_lt _ (by decide)
theorem felt_neg_canonical (a : Nat) (h : a < falconQ) : feltNeg a < falconQ := by
  unfold feltNeg; split <;> omega

/-- The `u32` product in `FalconFelt::multiply` cannot overflow on canonical inputs. -/
theorem felt_mul_no_u32_overflow (a b : Nat) (ha : a < falconQ) (hb : b < falconQ) :
    a * b < u32Mod := by
  have : a * b ≤ (falconQ - 1) * (falconQ - 1) := Nat.mul_le_mul (by omega) (by omega)
  have hb2 : (falconQ - 1) * (falconQ - 1) < u32Mod := by decide
  omega

/-- The `u16` addition in `Polynomial::reduce_negacyclic` cannot overflow. -/
theorem reduce_negacyclic_no_u16_overflow : (falconQ - 1) + (falconQ - 1) < 2 ^ 16 := by decide

/-- The addition chain in `impl Inverse for FalconFelt` computes `a^(q-2)`.
    Exponents of the chain, in source order. -/
def inverseChainExponent : Nat :=
  let two := 1 + 1
  let three := two + 1
  let six := three + three
  let twelve := six + six
  let fifteen := twelve + three
  let thirty := fifteen + fifteen
  let sixty := thirty + thirty
  let sixtyThree := sixty + three
  let sq := sixtyThree + sixtyThree
  let qu := sq + sq
  let oc := qu + qu
  let hx := oc + oc
  let tt := hx + hx
  let sf := tt + tt
  let allOnes := sf + sixtyThree
  let twoETwelve := allOnes + 1
  let twoEThirteen := twoETwelve + twoETwelve
  twoEThirteen + allOnes

/-- The vendored inversion really is exponentiation by `q - 2` (Fermat inverse). -/
theorem inverse_addition_chain_exponent_is_q_minus_two :
    inverseChainExponent = falconQ - 2 := by decide

/-- Repeated squaring, used by `CyclotomicFourier::primitive_root_of_unity`. -/
def feltSquarings (a : Nat) : Nat → Nat
  | 0 => a
  | k + 1 => feltSquarings (feltMul a a) k

/-- `1331` really has multiplicative order `2^12` modulo `q`, as the comment in
    `impl CyclotomicFourier for FalconFelt` claims. -/
theorem root_1331_order_is_two_pow_twelve :
    feltSquarings 1331 12 = 1 ∧ feltSquarings 1331 11 ≠ 1 := by decide

/-- The `FELT_NINV_*` table of `math/fft.rs` really holds the inverses of the
    supported transform lengths. -/
def feltNinvTable : List (Nat × Nat) :=
  [(1, 1), (2, 6145), (4, 9217), (8, 10753), (16, 11521), (32, 11905), (64, 12097),
   (128, 12193), (256, 12241), (512, 12265)]

theorem felt_ninv_table_correct :
    feltNinvTable.all (fun p => feltMul p.1 p.2 == 1) = true := by decide

/-- The first non-trivial entries of `FELT_BITREVERSED_POWERS` and
    `FELT_BITREVERSED_POWERS_INVERSE` are mutually inverse. -/
theorem felt_bitreversed_powers_inverse_consistent : feltMul 1479 10810 = 1 := by decide

/-- `2^{-1} mod q`, used by `CyclotomicFourier::split_fft`. -/
def feltTwoInv : Nat := 6145
theorem felt_two_inv_correct : feltMul 2 feltTwoInv = 1 := by decide

/-! ## Section 3: bit / byte packing

Both key encodings of the vendored tree (`PublicKey::write_into` /
`read_from`, `encode_i8` / `decode_i8`) are big-endian bit accumulators: fixed
width chunks are shifted into a `u32` and flushed a byte at a time, most
significant bit first. The model below is the same stream, expressed on
`List Bool`. -/

/-- Little-endian bit expansion of `v` to `w` bits. -/
def natToBitsLE : Nat → Nat → List Bool
  | 0, _ => []
  | w + 1, v => (v % 2 == 1) :: natToBitsLE w (v / 2)

/-- Value of a little-endian bit list. -/
def bitsToNatLE : List Bool → Nat
  | [] => 0
  | b :: bs => b.toNat + 2 * bitsToNatLE bs

/-- Big-endian (source order) bit expansion. -/
def natToBits (w v : Nat) : List Bool := (natToBitsLE w v).reverse
/-- Value of a big-endian bit list. -/
def bitsToNat (l : List Bool) : Nat := bitsToNatLE l.reverse

theorem nat_mod_two_pow_succ (v w : Nat) :
    v % 2 ^ (w + 1) = v % 2 + 2 * (v / 2 % 2 ^ w) := by
  have hp : (2 : Nat) ^ (w + 1) = 2 * 2 ^ w := by
    rw [Nat.pow_succ, Nat.mul_comm]
  have h4 : v / 2 / 2 ^ w = v / 2 ^ (w + 1) := by
    rw [Nat.div_div_eq_div_mul, hp]
  have h2 := Nat.div_add_mod (v / 2) (2 ^ w)
  have h3 := Nat.div_add_mod v (2 ^ (w + 1))
  have h5 : 2 ^ (w + 1) * (v / 2 ^ (w + 1)) = 2 * (2 ^ w * (v / 2 / 2 ^ w)) := by
    rw [h4, hp, Nat.mul_assoc]
  rw [h5] at h3
  omega

theorem nat_to_bits_le_length (w v : Nat) : (natToBitsLE w v).length = w := by
  induction w generalizing v with
  | zero => rfl
  | succ w ih => simp [natToBitsLE, ih]

theorem bits_to_nat_le_of_nat_to_bits_le (w v : Nat) :
    bitsToNatLE (natToBitsLE w v) = v % 2 ^ w := by
  induction w generalizing v with
  | zero => simp [natToBitsLE, bitsToNatLE, Nat.mod_one]
  | succ w ih =>
    have hm := nat_mod_two_pow_succ v w
    have hstep : bitsToNatLE (natToBitsLE (w + 1) v)
        = (v % 2 == 1).toNat + 2 * (v / 2 % 2 ^ w) := by
      simp only [natToBitsLE, bitsToNatLE, ih]
    rw [hstep, hm]
    rcases Nat.mod_two_eq_zero_or_one v with h | h <;> rw [h] <;> rfl

theorem nat_to_bits_le_of_bits_to_nat_le :
    ∀ l : List Bool, natToBitsLE l.length (bitsToNatLE l) = l := by
  intro l
  induction l with
  | nil => rfl
  | cons b bs ih =>
    have hx : (b.toNat + 2 * bitsToNatLE bs) % 2 = b.toNat := by
      cases b
      · show (0 + 2 * bitsToNatLE bs) % 2 = 0; omega
      · show (1 + 2 * bitsToNatLE bs) % 2 = 1; omega
    have hy : (b.toNat + 2 * bitsToNatLE bs) / 2 = bitsToNatLE bs := by
      cases b
      · show (0 + 2 * bitsToNatLE bs) / 2 = bitsToNatLE bs; omega
      · show (1 + 2 * bitsToNatLE bs) / 2 = bitsToNatLE bs; omega
    simp only [List.length_cons, natToBitsLE, bitsToNatLE, hx, hy, ih]
    cases b <;> rfl

theorem bits_to_nat_le_lt : ∀ l : List Bool, bitsToNatLE l < 2 ^ l.length := by
  intro l
  induction l with
  | nil => decide
  | cons b bs ih =>
    have h2 : (2 : Nat) ^ (bs.length + 1) = 2 * 2 ^ bs.length := by
      rw [Nat.pow_succ, Nat.mul_comm]
    simp only [List.length_cons, bitsToNatLE, h2]
    cases b
    · show 0 + 2 * bitsToNatLE bs < 2 * 2 ^ bs.length; omega
    · show 1 + 2 * bitsToNatLE bs < 2 * 2 ^ bs.length; omega

theorem nat_to_bits_length (w v : Nat) : (natToBits w v).length = w := by
  simp [natToBits, nat_to_bits_le_length]

theorem bits_to_nat_of_nat_to_bits (w v : Nat) : bitsToNat (natToBits w v) = v % 2 ^ w := by
  simp [bitsToNat, natToBits, bits_to_nat_le_of_nat_to_bits_le]

theorem bits_to_nat_of_nat_to_bits_of_lt (w v : Nat) (h : v < 2 ^ w) :
    bitsToNat (natToBits w v) = v := by
  rw [bits_to_nat_of_nat_to_bits, Nat.mod_eq_of_lt h]

theorem nat_to_bits_of_bits_to_nat (l : List Bool) : natToBits l.length (bitsToNat l) = l := by
  have h : natToBitsLE l.reverse.length (bitsToNatLE l.reverse) = l.reverse :=
    nat_to_bits_le_of_bits_to_nat_le l.reverse
  simp only [natToBits, bitsToNat, List.length_reverse] at h ⊢
  rw [h, List.reverse_reverse]

theorem bits_to_nat_lt (l : List Bool) : bitsToNat l < 2 ^ l.length := by
  have := bits_to_nat_le_lt l.reverse
  simpa [bitsToNat, List.length_reverse] using this

/-- The big-endian bit stream of a list of `w`-bit words. -/
def encodeBits (w : Nat) : List Nat → List Bool
  | [] => []
  | c :: cs => natToBits w c ++ encodeBits w cs

/-- The bit stream of a byte buffer. -/
def bytesToBits : List Nat → List Bool
  | [] => []
  | b :: bs => natToBits 8 b ++ bytesToBits bs

/-- Byte packing of a bit stream, zero padding the final partial byte
    (this is the `if acc_len > 0` flush of the source encoders). -/
def bitsToBytesAux : Nat → List Bool → List Nat
  | 0, _ => []
  | f + 1, bs =>
    match bs with
    | [] => []
    | _ =>
      let g := bs.take 8
      bitsToNat (g ++ List.replicate (8 - g.length) false) :: bitsToBytesAux f (bs.drop 8)

def bitsToBytes (bs : List Bool) : List Nat := bitsToBytesAux bs.length bs

theorem encode_bits_length (w : Nat) : ∀ cs : List Nat, (encodeBits w cs).length = w * cs.length := by
  intro cs
  induction cs with
  | nil => simp [encodeBits]
  | cons c cs ih => simp [encodeBits, nat_to_bits_length, ih, Nat.mul_succ, Nat.add_comm]

theorem bytes_to_bits_length : ∀ bs : List Nat, (bytesToBits bs).length = 8 * bs.length := by
  intro bs
  induction bs with
  | nil => rfl
  | cons b bs ih => simp [bytesToBits, nat_to_bits_length, ih, Nat.mul_succ, Nat.add_comm]

theorem bits_to_bytes_aux_roundtrip :
    ∀ (f : Nat) (bs : List Bool), bs.length ≤ f → bs.length % 8 = 0 →
      bytesToBits (bitsToBytesAux f bs) = bs := by
  intro f
  induction f with
  | zero =>
    intro bs hle _
    have : bs = [] := List.eq_nil_of_length_eq_zero (by omega)
    subst this
    rfl
  | succ f ih =>
    intro bs hle hmod
    match bs with
    | [] => rfl
    | b :: rest =>
      have hlen : (b :: rest).length ≥ 8 := by
        have : (b :: rest).length ≠ 0 := by simp
        omega
      have htake : ((b :: rest).take 8).length = 8 := by
        rw [List.length_take]
        omega
      have hdrop : ((b :: rest).drop 8).length = (b :: rest).length - 8 := List.length_drop 8 _
      have hpad : (8 - ((b :: rest).take 8).length) = 0 := by omega
      have hbit : natToBits 8 (bitsToNat ((b :: rest).take 8)) = (b :: rest).take 8 := by
        have := nat_to_bits_of_bits_to_nat ((b :: rest).take 8)
        rw [htake] at this
        exact this
      have hrest : bytesToBits (bitsToBytesAux f ((b :: rest).drop 8)) = (b :: rest).drop 8 := by
        refine ih _ (by omega) ?_
        omega
      show bytesToBits (bitsToNat ((b :: rest).take 8 ++
        List.replicate (8 - ((b :: rest).take 8).length) false) ::
        bitsToBytesAux f ((b :: rest).drop 8)) = b :: rest
      rw [hpad]
      simp only [List.replicate, List.append_nil, bytesToBits, hbit, hrest]
      exact List.take_append_drop 8 (b :: rest)

theorem bits_to_bytes_roundtrip (bs : List Bool) (h : bs.length % 8 = 0) :
    bytesToBits (bitsToBytes bs) = bs :=
  bits_to_bytes_aux_roundtrip bs.length bs (Nat.le_refl _) h

theorem bits_to_bytes_length (bs : List Bool) (h : bs.length % 8 = 0) :
    (bitsToBytes bs).length = bs.length / 8 := by
  have h1 := bits_to_bytes_roundtrip bs h
  have h2 := bytes_to_bits_length (bitsToBytes bs)
  rw [h1] at h2
  omega

/-! ## Section 4: public-key codec (vendor/keys/public_key.rs)

`PublicKey` is a `Polynomial<FalconFelt>`; `write_into` emits `LOG_N` followed
by the 512 coefficients packed at 14 bits each, and `read_from` reads exactly
`PK_LEN` bytes, rejects a wrong `LOG_N` byte, rejects any 14-bit word that is
not a canonical field element (`w.try_into()`), and finally rejects non-zero
leftover bits. -/

inductive Err where
  | unexpectedEof
  | badHeader
  | nonCanonicalCoefficient
  | trailingBits
  | highBitsOverflow
  | minusZero
  | unsupportedDegree
  deriving DecidableEq, Repr

/-- Reads `k` words of `w` bits, rejecting non-canonical words, then requires
    the leftover bits to be zero. -/
def decodeCoeffs (w : Nat) : Nat → List Bool → Except Err (List Nat)
  | 0, bs => if bs.all (fun b => b == false) then .ok [] else .error .trailingBits
  | k + 1, bs =>
    if bs.length < w then .error .unexpectedEof
    else if bitsToNat (bs.take w) < falconQ then
      match decodeCoeffs w k (bs.drop w) with
      | .ok r => .ok (bitsToNat (bs.take w) :: r)
      | .error e => .error e
    else .error .nonCanonicalCoefficient

/-- Model of `Serializable for &PublicKey`. -/
def encodePublicKey (cs : List Nat) : List Nat :=
  falconLogN :: bitsToBytes (encodeBits falconEncodingBits cs)

/-- Model of `Deserializable for PublicKey`. -/
def decodePublicKey (buf : List Nat) : Except Err (List Nat) :=
  if buf.length ≠ pkLen then .error .unexpectedEof
  else if buf.getD 0 0 ≠ falconLogN then .error .badHeader
  else decodeCoeffs falconEncodingBits falconN (bytesToBits (buf.drop 1))

theorem take_of_nat_to_bits_append (w c : Nat) (rest : List Bool) :
    (natToBits w c ++ rest).take w = natToBits w c := by
  have h : (natToBits w c ++ rest).take (natToBits w c).length = natToBits w c :=
    List.take_left _ _
  rw [nat_to_bits_length] at h
  exact h

theorem drop_of_nat_to_bits_append (w c : Nat) (rest : List Bool) :
    (natToBits w c ++ rest).drop w = rest := by
  have h : (natToBits w c ++ rest).drop (natToBits w c).length = rest :=
    List.drop_left _ _
  rw [nat_to_bits_length] at h
  exact h

theorem decode_coeffs_of_encode_bits :
    ∀ cs : List Nat, (∀ c ∈ cs, c < falconQ) →
      decodeCoeffs falconEncodingBits cs.length (encodeBits falconEncodingBits cs) = .ok cs := by
  intro cs
  induction cs with
  | nil => intro _; rfl
  | cons c cs ih =>
    intro hc
    have hcq : c < falconQ := hc c (by simp)
    have hlt : c < 2 ^ falconEncodingBits := by
      have : falconQ < 2 ^ falconEncodingBits := by decide
      omega
    have hnotlt : ¬ ((natToBits falconEncodingBits c ++ encodeBits falconEncodingBits cs).length
        < falconEncodingBits) := by
      rw [List.length_append, nat_to_bits_length]
      omega
    have hrec : decodeCoeffs falconEncodingBits cs.length (encodeBits falconEncodingBits cs)
        = .ok cs := ih (fun x hx => hc x (by simp [hx]))
    show decodeCoeffs falconEncodingBits (cs.length + 1)
      (natToBits falconEncodingBits c ++ encodeBits falconEncodingBits cs) = .ok (c :: cs)
    rw [decodeCoeffs]
    rw [if_neg hnotlt]
    simp only [take_of_nat_to_bits_append, drop_of_nat_to_bits_append,
      bits_to_nat_of_nat_to_bits_of_lt _ _ hlt, if_pos hcq, hrec]

/-- The public-key wire format round-trips for any canonical coefficient vector
    of the right length. -/
theorem pubkey_encode_decode_roundtrip (cs : List Nat)
    (hlen : cs.length = falconN) (hc : ∀ c ∈ cs, c < falconQ) :
    decodePublicKey (encodePublicKey cs) = .ok cs := by
  have hbits : (encodeBits falconEncodingBits cs).length = 7168 := by
    rw [encode_bits_length, hlen]; rfl
  have hmod : (encodeBits falconEncodingBits cs).length % 8 = 0 := by rw [hbits]
  have hbytes : (bitsToBytes (encodeBits falconEncodingBits cs)).length = 896 := by
    rw [bits_to_bytes_length _ hmod, hbits]
  have hlen897 : (encodePublicKey cs).length = pkLen := by
    simp only [encodePublicKey, List.length_cons, hbytes]; rfl
  have hround := bits_to_bytes_roundtrip (encodeBits falconEncodingBits cs) hmod
  simp only [decodePublicKey, if_neg (by omega : ¬ (encodePublicKey cs).length ≠ pkLen)]
  simp only [encodePublicKey, List.getD_cons_zero, List.drop_succ_cons, List.drop_zero,
    if_neg (by omega : ¬ falconLogN ≠ falconLogN), hround]
  rw [← hlen]
  exact decode_coeffs_of_encode_bits cs hc

/-- Successful public-key decoding yields exactly `N` canonical coefficients. -/
theorem decode_coeffs_ok_canonical :
    ∀ (k : Nat) (bs : List Bool) (cs : List Nat),
      decodeCoeffs falconEncodingBits k bs = .ok cs → cs.length = k ∧ ∀ c ∈ cs, c < falconQ := by
  intro k
  induction k with
  | zero =>
    intro bs cs h
    rw [decodeCoeffs] at h
    split at h
    · injection h with h; subst h; exact ⟨rfl, by simp⟩
    · exact absurd h (by simp)
  | succ k ih =>
    intro bs cs h
    rw [decodeCoeffs] at h
    by_cases hlen : bs.length < falconEncodingBits
    · rw [if_pos hlen] at h; exact absurd h (by simp)
    rw [if_neg hlen] at h
    by_cases hcanon : bitsToNat (bs.take falconEncodingBits) < falconQ
    · rw [if_pos hcanon] at h
      cases hd : decodeCoeffs falconEncodingBits k (bs.drop falconEncodingBits) with
      | error e => rw [hd] at h; exact absurd h (by simp)
      | ok r =>
        rw [hd] at h
        injection h with h
        subst h
        have hrec := ih (bs.drop falconEncodingBits) r hd
        refine ⟨by simp [hrec.1], ?_⟩
        intro c hcmem
        rcases List.mem_cons.mp hcmem with h1 | h1
        · subst h1; exact hcanon
        · exact hrec.2 c h1
    · rw [if_neg hcanon] at h; exact absurd h (by simp)

theorem pubkey_decode_ok_canonical (buf : List Nat) (cs : List Nat)
    (h : decodePublicKey buf = .ok cs) : cs.length = falconN ∧ ∀ c ∈ cs, c < falconQ := by
  simp only [decodePublicKey] at h
  split at h
  · exact absurd h (by simp)
  · split at h
    · exact absurd h (by simp)
    · exact decode_coeffs_ok_canonical falconN _ cs h

/-! ## Section 5: secret-key codec (vendor/keys/secret_key.rs)

`encode_i8` / `decode_i8` are the same bit accumulator at widths 6 (for f, g)
and 8 (for F). Coefficients are stored as the low `bits` bits of the two's
complement value; `decode_i8` maps a word `w` back to `w - 2^bits` when
`w > 2^(bits-1) - 1`. -/

/-- `2^(bits-1)`, the half range of the signed coefficient window. -/
def halfRange (bits : Nat) : Nat := 2 ^ (bits - 1)

/-- Model of the `encode_i8` bound check (`|x| <= 2^(bits-1) - 1`). -/
def encodeI8Accepts (bits : Nat) (z : Int) : Bool :=
  decide (-((halfRange bits : Nat) : Int) + 1 ≤ z ∧ z + 1 ≤ ((halfRange bits : Nat) : Int))

/-- Model of one `decode_i8` word (`w > 2^(bits-1) - 1` is `2^(bits-1) <= w`). -/
def decodeI8Word (bits w : Nat) : Int :=
  if halfRange bits ≤ w then (w : Int) - ((2 ^ bits : Nat) : Int) else (w : Int)

/-- Model of one `encode_i8` word (`c as u8 & mask`). -/
def encodeI8Word (bits : Nat) (z : Int) : Nat := (z % (2 ^ bits : Nat)).toNat

theorem two_pow_pos (k : Nat) : 0 < 2 ^ k := by
  induction k with
  | zero => decide
  | succ n ih => rw [Nat.pow_succ]; omega

theorem decode_i8_inverts_encode_i8 (bits : Nat) (z : Int)
    (hb : 1 ≤ bits) (h : encodeI8Accepts bits z = true) :
    decodeI8Word bits (encodeI8Word bits z) = z := by
  have hpow : (2 : Nat) ^ bits = 2 * halfRange bits := by
    cases bits with
    | zero => omega
    | succ n => simp [halfRange, Nat.pow_succ, Nat.mul_comm]
  have h1 : 0 < halfRange bits := two_pow_pos _
  have _hM : ((2 ^ bits : Nat) : Int) = 2 * ((halfRange bits : Nat) : Int) := by
    exact_mod_cast hpow
  simp only [encodeI8Accepts, decide_eq_true_eq] at h
  by_cases hz : 0 ≤ z
  · have hr : z % ((2 ^ bits : Nat) : Int) = z := Int.emod_eq_of_lt hz (by omega)
    have htn : ((z.toNat : Nat) : Int) = z := Int.toNat_of_nonneg hz
    simp only [encodeI8Word, decodeI8Word, hr]
    rw [if_neg (by omega)]
    omega
  · have hlow : (0 : Int) ≤ z + ((2 ^ bits : Nat) : Int) := by omega
    have hhigh : z + ((2 ^ bits : Nat) : Int) < ((2 ^ bits : Nat) : Int) := by omega
    have hshift : (z + ((2 ^ bits : Nat) : Int)) % ((2 ^ bits : Nat) : Int)
        = z % ((2 ^ bits : Nat) : Int) := by simp
    have hr : z % ((2 ^ bits : Nat) : Int) = z + ((2 ^ bits : Nat) : Int) := by
      rw [← hshift, Int.emod_eq_of_lt hlow hhigh]
    have htn : (((z + ((2 ^ bits : Nat) : Int)).toNat : Nat) : Int) = z + ((2 ^ bits : Nat) : Int) :=
      Int.toNat_of_nonneg hlow
    simp only [encodeI8Word, decodeI8Word, hr]
    rw [if_pos (by omega)]
    omega

/-- SECURITY / asymmetry: `decode_i8` accepts one word per width that
    `encode_i8` refuses to re-encode (`-2^(bits-1)`). A `SecretKey`
    deserialized with such a coefficient panics inside the `encode_i8(..)
    .unwrap()` of `write_into`, and therefore inside `PartialEq` (which
    compares `to_bytes()`). -/
theorem secret_key_decode_range_exceeds_encode_range :
    decodeI8Word widthSmallPolyCoefficient 32 = -32 ∧
    encodeI8Accepts widthSmallPolyCoefficient (-32) = false ∧
    decodeI8Word widthBigPolyCoefficient 128 = -128 ∧
    encodeI8Accepts widthBigPolyCoefficient (-128) = false := by decide

/-- `decode_i8` consumes exactly `ceil(N * bits / 8)` bytes and ends with an
    empty accumulator, so its `acc & ((1 << acc_len) - 1) == 0` test is
    vacuously true and it can never return `None` at these widths. This is why
    the two `.unwrap()` calls in `SecretKey::read_from` cannot trip. -/
theorem decode_i8_never_rejects_at_falcon_widths :
    falconN * widthSmallPolyCoefficient % 8 = 0 ∧
    falconN * widthBigPolyCoefficient % 8 = 0 ∧
    (falconN * widthSmallPolyCoefficient + 7) / 8 * 8 = falconN * widthSmallPolyCoefficient ∧
    (falconN * widthBigPolyCoefficient + 7) / 8 * 8 = falconN * widthBigPolyCoefficient := by
  decide

/-- The `ntru_gen` coefficient bound checks are exactly the ranges `encode_i8`
    accepts, so a key that passes key generation is always serializable. -/
theorem keygen_small_bound_matches_encode_i8 (z : Int) :
    encodeI8Accepts widthSmallPolyCoefficient z = true ↔
      (-(maxSmallPolyCoefficient : Int) ≤ z ∧ z ≤ (maxSmallPolyCoefficient : Int)) := by
  simp only [encodeI8Accepts, halfRange, widthSmallPolyCoefficient, maxSmallPolyCoefficient,
    decide_eq_true_eq, Nat.reducePow, Nat.reduceSub]
  omega

theorem keygen_big_bound_matches_encode_i8 (z : Int) :
    encodeI8Accepts widthBigPolyCoefficient z = true ↔
      (-(maxBigPolyCoefficient : Int) ≤ z ∧ z ≤ (maxBigPolyCoefficient : Int)) := by
  simp only [encodeI8Accepts, halfRange, widthBigPolyCoefficient, maxBigPolyCoefficient,
    decide_eq_true_eq, Nat.reducePow, Nat.reduceSub]
  omega

/-- Model of the `SecretKey::read_from` header checks. -/
def decodeSecretKeyHeader (header : Nat) : Except Err Nat :=
  if header / 16 ≠ secretKeyHeaderNibble then .error .badHeader
  else if 2 ^ (header % 16) ≠ falconN then .error .unsupportedDegree
  else .ok (2 ^ (header % 16))

theorem secret_key_header_accepts_only_degree_512 (header : Nat) (n : Nat)
    (h : decodeSecretKeyHeader header = .ok n) : n = falconN := by
  simp only [decodeSecretKeyHeader] at h
  split at h
  · exact absurd h (by simp)
  · split at h
    · exact absurd h (by simp)
    · injection h with h; omega

theorem secret_key_header_example : decodeSecretKeyHeader (5 * 16 + 9) = .ok 512 := by rfl

/-! ## Section 6: compressed signature codec (vendor/signature.rs)

`SignaturePoly`'s `Deserializable` is Falcon Algorithm 18: for each of the 512
coefficients, one sign bit, seven low bits, then a unary-coded high part
terminated by a set bit. The vendored copy carries a LOCAL fix on top of
upstream (marked `SECURITY (F-1)`): both accumulator reads are bounds-checked
against `SIG_POLY_BYTE_LEN` and fail with `UnexpectedEof` instead of indexing
out of range (upstream panics, which under `panic = "abort"` is a remote kill).
The `acc` accumulator is a wrapping `u32`; only its low bits are ever read,
which the `% u32Mod` below reproduces. -/

structure SigDecState where
  idx : Nat
  acc : Nat
  accLen : Nat
  deriving DecidableEq, Repr

def sigByte (input : List Nat) (i : Nat) : Nat := input.getD i 0

/-- The `if acc_len == 0 { ... }` refill inside the unary loop, with the F-1
    bounds check. -/
def sigRefill (input : List Nat) (st : SigDecState) : Except Err SigDecState :=
  if st.accLen = 0 then
    if sigPolyByteLen ≤ st.idx then .error .unexpectedEof
    else .ok { idx := st.idx + 1, acc := (st.acc * 256 + sigByte input st.idx) % u32Mod,
               accLen := 8 }
  else .ok st

/-- The unary high-bits loop. `fuel` is an upper bound on the number of
    iterations; see `sig_unary_fuel_is_unreachable`. -/
def sigUnaryLoop (input : List Nat) : Nat → Nat → SigDecState → Except Err (Nat × SigDecState)
  | 0, _, _ => .error .highBitsOverflow
  | f + 1, m, st =>
    match sigRefill input st with
    | .error e => .error e
    | .ok st1 =>
      if st1.acc / 2 ^ (st1.accLen - 1) % 2 = 1 then
        .ok (m, { st1 with accLen := st1.accLen - 1 })
      else if 2048 ≤ m + 128 then .error .highBitsOverflow
      else sigUnaryLoop input f (m + 128) { st1 with accLen := st1.accLen - 1 }

def sigUnaryFuel : Nat := 17

/-- Tail of one coefficient: run the unary loop, reject `-0`, rebuild the
    canonical field element. -/
def decodeSigCoeffFrom (input : List Nat) (s m0 : Nat) (st1 : SigDecState) :
    Except Err (Nat × SigDecState) :=
  match sigUnaryLoop input sigUnaryFuel m0 st1 with
  | .error e => .error e
  | .ok (m, st2) =>
    if s = 1 ∧ m = 0 then .error .minusZero
    else .ok (if s = 1 then falconQ - m else m, st2)

/-- One coefficient of Algorithm 18. -/
def decodeSigCoeff (input : List Nat) (st : SigDecState) : Except Err (Nat × SigDecState) :=
  if sigPolyByteLen ≤ st.idx then .error .unexpectedEof
  else
    decodeSigCoeffFrom input
      ((st.acc * 256 + sigByte input st.idx) % u32Mod / 2 ^ st.accLen / 128 % 2)
      ((st.acc * 256 + sigByte input st.idx) % u32Mod / 2 ^ st.accLen % 128)
      { idx := st.idx + 1, acc := (st.acc * 256 + sigByte input st.idx) % u32Mod,
        accLen := st.accLen }

def decodeSigCoeffs (input : List Nat) : Nat → SigDecState → Except Err (List Nat × SigDecState)
  | 0, st => .ok ([], st)
  | k + 1, st =>
    match decodeSigCoeff input st with
    | .error e => .error e
    | .ok (c, st1) =>
      match decodeSigCoeffs input k st1 with
      | .error e => .error e
      | .ok (cs, st2) => .ok (c :: cs, st2)

/-- Model of `Deserializable for SignaturePoly`. -/
def decodeSignaturePoly (input : List Nat) : Except Err (List Nat) :=
  if input.length ≠ sigPolyByteLen then .error .unexpectedEof
  else
    match decodeSigCoeffs input falconN { idx := 0, acc := 0, accLen := 0 } with
    | .error e => .error e
    | .ok (cs, st) => if st.acc % 2 ^ st.accLen ≠ 0 then .error .trailingBits else .ok cs

/-- The `m >= 2048` guard fires no later than the 16th unary iteration, so the
    fuel of `sigUnaryFuel = 17` in the model never truncates a run the source
    would have accepted. -/
theorem sig_unary_fuel_is_unreachable (m0 : Nat) (h : m0 ≤ 127) :
    2048 ≤ m0 + 128 * (sigUnaryFuel - 1) := by
  simp only [sigUnaryFuel]
  omega

theorem sig_unary_loop_m_bound (input : List Nat) :
    ∀ (f m : Nat) (st : SigDecState) (m' : Nat) (st' : SigDecState),
      m ≤ maxSigCoefficient → sigUnaryLoop input f m st = .ok (m', st') →
      m' ≤ maxSigCoefficient := by
  intro f
  induction f with
  | zero => intro m st m' st' _ h; exact absurd h (by simp [sigUnaryLoop])
  | succ f ih =>
    intro m st m' st' hm h
    rw [sigUnaryLoop] at h
    cases hrf : sigRefill input st with
    | error e => rw [hrf] at h; exact absurd h (by simp)
    | ok st1 =>
      rw [hrf] at h
      dsimp only at h
      by_cases hbit : st1.acc / 2 ^ (st1.accLen - 1) % 2 = 1
      · rw [if_pos hbit] at h
        simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨h1, _⟩ := h
        omega
      · rw [if_neg hbit] at h
        by_cases hov : 2048 ≤ m + 128
        · rw [if_pos hov] at h; exact absurd h (by simp)
        · rw [if_neg hov] at h
          exact ih (m + 128) _ m' st' (by simp only [maxSigCoefficient]; omega) h

/-- A decoded coefficient is either a small non-negative value or `q - m` for a
    small positive `m`: exactly the window Falcon's `are_coefficients_valid`
    accepts. -/
theorem decode_sig_coeff_from_range (input : List Nat) (s m0 : Nat) (st1 : SigDecState)
    (hm0 : m0 ≤ maxSigCoefficient) (c : Nat) (st2 : SigDecState)
    (h : decodeSigCoeffFrom input s m0 st1 = .ok (c, st2)) :
    c ≤ maxSigCoefficient ∨ (falconQ - maxSigCoefficient ≤ c ∧ c < falconQ) := by
  rw [decodeSigCoeffFrom] at h
  cases hu : sigUnaryLoop input sigUnaryFuel m0 st1 with
  | error e => rw [hu] at h; exact absurd h (by simp)
  | ok pr =>
    obtain ⟨m1, s1⟩ := pr
    rw [hu] at h
    dsimp only at h
    have hmb : m1 ≤ maxSigCoefficient :=
      sig_unary_loop_m_bound input sigUnaryFuel m0 st1 m1 s1 hm0 hu
    by_cases hz : s = 1 ∧ m1 = 0
    · rw [if_pos hz] at h; exact absurd h (by simp)
    · rw [if_neg hz] at h
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨h1, _⟩ := h
      by_cases hs : s = 1
      · rw [if_pos hs] at h1
        have hpos : m1 ≠ 0 := fun hcz => hz ⟨hs, hcz⟩
        right
        simp only [maxSigCoefficient, falconQ] at hmb h1 ⊢
        omega
      · rw [if_neg hs] at h1
        left
        omega

theorem decode_sig_coeff_range (input : List Nat) (st : SigDecState) (c : Nat)
    (st2 : SigDecState) (h : decodeSigCoeff input st = .ok (c, st2)) :
    c ≤ maxSigCoefficient ∨ (falconQ - maxSigCoefficient ≤ c ∧ c < falconQ) := by
  rw [decodeSigCoeff] at h
  by_cases hi : sigPolyByteLen ≤ st.idx
  · rw [if_pos hi] at h; exact absurd h (by simp)
  · rw [if_neg hi] at h
    refine decode_sig_coeff_from_range input _ _ _ ?_ c st2 h
    have hlt : (st.acc * 256 + sigByte input st.idx) % u32Mod / 2 ^ st.accLen % 128 < 128 :=
      Nat.mod_lt _ (by decide)
    simp only [maxSigCoefficient]
    omega

theorem decode_sig_coeffs_range (input : List Nat) :
    ∀ (k : Nat) (st : SigDecState) (cs : List Nat) (st' : SigDecState),
      decodeSigCoeffs input k st = .ok (cs, st') →
      ∀ c ∈ cs, c ≤ maxSigCoefficient ∨ (falconQ - maxSigCoefficient ≤ c ∧ c < falconQ) := by
  intro k
  induction k with
  | zero =>
    intro st cs st' h c hc
    rw [decodeSigCoeffs] at h
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨h1, _⟩ := h
    subst h1
    exact absurd hc (by simp)
  | succ k ih =>
    intro st cs st' h c hc
    rw [decodeSigCoeffs] at h
    cases h1 : decodeSigCoeff input st with
    | error e => rw [h1] at h; exact absurd h (by simp)
    | ok pr =>
      obtain ⟨c1, s1⟩ := pr
      rw [h1] at h
      dsimp only at h
      cases h2 : decodeSigCoeffs input k s1 with
      | error e => rw [h2] at h; exact absurd h (by simp)
      | ok r =>
        obtain ⟨cs2, st2⟩ := r
        rw [h2] at h
        dsimp only at h
        simp only [Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨h3, _⟩ := h
        subst h3
        rcases List.mem_cons.mp hc with h4 | h4
        · subst h4
          exact decode_sig_coeff_range input st _ _ h1
        · exact ih s1 cs2 st2 h2 c h4

/-- Every coefficient of a successfully decoded signature polynomial has a
    balanced value in `[-2047, 2047]`. -/
theorem decode_signature_poly_balanced_bound (input : List Nat) (cs : List Nat)
    (h : decodeSignaturePoly input = .ok cs) :
    ∀ c ∈ cs, -(maxSigCoefficient : Int) ≤ balancedValue c ∧
      balancedValue c ≤ (maxSigCoefficient : Int) := by
  intro c hc
  have hrange : c ≤ maxSigCoefficient ∨ (falconQ - maxSigCoefficient ≤ c ∧ c < falconQ) := by
    rw [decodeSignaturePoly] at h
    by_cases hl : input.length ≠ sigPolyByteLen
    · rw [if_pos hl] at h; exact absurd h (by simp)
    · rw [if_neg hl] at h
      cases hd : decodeSigCoeffs input falconN { idx := 0, acc := 0, accLen := 0 } with
      | error e => rw [hd] at h; exact absurd h (by simp)
      | ok pr =>
        obtain ⟨cs1, st1⟩ := pr
        rw [hd] at h
        dsimp only at h
        by_cases ht : st1.acc % 2 ^ st1.accLen ≠ 0
        · rw [if_pos ht] at h; exact absurd h (by simp)
        · rw [if_neg ht] at h
          simp only [Except.ok.injEq] at h
          subst h
          exact decode_sig_coeffs_range input falconN _ cs1 st1 hd c hc
  simp only [balancedValue, maxSigCoefficient, falconQ] at hrange ⊢
  split <;> omega

/-- SECURITY: the compressed decoder alone does NOT imply the Falcon norm
    bound. A blob whose 512 coefficients all decode to the extreme value 2047
    is accepted by `SignaturePoly::read_from` and has squared norm far above
    `beta^2`; the norm check is a separate obligation of the verifier
    (`falcon_sig::verify`), which the vendor tree no longer contains. -/
theorem decode_range_does_not_imply_norm_bound :
    sigL2Bound < falconN * (maxSigCoefficient * maxSigCoefficient) := by decide

/-- Model of `are_coefficients_valid` (the check `SignaturePoly::try_from`
    applies to the signer's own output). -/
def areCoefficientsValid (x : List Int) : Bool :=
  x.length == falconN &&
    x.all (fun c => decide (-(maxSigCoefficient : Int) ≤ c ∧ c ≤ (maxSigCoefficient : Int)))

theorem are_coefficients_valid_iff (x : List Int) :
    areCoefficientsValid x = true ↔
      x.length = falconN ∧ ∀ c ∈ x, -(maxSigCoefficient : Int) ≤ c ∧
        c ≤ (maxSigCoefficient : Int) := by
  simp [areCoefficientsValid]

/-- Positive example: two zero bytes then a set bit decode the coefficient 0. -/
theorem sig_decode_single_zero_coefficient :
    decodeSigCoeff [0, 128] { idx := 0, acc := 0, accLen := 0 }
      = .ok (0, { idx := 2, acc := 128, accLen := 7 }) := by rfl

/-- Negative example: a set sign bit with an empty high part is the forbidden
    `-0` encoding and is rejected. -/
theorem sig_decode_minus_zero_rejected :
    decodeSigCoeff [128, 128] { idx := 0, acc := 0, accLen := 0 } = .error .minusZero := by rfl

/-- Negative example: an all-zero buffer never terminates a unary run, so the
    high-bits guard rejects it. -/
theorem sig_decode_all_zero_rejected :
    decodeSigCoeff [] { idx := 0, acc := 0, accLen := 0 } = .error .highBitsOverflow := by rfl

/-- The F-1 bounds check really is reachable: a state positioned at the end of
    the buffer fails closed instead of indexing out of range. -/
theorem sig_decode_eof_guard :
    decodeSigCoeff [] { idx := sigPolyByteLen, acc := 0, accLen := 0 } = .error .unexpectedEof := by
  rfl

/-- Index list `[0, 1, ..., n-1]` (this Lean toolchain's `Std` carries no
    length lemma for `List.range`). -/
def idxList : Nat → List Nat
  | 0 => []
  | n + 1 => idxList n ++ [n]

theorem idx_list_length (n : Nat) : (idxList n).length = n := by
  induction n with
  | zero => rfl
  | succ n ih => simp [idxList, ih]

/-! ## Section 7: polynomials (vendor/math/polynomial.rs)

`Polynomial<F>` is a plain coefficient vector. Only the `Polynomial<FalconFelt>`
operations are integer arithmetic; the `Complex64` / `f64` instantiations are a
dependency boundary and are not modelled. -/

/-- `Polynomial::<FalconFelt>::norm_squared`, over balanced coefficient values. -/
def normSquared : List Nat → Nat
  | [] => 0
  | c :: cs => (balancedValue c).natAbs * (balancedValue c).natAbs + normSquared cs

/-- `Polynomial::<FalconFelt>::to_balanced_values`. -/
def toBalancedValues (cs : List Nat) : List Int := cs.map balancedValue

/-- `Polynomial::reduce_negacyclic`: `c[i] = (-a[N+i] + a[i]) mod q`. -/
def reduceNegacyclic (a : List Nat) : List Nat :=
  (idxList falconN).map (fun i =>
    ((falconQ - a.getD (falconN + i) 0 % falconQ) % falconQ + a.getD i 0 % falconQ) % falconQ)

/-- `Polynomial::degree` / `is_zero` (index of the last non-zero coefficient). -/
def degreeOf (cs : List Nat) : Option Nat :=
  match (cs.reverse.dropWhile (fun c => c == 0)).length with
  | 0 => none
  | k + 1 => some k

theorem norm_squared_bound :
    ∀ (cs : List Nat) (b : Nat), (∀ c ∈ cs, (balancedValue c).natAbs ≤ b) →
      normSquared cs ≤ cs.length * (b * b) := by
  intro cs
  induction cs with
  | nil => intro b _; simp [normSquared]
  | cons c cs ih =>
    intro b h
    have hc : (balancedValue c).natAbs ≤ b := h c (by simp)
    have hrec : normSquared cs ≤ cs.length * (b * b) := ih b (fun x hx => h x (by simp [hx]))
    have hsq : (balancedValue c).natAbs * (balancedValue c).natAbs ≤ b * b :=
      Nat.mul_le_mul hc hc
    simp only [normSquared, List.length_cons, Nat.succ_mul]
    omega

theorem reduce_negacyclic_length (a : List Nat) : (reduceNegacyclic a).length = falconN := by
  simp [reduceNegacyclic, idx_list_length]

theorem reduce_negacyclic_canonical (a : List Nat) :
    ∀ c ∈ reduceNegacyclic a, c < falconQ := by
  intro c hc
  simp only [reduceNegacyclic, List.mem_map] at hc
  obtain ⟨i, _, hi⟩ := hc
  rw [← hi]
  exact Nat.mod_lt _ (by decide)

/-- `Polynomial::mul_modulo_p` claims the un-reduced product stays below the
    host (Goldilocks) prime; with `N` terms of size `(q-1)^2` it does. -/
theorem mul_modulo_p_no_goldilocks_overflow :
    falconN * ((falconQ - 1) * (falconQ - 1)) < goldilocksP := by decide

theorem degree_of_zero_polynomial : degreeOf (List.replicate 4 0) = none := by decide
theorem degree_of_example : degreeOf [1, 0, 5, 0] = some 2 := by decide

/-- SECURITY / robustness note: `impl Div for Polynomial` writes
    `if self.is_zero() { Self::zero(); }` — an expression statement, not a
    return — and then calls `remainder.degree().unwrap()`, which is `none` for
    the zero polynomial. The zero numerator case is therefore a panic, not the
    zero quotient. The model records only that the degree is absent. -/
theorem poly_div_zero_numerator_has_no_degree : degreeOf ([] : List Nat) = none := by decide

/-! ## Section 8: hash-to-point (vendor/hash_to_point.rs)

This is the single intentional functional change of the vendor tree: an
overwrite-mode Poseidon sponge over Goldilocks with a non-zero capacity
constant. The permutation itself is an opaque callback (dependency boundary);
what is modelled is the sponge layout, the squeeze budget and the reduction of
each squeezed element modulo `q`.

NOTE (honesty): this construction performs NO rejection sampling. Each
coefficient consumes one full field element reduced modulo `q`, which is the
specification's sanctioned no-rejection variant; the resulting bias is bounded
by `q / p`, pinned below. -/

structure PoseidonPermutation where
  run : List Nat → List Nat
  lengthPreserved : ∀ s : List Nat, s.length = spongeWidth → (run s).length = spongeWidth

/-- One 5-byte little-endian salt chunk, as in `Nonce::to_elements`. -/
def nonceElement (bytes : List Nat) (i : Nat) : Nat :=
  bytes.getD (5 * i) 0 + bytes.getD (5 * i + 1) 0 * 256 + bytes.getD (5 * i + 2) 0 * 65536
    + bytes.getD (5 * i + 3) 0 * 16777216 + bytes.getD (5 * i + 4) 0 * 4294967296

def nonceToElements (bytes : List Nat) : List Nat :=
  (idxList nonceElements).map (nonceElement bytes)

/-- Rate = the salt elements, capacity = `[IMFH, 0, 0, 0]`. -/
def h2pInitialState (nonce : List Nat) : List Nat :=
  nonceToElements nonce ++ [domainFalconH2P, 0, 0, 0]

/-- Overwrite-mode absorption of the 8 message limbs into the rate. -/
def h2pAbsorbMessage (st msg : List Nat) : List Nat :=
  (idxList spongeWidth).map (fun i => if i < spongeRate then msg.getD i 0 else st.getD i 0)

def h2pSqueeze (P : PoseidonPermutation) : Nat → List Nat → List Nat
  | 0, _ => []
  | k + 1, st => (P.run st).take spongeRate ++ h2pSqueeze P k (P.run st)

/-- `felt_to_falcon_felt`. -/
def feltToFalconFelt (x : Nat) : Nat := x % falconQ

def hashToPoint (P : PoseidonPermutation) (msg nonce : List Nat) : List Nat :=
  (h2pSqueeze P squeezeRounds (h2pAbsorbMessage (P.run (h2pInitialState nonce)) msg)).map
    feltToFalconFelt

theorem nonce_to_elements_length (bytes : List Nat) :
    (nonceToElements bytes).length = nonceElements := by
  simp [nonceToElements, idx_list_length]

theorem h2p_initial_state_length (nonce : List Nat) :
    (h2pInitialState nonce).length = spongeWidth := by
  simp [h2pInitialState, nonce_to_elements_length, nonceElements, spongeWidth]


theorem h2p_absorb_message_length (st msg : List Nat) :
    (h2pAbsorbMessage st msg).length = spongeWidth := by
  simp [h2pAbsorbMessage, idx_list_length]

theorem h2p_squeeze_length (P : PoseidonPermutation) :
    ∀ (k : Nat) (st : List Nat), st.length = spongeWidth →
      (h2pSqueeze P k st).length = k * spongeRate := by
  intro k
  induction k with
  | zero => intro st _; simp [h2pSqueeze]
  | succ k ih =>
    intro st hst
    have hrun : (P.run st).length = spongeWidth := P.lengthPreserved st hst
    have htake : ((P.run st).take spongeRate).length = spongeRate := by
      rw [List.length_take, hrun]
      decide
    simp only [h2pSqueeze, List.length_append, htake, ih (P.run st) hrun, Nat.succ_mul]
    omega

/-- The sponge yields exactly `N` coefficients. -/
theorem hash_to_point_length (P : PoseidonPermutation) (msg nonce : List Nat) :
    (hashToPoint P msg nonce).length = falconN := by
  simp only [hashToPoint, List.length_map,
    h2p_squeeze_length P squeezeRounds _ (h2p_absorb_message_length _ _)]
  rfl

theorem hash_to_point_canonical (P : PoseidonPermutation) (msg nonce : List Nat) :
    ∀ c ∈ hashToPoint P msg nonce, c < falconQ := by
  intro c hc
  simp only [hashToPoint, List.mem_map] at hc
  obtain ⟨x, _, hx⟩ := hc
  rw [← hx]
  exact Nat.mod_lt _ (by decide)

/-- One full field element per coefficient, and no element reused. -/
theorem hash_to_point_squeeze_budget : squeezeRounds * spongeRate = falconN := by decide

/-- The bias of the no-rejection reduction is below `2^-50` per coefficient. -/
theorem hash_to_point_bias_below_two_pow_fifty : falconQ * 2 ^ 50 < goldilocksP := by decide

/-- The capacity domain separator is non-zero, unlike every other Poseidon
    sponge in the host crate. -/
theorem hash_to_point_capacity_is_domain_separated : domainFalconH2P ≠ 0 := by decide

/-- The 5-byte salt packing is injective (each chunk stays below `2^40`, which
    is below the Goldilocks modulus, so no wrap-around collides two salts). -/
theorem nonce_packing_injective
    (b0 b1 b2 b3 b4 c0 c1 c2 c3 c4 : Nat)
    (hb0 : b0 < 256) (hb1 : b1 < 256) (hb2 : b2 < 256) (hb3 : b3 < 256) (_hb4 : b4 < 256)
    (hc0 : c0 < 256) (hc1 : c1 < 256) (hc2 : c2 < 256) (hc3 : c3 < 256) (_hc4 : c4 < 256)
    (h : b0 + b1 * 256 + b2 * 65536 + b3 * 16777216 + b4 * 4294967296
       = c0 + c1 * 256 + c2 * 65536 + c3 * 16777216 + c4 * 4294967296) :
    b0 = c0 ∧ b1 = c1 ∧ b2 = c2 ∧ b3 = c3 ∧ b4 = c4 := by omega

theorem nonce_element_below_goldilocks
    (b0 b1 b2 b3 b4 : Nat)
    (hb0 : b0 < 256) (hb1 : b1 < 256) (hb2 : b2 < 256) (hb3 : b3 < 256) (hb4 : b4 < 256) :
    b0 + b1 * 256 + b2 * 65536 + b3 * 16777216 + b4 * 4294967296 < goldilocksP := by
  simp only [goldilocksP]
  omega

/-! ## Section 9: FFT index algebra (vendor/math/fft.rs)

`math/fft.rs` is 1917 lines, of which about 1550 are the three precomputed
`Complex64` / `FalconFelt` twiddle tables. The `Complex64` transforms are `f64`
arithmetic and are a dependency boundary. What is modelled here is the pure
integer index algebra (`bitreverse_index`, `bitreverse_array`) and the
`split_fft` / `merge_fft` butterflies over `FalconFelt`. -/

/-- `CyclotomicFourier::bitreverse_index(arg, 2^k)`. -/
def bitreverseIndex (k a : Nat) : Nat := bitsToNat (natToBitsLE k a)

theorem bitreverse_index_lt (k a : Nat) : bitreverseIndex k a < 2 ^ k := by
  have h := bits_to_nat_lt (natToBitsLE k a)
  rw [nat_to_bits_le_length] at h
  exact h

theorem bitreverse_index_involutive (k a : Nat) (h : a < 2 ^ k) :
    bitreverseIndex k (bitreverseIndex k a) = a := by
  have hl : (natToBitsLE k a).length = k := nat_to_bits_le_length k a
  have hr : (natToBitsLE k a).reverse.length = k := by rw [List.length_reverse, hl]
  have h1 : natToBitsLE k (bitsToNatLE (natToBitsLE k a).reverse) = (natToBitsLE k a).reverse := by
    have hx := nat_to_bits_le_of_bits_to_nat_le (natToBitsLE k a).reverse
    rw [hr] at hx
    exact hx
  simp only [bitreverseIndex, bitsToNat]
  rw [h1, List.reverse_reverse, bits_to_nat_le_of_nat_to_bits_le, Nat.mod_eq_of_lt h]

theorem bitreverse_index_example : bitreverseIndex falconLogN 1 = 256 := by decide

/-- `CyclotomicFourier::split_fft` over `FalconFelt`. -/
def splitFftFelt (psiInvRev f : List Nat) : List Nat × List Nat :=
  ((idxList (f.length / 2)).map (fun i =>
      feltMul feltTwoInv (feltAdd (f.getD (2 * i) 0) (f.getD (2 * i + 1) 0))),
   (idxList (f.length / 2)).map (fun i =>
      feltMul (feltMul feltTwoInv (psiInvRev.getD (f.length / 2 + i) 0))
        (feltSub (f.getD (2 * i) 0) (f.getD (2 * i + 1) 0))))

/-- `CyclotomicFourier::merge_fft` over `FalconFelt`. -/
def mergeFftFelt (psiRev f0 f1 : List Nat) : List Nat :=
  (idxList (2 * f0.length)).map (fun j =>
    if j % 2 = 0 then
      feltAdd (f0.getD (j / 2) 0) (feltMul (psiRev.getD (f0.length + j / 2) 0) (f1.getD (j / 2) 0))
    else
      feltSub (f0.getD (j / 2) 0) (feltMul (psiRev.getD (f0.length + j / 2) 0) (f1.getD (j / 2) 0)))

theorem split_fft_lengths (psiInvRev f : List Nat) :
    (splitFftFelt psiInvRev f).1.length = f.length / 2 ∧
    (splitFftFelt psiInvRev f).2.length = f.length / 2 := by
  constructor <;> simp [splitFftFelt, idx_list_length]

theorem merge_fft_length (psiRev f0 f1 : List Nat) :
    (mergeFftFelt psiRev f0 f1).length = 2 * f0.length := by
  simp [mergeFftFelt, idx_list_length]

/-- Positive example: with the vendored twiddle constants, `merge_fft` really
    inverts `split_fft` at length 2. -/
theorem split_merge_roundtrip_example :
    mergeFftFelt [1, 1479] (splitFftFelt [1, 10810] [3, 7]).1
      (splitFftFelt [1, 10810] [3, 7]).2 = [3, 7] := by decide

/-! ## Section 10: Gaussian sampler tables (vendor/math/samplerz.rs)

`approx_exp` and `ber_exp` are `f64` / fixed-point routines and are a
dependency boundary. `base_sampler` is pure integer arithmetic over the
reverse cumulative distribution table, and is modelled. -/

def rcdt : List Nat :=
  [3024686241123004913666, 1564742784480091954050, 636254429462080897535,
   199560484645026482916, 47667343854657281903, 8595902006365044063,
   1163297957344668388, 117656387352093658, 8867391802663976, 496969357462633,
   20680885154299, 638331848991, 14602316184, 247426747, 3104126, 28824, 198, 1]

/-- `base_sampler`: the number of table entries strictly above the drawn value. -/
def baseSampler (u : Nat) : Nat := (rcdt.filter (fun r => decide (u < r))).length

def isStrictlyDecreasing : List Nat → Bool
  | [] => true
  | [_] => true
  | a :: b :: t => decide (b < a) && isStrictlyDecreasing (b :: t)

theorem rcdt_length : rcdt.length = 18 := by decide
theorem rcdt_strictly_decreasing : isStrictlyDecreasing rcdt = true := by decide

theorem base_sampler_range (u : Nat) : baseSampler u ≤ 18 := by
  have h : (rcdt.filter (fun r => decide (u < r))).length ≤ rcdt.length :=
    List.length_filter_le _ _
  rw [rcdt_length] at h
  simp only [baseSampler]
  omega

theorem base_sampler_top_value : baseSampler 0 = 18 := by decide
theorem base_sampler_bottom_value : baseSampler 3024686241123004913666 = 0 := by decide

/-- `base_sampler` consumes 9 bytes into a `u128`; the value therefore stays
    below `2^72`, above the head of the table, so every table row is reachable. -/
theorem base_sampler_input_bound
    (b0 b1 b2 b3 b4 b5 b6 b7 b8 : Nat)
    (h0 : b0 < 256) (h1 : b1 < 256) (h2 : b2 < 256) (h3 : b3 < 256) (h4 : b4 < 256)
    (h5 : b5 < 256) (h6 : b6 < 256) (h7 : b7 < 256) (h8 : b8 < 256) :
    b0 + b1 * 256 + b2 * 65536 + b3 * 16777216 + b4 * 4294967296 + b5 * 1099511627776
      + b6 * 281474976710656 + b7 * 72057594037927936 + b8 * 18446744073709551616
      < 2 ^ 72 := by
  omega

/-! ## Section 11: native key generation and signing (vendor/math/mod.rs,
vendor/keys/secret_key.rs)

`ntru_gen` and `sign_helper` are rejection loops driven by `f64` Gram-Schmidt
norms and by the `f64` fast-Fourier Gaussian sampler. Neither the floating
point arithmetic nor the NTRU equation is modelled; what is recorded is the
shape of the acceptance conditions the loops enforce before returning. -/

/-- `babai_reduce` gives up after this many iterations and key generation
    restarts with fresh randomness. -/
def babaiIterationCap : Nat := 1000
theorem babai_iteration_cap_pinned : babaiIterationCap = 1000 := rfl

/-- `gamma > 1.3689 * (MODULUS as f64)` rejects the sampled `(f, g)`; the bound
    is pinned here in units of `1/10000`. -/
def gramSchmidtBoundScaled : Nat := 13689 * falconQ
theorem gram_schmidt_bound_pinned : gramSchmidtBoundScaled = 168224121 := by decide

/-- The integer part of what `ntru_gen` guarantees about its output. The NTRU
    equation `f*G - g*F = q`, the invertibility of `FFT(f)` and the
    Gram-Schmidt bound are `f64` / algebraic obligations kept as premises. -/
structure NtruGenAccepted where
  f : List Int
  g : List Int
  bigF : List Int
  bigG : List Int
  fBound : ∀ c ∈ f, -(maxSmallPolyCoefficient : Int) ≤ c ∧ c ≤ (maxSmallPolyCoefficient : Int)
  gBound : ∀ c ∈ g, -(maxSmallPolyCoefficient : Int) ≤ c ∧ c ≤ (maxSmallPolyCoefficient : Int)
  bigFBound : ∀ c ∈ bigF, -(maxBigPolyCoefficient : Int) ≤ c ∧ c ≤ (maxBigPolyCoefficient : Int)
  bigGBound : ∀ c ∈ bigG, -(maxBigPolyCoefficient : Int) ≤ c ∧ c ≤ (maxBigPolyCoefficient : Int)

/-- Everything key generation returns is encodable, so `SecretKey::write_into`
    cannot hit its `encode_i8(..).unwrap()` panic on a freshly generated key. -/
theorem ntru_gen_output_is_encodable (k : NtruGenAccepted) :
    (∀ c ∈ k.f, encodeI8Accepts widthSmallPolyCoefficient c = true) ∧
    (∀ c ∈ k.g, encodeI8Accepts widthSmallPolyCoefficient c = true) ∧
    (∀ c ∈ k.bigF, encodeI8Accepts widthBigPolyCoefficient c = true) ∧
    (∀ c ∈ k.bigG, encodeI8Accepts widthBigPolyCoefficient c = true) := by
  refine ⟨fun c hc => ?_, fun c hc => ?_, fun c hc => ?_, fun c hc => ?_⟩
  · exact (keygen_small_bound_matches_encode_i8 c).mpr (k.fBound c hc)
  · exact (keygen_small_bound_matches_encode_i8 c).mpr (k.gBound c hc)
  · exact (keygen_big_bound_matches_encode_i8 c).mpr (k.bigFBound c hc)
  · exact (keygen_big_bound_matches_encode_i8 c).mpr (k.bigGBound c hc)

/-- What `SecretKey::sign_helper` guarantees about its own output: the two
    rejection tests it leaves the loop on. The squared norm is computed in
    `f64` from the FFT representation and is carried here as a number, not
    recomputed. -/
structure NativeSignature where
  s2 : List Int
  coefficientsValid : areCoefficientsValid s2 = true
  normSquaredEstimate : Nat
  normAccepted : normSquaredEstimate ≤ sigL2Bound

theorem native_signature_coefficients_bounded (sg : NativeSignature) :
    sg.s2.length = falconN ∧
      ∀ c ∈ sg.s2, -(maxSigCoefficient : Int) ≤ c ∧ c ≤ (maxSigCoefficient : Int) :=
  (are_coefficients_valid_iff sg.s2).mp sg.coefficientsValid

/-- The vendored signer's own norm test is the same `<= beta^2` predicate the
    host verifier applies; the vendored tree itself contains NO verifier
    (`Signature::verify` and `PublicKey::verify` were removed), so nothing in
    this file re-checks `s1 = c - s2*h`. -/
theorem native_signature_norm_within_bound (sg : NativeSignature) :
    sg.normSquaredEstimate ≤ sigL2Bound := sg.normAccepted

/-- A concrete non-vacuous native signature witness: the all-zero polynomial
    passes `are_coefficients_valid` and the norm test. -/
def exampleNativeSignature : NativeSignature where
  s2 := List.replicate falconN 0
  coefficientsValid := (are_coefficients_valid_iff _).mpr
    ⟨by simp, fun c hc => by
      have hz := List.eq_of_mem_replicate hc
      subst hz
      simp only [maxSigCoefficient]
      omega⟩
  normSquaredEstimate := 0
  normAccepted := by decide

theorem example_native_signature_length : exampleNativeSignature.s2.length = falconN := by
  simp [exampleNativeSignature]

/-- Positive example: the public-key codec round-trips a concrete key. -/
theorem pubkey_roundtrip_example :
    decodePublicKey (encodePublicKey (List.replicate falconN 5))
      = .ok (List.replicate falconN 5) := by
  refine pubkey_encode_decode_roundtrip _ (by simp) ?_
  intro c hc
  have := List.eq_of_mem_replicate hc
  subst this
  decide

end Zkp.Implementation.FalconVendor
