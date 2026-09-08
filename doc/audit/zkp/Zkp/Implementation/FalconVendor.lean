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
  have hM : ((2 ^ bits : Nat) : Int) = 2 * ((halfRange bits : Nat) : Int) := by
    exact_mod_cast hpow
  simp only [encodeI8Accepts, decide_eq_true_eq] at h
  by_cases hz : 0 ≤ z
  · have hr : z % ((2 ^ bits : Nat) : Int) = z := Int.emod_eq_of_lt hz (by omega)
    simp only [encodeI8Word, decodeI8Word, hr]
    rw [if_neg (by omega)]
    omega
  · have hlow : (0 : Int) ≤ z + ((2 ^ bits : Nat) : Int) := by omega
    have hhigh : z + ((2 ^ bits : Nat) : Int) < ((2 ^ bits : Nat) : Int) := by omega
    have hshift : (z + ((2 ^ bits : Nat) : Int)) % ((2 ^ bits : Nat) : Int)
        = z % ((2 ^ bits : Nat) : Int) := by
      have hx := Int.add_mul_emod_self_left (a := z) (b := ((2 ^ bits : Nat) : Int)) (c := 1)
      simpa using hx
    have hr : z % ((2 ^ bits : Nat) : Int) = z + ((2 ^ bits : Nat) : Int) := by
      rw [← hshift, Int.emod_eq_of_lt hlow hhigh]
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

end Zkp.Implementation.FalconVendor
