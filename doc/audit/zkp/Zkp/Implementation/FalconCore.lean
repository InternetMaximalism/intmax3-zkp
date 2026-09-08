import Std

/-!
# Falcon-512 signature core: wire format, native verification, in-circuit gadget

Handwritten source-oriented semantics of `src/falcon_sig/mod.rs`,
`src/falcon_sig/gadget.rs` and `src/falcon_sig/compat.rs`. This is a MODEL, not a
refinement proof of the Rust, of plonky2 circuit lowering, or of the vendored
Falcon math under `src/falcon_sig/vendor/`. Nothing here certifies that the shipped
binary behaves as modelled.

What is modelled concretely:

* the wire constants (version byte, 40-byte salt, 625-byte compressed `s2`,
  666-byte signature, 1024-byte public polynomial, 1690-byte cosign blob) and the
  arithmetic that ties them together;
* the Golomb-Rice compressed `s2` codec of `vendor/signature.rs` at bit level —
  1 sign bit, 7 low bits, unary high bits, terminator — together with EVERY check
  the decoder performs: buffer exhaustion, the `high bits >= 2048` rejection, the
  `-0` rejection, and the non-zero-unused-bits rejection;
* `FalconSignature::from_bytes` including its re-encoding canonicity check, and
  `encode_cosign_blob` / `decode_cosign_blob` including the per-coefficient `< q`
  gate, in the SOURCE ORDER of checks (version, then length, then structure);
* the `encode(h)` 14-bit-lane packing and the 40-byte-salt -> 8-element packing,
  with their injectivity arguments;
* the norm predicate `||(s1, s2)||^2 <= beta^2` over centered coefficients, its
  inclusive boundary, and its no-field-wrap bound;
* the gadget's mod-q decomposition primitive, its canonical-coefficient gate, the
  free centering bit, and the 26-bit slack range check, plus a comparison of the
  circuit's gate set against the native check list.

NAMED BOUNDARIES (assumed, never proved here):

* `LatticeHardness` — NTRU/GPV unforgeability. Nothing below says a signature that
  passes the norm bound was produced by the key holder.
* `HashEnvironment.poseidon` — an opaque callback. Poseidon collision/preimage
  resistance is NOT assumed; identity-binding statements carry an explicit
  injectivity premise on the concrete compared pair.
* `HashEnvironment.hashToPoint` — the `IMFH`-domained Poseidon sponge of
  `vendor/hash_to_point.rs` is an opaque function of (salt, message digest); its
  uniformity, its bias bound and its in-circuit mirror are not modelled.
* `PolynomialProduct.mul` — the negacyclic product in `Z_q[X]/(X^512+1)`. The
  native path computes it with a floating-point-free exact NTT (`FastFft`), the
  circuit with a range-checked in-circuit NTT; that both equal the schoolbook
  product is a boundary, not a theorem here.
* keygen (`SecretKey::with_rng`, the ChaCha20 seed derivation), the trapdoor
  sampler, salt freshness, and zeroization are outside the model entirely.

Everything about SOUNDNESS of the plonky2 proof system, about gate lowering, and
about consumers wiring the gadget's `message_digest` / `verify` inputs correctly is
likewise assumed away and named in the line maps.
-/

namespace Zkp.Implementation.FalconCore

/-! ## 1. Pinned constants -/

/-- Falcon-512 ring degree (`vendor::N`, `FALCON_N`). -/
def falconN : Nat := 512

/-- Falcon-512 modulus `q` (`vendor::MODULUS`, `FALCON_Q`). -/
def falconQ : Nat := 12289

/-- Salt / nonce length in bytes (`vendor::SIG_NONCE_LEN`). -/
def sigNonceLen : Nat := 40

/-- Padded compressed-`s2` field length in bytes (`vendor::SIG_POLY_BYTE_LEN`). -/
def sigPolyByteLen : Nat := 625

/-- Version byte of the v1 wire format (`FALCON_SIG_V1`). -/
def falconSigV1 : Nat := 1

/-- `FALCON_SIG_BYTES = 1 + 40 + 625`. -/
def falconSigBytes : Nat := 1 + sigNonceLen + sigPolyByteLen

/-- `FALCON_PK_H_BYTES = 2 * 512`. -/
def falconPkHBytes : Nat := 2 * falconN

/-- `FALCON_COSIGN_BLOB_BYTES = 666 + 1024`. -/
def falconCosignBlobBytes : Nat := falconSigBytes + falconPkHBytes

/-- `FALCON_SIG_L2_BOUND = beta^2`. -/
def falconSigL2Bound : Nat := 34034726

/-- Transport band of a compressed `s2` coefficient (`are_coefficients_valid`). -/
def s2CoeffBand : Nat := 2047

/-- Largest centered magnitude of a canonical residue: `q / 2 = 6144`. -/
def maxCenteredMagnitude : Nat := 6144

def domainFalconH2P : Nat := 0x494d4648
def domainFalconPk : Nat := 0x494d464b
def domainFalconKeygen : Nat := 0x494d4647
def domainFalconBatch : Nat := 0x494d4642

/-- Goldilocks prime `p = 2^64 - 2^32 + 1` (`compat::Felt`). -/
def fieldModulus : Nat := 18446744069414584321

/-- `2^32 mod q` (`gadget::POW32_MOD_Q`). -/
def pow32ModQ : Nat := 10952

/-- Primitive 1024-th root of unity mod q used by the in-circuit NTT. -/
def ntoPsi : Nat := 49

/-- `512^{-1} mod q` (`gadget::N_INV`). -/
def ntoNInv : Nat := 12265

theorem falcon_n_pinned : falconN = 512 := rfl
theorem falcon_q_pinned : falconQ = 12289 := rfl
theorem sig_nonce_len_pinned : sigNonceLen = 40 := rfl
theorem sig_poly_byte_len_pinned : sigPolyByteLen = 625 := rfl
theorem falcon_sig_v1_pinned : falconSigV1 = 1 := rfl
theorem falcon_sig_l2_bound_pinned : falconSigL2Bound = 34034726 := rfl
theorem s2_coeff_band_pinned : s2CoeffBand = 2047 := rfl
theorem domain_falcon_h2p_pinned : domainFalconH2P = 0x494d4648 := rfl
theorem domain_falcon_pk_pinned : domainFalconPk = 0x494d464b := rfl
theorem domain_falcon_keygen_pinned : domainFalconKeygen = 0x494d4647 := rfl
theorem domain_falcon_batch_pinned : domainFalconBatch = 0x494d4642 := rfl
theorem pow32_mod_q_pinned : pow32ModQ = 10952 := rfl
theorem nto_psi_pinned : ntoPsi = 49 := rfl
theorem nto_n_inv_pinned : ntoNInv = 12265 := rfl

/-- The bare v1 signature is exactly 666 bytes. -/
theorem falcon_sig_bytes_pinned : falconSigBytes = 666 := rfl

/-- The transported public polynomial is exactly 1024 bytes (512 x u16-LE). -/
theorem falcon_pk_h_bytes_pinned : falconPkHBytes = 1024 := rfl

/-- SECURITY (fund safety): the COSIGN transport blob length is exactly 1690 bytes,
matching the `falconCosignBlobBytes` value pinned independently in the
`Zkp.Implementation.ChannelTypes` model of the structural signature checks. -/
theorem falcon_cosign_blob_bytes_pinned : falconCosignBlobBytes = 1690 := rfl

/-- The blob length is the sum of its two documented pieces, not an independent literal. -/
theorem falcon_cosign_blob_bytes_decomposes :
    falconCosignBlobBytes = (1 + sigNonceLen + sigPolyByteLen) + 2 * falconN := rfl

/-- The four Falcon domain constants are pairwise distinct (`falcon_domains_do_not_collide`,
the new-vs-new half; collision against the wider registry is not modelled here). -/
theorem falcon_domains_pairwise_distinct :
    domainFalconH2P ≠ domainFalconPk ∧ domainFalconH2P ≠ domainFalconKeygen ∧
    domainFalconH2P ≠ domainFalconBatch ∧ domainFalconPk ≠ domainFalconKeygen ∧
    domainFalconPk ≠ domainFalconBatch ∧ domainFalconKeygen ≠ domainFalconBatch := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;> decide

/-! ## 2. Bits and bytes

The compressed `s2` field is a bit stream packed MSB-first into bytes. The Rust
decoder is byte-paced (`acc`/`acc_len`); at the level that matters for the checks it
is exactly a bit reader, which is how it is modelled. -/

def bv (b : Bool) : Nat := if b then 1 else 0

theorem bv_lt_two (b : Bool) : bv b < 2 := by cases b <;> decide

theorem bv_decide_mod_two (x : Nat) : bv (decide (x % 2 = 1)) = x % 2 := by
  rcases Nat.mod_two_eq_zero_or_one x with h | h <;> simp [bv, h]

/-- The 8 bits of a byte, most significant first. -/
def byteBits (x : Nat) : List Bool :=
  [decide (x / 128 % 2 = 1), decide (x / 64 % 2 = 1), decide (x / 32 % 2 = 1),
   decide (x / 16 % 2 = 1), decide (x / 8 % 2 = 1), decide (x / 4 % 2 = 1),
   decide (x / 2 % 2 = 1), decide (x % 2 = 1)]

def packByte (b7 b6 b5 b4 b3 b2 b1 b0 : Bool) : Nat :=
  128 * bv b7 + 64 * bv b6 + 32 * bv b5 + 16 * bv b4 + 8 * bv b3 + 4 * bv b2 +
    2 * bv b1 + bv b0

/-- Groups a bit stream into bytes, MSB first; a trailing partial group is dropped
(the encoder never produces one: it always pads to a whole number of bytes). -/
def bitsToBytes : List Bool → List Nat
  | b7 :: b6 :: b5 :: b4 :: b3 :: b2 :: b1 :: b0 :: rest =>
      packByte b7 b6 b5 b4 b3 b2 b1 b0 :: bitsToBytes rest
  | _ => []

def bytesToBits : List Nat → List Bool
  | [] => []
  | x :: xs => byteBits x ++ bytesToBits xs

theorem byte_bits_length (x : Nat) : (byteBits x).length = 8 := rfl

theorem bytes_to_bits_length (xs : List Nat) : (bytesToBits xs).length = 8 * xs.length := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
      simp only [bytesToBits, List.length_append, byte_bits_length, ih, List.length_cons]
      omega

theorem pack_byte_lt (b7 b6 b5 b4 b3 b2 b1 b0 : Bool) :
    packByte b7 b6 b5 b4 b3 b2 b1 b0 < 256 := by
  have h7 := bv_lt_two b7; have h6 := bv_lt_two b6; have h5 := bv_lt_two b5
  have h4 := bv_lt_two b4; have h3 := bv_lt_two b3; have h2 := bv_lt_two b2
  have h1 := bv_lt_two b1; have h0 := bv_lt_two b0
  simp only [packByte]
  omega

theorem byte_bits_pack_byte (b7 b6 b5 b4 b3 b2 b1 b0 : Bool) :
    byteBits (packByte b7 b6 b5 b4 b3 b2 b1 b0) = [b7, b6, b5, b4, b3, b2, b1, b0] := by
  cases b7 <;> cases b6 <;> cases b5 <;> cases b4 <;> cases b3 <;> cases b2 <;>
    cases b1 <;> cases b0 <;> rfl

theorem pack_byte_byte_bits (x : Nat) (h : x < 256) :
    packByte (decide (x / 128 % 2 = 1)) (decide (x / 64 % 2 = 1)) (decide (x / 32 % 2 = 1))
      (decide (x / 16 % 2 = 1)) (decide (x / 8 % 2 = 1)) (decide (x / 4 % 2 = 1))
      (decide (x / 2 % 2 = 1)) (decide (x % 2 = 1)) = x := by
  simp only [packByte, bv_decide_mod_two]
  omega

/-- Byte stream -> bit stream -> byte stream is the identity on canonical bytes.
This is the direction the re-encoding canonicity check of `from_bytes` relies on. -/
theorem bits_of_bytes_left_inverse (xs : List Nat) (h : ∀ x ∈ xs, x < 256) :
    bitsToBytes (bytesToBits xs) = xs := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
      have hx : x < 256 := h x (by simp)
      have htail : ∀ y ∈ xs, y < 256 := fun y hy => h y (by simp [hy])
      simp only [bytesToBits, byteBits, List.cons_append, List.nil_append, List.append_eq,
        bitsToBytes, pack_byte_byte_bits x hx, ih htail]

/-- Bit stream -> byte stream -> bit stream is the identity on whole-byte streams. -/
theorem bytes_of_bits_left_inverse :
    ∀ (n : Nat) (bits : List Bool), bits.length = 8 * n → bytesToBits (bitsToBytes bits) = bits := by
  intro n
  induction n with
  | zero =>
      intro bits h
      simp only [Nat.mul_zero, List.length_eq_zero] at h
      subst h
      rfl
  | succ n ih =>
      intro bits h
      rcases bits with _ | ⟨b7, t1⟩
      · simp only [List.length_nil] at h; omega
      rcases t1 with _ | ⟨b6, t2⟩
      · simp only [List.length_cons, List.length_nil] at h; omega
      rcases t2 with _ | ⟨b5, t3⟩
      · simp only [List.length_cons, List.length_nil] at h; omega
      rcases t3 with _ | ⟨b4, t4⟩
      · simp only [List.length_cons, List.length_nil] at h; omega
      rcases t4 with _ | ⟨b3, t5⟩
      · simp only [List.length_cons, List.length_nil] at h; omega
      rcases t5 with _ | ⟨b2, t6⟩
      · simp only [List.length_cons, List.length_nil] at h; omega
      rcases t6 with _ | ⟨b1, t7⟩
      · simp only [List.length_cons, List.length_nil] at h; omega
      rcases t7 with _ | ⟨b0, rest⟩
      · simp only [List.length_cons, List.length_nil] at h; omega
      have hrest : rest.length = 8 * n := by
        simp only [List.length_cons] at h; omega
      simp only [bitsToBytes, bytesToBits, byte_bits_pack_byte, ih rest hrest,
        List.cons_append, List.nil_append]

theorem bits_to_bytes_length :
    ∀ (n : Nat) (bits : List Bool), bits.length = 8 * n → (bitsToBytes bits).length = n := by
  intro n bits h
  have := bytes_of_bits_left_inverse n bits h
  have hlen : (bytesToBits (bitsToBytes bits)).length = bits.length := by rw [this]
  rw [bytes_to_bits_length] at hlen
  omega

/-! ## 3. The Golomb-Rice compressed `s2` codec

`vendor/signature.rs`, Algorithms 17/18 of the Falcon specification, with the two
local bounds fixes (F-1) that turn buffer exhaustion into an error instead of a
panic. Per coefficient: 1 sign bit, the 7 low bits of `|c|` (MSB first), then
`|c| >> 7` zero bits and a terminating one bit. -/

inductive S2Error where
  /-- The 625-byte buffer ran out mid-coefficient (`DeserializationError::UnexpectedEof`). -/
  | unexpectedEof
  /-- Unary run pushed the high bits to `>= 2048` (`"high bits ... exceed 2048"`). -/
  | highBitsExceed
  /-- Sign bit set with magnitude zero (`"-0 is forbidden"`). -/
  | negativeZero
  /-- `acc & ((1 << acc_len) - 1) != 0` — non-zero unused bits in the last consumed byte. -/
  | nonZeroUnusedBits
  /-- Re-encoding the decoded polynomial did not reproduce the wire bytes. This check
  lives in `FalconSignature::from_bytes`, NOT in the vendored decoder. -/
  | reencodeMismatch
  deriving DecidableEq, Repr

/-- The 7 low bits of `t`, most significant first. -/
def lowBits7 (t : Nat) : List Bool :=
  [decide (t / 64 % 2 = 1), decide (t / 32 % 2 = 1), decide (t / 16 % 2 = 1),
   decide (t / 8 % 2 = 1), decide (t / 4 % 2 = 1), decide (t / 2 % 2 = 1),
   decide (t % 2 = 1)]

def readBit : List Bool → Except S2Error (Bool × List Bool)
  | [] => .error .unexpectedEof
  | b :: bs => .ok (b, bs)

def readLow7 : List Bool → Except S2Error (Nat × List Bool)
  | b6 :: b5 :: b4 :: b3 :: b2 :: b1 :: b0 :: rest =>
      .ok (64 * bv b6 + 32 * bv b5 + 16 * bv b4 + 8 * bv b3 + 4 * bv b2 + 2 * bv b1 + bv b0,
        rest)
  | _ => .error .unexpectedEof

/-- The unary high-bit run. Each zero bit adds 128; the source checks `m >= 2048`
AFTER the increment, so the largest acceptable magnitude is exactly 2047. -/
def readUnary (m : Nat) : List Bool → Except S2Error (Nat × List Bool)
  | [] => .error .unexpectedEof
  | true :: bs => .ok (m, bs)
  | false :: bs => if m + 128 ≥ 2048 then .error .highBitsExceed else readUnary (m + 128) bs

/-- One coefficient, as `Algorithm 18` decodes it: sign, 7 low bits, unary high bits,
then the `-0` rejection. -/
def decodeCoeff (bits : List Bool) : Except S2Error (Int × List Bool) :=
  match readBit bits with
  | .error e => .error e
  | .ok (s, r1) =>
    match readLow7 r1 with
    | .error e => .error e
    | .ok (low, r2) =>
      match readUnary low r2 with
      | .error e => .error e
      | .ok (m, r3) =>
        -- `s != 0 && m == 0` is the `-0` rejection; otherwise the source stores the canonical
        -- residue `q - m` (negative) or `m`, whose `balanced_value()` is `-m` resp. `m` for
        -- every in-band magnitude. The model carries the balanced value directly.
        if s then (if m = 0 then .error .negativeZero else .ok (-(m : Int), r3))
        else .ok ((m : Int), r3)

def decodeCoeffs : Nat → List Bool → Except S2Error (List Int × List Bool)
  | 0, bits => .ok ([], bits)
  | n + 1, bits =>
    match decodeCoeff bits with
    | .error e => .error e
    | .ok (c, rest) =>
      match decodeCoeffs n rest with
      | .error e => .error e
      | .ok (cs, rest') => .ok (c :: cs, rest')

def encodeCoeff (c : Int) : List Bool :=
  decide (c < 0) :: (lowBits7 c.natAbs ++ (List.replicate (c.natAbs / 128) false ++ [true]))

def encodeCoeffs : List Int → List Bool
  | [] => []
  | c :: cs => encodeCoeff c ++ encodeCoeffs cs

/-- Per-coefficient cost `9 + (|c| >> 7)` bits — exactly the formula
`s2_fits_padded_encoding` sums over. -/
theorem encode_coeff_length (c : Int) : (encodeCoeff c).length = 9 + c.natAbs / 128 := by
  simp only [encodeCoeff, lowBits7, List.length_cons, List.length_append, List.length_replicate,
    List.length_nil]
  omega

theorem read_low7_low_bits (t : Nat) (rest : List Bool) :
    readLow7 (lowBits7 t ++ rest) = .ok (t % 128, rest) := by
  simp only [lowBits7, List.cons_append, List.nil_append, readLow7, bv_decide_mod_two]
  have : 64 * (t / 64 % 2) + 32 * (t / 32 % 2) + 16 * (t / 16 % 2) + 8 * (t / 8 % 2) +
      4 * (t / 4 % 2) + 2 * (t / 2 % 2) + t % 2 = t % 128 := by omega
  rw [this]

theorem read_unary_replicate (k : Nat) :
    ∀ (m : Nat) (rest : List Bool), m + 128 * k < 2048 →
      readUnary m (List.replicate k false ++ (true :: rest)) = .ok (m + 128 * k, rest) := by
  induction k with
  | zero => intro m rest _; simp [readUnary]
  | succ k ih =>
      intro m rest h
      have hstep : ¬ (m + 128 ≥ 2048) := by omega
      simp only [List.replicate_succ, List.cons_append, readUnary, if_neg hstep, List.append_eq]
      rw [ih (m + 128) rest (by omega)]
      have heq : m + 128 + 128 * k = m + 128 * (k + 1) := by omega
      rw [heq]

/-- Decoding an encoded coefficient returns it unchanged and consumes exactly its bits.
The band premise `|c| <= 2047` is the decoder's own acceptance range. -/
theorem decode_encode_coeff (c : Int) (h : c.natAbs ≤ s2CoeffBand) (rest : List Bool) :
    decodeCoeff (encodeCoeff c ++ rest) = .ok (c, rest) := by
  have hband : c.natAbs ≤ 2047 := h
  have hsplit : c.natAbs % 128 + 128 * (c.natAbs / 128) = c.natAbs := by omega
  simp only [encodeCoeff, List.cons_append, List.append_assoc, List.nil_append, List.append_eq,
    decodeCoeff, readBit, read_low7_low_bits]
  rw [read_unary_replicate (c.natAbs / 128) (c.natAbs % 128) rest (by omega)]
  rw [hsplit]
  dsimp only
  by_cases hneg : c < 0
  · have hz : ¬ (c.natAbs = 0) := by omega
    rw [if_pos (by simp [hneg]), if_neg hz]
    simp only [Except.ok.injEq, Prod.mk.injEq, and_true]
    omega
  · rw [if_neg (by simp [hneg])]
    simp only [Except.ok.injEq, Prod.mk.injEq, and_true]
    omega

theorem decode_encode_coeffs :
    ∀ (cs : List Int), (∀ c ∈ cs, c.natAbs ≤ s2CoeffBand) →
      ∀ (rest : List Bool), decodeCoeffs cs.length (encodeCoeffs cs ++ rest) = .ok (cs, rest) := by
  intro cs
  induction cs with
  | nil => intro _ rest; simp [decodeCoeffs, encodeCoeffs]
  | cons c cs ih =>
      intro hband rest
      have hc : c.natAbs ≤ s2CoeffBand := hband c (by simp)
      have htail : ∀ x ∈ cs, x.natAbs ≤ s2CoeffBand := fun x hx => hband x (by simp [hx])
      simp only [List.length_cons, encodeCoeffs, List.append_assoc, decodeCoeffs,
        decode_encode_coeff c hc, ih htail rest]

/-! ## 4. The padded 625-byte `s2` field -/

/-- Whether the coefficient list fits the fixed padded encoding (`s2_fits_padded_encoding`);
the signer re-samples when it does not, so every emitted signature satisfies it. -/
def s2FitsPaddedEncoding (cs : List Int) : Bool :=
  decide ((encodeCoeffs cs).length ≤ sigPolyByteLen * 8)

def encodeS2Bits (cs : List Int) : List Bool :=
  encodeCoeffs cs ++ List.replicate (sigPolyByteLen * 8 - (encodeCoeffs cs).length) false

def encodeS2Bytes (cs : List Int) : List Nat := bitsToBytes (encodeS2Bits cs)

/-- The decoder of the 625-byte field: decode 512 coefficients from the bit stream, then
require that the unused bits of the LAST CONSUMED byte are zero. Note what this does NOT
check: the padding bytes after the consumed prefix. That gap is closed one level up, by
the re-encoding check in `FalconSignature::from_bytes`. -/
def decodeS2FromBits (bits : List Bool) : Except S2Error (List Int) :=
  match decodeCoeffs falconN bits with
  | .error e => .error e
  | .ok (cs, rest) =>
      let consumed := bits.length - rest.length
      let unused := (8 - consumed % 8) % 8
      if (rest.take unused).all (fun b => !b) then .ok cs else .error .nonZeroUnusedBits

/-- `SignaturePoly::read_from`: `read_array::<625>` first (short input is `UnexpectedEof`),
then the bit-level decode. -/
def decodeS2Bytes (wire : List Nat) : Except S2Error (List Int) :=
  if wire.length < sigPolyByteLen then .error .unexpectedEof
  else decodeS2FromBits (bytesToBits (wire.take sigPolyByteLen))

theorem take_replicate_false_all (k m : Nat) :
    ((List.replicate k false).take m).all (fun b => !b) = true := by
  induction m generalizing k with
  | zero => simp
  | succ m ih =>
      cases k with
      | zero => simp
      | succ k => simp [List.replicate_succ, ih]

theorem encode_s2_bits_length (cs : List Int) (h : s2FitsPaddedEncoding cs = true) :
    (encodeS2Bits cs).length = sigPolyByteLen * 8 := by
  have h' : (encodeCoeffs cs).length ≤ sigPolyByteLen * 8 := by
    simpa [s2FitsPaddedEncoding] using h
  simp only [encodeS2Bits, List.length_append, List.length_replicate]
  omega

theorem encode_s2_bytes_length (cs : List Int) (h : s2FitsPaddedEncoding cs = true) :
    (encodeS2Bytes cs).length = sigPolyByteLen := by
  have := encode_s2_bits_length cs h
  exact bits_to_bytes_length sigPolyByteLen (encodeS2Bits cs) (by omega)

/-- Round trip of the whole 625-byte field: an encodable, in-band, length-512
coefficient list decodes back to itself. -/
theorem decode_s2_bytes_encode (cs : List Int) (hlen : cs.length = falconN)
    (hband : ∀ c ∈ cs, c.natAbs ≤ s2CoeffBand) (hfits : s2FitsPaddedEncoding cs = true) :
    decodeS2Bytes (encodeS2Bytes cs) = .ok cs := by
  have hbits : (encodeS2Bits cs).length = sigPolyByteLen * 8 := encode_s2_bits_length cs hfits
  have hbytes : (encodeS2Bytes cs).length = sigPolyByteLen := encode_s2_bytes_length cs hfits
  have hround : bytesToBits (encodeS2Bytes cs) = encodeS2Bits cs := by
    simpa [encodeS2Bytes] using
      bytes_of_bits_left_inverse sigPolyByteLen (encodeS2Bits cs) (by omega)
  have htake : List.take sigPolyByteLen (encodeS2Bytes cs) = encodeS2Bytes cs := by
    rw [← hbytes]
    exact List.take_length _
  rw [decodeS2Bytes, if_neg (by omega : ¬ (encodeS2Bytes cs).length < sigPolyByteLen), htake,
    hround]
  simp only [decodeS2FromBits, encodeS2Bits]
  rw [← hlen, decode_encode_coeffs cs hband]
  simp [take_replicate_false_all]

/-! ## 5. The 666-byte v1 signature wire format

`FalconSignature::to_bytes` / `from_bytes`. The order of checks is load bearing: the
VERSION byte is inspected first, so a legacy ~76 KB proof blob is rejected by policy
rather than by an incidental parse failure. -/

inductive FalconSigError where
  /-- Empty input: no version byte. -/
  | empty
  /-- Leading byte is not `FALCON_SIG_V1`. -/
  | unsupportedVersion (b : Nat)
  /-- Wrong total length; the expected value travels in the error (two gates share it). -/
  | invalidLength (actual expected : Nat)
  /-- The compressed `s2` field is not canonical. -/
  | malformedS2 (e : S2Error)
  /-- A cosign blob carried a public-key coefficient `>= q`, at this index. -/
  | nonCanonicalPublicKey (i : Nat)
  /-- Parsed, but the signature did not verify against the authenticated `pk_g`. -/
  | verificationFailed
  deriving DecidableEq, Repr

/-- A parsed signature: the 40 salt bytes and the 512 balanced `s2` coefficients. -/
structure SignatureParts where
  salt : List Nat
  s2 : List Int
  deriving DecidableEq, Repr

/-- Well-formedness of a signature as the NATIVE constructors can produce one: signing
emits it, and `from_bytes` enforces exactly these three facts. -/
structure SignatureWellFormed (s : SignatureParts) : Prop where
  saltLen : s.salt.length = sigNonceLen
  saltBytes : ∀ b ∈ s.salt, b < 256
  polyLen : s.s2.length = falconN
  band : ∀ c ∈ s.s2, c.natAbs ≤ s2CoeffBand
  fits : s2FitsPaddedEncoding s.s2 = true

def encodeSignature (s : SignatureParts) : List Nat :=
  falconSigV1 :: (s.salt ++ encodeS2Bytes s.s2)

/-- `FalconSignature::from_bytes`. Checks in source order: version, exact length,
vendored canonical `s2` decode, then the re-encoding equality that closes the
padding-byte malleability hole. -/
def decodeSignature (bytes : List Nat) : Except FalconSigError SignatureParts :=
  match bytes with
  | [] => .error .empty
  | v :: rest =>
      if v ≠ falconSigV1 then .error (.unsupportedVersion v)
      else if (v :: rest).length ≠ falconSigBytes then
        .error (.invalidLength (v :: rest).length falconSigBytes)
      else
        match decodeS2Bytes (rest.drop sigNonceLen) with
        | .error e => .error (.malformedS2 e)
        | .ok cs =>
            if encodeS2Bytes cs ≠ rest.drop sigNonceLen then
              .error (.malformedS2 .reencodeMismatch)
            else .ok ⟨rest.take sigNonceLen, cs⟩

theorem encode_signature_length (s : SignatureParts) (hs : SignatureWellFormed s) :
    (encodeSignature s).length = falconSigBytes := by
  have h2 := encode_s2_bytes_length s.s2 hs.fits
  simp only [encodeSignature, List.length_cons, List.length_append, hs.saltLen, h2,
    falconSigBytes]
  omega

/-- Layout widths: version byte at offset 0, salt at `[1, 41)`, compressed `s2` at
`[41, 666)`. -/
theorem encode_signature_layout (s : SignatureParts) (hs : SignatureWellFormed s) :
    (encodeSignature s).head? = some falconSigV1 ∧
    ((encodeSignature s).drop 1).take sigNonceLen = s.salt ∧
    ((encodeSignature s).drop 1).drop sigNonceLen = encodeS2Bytes s.s2 := by
  exact ⟨rfl, List.take_left' hs.saltLen, List.drop_left' hs.saltLen⟩

/-- Wire round trip: an honestly produced signature decodes back to itself. -/
theorem decode_encode_signature (s : SignatureParts) (hs : SignatureWellFormed s) :
    decodeSignature (encodeSignature s) = .ok s := by
  have hlen := encode_signature_length s hs
  have hdrop : (s.salt ++ encodeS2Bytes s.s2).drop sigNonceLen = encodeS2Bytes s.s2 :=
    List.drop_left' hs.saltLen
  have htake : (s.salt ++ encodeS2Bytes s.s2).take sigNonceLen = s.salt :=
    List.take_left' hs.saltLen
  have hs2 : decodeS2Bytes (encodeS2Bytes s.s2) = .ok s.s2 :=
    decode_s2_bytes_encode s.s2 hs.polyLen hs.band hs.fits
  simp only [encodeSignature, decodeSignature, hdrop, htake, hs2, ne_eq, not_true_eq_false,
    if_false]
  rw [if_neg (by simpa [encodeSignature] using hlen)]

/-- SECURITY (bijective wire encoding — signature BYTES feed keccak digests downstream):
an accepted byte string is EXACTLY the re-encoding of what it decoded to. -/
theorem decode_signature_determines_bytes (bytes : List Nat) (s : SignatureParts)
    (h : decodeSignature bytes = .ok s) : bytes = encodeSignature s := by
  rcases bytes with _ | ⟨v, rest⟩
  · simp [decodeSignature] at h
  simp only [decodeSignature] at h
  by_cases hv : v = falconSigV1
  case neg => rw [if_pos hv] at h; simp at h
  rw [if_neg (by intro hc; exact hc hv)] at h
  by_cases hl : (v :: rest).length = falconSigBytes
  case neg => rw [if_pos hl] at h; simp at h
  rw [if_neg (by intro hc; exact hc hl)] at h
  split at h
  · simp at h
  · rename_i cs _
    by_cases hre : encodeS2Bytes cs = rest.drop sigNonceLen
    case neg => rw [if_pos hre] at h; simp at h
    rw [if_neg (by intro hc; exact hc hre)] at h
    simp only [Except.ok.injEq] at h
    subst h
    simp only [encodeSignature, hv, hre, List.take_append_drop]

/-- Malleability freedom: two byte strings decoding to the same signature are equal. -/
theorem decode_signature_injective (a b : List Nat) (s : SignatureParts)
    (ha : decodeSignature a = .ok s) (hb : decodeSignature b = .ok s) : a = b := by
  rw [decode_signature_determines_bytes a s ha, decode_signature_determines_bytes b s hb]

/-- Accepted input has the exact fixed length. -/
theorem decode_signature_length (bytes : List Nat) (s : SignatureParts)
    (h : decodeSignature bytes = .ok s) : bytes.length = falconSigBytes := by
  rcases bytes with _ | ⟨v, rest⟩
  · simp [decodeSignature] at h
  simp only [decodeSignature] at h
  by_cases hv : v = falconSigV1
  case neg => rw [if_pos hv] at h; simp at h
  rw [if_neg (by intro hc; exact hc hv)] at h
  by_cases hl : (v :: rest).length = falconSigBytes
  case neg => rw [if_pos hl] at h; simp at h
  exact hl

/-- SECURITY (TM-C8 / O-9 downgrade rejection): a non-v1 leading byte is rejected on the
VERSION gate, whatever the rest of the input is — no length or structural parsing runs. -/
theorem decode_signature_version_gate_first (v : Nat) (rest : List Nat)
    (hv : v ≠ falconSigV1) :
    decodeSignature (v :: rest) = .error (.unsupportedVersion v) := by
  simp only [decodeSignature, ne_eq]
  rw [if_pos hv]

/-- Concrete instance of the gate: the captured 77_872-byte legacy `SingleSigCircuit`
proof blob (leading byte `0x9c` in the test) is rejected as an unsupported version, not
as a length or parse error. -/
theorem legacy_proof_blob_rejected_on_version_gate (rest : List Nat) :
    decodeSignature (0x9c :: rest) = .error (.unsupportedVersion 0x9c) :=
  decode_signature_version_gate_first 0x9c rest (by decide)

/-- Empty input is the distinct `Empty` error (no panic, no indexing). -/
theorem decode_signature_empty : decodeSignature [] = .error .empty := rfl

/-! ## 6. The 1690-byte COSIGN transport blob -/

def encodePkH : List Nat → List Nat
  | [] => []
  | c :: cs => (c % 256) :: (c / 256) :: encodePkH cs

/-- Little-endian u16 pairs with the per-coefficient canonicity gate; the FIRST
out-of-range index wins, exactly as the source's early return does. -/
def decodePkH : Nat → List Nat → Except FalconSigError (List Nat)
  | i, b0 :: b1 :: rest =>
      let c := b0 + 256 * b1
      if c ≥ falconQ then .error (.nonCanonicalPublicKey i)
      else
        match decodePkH (i + 1) rest with
        | .error e => .error e
        | .ok cs => .ok (c :: cs)
  | _, _ => .ok []

def encodeCosignBlob (s : SignatureParts) (h : List Nat) : List Nat :=
  encodeSignature s ++ encodePkH h

/-- `decode_cosign_blob`: version gate FIRST, then the exact 1690-byte length, then the
666-byte signature prefix, then the public polynomial. -/
def decodeCosignBlob (bytes : List Nat) :
    Except FalconSigError (SignatureParts × List Nat) :=
  match bytes with
  | [] => .error .empty
  | v :: rest =>
      if v ≠ falconSigV1 then .error (.unsupportedVersion v)
      else if (v :: rest).length ≠ falconCosignBlobBytes then
        .error (.invalidLength (v :: rest).length falconCosignBlobBytes)
      else
        match decodeSignature ((v :: rest).take falconSigBytes) with
        | .error e => .error e
        | .ok sig =>
            match decodePkH 0 ((v :: rest).drop falconSigBytes) with
            | .error e => .error e
            | .ok pk => .ok (sig, pk)

theorem encode_pk_h_length (h : List Nat) : (encodePkH h).length = 2 * h.length := by
  induction h with
  | nil => rfl
  | cons c cs ih => simp only [encodePkH, List.length_cons, ih]; omega

theorem decode_encode_pk_h :
    ∀ (h : List Nat), (∀ c ∈ h, c < falconQ) → ∀ i, decodePkH i (encodePkH h) = .ok h := by
  intro h
  induction h with
  | nil => intro _ i; rfl
  | cons c cs ih =>
      intro hall i
      have hc : c < falconQ := hall c (by simp)
      have htail : ∀ x ∈ cs, x < falconQ := fun x hx => hall x (by simp [hx])
      have hval : c % 256 + 256 * (c / 256) = c := by omega
      simp only [encodePkH, decodePkH, hval]
      rw [if_neg (by omega), ih htail (i + 1)]

/-- The blob is exactly 1690 bytes: 666 of signature and 1024 of public polynomial. -/
theorem encode_cosign_blob_length (s : SignatureParts) (hs : SignatureWellFormed s)
    (h : List Nat) (hh : h.length = falconN) :
    (encodeCosignBlob s h).length = falconCosignBlobBytes := by
  simp only [encodeCosignBlob, List.length_append, encode_signature_length s hs,
    encode_pk_h_length, hh, falconCosignBlobBytes, falconPkHBytes]

/-- Blob round trip. -/
theorem decode_encode_cosign_blob (s : SignatureParts) (hs : SignatureWellFormed s)
    (h : List Nat) (hh : h.length = falconN) (hcanon : ∀ c ∈ h, c < falconQ) :
    decodeCosignBlob (encodeCosignBlob s h) = .ok (s, h) := by
  have hsig : (encodeSignature s).length = falconSigBytes := encode_signature_length s hs
  have hblob : (encodeCosignBlob s h).length = falconCosignBlobBytes :=
    encode_cosign_blob_length s hs h hh
  have htake : (encodeCosignBlob s h).take falconSigBytes = encodeSignature s :=
    List.take_left' hsig
  have hdrop : (encodeCosignBlob s h).drop falconSigBytes = encodePkH h :=
    List.drop_left' hsig
  have hcons : encodeCosignBlob s h =
      falconSigV1 :: (s.salt ++ encodeS2Bytes s.s2 ++ encodePkH h) := by
    simp [encodeCosignBlob, encodeSignature]
  rw [hcons] at hblob htake hdrop
  rw [hcons]
  simp only [decodeCosignBlob]
  rw [if_neg (by intro hc; exact hc rfl), if_neg (by intro hc; exact hc hblob), htake, hdrop,
    decode_encode_signature s hs, decode_encode_pk_h h hcanon 0]

/-- SECURITY (fund safety, TM-C8): acceptance forces the exact 1690-byte length. A bare
666-byte signature, a truncation and an extension are all rejected. -/
theorem decode_cosign_blob_length (bytes : List Nat) (r : SignatureParts × List Nat)
    (h : decodeCosignBlob bytes = .ok r) : bytes.length = falconCosignBlobBytes := by
  rcases bytes with _ | ⟨v, rest⟩
  · simp [decodeCosignBlob] at h
  simp only [decodeCosignBlob] at h
  by_cases hv : v = falconSigV1
  case neg => rw [if_pos hv] at h; simp at h
  rw [if_neg (by intro hc; exact hc hv)] at h
  by_cases hl : (v :: rest).length = falconCosignBlobBytes
  case neg => rw [if_pos hl] at h; simp at h
  exact hl

/-- The version gate runs BEFORE the length gate on the blob entry point too. -/
theorem decode_cosign_blob_version_gate_first (v : Nat) (rest : List Nat)
    (hv : v ≠ falconSigV1) :
    decodeCosignBlob (v :: rest) = .error (.unsupportedVersion v) := by
  simp only [decodeCosignBlob, ne_eq]
  rw [if_pos hv]

/-- Wrong length with a correct version byte is an `InvalidLength` carrying the COSIGN
expectation (1690), not the bare-signature expectation (666). -/
theorem decode_cosign_blob_length_gate (rest : List Nat)
    (hl : (falconSigV1 :: rest).length ≠ falconCosignBlobBytes) :
    decodeCosignBlob (falconSigV1 :: rest) =
      .error (.invalidLength (falconSigV1 :: rest).length falconCosignBlobBytes) := by
  simp only [decodeCosignBlob, ne_eq, not_true_eq_false, if_false]
  rw [if_pos hl]

end Zkp.Implementation.FalconCore
