import Std

/-!
# Regev lattice STARK statements and the BabyBear hash-signature

Handwritten semantic model of two production sources:

* `src/regev/transfer_stark.rs` (3206 lines) — the plonky3 batch-STARK statements
  E-1 `channelTxZKP`, E-2 `channelUpdateZKP`, E-3 `withdrawClaimZKP` and the
  balance-refresh proof: column layout, public-value encoders, constraint families,
  prove-side witness checks and the statement-level verifier.
* `src/regev/hash_sig.rs` (1313 lines) — the Poseidon2-BabyBear hash signature used
  as the SENDER authorization that `ChannelStateUpdate` records as "sender
  hash-signature present but not verified here": key format, sponge equations, the
  binding AIR and its public values.

This is NOT a refinement proof of the Rust code, of the plonky3 prover/verifier, of
the vendored `p3-batch-stark` backend, or of any compiler. Nothing here establishes
proof soundness, zero-knowledge, hash collision/preimage resistance or lattice
hardness; those stay explicit premises, opaque callbacks or named boundaries.

## Named boundaries (all undischarged)

* `StarkSoundness` — `stark::prove_batch` / `verify_batch`, FRI, the hiding PCS and
  the Fiat-Shamir challenger are modelled as an opaque `Backend` callback returning
  the shared evaluation challenge. Accepting a proof is a hypothesis, never a
  conclusion, and no theorem here says an accepted proof implies a true statement.
* `EvaluationArgumentSoundness` — the source argues (Schwartz-Zippel at the
  post-commitment challenge `z`) that matching published evaluations pin the
  committed columns to the claimed public polynomials. The model compares
  evaluations structurally; it does NOT claim polynomial identity from a point
  agreement, and `Chal` is `Int` here, not the quartic BabyBear extension.
* `Poseidon2Permutation` — the audited `default_babybear_poseidon2_16` permutation
  and the upstream `Poseidon2Air` round constraints are a callback record
  (`Poseidon2`); no preimage/collision resistance and no round-constraint lowering
  is asserted.
* `FieldProducts` — "a product that vanishes mod q has a vanishing factor"
  (primality of q), the premise that turns the cubic/quadratic smallness gates into
  membership facts. Stated as a `Prop` and taken as a hypothesis, never proved.
* `UpstreamRegev` — `regev_plonky3` keygen/encrypt/`encode_value_message`, the
  negacyclic NTT, `RegevParams::delta()`, `config.is_zk()` and the postcard codec.
  `encodeAmount` here is the DOCUMENTED D1 encoding (1 bit per coefficient, low 64
  coefficients), not a translation of the upstream function body.
* `LatticeHardness` — Ring-LWE / the `n = 2048` parameter choice.
* `KeccakDigest` — the IMPA channel-tx digest whose 16-bit limbs become the
  hash-signature message; treated as given bytes, never as an injective function.
* `NativeTargetRefinement` — Rust integer/array/allocation behaviour, error message
  strings (errors are modelled payload-free), and the trace/LDE layer.

Field elements of the dual-key and decryption AIRs are modelled as `Int`
representatives with `FZero x := x % q = 0` for "the constraint vanishes in the
field". The hash-signature section instead models field elements by their canonical
representative in `[0, q)` with `fadd x y = (x + y) % q`; both are conventions of
this model, not extra source checks.
-/
namespace Zkp.Implementation.RegevProofs

set_option maxRecDepth 8192

/-! ## Parameters (src/regev/params.rs, transfer_stark.rs lines 1345-1369) -/

def regevN : Nat := 2048
def regevQ : Nat := 2013265921
def regevPlainBits : Nat := 8
def regevEta : Nat := 2
def maxHomoAddsBeforeRefresh : Nat := 64
def deltaU32 : Nat := regevQ / 2 ^ regevPlainBits
def halfDeltaU32 : Nat := deltaU32 / 2
def digitBits : Nat := regevPlainBits
def noiseLoBits : Nat := 19
def noiseHiHalfBits : Nat := 3
def carryBits : Nat := 8
def amountBits : Nat := 64

theorem parameters_pinned :
    regevN = 2048 ∧ regevQ = 2013265921 ∧ regevPlainBits = 8 ∧ regevEta = 2 ∧
      maxHomoAddsBeforeRefresh = 64 ∧ deltaU32 = 7864320 ∧ halfDeltaU32 = 3932160 ∧
      digitBits = 8 ∧ noiseLoBits = 19 ∧ noiseHiHalfBits = 3 ∧ carryBits = 8 := by
  refine ⟨rfl, rfl, rfl, rfl, rfl, by decide, by decide, rfl, rfl, rfl, rfl⟩

/-- The three compile-time assertions of `transfer_stark.rs` lines 1361-1369. -/
theorem delta_constants_pinned :
    deltaU32 % 2 = 0 ∧ 256 * deltaU32 + 1 = regevQ ∧ deltaU32 = 15 * 2 ^ noiseLoBits ∧
      (2 ^ noiseLoBits - 1) + 14 * 2 ^ noiseLoBits = deltaU32 - 1 := by
  refine ⟨by decide, by decide, by decide, by decide⟩

/-! ## Purpose domain words (transfer_stark.rs lines 145-189) -/

def channelTxZkpDomain : Nat := 0x494d435a
/-- `CHANNEL_UPDATE_ZKP_DOMAIN_V2` ("IMU2"); the retired v1 word is `0x494d555a`. -/
def channelUpdateZkpDomain : Nat := 0x494d5532
def channelUpdateZkpDomainV1Retired : Nat := 0x494d555a
def withdrawClaimZkpDomain : Nat := 0x494d575a
def balanceRefreshZkpDomain : Nat := 0x494d5246

inductive RegevProofPurpose where
  | channelTx
  | channelUpdate
  | withdrawClaim
  | balanceRefresh
  deriving DecidableEq, Repr

def RegevProofPurpose.domain : RegevProofPurpose → Nat
  | .channelTx => channelTxZkpDomain
  | .channelUpdate => channelUpdateZkpDomain
  | .withdrawClaim => withdrawClaimZkpDomain
  | .balanceRefresh => balanceRefreshZkpDomain

/-- The `const _` block at lines 162-167: every purpose word is `< q`, so
`F::from_u32` cannot alias two purposes. -/
theorem purpose_domains_below_q : ∀ p : RegevProofPurpose, p.domain < regevQ := by
  intro p; cases p <;> decide

/-- Domain separation is injective on purposes (and none collides with the retired
v1 update word). This is a statement about the four constants only; the transcript
consequence is the `StarkSoundness` boundary. -/
theorem purpose_domains_injective :
    ∀ p p' : RegevProofPurpose, p.domain = p'.domain → p = p' := by
  intro p p' h; cases p <;> cases p' <;> first | rfl | (exact absurd h (by decide))

theorem retired_update_domain_distinct :
    ∀ p : RegevProofPurpose, p.domain ≠ channelUpdateZkpDomainV1Retired := by
  intro p; cases p <;> decide

/-! ## Dual-key column layout (transfer_stark.rs lines 222-342) -/

def colAS : Nat := 0
def colBS : Nat := 1
def colAR : Nat := 2
def colBR : Nat := 3
def numKeyCols : Nat := 4
def ctCols : Nat := 10
def offC1 : Nat := 0
def offC2 : Nat := 1
def offR : Nat := 2
def offE1U : Nat := 3
def offE1V : Nat := 4
def offE2U : Nat := 5
def offE2V : Nat := 6
def offM : Nat := 7
def offK1 : Nat := 8
def offK2 : Nat := 9
def ctBase (j : Nat) : Nat := numKeyCols + j * ctCols

def auxAS : Nat := 0
def auxBS : Nat := 1
def auxAR : Nat := 2
def auxBR : Nat := 3
def numKeyAux : Nat := 4
def ctAux : Nat := 8
def aoffC1 : Nat := 0
def aoffC2 : Nat := 1
def aoffR : Nat := 2
def aoffE1 : Nat := 3
def aoffE2 : Nat := 4
def aoffM : Nat := 5
def aoffK1 : Nat := 6
def aoffK2 : Nat := 7
def auxBase (j : Nat) : Nat := numKeyAux + j * ctAux

/-- `AirShape` of lines 281-292. -/
structure AirShape where
  numCts : Nat
  recipientCt : List Bool
  exposeM : List Bool
  carryBefore : Nat
  carryDelta : Nat
  carryAfter : Nat
  deriving Repr

def AirShape.carryCol (s : AirShape) : Nat := numKeyCols + s.numCts * ctCols
def AirShape.numCols (s : AirShape) : Nat := s.carryCol + 1
def AirShape.numPublicValues (s : AirShape) (n numExtra : Nat) : Nat :=
  1 + numExtra + (numKeyCols + 2 * s.numCts) * n
def AirShape.numPublishedEvals (s : AirShape) : Nat :=
  numKeyAux + 2 * s.numCts + (s.exposeM.filter (fun e => e)).length

def e1Shape : AirShape :=
  { numCts := 3, recipientCt := [false, true, false], exposeM := [false, false, false],
    carryBefore := 0, carryDelta := 1, carryAfter := 2 }

def e2Shape : AirShape :=
  { numCts := 4, recipientCt := [false, false, false, true], exposeM := [false, false, true, true],
    carryBefore := 0, carryDelta := 2, carryAfter := 1 }

def amountLimbPvs : Nat := 4
def e2NumExtraPvs : Nat := amountLimbPvs + 1

theorem e1_layout_pinned :
    e1Shape.carryCol = 34 ∧ e1Shape.numCols = 35 ∧ e1Shape.numPublishedEvals = 10 ∧
      e1Shape.numPublicValues regevN 0 = 20481 := by
  refine ⟨by decide, by decide, by decide, by decide⟩

theorem e2_layout_pinned :
    e2Shape.carryCol = 44 ∧ e2Shape.numCols = 45 ∧ e2Shape.numPublishedEvals = 14 ∧
      e2Shape.numPublicValues regevN e2NumExtraPvs = 24582 := by
  refine ⟨by decide, by decide, by decide, by decide⟩

/-- Every column index a shape assigns: the four key columns, ten per ciphertext,
then the single carry column. -/
def assignedColumns (s : AirShape) : List Nat :=
  List.range numKeyCols ++
    ((List.range s.numCts).map (fun j => (List.range ctCols).map (fun o => ctBase j + o))).join ++
    [s.carryCol]

/-- Layout soundness: the assignment covers `0 .. numCols-1` exactly once (no gap,
no overlap) for both dual-key shapes. -/
theorem e1_columns_partition : assignedColumns e1Shape = List.range e1Shape.numCols := by
  decide

theorem e2_columns_partition : assignedColumns e2Shape = List.range e2Shape.numCols := by
  decide

/-- Aux (permutation) column count: four key evaluations then eight per ciphertext. -/
def AirShape.numAuxCols (s : AirShape) : Nat := numKeyAux + s.numCts * ctAux

theorem aux_layout_pinned :
    e1Shape.numAuxCols = 28 ∧ e2Shape.numAuxCols = 36 ∧ auxBase 0 = 4 ∧ auxBase 1 = 12 := by
  refine ⟨by decide, by decide, by decide, by decide⟩

/-! ## Decryption-core / refresh column layout (transfer_stark.rs lines 1371-1429) -/

def decA : Nat := 0
def decB : Nat := 1
def decC1 : Nat := 2
def decC2 : Nat := 3
def decS : Nat := 4
def decEpkU : Nat := 5
def decEpkV : Nat := 6
def decKPk : Nat := 7
def decV : Nat := 8
def decKV : Nat := 9
def decDBits : Nat := 10
def decNoiseLo : Nat := decDBits + digitBits
def decNoiseU : Nat := decNoiseLo + noiseLoBits
def decNoiseV : Nat := decNoiseU + noiseHiHalfBits
def decBit : Nat := decNoiseV + noiseHiHalfBits
def decCarry : Nat := decBit + 1
def decCoreCols : Nat := decCarry + carryBits

def rfC1New : Nat := decCoreCols
def rfC2New : Nat := rfC1New + 1
def rfR : Nat := rfC2New + 1
def rfE1U : Nat := rfR + 1
def rfE1V : Nat := rfE1U + 1
def rfE2U : Nat := rfE1V + 1
def rfE2V : Nat := rfE2U + 1
def rfK1 : Nat := rfE2V + 1
def rfK2 : Nat := rfK1 + 1
def rfCols : Nat := rfK2 + 1

def dauxA : Nat := 0
def dauxB : Nat := 1
def dauxC1 : Nat := 2
def dauxC2 : Nat := 3
def dauxS : Nat := 4
def dauxEpk : Nat := 5
def dauxKPk : Nat := 6
def dauxV : Nat := 7
def dauxKV : Nat := 8
def dauxBit : Nat := 9
def decCoreAux : Nat := 10
def rfauxC1New : Nat := decCoreAux
def rfauxC2New : Nat := rfauxC1New + 1
def rfauxR : Nat := rfauxC2New + 1
def rfauxE1 : Nat := rfauxR + 1
def rfauxE2 : Nat := rfauxE1 + 1
def rfauxK1 : Nat := rfauxE2 + 1
def rfauxK2 : Nat := rfauxK1 + 1
def refreshAuxCols : Nat := rfauxK2 + 1

def decNumPublished : Nat := 5
def rfNumPublished : Nat := 6

theorem decryption_core_layout_pinned :
    decDBits = 10 ∧ decNoiseLo = 18 ∧ decNoiseU = 37 ∧ decNoiseV = 40 ∧ decBit = 43 ∧
      decCarry = 44 ∧ decCoreCols = 52 := by
  refine ⟨rfl, by decide, by decide, by decide, by decide, by decide, by decide⟩

theorem refresh_layout_pinned :
    rfC1New = 52 ∧ rfK2 = 60 ∧ rfCols = 61 ∧ refreshAuxCols = 17 := by
  refine ⟨by decide, by decide, by decide, by decide⟩

/-- Column assignment of the decryption core: ten scalar columns, then the digit,
noise-lo, noise-hi-half, bit and carry bit ranges. -/
def decCoreColumns : List Nat :=
  [decA, decB, decC1, decC2, decS, decEpkU, decEpkV, decKPk, decV, decKV] ++
    (List.range digitBits).map (fun j => decDBits + j) ++
    (List.range noiseLoBits).map (fun j => decNoiseLo + j) ++
    (List.range noiseHiHalfBits).map (fun j => decNoiseU + j) ++
    (List.range noiseHiHalfBits).map (fun j => decNoiseV + j) ++
    [decBit] ++ (List.range carryBits).map (fun j => decCarry + j)

def refreshColumns : List Nat :=
  decCoreColumns ++ [rfC1New, rfC2New, rfR, rfE1U, rfE1V, rfE2U, rfE2V, rfK1, rfK2]

theorem dec_core_columns_partition : decCoreColumns = List.range decCoreCols := by
  decide

theorem refresh_columns_partition : refreshColumns = List.range rfCols := by
  decide

/-- E-3 and refresh public-value counts (`num_public_values` at lines 1660-1663 and
1719-1722). -/
def decNumPublicValues (n : Nat) : Nat := 1 + amountLimbPvs + 4 * n
def refreshNumPublicValues (n : Nat) : Nat := 1 + 6 * n

theorem dec_public_value_counts_pinned :
    decNumPublicValues regevN = 8197 ∧ refreshNumPublicValues regevN = 12289 := by
  refine ⟨by decide, by decide⟩

/-! ## List helpers used by the encoder-injectivity proofs -/

theorem list_append_split {a : Type} :
    ∀ (l1 l2 r1 r2 : List a), l1 ++ r1 = l2 ++ r2 → l1.length = l2.length → l1 = l2 ∧ r1 = r2
  | [], [], r1, r2, h, _ => ⟨rfl, by simpa using h⟩
  | [], _ :: _, _, _, _, hl => by simp at hl
  | _ :: _, [], _, _, _, hl => by simp at hl
  | x :: xs, y :: ys, r1, r2, h, hl => by
      have hxy : x = y := (List.cons.injEq _ _ _ _ ▸ h).1
      have htl : xs ++ r1 = ys ++ r2 := (List.cons.injEq _ _ _ _ ▸ h).2
      have hlen : xs.length = ys.length := by simpa using hl
      have ih := list_append_split xs ys r1 r2 htl hlen
      exact ⟨by rw [hxy, ih.1], ih.2⟩

theorem join_uniform_inj (n : Nat) :
    ∀ (xs ys : List (List Nat)), (∀ l ∈ xs, l.length = n) → (∀ l ∈ ys, l.length = n) →
      xs.length = ys.length → xs.join = ys.join → xs = ys
  | [], [], _, _, _, _ => rfl
  | [], _ :: _, _, _, hl, _ => by simp at hl
  | _ :: _, [], _, _, hl, _ => by simp at hl
  | x :: xs, y :: ys, hx, hy, hl, h => by
      have hxlen : x.length = n := hx x (by simp)
      have hylen : y.length = n := hy y (by simp)
      have hj : x ++ xs.join = y ++ ys.join := by simpa using h
      have hsplit := list_append_split x y xs.join ys.join hj (by rw [hxlen, hylen])
      have ih := join_uniform_inj n xs ys (fun l hl' => hx l (by simp [hl']))
        (fun l hl' => hy l (by simp [hl'])) (by simpa using hl) hsplit.2
      rw [hsplit.1, ih]

/-! ## Statement data (RegevPk / RegevCiphertext and their canonicality checks)

Models `src/regev/keys.rs::RegevPk::validate`, `src/regev/encrypt.rs::
RegevCiphertext::validate` and the `to_upstream_pk` / `to_upstream_ct` conversions
that every prove/verify entry point calls FIRST. Error payload strings are not
modelled. -/

inductive RegevError where
  | invalidPk
  | invalidCiphertext
  | invalidSk
  | decryptOverflow
  | invalidWitness
  | proofCodec
  | proofVerification
  | purposeMismatch
  deriving DecidableEq, Repr

structure RegevPkM where
  a : List Nat
  b : List Nat
  deriving DecidableEq, Repr

structure RegevCtM where
  c1 : List Nat
  c2 : List Nat
  deriving DecidableEq, Repr

def canonicalPoly (xs : List Nat) : Bool := xs.all (fun c => decide (c < regevQ))

def pkValidate (pk : RegevPkM) : Except RegevError Unit :=
  if pk.a.length ≠ regevN ∨ pk.b.length ≠ regevN then .error .invalidPk
  else if canonicalPoly (pk.a ++ pk.b) then .ok () else .error .invalidPk

def ctValidate (ct : RegevCtM) : Except RegevError Unit :=
  if ct.c1.length ≠ regevN ∨ ct.c2.length ≠ regevN then .error .invalidCiphertext
  else if canonicalPoly (ct.c1 ++ ct.c2) then .ok () else .error .invalidCiphertext

def PkShaped (pk : RegevPkM) : Prop := pk.a.length = regevN ∧ pk.b.length = regevN
def CtShaped (ct : RegevCtM) : Prop := ct.c1.length = regevN ∧ ct.c2.length = regevN

theorem pk_validate_ok_shape {pk : RegevPkM} (h : pkValidate pk = .ok ()) : PkShaped pk := by
  unfold pkValidate at h
  split at h
  · exact absurd h (by simp)
  · next hne =>
    have h2 := not_or.mp hne
    exact ⟨by omega, by omega⟩

theorem pk_validate_ok_canonical {pk : RegevPkM} (h : pkValidate pk = .ok ()) :
    ∀ c ∈ pk.a ++ pk.b, c < regevQ := by
  unfold pkValidate at h
  split at h
  · exact absurd h (by simp)
  · split at h
    · next hc =>
      intro c hcm
      have := List.all_eq_true.mp hc c hcm
      simpa using this
    · exact absurd h (by simp)

theorem ct_validate_ok_shape {ct : RegevCtM} (h : ctValidate ct = .ok ()) : CtShaped ct := by
  unfold ctValidate at h
  split at h
  · exact absurd h (by simp)
  · next hne =>
    have h2 := not_or.mp hne
    exact ⟨by omega, by omega⟩

theorem ct_validate_ok_canonical {ct : RegevCtM} (h : ctValidate ct = .ok ()) :
    ∀ c ∈ ct.c1 ++ ct.c2, c < regevQ := by
  unfold ctValidate at h
  split at h
  · exact absurd h (by simp)
  · split at h
    · next hc =>
      intro c hcm
      have := List.all_eq_true.mp hc c hcm
      simpa using this
    · exact absurd h (by simp)

/-! ## Public-value encoders (transfer_stark.rs lines 654-708, 1993-2009, 2110-2126) -/

def ctBlocks (cts : List RegevCtM) : List (List Nat) := cts.bind (fun ct => [ct.c1, ct.c2])

def polyBlocks (spk rpk : RegevPkM) (cts : List RegevCtM) : List (List Nat) :=
  [spk.a, spk.b, rpk.a, rpk.b] ++ ctBlocks cts

/-- `[domain] ++ extra ++ a_s ++ b_s ++ a_r ++ b_r ++ (c1, c2)*num_cts`. -/
def dualKeyPublicValues (domain : Nat) (extra : List Nat) (spk rpk : RegevPkM)
    (cts : List RegevCtM) : List Nat :=
  (domain :: extra) ++ (polyBlocks spk rpk cts).join

def amountLimbs (amount : Nat) : List Nat :=
  [amount % 65536, amount / 65536 % 65536, amount / 4294967296 % 65536,
   amount / 281474976710656 % 65536]

def e2ExtraPvs (amount tokenIndex : Nat) : List Nat := amountLimbs amount ++ [tokenIndex]

def channelTxPublicValues (spk rpk : RegevPkM) (before encAmount after : RegevCtM) : List Nat :=
  dualKeyPublicValues channelTxZkpDomain [] spk rpk [before, encAmount, after]

def channelUpdatePublicValues (spk rpk : RegevPkM) (before after senderDelta receiverDelta : RegevCtM)
    (amount tokenIndex : Nat) : List Nat :=
  dualKeyPublicValues channelUpdateZkpDomain (e2ExtraPvs amount tokenIndex) spk rpk
    [before, after, senderDelta, receiverDelta]

def decryptionPublicValues (domain amount : Nat) (pk : RegevPkM) (ct : RegevCtM) : List Nat :=
  (domain :: amountLimbs amount) ++ ([pk.a, pk.b, ct.c1, ct.c2]).join

def refreshPublicValues (domain : Nat) (pk : RegevPkM) (oldCt newCt : RegevCtM) : List Nat :=
  domain :: ([pk.a, pk.b, oldCt.c1, oldCt.c2, newCt.c1, newCt.c2]).join

theorem ct_blocks_length (cts : List RegevCtM) : (ctBlocks cts).length = 2 * cts.length := by
  induction cts with
  | nil => rfl
  | cons c cs ih => simp [ctBlocks, List.bind] at ih ⊢; omega

theorem poly_blocks_uniform {spk rpk : RegevPkM} {cts : List RegevCtM}
    (hs : PkShaped spk) (hr : PkShaped rpk) (hc : ∀ ct ∈ cts, CtShaped ct) :
    ∀ l ∈ polyBlocks spk rpk cts, l.length = regevN := by
  intro l hl
  rcases List.mem_append.mp hl with h | h
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at h
    rcases h with h | h | h | h
    · exact h ▸ hs.1
    · exact h ▸ hs.2
    · exact h ▸ hr.1
    · exact h ▸ hr.2
  · obtain ⟨ct, hct, hl2⟩ := List.mem_bind.mp h
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hl2
    rcases hl2 with h2 | h2
    · exact h2 ▸ (hc ct hct).1
    · exact h2 ▸ (hc ct hct).2

theorem join_uniform_length (n : Nat) :
    ∀ (xs : List (List Nat)), (∀ l ∈ xs, l.length = n) → xs.join.length = xs.length * n
  | [], _ => by simp
  | x :: xs, h => by
      have hx : x.length = n := h x (by simp)
      have ih := join_uniform_length n xs (fun l hl => h l (by simp [hl]))
      simp [List.join, hx, ih, Nat.succ_mul]
      omega

theorem poly_blocks_length (spk rpk : RegevPkM) (cts : List RegevCtM) :
    (polyBlocks spk rpk cts).length = numKeyCols + 2 * cts.length := by
  simp [polyBlocks, ct_blocks_length, numKeyCols]
  omega

theorem dual_key_public_values_length {spk rpk : RegevPkM} {cts : List RegevCtM}
    (domain : Nat) (extra : List Nat)
    (hs : PkShaped spk) (hr : PkShaped rpk) (hc : ∀ ct ∈ cts, CtShaped ct) :
    (dualKeyPublicValues domain extra spk rpk cts).length =
      1 + extra.length + (numKeyCols + 2 * cts.length) * regevN := by
  have hjoin := join_uniform_length regevN (polyBlocks spk rpk cts)
    (poly_blocks_uniform hs hr hc)
  simp [dualKeyPublicValues, hjoin, poly_blocks_length]
  omega

/-! ## Encoder injectivity

The security property the source relies on when it says the verifier "rebuilds the
public values itself": two different statements (or two different purposes) produce
different public-value vectors. Whether a different vector produces a diverging
Fiat-Shamir transcript is the `StarkSoundness` boundary. -/

theorem ct_blocks_inj :
    ∀ (cts cts' : List RegevCtM), ctBlocks cts = ctBlocks cts' → cts = cts'
  | [], [], _ => rfl
  | [], _ :: _, h => by simp [ctBlocks, List.bind] at h
  | _ :: _, [], h => by simp [ctBlocks, List.bind] at h
  | c :: cs, d :: ds, h => by
      simp only [ctBlocks, List.bind, List.map, List.join, List.cons_append, List.nil_append,
        List.cons.injEq] at h
      have hcd : c = d := by
        cases c; cases d; simp_all
      have htl : ctBlocks cs = ctBlocks ds := by
        simpa [ctBlocks] using h.2.2
      rw [hcd, ct_blocks_inj cs ds htl]

theorem dual_key_public_values_injective
    {domain domain' : Nat} {extra extra' : List Nat}
    {spk rpk spk' rpk' : RegevPkM} {cts cts' : List RegevCtM}
    (hs : PkShaped spk) (hr : PkShaped rpk) (hc : ∀ ct ∈ cts, CtShaped ct)
    (hs' : PkShaped spk') (hr' : PkShaped rpk') (hc' : ∀ ct ∈ cts', CtShaped ct)
    (hextra : extra.length = extra'.length) (hnum : cts.length = cts'.length)
    (h : dualKeyPublicValues domain extra spk rpk cts =
        dualKeyPublicValues domain' extra' spk' rpk' cts') :
    domain = domain' ∧ extra = extra' ∧ spk = spk' ∧ rpk = rpk' ∧ cts = cts' := by
  have hhead : (domain :: extra).length = (domain' :: extra').length := by
    simp [hextra]
  have hsplit := list_append_split (domain :: extra) (domain' :: extra')
    ((polyBlocks spk rpk cts).join) ((polyBlocks spk' rpk' cts').join) h hhead
  have hd : domain = domain' ∧ extra = extra' := by
    have := hsplit.1
    simp only [List.cons.injEq] at this
    exact this
  have hlen : (polyBlocks spk rpk cts).length = (polyBlocks spk' rpk' cts').length := by
    rw [poly_blocks_length, poly_blocks_length, hnum]
  have hblocks : polyBlocks spk rpk cts = polyBlocks spk' rpk' cts' :=
    join_uniform_inj regevN _ _ (poly_blocks_uniform hs hr hc) (poly_blocks_uniform hs' hr' hc')
      hlen hsplit.2
  simp only [polyBlocks, List.cons_append, List.nil_append, List.cons.injEq] at hblocks
  obtain ⟨ha1, hb1, ha2, hb2, hrest⟩ := hblocks
  refine ⟨hd.1, hd.2, ?_, ?_, ct_blocks_inj cts cts' hrest⟩
  · cases spk; cases spk'; simp_all
  · cases rpk; cases rpk'; simp_all

/-- Cross-purpose separation at the encoder level: an E-1 and an E-2 public-value
vector never coincide, because the leading domain word differs. -/
theorem channel_tx_update_public_values_differ
    (spk rpk spk' rpk' : RegevPkM) (b e a : RegevCtM) (b' a' sd rd : RegevCtM)
    (amount tokenIndex : Nat) :
    channelTxPublicValues spk rpk b e a ≠
      channelUpdatePublicValues spk' rpk' b' a' sd rd amount tokenIndex := by
  intro h
  simp only [channelTxPublicValues, channelUpdatePublicValues, dualKeyPublicValues,
    List.cons_append, List.nil_append, List.cons.injEq] at h
  exact absurd h.1 (by decide)

/-! ## Amount encodings (transfer_stark.rs lines 682-708; the D1 bit encoding) -/

theorem amount_limbs_injective {x y : Nat} (hx : x < 18446744073709551616)
    (hy : y < 18446744073709551616) (h : amountLimbs x = amountLimbs y) : x = y := by
  simp only [amountLimbs, List.cons.injEq, and_true] at h
  obtain ⟨h0, h1, h2, h3⟩ := h
  omega

def bitAt (v i : Nat) : Nat := v / 2 ^ i % 2

/-- `encode_amount` (deviation D1): one bit per coefficient, the amount in the low
64 coefficients, zero above. Modelled from the documented encoding; the body of the
upstream `encode_value_message` is the `UpstreamRegev` boundary. -/
def encodeAmount (v : Nat) : List Nat :=
  (List.range amountBits).map (bitAt v) ++ List.replicate (regevN - amountBits) 0

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

/-- Weighted little-endian value of a digit list starting at weight `2 ^ i`. -/
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
    show d * 2 ^ i + listWeighted (ds ++ ys) (i + 1) =
      d * 2 ^ i + listWeighted ds (i + 1) + listWeighted ys (i + (ds.length + 1))
    rw [ih ys (i + 1)]
    have hi : i + 1 + ds.length = i + (ds.length + 1) := by omega
    rw [hi]
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
  | zero => simp [List.range, List.range.loop, listWeighted, Nat.mod_one]
  | succ w ih =>
    rw [range_succ_append, List.map_append, list_weighted_append, ih]
    simp only [List.map, listWeighted, List.length_map, range_length_eq, Nat.zero_add]
    rw [mod_two_pow_succ v w]
    omega

/-- The value of the whole 2048-coefficient message column is the amount itself
(the padding coefficients contribute nothing). -/
theorem encode_amount_value (v : Nat) (h : v < 2 ^ amountBits) :
    listWeighted (encodeAmount v) 0 = v := by
  rw [encodeAmount, list_weighted_append, list_weighted_bits,
    list_weighted_replicate_zero]
  simpa using Nat.mod_eq_of_lt h

/-- ENCODER INJECTIVITY: distinct u64 amounts have distinct message columns, so the
public message polynomial `encode_amount(amount)` that `verify_channel_update` and
`verify_withdraw_claim` recompute determines the amount. -/
theorem encode_amount_injective {x y : Nat} (hx : x < 2 ^ amountBits)
    (hy : y < 2 ^ amountBits) (h : encodeAmount x = encodeAmount y) : x = y := by
  have hv : listWeighted (encodeAmount x) 0 = listWeighted (encodeAmount y) 0 := by rw [h]
  rw [encode_amount_value x hx, encode_amount_value y hy] at hv
  exact hv

theorem encode_amount_length (v : Nat) : (encodeAmount v).length = regevN := by
  simp [encodeAmount, range_length_eq, amountBits, regevN]

/-- The property the F2-C soundness argument leans on: the public encoding pins the
coefficients at index >= 64 to zero. -/
theorem encode_amount_high_zero (v : Nat) :
    (encodeAmount v).drop amountBits = List.replicate (regevN - amountBits) 0 := by
  have hlen : ((List.range amountBits).map (bitAt v)).length = amountBits := by
    simp [range_length_eq]
  calc (encodeAmount v).drop amountBits
      = ((List.range amountBits).map (bitAt v) ++
          List.replicate (regevN - amountBits) 0).drop
            ((List.range amountBits).map (bitAt v)).length := by rw [encodeAmount, hlen]
    _ = List.replicate (regevN - amountBits) 0 := List.drop_left _ _

/-! ## Evaluation arguments and aux-column layout (transfer_stark.rs lines 348-394,
1457-1501)

Each lookup's aux column index equals its position in the spec list, so this list
IS the aux layout and the order of the published evaluations. -/

inductive LookupKind where
  | globalEval (name : String)
  | localEval
  deriving DecidableEq, Repr

def LookupKind.isGlobal : LookupKind → Bool
  | .globalEval _ => true
  | .localEval => false

def ctLookupKinds (s : AirShape) (j : Nat) : List LookupKind :=
  [ .globalEval s!"eval:c1:ct{j}", .globalEval s!"eval:c2:ct{j}", .localEval, .localEval,
    .localEval,
    (if s.exposeM.getD j false then .globalEval s!"eval:m:ct{j}" else .localEval),
    .localEval, .localEval ]

def dualKeyLookupKinds (s : AirShape) : List LookupKind :=
  [ .globalEval "eval:a_s", .globalEval "eval:b_s", .globalEval "eval:a_r",
    .globalEval "eval:b_r" ] ++ (List.range s.numCts).bind (ctLookupKinds s)

def decryptionCoreLookupKinds (exposeBit : Bool) : List LookupKind :=
  [ .globalEval "eval:a", .globalEval "eval:b", .globalEval "eval:c1", .globalEval "eval:c2",
    .localEval, .localEval, .localEval, .localEval, .localEval,
    (if exposeBit then .globalEval "eval:amount_bits" else .localEval) ]

def refreshLookupKinds : List LookupKind :=
  decryptionCoreLookupKinds false ++
    [ .globalEval "eval:c1_new", .globalEval "eval:c2_new", .localEval, .localEval, .localEval,
      .localEval, .localEval ]

/-- Each ciphertext contributes exactly `CT_AUX = 8` aux columns, so the aux layout
`auxBase j + AOFF_*` is the position of the corresponding lookup. -/
theorem dual_key_lookup_layout :
    (dualKeyLookupKinds e1Shape).length = e1Shape.numAuxCols ∧
      (dualKeyLookupKinds e2Shape).length = e2Shape.numAuxCols ∧
      (decryptionCoreLookupKinds true).length = decCoreAux ∧
      refreshLookupKinds.length = refreshAuxCols := by
  refine ⟨by decide, by decide, by decide, by decide⟩

/-- The verifier's published-evaluation shape check counts exactly the `Kind::Global`
lookups of the AIR it is verifying. -/
theorem published_eval_counts_match_lookups :
    ((dualKeyLookupKinds e1Shape).filter LookupKind.isGlobal).length = e1Shape.numPublishedEvals ∧
      ((dualKeyLookupKinds e2Shape).filter LookupKind.isGlobal).length = e2Shape.numPublishedEvals ∧
      ((decryptionCoreLookupKinds true).filter LookupKind.isGlobal).length = decNumPublished ∧
      (refreshLookupKinds.filter LookupKind.isGlobal).length = rfNumPublished := by
  refine ⟨by decide, by decide, by decide, by decide⟩

/-- Privacy side of the layout: in E-1 no message evaluation is published, and in
the refresh AIR the normalized bit column (the SECRET balance) stays `Kind::Local`.
This is a statement about which evaluations the AIR exposes, not a zero-knowledge
claim (see the `StarkSoundness` boundary). -/
theorem secret_message_columns_not_published :
    (∀ j, j < e1Shape.numCts → LookupKind.localEval ∈ ctLookupKinds e1Shape j) ∧
      (decryptionCoreLookupKinds false).getD 9 .localEval = .localEval ∧
      refreshLookupKinds.getD 9 .localEval = .localEval := by
  refine ⟨?_, by decide, by decide⟩
  intro j _
  simp [ctLookupKinds]

/-- In E-2 exactly the two delta ciphertexts expose their message evaluation, which
is what lets the verifier pin them to the PUBLIC amount. -/
theorem e2_exposed_messages_are_the_deltas :
    e2Shape.exposeM = [false, false, true, true] ∧
      e2Shape.carryDelta = 2 ∧ e2Shape.recipientCt.getD 3 false = true := by
  refine ⟨rfl, rfl, by decide⟩

/-! ## Ring identities at the shared challenge (transfer_stark.rs lines 443-482)

Each ciphertext is bound to ONE of the two key pairs; that selection is what makes
the statement dual-key. The equations themselves are recorded structurally (which
aux columns each identity reads); the extension-field arithmetic and the
Schwartz-Zippel step stay the `EvaluationArgumentSoundness` boundary. -/

structure RingEq where
  keyAux : Nat
  rAux : Nat
  eAux : Nat
  ctAux : Nat
  quotientAux : Nat
  scaledMessageAux : Option Nat
  deriving DecidableEq, Repr, Inhabited

def dualKeyRingEqs (s : AirShape) : List RingEq :=
  (List.range s.numCts).bind (fun j =>
    let recip := s.recipientCt.getD j false
    [ { keyAux := if recip then auxAR else auxAS, rAux := auxBase j + aoffR,
        eAux := auxBase j + aoffE1, ctAux := auxBase j + aoffC1,
        quotientAux := auxBase j + aoffK1, scaledMessageAux := none },
      { keyAux := if recip then auxBR else auxBS, rAux := auxBase j + aoffR,
        eAux := auxBase j + aoffE2, ctAux := auxBase j + aoffC2,
        quotientAux := auxBase j + aoffK2,
        scaledMessageAux := some (auxBase j + aoffM) } ])

/-- E-1: `before` and `after` are bound to the SENDER key pair, `enc_amount` (index
1) to the RECIPIENT pair. -/
theorem e1_key_binding_selection :
    ((dualKeyRingEqs e1Shape).map (fun e => e.keyAux)) =
      [auxAS, auxBS, auxAR, auxBR, auxAS, auxBS] := by
  decide

/-- E-2: `before`, `after`, `sender_delta` under the sender pair; `receiver_delta`
(index 3) under the recipient pair. -/
theorem e2_key_binding_selection :
    ((dualKeyRingEqs e2Shape).map (fun e => e.keyAux)) =
      [auxAS, auxBS, auxAS, auxBS, auxAS, auxBS, auxAR, auxBR] := by
  decide

theorem ring_eq_count :
    (dualKeyRingEqs e1Shape).length = 2 * e1Shape.numCts ∧
      (dualKeyRingEqs e2Shape).length = 2 * e2Shape.numCts := by
  refine ⟨by decide, by decide⟩

/-! ## Field-level gates (transfer_stark.rs lines 407-441, 1522-1592)

Column values are `Int` representatives; a constraint "holds" when its expression is
zero modulo q. `FieldProducts` (q prime) is the premise that turns a vanishing
product into a vanishing factor; it is never proved here. -/

def FZero (x : Int) : Prop := x % (regevQ : Int) = 0
def Canonical (x : Int) : Prop := 0 ≤ x ∧ x < (regevQ : Int)
def FieldProducts : Prop := ∀ x y : Int, FZero (x * y) → FZero x ∨ FZero y

/-- `builder.assert_bool(m)`. -/
def BoolGate (x : Int) : Prop := FZero (x * (x - 1))
/-- `r * (r - 1) * (r + 1) = 0`: ternary randomness / secret key. -/
def TernaryGate (x : Int) : Prop := FZero (x * ((x - 1) * (x + 1)))
/-- `x * (x - 1) * (x - 2) = 0`: a CBD(2) noise half. -/
def CbdHalfGate (x : Int) : Prop := FZero (x * ((x - 1) * (x - 2)))

theorem small_fzero_eq_zero (x : Int) (h : FZero x) (hlo : -(regevQ : Int) < x)
    (hhi : x < (regevQ : Int)) : x = 0 := by
  unfold FZero at h
  have hq : ((regevQ : Nat) : Int) = 2013265921 := by decide
  rw [hq] at h hlo hhi
  omega

theorem bool_gate_forces_bit (hf : FieldProducts) (x : Int) (hc : Canonical x)
    (h : BoolGate x) : x = 0 ∨ x = 1 := by
  obtain ⟨hc0, hc1⟩ := hc
  have hq : ((regevQ : Nat) : Int) = 2013265921 := by decide
  rw [hq] at hc1
  rcases hf _ _ h with h0 | h1
  · exact Or.inl (small_fzero_eq_zero x h0 (by rw [hq]; omega) (by rw [hq]; omega))
  · have h1' := small_fzero_eq_zero (x - 1) h1 (by rw [hq]; omega) (by rw [hq]; omega)
    exact Or.inr (by omega)

theorem ternary_gate_forces (hf : FieldProducts) (x : Int) (hc : Canonical x)
    (h : TernaryGate x) : x = 0 ∨ x = 1 ∨ x = (regevQ : Int) - 1 := by
  obtain ⟨hc0, hc1⟩ := hc
  have hq : ((regevQ : Nat) : Int) = 2013265921 := by decide
  rw [hq] at hc1
  rcases hf _ _ h with h0 | hrest
  · exact Or.inl (small_fzero_eq_zero x h0 (by rw [hq]; omega) (by rw [hq]; omega))
  · rcases hf _ _ hrest with h1 | h2
    · have h1' := small_fzero_eq_zero (x - 1) h1 (by rw [hq]; omega) (by rw [hq]; omega)
      exact Or.inr (Or.inl (by omega))
    · have h2' : (x + 1) % (2013265921 : Int) = 0 := by
        simp only [FZero] at h2
        rw [hq] at h2
        exact h2
      exact Or.inr (Or.inr (by rw [hq]; omega))

theorem cbd_half_gate_forces (hf : FieldProducts) (x : Int) (hc : Canonical x)
    (h : CbdHalfGate x) : x = 0 ∨ x = 1 ∨ x = 2 := by
  obtain ⟨hc0, hc1⟩ := hc
  have hq : ((regevQ : Nat) : Int) = 2013265921 := by decide
  rw [hq] at hc1
  rcases hf _ _ h with h0 | hrest
  · exact Or.inl (small_fzero_eq_zero x h0 (by rw [hq]; omega) (by rw [hq]; omega))
  · rcases hf _ _ hrest with h1 | h2
    · have h1' := small_fzero_eq_zero (x - 1) h1 (by rw [hq]; omega) (by rw [hq]; omega)
      exact Or.inr (Or.inl (by omega))
    · have h2' := small_fzero_eq_zero (x - 2) h2 (by rw [hq]; omega) (by rw [hq]; omega)
      exact Or.inr (Or.inr (by omega))

/-! ## Ripple-carry chains (transfer_stark.rs lines 423-441 and 1566-1575)

Both AIRs use the same shape: `src_i + c_i = out_i + 2*c_{i+1}` with `c_0 = 0` and a
last-row form that forces the final carry to zero, so the identity holds over the
integers. -/

/-- Little-endian value of a column over its first `k` rows. -/
def colValue (f : Nat → Int) : Nat → Int
  | 0 => 0
  | k + 1 => f 0 + 2 * colValue (fun i => f (i + 1)) k

theorem col_value_add (f g : Nat → Int) :
    ∀ k, colValue (fun i => f i + g i) k = colValue f k + colValue g k := by
  intro k
  induction k generalizing f g with
  | zero => simp [colValue]
  | succ k ih =>
    show f 0 + g 0 + 2 * colValue (fun i => f (i + 1) + g (i + 1)) k = _
    rw [ih (fun i => f (i + 1)) (fun i => g (i + 1))]
    show _ = (f 0 + 2 * colValue (fun i => f (i + 1)) k) + (g 0 + 2 * colValue (fun i => g (i + 1)) k)
    omega

theorem col_value_nonneg (f : Nat → Int) :
    ∀ k, (∀ i, i < k → 0 ≤ f i) → 0 ≤ colValue f k := by
  intro k
  induction k generalizing f with
  | zero => intro _; simp [colValue]
  | succ k ih =>
    intro h
    have h0 : 0 ≤ f 0 := h 0 (by omega)
    have hrest : 0 ≤ colValue (fun i => f (i + 1)) k :=
      ih (fun i => f (i + 1)) (fun i hi => h (i + 1) (by omega))
    show 0 ≤ f 0 + 2 * colValue (fun i => f (i + 1)) k
    omega

/-- The generic ripple-carry soundness statement: with `c_0` free, the chain forces
`value(src) + c_0 = value(out)` over the INTEGERS. Applied twice: to the
`before = after + delta` conservation chain and to the digit-to-bit normalization
adder. -/
theorem carry_chain_value :
    ∀ (n : Nat) (src out carry : Nat → Int),
      (∀ i, i + 1 < n + 1 → src i + carry i - out i - 2 * carry (i + 1) = 0) →
      (src n + carry n - out n = 0) →
      colValue src (n + 1) + carry 0 = colValue out (n + 1) := by
  intro n
  induction n with
  | zero =>
    intro src out carry _ hlast
    show src 0 + 2 * colValue (fun i => src (i + 1)) 0 + carry 0 =
      out 0 + 2 * colValue (fun i => out (i + 1)) 0
    simp only [colValue]
    omega
  | succ n ih =>
    intro src out carry htrans hlast
    have h0 : src 0 + carry 0 - out 0 - 2 * carry 1 = 0 := htrans 0 (by omega)
    have hshift := ih (fun i => src (i + 1)) (fun i => out (i + 1)) (fun i => carry (i + 1))
      (fun i hi => htrans (i + 1) (by omega)) hlast
    simp only [Nat.zero_add] at hshift h0
    show src 0 + 2 * colValue (fun i => src (i + 1)) (n + 1) + carry 0 =
      out 0 + 2 * colValue (fun i => out (i + 1)) (n + 1)
    omega

/-! ### E-1/E-2 conservation: `before = after + delta` over the integers -/

structure ConservationChain (n : Nat) where
  before : Nat → Int
  delta : Nat → Int
  after : Nat → Int
  carry : Nat → Int
  /-- `builder.assert_bool` on every message column and on the carry column. -/
  messagesBoolean : ∀ i, i ≤ n → (before i = 0 ∨ before i = 1) ∧ (delta i = 0 ∨ delta i = 1) ∧
    (after i = 0 ∨ after i = 1)
  carryBoolean : ∀ i, i ≤ n → carry i = 0 ∨ carry i = 1
  /-- `builder.when_first_row().assert_zero(carry)`. -/
  firstCarryZero : carry 0 = 0
  /-- `when_transition`: `after + delta + carry - before = 2 * carry_next`. -/
  transitionGate : ∀ i, i + 1 < n + 1 →
    FZero (after i + delta i + carry i - before i - 2 * carry (i + 1))
  /-- `when_last_row`: the same expression without the next carry. -/
  lastRowGate : FZero (after n + delta n + carry n - before n)

/-- Step 1: each field constraint of the chain also holds over the integers, because
every term is a bit and `|expr| <= 4 < q`. This is the source's SECURITY note at
line 424 made explicit. -/
theorem conservation_gates_integral {n : Nat} (c : ConservationChain n) :
    (∀ i, i + 1 < n + 1 →
        c.after i + c.delta i + c.carry i - c.before i - 2 * c.carry (i + 1) = 0) ∧
      (c.after n + c.delta n + c.carry n - c.before n = 0) := by
  have hq : ((regevQ : Nat) : Int) = 2013265921 := by decide
  constructor
  · intro i hi
    have hb := c.messagesBoolean i (by omega)
    have hc := c.carryBoolean i (by omega)
    have hc' := c.carryBoolean (i + 1) (by omega)
    refine small_fzero_eq_zero _ (c.transitionGate i hi) ?_ ?_ <;> rw [hq] <;> omega
  · have hb := c.messagesBoolean n (by omega)
    have hc := c.carryBoolean n (by omega)
    refine small_fzero_eq_zero _ c.lastRowGate ?_ ?_ <;> rw [hq] <;> omega

/-- CONSERVATION (fund safety, detail2 E-1.2): the committed message columns satisfy
`value(before) = value(after) + value(delta)` over the integers. -/
theorem conservation_over_integers {n : Nat} (c : ConservationChain n) :
    colValue c.before (n + 1) = colValue c.after (n + 1) + colValue c.delta (n + 1) := by
  obtain ⟨htrans, hlast⟩ := conservation_gates_integral c
  have hsum := carry_chain_value n (fun i => c.after i + c.delta i) c.before c.carry
    (by
      intro i hi
      have h := htrans i hi
      show c.after i + c.delta i + c.carry i - c.before i - 2 * c.carry (i + 1) = 0
      omega)
    (by
      show c.after n + c.delta n + c.carry n - c.before n = 0
      omega)
  rw [col_value_add] at hsum
  rw [c.firstCarryZero] at hsum
  omega

/-- NO UNDERFLOW: because every plaintext is a committed bit vector (hence
non-negative) and the final carry is zero, the spent delta can never exceed the
balance. -/
theorem conservation_no_underflow {n : Nat} (c : ConservationChain n) :
    colValue c.delta (n + 1) ≤ colValue c.before (n + 1) := by
  have hafter : 0 ≤ colValue c.after (n + 1) := by
    refine col_value_nonneg _ _ (fun i hi => ?_)
    rcases (c.messagesBoolean i (by omega)).2.2 with h | h <;> omega
  have := conservation_over_integers c
  omega

/-! ### Digit extraction and the digit-to-bit normalization adder
(transfer_stark.rs lines 1304-1343, 1550-1575) -/

/-- Uniqueness of the digit/noise decomposition `v + delta/2 = delta*d + ns (mod q)`:
the ranges `d < 256` and `ns < delta` make the residue determine BOTH. This is the
no-wrap analysis of lines 1315-1327; it is the reason the shifted noise is
decomposed as `lo + (u+v)*2^19` rather than as a plain 23-bit value. -/
theorem digit_decomposition_unique (d d' ns ns' : Int)
    (hd : 0 ≤ d) (hd2 : d < 256) (hd' : 0 ≤ d') (hd'2 : d' < 256)
    (hns : 0 ≤ ns) (hns2 : ns < (deltaU32 : Int))
    (hns' : 0 ≤ ns') (hns'2 : ns' < (deltaU32 : Int))
    (h : FZero ((deltaU32 : Int) * d + ns - ((deltaU32 : Int) * d' + ns'))) :
    d = d' ∧ ns = ns' := by
  have hdelta : ((deltaU32 : Nat) : Int) = 7864320 := by decide
  have hq : ((regevQ : Nat) : Int) = 2013265921 := by decide
  rw [hdelta] at hns2 hns'2 h
  have hzero : (7864320 : Int) * d + ns - (7864320 * d' + ns') = 0 := by
    refine small_fzero_eq_zero _ h ?_ ?_ <;> rw [hq] <;> omega
  omega

/-- The 23-bit alternative the source rejects really is unsound: with `ns` merely
`< 2^23` the same residue admits two different digits (`d` and `d + 255` shifted by
one), so the `lo + (u+v)*2^19` shape is load-bearing. -/
theorem digit_decomposition_wrap_witness :
    (7864320 : Int) * 255 + 7864321 - ((7864320 : Int) * 0 + 0) = (regevQ : Int) ∧
      (7864321 : Int) < 2 ^ 23 := by
  refine ⟨by decide, by decide⟩

/-- The normalization adder binds the digit column and the bit column to the SAME
integer value (constraint (4) of the decryption core). -/
structure NormalizationChain (n : Nat) where
  digit : Nat → Int
  bit : Nat → Int
  carry : Nat → Int
  digitRange : ∀ i, i ≤ n → 0 ≤ digit i ∧ digit i < 256
  bitBoolean : ∀ i, i ≤ n → bit i = 0 ∨ bit i = 1
  carryRange : ∀ i, i ≤ n → 0 ≤ carry i ∧ carry i < 256
  firstCarryZero : carry 0 = 0
  transitionGate : ∀ i, i + 1 < n + 1 →
    FZero (digit i + carry i - bit i - 2 * carry (i + 1))
  lastRowGate : FZero (digit n + carry n - bit n)

theorem normalization_binds_digits_to_bits {n : Nat} (c : NormalizationChain n) :
    colValue c.digit (n + 1) = colValue c.bit (n + 1) := by
  have hq : ((regevQ : Nat) : Int) = 2013265921 := by decide
  have htrans : ∀ i, i + 1 < n + 1 →
      c.digit i + c.carry i - c.bit i - 2 * c.carry (i + 1) = 0 := by
    intro i hi
    have hd := c.digitRange i (by omega)
    have hb := c.bitBoolean i (by omega)
    have hc := c.carryRange i (by omega)
    have hc' := c.carryRange (i + 1) (by omega)
    refine small_fzero_eq_zero _ (c.transitionGate i hi) ?_ ?_ <;> rw [hq] <;> omega
  have hlast : c.digit n + c.carry n - c.bit n = 0 := by
    have hd := c.digitRange n (by omega)
    have hb := c.bitBoolean n (by omega)
    have hc := c.carryRange n (by omega)
    refine small_fzero_eq_zero _ c.lastRowGate ?_ ?_ <;> rw [hq] <;> omega
  have := carry_chain_value n c.digit c.bit c.carry htrans hlast
  rw [c.firstCarryZero] at this
  omega

/-- The carry bound of lines 1337-1343: with `d <= 255`, `bit <= 1` and `c_0 = 0`
every carry stays below 256, so `CARRY_BITS = 8` boolean columns are enough (and 7
would not be: `c` can exceed 127). -/
theorem normalization_carry_bound (d c bit cnext : Int)
    (hd : 0 ≤ d ∧ d < 256) (hc : 0 ≤ c ∧ c < 256) (hb : bit = 0 ∨ bit = 1)
    (h : d + c - bit - 2 * cnext = 0) : 0 ≤ cnext ∧ cnext < 256 := by
  omega

theorem normalization_carry_can_exceed_half :
    ∃ d c bit cnext : Int, (0 ≤ d ∧ d < 256) ∧ (0 ≤ c ∧ c < 256) ∧ (bit = 0 ∨ bit = 1) ∧
      d + c - bit - 2 * cnext = 0 ∧ 127 < cnext := by
  refine ⟨255, 255, 0, 255, ⟨by decide, by decide⟩, ⟨by decide, by decide⟩, Or.inl rfl,
    by decide, by decide⟩

/-! ## Evaluation of a public polynomial at the shared challenge
(transfer_stark.rs lines 996-1031)

`Chal` is `Int` here: the model reproduces the Horner recursion and the positional
comparison, NOT the quartic BabyBear extension arithmetic or the Schwartz-Zippel
step (`EvaluationArgumentSoundness`). -/

abbrev Chal := Int

def evalAt : List Nat → Chal → Chal
  | [], _ => 0
  | c :: cs, z => (c : Chal) + z * evalAt cs z

/-- The source's `eval_at`: fold `acc * z + c` over the REVERSED coefficients. -/
def evalAtFold (coeffs : List Nat) (z : Chal) : Chal :=
  List.foldl (fun (acc : Chal) (c : Nat) => acc * z + (c : Chal)) (0 : Chal) coeffs.reverse

theorem eval_at_matches_fold (z : Chal) : ∀ coeffs, evalAtFold coeffs z = evalAt coeffs z := by
  intro coeffs
  induction coeffs with
  | nil => rfl
  | cons c cs ih =>
    have hstep : evalAtFold (c :: cs) z = evalAtFold cs z * z + (c : Chal) := by
      simp [evalAtFold, List.reverse_cons, List.foldl_append]
    rw [hstep, ih]
    show evalAt cs z * z + (c : Chal) = (c : Chal) + z * evalAt cs z
    rw [Int.mul_comm]
    exact Int.add_comm _ _

/-! ## Proof, backend and the shape checks (transfer_stark.rs lines 822-894) -/

inductive RegevSecurityLevel where
  | test
  | production
  deriving DecidableEq, Repr

/-- The parts of a `BatchProof` this model reads: the per-instance degree bits and
the first instance's published (`Kind::Global`) evaluations. Everything else is an
opaque payload. -/
structure ProofM where
  degreeBits : List Nat
  publishedEvals : List Chal
  payload : Nat
  deriving DecidableEq, Repr

/-- The plonky3 backend as an opaque callback pair: `postcard::from_bytes` and
`stark::verify_batch` (which returns the shared evaluation challenge `z`). No
property of either is assumed — this is the `StarkSoundness` boundary. -/
structure Backend where
  decode : List Nat → Except RegevError ProofM
  verifyBatch : RegevSecurityLevel → Nat → List Nat → ProofM → Except RegevError Chal

/-- Which AIR (and hence which lookup set) the verifier instantiates. -/
def airChannelTx : Nat := 1
def airChannelUpdate : Nat := 2
def airWithdrawClaim : Nat := 3
def airBalanceRefresh : Nat := 4
def airHashSig : Nat := 5

def logRingN : Nat := 11
/-- `config.is_zk()` is 1 for both levels (both are hiding configs) — an
`UpstreamRegev` boundary value, pinned here. -/
def configIsZk : Nat := 1
def expectedDegreeBits : Nat := logRingN + configIsZk

theorem expected_degree_bits_pinned : expectedDegreeBits = 12 := by decide

/-- `r` then `k`, propagating `r`'s error: the `?` sequencing of the source. -/
def ensure (r : Except RegevError Unit) (k : Except RegevError Unit) : Except RegevError Unit :=
  match r with
  | .error e => .error e
  | .ok _ => k

theorem ensure_error {r : Except RegevError Unit} {e : RegevError}
    (h : r = .error e) (k : Except RegevError Unit) : ensure r k = .error e := by
  rw [h]; rfl

theorem ensure_ok_iff (r k : Except RegevError Unit) :
    ensure r k = .ok () ↔ r = .ok () ∧ k = .ok () := by
  cases r with
  | error e => simp [ensure]
  | ok u => cases u; simp [ensure]

def verifyOne (bk : Backend) (level : RegevSecurityLevel) (airId : Nat) (proofBytes : List Nat)
    (pvs : List Nat) (numPublished expectedDb : Nat) : Except RegevError (Chal × ProofM) :=
  match bk.decode proofBytes with
  | .error e => .error e
  | .ok p =>
      if p.degreeBits ≠ [expectedDb] then .error .proofVerification
      else if p.publishedEvals.length ≠ numPublished then .error .proofVerification
      else
        match bk.verifyBatch level airId pvs p with
        | .error e => .error e
        | .ok z => .ok (z, p)

theorem verify_one_ok {bk : Backend} {level : RegevSecurityLevel} {airId : Nat}
    {proofBytes pvs : List Nat} {numPublished expectedDb : Nat} {z : Chal} {p : ProofM}
    (h : verifyOne bk level airId proofBytes pvs numPublished expectedDb = .ok (z, p)) :
    bk.decode proofBytes = .ok p ∧ p.degreeBits = [expectedDb] ∧
      p.publishedEvals.length = numPublished ∧ bk.verifyBatch level airId pvs p = .ok z := by
  unfold verifyOne at h
  cases hd : bk.decode proofBytes with
  | error e => rw [hd] at h; exact absurd h (by simp)
  | ok p' =>
    rw [hd] at h
    dsimp only at h
    by_cases h1 : p'.degreeBits ≠ [expectedDb]
    · rw [if_pos h1] at h; exact absurd h (by simp)
    · rw [if_neg h1] at h
      by_cases h2 : p'.publishedEvals.length ≠ numPublished
      · rw [if_pos h2] at h; exact absurd h (by simp)
      · rw [if_neg h2] at h
        cases hv : bk.verifyBatch level airId pvs p' with
        | error e => rw [hv] at h; exact absurd h (by simp)
        | ok z' =>
          rw [hv] at h
          have heq : (z', p') = (z, p) := by
            simpa using h
          have hz : z' = z := congrArg Prod.fst heq
          have hp : p' = p := congrArg Prod.snd heq
          rw [← hz, ← hp]
          refine ⟨?_, by simpa using h1, by simpa using h2, ?_⟩
          · first | exact hd | rfl
          · first | exact hv | rfl

def checkPublishedEvals (p : ProofM) (expected : List Chal) : Except RegevError Unit :=
  if p.publishedEvals = expected then .ok () else .error .proofVerification

/-- Expected published evaluations in lookup order (lines 1003-1031): the four key
polynomials, then per ciphertext `c1, c2` and — where the shape exposes it — the
PUBLIC message polynomial. -/
def expectedPublishedEvals (s : AirShape) (spk rpk : RegevPkM) (cts : List RegevCtM)
    (mPub : List Nat) (z : Chal) : List Chal :=
  [evalAt spk.a z, evalAt spk.b z, evalAt rpk.a z, evalAt rpk.b z] ++
    (List.range s.numCts).bind (fun j =>
      let ct := cts.getD j ⟨[], []⟩
      [evalAt ct.c1 z, evalAt ct.c2 z] ++
        (if s.exposeM.getD j false then [evalAt mPub z] else []))

/-! ## The four verifiers (transfer_stark.rs lines 1128-1159, 1238-1284, 2063-2104,
2181-2208)

Each rebuilds the public values from the CLAIMED statement with ITS OWN purpose
domain word, after validating every key and ciphertext canonically. -/

def verifyChannelTx (bk : Backend) (level : RegevSecurityLevel) (spk rpk : RegevPkM)
    (before encAmount after : RegevCtM) (proofBytes : List Nat) : Except RegevError Unit :=
  ensure (pkValidate spk) (ensure (pkValidate rpk) (ensure (ctValidate before)
    (ensure (ctValidate encAmount) (ensure (ctValidate after)
      (match verifyOne bk level airChannelTx proofBytes
          (channelTxPublicValues spk rpk before encAmount after)
          e1Shape.numPublishedEvals expectedDegreeBits with
       | .error e => .error e
       | .ok (z, p) =>
           checkPublishedEvals p
             (expectedPublishedEvals e1Shape spk rpk [before, encAmount, after] [] z))))))

def verifyChannelUpdate (bk : Backend) (level : RegevSecurityLevel) (spk rpk : RegevPkM)
    (before after senderDelta receiverDelta : RegevCtM) (amount tokenIndex : Nat)
    (proofBytes : List Nat) : Except RegevError Unit :=
  ensure (pkValidate spk) (ensure (pkValidate rpk) (ensure (ctValidate before)
    (ensure (ctValidate after) (ensure (ctValidate senderDelta) (ensure (ctValidate receiverDelta)
      (match verifyOne bk level airChannelUpdate proofBytes
          (channelUpdatePublicValues spk rpk before after senderDelta receiverDelta amount
            tokenIndex)
          e2Shape.numPublishedEvals expectedDegreeBits with
       | .error e => .error e
       | .ok (z, p) =>
           checkPublishedEvals p
             (expectedPublishedEvals e2Shape spk rpk [before, after, senderDelta, receiverDelta]
               (encodeAmount amount) z)))))))

def verifyWithdrawClaim (bk : Backend) (level : RegevSecurityLevel) (pk : RegevPkM)
    (ct : RegevCtM) (amount : Nat) (proofBytes : List Nat) : Except RegevError Unit :=
  ensure (pkValidate pk) (ensure (ctValidate ct)
    (match verifyOne bk level airWithdrawClaim proofBytes
        (decryptionPublicValues withdrawClaimZkpDomain amount pk ct)
        decNumPublished expectedDegreeBits with
     | .error e => .error e
     | .ok (z, p) =>
         checkPublishedEvals p
           [evalAt pk.a z, evalAt pk.b z, evalAt ct.c1 z, evalAt ct.c2 z,
             evalAt (encodeAmount amount) z]))

def verifyBalanceRefresh (bk : Backend) (level : RegevSecurityLevel) (pk : RegevPkM)
    (oldCt newCt : RegevCtM) (proofBytes : List Nat) : Except RegevError Unit :=
  ensure (pkValidate pk) (ensure (ctValidate oldCt) (ensure (ctValidate newCt)
    (match verifyOne bk level airBalanceRefresh proofBytes
        (refreshPublicValues balanceRefreshZkpDomain pk oldCt newCt)
        rfNumPublished expectedDegreeBits with
     | .error e => .error e
     | .ok (z, p) =>
         checkPublishedEvals p
           [evalAt pk.a z, evalAt pk.b z, evalAt oldCt.c1 z, evalAt oldCt.c2 z,
             evalAt newCt.c1 z, evalAt newCt.c2 z])))

/-! ## Statement-level verifier (transfer_stark.rs lines 2214-2336) -/

inductive RegevStatement where
  | channelTx (senderPk recipientPk : RegevPkM) (before encAmount after : RegevCtM)
  | channelUpdate (senderPk recipientPk : RegevPkM)
      (before after senderDelta receiverDelta : RegevCtM) (amount tokenIndex : Nat)
  | withdrawClaim (userPk : RegevPkM) (userAmountCt : RegevCtM) (amount : Nat)
  | balanceRefresh (pk : RegevPkM) (oldCt newCt : RegevCtM)
  deriving Repr

def RegevStatement.variant : RegevStatement → RegevProofPurpose
  | .channelTx .. => .channelTx
  | .channelUpdate .. => .channelUpdate
  | .withdrawClaim .. => .withdrawClaim
  | .balanceRefresh .. => .balanceRefresh

def realRegevProofVerify (bk : Backend) (level : RegevSecurityLevel)
    (purpose : RegevProofPurpose) (proofBytes : List Nat) (statement : RegevStatement) :
    Except RegevError Unit :=
  match purpose, statement with
  | .channelTx, .channelTx spk rpk before encAmount after =>
      verifyChannelTx bk level spk rpk before encAmount after proofBytes
  | .channelUpdate, .channelUpdate spk rpk before after sd rd amount tokenIndex =>
      verifyChannelUpdate bk level spk rpk before after sd rd amount tokenIndex proofBytes
  | .withdrawClaim, .withdrawClaim pk ct amount =>
      verifyWithdrawClaim bk level pk ct amount proofBytes
  | .balanceRefresh, .balanceRefresh pk oldCt newCt =>
      verifyBalanceRefresh bk level pk oldCt newCt proofBytes
  | _, _ => .error .purposeMismatch

/-- The structural half of the F2-B defense: a purpose that does not match the
statement variant is rejected before any proof work, for EVERY backend. -/
theorem purpose_mismatch_rejected (bk : Backend) (level : RegevSecurityLevel)
    (purpose : RegevProofPurpose) (proofBytes : List Nat) (statement : RegevStatement)
    (h : purpose ≠ statement.variant) :
    realRegevProofVerify bk level purpose proofBytes statement = .error .purposeMismatch := by
  cases purpose <;> cases statement <;> first | rfl | exact absurd rfl h

/-! ### What acceptance does and does not establish -/

theorem verify_channel_tx_rejects_noncanonical_key (bk : Backend) (level : RegevSecurityLevel)
    {spk : RegevPkM} (rpk : RegevPkM) (before encAmount after : RegevCtM) (proofBytes : List Nat)
    (h : pkValidate spk = .error .invalidPk) :
    verifyChannelTx bk level spk rpk before encAmount after proofBytes = .error .invalidPk := by
  unfold verifyChannelTx
  exact ensure_error h _

theorem verify_channel_tx_rejects_noncanonical_ciphertext (bk : Backend)
    (level : RegevSecurityLevel) (spk rpk : RegevPkM) {before : RegevCtM}
    (encAmount after : RegevCtM) (proofBytes : List Nat)
    (hs : pkValidate spk = .ok ()) (hr : pkValidate rpk = .ok ())
    (h : ctValidate before = .error .invalidCiphertext) :
    verifyChannelTx bk level spk rpk before encAmount after proofBytes =
      .error .invalidCiphertext := by
  unfold verifyChannelTx
  rw [hs, hr]
  show ensure (ctValidate before) _ = _
  exact ensure_error h _

theorem verify_withdraw_claim_rejects_noncanonical_key (bk : Backend)
    (level : RegevSecurityLevel) {pk : RegevPkM} (ct : RegevCtM) (amount : Nat)
    (proofBytes : List Nat) (h : pkValidate pk = .error .invalidPk) :
    verifyWithdrawClaim bk level pk ct amount proofBytes = .error .invalidPk := by
  unfold verifyWithdrawClaim
  exact ensure_error h _

/-- Acceptance of an E-1 proof means exactly: the statement was canonical, the proof
decoded, its trace height and published-evaluation count had the expected shape, the
opaque backend accepted the public values REBUILT FROM THE STATEMENT with the E-1
domain word, and its published evaluations equal the ones recomputed from that same
statement. It does NOT mean the underlying ring identities hold — that is the
`StarkSoundness` / `EvaluationArgumentSoundness` boundary. -/
theorem verify_channel_tx_binds_statement (bk : Backend) (level : RegevSecurityLevel)
    (spk rpk : RegevPkM) (before encAmount after : RegevCtM) (proofBytes : List Nat)
    (h : verifyChannelTx bk level spk rpk before encAmount after proofBytes = .ok ()) :
    ∃ p z, bk.decode proofBytes = .ok p ∧
      p.degreeBits = [expectedDegreeBits] ∧
      p.publishedEvals.length = e1Shape.numPublishedEvals ∧
      bk.verifyBatch level airChannelTx (channelTxPublicValues spk rpk before encAmount after) p
        = .ok z ∧
      p.publishedEvals = expectedPublishedEvals e1Shape spk rpk [before, encAmount, after] [] z := by
  simp only [verifyChannelTx, ensure_ok_iff] at h
  obtain ⟨_, _, _, _, _, hfin⟩ := h
  cases hv : verifyOne bk level airChannelTx proofBytes
      (channelTxPublicValues spk rpk before encAmount after) e1Shape.numPublishedEvals
      expectedDegreeBits with
  | error e => rw [hv] at hfin; exact absurd hfin (by simp)
  | ok zp =>
    obtain ⟨z, p⟩ := zp
    rw [hv] at hfin
    dsimp only at hfin
    obtain ⟨hdec, hdb, hlen, hvb⟩ := verify_one_ok hv
    refine ⟨p, z, hdec, hdb, hlen, hvb, ?_⟩
    unfold checkPublishedEvals at hfin
    by_cases hc : p.publishedEvals =
        expectedPublishedEvals e1Shape spk rpk [before, encAmount, after] [] z
    · exact hc
    · rw [if_neg hc] at hfin; exact absurd hfin (by simp)

/-- F2-C (E-2 public-amount binding): acceptance forces BOTH delta ciphertexts'
published message evaluations to equal the evaluation of `encode_amount(amount)`
recomputed by the verifier from the PUBLIC amount. Positions 10 and 13 are the two
`expose_m` slots of the E-2 lookup order. -/
theorem verify_channel_update_pins_delta_messages (bk : Backend) (level : RegevSecurityLevel)
    (spk rpk : RegevPkM) (before after senderDelta receiverDelta : RegevCtM)
    (amount tokenIndex : Nat) (proofBytes : List Nat)
    (h : verifyChannelUpdate bk level spk rpk before after senderDelta receiverDelta amount
      tokenIndex proofBytes = .ok ()) :
    ∃ p z, bk.decode proofBytes = .ok p ∧
      bk.verifyBatch level airChannelUpdate
        (channelUpdatePublicValues spk rpk before after senderDelta receiverDelta amount
          tokenIndex) p = .ok z ∧
      p.publishedEvals.getD 10 0 = evalAt (encodeAmount amount) z ∧
      p.publishedEvals.getD 13 0 = evalAt (encodeAmount amount) z := by
  simp only [verifyChannelUpdate, ensure_ok_iff] at h
  obtain ⟨_, _, _, _, _, _, hfin⟩ := h
  cases hv : verifyOne bk level airChannelUpdate proofBytes
      (channelUpdatePublicValues spk rpk before after senderDelta receiverDelta amount tokenIndex)
      e2Shape.numPublishedEvals expectedDegreeBits with
  | error e => rw [hv] at hfin; exact absurd hfin (by simp)
  | ok zp =>
    obtain ⟨z, p⟩ := zp
    rw [hv] at hfin
    dsimp only at hfin
    obtain ⟨hdec, _, _, hvb⟩ := verify_one_ok hv
    unfold checkPublishedEvals at hfin
    by_cases hc : p.publishedEvals =
        expectedPublishedEvals e2Shape spk rpk [before, after, senderDelta, receiverDelta]
          (encodeAmount amount) z
    · refine ⟨p, z, hdec, hvb, ?_, ?_⟩ <;> rw [hc] <;>
        simp [expectedPublishedEvals, e2Shape, List.range, List.range.loop, List.bind]
    · rw [if_neg hc] at hfin; exact absurd hfin (by simp)

/-! ## Prove-side conservation checks (transfer_stark.rs lines 1102-1112, 1196-1211)

The native refusals that keep the prover from building an unsatisfiable trace. They
are the SAME arithmetic the in-circuit ripple carry enforces, over u64. -/

def u64Limit : Nat := 18446744073709551616

def proveConservationCheck (beforeAmt afterAmt amount : Nat) : Except RegevError Unit :=
  if afterAmt + amount < u64Limit ∧ afterAmt + amount = beforeAmt then .ok ()
  else .error .invalidWitness

def proveDeltaAmountCheck (senderDeltaAmt receiverDeltaAmt amount : Nat) :
    Except RegevError Unit :=
  if senderDeltaAmt = amount ∧ receiverDeltaAmt = amount then .ok ()
  else .error .invalidWitness

theorem prove_conservation_check_sound {b a m : Nat} (h : proveConservationCheck b a m = .ok ()) :
    b = a + m ∧ m ≤ b := by
  unfold proveConservationCheck at h
  split at h
  · next hc => exact ⟨hc.2.symm, by omega⟩
  · exact absurd h (by simp)

theorem prove_conservation_check_rejects_underflow (b a m : Nat) (h : b < m) :
    proveConservationCheck b a m = .error .invalidWitness := by
  unfold proveConservationCheck
  split
  · next hc => omega
  · rfl

theorem prove_delta_amount_check_sound {sd rd m : Nat} (h : proveDeltaAmountCheck sd rd m = .ok ()) :
    sd = m ∧ rd = m := by
  unfold proveDeltaAmountCheck at h
  split at h
  · next hc => exact hc
  · exact absurd h (by simp)

/-! ## A concrete accepting run (non-vacuity)

The canonical all-zero key and the canonical zero ciphertext (`RegevPk::padding` /
`RegevCiphertext::padding`) form a well-shaped E-1 statement, and with a stub
backend that decodes to a shape-correct proof whose published evaluations are the
recomputed ones, `verifyChannelTx` returns `ok`. This shows the verifier model is
not vacuously rejecting; it establishes nothing about real proofs. -/

theorem all_replicate_below_q (n c : Nat) (h : c < regevQ) :
    (List.replicate n c).all (fun x => decide (x < regevQ)) = true := by
  induction n with
  | zero => rfl
  | succ n ih => simp [List.replicate, List.all_cons, h, ih]

theorem all_append_true (f : Nat → Bool) :
    ∀ xs ys : List Nat, xs.all f = true → ys.all f = true → (xs ++ ys).all f = true
  | [], ys, _, hy => by simpa using hy
  | x :: xs, ys, hx, hy => by
      simp only [List.cons_append, List.all_cons, Bool.and_eq_true] at hx ⊢
      exact ⟨hx.1, all_append_true f xs ys hx.2 hy⟩

theorem zero_polys_canonical :
    ((List.replicate regevN 0 ++ List.replicate regevN 0).all
      (fun c => decide (c < regevQ))) = true :=
  all_append_true _ _ _ (all_replicate_below_q regevN 0 (by decide))
    (all_replicate_below_q regevN 0 (by decide))

def zeroPk : RegevPkM := ⟨List.replicate regevN 0, List.replicate regevN 0⟩
def zeroCt : RegevCtM := ⟨List.replicate regevN 0, List.replicate regevN 0⟩

theorem zero_pk_validates : pkValidate zeroPk = .ok () := by
  simp [pkValidate, zeroPk, canonicalPoly, zero_polys_canonical]
  intro _
  decide

theorem zero_ct_validates : ctValidate zeroCt = .ok () := by
  simp [ctValidate, zeroCt, canonicalPoly, zero_polys_canonical]
  intro _
  decide

def exampleChallenge : Chal := 7

def exampleExpectedEvals : List Chal :=
  expectedPublishedEvals e1Shape zeroPk zeroPk [zeroCt, zeroCt, zeroCt] [] exampleChallenge

def exampleProof : ProofM :=
  { degreeBits := [expectedDegreeBits], publishedEvals := exampleExpectedEvals, payload := 0 }

def stubBackend : Backend :=
  { decode := fun _ => .ok exampleProof
    verifyBatch := fun _ _ _ _ => .ok exampleChallenge }

theorem example_expected_evals_length : exampleExpectedEvals.length = 10 := by
  simp [exampleExpectedEvals, expectedPublishedEvals, e1Shape, List.range, List.range.loop,
    List.bind]

theorem channel_tx_example_accepts :
    verifyChannelTx stubBackend .test zeroPk zeroPk zeroCt zeroCt zeroCt [] = .ok () := by
  simp only [verifyChannelTx, zero_pk_validates, zero_ct_validates, bind, Except.bind, verifyOne,
    stubBackend, exampleProof, checkPublishedEvals]
  simp only [e1_layout_pinned, example_expected_evals_length]
  norm_cast

end Zkp.Implementation.RegevProofs
