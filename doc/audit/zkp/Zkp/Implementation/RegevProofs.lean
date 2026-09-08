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

end Zkp.Implementation.RegevProofs
