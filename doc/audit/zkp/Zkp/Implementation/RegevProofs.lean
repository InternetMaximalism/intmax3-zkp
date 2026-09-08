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

/-- `max_constraint_degree()` reported by all four AIRs (and by the hash-signature
AIR): degree 3, matching the `log_blowup = 1` config. -/
def maxConstraintDegree : Nat := 3

/-- `main_next_row_columns()`: the dual-key AIRs open the single carry column, the
decryption core opens the eight carry-bit columns. -/
def decCarryColumns : List Nat := (List.range carryBits).map (fun j => decCarry + j)

theorem next_row_columns_pinned :
    maxConstraintDegree = 3 ∧ [e1Shape.carryCol] = [34] ∧ [e2Shape.carryCol] = [44] ∧
      decCarryColumns = [44, 45, 46, 47, 48, 49, 50, 51] := by
  refine ⟨rfl, by decide, by decide, by decide⟩

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
    have _h2 := not_or.mp hne
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
    have _h2 := not_or.mp hne
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

/-- E-3: acceptance pins the published bit-column evaluation to the evaluation of
`encode_amount(amount)` recomputed by the verifier from the PUBLIC amount, and the
key/ciphertext evaluations to the claimed statement. -/
theorem verify_withdraw_claim_binds_statement (bk : Backend) (level : RegevSecurityLevel)
    (pk : RegevPkM) (ct : RegevCtM) (amount : Nat) (proofBytes : List Nat)
    (h : verifyWithdrawClaim bk level pk ct amount proofBytes = .ok ()) :
    ∃ p z, bk.decode proofBytes = .ok p ∧
      p.degreeBits = [expectedDegreeBits] ∧
      p.publishedEvals.length = decNumPublished ∧
      bk.verifyBatch level airWithdrawClaim
        (decryptionPublicValues withdrawClaimZkpDomain amount pk ct) p = .ok z ∧
      p.publishedEvals =
        [evalAt pk.a z, evalAt pk.b z, evalAt ct.c1 z, evalAt ct.c2 z,
          evalAt (encodeAmount amount) z] := by
  simp only [verifyWithdrawClaim, ensure_ok_iff] at h
  obtain ⟨_, _, hfin⟩ := h
  cases hv : verifyOne bk level airWithdrawClaim proofBytes
      (decryptionPublicValues withdrawClaimZkpDomain amount pk ct) decNumPublished
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
        [evalAt pk.a z, evalAt pk.b z, evalAt ct.c1 z, evalAt ct.c2 z,
          evalAt (encodeAmount amount) z]
    · exact hc
    · rw [if_neg hc] at hfin; exact absurd hfin (by simp)

/-- The refresh statement contains the key and the two ciphertexts and NOTHING else:
no amount, no message limbs. What acceptance claims is only that the two ciphertexts
encrypt the same hidden plaintext under the same key. -/
theorem refresh_statement_carries_no_amount {pk : RegevPkM} {oldCt newCt : RegevCtM}
    (hp : PkShaped pk) (ho : CtShaped oldCt) (hn : CtShaped newCt) (domain : Nat) :
    (refreshPublicValues domain pk oldCt newCt).length = refreshNumPublicValues regevN := by
  have hjoin : ([pk.a, pk.b, oldCt.c1, oldCt.c2, newCt.c1, newCt.c2].join).length =
      6 * regevN := by
    rw [join_uniform_length regevN _ (by
      intro l hl
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hl
      rcases hl with h | h | h | h | h | h <;> rw [h]
      · exact hp.1
      · exact hp.2
      · exact ho.1
      · exact ho.2
      · exact hn.1
      · exact hn.2)]
    rfl
  show (domain :: ([pk.a, pk.b, oldCt.c1, oldCt.c2, newCt.c1, newCt.c2].join)).length = _
  rw [List.length_cons, hjoin, refreshNumPublicValues]
  omega

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

/-! # Poseidon2-BabyBear hash signature (src/regev/hash_sig.rs)

The SENDER authorization for an intra-channel transfer: the "signature" is a STARK
proof of knowledge of `sk_b` with `pk_b` and the message limbs as PUBLIC VALUES.
Field elements are modelled by their canonical representative in `[0, q)`, and the
permutation is the opaque `Poseidon2` callback (`Poseidon2Permutation` boundary):
nothing here asserts preimage or collision resistance, so nothing here asserts
unforgeability. -/

def poseidonWidth : Nat := 16
def sboxDegree : Nat := 7
def sboxRegisters : Nat := 1
def halfFullRounds : Nat := 4
def partialRounds : Nat := 13
/-- "BPKB" / "BSGB" domain words, both `< q` and distinct (lines 128-144). -/
def domainPkB : Nat := 0x42504b42
def domainSigB : Nat := 0x42534742
def skLimbs : Nat := 9
def digestLimbs : Nat := 8
def msgLimbs : Nat := 16
def spongeRate : Nat := 8
def sigAbsorbLen : Nat := 1 + skLimbs + msgLimbs
def sigBlocksCount : Nat := (sigAbsorbLen + spongeRate - 1) / spongeRate
def selCols : Nat := 6
def bindTailCols : Nat := selCols + skLimbs
def hashSigNumPv : Nat := digestLimbs + msgLimbs
def hashSigRealRows : Nat := 1 + sigBlocksCount
def hashSigHeight : Nat := 8
/-- `HASH_SIG_HEIGHT.trailing_zeros() + config.is_zk()`. -/
def hashSigDegreeBits : Nat := 3 + configIsZk

/-- Row width: the upstream `Poseidon2Cols` prefix (an `UpstreamRegev` boundary
value) plus the binding tail. -/
def hashSigCols (poseidonCols : Nat) : Nat := poseidonCols + bindTailCols

theorem hash_sig_constants_pinned :
    poseidonWidth = 16 ∧ sboxDegree = 7 ∧ sboxRegisters = 1 ∧ halfFullRounds = 4 ∧
      partialRounds = 13 ∧ skLimbs = 9 ∧ digestLimbs = 8 ∧ msgLimbs = 16 ∧ spongeRate = 8 ∧
      sigAbsorbLen = 26 ∧ sigBlocksCount = 4 ∧ selCols = 6 ∧ bindTailCols = 15 ∧
      hashSigNumPv = 24 ∧ hashSigRealRows = 5 ∧ hashSigHeight = 8 ∧ hashSigDegreeBits = 4 := by
  refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, by decide, by decide, rfl, by decide,
    by decide, by decide, rfl, by decide⟩

theorem hash_sig_row_width (poseidonCols : Nat) :
    hashSigCols poseidonCols = poseidonCols + 15 := by
  simp [hashSigCols, bindTailCols, selCols, skLimbs]

/-- The height is the smallest power of two above the real rows, so exactly three
padding rows exist. -/
theorem hash_sig_padding_rows : hashSigHeight - hashSigRealRows = 3 := by decide

/-- A2 (domain confusion): the two BabyBear domain words are distinct, both `< q`,
and distinct from every regev purpose word. -/
theorem hash_sig_domains_separated :
    domainPkB ≠ domainSigB ∧ domainPkB < regevQ ∧ domainSigB < regevQ ∧
      (∀ p : RegevProofPurpose, p.domain ≠ domainPkB ∧ p.domain ≠ domainSigB) := by
  refine ⟨by decide, by decide, by decide, ?_⟩
  intro p; cases p <;> exact ⟨by decide, by decide⟩

/-- The permutation as an opaque callback: only its width discipline is assumed. -/
structure Poseidon2 where
  permute : List Nat → List Nat
  permuteLength : ∀ st, st.length = poseidonWidth → (permute st).length = poseidonWidth

/-! ## Key material (hash_sig.rs lines 168-305) -/

def canonicalLimbs (xs : List Nat) : Bool := xs.all (fun x => decide (x < regevQ))

/-- `BabyBearSecretKey::from_canonical_limbs`: rejects non-canonical limbs and the
degenerate all-zero key (A1). -/
def skFromCanonicalLimbs (limbs : List Nat) : Except RegevError (List Nat) :=
  if limbs.length ≠ skLimbs then .error .proofVerification
  else if canonicalLimbs limbs = false then .error .proofVerification
  else if limbs.all (fun x => decide (x = 0)) then .error .proofVerification
  else .ok limbs

theorem sk_from_canonical_limbs_ok {limbs out : List Nat}
    (h : skFromCanonicalLimbs limbs = .ok out) :
    out = limbs ∧ limbs.length = skLimbs ∧ (∀ x ∈ limbs, x < regevQ) ∧
      ¬ (∀ x ∈ limbs, x = 0) := by
  unfold skFromCanonicalLimbs at h
  split at h
  · exact absurd h (by simp)
  · next hlen =>
    split at h
    · exact absurd h (by simp)
    · next hcanon =>
      split at h
      · exact absurd h (by simp)
      · next hzero =>
        have hout : out = limbs := by simpa using h.symm
        refine ⟨hout, by omega, ?_, ?_⟩
        · intro x hx
          have : canonicalLimbs limbs = true := by
            cases hc : canonicalLimbs limbs
            · exact absurd hc hcanon
            · rfl
          have := List.all_eq_true.mp this x hx
          simpa using this
        · intro hall
          exact hzero (List.all_eq_true.mpr (fun x hx => by simp [hall x hx]))

theorem sk_all_zero_rejected (limbs : List Nat) (h : ∀ x ∈ limbs, x = 0) :
    ∃ e, skFromCanonicalLimbs limbs = .error e := by
  unfold skFromCanonicalLimbs
  split
  · exact ⟨_, rfl⟩
  · split
    · exact ⟨_, rfl⟩
    · split
      · exact ⟨_, rfl⟩
      · next hz =>
        exact absurd (List.all_eq_true.mpr (fun x hx => by simp [h x hx])) hz

/-- `pk_b = Poseidon2([DOMAIN_PK_B] ++ sk ++ 0...)[0..8]` (lines 226-235). -/
def pkInput (sk : List Nat) : List Nat :=
  domainPkB :: (sk ++ List.replicate (poseidonWidth - 1 - skLimbs) 0)

def publicKeyOf (P : Poseidon2) (sk : List Nat) : List Nat :=
  (P.permute (pkInput sk)).take digestLimbs

theorem pk_input_length {sk : List Nat} (h : sk.length = skLimbs) :
    (pkInput sk).length = poseidonWidth := by
  simp [pkInput, h, poseidonWidth, skLimbs]

theorem public_key_length (P : Poseidon2) {sk : List Nat} (h : sk.length = skLimbs) :
    (publicKeyOf P sk).length = digestLimbs := by
  have hp := P.permuteLength (pkInput sk) (pk_input_length h)
  simp [publicKeyOf, hp, poseidonWidth, digestLimbs]
  decide

/-- `to_bytes32` / `from_bytes32`: the eight canonical limbs are the eight `Bytes32`
words, so the anchor round-trips (lines 274-305). The big-endian word packing itself
is the `NativeTargetRefinement` boundary. -/
def pkFromBytes32 (words : List Nat) : Except RegevError (List Nat) :=
  if words.length ≠ digestLimbs ∨ canonicalLimbs words = false then .error .proofVerification
  else .ok words

theorem pk_bytes32_roundtrip {digest : List Nat} (hlen : digest.length = digestLimbs)
    (hcanon : canonicalLimbs digest = true) : pkFromBytes32 digest = .ok digest := by
  unfold pkFromBytes32
  rw [if_neg]
  intro hcon
  rcases hcon with h | h
  · exact h hlen
  · rw [hcanon] at h; exact absurd h (by simp)

/-! ## Message-encoding injectivity (hash_sig.rs lines 307-327)

The IMPA digest's eight u32 words are re-split into sixteen 16-bit limbs, each
`< 2^16 < q`, so distinct digests give distinct field-element tuples. -/

def decomposeDigestToLimbs (words : List Nat) : List Nat :=
  words.bind (fun w => [w % 65536, w / 65536 % 65536])

theorem decompose_digest_length (words : List Nat) :
    (decomposeDigestToLimbs words).length = 2 * words.length := by
  induction words with
  | nil => rfl
  | cons w ws ih => simp [decomposeDigestToLimbs, List.bind] at ih ⊢; omega

theorem decompose_digest_limbs_below_q (words : List Nat) :
    ∀ x ∈ decomposeDigestToLimbs words, x < 65536 := by
  intro x hx
  obtain ⟨w, _, hx2⟩ := List.mem_bind.mp hx
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hx2
  rcases hx2 with h | h <;> subst h <;> omega

/-- Each message limb is `< 2^16 < q`, so absorbing it into BabyBear cannot alias
(the reason the raw 8x u32 digest is NOT absorbed directly). -/
theorem decompose_digest_limbs_canonical (words : List Nat) :
    ∀ x ∈ decomposeDigestToLimbs words, x < regevQ := by
  intro x hx
  have h := decompose_digest_limbs_below_q words x hx
  have hq : regevQ = 2013265921 := rfl
  omega

/-- MESSAGE-ENCODING INJECTIVITY (the P3 A-item): two different keccak digests never
produce the same `m_limbs`, so a proof's public message limbs determine the
channel-tx digest they were built from. -/
theorem decompose_digest_injective :
    ∀ (xs ys : List Nat), (∀ x ∈ xs, x < 4294967296) → (∀ y ∈ ys, y < 4294967296) →
      xs.length = ys.length → decomposeDigestToLimbs xs = decomposeDigestToLimbs ys → xs = ys
  | [], [], _, _, _, _ => rfl
  | [], _ :: _, _, _, hl, _ => by simp at hl
  | _ :: _, [], _, _, hl, _ => by simp at hl
  | x :: xs, y :: ys, hx, hy, hl, h => by
      simp only [decomposeDigestToLimbs, List.bind, List.map, List.join, List.cons_append,
        List.nil_append, List.cons.injEq] at h
      have hxb : x < 4294967296 := hx x (by simp)
      have hyb : y < 4294967296 := hy y (by simp)
      have hxy : x = y := by
        obtain ⟨h1, h2, _⟩ := h
        omega
      have htl : decomposeDigestToLimbs xs = decomposeDigestToLimbs ys := by
        simpa [decomposeDigestToLimbs] using h.2.2
      rw [hxy, decompose_digest_injective xs ys (fun a ha => hx a (by simp [ha]))
        (fun b hb => hy b (by simp [hb])) (by simpa using hl) htl]

/-! ## The sponge (hash_sig.rs lines 237-265 and the AIR's chaining, lines 1125-1198)

`sig_b = Poseidon2_sponge([DOMAIN_SIG_B] ++ sk ++ m)` with rate 8, overwrite on the
first block and add on the later ones. The absorbed stream is 26 elements padded to
four blocks of eight. -/

def fadd (x y : Nat) : Nat := (x + y) % regevQ

def sigAbsorbStream (sk m : List Nat) : List Nat :=
  (domainSigB :: (sk ++ m)) ++ List.replicate (sigBlocksCount * spongeRate - sigAbsorbLen) 0

def sigBlockList (sk m : List Nat) : List (List Nat) :=
  let a := sigAbsorbStream sk m
  [a.take 8, (a.drop 8).take 8, (a.drop 16).take 8, (a.drop 24).take 8]

theorem sig_absorb_stream_length {sk m : List Nat} (hs : sk.length = skLimbs)
    (hm : m.length = msgLimbs) : (sigAbsorbStream sk m).length = 32 := by
  simp [sigAbsorbStream, hs, hm, sigBlocksCount, spongeRate, sigAbsorbLen, skLimbs, msgLimbs]

/-- The AIR's per-position chaining constants (rows 1->2, 2->3, 3->4). -/
def airBlock1 (sk m : List Nat) : List Nat :=
  [sk.getD 7 0, sk.getD 8 0] ++ (List.range 6).map (fun j => m.getD j 0)
def airBlock2 (m : List Nat) : List Nat := (List.range 8).map (fun j => m.getD (6 + j) 0)
def airBlock3 (m : List Nat) : List Nat :=
  [m.getD 14 0, m.getD 15 0, 0, 0, 0, 0, 0, 0]

/-- FIDELITY: the four blocks the native sponge absorbs are exactly the blocks the
AIR's hand-written per-position equalities inject — `[DOMAIN_SIG_B, sk0..sk6]`,
`[sk7, sk8, m0..m5]`, `[m6..m13]`, `[m14, m15, 0...]`. -/
theorem sig_blocks_match_air_constants (s0 s1 s2 s3 s4 s5 s6 s7 s8 : Nat)
    (m0 m1 m2 m3 m4 m5 m6 m7 m8 m9 m10 m11 m12 m13 m14 m15 : Nat) :
    sigBlockList [s0, s1, s2, s3, s4, s5, s6, s7, s8]
        [m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15] =
      [ [domainSigB, s0, s1, s2, s3, s4, s5, s6],
        airBlock1 [s0, s1, s2, s3, s4, s5, s6, s7, s8]
          [m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15],
        airBlock2 [m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15],
        airBlock3 [m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15] ] := by
  rfl

/-- Absorb one block into the rate and carry the capacity: `next.rate[j] =
post[j] + block[j]`, `next.capacity = post.capacity` (the AIR's chaining shape). -/
def absorbBlock (state block : List Nat) : List Nat :=
  List.zipWith fadd (state.take spongeRate) block ++ state.drop spongeRate

theorem absorb_block_length {state block : List Nat} (hs : state.length = poseidonWidth)
    (hb : block.length = spongeRate) : (absorbBlock state block).length = poseidonWidth := by
  simp [absorbBlock, hs, hb, poseidonWidth, spongeRate]
  decide

/-! ## The binding AIR (hash_sig.rs lines 877-1203) -/

inductive RowKind where
  | pk
  | sig1
  | sig2
  | sig3
  | sig4
  | pad
  deriving DecidableEq, Repr

def advanceKind : RowKind → RowKind
  | .pk => .sig1
  | .sig1 => .sig2
  | .sig2 => .sig3
  | .sig3 => .sig4
  | .sig4 => .pad
  | .pad => .pad

/-- The one-hot selector columns `sel[0..6]`. -/
def selBits : RowKind → List Nat
  | .pk => [1, 0, 0, 0, 0, 0]
  | .sig1 => [0, 1, 0, 0, 0, 0]
  | .sig2 => [0, 0, 1, 0, 0, 0]
  | .sig3 => [0, 0, 0, 1, 0, 0]
  | .sig4 => [0, 0, 0, 0, 1, 0]
  | .pad => [0, 0, 0, 0, 0, 1]

theorem selector_one_hot (k : RowKind) :
    (selBits k).length = selCols ∧ (selBits k).foldl (fun a b => a + b) 0 = 1 := by
  cases k <;> exact ⟨by decide, by decide⟩

/-- FIDELITY: `advanceKind` is exactly the source's five shift-register constraints
`next_pk = 0`, `next_sigK = local_sig(K-1)`, `next_pad = local_sig4 + local_pad`. -/
theorem selector_shift_encoding (k : RowKind) :
    selBits (advanceKind k) =
      [0, (selBits k).getD 0 0, (selBits k).getD 1 0, (selBits k).getD 2 0,
        (selBits k).getD 3 0, (selBits k).getD 4 0 + (selBits k).getD 5 0] := by
  cases k <;> rfl

structure HashSigRow where
  inputs : List Nat
  post : List Nat
  kind : RowKind
  sk : List Nat

/-- The AIR's constraint set, gated by the one-hot selectors. `sig_b` (row 4's
output) is deliberately NOT bound to any public value (A6), and padding rows carry
no gated binding at all. -/
structure HashSigGates (P : Poseidon2) (pvPk pvM : List Nat) (rows : Nat → HashSigRow) : Prop where
  /-- (1) every row is a valid permutation (the audited upstream `Poseidon2Air`). -/
  permutation : ∀ i, i < hashSigHeight → (rows i).post = P.permute (rows i).inputs
  /-- (2) row 0 is the pk row and the selectors advance as a shift register. -/
  firstRowIsPk : (rows 0).kind = .pk
  selectorShift : ∀ i, i + 1 < hashSigHeight → (rows (i + 1)).kind = advanceKind (rows i).kind
  /-- (3) the secret key is held equal on every row. -/
  skBroadcast : ∀ i, i + 1 < hashSigHeight → (rows (i + 1)).sk = (rows i).sk
  /-- (4) pk row: `input = [DOMAIN_PK_B, sk(9), 0(6)]`, `output[0..8] = pk_b`. -/
  pkRow : ∀ i, i < hashSigHeight → (rows i).kind = .pk →
    (rows i).inputs = pkInput (rows i).sk ∧ ((rows i).post).take digestLimbs = pvPk
  /-- (5) first sponge row: `input = [DOMAIN_SIG_B, sk0..sk6, 0(8)]`. -/
  sig1Row : ∀ i, i < hashSigHeight → (rows i).kind = .sig1 →
    (rows i).inputs = (domainSigB :: (rows i).sk.take 7) ++ List.replicate 8 0
  /-- (6)-(8) the three chaining constraints. -/
  chain1 : ∀ i, i + 1 < hashSigHeight → (rows i).kind = .sig1 →
    (rows (i + 1)).inputs = absorbBlock (rows i).post (airBlock1 (rows i).sk pvM)
  chain2 : ∀ i, i + 1 < hashSigHeight → (rows i).kind = .sig2 →
    (rows (i + 1)).inputs = absorbBlock (rows i).post (airBlock2 pvM)
  chain3 : ∀ i, i + 1 < hashSigHeight → (rows i).kind = .sig3 →
    (rows (i + 1)).inputs = absorbBlock (rows i).post (airBlock3 pvM)

/-- The selector schedule is forced: rows 0..4 are the pk row and the four sponge
rows, and every later row is a padding row. -/
theorem selector_schedule_forced (P : Poseidon2) (pvPk pvM : List Nat)
    (rows : Nat → HashSigRow) (g : HashSigGates P pvPk pvM rows) :
    (rows 0).kind = .pk ∧ (rows 1).kind = .sig1 ∧ (rows 2).kind = .sig2 ∧
      (rows 3).kind = .sig3 ∧ (rows 4).kind = .sig4 ∧ (rows 5).kind = .pad ∧
      (rows 6).kind = .pad ∧ (rows 7).kind = .pad := by
  have h0 := g.firstRowIsPk
  have h1 := g.selectorShift 0 (by decide)
  have h2 := g.selectorShift 1 (by decide)
  have h3 := g.selectorShift 2 (by decide)
  have h4 := g.selectorShift 3 (by decide)
  have h5 := g.selectorShift 4 (by decide)
  have h6 := g.selectorShift 5 (by decide)
  have h7 := g.selectorShift 6 (by decide)
  rw [h0] at h1
  rw [h1] at h2
  rw [h2] at h3
  rw [h3] at h4
  rw [h4] at h5
  rw [h5] at h6
  rw [h6] at h7
  exact ⟨h0, h1, h2, h3, h4, h5, h6, h7⟩

/-- WHAT THE PROOF ESTABLISHES (1/2): the public `pk_b` is the Poseidon2 image of the
witnessed secret key that every row carries. Combined with `Poseidon2Permutation`
preimage resistance (NOT proved here) this is the knowledge-of-`sk_b` statement. -/
theorem hash_sig_pk_row_binds_public_key (P : Poseidon2) (pvPk pvM : List Nat)
    (rows : Nat → HashSigRow) (g : HashSigGates P pvPk pvM rows) :
    pvPk = publicKeyOf P (rows 0).sk := by
  obtain ⟨hin, hout⟩ := g.pkRow 0 (by decide) g.firstRowIsPk
  have hperm := g.permutation 0 (by decide)
  rw [← hout, hperm, hin]
  rfl

/-- The sponge inputs the AIR forces on rows 1..4, as a function of the broadcast
secret key and the PUBLIC message limbs alone. -/
def nativeSigInput0 (sk : List Nat) : List Nat :=
  (domainSigB :: sk.take 7) ++ List.replicate 8 0
def nativeSigInput1 (P : Poseidon2) (sk m : List Nat) : List Nat :=
  absorbBlock (P.permute (nativeSigInput0 sk)) (airBlock1 sk m)
def nativeSigInput2 (P : Poseidon2) (sk m : List Nat) : List Nat :=
  absorbBlock (P.permute (nativeSigInput1 P sk m)) (airBlock2 m)
def nativeSigInput3 (P : Poseidon2) (sk m : List Nat) : List Nat :=
  absorbBlock (P.permute (nativeSigInput2 P sk m)) (airBlock3 m)

/-- WHAT THE PROOF ESTABLISHES (2/2): rows 1..4 are exactly the native sponge run on
`[DOMAIN_SIG_B] ++ sk ++ m` — the same secret key as the pk row (broadcast register)
and the message limbs taken from the PUBLIC values. -/
theorem hash_sig_sig_rows_are_native_sponge (P : Poseidon2) (pvPk pvM : List Nat)
    (rows : Nat → HashSigRow) (g : HashSigGates P pvPk pvM rows) :
    (rows 1).inputs = nativeSigInput0 (rows 0).sk ∧
      (rows 2).inputs = nativeSigInput1 P (rows 0).sk pvM ∧
      (rows 3).inputs = nativeSigInput2 P (rows 0).sk pvM ∧
      (rows 4).inputs = nativeSigInput3 P (rows 0).sk pvM := by
  obtain ⟨_, k1, k2, k3, _, _, _, _⟩ := selector_schedule_forced P pvPk pvM rows g
  have hsk1 : (rows 1).sk = (rows 0).sk := g.skBroadcast 0 (by decide)
  have hsk2 : (rows 2).sk = (rows 0).sk := by
    rw [g.skBroadcast 1 (by decide), hsk1]
  have _hsk3 : (rows 3).sk = (rows 0).sk := by
    rw [g.skBroadcast 2 (by decide), hsk2]
  have e1 : (rows 1).inputs = (domainSigB :: (rows 0).sk.take 7) ++ List.replicate 8 0 := by
    have := g.sig1Row 1 (by decide) k1
    rw [hsk1] at this
    exact this
  have e2 : (rows 2).inputs = absorbBlock (rows 1).post (airBlock1 (rows 0).sk pvM) := by
    have := g.chain1 1 (by decide) k1
    rw [hsk1] at this
    exact this
  have e3 : (rows 3).inputs = absorbBlock (rows 2).post (airBlock2 pvM) :=
    g.chain2 2 (by decide) k2
  have e4 : (rows 4).inputs = absorbBlock (rows 3).post (airBlock3 pvM) :=
    g.chain3 3 (by decide) k3
  have p1 := g.permutation 1 (by decide)
  have p2 := g.permutation 2 (by decide)
  have p3 := g.permutation 3 (by decide)
  refine ⟨e1, ?_, ?_, ?_⟩
  · rw [e2, p1, e1]; rfl
  · rw [e3, p2, e2, p1, e1]; rfl
  · rw [e4, p3, e3, p2, e2, p1, e1]; rfl

/-- Padding rows: every row above index 4 is a `pad` row, and the ONLY gate that
mentions it is the permutation constraint — the pk-row, sig1-row and chaining gates
are all conditioned on a non-pad selector. A spliced padding permutation therefore
cannot affect `pk_b` (only the pk row binds it) or `m` (only the chaining gates read
it). -/
theorem hash_sig_padding_rows_only_permutation (P : Poseidon2) (pvPk pvM : List Nat)
    (rows : Nat → HashSigRow) (g : HashSigGates P pvPk pvM rows) :
    ∀ i, 5 ≤ i → i < hashSigHeight →
      (rows i).kind = .pad ∧ (rows i).post = P.permute (rows i).inputs := by
  obtain ⟨_, _, _, _, _, k5, k6, k7⟩ := selector_schedule_forced P pvPk pvM rows g
  intro i h5 hi
  refine ⟨?_, g.permutation i hi⟩
  have : i = 5 ∨ i = 6 ∨ i = 7 := by
    have : i < 8 := by simpa [hashSigHeight] using hi
    omega
  rcases this with h | h | h
  · rw [h]; exact k5
  · rw [h]; exact k6
  · rw [h]; exact k7

/-! ## Hash-signature public values and verification (hash_sig.rs lines 1305-1310,
transfer_stark.rs lines 954-994)

The public values are `[pk_b(8) ++ m(16)]` — `sig_b` is witness-only and never
appears. The verifier is handed the public values by its CALLER, which recomputes
`pk_b` from the registered `MemberLeaf` and `m` from the channel-tx digest. -/

def hashSigPublicValues (pkB mLimbs : List Nat) : List Nat := pkB ++ mLimbs

theorem hash_sig_public_values_length {pkB mLimbs : List Nat} (hp : pkB.length = digestLimbs)
    (hm : mLimbs.length = msgLimbs) : (hashSigPublicValues pkB mLimbs).length = hashSigNumPv := by
  simp [hashSigPublicValues, hp, hm, hashSigNumPv]

/-- The statement a relying party rebuilds (P3-5): the member's registered `pk_b`
and the 16-bit limbs of the channel-tx digest. -/
def hashSigStatement (memberPkB txDigest : List Nat) : List Nat :=
  hashSigPublicValues memberPkB (decomposeDigestToLimbs txDigest)

/-- STATEMENT INJECTIVITY: the public-value vector determines both the member key and
the channel-tx digest it authorizes, so a proof cannot be re-aimed at another member
or another transaction without changing the absorbed public values. Whether a changed
public-value vector really invalidates the proof is the `StarkSoundness` boundary. -/
theorem hash_sig_statement_injective {pk pk' d d' : List Nat}
    (hp : pk.length = digestLimbs) (hp' : pk'.length = digestLimbs)
    (hd : d.length = 8) (hd' : d'.length = 8)
    (hdb : ∀ x ∈ d, x < 4294967296) (hdb' : ∀ x ∈ d', x < 4294967296)
    (h : hashSigStatement pk d = hashSigStatement pk' d') : pk = pk' ∧ d = d' := by
  have hsplit := list_append_split pk pk' (decomposeDigestToLimbs d) (decomposeDigestToLimbs d')
    h (by rw [hp, hp'])
  exact ⟨hsplit.1, decompose_digest_injective d d' hdb hdb' (by rw [hd, hd']) hsplit.2⟩

def verifyHashSig (bk : Backend) (level : RegevSecurityLevel) (proofBytes : List Nat)
    (publicValues : List Nat) : Except RegevError Unit :=
  if publicValues.length ≠ hashSigNumPv then .error .proofVerification
  else
    match bk.decode proofBytes with
    | .error e => .error e
    | .ok p =>
        if p.degreeBits ≠ [hashSigDegreeBits] then .error .proofVerification
        else
          match bk.verifyBatch level airHashSig publicValues p with
          | .error e => .error e
          | .ok _ => .ok ()

/-- The public-value count is checked BEFORE the proof bytes are touched (line 966). -/
theorem verify_hash_sig_checks_pv_count_first (bk : Backend) (level : RegevSecurityLevel)
    (proofBytes publicValues : List Nat) (h : publicValues.length ≠ hashSigNumPv) :
    verifyHashSig bk level proofBytes publicValues = .error .proofVerification := by
  unfold verifyHashSig
  rw [if_pos h]

/-- Acceptance means: the caller-supplied public values were absorbed by the backend
for the hash-signature AIR at the pinned trace height. It does NOT mean the signer
was authorized for anything — that binding is the caller's `pk_b` lookup in the
member tree, and unforgeability is the `Poseidon2Permutation` boundary. -/
theorem verify_hash_sig_binds_public_values (bk : Backend) (level : RegevSecurityLevel)
    (proofBytes publicValues : List Nat)
    (h : verifyHashSig bk level proofBytes publicValues = .ok ()) :
    publicValues.length = hashSigNumPv ∧
      ∃ p z, bk.decode proofBytes = .ok p ∧ p.degreeBits = [hashSigDegreeBits] ∧
        bk.verifyBatch level airHashSig publicValues p = .ok z := by
  unfold verifyHashSig at h
  by_cases hlen : publicValues.length ≠ hashSigNumPv
  · rw [if_pos hlen] at h; exact absurd h (by simp)
  · rw [if_neg hlen] at h
    refine ⟨by simpa using hlen, ?_⟩
    cases hd : bk.decode proofBytes with
    | error e => rw [hd] at h; exact absurd h (by simp)
    | ok p =>
      rw [hd] at h
      dsimp only at h
      by_cases hdb : p.degreeBits ≠ [hashSigDegreeBits]
      · rw [if_pos hdb] at h; exact absurd h (by simp)
      · rw [if_neg hdb] at h
        cases hv : bk.verifyBatch level airHashSig publicValues p with
        | error e => rw [hv] at h; exact absurd h (by simp)
        | ok z => exact ⟨p, z, by first | exact hd | rfl, by simpa using hdb,
            by first | exact hv | rfl⟩

/-- The public-value vector is EXACTLY the key and the message: there is no nonce,
counter, expiry or channel-state component in it. The freshness of the authorization
is therefore entirely carried by the channel-tx digest the caller puts into `m`; a
relying party that accepts the same digest twice accepts the same authorization
twice. This model records that usage discipline, it does not enforce it. -/
theorem hash_sig_public_values_decompose {pkB mLimbs : List Nat}
    (hp : pkB.length = digestLimbs) :
    (hashSigPublicValues pkB mLimbs).take digestLimbs = pkB ∧
      (hashSigPublicValues pkB mLimbs).drop digestLimbs = mLimbs := by
  constructor
  · rw [hashSigPublicValues, ← hp]
    exact List.take_left _ _
  · rw [hashSigPublicValues, ← hp]
    exact List.drop_left _ _

/-- A concrete accepting hash-signature run (non-vacuity), with a stub backend. -/
def hashSigStubProof : ProofM :=
  { degreeBits := [hashSigDegreeBits], publishedEvals := [], payload := 0 }

def hashSigStubBackend : Backend :=
  { decode := fun _ => .ok hashSigStubProof
    verifyBatch := fun _ _ _ _ => .ok 0 }

theorem hash_sig_example_accepts :
    verifyHashSig hashSigStubBackend .production []
      (hashSigPublicValues (List.replicate digestLimbs 0) (List.replicate msgLimbs 0))
      = .ok () := by
  unfold verifyHashSig hashSigPublicValues hashSigStubBackend hashSigStubProof
  simp [hashSigNumPv, digestLimbs, msgLimbs]

end Zkp.Implementation.RegevProofs
