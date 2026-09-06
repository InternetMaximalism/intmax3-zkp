import Std

/-!
# CloseAssetBacking: handwritten implementation semantics

Source: `src/circuits/channel/close_asset_backing_circuit.rs`, runtime 05ec7ae.
This module does NOT import the historical axiomatized Zkp/Core models.
It is a manual translation, NOT a Rust/Plonky2 compiler-refinement theorem.

The source allocates arbitrary proof/private-state/extended-state/vector/path
witness wires. In particular `fill_witness` is NOT a soundness assumption:
`prove` accepts the public witness struct directly and does not call its native
constructor. Computed commitments, path roots and public-input wires are kept
separate from these allocations. `constructorProgram` records source ordering;
`CircuitConstraints` gives the denotation of its local checks after lowering.

Explicit dependency boundaries:
* `FieldGateLowering`: checked u32 words, safe Boolean gates, arithmetic,
  equality, select and connect have the stated natural-number/Boolean meaning.
  This needs the actual Plonky2 field/gadgets, not an assumption of asset safety.
* `MerkleContract` is a DATA-ONLY interface. `CanonicalEmptyRoot` and
  `RowPathContracts` provide exact-index, same-path replacement semantics ONLY
  for the finite concrete rows/visited trees of the statement being checked.
  They do not quantify over all possible asset maps or assert globally exact
  openings for a finite cryptographic hash. They are not theorems about
  Poseidon, collisions, SparseMerkleTree or the compiler.
* `RecursiveVerifierContract`: verification under the constant Balance VK,
  including self-VK public-input binding, certifies the corresponding Balance
  statement. No conservation/latest-state conclusion is assumed of that proof.
* Native/circuit hash byte/word agreement, scoped commitment binding and
  scoped tree-root binding are supplied at the theorem using them. No global
  impossible injectivity claim for finite cryptographic hashes is postulated.

The callee does not check N-of-N ChannelState signatures, latest signed H,
L1 finality, channel freeze status, individual encrypted member balances,
withdrawal availability, or a relationship between block_r and a send cursor.
Those are caller/dependency obligations, not conclusions of this file.
PrivateStateTarget::new also does NOT range-check its nonce or salt here.
The extended state's inner fields are connected to Balance; its extra hash
chains are only committed, not proved final inside this circuit.

Tests in Rust lines 577-914 were read but are not translated as production
constraints, and no Rust proving/adversarial tests are executed by this model.
-/

namespace Zkp.Implementation.CloseAssetBacking

def maxTokens : Nat := 10
def wordBase : Nat := 2 ^ 32
def blockLimit : Nat := 2 ^ 63
def assetTreeHeight : Nat := 32
def tokenFundsDomain : Nat := 0x494d5446
def publicInputsLength : Nat := 26
def balancePublicInputsLength : Nat := 29

/-- Eight big-endian u32 limbs; raw targets remain Nat until range-checked. -/
structure Words8 where
  w0 : Nat
  w1 : Nat
  w2 : Nat
  w3 : Nat
  w4 : Nat
  w5 : Nat
  w6 : Nat
  w7 : Nat
  deriving DecidableEq, Repr

def Words8.words (w : Words8) : List Nat :=
  [w.w0, w.w1, w.w2, w.w3, w.w4, w.w5, w.w6, w.w7]

def Words8.zero : Words8 := ⟨0, 0, 0, 0, 0, 0, 0, 0⟩

def Words8.Checked (w : Words8) : Prop := ∀ x ∈ w.words, x < wordBase

instance (w : Words8) : Decidable w.Checked := inferInstanceAs (Decidable (∀ x ∈ w.words, x < wordBase))

def Words8.value (w : Words8) : Nat :=
  w.words.foldl (fun acc limb => acc * wordBase + limb) 0

theorem words8_length (w : Words8) : w.words.length = 8 := rfl

theorem words8_words_injective {a b : Words8} (h : a.words = b.words) : a = b := by
  cases a
  cases b
  simp only [Words8.words, List.cons.injEq] at h
  rcases h with ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, _⟩
  rfl

inductive Error where
  | invalidAssetVector
  | assetTreeRootMismatch
  | balanceProofVerification
  | balancePrivateCommitmentMismatch
  | balancePublicStateMismatch
  | balanceChannelMismatch
  | balanceSettledChainMismatch
  | invalidPublicInputs
  | failedToProve
  deriving DecidableEq, Repr

/-- Same layout is used for native values and target references; the parser
    below, not this raw structure, enforces the native ranges. -/
structure PublicInputs where
  channelId : Nat
  settledTxChain : Words8
  tokenFundsDigest : Words8
  extendedStateCommitment : Words8
  anchorBlockNumber : Nat
  deriving DecidableEq, Repr

def PublicInputs.words (p : PublicInputs) : List Nat :=
  [p.channelId] ++ p.settledTxChain.words ++ p.tokenFundsDigest.words ++
    p.extendedStateCommitment.words ++ [p.anchorBlockNumber]

def PublicInputs.Canonical (p : PublicInputs) : Prop :=
  (0 < p.channelId ∧ p.channelId < wordBase) ∧ p.anchorBlockNumber < blockLimit ∧
  p.settledTxChain.Checked ∧ p.tokenFundsDigest.Checked ∧ p.extendedStateCommitment.Checked

/-- Target parsing checks only the exact 26-element shape; no range gate is
    added by CloseAssetBackingPublicInputsTarget::from_pis. -/
def parseTargets : List Nat → Option PublicInputs
  | [c, s0, s1, s2, s3, s4, s5, s6, s7,
       t0, t1, t2, t3, t4, t5, t6, t7,
       e0, e1, e2, e3, e4, e5, e6, e7, a] =>
      some ⟨c, ⟨s0,s1,s2,s3,s4,s5,s6,s7⟩, ⟨t0,t1,t2,t3,t4,t5,t6,t7⟩,
        ⟨e0,e1,e2,e3,e4,e5,e6,e7⟩, a⟩
  | _ => none

/-- Native check ordering is channel, anchor, then settled/TFD/extended bytes.
    Error strings are erased, but error variants and success values are not. -/
def parsePublicInputs (words : List Nat) : Except Error PublicInputs :=
  match parseTargets words with
  | none => .error .invalidPublicInputs
  | some p =>
      if 0 < p.channelId ∧ p.channelId < wordBase then
        if p.anchorBlockNumber < blockLimit then
          if p.settledTxChain.Checked then
            if p.tokenFundsDigest.Checked then
              if p.extendedStateCommitment.Checked then .ok p
              else .error .invalidPublicInputs
            else .error .invalidPublicInputs
          else .error .invalidPublicInputs
        else .error .invalidPublicInputs
      else .error .invalidPublicInputs

/-- PrimeField64::to_canonical_u64 is a dependency, not identity on field data. -/
def parseFieldPublicInputs {F : Type} (canonicalU64 : F → Nat) (values : List F) :=
  parsePublicInputs (values.map canonicalU64)

theorem public_inputs_length (p : PublicInputs) : p.words.length = publicInputsLength := by
  simp [PublicInputs.words, Words8.words, publicInputsLength]

theorem target_encode_decode (p : PublicInputs) : parseTargets p.words = some p := by
  cases p with
  | mk c s t e a => cases s; cases t; cases e; rfl

theorem native_encode_decode (p : PublicInputs) (h : p.Canonical) :
    parsePublicInputs p.words = .ok p := by
  rcases h with ⟨hc, ha, hs, ht, he⟩
  simp [parsePublicInputs, target_encode_decode, hc.1, hc.2, ha, hs, ht, he,
    Nat.not_le.mpr hc.2, Nat.not_le.mpr ha]

theorem public_input_encoding_injective {a b : PublicInputs}
    (h : a.words = b.words) : a = b := by
  have eq := congrArg parseTargets h
  simpa only [target_encode_decode, Option.some.injEq] using eq

/-- A row contains independently witnessed registry, amount, Boolean and path.
    The source represents these as parallel fixed-size arrays. -/
structure Row (Path : Type) where
  registry : Nat
  amount : Words8
  active : Bool
  path : Path

def bit (b : Bool) : Nat := if b then 1 else 0

def activeCount : List Bool → Nat
  | [] => 0
  | b :: bs => bit b + activeCount bs

/-- Initial predecessor=true contributes the tautological first gate; every
    remaining clause is exactly a[t+1]*(1-a[t])=0 from lines 439-443. -/
def NoRise : Bool → List Bool → Prop
  | _, [] => True
  | previous, b :: bs => bit b * (1 - bit previous) = 0 ∧ NoRise b bs

def activity {Path : Type} (rows : List (Row Path)) := rows.map Row.active

def PaddingGates {Path : Type} (r : Row Path) : Prop :=
  bit (!r.active) * r.registry = 0 ∧
  ∀ limb ∈ r.amount.words, bit (!r.active) * limb = 0

/-- j-active, not i-active, is the actual source condition. Prefix constraints
    establish i-active when j-active; we do not strengthen this local gate. -/
def UniqueGates {Path : Type} : List (Row Path) → Prop
  | [] => True
  | r :: rs => (∀ s ∈ rs, s.active = true → r.registry ≠ s.registry) ∧ UniqueGates rs

def RangeGates {Path : Type} (rows : List (Row Path)) : Prop :=
  ∀ r ∈ rows, r.registry < wordBase ∧ r.amount.Checked

structure VectorGates {Path : Type} (count : Nat) (rows : List (Row Path)) : Prop where
  width : rows.length = maxTokens
  countRange : count < wordBase
  ranges : RangeGates rows
  prefixGates : NoRise true (activity rows)
  sum : activeCount (activity rows) = count
  first : (activity rows).head? = some true
  padding : ∀ r ∈ rows, PaddingGates r
  distinct : UniqueGates rows

theorem active_count_le_length (bs : List Bool) : activeCount bs ≤ bs.length := by
  induction bs with
  | nil => simp [activeCount]
  | cons b bs ih => cases b <;> simp [activeCount, bit] <;> omega

theorem no_rise_after_false (bs : List Bool) (h : NoRise false bs) :
    bs = List.replicate bs.length false := by
  induction bs with
  | nil => rfl
  | cons b bs ih =>
      cases b with
      | false =>
          have ht : NoRise false bs := h.2
          simpa [List.replicate_succ] using congrArg (List.cons false) (ih ht)
      | true => simp [NoRise, bit] at h

theorem active_count_replicate_false (n : Nat) :
    activeCount (List.replicate n false) = 0 := by
  induction n with
  | zero => rfl
  | succ n ih => simp [List.replicate_succ, activeCount, bit, ih]

theorem prefix_gates_determine_all_activity (bs : List Bool) (h : NoRise true bs) :
    bs = List.replicate (activeCount bs) true ++
      List.replicate (bs.length - activeCount bs) false := by
  induction bs with
  | nil => rfl
  | cons b bs ih =>
      cases b with
      | false =>
          have hf := no_rise_after_false bs h.2
          have hc : activeCount bs = 0 := by rw [hf]; exact active_count_replicate_false _
          simp only [activeCount, bit, Bool.false_eq_true, ↓reduceIte, Nat.zero_add, hc]
          simpa [List.replicate_succ] using congrArg (List.cons false) hf
      | true =>
          have ht := ih h.2
          have hb := active_count_le_length bs
          have hd : (bs.length + 1) - (1 + activeCount bs) = bs.length - activeCount bs := by omega
          simpa [activeCount, bit, Nat.add_comm 1, List.replicate_succ, hd] using
            congrArg (List.cons true) ht

theorem vector_token_count_bounds {Path : Type} {count : Nat} {rows : List (Row Path)}
    (g : VectorGates count rows) : 1 ≤ count ∧ count ≤ maxTokens := by
  have hle := active_count_le_length (activity rows)
  have hlen : (activity rows).length = maxTokens := by simp [activity, g.width]
  have hfirst := g.first
  have hpositive : 1 ≤ activeCount (activity rows) := by
    cases hbs : activity rows with
    | nil => simp [hbs] at hfirst
    | cons b bs =>
        have hb : b = true := by simpa [hbs] using hfirst
        simp [hbs, hb, activeCount, bit]
        omega
  rw [g.sum] at hpositive hle
  omega

theorem canonical_activity_vector {Path : Type} {count : Nat} {rows : List (Row Path)}
    (g : VectorGates count rows) :
    activity rows = List.replicate count true ++ List.replicate (maxTokens - count) false := by
  have h := prefix_gates_determine_all_activity (activity rows) g.prefixGates
  rw [g.sum] at h
  simpa [activity, g.width] using h

theorem inactive_registry_and_amount_zero {Path : Type} {r : Row Path}
    (g : PaddingGates r) (h : r.active = false) :
    r.registry = 0 ∧ r.amount = Words8.zero := by
  have hr : r.registry = 0 := by simpa [h, bit] using g.1
  have hw : ∀ limb ∈ r.amount.words, limb = 0 := by simpa [h, bit] using g.2
  refine ⟨hr, ?_⟩
  cases he : r.amount with
  | mk a b c d e f g h =>
      simp only [he, Words8.words, List.mem_cons, List.not_mem_nil, or_false] at hw
      have ha := hw a (Or.inl rfl)
      have hb := hw b (Or.inr (Or.inl rfl))
      have hc := hw c (Or.inr (Or.inr (Or.inl rfl)))
      have hd := hw d (Or.inr (Or.inr (Or.inr (Or.inl rfl))))
      have he := hw e (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl rfl)))))
      have hf := hw f (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl rfl))))))
      have hg := hw g (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl rfl)))))))
      have hh := hw h (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr rfl)))))))
      simp [Words8.zero, ha, hb, hc, hd, he, hf, hg, hh]

/-- Sparse leaf maps are semantic values, not hash roots. -/
abbrev AssetMap := Nat → Words8

def emptyAssets : AssetMap := fun _ => Words8.zero

def insertAsset (tree : AssetMap) (key : Nat) (amount : Words8) : AssetMap :=
  fun k => if k = key then amount else tree k

def applyRows {Path : Type} : List (Row Path) → AssetMap → AssetMap
  | [], tree => tree
  | r :: rs, tree =>
      applyRows rs (if r.active then insertAsset tree r.registry r.amount else tree)

def canonicalAssets {Path : Type} (rows : List (Row Path)) : AssetMap :=
  applyRows rows emptyAssets

theorem apply_rows_unlisted_frame {Path : Type} (rows : List (Row Path))
    (tree : AssetMap) (key : Nat)
    (h : ∀ r ∈ rows, r.active = true → key ≠ r.registry) :
    applyRows rows tree key = tree key := by
  induction rows generalizing tree with
  | nil => rfl
  | cons r rs ih =>
      have ht : ∀ s ∈ rs, s.active = true → key ≠ s.registry := by
        intro s hs ha; exact h s (by simp [hs]) ha
      simp only [applyRows]
      rw [ih _ ht]
      cases ha : r.active with
      | false => simp [ha]
      | true => simp [ha, insertAsset, h r (by simp) ha]

theorem canonical_assets_no_unlisted_balance {Path : Type} (rows : List (Row Path))
    (key : Nat) (h : ∀ r ∈ rows, r.active = true → key ≠ r.registry) :
    canonicalAssets rows key = Words8.zero :=
  apply_rows_unlisted_frame rows emptyAssets key h

theorem unique_rows_preserve_every_exact_amount {Path : Type} (rows : List (Row Path))
    (tree : AssetMap) (g : UniqueGates rows) :
    ∀ r ∈ rows, r.active = true → applyRows rows tree r.registry = r.amount := by
  induction rows generalizing tree with
  | nil => simp
  | cons r rs ih =>
      intro s hs ha
      simp only [List.mem_cons] at hs
      rcases hs with hsame | htail
      · subst s
        simp only [applyRows, ha, ↓reduceIte]
        rw [apply_rows_unlisted_frame rs _ r.registry g.1]
        simp [insertAsset]
      · exact ih _ g.2 s htail ha

/-- Data-only interface: no global opening, injectivity or update law for all
    AssetMaps is imposed on a finite cryptographic hash. -/
structure MerkleContract (Root Path : Type) where
  encode : AssetMap → Root
  emptyRoot : Root
  pathRoot : Path → Words8 → Nat → Root

def CanonicalEmptyRoot {Root Path : Type} (m : MerkleContract Root Path) : Prop :=
  m.emptyRoot = m.encode emptyAssets

/-- A scoped primitive dependency for ONE concrete path, old tree, key and
    amount. It is not a canonical-vector or complete-circuit safety premise.
    A cryptographic refinement must justify this implication for the actually
    compared encodings, including canonical tree/path representation. -/
def PathReplacementAt {Root Path : Type} (m : MerkleContract Root Path)
    (tree : AssetMap) (r : Row Path) : Prop :=
  r.registry < wordBase →
  m.pathRoot r.path Words8.zero r.registry = m.encode tree →
  m.pathRoot r.path r.amount r.registry = m.encode (insertAsset tree r.registry r.amount)

/-- Finite trace of dependency obligations, separate from the actual gate
    constraints. Inactive rows need no root-replacement premise. There is NO
    quantification over unrelated paths or asset maps. -/
def RowPathContracts {Root Path : Type} (m : MerkleContract Root Path) :
    List (Row Path) → AssetMap → Prop
  | [], _ => True
  | r :: rs, tree =>
      (r.active = true → PathReplacementAt m tree r) ∧
      RowPathContracts m rs (if r.active then insertAsset tree r.registry r.amount else tree)

def pathFold {Root Path : Type} (m : MerkleContract Root Path) :
    List (Row Path) → Root → Root
  | [], root => root
  | r :: rs, root =>
      let inserted := m.pathRoot r.path r.amount r.registry
      pathFold m rs (if r.active then inserted else root)

/-- Conditional verification is imposed only on active rows. `pathFold`
    nonetheless computes the inserted root for every row, as the builder does. -/
def PathGates {Root Path : Type} (m : MerkleContract Root Path) :
    List (Row Path) → Root → Prop
  | [], _ => True
  | r :: rs, root =>
      (r.active = true → m.pathRoot r.path Words8.zero r.registry = root) ∧
      PathGates m rs (if r.active then m.pathRoot r.path r.amount r.registry else root)

theorem path_fold_reconstructs_exact_tree {Root Path : Type} (m : MerkleContract Root Path)
    (rows : List (Row Path)) (tree : AssetMap) (ranges : RangeGates rows)
    (contracts : RowPathContracts m rows tree)
    (g : PathGates m rows (m.encode tree)) :
    pathFold m rows (m.encode tree) = m.encode (applyRows rows tree) := by
  induction rows generalizing tree with
  | nil => rfl
  | cons r rs ih =>
      have htRange : RangeGates rs := by
        intro s hs; exact ranges s (by simp [hs])
      cases ha : r.active with
      | false =>
          have ht : PathGates m rs (m.encode tree) := by simpa [ha] using g.2
          have hc : RowPathContracts m rs tree := by simpa [ha] using contracts.2
          simpa [pathFold, applyRows, ha] using ih tree htRange hc ht
      | true =>
          have hz := g.1 ha
          have hu := contracts.1 ha (ranges r (by simp)).1 hz
          have ht : PathGates m rs (m.encode (insertAsset tree r.registry r.amount)) := by
            simpa [ha, hu] using g.2
          have hc : RowPathContracts m rs (insertAsset tree r.registry r.amount) := by
            simpa [ha] using contracts.2
          simpa [pathFold, applyRows, ha, hu] using ih _ htRange hc ht

theorem canonical_root_from_empty {Root Path : Type} (m : MerkleContract Root Path)
    (rows : List (Row Path)) (ranges : RangeGates rows)
    (emptyCorrect : CanonicalEmptyRoot m) (contracts : RowPathContracts m rows emptyAssets)
    (g : PathGates m rows m.emptyRoot) :
    pathFold m rows m.emptyRoot = m.encode (canonicalAssets rows) := by
  rw [emptyCorrect] at g ⊢
  exact path_fold_reconstructs_exact_tree m rows emptyAssets ranges contracts g

def registryWords {Path : Type} (rows : List (Row Path)) : List Nat := rows.map Row.registry

def amountWords {Path : Type} : List (Row Path) → List Nat
  | [] => []
  | r :: rs => r.amount.words ++ amountWords rs

def tokenFundsPreimage {Path : Type} (count : Nat) (rows : List (Row Path)) : List Nat :=
  [tokenFundsDomain] ++ registryWords rows ++ [count] ++ amountWords rows

theorem amount_words_length {Path : Type} (rows : List (Row Path)) :
    (amountWords rows).length = 8 * rows.length := by
  induction rows with
  | nil => rfl
  | cons r rs ih => simp [amountWords, words8_length, ih]; omega

theorem token_funds_preimage_full_width {Path : Type} (count : Nat) (rows : List (Row Path))
    (h : rows.length = maxTokens) : (tokenFundsPreimage count rows).length = 92 := by
  simp [tokenFundsPreimage, registryWords, amount_words_length, h, maxTokens]

theorem token_funds_preimage_injective_fields {Path : Type} {a b : List (Row Path)}
    {ca cb : Nat} (hw : a.length = b.length)
    (h : tokenFundsPreimage ca a = tokenFundsPreimage cb b) :
    registryWords a = registryWords b ∧ ca = cb ∧ amountWords a = amountWords b := by
  have htail : registryWords a ++ (ca :: amountWords a) =
      registryWords b ++ (cb :: amountWords b) := by
    simpa [tokenFundsPreimage, List.append_assoc] using h
  have hl : (registryWords a).length = (registryWords b).length := by simp [registryWords, hw]
  have hp := List.append_inj htail hl
  have hc : ca = cb ∧ amountWords a = amountWords b := by simpa using hp.2
  exact ⟨hp.1, hc⟩

/-- Scoped collision-resistance premise for the two exact preimages compared.
    It does not assume vector equality or the desired asset-safety conclusion. -/
def KeccakBindingAt (hash : List Nat → Words8) (a b : List Nat) : Prop :=
  hash a = hash b → a = b

theorem token_funds_digest_binds_complete_vector {Path : Type} (hash : List Nat → Words8)
    {a b : List (Row Path)} {ca cb : Nat} (hw : a.length = b.length)
    (hb : KeccakBindingAt hash (tokenFundsPreimage ca a) (tokenFundsPreimage cb b))
    (he : hash (tokenFundsPreimage ca a) = hash (tokenFundsPreimage cb b)) :
    registryWords a = registryWords b ∧ ca = cb ∧ amountWords a = amountWords b :=
  token_funds_preimage_injective_fields hw (hb he)

/-- Four field elements, unlike the eight u32 limbs of Bytes32. No extra
    canonical-integer range constraint is invented for these field wires. -/
structure Hash4 where
  h0 : Nat
  h1 : Nat
  h2 : Nat
  h3 : Nat
  deriving DecidableEq, Repr

def Hash4.words (h : Hash4) : List Nat := [h.h0, h.h1, h.h2, h.h3]

structure PrivateState where
  assetTreeRoot : Hash4
  nullifierTreeRoot : Hash4
  sentTxTreeRoot : Hash4
  previousPrivateCommitment : Hash4
  nonce : Nat
  salt : Hash4
  deriving DecidableEq, Repr

def PrivateState.words (p : PrivateState) : List Nat :=
  p.assetTreeRoot.words ++ p.nullifierTreeRoot.words ++ p.sentTxTreeRoot.words ++
    p.previousPrivateCommitment.words ++ [p.nonce] ++ p.salt.words

structure InnerPublicState where
  blockNumber : Nat
  timestampHi : Nat
  timestampLo : Nat
  accountTreeRoot : Hash4
  depositTreeRoot : Hash4
  previousPublicStateRoot : Hash4
  deriving DecidableEq, Repr

def InnerPublicState.words (p : InnerPublicState) : List Nat :=
  [p.blockNumber, p.timestampHi, p.timestampLo] ++ p.accountTreeRoot.words ++
    p.depositTreeRoot.words ++ p.previousPublicStateRoot.words

structure ExtendedPublicState where
  inner : InnerPublicState
  blockHashChain : Words8
  depositHashChain : Words8
  depositCount : Nat
  channelRegistrationHashChain : Words8
  blockProducerSignatureChain : Words8
  deriving DecidableEq, Repr

def ExtendedPublicState.words (p : ExtendedPublicState) : List Nat :=
  p.inner.words ++ p.blockHashChain.words ++ p.depositHashChain.words ++ [p.depositCount] ++
    p.channelRegistrationHashChain.words ++ p.blockProducerSignatureChain.words

/-- The checked constructor does not constrain the field-valued roots to u32. -/
def ExtendedPublicState.Checked (p : ExtendedPublicState) : Prop :=
  p.inner.blockNumber < blockLimit ∧ p.inner.timestampHi < wordBase ∧
  p.inner.timestampLo < wordBase ∧ p.blockHashChain.Checked ∧
  p.depositHashChain.Checked ∧ p.depositCount < blockLimit ∧
  p.channelRegistrationHashChain.Checked ∧ p.blockProducerSignatureChain.Checked

structure BalanceStatement where
  channelId : Nat
  publicState : InnerPublicState
  blockR : Nat
  privateCommitment : Hash4
  settledTxChain : Words8
  deriving DecidableEq, Repr

structure VerifierKey where
  circuitDigest : Hash4
  constantsSigmasCap : List Hash4
  deriving DecidableEq, Repr

/-- This view is supplied by BalanceFullPublicInputs decoding. That decoder
    and the extraction of the cyclic verifier tail are explicit dependencies. -/
structure BalanceProofView (Proof : Type) where
  artifact : Proof
  statement : BalanceStatement
  embeddedVerifierKey : VerifierKey
  publicInputCount : Nat
  cyclicKeyCheck : Bool
  nativeVerification : Bool
  nativeDecode : Bool

/-- Sharing this semantic hash interface between native/target interpretations
    requires HashImplementationAgreement; it is not a byte-code equivalence. -/
structure HashFunctions where
  privateCommitment : List Nat → Hash4
  extendedCommitment : List Nat → Words8
  tokenFundsHash : List Nat → Words8

structure HashImplementationAgreement (native circuit : HashFunctions) : Prop where
  privateHash : ∀ words, native.privateCommitment words = circuit.privateCommitment words
  extendedHash : ∀ words, native.extendedCommitment words = circuit.extendedCommitment words
  tokenHash : ∀ words, native.tokenFundsHash words = circuit.tokenFundsHash words

/-- Raw witness/target values. In particular rows.active is arbitrary here. -/
structure Witness (Proof Path : Type) where
  finalBalanceProof : BalanceProofView Proof
  extendedState : ExtendedPublicState
  privateState : PrivateState
  tokenCount : Nat
  rows : List (Row Path)

def computedPublicInputs {Proof Path : Type} (hash : HashFunctions) (w : Witness Proof Path) :
    PublicInputs :=
  { channelId := w.finalBalanceProof.statement.channelId
    settledTxChain := w.finalBalanceProof.statement.settledTxChain
    tokenFundsDigest := hash.tokenFundsHash (tokenFundsPreimage w.tokenCount w.rows)
    extendedStateCommitment := hash.extendedCommitment w.extendedState.words
    anchorBlockNumber := w.extendedState.inner.blockNumber }

structure ComputedWires where
  openedPrivateCommitment : Hash4
  reconstructedRoot : Hash4
  publicInputs : PublicInputs

def computeWires {Proof Path : Type} (m : MerkleContract Hash4 Path) (hash : HashFunctions)
    (w : Witness Proof Path) : ComputedWires :=
  { openedPrivateCommitment := hash.privateCommitment w.privateState.words
    reconstructedRoot := pathFold m w.rows m.emptyRoot
    publicInputs := computedPublicInputs hash w }

/-- Constant-VK recursive verification is opaque, but its promised result is
    only the exact Balance statement under that VK, NOT economic soundness. -/
structure RecursiveVerifierContract (Proof : Type) where
  pinnedKey : VerifierKey
  expectedBalancePiCount : Nat
  circuitAccepts : BalanceProofView Proof → Prop
  balanceRelation : VerifierKey → Proof → BalanceStatement → Prop
  sound : ∀ p, circuitAccepts p →
    p.embeddedVerifierKey = pinnedKey ∧
    p.publicInputCount = expectedBalancePiCount ∧
    balanceRelation pinnedKey p.artifact p.statement

/-- Denotation of the local gates AFTER field/gadget lowering. It neither
    requires native constructor success nor a signed ChannelState witness. -/
structure CircuitConstraints {Proof Path : Type} (m : MerkleContract Hash4 Path)
    (hash : HashFunctions) (recursive : RecursiveVerifierContract Proof)
    (w : Witness Proof Path) : Prop where
  verifiedBalance : recursive.circuitAccepts w.finalBalanceProof
  privateOpening : hash.privateCommitment w.privateState.words =
    w.finalBalanceProof.statement.privateCommitment
  publicConnection : w.finalBalanceProof.statement.publicState = w.extendedState.inner
  extendedRanges : w.extendedState.Checked
  vector : VectorGates w.tokenCount w.rows
  paths : PathGates m w.rows m.emptyRoot
  rootConnection : pathFold m w.rows m.emptyRoot = w.privateState.assetTreeRoot

/-- Compiler/field lowering obligation: a satisfying raw gate assignment
    yields the listed local constraints. This is passed explicitly, not proved
    or installed as an axiom. It asserts no canonical reconstruction result. -/
def FieldGateLowering {Proof Path : Type} (m : MerkleContract Hash4 Path)
    (hash : HashFunctions) (recursive : RecursiveVerifierContract Proof)
    (rawSatisfied : Witness Proof Path → Prop) : Prop :=
  ∀ w, rawSatisfied w → CircuitConstraints m hash recursive w

theorem circuit_binds_recursive_statement {Proof Path : Type}
    {m : MerkleContract Hash4 Path} {hash : HashFunctions}
    {recursive : RecursiveVerifierContract Proof} {w : Witness Proof Path}
    (g : CircuitConstraints m hash recursive w) :
    w.finalBalanceProof.embeddedVerifierKey = recursive.pinnedKey ∧
    w.finalBalanceProof.publicInputCount = recursive.expectedBalancePiCount ∧
    recursive.balanceRelation recursive.pinnedKey w.finalBalanceProof.artifact
      w.finalBalanceProof.statement := recursive.sound _ g.verifiedBalance

theorem circuit_private_root_is_exact_full_vector {Proof Path : Type}
    {m : MerkleContract Hash4 Path} {hash : HashFunctions}
    {recursive : RecursiveVerifierContract Proof} {w : Witness Proof Path}
    (g : CircuitConstraints m hash recursive w)
    (emptyCorrect : CanonicalEmptyRoot m) (contracts : RowPathContracts m w.rows emptyAssets) :
    w.privateState.assetTreeRoot = m.encode (canonicalAssets w.rows) := by
  rw [← g.rootConnection]
  exact canonical_root_from_empty m w.rows g.vector.ranges emptyCorrect contracts g.paths

theorem circuit_public_anchor_is_balance_public_height {Proof Path : Type}
    {m : MerkleContract Hash4 Path} {hash : HashFunctions}
    {recursive : RecursiveVerifierContract Proof} {w : Witness Proof Path}
    (g : CircuitConstraints m hash recursive w) :
    (computedPublicInputs hash w).anchorBlockNumber =
      w.finalBalanceProof.statement.publicState.blockNumber := by
  exact congrArg InnerPublicState.blockNumber g.publicConnection.symm

theorem circuit_does_not_mix_channel_or_settled_wires {Proof Path : Type}
    (hash : HashFunctions) (w : Witness Proof Path) :
    (computedPublicInputs hash w).channelId = w.finalBalanceProof.statement.channelId ∧
    (computedPublicInputs hash w).settledTxChain = w.finalBalanceProof.statement.settledTxChain :=
  ⟨rfl, rfl⟩

theorem circuit_range_and_zero_suffix {Proof Path : Type}
    {m : MerkleContract Hash4 Path} {hash : HashFunctions}
    {recursive : RecursiveVerifierContract Proof} {w : Witness Proof Path}
    (g : CircuitConstraints m hash recursive w) :
    1 ≤ w.tokenCount ∧ w.tokenCount ≤ maxTokens ∧
    activity w.rows = List.replicate w.tokenCount true ++
      List.replicate (maxTokens - w.tokenCount) false ∧
    (∀ r ∈ w.rows, r.registry < wordBase ∧ r.amount.Checked) ∧
    (∀ r ∈ w.rows, r.active = false → r.registry = 0 ∧ r.amount = Words8.zero) := by
  obtain ⟨hl, hu⟩ := vector_token_count_bounds g.vector
  refine ⟨hl, hu, canonical_activity_vector g.vector, g.vector.ranges, ?_⟩
  intro r hr ha
  exact inactive_registry_and_amount_zero (g.vector.padding r hr) ha

/-- Scoped binding to an independently specified private state. Hash binding
    alone is insufficient without the reference opening equation. -/
def PrivateCommitmentBindingAt (hash : HashFunctions) (a b : PrivateState) : Prop :=
  hash.privateCommitment a.words = hash.privateCommitment b.words → a = b

def TreeRootBindingAt {Path : Type} (m : MerkleContract Hash4 Path) (a b : AssetMap) : Prop :=
  m.encode a = m.encode b → a = b

theorem authenticated_private_tree_has_exact_listed_and_no_unlisted_assets
    {Proof Path : Type} {m : MerkleContract Hash4 Path} {hash : HashFunctions}
    {recursive : RecursiveVerifierContract Proof} {w : Witness Proof Path}
    (g : CircuitConstraints m hash recursive w)
    (emptyCorrect : CanonicalEmptyRoot m) (contracts : RowPathContracts m w.rows emptyAssets)
    (referencePrivate : PrivateState) (referenceAssets : AssetMap)
    (referenceOpening : hash.privateCommitment referencePrivate.words =
      w.finalBalanceProof.statement.privateCommitment)
    (referenceRoot : referencePrivate.assetTreeRoot = m.encode referenceAssets)
    (privateBinding : PrivateCommitmentBindingAt hash w.privateState referencePrivate)
    (treeBinding : TreeRootBindingAt m referenceAssets (canonicalAssets w.rows)) :
    w.privateState = referencePrivate ∧
    referenceAssets = canonicalAssets w.rows ∧
    (∀ r ∈ w.rows, r.active = true → referenceAssets r.registry = r.amount) ∧
    (∀ key, (∀ r ∈ w.rows, r.active = true → key ≠ r.registry) →
      referenceAssets key = Words8.zero) := by
  have hp : w.privateState = referencePrivate :=
    privateBinding (g.privateOpening.trans referenceOpening.symm)
  have hr := circuit_private_root_is_exact_full_vector g emptyCorrect contracts
  rw [hp, referenceRoot] at hr
  have ht := treeBinding hr
  refine ⟨hp, ht, ?_, ?_⟩
  · rw [ht]
    exact unique_rows_preserve_every_exact_amount w.rows emptyAssets g.vector.distinct
  · intro key hk
    rw [ht]
    exact canonical_assets_no_unlisted_balance w.rows key hk

theorem lowered_assignment_has_canonical_root {Proof Path : Type}
    {m : MerkleContract Hash4 Path} {hash : HashFunctions}
    {recursive : RecursiveVerifierContract Proof} {raw : Witness Proof Path → Prop}
    (lowering : FieldGateLowering m hash recursive raw) (w : Witness Proof Path) (h : raw w)
    (emptyCorrect : CanonicalEmptyRoot m) (contracts : RowPathContracts m w.rows emptyAssets) :
    w.privateState.assetTreeRoot = m.encode (canonicalAssets w.rows) :=
  circuit_private_root_is_exact_full_vector (lowering w h) emptyCorrect contracts

/-- Macro operations preserve constructor order; array loops are expanded.
    Dependency calls are deliberately visible rather than replaced by extra
    native admissions. Their internals are not a Plonky2 gate serialization. -/
inductive BuildOp where
  | assertBalancePiShape
  | startStandardRecursionZk
  | allocateProofAndVerifyPinnedCyclic
  | decodeBalanceTargetPis
  | allocatePrivateUnchecked
  | computePrivatePoseidon
  | connectPrivateCommitment
  | allocateExtendedChecked
  | connectInnerPublicState
  | allocateCount
  | rangeCount32
  | allocateRegistry (row : Nat)
  | rangeRegistry32 (row : Nat)
  | allocateCheckedU256 (row : Nat)
  | allocateSafeBoolean (row : Nat)
  | allocatePath (row height : Nat)
  | constantZero
  | constantOne
  | subtractActivityFromOne (row : Nat)
  | multiplyNextActivity (row : Nat)
  | connectNoRiseZero (row : Nat)
  | addActivityToSum (row : Nat)
  | connectSumToCount
  | assertFirstActive
  | notActivity (row : Nat)
  | multiplyInactiveRegistry (row : Nat)
  | connectInactiveRegistryZero (row : Nat)
  | multiplyInactiveAmount (row limb : Nat)
  | connectInactiveAmountZero (row limb : Nat)
  | equalRegistry (earlier later : Nat)
  | andEqualWithLaterActive (earlier later : Nat)
  | connectDuplicateZero (earlier later : Nat)
  | constantZeroLeaf
  | constantEmptyRoot
  | conditionalVerifyZeroPath (row : Nat)
  | computeInsertedRoot (row : Nat)
  | selectUpdatedRoot (row : Nat)
  | connectFinalAssetRoot
  | constantTokenFundsDomain
  | flattenAmountLimbs
  | concatenateDigestPreimage
  | computeKeccakTokenFunds
  | computeExtendedPoseidonBytes
  | assembleComputedPublicInputs
  | registerPublicInputs (count : Nat)
  | buildCircuit
  deriving DecidableEq, Repr

def constructorProgram : List BuildOp :=
  [.assertBalancePiShape, .startStandardRecursionZk,
   .allocateProofAndVerifyPinnedCyclic, .decodeBalanceTargetPis,
   .allocatePrivateUnchecked, .computePrivatePoseidon, .connectPrivateCommitment,
   .allocateExtendedChecked, .connectInnerPublicState, .allocateCount, .rangeCount32] ++
  (List.range maxTokens).bind (fun i => [.allocateRegistry i, .rangeRegistry32 i]) ++
  (List.range maxTokens).map BuildOp.allocateCheckedU256 ++
  (List.range maxTokens).map BuildOp.allocateSafeBoolean ++
  (List.range maxTokens).map (fun i => .allocatePath i assetTreeHeight) ++
  [.constantZero, .constantOne] ++
  (List.range (maxTokens - 1)).bind (fun i =>
    [.subtractActivityFromOne i, .multiplyNextActivity i, .connectNoRiseZero i]) ++
  (List.range maxTokens).map BuildOp.addActivityToSum ++
  [.connectSumToCount, .assertFirstActive] ++
  (List.range maxTokens).bind (fun i =>
    [.notActivity i, .multiplyInactiveRegistry i, .connectInactiveRegistryZero i] ++
    (List.range 8).bind (fun j => [.multiplyInactiveAmount i j, .connectInactiveAmountZero i j])) ++
  (List.range maxTokens).bind (fun i =>
    ((List.range maxTokens).drop (i + 1)).bind (fun j =>
      [.equalRegistry i j, .andEqualWithLaterActive i j, .connectDuplicateZero i j])) ++
  [.constantZeroLeaf, .constantEmptyRoot] ++
  (List.range maxTokens).bind (fun i =>
    [.conditionalVerifyZeroPath i, .computeInsertedRoot i, .selectUpdatedRoot i]) ++
  [.connectFinalAssetRoot, .constantTokenFundsDomain, .flattenAmountLimbs,
   .concatenateDigestPreimage, .computeKeccakTokenFunds, .computeExtendedPoseidonBytes,
   .assembleComputedPublicInputs, .registerPublicInputs publicInputsLength, .buildCircuit]

/-- The Rust assertion precedes builder creation. vd_vec_len(config) is an
    external size calculation; its result is passed explicitly here. -/
def newCircuitProgram (providedPiCount verifierTailLength : Nat) : Option (List BuildOp) :=
  if providedPiCount = balancePublicInputsLength + verifierTailLength then
    some constructorProgram
  else none

theorem constructor_admits_only_exact_cyclic_balance_shape {provided tail : Nat}
    {program : List BuildOp} (h : newCircuitProgram provided tail = some program) :
    provided = balancePublicInputsLength + tail ∧ program = constructorProgram := by
  unfold newCircuitProgram at h
  split at h
  · rename_i hs
    exact ⟨hs, (Option.some.inj h).symm⟩
  · contradiction

theorem constructor_starts_with_pinned_recursive_verification :
    constructorProgram.take 4 = [.assertBalancePiShape, .startStandardRecursionZk,
      .allocateProofAndVerifyPinnedCyclic, .decodeBalanceTargetPis] := by decide

theorem constructor_registers_exact_26_inputs_then_builds :
    constructorProgram.reverse.take 2 = [.buildCircuit, .registerPublicInputs 26] := by decide

theorem constructor_allocates_exactly_ten_safe_activity_witnesses :
    constructorProgram.filter (fun op => match op with
      | .allocateSafeBoolean _ => true | _ => false) =
      (List.range 10).map BuildOp.allocateSafeBoolean := by decide

theorem constructor_checks_all_45_ordered_registry_pairs :
    (constructorProgram.filter (fun op => match op with
      | .equalRegistry _ _ => true | _ => false)).length = 45 := by decide

structure Entry where
  registry : Nat
  amount : Words8
  deriving DecidableEq, Repr

/-- ChannelState is a projection of inspected fields only. There is no
    invented signature/finality/epoch validation in the native constructor. -/
structure ChannelStateMirror where
  channelId : Nat
  balanceChannelId : Nat
  fundChannelId : Nat
  settledTxChain : Words8
  tokenCount : Nat
  entries : List Entry

/-- Rust u8/u32/U256 and [T;10] typing is an explicit input domain. -/
def ChannelStateMirror.NativeTyped (s : ChannelStateMirror) : Prop :=
  s.tokenCount < 256 ∧ s.entries.length = maxTokens ∧
  ∀ e ∈ s.entries, e.registry < wordBase ∧ e.amount.Checked

def nativeUniqueKeys : List Entry → Bool
  | [] => true
  | e :: es => (es.all (fun f => e.registry != f.registry)) && nativeUniqueKeys es

def nativePaddingZero (count : Nat) (es : List Entry) : Bool :=
  (es.drop count).all (fun e => e.registry == 0 && e.amount == Words8.zero)

/-- Native construction proves a path BEFORE insertion, using index zero for
    inactive rows. debug_assert!(zero leaf) is NOT a release-mode admission. -/
def constructNativeRows {Path : Type} (makePath : AssetMap → Nat → Path)
    (count : Nat) : Nat → List Entry → AssetMap → List (Row Path) × AssetMap
  | _, [], tree => ([], tree)
  | position, e :: es, tree =>
      let active := decide (position < count)
      let index := if active then e.registry else 0
      let path := makePath tree index
      let next := if active then insertAsset tree e.registry e.amount else tree
      let tail := constructNativeRows makePath count (position + 1) es next
      (⟨e.registry, e.amount, active, path⟩ :: tail.1, tail.2)

theorem native_tree_builder_matches_sequential_asset_updates {Path : Type}
    (makePath : AssetMap → Nat → Path) (count position : Nat) (es : List Entry) (tree : AssetMap) :
    (constructNativeRows makePath count position es tree).2 =
      applyRows (constructNativeRows makePath count position es tree).1 tree := by
  induction es generalizing tree position with
  | nil => rfl
  | cons e es ih =>
      simp only [constructNativeRows, applyRows]
      exact ih _ _

structure NativeCheck where
  passes : Bool
  error : Error

def runNativeChecks : List NativeCheck → Except Error Unit
  | [] => .ok ()
  | c :: cs => if c.passes then runNativeChecks cs else .error c.error

theorem native_checks_success_means_every_check_passed (checks : List NativeCheck)
    (h : runNativeChecks checks = .ok ()) : ∀ c ∈ checks, c.passes = true := by
  induction checks with
  | nil => simp
  | cons c cs ih =>
      cases hp : c.passes with
      | false => simp [runNativeChecks, hp] at h
      | true =>
          have ht : runNativeChecks cs = .ok () := by simpa [runNativeChecks, hp] using h
          intro d hd
          rcases List.mem_cons.mp hd with hd | hd
          · simpa [hd] using hp
          · exact ih ht d hd

def nativeChecks {Proof Path : Type} (m : MerkleContract Hash4 Path) (hash : HashFunctions)
    (makePath : AssetMap → Nat → Path) (s : ChannelStateMirror) (w : Witness Proof Path) :
    List NativeCheck :=
  let p := w.finalBalanceProof
  let built := constructNativeRows makePath s.tokenCount 0 s.entries emptyAssets
  [⟨p.cyclicKeyCheck, .balanceProofVerification⟩,
   ⟨p.nativeVerification, .balanceProofVerification⟩,
   ⟨p.nativeDecode, .balanceProofVerification⟩,
   ⟨decide (p.statement.privateCommitment = hash.privateCommitment w.privateState.words),
     .balancePrivateCommitmentMismatch⟩,
   ⟨decide (p.statement.publicState = w.extendedState.inner), .balancePublicStateMismatch⟩,
   ⟨decide (s.channelId = s.balanceChannelId ∧ s.channelId = s.fundChannelId), .invalidAssetVector⟩,
   ⟨decide (p.statement.channelId = s.channelId), .balanceChannelMismatch⟩,
   ⟨decide (p.statement.settledTxChain = s.settledTxChain), .balanceSettledChainMismatch⟩,
   ⟨decide (1 ≤ s.tokenCount ∧ s.tokenCount ≤ maxTokens), .invalidAssetVector⟩,
   ⟨nativeUniqueKeys (s.entries.take s.tokenCount), .invalidAssetVector⟩,
   ⟨nativePaddingZero s.tokenCount s.entries, .invalidAssetVector⟩,
   ⟨decide (m.encode built.2 = w.privateState.assetTreeRoot), .assetTreeRootMismatch⟩]

def fromPrivateStateAndChannelState {Proof Path : Type} (m : MerkleContract Hash4 Path)
    (hash : HashFunctions) (makePath : AssetMap → Nat → Path)
    (s : ChannelStateMirror) (input : Witness Proof Path) : Except Error (Witness Proof Path) :=
  match runNativeChecks (nativeChecks m hash makePath s input) with
  | .error err => .error err
  | .ok () =>
      .ok { input with
        tokenCount := s.tokenCount
        rows := (constructNativeRows makePath s.tokenCount 0 s.entries emptyAssets).1 }

/-- FullPrivateState::to_private_state delegates tree-root extraction. Its
    storage representation and serialization are not verified here. -/
def fromFullPrivateStateAndChannelState {Full Proof Path : Type}
    (toPrivateState : Full → PrivateState) (full : Full) (m : MerkleContract Hash4 Path)
    (hash : HashFunctions) (makePath : AssetMap → Nat → Path)
    (s : ChannelStateMirror) (input : Witness Proof Path) : Except Error (Witness Proof Path) :=
  fromPrivateStateAndChannelState m hash makePath s { input with privateState := toPrivateState full }

theorem native_constructor_checks_exact_canonical_tree_before_success {Proof Path : Type}
    (m : MerkleContract Hash4 Path) (hash : HashFunctions)
    (makePath : AssetMap → Nat → Path) (s : ChannelStateMirror) (input output : Witness Proof Path)
    (h : fromPrivateStateAndChannelState m hash makePath s input = .ok output) :
    output.privateState.assetTreeRoot = m.encode (canonicalAssets output.rows) := by
  unfold fromPrivateStateAndChannelState at h
  split at h
  · contradiction
  next hc =>
    have ho := Except.ok.inj h
    subst output
    have hall := native_checks_success_means_every_check_passed _ hc
    have hroot := hall
      ⟨decide (m.encode (constructNativeRows makePath s.tokenCount 0 s.entries emptyAssets).2 =
        input.privateState.assetTreeRoot), .assetTreeRootMismatch⟩ (by simp [nativeChecks])
    have he : m.encode (constructNativeRows makePath s.tokenCount 0 s.entries emptyAssets).2 =
        input.privateState.assetTreeRoot := of_decide_eq_true hroot
    rw [native_tree_builder_matches_sequential_asset_updates] at he
    exact he.symm

/-- public_inputs decodes only; it does not re-run verification or admission. -/
def witnessPublicInputs {Proof Path : Type} (hash : HashFunctions) (w : Witness Proof Path) :
    Except Error PublicInputs :=
  if w.finalBalanceProof.nativeDecode then .ok (computedPublicInputs hash w)
  else .error .balanceProofVerification

def fillRows {Path : Type} (count : Nat) : Nat → List (Row Path) → List (Row Path)
  | _, [] => []
  | position, r :: rs =>
      { r with active := decide (position < count) } :: fillRows count (position + 1) rs

/-- Copy proof, state, count, registry, U256 limbs, paths; recompute ONLY the
    activity assignment. Native u8/u32 typing is a separate domain premise. -/
def fillWitness {Proof Path : Type} (w : Witness Proof Path) : Witness Proof Path :=
  { w with rows := fillRows w.tokenCount 0 w.rows }

def prove {Proof Path Output : Type} (backend : Witness Proof Path → Except String Output)
    (w : Witness Proof Path) : Except Error Output :=
  match backend (fillWitness w) with
  | .ok proof => .ok proof
  | .error _ => .error .failedToProve

theorem fill_witness_preserves_every_registry_word {Path : Type}
    (count position : Nat) (rows : List (Row Path)) :
    registryWords (fillRows count position rows) = registryWords rows := by
  induction rows generalizing position with
  | nil => rfl
  | cons r rs ih =>
      change r.registry :: registryWords (fillRows count (position + 1) rs) =
        r.registry :: registryWords rs
      rw [ih]

theorem fill_witness_preserves_every_amount_limb {Path : Type}
    (count position : Nat) (rows : List (Row Path)) :
    amountWords (fillRows count position rows) = amountWords rows := by
  induction rows generalizing position with
  | nil => rfl
  | cons r rs ih => simp [fillRows, amountWords, ih]

theorem fill_witness_preserves_token_funds_preimage {Proof Path : Type}
    (w : Witness Proof Path) :
    tokenFundsPreimage (fillWitness w).tokenCount (fillWitness w).rows =
      tokenFundsPreimage w.tokenCount w.rows := by
  simp [fillWitness, tokenFundsPreimage, fill_witness_preserves_every_registry_word,
    fill_witness_preserves_every_amount_limb]

theorem native_public_input_projection_agrees_with_filled_circuit {Proof Path : Type}
    (hash : HashFunctions) (w : Witness Proof Path) :
    computedPublicInputs hash (fillWitness w) = computedPublicInputs hash w := by
  simp [computedPublicInputs, fill_witness_preserves_token_funds_preimage, fillWitness,
    tokenFundsPreimage, fill_witness_preserves_every_registry_word,
    fill_witness_preserves_every_amount_limb]

theorem native_target_public_inputs_agree_under_hash_implementation_contract {Proof Path : Type}
    (native circuit : HashFunctions) (h : HashImplementationAgreement native circuit)
    (w : Witness Proof Path) :
    computedPublicInputs native w = computedPublicInputs circuit (fillWitness w) := by
  rw [native_public_input_projection_agrees_with_filled_circuit]
  simp [computedPublicInputs, h.tokenHash, h.extendedHash]

theorem proving_wrapper_has_no_extra_native_admission {Proof Path Output : Type}
    (backend : Witness Proof Path → Except String Output) (w : Witness Proof Path) (p : Output)
    (h : backend (fillWitness w) = .ok p) : prove backend w = .ok p := by
  simp [prove, h]

theorem private_state_commitment_preimage_has_all_21_fields (p : PrivateState) :
    p.words.length = 21 := by
  simp [PrivateState.words, Hash4.words]

theorem extended_state_commitment_preimage_has_all_48_fields (p : ExtendedPublicState) :
    p.words.length = 48 := by
  simp [ExtendedPublicState.words, InnerPublicState.words, Hash4.words, Words8.words]

def ExtendedCommitmentBindingAt (hash : HashFunctions) (a b : ExtendedPublicState) : Prop :=
  hash.extendedCommitment a.words = hash.extendedCommitment b.words → a = b

theorem extended_commitment_and_anchor_bind_one_public_state {Proof Path : Type}
    {m : MerkleContract Hash4 Path} {hash : HashFunctions}
    {recursive : RecursiveVerifierContract Proof} {w : Witness Proof Path}
    (g : CircuitConstraints m hash recursive w) (reference : ExtendedPublicState)
    (binding : ExtendedCommitmentBindingAt hash w.extendedState reference)
    (commitment : (computedPublicInputs hash w).extendedStateCommitment =
      hash.extendedCommitment reference.words) :
    w.extendedState = reference ∧
    w.finalBalanceProof.statement.publicState = reference.inner ∧
    (computedPublicInputs hash w).anchorBlockNumber = reference.inner.blockNumber := by
  have he : w.extendedState = reference := binding commitment
  refine ⟨he, g.publicConnection.trans (congrArg ExtendedPublicState.inner he), ?_⟩
  exact congrArg (fun p : ExtendedPublicState => p.inner.blockNumber) he

theorem checked_eight_big_endian_limbs_fit_u256 (w : Words8) (h : w.Checked) :
    w.value < 2 ^ 256 := by
  cases w with
  | mk a b c d e f g i =>
      simp [Words8.Checked, Words8.words, wordBase] at h
      simp [Words8.value, Words8.words, wordBase]
      omega

theorem circuit_each_fund_amount_fits_u256 {Proof Path : Type}
    {m : MerkleContract Hash4 Path} {hash : HashFunctions}
    {recursive : RecursiveVerifierContract Proof} {w : Witness Proof Path}
    (g : CircuitConstraints m hash recursive w) :
    ∀ r ∈ w.rows, r.amount.value < 2 ^ 256 := by
  intro r hr
  exact checked_eight_big_endian_limbs_fit_u256 r.amount (g.vector.ranges r hr).2

theorem target_decode_success_reconstructs_exact_input {words : List Nat} {p : PublicInputs}
    (h : parseTargets words = some p) : p.words = words := by
  unfold parseTargets at h
  split at h
  · have hp := Option.some.inj h
    subst p
    rfl
  · contradiction

theorem target_decode_success_has_exact_26_words {words : List Nat} {p : PublicInputs}
    (h : parseTargets words = some p) : words.length = publicInputsLength := by
  rw [← target_decode_success_reconstructs_exact_input h]
  exact public_inputs_length p

theorem native_decode_success_is_canonical {words : List Nat} {p : PublicInputs}
    (h : parsePublicInputs words = .ok p) : p.Canonical := by
  unfold parsePublicInputs at h
  split at h
  · contradiction
  · split at h
    · split at h
      · split at h
        · split at h
          · split at h
            · have hp := Except.ok.inj h
              subst p
              exact ⟨by assumption, by assumption, by assumption, by assumption, by assumption⟩
            · contradiction
          · contradiction
        · contradiction
      · contradiction
    · contradiction

/-- Positive concrete examples establish nonempty normal vector/parser paths.
    These are kernel checked, not new Rust proof generation or exploit tests. -/
def normalAmount (n : Nat) : Words8 := ⟨0,0,0,0,0,0,0,n⟩

def normalRows : List (Row Unit) :=
  [⟨0, normalAmount 11, true, ()⟩,
   ⟨17, normalAmount 22, true, ()⟩,
   ⟨4294967295, normalAmount 33, true, ()⟩] ++
  List.replicate 7 ⟨0, Words8.zero, false, ()⟩

theorem example_three_token_exact_vector_without_aggregation :
    canonicalAssets normalRows 0 = normalAmount 11 ∧
    canonicalAssets normalRows 17 = normalAmount 22 ∧
    canonicalAssets normalRows 4294967295 = normalAmount 33 ∧
    canonicalAssets normalRows 19 = Words8.zero := by decide

theorem example_ten_positions_still_hash_92_words :
    (tokenFundsPreimage 3 normalRows).length = 92 := by decide

theorem example_native_public_inputs_round_trip :
    parsePublicInputs (PublicInputs.words
      ⟨91, normalAmount 1, normalAmount 2, normalAmount 3, 12⟩) =
      .ok ⟨91, normalAmount 1, normalAmount 2, normalAmount 3, 12⟩ := by
  apply native_encode_decode
  simp [PublicInputs.Canonical, Words8.Checked, normalAmount, Words8.words, wordBase, blockLimit]

theorem example_normal_prefix_determined_by_gates :
    NoRise true (activity normalRows) ∧ activeCount (activity normalRows) = 3 := by
  simp [NoRise, activity, normalRows, activeCount, bit, List.replicate_succ]

theorem example_normal_vector_satisfies_all_local_vector_gates : VectorGates 3 normalRows := by
  constructor
  · rfl
  · decide
  · simp [RangeGates, normalRows, Words8.Checked, Words8.words, Words8.zero,
      normalAmount, wordBase]
  · exact example_normal_prefix_determined_by_gates.1
  · exact example_normal_prefix_determined_by_gates.2
  · rfl
  · simp [normalRows, PaddingGates, bit, Words8.zero, Words8.words]
  · simp [UniqueGates, normalRows, List.replicate_succ]

end Zkp.Implementation.CloseAssetBacking
