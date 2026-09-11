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

/-! ### Gate lowering: per-primitive satisfaction semantics for `constructorProgram`

`CircuitConstraints` above is the hand-written gate predicate; `constructorProgram`
is the ordered transcript of the builder calls in `CloseAssetBackingCircuit::new`
(`src/circuits/channel/close_asset_backing_circuit.rs:400-527`). This section
closes the gap between the two INSIDE the model: an `Assignment` values every
wire the constructor allocates, `BuildOp.holds` states exactly the local
proposition the named plonky2 primitive enforces on those wires, and
`program_satisfied_implies_constraints` derives every `CircuitConstraints` field
from the ordered program alone, with no extra admission premise and no residual
side hypothesis.

What stays outside the model is therefore PER-PRIMITIVE rather than
whole-circuit: (i) each `holds` case must match the real gate set emitted by that
one builder call (`range_check`, `connect`, `add_virtual_bool_target_safe`,
`add`/`sub`/`mul`, `not`, `assert_one`, `is_equal`/`and`,
`PoseidonHashOutTarget::select`, `keccak256`, `hash_inputs`,
`add_proof_target_and_verify_cyclic`, `SparseMerkleProofTarget::
conditional_verify`/`get_root`), and (ii) the digest and verifier-data pinning —
`Environment.hash`, `Environment.merkle` and `Environment.recursive` must be the
real gadgets and the real pinned Balance circuit. Neither is proved here.

Field arithmetic is modeled over `Nat`. That is sound for these gates because
every quantity in an arithmetic gate here is Boolean, a 32-bit range-checked
limb, or a sum of at most ten Boolean limbs, so it stays far below the Goldilocks
modulus and the field equations force the `Nat` equations used below. The two
truncated subtractions (`one - bit` at :440 and `not` at :452) are only ever
evaluated at a limb the same op list has already constrained Boolean.
-/

/-- The opaque dependencies of one circuit instance, bundled so that a single
    `Assignment` can mention all three. Nothing new is assumed: these are the
    same `MerkleContract`, `HashFunctions` and `RecursiveVerifierContract` that
    `CircuitConstraints` already takes as parameters. -/
structure Environment (Proof Path : Type) where
  merkle : MerkleContract Hash4 Path
  hash : HashFunctions
  recursive : RecursiveVerifierContract Proof

def indexedWires {α : Type} (f : Nat → α) (start : Nat) : Nat → List α
  | 0 => []
  | n + 1 => f start :: indexedWires f (start + 1) n

def sumWires (w : Nat → Nat) (start : Nat) : Nat → Nat
  | 0 => 0
  | n + 1 => w start + sumWires w (start + 1) n

theorem indexed_wires_length {α : Type} (f : Nat → α) (n : Nat) :
    ∀ s, (indexedWires f s n).length = n := by
  induction n with
  | zero => intro s; rfl
  | succ n ih => intro s; simp [indexedWires, ih]

theorem indexed_wires_head {α : Type} (f : Nat → α) (n s : Nat) :
    (indexedWires f s (n + 1)).head? = some (f s) := by
  simp [indexedWires]

theorem mem_indexed_wires {α : Type} (f : Nat → α) (n : Nat) :
    ∀ s x, x ∈ indexedWires f s n → ∃ i, i < n ∧ x = f (s + i) := by
  induction n with
  | zero => intro s x hx; exact absurd hx (by simp [indexedWires])
  | succ n ih =>
      intro s x hx
      simp only [indexedWires, List.mem_cons] at hx
      rcases hx with rfl | hx
      · exact ⟨0, Nat.succ_pos n, rfl⟩
      · obtain ⟨i, hi, hx⟩ := ih (s + 1) x hx
        exact ⟨i + 1, by omega, hx.trans (congrArg f (by omega))⟩

theorem map_indexed_wires {α β : Type} (g : α → β) (f : Nat → α) (n : Nat) :
    ∀ s, (indexedWires f s n).map g = indexedWires (fun i => g (f i)) s n := by
  induction n with
  | zero => intro s; rfl
  | succ n ih => intro s; simp [indexedWires, ih]

theorem sum_wires_snoc (w : Nat → Nat) (n : Nat) :
    ∀ s, sumWires w s (n + 1) = sumWires w s n + w (s + n) := by
  induction n with
  | zero => intro s; simp [sumWires]
  | succ n ih =>
      intro s
      have step : sumWires w s (n + 1 + 1) = w s + sumWires w (s + 1) (n + 1) := rfl
      rw [step, ih (s + 1)]
      have hidx : s + 1 + n = s + (n + 1) := by omega
      rw [hidx, ← Nat.add_assoc]
      rfl

theorem bit_of_boolean_wire (x : Nat) (h : x = 0 ∨ x = 1) : bit (x == 1) = x := by
  rcases h with h | h <;> simp [h, bit]

theorem not_bit_of_boolean_wire (x : Nat) (h : x = 0 ∨ x = 1) :
    bit (!(x == 1)) = 1 - x := by
  rcases h with h | h <;> simp [h, bit]

theorem range_loop_append (n : Nat) : ∀ ns : List Nat,
    List.range.loop n ns = List.range n ++ ns := by
  induction n with
  | zero => intro ns; rfl
  | succ n ih =>
      intro ns
      have h1 : List.range.loop (n + 1) ns = List.range.loop n (n :: ns) := rfl
      have h2 : List.range (n + 1) = List.range.loop n [n] := rfl
      rw [h1, ih (n :: ns), h2, ih [n], List.append_assoc]
      rfl

theorem range_succ_snoc (n : Nat) : List.range (n + 1) = List.range n ++ [n] := by
  have h2 : List.range (n + 1) = List.range.loop n [n] := rfl
  rw [h2, range_loop_append]

theorem length_range_eq (n : Nat) : (List.range n).length = n := by
  induction n with
  | zero => rfl
  | succ n ih => rw [range_succ_snoc]; simp [ih]

theorem mem_range_loop_iff (n : Nat) : ∀ (ns : List Nat) (i : Nat),
    i ∈ List.range.loop n ns ↔ (i < n ∨ i ∈ ns) := by
  induction n with
  | zero => intro ns i; simp [List.range.loop]; omega
  | succ n ih =>
      intro ns i
      rw [show List.range.loop (n + 1) ns = List.range.loop n (n :: ns) from rfl, ih]
      constructor
      · rintro (h | h)
        · exact Or.inl (by omega)
        · rcases List.mem_cons.mp h with rfl | h
          · exact Or.inl (by omega)
          · exact Or.inr h
      · rintro (h | h)
        · rcases Nat.lt_or_ge i n with h2 | h2
          · exact Or.inl h2
          · exact Or.inr (List.mem_cons.mpr (Or.inl (by omega)))
        · exact Or.inr (List.mem_cons.mpr (Or.inr h))

theorem mem_range_iff_lt (i n : Nat) : i ∈ List.range n ↔ i < n := by
  simpa using mem_range_loop_iff n [] i

/-- The inner `((List.range n).drop (i+1))` of the ordered duplicate-registry
    loop enumerates exactly the strictly later positions. -/
theorem mem_drop_range_iff (n : Nat) : ∀ k j : Nat,
    j ∈ (List.range n).drop k ↔ (k ≤ j ∧ j < n) := by
  induction n with
  | zero =>
      intro k j
      constructor
      · intro h
        have : (List.range 0).drop k = [] := by simp [List.range, List.range.loop]
        rw [this] at h
        exact absurd h (by simp)
      · intro h; omega
  | succ n ih =>
      intro k j
      rcases Nat.lt_or_ge n k with hk | hk
      · have hlen : (List.range (n + 1)).length ≤ k := by rw [length_range_eq]; omega
        rw [List.drop_eq_nil_of_le hlen]
        constructor
        · intro h; exact absurd h (by simp)
        · intro h; omega
      · have hlen : k ≤ (List.range n).length := by rw [length_range_eq]; exact hk
        rw [range_succ_snoc, List.drop_append_of_le_length hlen, List.mem_append, ih k j]
        constructor
        · rintro (h | h)
          · exact ⟨h.1, by omega⟩
          · have hj : j = n := by simpa using h
            omega
        · intro h
          rcases Nat.lt_or_ge j n with hj | hj
          · exact Or.inl ⟨h.1, hj⟩
          · have hj2 : j = n := by omega
            exact Or.inr (by simp [hj2])

theorem words8_zero_limb : ∀ j, j < 8 → Words8.zero.words.getD j 0 = 0
  | 0, _ => rfl
  | 1, _ => rfl
  | 2, _ => rfl
  | 3, _ => rfl
  | 4, _ => rfl
  | 5, _ => rfl
  | 6, _ => rfl
  | 7, _ => rfl
  | _ + 8, h => absurd h (by omega)

theorem words8_mem_is_a_limb (w : Words8) (x : Nat) (h : x ∈ w.words) :
    ∃ j, j < 8 ∧ w.words.getD j 0 = x := by
  cases w with
  | mk a b c d e f g i =>
      simp only [Words8.words, List.mem_cons, List.not_mem_nil, or_false] at h
      rcases h with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      · exact ⟨0, by omega, rfl⟩
      · exact ⟨1, by omega, rfl⟩
      · exact ⟨2, by omega, rfl⟩
      · exact ⟨3, by omega, rfl⟩
      · exact ⟨4, by omega, rfl⟩
      · exact ⟨5, by omega, rfl⟩
      · exact ⟨6, by omega, rfl⟩
      · exact ⟨7, by omega, rfl⟩

/-- Every wire `CloseAssetBackingCircuit::new` allocates or derives, in source
    order: the recursively verified Balance proof target together with the
    public inputs `BalanceFullPublicInputsTarget::from_pis` re-slices out of it
    (:409-414), the witnessed `PrivateStateTarget` and its Poseidon opening
    (:416-418), the checked `ExtendedPublicStateTarget` (:420), the token count,
    ten registry limbs, ten checked U256 funds, ten safe activity bits and ten
    height-32 asset paths (:425-435), the arithmetic intermediates of the
    prefix/padding/duplicate loops (:437-466), the reconstructed-root chain
    (:471-494), the digest preimage and the two recomputed commitments
    (:496-510), and the 26 registered public wires (:511-518). -/
structure Assignment {Proof Path : Type} (e : Environment Proof Path) where
  balanceProofWire : BalanceProofView Proof
  privateStateWire : PrivateState
  openedPrivateCommitmentWire : Hash4
  extendedStateWire : ExtendedPublicState
  tokenCountWire : Nat
  registryWire : Nat → Nat
  amountWire : Nat → Words8
  activityWire : Nat → Nat
  pathWire : Nat → Path
  zeroWire : Nat
  oneWire : Nat
  oneMinusActivityWire : Nat → Nat
  riseProductWire : Nat → Nat
  activitySumWire : Nat → Nat
  inactiveWire : Nat → Nat
  dirtyRegistryWire : Nat → Nat
  dirtyAmountWire : Nat → Nat → Nat
  registryEqualWire : Nat → Nat → Nat
  duplicateActiveWire : Nat → Nat → Nat
  zeroLeafWire : Words8
  rootWire : Nat → Hash4
  insertedRootWire : Nat → Hash4
  tokenFundsDomainWire : Nat
  amountLimbsWire : List Nat
  digestPreimageWire : List Nat
  tokenFundsDigestWire : Words8
  extendedCommitmentWire : Words8
  publicWire : PublicInputs

/-- One token position as the model's `Row`: the four parallel arrays of
    `close_asset_backing_circuit.rs:387-390` read at the same index. -/
def rowWire {Proof Path : Type} {e : Environment Proof Path} (a : Assignment e)
    (i : Nat) : Row Path :=
  { registry := a.registryWire i
    amount := a.amountWire i
    active := a.activityWire i == 1
    path := a.pathWire i }

def assignedRows {Proof Path : Type} {e : Environment Proof Path}
    (a : Assignment e) : List (Row Path) := indexedWires (rowWire a) 0 maxTokens

/-- The 26 registered public wires, in `to_vec` order (:180-189, :518). -/
def readPublic {Proof Path : Type} {e : Environment Proof Path}
    (a : Assignment e) : PublicInputs := a.publicWire

/-- The witness half, at the widths `fill_witness` writes (:527-560). An
    activity WIRE decodes to the Boolean the model uses; `allocateSafeBoolean` is
    what makes that decoding lossless. -/
def readWitness {Proof Path : Type} {e : Environment Proof Path}
    (a : Assignment e) : Witness Proof Path where
  finalBalanceProof := a.balanceProofWire
  extendedState := a.extendedStateWire
  privateState := a.privateStateWire
  tokenCount := a.tokenCountWire
  rows := assignedRows a

theorem read_witness_rows {Proof Path : Type} {e : Environment Proof Path}
    (a : Assignment e) : (readWitness a).rows = assignedRows a := rfl

theorem row_wire_active_iff {Proof Path : Type} {e : Environment Proof Path}
    (a : Assignment e) (i : Nat) : (rowWire a i).active = true ↔ a.activityWire i = 1 := by
  simp [rowWire]

theorem row_wire_if_active {Proof Path : Type} {e : Environment Proof Path}
    {α : Type} (a : Assignment e) (i : Nat) (x y : α) :
    (if (rowWire a i).active = true then x else y) = (if a.activityWire i = 1 then x else y) := by
  by_cases h : a.activityWire i = 1
  · rw [if_pos ((row_wire_active_iff a i).mpr h), if_pos h]
  · rw [if_neg (fun hc => h ((row_wire_active_iff a i).mp hc)), if_neg h]

/-- Local satisfaction semantics of one builder call, wire by wire. Source lines
    are `src/circuits/channel/close_asset_backing_circuit.rs`.

* `assertBalancePiShape` — :401-405, the build-time
  `assert_eq!(balance_vd.common.num_public_inputs, BALANCE_PUBLIC_INPUTS_LEN +
  vd_vec_len(config))` pins the consumed proof to the canonical cyclic width.
* `startStandardRecursionZk` — :406-407, config selection; emits no gate.
* `allocateProofAndVerifyPinnedCyclic` — :409, the three effects of
  `add_proof_target_and_verify_cyclic`: constant verifier data, the cyclic
  self-VD connect and the recursive verification, i.e. exactly
  `RecursiveVerifierContract.circuitAccepts`.
* `decodeBalanceTargetPis` — :410-414, pure re-slicing of the verified proof's
  public-input targets into `balance_pis`; no gate, so the op is `True` and the
  aliasing is carried by `Assignment.balanceProofWire.statement`.
* `allocatePrivateUnchecked` — :416, `PrivateStateTarget::new`
  (src/common/private_state.rs:141-152) allocates four raw Poseidon roots, a raw
  nonce and a raw salt with NO range check, so this op constrains nothing.
* `computePrivatePoseidon` — :417, `hash_inputs` over the 21-element `to_vec`.
* `connectPrivateCommitment` — :418.
* `allocateExtendedChecked` — :420, `ExtendedPublicStateTarget::new(_, true)`
  (src/circuits/validity/block_hash_chain/ext_public_state.rs:154-166)
  range-checks the block number, both timestamp limbs, the deposit count and all
  four Bytes32 chains; the three inner Poseidon roots stay unconstrained.
* `connectInnerPublicState` — :421-423.
* `allocateCount` :425 (raw), `rangeCount32` :426.
* `allocateRegistry` :428 (raw), `rangeRegistry32` :429.
* `allocateCheckedU256` — :432, `U256Target::new(_, true)` range-checks all
  eight limbs.
* `allocateSafeBoolean` — :433, `add_virtual_bool_target_safe` constrains the
  limb to {0,1}.
* `allocatePath` — :434-435, `AssetMerkleProofTarget::new` allocates the 32
  sibling hashes; every gate it takes part in is emitted later by
  `conditional_verify`/`get_root`, so the allocation itself constrains nothing.
* `constantZero` :437 — the `zero` constant, which is also the seed of the
  activity accumulator at :444 and the right-hand side of every
  `connect(_, zero)` below. `constantOne` :438.
* `subtractActivityFromOne` :440, `multiplyNextActivity` :441,
  `connectNoRiseZero` :442.
* `addActivityToSum` :445-447, `connectSumToCount` :448, `assertFirstActive`
  :449.
* `notActivity` :452, `multiplyInactiveRegistry` :453,
  `connectInactiveRegistryZero` :454, `multiplyInactiveAmount` :455-456,
  `connectInactiveAmountZero` :457.
* `equalRegistry` :462, `andEqualWithLaterActive` :463, `connectDuplicateZero`
  :464.
* `constantZeroLeaf` :471, `constantEmptyRoot` :472-473.
* `conditionalVerifyZeroPath` — :475-481, `SparseMerkleProofTarget::
  conditional_verify` asserts the opened root equals the running root ONLY when
  the activity bit is one.
* `computeInsertedRoot` :482-486, `selectUpdatedRoot` :487-492,
  `connectFinalAssetRoot` :494.
* `constantTokenFundsDomain` :496, `flattenAmountLimbs` :497-500,
  `concatenateDigestPreimage` :501-507, `computeKeccakTokenFunds` :508-509,
  `computeExtendedPoseidonBytes` :510, `assembleComputedPublicInputs` :511-517.
* `registerPublicInputs` — :518, `register_public_inputs(to_vec())` at the
  exact `CLOSE_ASSET_BACKING_PUBLIC_INPUTS_LEN` width asserted at :163.
* `buildCircuit` — :520, emits no constraint. -/
def BuildOp.holds {Proof Path : Type} {e : Environment Proof Path}
    (op : BuildOp) (a : Assignment e) : Prop :=
  match op with
  | .assertBalancePiShape =>
      a.balanceProofWire.publicInputCount = e.recursive.expectedBalancePiCount
  | .startStandardRecursionZk => True
  | .allocateProofAndVerifyPinnedCyclic => e.recursive.circuitAccepts a.balanceProofWire
  | .decodeBalanceTargetPis => True
  | .allocatePrivateUnchecked => True
  | .computePrivatePoseidon =>
      e.hash.privateCommitment a.privateStateWire.words = a.openedPrivateCommitmentWire
  | .connectPrivateCommitment =>
      a.openedPrivateCommitmentWire = a.balanceProofWire.statement.privateCommitment
  | .allocateExtendedChecked => a.extendedStateWire.Checked
  | .connectInnerPublicState =>
      a.balanceProofWire.statement.publicState = a.extendedStateWire.inner
  | .allocateCount => True
  | .rangeCount32 => a.tokenCountWire < wordBase
  | .allocateRegistry _ => True
  | .rangeRegistry32 row => a.registryWire row < wordBase
  | .allocateCheckedU256 row => (a.amountWire row).Checked
  | .allocateSafeBoolean row => a.activityWire row = 0 ∨ a.activityWire row = 1
  | .allocatePath _ _ => True
  | .constantZero => a.zeroWire = 0 ∧ a.activitySumWire 0 = a.zeroWire
  | .constantOne => a.oneWire = 1
  | .subtractActivityFromOne row =>
      a.oneMinusActivityWire row = a.oneWire - a.activityWire row
  | .multiplyNextActivity row =>
      a.riseProductWire row = a.activityWire (row + 1) * a.oneMinusActivityWire row
  | .connectNoRiseZero row => a.riseProductWire row = a.zeroWire
  | .addActivityToSum row =>
      a.activitySumWire (row + 1) = a.activitySumWire row + a.activityWire row
  | .connectSumToCount => a.activitySumWire maxTokens = a.tokenCountWire
  | .assertFirstActive => a.activityWire 0 = 1
  | .notActivity row => a.inactiveWire row = 1 - a.activityWire row
  | .multiplyInactiveRegistry row =>
      a.dirtyRegistryWire row = a.inactiveWire row * a.registryWire row
  | .connectInactiveRegistryZero row => a.dirtyRegistryWire row = a.zeroWire
  | .multiplyInactiveAmount row limb =>
      a.dirtyAmountWire row limb = a.inactiveWire row * (a.amountWire row).words.getD limb 0
  | .connectInactiveAmountZero row limb => a.dirtyAmountWire row limb = a.zeroWire
  | .equalRegistry earlier later =>
      a.registryEqualWire earlier later =
        (if a.registryWire earlier = a.registryWire later then 1 else 0)
  | .andEqualWithLaterActive earlier later =>
      a.duplicateActiveWire earlier later =
        a.registryEqualWire earlier later * a.activityWire later
  | .connectDuplicateZero earlier later => a.duplicateActiveWire earlier later = a.zeroWire
  | .constantZeroLeaf => a.zeroLeafWire = Words8.zero
  | .constantEmptyRoot => a.rootWire 0 = e.merkle.emptyRoot
  | .conditionalVerifyZeroPath row =>
      a.activityWire row = 1 →
        e.merkle.pathRoot (a.pathWire row) a.zeroLeafWire (a.registryWire row) = a.rootWire row
  | .computeInsertedRoot row =>
      a.insertedRootWire row =
        e.merkle.pathRoot (a.pathWire row) (a.amountWire row) (a.registryWire row)
  | .selectUpdatedRoot row =>
      a.rootWire (row + 1) =
        (if a.activityWire row = 1 then a.insertedRootWire row else a.rootWire row)
  | .connectFinalAssetRoot => a.rootWire maxTokens = a.privateStateWire.assetTreeRoot
  | .constantTokenFundsDomain => a.tokenFundsDomainWire = tokenFundsDomain
  | .flattenAmountLimbs => a.amountLimbsWire = amountWords (assignedRows a)
  | .concatenateDigestPreimage =>
      a.digestPreimageWire =
        [a.tokenFundsDomainWire] ++ registryWords (assignedRows a) ++ [a.tokenCountWire] ++
          a.amountLimbsWire
  | .computeKeccakTokenFunds =>
      a.tokenFundsDigestWire = e.hash.tokenFundsHash a.digestPreimageWire
  | .computeExtendedPoseidonBytes =>
      a.extendedCommitmentWire = e.hash.extendedCommitment a.extendedStateWire.words
  | .assembleComputedPublicInputs =>
      a.publicWire =
        { channelId := a.balanceProofWire.statement.channelId
          settledTxChain := a.balanceProofWire.statement.settledTxChain
          tokenFundsDigest := a.tokenFundsDigestWire
          extendedStateCommitment := a.extendedCommitmentWire
          anchorBlockNumber := a.extendedStateWire.inner.blockNumber }
  | .registerPublicInputs count => a.publicWire.words.length = count
  | .buildCircuit => True

def ProgramSatisfied {Proof Path : Type} {e : Environment Proof Path}
    (prog : List BuildOp) (a : Assignment e) : Prop := ∀ op ∈ prog, op.holds a

theorem satisfied_append {Proof Path : Type} {e : Environment Proof Path}
    {l r : List BuildOp} {a : Assignment e} (h : ProgramSatisfied (l ++ r) a) :
    ProgramSatisfied l a ∧ ProgramSatisfied r a :=
  ⟨fun op hm => h op (List.mem_append.mpr (Or.inl hm)),
   fun op hm => h op (List.mem_append.mpr (Or.inr hm))⟩

theorem satisfied_append_of {Proof Path : Type} {e : Environment Proof Path}
    {l r : List BuildOp} {a : Assignment e}
    (hl : ProgramSatisfied l a) (hr : ProgramSatisfied r a) : ProgramSatisfied (l ++ r) a := by
  intro op hm
  rcases List.mem_append.mp hm with h | h
  · exact hl op h
  · exact hr op h

theorem satisfied_nil {Proof Path : Type} {e : Environment Proof Path}
    {a : Assignment e} : ProgramSatisfied [] a := by
  intro op hop
  exact absurd hop (List.not_mem_nil op)

theorem satisfied_cons_of {Proof Path : Type} {e : Environment Proof Path}
    {op : BuildOp} {rest : List BuildOp} {a : Assignment e}
    (hhead : op.holds a) (htail : ProgramSatisfied rest a) : ProgramSatisfied (op :: rest) a := by
  intro o ho
  rcases List.mem_cons.mp ho with rfl | ho
  · exact hhead
  · exact htail o ho

theorem satisfied_map_range {Proof Path : Type} {e : Environment Proof Path}
    {g : Nat → BuildOp} {n : Nat} {a : Assignment e}
    (h : ProgramSatisfied ((List.range n).map g) a) : ∀ i, i < n → (g i).holds a :=
  fun i hi => h (g i) (List.mem_map.mpr ⟨i, (mem_range_iff_lt _ _).mpr hi, rfl⟩)

theorem satisfied_map_range_of {Proof Path : Type} {e : Environment Proof Path}
    {g : Nat → BuildOp} {n : Nat} {a : Assignment e}
    (h : ∀ i, i < n → (g i).holds a) : ProgramSatisfied ((List.range n).map g) a := by
  intro op hm
  obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hm
  exact h i ((mem_range_iff_lt _ _).mp hi)

theorem satisfied_bind_range {Proof Path : Type} {e : Environment Proof Path}
    {g : Nat → List BuildOp} {n : Nat} {a : Assignment e}
    (h : ProgramSatisfied ((List.range n).bind g) a) :
    ∀ i, i < n → ProgramSatisfied (g i) a := by
  intro i hi op hop
  exact h op (List.mem_bind.mpr ⟨i, (mem_range_iff_lt _ _).mpr hi, hop⟩)

theorem satisfied_bind_range_of {Proof Path : Type} {e : Environment Proof Path}
    {g : Nat → List BuildOp} {n : Nat} {a : Assignment e}
    (h : ∀ i, i < n → ProgramSatisfied (g i) a) :
    ProgramSatisfied ((List.range n).bind g) a := by
  intro op hop
  obtain ⟨i, hi, hop⟩ := List.mem_bind.mp hop
  exact h i ((mem_range_iff_lt _ _).mp hi) op hop

theorem satisfied_ordered_pairs {Proof Path : Type} {e : Environment Proof Path}
    {g : Nat → Nat → List BuildOp} {n : Nat} {a : Assignment e}
    (h : ProgramSatisfied
      ((List.range n).bind (fun i => ((List.range n).drop (i + 1)).bind (g i))) a) :
    ∀ i j, i < j → j < n → ProgramSatisfied (g i j) a := by
  intro i j hij hj op hop
  refine h op (List.mem_bind.mpr ⟨i, (mem_range_iff_lt _ _).mpr (Nat.lt_trans hij hj), ?_⟩)
  exact List.mem_bind.mpr ⟨j, (mem_drop_range_iff n (i + 1) j).mpr ⟨hij, hj⟩, hop⟩

theorem satisfied_ordered_pairs_of {Proof Path : Type} {e : Environment Proof Path}
    {g : Nat → Nat → List BuildOp} {n : Nat} {a : Assignment e}
    (h : ∀ i j, i < j → j < n → ProgramSatisfied (g i j) a) :
    ProgramSatisfied ((List.range n).bind (fun i => ((List.range n).drop (i + 1)).bind (g i))) a := by
  intro op hop
  obtain ⟨i, _, hop⟩ := List.mem_bind.mp hop
  obtain ⟨j, hj, hop⟩ := List.mem_bind.mp hop
  obtain ⟨hij, hjn⟩ := (mem_drop_range_iff _ _ _).mp hj
  exact h i j (by omega) hjn op hop

theorem activity_assigned_rows {Proof Path : Type} {e : Environment Proof Path}
    (a : Assignment e) :
    activity (assignedRows a) = indexedWires (fun i => a.activityWire i == 1) 0 maxTokens := by
  show (indexedWires (rowWire a) 0 maxTokens).map Row.active = _
  rw [map_indexed_wires]
  rfl

theorem indexed_range_gates {Proof Path : Type} {e : Environment Proof Path}
    (a : Assignment e) (n : Nat) : ∀ s,
    (∀ i, i < n → a.registryWire (s + i) < wordBase) →
    (∀ i, i < n → (a.amountWire (s + i)).Checked) →
    RangeGates (indexedWires (rowWire a) s n) := by
  intro s hr ha r hmem
  obtain ⟨i, hi, rfl⟩ := mem_indexed_wires (rowWire a) n s r hmem
  exact ⟨hr i hi, ha i hi⟩

theorem indexed_no_rise (w : Nat → Nat) (n : Nat) : ∀ (s : Nat) (previous : Bool),
    (∀ i, i < n → w (s + i) = 0 ∨ w (s + i) = 1) →
    (∀ i, i + 1 < n → w (s + i + 1) * (1 - w (s + i)) = 0) →
    (0 < n → bit (w s == 1) * (1 - bit previous) = 0) →
    NoRise previous (indexedWires (fun i => w i == 1) s n) := by
  induction n with
  | zero => intro s previous _ _ _; trivial
  | succ n ih =>
      intro s previous hbool hmono hhead
      refine ⟨hhead (Nat.succ_pos n), ?_⟩
      refine ih (s + 1) (w s == 1) ?_ ?_ ?_
      · intro i hi
        have hb := hbool (i + 1) (by omega)
        rwa [show s + (i + 1) = s + 1 + i from by omega] at hb
      · intro i hi
        have hm := hmono (i + 1) (by omega)
        rwa [show s + (i + 1) + 1 = s + 1 + i + 1 from by omega,
          show s + (i + 1) = s + 1 + i from by omega] at hm
      · intro hn
        have hb0 : w s = 0 ∨ w s = 1 := by simpa using hbool 0 (by omega)
        have hb1 : w (s + 1) = 0 ∨ w (s + 1) = 1 := by simpa using hbool 1 (by omega)
        have hm := hmono 0 (by omega)
        rw [bit_of_boolean_wire (w (s + 1)) hb1, bit_of_boolean_wire (w s) hb0]
        simpa using hm

theorem indexed_active_count (w : Nat → Nat) (n : Nat) : ∀ s,
    (∀ i, i < n → w (s + i) = 0 ∨ w (s + i) = 1) →
    activeCount (indexedWires (fun i => w i == 1) s n) = sumWires w s n := by
  induction n with
  | zero => intro s _; rfl
  | succ n ih =>
      intro s hbool
      have hb0 : w s = 0 ∨ w s = 1 := by simpa using hbool 0 (by omega)
      have htail : ∀ i, i < n → w (s + 1 + i) = 0 ∨ w (s + 1 + i) = 1 := by
        intro i hi
        have hb := hbool (i + 1) (by omega)
        rwa [show s + (i + 1) = s + 1 + i from by omega] at hb
      show bit (w s == 1) + activeCount (indexedWires (fun i => w i == 1) (s + 1) n) = _
      rw [bit_of_boolean_wire (w s) hb0, ih (s + 1) htail]
      rfl

theorem accumulator_is_prefix_sum {Proof Path : Type} {e : Environment Proof Path}
    (a : Assignment e) (n : Nat)
    (hstep : ∀ i, i < n → a.activitySumWire (i + 1) = a.activitySumWire i + a.activityWire i) :
    a.activitySumWire n = a.activitySumWire 0 + sumWires a.activityWire 0 n := by
  induction n with
  | zero => simp [sumWires]
  | succ n ih =>
      have hprev : a.activitySumWire n = a.activitySumWire 0 + sumWires a.activityWire 0 n :=
        ih (fun i hi => hstep i (by omega))
      rw [hstep n (by omega), hprev, sum_wires_snoc a.activityWire n 0, Nat.zero_add,
        Nat.add_assoc]

theorem indexed_padding_gates {Proof Path : Type} {e : Environment Proof Path}
    (a : Assignment e) (n : Nat) : ∀ s,
    (∀ i, i < n → a.activityWire (s + i) = 0 ∨ a.activityWire (s + i) = 1) →
    (∀ i, i < n → a.inactiveWire (s + i) = 1 - a.activityWire (s + i)) →
    (∀ i, i < n → a.inactiveWire (s + i) * a.registryWire (s + i) = 0) →
    (∀ i j, i < n → j < 8 →
      a.inactiveWire (s + i) * (a.amountWire (s + i)).words.getD j 0 = 0) →
    ∀ r ∈ indexedWires (rowWire a) s n, PaddingGates r := by
  intro s hbool hnot hreg hamt r hmem
  obtain ⟨i, hi, rfl⟩ := mem_indexed_wires (rowWire a) n s r hmem
  have hb : bit (!(a.activityWire (s + i) == 1)) = a.inactiveWire (s + i) := by
    rw [not_bit_of_boolean_wire _ (hbool i hi), hnot i hi]
  refine ⟨?_, ?_⟩
  · show bit (!(a.activityWire (s + i) == 1)) * a.registryWire (s + i) = 0
    rw [hb]
    exact hreg i hi
  · intro limb hlimb
    show bit (!(a.activityWire (s + i) == 1)) * limb = 0
    rw [hb]
    obtain ⟨j, hj, rfl⟩ := words8_mem_is_a_limb (a.amountWire (s + i)) limb hlimb
    exact hamt i j hi hj

theorem indexed_unique_gates {Proof Path : Type} {e : Environment Proof Path}
    (a : Assignment e) (n : Nat) : ∀ s,
    (∀ i j, i < j → j < n →
      (if a.registryWire (s + i) = a.registryWire (s + j) then 1 else 0) *
        a.activityWire (s + j) = 0) →
    UniqueGates (indexedWires (rowWire a) s n) := by
  induction n with
  | zero => intro s _; trivial
  | succ n ih =>
      intro s hpair
      refine ⟨?_, ?_⟩
      · intro t hmem hact
        obtain ⟨k, hk, rfl⟩ := mem_indexed_wires (rowWire a) n (s + 1) t hmem
        have hact1 : a.activityWire (s + 1 + k) = 1 := by simpa [rowWire] using hact
        have hp := hpair 0 (k + 1) (by omega) (by omega)
        rw [show s + (k + 1) = s + 1 + k from by omega, Nat.add_zero, hact1, Nat.mul_one] at hp
        intro heq
        have heq' : a.registryWire s = a.registryWire (s + 1 + k) := heq
        rw [if_pos heq'] at hp
        exact absurd hp (by omega)
      · refine ih (s + 1) ?_
        intro i j hij hj
        have hp := hpair (i + 1) (j + 1) (by omega) (by omega)
        rwa [show s + (i + 1) = s + 1 + i from by omega,
          show s + (j + 1) = s + 1 + j from by omega] at hp

theorem indexed_path_gates {Proof Path : Type} (e : Environment Proof Path)
    (a : Assignment e) (n : Nat) : ∀ s,
    (∀ i, i < n → a.activityWire (s + i) = 1 →
      e.merkle.pathRoot (a.pathWire (s + i)) Words8.zero (a.registryWire (s + i)) =
        a.rootWire (s + i)) →
    (∀ i, i < n → a.rootWire (s + i + 1) =
      (if a.activityWire (s + i) = 1
        then e.merkle.pathRoot (a.pathWire (s + i)) (a.amountWire (s + i))
          (a.registryWire (s + i))
        else a.rootWire (s + i))) →
    PathGates e.merkle (indexedWires (rowWire a) s n) (a.rootWire s) := by
  induction n with
  | zero => intro s _ _; trivial
  | succ n ih =>
      intro s hcond hstep
      have hnext : (if a.activityWire s = 1
          then e.merkle.pathRoot (a.pathWire s) (a.amountWire s) (a.registryWire s)
          else a.rootWire s) = a.rootWire (s + 1) := by
        have hs := hstep 0 (by omega)
        rw [Nat.add_zero] at hs
        exact hs.symm
      refine ⟨?_, ?_⟩
      · intro hact
        have h1 : a.activityWire s = 1 := (row_wire_active_iff a s).mp hact
        have hc := hcond 0 (by omega)
        rw [Nat.add_zero] at hc
        exact hc h1
      · show PathGates e.merkle (indexedWires (rowWire a) (s + 1) n)
          (if (rowWire a s).active = true
            then e.merkle.pathRoot (a.pathWire s) (a.amountWire s) (a.registryWire s)
            else a.rootWire s)
        rw [row_wire_if_active a s, hnext]
        refine ih (s + 1) ?_ ?_
        · intro i hi
          have hc := hcond (i + 1) (by omega)
          rwa [show s + (i + 1) = s + 1 + i from by omega] at hc
        · intro i hi
          have hs := hstep (i + 1) (by omega)
          rwa [show s + (i + 1) = s + 1 + i from by omega] at hs

theorem indexed_path_fold {Proof Path : Type} (e : Environment Proof Path)
    (a : Assignment e) (n : Nat) : ∀ s,
    (∀ i, i < n → a.rootWire (s + i + 1) =
      (if a.activityWire (s + i) = 1
        then e.merkle.pathRoot (a.pathWire (s + i)) (a.amountWire (s + i))
          (a.registryWire (s + i))
        else a.rootWire (s + i))) →
    pathFold e.merkle (indexedWires (rowWire a) s n) (a.rootWire s) = a.rootWire (s + n) := by
  induction n with
  | zero => intro s _; rfl
  | succ n ih =>
      intro s hstep
      have hnext : (if a.activityWire s = 1
          then e.merkle.pathRoot (a.pathWire s) (a.amountWire s) (a.registryWire s)
          else a.rootWire s) = a.rootWire (s + 1) := by
        have hs := hstep 0 (by omega)
        rw [Nat.add_zero] at hs
        exact hs.symm
      show pathFold e.merkle (indexedWires (rowWire a) (s + 1) n)
          (if (rowWire a s).active = true
            then e.merkle.pathRoot (a.pathWire s) (a.amountWire s) (a.registryWire s)
            else a.rootWire s) = a.rootWire (s + (n + 1))
      rw [row_wire_if_active a s, hnext]
      have htail : ∀ i, i < n → a.rootWire (s + 1 + i + 1) =
          (if a.activityWire (s + 1 + i) = 1
            then e.merkle.pathRoot (a.pathWire (s + 1 + i)) (a.amountWire (s + 1 + i))
              (a.registryWire (s + 1 + i))
            else a.rootWire (s + 1 + i)) := by
        intro i hi
        have hs := hstep (i + 1) (by omega)
        rwa [show s + (i + 1) = s + 1 + i from by omega] at hs
      rw [ih (s + 1) htail, show s + 1 + n = s + (n + 1) from by omega]

/-- THE GATE-LOWERING THEOREM. Every field of `CircuitConstraints` follows from
    the ordered builder program alone: no extra environment hypothesis, no extra
    admission premise, no residual side condition. `Environment` still supplies
    the opaque dependency callbacks, but only as the SAME callbacks the
    corresponding `holds` cases already apply to the wire values. This is a
    statement about the MODEL of the builder program, not about plonky2's
    compiled gate set. -/
theorem program_satisfied_implies_constraints {Proof Path : Type}
    (e : Environment Proof Path) (a : Assignment e)
    (h : ProgramSatisfied constructorProgram a) :
    CircuitConstraints e.merkle e.hash e.recursive (readWitness a) := by
  unfold constructorProgram at h
  obtain ⟨h, hTail⟩ := satisfied_append h
  obtain ⟨h, hPathLoop⟩ := satisfied_append h
  obtain ⟨h, hLeafConst⟩ := satisfied_append h
  obtain ⟨h, hPairs⟩ := satisfied_append h
  obtain ⟨h, hPadding⟩ := satisfied_append h
  obtain ⟨h, hSumTail⟩ := satisfied_append h
  obtain ⟨h, hSumChunk⟩ := satisfied_append h
  obtain ⟨h, hRiseChunk⟩ := satisfied_append h
  obtain ⟨h, hConstChunk⟩ := satisfied_append h
  obtain ⟨h, _hPathAlloc⟩ := satisfied_append h
  obtain ⟨h, hBoolChunk⟩ := satisfied_append h
  obtain ⟨h, hAmountChunk⟩ := satisfied_append h
  obtain ⟨hHead, hRegistryChunk⟩ := satisfied_append h
  -- literal head chunk
  have hVerified : e.recursive.circuitAccepts a.balanceProofWire :=
    hHead .allocateProofAndVerifyPinnedCyclic (by simp)
  have hPoseidon : e.hash.privateCommitment a.privateStateWire.words =
      a.openedPrivateCommitmentWire := hHead .computePrivatePoseidon (by simp)
  have hOpening : a.openedPrivateCommitmentWire =
      a.balanceProofWire.statement.privateCommitment := hHead .connectPrivateCommitment (by simp)
  have hExtended : a.extendedStateWire.Checked := hHead .allocateExtendedChecked (by simp)
  have hInner : a.balanceProofWire.statement.publicState = a.extendedStateWire.inner :=
    hHead .connectInnerPublicState (by simp)
  have hCountRange : a.tokenCountWire < wordBase := hHead .rangeCount32 (by simp)
  -- constants
  have hZero : a.zeroWire = 0 ∧ a.activitySumWire 0 = a.zeroWire :=
    hConstChunk .constantZero (by simp)
  have hOne : a.oneWire = 1 := hConstChunk .constantOne (by simp)
  have hZeroLeaf : a.zeroLeafWire = Words8.zero := hLeafConst .constantZeroLeaf (by simp)
  have hEmptyRoot : a.rootWire 0 = e.merkle.emptyRoot := hLeafConst .constantEmptyRoot (by simp)
  have hSumCount : a.activitySumWire maxTokens = a.tokenCountWire :=
    hSumTail .connectSumToCount (by simp)
  have hFirst : a.activityWire 0 = 1 := hSumTail .assertFirstActive (by simp)
  have hFinalRoot : a.rootWire maxTokens = a.privateStateWire.assetTreeRoot :=
    hTail .connectFinalAssetRoot (by simp)
  -- indexed families
  have hRegistry : ∀ i, i < maxTokens → a.registryWire i < wordBase := by
    intro i hi
    exact (satisfied_bind_range hRegistryChunk i hi) (.rangeRegistry32 i) (by simp)
  have hAmount : ∀ i, i < maxTokens → (a.amountWire i).Checked :=
    satisfied_map_range hAmountChunk
  have hBool : ∀ i, i < maxTokens → a.activityWire i = 0 ∨ a.activityWire i = 1 :=
    satisfied_map_range hBoolChunk
  have hSumStep : ∀ i, i < maxTokens →
      a.activitySumWire (i + 1) = a.activitySumWire i + a.activityWire i :=
    satisfied_map_range hSumChunk
  have hRise : ∀ i, i + 1 < maxTokens →
      a.activityWire (i + 1) * (1 - a.activityWire i) = 0 := by
    intro i hi
    have hc := satisfied_bind_range hRiseChunk i (by simp only [maxTokens] at hi ⊢; omega)
    have h1 : a.oneMinusActivityWire i = a.oneWire - a.activityWire i :=
      hc (.subtractActivityFromOne i) (by simp)
    have h2 : a.riseProductWire i = a.activityWire (i + 1) * a.oneMinusActivityWire i :=
      hc (.multiplyNextActivity i) (by simp)
    have h3 : a.riseProductWire i = a.zeroWire := hc (.connectNoRiseZero i) (by simp)
    have h4 : a.activityWire (i + 1) * a.oneMinusActivityWire i = 0 := by
      rw [← h2, h3, hZero.1]
    rwa [h1, hOne] at h4
  have hNot : ∀ i, i < maxTokens → a.inactiveWire i = 1 - a.activityWire i := by
    intro i hi
    exact (satisfied_append (satisfied_bind_range hPadding i hi)).1 (.notActivity i) (by simp)
  have hDirtyReg : ∀ i, i < maxTokens → a.inactiveWire i * a.registryWire i = 0 := by
    intro i hi
    have hc := (satisfied_append (satisfied_bind_range hPadding i hi)).1
    have h1 : a.dirtyRegistryWire i = a.inactiveWire i * a.registryWire i :=
      hc (.multiplyInactiveRegistry i) (by simp)
    have h2 : a.dirtyRegistryWire i = a.zeroWire := hc (.connectInactiveRegistryZero i) (by simp)
    rw [← h1, h2, hZero.1]
  have hDirtyAmount : ∀ i j, i < maxTokens → j < 8 →
      a.inactiveWire i * (a.amountWire i).words.getD j 0 = 0 := by
    intro i j hi hj
    have hc :=
      satisfied_bind_range (satisfied_append (satisfied_bind_range hPadding i hi)).2 j hj
    have h1 : a.dirtyAmountWire i j = a.inactiveWire i * (a.amountWire i).words.getD j 0 :=
      hc (.multiplyInactiveAmount i j) (by simp)
    have h2 : a.dirtyAmountWire i j = a.zeroWire := hc (.connectInactiveAmountZero i j) (by simp)
    rw [← h1, h2, hZero.1]
  have hPair : ∀ i j, i < j → j < maxTokens →
      (if a.registryWire i = a.registryWire j then 1 else 0) * a.activityWire j = 0 := by
    intro i j hij hj
    have hc := satisfied_ordered_pairs hPairs i j hij hj
    have h1 : a.registryEqualWire i j =
        (if a.registryWire i = a.registryWire j then 1 else 0) :=
      hc (.equalRegistry i j) (by simp)
    have h2 : a.duplicateActiveWire i j = a.registryEqualWire i j * a.activityWire j :=
      hc (.andEqualWithLaterActive i j) (by simp)
    have h3 : a.duplicateActiveWire i j = a.zeroWire := hc (.connectDuplicateZero i j) (by simp)
    rw [← h1, ← h2, h3, hZero.1]
  have hCond : ∀ i, i < maxTokens → a.activityWire i = 1 →
      e.merkle.pathRoot (a.pathWire i) Words8.zero (a.registryWire i) = a.rootWire i := by
    intro i hi
    have hc : a.activityWire i = 1 →
        e.merkle.pathRoot (a.pathWire i) a.zeroLeafWire (a.registryWire i) = a.rootWire i :=
      (satisfied_bind_range hPathLoop i hi) (.conditionalVerifyZeroPath i) (by simp)
    rwa [hZeroLeaf] at hc
  have hStep : ∀ i, i < maxTokens → a.rootWire (i + 1) =
      (if a.activityWire i = 1
        then e.merkle.pathRoot (a.pathWire i) (a.amountWire i) (a.registryWire i)
        else a.rootWire i) := by
    intro i hi
    have hc := satisfied_bind_range hPathLoop i hi
    have hins : a.insertedRootWire i =
        e.merkle.pathRoot (a.pathWire i) (a.amountWire i) (a.registryWire i) :=
      hc (.computeInsertedRoot i) (by simp)
    have hsel : a.rootWire (i + 1) =
        (if a.activityWire i = 1 then a.insertedRootWire i else a.rootWire i) :=
      hc (.selectUpdatedRoot i) (by simp)
    rwa [hins] at hsel
  -- zero-shifted forms
  have hBool0 : ∀ i, i < maxTokens → a.activityWire (0 + i) = 0 ∨ a.activityWire (0 + i) = 1 := by
    intro i hi
    rw [Nat.zero_add]
    exact hBool i hi
  refine
    { verifiedBalance := hVerified
      privateOpening := hPoseidon.trans hOpening
      publicConnection := hInner
      extendedRanges := hExtended
      vector := ?_
      paths := ?_
      rootConnection := ?_ }
  · refine
      { width := indexed_wires_length _ _ _
        countRange := hCountRange
        ranges := ?_
        prefixGates := ?_
        sum := ?_
        first := ?_
        padding := ?_
        distinct := ?_ }
    · refine indexed_range_gates a maxTokens 0 ?_ ?_
      · intro i hi; rw [Nat.zero_add]; exact hRegistry i hi
      · intro i hi; rw [Nat.zero_add]; exact hAmount i hi
    · show NoRise true (activity (assignedRows a))
      rw [activity_assigned_rows]
      refine indexed_no_rise a.activityWire maxTokens 0 true hBool0 ?_ ?_
      · intro i hi
        simp only [Nat.zero_add]
        exact hRise i hi
      · intro _
        simp [bit]
    · show activeCount (activity (assignedRows a)) = a.tokenCountWire
      rw [activity_assigned_rows, indexed_active_count a.activityWire maxTokens 0 hBool0]
      have hacc := accumulator_is_prefix_sum a maxTokens hSumStep
      rw [hSumCount, hZero.2, hZero.1, Nat.zero_add] at hacc
      exact hacc.symm
    · show (activity (assignedRows a)).head? = some true
      rw [activity_assigned_rows, show maxTokens = 9 + 1 from rfl,
        indexed_wires_head (fun i => a.activityWire i == 1) 9 0, hFirst]
      rfl
    · refine indexed_padding_gates a maxTokens 0 hBool0 ?_ ?_ ?_
      · intro i hi; simp only [Nat.zero_add]; exact hNot i hi
      · intro i hi; simp only [Nat.zero_add]; exact hDirtyReg i hi
      · intro i j hi hj; simp only [Nat.zero_add]; exact hDirtyAmount i j hi hj
    · refine indexed_unique_gates a maxTokens 0 ?_
      intro i j hij hj
      simp only [Nat.zero_add]
      exact hPair i j hij hj
  · show PathGates e.merkle (assignedRows a) e.merkle.emptyRoot
    rw [← hEmptyRoot]
    refine indexed_path_gates e a maxTokens 0 ?_ ?_
    · intro i hi; simp only [Nat.zero_add]; exact hCond i hi
    · intro i hi; simp only [Nat.zero_add]; exact hStep i hi
  · show pathFold e.merkle (assignedRows a) e.merkle.emptyRoot =
      a.privateStateWire.assetTreeRoot
    rw [← hEmptyRoot, ← hFinalRoot]
    have hfold : pathFold e.merkle (indexedWires (rowWire a) 0 maxTokens) (a.rootWire 0) =
        a.rootWire (0 + maxTokens) := by
      refine indexed_path_fold e a maxTokens 0 ?_
      intro i hi
      simp only [Nat.zero_add]
      exact hStep i hi
    rw [Nat.zero_add] at hfold
    exact hfold

/-- The 26 registered wires are exactly the model's `computedPublicInputs` of the
    witness the same assignment reads back — again from the program alone. -/
theorem program_satisfied_computes_public_inputs {Proof Path : Type}
    (e : Environment Proof Path) (a : Assignment e)
    (h : ProgramSatisfied constructorProgram a) :
    readPublic a = computedPublicInputs e.hash (readWitness a) := by
  unfold constructorProgram at h
  obtain ⟨_, hTail⟩ := satisfied_append h
  have hDomain : a.tokenFundsDomainWire = tokenFundsDomain :=
    hTail .constantTokenFundsDomain (by simp)
  have hLimbs : a.amountLimbsWire = amountWords (assignedRows a) :=
    hTail .flattenAmountLimbs (by simp)
  have hPre : a.digestPreimageWire =
      [a.tokenFundsDomainWire] ++ registryWords (assignedRows a) ++ [a.tokenCountWire] ++
        a.amountLimbsWire := hTail .concatenateDigestPreimage (by simp)
  have hDigest : a.tokenFundsDigestWire = e.hash.tokenFundsHash a.digestPreimageWire :=
    hTail .computeKeccakTokenFunds (by simp)
  have hCommitment : a.extendedCommitmentWire =
      e.hash.extendedCommitment a.extendedStateWire.words :=
    hTail .computeExtendedPoseidonBytes (by simp)
  have hAssemble := hTail .assembleComputedPublicInputs (by simp)
  rw [hDomain, hLimbs] at hPre
  rw [hPre] at hDigest
  show a.publicWire = _
  rw [hAssemble, hDigest, hCommitment]
  rfl

end Zkp.Implementation.CloseAssetBacking
