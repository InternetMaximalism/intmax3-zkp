import Std

/-!
# Private-state layout and initialization

Manual source model of src/common/private_state.rs (all production methods).
The source's hash and tree calls remain explicit parameters. No collision
resistance, compiler refinement, field canonicality or tree soundness is
obtained merely by naming those parameters. In particular the target nonce
allocation is NOT a 32-bit range check; that bound belongs to native inputs.
Salt is the four-element Poseidon wrapper from src/common/salt.rs.
-/

namespace Zkp.Implementation.PrivateState

structure Hash4 where
  a : Nat
  b : Nat
  c : Nat
  d : Nat
  deriving DecidableEq, Repr

def hashWords (h : Hash4) : List Nat := [h.a, h.b, h.c, h.d]
def zeroHash : Hash4 := ⟨0, 0, 0, 0⟩

structure State where
  assetRoot : Hash4
  nullifierRoot : Hash4
  sentTxRoot : Hash4
  prevCommitment : Hash4
  nonce : Nat
  salt : Hash4
  deriving DecidableEq, Repr

def words (s : State) : List Nat :=
  hashWords s.assetRoot ++ hashWords s.nullifierRoot ++ hashWords s.sentTxRoot ++
  hashWords s.prevCommitment ++ [s.nonce] ++ hashWords s.salt

/-- Native nonce is u32, hash/salt components are u64. This is NOT a
Goldilocks-canonicality check and is not built into raw target State. -/
def NativeRepresentable (s : State) : Prop :=
  s.nonce < 2 ^ 32 ∧ ∀ n ∈ words s, n < 2 ^ 64

/-- `PrivateState::to_u64_vec` (source lines 104-114), transcribed on its own so
the agreement theorem below compares two separate transcriptions rather than
one definition with itself. -/
def nativeWords (s : State) : List Nat :=
  hashWords s.assetRoot ++ hashWords s.nullifierRoot ++ hashWords s.sentTxRoot ++
  hashWords s.prevCommitment ++ [s.nonce] ++ hashWords s.salt
/-- `PrivateStateTarget::to_vec` (source lines 122-132), transcribed separately. -/
def targetWords (s : State) : List Nat :=
  hashWords s.assetRoot ++ hashWords s.nullifierRoot ++ hashWords s.sentTxRoot ++
  hashWords s.prevCommitment ++ [s.nonce] ++ hashWords s.salt

def commitment (hash : List Nat → Hash4) (s : State) : Hash4 := hash (words s)

theorem private_state_has_21_field_elements (s : State) : (words s).length = 21 := by
  simp [words, hashWords]

theorem native_target_layout_agrees (s : State) : nativeWords s = targetWords s := rfl

theorem native_words_are_commitment_preimage (s : State) : nativeWords s = words s := rfl

theorem nonce_at_offset_16 (s : State) : (words s)[16]? = some s.nonce := rfl

theorem salt_at_offset_17 (s : State) : (words s).drop 17 = hashWords s.salt := rfl

theorem layout_injective {a b : State} (h : words a = words b) : a = b := by
  cases a with
  | mk aa an ast ac av az =>
    cases b with
    | mk ba bn bt bc bv bz =>
      cases aa; cases an; cases ast; cases ac; cases az
      cases ba; cases bn; cases bt; cases bc; cases bz
      simp only [words, hashWords, List.cons_append, List.nil_append,
        List.cons.injEq] at h
      rcases h with ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
        rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, _⟩
      rfl

/-- Binding only for the two actual compared preimages, not a global hash axiom. -/
theorem commitment_binds_this_pair (hash : List Nat → Hash4) (a b : State)
    (binding : hash (words a) = hash (words b) → words a = words b)
    (equal : commitment hash a = commitment hash b) : a = b :=
  layout_injective (binding equal)

structure TreeEnvironment (Asset Nullifiers Sent : Type) where
  emptyAsset : Asset
  emptyNullifiers : Nullifiers
  emptySent : Sent
  assetRoot : Asset → Hash4
  nullifierRoot : Nullifiers → Hash4
  sentRoot : Sent → Hash4

structure FullState (Asset Nullifiers Sent : Type) where
  assetTree : Asset
  nullifierTree : Nullifiers
  sentTree : Sent
  prevCommitment : Hash4
  nonce : Nat
  salt : Hash4

def fullNew (e : TreeEnvironment A N T) (salt : Hash4) : FullState A N T :=
  ⟨e.emptyAsset, e.emptyNullifiers, e.emptySent, zeroHash, 0, salt⟩

def toPrivate (e : TreeEnvironment A N T) (s : FullState A N T) : State :=
  ⟨e.assetRoot s.assetTree, e.nullifierRoot s.nullifierTree, e.sentRoot s.sentTree,
    s.prevCommitment, s.nonce, s.salt⟩

def newState (e : TreeEnvironment A N T) (salt : Hash4) : State :=
  ⟨e.assetRoot e.emptyAsset, e.nullifierRoot e.emptyNullifiers,
    e.sentRoot e.emptySent, zeroHash, 0, salt⟩

/-- Source `FullPrivateState::new` uses `AssetTree::init()` (line 57) while
`PrivateState::new` uses `AssetTree::new(ASSET_TREE_HEIGHT)` (line 90). Both are
modeled by the single `emptyAsset` handle, so this projection ASSUMES those two
constructors yield the same empty tree; that agreement is not proved here. -/
theorem full_new_projects_to_new (e : TreeEnvironment A N T) (salt : Hash4) :
    toPrivate e (fullNew e salt) = newState e salt := rfl

theorem genesis_preserves_salt (e : TreeEnvironment A N T) (salt : Hash4) :
    (newState e salt).salt = salt := rfl

theorem genesis_nonce_zero (e : TreeEnvironment A N T) (salt : Hash4) :
    (newState e salt).nonce = 0 := rfl

theorem genesis_previous_commitment_zero (e : TreeEnvironment A N T) (salt : Hash4) :
    (newState e salt).prevCommitment = zeroHash := rfl

theorem full_projection_uses_actual_roots (e : TreeEnvironment A N T)
    (s : FullState A N T) :
    (toPrivate e s).assetRoot = e.assetRoot s.assetTree ∧
    (toPrivate e s).nullifierRoot = e.nullifierRoot s.nullifierTree ∧
    (toPrivate e s).sentTxRoot = e.sentRoot s.sentTree := ⟨rfl, rfl, rfl⟩

inductive Field where
  | assetRoot | nullifierRoot | sentTxRoot | prevCommitment | nonce | salt
  deriving DecidableEq, Repr

inductive Allocation where
  | hash (field : Field)
  | virtualNonce
  deriving DecidableEq, Repr

def allocate : List Allocation := [.hash .assetRoot, .hash .nullifierRoot,
  .hash .sentTxRoot, .hash .prevCommitment, .virtualNonce, .hash .salt]

def witnessWrites (s : State) : List (Field × List Nat) :=
  [(.assetRoot, hashWords s.assetRoot), (.nullifierRoot, hashWords s.nullifierRoot),
   (.sentTxRoot, hashWords s.sentTxRoot), (.prevCommitment, hashWords s.prevCommitment),
   (.nonce, [s.nonce]), (.salt, hashWords s.salt)]

theorem allocation_order_is_source_order : allocate =
    [.hash .assetRoot, .hash .nullifierRoot, .hash .sentTxRoot,
     .hash .prevCommitment, .virtualNonce, .hash .salt] := rfl

theorem witness_order_is_source_order (s : State) :
    (witnessWrites s).map Prod.fst =
      [.assetRoot, .nullifierRoot, .sentTxRoot, .prevCommitment, .nonce, .salt] := rfl

theorem witness_flatten_is_commitment_preimage (s : State) :
    ((witnessWrites s).map Prod.snd).join = words s := by
  simp [witnessWrites, words, hashWords]

theorem target_hash_agrees_when_hash_calls_agree (nativeHash targetHash : List Nat → Hash4)
    (s : State) (sameCall : nativeHash (nativeWords s) = targetHash (targetWords s)) :
    commitment nativeHash s = commitment targetHash s := sameCall

end Zkp.Implementation.PrivateState
