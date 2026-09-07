import Zkp.Implementation.Spend
import Zkp.Implementation.BalancePublicInputs

/-!
# TxSettlement: the settled-transaction chain of the balance circuit

Handwritten SEMANTIC MODEL of src/circuits/balance/common/tx_settlement.rs
(596 lines, all read) together with the `AccountState::verify` /
`AccountStateTarget::new` code it calls in
src/circuits/balance/common/account_state.rs. This is NOT a refinement proof
of the Rust, plonky2 or compiler behaviour; it is a local executable
semantics plus kernel-checked theorems about that semantics.

What the source does (and the model mirrors):
* NATIVE admission `TxSettlement::new` / `new_with_tx_v2` /
  `new_with_optional_tx_v2` (`acceptSettlement`, `acceptLegacy`, `acceptTxV2`):
  spend proof verification, account-state Merkle checks, channel id and
  account-root equality, the legacy / TxV2 / mixed witness match, and the
  parsed spend public-input tx equality, in source order with source error
  precedence.
* ARBITRARY satisfying witnesses of `TxSettlementTarget::new`
  (`CircuitGates`): the same equalities as gate equations, the
  canonicity-enforcing `to_hash_out` conversion (`ToHashOutGates`), the
  two `conditional_verify` inclusion gates driven by the Boolean `use_tx_v2`,
  the four TxV2 conditional assertions and the `connect` of the tx to the
  verified spend statement's tx. The tx-tree index is the channel id wire:
  `TX_TREE_HEIGHT = CHANNEL_ID_BITS = 32`.
* `is_checked` reaches ONLY `channel_id`, `public_state` and `account_state`
  (`allocationPlan`); `tx`, `tx_v2` and the Merkle proofs are never
  range-checked here. `use_tx_v2` is `add_virtual_bool_target_safe`, so it is
  modeled as a `Bool`.
* `set_witness` (`fillWitness`, `witnessWritePlan`): flag := `tx_v2.is_some()`,
  missing TxV2 data replaced by dummy / default values; no checks.

Explicit premises / boundaries (never proved here, named in the line map):
* `Environment`: Poseidon Merkle roots of the four trees and the spend
  verifier are opaque callbacks shared by the native and circuit views
  (gadget lowering = native hash, pinned spend verifier key). Proof soundness
  of the spend proof is NOT assumed: `spendVerifies = true` only says the
  verifier accepted.
* `CanonicalRoots`: Poseidon outputs are canonical Goldilocks elements.
* `ToHashOutGates` is the semantic content of `Bytes32Target::to_hash_out`
  (plonky2 `split_low_high` + the `hi = 2^32-1 ⇒ lo = 0` side constraint);
  the gadget lowering itself is a boundary.
* `SpendNonceWordTyped`: the spend proof's nonce word is a u32; native
  parsing truncates with `as u32` while the circuit connects the raw wire.
* No signature validity, no finality, no hash injectivity, no statement of
  the form "acceptance ⇒ funds are safe".

Real source behaviour the model records honestly: the native `TryFrom<Bytes32>`
round trip through u64 arithmetic never fails for u32 limbs
(`native_try_from_never_rejects_u32_limbs`); non-canonical tx-tree roots are
rejected natively only because a non-canonical u64 never equals a canonical
Merkle root (`CanonicalRoots`), and in-circuit by `ToHashOutGates`.
-/

namespace Zkp.Implementation.TxSettlement

/-! ## Pinned constants -/

def channelIdBits : Nat := 32
def txTreeHeight : Nat := 32
def sendTreeHeight : Nat := 32
def channelTreeHeight : Nat := 32
def wordBase : Nat := 2 ^ 32
def blockLimit : Nat := 2 ^ 63
def goldilocks : Nat := 2 ^ 64 - 2 ^ 32 + 1
def userTransferClass : Nat := 0
def channelActionClass : Nat := 1
def txLength : Nat := 5
def txV2Length : Nat := 10

theorem tx_tree_height_pinned : txTreeHeight = 32 := rfl
theorem tx_tree_height_is_channel_id_bits : txTreeHeight = channelIdBits := rfl
theorem send_and_channel_tree_heights_pinned : sendTreeHeight = 32 ∧ channelTreeHeight = 32 := ⟨rfl, rfl⟩
theorem user_transfer_class_pinned : userTransferClass = 0 ∧ channelActionClass = 1 := ⟨rfl, rfl⟩
theorem word_base_matches_spend_and_balance :
    wordBase = Spend.wordBase ∧ wordBase = BalancePublicInputs.wordBase ∧
    blockLimit = BalancePublicInputs.blockLimit := ⟨rfl, rfl, rfl⟩
theorem goldilocks_pinned : goldilocks = 18446744069414584321 := by decide

/-! ## Value types shared with the modeled callees -/

abbrev Hash4 := Spend.Hash4
abbrev Tx := Spend.Tx
abbrev PublicState := BalancePublicInputs.PublicState

def hashCanonical (h : Hash4) : Prop :=
  h.h0 < goldilocks ∧ h.h1 < goldilocks ∧ h.h2 < goldilocks ∧ h.h3 < goldilocks

/-- `PublicState.account_tree_root` viewed as the same Poseidon hash type as
    `AccountState.account_tree_root` (both are `PoseidonHashOut` in Rust). -/
def rootToHash4 (r : BalancePublicInputs.Root) : Hash4 := ⟨r.a, r.b, r.c, r.d⟩

theorem root_conversion_injective {r s : BalancePublicInputs.Root}
    (h : rootToHash4 r = rootToHash4 s) : r = s := by
  cases r; cases s; simp [rootToHash4] at h; obtain ⟨h0, h1, h2, h3⟩ := h; subst h0 h1 h2 h3; rfl

/-- `Bytes32` as eight u32 limbs; `(a,b)` is the (high, low) pair of element 0. -/
structure Bytes32 where
  a : Nat
  b : Nat
  c : Nat
  d : Nat
  e : Nat
  f : Nat
  g : Nat
  h : Nat
  deriving DecidableEq, Repr

def Bytes32.limbs (x : Bytes32) : List Nat := [x.a, x.b, x.c, x.d, x.e, x.f, x.g, x.h]
def Bytes32.Typed (x : Bytes32) : Prop := ∀ n ∈ x.limbs, n < wordBase

/-- Native `Bytes32::reduce_to_hash_out`: u64 `high << 32 + low` per pair, no field reduction. -/
def Bytes32.reduceNative (x : Bytes32) : Hash4 :=
  ⟨x.a * wordBase + x.b, x.c * wordBase + x.d, x.e * wordBase + x.f, x.g * wordBase + x.h⟩

/-- Target `Bytes32Target::reduce_to_hash_out`: `mul_const_add` is Goldilocks arithmetic. -/
def Bytes32.fieldReduce (x : Bytes32) : Hash4 :=
  ⟨(x.a * wordBase + x.b) % goldilocks, (x.c * wordBase + x.d) % goldilocks,
   (x.e * wordBase + x.f) % goldilocks, (x.g * wordBase + x.h) % goldilocks⟩

/-- `From<PoseidonHashOut> for Bytes32` (native u64 split) and, for canonical
    elements, `Bytes32Target::from_hash_out` (unique `safe_split_lo_and_hi`). -/
def hashToBytes32 (h : Hash4) : Bytes32 :=
  ⟨h.h0 / wordBase, h.h0 % wordBase, h.h1 / wordBase, h.h1 % wordBase,
   h.h2 / wordBase, h.h2 % wordBase, h.h3 / wordBase, h.h3 % wordBase⟩

/-- Native `TryFrom<Bytes32> for PoseidonHashOut`: reduce, split back, compare. -/
def Bytes32.tryToHashOut (x : Bytes32) : Option Hash4 :=
  if hashToBytes32 x.reduceNative = x then some x.reduceNative else none

/-- Semantic content of `Bytes32Target::to_hash_out`: the bare field reduction,
    split back through the unique 32/32 decomposition of a canonical element,
    must `connect` to the original limbs. -/
def ToHashOutGates (x : Bytes32) : Prop := x = hashToBytes32 x.fieldReduce

theorem pair_gate_forces_canonical_pair (a b : Nat)
    (ha : a = (a * wordBase + b) % goldilocks / wordBase)
    (hb : b = (a * wordBase + b) % goldilocks % wordBase) :
    a * wordBase + b < goldilocks ∧ a < wordBase ∧ b < wordBase ∧
      (a * wordBase + b) % goldilocks = a * wordBase + b := by
  simp only [wordBase, goldilocks] at *
  omega

theorem typed_canonical_pair_passes_gate (a b : Nat) (ha : a < wordBase) (hb : b < wordBase)
    (canon : a * wordBase + b < goldilocks) :
    a = (a * wordBase + b) % goldilocks / wordBase ∧
      b = (a * wordBase + b) % goldilocks % wordBase ∧
      (a * wordBase + b) % goldilocks = a * wordBase + b := by
  simp only [wordBase, goldilocks] at *
  omega

/-- The canonical gate forces u32 limbs, a canonical element and agreement
    between the target (field) reduction and the native (u64) reduction. -/
theorem canonical_gate_forces_native_agreement (x : Bytes32) (gate : ToHashOutGates x) :
    x.Typed ∧ hashCanonical x.reduceNative ∧ x.fieldReduce = x.reduceNative := by
  cases x with
  | mk a b c d e f g h =>
    simp only [ToHashOutGates, hashToBytes32, Bytes32.fieldReduce, Bytes32.mk.injEq] at gate
    obtain ⟨ha, hb, hc, hd, he, hf, hg, hh⟩ := gate
    obtain ⟨c0, a0, b0, r0⟩ := pair_gate_forces_canonical_pair a b ha hb
    obtain ⟨c1, a1, b1, r1⟩ := pair_gate_forces_canonical_pair c d hc hd
    obtain ⟨c2, a2, b2, r2⟩ := pair_gate_forces_canonical_pair e f he hf
    obtain ⟨c3, a3, b3, r3⟩ := pair_gate_forces_canonical_pair g h hg hh
    refine ⟨?_, ⟨c0, c1, c2, c3⟩, ?_⟩
    · intro n hn
      simp only [Bytes32.limbs, List.mem_cons, List.mem_nil_iff, or_false] at hn
      rcases hn with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> assumption
    · simp only [Bytes32.fieldReduce, Bytes32.reduceNative, r0, r1, r2, r3]

theorem typed_canonical_bytes_pass_the_canonical_gate (x : Bytes32) (typed : x.Typed)
    (canon : hashCanonical x.reduceNative) :
    ToHashOutGates x ∧ x.fieldReduce = x.reduceNative := by
  cases x with
  | mk a b c d e f g h =>
    have limbs : a < wordBase ∧ b < wordBase ∧ c < wordBase ∧ d < wordBase ∧
        e < wordBase ∧ f < wordBase ∧ g < wordBase ∧ h < wordBase := by
      simp only [Bytes32.Typed, Bytes32.limbs, List.mem_cons, List.mem_nil_iff, or_false,
        forall_eq_or_imp, forall_eq] at typed
      exact typed
    obtain ⟨la, lb, lc, ld, le, lf, lg, lh⟩ := limbs
    obtain ⟨c0, c1, c2, c3⟩ := canon
    obtain ⟨ha, hb, r0⟩ := typed_canonical_pair_passes_gate a b la lb c0
    obtain ⟨hc, hd, r1⟩ := typed_canonical_pair_passes_gate c d lc ld c1
    obtain ⟨he, hf, r2⟩ := typed_canonical_pair_passes_gate e f le lf c2
    obtain ⟨hg, hh, r3⟩ := typed_canonical_pair_passes_gate g h lg lh c3
    constructor
    · simp only [ToHashOutGates, hashToBytes32, Bytes32.fieldReduce, Bytes32.mk.injEq]
      exact ⟨ha, hb, hc, hd, he, hf, hg, hh⟩
    · simp only [Bytes32.fieldReduce, Bytes32.reduceNative, r0, r1, r2, r3]

/-- The Bytes32 encoding of the Goldilocks modulus: limbs `(2^32-1, 1)`. -/
def modulusBytes : Bytes32 := ⟨wordBase - 1, 1, 0, 0, 0, 0, 0, 0⟩
def zeroBytes : Bytes32 := ⟨0, 0, 0, 0, 0, 0, 0, 0⟩

/-- The bare (field) reduction is many-to-one: the SECURITY comment at
    tx_settlement.rs:286-293 is exact. -/
theorem bare_reduction_aliases_noncanonical_bytes :
    modulusBytes ≠ zeroBytes ∧ modulusBytes.fieldReduce = zeroBytes.fieldReduce ∧
      modulusBytes.reduceNative ≠ zeroBytes.reduceNative := by
  refine ⟨by decide, ?_, by decide⟩
  simp only [Bytes32.fieldReduce, modulusBytes, zeroBytes, wordBase, goldilocks]
  decide

theorem canonical_gate_rejects_the_modulus_encoding : ¬ ToHashOutGates modulusBytes := by
  intro gate
  obtain ⟨_, canon, _⟩ := canonical_gate_forces_native_agreement modulusBytes gate
  simp only [hashCanonical, Bytes32.reduceNative, modulusBytes, wordBase, goldilocks] at canon
  omega

/-- The native `TryFrom<Bytes32>` is a u64 round trip; with u32 limbs it never fails,
    so it does NOT by itself reject the non-canonical encoding (contrary to the
    comment's wording). Native rejection of such roots comes from `CanonicalRoots`. -/
theorem native_try_from_never_rejects_u32_limbs (x : Bytes32) (typed : x.Typed) :
    x.tryToHashOut = some x.reduceNative := by
  cases x with
  | mk a b c d e f g h =>
    have limbs : a < wordBase ∧ b < wordBase ∧ c < wordBase ∧ d < wordBase ∧
        e < wordBase ∧ f < wordBase ∧ g < wordBase ∧ h < wordBase := by
      simp only [Bytes32.Typed, Bytes32.limbs, List.mem_cons, List.mem_nil_iff, or_false,
        forall_eq_or_imp, forall_eq] at typed
      exact typed
    have key : hashToBytes32 (Bytes32.reduceNative ⟨a, b, c, d, e, f, g, h⟩) = ⟨a, b, c, d, e, f, g, h⟩ := by
      simp only [hashToBytes32, Bytes32.reduceNative, Bytes32.mk.injEq, wordBase] at *
      omega
    simp [Bytes32.tryToHashOut, key]

theorem modulus_encoding_passes_native_try_from :
    modulusBytes.tryToHashOut = some ⟨goldilocks, 0, 0, 0⟩ := by
  rw [native_try_from_never_rejects_u32_limbs modulusBytes (by decide)]
  simp only [Bytes32.reduceNative, modulusBytes, wordBase, goldilocks]
  decide

theorem noncanonical_native_hash_never_equals_a_canonical_root (r : Hash4)
    (canon : hashCanonical r) : modulusBytes.reduceNative ≠ r := by
  intro h
  subst h
  simp only [hashCanonical, Bytes32.reduceNative, modulusBytes, wordBase, goldilocks] at canon
  omega

/-! ## Leaves, account state and TxV2 -/

structure SendLeaf where
  prev : Nat
  cur : Nat
  txTreeRoot : Bytes32
  deriving DecidableEq, Repr

structure ChannelLeaf where
  index : Nat
  prev : Nat
  sendTreeRoot : Hash4
  memberPubkeysRoot : Hash4
  deriving DecidableEq, Repr

/-- `AccountState` (account_state.rs:34-43). `Path` is an opaque Merkle proof. -/
structure AccountState (Path : Type) where
  channelId : Nat
  accountTreeRoot : Hash4
  sendLeaf : SendLeaf
  sendLeafIndex : Nat
  sendMerkleProof : Path
  channelLeaf : ChannelLeaf
  userMerkleProof : Path

/-- `TxV2` (tx.rs:417-422); `txClass` is the enum discriminant word. -/
structure TxV2 where
  txClass : Nat
  transferTreeRoot : Hash4
  nonce : Nat
  channelActionRoot : Hash4
  deriving DecidableEq, Repr

/-- `TxV2::default()`: `UserTransfer`, zero roots, nonce 0. -/
def defaultTxV2 : TxV2 := ⟨userTransferClass, Spend.zeroHash, 0, Spend.zeroHash⟩

/-- The only TxV2 leaf the settlement accepts for a given legacy `tx`. -/
def userTransferTxV2 (tx : Tx) : TxV2 := ⟨userTransferClass, tx.transferTreeRoot, tx.nonce, Spend.zeroHash⟩

def SendLeaf.Typed (l : SendLeaf) : Prop := l.prev < blockLimit ∧ l.cur < blockLimit ∧ l.txTreeRoot.Typed
def ChannelLeaf.Typed (l : ChannelLeaf) : Prop := l.index < wordBase ∧ l.prev < blockLimit
def AccountState.Typed {Path : Type} (a : AccountState Path) : Prop :=
  a.channelId < wordBase ∧ a.sendLeaf.Typed ∧ a.sendLeafIndex < wordBase ∧ a.channelLeaf.Typed
def PublicStateTyped (p : PublicState) : Prop :=
  p.blockNumber < blockLimit ∧ p.timestampHi < wordBase ∧ p.timestampLo < wordBase

/-- `tx_block_number` / `send_block_number_before_tx` (native and target). -/
def AccountState.txBlockNumber {Path : Type} (a : AccountState Path) : Nat := a.sendLeaf.cur
def AccountState.sendBlockNumberBeforeTx {Path : Type} (a : AccountState Path) : Nat := a.sendLeaf.prev

theorem block_number_accessors_read_the_send_leaf {Path : Type} (a : AccountState Path) :
    a.txBlockNumber = a.sendLeaf.cur ∧ a.sendBlockNumberBeforeTx = a.sendLeaf.prev := ⟨rfl, rfl⟩

/-! ## Dependency environment -/

/-- Opaque Merkle-root computations of the four trees and the spend verifier.
    The same callbacks serve the native path and the circuit view (gadget
    lowering boundary). `spendVerifies` is the verifier's verdict, not soundness. -/
structure Environment (Path Proof : Type) where
  txRoot : Tx → Nat → Path → Hash4
  txV2Root : TxV2 → Nat → Path → Hash4
  sendRoot : SendLeaf → Nat → Path → Hash4
  channelRoot : ChannelLeaf → Nat → Path → Hash4
  spendVerifies : Proof → Bool
  proofPublicInputs : Proof → List Nat

/-- Poseidon outputs are canonical Goldilocks elements (`to_canonical_u64`). -/
def CanonicalRoots {Path Proof : Type} (env : Environment Path Proof) : Prop :=
  (∀ tx index path, hashCanonical (env.txRoot tx index path)) ∧
  (∀ tx index path, hashCanonical (env.txV2Root tx index path))

/-- The spend proof's nonce public-input word is in the u32 domain. -/
def SpendNonceWordTyped {Path Proof : Type} (env : Environment Path Proof) (proof : Proof) : Prop :=
  ∀ p, Spend.parseTargetPublicInputs (env.proofPublicInputs proof) = some p → p.tx.nonce < wordBase

/-! ## Native admission (`TxSettlement::new*`) -/

inductive Fault where
  | invalidSpendProof
  | invalidSendMerkleProof
  | invalidUserMerkleProof
  | invalidUserId
  | invalidPublicState
  | invalidTxV2MerkleProof
  | invalidTxMerkleProof
  | inconsistentWitness
  | spendPublicInputsUnparsable
  | spendTxMismatch
  deriving DecidableEq, Repr

abbrev Result (α : Type) := Except Fault α

def check (condition : Bool) (fault : Fault) : Result Unit :=
  if condition then .ok () else .error fault

/-- The accepted value (`TxSettlement` struct, lines 62-71). -/
structure Settlement (Path Proof : Type) where
  channelId : Nat
  tx : Tx
  publicState : PublicState
  accountState : AccountState Path
  txMerkleProof : Path
  txV2MerkleProof : Option Path
  txV2 : Option TxV2
  spendProof : Proof

/-- `AccountState::verify` (account_state.rs:68-87): send-leaf inclusion under the
    channel leaf's send-tree root, then channel-leaf inclusion at index `channel_id`. -/
def verifyAccountState {Path Proof : Type} (env : Environment Path Proof)
    (a : AccountState Path) : Result Unit := do
  check (env.sendRoot a.sendLeaf a.sendLeafIndex a.sendMerkleProof == a.channelLeaf.sendTreeRoot)
    .invalidSendMerkleProof
  check (env.channelRoot a.channelLeaf a.channelId a.userMerkleProof == a.accountTreeRoot)
    .invalidUserMerkleProof

/-- Lines 155-197: the tx-tree index is `channel_id.as_u64()`. -/
def verifyTxInclusion {Path Proof : Type} (env : Environment Path Proof) (channelId : Nat) (tx : Tx)
    (txTreeRoot : Hash4) (txMerkleProof : Path) (txV2MerkleProof : Option Path)
    (txV2 : Option TxV2) : Result Unit :=
  match txV2, txV2MerkleProof with
  | some v2, some p2 => do
      check (env.txV2Root v2 channelId p2 == txTreeRoot) .invalidTxV2MerkleProof
      check (v2.txClass == userTransferClass) .inconsistentWitness
      check (v2.channelActionRoot == Spend.zeroHash) .inconsistentWitness
      check (v2.transferTreeRoot == tx.transferTreeRoot) .inconsistentWitness
      check (v2.nonce == tx.nonce) .inconsistentWitness
  | none, none =>
      check (env.txRoot tx channelId txMerkleProof == txTreeRoot) .invalidTxMerkleProof
  | some _, none => throw .inconsistentWitness
  | none, some _ => throw .inconsistentWitness

/-- Lines 200-206 / 235-243: `SpendPublicInputs::from_pis_u64` on the proof's public inputs. -/
def parseSpendPis {Path Proof : Type} (env : Environment Path Proof) (proof : Proof) :
    Result Spend.PublicInputs :=
  match Spend.parseNativePublicInputs (env.proofPublicInputs proof) with
  | .error _ => .error .spendPublicInputsUnparsable
  | .ok p => .ok p

/-- `new_with_optional_tx_v2` (lines 125-223), in source order. -/
def acceptSettlement {Path Proof : Type} (env : Environment Path Proof) (channelId : Nat) (tx : Tx)
    (publicState : PublicState) (accountState : AccountState Path) (txMerkleProof : Path)
    (txV2MerkleProof : Option Path) (txV2 : Option TxV2) (spendProof : Proof) :
    Result (Settlement Path Proof) := do
  check (env.spendVerifies spendProof) .invalidSpendProof
  verifyAccountState env accountState
  check (accountState.channelId == channelId) .invalidUserId
  check (accountState.accountTreeRoot == rootToHash4 publicState.accountRoot) .invalidPublicState
  verifyTxInclusion env channelId tx accountState.sendLeaf.txTreeRoot.reduceNative txMerkleProof
    txV2MerkleProof txV2
  let spendPis ← parseSpendPis env spendProof
  check (spendPis.tx == tx) .spendTxMismatch
  pure ⟨channelId, tx, publicState, accountState, txMerkleProof, txV2MerkleProof, txV2, spendProof⟩

/-- `TxSettlement::new` (lines 78-99). -/
def acceptLegacy {Path Proof : Type} (env : Environment Path Proof) (channelId : Nat) (tx : Tx)
    (publicState : PublicState) (accountState : AccountState Path) (txMerkleProof : Path)
    (spendProof : Proof) : Result (Settlement Path Proof) :=
  acceptSettlement env channelId tx publicState accountState txMerkleProof none none spendProof

/-- `TxSettlement::new_with_tx_v2` (lines 101-123). -/
def acceptTxV2 {Path Proof : Type} (env : Environment Path Proof) (channelId : Nat) (tx : Tx)
    (publicState : PublicState) (accountState : AccountState Path) (txMerkleProof : Path)
    (txV2MerkleProof : Path) (txV2 : TxV2) (spendProof : Proof) : Result (Settlement Path Proof) :=
  acceptSettlement env channelId tx publicState accountState txMerkleProof (some txV2MerkleProof)
    (some txV2) spendProof

/-- `TxSettlement::spend_pis` (lines 235-243). -/
def Settlement.spendPis {Path Proof : Type} (env : Environment Path Proof)
    (s : Settlement Path Proof) : Result Spend.PublicInputs :=
  parseSpendPis env s.spendProof

/-! ## Except helpers (local copies of the ChannelStateUpdate pattern) -/

theorem check_ok_iff (condition : Bool) (fault : Fault) :
    check condition fault = .ok () ↔ condition = true := by
  cases condition <;> simp [check]
theorem check_false (fault : Fault) : check false fault = .error fault := rfl
theorem bind_ok_iff {α β : Type} (r : Result α) (f : α → Result β) (value : β) :
    (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]
theorem unit_bind_ok_iff {α : Type} (r : Result Unit) (s : Result α) (value : α) :
    (r >>= fun _ => s) = .ok value ↔ r = .ok () ∧ s = .ok value := by
  cases r with
  | error error => simp [Bind.bind, Except.bind]
  | ok value => cases value; simp [Bind.bind, Except.bind]
theorem exists_unit (p : Unit → Prop) : (∃ x, p x) ↔ p () := by
  constructor
  · rintro ⟨⟨⟩, h⟩; exact h
  · intro h; exact ⟨(), h⟩
theorem pure_ok_iff {α : Type} (a b : α) : (pure a : Result α) = .ok b ↔ a = b := by
  constructor
  · intro h; exact Except.ok.inj h
  · intro h; subst h; rfl
theorem throw_ok_iff_false {α : Type} (fault : Fault) (value : α) :
    ((throw fault : Result α) = .ok value) ↔ False := by
  constructor
  · intro h; cases h
  · intro h; exact h.elim
theorem error_bind {α β : Type} (fault : Fault) (f : α → Result β) :
    ((.error fault : Result α) >>= f) = .error fault := rfl

/-! ## Facts derived from native acceptance -/

theorem verify_account_state_ok_iff {Path Proof : Type} (env : Environment Path Proof)
    (a : AccountState Path) :
    verifyAccountState env a = .ok () ↔
      env.sendRoot a.sendLeaf a.sendLeafIndex a.sendMerkleProof = a.channelLeaf.sendTreeRoot ∧
      env.channelRoot a.channelLeaf a.channelId a.userMerkleProof = a.accountTreeRoot := by
  simp [verifyAccountState, unit_bind_ok_iff, check_ok_iff]

/-- Exactly the two admitted witness layouts (lines 156-197). -/
def TxInclusionFacts {Path Proof : Type} (env : Environment Path Proof) (channelId : Nat) (tx : Tx)
    (txTreeRoot : Hash4) (txMerkleProof : Path) (txV2MerkleProof : Option Path)
    (txV2 : Option TxV2) : Prop :=
  (txV2 = none ∧ txV2MerkleProof = none ∧ env.txRoot tx channelId txMerkleProof = txTreeRoot) ∨
  (∃ p2, txV2 = some (userTransferTxV2 tx) ∧ txV2MerkleProof = some p2 ∧
    env.txV2Root (userTransferTxV2 tx) channelId p2 = txTreeRoot)

theorem verify_tx_inclusion_ok_iff {Path Proof : Type} (env : Environment Path Proof)
    (channelId : Nat) (tx : Tx) (txTreeRoot : Hash4) (txMerkleProof : Path)
    (txV2MerkleProof : Option Path) (txV2 : Option TxV2) :
    verifyTxInclusion env channelId tx txTreeRoot txMerkleProof txV2MerkleProof txV2 = .ok () ↔
      TxInclusionFacts env channelId tx txTreeRoot txMerkleProof txV2MerkleProof txV2 := by
  cases txV2 with
  | none =>
    cases txV2MerkleProof with
    | none => simp [verifyTxInclusion, TxInclusionFacts, check_ok_iff]
    | some p2 => simp [verifyTxInclusion, TxInclusionFacts, throw_ok_iff_false]
  | some v2 =>
    cases txV2MerkleProof with
    | none => simp [verifyTxInclusion, TxInclusionFacts, throw_ok_iff_false]
    | some p2 =>
      cases v2 with
      | mk cls root nonce action =>
        simp only [verifyTxInclusion, TxInclusionFacts, unit_bind_ok_iff, check_ok_iff, beq_iff_eq,
          userTransferTxV2, Option.some.injEq, TxV2.mk.injEq, reduceCtorEq, false_and, false_or]
        constructor
        · rintro ⟨hr, hc, ha, ht, hn⟩
          subst hc ha ht hn
          exact ⟨p2, ⟨rfl, rfl, rfl, rfl⟩, rfl, hr⟩
        · rintro ⟨p2', ⟨hc, ht, hn, ha⟩, hp, hr⟩
          subst hc ht hn ha
          cases hp
          exact ⟨hr, rfl, rfl, rfl, rfl⟩

theorem parse_spend_pis_ok_iff {Path Proof : Type} (env : Environment Path Proof) (proof : Proof)
    (p : Spend.PublicInputs) :
    parseSpendPis env proof = .ok p ↔
      Spend.parseNativePublicInputs (env.proofPublicInputs proof) = .ok p := by
  unfold parseSpendPis
  cases Spend.parseNativePublicInputs (env.proofPublicInputs proof) <;> simp

/-- Everything `new_with_optional_tx_v2` established when it returned `Ok`. -/
structure NativeFacts {Path Proof : Type} (env : Environment Path Proof) (channelId : Nat) (tx : Tx)
    (publicState : PublicState) (accountState : AccountState Path) (txMerkleProof : Path)
    (txV2MerkleProof : Option Path) (txV2 : Option TxV2) (spendProof : Proof)
    (s : Settlement Path Proof) : Prop where
  result : s = ⟨channelId, tx, publicState, accountState, txMerkleProof, txV2MerkleProof, txV2, spendProof⟩
  spendVerified : env.spendVerifies spendProof = true
  sendInclusion : env.sendRoot accountState.sendLeaf accountState.sendLeafIndex
    accountState.sendMerkleProof = accountState.channelLeaf.sendTreeRoot
  channelInclusion : env.channelRoot accountState.channelLeaf accountState.channelId
    accountState.userMerkleProof = accountState.accountTreeRoot
  channelMatch : accountState.channelId = channelId
  rootMatch : accountState.accountTreeRoot = rootToHash4 publicState.accountRoot
  txInclusion : TxInclusionFacts env channelId tx accountState.sendLeaf.txTreeRoot.reduceNative
    txMerkleProof txV2MerkleProof txV2
  spendPis : ∃ p, Spend.parseNativePublicInputs (env.proofPublicInputs spendProof) = .ok p ∧ p.tx = tx

theorem native_acceptance_derives_checks {Path Proof : Type} (env : Environment Path Proof)
    (channelId : Nat) (tx : Tx) (publicState : PublicState) (accountState : AccountState Path)
    (txMerkleProof : Path) (txV2MerkleProof : Option Path) (txV2 : Option TxV2) (spendProof : Proof)
    (s : Settlement Path Proof)
    (accepted : acceptSettlement env channelId tx publicState accountState txMerkleProof
      txV2MerkleProof txV2 spendProof = .ok s) :
    NativeFacts env channelId tx publicState accountState txMerkleProof txV2MerkleProof txV2
      spendProof s := by
  simp only [acceptSettlement, bind_ok_iff, unit_bind_ok_iff, exists_unit, check_ok_iff, pure_ok_iff,
    verify_account_state_ok_iff, verify_tx_inclusion_ok_iff, parse_spend_pis_ok_iff, beq_iff_eq]
    at accepted
  obtain ⟨spendOk, ⟨sendOk, chanOk⟩, idOk, rootOk, inclusion, p, parseOk, txOk, result⟩ := accepted
  exact ⟨result.symm, spendOk, sendOk, chanOk, idOk, rootOk, inclusion, p, parseOk, txOk⟩

theorem accepted_settlement_returns_its_inputs {Path Proof : Type} (env : Environment Path Proof)
    (channelId : Nat) (tx : Tx) (publicState : PublicState) (accountState : AccountState Path)
    (txMerkleProof : Path) (txV2MerkleProof : Option Path) (txV2 : Option TxV2) (spendProof : Proof)
    (s : Settlement Path Proof)
    (accepted : acceptSettlement env channelId tx publicState accountState txMerkleProof
      txV2MerkleProof txV2 spendProof = .ok s) :
    s = ⟨channelId, tx, publicState, accountState, txMerkleProof, txV2MerkleProof, txV2, spendProof⟩ :=
  (native_acceptance_derives_checks env channelId tx publicState accountState txMerkleProof
    txV2MerkleProof txV2 spendProof s accepted).result

/-- The native settled chain: public-state account root → channel leaf at
    `channel_id` → send-tree root → send leaf at `send_leaf_index` → reduced
    tx-tree root → tx (or its pinned TxV2 form) at tx-tree index `channel_id`,
    and the verified spend statement's tx is that tx. -/
theorem native_settled_chain {Path Proof : Type} (env : Environment Path Proof)
    (channelId : Nat) (tx : Tx) (publicState : PublicState) (accountState : AccountState Path)
    (txMerkleProof : Path) (txV2MerkleProof : Option Path) (txV2 : Option TxV2) (spendProof : Proof)
    (s : Settlement Path Proof)
    (accepted : acceptSettlement env channelId tx publicState accountState txMerkleProof
      txV2MerkleProof txV2 spendProof = .ok s) :
    env.channelRoot accountState.channelLeaf channelId accountState.userMerkleProof =
        rootToHash4 publicState.accountRoot ∧
    env.sendRoot accountState.sendLeaf accountState.sendLeafIndex accountState.sendMerkleProof =
        accountState.channelLeaf.sendTreeRoot ∧
    TxInclusionFacts env channelId tx accountState.sendLeaf.txTreeRoot.reduceNative txMerkleProof
        txV2MerkleProof txV2 ∧
    (∃ p, Spend.parseNativePublicInputs (env.proofPublicInputs spendProof) = .ok p ∧ p.tx = tx) := by
  have facts := native_acceptance_derives_checks env channelId tx publicState accountState
    txMerkleProof txV2MerkleProof txV2 spendProof s accepted
  refine ⟨?_, facts.sendInclusion, facts.txInclusion, facts.spendPis⟩
  rw [← facts.channelMatch, facts.channelInclusion, facts.rootMatch]

theorem accepted_tx_v2_is_pinned_by_tx {Path Proof : Type} (env : Environment Path Proof)
    (channelId : Nat) (tx : Tx) (publicState : PublicState) (accountState : AccountState Path)
    (txMerkleProof : Path) (txV2MerkleProof : Option Path) (v2 : TxV2) (spendProof : Proof)
    (s : Settlement Path Proof)
    (accepted : acceptSettlement env channelId tx publicState accountState txMerkleProof
      txV2MerkleProof (some v2) spendProof = .ok s) :
    v2 = userTransferTxV2 tx ∧ v2.txClass = userTransferClass ∧ v2.channelActionRoot = Spend.zeroHash := by
  have facts := native_acceptance_derives_checks env channelId tx publicState accountState
    txMerkleProof txV2MerkleProof (some v2) spendProof s accepted
  rcases facts.txInclusion with ⟨h, _, _⟩ | ⟨_, h, _, _⟩
  · cases h
  · cases h; exact ⟨rfl, rfl, rfl⟩

theorem accepted_spend_pis_matches_tx {Path Proof : Type} (env : Environment Path Proof)
    (channelId : Nat) (tx : Tx) (publicState : PublicState) (accountState : AccountState Path)
    (txMerkleProof : Path) (txV2MerkleProof : Option Path) (txV2 : Option TxV2) (spendProof : Proof)
    (s : Settlement Path Proof)
    (accepted : acceptSettlement env channelId tx publicState accountState txMerkleProof
      txV2MerkleProof txV2 spendProof = .ok s) :
    ∃ p, s.spendPis env = .ok p ∧ p.tx = s.tx := by
  have facts := native_acceptance_derives_checks env channelId tx publicState accountState
    txMerkleProof txV2MerkleProof txV2 spendProof s accepted
  obtain ⟨p, parseOk, txOk⟩ := facts.spendPis
  refine ⟨p, ?_, ?_⟩
  · rw [facts.result]; simpa [Settlement.spendPis, parse_spend_pis_ok_iff] using parseOk
  · rw [facts.result]; exact txOk

/-- Native nonce comparison is on the `as u32`-truncated word: the raw public
    input may carry `tx.nonce + k·2^32` and still be accepted natively. -/
theorem native_spend_tx_match_is_modulo_word_base {Path Proof : Type} (env : Environment Path Proof)
    (channelId : Nat) (tx : Tx) (publicState : PublicState) (accountState : AccountState Path)
    (txMerkleProof : Path) (txV2MerkleProof : Option Path) (txV2 : Option TxV2) (spendProof : Proof)
    (s : Settlement Path Proof)
    (accepted : acceptSettlement env channelId tx publicState accountState txMerkleProof
      txV2MerkleProof txV2 spendProof = .ok s) :
    ∃ p, Spend.parseTargetPublicInputs (env.proofPublicInputs spendProof) = some p ∧
      p.tx.transferTreeRoot = tx.transferTreeRoot ∧ p.tx.nonce % wordBase = tx.nonce := by
  obtain ⟨q, parseOk, txOk⟩ := (native_acceptance_derives_checks env channelId tx publicState
    accountState txMerkleProof txV2MerkleProof txV2 spendProof s accepted).spendPis
  unfold Spend.parseNativePublicInputs at parseOk
  cases h : Spend.parseTargetPublicInputs (env.proofPublicInputs spendProof) with
  | none => rw [h] at parseOk; cases parseOk
  | some p =>
    rw [h] at parseOk
    have hq := Except.ok.inj parseOk
    subst hq
    refine ⟨p, rfl, ?_, ?_⟩
    · rw [← txOk]
    · rw [← txOk]; rfl

/-! ## Error precedence and rejected shapes -/

theorem invalid_spend_proof_is_reported_first {Path Proof : Type} (env : Environment Path Proof)
    (channelId : Nat) (tx : Tx) (publicState : PublicState) (accountState : AccountState Path)
    (txMerkleProof : Path) (txV2MerkleProof : Option Path) (txV2 : Option TxV2) (spendProof : Proof)
    (rejected : env.spendVerifies spendProof = false) :
    acceptSettlement env channelId tx publicState accountState txMerkleProof txV2MerkleProof txV2
      spendProof = .error .invalidSpendProof := by
  simp [acceptSettlement, rejected, check_false, error_bind]

theorem account_state_is_checked_before_channel_id {Path Proof : Type} (env : Environment Path Proof)
    (channelId : Nat) (tx : Tx) (publicState : PublicState) (accountState : AccountState Path)
    (txMerkleProof : Path) (txV2MerkleProof : Option Path) (txV2 : Option TxV2) (spendProof : Proof)
    (verified : env.spendVerifies spendProof = true)
    (badSend : env.sendRoot accountState.sendLeaf accountState.sendLeafIndex
      accountState.sendMerkleProof ≠ accountState.channelLeaf.sendTreeRoot) :
    acceptSettlement env channelId tx publicState accountState txMerkleProof txV2MerkleProof txV2
      spendProof = .error .invalidSendMerkleProof := by
  simp [acceptSettlement, verifyAccountState, verified, badSend, check, check_false, error_bind]

theorem mixed_tx_v2_witness_is_never_accepted {Path Proof : Type} (env : Environment Path Proof)
    (channelId : Nat) (tx : Tx) (publicState : PublicState) (accountState : AccountState Path)
    (txMerkleProof : Path) (txV2MerkleProof : Option Path) (txV2 : Option TxV2) (spendProof : Proof)
    (mixed : txV2.isSome ≠ txV2MerkleProof.isSome) (s : Settlement Path Proof) :
    acceptSettlement env channelId tx publicState accountState txMerkleProof txV2MerkleProof txV2
      spendProof ≠ .ok s := by
  intro accepted
  have facts := native_acceptance_derives_checks env channelId tx publicState accountState
    txMerkleProof txV2MerkleProof txV2 spendProof s accepted
  rcases facts.txInclusion with ⟨h1, h2, _⟩ | ⟨_, h1, h2, _⟩ <;> subst h1 h2 <;> exact mixed rfl

theorem wrapper_entry_points_fix_the_option_shape {Path Proof : Type} (env : Environment Path Proof)
    (channelId : Nat) (tx : Tx) (publicState : PublicState) (accountState : AccountState Path)
    (txMerkleProof : Path) (txV2MerkleProof : Path) (txV2 : TxV2) (spendProof : Proof) :
    acceptLegacy env channelId tx publicState accountState txMerkleProof spendProof =
      acceptSettlement env channelId tx publicState accountState txMerkleProof none none spendProof ∧
    acceptTxV2 env channelId tx publicState accountState txMerkleProof txV2MerkleProof txV2 spendProof =
      acceptSettlement env channelId tx publicState accountState txMerkleProof (some txV2MerkleProof)
        (some txV2) spendProof := ⟨rfl, rfl⟩

/-! ## Circuit view: allocation, arbitrary witness gates -/

/-- The nine allocations of `TxSettlementTarget::new` (lines 271-279) and whether
    each receives the `is_checked` argument. -/
inductive Allocation where
  | channelId | tx | publicState | accountState | txMerkleProof | useTxV2 | txV2MerkleProof | txV2
  | spendProof
  deriving DecidableEq, Repr

def allocationPlan (checked : Bool) : List (Allocation × Bool) :=
  [(.channelId, checked), (.tx, false), (.publicState, checked), (.accountState, checked),
   (.txMerkleProof, false), (.useTxV2, false), (.txV2MerkleProof, false), (.txV2, false),
   (.spendProof, false)]

theorem is_checked_reaches_only_channel_public_and_account :
    ((allocationPlan true).filter (·.2)).map (·.1) = [.channelId, .publicState, .accountState] ∧
    ((allocationPlan false).filter (·.2)) = [] := ⟨rfl, rfl⟩

theorem tx_and_tx_v2_are_never_range_checked (checked : Bool) :
    (.tx, false) ∈ allocationPlan checked ∧ (.txV2, false) ∈ allocationPlan checked := by
  cases checked <;> simp [allocationPlan]

/-- `set_witness` (lines 350-367) writes every allocation once, in allocation order. -/
def witnessWritePlan : List Allocation :=
  [.channelId, .tx, .publicState, .accountState, .txMerkleProof, .useTxV2, .txV2MerkleProof, .txV2,
   .spendProof]

theorem witness_write_covers_every_allocation_in_order (checked : Bool) :
    (allocationPlan checked).map (·.1) = witnessWritePlan := by
  cases checked <;> rfl

/-- One assignment of the circuit's wires. `useTxV2` is `add_virtual_bool_target_safe`. -/
structure Witness (Path Proof : Type) where
  channelId : Nat
  tx : Tx
  publicState : PublicState
  accountState : AccountState Path
  txMerkleProof : Path
  useTxV2 : Bool
  txV2MerkleProof : Path
  txV2 : TxV2
  spendProof : Proof

/-- Range checks performed when `is_checked = true`: channel id (32 bits), public
    state block number (63) and timestamp limbs (32), account-state channel id,
    send-leaf block numbers, tx-tree-root limbs, send-leaf index and channel-leaf
    index/prev. Nothing else. -/
def AllocationChecks {Path Proof : Type} (w : Witness Path Proof) : Prop :=
  w.channelId < wordBase ∧ PublicStateTyped w.publicState ∧ w.accountState.Typed

/-- `AccountStateTarget::new` (account_state.rs:110-135): both inclusion gates are
    unconditional; `split_le` of the indices bounds them below `2^32`. -/
structure AccountStateGates {Path Proof : Type} (env : Environment Path Proof)
    (a : AccountState Path) : Prop where
  sendIndexBits : a.sendLeafIndex < 2 ^ sendTreeHeight
  sendInclusion : env.sendRoot a.sendLeaf a.sendLeafIndex a.sendMerkleProof = a.channelLeaf.sendTreeRoot
  channelIndexBits : a.channelId < 2 ^ channelTreeHeight
  channelInclusion : env.channelRoot a.channelLeaf a.channelId a.userMerkleProof = a.accountTreeRoot

/-- Gate equations of `TxSettlementTarget::new` (lines 271-328) for an ARBITRARY
    witness. The tx-tree index of both `conditional_verify` calls is the channel
    id wire; both Merkle-path gadgets decompose it into `TX_TREE_HEIGHT` bits. -/
structure CircuitGates {Path Proof : Type} (env : Environment Path Proof) (checked : Bool)
    (w : Witness Path Proof) : Prop where
  allocation : checked = true → AllocationChecks w
  spendVerified : env.spendVerifies w.spendProof = true
  accountState : AccountStateGates env w.accountState
  channelConnect : w.accountState.channelId = w.channelId
  rootConnect : w.accountState.accountTreeRoot = rootToHash4 w.publicState.accountRoot
  txTreeRootCanonical : ToHashOutGates w.accountState.sendLeaf.txTreeRoot
  indexBits : w.channelId < 2 ^ txTreeHeight
  legacyInclusion : w.useTxV2 = false →
    env.txRoot w.tx w.channelId w.txMerkleProof = w.accountState.sendLeaf.txTreeRoot.fieldReduce
  v2Inclusion : w.useTxV2 = true →
    env.txV2Root w.txV2 w.channelId w.txV2MerkleProof = w.accountState.sendLeaf.txTreeRoot.fieldReduce
  v2Class : w.useTxV2 = true → w.txV2.txClass = userTransferClass
  v2ZeroAction : w.useTxV2 = true → w.txV2.channelActionRoot = Spend.zeroHash
  v2TransferRoot : w.useTxV2 = true → w.txV2.transferTreeRoot = w.tx.transferTreeRoot
  v2Nonce : w.useTxV2 = true → w.txV2.nonce = w.tx.nonce
  spendTxConnect : ∃ p, Spend.parseTargetPublicInputs (env.proofPublicInputs w.spendProof) = some p ∧
    p.tx = w.tx

/-- The unresolved plonky2 lowering: whatever the builder accepts satisfies the gates. -/
def FieldAndGadgetLowering {Path Proof Raw : Type} (env : Environment Path Proof) (checked : Bool)
    (accepts : Raw → Witness Path Proof → Prop) : Prop :=
  ∀ raw w, accepts raw w → CircuitGates env checked w

/-- When `use_tx_v2` is set, the whole TxV2 leaf is determined by `tx`. -/
theorem tx_v2_wire_is_pinned_by_tx_when_used {Path Proof : Type} {env : Environment Path Proof}
    {checked : Bool} {w : Witness Path Proof} (g : CircuitGates env checked w) (used : w.useTxV2 = true) :
    w.txV2 = userTransferTxV2 w.tx := by
  have c := g.v2Class used
  have a := g.v2ZeroAction used
  have t := g.v2TransferRoot used
  have n := g.v2Nonce used
  cases hv : w.txV2 with
  | mk cls root nonce action =>
    rw [hv] at c a t n
    simp only at c a t n
    subst c a t n
    rfl

/-- The circuit's settled chain for an arbitrary satisfying witness. The tx
    included at tx-tree index `channel_id` is exactly the tx of the verified
    spend statement, under the committed public-state account root. -/
theorem settled_chain_binds_spend_tx_to_the_public_account_root {Path Proof : Type}
    {env : Environment Path Proof} {checked : Bool} {w : Witness Path Proof}
    (g : CircuitGates env checked w) :
    env.channelRoot w.accountState.channelLeaf w.channelId w.accountState.userMerkleProof =
        rootToHash4 w.publicState.accountRoot ∧
    env.sendRoot w.accountState.sendLeaf w.accountState.sendLeafIndex w.accountState.sendMerkleProof =
        w.accountState.channelLeaf.sendTreeRoot ∧
    w.accountState.sendLeaf.txTreeRoot.Typed ∧
    hashCanonical w.accountState.sendLeaf.txTreeRoot.reduceNative ∧
    (if w.useTxV2 then
        env.txV2Root (userTransferTxV2 w.tx) w.channelId w.txV2MerkleProof =
          w.accountState.sendLeaf.txTreeRoot.reduceNative
      else env.txRoot w.tx w.channelId w.txMerkleProof = w.accountState.sendLeaf.txTreeRoot.reduceNative) ∧
    w.channelId < 2 ^ txTreeHeight ∧
    (∃ p, Spend.parseTargetPublicInputs (env.proofPublicInputs w.spendProof) = some p ∧ p.tx = w.tx) := by
  obtain ⟨typed, canon, agree⟩ := canonical_gate_forces_native_agreement _ g.txTreeRootCanonical
  refine ⟨?_, g.accountState.sendInclusion, typed, canon, ?_, g.indexBits, g.spendTxConnect⟩
  · rw [← g.channelConnect, g.accountState.channelInclusion, g.rootConnect]
  · cases used : w.useTxV2 with
    | false => simp only [Bool.false_eq_true, if_false]; rw [← agree]; exact g.legacyInclusion used
    | true =>
      simp only [if_true]
      rw [← agree, ← tx_v2_wire_is_pinned_by_tx_when_used g used]
      exact g.v2Inclusion used

/-- The circuit never uses the many-to-one bare reduction on the prover-supplied root. -/
theorem circuit_tx_tree_root_is_the_canonical_native_value {Path Proof : Type}
    {env : Environment Path Proof} {checked : Bool} {w : Witness Path Proof}
    (g : CircuitGates env checked w) :
    w.accountState.sendLeaf.txTreeRoot.fieldReduce = w.accountState.sendLeaf.txTreeRoot.reduceNative ∧
    w.accountState.sendLeaf.txTreeRoot.tryToHashOut = some w.accountState.sendLeaf.txTreeRoot.reduceNative := by
  obtain ⟨typed, _, agree⟩ := canonical_gate_forces_native_agreement _ g.txTreeRootCanonical
  exact ⟨agree, native_try_from_never_rejects_u32_limbs _ typed⟩

/-- Merkle index decomposition bounds the channel id even when `is_checked = false`. -/
theorem channel_id_is_bounded_without_is_checked {Path Proof : Type} {env : Environment Path Proof}
    {w : Witness Path Proof} (g : CircuitGates env false w) :
    w.channelId < wordBase ∧ w.accountState.sendLeafIndex < wordBase := by
  refine ⟨g.indexBits, ?_⟩
  have h := g.accountState.sendIndexBits
  simpa [sendTreeHeight, wordBase] using h

/-! ## `set_witness` fill and the native → circuit bridge -/

/-- `TxSettlementTarget::set_witness` (lines 343-368): no checks; `use_tx_v2 :=
    tx_v2.is_some()`, missing proof replaced by `TxV2MerkleProof::dummy`, missing
    leaf by `TxV2::default()`. -/
def fillWitness {Path Proof : Type} (dummyPath : Path) (s : Settlement Path Proof) :
    Witness Path Proof :=
  { channelId := s.channelId, tx := s.tx, publicState := s.publicState,
    accountState := s.accountState, txMerkleProof := s.txMerkleProof, useTxV2 := s.txV2.isSome,
    txV2MerkleProof := s.txV2MerkleProof.getD dummyPath, txV2 := s.txV2.getD defaultTxV2,
    spendProof := s.spendProof }

theorem fill_flag_follows_tx_v2_presence_not_the_proof {Path Proof : Type} (dummyPath : Path)
    (s : Settlement Path Proof) :
    (fillWitness dummyPath s).useTxV2 = s.txV2.isSome ∧
    (fillWitness dummyPath s).txV2MerkleProof = s.txV2MerkleProof.getD dummyPath := ⟨rfl, rfl⟩

def NativeTyped {Path : Type} (publicState : PublicState) (accountState : AccountState Path) : Prop :=
  PublicStateTyped publicState ∧ accountState.Typed

/-- A natively accepted settlement, filled by `set_witness`, satisfies every gate
    (with `is_checked = true`) provided the Rust types' ranges hold, Poseidon roots
    are canonical and the spend proof's nonce word is a u32. -/
theorem native_acceptance_fills_a_satisfying_witness {Path Proof : Type} (env : Environment Path Proof)
    (canon : CanonicalRoots env) (dummyPath : Path) (channelId : Nat) (tx : Tx)
    (publicState : PublicState) (accountState : AccountState Path) (txMerkleProof : Path)
    (txV2MerkleProof : Option Path) (txV2 : Option TxV2) (spendProof : Proof)
    (s : Settlement Path Proof)
    (accepted : acceptSettlement env channelId tx publicState accountState txMerkleProof
      txV2MerkleProof txV2 spendProof = .ok s)
    (typed : NativeTyped publicState accountState) (nonceWord : SpendNonceWordTyped env spendProof) :
    CircuitGates env true (fillWitness dummyPath s) := by
  have facts := native_acceptance_derives_checks env channelId tx publicState accountState
    txMerkleProof txV2MerkleProof txV2 spendProof s accepted
  obtain ⟨publicTyped, accountTyped⟩ := typed
  obtain ⟨idRange, sendTyped, indexRange, _⟩ := accountTyped
  obtain ⟨_, _, bytesTyped⟩ := sendTyped
  have rootCanonical : hashCanonical accountState.sendLeaf.txTreeRoot.reduceNative := by
    rcases facts.txInclusion with ⟨_, _, h⟩ | ⟨p2, _, _, h⟩
    · rw [← h]; exact canon.1 _ _ _
    · rw [← h]; exact canon.2 _ _ _
  obtain ⟨gate, agree⟩ := typed_canonical_bytes_pass_the_canonical_gate _ bytesTyped rootCanonical
  have spendTarget : ∃ p, Spend.parseTargetPublicInputs (env.proofPublicInputs spendProof) = some p ∧
      p.tx = tx := by
    obtain ⟨p, parseOk, root, nonce⟩ := native_spend_tx_match_is_modulo_word_base env channelId tx
      publicState accountState txMerkleProof txV2MerkleProof txV2 spendProof s accepted
    refine ⟨p, parseOk, ?_⟩
    have small := nonceWord p parseOk
    rw [Nat.mod_eq_of_lt small] at nonce
    cases hp : p.tx with
    | mk r n => rw [hp] at root nonce; simp only at root nonce; rw [root, nonce]
  rw [facts.result]
  rcases facts.txInclusion with ⟨hv, hp, inclusion⟩ | ⟨p2, hv, hp, inclusion⟩
  · subst hv hp
    exact {
      allocation := fun _ => ⟨facts.channelMatch ▸ idRange, publicTyped, idRange, ⟨‹_›, ‹_›, bytesTyped⟩,
        indexRange, ‹_›⟩
      spendVerified := facts.spendVerified
      accountState := {
        sendIndexBits := by simpa [sendTreeHeight, wordBase] using indexRange
        sendInclusion := facts.sendInclusion
        channelIndexBits := by simpa [channelTreeHeight, wordBase] using idRange
        channelInclusion := facts.channelInclusion }
      channelConnect := facts.channelMatch
      rootConnect := facts.rootMatch
      txTreeRootCanonical := gate
      indexBits := by simpa [txTreeHeight, wordBase] using (facts.channelMatch ▸ idRange)
      legacyInclusion := fun _ => by simpa [fillWitness, agree] using inclusion
      v2Inclusion := fun h => by simp [fillWitness] at h
      v2Class := fun h => by simp [fillWitness] at h
      v2ZeroAction := fun h => by simp [fillWitness] at h
      v2TransferRoot := fun h => by simp [fillWitness] at h
      v2Nonce := fun h => by simp [fillWitness] at h
      spendTxConnect := spendTarget }
  · subst hv hp
    exact {
      allocation := fun _ => ⟨facts.channelMatch ▸ idRange, publicTyped, idRange, ⟨‹_›, ‹_›, bytesTyped⟩,
        indexRange, ‹_›⟩
      spendVerified := facts.spendVerified
      accountState := {
        sendIndexBits := by simpa [sendTreeHeight, wordBase] using indexRange
        sendInclusion := facts.sendInclusion
        channelIndexBits := by simpa [channelTreeHeight, wordBase] using idRange
        channelInclusion := facts.channelInclusion }
      channelConnect := facts.channelMatch
      rootConnect := facts.rootMatch
      txTreeRootCanonical := gate
      indexBits := by simpa [txTreeHeight, wordBase] using (facts.channelMatch ▸ idRange)
      legacyInclusion := fun h => by simp [fillWitness] at h
      v2Inclusion := fun _ => by simpa [fillWitness, agree] using inclusion
      v2Class := fun _ => rfl
      v2ZeroAction := fun _ => rfl
      v2TransferRoot := fun _ => rfl
      v2Nonce := fun _ => rfl
      spendTxConnect := spendTarget }

/-! ## Positive example: a normal legacy settlement -/

def exampleTxTreeRoot : Hash4 := ⟨1, 2, 3, 4⟩
def exampleSendTreeRoot : Hash4 := ⟨9, 9, 9, 9⟩
def exampleAccountRoot : Hash4 := ⟨7, 7, 7, 7⟩

def exampleEnv : Environment Unit Unit :=
  { txRoot := fun _ _ _ => exampleTxTreeRoot
    txV2Root := fun _ _ _ => exampleTxTreeRoot
    sendRoot := fun _ _ _ => exampleSendTreeRoot
    channelRoot := fun _ _ _ => exampleAccountRoot
    spendVerifies := fun _ => true
    proofPublicInputs := fun _ =>
      Spend.PublicInputTargets.words ⟨Spend.zeroHash, Spend.zeroHash, Spend.emptyTx, 1⟩ }

def exampleAccountState : AccountState Unit :=
  { channelId := 1, accountTreeRoot := exampleAccountRoot,
    sendLeaf := ⟨0, 5, hashToBytes32 exampleTxTreeRoot⟩, sendLeafIndex := 0, sendMerkleProof := (),
    channelLeaf := ⟨1, 0, exampleSendTreeRoot, Spend.zeroHash⟩, userMerkleProof := () }

def examplePublicState : PublicState :=
  ⟨5, 0, 0, ⟨7, 7, 7, 7⟩, BalancePublicInputs.Root.zero, BalancePublicInputs.Root.zero⟩

def exampleSettlement : Settlement Unit Unit :=
  ⟨1, Spend.emptyTx, examplePublicState, exampleAccountState, (), none, none, ()⟩

theorem example_legacy_settlement_is_accepted :
    acceptLegacy exampleEnv 1 Spend.emptyTx examplePublicState exampleAccountState () () =
      .ok exampleSettlement := by
  rfl

theorem example_settlement_fills_a_satisfying_witness :
    CircuitGates exampleEnv true (fillWitness () exampleSettlement) := by
  refine native_acceptance_fills_a_satisfying_witness exampleEnv ?_ () 1 Spend.emptyTx examplePublicState
    exampleAccountState () none none () exampleSettlement example_legacy_settlement_is_accepted ?_ ?_
  · exact ⟨fun _ _ _ => by decide, fun _ _ _ => by decide⟩
  · exact ⟨⟨by decide, by decide, by decide⟩, by decide, ⟨by decide, by decide, by decide⟩, by decide,
      ⟨by decide, by decide⟩⟩
  · intro p h
    simp [exampleEnv, Spend.target_parser_round_trip_with_arbitrary_suffix] at h
    subst h; decide

theorem example_mixed_witness_is_rejected (s : Settlement Unit Unit) :
    acceptSettlement exampleEnv 1 Spend.emptyTx examplePublicState exampleAccountState () (some ())
      none () ≠ .ok s :=
  mixed_tx_v2_witness_is_never_accepted exampleEnv 1 Spend.emptyTx examplePublicState
    exampleAccountState () (some ()) none () (by decide) s

end Zkp.Implementation.TxSettlement
